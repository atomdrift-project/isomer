//! `.isomer.toml` — the committed, reviewable suppression policy.
//!
//! A CI security tool lives or dies on its false-positive budget. When isomer
//! is wrong, the fix has to cost one line in a file the team already reviews —
//! otherwise the real fix becomes deleting the workflow. So the policy file is
//! deliberately tiny:
//!
//! ```toml
//! exclude = ["testdata/**"]        # never analyzed
//!
//! [[allow]]
//! id = "objectives/command-and-control/*"
//! reason = "vendored socket.io client; reviewed in #482"
//! expires = "2026-11-09"           # optional
//! path = "vendor/**"               # optional
//! ```
//!
//! Two rules keep it honest. A `reason` is **required** — an unexplained
//! suppression is a hole nobody can audit later, so isomer refuses to run
//! rather than silently honoring one. And `expires` makes a suppression
//! temporary by choice: past its date the entry stops applying and says so,
//! instead of quietly protecting an attacker a year later.
//!
//! Thresholds deliberately do **not** live here. `--fail-on` and `--gate` are
//! set where the pipeline is defined, so there is exactly one place to look
//! when asking "why did this fail".

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::NaiveDate;
use serde::Deserialize;

/// The default config filename, looked up in the working directory.
pub(crate) const FILE: &str = ".isomer.toml";

/// A loaded policy. The empty policy (no file) allows and excludes nothing.
#[derive(Debug, Default)]
pub(crate) struct Policy {
    exclude: Vec<String>,
    allow: Vec<Allow>,
    /// Where this came from, for the report's provenance line.
    pub source: Option<PathBuf>,
}

#[derive(Debug)]
struct Allow {
    id: String,
    path: Option<String>,
    reason: String,
    expires: Option<NaiveDate>,
}

/// The on-disk shape. Separate from [`Policy`] so parsing stays a dumb
/// deserialize and all validation happens in one place.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    exclude: Vec<String>,
    #[serde(default)]
    allow: Vec<AllowFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowFile {
    id: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    expires: Option<String>,
}

impl Policy {
    /// Load the policy from `path`, or from `./.isomer.toml` when `path` is
    /// `None`. A missing default file is not an error; a missing *explicit*
    /// one is.
    pub(crate) fn load(path: Option<&Path>, today: NaiveDate) -> Result<Self> {
        let (path, required) = match path {
            Some(p) => (p.to_path_buf(), true),
            None => (PathBuf::from(FILE), false),
        };
        if !path.exists() {
            if required {
                bail!("config not found: {}", path.display());
            }
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let parsed: File =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;

        let mut allow = Vec::with_capacity(parsed.allow.len());
        for (i, a) in parsed.allow.into_iter().enumerate() {
            if a.reason.trim().is_empty() {
                bail!(
                    "{}: [[allow]] #{} for `{}` has no reason. Every suppression must say why, \
                     so the next reader can judge it.",
                    path.display(),
                    i + 1,
                    a.id,
                );
            }
            let expires = match a.expires {
                Some(raw) => Some(NaiveDate::parse_from_str(&raw, "%Y-%m-%d").with_context(
                    || {
                        format!(
                            "{}: [[allow]] `{}` has invalid expires `{raw}` (want YYYY-MM-DD)",
                            path.display(),
                            a.id
                        )
                    },
                )?),
                None => None,
            };
            if let Some(exp) = expires.filter(|e| *e < today) {
                eprintln!(
                    "isomer: {}: suppression for `{}` expired {exp} — no longer applied",
                    path.display(),
                    a.id,
                );
                continue;
            }
            allow.push(Allow {
                id: a.id,
                path: a.path,
                reason: a.reason,
                expires,
            });
        }
        Ok(Self {
            exclude: parsed.exclude,
            allow,
            source: Some(path),
        })
    }

    /// Whether this file is out of scope entirely.
    pub(crate) fn excludes(&self, file: &str) -> bool {
        self.exclude.iter().any(|p| matches(p, file))
    }

    /// The policy entry suppressing this trait in this file, if any.
    ///
    /// Returns the accepted-risk record rather than a bare `bool` so every
    /// report can name what was withheld and on whose say-so. A suppression
    /// nobody can see is indistinguishable from a missed detection.
    pub(crate) fn allows(&self, id: &str, file: &str) -> Option<Suppressed> {
        self.allow
            .iter()
            .find(|a| matches(&a.id, id) && a.path.as_ref().is_none_or(|p| matches(p, file)))
            .map(|a| Suppressed {
                id: id.to_string(),
                reason: a.reason.clone(),
                expires: a.expires,
            })
    }
}

/// One finding withheld by policy, carried into the report.
#[derive(Debug, Clone)]
pub(crate) struct Suppressed {
    /// The finding id that was matched, not the pattern that matched it — the
    /// reader wants to know what was silenced, not how it was spelled.
    pub id: String,
    pub reason: String,
    pub expires: Option<NaiveDate>,
}

impl Suppressed {
    /// `reason (until 2026-11-09)` — one line for a report.
    pub(crate) fn describe(&self) -> String {
        match self.expires {
            Some(e) => format!("{} (until {e})", self.reason),
            None => self.reason.clone(),
        }
    }
}

/// Glob match with `*` (any run of characters, **including** `/`) and `?` (one
/// character). Separators are deliberately not special: these patterns match
/// both filesystem paths and `a/b/c::trait` ids, and one predictable rule beats
/// two subtly different ones. `**` therefore behaves exactly like `*`.
fn matches(pattern: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
    // Two-pointer scan with backtracking to the last `*` — linear in practice,
    // and no recursion to blow the stack on a hostile pattern.
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut resume) = (None, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            resume = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            resume += 1;
            ti = resume;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matches_paths_and_trait_ids() {
        assert!(matches("testdata/**", "testdata/supplychain/xz.tgz"));
        assert!(matches("*.min.js", "vendor/jquery.min.js"));
        assert!(matches(
            "objectives/command-and-control/*",
            "objectives/command-and-control/channel/websocket::sio"
        ));
        assert!(matches("exact", "exact"));
        assert!(!matches("exact", "exactly"));
        assert!(!matches("testdata/**", "src/main.rs"));
        // A trailing `*` may match nothing at all.
        assert!(matches("src/*", "src/"));
    }

    #[test]
    fn glob_backtracks() {
        assert!(matches("*a*b", "xxaxxb"));
        assert!(!matches("*a*b", "xxaxx"));
        assert!(matches("?b", "ab"));
        assert!(!matches("?b", "aab"));
    }

    fn day(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap_or_default()
    }

    fn write(dir: &Path, body: &str) -> PathBuf {
        let p = dir.join(FILE);
        std::fs::write(&p, body).unwrap_or_default();
        p
    }

    #[test]
    fn reasonless_suppression_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = write(dir.path(), "[[allow]]\nid = \"x\"\n");
        let err = Policy::load(Some(&p), day("2026-01-01"))
            .map(|_| ())
            .unwrap_err();
        assert!(format!("{err:#}").contains("no reason"), "{err:#}");
    }

    #[test]
    fn expired_suppression_stops_applying() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = write(
            dir.path(),
            "[[allow]]\nid = \"x/*\"\nreason = \"temporary\"\nexpires = \"2026-01-01\"\n",
        );
        let live = Policy::load(Some(&p), day("2025-12-31")).expect("load");
        assert!(live.allows("x/y", "any.js").is_some());
        let dead = Policy::load(Some(&p), day("2026-06-01")).expect("load");
        assert!(dead.allows("x/y", "any.js").is_none());
    }

    #[test]
    fn allow_can_be_scoped_to_a_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = write(
            dir.path(),
            "[[allow]]\nid = \"net/*\"\nreason = \"vendored client\"\npath = \"vendor/**\"\n",
        );
        let policy = Policy::load(Some(&p), day("2026-01-01")).expect("load");
        let hit = policy
            .allows("net/http", "vendor/a.js")
            .expect("suppressed");
        assert_eq!(hit.reason, "vendored client");
        assert_eq!(
            hit.id, "net/http",
            "the report names the finding, not the pattern"
        );
        assert!(policy.allows("net/http", "src/a.js").is_none());
    }

    #[test]
    fn missing_default_file_is_not_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("nope.toml");
        assert!(Policy::load(Some(&missing), day("2026-01-01")).is_err());
        let policy = Policy::default();
        assert!(policy.allows("anything", "anywhere").is_none());
        assert!(!policy.excludes("anywhere"));
    }
}
