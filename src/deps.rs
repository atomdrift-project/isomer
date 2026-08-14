//! Dependency behavioral delta — what the dependencies a change *added* can do.
//!
//! "Added dependency: peacenotwar" is a tripwire, not an answer: the risk is
//! what peacenotwar *does*, and its code isn't in the package that declared it.
//! So for each runtime dependency a change adds, fetch it and analyze it, and
//! report the capability — the file-overwrite, the network egress — attributed
//! to the dependency that introduced it. This is the transitive supply-chain
//! case (event-stream → flatmap-stream) a manifest diff alone is blind to.
//!
//! A network step, gated behind `--deps`. Fetch and analysis failures are
//! reported per dependency, never swallowed — a gap in coverage must not read
//! as a clean dependency.

use cleave::AnalysisOptions;
use cleave::types::DiffReportV1;

use crate::Severity;
use crate::rubric::severity_from_crit;

/// How many findings a dependency's profile names, worst-first.
const MAX_HIGHLIGHTS: usize = 4;

/// One added dependency, fetched and profiled for what it can do.
#[derive(Debug)]
pub(crate) struct DepProfile {
    /// The declared coordinate, `peacenotwar@^9.1.3`.
    pub coord: String,
    /// The package ecosystem, `npm` / `pypi` / …, for the section's context.
    pub ecosystem: &'static str,
    /// Worst severity found in the fetched dependency.
    pub severity: Severity,
    /// Strongest finding descriptions, worst-first — what the dependency does.
    pub highlights: Vec<String>,
    /// Set when the dependency could not be fetched or analyzed, so a gap in
    /// coverage is reported rather than mistaken for a clean dependency.
    pub note: Option<String>,
}

pub(crate) fn severity(profiles: &[DepProfile]) -> Severity {
    profiles
        .iter()
        .map(|profile| profile.severity)
        .max()
        .unwrap_or(Severity::None)
}

/// Fetch and profile every runtime dependency the change added. Empty when the
/// change added none. `progress` shows the fetch spinner for a human at a
/// terminal.
pub(crate) fn profiles(
    diff: &DiffReportV1,
    options: &AnalysisOptions,
    progress: bool,
) -> Vec<DepProfile> {
    added(diff)
        .iter()
        .map(|dep| profile(dep, options, progress))
        .collect()
}

/// A runtime dependency a change declared: its ecosystem, name, and the version
/// spec as written in the manifest.
struct Added {
    ecosystem: &'static str,
    name: String,
    spec: String,
}

/// Fetch one added dependency and summarize what it does.
fn profile(dep: &Added, options: &AnalysisOptions, progress: bool) -> DepProfile {
    let coord = format!("{}@{}", dep.name, dep.spec);
    // Exact pins identify one immutable release. A range (`^0.1.0`) does not:
    // fetching its floor would miss the later compatible release an installer
    // actually resolves — precisely the event-stream/flatmap-stream failure
    // mode. Leave ranges unversioned so the registry resolver selects the
    // current release; lockfiles, when present, contribute exact pins.
    let purl = match exact_version(&dep.spec) {
        Some(v) => format!("pkg:{}/{}@{}", dep.ecosystem, dep.name, v),
        None => format!("pkg:{}/{}", dep.ecosystem, dep.name),
    };
    let mut out = DepProfile {
        coord,
        ecosystem: dep.ecosystem,
        severity: Severity::None,
        highlights: Vec::new(),
        note: None,
    };
    let bytes = match crate::fetch::fetch_bytes(&purl, progress) {
        Ok((bytes, _name)) => bytes,
        Err(e) => {
            out.note = Some(format!("could not fetch: {e:#}"));
            return out;
        }
    };
    match cleave::analyze_bytes_owned(bytes, &purl, options) {
        Ok(report) => (out.severity, out.highlights) = summarize(&report),
        Err(e) => out.note = Some(format!("could not analyze: {e:#}")),
    }
    out
}

/// A fetched dependency's analysis, read down to what the profile shows: its
/// worst severity and the strongest distinct findings — the capabilities the
/// dependency introduces.
fn summarize(report: &cleave::AnalysisReport) -> (Severity, Vec<String>) {
    let mut findings: Vec<(Severity, String)> = crate::evidence::all_findings(report)
        .filter_map(|f| {
            let sev = severity_from_crit(f.crit);
            (sev != Severity::None && !f.desc.is_empty())
                .then(|| (sev, crate::printable(f.desc.as_str())))
        })
        .collect();
    // Worst first; one line per distinct description so the profile shows
    // variety, not the same rule repeated.
    findings.sort_by_key(|(sev, _)| std::cmp::Reverse(*sev));
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    findings.retain(|(_, d)| seen.insert(d.clone()));
    let worst = findings.first().map_or(Severity::None, |(s, _)| *s);
    let highlights = findings
        .into_iter()
        .take(MAX_HIGHLIGHTS)
        .map(|(_, d)| d)
        .collect();
    (worst, highlights)
}

/// An exact manifest version, or `None` for every range/tag/URL. Treating the
/// floor of a range as the resolved dependency is unsound for security review:
/// an attacker commonly publishes a later version that still satisfies it.
fn exact_version(spec: &str) -> Option<String> {
    let spec = spec.trim();
    if spec.is_empty()
        || spec.starts_with(['^', '~', '<', '>'])
        || spec.contains(|c: char| c.is_whitespace() || matches!(c, '|' | ',' | '*'))
        || spec.to_ascii_lowercase().contains('x')
        || spec.contains("://")
    {
        return None;
    }
    let token = spec
        .strip_prefix('=')
        .unwrap_or(spec)
        .trim_start_matches('v');
    let exact = token.chars().next().is_some_and(|c| c.is_ascii_digit())
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'));
    exact.then(|| token.to_string())
}

/// The runtime dependencies a diff added, read from every changed manifest's kv
/// scope. Only `dependencies.<name>` direct children — a deeper path is a
/// sub-field of the version spec, and dev/build trees don't ship to end users.
fn added(diff: &DiffReportV1) -> Vec<Added> {
    let mut out = Vec::new();
    for file in &diff.files {
        let Some(ecosystem) = ecosystem(&file.path) else {
            continue;
        };
        let Some(kv) = file.scopes.kv.as_ref() else {
            continue;
        };
        for entry in &kv.added {
            let Some(rest) = entry.path.strip_prefix("dependencies.") else {
                continue;
            };
            if rest.is_empty() || rest.contains('.') {
                continue;
            }
            let Some(spec) = entry.value.as_str() else {
                continue;
            };
            out.push(Added {
                ecosystem,
                name: rest.to_string(),
                spec: spec.to_string(),
            });
        }
    }
    out
}

/// The PURL ecosystem for a manifest, keyed on its filename (the diff carries
/// the member path, e.g. `<root>!!package/package.json`). `None` when the file
/// declares no fetchable runtime dependencies, so no purl can be built.
fn ecosystem(path: &str) -> Option<&'static str> {
    let base = path.rsplit(['/', '!']).next().unwrap_or(path);
    match base {
        "package.json" | "package-lock.json" => Some("npm"),
        "pyproject.toml" | "requirements.txt" | "poetry.lock" | "Pipfile.lock" => Some("pypi"),
        "Cargo.toml" | "Cargo.lock" => Some("cargo"),
        "Gemfile.lock" => Some("gem"),
        "composer.json" | "composer.lock" => Some("composer"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{DepProfile, exact_version, severity};
    use crate::Severity;

    #[test]
    fn dependency_fetch_only_pins_exact_versions() {
        assert_eq!(exact_version("1.2.3").as_deref(), Some("1.2.3"));
        assert_eq!(
            exact_version("=v1.2.3-beta.1").as_deref(),
            Some("1.2.3-beta.1")
        );
        for range in ["^0.1.0", "~1.2.3", ">=1.2.3 <2", "1.x", "*", "latest"] {
            assert_eq!(exact_version(range), None, "{range} is not an exact pin");
        }
    }

    #[test]
    fn added_dependency_profiles_contribute_their_worst_severity() {
        let profile = |severity| DepProfile {
            coord: "dep@1".to_string(),
            ecosystem: "npm",
            severity,
            highlights: Vec::new(),
            note: None,
        };
        assert_eq!(
            severity(&[profile(Severity::Medium), profile(Severity::Critical)]),
            Severity::Critical
        );
        assert_eq!(severity(&[]), Severity::None);
    }
}
