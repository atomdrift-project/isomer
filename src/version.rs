//! Version detection and bump classification.
//!
//! Proportionality is the heart of the differential thesis: the same capability
//! gain means very different things in a patch release versus a major one.
//! isomer detects versions from the input paths (or explicit `--base-version` /
//! `--head-version` flags), classifies the bump, and hands the tolerance to the
//! rubric. Detection is deliberately conservative — an undetectable version
//! yields no proportionality claim rather than a wrong one.

use crate::Severity;

/// A parsed `major.minor.patch` version. Pre-release / build metadata is kept
/// in `raw` for display but does not affect bump classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    /// The token exactly as detected, e.g. `5.6.0` or `12.0.1`.
    pub raw: String,
}

impl Version {
    /// Parse a bare version token (`5.6.0`, `1.2`, `3.0.1-rc2`). Requires at
    /// least `major.minor`; a missing patch defaults to 0.
    pub(crate) fn parse(s: &str) -> Option<Self> {
        let core = s.split(['-', '+']).next().unwrap_or(s);
        let mut it = core.split('.');
        let major = it.next()?.parse().ok()?;
        let minor = it.next()?.parse().ok()?;
        let patch = it.next().and_then(|p| p.parse().ok()).unwrap_or(0);
        Some(Self {
            major,
            minor,
            patch,
            raw: s.to_string(),
        })
    }

    /// Extract the most complete version-like token from a filename, e.g.
    /// `liblzma.so.5.6.0` → `5.6.0`, `node-ipc-12.0.1.tgz` → `12.0.1`.
    /// Prefers tokens with more components so `foo-2-1.2.3` picks `1.2.3`.
    pub(crate) fn detect(name: &str) -> Option<Self> {
        let mut best: Option<Version> = None;
        let mut best_parts = 0usize;
        for run in version_char_runs(name) {
            let tok = run.trim_matches('.');
            let parts = tok.split('.').count();
            if parts < 2 {
                continue;
            }
            if parts > best_parts
                && let Some(v) = Version::parse(tok)
            {
                best_parts = parts;
                best = Some(v);
            }
        }
        best
    }
}

/// Maximal substrings composed only of ASCII digits and `.`.
fn version_char_runs(s: &str) -> Vec<&str> {
    let bytes = s.as_bytes();
    let mut runs = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() || bytes[i] == b'.' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                i += 1;
            }
            runs.push(&s[start..i]);
        } else {
            i += 1;
        }
    }
    runs
}

/// How the new version relates to the old one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Bump {
    Major,
    Minor,
    Patch,
    Same,
    /// The new version is lower — itself a supply-chain red flag.
    Downgrade,
}

impl Bump {
    pub(crate) fn classify(old: &Version, new: &Version) -> Bump {
        use std::cmp::Ordering::{Equal, Greater, Less};
        match (
            new.major.cmp(&old.major),
            new.minor.cmp(&old.minor),
            new.patch.cmp(&old.patch),
        ) {
            (Greater, _, _) => Bump::Major,
            (Less, _, _) => Bump::Downgrade,
            (Equal, Greater, _) => Bump::Minor,
            (Equal, Less, _) => Bump::Downgrade,
            (Equal, Equal, Greater) => Bump::Patch,
            (Equal, Equal, Less) => Bump::Downgrade,
            (Equal, Equal, Equal) => Bump::Same,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Bump::Major => "major",
            Bump::Minor => "minor",
            Bump::Patch => "patch",
            Bump::Same => "same",
            Bump::Downgrade => "downgrade",
        }
    }

    /// Highest behavioral-capability severity considered *proportionate* for
    /// this bump. Anything above it is disproportionate drift — a patch that
    /// adds an execution primitive, a minor that adds network egress.
    pub(crate) fn tolerance(self) -> Severity {
        match self {
            Bump::Major => Severity::High,
            Bump::Minor => Severity::Medium,
            Bump::Patch | Bump::Same | Bump::Downgrade => Severity::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_from_real_filenames() {
        assert_eq!(Version::detect("liblzma.so.5.6.0").unwrap().raw, "5.6.0");
        assert_eq!(Version::detect("node-ipc-12.0.1.tgz").unwrap().raw, "12.0.1");
        assert!(Version::detect("index.js").is_none());
    }

    #[test]
    fn classify_bumps() {
        let v = Version::parse;
        assert_eq!(
            Bump::classify(&v("5.4.5").unwrap(), &v("5.6.0").unwrap()),
            Bump::Minor
        );
        assert_eq!(
            Bump::classify(&v("12.0.0").unwrap(), &v("12.0.1").unwrap()),
            Bump::Patch
        );
        assert_eq!(
            Bump::classify(&v("1.0.0").unwrap(), &v("2.0.0").unwrap()),
            Bump::Major
        );
        assert_eq!(
            Bump::classify(&v("2.0.0").unwrap(), &v("1.9.9").unwrap()),
            Bump::Downgrade
        );
    }

    #[test]
    fn tolerance_tightens_for_smaller_bumps() {
        assert_eq!(Bump::Patch.tolerance(), Severity::None);
        assert_eq!(Bump::Minor.tolerance(), Severity::Medium);
        assert_eq!(Bump::Major.tolerance(), Severity::High);
    }
}
