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

/// Which version component moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BumpKind {
    Major,
    Minor,
    Patch,
    Same,
    /// The new version is lower — itself a supply-chain red flag.
    Downgrade,
}

/// How the new version relates to the old one, including *how far* it moved:
/// `5.4.5 → 5.6.0` is `Minor` with `steps = 2` (two minor releases), which the
/// report states honestly rather than calling it "a minor release".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Bump {
    pub kind: BumpKind,
    pub steps: u64,
}

impl Bump {
    pub(crate) fn classify(old: &Version, new: &Version) -> Bump {
        use std::cmp::Ordering::{Equal, Greater, Less};
        let (kind, steps) = match (
            new.major.cmp(&old.major),
            new.minor.cmp(&old.minor),
            new.patch.cmp(&old.patch),
        ) {
            (Greater, _, _) => (BumpKind::Major, new.major - old.major),
            (Less, _, _) => (BumpKind::Downgrade, 0),
            (Equal, Greater, _) => (BumpKind::Minor, new.minor - old.minor),
            (Equal, Less, _) => (BumpKind::Downgrade, 0),
            (Equal, Equal, Greater) => (BumpKind::Patch, new.patch - old.patch),
            (Equal, Equal, Less) => (BumpKind::Downgrade, 0),
            (Equal, Equal, Equal) => (BumpKind::Same, 0),
        };
        Bump { kind, steps }
    }

    pub(crate) fn label(self) -> &'static str {
        match self.kind {
            BumpKind::Major => "major",
            BumpKind::Minor => "minor",
            BumpKind::Patch => "patch",
            BumpKind::Same => "same",
            BumpKind::Downgrade => "downgrade",
        }
    }

    /// Human phrase: `minor release` for one step, `2 minor releases` for more.
    pub(crate) fn describe(self) -> String {
        match self.kind {
            BumpKind::Same => "same version".to_string(),
            BumpKind::Downgrade => "downgrade".to_string(),
            _ if self.steps > 1 => format!("{} {} releases", self.steps, self.label()),
            _ => format!("{} release", self.label()),
        }
    }

    /// Highest behavioral-capability severity considered *proportionate* for
    /// this bump. Anything above it is disproportionate drift — a patch that
    /// adds an execution primitive, a minor that adds network egress. Keyed on
    /// the component that moved, not the distance: two minor releases still do
    /// not license an execution-hijack primitive.
    pub(crate) fn tolerance(self) -> Severity {
        match self.kind {
            BumpKind::Major => Severity::High,
            BumpKind::Minor => Severity::Medium,
            BumpKind::Patch | BumpKind::Same | BumpKind::Downgrade => Severity::None,
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
        // 5.4.5 → 5.6.0 is TWO minor releases, not one.
        let b = Bump::classify(&v("5.4.5").unwrap(), &v("5.6.0").unwrap());
        assert_eq!(b.kind, BumpKind::Minor);
        assert_eq!(b.steps, 2);
        assert_eq!(b.describe(), "2 minor releases");

        assert_eq!(Bump::classify(&v("12.0.0").unwrap(), &v("12.0.1").unwrap()).kind, BumpKind::Patch);
        assert_eq!(Bump::classify(&v("5.4.5").unwrap(), &v("5.5.0").unwrap()).describe(), "minor release");
        assert_eq!(Bump::classify(&v("1.0.0").unwrap(), &v("2.0.0").unwrap()).kind, BumpKind::Major);
        assert_eq!(Bump::classify(&v("2.0.0").unwrap(), &v("1.9.9").unwrap()).kind, BumpKind::Downgrade);
    }

    #[test]
    fn tolerance_tightens_for_smaller_bumps() {
        let b = |kind| Bump { kind, steps: 1 };
        assert_eq!(b(BumpKind::Patch).tolerance(), Severity::None);
        assert_eq!(b(BumpKind::Minor).tolerance(), Severity::Medium);
        assert_eq!(b(BumpKind::Major).tolerance(), Severity::High);
        // Two minor releases still don't license a High capability.
        assert_eq!(Bump { kind: BumpKind::Minor, steps: 2 }.tolerance(), Severity::Medium);
    }
}
