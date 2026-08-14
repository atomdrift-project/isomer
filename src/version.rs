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
    /// The version in normalized dotted form: `parse` keeps its input verbatim
    /// (so a `-rc2` or `+build` suffix survives), while `detect` and
    /// `from_claim` rewrite their separators — `4_3_0` and `4, 3, 0, 0` both
    /// arrive here dotted. `crate::analysis::clean_name` strips both spellings
    /// from a filename precisely because this is not the source token.
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
    /// `liblzma.so.5.6.0` → `5.6.0`, `ClassicShellSetup_4_3_0.exe` →
    /// `4.3.0`. Dots and underscores are the two common unambiguous in-token
    /// separators; hyphens remain token boundaries because they also separate
    /// nearly every package name from its version.
    pub(crate) fn detect(name: &str) -> Option<Self> {
        let mut best: Option<Version> = None;
        let mut best_parts = 0usize;
        // Every maximal run of ASCII digits and version separators is a
        // candidate. Validate every component before normalizing so malformed
        // names (`1__2`) do not become plausible versions by accident.
        for run in name.split(|c: char| !(c.is_ascii_digit() || matches!(c, '.' | '_'))) {
            let tok = run.trim_matches(['.', '_']);
            let parts: Vec<&str> = tok.split(['.', '_']).collect();
            if parts.len() > best_parts
                && let Some(v) = Self::from_numeric_parts(&parts)
            {
                best_parts = parts.len();
                best = Some(v);
            }
        }
        best
    }

    /// Parse a version claim extracted from artifact metadata. PE resources
    /// commonly spell `4.3.0.0` as `4, 3, 0, 0`; normalize that representation
    /// without accepting arbitrary prose surrounding a number.
    pub(crate) fn from_claim(claim: &str) -> Option<Self> {
        let parts: Vec<&str> = claim.split(['.', '_', ',']).map(str::trim).collect();
        Self::from_numeric_parts(&parts)
    }

    /// A version from already-split components, in dot form. Every component
    /// must be a non-empty digit run: validating before normalizing is what
    /// keeps a malformed `1__2` — or prose around a number — from becoming a
    /// plausible version by accident.
    fn from_numeric_parts(parts: &[&str]) -> Option<Self> {
        if parts.len() < 2
            || !parts
                .iter()
                .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
        {
            return None;
        }
        Self::parse(&parts.join("."))
    }
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
            (Equal, Greater, _) => (BumpKind::Minor, new.minor - old.minor),
            (Equal, Equal, Greater) => (BumpKind::Patch, new.patch - old.patch),
            (Equal, Equal, Equal) => (BumpKind::Same, 0),
            // Whichever component moved backwards, the release went backwards;
            // the depth it happened at carries no extra signal. The arms above
            // are mutually exclusive with these, so order is not load-bearing.
            (Less, _, _) | (Equal, Less, _) | (Equal, Equal, Less) => (BumpKind::Downgrade, 0),
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
        assert_eq!(
            Version::detect("node-ipc-12.0.1.tgz").unwrap().raw,
            "12.0.1"
        );
        let classic = Version::detect("ClassicShellSetup_4_3_0.exe").unwrap();
        assert_eq!((classic.major, classic.minor, classic.patch), (4, 3, 0));
        assert_eq!(classic.raw, "4.3.0");
        assert!(Version::detect("ClassicShellSetup_4__3_0.exe").is_none());
        assert!(Version::detect("index.js").is_none());
    }

    #[test]
    fn parses_numeric_identity_claims_without_accepting_prose() {
        assert_eq!(Version::from_claim("4, 3, 0, 0").unwrap().raw, "4.3.0.0");
        assert_eq!(Version::from_claim("12_0_1").unwrap().raw, "12.0.1");
        assert!(Version::from_claim("release 4.3.0").is_none());
    }

    #[test]
    fn classify_bumps() {
        let v = Version::parse;
        // 5.4.5 → 5.6.0 is TWO minor releases, not one.
        let b = Bump::classify(&v("5.4.5").unwrap(), &v("5.6.0").unwrap());
        assert_eq!(b.kind, BumpKind::Minor);
        assert_eq!(b.steps, 2);
        assert_eq!(b.describe(), "2 minor releases");

        assert_eq!(
            Bump::classify(&v("12.0.0").unwrap(), &v("12.0.1").unwrap()).kind,
            BumpKind::Patch
        );
        assert_eq!(
            Bump::classify(&v("5.4.5").unwrap(), &v("5.5.0").unwrap()).describe(),
            "minor release"
        );
        assert_eq!(
            Bump::classify(&v("1.0.0").unwrap(), &v("2.0.0").unwrap()).kind,
            BumpKind::Major
        );
        assert_eq!(
            Bump::classify(&v("2.0.0").unwrap(), &v("1.9.9").unwrap()).kind,
            BumpKind::Downgrade
        );
    }

    #[test]
    fn tolerance_tightens_for_smaller_bumps() {
        let b = |kind| Bump { kind, steps: 1 };
        assert_eq!(b(BumpKind::Patch).tolerance(), Severity::None);
        assert_eq!(b(BumpKind::Minor).tolerance(), Severity::Medium);
        assert_eq!(b(BumpKind::Major).tolerance(), Severity::High);
        // Two minor releases still don't license a High capability.
        assert_eq!(
            Bump {
                kind: BumpKind::Minor,
                steps: 2
            }
            .tolerance(),
            Severity::Medium
        );
    }
}
