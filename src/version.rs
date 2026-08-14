//! Version detection and bump classification.
//!
//! Proportionality is the heart of the differential thesis: the same capability
//! gain means very different things in a patch release versus a major one.
//! isomer detects versions from the input paths (or explicit `--base-version` /
//! `--head-version` flags), classifies the bump, and hands the tolerance to the
//! rubric. Detection is deliberately conservative — an undetectable version
//! yields no proportionality claim rather than a wrong one.

use crate::Severity;

/// A parsed dotted-numeric version. Pre-release / build metadata is kept in
/// `raw` for display but does not affect bump classification.
///
/// The first three components retain their usual major/minor/patch meaning.
/// Additional numeric components are preserved because WordPress and Windows
/// packages commonly use four-part versions (`4.4.6.4`, `10.0.19045.4046`).
/// For release-tolerance purposes those deeper components are patch-level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    extra: Vec<u64>,
    /// The version in normalized dotted form: `parse` keeps its input verbatim
    /// (so a `-rc2` or `+build` suffix survives), while `detect` and
    /// `from_claim` rewrite their separators — `4_3_0` and `4, 3, 0, 0` both
    /// arrive here dotted. `crate::analysis::clean_name` strips both spellings
    /// from a filename precisely because this is not the source token.
    pub raw: String,
}

impl Version {
    /// Parse a bare version token (`5.6.0`, `1.2`, `4.4.6.4`,
    /// `3.0.1-rc2`). Requires at least `major.minor`; a missing patch defaults
    /// to 0 and every numeric component is retained.
    pub(crate) fn parse(s: &str) -> Option<Self> {
        let core = s.split(['-', '+']).next().unwrap_or(s);
        let parts = core
            .split('.')
            .map(str::parse)
            .collect::<Result<Vec<u64>, _>>()
            .ok()?;
        if parts.len() < 2 {
            return None;
        }
        Some(Self {
            major: parts[0],
            minor: parts[1],
            patch: parts.get(2).copied().unwrap_or(0),
            extra: parts.get(3..).unwrap_or_default().to_vec(),
            raw: s.to_string(),
        })
    }

    fn component(&self, index: usize) -> u64 {
        match index {
            0 => self.major,
            1 => self.minor,
            2 => self.patch,
            _ => self.extra.get(index - 3).copied().unwrap_or(0),
        }
    }

    fn component_count(&self) -> usize {
        3 + self.extra.len()
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
        let mut best = best?;
        if let Some(suffix) = common_prerelease_suffix(name, &best.raw) {
            best.raw.push_str(suffix);
        }
        Some(best)
    }

    /// Parse a version claim extracted from artifact metadata. PE resources
    /// commonly spell `4.3.0.0` as `4, 3, 0, 0`; normalize that representation
    /// without accepting arbitrary prose surrounding a number.
    pub(crate) fn from_claim(claim: &str) -> Option<Self> {
        if claim.contains(',') {
            let parts: Vec<&str> = claim.split(',').map(str::trim).collect();
            return Self::from_numeric_parts(&parts);
        }
        if !claim
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
        {
            return None;
        }
        Self::parse(&claim.replace('_', "."))
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
    /// A change within the same numeric version, such as `1.0.0-rc.1` to
    /// `1.0.0`. It receives the same tight tolerance as a patch release.
    Prerelease,
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
        let width = old.component_count().max(new.component_count());
        for index in 0..width {
            let old_part = old.component(index);
            let new_part = new.component(index);
            if new_part < old_part {
                return Bump {
                    kind: BumpKind::Downgrade,
                    steps: 0,
                };
            }
            if new_part > old_part {
                return Bump {
                    kind: match index {
                        0 => BumpKind::Major,
                        1 => BumpKind::Minor,
                        _ => BumpKind::Patch,
                    },
                    steps: new_part - old_part,
                };
            }
        }
        fn prerelease(version: &Version) -> Option<&str> {
            version
                .raw
                .split_once('-')
                .map(|(_, suffix)| suffix.split('+').next().unwrap_or(suffix))
        }
        let old_prerelease = prerelease(old);
        let new_prerelease = prerelease(new);
        if old_prerelease != new_prerelease {
            return Bump {
                kind: if old_prerelease.is_none() {
                    BumpKind::Downgrade
                } else {
                    BumpKind::Prerelease
                },
                steps: 0,
            };
        }
        Bump {
            kind: BumpKind::Same,
            steps: 0,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self.kind {
            BumpKind::Major => "major",
            BumpKind::Minor => "minor",
            BumpKind::Patch => "patch",
            BumpKind::Prerelease => "prerelease",
            BumpKind::Same => "same",
            BumpKind::Downgrade => "downgrade",
        }
    }

    /// Human phrase: `minor release` for one step, `2 minor releases` for more.
    pub(crate) fn describe(self) -> String {
        match self.kind {
            BumpKind::Same => "same version".to_string(),
            BumpKind::Prerelease => "prerelease transition".to_string(),
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
            BumpKind::Patch | BumpKind::Prerelease | BumpKind::Same | BumpKind::Downgrade => {
                Severity::None
            }
        }
    }
}

/// Preserve common SemVer prerelease suffixes after the numeric token without
/// mistaking platform tags such as `-linux-x64` for versions. Archive suffixes
/// are removed first so `-rc.1.tgz` becomes exactly `-rc.1`.
fn common_prerelease_suffix<'a>(name: &'a str, numeric: &str) -> Option<&'a str> {
    let stem = [
        ".tar.gz", ".tar.xz", ".tar.bz2", ".tgz", ".txz", ".tbz2", ".whl", ".zip", ".gz", ".xz",
        ".sample",
    ]
    .iter()
    .find_map(|extension| name.strip_suffix(extension))
    .unwrap_or(name);
    let start = stem.find(numeric)? + numeric.len();
    let suffix = stem.get(start..)?;
    let prerelease = suffix.strip_prefix('-')?;
    if prerelease.is_empty()
        || !prerelease
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return None;
    }
    let mut identifiers = prerelease.split(['.', '-']);
    let first = identifiers.next()?.to_ascii_lowercase();
    let second = identifiers.next().map(str::to_ascii_lowercase);
    let known = |identifier: &str| {
        matches!(
            identifier,
            "alpha" | "beta" | "rc" | "pre" | "preview" | "dev" | "canary" | "next"
        )
    };
    (known(&first)
        || (first.bytes().all(|byte| byte.is_ascii_digit()) && second.is_some_and(|s| known(&s))))
    .then_some(suffix)
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
        assert_eq!(
            Version::detect("keyv-6.0.0-rc.1.tgz").unwrap().raw,
            "6.0.0-rc.1"
        );
        assert_eq!(
            Version::detect("joyfill-0.1.2-2773.beta.0.tgz")
                .unwrap()
                .raw,
            "0.1.2-2773.beta.0"
        );
        assert_eq!(
            Version::detect("tool-1.2.3-linux-x64.tgz").unwrap().raw,
            "1.2.3"
        );
    }

    #[test]
    fn parses_numeric_identity_claims_without_accepting_prose() {
        assert_eq!(Version::from_claim("4, 3, 0, 0").unwrap().raw, "4.3.0.0");
        assert_eq!(Version::from_claim("12_0_1").unwrap().raw, "12.0.1");
        assert_eq!(Version::from_claim("6.0.0-rc.1").unwrap().raw, "6.0.0-rc.1");
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

        let wordpress = Bump::classify(&v("4.4.6.3").unwrap(), &v("4.4.6.4").unwrap());
        assert_eq!(wordpress.kind, BumpKind::Patch);
        assert_eq!(wordpress.describe(), "patch release");
        let prerelease = Bump::classify(&v("6.0.0-rc.1").unwrap(), &v("6.0.0").unwrap());
        assert_eq!(prerelease.kind, BumpKind::Prerelease);
        assert_eq!(prerelease.describe(), "prerelease transition");
        assert_eq!(
            Bump::classify(&v("4.3.0.0").unwrap(), &v("4.3.0").unwrap()).kind,
            BumpKind::Same
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
