//! Version detection and bump classification.
//!
//! Proportionality is the heart of the differential thesis: the same capability
//! gain means very different things in a patch release versus a major one.
//! isomer detects versions from the input paths (or explicit `--base-version` /
//! `--head-version` flags), classifies the bump, and hands the tolerance to the
//! rubric. Detection is deliberately conservative — an undetectable version
//! yields no proportionality claim rather than a wrong one.

use crate::Severity;

/// A parsed dotted-numeric version. The prerelease tag takes part in bump
/// classification ([`Version::prerelease`]); build metadata (`+build.5`) is
/// kept in `raw` for display and ignored everywhere else, as SemVer requires.
///
/// The first three components retain their usual major/minor/patch meaning.
/// Additional numeric components are preserved because WordPress and Windows
/// packages commonly use four-part versions (`4.4.6.4`, `10.0.19045.4046`).
/// For release-tolerance purposes those deeper components are patch-level.
///
/// Equality is by meaning, not spelling: `1.2` equals `1.2.0`, and build
/// metadata never distinguishes two versions.
#[derive(Debug, Clone)]
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

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        let width = self.component_count().max(other.component_count());
        (0..width).all(|i| self.component(i) == other.component(i))
            && self.prerelease() == other.prerelease()
    }
}

impl Eq for Version {}

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

    /// The SemVer prerelease tag — `rc.1` in `6.0.0-rc.1+build-5` — or `None`
    /// for a release. Build metadata is removed *first*: a hyphen inside it
    /// (`1.2.3+build-5`) is not a prerelease separator, and reading it as one
    /// once classified a rebuild of `1.2.3` as a downgrade.
    pub(crate) fn prerelease(&self) -> Option<&str> {
        let without_build = self
            .raw
            .split_once('+')
            .map_or(self.raw.as_str(), |(v, _)| v);
        without_build.split_once('-').map(|(_, pre)| pre)
    }

    /// Parse a version the user typed — `--base-version` / `--head-version` —
    /// where a leading `v` is the common spelling and a value that does not
    /// parse is a mistake to report, not a hint to ignore.
    pub(crate) fn parse_override(flag: &str, value: &str) -> anyhow::Result<Self> {
        let trimmed = value.trim();
        Self::parse(trimmed.strip_prefix(['v', 'V']).unwrap_or(trimmed)).ok_or_else(|| {
            anyhow::anyhow!(
                "{flag} `{}` is not a version (expected MAJOR.MINOR[.PATCH…][-PRERELEASE][+BUILD])",
                crate::printable(value)
            )
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

/// Which version component moved. Serialized by name, as the report's `bump`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
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

/// What a release's version number promises about new behavior — the bar the
/// shape rules scale with. One reading of [`BumpKind`] rather than a pressure
/// number spelled out at each rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Promise {
    /// Same version, patch, prerelease, or downgrade: nothing new should ship.
    Nothing,
    /// A minor release: new features, within reason.
    Features,
    /// A major release: anything may change.
    Anything,
}

impl BumpKind {
    /// What this kind of release promises. A downgrade promises less than
    /// anything, so it reads as the strictest promise.
    pub(crate) fn promise(self) -> Promise {
        match self {
            Self::Same | Self::Patch | Self::Prerelease | Self::Downgrade => Promise::Nothing,
            Self::Minor => Promise::Features,
            Self::Major => Promise::Anything,
        }
    }
}

/// How the new version relates to the old one, including *how far* it moved:
/// `5.4.5 → 5.6.0` is `Minor` with `steps = 2` (two minor releases), which the
/// report states honestly rather than calling it "a minor release".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Bump {
    pub kind: BumpKind,
    /// How many releases of `kind` the bump spans. Only a numeric move has a
    /// distance; [`Bump::new`] keeps it zero for every other kind.
    steps: u64,
}

impl Bump {
    /// A bump of `kind` spanning `steps` releases. A distance is recorded only
    /// for a major, minor, or patch move: "two same-version releases" is not a
    /// thing, so any other kind carries none.
    pub(crate) fn new(kind: BumpKind, steps: u64) -> Self {
        let steps = match kind {
            BumpKind::Major | BumpKind::Minor | BumpKind::Patch => steps,
            BumpKind::Prerelease | BumpKind::Same | BumpKind::Downgrade => 0,
        };
        Self { kind, steps }
    }

    /// The distance, for a numeric move.
    pub(crate) fn steps(self) -> Option<u64> {
        (self.steps > 0).then_some(self.steps)
    }

    pub(crate) fn classify(old: &Version, new: &Version) -> Bump {
        let width = old.component_count().max(new.component_count());
        for index in 0..width {
            let old_part = old.component(index);
            let new_part = new.component(index);
            if new_part < old_part {
                return Bump::new(BumpKind::Downgrade, 0);
            }
            if new_part > old_part {
                let kind = match index {
                    0 => BumpKind::Major,
                    1 => BumpKind::Minor,
                    _ => BumpKind::Patch,
                };
                return Bump::new(kind, new_part - old_part);
            }
        }
        // Same numeric version: SemVer precedence over the prerelease tags
        // decides. A release outranks every prerelease of it, so `1.0.0` →
        // `1.0.0-rc.1` moves backwards, and so does `rc.2` → `rc.1`.
        match prerelease_order(old.prerelease(), new.prerelease()) {
            std::cmp::Ordering::Less => {
                return Bump::new(BumpKind::Prerelease, 0);
            }
            std::cmp::Ordering::Greater => {
                return Bump::new(BumpKind::Downgrade, 0);
            }
            std::cmp::Ordering::Equal => {}
        }
        Bump::new(BumpKind::Same, 0)
    }

    /// Human phrase: `minor release` for one step, `2 minor releases` for more.
    pub(crate) fn describe(self) -> String {
        self.to_string()
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

/// SemVer precedence of two prerelease tags on the same numeric version: `Less`
/// when `old` precedes `new`. No tag (a release) outranks any tag; otherwise
/// dot-separated identifiers compare left to right, numeric ones numerically
/// and below alphanumeric ones, and a shorter tag that is a prefix of a longer
/// one comes first.
fn prerelease_order(old: Option<&str>, new: Option<&str>) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let (old, new) = match (old, new) {
        (None, None) => return Ordering::Equal,
        (None, Some(_)) => return Ordering::Greater,
        (Some(_), None) => return Ordering::Less,
        (Some(old), Some(new)) => (old, new),
    };
    let identifier = |id: &str| -> (bool, u64) {
        match id.parse::<u64>() {
            Ok(n) if id.bytes().all(|b| b.is_ascii_digit()) => (false, n),
            _ => (true, 0),
        }
    };
    let mut a = old.split('.');
    let mut b = new.split('.');
    loop {
        match (a.next(), b.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) => {
                let order = match (identifier(x), identifier(y)) {
                    ((false, m), (false, n)) => m.cmp(&n),
                    ((false, _), (true, _)) => Ordering::Less,
                    ((true, _), (false, _)) => Ordering::Greater,
                    ((true, _), (true, _)) => x.cmp(y),
                };
                if order != Ordering::Equal {
                    return order;
                }
            }
        }
    }
}

impl BumpKind {
    /// The kind's name, as the report's `bump` field spells it.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Major => "major",
            Self::Minor => "minor",
            Self::Patch => "patch",
            Self::Prerelease => "prerelease",
            Self::Same => "same",
            Self::Downgrade => "downgrade",
        }
    }
}

impl std::fmt::Display for BumpKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `minor release` for one step, `2 minor releases` for more.
impl std::fmt::Display for Bump {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.kind, self.steps()) {
            (BumpKind::Same, _) => f.write_str("same version"),
            (BumpKind::Prerelease, _) => f.write_str("prerelease transition"),
            (BumpKind::Downgrade, _) => f.write_str("downgrade"),
            (kind, Some(steps)) if steps > 1 => write!(f, "{steps} {kind} releases"),
            (kind, _) => write!(f, "{kind} release"),
        }
    }
}

/// Archive extensions a published filename can end in, compound ones first so
/// `.tar.gz` is stripped whole rather than leaving `.tar` behind. One list for
/// every place a name is read, so the version and the display name agree on
/// where the name ends.
pub(crate) const ARCHIVE_SUFFIXES: [&str; 12] = [
    ".tar.gz", ".tar.xz", ".tar.bz2", ".tar.zst", ".tgz", ".txz", ".tbz2", ".tar", ".whl", ".zip",
    ".gz", ".xz",
];

/// The name without its archive extension, if it has one.
pub(crate) fn strip_archive_suffix(name: &str) -> Option<&str> {
    ARCHIVE_SUFFIXES
        .iter()
        .find_map(|suffix| name.strip_suffix(suffix))
}

/// Preserve common SemVer prerelease suffixes after the numeric token without
/// mistaking platform tags such as `-linux-x64` for versions. Archive suffixes
/// are removed first so `-rc.1.tgz` becomes exactly `-rc.1`; so is the
/// `.sample` a quarantine store appends.
fn common_prerelease_suffix<'a>(name: &'a str, numeric: &str) -> Option<&'a str> {
    let stem = name.strip_suffix(".sample").unwrap_or(name);
    let stem = strip_archive_suffix(stem).unwrap_or(stem);
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
        assert_eq!(b.steps(), Some(2));
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

    /// Build metadata is not a prerelease, even when it contains a hyphen.
    #[test]
    fn build_metadata_never_reads_as_a_prerelease() {
        let v = |s| Version::parse(s).unwrap();
        assert_eq!(v("1.2.3+build-5").prerelease(), None);
        assert_eq!(v("1.2.3-rc.1+build-5").prerelease(), Some("rc.1"));
        assert_eq!(
            Bump::classify(&v("1.2.3"), &v("1.2.3+build-5")).kind,
            BumpKind::Same
        );
        assert_eq!(v("1.2.3"), v("1.2.3+build-5"));
        assert_eq!(v("1.2"), v("1.2.0"));
        assert_ne!(v("1.2.0"), v("1.2.0-rc.1"));
    }

    #[test]
    fn prerelease_moves_follow_semver_precedence() {
        let kind =
            |a, b| Bump::classify(&Version::parse(a).unwrap(), &Version::parse(b).unwrap()).kind;
        assert_eq!(kind("1.0.0-rc.1", "1.0.0-rc.2"), BumpKind::Prerelease);
        assert_eq!(kind("1.0.0-rc.2", "1.0.0-rc.1"), BumpKind::Downgrade);
        assert_eq!(kind("1.0.0-rc.9", "1.0.0-rc.10"), BumpKind::Prerelease);
        assert_eq!(kind("1.0.0-alpha", "1.0.0-beta"), BumpKind::Prerelease);
        assert_eq!(kind("1.0.0-alpha.1", "1.0.0-alpha"), BumpKind::Downgrade);
        assert_eq!(kind("1.0.0", "1.0.0-rc.1"), BumpKind::Downgrade);
        assert_eq!(kind("1.0.0-rc.1", "1.0.0"), BumpKind::Prerelease);
    }

    #[test]
    fn version_overrides_accept_a_v_prefix_and_reject_junk() {
        assert_eq!(
            Version::parse_override("--base-version", "v1.2.3")
                .unwrap()
                .raw,
            "1.2.3"
        );
        assert!(Version::parse_override("--base-version", "7").is_err());
        assert!(Version::parse_override("--base-version", "latest").is_err());
    }

    #[test]
    fn tolerance_tightens_for_smaller_bumps() {
        let b = |kind| Bump::new(kind, 1);
        assert_eq!(b(BumpKind::Patch).tolerance(), Severity::None);
        assert_eq!(b(BumpKind::Minor).tolerance(), Severity::Medium);
        assert_eq!(b(BumpKind::Major).tolerance(), Severity::High);
        // Two minor releases still don't license a High capability.
        assert_eq!(Bump::new(BumpKind::Minor, 2).tolerance(), Severity::Medium);
        // A same-version bump has no distance to report.
        assert_eq!(Bump::new(BumpKind::Same, 3).steps(), None);
    }
}
