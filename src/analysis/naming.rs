//! The artifact's name and versions, from the paths, the flags, and its own claims.

use std::path::Path;

use anyhow::Result;
use cleave::types::{DiffReportV1, FileDiffEntry};

use crate::member::MemberPath;
use crate::options::Options;
use crate::version::{Bump, Version};

/// Detected versions and the artifact name for the header, from the input
/// paths (or explicit `--base-version` / `--head-version`).
#[derive(Debug)]
pub(crate) struct Naming {
    pub name: String,
    pub old: Option<Version>,
    pub new: Option<Version>,
    pub bump: Option<Bump>,
}

impl Naming {
    pub(super) fn resolve(
        old: &Path,
        new: &Path,
        opts: &Options,
        diff: &DiffReportV1,
    ) -> Result<Self> {
        let ob = basename(old);
        let nb = basename(new);
        // The artifact's own claimed version, when the filename carries none.
        //
        // Two orderings matter here. The root entry describes the artifact
        // itself, so it is asked first — otherwise a vendored library's
        // `package.json` inside the package could name the *package's* version.
        // And an entry that parses both sides is preferred over one that parses
        // only one: a half-parsed claim leaves `bump` as `None`, which switches
        // off every release-pressure detector at once, so a later member that
        // could have answered must not be skipped.
        let claims = |want_both: bool| {
            let mut entries: Vec<&FileDiffEntry> = diff.files.iter().collect();
            entries.sort_by_key(|f| !MemberPath::new(&f.path).is_root());
            entries
                .into_iter()
                .filter_map(|file| file.identity.as_ref())
                .find_map(|identity| {
                    let claimed = |side: &Option<filefacts::Identity>| {
                        side.as_ref()
                            .and_then(|id| id.version.as_ref())
                            .and_then(|claim| Version::from_claim(&claim.value))
                    };
                    let (old, new) = (claimed(&identity.old), claimed(&identity.new));
                    let enough = if want_both {
                        old.is_some() && new.is_some()
                    } else {
                        old.is_some() || new.is_some()
                    };
                    enough.then_some((old, new))
                })
        };
        let (old_claim, new_claim) = claims(true)
            .or_else(|| claims(false))
            .unwrap_or((None, None));
        // An override the user typed must parse: silently falling back to the
        // filename would judge proportionality against a version they did not
        // mean.
        let overridden =
            |flag, value: Option<&str>| value.map(|v| Version::parse_override(flag, v)).transpose();
        let ov = overridden("--base-version", opts.base_version.as_deref())?
            .or_else(|| Version::detect(&ob))
            .or(old_claim);
        let nv = overridden("--head-version", opts.head_version.as_deref())?
            .or_else(|| Version::detect(&nb))
            .or(new_claim);
        let bump = match (&ov, &nv) {
            (Some(o), Some(n)) => Some(Bump::classify(o, n)),
            _ => None,
        };
        Ok(Self {
            name: artifact_name(&nb, &ob, nv.as_ref().or(ov.as_ref())),
            old: ov,
            new: nv,
            bump,
        })
    }
}

/// A path's final component, for naming a file in output. Falls back to the
/// whole path when there is no final component (`/`, or a path ending in `..`).
pub(crate) fn basename(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}

/// A display name: the new file's basename with the detected version token and
/// any archive extension stripped, separators tidied. Falls back to the old
/// basename when the new one empties out or is a content hash (quarantine
/// stores name samples by digest — `13ccd9….sample` is no name for a report).
pub(super) fn artifact_name(new_base: &str, old_base: &str, ver: Option<&Version>) -> String {
    let new_clean = clean_name(new_base, ver);
    let old_clean = clean_name(old_base, ver);
    // A filename is attacker-chosen — a pull request names its own files, and a
    // package names its own archive — and this lands in the masthead.
    crate::printable(
        if new_clean.is_empty()
            || (hexish(&new_clean) && !old_clean.is_empty() && !hexish(&old_clean))
        {
            &old_clean
        } else {
            &new_clean
        },
    )
}

/// A name that is just a hex digest (with or without an extension).
pub(super) fn hexish(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name);
    stem.len() >= 16 && stem.chars().all(|c| c.is_ascii_hexdigit())
}

pub(super) fn clean_name(base: &str, ver: Option<&Version>) -> String {
    let mut s = base.to_string();
    if let Some(v) = ver {
        s = s.replace(&v.raw, "");
        // Windows installers commonly encode dotted versions with
        // underscores. `Version::detect` normalizes those for display, so
        // remove the source spelling too when deriving the artifact name.
        s = s.replace(&v.raw.replace('.', "_"), "");
    }
    // A long leading digit run is a quarantine/timestamp prefix, not a name.
    if let Some((head, rest)) = s.split_once('-')
        && head.len() >= 8
        && head.bytes().all(|b| b.is_ascii_digit())
    {
        s = rest.to_string();
    }
    if let Some(stripped) = crate::version::strip_archive_suffix(&s) {
        s = stripped.to_string();
    }
    // Collapse separators left behind by removing the version token.
    while s.contains("..") {
        s = s.replace("..", ".");
    }
    while s.contains("--") {
        s = s.replace("--", "-");
    }
    while s.contains("_.") || s.contains("-.") {
        s = s.replace("_.", ".").replace("-.", ".");
    }
    s.trim_matches(['-', '.', '_', ' ']).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_archive_extension_leaves_the_name() {
        for base in [
            "foo-1.2.3.tar.gz",
            "foo-1.2.3.tar.bz2",
            "foo-1.2.3.tbz2",
            "foo-1.2.3.tar.zst",
            "foo-1.2.3.tar",
            "foo-1.2.3.whl",
        ] {
            let version = Version::detect(base);
            assert_eq!(clean_name(base, version.as_ref()), "foo", "{base}");
        }
    }
}
