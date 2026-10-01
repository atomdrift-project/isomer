//! Fetching a published artifact by package URL, for the verbs that compare two
//! *remote* versions (`purl`, `oci`) rather than two local trees.
//!
//! The fetch itself is fletch's, reached through scan's one-shot
//! [`scan::fetch::fetch_one`]: it resolves the PURL against the ecosystem's
//! registry, pulls the artifact, and returns the bytes. fletch's `SafeResolver`
//! refuses any host resolving to a private / loopback / link-local / metadata
//! address on every redirect hop, so a hostile registry redirect can't turn a
//! version comparison into an SSRF. We write each side to a scratch file under
//! one temp dir and hand the pair to the same pipeline `fs` uses — the judging
//! and rendering never learn the bytes came from a registry.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::Outcome;
use crate::analysis::{Comparison, Framing, Verb};
use crate::options::Options;

/// Fetch two published versions of a package and judge the delta between them,
/// exactly as `fs` judges two local trees.
pub fn purl(old: &str, new: &str, opts: &Options) -> Result<Outcome> {
    compare(Verb::Purl, old, new, opts)
}

/// Fetch two container images — references like `nginx:1.25`, or `pkg:oci`
/// purls — and judge the delta between them.
pub fn oci(old: &str, new: &str, opts: &Options) -> Result<Outcome> {
    compare(
        Verb::Oci,
        &crate::purl::oci(old)?,
        &crate::purl::oci(new)?,
        opts,
    )
}

fn compare(verb: Verb, old: &str, new: &str, opts: &Options) -> Result<Outcome> {
    if opts.offline {
        let name = match verb {
            Verb::Oci => "oci",
            _ => "purl",
        };
        anyhow::bail!("`isomer {name}` fetches from a registry; not available under --offline");
    }
    opts.validate()?;
    // One temp dir holds both sides, each in its own subdirectory: the file is
    // named by the registry, and two versions served under one basename (a
    // `…/download` URL) would otherwise overwrite each other and diff a file
    // against itself — which reads as clean. Removed when `dir` drops, after
    // the report is rendered.
    let dir = tempfile::tempdir().context("creating scratch dir for fetched artifacts")?;
    let progress = opts.progress;
    let old_path = fetch_to(&side(dir.path(), "old")?, old, progress)
        .with_context(|| format!("fetching base {old}"))?;
    let new_path = fetch_to(&side(dir.path(), "new")?, new, progress)
        .with_context(|| format!("fetching head {new}"))?;

    let comparison = Comparison::run(&old_path, &new_path)?;
    let a = comparison.judge(verb, &old_path, &new_path, opts, Framing::default())?;
    Ok(Outcome {
        report: a.render(opts.format)?,
        clean: a.clean(),
    })
}

/// A fresh subdirectory for one side of the comparison.
fn side(dir: &Path, name: &str) -> Result<PathBuf> {
    let path = dir.join(name);
    std::fs::create_dir(&path).with_context(|| format!("creating {}", path.display()))?;
    Ok(path)
}

/// Fetch one PURL and write its bytes to a file under `dir`, named after the
/// payload so cleave detects the format and [`crate::version`] reads the version
/// token. Returns the written path.
pub(crate) fn fetch_to(dir: &Path, purl: &str, progress: bool) -> Result<PathBuf> {
    let (bytes, name) = fetch_bytes(purl, progress)?;
    // The payload's own basename when the registry gave a clean one, else a name
    // derived from the PURL. Never a path — a fetched name is registry-
    // influenced, so its directory components are dropped and it can only land
    // inside the scratch dir.
    let base = Path::new(&name)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty() && n != "." && n != "..")
        .unwrap_or_else(|| purl_basename(purl));
    let path = dir.join(base);
    std::fs::write(&path, &bytes).with_context(|| format!("writing fetched {purl}"))?;
    Ok(path)
}

/// Fetch one PURL and return its bytes and the payload's registry name. The raw
/// fetch behind [`fetch_to`]; the dependency profiler analyzes the bytes in
/// memory rather than writing them to disk.
pub(crate) fn fetch_bytes(purl: &str, progress: bool) -> Result<(Vec<u8>, String)> {
    let locator = filefacts::RefLocator::Purl(purl.to_string());
    let (bytes, name, _record) = scan::fetch::fetch_one(locator, progress)?;
    Ok((bytes, name))
}

/// A filesystem-safe stem from a PURL when the payload carried no usable name —
/// `pkg:npm/left-pad@1.3.0` → `left-pad-1.3.0`. Keeps only name-safe characters
/// so nothing in an attacker-influenced PURL escapes the scratch dir.
fn purl_basename(purl: &str) -> String {
    let tail = purl.rsplit('/').next().unwrap_or(purl).replace('@', "-");
    let cleaned: String = tail
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '-'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "artifact".to_string()
    } else {
        cleaned
    }
}
