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
use tempfile::TempDir;

use crate::analysis::{self, Analysis};
use crate::{Cli, Format};

/// Fetch two published versions of one artifact and judge the delta between
/// them, exactly as `fs` judges two local trees. `verb` names the surface
/// (`purl` / `oci`) in the report.
pub(crate) fn compare(verb: &'static str, old: &str, new: &str, cli: &Cli) -> Result<bool> {
    if cli.offline {
        anyhow::bail!("`isomer {verb}` fetches from a registry; not available under --offline");
    }
    // One temp dir holds both sides; it is removed when `dir` drops, after the
    // report is rendered.
    let dir = tempfile::tempdir().context("creating scratch dir for fetched artifacts")?;
    // Progress on the fetch only when a human is watching and reading the
    // terminal report — a piped or JSON run stays quiet.
    let progress =
        cli.format == Format::Terminal && std::io::IsTerminal::is_terminal(&std::io::stderr());
    let old_path = fetch_to(&dir, old, progress).with_context(|| format!("fetching base {old}"))?;
    let new_path = fetch_to(&dir, new, progress).with_context(|| format!("fetching head {new}"))?;

    let options = cleave::AnalysisOptions::default();
    let report = analysis::diff(&old_path, &new_path, &options)?;
    let mut a = Analysis::new(verb, &old_path, &new_path, &options, &report, cli)?;
    if cli.deps {
        a.deps = crate::deps::profiles(a.diff, &options, progress);
    }
    crate::write_stdout(&a.render(cli.format, cli)?)?;
    Ok(a.clean)
}

/// Fetch one PURL and write its bytes to a file under `dir`, named after the
/// payload so cleave detects the format and [`crate::version`] reads the version
/// token. Returns the written path.
pub(crate) fn fetch_to(dir: &TempDir, purl: &str, progress: bool) -> Result<PathBuf> {
    let (bytes, name) = fetch_bytes(purl, progress)?;
    let path = dir.path().join(scratch_name(&name, purl));
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

/// A safe scratch filename for a fetched payload: the payload's own basename
/// when the registry gave a clean one, else a name derived from the PURL. Never
/// a path — a fetched name is registry-influenced, so its directory components
/// are dropped so it can only land inside the scratch dir.
fn scratch_name(payload_name: &str, purl: &str) -> String {
    let base = Path::new(payload_name)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty() && n != "." && n != "..");
    base.unwrap_or_else(|| purl_basename(purl))
}

/// Normalize an `oci` argument to a PURL. A bare image reference
/// (`nginx:1.25`, `ghcr.io/owner/img:tag`) becomes `pkg:oci/<image>@<tag>`, the
/// registry riding along as a `repository_url` qualifier; an argument already
/// in `pkg:` form is passed through unchanged.
pub(crate) fn oci_purl(image: &str) -> String {
    let image = image.trim();
    if image.starts_with("pkg:") {
        return image.to_string();
    }
    let bare = image.strip_prefix("docker://").unwrap_or(image);
    // The tag opens only after the last `/` — otherwise the `:` is a registry
    // port (`localhost:5000/img`), not a tag.
    let (path, tag) = match bare.rsplit_once(':') {
        Some((path, tag)) if !tag.contains('/') => (path, tag),
        _ => (bare, "latest"),
    };
    match path.rsplit_once('/') {
        Some((registry, leaf)) => {
            format!(
                "pkg:oci/{}@{tag}?repository_url={}",
                leaf.to_ascii_lowercase(),
                registry.replace('/', "%2F")
            )
        }
        None => format!("pkg:oci/{}@{tag}", path.to_ascii_lowercase()),
    }
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
