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

use crate::Cli;
use crate::analysis::{self, Analysis};

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
    let progress = cli.progress();
    let old_path = fetch_to(&dir, old, progress).with_context(|| format!("fetching base {old}"))?;
    let new_path = fetch_to(&dir, new, progress).with_context(|| format!("fetching head {new}"))?;

    let options = cleave::AnalysisOptions::default();
    let report = analysis::diff(&old_path, &new_path, &options)?;
    let mut a = Analysis::new(verb, &old_path, &new_path, &options, &report, cli)?;
    a.finish(cli);
    crate::write_stdout(&a.render(cli.format, cli)?)?;
    Ok(a.clean)
}

/// Fetch one PURL and write its bytes to a file under `dir`, named after the
/// payload so cleave detects the format and [`crate::version`] reads the version
/// token. Returns the written path.
pub(crate) fn fetch_to(dir: &TempDir, purl: &str, progress: bool) -> Result<PathBuf> {
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
    let path = dir.path().join(base);
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
    // A digest pin (`nginx@sha256:…`) is the version, and its own `:` must not
    // be read as a tag separator — splitting there would yield `nginx@sha256`
    // and a stray digest. Digests bind after the name, so `@` wins over `:`.
    let (path, tag) = match bare.split_once('@') {
        Some((path, digest)) => (path, digest),
        // Otherwise the tag opens only after the last `/` — a `:` before that is
        // a registry port (`localhost:5000/img`), not a tag.
        None => match bare.rsplit_once(':') {
            Some((path, tag)) if !tag.contains('/') => (path, tag),
            _ => (bare, "latest"),
        },
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

#[cfg(test)]
mod tests {
    use super::oci_purl;

    /// A digest pin is how CI names a base image, and its own `:` must not be
    /// mistaken for a tag separator — nor a registry port for one.
    #[test]
    fn oci_references_normalize_to_purls() {
        assert_eq!(oci_purl("nginx:1.25"), "pkg:oci/nginx@1.25");
        assert_eq!(oci_purl("nginx"), "pkg:oci/nginx@latest");
        assert_eq!(
            oci_purl("nginx@sha256:abc123"),
            "pkg:oci/nginx@sha256:abc123"
        );
        assert_eq!(
            oci_purl("ghcr.io/owner/img:v2"),
            "pkg:oci/img@v2?repository_url=ghcr.io%2Fowner"
        );
        // The `:` here is a registry port, not a tag.
        assert_eq!(
            oci_purl("localhost:5000/img"),
            "pkg:oci/img@latest?repository_url=localhost:5000"
        );
        // An argument already in purl form is passed through untouched.
        assert_eq!(oci_purl("pkg:oci/img@1.0"), "pkg:oci/img@1.0");
    }
}
