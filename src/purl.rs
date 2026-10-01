//! Package URLs: the ecosystems isomer resolves dependencies in, and the one
//! way it spells a coordinate.
//!
//! Every purl isomer builds goes through fletch's canonical encoder. Formatting
//! them by hand once spelled the same scoped npm package two ways — with `@`
//! and with `%40` — on the two sides of a registry comparison, so one package
//! read as two.

use anyhow::{Result, anyhow};
use fletch::purl::{Purl, PurlComponents};

/// A package ecosystem a manifest declares runtime dependencies in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Ecosystem {
    Npm,
    Pypi,
    Cargo,
    Gem,
    Composer,
}

impl Ecosystem {
    /// The ecosystem a manifest or lockfile declares dependencies in, by its
    /// file name. `None` for a file that declares no fetchable runtime
    /// dependencies.
    pub(crate) fn of_manifest(file_name: &str) -> Option<Self> {
        match file_name {
            "package.json" | "package-lock.json" => Some(Self::Npm),
            "pyproject.toml" | "requirements.txt" | "poetry.lock" | "Pipfile.lock" => {
                Some(Self::Pypi)
            }
            "Cargo.toml" | "Cargo.lock" => Some(Self::Cargo),
            "Gemfile.lock" => Some(Self::Gem),
            "composer.json" | "composer.lock" => Some(Self::Composer),
            _ => None,
        }
    }

    /// The purl `type` for this ecosystem.
    pub(crate) fn purl_type(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pypi => "pypi",
            Self::Cargo => "cargo",
            Self::Gem => "gem",
            Self::Composer => "composer",
        }
    }
}

/// The canonical purl for a package as a manifest names it — `@scope/name` or
/// `vendor/name`, whose leading segments are the purl namespace — at an exact
/// `version`, or versionless.
pub(crate) fn package(ecosystem: Ecosystem, name: &str, version: Option<&str>) -> Result<String> {
    let (namespace, leaf) = match name.rsplit_once('/') {
        Some((namespace, leaf)) => (namespace.split('/').map(str::to_owned).collect(), leaf),
        None => (Vec::new(), name),
    };
    build(PurlComponents {
        typ: ecosystem.purl_type().to_owned(),
        namespace,
        name: leaf.to_owned(),
        version: version.map(str::to_owned),
        qualifiers: Default::default(),
        subpath: Vec::new(),
    })
}

/// Normalize an `oci` argument to a purl. A bare image reference
/// (`nginx:1.25`, `ghcr.io/owner/img:tag`) becomes `pkg:oci/<image>@<tag>`, the
/// registry riding along as a `repository_url` qualifier; an argument already
/// in `pkg:` form is passed through unchanged.
pub(crate) fn oci(image: &str) -> Result<String> {
    let image = image.trim();
    if image.starts_with("pkg:") {
        return Ok(image.to_owned());
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
    let (registry, leaf) = match path.rsplit_once('/') {
        Some((registry, leaf)) => (Some(registry), leaf),
        None => (None, path),
    };
    build(PurlComponents {
        typ: "oci".to_owned(),
        namespace: Vec::new(),
        name: leaf.to_ascii_lowercase(),
        version: Some(tag.to_owned()),
        qualifiers: registry
            .map(|r| ("repository_url".to_owned(), r.to_owned()))
            .into_iter()
            .collect(),
        subpath: Vec::new(),
    })
}

fn build(components: PurlComponents) -> Result<String> {
    let shown = format!("{}/{}", components.typ, components.name);
    Purl::from_components(components)
        .map(|purl| purl.canonical())
        .map_err(|e| {
            anyhow!(
                "cannot form a package URL for {}: {e}",
                crate::printable(&shown)
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A digest pin is how CI names a base image, and its own `:` must not be
    /// mistaken for a tag separator — nor a registry port for one.
    #[test]
    fn oci_references_normalize_to_purls() {
        let p = |s| oci(s).unwrap();
        assert_eq!(p("nginx:1.25"), "pkg:oci/nginx@1.25");
        assert_eq!(p("nginx"), "pkg:oci/nginx@latest");
        assert_eq!(p("nginx@sha256:abc123"), "pkg:oci/nginx@sha256:abc123");
        assert_eq!(
            p("ghcr.io/owner/img:v2"),
            "pkg:oci/img@v2?repository_url=ghcr.io%2Fowner"
        );
        // The `:` here is a registry port, not a tag.
        assert_eq!(
            p("localhost:5000/img"),
            "pkg:oci/img@latest?repository_url=localhost:5000"
        );
        // An argument already in purl form is passed through untouched.
        assert_eq!(p("pkg:oci/img@1.0"), "pkg:oci/img@1.0");
    }

    /// A scoped npm name is spelled one way whichever side built it.
    #[test]
    fn scoped_names_encode_their_namespace() {
        assert_eq!(
            package(Ecosystem::Npm, "@scope/pkg", Some("1.0.0")).unwrap(),
            "pkg:npm/%40scope/pkg@1.0.0"
        );
        assert_eq!(
            package(Ecosystem::Npm, "left-pad", None).unwrap(),
            "pkg:npm/left-pad"
        );
        assert_eq!(
            package(Ecosystem::Composer, "vendor/pkg", Some("1.0")).unwrap(),
            "pkg:composer/vendor/pkg@1.0"
        );
    }

    #[test]
    fn manifests_name_their_ecosystem() {
        assert_eq!(Ecosystem::of_manifest("package.json"), Some(Ecosystem::Npm));
        assert_eq!(Ecosystem::of_manifest("Cargo.lock"), Some(Ecosystem::Cargo));
        assert_eq!(Ecosystem::of_manifest("mypackage.json"), None);
    }
}
