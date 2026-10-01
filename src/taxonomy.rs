//! Trait ids — cleave's `root/path/…::local` taxonomy — read in one place.
//!
//! An id names what a trait *is* by its path (`micro-behaviors/process/create`)
//! and gives it an unstable local name after `::`. Everything isomer decides
//! from an id — its capability class, whether it is behavior or a signature,
//! whether it sits under a hierarchy a detector joins on — goes through
//! [`TraitId`] and [`under`]. Matching was once done three ways across the
//! code, and the substring one let `exec` match `executable`.

/// The taxonomy root a trait id lives under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Root {
    /// Structural facts about a file: `metadata/binary/linking/runtime`.
    Metadata,
    /// Behavior primitives: `micro-behaviors/process/create`.
    MicroBehaviors,
    /// Attacker objectives (MBC): `objectives/command-and-control`.
    Objectives,
    /// Library identity and known malware families.
    WellKnown,
    /// Third-party signature rules.
    ThirdParty,
    /// A root this build does not know — a new taxonomy branch.
    Other,
}

/// A trait id, `micro-behaviors/process/create::exec`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TraitId<'a>(&'a str);

impl<'a> TraitId<'a> {
    pub(crate) fn new(id: &'a str) -> Self {
        Self(id)
    }

    /// The taxonomy path before `::` — what the trait is, without its
    /// unstable local name.
    pub(crate) fn namespace(self) -> &'a str {
        self.0
            .split_once("::")
            .map_or(self.0, |(namespace, _)| namespace)
    }

    /// The local name after the last `::`, when there is one.
    pub(crate) fn leaf(self) -> Option<&'a str> {
        self.0.rsplit_once("::").map(|(_, leaf)| leaf)
    }

    pub(crate) fn root(self) -> Root {
        match self.namespace().split('/').next().unwrap_or_default() {
            "metadata" => Root::Metadata,
            "micro-behaviors" => Root::MicroBehaviors,
            "objectives" => Root::Objectives,
            "well-known" => Root::WellKnown,
            "third_party" => Root::ThirdParty,
            _ => Root::Other,
        }
    }

    /// The namespace below a known root: `metadata/binary/linking/runtime::ifunc`
    /// reads as `binary/linking/runtime`. An unknown root is kept, since it is
    /// the only thing saying where the trait came from.
    pub(crate) fn path(self) -> &'a str {
        let namespace = self.namespace();
        match (self.root(), namespace.split_once('/')) {
            (Root::Other, _) | (_, None) => namespace,
            (_, Some((_, rest))) => rest,
        }
    }

    /// Behavior a file exhibits — a primitive or an objective — as opposed to
    /// a structural fact, a library identity, or a signature.
    pub(crate) fn is_behavioral(self) -> bool {
        matches!(self.root(), Root::MicroBehaviors | Root::Objectives)
    }

    pub(crate) fn is_metadata(self) -> bool {
        self.root() == Root::Metadata
    }

    /// A known-bad detection: a third-party signature rule or a named malware
    /// family. A hit means "we recognize this", not "this behaves badly".
    pub(crate) fn is_signature(self) -> bool {
        self.root() == Root::ThirdParty || self.is_under("well-known/malware")
    }

    /// Whether the trait sits in `hierarchy` — at a path-segment boundary,
    /// never inside a segment or the local name.
    pub(crate) fn is_under(self, hierarchy: &str) -> bool {
        under(self.namespace(), hierarchy)
    }
}

/// Whether a `/`-separated taxonomy path — a namespace, or a capability class —
/// is `hierarchy` or lies below it. `process/create` is under `process`;
/// `process/created` is not under `process/create`. A class's `::leaf` is not
/// part of its path.
pub(crate) fn under(path: &str, hierarchy: &str) -> bool {
    let path = path.split_once("::").map_or(path, |(path, _)| path);
    path == hierarchy
        || path
            .strip_prefix(hierarchy)
            .is_some_and(|rest| rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_split_into_root_path_and_leaf() {
        let id = TraitId::new("metadata/binary/linking/runtime::ifunc");
        assert_eq!(id.root(), Root::Metadata);
        assert_eq!(id.namespace(), "metadata/binary/linking/runtime");
        assert_eq!(id.path(), "binary/linking/runtime");
        assert_eq!(id.leaf(), Some("ifunc"));
        assert!(id.is_metadata() && !id.is_behavioral());

        let other = TraitId::new("brand-new-root/x::y");
        assert_eq!(other.root(), Root::Other);
        assert_eq!(other.path(), "brand-new-root/x");
        assert_eq!(TraitId::new("third_party/elastic/XZ").leaf(), None);
    }

    #[test]
    fn hierarchy_matching_respects_segments() {
        let id = TraitId::new("micro-behaviors/process/create/exec::spawn");
        assert!(id.is_under("micro-behaviors/process"));
        assert!(id.is_under("micro-behaviors/process/create"));
        assert!(!id.is_under("micro-behaviors/proc"));
        assert!(!id.is_under("micro-behaviors/process/create/exec::spawn"));
        assert!(under("binary/linking/runtime::ifunc", "binary/linking"));
        assert!(!under("os/signals", "os/signal"));
    }

    #[test]
    fn signatures_are_known_entities_not_behavior_objectives() {
        assert!(TraitId::new("third_party/elastic/XZBackdoor").is_signature());
        assert!(
            TraitId::new("well-known/malware/trojan/pegglecrew::pegglecrew-mbr-wiper")
                .is_signature()
        );
        assert!(
            !TraitId::new(
                "objectives/supply-chain/trojanized/app/installer::unsigned-branded-mbr-wiper"
            )
            .is_signature()
        );
        assert!(!TraitId::new("well-known/lib/core/suncalc::x").is_signature());
    }
}
