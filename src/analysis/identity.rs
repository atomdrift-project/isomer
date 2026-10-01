//! Identity claims as context: what each side says it is, apart from the verdict.

use std::collections::BTreeMap;

use cleave::types::FileDiffEntry;

use crate::member::MemberPath;

use super::{Analysis, shown_member_path};

/// The identity a changed file carries, unless it is filename-only. A name
/// merely derived from the path is not a publisher claim, and reading it as one
/// would turn every rename into identity drift.
pub(super) fn meaningful_identity(file: &FileDiffEntry) -> Option<&cleave::types::IdentityDiff> {
    let identity = file.identity.as_ref()?;
    let filename_only = |side: &Option<filefacts::Identity>| {
        side.as_ref()
            .is_some_and(crate::rubric::filename_only_identity)
    };
    (!filename_only(&identity.old) && !filename_only(&identity.new)).then_some(identity)
}

/// Root claims first, then members alphabetically, capped at `cap` — a large
/// package must not drown out the artifact's own identity.
pub(super) fn ranked(mut entries: Vec<(usize, String)>, cap: usize) -> Vec<String> {
    entries.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    entries.truncate(cap);
    entries.into_iter().map(|(_, text)| text).collect()
}

/// Every identity claim an artifact carries, in a fixed field order, each value
/// tagged with how it was established — `verified` when a signature backs it,
/// `claimed` when only the metadata asserts it. The signer's own name rides
/// along with the trust verdict; an unsigned-but-trusted artifact reports the
/// verdict alone.
///
/// `include_version` is the only axis of variation between the two readings
/// below: a version bump is not identity drift, so the field-level diff drops
/// it, while the LLM payload — which describes an artifact rather than
/// comparing two — keeps it.
pub(super) fn identity_claim_list(
    identity: &filefacts::Identity,
    include_version: bool,
) -> Vec<(&'static str, String)> {
    let mut claims = Vec::new();
    let mut add = |label: &'static str, claim: Option<&filefacts::Claim>| {
        let Some(claim) = claim else {
            return;
        };
        let value = crate::printable(&claim.value);
        if value.is_empty() {
            return;
        }
        let provenance = if claim.verified {
            "verified"
        } else {
            "claimed"
        };
        claims.push((label, format!("{value} [{provenance}]")));
    };
    add("name", identity.name.as_ref());
    add("title", identity.title.as_ref());
    add("project", identity.project.as_ref());
    add("identifier", identity.identifier.as_ref());
    if include_version {
        add("version", identity.version.as_ref());
    }
    add("organization", identity.organization.as_ref());
    add("producer", identity.producer.as_ref());
    add("team", identity.team_id.as_ref());
    if let Some(signer) = &identity.signer {
        let signer_name = signer
            .organization
            .as_deref()
            .or(signer.common_name.as_deref())
            .unwrap_or_default();
        if !signer_name.is_empty() {
            claims.push((
                "signer",
                format!(
                    "{} [parsed, {}]",
                    crate::printable(signer_name),
                    trust_label(identity.trust)
                ),
            ));
        }
    } else if identity.trust != filefacts::Trust::Unsigned {
        claims.push(("trust", trust_label(identity.trust)));
    }
    claims
}

/// The claims as `field=value [provenance]` lines, for the LLM payload.
pub(super) fn identity_claims(identity: &filefacts::Identity) -> Vec<String> {
    identity_claim_list(identity, true)
        .into_iter()
        .map(|(label, value)| format!("{label}={value}"))
        .collect()
}

/// The claims keyed by field, for a field-level terminal diff. Values retain
/// their trust marker so a claim becoming verified (or losing verification) is
/// visible even when its text did not change.
pub(super) fn identity_claim_fields(
    identity: &filefacts::Identity,
    include_version: bool,
) -> BTreeMap<&'static str, String> {
    identity_claim_list(identity, include_version)
        .into_iter()
        .collect()
}

pub(super) fn changed_identity_claims(
    path: &str,
    old: &BTreeMap<&'static str, String>,
    new: &BTreeMap<&'static str, String>,
) -> Vec<String> {
    let fields: std::collections::BTreeSet<&'static str> =
        old.keys().chain(new.keys()).copied().collect();
    fields
        .into_iter()
        .filter_map(|field| match (old.get(field), new.get(field)) {
            (Some(old), Some(new)) if old != new => {
                Some(format!("{path}: ~ {field} {old} → {new}"))
            }
            (Some(old), None) => Some(format!("{path}: − {field} {old}")),
            (None, Some(new)) => Some(format!("{path}: + {field} {new}")),
            _ => None,
        })
        .collect()
}

pub(super) fn trust_label(trust: filefacts::Trust) -> String {
    format!("{trust:?}").to_ascii_lowercase()
}

impl Analysis<'_> {
    /// Parsed identity claims are useful context, but deliberately remain
    /// separate from the verdict. The diff carries normalized filefacts
    /// identity on each changed member; show the root claim first and only a
    /// few member claims so a large package cannot drown out behavior.
    pub(crate) fn identity_summary(&self) -> Vec<String> {
        let mut entries: Vec<(usize, String)> = Vec::new();
        for file in &self.judged_diff.files {
            let Some(identity) = meaningful_identity(file) else {
                continue;
            };
            let old = identity
                .old
                .as_ref()
                .map(identity_claims)
                .unwrap_or_default();
            let new = identity
                .new
                .as_ref()
                .map(identity_claims)
                .unwrap_or_default();
            if old.is_empty() && new.is_empty() {
                continue;
            }
            let side = |label: &str, claims: &[String]| {
                if claims.is_empty() {
                    return String::new();
                }
                format!("{label} {}", claims.join(", "))
            };
            let mut text = format!("{}: ", shown_member_path(&file.path));
            let old_text = side("old", &old);
            let new_text = side("new", &new);
            if !old_text.is_empty() {
                text.push_str(&old_text);
            }
            if !old_text.is_empty() && !new_text.is_empty() {
                text.push_str(" -> ");
            }
            if !new_text.is_empty() {
                text.push_str(&new_text);
            }
            // The root describes the artifact; member claims provide useful
            // attribution (e.g. a library inside a package) but rank behind it.
            entries.push((usize::from(!MemberPath::new(&file.path).is_root()), text));
        }
        ranked(entries, 6)
    }

    /// Identity claims that actually changed, for the compact terminal view.
    /// The masthead already names the root artifact and version, so repeating
    /// an unchanged `name`, `identifier`, and `version` block adds no context.
    /// Member versions remain eligible because they are not represented there.
    pub(crate) fn identity_change_summary(&self) -> Vec<String> {
        let mut entries: Vec<(usize, String)> = Vec::new();
        for file in &self.judged_diff.files {
            let Some(identity) = meaningful_identity(file) else {
                continue;
            };
            let include_version = !MemberPath::new(&file.path).is_root();
            let old = identity
                .old
                .as_ref()
                .map(|id| identity_claim_fields(id, include_version))
                .unwrap_or_default();
            let new = identity
                .new
                .as_ref()
                .map(|id| identity_claim_fields(id, include_version))
                .unwrap_or_default();
            let priority = usize::from(!MemberPath::new(&file.path).is_root());
            entries.extend(
                changed_identity_claims(&shown_member_path(&file.path), &old, &new)
                    .into_iter()
                    .map(|line| (priority, line)),
            );
        }
        ranked(entries, 8)
    }
}
