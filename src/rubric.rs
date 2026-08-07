//! The v0 rubric — a transparent stand-in for the Valence model.
//!
//! It judges a cleave diff on three independent axes; the verdict is the worst
//! of them:
//!
//! - **behavioral** — capability-drift risk keyed on the trait *namespace*,
//!   independent of criticality. A compression library that gains an `ifunc`
//!   resolver trips here with no signature — the axis that would have caught
//!   xz-utils (CVE-2024-3094) on release day. Grouped into human categories
//!   (execution-hijack, network, obfuscation, …).
//! - **signature** — cleave criticality of gained known-bad traits
//!   (`third_party/*` YARA hits, malware/hidden-payload objectives). Catches
//!   *known* attacks; summarized as a count plus any referenced CVE.
//! - **identity** — a drifted signer/publisher forces at least High on its own.
//!
//! Known-bad signature ids carry no capability segments, so the behavioral axis
//! is automatically independent of the signature axis. Proportionality
//! (drift vs. version bump) is applied by the caller with [`crate::version`].

use std::collections::HashMap;

use cleave::Criticality;
use cleave::types::{DiffReportV1, FileDiffEntry, TraitChange};

use crate::Severity;

/// The full rubric outcome.
#[derive(Debug)]
pub(crate) struct Assessment {
    pub severity: Severity,
    pub behavioral: Behavioral,
    pub signature: Signature,
    pub identity: Identity,
}

/// Behavioral capability drift, grouped by capability category.
#[derive(Debug)]
pub(crate) struct Behavioral {
    pub severity: Severity,
    /// Categories, worst severity first (then most-populous first).
    pub categories: Vec<Category>,
}

impl Behavioral {
    /// Total distinct capability traits gained across all categories.
    pub(crate) fn total(&self) -> usize {
        self.categories.iter().map(|c| c.ids.len()).sum()
    }
}

/// One capability category (e.g. `execution-hijack`) and the traits under it.
#[derive(Debug)]
pub(crate) struct Category {
    pub severity: Severity,
    /// Short kebab label, e.g. `execution-hijack`.
    pub class: &'static str,
    /// Human phrase, e.g. `gained an ifunc resolver`.
    pub phrase: &'static str,
    /// Full hierarchical trait ids, sorted and de-duplicated (for `--explain`).
    pub ids: Vec<String>,
}

impl Assessment {
    /// Every gained trait id the rubric judged (behavioral categories plus
    /// signature hits), for evidence rendering.
    pub(crate) fn gained_ids(&self) -> std::collections::HashSet<String> {
        let mut ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        for c in &self.behavioral.categories {
            ids.extend(c.ids.iter().cloned());
        }
        ids.extend(self.signature.ids.iter().map(|(_, id)| id.clone()));
        ids
    }
}

/// Known-bad signature matches.
#[derive(Debug)]
pub(crate) struct Signature {
    pub severity: Severity,
    /// A CVE referenced by any matched rule, if present.
    pub cve: Option<String>,
    /// `(severity, full-id)` pairs, worst first (for count and `--explain`).
    pub ids: Vec<(Severity, String)>,
}

/// Signer / publisher drift.
#[derive(Debug)]
pub(crate) struct Identity {
    pub severity: Severity,
    /// How many files drifted identity.
    pub files: usize,
}

/// Judge a whole diff report.
pub(crate) fn assess(diff: &DiffReportV1) -> Assessment {
    let mut groups: HashMap<&'static str, Category> = HashMap::new();
    let mut sig_ids: Vec<(Severity, String)> = Vec::new();
    let mut cve: Option<String> = None;
    let mut identity_files = 0usize;

    for file in &diff.files {
        if file.identity.as_ref().is_some_and(|i| i.changed) {
            identity_files += 1;
        }
        for tc in gained_traits(file) {
            if is_signature(&tc.id) {
                let sev = severity_from_crit(tc.crit);
                if sev != Severity::None {
                    sig_ids.push((sev, tc.id.clone()));
                    if cve.is_none() {
                        cve = extract_cve(&tc.id);
                    }
                }
            } else if let Some((sev, class, phrase)) = capability_risk(&tc.id) {
                let entry = groups.entry(class).or_insert(Category {
                    severity: sev,
                    class,
                    phrase,
                    ids: Vec::new(),
                });
                entry.severity = entry.severity.max(sev);
                entry.ids.push(tc.id.clone());
            }
        }
    }

    let mut categories: Vec<Category> = groups.into_values().collect();
    for c in &mut categories {
        c.ids.sort();
        c.ids.dedup();
    }
    // Worst severity first, then the busiest category, then stable by label.
    categories.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.ids.len().cmp(&a.ids.len()))
            .then(a.class.cmp(b.class))
    });

    sig_ids.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    sig_ids.dedup();

    let behavioral_sev = categories
        .iter()
        .map(|c| c.severity)
        .max()
        .unwrap_or(Severity::None);
    let signature_sev = sig_ids.iter().map(|s| s.0).max().unwrap_or(Severity::None);
    let identity_sev = if identity_files > 0 {
        Severity::High
    } else {
        Severity::None
    };

    Assessment {
        severity: behavioral_sev.max(signature_sev).max(identity_sev),
        behavioral: Behavioral {
            severity: behavioral_sev,
            categories,
        },
        signature: Signature {
            severity: signature_sev,
            cve,
            ids: sig_ids,
        },
        identity: Identity {
            severity: identity_sev,
            files: identity_files,
        },
    }
}

/// Traits newly present or promoted to a higher criticality on the new side.
/// Removals and demotions are security *improvements* and are not judged.
fn gained_traits(file: &FileDiffEntry) -> impl Iterator<Item = &TraitChange> {
    let traits = file.scopes.traits.as_ref();
    let added = traits.into_iter().flat_map(|t| t.added.iter());
    let promoted = traits.into_iter().flat_map(|t| {
        t.changed
            .iter()
            .filter(|c| crit_rank(c.new.crit) > crit_rank(c.old.crit))
            .map(|c| &c.new)
    });
    added.chain(promoted)
}

/// Known-bad detection namespaces. A hit means "we recognize this", not "this
/// behaves badly" — that's the behavioral axis's job.
fn is_signature(id: &str) -> bool {
    id.starts_with("third_party/")
        || id.contains("malware/")
        || id.contains("hidden-payload")
        || id.contains("trojanized")
}

fn severity_from_crit(crit: Criticality) -> Severity {
    match crit {
        Criticality::Hostile => Severity::Critical,
        Criticality::Suspicious => Severity::High,
        Criticality::Notable => Severity::Medium,
        _ => Severity::None,
    }
}

fn crit_rank(c: Criticality) -> u8 {
    match c {
        Criticality::Hostile => 5,
        Criticality::Suspicious => 4,
        Criticality::Notable => 3,
        Criticality::Baseline => 2,
        Criticality::Component => 1,
        Criticality::Exception | Criticality::Filtered => 0,
    }
}

/// Capability-drift risk of a gained trait, keyed on segments of its taxonomy
/// path rather than its assigned criticality. Returns `(severity, class label,
/// human phrase)`. The table is ordered by descending severity; the first
/// matching segment wins.
///
/// These fire regardless of how cleave graded the trait, so a *novel* attack —
/// one no signature covers — still lights up the moment it introduces an
/// execution-hijack primitive, network egress, or obfuscation into an artifact
/// that had none.
fn capability_risk(id: &str) -> Option<(Severity, &'static str, &'static str)> {
    const TABLE: &[(&str, Severity, &str, &str)] = &[
        // Critical — the attacker objective is explicit in the taxonomy.
        ("command-and-control", Severity::Critical, "C2", "gained C2 signaling"),
        ("exfiltration", Severity::Critical, "exfiltration", "gained data exfiltration"),
        ("impact/", Severity::Critical, "destructive-impact", "gained destructive impact"),
        // High — primitives that grant code execution or egress. `ifunc` is the
        // resolver-hijack mechanism the xz backdoor used.
        ("linking/runtime::ifunc", Severity::High, "execution-hijack", "gained an ifunc resolver"),
        ("process/create", Severity::High, "process-execution", "gained process execution"),
        ("child-process", Severity::High, "process-execution", "gained process execution"),
        ("process/inject", Severity::High, "process-injection", "gained process injection"),
        ("communications/", Severity::High, "network", "gained network access"),
        ("credential-access", Severity::High, "credential-access", "gained credential access"),
        ("install-hook", Severity::High, "install-hook", "gained an install hook"),
        // Medium — enablers: new runtime linkage, obfuscation, hidden data,
        // host reconnaissance. Individually noisy, collectively damning.
        ("linking/runtime", Severity::Medium, "runtime-linkage", "new runtime linkage"),
        ("obfuscation", Severity::Medium, "obfuscation", "gained obfuscation"),
        ("encode/xor", Severity::Medium, "xor-encoding", "gained xor-encoded data"),
        ("decode/base64", Severity::Medium, "base64", "gained base64 decoding"),
        ("string/assembly", Severity::Medium, "hidden-byte-strings", "gained hidden byte strings"),
        ("discovery/system", Severity::Medium, "host-recon", "gained host reconnaissance"),
        ("fingerprint", Severity::Medium, "host-recon", "gained host reconnaissance"),
    ];
    TABLE
        .iter()
        .find(|(seg, _, _, _)| id.contains(seg))
        .map(|&(_, sev, class, phrase)| (sev, class, phrase))
}

/// Pull a `CVE-YYYY-NNNN` out of a trait id that references one in either
/// `CVE/2024/3094` (path) or `CVE-2024-3094` form.
fn extract_cve(id: &str) -> Option<String> {
    let pos = id.find("CVE")?;
    let sep: &[char] = &['/', '-', '_'];
    let mut parts = id[pos + 3..]
        .split(|c| sep.contains(&c))
        .filter(|s| !s.is_empty());
    let year = parts.next()?;
    let num = parts.next()?;
    let ok = year.len() == 4
        && year.bytes().all(|b| b.is_ascii_digit())
        && !num.is_empty()
        && num.bytes().all(|b| b.is_ascii_digit());
    ok.then(|| format!("CVE-{year}-{num}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifunc_is_high_execution_hijack() {
        let (sev, class, _) =
            capability_risk("metadata/binary/linking/runtime::ifunc").unwrap();
        assert_eq!(sev, Severity::High);
        assert_eq!(class, "execution-hijack");
    }

    #[test]
    fn plain_loader_dep_is_medium_runtime_linkage() {
        let (sev, class, _) =
            capability_risk("metadata/binary/linking/runtime::library-loader-dep").unwrap();
        assert_eq!(sev, Severity::Medium);
        assert_eq!(class, "runtime-linkage");
    }

    #[test]
    fn signature_ids_carry_no_capability() {
        assert!(capability_risk("third_party/elastic/Linux_Trojan_XZBackdoor").is_none());
        assert!(is_signature("third_party/elastic/Linux_Trojan_XZBackdoor"));
    }

    #[test]
    fn cve_extracted_from_path_form() {
        assert_eq!(
            extract_cve("third_party/SigBase/BKDR/Xzutil/Binary/CVE/2024/3094/Mar24").as_deref(),
            Some("CVE-2024-3094")
        );
        assert_eq!(extract_cve("third_party/elastic/whatever"), None);
    }
}
