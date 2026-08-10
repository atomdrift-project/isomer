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
    pub structure: Structure,
    /// Findings withheld by `.isomer.toml`, deduplicated. Reported so a
    /// suppressed run never looks the same as a clean one.
    pub suppressed: Vec<crate::policy::Suppressed>,
}

/// Behavioral capability drift, grouped by *capability class* (execution-hijack,
/// network, C2, obfuscation, …). Class grouping is the right granularity for the
/// new-vs-existing question: a taxonomy segment like `binary` is present in
/// every ELF, but the *class* `execution-hijack` (the ifunc) is genuinely new.
#[derive(Debug)]
pub(crate) struct Behavioral {
    pub severity: Severity,
    /// Capability classes, worst severity first (then most new traits first).
    pub categories: Vec<Category>,
    /// Capability classes that had *no* trait in the base version — a wholly
    /// new kind of behavior, the strongest differential signal.
    pub new_categories: std::collections::HashSet<String>,
}

impl Behavioral {
    /// True when this category's class is absent from the base.
    pub(crate) fn is_new_category(&self, c: &Category) -> bool {
        self.new_categories.contains(&c.class)
    }
}

/// One capability class (e.g. `execution-hijack`) and the traits under it that
/// the diff surfaced, along with the namespaces they live in.
#[derive(Debug)]
pub(crate) struct Category {
    pub severity: Severity,
    /// Kebab class key, e.g. `execution-hijack`.
    pub class: String,
    /// Human label, e.g. `execution hijack`.
    pub label: String,
    /// Distinct trait namespaces under this class, e.g. `binary/linking/runtime`.
    pub namespaces: Vec<String>,
    /// Full ids of traits that are genuinely new (absent on the old side).
    pub new_ids: Vec<String>,
    /// Full ids of traits that existed before and were escalated in criticality.
    pub escalated_ids: Vec<String>,
}

impl Assessment {
    /// Every gained trait id the rubric judged (behavioral plus signature),
    /// for evidence rendering.
    pub(crate) fn gained_ids(&self) -> std::collections::HashSet<String> {
        let mut ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        for c in &self.behavioral.categories {
            ids.extend(c.new_ids.iter().cloned());
            ids.extend(c.escalated_ids.iter().cloned());
        }
        ids.extend(self.signature.ids.iter().map(|m| m.id.clone()));
        ids
    }

    /// Severity considering only *newly-introduced* risk — categories with new
    /// traits, newly-matched signatures, and identity drift (a signer change is
    /// inherently new). This is what a CI gate keyed on new issues (rather than
    /// re-litigating pre-existing ones) uses.
    pub(crate) fn new_severity(&self) -> Severity {
        let behavioral = self
            .behavioral
            .categories
            .iter()
            .filter(|c| !c.new_ids.is_empty())
            .map(|c| c.severity)
            .max()
            .unwrap_or(Severity::None);
        let signature = self
            .signature
            .ids
            .iter()
            .filter(|m| m.is_new)
            .map(|m| m.severity)
            .max()
            .unwrap_or(Severity::None);
        // Structural facts are all added kv entries — inherently new.
        behavioral
            .max(signature)
            .max(self.identity.severity)
            .max(self.structure.severity)
    }
}

/// Known-bad signature matches.
#[derive(Debug)]
pub(crate) struct Signature {
    pub severity: Severity,
    /// A CVE referenced by any matched rule, if present.
    pub cve: Option<String>,
    /// Matched rules, worst first.
    pub ids: Vec<SigMatch>,
}

/// One matched known-bad rule.
#[derive(Debug)]
pub(crate) struct SigMatch {
    pub severity: Severity,
    /// Full trait id of the matched rule.
    pub id: String,
    /// The rule's human description — the campaign or intent an analyst
    /// triages on. May be empty when the rule carries none.
    pub desc: String,
    /// True when the rule was absent on the old side (vs escalated).
    pub is_new: bool,
}

/// Signer / publisher drift — the *meaningful* fields only (version is
/// excluded; a version bump is not a publisher change).
#[derive(Debug)]
pub(crate) struct Identity {
    pub severity: Severity,
    /// Field-level changes, e.g. `("signer", "Apple Dev X", "unsigned")`.
    pub changes: Vec<IdentityChange>,
}

/// One identity field that changed old → new.
#[derive(Debug)]
pub(crate) struct IdentityChange {
    pub label: &'static str,
    pub old: String,
    pub new: String,
}

/// Structural anomalies read from the binary's kv scope — a new linked
/// dependency, functions turned into ifunc resolvers, new imports. These are
/// raw ELF/Mach-O/PE facts, not rule matches, so they catch an xz-class attack
/// even with no trait or signature firing.
#[derive(Debug)]
pub(crate) struct Structure {
    pub severity: Severity,
    pub facts: Vec<StructFact>,
}

impl Structure {
    /// Whether the change introduced external third-party code — a new runtime
    /// dependency or a new/moved GitHub Action. These supply-chain events are
    /// always worth surfacing, even below the gate threshold.
    pub(crate) fn adds_external_code(&self) -> bool {
        self.facts
            .iter()
            .any(|f| matches!(f.label, "dependency" | "github action"))
    }
}

/// How a structural fact came to be, so the display can mark newly-present
/// structure (`+`) apart from existing structure altered in place (`~`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FactKind {
    /// Absent in the base version.
    Added,
    /// Existed before but changed state (e.g. a section became RWX).
    Became,
}

/// One structural fact, e.g. `("loader dependency", "ld-linux-x86-64.so.2")`.
#[derive(Debug)]
pub(crate) struct StructFact {
    pub severity: Severity,
    pub kind: FactKind,
    pub label: &'static str,
    pub detail: String,
}

/// Judge a whole diff report. `base_classes` is the set of capability classes
/// present in the *old* version, used to tell a wholly new capability class
/// from one that merely gained a trait. `policy` withholds findings the repo
/// has reviewed and accepted.
pub(crate) fn assess(
    diff: &DiffReportV1,
    base_classes: &std::collections::HashSet<String>,
    policy: &crate::policy::Policy,
) -> Assessment {
    let mut groups: HashMap<&'static str, Category> = HashMap::new();
    let mut sig_ids: Vec<SigMatch> = Vec::new();
    let mut cve: Option<String> = None;
    let mut identity_changes: Vec<IdentityChange> = Vec::new();
    let mut suppressed: Vec<crate::policy::Suppressed> = Vec::new();

    for file in &diff.files {
        if policy.excludes(&file.path) {
            continue;
        }
        // Identity *drift* needs a previous identity to drift from. A file the
        // change adds has none, so cleave reports `absent → <author>` — true,
        // but not a publisher change: committing a first `package.json` would
        // otherwise read as a takeover.
        if let Some(idd) = file
            .identity
            .as_ref()
            .filter(|i| i.changed)
            .filter(|_| !matches!(file.status, cleave::types::FileStatus::Added))
        {
            let changes = meaningful_identity_changes(idd.old.as_ref(), idd.new.as_ref());
            match policy.allows(IDENTITY_ID, &file.path) {
                Some(s) => suppressed.extend(changes.iter().map(|_| s.clone())),
                None => identity_changes.extend(changes),
            }
        }
        for (is_new, tc) in gained_traits(file) {
            if let Some(s) = policy.allows(&tc.id, &file.path) {
                suppressed.push(s);
                continue;
            }
            // Component atoms are the building blocks composites are assembled
            // from, not findings: `arithmetic-sub-density` exists so that
            // `js-arithmetic-array-init` can require density *and* volume
            // together. Judging an atom on its own reports the ingredient as
            // the dish — a two-line file with one subtraction reads as gained
            // obfuscation. Exceptions and filtered traits are negations and
            // were never findings either.
            if !is_finding(tc.crit) {
                continue;
            }
            if is_signature(&tc.id) {
                let sev = severity_from_crit(tc.crit);
                if sev != Severity::None {
                    sig_ids.push(SigMatch {
                        severity: sev,
                        id: tc.id.clone(),
                        desc: tc.desc.clone(),
                        is_new,
                    });
                    if cve.is_none() {
                        cve = extract_cve(&tc.id);
                    }
                }
            } else if let Some((sev, class, _phrase)) = capability_risk(&tc.id) {
                let entry = groups.entry(class).or_insert_with(|| Category {
                    severity: sev,
                    class: class.to_string(),
                    label: humanize(class),
                    namespaces: Vec::new(),
                    new_ids: Vec::new(),
                    escalated_ids: Vec::new(),
                });
                entry.severity = entry.severity.max(sev);
                entry.namespaces.push(namespace_of(&tc.id));
                if is_new {
                    entry.new_ids.push(tc.id.clone());
                } else {
                    entry.escalated_ids.push(tc.id.clone());
                }
            }
        }
    }

    let mut categories: Vec<Category> = groups.into_values().collect();
    for c in &mut categories {
        c.namespaces.sort();
        c.namespaces.dedup();
        c.new_ids.sort();
        c.new_ids.dedup();
        c.escalated_ids.sort();
        c.escalated_ids.dedup();
    }
    // Worst severity first, then the most new traits, then stable by class.
    categories.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.new_ids.len().cmp(&a.new_ids.len()))
            .then(a.class.cmp(&b.class))
    });

    // One entry per rule with its worst criticality kept, then worst first.
    sig_ids.sort_by(|a, b| a.id.cmp(&b.id).then(b.severity.cmp(&a.severity)));
    sig_ids.dedup_by(|a, b| a.id == b.id);
    sig_ids.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(&b.id)));

    // A class is new when the base version carried no trait of it.
    let new_categories: std::collections::HashSet<String> = categories
        .iter()
        .map(|c| c.class.clone())
        .filter(|c| !base_classes.contains(c))
        .collect();

    let behavioral_sev = categories
        .iter()
        .map(|c| c.severity)
        .max()
        .unwrap_or(Severity::None);
    let signature_sev = sig_ids
        .iter()
        .map(|s| s.severity)
        .max()
        .unwrap_or(Severity::None);
    let identity_sev = if identity_changes.is_empty() {
        Severity::None
    } else {
        Severity::High
    };

    let structure = structural_facts(diff, policy, &mut suppressed);
    let structure_sev = structure.severity;

    // One line per accepted risk, however many files it covered.
    suppressed.sort_by(|a, b| a.id.cmp(&b.id).then(a.reason.cmp(&b.reason)));
    suppressed.dedup_by(|a, b| a.id == b.id && a.reason == b.reason);

    Assessment {
        suppressed,
        severity: behavioral_sev
            .max(signature_sev)
            .max(identity_sev)
            .max(structure_sev),
        behavioral: Behavioral {
            severity: behavioral_sev,
            categories,
            new_categories,
        },
        signature: Signature {
            severity: signature_sev,
            cve,
            ids: sig_ids,
        },
        identity: Identity {
            severity: identity_sev,
            changes: identity_changes,
        },
        structure,
    }
}

/// Structural anomalies from the changed files' kv scope. Every fact is an
/// *added* kv entry, so it is inherently new — a fresh dependency, ifunc, or
/// import that was absent from the base version.
fn structural_facts(
    diff: &DiffReportV1,
    policy: &crate::policy::Policy,
    suppressed: &mut Vec<crate::policy::Suppressed>,
) -> Structure {
    let (mut deps, mut ifuncs, mut dynsyms): (Vec<String>, Vec<String>, Vec<String>) =
        (Vec::new(), Vec::new(), Vec::new());
    // Newly-declared source-package runtime dependencies (npm `dependencies`,
    // etc.). A gained external dependency is the event-stream / node-ipc
    // supply-chain shape — the version pulls in code it never shipped before.
    let mut pkg_deps: Vec<String> = Vec::new();
    // GitHub Actions `uses:` references — third-party code that runs in CI with
    // repo secrets. A newly-added action, or a moved `@ref`, is the
    // tj-actions/changed-files supply-chain surface.
    let (mut actions_new, mut actions_moved): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
    let mut audit = false;
    // Added sections tracked apart from existing ones that changed state, so
    // the display can mark `+` (new structure) vs `~` (altered structure).
    let (mut rwx_new, mut rwx_became): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
    let (mut entropy_new, mut entropy_became): (Vec<String>, Vec<String>) =
        (Vec::new(), Vec::new());
    for file in &diff.files {
        if policy.excludes(&file.path) {
            continue;
        }
        if let Some(kv) = file.scopes.kv.as_ref() {
            for k in &kv.added {
                let p = &k.path;
                if p.contains("needed_versions") {
                    continue;
                }
                if let Some(name) = dependency_name(p) {
                    pkg_deps.push(name);
                } else if p.ends_with(".uses") {
                    if let Some(a) = github_action(&k.value) {
                        actions_new.push(a);
                    }
                } else if p.contains("needed") {
                    push_val(&mut deps, &k.value);
                } else if p.contains("ifuncs") {
                    push_val(&mut ifuncs, &k.value);
                } else if p.contains("dynsym")
                    && let Some(name) = between(p, "name=", "]")
                {
                    dynsyms.push(name);
                }
            }
            // A moved `@ref` on an existing action — the mutable-tag surface the
            // tj-actions compromise abused (the tag was repointed to a malicious
            // commit). Reported with the ref it moved *to*.
            for c in &kv.changed {
                if c.new.path.ends_with(".uses")
                    && let Some(a) = github_action(&c.new.value)
                {
                    actions_moved.push(a);
                }
            }
        }
        // A newly-set dynamic-linker auditor hook — xz's interception surface.
        if let Some(m) = file.scopes.metrics.as_ref() {
            for a in &m.added {
                if a.path.ends_with("has_dt_audit") || a.path.ends_with("has_dt_depaudit") {
                    audit = true;
                }
            }
        }
        // Sections that became writable+executable, or a region that turned
        // high-entropy (a packed / self-decrypting payload appearing).
        if let Some(sec) = file.scopes.sections.as_ref() {
            for s in &sec.added {
                if is_rwx(&s.permissions) {
                    rwx_new.push(s.name.clone());
                }
                if s.entropy >= HIGH_ENTROPY {
                    entropy_new.push(s.name.clone());
                }
            }
            for c in &sec.changed {
                if is_rwx(&c.new.permissions) && !is_rwx(&c.old.permissions) {
                    rwx_became.push(c.new.name.clone());
                }
                // Turned high-entropy *and* grew — data replaced by a payload,
                // not a benign edit to an already-packed resource.
                if c.new.entropy >= HIGH_ENTROPY
                    && c.new.size > c.old.size
                    && c.new.entropy - c.old.entropy > 0.5
                {
                    entropy_became.push(c.new.name.clone());
                }
            }
        }
    }
    // A moved-to ref that is *also* a brand-new action is only the "new"
    // event; don't double-report it as moved.
    actions_moved.retain(|a| !actions_new.contains(a));
    for v in [
        &mut deps,
        &mut ifuncs,
        &mut dynsyms,
        &mut pkg_deps,
        &mut actions_new,
        &mut actions_moved,
        &mut rwx_new,
        &mut rwx_became,
        &mut entropy_new,
        &mut entropy_became,
    ] {
        v.sort();
        v.dedup();
    }
    let imports: Vec<String> = dynsyms
        .into_iter()
        .filter(|d| !ifuncs.contains(d))
        .collect();

    use FactKind::{Added, Became};
    let mut facts = Vec::new();
    let mut push = |severity: Severity, kind: FactKind, label: &'static str, names: &[String]| {
        if names.is_empty() {
            return;
        }
        // Structural facts are aggregated across the whole change, so they
        // carry no single path — a path-scoped `[[allow]]` cannot match one.
        if let Some(s) = policy.allows(&structure_id(label), "") {
            suppressed.push(s);
            return;
        }
        facts.push(StructFact {
            severity,
            kind,
            label,
            detail: names.join(" · "),
        });
    };
    if audit {
        push(
            Severity::High,
            Added,
            "linker audit hook",
            &["DT_AUDIT — intercepts symbol resolution".to_string()],
        );
    }
    // A library that gains a *direct* dependency on the dynamic loader is the
    // xz tell — high on its own.
    push(Severity::High, Added, "loader dependency", &deps);
    push(Severity::High, Added, "ifunc resolvers", &ifuncs);
    push(Severity::High, Added, "writable+executable", &rwx_new);
    push(Severity::High, Became, "writable+executable", &rwx_became);
    push(Severity::Medium, Added, "imports", &imports);
    push(Severity::Medium, Added, "high-entropy region", &entropy_new);
    push(
        Severity::Medium,
        Became,
        "high-entropy region",
        &entropy_became,
    );
    // A gained runtime dependency is the supply-chain event isomer exists to
    // surface (event-stream added `flatmap-stream`; node-ipc added
    // `peacenotwar`). Medium: it makes the diff speak so a reviewer sees the
    // new dependency, but stays below the default `--fail-on high` so a routine
    // dependency bump doesn't break CI on its own.
    push(Severity::Medium, Added, "dependency", &pkg_deps);
    // Third-party CI code, same reasoning as a runtime dependency: a new action
    // — or one whose mutable tag was repointed — runs with repo secrets.
    push(Severity::Medium, Added, "github action", &actions_new);
    push(Severity::Medium, Became, "github action", &actions_moved);
    Structure {
        severity: facts
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::None),
        facts,
    }
}

/// Shannon-entropy threshold (bits/byte) above which a section reads as packed
/// or encrypted rather than normal code or data.
const HIGH_ENTROPY: f64 = 7.2;

/// A section mapped both writable and executable — a self-modifying / runtime
/// code-generation surface.
fn is_rwx(perms: &Option<String>) -> bool {
    perms
        .as_deref()
        .is_some_and(|p| p.contains("write") && p.contains("exec"))
}

/// The dependency name from a source-package manifest kv path, if the path
/// declares a *runtime* dependency. `dependencies.left-pad` → `left-pad`,
/// `optionalDependencies.foo` → `foo`. Build-time trees (`devDependencies`)
/// and non-manifest paths return `None` — a dev dependency does not ship in
/// the installed package, so it is not the runtime supply-chain surface.
fn dependency_name(path: &str) -> Option<String> {
    for root in [
        "dependencies.",
        "optionalDependencies.",
        "peerDependencies.",
    ] {
        if let Some(rest) = path.strip_prefix(root) {
            // Only a direct child (`dependencies.<name>`); a deeper path is a
            // sub-field of the version spec, not a distinct dependency.
            if !rest.is_empty() && !rest.contains('.') {
                return Some(rest.to_string());
            }
        }
    }
    None
}

/// A GitHub Actions `uses:` value that references *remote* third-party code —
/// `owner/repo@ref` (optionally with a `/subpath`). Returns the reference,
/// flagging a mutable `@tag`/`@branch` (the surface the tj-actions tag-move
/// abused) apart from an immutable `@<40-hex-sha>` pin. Local (`./…`) and
/// container (`docker://…`) uses are not fetchable third-party code and return
/// `None`.
fn github_action(v: &serde_json::Value) -> Option<String> {
    let raw = v.as_str()?.trim();
    if raw.starts_with('.') || raw.contains("://") {
        return None;
    }
    let (repo, git_ref) = raw.split_once('@')?;
    // `owner/repo` at minimum — a slug with no slash is not a remote action.
    if !repo.contains('/') || repo.is_empty() {
        return None;
    }
    let pinned = git_ref.len() == 40 && git_ref.bytes().all(|b| b.is_ascii_hexdigit());
    Some(if pinned {
        raw.to_string()
    } else {
        format!("{raw} (unpinned)")
    })
}

/// Push a kv leaf value (string name or number) onto a list.
fn push_val(out: &mut Vec<String>, v: &serde_json::Value) {
    if let Some(s) = v.as_str() {
        out.push(s.to_string());
    } else if v.is_number() {
        out.push(v.to_string());
    }
}

/// The substring of `s` between `open` and the next `close`.
fn between(s: &str, open: &str, close: &str) -> Option<String> {
    let (_, rest) = s.split_once(open)?;
    let (inner, _) = rest.split_once(close)?;
    Some(inner.to_string())
}

/// Traits newly present (`true`) or escalated from a lower criticality
/// (`false`) on the new side. Removals and demotions are security
/// *improvements* and are not judged.
fn gained_traits(file: &FileDiffEntry) -> impl Iterator<Item = (bool, &TraitChange)> {
    let traits = file.scopes.traits.as_ref();
    let added = traits
        .into_iter()
        .flat_map(|t| t.added.iter().map(|tc| (true, tc)));
    let promoted = traits.into_iter().flat_map(|t| {
        t.changed
            .iter()
            .filter(|c| crit_rank(c.new.crit) > crit_rank(c.old.crit))
            .map(|c| (false, &c.new))
    });
    added.chain(promoted)
}

/// Trait namespace: the taxonomy path before `::`, with the leading taxonomy
/// root stripped so `metadata/binary/linking/runtime::ifunc` reads as
/// `binary/linking/runtime`.
fn namespace_of(id: &str) -> String {
    const ROOTS: &[&str] = &[
        "metadata",
        "micro-behaviors",
        "objectives",
        "well-known",
        "third_party",
    ];
    let path = id.split("::").next().unwrap_or(id);
    match path.split_once('/') {
        Some((root, rest)) if ROOTS.contains(&root) => rest.to_string(),
        _ => path.to_string(),
    }
}

/// Turn a kebab class label into words: `execution-hijack` → `execution hijack`.
fn humanize(class: &str) -> String {
    class.replace('-', " ")
}

/// Meaningful identity changes between two sides. Deliberately excludes
/// `version` (a version bump is not a publisher change) and signature
/// timestamps; a change in author, signer, organization, publisher account,
/// producer, or contact is what actually signals identity drift.
fn meaningful_identity_changes(
    old: Option<&filefacts::Identity>,
    new: Option<&filefacts::Identity>,
) -> Vec<IdentityChange> {
    use filefacts::Identity;
    let mut out = Vec::new();

    // Name the side that exists — `Dominic Tarr → removed` tells the analyst
    // *whose* identity vanished, where `present → removed` says nothing.
    fn describe_side(i: &Identity) -> String {
        [signer(i), authors(i), claim(&i.name)]
            .into_iter()
            .find(|s| !s.is_empty())
            .unwrap_or_else(|| "present".to_string())
    }
    let (o, n) = match (old, new) {
        (Some(o), Some(n)) => (o, n),
        (Some(o), None) => {
            out.push(IdentityChange {
                label: "identity",
                old: describe_side(o),
                new: "removed".into(),
            });
            return out;
        }
        (None, Some(n)) => {
            out.push(IdentityChange {
                label: "identity",
                old: "absent".into(),
                new: describe_side(n),
            });
            return out;
        }
        (None, None) => return out,
    };

    fn claim(c: &Option<filefacts::Claim>) -> String {
        c.as_ref().map(|c| c.value.clone()).unwrap_or_default()
    }
    fn authors(i: &Identity) -> String {
        i.authors
            .iter()
            .filter_map(|p| p.name.clone())
            .collect::<Vec<_>>()
            .join(", ")
    }
    fn signer(i: &Identity) -> String {
        i.signer
            .as_ref()
            .and_then(|s| {
                s.common_name
                    .clone()
                    .or_else(|| s.organization.clone())
                    .or_else(|| s.subject.clone())
            })
            .unwrap_or_default()
    }
    fn ids(i: &Identity) -> String {
        i.unique_ids
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    let mut push = |label: &'static str, ov: String, nv: String| {
        if ov != nv {
            out.push(IdentityChange {
                label,
                old: ov,
                new: nv,
            });
        }
    };
    push("authors", authors(o), authors(n));
    push("signer", signer(o), signer(n));
    push(
        "organization",
        claim(&o.organization),
        claim(&n.organization),
    );
    push("producer", claim(&o.producer), claim(&n.producer));
    push("team id", claim(&o.team_id), claim(&n.team_id));
    push("publisher id", ids(o), ids(n));
    push("package name", claim(&o.name), claim(&n.name));
    out
}

/// Known-bad detection namespaces. A hit means "we recognize this", not "this
/// behaves badly" — that's the behavioral axis's job.
fn is_signature(id: &str) -> bool {
    id.starts_with("third_party/")
        || id.contains("malware/")
        || id.contains("hidden-payload")
        || id.contains("trojanized")
}

/// Whether a criticality tier is worth reporting as a change.
///
/// Notable and above only. The tiers below it are not findings:
/// `Component` marks an atom that exists to be referenced by a composite rule
/// (`arithmetic-sub-density` is how `js-arithmetic-array-init` requires
/// density *and* volume together), `Baseline` marks an unremarkable
/// observation, and exceptions and filtered traits are negations. Reporting
/// any of them turns `return a-b` into "gained obfuscation" and spends the
/// false-positive budget on noise.
///
/// A low-tier atom that matters is one a higher-tier composite is built from —
/// and that composite fires as its own trait, carrying its own id and
/// criticality, so it is judged here on its own merit and its legs are pulled
/// in as evidence by [`crate::evidence`].
fn is_finding(crit: Criticality) -> bool {
    matches!(
        crit,
        Criticality::Hostile | Criticality::Suspicious | Criticality::Notable
    )
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
        (
            "command-and-control",
            Severity::Critical,
            "C2",
            "gained C2 signaling",
        ),
        (
            "exfiltration",
            Severity::Critical,
            "exfiltration",
            "gained data exfiltration",
        ),
        (
            "impact/",
            Severity::Critical,
            "destructive-impact",
            "gained destructive impact",
        ),
        // High — primitives that grant code execution or egress. `ifunc` is the
        // resolver-hijack mechanism the xz backdoor used.
        (
            "linking/runtime::ifunc",
            Severity::High,
            "execution-hijack",
            "gained an ifunc resolver",
        ),
        (
            "process/create",
            Severity::High,
            "process-execution",
            "gained process execution",
        ),
        (
            "child-process",
            Severity::High,
            "process-execution",
            "gained process execution",
        ),
        (
            "process/inject",
            Severity::High,
            "process-injection",
            "gained process injection",
        ),
        // Network egress is Medium, not High. A file that gains an HTTP call
        // is worth naming — especially when it had none before, which the
        // new-vs-expanded split already reports — but it is also what ordinary
        // feature work looks like, and failing every such pull request is how
        // a scanner gets switched off. The attacker-objective classes above
        // stay Critical, and proportionality still escalates network drift a
        // patch release had no business introducing.
        (
            "communications/",
            Severity::Medium,
            "network",
            "gained network access",
        ),
        (
            "credential-access",
            Severity::High,
            "credential-access",
            "gained credential access",
        ),
        (
            "install-hook",
            Severity::High,
            "install-hook",
            "gained an install hook",
        ),
        // Medium — enablers: new runtime linkage, obfuscation, hidden data,
        // host reconnaissance. Individually noisy, collectively damning.
        (
            "linking/runtime",
            Severity::Medium,
            "runtime-linkage",
            "new runtime linkage",
        ),
        (
            "obfuscation",
            Severity::Medium,
            "obfuscation",
            "gained obfuscation",
        ),
        (
            "encode/xor",
            Severity::Medium,
            "xor-encoding",
            "gained xor-encoded data",
        ),
        (
            "decode/base64",
            Severity::Medium,
            "base64",
            "gained base64 decoding",
        ),
        (
            "string/assembly",
            Severity::Medium,
            "hidden-byte-strings",
            "gained hidden byte strings",
        ),
        (
            "discovery/system",
            Severity::Medium,
            "host-recon",
            "gained host reconnaissance",
        ),
        (
            "fingerprint",
            Severity::Medium,
            "host-recon",
            "gained host reconnaissance",
        ),
    ];
    TABLE
        .iter()
        .find(|(seg, _, _, _)| id.contains(seg))
        .map(|&(_, sev, class, phrase)| (sev, class, phrase))
}

/// Severity of the capability class a trait id maps to; `Severity::None` for
/// ids carrying no behavioral capability. Lets evidence rank a
/// baseline-criticality note by the capability it proves — an SSH-protocol
/// string is weak as a rule but strong as proof of gained network reach.
pub(crate) fn capability_severity(id: &str) -> Severity {
    capability_risk(id).map_or(Severity::None, |(s, _, _)| s)
}

/// The capability class a trait id maps to, if any. `None` for ids that carry
/// no behavioral capability (structural metadata, signatures). Used to collect
/// the base version's capability classes.
pub(crate) fn capability_class(id: &str) -> Option<&'static str> {
    if is_signature(id) {
        return None;
    }
    capability_risk(id).map(|(_, class, _)| class)
}

/// The suppression id for publisher drift. Identity changes have no trait id
/// of their own, but `.isomer.toml` must still be able to accept one.
pub(crate) const IDENTITY_ID: &str = "identity";

/// The suppression id for a structural fact, e.g. `structure/loader-dependency`.
/// Shared with the SARIF rule ids, so what a report calls a finding is exactly
/// what `.isomer.toml` calls it.
pub(crate) fn structure_id(label: &str) -> String {
    format!("structure/{}", slug(label))
}

/// Kebab-case a human label for use inside an id.
pub(crate) fn slug(label: &str) -> String {
    label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

/// The readable tail of a trait id — the rule name an analyst greps for.
/// `third_party/elastic/Linux_Trojan_XZBackdoor` reads as
/// `elastic/Linux_Trojan_XZBackdoor`; a taxonomy id reads as its leaf.
pub(crate) fn short_name(id: &str) -> String {
    if let Some((_, leaf)) = id.rsplit_once("::") {
        return leaf.to_string();
    }
    if let Some(rest) = id.strip_prefix("third_party/") {
        let segs: Vec<&str> = rest.split('/').collect();
        return match (segs.first(), segs.last()) {
            (Some(v), Some(l)) if segs.len() > 1 => format!("{v}/{l}"),
            (Some(v), _) => v.to_string(),
            _ => rest.to_string(),
        };
    }
    id.rsplit('/').next().unwrap_or(id).to_string()
}

/// Pull a `CVE-YYYY-NNNN` out of a trait id that references one in either
/// `CVE/2024/3094` (path) or `CVE-2024-3094` form.
fn extract_cve(id: &str) -> Option<String> {
    let (_, rest) = id.split_once("CVE")?;
    let sep: &[char] = &['/', '-', '_'];
    let mut parts = rest.split(|c| sep.contains(&c)).filter(|s| !s.is_empty());
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
        let (sev, class, _) = capability_risk("metadata/binary/linking/runtime::ifunc").unwrap();
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
    fn ifunc_and_loaders_are_different_classes() {
        // The load-bearing distinction for new-vs-existing: within one
        // namespace, the ifunc is `execution-hijack` (the new thing) while the
        // loader traits are `runtime-linkage` (pre-existing for any .so).
        assert_eq!(
            capability_class("metadata/binary/linking/runtime::ifunc"),
            Some("execution-hijack")
        );
        assert_eq!(
            capability_class("metadata/binary/linking/runtime::dynamic-loader-needed"),
            Some("runtime-linkage")
        );
        // Signatures and structural traits are not capability classes.
        assert_eq!(capability_class("third_party/elastic/XZBackdoor"), None);
    }

    /// A component atom is an ingredient of a composite rule, not a finding.
    /// Judging one directly turned `return a-b` into "gained obfuscation".
    #[test]
    fn component_atoms_are_not_findings() {
        assert!(!is_finding(Criticality::Component));
        assert!(!is_finding(Criticality::Baseline));
        assert!(!is_finding(Criticality::Exception));
        assert!(!is_finding(Criticality::Filtered));
        assert!(is_finding(Criticality::Notable));
        assert!(is_finding(Criticality::Suspicious));
        assert!(is_finding(Criticality::Hostile));
    }

    #[test]
    fn rwx_needs_both_write_and_exec() {
        assert!(is_rwx(&Some("write,alloc,executable".into())));
        assert!(!is_rwx(&Some("alloc,executable".into())));
        assert!(!is_rwx(&Some("write,alloc".into())));
        assert!(!is_rwx(&None));
    }

    #[test]
    fn dependency_name_reads_runtime_manifests_only() {
        // A direct runtime dependency — the node-ipc / event-stream shape.
        assert_eq!(
            dependency_name("dependencies.peacenotwar").as_deref(),
            Some("peacenotwar")
        );
        assert_eq!(
            dependency_name("optionalDependencies.foo").as_deref(),
            Some("foo")
        );
        // A lockfile sub-field of a version spec is not a distinct dependency.
        assert_eq!(dependency_name("dependencies.foo.version"), None);
        // Build-time deps don't ship in the installed package.
        assert_eq!(dependency_name("devDependencies.jest"), None);
        // Unrelated manifest keys.
        assert_eq!(dependency_name("scripts.postinstall"), None);
        assert_eq!(dependency_name("dependencies"), None);
    }

    #[test]
    fn github_action_flags_remote_refs_and_pinning() {
        let a = |s: &str| github_action(&serde_json::Value::String(s.into()));
        // Remote action on a mutable tag — the tj-actions surface.
        assert_eq!(
            a("tj-actions/changed-files@v44").as_deref(),
            Some("tj-actions/changed-files@v44 (unpinned)")
        );
        // Immutable SHA pin — no unpinned flag.
        let sha = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        assert_eq!(
            a(&format!("actions/checkout@{sha}")).as_deref(),
            Some(format!("actions/checkout@{sha}").as_str())
        );
        // Local and container uses are not fetchable third-party code.
        assert_eq!(a("./.github/actions/local"), None);
        assert_eq!(a("docker://alpine:3"), None);
        // A bare slug with no owner/repo is not a remote action.
        assert_eq!(a("node@18"), None);
    }

    #[test]
    fn namespace_strips_taxonomy_root() {
        assert_eq!(
            namespace_of("objectives/command-and-control/channel/websocket::sio"),
            "command-and-control/channel/websocket"
        );
        assert_eq!(
            namespace_of("micro-behaviors/data/encode/xor::x"),
            "data/encode/xor"
        );
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
