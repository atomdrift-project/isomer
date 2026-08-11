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

use std::collections::{HashMap, HashSet};

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
    pub new_categories: HashSet<String>,
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
    /// for evidence rendering. Borrowed: the ids live in the assessment, and
    /// evidence only ever reads them.
    pub(crate) fn gained_ids(&self) -> HashSet<&str> {
        self.behavioral
            .categories
            .iter()
            .flat_map(|c| c.new_ids.iter().chain(&c.escalated_ids))
            .chain(self.signature.ids.iter().map(|m| &m.id))
            .map(String::as_str)
            .collect()
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
/// from one that merely gained a trait.
pub(crate) fn assess(diff: &DiffReportV1, base_classes: &HashSet<String>) -> Assessment {
    let mut groups: HashMap<String, Category> = HashMap::new();
    let mut sig_ids: Vec<SigMatch> = Vec::new();
    let mut cve: Option<String> = None;
    let mut identity_changes: Vec<IdentityChange> = Vec::new();

    for file in &diff.files {
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
            identity_changes.extend(meaningful_identity_changes(
                idd.old.as_ref(),
                idd.new.as_ref(),
            ));
        }
        for (is_new, tc) in gained_traits(file) {
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
            } else if let Some(class) = capability_class(&tc.id) {
                // Severity is the grading traits-dev already maintains.
                // Keeping a second opinion here would mean two places to
                // update and two answers to reconcile every time a trait
                // is added or regraded.
                let sev = severity_from_crit(tc.crit);
                let entry = groups.entry(class.clone()).or_insert_with(|| Category {
                    severity: sev,
                    label: humanize(&class),
                    class,
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
    let new_categories: HashSet<String> = categories
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

    let structure = structural_facts(diff);
    let structure_sev = structure.severity;

    // One line per accepted risk, however many files it covered.

    Assessment {
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
fn structural_facts(diff: &DiffReportV1) -> Structure {
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
        if let Some(kv) = file.scopes.kv.as_ref() {
            for k in &kv.added {
                let p = &k.path;
                if p.contains("needed_versions") {
                    continue;
                }
                if let Some(name) = dependency_name(p) {
                    pkg_deps.push(name.to_owned());
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
        facts.push(StructFact {
            severity,
            kind,
            label,
            // The names are lifted from the artifact (dependency and action
            // names, section names, imports); neutralize control chars so a
            // crafted name can't spoof the terminal. The ` · ` separators are
            // ours and survive unchanged.
            detail: crate::printable(&names.join(" · ")),
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
fn dependency_name(path: &str) -> Option<&str> {
    [
        "dependencies.",
        "optionalDependencies.",
        "peerDependencies.",
    ]
    .into_iter()
    .find_map(|root| path.strip_prefix(root))
    // Only a direct child (`dependencies.<name>`); a deeper path is a
    // sub-field of the version spec, not a distinct dependency.
    .filter(|rest| !rest.is_empty() && !rest.contains('.'))
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
    // `owner/repo` at minimum — a slug with no slash is not a remote action
    // (this also rejects an empty owner, e.g. `@v44`).
    if !repo.contains('/') {
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
/// `binary/linking/runtime`. Shared with [`crate::evidence`], so the namespaces
/// a verdict groups by and the ones its evidence names cannot drift apart.
pub(crate) fn namespace_of(id: &str) -> String {
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

/// Meaningful identity changes between two sides. Deliberately excludes
/// `version` (a version bump is not a publisher change) and signature
/// timestamps; a change in author, signer, organization, publisher account,
/// producer, or contact is what actually signals identity drift.
fn meaningful_identity_changes(
    old: Option<&filefacts::Identity>,
    new: Option<&filefacts::Identity>,
) -> Vec<IdentityChange> {
    use filefacts::Identity;

    // Every field below is a *claim the artifact makes about itself* — an npm
    // `author`, a signature subject — so it is attacker-controlled text on its
    // way to an analyst's terminal. Neutralized here, at the one place they are
    // read, rather than at each of the four renderers downstream.
    fn claim(c: &Option<filefacts::Claim>) -> String {
        crate::printable(c.as_ref().map_or("", |c| c.value.as_str()))
    }
    fn authors(i: &Identity) -> String {
        crate::printable(
            &i.authors
                .iter()
                .filter_map(|p| p.name.clone())
                .collect::<Vec<_>>()
                .join(", "),
        )
    }
    fn signer(i: &Identity) -> String {
        crate::printable(
            i.signer
                .as_ref()
                .and_then(|s| {
                    s.common_name
                        .as_deref()
                        .or(s.organization.as_deref())
                        .or(s.subject.as_deref())
                })
                .unwrap_or_default(),
        )
    }
    fn ids(i: &Identity) -> String {
        crate::printable(
            &i.unique_ids
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(", "),
        )
    }
    // Name the side that exists — `Dominic Tarr → removed` tells the analyst
    // *whose* identity vanished, where `present → removed` says nothing.
    fn describe_side(i: &Identity) -> String {
        [signer(i), authors(i), claim(&i.name)]
            .into_iter()
            .find(|s| !s.is_empty())
            .unwrap_or_else(|| "present".to_string())
    }

    let mut out = Vec::new();
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
        // Identity *appearing* (absent → present) is not drift. A remediated
        // release restoring the author metadata a malicious version stripped is
        // benign; the suspicious direction — `present → absent`, identity
        // stripped — is still reported above. Reporting this side too made every
        // during→after and before→after comparison read as a publisher event
        // (`absent → Alex Gherghisan`) when nothing was taken over.
        (None, _) => return out,
    };

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
pub(crate) fn is_finding(crit: Criticality) -> bool {
    matches!(
        crit,
        Criticality::Hostile | Criticality::Suspicious | Criticality::Notable
    )
}

pub(crate) fn severity_from_crit(crit: Criticality) -> Severity {
    match crit {
        Criticality::Hostile => Severity::Critical,
        Criticality::Suspicious => Severity::High,
        Criticality::Notable => Severity::Medium,
        _ => Severity::None,
    }
}

/// Total order over cleave's criticality tiers, worst highest. The enum itself
/// is not `Ord`, so every comparison in isomer goes through this one ranking.
pub(crate) fn crit_rank(c: Criticality) -> u8 {
    match c {
        Criticality::Hostile => 5,
        Criticality::Suspicious => 4,
        Criticality::Notable => 3,
        Criticality::Baseline => 2,
        Criticality::Component => 1,
        Criticality::Exception | Criticality::Filtered => 0,
    }
}

/// The capability class a trait belongs to, derived from its taxonomy path.
///
/// The taxonomy already encodes what a trait *is*; a hand-maintained table
/// mapping id substrings to classes could only ever cover the branches someone
/// remembered to enumerate, which is the wrong shape for a tool that claims to
/// catch novel attacks. Depth varies by root because the roots mean different
/// things:
///
/// | root | depth | example class |
/// |------|-------|---------------|
/// | `objectives/` | 1 | `command-and-control` — the MBC objective |
/// | `micro-behaviors/` | 2 | `data/encode` — micro-objective and behavior |
/// | `metadata/` | 3 | `binary/linking/runtime` |
///
/// `well-known/` (library identity) and `third_party/` (signatures) carry no
/// capability: the first says what the code *is*, the second that we recognize
/// it. Both are judged on other axes.
pub(crate) fn capability_class(id: &str) -> Option<String> {
    if is_signature(id) {
        return None;
    }
    let path = id.split("::").next().unwrap_or(id);
    let (root, rest) = path.split_once('/')?;
    // Under `objectives/` and `micro-behaviors/` the path *is* the behavior
    // taxonomy, so the path names the capability. Under `metadata/` the path
    // names a structural location and the leaf names the fact — grouping by
    // path alone would file an ifunc resolver alongside the ordinary loader
    // entries every shared object has, and bury the one thing that mattered.
    if root == "metadata" {
        let leaf = id.rsplit_once("::").map(|(_, l)| l);
        let path: Vec<&str> = rest.split('/').take(3).collect();
        return Some(match leaf {
            Some(leaf) => format!("{}::{leaf}", path.join("/")),
            None => path.join("/"),
        });
    }
    // Depth per the table above. An unenumerated root falls to the same
    // granularity as `micro-behaviors` rather than being dropped: a new
    // taxonomy branch should surface as a class, not vanish.
    let depth = match root {
        "well-known" | "third_party" => return None,
        "objectives" => 1,
        _ => 2,
    };
    let class = rest.split('/').take(depth).collect::<Vec<_>>().join("/");
    // A root with nothing under it (`objectives/`) names no capability.
    (!class.is_empty()).then_some(class)
}

/// A readable name for a class. `command-and-control` reads as `command and
/// control`; a `metadata` class reads as its leaf (`…runtime::ifunc` → `ifunc`),
/// which is the part that names the fact. Path separators are otherwise kept
/// because they carry meaning.
fn humanize(class: &str) -> String {
    match class.rsplit_once("::") {
        Some((_, leaf)) => leaf.replace('-', " "),
        None => class.replace('-', " "),
    }
}

/// The stable id for a structural fact, e.g. `structure/loader-dependency`.
/// This is the SARIF rule id, so a Security-tab alert keeps the same identity
/// across runs and can be tracked or dismissed there.
pub(crate) fn structure_id(label: &str) -> String {
    format!("structure/{}", slug(label))
}

/// Kebab-case a human label for use inside an id.
pub(crate) fn slug(label: &str) -> String {
    let kebab: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    kebab.trim_matches('-').to_string()
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

    /// The class comes from the taxonomy, at a depth that suits each root, so
    /// a branch nobody enumerated still gets a class instead of vanishing.
    #[test]
    fn class_is_derived_from_the_taxonomy() {
        let c = |id| capability_class(id);
        // objectives: the MBC objective itself.
        assert_eq!(
            c("objectives/command-and-control/channel/websocket::sio").as_deref(),
            Some("command-and-control")
        );
        assert_eq!(
            c("objectives/exfiltration/http/upload::x").as_deref(),
            Some("exfiltration")
        );
        // micro-behaviors: micro-objective and behavior.
        assert_eq!(
            c("micro-behaviors/data/encode/xor::x").as_deref(),
            Some("data/encode")
        );
        assert_eq!(
            c("micro-behaviors/communications/dns/lookup/txt::x").as_deref(),
            Some("communications/dns")
        );
        // metadata: three segments, enough to separate structural neighbours.
        // metadata keeps the leaf: the ifunc must not be filed with the
        // ordinary loader entries every shared object already has.
        assert_eq!(
            c("metadata/binary/linking/runtime::ifunc").as_deref(),
            Some("binary/linking/runtime::ifunc")
        );
        assert_ne!(
            c("metadata/binary/linking/runtime::ifunc"),
            c("metadata/binary/linking/runtime::dynamic-loader-needed")
        );
        // Library identity and signatures are not capabilities.
        assert_eq!(c("well-known/lib/core/suncalc::x"), None);
        assert_eq!(c("third_party/elastic/XZBackdoor"), None);
        // An unenumerated root still yields a class rather than nothing.
        assert_eq!(
            c("brand-new-root/persistence/service::x").as_deref(),
            Some("persistence/service")
        );
        // A root with nothing under it names no capability.
        assert_eq!(c("objectives/"), None);
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
            dependency_name("dependencies.peacenotwar"),
            Some("peacenotwar")
        );
        assert_eq!(dependency_name("optionalDependencies.foo"), Some("foo"));
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
