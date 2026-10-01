//! The `--format json` wire schema.
//!
//! Shape and conventions mirror `../scan`'s JSON envelope so one parser serves
//! the whole toolchain: a compact, **typed** object (fields serialize in
//! declaration order, so the verdict reads first and the bulky `raw` diff last),
//! short keys, lowercase severity words, and a curated analysis section sitting
//! beside the complete `raw` cleave report — scan's `{ml, llm, raw}` pattern,
//! here `{…meta, verdict, llm, raw}`.
//!
//! Where isomer is differential rather than single-artifact it deviates on
//! purpose: the `verdict` section describes a *change* (behavioral / signature /
//! identity / structure drift, ML-risk jump, proportionality), and a `gate`
//! object states the CI exit decision outright — the one thing a pipeline must
//! read without re-deriving it.
//!
//! The wire structs come first; [`envelope`] maps an [`Analysis`] onto them.

use anyhow::Result;
use cleave::types::{
    DiffReportV1, FileDiffEntry, FileStatus, KvChange, MetricChange, ScopeDiff, ScopeDiffs,
    SectionChange, TraitChange,
};
use serde::Serialize;

use crate::Severity;
use crate::analysis::Analysis;
use crate::member::MemberPath;
use crate::version::BumpKind;

/// How one item moved between the two sides.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Change {
    Added,
    Removed,
    Changed,
}

/// Top-level envelope. Generic over the raw report so this module stays
/// decoupled from cleave's diff types.
#[derive(Serialize)]
pub(crate) struct Envelope<'a, R: Serialize> {
    /// Envelope schema version.
    pub v: &'static str,
    /// Producing engine, `isomer/<pkg-version>` (mirrors scan's `eng`).
    pub eng: &'static str,
    /// The isomer surface that produced this report, e.g. `fs`.
    pub verb: crate::analysis::Verb,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact: Option<&'a str>,
    pub version: Version<'a>,
    /// Identity claims of each side — name, version, signer, trust tier — the
    /// provenance an analyst needs to judge who published what. The `changed`
    /// subset drives `verdict.identity`; this carries the full claims.
    pub provenance: Provenance<'a>,
    /// The differential assessment plus the gate decision.
    pub verdict: Verdict<'a>,
    /// Stable, uncapped machine-learning feature record. Unlike the curated
    /// terminal view, this preserves every per-file trait, metric, fact, and
    /// section delta, plus the complete scope totals.
    pub features: FeatureSet<'a>,
    /// The proof behind the verdict: context windows for the gained traits, in
    /// file order (locator · code · description). Present so the UI and a cache
    /// can render the evidence table without re-reading the artifact.
    pub evidence: Vec<Ev<'a>>,
    /// What each dependency the change *added* can do, from fetching and
    /// analyzing it (`--deps`). Absent when the flag wasn't set.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub deps: Vec<Dep<'a>>,
    /// Current registry evidence for both sides, including provider records and errors.
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    pub registry: &'a [crate::registry::Comparison],
    /// Optional `--llm` interpretation (mirrors scan's `llm`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm: Option<Llm<'a>>,
    /// The complete underlying cleave diff — every scope and per-file delta the
    /// curated sections were distilled from (scan's `raw`). Kept last so a human
    /// reading top-down meets the verdict before the bulk, and so a consumer
    /// (prism, the CLI cache) can regenerate anything the curated view omits.
    pub raw: &'a R,
}

/// Stable differential features, versioned separately from the surrounding
/// presentation envelope so model pipelines can evolve on their own cadence.
#[derive(Serialize)]
pub(crate) struct FeatureSet<'a> {
    /// Judged summary after archive-root normalization. `scopes` below retains
    /// Cleave's original aggregate totals, which may precede normalization.
    pub judged_summary: cleave::types::DiffSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trait_shift: Option<crate::behavior_shift::Shift>,
    pub v: &'static str,
    pub topology: Topology,
    pub scopes: FeatureScopes,
    pub files: Vec<FileFeatures<'a>>,
}

#[derive(Serialize)]
pub(crate) struct Topology {
    pub added: u32,
    pub removed: u32,
    pub changed: u32,
    pub unchanged: u32,
    pub compared: u32,
}

#[derive(Serialize)]
pub(crate) struct FeatureScopes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traits: Option<ScopeStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<ScopeStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facts: Option<ScopeStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbols: Option<ScopeStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strings: Option<ScopeStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sections: Option<ScopeStats>,
}

/// Counts and weights are Cleave's complete pre-presentation totals. The
/// explicit row counts make accidental upstream truncation observable.
#[derive(Serialize)]
pub(crate) struct ScopeStats {
    pub added: usize,
    pub removed: usize,
    pub changed: usize,
    pub old_count: u32,
    pub new_count: u32,
    pub old_weight: f32,
    pub new_weight: f32,
    pub change_weight: f32,
    pub roc: f32,
    pub truncated: bool,
}

#[derive(Serialize)]
pub(crate) struct FileFeatures<'a> {
    pub path: &'a str,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub file_type: Option<&'a str>,
    pub status: FileStatus,
    pub archive_depth: usize,
    pub identity_changed: bool,
    pub scopes: FeatureScopes,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub traits: Vec<TraitDelta<'a>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub metrics: Vec<ValueDelta<'a>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub facts: Vec<FactDelta<'a>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sections: Vec<SectionDelta<'a>>,
}

#[derive(Serialize)]
pub(crate) struct TraitDelta<'a> {
    pub id: &'a str,
    pub change: Change,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old: Option<TraitSide<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new: Option<TraitSide<'a>>,
}

#[derive(Serialize)]
pub(crate) struct TraitSide<'a> {
    pub criticality: cleave::Criticality,
    pub confidence: f32,
    /// Criticality weight multiplied by confidence: the same importance used
    /// to rank terminal traits.
    pub score: f32,
    pub count: u32,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub description: &'a str,
}

/// A metric value transition. Numeric fields are populated whenever both the
/// underlying JSON value and the requested calculation are meaningful.
#[derive(Serialize)]
pub(crate) struct ValueDelta<'a> {
    pub path: &'a str,
    pub change: Change,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old: Option<&'a serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new: Option<&'a serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub absolute_delta: Option<f64>,
    /// Signed change relative to `abs(old)`. Undefined for additions and a
    /// zero old value rather than represented as infinity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relative_delta: Option<f64>,
}

#[derive(Serialize)]
pub(crate) struct FactDelta<'a> {
    pub path: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub namespace: &'a str,
    pub change: Change,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old: Option<&'a serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new: Option<&'a serde_json::Value>,
}

#[derive(Serialize)]
pub(crate) struct SectionDelta<'a> {
    pub name: &'a str,
    pub change: Change,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old: Option<SectionSide<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new: Option<SectionSide<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_delta: Option<i128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy_delta: Option<f64>,
}

#[derive(Serialize)]
pub(crate) struct SectionSide<'a> {
    pub size: u64,
    pub entropy: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<&'a str>,
}

/// One added dependency, profiled by fetching and analyzing it.
#[derive(Serialize)]
pub(crate) struct Dep<'a> {
    pub profile: &'a crate::deps::RiskProfile,
    /// The predecessor's profile, when the dependency replaced one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_profile: Option<&'a crate::deps::RiskProfile>,
    /// The predecessor's coordinate, when the dependency replaced one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline: Option<&'a str>,
    pub new_severity: Severity,
    pub comparison: &'a str,
    /// The declared coordinate, `peacenotwar@^9.1.3`.
    pub coord: &'a str,
    pub ecosystem: crate::purl::Ecosystem,
    /// Worst severity found in the fetched dependency.
    pub severity: Severity,
    /// Strongest finding descriptions, worst-first.
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    pub highlights: &'a [String],
    /// Present when the dependency could not be fetched or analyzed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'a str>,
}

/// Full identity claims for each side (the `changed` subset lives in
/// `verdict.identity`). Reuses filefacts's canonical `Identity` serialization,
/// the same shape cleave emits as a file's `ident`.
#[derive(Serialize)]
pub(crate) struct Provenance<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old: Option<&'a filefacts::Identity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new: Option<&'a filefacts::Identity>,
}

/// One evidence hunk — a contiguous matched region attributed to its top rule
/// (criticality × confidence), with a short diff-style excerpt.
#[derive(Serialize)]
pub(crate) struct Ev<'a> {
    /// Archive member the hunk came from, when the artifact is a container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member: Option<&'a str>,
    /// `file:line` (text) or `file:0x<offset>` (binary).
    pub location: &'a str,
    /// The top rule's severity.
    pub severity: Severity,
    /// The top rule's description.
    pub desc: &'a str,
    pub lines: Vec<EvLine<'a>>,
}

/// One line of an evidence hunk's excerpt.
#[derive(Serialize)]
pub(crate) struct EvLine<'a> {
    /// Source line number, or hex byte offset for binaries.
    pub locator: &'a str,
    /// The code (windowed around the match) or a hex byte run.
    pub text: &'a str,
    /// `true` when the line is absent from the old version, `false` when
    /// present in both; omitted when no old text was available to diff.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub added: Option<bool>,
    /// Whether a rule matched on this line (vs pure context). Omitted when
    /// false.
    #[serde(rename = "match", skip_serializing_if = "is_false")]
    pub is_match: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Serialize)]
pub(crate) struct Version<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new: Option<&'a str>,
    /// Semver bump class: `major` | `minor` | `patch` | `same` | `downgrade`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bump: Option<BumpKind>,
}

#[derive(Serialize)]
pub(crate) struct Verdict<'a> {
    /// Overall severity (rubric ∪ current ML risk): the "how bad is it now" axis.
    pub severity: Severity,
    /// Change-only severity (newly-introduced risk ∪ an ML-risk jump): the axis
    /// the default `--gate new` acts on.
    pub new_severity: Severity,
    pub gate: Gate,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk: Option<Risk>,
    pub proportionality: Prop<'a>,
    pub behavioral: Behavioral<'a>,
    pub signature: Signature<'a>,
    pub identity: Identity<'a>,
    pub structure: Structure,
    /// How much of the artifact's behavioral fingerprint this release
    /// introduced, and whether that quantity alone raised the gate.
    pub behavior_mass: BehaviorMass,
    /// MITRE ATT&CK and MBC ids the change moved. Ids only — isomer ships no
    /// catalog mapping them to prose, and a consumer that has one can join on
    /// these.
    pub frameworks: Frameworks<'a>,
}

/// The behavior-quantity axis: weighed mass and blind id counts, each with
/// the share of the artifact they represent, plus the severity they earned.
/// Reported always, so a passing run shows the headroom it had.
#[derive(Serialize)]
pub(crate) struct BehaviorMass {
    pub severity: Severity,
    pub mass: f32,
    pub share: f32,
    pub ids_gained: u32,
    pub id_share: f32,
}

#[derive(Serialize)]
pub(crate) struct Frameworks<'a> {
    pub attack: Ids<'a>,
    pub mbc: Ids<'a>,
}

#[derive(Serialize)]
pub(crate) struct Ids<'a> {
    /// Present on the new side and absent on the old.
    pub new: Vec<&'a str>,
    /// Present on the old side and absent on the new.
    pub removed: Vec<&'a str>,
    /// Present on both.
    pub unchanged: usize,
}

/// The CI exit decision, stated so a pipeline never re-derives it.
#[derive(Serialize)]
pub(crate) struct Gate {
    /// Which axis the gate reads: `new` (default) or `any`.
    pub on: crate::Gate,
    /// The `--fail-on` threshold.
    pub fail_on: Severity,
    /// The severity actually compared against the threshold.
    pub severity: Severity,
    /// `true` when the run exits non-zero.
    pub fail: bool,
}

#[derive(Serialize)]
pub(crate) struct Risk {
    pub old: f32,
    pub new: f32,
    pub delta: f32,
    pub new_classification: String,
    pub model: &'static str,
}

#[derive(Serialize)]
pub(crate) struct Prop<'a> {
    pub disproportionate: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'a str>,
    /// Behavior-vs-content skew note (the surgical-implant tell), when it fired.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skew: Option<&'a str>,
}

#[derive(Serialize)]
pub(crate) struct Behavioral<'a> {
    pub severity: Severity,
    pub categories: Vec<Category<'a>>,
}

#[derive(Serialize)]
pub(crate) struct Category<'a> {
    /// Kebab class key, e.g. `execution-hijack`.
    pub class: &'a str,
    pub label: &'a str,
    pub severity: Severity,
    /// The class had no trait in the base version — a wholly new behavior.
    #[serde(rename = "new")]
    pub new_category: bool,
    /// Trait namespaces under this class.
    pub namespaces: &'a [String],
    /// Full ids of traits absent on the old side.
    pub new_ids: &'a [String],
    /// Full ids of pre-existing traits escalated in criticality.
    pub escalated_ids: &'a [String],
}

#[derive(Serialize)]
pub(crate) struct Signature<'a> {
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cve: Option<&'a str>,
    pub count: usize,
    pub ids: Vec<SigId<'a>>,
}

#[derive(Serialize)]
pub(crate) struct SigId<'a> {
    pub id: &'a str,
    /// The rule's human description, when it carries one.
    #[serde(skip_serializing_if = "str::is_empty")]
    pub desc: &'a str,
    /// Per-signature severity.
    pub crit: Severity,
    /// Absent on the old side (vs an escalation of an existing match).
    pub new: bool,
}

#[derive(Serialize)]
pub(crate) struct Identity<'a> {
    pub severity: Severity,
    pub changes: Vec<IdChange<'a>>,
}

#[derive(Serialize)]
pub(crate) struct IdChange<'a> {
    pub field: crate::rubric::IdentityField,
    pub old: &'a str,
    pub new: &'a str,
}

#[derive(Serialize)]
pub(crate) struct Structure {
    pub severity: Severity,
    pub facts: Vec<Fact>,
}

#[derive(Serialize)]
pub(crate) struct Fact {
    pub severity: Severity,
    /// `added` for newly-present structure, `became` for existing structure
    /// altered in place.
    pub change: crate::rubric::FactKind,
    pub label: crate::rubric::FactLabel,
    pub detail: String,
}

#[derive(Serialize)]
pub(crate) struct Llm<'a> {
    pub nature: &'a str,
    pub verdict: &'a str,
    pub model: &'a str,
}

// ── mapping ─────────────────────────────────────────────────────────────────

/// Build the `--format json` envelope. Compact and typed, mirroring
/// `../scan`: a curated `verdict` and its evidence beside the full `raw`
/// cleave diff.
pub(crate) fn envelope(analysis: &Analysis<'_>) -> Result<String> {
    let a = &analysis.assessment;
    let categories = a
        .behavioral
        .categories
        .iter()
        .map(|c| Category {
            class: &c.class,
            label: &c.label,
            severity: c.severity,
            new_category: a.behavioral.is_new_category(c),
            namespaces: &c.namespaces,
            new_ids: &c.new_ids,
            escalated_ids: &c.escalated_ids,
        })
        .collect();
    let sig_ids = a
        .signature
        .ids
        .iter()
        .map(|m| SigId {
            id: &m.id,
            desc: &m.desc,
            crit: m.severity,
            new: m.is_new,
        })
        .collect();
    let facts = a
        .structure
        .facts
        .iter()
        .map(|f| Fact {
            severity: f.severity,
            change: f.kind,
            label: f.label,
            detail: f.sentence(),
        })
        .collect();
    let changes = a
        .identity
        .changes
        .iter()
        .map(|c| IdChange {
            field: c.label,
            old: &c.old,
            new: &c.new,
        })
        .collect();

    // The proof hunks and the full identity claims — everything the UI and
    // the CLI cache need to redraw without re-reading the artifact.
    let hunks = analysis.hunks(usize::MAX);
    let evidence = hunks
        .iter()
        .map(|h| Ev {
            member: h.member.as_deref(),
            location: &h.location,
            severity: h.severity,
            desc: &h.desc,
            lines: h
                .lines
                .iter()
                .map(|l| EvLine {
                    locator: &l.locator,
                    text: &l.text,
                    added: l.added.as_flag(),
                    is_match: l.is_match,
                })
                .collect(),
        })
        .collect();
    // The root describes the artifact itself, so it is asked first — the
    // same ordering `Naming::resolve` uses — before any member's identity.
    let provenance = analysis
        .diff
        .files
        .iter()
        .filter(|f| MemberPath::new(&f.path).is_root())
        .chain(analysis.diff.files.iter())
        .find_map(|f| f.identity.as_ref())
        .map_or((None, None), |idd| (idd.old.as_ref(), idd.new.as_ref()));
    let mut features = feature_set(analysis.display_diff());
    features.trait_shift = Some(analysis.shift.clone());

    let envelope = Envelope {
        v: "2",
        eng: concat!("isomer/", env!("CARGO_PKG_VERSION")),
        verb: analysis.verb,
        artifact: (!analysis.naming.name.is_empty()).then_some(analysis.naming.name.as_str()),
        version: Version {
            old: analysis.naming.old.as_ref().map(|v| v.raw.as_str()),
            new: analysis.naming.new.as_ref().map(|v| v.raw.as_str()),
            bump: analysis.naming.bump.map(|b| b.kind),
        },
        provenance: Provenance {
            old: provenance.0,
            new: provenance.1,
        },
        verdict: Verdict {
            severity: analysis.verdict,
            new_severity: analysis.new_verdict,
            gate: Gate {
                on: analysis.gate(),
                fail_on: analysis.fail_on(),
                severity: analysis.gated(),
                fail: !analysis.clean(),
            },
            risk: analysis.shown_risk().map(|r| Risk {
                old: r.old,
                new: r.new,
                delta: r.delta(),
                new_classification: r.new_classification.to_string(),
                model: if analysis.risk_llm_raised() {
                    "azoth+llm"
                } else {
                    "azoth"
                },
            }),
            proportionality: Prop {
                disproportionate: analysis.prop.drift.is_disproportionate(),
                note: analysis.prop.drift.note(),
                skew: analysis.prop.skew.as_deref(),
            },
            behavioral: Behavioral {
                severity: a.behavioral.severity(),
                categories,
            },
            signature: Signature {
                severity: a.signature.severity(),
                cve: a.signature.cve.as_deref(),
                count: a.signature.ids.len(),
                ids: sig_ids,
            },
            identity: Identity {
                severity: a.identity.severity(),
                changes,
            },
            frameworks: Frameworks {
                attack: Ids {
                    new: analysis.survey.attack.gained(),
                    removed: analysis.survey.attack.lost(),
                    unchanged: analysis.survey.attack.kept(),
                },
                mbc: Ids {
                    new: analysis.survey.mbc.gained(),
                    removed: analysis.survey.mbc.lost(),
                    unchanged: analysis.survey.mbc.kept(),
                },
            },
            structure: Structure {
                severity: a.structure.severity(),
                facts,
            },
            behavior_mass: BehaviorMass {
                severity: analysis.behavior_mass,
                mass: analysis.shift.injected_mass(),
                share: analysis.shift.injected_share(),
                ids_gained: analysis.shift.injected_ids(),
                id_share: analysis.shift.injected_id_share(),
            },
        },
        features,
        evidence,
        deps: analysis
            .deps
            .iter()
            .map(|d| Dep {
                profile: &d.risk,
                baseline_profile: d.baseline_risk.as_ref(),
                coord: &d.coord,
                ecosystem: d.ecosystem,
                severity: d.severity,
                highlights: &d.highlights,
                note: d.note.as_deref(),
                baseline: d.baseline.as_deref(),
                new_severity: d.new_severity,
                comparison: &d.comparison,
            })
            .collect(),
        llm: analysis.interp.as_ref().map(|i| Llm {
            nature: &i.nature,
            verdict: &i.verdict,
            model: &i.model,
        }),
        raw: analysis.report,
        registry: &analysis.registry,
    };
    Ok(serde_json::to_string(&envelope)?)
}

/// Convert Cleave's complete judged differential into a compact, stable
/// feature record. This intentionally has no display cap: terminal rendering
/// is the only consumer allowed to discard low-importance rows.
pub(crate) fn feature_set(diff: &DiffReportV1) -> FeatureSet<'_> {
    let summary = &diff.summary;
    let compared = summary.files_added
        + summary.files_removed
        + summary.files_changed
        + summary.files_unchanged;
    FeatureSet {
        judged_summary: diff.summary.clone(),
        trait_shift: None,
        v: "1",
        topology: Topology {
            added: summary.files_added,
            removed: summary.files_removed,
            changed: summary.files_changed,
            unchanged: summary.files_unchanged,
            compared,
        },
        scopes: feature_scopes(&diff.scopes),
        files: diff.files.iter().map(file_features).collect(),
    }
}

fn feature_scopes(scopes: &ScopeDiffs) -> FeatureScopes {
    FeatureScopes {
        traits: scopes.traits.as_ref().map(scope_stats),
        metrics: scopes.metrics.as_ref().map(scope_stats),
        facts: scopes.kv.as_ref().map(scope_stats),
        symbols: scopes.symbols.as_ref().map(scope_stats),
        strings: scopes.strings.as_ref().map(scope_stats),
        sections: scopes.sections.as_ref().map(scope_stats),
    }
}

fn scope_stats<T>(scope: &ScopeDiff<T>) -> ScopeStats {
    ScopeStats {
        added: scope.added.len(),
        removed: scope.removed.len(),
        changed: scope.changed.len(),
        old_count: scope.old_count,
        new_count: scope.new_count,
        old_weight: scope.old_weight,
        new_weight: scope.new_weight,
        change_weight: scope.change_weight,
        roc: scope.roc,
        truncated: scope.truncated,
    }
}

fn file_features(file: &FileDiffEntry) -> FileFeatures<'_> {
    FileFeatures {
        path: &file.path,
        file_type: file.file_type.as_deref(),
        status: file.status,
        archive_depth: crate::member::MemberPath::new(&file.path).depth(),
        identity_changed: file.identity.as_ref().is_some_and(|id| id.changed),
        scopes: feature_scopes(&file.scopes),
        traits: trait_features(file.scopes.traits.as_ref()),
        metrics: metric_features(file.scopes.metrics.as_ref()),
        facts: fact_features(file.scopes.kv.as_ref()),
        sections: section_features(file.scopes.sections.as_ref()),
    }
}

fn trait_side(t: &TraitChange) -> TraitSide<'_> {
    TraitSide {
        criticality: t.crit,
        confidence: t.conf,
        score: crate::rubric::importance(t.crit, t.conf),
        count: t.count,
        description: &t.desc,
    }
}

fn trait_features(scope: Option<&ScopeDiff<TraitChange>>) -> Vec<TraitDelta<'_>> {
    use TraitDelta;

    let Some(scope) = scope else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(scope.added.len() + scope.removed.len() + scope.changed.len());
    out.extend(scope.added.iter().map(|t| TraitDelta {
        id: &t.id,
        change: Change::Added,
        old: None,
        new: Some(trait_side(t)),
    }));
    out.extend(scope.removed.iter().map(|t| TraitDelta {
        id: &t.id,
        change: Change::Removed,
        old: Some(trait_side(t)),
        new: None,
    }));
    out.extend(scope.changed.iter().map(|t| TraitDelta {
        id: &t.new.id,
        change: Change::Changed,
        old: Some(trait_side(&t.old)),
        new: Some(trait_side(&t.new)),
    }));
    out
}

/// How far a numeric value moved, three ways.
#[derive(Debug, PartialEq)]
struct NumericDelta {
    /// Signed change; an addition counts from zero, a removal to zero.
    delta: Option<f64>,
    absolute: Option<f64>,
    /// Signed change relative to `abs(old)`; undefined from zero.
    relative: Option<f64>,
}

fn numeric_delta(old: Option<f64>, new: Option<f64>) -> NumericDelta {
    let delta = match (old, new) {
        (Some(old), Some(new)) => Some(new - old),
        (None, Some(new)) => Some(new),
        (Some(old), None) => Some(-old),
        (None, None) => None,
    };
    NumericDelta {
        delta,
        absolute: delta.map(f64::abs),
        relative: match (old, new) {
            (Some(old), Some(new)) if old != 0.0 => Some((new - old) / old.abs()),
            _ => None,
        },
    }
}

fn value_delta<'a>(
    path: &'a str,
    change: Change,
    old: Option<&'a serde_json::Value>,
    new: Option<&'a serde_json::Value>,
) -> ValueDelta<'a> {
    let moved = numeric_delta(
        old.and_then(serde_json::Value::as_f64),
        new.and_then(serde_json::Value::as_f64),
    );
    ValueDelta {
        path,
        change,
        old,
        new,
        delta: moved.delta,
        absolute_delta: moved.absolute,
        relative_delta: moved.relative,
    }
}

fn metric_features(scope: Option<&ScopeDiff<MetricChange>>) -> Vec<ValueDelta<'_>> {
    let Some(scope) = scope else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(scope.added.len() + scope.removed.len() + scope.changed.len());
    out.extend(
        scope
            .added
            .iter()
            .map(|m| value_delta(&m.path, Change::Added, None, Some(&m.value))),
    );
    out.extend(
        scope
            .removed
            .iter()
            .map(|m| value_delta(&m.path, Change::Removed, Some(&m.value), None)),
    );
    out.extend(scope.changed.iter().map(|m| {
        value_delta(
            &m.new.path,
            Change::Changed,
            Some(&m.old.value),
            Some(&m.new.value),
        )
    }));
    out
}

fn fact_features(scope: Option<&ScopeDiff<KvChange>>) -> Vec<FactDelta<'_>> {
    use FactDelta;

    let Some(scope) = scope else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(scope.added.len() + scope.removed.len() + scope.changed.len());
    out.extend(scope.added.iter().map(|f| FactDelta {
        path: &f.path,
        namespace: &f.namespace,
        change: Change::Added,
        old: None,
        new: Some(&f.value),
    }));
    out.extend(scope.removed.iter().map(|f| FactDelta {
        path: &f.path,
        namespace: &f.namespace,
        change: Change::Removed,
        old: Some(&f.value),
        new: None,
    }));
    out.extend(scope.changed.iter().map(|f| FactDelta {
        path: &f.new.path,
        namespace: &f.new.namespace,
        change: Change::Changed,
        old: Some(&f.old.value),
        new: Some(&f.new.value),
    }));
    out
}

fn section_side(s: &SectionChange) -> SectionSide<'_> {
    SectionSide {
        size: s.size,
        entropy: s.entropy,
        permissions: s.permissions.as_deref(),
    }
}

fn section_features(scope: Option<&ScopeDiff<SectionChange>>) -> Vec<SectionDelta<'_>> {
    use SectionDelta;

    let Some(scope) = scope else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(scope.added.len() + scope.removed.len() + scope.changed.len());
    out.extend(scope.added.iter().map(|s| SectionDelta {
        name: &s.name,
        change: Change::Added,
        old: None,
        new: Some(section_side(s)),
        size_delta: Some(i128::from(s.size)),
        entropy_delta: None,
    }));
    out.extend(scope.removed.iter().map(|s| SectionDelta {
        name: &s.name,
        change: Change::Removed,
        old: Some(section_side(s)),
        new: None,
        size_delta: Some(-i128::from(s.size)),
        entropy_delta: None,
    }));
    out.extend(scope.changed.iter().map(|s| SectionDelta {
        name: &s.new.name,
        change: Change::Changed,
        old: Some(section_side(&s.old)),
        new: Some(section_side(&s.new)),
        size_delta: Some(i128::from(s.new.size) - i128::from(s.old.size)),
        entropy_delta: Some(s.new.entropy - s.old.entropy),
    }));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_feature_deltas_are_signed_and_safe_at_zero() {
        assert_eq!(
            numeric_delta(Some(10.0), Some(15.0)),
            NumericDelta {
                delta: Some(5.0),
                absolute: Some(5.0),
                relative: Some(0.5)
            }
        );
        assert_eq!(
            numeric_delta(None, Some(15.0)),
            NumericDelta {
                delta: Some(15.0),
                absolute: Some(15.0),
                relative: None
            }
        );
        assert_eq!(
            numeric_delta(Some(15.0), None),
            NumericDelta {
                delta: Some(-15.0),
                absolute: Some(15.0),
                relative: None
            }
        );
        assert_eq!(
            numeric_delta(Some(0.0), Some(2.0)),
            NumericDelta {
                delta: Some(2.0),
                absolute: Some(2.0),
                relative: None
            }
        );
    }
}
