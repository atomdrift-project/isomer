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
//! These are wire structs only; `fs::json` maps the domain types onto them.

use serde::Serialize;

/// Top-level envelope. Generic over the raw report so this module stays
/// decoupled from cleave's diff types.
#[derive(Serialize)]
pub(crate) struct Envelope<'a, R: Serialize> {
    /// Envelope schema version.
    pub v: &'static str,
    /// Producing engine, `isomer/<pkg-version>` (mirrors scan's `eng`).
    pub eng: &'static str,
    /// The isomer surface that produced this report, e.g. `fs`.
    pub verb: &'static str,
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
    pub status: &'static str,
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
    pub change: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old: Option<TraitSide<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new: Option<TraitSide<'a>>,
}

#[derive(Serialize)]
pub(crate) struct TraitSide<'a> {
    pub criticality: &'static str,
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
    pub change: &'static str,
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
    pub change: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old: Option<&'a serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new: Option<&'a serde_json::Value>,
}

#[derive(Serialize)]
pub(crate) struct SectionDelta<'a> {
    pub name: &'a str,
    pub change: &'static str,
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
    /// The declared coordinate, `peacenotwar@^9.1.3`.
    pub coord: &'a str,
    pub ecosystem: &'a str,
    /// Worst severity found in the fetched dependency.
    pub severity: &'static str,
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
    /// The top rule's severity word.
    pub severity: &'a str,
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
    pub bump: Option<&'static str>,
}

#[derive(Serialize)]
pub(crate) struct Verdict<'a> {
    /// Overall severity (rubric ∪ current ML risk): the "how bad is it now" axis.
    pub severity: &'static str,
    /// Change-only severity (newly-introduced risk ∪ an ML-risk jump): the axis
    /// the default `--gate new` acts on.
    pub new_severity: &'static str,
    pub gate: Gate,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk: Option<Risk>,
    pub proportionality: Prop<'a>,
    pub behavioral: Behavioral<'a>,
    pub signature: Signature<'a>,
    pub identity: Identity<'a>,
    pub structure: Structure<'a>,
    /// MITRE ATT&CK and MBC ids the change moved. Ids only — isomer ships no
    /// catalog mapping them to prose, and a consumer that has one can join on
    /// these.
    pub frameworks: Frameworks<'a>,
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
    pub on: &'static str,
    /// The `--fail-on` threshold.
    pub fail_on: &'static str,
    /// The severity actually compared against the threshold.
    pub severity: &'static str,
    /// `true` when the run exits non-zero.
    pub fail: bool,
}

#[derive(Serialize)]
pub(crate) struct Risk {
    pub old: f32,
    pub new: f32,
    pub delta: f32,
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
    pub severity: &'static str,
    pub categories: Vec<Category<'a>>,
}

#[derive(Serialize)]
pub(crate) struct Category<'a> {
    /// Kebab class key, e.g. `execution-hijack`.
    pub class: &'a str,
    pub label: &'a str,
    pub severity: &'static str,
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
    pub severity: &'static str,
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
    /// Per-signature severity word.
    pub crit: &'static str,
    /// Absent on the old side (vs an escalation of an existing match).
    pub new: bool,
}

#[derive(Serialize)]
pub(crate) struct Identity<'a> {
    pub severity: &'static str,
    pub changes: Vec<IdChange<'a>>,
}

#[derive(Serialize)]
pub(crate) struct IdChange<'a> {
    pub field: &'static str,
    pub old: &'a str,
    pub new: &'a str,
}

#[derive(Serialize)]
pub(crate) struct Structure<'a> {
    pub severity: &'static str,
    pub facts: Vec<Fact<'a>>,
}

#[derive(Serialize)]
pub(crate) struct Fact<'a> {
    pub severity: &'static str,
    /// `added` for newly-present structure, `became` for existing structure
    /// altered in place.
    pub change: &'static str,
    pub label: &'static str,
    pub detail: &'a str,
}

#[derive(Serialize)]
pub(crate) struct Llm<'a> {
    pub nature: &'a str,
    pub verdict: &'a str,
    pub model: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The envelope serializes in declaration order (verdict before the bulky
    /// raw), omits absent optionals, and states the gate decision outright.
    #[test]
    fn envelope_shape_is_stable() {
        let raw = serde_json::json!({"diff": "…"});
        let env = Envelope::<'_, serde_json::Value> {
            v: "2",
            eng: "isomer/test",
            verb: "fs",
            artifact: Some("liblzma.so"),
            version: Version {
                old: Some("5.4.5"),
                new: Some("5.6.0"),
                bump: Some("minor"),
            },
            provenance: Provenance {
                old: None,
                new: None,
            },
            verdict: Verdict {
                severity: "critical",
                new_severity: "critical",
                gate: Gate {
                    on: "new",
                    fail_on: "high",
                    severity: "critical",
                    fail: true,
                },
                risk: Some(Risk {
                    old: 0.1,
                    new: 0.98,
                    delta: 0.88,
                    model: "azoth",
                }),
                proportionality: Prop {
                    disproportionate: true,
                    note: None,
                    skew: None,
                },
                behavioral: Behavioral {
                    severity: "high",
                    categories: Vec::new(),
                },
                signature: Signature {
                    severity: "none",
                    cve: None,
                    count: 0,
                    ids: Vec::new(),
                },
                identity: Identity {
                    severity: "none",
                    changes: Vec::new(),
                },
                frameworks: Frameworks {
                    attack: Ids {
                        new: vec!["T1055"],
                        removed: Vec::new(),
                        unchanged: 2,
                    },
                    mbc: Ids {
                        new: Vec::new(),
                        removed: Vec::new(),
                        unchanged: 0,
                    },
                },
                structure: Structure {
                    severity: "high",
                    facts: Vec::new(),
                },
            },
            features: FeatureSet {
                v: "1",
                topology: Topology {
                    added: 0,
                    removed: 0,
                    changed: 1,
                    unchanged: 0,
                    compared: 1,
                },
                scopes: FeatureScopes {
                    traits: None,
                    metrics: None,
                    facts: None,
                    symbols: None,
                    strings: None,
                    sections: None,
                },
                files: Vec::new(),
            },
            evidence: Vec::new(),
            deps: Vec::new(),
            llm: None,
            raw: &raw,
        };
        let s = serde_json::to_string(&env).unwrap();
        // Field order: verdict and its proof precede the bulky raw diff.
        let order = [
            "\"v\"",
            "\"verdict\"",
            "\"features\"",
            "\"evidence\"",
            "\"raw\"",
        ];
        for k in order {
            assert!(s.contains(k), "missing {k}");
        }
        let pos: Vec<usize> = order.iter().map(|k| s.find(k).unwrap()).collect();
        assert!(pos.windows(2).all(|w| w[0] < w[1]), "keys out of order");
        // Absent optionals are omitted, not null.
        assert!(!s.contains("\"llm\""), "llm must be omitted when None");
        assert!(!s.contains("\"note\""), "note must be omitted when None");
        // The gate decision is present and explicit.
        assert!(
            s.contains(r#""gate":{"on":"new","fail_on":"high","severity":"critical","fail":true}"#)
        );
    }
}
