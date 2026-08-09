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
    /// The proof behind the verdict: context windows for the gained traits, in
    /// file order (locator · code · description). Present so the UI and a cache
    /// can render the evidence table without re-reading the artifact.
    pub evidence: Vec<Ev<'a>>,
    /// Optional `--llm` interpretation (mirrors scan's `llm`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm: Option<Llm<'a>>,
    /// The complete underlying cleave diff — every scope and per-file delta the
    /// curated sections were distilled from (scan's `raw`). Kept last so a human
    /// reading top-down meets the verdict before the bulk, and so a consumer
    /// (prism, the CLI cache) can regenerate anything the curated view omits.
    pub raw: &'a R,
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

/// One evidence window — a matched region rendered as `locator · code · desc`.
#[derive(Serialize)]
pub(crate) struct Ev<'a> {
    /// Archive member the window came from, when the artifact is a container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member: Option<&'a str>,
    pub locator: &'a str,
    pub code: &'a str,
    pub desc: &'a str,
    pub hostile: bool,
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
            v: "1",
            eng: "isomer/test",
            verb: "fs",
            artifact: Some("liblzma.so"),
            version: Version { old: Some("5.4.5"), new: Some("5.6.0"), bump: Some("minor") },
            provenance: Provenance { old: None, new: None },
            verdict: Verdict {
                severity: "critical",
                new_severity: "critical",
                gate: Gate { on: "new", fail_on: "high", severity: "critical", fail: true },
                risk: Some(Risk { old: 0.1, new: 0.98, delta: 0.88, model: "azoth" }),
                proportionality: Prop { disproportionate: true, note: None },
                behavioral: Behavioral { severity: "high", categories: Vec::new() },
                signature: Signature { severity: "none", cve: None, count: 0, ids: Vec::new() },
                identity: Identity { severity: "none", changes: Vec::new() },
                structure: Structure { severity: "high", facts: Vec::new() },
            },
            evidence: Vec::new(),
            llm: None,
            raw: &raw,
        };
        let s = serde_json::to_string(&env).unwrap();
        // Field order: verdict and its proof precede the bulky raw diff.
        let order = ["\"v\"", "\"verdict\"", "\"evidence\"", "\"raw\""];
        for k in order {
            assert!(s.contains(k), "missing {k}");
        }
        let pos: Vec<usize> = order.iter().map(|k| s.find(k).unwrap()).collect();
        assert!(pos.windows(2).all(|w| w[0] < w[1]), "keys out of order");
        // Absent optionals are omitted, not null.
        assert!(!s.contains("\"llm\""), "llm must be omitted when None");
        assert!(!s.contains("\"note\""), "note must be omitted when None");
        // The gate decision is present and explicit.
        assert!(s.contains(r#""gate":{"on":"new","fail_on":"high","severity":"critical","fail":true}"#));
    }
}
