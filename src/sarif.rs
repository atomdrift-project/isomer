//! `--format sarif` — SARIF 2.1.0 for GitHub code scanning.
//!
//! SARIF is what turns a verdict into an annotation on the exact line of the
//! pull request that introduced it, plus a tracked record in the Security tab.
//! Emitting it is why the action needs no UI code of its own.
//!
//! The mapping is deliberate. isomer is differential, so a *finding* here is a
//! change — a capability class the artifact gained, a known-bad rule that newly
//! matched, a publisher that drifted, a structural anomaly that appeared — not
//! a static property of the code. Each finding is anchored to the bytes that
//! prove it when evidence exists, and to the changed file otherwise; a finding
//! with no honest location is reported at the file rather than invented
//! somewhere precise-looking.

use anyhow::Result;
use serde_json::{Value, json};

use crate::Severity;
use crate::analysis::Analysis;

/// One SARIF result before it is indexed against the rule table.
struct Finding {
    /// Stable rule id, e.g. `isomer/capability/execution-hijack`.
    rule: String,
    /// Human rule name for the Security-tab list.
    name: String,
    severity: Severity,
    /// What happened, in one sentence.
    message: String,
    /// Longer guidance shown on the alert page.
    help: String,
    /// Trait ids this finding covers, used to locate its evidence.
    ids: Vec<String>,
    /// Namespace prefixes to fall back on when no evidence hunk carries one of
    /// `ids` exactly — a composite rule often owns the window that proves a
    /// trait underneath it.
    hints: Vec<String>,
    tags: Vec<String>,
}

/// Render the analysis as a SARIF 2.1.0 log.
pub(crate) fn report(a: &Analysis<'_>) -> Result<String> {
    let mut findings = findings(a);
    // Newly-introduced technique ids ride along as tags on every rule this
    // change produced. Code scanning surfaces tags as filters, so an analyst
    // can pivot from an alert to the technique without isomer needing a
    // catalog of its own.
    let techniques: Vec<String> = a
        .survey
        .attack
        .gained()
        .iter()
        .map(|id| format!("attack/{id}"))
        .chain(a.survey.mbc.gained().iter().map(|id| format!("mbc/{id}")))
        .collect();
    for f in &mut findings {
        f.tags.extend(techniques.iter().cloned());
    }
    let hunks = a.hunks(EVIDENCE_CAP);

    let mut rules: Vec<Value> = Vec::new();
    let mut results: Vec<Value> = Vec::new();
    for f in &findings {
        // One rule per distinct id; results carry the index back to it.
        let index = match rules.iter().position(|r| r["id"] == json!(f.rule)) {
            Some(i) => i,
            None => {
                rules.push(json!({
                    "id": f.rule,
                    "name": f.name,
                    "shortDescription": {"text": f.name},
                    "fullDescription": {"text": f.help},
                    "help": {"text": f.help, "markdown": f.help},
                    "defaultConfiguration": {"level": level(f.severity)},
                    "properties": {
                        "tags": f.tags,
                        "problem.severity": problem_severity(f.severity),
                        "security-severity": security_severity(f.severity),
                    },
                }));
                rules.len() - 1
            }
        };
        results.push(json!({
            "ruleId": f.rule,
            "ruleIndex": index,
            "level": level(f.severity),
            "message": {"text": f.message},
            "locations": [locate(a, &hunks, f)],
            "partialFingerprints": {"isomerFindingV1": fingerprint(&f.rule, &f.ids)},
        }));
    }

    let log = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "isomer",
                "semanticVersion": env!("CARGO_PKG_VERSION"),
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/atomdrift-project/isomer",
                "rules": rules,
            }},
            // A clean run still uploads: code scanning resolves alerts that no
            // longer appear, so an empty result set is how a fixed finding
            // gets closed.
            "results": results,
            "invocations": [{"executionSuccessful": true}],
        }],
    });
    Ok(serde_json::to_string_pretty(&log)?)
}

/// Evidence hunks fetched for locating findings. Generous: every finding wants
/// its own anchor, and hunks are already computed once and cached.
const EVIDENCE_CAP: usize = 24;

/// Turn the assessment into one finding per changed thing.
fn findings(a: &Analysis<'_>) -> Vec<Finding> {
    let mut out = Vec::new();
    let assessment = &a.assessment;

    for c in &assessment.behavioral.categories {
        let fresh = assessment.behavioral.is_new_category(c);
        let verb = if fresh { "gained" } else { "expanded" };
        let mut ids = c.new_ids.clone();
        ids.extend(c.escalated_ids.iter().cloned());
        out.push(Finding {
            rule: format!("isomer/capability/{}", c.class),
            name: format!("Gained capability: {}", c.label),
            severity: c.severity,
            message: format!(
                "{} {} — {} ({}){}",
                a.naming.name,
                verb,
                c.label,
                c.namespaces.join(", "),
                a.prop
                    .note
                    .as_ref()
                    .filter(|_| a.prop.disproportionate)
                    .map(|n| format!(". {n}"))
                    .unwrap_or_default(),
            ),
            help: format!(
                "The new version exhibits `{}` behavior that the base version did not. \
                 isomer judges capability drift against the size of the change: a small \
                 version bump that gains an execution, network, or exfiltration primitive \
                 is the shape of a supply-chain compromise. Suppress with an `[[allow]]` \
                 entry in `.isomer.toml` if this capability is expected.",
                c.class
            ),
            ids,
            hints: c.namespaces.clone(),
            tags: vec![
                "security".into(),
                "supply-chain".into(),
                format!("capability/{}", c.class),
            ],
        });
    }

    for m in &assessment.signature.ids {
        let name = crate::rubric::short_name(&m.id);
        out.push(Finding {
            rule: format!("isomer/signature/{name}"),
            name: format!("Known-bad rule matched: {name}"),
            severity: m.severity,
            message: if m.desc.is_empty() {
                format!("{} matches known-bad rule {name}", a.naming.name)
            } else {
                format!(
                    "{} matches known-bad rule {name} — {}",
                    a.naming.name, m.desc
                )
            },
            help: format!(
                "A known-malicious detection rule matched content that is {} in this change.{}",
                if m.is_new { "new" } else { "escalated" },
                assessment
                    .signature
                    .cve
                    .as_ref()
                    .map(|c| format!(" Referenced vulnerability: {c}."))
                    .unwrap_or_default(),
            ),
            ids: vec![m.id.clone()],
            hints: Vec::new(),
            tags: vec!["security".into(), "supply-chain".into(), "malware".into()],
        });
    }

    for ch in &assessment.identity.changes {
        let old = if ch.old.is_empty() { "none" } else { &ch.old };
        let new = if ch.new.is_empty() { "none" } else { &ch.new };
        out.push(Finding {
            rule: "isomer/identity".into(),
            name: "Publisher identity drift".into(),
            severity: assessment.identity.severity,
            message: format!("{} changed: {old} → {new}", ch.label),
            help: "The party that signed or published this artifact changed. A new signer on \
                   an established package is how an account takeover first shows up in the \
                   artifact itself."
                .into(),
            ids: Vec::new(),
            hints: Vec::new(),
            tags: vec![
                "security".into(),
                "supply-chain".into(),
                "provenance".into(),
            ],
        });
    }

    for f in &assessment.structure.facts {
        let kind = match f.kind {
            crate::rubric::FactKind::Added => "gained",
            crate::rubric::FactKind::Became => "altered",
        };
        out.push(Finding {
            rule: format!("isomer/{}", crate::rubric::structure_id(f.label)),
            name: format!("Structural change: {}", f.label),
            severity: f.severity,
            message: format!("{} {kind} {} — {}", a.naming.name, f.label, f.detail),
            help: "A raw structural property of the binary changed — a linked dependency, an \
                   ifunc resolver, a writable+executable section. These are facts read from \
                   the file format rather than rule matches, so they catch a novel attack that \
                   no signature covers."
                .into(),
            ids: Vec::new(),
            hints: Vec::new(),
            tags: vec!["security".into(), "supply-chain".into(), "structure".into()],
        });
    }

    // Worst first, so the Security tab's default ordering is the triage order.
    out.sort_by_key(|f| std::cmp::Reverse(f.severity));
    out
}

/// The best honest location for a finding.
///
/// In order: the evidence hunk proving one of its trait ids exactly; a hunk
/// under one of its namespaces; the strongest hunk in the change. A finding
/// with no trait ids at all (publisher drift, a structural fact) is a property
/// of the change rather than of a line, so it lands on the first changed file
/// with no region — better an imprecise location than a precise fiction.
fn locate(a: &Analysis<'_>, hunks: &[&crate::evidence::Hunk], f: &Finding) -> Value {
    let anchor = (!f.ids.is_empty() || !f.hints.is_empty())
        .then(|| {
            hunks
                .iter()
                .find(|h| f.ids.iter().any(|id| id == &h.id))
                .or_else(|| {
                    hunks
                        .iter()
                        .find(|h| f.hints.iter().any(|ns| h.id.contains(ns.as_str())))
                })
                // Still nothing: the strongest evidence in the change is a
                // better pointer than an arbitrary file.
                .or_else(|| hunks.first())
        })
        .flatten();
    if let Some(h) = anchor {
        let mut physical = json!({
            "artifactLocation": {"uri": uri(&h.file)},
        });
        if let Some(line) = h.line {
            physical["region"] = json!({"startLine": line});
        }
        let mut loc = json!({"physicalLocation": physical});
        if let Some(member) = &h.member {
            // Name the archive member in a logical location — the physical
            // file is the container, and pointing a line number inside a
            // tarball at the repo would be a lie.
            loc["logicalLocations"] = json!([{"name": member, "kind": "member"}]);
        }
        return loc;
    }
    let file = a
        .pairs
        .first()
        .map(|p| p.label.clone())
        .unwrap_or_else(|| a.naming.name.clone());
    json!({"physicalLocation": {"artifactLocation": {"uri": uri(&file)}}})
}

/// A SARIF artifact URI: repo-relative, forward slashes, no `./` prefix.
fn uri(path: &str) -> String {
    let p = path.replace('\\', "/");
    let p = p.strip_prefix("./").unwrap_or(&p);
    p.trim_start_matches('/').to_string()
}

/// SARIF result levels. GitHub renders `error` as a failing annotation.
fn level(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::None => "note",
    }
}

fn problem_severity(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::None => "recommendation",
    }
}

/// GitHub maps this 0–10 score onto its own critical/high/medium/low chips.
fn security_severity(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "9.5",
        Severity::High => "7.5",
        Severity::Medium => "5.0",
        Severity::Low => "2.0",
        Severity::None => "0.0",
    }
}

/// A stable identifier for one finding across runs, so code scanning tracks an
/// alert rather than closing and reopening it as lines move. FNV-1a: tiny,
/// dependency-free, and — unlike a stdlib hasher — guaranteed to produce the
/// same value in every future build.
fn fingerprint(rule: &str, ids: &[String]) -> String {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x100_0000_01b3;
    let mut h = OFFSET;
    let mut eat = |s: &str| {
        for b in s.bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(PRIME);
        }
    };
    eat(rule);
    // Sorted, so a reordered trait list is the same finding.
    let mut sorted: Vec<&str> = ids.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    for id in sorted {
        eat("\0");
        eat(id);
    }
    format!("{h:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_order_independent_and_stable() {
        let a = fingerprint("isomer/capability/C2", &["b".into(), "a".into()]);
        let b = fingerprint("isomer/capability/C2", &["a".into(), "b".into()]);
        assert_eq!(a, b, "id order must not change the fingerprint");
        assert_ne!(
            a,
            fingerprint("isomer/capability/network", &["a".into(), "b".into()])
        );
        // Pinned: the value is a wire contract with code scanning's alert
        // tracking, so a refactor must not silently change it.
        assert_eq!(fingerprint("r", &[]), "af63ef4c86020cd5");
    }

    #[test]
    fn uris_are_repo_relative() {
        assert_eq!(uri("./src/a.js"), "src/a.js");
        assert_eq!(uri("/src/a.js"), "src/a.js");
        assert_eq!(uri("src\\a.js"), "src/a.js");
    }

    /// Structural rule ids are stable strings: GitHub tracks a Security-tab
    /// alert by rule id, so changing one silently reopens every alert.
    #[test]
    fn structure_rule_ids_are_stable() {
        assert_eq!(
            crate::rubric::structure_id("loader dependency"),
            "structure/loader-dependency"
        );
        assert_eq!(
            crate::rubric::structure_id("writable+executable"),
            "structure/writable-executable"
        );
    }
}
