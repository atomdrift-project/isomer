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
//!
//! The log is a typed model serialized by serde, not a `json!` tree: a field
//! name typo is a compile error rather than an alert GitHub silently ignores,
//! and there is no `Value` indexing to panic on.

use std::collections::HashMap;

use anyhow::Result;
use serde::Serialize;

use crate::Severity;
use crate::analysis::Analysis;
use crate::taxonomy::{TraitId, under};

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
    /// What tells this finding apart from another under the same rule when it
    /// has no trait ids: the identity field and its two values, or the
    /// structural fact's subject and detail. Without it every publisher drift
    /// in a run shared one fingerprint, and code scanning merged them into a
    /// single alert.
    distinct: Vec<String>,
    tags: Vec<String>,
}

#[derive(Serialize)]
struct Log<'a> {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: [Run<'a>; 1],
}

#[derive(Serialize)]
struct Run<'a> {
    tool: Tool<'a>,
    /// A clean run still uploads: code scanning resolves alerts that no longer
    /// appear, so an empty result set is how a fixed finding gets closed.
    results: Vec<SarifResult<'a>>,
    invocations: [Invocation; 1],
}

#[derive(Serialize)]
struct Tool<'a> {
    driver: Driver<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Driver<'a> {
    name: &'static str,
    semantic_version: &'static str,
    version: &'static str,
    information_uri: &'static str,
    rules: Vec<Rule<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Rule<'a> {
    id: &'a str,
    name: &'a str,
    short_description: Text<'a>,
    full_description: Text<'a>,
    help: Help<'a>,
    default_configuration: Configuration,
    properties: RuleProperties<'a>,
}

#[derive(Serialize)]
struct Text<'a> {
    text: &'a str,
}

#[derive(Serialize)]
struct Help<'a> {
    text: &'a str,
    markdown: &'a str,
}

#[derive(Serialize)]
struct Configuration {
    level: &'static str,
}

#[derive(Serialize)]
struct RuleProperties<'a> {
    tags: &'a [String],
    /// GitHub's own vocabulary: the same three tiers as `level`, except that
    /// its lowest is a recommendation.
    #[serde(rename = "problem.severity")]
    problem_severity: &'static str,
    #[serde(rename = "security-severity")]
    security_severity: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult<'a> {
    rule_id: &'a str,
    rule_index: usize,
    level: &'static str,
    message: Text<'a>,
    locations: [Location<'a>; 1],
    partial_fingerprints: Fingerprints,
}

#[derive(Serialize)]
struct Fingerprints {
    #[serde(rename = "isomerFindingV1")]
    isomer_finding_v1: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Location<'a> {
    physical_location: PhysicalLocation,
    /// The archive member, when the physical file is its container: pointing
    /// a line number inside a tarball at the repo would be a lie.
    #[serde(skip_serializing_if = "Option::is_none")]
    logical_locations: Option<[LogicalLocation<'a>; 1]>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PhysicalLocation {
    artifact_location: ArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<Region>,
}

#[derive(Serialize)]
struct ArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Region {
    start_line: u64,
}

#[derive(Serialize)]
struct LogicalLocation<'a> {
    name: &'a str,
    kind: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Invocation {
    execution_successful: bool,
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
    let fallback_file = a
        .pairs
        .first()
        .map_or(a.naming.name.as_str(), |p| p.label.as_str());

    let mut rules: Vec<Rule<'_>> = Vec::new();
    let mut rule_index: HashMap<&str, usize> = HashMap::new();
    let mut results = Vec::with_capacity(findings.len());
    for f in &findings {
        // One rule per distinct id; results carry the index back to it.
        let index = *rule_index.entry(f.rule.as_str()).or_insert_with(|| {
            rules.push(Rule {
                id: &f.rule,
                name: &f.name,
                short_description: Text { text: &f.name },
                full_description: Text { text: &f.help },
                help: Help {
                    text: &f.help,
                    markdown: &f.help,
                },
                default_configuration: Configuration {
                    level: level(f.severity),
                },
                properties: RuleProperties {
                    tags: &f.tags,
                    problem_severity: problem_severity(f.severity),
                    security_severity: security_severity(f.severity),
                },
            });
            rules.len() - 1
        });
        results.push(SarifResult {
            rule_id: &f.rule,
            rule_index: index,
            level: level(f.severity),
            message: Text { text: &f.message },
            locations: [locate(&hunks, f, fallback_file)],
            partial_fingerprints: Fingerprints {
                isomer_finding_v1: fingerprint(&f.rule, &f.ids, &f.distinct),
            },
        });
    }

    let log = Log {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: [Run {
            tool: Tool {
                driver: Driver {
                    name: "isomer",
                    semantic_version: crate::VERSION,
                    version: crate::VERSION,
                    information_uri: "https://github.com/atomdrift-project/isomer",
                    rules,
                },
            },
            results,
            invocations: [Invocation {
                execution_successful: true,
            }],
        }],
    };
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
                    .drift
                    .escalation_note()
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
            distinct: Vec::new(),
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
            distinct: Vec::new(),
            tags: vec!["security".into(), "supply-chain".into(), "malware".into()],
        });
    }

    for ch in &assessment.identity.changes {
        let (old, new) = ch.shown();
        out.push(Finding {
            rule: "isomer/identity".into(),
            name: "Publisher identity drift".into(),
            severity: assessment.identity.severity(),
            message: format!("{} changed: {old} → {new}", ch.label),
            help: "The party that signed or published this artifact changed. A new signer on \
                   an established package is how an account takeover first shows up in the \
                   artifact itself."
                .into(),
            ids: Vec::new(),
            hints: Vec::new(),
            distinct: vec![ch.label.as_str().to_owned(), old.to_owned(), new.to_owned()],
            tags: vec![
                "security".into(),
                "supply-chain".into(),
                "provenance".into(),
            ],
        });
    }

    for f in &assessment.structure.facts {
        let kind = f.kind.as_str();
        out.push(Finding {
            rule: format!("isomer/{}", f.label.rule_id()),
            name: format!("Structural change: {}", f.label),
            severity: f.severity,
            message: format!("{} {kind} {} — {}", a.naming.name, f.label, f.sentence()),
            help: "A raw structural property of the binary changed — a linked dependency, an \
                   ifunc resolver, a writable+executable section. These are facts read from \
                   the file format rather than rule matches, so they catch a novel attack that \
                   no signature covers."
                .into(),
            ids: Vec::new(),
            hints: Vec::new(),
            // `added` and `became` are different findings under one label.
            distinct: vec![kind.to_owned(), f.sentence()],
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
fn locate<'h>(
    hunks: &[&'h crate::evidence::Hunk],
    f: &Finding,
    fallback_file: &str,
) -> Location<'h> {
    let anchor = if f.ids.is_empty() && f.hints.is_empty() {
        None
    } else {
        hunks
            .iter()
            .find(|h| f.ids.iter().any(|id| id == &h.id))
            .or_else(|| {
                hunks.iter().find(|h| {
                    let id = TraitId::new(&h.id);
                    f.hints
                        .iter()
                        .any(|ns| id.is_under(ns) || under(id.path(), ns))
                })
            })
            // Still nothing: the strongest evidence in the change is a better
            // pointer than an arbitrary file.
            .or_else(|| hunks.first())
    };
    match anchor {
        Some(h) => Location {
            physical_location: PhysicalLocation {
                artifact_location: ArtifactLocation { uri: uri(&h.file) },
                region: h.line.map(|start_line| Region { start_line }),
            },
            logical_locations: h.member.as_deref().map(|name| {
                [LogicalLocation {
                    name,
                    kind: "member",
                }]
            }),
        },
        None => Location {
            physical_location: PhysicalLocation {
                artifact_location: ArtifactLocation {
                    uri: uri(fallback_file),
                },
                region: None,
            },
            logical_locations: None,
        },
    }
}

/// Bytes a URI path may carry as-is: RFC 3986's unreserved characters, the
/// sub-delimiters, `:`, `@`, and `/` as the segment separator. Everything else
/// — a space, `#`, `?`, `%`, any non-ASCII byte — is percent-encoded.
const URI_PATH: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~')
    .remove(b'!')
    .remove(b'$')
    .remove(b'&')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')')
    .remove(b'*')
    .remove(b'+')
    .remove(b',')
    .remove(b';')
    .remove(b'=')
    .remove(b':')
    .remove(b'@')
    .remove(b'/');

/// A SARIF artifact URI: repo-relative, forward slashes, no `./` prefix, and
/// percent-encoded — a pull request is free to name a file `a b#c.js`, and a
/// raw `#` would end the path at a fragment.
fn uri(path: &str) -> String {
    let p = path.replace('\\', "/");
    let p = p.strip_prefix("./").unwrap_or(&p);
    percent_encoding::utf8_percent_encode(p.trim_start_matches('/'), URI_PATH).to_string()
}

/// SARIF result levels. GitHub renders `error` as a failing annotation.
fn level(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::None => "note",
    }
}

/// GitHub's `problem.severity` vocabulary.
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
///
/// `distinct` separates findings that share a rule and carry no trait ids. It
/// is hashed after its own separator, and only when present, so every finding
/// that has no such parts keeps the fingerprint it always had.
fn fingerprint(rule: &str, ids: &[String], distinct: &[String]) -> String {
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
    // In order: these are positional (a field, then its old and new values).
    for part in distinct {
        eat("\u{1}");
        eat(part);
    }
    format!("{h:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_order_independent_and_stable() {
        let a = fingerprint("isomer/capability/C2", &["b".into(), "a".into()], &[]);
        let b = fingerprint("isomer/capability/C2", &["a".into(), "b".into()], &[]);
        assert_eq!(a, b, "id order must not change the fingerprint");
        assert_ne!(
            a,
            fingerprint("isomer/capability/network", &["a".into(), "b".into()], &[])
        );
        // Pinned: the value is a wire contract with code scanning's alert
        // tracking, so a refactor must not silently change it.
        assert_eq!(fingerprint("r", &[], &[]), "af63ef4c86020cd5");
    }

    /// Two publisher drifts in one run are two alerts, not one.
    #[test]
    fn findings_without_trait_ids_still_fingerprint_apart() {
        let signer = fingerprint(
            "isomer/identity",
            &[],
            &["signer".into(), "A".into(), "B".into()],
        );
        let org = fingerprint(
            "isomer/identity",
            &[],
            &["organization".into(), "A".into(), "B".into()],
        );
        assert_ne!(signer, org);
        assert_ne!(signer, fingerprint("isomer/identity", &[], &[]));
        // Positional: swapping old and new is a different change.
        assert_ne!(
            signer,
            fingerprint(
                "isomer/identity",
                &[],
                &["signer".into(), "B".into(), "A".into()]
            )
        );
    }

    #[test]
    fn uris_are_repo_relative() {
        assert_eq!(uri("./src/a.js"), "src/a.js");
        assert_eq!(uri("/src/a.js"), "src/a.js");
        assert_eq!(uri("src\\a.js"), "src/a.js");
    }

    /// A raw `#` or `?` would end the path; a space or `%` is not a valid URI
    /// character at all.
    #[test]
    fn uris_are_percent_encoded() {
        assert_eq!(uri("a b#c?.js"), "a%20b%23c%3F.js");
        assert_eq!(uri("100%.js"), "100%25.js");
        assert_eq!(uri("dir/ü.js"), "dir/%C3%BC.js");
        assert_eq!(uri("scope/@pkg/a-b_c~d.js"), "scope/@pkg/a-b_c~d.js");
    }

    /// Structural rule ids are stable strings: GitHub tracks a Security-tab
    /// alert by rule id, so changing one silently reopens every alert.
    #[test]
    fn structure_rule_ids_are_stable() {
        use crate::rubric::FactLabel;
        assert_eq!(
            FactLabel::LoaderDependency.rule_id(),
            "structure/loader-dependency"
        );
        assert_eq!(
            FactLabel::WritableExecutable.rule_id(),
            "structure/writable-executable"
        );
    }
}
