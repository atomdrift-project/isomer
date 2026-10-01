//! Every renderer, end to end, over one synthetic change: no artifact on disk,
//! no model, no network. The checks are the contract each format keeps with
//! its reader, not a byte-for-byte snapshot of today's layout.

use std::path::Path;

use cleave::Criticality;
use cleave::types::{AnalysisReport, FileDiffEntry, FileStatus, KvChange, ScopeDiff, ScopeDiffs};

use super::{Analysis, Verb};
use crate::options::Options;
use crate::testkit::{diff, entry, finding};
use crate::{Format, Gate, Severity};

/// A package that gained a hostile behavior in one source file, swapped its
/// signer for a name carrying markdown, and gained a loader dependency.
fn report() -> AnalysisReport {
    let source = FileDiffEntry {
        scopes: ScopeDiffs {
            traits: Some(ScopeDiff {
                added: vec![finding(
                    "objectives/exfiltration/http/upload::credential-upload",
                    Criticality::Hostile,
                )],
                ..Default::default()
            }),
            ..Default::default()
        },
        ..entry(
            "<root>!!package/index.js",
            "javascript",
            FileStatus::Changed,
        )
    };
    let mut root = entry("<root>", "elf", FileStatus::Changed);
    root.scopes.kv = Some(ScopeDiff {
        added: vec![KvChange {
            path: "elf.needed[]=ld-linux-x86-64.so.2".to_owned(),
            namespace: "elf".to_owned(),
            value: serde_json::Value::String("ld-linux-x86-64.so.2".to_owned()),
        }],
        ..Default::default()
    });
    root.identity = Some(cleave::types::IdentityDiff {
        changed: true,
        old: Some(signed_by("Example Corp")),
        new: Some(signed_by("![✅ CLEAN](https://x/b.svg) @team")),
    });
    let mut report: AnalysisReport =
        serde_json::from_value(serde_json::json!({"version": "3"})).unwrap();
    report.diff = Some(diff(vec![root, source]));
    report
}

fn signed_by(name: &str) -> filefacts::Identity {
    let signer = serde_json::json!({"common_name": name, "source": "pe.signer"});
    filefacts::Identity {
        signer: Some(serde_json::from_value(signer).unwrap()),
        trust: filefacts::Trust::CaSigned,
        ..Default::default()
    }
}

/// Judge the synthetic change offline, as the `fs` verb would.
fn render(format: Format) -> String {
    let report = report();
    let options = cleave::AnalysisOptions::default();
    let opts = Options {
        offline: true,
        gate: Gate::Any,
        ..Options::default()
    };
    let mut a = Analysis::new(
        Verb::Fs,
        Path::new("pkg-1.0.0.tgz"),
        Path::new("pkg-1.0.1.tgz"),
        &options,
        &report,
        &opts,
    )
    .unwrap();
    a.finish(&opts);
    assert_eq!(a.verdict, Severity::Critical, "the fixture must be hostile");
    assert!(!a.clean());
    a.render(format).unwrap()
}

#[test]
fn the_terminal_names_the_verdict_and_what_was_gained() {
    colored::control::set_override(false);
    let out = render(Format::Terminal);
    assert!(out.contains("HOSTILE"), "{out}");
    assert!(out.contains("exfiltration/http/upload"), "{out}");
    assert!(out.contains("loader dependency"), "{out}");
    assert!(out.contains("signer"), "{out}");
}

#[test]
fn json_states_the_gate_and_types_every_severity() {
    let out = render(Format::Json);
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    let verdict = &json["verdict"];
    assert_eq!(verdict["severity"], "critical");
    assert_eq!(verdict["gate"]["on"], "any");
    assert_eq!(verdict["gate"]["fail_on"], "high");
    assert_eq!(verdict["gate"]["fail"], true);
    assert_eq!(
        verdict["structure"]["facts"][0]["label"],
        "loader dependency"
    );
    assert_eq!(verdict["structure"]["facts"][0]["change"], "added");
    assert_eq!(verdict["identity"]["changes"][0]["field"], "signer");
    assert_eq!(json["version"]["bump"], "patch");
    assert_eq!(json["verb"], "fs");
    // Absent optionals are omitted, not null: offline, there is no model.
    assert!(json.get("llm").is_none(), "{out}");
    assert!(verdict.get("risk").is_none(), "{out}");
    // The verdict and its proof precede the bulky raw diff, so a reader that
    // stops early has already seen the decision.
    let order = [
        "\"v\"",
        "\"verdict\"",
        "\"features\"",
        "\"evidence\"",
        "\"raw\"",
    ];
    let at: Vec<usize> = order
        .iter()
        .map(|key| out.find(key).unwrap_or_else(|| panic!("missing {key}")))
        .collect();
    assert!(at.windows(2).all(|w| w[0] < w[1]), "keys out of order");
}

#[test]
fn sarif_gives_every_finding_its_own_rule_and_fingerprint() {
    let out = render(Format::Sarif);
    let log: serde_json::Value = serde_json::from_str(&out).unwrap();
    let run = &log["runs"][0];
    let results = run["results"].as_array().unwrap();
    // A capability, an identity drift, and a structural fact.
    assert_eq!(results.len(), 3, "{out}");
    let mut fingerprints: Vec<&str> = results
        .iter()
        .map(|r| {
            r["partialFingerprints"]["isomerFindingV1"]
                .as_str()
                .unwrap()
        })
        .collect();
    fingerprints.sort_unstable();
    fingerprints.dedup();
    assert_eq!(fingerprints.len(), 3);
    for r in results {
        let index = usize::try_from(r["ruleIndex"].as_u64().unwrap()).unwrap();
        assert_eq!(run["tool"]["driver"]["rules"][index]["id"], r["ruleId"]);
    }
    assert!(
        results
            .iter()
            .any(|r| r["ruleId"] == "isomer/structure/loader-dependency")
    );
}

#[test]
fn markdown_cannot_be_forged_by_the_artifact() {
    let out = render(Format::Markdown);
    assert!(out.starts_with(crate::markdown::MARKER), "{out}");
    assert!(out.contains("HOSTILE"), "{out}");
    // The signer's markdown arrives as text: no image, no link, no mention.
    assert!(!out.contains("![✅"), "{out}");
    assert!(!out.contains("](https://"), "{out}");
    assert!(!out.contains(" @team"), "{out}");
    // And the gate verdict closes the comment.
    assert!(out.trim_end().ends_with("</sub>"), "{out}");
}

#[test]
fn interpret_is_exactly_the_payload_the_model_reads() {
    let out = render(Format::Interpret);
    assert!(out.starts_with("artifact: "), "{out}");
    assert!(out.contains("DIFFERENTIAL SHAPE"), "{out}");
    assert!(out.contains("deterministic gate is FAIL"), "{out}");
}
