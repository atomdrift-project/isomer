//! Small differential records: no corpus, model bundle, network, or scanners.
//! These exercise the production rubric and decision functions together.

use std::collections::HashSet;
use std::path::Path;

use cleave::Criticality;
use cleave::types::{
    Changed, DiffReportV1, DiffSummary, FileDiffEntry, FileStatus, KvChange, MetricChange,
    ScopeDiff, ScopeDiffs, ScopeRocs, TraitChange,
};

use super::{
    Naming, Proportionality, Remediation, capability_shape, change_shape_escalation,
    deterministic_verdicts, normalized_archive_diff, remediation_cleanup_context,
    significant_risk_escalation, source_download_write_execute_anomaly,
};
use crate::Severity;
use crate::risk::Risk;
use crate::rubric::{Assessment, assess};
use crate::version::{Bump, BumpKind};

fn finding(id: &str, crit: Criticality) -> TraitChange {
    TraitChange {
        id: id.to_owned(),
        trait_section: id.split('/').next().unwrap().to_owned(),
        crit,
        conf: 1.0,
        count: 1,
        desc: id.to_owned(),
    }
}

fn source(path: &str, traits: &[&str]) -> FileDiffEntry {
    FileDiffEntry {
        path: format!("<root>!!package/{path}"),
        file_type: Some("javascript".to_owned()),
        status: FileStatus::Added,
        identity: None,
        scopes: ScopeDiffs {
            traits: Some(ScopeDiff {
                added: traits
                    .iter()
                    .map(|id| finding(id, Criticality::Notable))
                    .collect(),
                ..Default::default()
            }),
            ..Default::default()
        },
        old_formula: None,
        new_formula: None,
    }
}

fn report(files: Vec<FileDiffEntry>) -> DiffReportV1 {
    DiffReportV1 {
        old_root: "before.zip".to_owned(),
        new_root: "after.zip".to_owned(),
        summary: DiffSummary {
            files_added: 2,
            files_changed: 4,
            files_unchanged: 100,
            overall_roc: 0.12,
            scope_roc: ScopeRocs {
                traits: 0.12,
                ..Default::default()
            },
            ..Default::default()
        },
        files,
        scopes: ScopeDiffs::default(),
    }
}

fn shape(diff: &DiffReportV1, kind: BumpKind) -> Severity {
    change_shape_escalation(
        &assess(diff, &HashSet::new()),
        diff,
        Some(Bump { kind, steps: 1 }),
        false,
        false,
        &HashSet::new(),
    )
}

#[test]
fn encoded_execution_cluster_uses_namespaces_and_requires_all_four_legs() {
    let ids = [
        "metadata/file/encoded::large-literal",
        "objectives/anti-static/obfuscation/string::concealed-strings",
        "micro-behaviors/process/create/child::launch",
        "micro-behaviors/fs/write/file::write",
    ];
    let complete = report(vec![source("library.js", &ids)]);
    assert!(super::gained_encoded_execution_cluster(&complete));
    assert_eq!(shape(&complete, BumpKind::Patch), Severity::High);
    let mut detached = complete.clone();
    detached.files[0].scopes.traits.as_mut().unwrap().added[3].id =
        "micro-behaviors/process/daemonize/detach::detaches-child".to_owned();
    assert!(super::gained_encoded_execution_cluster(&detached));
    let mut url_only = complete.clone();
    url_only.files[0].scopes.traits.as_mut().unwrap().added[3].id =
        "micro-behaviors/communications/http/url/forge::url".to_owned();
    assert!(!super::gained_encoded_execution_cluster(&url_only));
    for missing in 0..ids.len() {
        let partial: Vec<_> = ids
            .iter()
            .enumerate()
            .filter_map(|(index, id)| (index != missing).then_some(*id))
            .collect();
        assert!(!super::gained_encoded_execution_cluster(&report(vec![
            source("library.js", &partial)
        ])));
    }
    let split = report(vec![
        source("encoding.js", &ids[..2]),
        source("worker.js", &ids[2..]),
    ]);
    assert!(!super::gained_encoded_execution_cluster(&split));
    let mut aggregate = complete.clone();
    aggregate.files[0].file_type = Some("npm".to_owned());
    assert!(!super::gained_encoded_execution_cluster(&aggregate));
    let mut removed = complete.clone();
    removed.files[0].status = FileStatus::Removed;
    assert!(!super::gained_encoded_execution_cluster(&removed));
    let mut noise = complete.clone();
    noise.files[0].scopes.traits.as_mut().unwrap().added[0].crit = Criticality::Component;
    assert!(!super::gained_encoded_execution_cluster(&noise));
    let mut lookalike = complete;
    lookalike.files[0].scopes.traits.as_mut().unwrap().added[0].id =
        "metadata/file/encoded-unrelated::label".to_owned();
    assert!(!super::gained_encoded_execution_cluster(&lookalike));
}

#[test]
fn network_interface_and_folder_write_do_not_establish_targeting() {
    // A bundled transport helper probes interfaces; another module writes a
    // file. Co-occurrence does not establish a guard or victim selection.
    let mut diff = report(vec![source(
        "bundle.js",
        &[
            "micro-behaviors/os/network/interface::node-network-interfaces-call",
            "micro-behaviors/fs/path/location::user-folder-file-write",
        ],
    )]);
    let verdict = |diff: &DiffReportV1| {
        let assessment = assess(diff, &HashSet::new());
        deterministic_verdicts(
            &assessment,
            assessment.new_severity(),
            Severity::None,
            Severity::None,
            false,
        )
    };
    assert_eq!(verdict(&diff), (Severity::Medium, Severity::Medium));
    assert_eq!(shape(&diff, BumpKind::Patch), Severity::None);

    // Independent evidence of hostile impact must still fail the gate.
    diff.files[0]
        .scopes
        .traits
        .as_mut()
        .unwrap()
        .added
        .push(finding(
            "objectives/impact/deface/user-folder::library-plants-file-in-user-folders",
            Criticality::Hostile,
        ));
    assert_eq!(verdict(&diff), (Severity::Critical, Severity::Critical));
}

#[test]
fn personal_folder_report_saving_does_not_establish_hostile_planting() {
    let diff = report(vec![source(
        "report.js",
        &[
            "micro-behaviors/fs/path/location::user-folder-file-write",
            "micro-behaviors/fs/path/location::home-desktop-path-expression",
            "micro-behaviors/fs/path/location::home-cloud-sync-path-expression",
            "micro-behaviors/fs/enumerate/directory::node-readdir-sync-call",
        ],
    )]);
    let assessment = assess(&diff, &HashSet::new());
    assert_eq!(assessment.new_severity(), Severity::Medium);
    assert_eq!(shape(&diff, BumpKind::Major), Severity::None);
    assert_eq!(
        deterministic_verdicts(
            &assessment,
            assessment.new_severity(),
            Severity::None,
            Severity::None,
            false
        ),
        (Severity::Medium, Severity::Medium)
    );
}

#[test]
fn native_build_hook_requires_syscall_or_signal_capability() {
    let diff_with = |id: &str| {
        report(vec![source(
            "bundle.js",
            &[
                "micro-behaviors/process/create/exec::node-exec-call",
                "objectives/supply-chain/install-hook/scripts/lifecycle::has-postinstall",
                id,
            ],
        )])
    };
    for id in [
        // WAO: an HTTP header was incorrectly treated as a raw syscall.
        "micro-behaviors/communications/http/post::raw-content-length-header",
        "metadata/file/string::syscall-documentation",
        "metadata/file/string::sigaction-text",
    ] {
        assert_eq!(
            shape(&diff_with(id), BumpKind::Patch),
            Severity::None,
            "{id}"
        );
    }
    for id in [
        "micro-behaviors/os/syscall/raw::raw-network-syscalls",
        "micro-behaviors/os/signal/handler::sigaction-source-call",
    ] {
        let diff = diff_with(id);
        assert_eq!(shape(&diff, BumpKind::Patch), Severity::High, "{id}");
        // Source archives still require independent build-macro evidence.
        assert_eq!(
            change_shape_escalation(
                &assess(&diff, &HashSet::new()),
                &diff,
                Some(Bump {
                    kind: BumpKind::Patch,
                    steps: 1
                }),
                true,
                false,
                &HashSet::new()
            ),
            Severity::None,
        );
    }
}

#[test]
fn structural_linker_facts_require_exact_elf_fields() {
    let structure = |path: &str, file_type: &str| {
        let mut file = source("data.json", &[]);
        file.file_type = Some(file_type.to_owned());
        file.scopes.kv = Some(ScopeDiff {
            added: vec![KvChange {
                path: path.to_owned(),
                value: serde_json::json!("ld-linux-x86-64.so.2"),
                ..Default::default()
            }],
            ..Default::default()
        });
        assess(&report(vec![file]), &HashSet::new()).structure
    };
    for path in [
        "json.Extra confirmation is needed to process your payment.",
        "json.You may delete tokens if they are no longer needed.",
        "json.elf.needed[]=example",
        "json.ifuncs[]=example",
        "json.dynsym[name=example].value",
        "elf.needed_versions[lib=libc.so.6].versions[]=GLIBC_2.34",
        "elf.needed_unrelated",
        "elf.ifuncs_unrelated",
    ] {
        assert_eq!(structure(path, "json").severity, Severity::None, "{path}");
    }
    for path in ["elf.needed[]=ld-linux-x86-64.so.2", "elf.ifuncs[]=resolve"] {
        assert_eq!(structure(path, "elf").severity, Severity::High, "{path}");
    }
    assert_eq!(
        structure("elf.dynsym_funcs[name=read].type", "elf").severity,
        Severity::Medium
    );
}

#[test]
fn structural_audit_hook_requires_exact_positive_metric() {
    for (path, value, expected) in [
        ("elf.has_dt_audit", 1, Severity::High),
        ("elf.has_dt_depaudit", 1, Severity::High),
        ("elf.has_dt_audit", 0, Severity::None),
        ("source.has_dt_audit", 1, Severity::None),
        ("source.has_dt_depaudit", 1, Severity::None),
    ] {
        let mut file = source("example", &[]);
        file.scopes.metrics = Some(ScopeDiff {
            added: vec![MetricChange {
                path: path.to_owned(),
                value: serde_json::json!(value),
            }],
            ..Default::default()
        });
        assert_eq!(
            assess(&report(vec![file]), &HashSet::new())
                .structure
                .severity,
            expected,
            "{path}={value}"
        );
    }
}

#[test]
fn secret_egress_requires_file_local_secret_evidence_and_routine_release() {
    let ids = [
        "micro-behaviors/crypto/library/blockchain/wallet::renamed-wallet-api",
        "micro-behaviors/data/encode/base64::encode",
        "micro-behaviors/communications/http/url/domain::js-remote-host-url",
    ];
    let together = report(vec![source("wallet.js", &ids)]);
    assert_eq!(shape(&together, BumpKind::Patch), Severity::High);
    assert_eq!(shape(&together, BumpKind::Major), Severity::None);

    for (baseline, expected) in [
        (
            vec!["crypto/library", "data/encode", "communications/http"],
            Severity::None,
        ),
        (vec!["crypto/library", "data/encode"], Severity::High),
    ] {
        let base_classes = baseline.into_iter().map(str::to_owned).collect();
        let assessment = assess(&together, &base_classes);
        assert_eq!(
            change_shape_escalation(
                &assessment,
                &together,
                Some(Bump {
                    kind: BumpKind::Patch,
                    steps: 1
                }),
                false,
                false,
                &HashSet::new(),
            ),
            expected
        );
    }

    let split = report(vec![
        source("wallet.js", &ids[..1]),
        source("bytecode.js", &ids[1..2]),
        source("http.js", &ids[2..]),
    ]);
    assert_eq!(shape(&split, BumpKind::Patch), Severity::None);

    let mut aggregate = source("archive.tgz", &ids);
    aggregate.file_type = Some("npm".into());
    let mut with_aggregate = split.clone();
    with_aggregate.files.push(aggregate);
    assert_eq!(shape(&with_aggregate, BumpKind::Patch), Severity::None);

    for status in [FileStatus::Removed, FileStatus::Unchanged] {
        let mut file = source("wallet.js", &ids);
        file.status = status;
        assert_eq!(shape(&report(vec![file]), BumpKind::Patch), Severity::None);
    }
    let ordinary_client = report(vec![source(
        "client.js",
        &[
            "micro-behaviors/crypto/library/blockchain/transaction::viem-wallet-client",
            "micro-behaviors/communications/http/url/rpc::bsc-dataseed-provider",
            ids[1],
            ids[2],
        ],
    )]);
    assert_eq!(shape(&ordinary_client, BumpKind::Patch), Severity::None);
}

#[test]
fn native_format_markers_require_whole_tokens() {
    for id in [
        "micro-behaviors/fs/proc/container::container-self-cgroup",
        "micro-behaviors/data/control-flow/module-exec::module-scope-string-function",
        "micro-behaviors/data/control-flow/module-exec::module-scope-zero-arg-call",
    ] {
        assert!(
            !capability_shape(&source("bundle.js", &[id])).executable,
            "{id}"
        );
    }
    for id in [
        "metadata/binary/elf::header",
        "metadata/lang/compiled::rust",
        "micro-behaviors/linking/elf::ifunc",
        "micro-behaviors/linking/pe::pe-import",
        "micro-behaviors/linking/macho::load-command",
    ] {
        assert!(
            capability_shape(&source("payload", &[id])).executable,
            "{id}"
        );
    }
}

#[test]
fn download_execution_chain_requires_platform_branch_not_system_information() {
    let patch = Some(Bump {
        kind: BumpKind::Patch,
        steps: 1,
    });
    let entrypoints = HashSet::from(["package/tool.js".to_owned()]);
    for (platform, expected) in [
        ("runtime::os-release-call", false),
        ("runtime::process-platform-member", false),
        ("runtime::python-platform-branch", false),
        ("branch::arbitrary-local-name", true),
        ("branch/compare::another-name", true),
        ("branchless::lookalike", false),
    ] {
        let platform = format!("micro-behaviors/os/sysinfo/platform/{platform}");
        let diff = report(vec![source(
            "tool.js",
            &[
                "micro-behaviors/communications/http/download/write::script-fetches-and-writes-remote-content",
                "micro-behaviors/fs/file/write/async::node-write-file-promise",
                "micro-behaviors/process/create/spawn::child-process-creation-api",
                &platform,
            ],
        )]);
        assert_eq!(
            source_download_write_execute_anomaly(&diff, patch, &entrypoints).is_some(),
            expected,
            "{platform}"
        );
    }
}

#[test]
fn generic_capability_churn_is_release_pressure_not_a_major_upgrade_blocker() {
    let mut diff = report(vec![source(
        "index.js",
        &[
            "micro-behaviors/communications/http::new-client",
            "micro-behaviors/time/schedule::new-timer",
            "micro-behaviors/data/serialize::new-serializer",
            "micro-behaviors/data/string::new-format",
            "micro-behaviors/fs/path::new-path-api",
            "micro-behaviors/os/env::new-config-key",
        ],
    )]);
    diff.summary.files_added = 1;
    diff.summary.files_changed = 3;
    diff.summary.overall_roc = 0.89;
    diff.summary.scope_roc.traits = 0.64;
    assert_eq!(shape(&diff, BumpKind::Major), Severity::None);
    assert_eq!(shape(&diff, BumpKind::Minor), Severity::None);
    assert_eq!(shape(&diff, BumpKind::Patch), Severity::High);

    let all_existing = assess(&diff, &HashSet::new())
        .behavioral
        .categories
        .into_iter()
        .map(|c| c.class)
        .collect();
    let assessment = assess(&diff, &all_existing);
    assert_eq!(
        change_shape_escalation(
            &assessment,
            &diff,
            Some(Bump {
                kind: BumpKind::Patch,
                steps: 1
            }),
            false,
            false,
            &HashSet::new(),
        ),
        Severity::None
    );

    // Keep the cluster predicate isolated from the focused-edit branches.
    diff.summary.files_changed = 8;
    diff.summary.scope_roc.traits = 0.45;
    let patch = Some(Bump {
        kind: BumpKind::Patch,
        steps: 1,
    });
    for existing in [
        HashSet::new(),
        HashSet::from([
            "communications/http".to_owned(),
            "data/serialize".to_owned(),
        ]),
    ] {
        let assessment = assess(&diff, &existing);
        assert_eq!(
            change_shape_escalation(&assessment, &diff, patch, false, false, &HashSet::new(),),
            if existing.is_empty() {
                Severity::High
            } else {
                Severity::None
            }
        );
        assert_eq!(assessment.behavioral.categories.len(), 6);
    }
}

#[test]
fn author_credit_replacement_is_reviewable_not_a_publisher_takeover() {
    let mut file = source("package.json", &[]);
    file.status = FileStatus::Changed;
    file.identity = Some(identity_change(
        serde_json::json!({"authors": [{"name": "SDK generator", "role": "author", "source": "npm.author"}]}),
        serde_json::json!({"authors": [{"name": "Project maintainers", "role": "author", "source": "npm.author"}]}),
    ));
    let mut diff = report(vec![file]);
    let assessment = assess(&diff, &HashSet::new());
    assert_eq!(assessment.identity.severity, Severity::Medium);
    assert_eq!(assessment.new_severity(), Severity::Medium);
    assert_eq!(assessment.identity.changes.len(), 1);
    assert_eq!(assessment.identity.changes[0].old, "SDK generator");

    // Author metadata never suppresses a newly gained dangerous capability.
    diff.files.push(source("payload.js", &[]));
    diff.files[1]
        .scopes
        .traits
        .as_mut()
        .unwrap()
        .added
        .push(finding(
            "objectives/credential-access/exfiltration::credential-upload",
            Criticality::Hostile,
        ));
    assert_eq!(
        assess(&diff, &HashSet::new()).new_severity(),
        Severity::Critical
    );
}

#[test]
fn deleted_member_is_not_identity_drift_but_stripping_surviving_member_is() {
    for (status, claim_source, expected) in [
        (FileStatus::Removed, "file.basename", Severity::None),
        (FileStatus::Removed, "npm.name", Severity::None),
        (FileStatus::Changed, "file.basename", Severity::None),
        (FileStatus::Changed, "npm.name", Severity::High),
    ] {
        let mut file = source("example-1.2.3.tgz", &[]);
        file.file_type = Some("tar.gz".to_owned());
        file.status = status;
        file.identity = Some(cleave::types::IdentityDiff {
            old: Some(filefacts::Identity {
                name: Some(filefacts::Claim::claimed("example", claim_source)),
                ..Default::default()
            }),
            new: None,
            changed: true,
        });
        assert_eq!(
            assess(&report(vec![file]), &HashSet::new()).new_severity(),
            expected,
            "identity source: {claim_source}, status: {status:?}"
        );
    }
}

#[test]
fn signer_changes_and_author_stripping_still_block() {
    for (old, new) in [
        (
            serde_json::json!({"authors": [{"name": "Maintainer", "role": "author", "source": "npm.author"}]}),
            serde_json::json!({"authors": []}),
        ),
        (
            serde_json::json!({"signer": {"common_name": "Publisher", "source": "certificate"}}),
            serde_json::json!({"signer": {"common_name": "Other publisher", "source": "certificate"}}),
        ),
        (
            serde_json::json!({"authors": [{"name": "Publisher", "role": "publisher", "source": "manifest"}]}),
            serde_json::json!({"authors": [{"name": "Other publisher", "role": "publisher", "source": "manifest"}]}),
        ),
    ] {
        let mut file = source("package.json", &[]);
        file.status = FileStatus::Changed;
        file.identity = Some(identity_change(old, new));
        assert_eq!(
            assess(&report(vec![file]), &HashSet::new()).new_severity(),
            Severity::High
        );
    }
}

fn identity_change(old: serde_json::Value, new: serde_json::Value) -> cleave::types::IdentityDiff {
    let identity = |fields: serde_json::Value| {
        let mut value = serde_json::to_value(filefacts::Identity::default()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .extend(fields.as_object().unwrap().clone());
        serde_json::from_value(value).unwrap()
    };
    cleave::types::IdentityDiff {
        old: Some(identity(old)),
        new: Some(identity(new)),
        changed: true,
    }
}

#[test]
fn clean_release_probability_changes_do_not_trip_the_gate() {
    for (old, new) in [
        (0.8268818, 0.90072995),  // Clean cross-major wallet update.
        (0.38615948, 0.51124525), // Clean CLI update.
        (0.10068662, 0.54367155), // Action installer maintenance.
        (0.04819114, 0.61538875), // Disabled PHP handlers retained in a repair.
        (0.49, 0.51),
        (0.89, 0.91), // Either classification boundary.
        (0.95, 0.95),
        (0.95, 0.30), // Stable and decreasing risk.
    ] {
        assert_eq!(
            significant_risk_escalation(Risk {
                old,
                new,
                new_classification: scan::Classification::Hostile
            }),
            Severity::None,
            "unexpected escalation for {old} -> {new}"
        );
    }
}

#[test]
fn substantial_probability_increases_remain_independent_signals() {
    for (old, new, want) in [
        (0.10, 0.80, Severity::High),
        (0.20, 0.95, Severity::Critical),
        (0.70, 0.95, Severity::Critical),
    ] {
        let assessment = assess(&report(vec![]), &HashSet::new());
        let risk = significant_risk_escalation(Risk {
            old,
            new,
            new_classification: scan::Classification::Hostile,
        });
        assert_eq!(
            deterministic_verdicts(&assessment, Severity::None, risk, Severity::None, false),
            (want, want)
        );
    }
}

#[test]
fn modest_high_band_increases_need_more_evidence() {
    for (old, new) in [(0.40, 0.78), (0.20, 0.74)] {
        assert_eq!(
            significant_risk_escalation(Risk {
                old,
                new,
                new_classification: scan::Classification::Hostile
            }),
            Severity::None
        );
    }
}

#[test]
fn calibrated_model_decision_caps_probability_escalation() {
    for (old, new, classification, expected) in [
        // Apollo Core: both routes classify the clean update as benign.
        (
            0.8005945,
            0.90685314,
            scan::Classification::Benign,
            Severity::None,
        ),
        (0.10, 0.99, scan::Classification::Benign, Severity::None),
        (0.10, 0.99, scan::Classification::Suspicious, Severity::High),
        (
            0.10,
            0.99,
            scan::Classification::Hostile,
            Severity::Critical,
        ),
        (0.99, 0.99, scan::Classification::Hostile, Severity::None),
    ] {
        let jump = significant_risk_escalation(Risk {
            old,
            new,
            new_classification: classification,
        });
        assert_eq!(jump, expected);
        let assessment = assess(&report(vec![]), &HashSet::new());
        assert_eq!(
            deterministic_verdicts(&assessment, Severity::None, jump, Severity::None, false),
            (expected, expected)
        );
        // A benign model decision cannot veto independent structural evidence.
        assert_eq!(
            deterministic_verdicts(&assessment, Severity::None, jump, Severity::Critical, false),
            (Severity::Critical, Severity::Critical)
        );
    }
}

#[test]
fn facts_can_fail_both_verdicts_without_any_traits_or_model() {
    // Package destruction: the inventory disappears, without introducing
    // any finding. Feed real summary facts through the shape detector too.
    let mut diff = report(vec![]);
    diff.summary.files_removed = 150;
    diff.summary.overall_roc = 0.80;
    diff.summary.scope_roc.traits = 0.90;
    let assessment = assess(&diff, &HashSet::new());
    assert_eq!(
        deterministic_verdicts(
            &assessment,
            Severity::None,
            Severity::None,
            shape(&diff, BumpKind::Patch),
            false
        ),
        (Severity::High, Severity::High)
    );
    // A small cleanup or a broad replacement is not this destruction shape.
    diff.summary.files_removed = 5;
    assert_eq!(shape(&diff, BumpKind::Patch), Severity::None);
    diff.summary.files_removed = 150;
    diff.summary.files_added = 150;
    assert_eq!(shape(&diff, BumpKind::Patch), Severity::None);
}

#[test]
fn known_hostile_behavior_survives_a_flat_or_missing_model() {
    let mut file = source("entry.js", &[]);
    file.scopes.traits.as_mut().unwrap().added.push(finding(
        "objectives/credential-access/exfil::private-key-upload",
        Criticality::Hostile,
    ));
    let assessment = assess(&report(vec![file]), &HashSet::new());
    assert_eq!(
        deterministic_verdicts(
            &assessment,
            assessment.new_severity(),
            Severity::None,
            Severity::None,
            false
        ),
        (Severity::Critical, Severity::Critical)
    );
}

#[test]
fn ordinary_web_ui_and_settings_files_are_not_a_payload() {
    let diff = report(vec![
        source(
            "ui.js",
            &[
                "micro-behaviors/communications/http/request::fetch-json",
                "micro-behaviors/ui/window/manage::dom-click",
            ],
        ),
        source(
            "settings.js",
            &[
                "micro-behaviors/communications/http/request::nonce-parameter",
                "micro-behaviors/os/security/auth::admin-capability-check",
                "micro-behaviors/data/db/access::update-option",
            ],
        ),
    ]);
    assert_eq!(shape(&diff, BumpKind::Patch), Severity::None);
}

fn external_html_diff() -> DiffReportV1 {
    report(vec![
        source(
            "feed.js",
            &[
                "micro-behaviors/communications/http/request/json::fetch-external-url",
                "micro-behaviors/communications/http/request/client::fetch-then-json",
                "micro-behaviors/ui/window/manage/html-insert::arbitrary-insert",
                "micro-behaviors/communications/http/request/plugin-install::arbitrary-endpoint",
            ],
        ),
        source(
            "settings.js",
            &[
                "micro-behaviors/communications/http/request::nonce-parameter",
                "micro-behaviors/data/db/access::update-option",
            ],
        ),
    ])
}

#[test]
fn patch_introducing_external_html_in_admin_context_is_reviewable() {
    let diff = external_html_diff();
    assert_eq!(shape(&diff, BumpKind::Patch), Severity::High);
    assert_eq!(shape(&diff, BumpKind::Same), Severity::High);
    assert_eq!(shape(&diff, BumpKind::Major), Severity::None);
}

#[test]
fn external_html_evidence_must_be_local_and_new() {
    for missing in 0..4 {
        let mut diff = external_html_diff();
        let moved = diff.files[0]
            .scopes
            .traits
            .as_mut()
            .unwrap()
            .added
            .remove(missing);
        diff.files[1]
            .scopes
            .traits
            .as_mut()
            .unwrap()
            .added
            .push(moved);
        assert_eq!(
            shape(&diff, BumpKind::Patch),
            Severity::None,
            "unrelated files supplied missing leg {missing}"
        );
    }
    let mut diff = external_html_diff();
    diff.files[0].status = FileStatus::Unchanged;
    assert_eq!(shape(&diff, BumpKind::Patch), Severity::None);
}

#[test]
fn archive_aggregate_cannot_join_clues_from_unrelated_members() {
    let mut diff = external_html_diff();
    let mut aggregate = diff.files[0].clone();
    aggregate.path = "<root>".to_owned();
    aggregate.file_type = Some("zip".to_owned());
    aggregate.status = FileStatus::Changed;
    let moved = diff.files[0]
        .scopes
        .traits
        .as_mut()
        .unwrap()
        .added
        .remove(0);
    diff.files[1]
        .scopes
        .traits
        .as_mut()
        .unwrap()
        .added
        .push(moved);
    diff.files.push(aggregate);
    assert_eq!(shape(&diff, BumpKind::Patch), Severity::None);
}

#[test]
fn hierarchy_rules_ignore_local_names_but_require_real_category_gains() {
    let mut diff = external_html_diff();
    for file in &mut diff.files {
        for item in &mut file.scopes.traits.as_mut().unwrap().added {
            item.id = format!("{}::renamed-42", super::trait_namespace(&item.id));
            item.desc = "Unstable presentation text".to_owned();
        }
    }
    assert_eq!(shape(&diff, BumpKind::Patch), Severity::High);
    for index in 0..4 {
        let mut changed = diff.clone();
        let traits = changed.files[0].scopes.traits.as_mut().unwrap();
        let mut old = traits.added[index].clone();
        old.id = old.id.replace("renamed-42", "previous-name");
        traits.removed.push(old);
        assert_eq!(
            shape(&changed, BumpKind::Patch),
            Severity::None,
            "renaming a local ID must not manufacture a new hierarchy"
        );

        let mut lookalike = diff.clone();
        let item = &mut lookalike.files[0].scopes.traits.as_mut().unwrap().added[index];
        item.id = item.id.replace("::", "-lookalike::");
        assert_eq!(shape(&lookalike, BumpKind::Patch), Severity::None);

        let mut weak = diff.clone();
        weak.files[0].scopes.traits.as_mut().unwrap().added[index].crit = Criticality::Component;
        assert_eq!(shape(&weak, BumpKind::Patch), Severity::None);
    }
}

#[test]
fn local_trait_names_and_descriptions_cannot_supply_binary_capabilities() {
    let mut file = source(
        "data.js",
        &["metadata/file/string::http-execve-elf-main-entry"],
    );
    file.scopes.traits.as_mut().unwrap().added[0].desc =
        "encrypted archive executable member socket spawn password".to_owned();
    let shape = capability_shape(&file);
    assert!(!shape.executable);
    assert!(shape.families.is_empty());
    assert!(!super::package_payload_context(&report(vec![file])));
}

#[test]
fn disguised_encrypted_archive_uses_metrics_without_traits() {
    let fields = [
        ("archive.security.encrypted_count", 5.0),
        ("archive.executable_count", 1.0),
        (
            "consistency.extension_content_mismatch.archive_as_unknown",
            1.0,
        ),
    ];
    let mut archive = source("payload.dat", &[]);
    archive.file_type = Some("zip".to_owned());
    archive.scopes.traits = None;
    archive.scopes.metrics = Some(ScopeDiff {
        added: fields
            .iter()
            .map(|(path, value)| MetricChange {
                path: (*path).to_owned(),
                value: serde_json::json!(value),
            })
            .collect(),
        ..Default::default()
    });
    let diff = report(vec![archive]);
    assert!(super::added_disguised_encrypted_archive(&diff));
    assert!(super::package_payload_context(&diff));
    for index in 0..fields.len() {
        let mut missing = diff.clone();
        missing.files[0]
            .scopes
            .metrics
            .as_mut()
            .unwrap()
            .added
            .remove(index);
        assert!(!super::added_disguised_encrypted_archive(&missing));
        let mut zero = diff.clone();
        zero.files[0].scopes.metrics.as_mut().unwrap().added[index].value = serde_json::json!(0);
        assert!(!super::added_disguised_encrypted_archive(&zero));
    }
    let mut few = diff.clone();
    few.files[0].scopes.metrics.as_mut().unwrap().added[0].value = serde_json::json!(4);
    assert!(!super::added_disguised_encrypted_archive(&few));
    let mut existing = diff.clone();
    existing.files[0].status = FileStatus::Unchanged;
    assert!(!super::added_disguised_encrypted_archive(&existing));
    assert!(!super::package_payload_context(&existing));
    let mut split = diff.clone();
    let mut member = split.files[0].clone();
    member.path.push_str("!!other.zip");
    let metric = split.files[0]
        .scopes
        .metrics
        .as_mut()
        .unwrap()
        .added
        .remove(0);
    member.scopes.metrics.as_mut().unwrap().added = vec![metric];
    split.files.push(member);
    assert!(!super::added_disguised_encrypted_archive(&split));
    // Neither archive has both executable and encrypted-member evidence.
    split.files[0].scopes.metrics.as_mut().unwrap().added.pop();
    assert!(!super::package_payload_context(&split));
}

#[test]
fn cleanup_requires_disabled_code_not_a_particular_implant_filename() {
    let temp = tempfile::tempdir().unwrap();
    let old = temp.path().join("before.php");
    let new = temp.path().join("after.php");
    std::fs::write(
        &old,
        "<?php function a() { run(); } function b() { run(); }",
    )
    .unwrap();
    std::fs::write(
        &new,
        "<?php function a() { return; run(); } function b() { return; run(); }",
    )
    .unwrap();
    let mut file = source(
        "repair.php",
        &[
            "objectives/supply-chain/hidden-payload/staging::different-indicator",
            "micro-behaviors/fs/delete/file::different-delete-api",
        ],
    );
    file.path = "repair.php".to_owned();
    file.file_type = Some("php".to_owned());
    file.status = FileStatus::Changed;
    file.scopes.traits.as_mut().unwrap().added[0].crit = Criticality::Component;
    let diff = report(vec![file]);
    let assess_cleanup = |diff: &DiffReportV1| {
        remediation_cleanup_context(&old, &new, &assess(diff, &HashSet::new()), diff, diff, None)
    };
    assert_eq!(assess_cleanup(&diff), Some(Remediation::FocusedCleanup));
    std::fs::write(
        &new,
        "<?php function a() { return; run(); } function b() { run(); }",
    )
    .unwrap();
    assert_eq!(assess_cleanup(&diff), None);
    std::fs::write(
        &new,
        "<?php /* function a() { return; } function b() { return; } */",
    )
    .unwrap();
    assert_eq!(assess_cleanup(&diff), None);
}

#[test]
fn model_recovery_requires_a_high_baseline_and_a_large_drop() {
    let diff = report(vec![]);
    let assessment = assess(&diff, &HashSet::new());
    for (risk, expected) in [
        (
            Some(Risk {
                old: 0.95597947,
                new: 0.51124525,
                new_classification: scan::Classification::Benign,
            }),
            Some(Remediation::ModelRecovery),
        ),
        (
            Some(Risk {
                old: 0.95,
                new: 0.60,
                new_classification: scan::Classification::Benign,
            }),
            None,
        ),
        (
            Some(Risk {
                old: 0.70,
                new: 0.10,
                new_classification: scan::Classification::Benign,
            }),
            None,
        ),
        (
            Some(Risk {
                old: 0.10,
                new: 0.95,
                new_classification: scan::Classification::Hostile,
            }),
            None,
        ),
        (None, None),
    ] {
        assert_eq!(
            remediation_cleanup_context(
                Path::new("before"),
                Path::new("after"),
                &assessment,
                &diff,
                &diff,
                risk
            ),
            expected
        );
    }
}

#[test]
fn cleanup_budget_counts_members_not_expanded_containers() {
    let mut files: Vec<_> = (0..4)
        .map(|index| {
            let mut file = source(&format!("file{index}.php"), &[]);
            file.status = FileStatus::Changed;
            file
        })
        .collect();
    assert_eq!(super::cleanup_member_counts(&report(files.clone())), (4, 0));
    let mut root = source("ignored", &[]);
    root.path = "<root>".to_owned();
    root.file_type = Some("zip".to_owned());
    root.status = FileStatus::Changed;
    files.push(root);
    assert_eq!(super::cleanup_member_counts(&report(files.clone())), (4, 0));
    let mut opaque = source("opaque.zip", &[]);
    opaque.file_type = Some("zip".to_owned());
    files.push(opaque.clone());
    assert_eq!(super::cleanup_member_counts(&report(files.clone())), (4, 1));
    let mut nested = source("ignored", &[]);
    nested.path = format!("{}!!child.js", opaque.path);
    files.push(nested);
    assert_eq!(super::cleanup_member_counts(&report(files.clone())), (4, 1));
    // A similarly named file is not a descendant; the !! boundary is required.
    let mut extra = source("ignored", &[]);
    extra.path = format!("{}-other", opaque.path);
    files.push(extra);
    assert_eq!(super::cleanup_member_counts(&report(files)), (4, 2));
}

#[test]
fn cleanup_behavior_budget_counts_unknowns_and_gains_not_baseline_churn() {
    let mut unchanged_behavior = source("library.js", &[]);
    unchanged_behavior.status = FileStatus::Changed;
    let mut diff = report(vec![unchanged_behavior.clone(); 8]);
    assert_eq!(super::cleanup_behavior_changes(&diff), 0);
    diff.files[0]
        .scopes
        .traits
        .as_mut()
        .unwrap()
        .added
        .push(finding(
            "micro-behaviors/communications/http/client::request",
            Criticality::Notable,
        ));
    assert_eq!(super::cleanup_behavior_changes(&diff), 1);
    diff.files[1].scopes.traits = None;
    diff.files[2].scopes.traits.as_mut().unwrap().truncated = true;
    diff.files[3].status = FileStatus::Added;
    assert_eq!(super::cleanup_behavior_changes(&diff), 4);
    assert!(super::focused_cleanup_budget(&diff));
    diff.files[4]
        .scopes
        .traits
        .as_mut()
        .unwrap()
        .added
        .push(finding(
            "metadata/file/format::marker",
            Criticality::Baseline,
        ));
    assert_eq!(super::cleanup_behavior_changes(&diff), 4);
    diff.files[5]
        .scopes
        .traits
        .as_mut()
        .unwrap()
        .changed
        .push(Changed {
            old: finding("objectives/execution::example", Criticality::Notable),
            new: finding("objectives/execution::example", Criticality::Suspicious),
        });
    assert_eq!(super::cleanup_behavior_changes(&diff), 5);
    assert!(!super::focused_cleanup_budget(&diff));
    let broad = report(vec![unchanged_behavior.clone(); 17]);
    assert!(!super::focused_cleanup_budget(&broad));
    let additions = report(vec![source("one.js", &[]), source("two.js", &[])]);
    assert!(!super::focused_cleanup_budget(&additions));
}

#[test]
fn remediation_preserves_independent_danger_signals() {
    let empty = || assess(&report(vec![]), &HashSet::new());
    let final_severity = |a: &Assessment, rubric, model| {
        deterministic_verdicts(a, rubric, model, Severity::None, true)
    };
    assert_eq!(
        final_severity(&empty(), Severity::High, Severity::None),
        (Severity::Medium, Severity::Medium)
    );
    for axis in 0..3 {
        let mut assessment = empty();
        match axis {
            0 => assessment.identity.severity = Severity::High,
            1 => assessment.structure.severity = Severity::High,
            _ => assessment.signature.severity = Severity::High,
        }
        assert_eq!(
            final_severity(&assessment, Severity::None, Severity::None),
            (Severity::High, Severity::High)
        );
    }
    assert_eq!(
        final_severity(&empty(), Severity::Critical, Severity::None),
        (Severity::Critical, Severity::Critical)
    );
    assert_eq!(
        final_severity(&empty(), Severity::None, Severity::Critical),
        (Severity::Critical, Severity::Critical)
    );
}

#[test]
fn decoded_offset_churn_does_not_introduce_existing_behavior() {
    let id = "micro-behaviors/os/console/io::silenced";
    let mut old = source("app.js!!package/app.js##unicode-escape@100", &[]);
    old.status = FileStatus::Removed;
    old.scopes
        .traits
        .as_mut()
        .unwrap()
        .removed
        .push(finding(id, Criticality::Suspicious));
    let mut new = source("app.js!!package/app.js##unicode-escape@120", &[]);
    new.scopes
        .traits
        .as_mut()
        .unwrap()
        .added
        .push(finding(id, Criticality::Suspicious));
    let mut parent = new.clone();
    parent.path = "<root>!!package/app.js".to_owned();
    parent.status = FileStatus::Changed;
    let mut aggregate = parent.clone();
    aggregate.path = "<root>".to_owned();
    aggregate.file_type = Some("zip".to_owned());
    let raw = report(vec![old, new, parent, aggregate]);
    let judged = normalized_archive_diff(&raw);
    assert_eq!(
        assess(&judged, &HashSet::new()).new_severity(),
        Severity::None
    );
    // Preserve the raw report and all non-trait evidence.
    assert_eq!(raw.files[1].scopes.traits.as_ref().unwrap().added.len(), 1);
    assert_eq!(judged.files.len(), raw.files.len());

    // Without baseline evidence, the shifted view must remain suspicious.
    let mut unknown_baseline = raw.clone();
    unknown_baseline.files.remove(0);
    assert_eq!(
        assess(&normalized_archive_diff(&unknown_baseline), &HashSet::new()).new_severity(),
        Severity::High
    );

    // Reclassification must not erase a promotion of an existing capability.
    let mut promoted = raw.clone();
    promoted.files[0].scopes.traits.as_mut().unwrap().removed[0].crit = Criticality::Notable;
    let promoted = normalized_archive_diff(&promoted);
    assert_eq!(assess(&promoted, &HashSet::new()).severity, Severity::High);

    // The same capability in a different source file is still new there.
    let mut other = raw.files[1].clone();
    other.path = "<root>!!package/other.js!!package/other.js##unicode-escape@100".to_owned();
    let mut independent = raw.clone();
    independent.files.push(other);
    assert_eq!(
        assess(&normalized_archive_diff(&independent), &HashSet::new()).new_severity(),
        Severity::High
    );

    // A genuinely new hostile capability in the shifted payload survives.
    let mut attack = raw.clone();
    attack.files[1]
        .scopes
        .traits
        .as_mut()
        .unwrap()
        .added
        .push(finding(
            "objectives/credential-access/exfil::private-key-upload",
            Criticality::Hostile,
        ));
    assert_eq!(
        assess(&normalized_archive_diff(&attack), &HashSet::new()).new_severity(),
        Severity::Critical
    );
}

#[test]
fn preexisting_escalated_behavior_is_not_new_release_pressure() {
    let mut file = source("helper.js", &[]);
    file.status = FileStatus::Changed;
    file.scopes.traits.as_mut().unwrap().changed.push(Changed {
        old: finding("micro-behaviors/process/create::exec", Criticality::Notable),
        new: finding(
            "micro-behaviors/process/create::exec",
            Criticality::Suspicious,
        ),
    });
    let diff = report(vec![file]);
    let assessment = assess(&diff, &HashSet::new());
    let naming = Naming {
        name: "example".to_owned(),
        old: None,
        new: None,
        bump: Some(Bump {
            kind: BumpKind::Patch,
            steps: 1,
        }),
    };
    assert!(
        !Proportionality::eval(&assessment, &naming, &diff, false, false, &HashSet::new())
            .drift
            .is_disproportionate()
    );
    assert_eq!(
        deterministic_verdicts(
            &assessment,
            assessment.new_severity(),
            Severity::None,
            Severity::None,
            false
        ),
        (Severity::High, Severity::None)
    );
}
