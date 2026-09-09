//! Small differential records: no corpus, model bundle, network, or scanners.
//! These exercise the production rubric and decision functions together.

use std::collections::HashSet;
use std::path::Path;

use cleave::Criticality;
use cleave::types::{
    Changed, DiffReportV1, DiffSummary, FileDiffEntry, FileStatus, ScopeDiff, ScopeDiffs,
    ScopeRocs, TraitChange,
};

use super::{
    Naming, Proportionality, Remediation, change_shape_escalation, deterministic_verdicts,
    normalized_archive_diff, remediation_cleanup_context, significant_risk_escalation,
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
            significant_risk_escalation(Risk { old, new }),
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
        let risk = significant_risk_escalation(Risk { old, new });
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
            significant_risk_escalation(Risk { old, new }),
            Severity::None
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
                "micro-behaviors/ui/window/manage/html::dom-outer-html-insertion-sink",
                "micro-behaviors/communications/http/request/wordpress::plugin-upload-action-endpoint",
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
fn model_recovery_requires_a_high_baseline_and_a_large_drop() {
    let diff = report(vec![]);
    let assessment = assess(&diff, &HashSet::new());
    for (risk, expected) in [
        (
            Some(Risk {
                old: 0.95597947,
                new: 0.51124525,
            }),
            Some(Remediation::ModelRecovery),
        ),
        (
            Some(Risk {
                old: 0.95,
                new: 0.60,
            }),
            None,
        ),
        (
            Some(Risk {
                old: 0.70,
                new: 0.10,
            }),
            None,
        ),
        (
            Some(Risk {
                old: 0.10,
                new: 0.95,
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
