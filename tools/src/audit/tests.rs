use super::*;

fn sample(path: impl Into<PathBuf>) -> SampleFile {
    let path = path.into();
    SampleFile {
        logical_name: path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
        path,
        provenance: Value::Null,
    }
}

fn artifact() -> Artifact {
    Artifact {
        name: "example".into(),
        year: 2026,
        before: Some(sample("before.zip")),
        during: Some(sample("during.zip")),
        after: Some(sample("after.zip")),
        baseline: Vec::new(),
    }
}

fn transition(detected: bool) -> Transition {
    Transition {
        detected: Some(detected),
        severity: if detected { "high" } else { "none" }.into(),
        error: None,
        diagnostic: json!({"exact_run": true}),
    }
}

fn side(subject: &str, phase: &str, version: Option<&str>, file: &str) -> Value {
    json!({"subject": subject, "phase": phase, "version": version, "file": file})
}

fn pair(kind: &str, old: Value, new: Value) -> Value {
    json!({"kind": kind, "old": old, "new": new})
}

fn write_tree(root: &Path, pairs: &[Value]) {
    fs::create_dir_all(root.join("incident")).unwrap();
    for pair in pairs {
        for key in ["old", "new"] {
            let side: Side = serde_json::from_value(pair[key].clone()).unwrap();
            let path = root
                .join("incident")
                .join(&side.subject)
                .join(&side.phase)
                .join(side.version().unwrap_or_else(|| "unversioned".into()))
                .join(&side.file);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, &side.phase).unwrap();
        }
    }
    fs::write(
        root.join("incident/pairs.yaml"),
        serde_yaml::to_string(&json!({"record": "incident", "pairs": pairs})).unwrap(),
    )
    .unwrap();
}

fn attack_pairs() -> Vec<Value> {
    let old = side("demo", "before", None, "before.js");
    let during = side("demo", "during", Some("01"), "during.js");
    let after = side("demo", "after", Some("02"), "after.js");
    vec![
        pair("attack", old, during.clone()),
        pair("remediation", during, after),
    ]
}

fn args(root: &Path) -> Args {
    Args {
        corpus: root.to_path_buf(),
        isomer: root.join("detector"),
        traits: None,
        fail_on: "high".into(),
        jobs: 3,
        timeout: 5,
        limit: 0,
        json: true,
        check_corpus: false,
        stream_results: None,
    }
}

#[test]
fn remediation_is_judged_independently_of_the_net_comparison() {
    let artifact = artifact();
    let work = transitions_of(0, &artifact);
    for net in [false, true] {
        let runs = BTreeMap::from([
            ((0, "bd".into()), transition(true)),
            ((0, "da".into()), transition(true)),
            ((0, "ba".into()), transition(net)),
        ]);
        let summary = summarize(std::slice::from_ref(&artifact), &work, &runs);
        let failures = summary["violations"][0]["issues"].as_array().unwrap();
        assert_eq!(failures.len(), 1 + usize::from(net));
        assert!(failures[0].as_str().unwrap().starts_with("FP-REMEDIATION"));
        assert_eq!(
            summary["violations"][0]["diagnostics"]["during->after"],
            json!({"exact_run": true})
        );
    }
}

#[test]
fn compact_diagnostics_preserve_the_exact_verdict() {
    let verdict =
        json!({"gate": {"fail": true, "severity": "high"}, "risk": {"old": 0.1, "new": 0.9}});
    let report = json!({"verdict": verdict, "features": {"trait_shift": {"complete": true}, "judged_summary": {"overall_roc": 0.1}, "scopes": {"metrics": {"roc": 0}}, "topology": {"unchanged": 10}, "files": [{"large_source": "not retained"}]}, "raw": {"diff": {"summary": {"files_added": 1}, "files": [{"large_source": "not retained"}]}}});
    let run = parse_transition(Some(1), &report.to_string(), "");
    assert_eq!(run.detected, Some(true));
    assert_eq!(
        run.diagnostic,
        json!({"verdict": verdict, "summary": {"files_added": 1}, "trait_shift": {"complete": true}, "judged_summary": {"overall_roc": 0.1}, "scopes": {"metrics": {"roc": 0}}, "topology": {"unchanged": 10}})
    );
}

#[test]
fn skipped_rules_are_errors_even_with_valid_verdicts() {
    for detected in [false, true] {
        let report = json!({"verdict": {"gate": {"fail": detected, "severity": "high"}}});
        let run = parse_transition(
            Some(i32::from(detected)),
            &report.to_string(),
            "⚠️  WARNING: skipped 2 trait file(s) this build of isomer could not parse; their rules will not run.\n   Failed to parse YAML in \"traits/example.yaml\"\n",
        );
        assert_eq!(run.detected, None);
        let error = run.error.as_ref().unwrap();
        assert!(error.contains("incomplete trait coverage"));
        assert!(error.contains("traits/example.yaml"));
        assert_eq!(issue("bd", &run), Some("ERROR"));
    }
}

#[test]
fn unrelated_warnings_do_not_discard_verdicts() {
    let run = parse_transition(
        Some(0),
        r#"{"verdict":{"gate":{"fail":false,"severity":"none"}}}"#,
        "WARNING: optional display feature unavailable\n",
    );
    assert_eq!(run.detected, Some(false));
    assert_eq!(run.error, None);
}

#[test]
fn scanner_errors_and_malformed_reports_are_reported() {
    for (code, stdout, stderr, expected) in [
        (Some(2), "", "first line\nlast line\n", "last line"),
        (Some(0), "invalid", "", "unparseable json"),
        (Some(1), "{}", "", "unparseable json"),
        (
            Some(0),
            r#"{"verdict":{"gate":{"fail":"yes"}}}"#,
            "",
            "unparseable json",
        ),
    ] {
        assert_eq!(
            parse_transition(code, stdout, stderr).error.as_deref(),
            Some(expected)
        );
    }
}

#[test]
fn diagnostic_payloads_never_change_expectations() {
    let artifact = artifact();
    let work = transitions_of(0, &artifact);
    let runs = BTreeMap::from([
        ((0, "bd".into()), transition(true)),
        ((0, "da".into()), transition(false)),
        ((0, "ba".into()), transition(true)),
    ]);
    let summary = summarize(&[artifact], &work, &runs);
    assert_eq!(
        summary["violations"][0]["issues"].as_array().unwrap().len(),
        1
    );
    assert!(
        summary["violations"][0]["issues"][0]
            .as_str()
            .unwrap()
            .starts_with("FP-NET")
    );
}

#[test]
fn qualified_labels_warn_without_changing_hit_miss_or_error_gates() {
    for classification in ["affected", "carrier", "baseline_candidate"] {
        for run in [
            transition(true),
            transition(false),
            Transition::error("scanner error"),
        ] {
            let mut artifact = artifact();
            artifact.during.as_mut().unwrap().provenance =
                json!({"classification": classification});
            let work = transitions_of(0, &artifact);
            let runs = BTreeMap::from([
                ((0, "bd".into()), run.clone()),
                ((0, "da".into()), transition(false)),
                ((0, "ba".into()), transition(false)),
            ]);
            let summary = summarize(&[artifact], &work, &runs);
            assert_eq!(
                summary["violations"].as_array().unwrap().len(),
                usize::from(run.detected != Some(true))
            );
            let warnings = &summary["evidence_warnings"][0]["transitions"];
            assert_eq!(warnings["bd"][0]["side"], "new");
            assert_eq!(warnings["da"][0]["side"], "old");
            assert_eq!(warnings["bd"][0]["classification"], classification);
            assert!(warnings.get("ba").is_none());
        }
    }
    for classification in [
        json!("clean"),
        json!("malicious"),
        json!("remediated"),
        json!("fixed"),
        Value::Null,
    ] {
        let mut sample = sample("sample.js");
        sample.provenance = json!({"classification": classification});
        assert!(evidence_warnings(&sample, &sample).is_empty());
    }
}

#[test]
fn corpus_preserves_versions_distributed_names_and_unknown_claims() {
    let root = tempfile::tempdir().unwrap();
    write_tree(root.path(), &attack_pairs());
    let artifacts = load_artifacts(root.path()).unwrap();
    assert_eq!(artifacts.len(), 1);
    let artifact = &artifacts[0];
    assert_eq!(artifact.name, "incident/demo@01");
    let before = artifact.before.as_ref().unwrap();
    assert_eq!(
        before.path.parent().unwrap().file_name().unwrap(),
        "unversioned"
    );
    for key in ["classification", "version", "declared_sha256"] {
        assert!(before.provenance[key].is_null());
    }
    let during = artifact.during.as_ref().unwrap();
    assert_eq!(during.path.parent().unwrap().file_name().unwrap(), "01");
    assert_eq!(
        during.logical_name,
        during.path.file_name().unwrap().to_string_lossy()
    );
}

#[test]
fn remediation_is_matched_by_subject_and_digest() {
    let root = tempfile::tempdir().unwrap();
    let mut pairs = Vec::new();
    for subject in ["one", "two"] {
        let old = side(subject, "before", Some("1.0"), "before.js");
        let mut during = side(subject, "during", Some("1.1"), "during.js");
        during["sha256"] = json!("same");
        let after = side(
            subject,
            "after",
            Some("1.2"),
            &format!("{subject}-fixed.js"),
        );
        pairs.extend([
            pair("attack", old, during.clone()),
            pair("remediation", during, after),
        ]);
    }
    write_tree(root.path(), &pairs);
    let artifacts = load_artifacts(root.path()).unwrap();
    assert_eq!(artifacts.len(), 2);
    assert_eq!(
        artifacts[0].after.as_ref().unwrap().logical_name,
        "one-fixed.js"
    );
    assert_eq!(
        artifacts[1].after.as_ref().unwrap().logical_name,
        "two-fixed.js"
    );
}

#[test]
fn baseline_chain_is_attached_once_per_subject_and_compares_adjacent_releases() {
    let root = tempfile::tempdir().unwrap();
    let old = side("demo", "before", Some("1.0"), "1.0.tgz");
    let next = side("demo", "before", Some("1.1"), "1.1.tgz");
    let latest = side("demo", "before", Some("1.2"), "1.2.tgz");
    write_tree(
        root.path(),
        &[
            pair(
                "attack",
                latest.clone(),
                side("demo", "during", Some("1.3"), "1.3.tgz"),
            ),
            pair(
                "attack",
                latest.clone(),
                side("demo", "during", Some("1.4"), "1.4.tgz"),
            ),
            pair("baseline", old, next.clone()),
            pair("baseline", next, latest),
        ],
    );
    let artifacts = load_artifacts(root.path()).unwrap();
    assert_eq!(artifacts.len(), 2);
    assert_eq!(
        artifacts
            .iter()
            .map(|a| a.baseline.len())
            .collect::<Vec<_>>(),
        [3, 0]
    );
    let work: Vec<_> = artifacts
        .iter()
        .enumerate()
        .flat_map(|(i, a)| transitions_of(i, a))
        .collect();
    assert_eq!(work.iter().filter(|w| w.kind.starts_with("bb")).count(), 2);
    assert_eq!(work.iter().filter(|w| w.kind == "bd").count(), 2);
}

#[test]
fn clean_only_subjects_and_remediation_without_clean_comparators_are_judged() {
    let root = tempfile::tempdir().unwrap();
    write_tree(
        root.path(),
        &[
            pair(
                "baseline",
                side("clean", "before", Some("1.0"), "1.0.tgz"),
                side("clean", "before", Some("1.1"), "1.1.tgz"),
            ),
            pair(
                "remediation",
                side("demo", "during", Some("1.1"), "during.js"),
                side("demo", "after", Some("1.2"), "after.js"),
            ),
        ],
    );
    let artifacts = load_artifacts(root.path()).unwrap();
    assert_eq!(artifacts.len(), 2);
    assert!(artifacts[0].during.is_none());
    assert!(artifacts[1].before.is_none());
    assert_eq!(transitions_of(0, &artifacts[0])[0].kind, "bb0");
    assert_eq!(transitions_of(1, &artifacts[1])[0].kind, "da");
    assert_eq!(issue("da", &transition(true)), Some("FP-REMEDIATION"));
    assert_eq!(issue("bb0", &transition(true)), Some("FP-BASELINE"));
}

#[test]
fn missing_sample_drops_its_attack_comparison_and_bad_yaml_fails() {
    let root = tempfile::tempdir().unwrap();
    write_tree(root.path(), &attack_pairs()[..1]);
    fs::remove_file(
        root.path()
            .join("incident/demo/before/unversioned/before.js"),
    )
    .unwrap();
    assert!(load_artifacts(root.path()).unwrap().is_empty());
    fs::write(root.path().join("incident/pairs.yaml"), "pairs: [invalid").unwrap();
    assert!(load_artifacts(root.path()).is_err());
}

#[test]
fn incident_year_sorts_artifacts_and_check_corpus_does_not_need_a_detector() {
    let root = tempfile::tempdir().unwrap();
    write_tree(root.path(), &attack_pairs());
    fs::write(
        root.path().join("incident/README.md"),
        "# Incident\n**When:** 2026-01-01\n",
    )
    .unwrap();
    assert_eq!(load_artifacts(root.path()).unwrap()[0].year, 2026);
    let mut args = args(root.path());
    args.check_corpus = true;
    let mut output = Vec::new();
    assert_eq!(execute(&args, &mut output).unwrap(), 0);
    let report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(
        report,
        json!({"artifacts": 1, "comparisons": {"before->during": 1, "during->after": 1, "before->after": 1}})
    );
}

#[test]
fn independent_input_copies_survive_renames_replacements_and_edits() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source.zip");
    fs::write(&source, b"captured bytes").unwrap();
    let sample = sample(&source);
    let snapshots = snapshot_samples([&sample, &sample], &root.path().join("copies")).unwrap();
    assert_eq!(snapshots.len(), 1);
    let snapshot = &snapshots[&source];
    assert_eq!(
        snapshot.sha256,
        format!("{:x}", Sha256::digest(b"captured bytes"))
    );
    assert_eq!(snapshot.size, 14);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_ne!(
            fs::metadata(&source).unwrap().ino(),
            fs::metadata(&snapshot.path).unwrap().ino()
        );
    }
    let renamed = root.path().join("renamed.zip");
    fs::rename(&source, &renamed).unwrap();
    fs::write(renamed, b"changed original inode").unwrap();
    fs::write(&source, b"replacement file").unwrap();
    assert_eq!(fs::read(&snapshot.path).unwrap(), b"captured bytes");
}

#[test]
fn same_basename_does_not_alias_distinct_inputs() {
    let root = tempfile::tempdir().unwrap();
    let samples: Vec<_> = ["before", "during"]
        .into_iter()
        .map(|phase| {
            let path = root.path().join(phase).join("sample.zip");
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, phase).unwrap();
            sample(path)
        })
        .collect();
    let snapshots = snapshot_samples(&samples, &root.path().join("copies")).unwrap();
    assert_eq!(snapshots.len(), 2);
    for sample in &samples {
        assert_eq!(
            fs::read_to_string(&snapshots[&sample.path].path).unwrap(),
            sample
                .path
                .parent()
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy()
        );
    }
}

#[test]
fn missing_inputs_and_modifications_during_copy_are_errors() {
    let root = tempfile::tempdir().unwrap();
    let sample = sample(root.path().join("source.zip"));
    assert!(snapshot_samples([&sample], &root.path().join("missing")).is_err());
    fs::write(&sample.path, b"bytes").unwrap();
    let before = fs::metadata(&sample.path).unwrap();
    fs::write(&sample.path, b"changed").unwrap();
    let after = fs::metadata(&sample.path).unwrap();
    assert!(!unchanged(&before, &after, 5));
    assert!(!unchanged(&after, &after, 5));
}

#[test]
fn trait_snapshot_preserves_working_edits_and_excludes_git() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("working");
    fs::create_dir_all(source.join(".git")).unwrap();
    fs::create_dir_all(source.join("nested")).unwrap();
    fs::write(source.join("rule.yaml"), "working edit").unwrap();
    fs::write(source.join("nested/other.yaml"), "nested edit").unwrap();
    fs::write(source.join(".git/config"), "not rules").unwrap();
    let snapshot = snapshot_traits(Some(&source), &root.path().join("snapshot"))
        .unwrap()
        .unwrap();
    fs::write(source.join("rule.yaml"), "later edit").unwrap();
    assert_eq!(
        fs::read_to_string(snapshot.join("rule.yaml")).unwrap(),
        "working edit"
    );
    assert_eq!(
        fs::read_to_string(snapshot.join("nested/other.yaml")).unwrap(),
        "nested edit"
    );
    assert!(!snapshot.join(".git").exists());
    assert!(
        snapshot_traits(None, Path::new("unused"))
            .unwrap()
            .is_none()
    );
}

#[test]
fn worker_budget_leaves_room_for_scanner_threads_and_memory() {
    for (cpus, expected) in [(0, 1), (1, 1), (2, 1), (4, 2), (16, 8), (64, 8)] {
        assert_eq!(default_jobs(cpus), expected);
    }
}

#[test]
fn selected_claims_and_measured_hashes_survive_manifest_edits() {
    let root = tempfile::tempdir().unwrap();
    let mut pairs = attack_pairs();
    pairs[0]["new"]["classification"] = json!("affected");
    pairs[0]["new"]["sha256"] = json!("unverified-claim");
    // Match remediation to the same declared digest.
    pairs[1]["old"]["sha256"] = json!("unverified-claim");
    write_tree(root.path(), &pairs);
    let artifacts = load_artifacts(root.path()).unwrap();
    let artifact = &artifacts[0];
    let work = transitions_of(0, artifact);
    let snapshots = snapshot_samples(
        work.iter().flat_map(|w| [&w.old, &w.new]),
        &root.path().join("copies"),
    )
    .unwrap();
    fs::write(root.path().join("incident/pairs.yaml"), "pairs: []\n").unwrap();
    #[derive(Default)]
    struct Stream {
        bytes: Vec<u8>,
        flushes: usize,
    }
    impl Write for Stream {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }
    let mut stream = Stream::default();
    write_stream_record(
        &mut stream,
        &work[0],
        artifact,
        &transition(false),
        &snapshots,
    )
    .unwrap();
    assert_eq!(stream.flushes, 1);
    let record: Value = serde_json::from_slice(&stream.bytes).unwrap();
    assert_eq!(record["issue"], "MISS");
    assert_eq!(record["expected_detected"], true);
    assert_eq!(
        record["new"]["provenance"],
        json!({"record": "incident", "phase": "during", "classification": "affected", "version": "01", "declared_sha256": "unverified-claim"})
    );
    assert_eq!(
        record["new"]["sha256"],
        format!("{:x}", Sha256::digest(b"during"))
    );
    assert_eq!(record["evidence_warnings"][0]["classification"], "affected");
    assert_eq!(record["old"]["path"], json!(work[0].old.path));
}

#[cfg(unix)]
fn executable(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(unix)]
#[test]
fn detector_copy_survives_rebuild_symlink_retargeting_and_path_lookup() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("detector");
    executable(&source, "original detector");
    let alias = root.path().join("isomer");
    symlink(&source, &alias).unwrap();
    let captured = snapshot_executable(&alias, &root.path().join("copy")).unwrap();
    assert!(!captured.path.is_symlink());
    assert_eq!(
        captured.sha256,
        format!("{:x}", Sha256::digest(b"original detector"))
    );
    assert_eq!(captured.size, 17);
    assert_eq!(
        fs::metadata(&captured.path).unwrap().permissions().mode() & 0o7777,
        0o500
    );
    fs::write(&source, "rebuilt detector").unwrap();
    fs::remove_file(source).unwrap();
    assert_eq!(
        fs::read_to_string(captured.path).unwrap(),
        "original detector"
    );
    assert!(snapshot_executable(Path::new("sh"), &root.path().join("path-copy")).is_ok());
}

#[cfg(unix)]
#[test]
fn nonexecutable_and_missing_detectors_abort_before_comparisons() {
    let root = tempfile::tempdir().unwrap();
    write_tree(root.path(), &attack_pairs());
    let args = args(root.path());
    for contents in [None, Some("not executable")] {
        if let Some(contents) = contents {
            fs::write(&args.isomer, contents).unwrap();
        }
        let error = execute(&args, &mut Vec::new()).unwrap_err();
        assert!(format!("{error:#}").contains("cannot snapshot executable"));
    }
    assert!(snapshot_executable(root.path(), &root.path().join("copy")).is_err());
}

#[cfg(unix)]
#[test]
fn existing_stream_and_input_snapshot_failure_start_no_comparisons() {
    let root = tempfile::tempdir().unwrap();
    write_tree(root.path(), &attack_pairs());
    let mut args = args(root.path());
    let marker = root.path().join("started");
    executable(
        &args.isomer,
        &format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
    );
    let path = root.path().join("results.jsonl");
    fs::write(&path, "previous run\n").unwrap();
    args.stream_results = Some(path.clone());
    assert!(execute(&args, &mut Vec::new()).is_err());
    assert_eq!(fs::read_to_string(path).unwrap(), "previous run\n");
    assert!(!marker.exists());
    // Directly exercise setup with an already-selected input that vanished.
    let missing = sample(root.path().join("missing.zip"));
    assert!(snapshot_samples([&missing], &root.path().join("copies")).is_err());
    assert!(!marker.exists());
}

#[cfg(unix)]
#[test]
fn runner_passes_offline_flags_and_traits_and_handles_timeout() {
    let root = tempfile::tempdir().unwrap();
    let detector = root.path().join("detector");
    executable(
        &detector,
        r##"#!/bin/sh
test "$1" = --offline && test "$2" = fs && test "$3" = before.zip && test "$4" = during.zip || exit 2
test "$5" = --format && test "$6" = json && test "$7" = --fail-on && test "$8" = high || exit 2
test "$CLEAVE_TRAITS_DIR" = /captured/traits || exit 2
printf '%s\n' '{"verdict":{"gate":{"fail":true,"severity":"high"}}}'
exit 1
"##,
    );
    let run = run_transition(
        &detector,
        Some(Path::new("/captured/traits")),
        "high",
        &sample("before.zip"),
        &sample("during.zip"),
        None,
    )
    .unwrap();
    assert_eq!(run.detected, Some(true));
    executable(&detector, "#!/bin/sh\nsleep 20 &\nwait\n");
    let started = Instant::now();
    let run = run_transition(
        &detector,
        None,
        "high",
        &sample("old"),
        &sample("new"),
        Some(Duration::from_millis(50)),
    )
    .unwrap();
    assert_eq!(run.error.as_deref(), Some("timeout"));
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[cfg(unix)]
#[test]
fn timeout_also_kills_children_that_outlive_the_scanner() {
    let root = tempfile::tempdir().unwrap();
    let detector = root.path().join("detector");
    executable(&detector, "#!/bin/sh\nsleep 20 &\nexit 0\n");
    let started = Instant::now();
    let run = run_transition(
        &detector,
        None,
        "high",
        &sample("old"),
        &sample("new"),
        Some(Duration::from_millis(50)),
    )
    .unwrap();
    assert_eq!(run.error.as_deref(), Some("timeout"));
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[cfg(unix)]
#[test]
fn streamed_results_are_visible_in_completion_order_and_preserve_final_gate() {
    let root = tempfile::tempdir().unwrap();
    let mut pairs = attack_pairs();
    for pair in &mut pairs {
        for key in ["old", "new"] {
            pair[key]["classification"] = json!("affected");
        }
    }
    write_tree(root.path(), &pairs);
    let mut args = args(root.path());
    args.stream_results = Some(root.path().join("results.jsonl"));
    let release_bd = root.path().join("release-bd");
    let release_da = root.path().join("release-da");
    executable(
        &args.isomer,
        &format!(
            r##"#!/bin/sh
old=$(cat "$3")
new=$(cat "$4")
case "$old:$new" in
  before:after) printf '%s\n' '{{"verdict":{{"gate":{{"fail":true,"severity":"high"}}}}}}'; exit 1 ;;
  before:during) while ! test -f '{}'; do sleep 0.02; done
    printf '%s\n' '{{"verdict":{{"gate":{{"fail":false,"severity":"medium"}}}}}}'; exit 0 ;;
  during:after) while ! test -f '{}'; do sleep 0.02; done
    echo 'scanner unavailable' >&2; exit 2 ;;
  *) echo 'wrong snapshot bytes' >&2; exit 2 ;;
esac
"##,
            release_bd.display(),
            release_da.display()
        ),
    );
    let detector_bytes = fs::read(&args.isomer).unwrap();
    std::thread::scope(|scope| {
        let handle = scope.spawn(|| {
            let mut output = Vec::new();
            let code = execute(&args, &mut output).unwrap();
            (code, output)
        });
        let started = Instant::now();
        let mut changed = false;
        loop {
            let text =
                fs::read_to_string(args.stream_results.as_ref().unwrap()).unwrap_or_default();
            let records: Vec<Value> = text
                .lines()
                .filter_map(|line| serde_json::from_str(line).ok())
                .collect();
            if records.len() >= 2 && !changed {
                assert_eq!(records[1]["issue"], "FP-NET");
                // The remaining runs must use captured bytes after inputs and detector change.
                for artifact in load_artifacts(root.path()).unwrap() {
                    for sample in [artifact.before, artifact.during, artifact.after]
                        .into_iter()
                        .flatten()
                    {
                        fs::write(sample.path, "replacement bytes").unwrap();
                    }
                }
                fs::write(&args.isomer, "rebuilt detector").unwrap();
                fs::write(&release_bd, "go").unwrap();
                changed = true;
            }
            if records.len() >= 3 {
                assert_eq!(records[2]["issue"], "MISS");
                fs::write(&release_da, "go").unwrap();
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "stream results did not arrive: {text}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let (code, output) = handle.join().unwrap();
        assert_eq!(code, 1);
        let summary: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(summary["before_during_detected"], 0);
        assert_eq!(summary["before_after_false_positives"], 1);
        assert_eq!(summary["errors"], 1);
        assert_eq!(
            summary["violations"][0]["issues"].as_array().unwrap().len(),
            3
        );
        let records: Vec<Value> = fs::read_to_string(args.stream_results.as_ref().unwrap())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records[0]["input_snapshot"], "independent-copies");
        assert_eq!(
            records[0]["detector_snapshot"]["sha256"],
            format!("{:x}", Sha256::digest(&detector_bytes))
        );
        assert_eq!(
            records
                .iter()
                .skip(1)
                .map(|r| r["issue"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["FP-NET", "MISS", "ERROR"]
        );
        for record in &records[1..] {
            assert_eq!(record["evidence_warnings"].as_array().unwrap().len(), 2);
            assert!(
                record["old"]["path"]
                    .as_str()
                    .unwrap()
                    .contains("incident/demo/")
            );
            assert_ne!(
                record["old"]["sha256"],
                format!("{:x}", Sha256::digest(b"replacement bytes"))
            );
        }
    });
}
