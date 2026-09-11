"""Fast audit-runner regressions; no corpus or scanner required."""
import json
import io
import contextlib
import hashlib
import os
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch, Mock
import yaml


audit = runpy.run_path(str(Path(__file__).with_name("validate-samples.py")))


def write_tree(root, pairs, files, record="incident"):
    """Write a miniature artifact tree: what build-artifacts.js generates, in small.

    ``files`` maps ``(subject, phase, release, name)`` to contents; ``pairs`` is the
    record's stated comparisons. The layout is the contract -- four segments under the
    record, then the file under the name it was distributed with.
    """
    for (subject, phase, release, name), body in files.items():
        directory = root / record / subject / phase / release
        directory.mkdir(parents=True, exist_ok=True)
        (directory / name).write_text(body)
    (root / record).mkdir(parents=True, exist_ok=True)
    (root / record / "pairs.yaml").write_text(
        yaml.safe_dump({"record": record, "pairs": pairs}, sort_keys=False))
    return root


def side(subject, phase, version, name, **extra):
    return {"subject": subject, "phase": phase, "version": version, "file": name, **extra}


class DetectorSnapshotTests(unittest.TestCase):
    def test_failed_detector_capture_stops_before_workers(self):
        with tempfile.TemporaryDirectory() as directory:
            sample = audit["SampleFile"](Path(directory) / "sample.zip", "sample.zip")
            artifact = audit["Artifact"]("example", 2026, sample, sample, None)
            for error in [OSError("unreadable detector"), ValueError("detector changed while copying")]:
                stderr = io.StringIO()
                with self.subTest(error=error), patch.dict(audit["main"].__globals__, {
                    "load_artifacts": Mock(return_value=[artifact]),
                    "snapshot_executable": Mock(side_effect=error),
                }), patch("sys.argv", ["validate-samples", "--corpus", directory]), \
                        patch("concurrent.futures.ThreadPoolExecutor") as executor, \
                        contextlib.redirect_stderr(stderr):
                    self.assertEqual(audit["main"](), 2)
                    executor.assert_not_called()
                self.assertIn("cannot snapshot executable", stderr.getvalue())

    def test_copy_survives_rebuild_and_path_lookup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "isomer-test-detector"
            source.write_bytes(b"original detector")
            source.chmod(0o700)
            with patch.dict(os.environ, {"PATH": str(root)}):
                captured = audit["snapshot_executable"](source.name, root / "copy")
            self.assertEqual(captured.sha256, hashlib.sha256(b"original detector").hexdigest())
            self.assertEqual(captured.size, len(b"original detector"))
            self.assertNotEqual(source.stat().st_ino, captured.path.stat().st_ino)
            self.assertEqual(captured.path.stat().st_mode & 0o7777, 0o500)
            source.write_bytes(b"rebuilt detector")
            source.unlink()
            self.assertEqual(captured.path.read_bytes(), b"original detector")

    def test_explicit_path_and_symlink_are_copied_not_followed_later(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "detector"
            source.write_bytes(b"original")
            source.chmod(0o700)
            alias = root / "isomer"
            alias.symlink_to(source)
            captured = audit["snapshot_executable"](str(alias), root / "copy")
            self.assertFalse(captured.path.is_symlink())
            source.write_bytes(b"replacement")
            self.assertEqual(captured.path.read_bytes(), b"original")

    def test_missing_or_nonexecutable_detector_aborts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "not-executable"
            source.write_bytes(b"data")
            source.chmod(0o600)
            for path in [source, root / "missing", root]:
                with self.subTest(path=path), self.assertRaises(FileNotFoundError):
                    audit["snapshot_executable"](str(path), root / "copy")


class AuditDiagnosticsTests(unittest.TestCase):
    def test_clean_net_comparison_does_not_forgive_remediation_detection(self):
        transition = audit["Transition"]
        sample = audit["SampleFile"](Path("sample.zip"), "sample.zip")
        artifact = audit["Artifact"]("example", 2026, sample, sample, sample)
        for net_detected in (False, True):
            with self.subTest(net_detected=net_detected):
                runs = {"bd": transition(True, "high"),
                        "da": transition(True, "high", diagnostic={"repair": True}),
                        "ba": transition(net_detected, "high" if net_detected else "none")}
                result = audit["audit"](artifact, runs)
                self.assertTrue(any(v.startswith("FP-REMEDIATION")
                                    for v in result.violations))
                self.assertEqual(len(result.violations), 1 + int(net_detected))
                self.assertEqual(audit["violation_diagnostics"](result)["during->after"],
                                 {"repair": True})

    def test_retains_exact_verdict_but_not_large_raw_evidence(self):
        verdict = {"gate": {"fail": True, "severity": "high"},
                   "risk": {"old": 0.1, "new": 0.9}}
        report = {"verdict": verdict,
                  "features": {"trait_shift": {"complete": True},
                               "judged_summary": {"overall_roc": 0.1},
                               "scopes": {"metrics": {"roc": 0}},
                               "topology": {"unchanged": 10},
                               "files": [{"large_source": "not retained"}]},
                  "raw": {"diff": {"summary": {"files_added": 1},
                                   "files": [{"large_source": "not retained"}]}}}
        process = Mock(returncode=1)
        process.communicate.return_value = (json.dumps(report), "")
        sample = audit["SampleFile"](Path("sample.zip"), "sample.zip")
        with patch("subprocess.Popen", return_value=process):
            run = audit["run_transition"]("isomer", None, "high", sample, sample, None)
        self.assertTrue(run.detected)
        self.assertEqual(run.diagnostic, {
            "verdict": verdict, "summary": {"files_added": 1},
            "trait_shift": {"complete": True},
            "judged_summary": {"overall_roc": 0.1},
            "scopes": {"metrics": {"roc": 0}},
            "topology": {"unchanged": 10}})

    def test_skipped_trait_files_are_errors_even_with_a_valid_verdict(self):
        sample = audit["SampleFile"](Path("sample.zip"), "sample.zip")
        for detected in (False, True):
            with self.subTest(detected=detected):
                report = {"verdict": {"gate": {"fail": detected, "severity": "high"}}}
                process = Mock(returncode=int(detected))
                process.communicate.return_value = (json.dumps(report),
                    "⚠️  WARNING: skipped 2 trait file(s) this build of isomer could not parse; "
                    "their rules will not run.\n"
                    '   Failed to parse YAML in "traits/example.yaml"\n')
                with patch("subprocess.Popen", return_value=process):
                    run = audit["run_transition"]("isomer", None, "high", sample, sample, None)
                self.assertIsNone(run.detected)
                self.assertIn("incomplete trait coverage", run.error)
                self.assertIn("traits/example.yaml", run.error)
                artifact = audit["Artifact"]("example", 2026, sample, sample, None)
                self.assertTrue(audit["audit"](artifact, {"bd": run}).violations)

    def test_unrelated_scanner_warning_preserves_verdict(self):
        sample = audit["SampleFile"](Path("sample.zip"), "sample.zip")
        process = Mock(returncode=0)
        process.communicate.return_value = (
            json.dumps({"verdict": {"gate": {"fail": False, "severity": "none"}}}),
            "WARNING: optional display feature unavailable\n")
        with patch("subprocess.Popen", return_value=process):
            run = audit["run_transition"]("isomer", None, "high", sample, sample, None)
        self.assertFalse(run.detected)
        self.assertIsNone(run.error)

    def test_diagnostics_do_not_change_audit_expectations(self):
        transition = audit["Transition"]
        sample = audit["SampleFile"](Path("sample.zip"), "sample.zip")
        artifact = audit["Artifact"]("example", 2026, sample, sample, sample)
        runs = {"bd": transition(True, "high", diagnostic={"attack": True}),
                "da": transition(False, "none"),
                "ba": transition(True, "high", diagnostic={"false_positive": True})}
        result = audit["audit"](artifact, runs)
        self.assertEqual(len(result.violations), 1)
        self.assertEqual(audit["violation_diagnostics"](result), {
            "before->after": {"false_positive": True}})
        runs["ba"] = transition(False, "none")
        self.assertEqual(audit["audit"](artifact, runs).violations, [])


class AuditProvenanceTests(unittest.TestCase):
    def test_selected_claims_survive_manifest_edits_and_do_not_forgive_misses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pairs_file = root / "incident" / "pairs.yaml"
            write_tree(root, [{
                "kind": "attack", "expect": "detect",
                "old": side("demo", "before", None, "before.js", classification="clean"),
                "new": side("demo", "during", "01", "during.js",
                            classification="affected", sha256="unverified-claim"),
            }], {
                ("demo", "before", "unversioned", "before.js"): "before",
                ("demo", "during", "01", "during.js"): "during",
            })
            artifact, = audit["load_artifacts"](root)
            snapshots = audit["snapshot_samples"](
                [artifact.before, artifact.during], root / "copies")
            pairs_file.write_text("record: incident\npairs: []\n")
            transition = audit["Transition"](False, "medium")
            stream = io.StringIO()
            audit["write_stream_record"](
                stream, (0, "bd"), artifact, artifact.before, artifact.during,
                transition, snapshots)
            row = json.loads(stream.getvalue())
            self.assertEqual(row["old"]["provenance"]["classification"], "clean")
            self.assertEqual(row["new"]["provenance"], {
                "record": "incident", "phase": "during", "classification": "affected",
                "version": "01", "declared_sha256": "unverified-claim",
            })
            self.assertEqual(row["new"]["sha256"], hashlib.sha256(b"during").hexdigest())
            self.assertTrue(row["expected_detected"])
            self.assertEqual(row["issue"], "MISS")
            result = audit["audit"](artifact, {"bd": transition})
            self.assertTrue(result.violations[0].startswith("MISS"))
            self.assertEqual(row["evidence_warnings"], result.evidence_warnings["bd"])
            self.assertEqual(row["evidence_warnings"][0]["classification"], "affected")
            self.assertEqual(row["evidence_warnings"][0]["side"], "new")

    def test_qualified_evidence_warns_on_hits_misses_and_errors_without_changing_gates(self):
        clean = audit["SampleFile"](Path("clean.js"), "clean.js", {"classification": "clean"})
        for classification in ("affected", "carrier", "baseline_candidate"):
            sample = audit["SampleFile"](Path("sample.js"), "sample.js",
                                         {"classification": classification})
            for transition in (audit["Transition"](True, "high"),
                               audit["Transition"](False, "medium"),
                               audit["Transition"](None, "?", "scanner error")):
                with self.subTest(classification=classification, detected=transition.detected):
                    artifact = audit["Artifact"]("qualified", 2026, clean, sample, clean)
                    runs = {"bd": transition, "da": audit["Transition"](False, "none"),
                            "ba": audit["Transition"](False, "none")}
                    result = audit["audit"](artifact, runs)
                    self.assertEqual(len(result.violations), int(transition.detected is not True))
                    self.assertEqual(set(result.evidence_warnings), {"bd", "da"})
                    self.assertEqual(result.evidence_warnings["bd"][0]["side"], "new")
                    self.assertEqual(result.evidence_warnings["da"][0]["side"], "old")
                    stream = io.StringIO()
                    audit["write_stream_record"](stream, (0, "bd"), artifact, clean, sample, transition)
                    row = json.loads(stream.getvalue())
                    self.assertTrue(row["expected_detected"])
                    expected_issue = None if transition.detected is True else (
                        "ERROR" if transition.error else "MISS")
                    self.assertEqual(row["issue"], expected_issue)
                    self.assertEqual(row["evidence_warnings"], result.evidence_warnings["bd"])

    def test_confirmed_classifications_do_not_get_context_warnings(self):
        for classification in ("clean", "malicious", "remediated", "fixed", None):
            sample = audit["SampleFile"](Path("sample.js"), "sample.js",
                                         {"classification": classification})
            self.assertEqual(audit["evidence_warnings"](sample, sample), [])

    def test_absent_corpus_claims_remain_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_tree(root, [{
                "kind": "attack", "expect": "detect",
                "old": side("demo", "before", None, "before.js"),
                "new": side("demo", "during", None, "during.js"),
            }], {
                ("demo", "before", "unversioned", "before.js"): "before.js",
                ("demo", "during", "unversioned", "during.js"): "during.js",
            })
            artifact, = audit["load_artifacts"](root)
            for sample in (artifact.before, artifact.during):
                for key in ("classification", "version", "declared_sha256"):
                    self.assertIsNone(sample.provenance[key])


class CorpusLoaderTests(unittest.TestCase):
    """The audit reads the comparisons the corpus states; these pin how it reads them."""

    def test_release_directory_addresses_the_file_including_unversioned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_tree(root, [{
                "kind": "attack", "expect": "detect",
                "old": side("demo", "before", "1.0", "demo-1.0.tgz"),
                "new": side("demo", "during", None, "payload.dll"),
            }], {
                ("demo", "before", "1.0", "demo-1.0.tgz"): "clean",
                ("demo", "during", "unversioned", "payload.dll"): "payload",
            })
            artifact, = audit["load_artifacts"](root)
            self.assertEqual(artifact.before.path.parent.name, "1.0")
            self.assertEqual(artifact.during.path.parent.name, "unversioned")
            # The filename is the distributed name, so nothing has to be staged for it.
            self.assertEqual(artifact.during.logical_name, artifact.during.path.name)
            self.assertEqual(artifact.name, "incident/demo")

    def test_remediation_is_matched_per_subject_not_by_digest_alone(self):
        """Two subjects can hold byte-identical compromised releases."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pairs = []
            files = {}
            for subject in ("one", "two"):
                pairs += [{
                    "kind": "attack", "expect": "detect",
                    "old": side(subject, "before", "1.0", "before.js"),
                    "new": side(subject, "during", "1.1", "during.js", sha256="same"),
                }, {
                    "kind": "remediation", "expect": "no-detect",
                    "old": side(subject, "during", "1.1", "during.js", sha256="same"),
                    "new": side(subject, "after", "1.2", f"{subject}-fixed.js"),
                }]
                files |= {
                    (subject, "before", "1.0", "before.js"): "clean",
                    (subject, "during", "1.1", "during.js"): "shared payload",
                    (subject, "after", "1.2", f"{subject}-fixed.js"): f"fixed {subject}",
                }
            write_tree(root, pairs, files)
            artifacts = audit["load_artifacts"](root)
            fixes = {a.during.provenance["record"] + "/" + a.after.path.name for a in artifacts}
            self.assertEqual(fixes, {"incident/one-fixed.js", "incident/two-fixed.js"})

    def test_baseline_chain_is_attached_once_per_subject(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_tree(root, [
                {"kind": "attack", "expect": "detect",
                 "old": side("demo", "before", "1.1", "demo-1.1.tgz"),
                 "new": side("demo", "during", "1.2", "demo-1.2.tgz")},
                {"kind": "attack", "expect": "detect",
                 "old": side("demo", "before", "1.1", "demo-1.1.tgz"),
                 "new": side("demo", "during", "1.3", "demo-1.3.tgz")},
                {"kind": "baseline", "expect": "no-detect",
                 "old": side("demo", "before", "1.0", "demo-1.0.tgz"),
                 "new": side("demo", "before", "1.1", "demo-1.1.tgz")},
            ], {
                ("demo", "before", "1.0", "demo-1.0.tgz"): "v1.0",
                ("demo", "before", "1.1", "demo-1.1.tgz"): "v1.1",
                ("demo", "during", "1.2", "demo-1.2.tgz"): "v1.2",
                ("demo", "during", "1.3", "demo-1.3.tgz"): "v1.3",
            })
            artifacts = audit["load_artifacts"](root)
            self.assertEqual(len(artifacts), 2)
            self.assertEqual([len(a.baseline) for a in artifacts], [2, 0])
            kinds = [k for a in artifacts for k, _, _ in audit["transitions_of"](a)]
            # One baseline comparison in total, not one per compromised release.
            self.assertEqual(kinds.count("bb0"), 1)
            self.assertEqual(kinds.count("bd"), 2)

    def test_clean_only_subject_still_contributes_its_upgrade(self):
        """No compromised release was recovered, but flagging the upgrade is still an FP."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_tree(root, [{
                "kind": "baseline", "expect": "no-detect",
                "old": side("demo", "before", "1.0", "demo-1.0.tgz"),
                "new": side("demo", "before", "1.1", "demo-1.1.tgz"),
            }], {
                ("demo", "before", "1.0", "demo-1.0.tgz"): "v1.0",
                ("demo", "before", "1.1", "demo-1.1.tgz"): "v1.1",
            })
            artifact, = audit["load_artifacts"](root)
            self.assertIsNone(artifact.during)
            self.assertEqual([k for k, _, _ in audit["transitions_of"](artifact)], ["bb0"])
            self.assertEqual(audit["audit"](artifact, {}).violations, [])

    def test_remediation_without_a_clean_comparator_is_still_judged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_tree(root, [{
                "kind": "remediation", "expect": "no-detect",
                "old": side("demo", "during", "1.1", "during.js"),
                "new": side("demo", "after", "1.2", "after.js"),
            }], {
                ("demo", "during", "1.1", "during.js"): "payload",
                ("demo", "after", "1.2", "after.js"): "fixed",
            })
            artifact, = audit["load_artifacts"](root)
            self.assertIsNone(artifact.before)
            self.assertEqual([k for k, _, _ in audit["transitions_of"](artifact)], ["da"])
            detected = audit["Transition"](True, "high")
            self.assertTrue(audit["audit"](artifact, {"da": detected})
                            .violations[0].startswith("FP-REMEDIATION"))

    def test_a_side_whose_file_is_absent_drops_the_comparison(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_tree(root, [{
                "kind": "attack", "expect": "detect",
                "old": side("demo", "before", "1.0", "missing.tgz"),
                "new": side("demo", "during", "1.1", "during.tgz"),
            }], {("demo", "during", "1.1", "during.tgz"): "payload"})
            self.assertEqual(audit["load_artifacts"](root), [])


class TraitSnapshotTests(unittest.TestCase):
    def test_snapshot_preserves_working_edits_and_isolates_later_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "working"
            source.mkdir()
            (source / "rule.yaml").write_text("working edit")
            (source / ".git").mkdir()
            (source / ".git" / "config").write_text("not rules")
            snapshot = Path(audit["snapshot_traits"](str(source), root / "snapshot"))
            (source / "rule.yaml").write_text("later edit")
            self.assertEqual((snapshot / "rule.yaml").read_text(), "working edit")
            self.assertFalse((snapshot / ".git").exists())

    def test_default_trait_discovery_is_unchanged(self):
        self.assertIsNone(audit["snapshot_traits"](None, Path("unused")))


class WorkerBudgetTests(unittest.TestCase):
    def test_default_leaves_room_for_scanner_threads_and_memory(self):
        for cpus, expected in ((None, 1), (1, 1), (2, 1), (4, 2), (16, 8), (64, 8)):
            with self.subTest(cpus=cpus), patch("os.cpu_count", return_value=cpus):
                self.assertEqual(audit["default_jobs"](), expected)

    def test_stream_record_is_complete_and_flushes(self):
        stream = Mock()
        transition = audit["Transition"](True, "high", diagnostic={"x": 1})
        sample = audit["SampleFile"](Path("sample.zip"), "sample.zip")
        artifact = audit["Artifact"]("example", 2026, sample, sample, None)
        audit["write_stream_record"](stream, (7, "bd"), artifact, sample, sample, transition)
        line = stream.write.call_args.args[0]
        self.assertEqual(json.loads(line), {
            "event": "comparison", "artifact": "example", "year": 2026,
            "old": {"path": "sample.zip", "logical_name": "sample.zip"},
            "new": {"path": "sample.zip", "logical_name": "sample.zip"},
            "expected_detected": True, "issue": None,
            "evidence_warnings": [],
            "artifact_index": 7, "transition": "bd", "detected": True,
            "severity": "high", "error": None, "diagnostic": {"x": 1},
        })
        stream.flush.assert_called_once_with()


class InputSnapshotTests(unittest.TestCase):
    def test_copies_survive_renames_replacements_and_in_place_edits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.zip"
            source.write_bytes(b"captured bytes")
            sample = audit["SampleFile"](source, "release-1.0.zip")
            snapshots = audit["snapshot_samples"]([sample, sample], root / "copies")
            self.assertEqual(len(snapshots), 1)
            snapshot = snapshots[source]
            self.assertEqual(snapshot.sha256, hashlib.sha256(b"captured bytes").hexdigest())
            self.assertEqual(snapshot.size, len(b"captured bytes"))
            self.assertNotEqual(snapshot.path.stat().st_ino, source.stat().st_ino)
            renamed = source.rename(root / "renamed.zip")
            renamed.write_bytes(b"changed original inode")
            source.write_bytes(b"replacement file")
            self.assertEqual(snapshot.path.read_bytes(), b"captured bytes")

    def test_same_basename_does_not_alias_distinct_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            samples = []
            for side in ("before", "during"):
                source = root / side / "sample.zip"
                source.parent.mkdir()
                source.write_bytes(side.encode())
                samples.append(audit["SampleFile"](source, "sample.zip"))
            snapshots = audit["snapshot_samples"](samples, root / "copies")
            self.assertEqual(len(snapshots), 2)
            for sample in samples:
                self.assertEqual(snapshots[sample.path].path.read_bytes(),
                                 sample.path.parent.name.encode())

    def test_missing_input_and_changes_during_copy_are_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.zip"
            sample = audit["SampleFile"](source, "sample.zip")
            with self.assertRaises(FileNotFoundError):
                audit["snapshot_samples"]([sample], root / "missing")
            source.write_bytes(b"bytes")
            before = Mock(st_size=5, st_mtime_ns=10, st_ctime_ns=10)
            after = Mock(st_size=5, st_mtime_ns=11, st_ctime_ns=11)
            with patch("os.fstat", side_effect=[before, after]), \
                    self.assertRaisesRegex(ValueError, "input changed while being copied"):
                audit["snapshot_samples"]([sample], root / "changed")


class StreamIntegrationTests(unittest.TestCase):
    def test_out_of_order_results_are_visible_before_next_completion_and_keep_final_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "results.jsonl"
            source = Path(directory) / "sample.zip"
            source.write_bytes(b"captured bytes")
            sample = audit["SampleFile"](source, "release-1.0.zip",
                                         {"classification": "affected"})
            artifact = audit["Artifact"]("example", 2026, sample, sample, sample)
            # Completion order: clean->after false positive, missed attack,
            # failed remediation lookup. Each prior record must already be
            # readable while the next result is being obtained.
            futures = [Mock(), Mock(), Mock()]
            def complete(index, transition):
                def result():
                    # Simulate an acquisition process replacing a queued input.
                    source.write_bytes(b"replacement bytes")
                    for call in executor.submit.call_args_list:
                        self.assertEqual(call.args[1], "/captured/isomer")
                        for copied in call.args[4:6]:
                            self.assertNotEqual(copied.path, source)
                            self.assertEqual(copied.path.read_bytes(), b"captured bytes")
                            self.assertEqual(copied.logical_name, "release-1.0.zip")
                    records = [json.loads(line) for line in path.read_text().splitlines()]
                    self.assertEqual(len(records), index + 1)
                    if index:
                        self.assertEqual(records[1]["issue"], "FP-NET")
                    if isinstance(transition, Exception):
                        raise transition
                    return transition
                return result
            futures[2].result.side_effect = complete(0, audit["Transition"](True, "high"))
            futures[0].result.side_effect = complete(1, audit["Transition"](False, "medium"))
            futures[1].result.side_effect = complete(2, OSError("scanner unavailable"))
            executor = Mock()
            executor.__enter__ = Mock(return_value=executor)
            executor.__exit__ = Mock(return_value=False)
            executor.submit.side_effect = futures
            stdout = io.StringIO()
            with patch.dict(audit["main"].__globals__, {
                "load_artifacts": Mock(return_value=[artifact]),
                "snapshot_executable": Mock(return_value=audit["SnapshotFile"](
                    Path("/captured/isomer"), "detector-digest", 123)),
                "snapshot_traits": Mock(return_value=None),  # isolated rule snapshot
            }), patch("sys.argv", ["validate-samples", "--corpus", directory,
                                   "--stream-results", str(path), "--json"]), \
                    patch("concurrent.futures.ThreadPoolExecutor", return_value=executor), \
                    patch("concurrent.futures.as_completed", return_value=iter(
                        [futures[2], futures[0], futures[1]])), \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(audit["main"](), 1)
            records = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(records[0]["input_snapshot"], "independent-copies")
            self.assertEqual(records[0]["detector_snapshot"], {
                "path": "/captured/isomer", "sha256": "detector-digest", "size": 123})
            for record in records[1:]:
                self.assertEqual(record["old"]["path"], str(source))
                self.assertEqual(record["old"]["sha256"],
                                 hashlib.sha256(b"captured bytes").hexdigest())
                self.assertEqual(record["old"]["size"], len(b"captured bytes"))
            self.assertEqual([r["issue"] for r in records[1:]], ["FP-NET", "MISS", "ERROR"])
            summary = json.loads(stdout.getvalue())
            self.assertEqual(summary["before_during_detected"], 0)
            self.assertEqual(summary["before_after_false_positives"], 1)
            self.assertEqual(summary["errors"], 1)
            self.assertEqual(len(summary["violations"][0]["issues"]), 3)
            self.assertEqual(summary["evidence_warnings"], [{
                "artifact": "example", "transitions": {
                    record["transition"]: record["evidence_warnings"]
                    for record in records[1:]
                },
            }])
            self.assertTrue(all(len(record["evidence_warnings"]) == 2
                                for record in records[1:]))

    def test_existing_stream_is_preserved_and_no_comparisons_are_started(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "results.jsonl"
            path.write_text("previous run\n")
            sample = audit["SampleFile"](Path("sample.zip"), "sample.zip")
            artifact = audit["Artifact"]("example", 2026, sample, sample, None)
            with patch.dict(audit["main"].__globals__, {
                "load_artifacts": Mock(return_value=[artifact]),
                "snapshot_executable": Mock(return_value=audit["SnapshotFile"](
                    Path("/captured/isomer"), "detector-digest", 123)),
                "snapshot_traits": Mock(return_value=None),  # isolated rule snapshot
            }), patch("sys.argv", ["validate-samples", "--corpus", directory,
                                   "--stream-results", str(path)]), \
                    patch("concurrent.futures.ThreadPoolExecutor") as executor, \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(audit["main"](), 2)
                executor.assert_not_called()
            self.assertEqual(path.read_text(), "previous run\n")

    def test_snapshot_failure_aborts_before_any_comparisons(self):
        with tempfile.TemporaryDirectory() as directory:
            sample = audit["SampleFile"](Path(directory) / "missing.zip", "missing.zip")
            artifact = audit["Artifact"]("example", 2026, sample, sample, None)
            stderr = io.StringIO()
            with patch.dict(audit["main"].__globals__, {
                "load_artifacts": Mock(return_value=[artifact]),
                "snapshot_executable": Mock(return_value=audit["SnapshotFile"](
                    Path("/captured/isomer"), "detector-digest", 123)),
                "snapshot_traits": Mock(return_value=None),  # isolated rule snapshot
            }), patch("sys.argv", ["validate-samples", "--corpus", directory]), \
                    patch("concurrent.futures.ThreadPoolExecutor") as executor, \
                    contextlib.redirect_stderr(stderr):
                self.assertEqual(audit["main"](), 2)
                executor.assert_not_called()
            self.assertIn("cannot snapshot inputs", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
