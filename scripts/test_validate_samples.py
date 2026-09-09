"""Fast audit-runner regressions; no corpus or scanner required."""
import json
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch, Mock


audit = runpy.run_path(str(Path(__file__).with_name("validate-samples.py")))


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
                  "raw": {"diff": {"summary": {"files_added": 1},
                                   "files": [{"large_source": "not retained"}]}}}
        process = Mock(returncode=1)
        process.communicate.return_value = (json.dumps(report), "")
        sample = audit["SampleFile"](Path("sample.zip"), "sample.zip")
        with patch("subprocess.Popen", return_value=process):
            run = audit["run_transition"]("isomer", None, "high", sample, sample, None)
        self.assertTrue(run.detected)
        self.assertEqual(run.diagnostic, {
            "verdict": verdict, "summary": {"files_added": 1}})

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


class ManifestParserTests(unittest.TestCase):
    def test_both_sequence_indentation_styles(self):
        for indent in (0, 2):
            with self.subTest(indent=indent):
                prefix = " " * indent
                text = "schema_version: 1\nsamples:\n" + "\n".join(prefix + line for line in [
                    "- artifact_id: widget", "  phase: before", "  classification: clean",
                    "  path: widget/before.zip", "  source:", "    path: ignored.zip",
                    "    notes:", "    - artifact_id: not-a-sample",
                    "- artifact_id: widget", "  phase: during", "  classification: malicious",
                    "  path: >-", "    widget/", "    during.zip",
                ]) + "\nunresolved:\n- artifact_id: not-a-sample\n  path: ignored.zip\n"
                self.assertEqual(audit["parse_samples_without_yaml"](text), [
                    {"artifact_id": "widget", "phase": "before", "classification": "clean",
                     "path": "widget/before.zip"},
                    {"artifact_id": "widget", "phase": "during", "classification": "malicious",
                     "path": "widget/ during.zip"},
                ])

    def test_first_field_need_not_be_artifact_id(self):
        text = "samples:\n- phase: before\n  artifact_id: widget\n  path: before.zip\n"
        self.assertEqual(audit["parse_samples_without_yaml"](text), [
            {"phase": "before", "artifact_id": "widget", "path": "before.zip"}])

    def test_comments_do_not_end_samples(self):
        text = "samples: # manifest entries\n# comment\n- artifact_id: widget\n  path: before.zip\n"
        self.assertEqual(audit["parse_samples_without_yaml"](text), [
            {"artifact_id": "widget", "path": "before.zip"}])

    def test_unsupported_syntax_is_not_an_empty_success(self):
        for text in ("samples: [{artifact_id: widget}]\n",
                     "samples:\n- {artifact_id: widget}\n",
                     "samples:\n- *sample_alias\n",
                     "samples:\n  [{artifact_id: widget}]\n"):
            with self.subTest(text=text):
                with self.assertRaisesRegex(ValueError, "unsupported samples syntax"):
                    audit["parse_samples_without_yaml"](text)
        self.assertEqual(audit["parse_samples_without_yaml"]("samples: []\n"), [])

    def test_missing_artifact_id_is_an_error(self):
        with self.assertRaisesRegex(ValueError, "artifact_id"):
            audit["parse_samples_without_yaml"]("samples:\n- phase: during\n  path: payload.js\n")

    def test_manifest_errors_are_not_silently_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "incident" / "samples" / "manifest.yaml"
            manifest.parent.mkdir(parents=True)
            manifest.write_text("samples: [{artifact_id: widget}]\n")
            with patch.dict(audit["load_samples"].__globals__, {"yaml": None}):
                with self.assertRaisesRegex(ValueError, "cannot read sample manifest"):
                    audit["load_artifacts"](Path(directory))


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


if __name__ == "__main__":
    unittest.main()
