"""Fast audit-runner regressions; no corpus or scanner required."""
import json
from pathlib import Path
import runpy
import unittest
from unittest.mock import patch, Mock


audit = runpy.run_path(str(Path(__file__).with_name("validate-samples.py")))


class AuditDiagnosticsTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
