#!/usr/bin/env python3
"""isomer self-audit against the supply-chain attack corpus.

Each attack ships an artifact in up to three phases — ``before`` (clean),
``during`` (compromised), and ``after`` (remediated). isomer is a *differential*
detector, so what it should say is defined by the transition, not the file:

    before -> during   MUST be detected      (the attack was introduced)
    during -> after    must NOT be detected   (remediation is not an attack)
    before -> after    must NOT be detected   (clean -> patched is not an attack)

"Detected" means isomer's gate fails at the chosen severity (``--fail-on high``
by default) — the exact signal a CI check keys on. Every transition that breaks
its expectation is a VIOLATION:

    MISS            before -> during did not trip the gate  (a missed attack)
    FP-REMEDIATION  during -> after tripped the gate         (remediation flagged)
    FP-NET          before -> after tripped the gate         (clean->patched flagged)

The script prints a per-violation report and a summary, and exits non-zero when
there is any violation or error — so ``make validate-samples`` gates on it.

Corpus, binary, and detection bar are all overridable; see ``--help``.
"""
from __future__ import annotations

import argparse
import ast
import concurrent.futures as cf
import json
import os
import re
import signal
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml
except ModuleNotFoundError:
    yaml = None

YAML_ERROR = getattr(yaml, "YAMLError", ValueError)

# Classification buckets. A phase can carry several samples (e.g. a clean
# release shipped alongside the compromised one); pick by classification so the
# pair is genuinely attack-vs-not, not just phase-vs-phase.
COMPROMISED = ("malicious", "affected", "carrier")
CLEAN = ("clean", "baseline_candidate")
REMEDIATED = ("remediated", "clean", "fixed")

SEVERITY_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Artifact:
    name: str
    year: int
    before: Path
    during: Path
    after: Path | None


@dataclass
class Transition:
    """One old->new isomer run: whether it was detected, and why."""

    detected: bool | None  # None on error
    severity: str
    error: str | None = None


@dataclass
class Result:
    name: str
    year: int
    bd: Transition
    da: Transition | None = None
    ba: Transition | None = None
    violations: list[str] = field(default_factory=list)


def scalar(value: str) -> str:
    """Decode the quoted scalar forms used by sample manifests."""
    value = value.strip()
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1].replace("''", "'")
    if value.startswith('"') and value.endswith('"'):
        try:
            decoded = ast.literal_eval(value)
        except (SyntaxError, ValueError):
            return value[1:-1]
        return decoded if isinstance(decoded, str) else value[1:-1]
    return value


def parse_samples_without_yaml(text: str) -> list[dict]:
    """Read the sample records without requiring a third-party YAML package.

    The corpus manifests are full YAML, but the audit only needs five scalar
    fields from entries under the top-level ``samples`` sequence. This small
    fallback deliberately understands only that subset; PyYAML remains the
    preferred parser when installed.
    """
    lines = text.splitlines()
    in_samples = False
    records: list[dict] = []
    current: dict | None = None
    i = 0

    def finish() -> None:
        if current and current.get("artifact_id"):
            records.append(current)

    while i < len(lines):
        line = lines[i]
        if line == "samples:":
            in_samples = True
            i += 1
            continue
        if in_samples and line and not line.startswith(" "):
            break
        if not in_samples:
            i += 1
            continue

        item = re.match(r"^  -(?:\s+([A-Za-z_][\w-]*):\s*(.*))?$", line)
        if item:
            finish()
            current = {}
            if item.group(1) == "artifact_id" and item.group(2):
                current["artifact_id"] = scalar(item.group(2))
            i += 1
            continue

        field = re.match(
            r"^    (artifact_id|phase|classification|path|sha256):(?:\s*(.*))?$",
            line,
        )
        if not field or current is None:
            i += 1
            continue

        key, value = field.group(1), field.group(2) or ""
        if value in (">", ">-", "|", "|-", ">+", "|+"):
            folded = value.startswith(">")
            parts: list[str] = []
            i += 1
            while i < len(lines) and (not lines[i] or lines[i].startswith("     ")):
                parts.append(lines[i].strip())
                i += 1
            current[key] = (" " if folded else "\n").join(parts).strip()
            continue
        current[key] = scalar(value)
        i += 1

    finish()
    return records


def load_samples(manifest: Path) -> list[dict]:
    text = manifest.read_text()
    if yaml is not None:
        doc = yaml.safe_load(text) or {}
        return doc.get("samples") or []
    return parse_samples_without_yaml(text)


def incident_year(meta: Path) -> int:
    """Return the top-level incident year, or sort undated records last.

    Manifest ``retrieved_at`` values describe when this corpus was assembled,
    not when the release changed. The curated metadata's top-level
    ``start_date`` is the only common historical timestamp suitable for
    ordering the calibration set.
    """
    try:
        text = meta.read_text()
    except OSError:
        return 9999
    match = re.search(r"^  start_date:\s*(\d{4})(?:-\d{2}-\d{2})?\s*$", text, re.M)
    return int(match.group(1)) if match else 9999


def extension(path: str | None) -> str:
    return Path(path).suffix.lower() if path else ""


def pick(samples: list[dict], prefer: tuple[str, ...], root: Path,
         match_path: str | None = None,
         exclude_sha256: str | None = None) -> dict | None:
    """Pick a present sample, preferring class and matching file form.

    A preserved incident report or source fragment is evidence, but it is not
    a meaningful old/new comparator for a release archive. Once a reference
    path exists, require the same suffix before pairing another phase; this
    still lets a reconstructed ``.tgz`` win over a loose ``.js`` payload.
    """
    candidates = [
        (i, s) for i, s in enumerate(samples)
        if s.get("path") and (root / s["path"]).is_file()
        and (exclude_sha256 is None or s.get("sha256") != exclude_sha256)
    ]
    if not candidates:
        return None

    if match_path:
        matching = [
            item for item in candidates
            if extension(item[1].get("path")) == extension(match_path)
        ]
        if not matching:
            return None
        candidates = matching

    def rank(item: tuple[int, dict]) -> tuple[int, int, int]:
        i, sample = item
        cls = sample.get("classification")
        class_rank = prefer.index(cls) if cls in prefer else len(prefer)
        extension_rank = 0 if extension(sample.get("path")) == extension(match_path) else 1
        return class_rank, extension_rank, i

    return min(candidates, key=rank)[1]


def load_artifacts(corpus: Path) -> list[Artifact]:
    """One Artifact per (attack, artifact_id) with at least before+during on disk."""
    out: list[Artifact] = []
    for manifest in sorted(corpus.glob("*/samples/manifest.yaml")):
        try:
            samples = load_samples(manifest)
        except (OSError, ValueError, YAML_ERROR):
            continue
        attack = manifest.parent.parent.name
        base = manifest.parent
        year = incident_year(base.parent / "meta.yaml")
        by_art: dict[str, dict[str, list[dict]]] = {}
        for s in samples:
            by_art.setdefault(s.get("artifact_id", "?"), {}).setdefault(
                s.get("phase"), []
            ).append(s)

        for art, phases in by_art.items():
            before = pick(phases.get("before", []), CLEAN, base)
            before_path = before.get("path") if before else None
            during = pick(
                phases.get("during", []), COMPROMISED, base, before_path,
                before.get("sha256") if before else None,
            )
            # Some incidents preserve the clean archive alongside a payload
            # fragment or extracted source file. Fall back across formats only
            # when a same-format candidate exists but is byte-identical to the
            # clean baseline (as in W3 Total Cache). Without that guard,
            # historical HTML/TXT/diff reports would masquerade as release
            # comparators. In the fallback case incomparable after phases stay
            # unset below.
            if not during:
                duplicate = pick(phases.get("during", []), COMPROMISED, base, before_path)
                if (
                    duplicate
                    and before
                    and before.get("sha256")
                    and duplicate.get("sha256") == before.get("sha256")
                ):
                    during = pick(
                        phases.get("during", []), COMPROMISED, base,
                        exclude_sha256=before.get("sha256"),
                    )
            during_path = during.get("path") if during else before_path
            after = pick(phases.get("after", []), REMEDIATED, base, during_path)
            if not (before and during):
                continue

            def path(sample: dict | None) -> Path | None:
                if not sample:
                    return None
                p = base / sample.get("path", "")
                return p if p.is_file() else None

            bp, dp, ap = path(before), path(during), path(after)
            if bp and dp:
                out.append(Artifact(f"{attack}/{art}", year, bp, dp, ap))
    out.sort(key=lambda artifact: (artifact.year, artifact.name))
    return out


def run_transition(isomer: str, traits: str | None, fail_on: str,
                   old: Path, new: Path, timeout: int | None) -> Transition:
    env = dict(os.environ)
    if traits:
        env["CLEAVE_TRAITS_DIR"] = traits
    # `--offline` keeps the audit about the deterministic rubric: no model round
    # trip, and crucially no LLM verdict escalation, so the pass/fail is
    # reproducible on any machine (an empty ISOMER_LLM still falls back to a
    # localhost endpoint, which --offline hard-disables).
    cmd = [isomer, "--offline", "fs", str(old), str(new),
           "--format", "json", "--fail-on", fail_on]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True, env=env, start_new_session=True)
    try:
        if timeout is None:
            stdout, stderr = p.communicate()
        else:
            stdout, stderr = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        # isomer may have parser/build children; kill the whole per-comparison
        # session so one pathological archive cannot keep a serial audit alive.
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        p.communicate()
        return Transition(None, "?", "timeout")
    # isomer exits 0 (clean) or 1 (gate failed); anything else is a real error.
    if p.returncode not in (0, 1):
        return Transition(None, "?", (stderr or "").strip().splitlines()[-1:][0]
                          if stderr.strip() else f"exit {p.returncode}")
    try:
        gate = json.loads(stdout)["verdict"]["gate"]
    except (ValueError, KeyError):
        return Transition(None, "?", "unparseable json")
    # `gate.severity` is the severity the active --gate actually evaluated
    # (new-only by default), so a MISS reads as the below-threshold level the
    # gate saw — not a pre-existing critical the gate never keyed on.
    return Transition(bool(gate["fail"]), gate.get("severity", "?"))


def audit(art: Artifact, isomer: str, traits: str | None, fail_on: str,
          timeout: int) -> Result:
    def go(old: Path, new: Path) -> Transition:
        return run_transition(isomer, traits, fail_on, old, new, timeout)

    bd = go(art.before, art.during)
    da = go(art.during, art.after) if art.after else None
    ba = go(art.before, art.after) if art.after else None
    res = Result(art.name, art.year, bd, da, ba)

    if bd.error:
        res.violations.append(f"ERROR before->during: {bd.error}")
    elif bd.detected is False:
        res.violations.append(f"MISS before->during not detected (sev={bd.severity})")
    if da:
        if da.error:
            res.violations.append(f"ERROR during->after: {da.error}")
        # The new side can restore a capability that the clean `before` had
        # and the malicious `during` removed. A standalone during->after diff
        # calls that newly-present-on-the-old-side trait "new"; when the
        # before->after comparison is clean, this is a baseline artifact, not
        # a remediation false positive.
        elif da.detected and not (ba and ba.detected is False):
            res.violations.append(f"FP-REMEDIATION during->after detected (sev={da.severity})")
    if ba:
        if ba.error:
            res.violations.append(f"ERROR before->after: {ba.error}")
        elif ba.detected:
            res.violations.append(f"FP-NET before->after detected (sev={ba.severity})")
    return res


def default_isomer() -> str:
    here = Path(__file__).resolve().parent.parent
    for cand in (here / "target/release/isomer", here / "target/debug/isomer"):
        if cand.is_file():
            return str(cand)
    return "isomer"


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Audit isomer against the supply-chain attack corpus.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("--corpus", type=Path,
                    default=Path(os.environ.get("ISOMER_SAMPLES_DIR",
                                Path.home() / "src/supplychain-attack-data/oss/attacks")),
                    help="corpus root holding <attack>/samples/manifest.yaml")
    ap.add_argument("--isomer", default=os.environ.get("ISOMER", default_isomer()),
                    help="isomer binary")
    ap.add_argument("--traits", default=os.environ.get("CLEAVE_TRAITS_DIR"),
                    help="trait directory (CLEAVE_TRAITS_DIR)")
    ap.add_argument("--fail-on", default="high",
                    choices=["low", "medium", "high", "critical"],
                    help="severity that counts as a detection")
    ap.add_argument("--jobs", type=int, default=1,
                    help="parallel artifacts (1 keeps resource use and output deterministic)")
    ap.add_argument("--timeout", type=int, default=0,
                    help="per-run seconds (0 = unlimited; timed-out comparisons are errors)")
    ap.add_argument("--limit", type=int, default=0, help="cap artifacts (0=all)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    if not args.corpus.is_dir():
        print(f"validate-samples: corpus not found at {args.corpus}\n"
              f"  set ISOMER_SAMPLES_DIR or pass --corpus.", file=sys.stderr)
        return 2

    artifacts = load_artifacts(args.corpus)
    if args.limit:
        artifacts = artifacts[: args.limit]
    if not artifacts:
        print(f"validate-samples: no before+during pairs under {args.corpus}", file=sys.stderr)
        return 2

    print(f"auditing {len(artifacts)} artifacts against {args.isomer} "
          f"(detect = fail-on {args.fail_on})…", file=sys.stderr)

    timeout = args.timeout or None
    results: list[Result] = []
    with cf.ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futs = {ex.submit(audit, a, args.isomer, args.traits, args.fail_on,
                          timeout): a for a in artifacts}
        for i, fut in enumerate(cf.as_completed(futs), 1):
            results.append(fut.result())
            print(f"\r  {i}/{len(artifacts)}", end="", file=sys.stderr, flush=True)
    print("", file=sys.stderr)
    results.sort(key=lambda r: (r.year, r.name))

    # Tallies.
    bd_ok = sum(1 for r in results if r.bd.detected)
    bd_total = sum(1 for r in results if r.bd.detected is not None)
    da_seen = [r for r in results if r.da and r.da.detected is not None]
    ba_seen = [r for r in results if r.ba and r.ba.detected is not None]
    da_fp = sum(1 for r in da_seen if r.da.detected)
    ba_fp = sum(1 for r in ba_seen if r.ba.detected)
    violations = [r for r in results if r.violations]
    errors = sum(1 for r in results
                 for t in (r.bd, r.da, r.ba) if t and t.error)

    if args.json:
        print(json.dumps({
            "artifacts": len(results),
            "before_during_detected": bd_ok, "before_during_total": bd_total,
            "during_after_false_positives": da_fp, "during_after_total": len(da_seen),
            "before_after_false_positives": ba_fp, "before_after_total": len(ba_seen),
            "errors": errors,
            "violations": [{"artifact": r.name, "issues": r.violations} for r in violations],
        }, indent=2))
        return 1 if violations else 0

    if violations:
        print(f"\nVIOLATIONS ({sum(len(r.violations) for r in violations)}):")
        for r in violations:
            for v in r.violations:
                kind, _, detail = v.partition(" ")
                print(f"  {kind:<15} {r.name:<48} {detail}")

    print("\nsummary:")
    print(f"  before -> during   {bd_ok}/{bd_total} detected"
          f"   ({bd_total - bd_ok} missed)")
    print(f"  during -> after    {da_fp}/{len(da_seen)} detected"
          f"   ({da_fp} false positive{'s' * (da_fp != 1)}; want 0)")
    print(f"  before -> after    {ba_fp}/{len(ba_seen)} detected"
          f"   ({ba_fp} false positive{'s' * (ba_fp != 1)}; want 0)")
    if errors:
        print(f"  errors             {errors}")

    total = sum(len(r.violations) for r in violations)
    print(f"\n  -> {'FAIL' if total else 'PASS'}"
          + (f" ({total} violation{'s' * (total != 1)})" if total else ""))
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
