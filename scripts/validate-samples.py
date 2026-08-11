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
import concurrent.futures as cf
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml
except ModuleNotFoundError:
    sys.exit("validate-samples: needs PyYAML (`pip install pyyaml`)")

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
    bd: Transition
    da: Transition | None = None
    ba: Transition | None = None
    violations: list[str] = field(default_factory=list)


def pick(samples: list[dict], prefer: tuple[str, ...]) -> dict | None:
    for cls in prefer:
        for s in samples:
            if s.get("classification") == cls:
                return s
    return samples[0] if samples else None


def load_artifacts(corpus: Path) -> list[Artifact]:
    """One Artifact per (attack, artifact_id) with at least before+during on disk."""
    out: list[Artifact] = []
    for manifest in sorted(corpus.glob("*/samples/manifest.yaml")):
        try:
            doc = yaml.safe_load(manifest.read_text()) or {}
        except (OSError, yaml.YAMLError):
            continue
        attack = manifest.parent.parent.name
        base = manifest.parent
        by_art: dict[str, dict[str, list[dict]]] = {}
        for s in doc.get("samples") or []:
            by_art.setdefault(s.get("artifact_id", "?"), {}).setdefault(
                s.get("phase"), []
            ).append(s)

        for art, phases in by_art.items():
            before = pick(phases.get("before", []), CLEAN)
            during = pick(phases.get("during", []), COMPROMISED)
            after = pick(phases.get("after", []), REMEDIATED)
            if not (before and during):
                continue

            def path(sample: dict | None) -> Path | None:
                if not sample:
                    return None
                p = base / sample["path"]
                return p if p.is_file() else None

            bp, dp, ap = path(before), path(during), path(after)
            if bp and dp:
                out.append(Artifact(f"{attack}/{art}", bp, dp, ap))
    return out


def run_transition(isomer: str, traits: str | None, fail_on: str,
                   old: Path, new: Path, timeout: int) -> Transition:
    env = dict(os.environ)
    if traits:
        env["CLEAVE_TRAITS_DIR"] = traits
    # `--offline` keeps the audit about the deterministic rubric: no model round
    # trip, and crucially no LLM verdict escalation, so the pass/fail is
    # reproducible on any machine (an empty ISOMER_LLM still falls back to a
    # localhost endpoint, which --offline hard-disables).
    cmd = [isomer, "--offline", "fs", str(old), str(new),
           "--format", "json", "--fail-on", fail_on]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return Transition(None, "?", "timeout")
    # isomer exits 0 (clean) or 1 (gate failed); anything else is a real error.
    if p.returncode not in (0, 1):
        return Transition(None, "?", (p.stderr or "").strip().splitlines()[-1:][0]
                          if p.stderr.strip() else f"exit {p.returncode}")
    try:
        gate = json.loads(p.stdout)["verdict"]["gate"]
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
    res = Result(art.name, bd, da, ba)

    if bd.error:
        res.violations.append(f"ERROR before->during: {bd.error}")
    elif bd.detected is False:
        res.violations.append(f"MISS before->during not detected (sev={bd.severity})")
    if da:
        if da.error:
            res.violations.append(f"ERROR during->after: {da.error}")
        elif da.detected:
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
    ap.add_argument("--jobs", type=int, default=min(8, (os.cpu_count() or 4)))
    ap.add_argument("--timeout", type=int, default=540, help="per-run seconds")
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

    results: list[Result] = []
    with cf.ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futs = {ex.submit(audit, a, args.isomer, args.traits, args.fail_on,
                          args.timeout): a for a in artifacts}
        for i, fut in enumerate(cf.as_completed(futs), 1):
            results.append(fut.result())
            print(f"\r  {i}/{len(artifacts)}", end="", file=sys.stderr, flush=True)
    print("", file=sys.stderr)
    results.sort(key=lambda r: r.name)

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
