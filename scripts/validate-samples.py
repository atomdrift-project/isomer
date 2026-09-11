#!/usr/bin/env python3
"""isomer self-audit against the supply-chain attack corpus.

Each attack ships an artifact in up to three phases — ``before`` (clean),
``during`` (compromised), and ``after`` (remediated). isomer is a *differential*
detector, so what it should say is defined by the transition, not the file:

    before -> during   MUST be detected      (the attack was introduced)
    during -> after    must NOT be detected   (remediation is not an attack)
    before -> after    must NOT be detected   (clean -> patched is not an attack)
    before -> before   must NOT be detected   (an honest upgrade is not an attack)

The last one needs an incident that preserved more than one pre-compromise
release — several do, and those clean releases are the only ground truth in the
corpus for what a *legitimate* upgrade of that exact package looks like. Each
adjacent pair of them, in version order, is a release the maintainer actually
shipped: if the gate fails on one, it would have blocked a real upgrade.

"Detected" means isomer's gate fails at the chosen severity (``--fail-on high``
by default) — the exact signal a CI check keys on. Every transition that breaks
its expectation is a VIOLATION:

    MISS            before -> during did not trip the gate  (a missed attack)
    FP-REMEDIATION  during -> after tripped the gate         (remediation flagged)
    FP-NET          before -> after tripped the gate         (clean->patched flagged)
    FP-BASELINE     before -> before tripped the gate        (honest upgrade flagged)

The script prints a per-violation report and a summary, and exits non-zero when
there is any violation or error — so ``make validate-samples`` gates on it.
Qualified evidence labels produce warnings, not exemptions: affected context
can lack the actual malicious payload, and clean labels need not mean risk-free.

The comparisons come from the corpus, not from this script. Each record in the artifact
tree ships a ``pairs.yaml`` naming every comparison it supports and what a differential
detector should conclude from each. This audit used to derive that itself — ranking
verification statuses, matching file formats, guessing version affinity from filenames,
and parsing each manifest twice to check the guessing against itself — which meant the
corpus and the audit could disagree about a package's release history with no single
place to fix it. Reading the corpus's own statement removed about 400 lines and raised
coverage from one comparison per package to one per compromised release.

The tree is generated from the records repository (``make artifacts`` there) and is
published to R2; it is not the records repository itself. Tree, binary, and detection bar
are all overridable; see ``--help``.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml
except ModuleNotFoundError:
    yaml = None

YAML_ERROR = getattr(yaml, "YAMLError", ValueError)

SEVERITY_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class SampleFile:
    path: Path
    logical_name: str
    # Preserve selection-time claims, separately from measured snapshot hashes.
    # In particular, `affected` context is not proof of a malicious payload.
    provenance: dict = field(default_factory=dict)


@dataclass
class SnapshotFile:
    path: Path
    sha256: str
    size: int


@dataclass
class Artifact:
    name: str
    year: int
    # None where the corpus recovered no clean comparator for this release. The
    # remediation comparison is still ground truth: a fix must not read as an attack,
    # whether or not the pre-attack release survived.
    before: SampleFile | None
    # None for a subject the corpus holds only clean releases of. There is no attack to
    # detect, but the release chain is still ground truth for what an honest upgrade
    # looks like, and flagging one would still be a false positive.
    during: SampleFile | None
    after: SampleFile | None
    # Every clean pre-compromise release of this artifact, in version order and
    # sharing `before`'s content form. Adjacent pairs are the honest upgrades.
    # Fewer than two entries means the incident preserved only one baseline and
    # there is no upgrade to judge.
    baseline: list[SampleFile] = field(default_factory=list)


@dataclass
class Transition:
    """One old->new isomer run: whether it was detected, and why."""

    detected: bool | None  # None on error
    severity: str
    error: str | None = None
    diagnostic: dict | None = None


@dataclass
class Result:
    name: str
    year: int
    bd: Transition | None
    da: Transition | None = None
    ba: Transition | None = None
    bb: list[Transition] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)
    evidence_warnings: dict[str, list[dict]] = field(default_factory=dict)


def evidence_warnings(old: SampleFile, new: SampleFile) -> list[dict]:
    """Expose qualified corpus labels without changing transition expectations."""
    qualifications = {
        "affected": "Affected context does not by itself establish a malicious payload.",
        "carrier": "A carrier label does not by itself establish an active malicious payload.",
        "baseline_candidate": "A baseline candidate is not a confirmed clean baseline.",
    }
    return [{"side": side, "classification": classification,
             "message": qualifications[classification]}
            for side, sample in (("old", old), ("new", new))
            if (classification := sample.provenance.get("classification")) in qualifications]


def incident_year(readme: Path) -> int:
    """The year the incident started, from the README the artifact tree generates."""
    try:
        text = readme.read_text()
    except OSError:
        return 0
    match = re.search(r"^\*\*When:\*\*\s*(\d{4})", text, re.M)
    return int(match.group(1)) if match else 0


def side_file(tree: Path, record: str, side: dict) -> SampleFile | None:
    """Resolve one side of a stated comparison to a file on disk.

    The path is the whole address: ``<record>/<subject>/<phase>/<release>/<file>``.
    ``unversioned`` is a release name like any other -- it is what the corpus says when a
    payload's affected release is genuinely unknown, and several records say so outright.

    The filename needs no repair. It is the name the artifact was distributed under, which
    is why the old ``sample_logical_name`` heuristics and the staging symlinks they fed
    are gone: there is nothing left to infer.
    """
    version = side.get("version")
    release = str(version) if version else "unversioned"
    path = tree / record / side["subject"] / side["phase"] / release / side["file"]
    if not path.is_file():
        return None
    return SampleFile(path, side["file"], {
        "record": record,
        "phase": side.get("phase"),
        "classification": side.get("classification"),
        "version": str(version) if version is not None else None,
        "declared_sha256": side.get("sha256"),
    })


def load_artifacts(tree: Path) -> list[Artifact]:
    """Read the comparisons the corpus states, from every record's ``pairs.yaml``.

    This used to be inference. The corpus recorded samples; the audit reconstructed which
    of them to compare, by ranking verification status, matching file formats, and
    guessing version affinity from filenames -- and it parsed the manifests twice, once
    with a YAML library and once with a hand-rolled scalar reader, purely to check that
    the guessing agreed with itself.

    The corpus now states its own expectations. `pairs.yaml` names every comparison and
    what a differential detector should conclude from it, so the audit reads them instead
    of deriving them. When the corpus and the audit disagree about what a package's
    release history looks like, that is now a corpus bug with one place to fix it.

    One Artifact per compromised release, so every attack pair is exercised rather than
    one per package. The baseline chain belongs to the subject rather than to any single
    release, so it is attached to the first artifact of each subject and not repeated.
    """
    if yaml is None:
        raise ValueError("PyYAML is required to read pairs.yaml")

    out: list[Artifact] = []
    for pairs_file in sorted(tree.glob("*/pairs.yaml")):
        try:
            document = yaml.safe_load(pairs_file.read_text()) or {}
        except (OSError, YAML_ERROR) as error:
            raise ValueError(f"cannot read {pairs_file}: {error}") from error
        record = str(document.get("record") or pairs_file.parent.name)
        year = incident_year(pairs_file.parent / "README.md")

        # Remediation is keyed on the exact compromised bytes it supersedes, so the
        # `after` attached below is the one the corpus paired with this release, not
        # whatever happens to be the newest fixed version of the package.
        fixed_for: dict[tuple[str, str], dict] = {}
        baselines: dict[str, list[dict]] = {}
        attacks: list[dict] = []
        for pair in document.get("pairs") or []:
            kind = pair.get("kind")
            if kind == "attack":
                attacks.append(pair)
            elif kind == "remediation":
                # Keyed on subject as well as digest: the same bytes are held under more
                # than one subject in several records, and a digest-only key let one
                # subject's remediation displace another's.
                fixed_for[(pair["old"]["subject"], str(pair["old"].get("sha256")))] = pair["new"]
            elif kind == "baseline":
                baselines.setdefault(pair["old"]["subject"], []).append(pair)

        chained: set[str] = set()

        def chain_for(subject: str) -> list[SampleFile]:
            """The subject's clean release chain, named once per subject."""
            if subject in chained:
                return []
            chained.add(subject)
            steps = baselines.get(subject) or []
            chain: list[SampleFile] = []
            for index, step in enumerate(steps):
                if index == 0:
                    first = side_file(tree, record, step["old"])
                    if first:
                        chain.append(first)
                nxt = side_file(tree, record, step["new"])
                if nxt:
                    chain.append(nxt)
            return chain

        for pair in attacks:
            before = side_file(tree, record, pair["old"])
            during = side_file(tree, record, pair["new"])
            if not (before and during):
                continue
            after_side = fixed_for.get((pair["new"]["subject"], str(pair["new"].get("sha256"))))
            after = side_file(tree, record, after_side) if after_side else None

            subject = pair["new"]["subject"]
            chain = chain_for(subject)

            version = during.provenance.get("version")
            name = f"{record}/{subject}" + (f"@{version}" if version else "")
            out.append(Artifact(name, year, before, during, after, chain))

        # A compromised release the corpus never found a clean comparator for still has a
        # remediation to judge. Without this the audit would test less than the corpus
        # states, purely because one of the three phases is missing.
        paired = {(p["new"]["subject"], str(p["new"].get("sha256"))) for p in attacks}
        for (subject, digest), after_side in fixed_for.items():
            if (subject, digest) in paired:
                continue
            during = next((side_file(tree, record, p["old"]) for p in document.get("pairs") or []
                           if p.get("kind") == "remediation"
                           and p["old"]["subject"] == subject
                           and str(p["old"].get("sha256")) == digest), None)
            after = side_file(tree, record, after_side)
            if not (during and after):
                continue
            version = during.provenance.get("version")
            name = f"{record}/{subject}" + (f"@{version}" if version else "") + " (no clean comparator)"
            out.append(Artifact(name, year, None, during, after, []))

        # A subject the corpus holds only clean releases of still carries ground truth:
        # each adjacent pair is an upgrade a user performed, and flagging one would be a
        # false positive. Without this the 9 such comparisons would go untested purely
        # because the incident's compromised release was never recovered.
        for subject in sorted(set(baselines) - chained):
            chain = chain_for(subject)
            if len(chain) > 1:
                out.append(Artifact(f"{record}/{subject}", year, chain[0], None, None, chain))

    out.sort(key=lambda artifact: (artifact.year, artifact.name))
    return out


def run_transition(isomer: str, traits: str | None, fail_on: str,
                   old: SampleFile, new: SampleFile,
                   timeout: int | None) -> Transition:
    env = dict(os.environ)
    if traits:
        env["CLEAVE_TRAITS_DIR"] = traits
    # `--offline` keeps the audit about the deterministic rubric: no model round
    # trip, and crucially no LLM verdict escalation, so the pass/fail is
    # reproducible on any machine (an empty ISOMER_LLM still falls back to a
    # localhost endpoint, which --offline hard-disables).
    # The files are handed to isomer where they sit. Samples used to be staged behind
    # symlinks because the audit had to invent a plausible filename for a file the corpus
    # stored under a digest or a capture timestamp; in the artifact tree the filename is
    # the one the artifact was distributed under, so there is nothing to stage.
    cmd = [isomer, "--offline", "fs", str(old.path), str(new.path),
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
    # Forward-compatible scanner builds can return a valid verdict after skipping
    # rules they cannot parse. Such a verdict cannot establish audit coverage,
    # even when it happens to agree with the expected detection.
    skipped = re.search(r"WARNING: skipped \d+ trait file\(s\)[^\n]*could not parse", stderr)
    if skipped:
        paths = re.findall(r'Failed to parse YAML in "([^"]+)"', stderr)
        detail = f" ({', '.join(paths)})" if paths else ""
        return Transition(None, "?", f"incomplete trait coverage: {skipped.group(0)}{detail}")
    try:
        report = json.loads(stdout)
        gate = report["verdict"]["gate"]
    except (ValueError, KeyError):
        return Transition(None, "?", "unparseable json")
    # `gate.severity` is the severity the active --gate actually evaluated
    # (new-only by default), so a MISS reads as the below-threshold level the
    # gate saw — not a pre-existing critical the gate never keyed on.
    # Keep the decision evidence from this exact run. Re-running a violation
    # can lose an intermittent scanner/cache/resource failure. Do not retain
    # full raw reports: decoded source and strings can be hundreds of MB.
    diagnostic = {
        "verdict": report["verdict"],
        "summary": report.get("raw", {}).get("diff", {}).get("summary"),
    }
    # Preserve compact, judged measurements for offline calibration, not the
    # potentially enormous per-file feature/evidence payload.
    features = report.get("features", {})
    for key in ("trait_shift", "judged_summary", "scopes", "topology"):
        if key in features:
            diagnostic[key] = features[key]
    return Transition(bool(gate["fail"]), gate.get("severity", "?"), diagnostic=diagnostic)


def violation_diagnostics(result: Result) -> dict:
    """Exact-run evidence for anomalous transitions, without changing gates."""
    transitions = [("before->during", result.bd, True),
                   ("during->after", result.da, False),
                   ("before->after", result.ba, False)]
    transitions.extend((f"before->before[{i}]", run, False)
                       for i, run in enumerate(result.bb))
    return {name: run.diagnostic for name, run, expected in transitions
            if run and run.detected is not None and run.detected != expected}


def transitions_of(art: Artifact) -> list[tuple[str, SampleFile, SampleFile]]:
    """The isomer runs this artifact needs, as (kind, old, new)."""
    work: list[tuple[str, SampleFile, SampleFile]] = []
    if art.before and art.during:
        work.append(("bd", art.before, art.during))
    if art.during and art.after:
        work.append(("da", art.during, art.after))
    if art.before and art.after:
        work.append(("ba", art.before, art.after))
    # Adjacent pairs only: the chain is a release history, and consecutive
    # releases are the upgrades a user actually performs. Every pair would be
    # quadratic for no new ground truth.
    for i, (old_side, new_side) in enumerate(zip(art.baseline, art.baseline[1:])):
        work.append((f"bb{i}", old_side, new_side))
    return work


def audit(art: Artifact, runs: dict[str, Transition]) -> Result:
    """Judge one artifact from its already-executed transitions."""
    bd, da, ba = runs.get("bd"), runs.get("da"), runs.get("ba")
    res = Result(art.name, art.year, bd, da, ba)
    res.evidence_warnings = {
        kind: warnings for kind, old, new in transitions_of(art)
        if (warnings := evidence_warnings(old, new))
    }

    if bd and bd.error:
        res.violations.append(f"ERROR before->during: {bd.error}")
    elif bd and bd.detected is False:
        res.violations.append(f"MISS before->during not detected (sev={bd.severity})")
    if da:
        if da.error:
            res.violations.append(f"ERROR during->after: {da.error}")
        # Judge each transition independently. A clean net comparison does
        # not establish why the remediation comparison tripped the gate.
        elif da.detected:
            res.violations.append(f"FP-REMEDIATION during->after detected (sev={da.severity})")
    if ba:
        if ba.error:
            res.violations.append(f"ERROR before->after: {ba.error}")
        elif ba.detected:
            res.violations.append(f"FP-NET before->after detected (sev={ba.severity})")
    for i, (old_side, new_side) in enumerate(zip(art.baseline, art.baseline[1:])):
        bb = runs.get(f"bb{i}")
        if not bb:
            continue
        res.bb.append(bb)
        # Name both releases: unlike the other three transitions there can be
        # several per artifact, and "which upgrade" is the whole finding.
        pair = f"{old_side.logical_name} -> {new_side.logical_name}"
        if bb.error:
            res.violations.append(f"ERROR before->before {pair}: {bb.error}")
        elif bb.detected:
            res.violations.append(
                f"FP-BASELINE before->before detected (sev={bb.severity}) {pair}"
            )
    return res


def default_isomer() -> str:
    here = Path(__file__).resolve().parent.parent
    for cand in (here / "target/release/isomer", here / "target/debug/isomer"):
        if cand.is_file():
            return str(cand)
    return "isomer"


def snapshot_traits(source: str | None, destination: Path) -> str | None:
    """Use one working-tree rule snapshot across all parallel comparisons."""
    if source is None:
        return None
    shutil.copytree(source, destination, ignore=shutil.ignore_patterns(".git"))
    return str(destination)


def snapshot_executable(command: str, destination: Path) -> SnapshotFile:
    """Pin detector bytes before workers start; rebuilding cannot mix versions.

    Use the same checked independent copy as inputs, not a hardlink. Model
    bundles and other runtime resources are not captured by this snapshot.
    """
    resolved = shutil.which(command)
    if resolved is None or not Path(resolved).is_file():
        raise FileNotFoundError(f"executable not found or not executable: {command}")
    source = Path(resolved).resolve()
    sample = SampleFile(source, source.name)
    captured = snapshot_samples([sample], destination)[source]
    # Owner-only execution; never propagate setuid/setgid from the source.
    captured.path.chmod(0o500)
    return captured


def snapshot_samples(samples: list[SampleFile], destination: Path) -> dict[Path, SnapshotFile]:
    """Copy each input once; later corpus renames/edits cannot change this run.

    These are independent copies, not symlinks or hardlinks. The recorded digest
    identifies the bytes actually scanned, not an unverified manifest claim.
    This is a per-file snapshot, not an atomic snapshot of the whole corpus.
    """
    snapshots: dict[Path, SnapshotFile] = {}
    for sample in samples:
        if sample.path in snapshots:
            continue
        target = destination / str(len(snapshots)) / sample.path.name
        target.parent.mkdir(parents=True)
        digest = hashlib.sha256()
        size = 0
        with sample.path.open("rb") as source, target.open("xb") as output:
            before = os.fstat(source.fileno())
            for block in iter(lambda: source.read(1024 * 1024), b""):
                output.write(block)
                digest.update(block)
                size += len(block)
            after = os.fstat(source.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns) or size != before.st_size:
            raise ValueError(f"input changed while being copied: {sample.path}")
        snapshots[sample.path] = SnapshotFile(target, digest.hexdigest(), size)
    return snapshots


def default_jobs() -> int:
    """Each scanner uses multiple cores and can retain several GB of data."""
    return min(8, max(1, (os.cpu_count() or 2) // 2))


def write_stream_record(stream, key: tuple[int, str], artifact: Artifact,
                        old: SampleFile, new: SampleFile, transition: Transition,
                        snapshots: dict[Path, SnapshotFile] | None = None) -> None:
    """Append one self-contained completed comparison and flush it immediately."""
    expected = key[1] == "bd"
    issue = None
    if transition.error or transition.detected is None:
        issue = "ERROR"
    elif transition.detected != expected:
        issue = {"bd": "MISS", "da": "FP-REMEDIATION", "ba": "FP-NET"}.get(
            key[1], "FP-BASELINE")
    def describe(sample: SampleFile) -> dict:
        description = {"path": str(sample.path), "logical_name": sample.logical_name}
        if sample.provenance:
            description["provenance"] = sample.provenance
        if snapshots is not None:
            snapshot = snapshots[sample.path]
            description.update(sha256=snapshot.sha256, size=snapshot.size)
        return description

    stream.write(json.dumps({
        "event": "comparison",
        "artifact_index": key[0],
        "artifact": artifact.name,
        "year": artifact.year,
        "transition": key[1],
        "old": describe(old),
        "new": describe(new),
        "expected_detected": expected,
        "evidence_warnings": evidence_warnings(old, new),
        "issue": issue,
        "detected": transition.detected,
        "severity": transition.severity,
        "error": transition.error,
        "diagnostic": transition.diagnostic,
    }, separators=(",", ":")) + "\n")
    stream.flush()


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Audit isomer against the supply-chain attack corpus.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("--corpus", type=Path,
                    default=Path(os.environ.get("ISOMER_SAMPLES_DIR",
                                Path.home() / "data/supplychain-attack-data")),
                    help="artifact tree holding <record>/pairs.yaml")
    ap.add_argument("--isomer", default=os.environ.get("ISOMER", default_isomer()),
                    help="isomer binary")
    ap.add_argument("--traits", default=os.environ.get("CLEAVE_TRAITS_DIR"),
                    help="trait directory (CLEAVE_TRAITS_DIR)")
    ap.add_argument("--fail-on", default="high",
                    choices=["low", "medium", "high", "critical"],
                    help="severity that counts as a detection")
    ap.add_argument("--jobs", type=int, default=0,
                    help="concurrent isomer runs (0 = half the CPUs, capped at 8; the report stays "
                         "deterministic either way, since runs are independent and "
                         "results are sorted before printing)")
    ap.add_argument("--timeout", type=int, default=0,
                    help="per-run seconds (0 = unlimited; timed-out comparisons are errors)")
    ap.add_argument("--limit", type=int, default=0, help="cap artifacts (0=all)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--check-corpus", action="store_true",
                    help="resolve every stated comparison against the tree; no scans")
    ap.add_argument("--stream-results", type=Path, metavar="PATH",
                    default=os.environ.get("ISOMER_AUDIT_STREAM_RESULTS"),
                    help="create a new JSONL file with flushed results in completion order")
    args = ap.parse_args()

    if not args.corpus.is_dir():
        print(f"validate-samples: artifact tree not found at {args.corpus}\n"
              f"  set ISOMER_SAMPLES_DIR or pass --corpus. The tree is generated from the\n"
              f"  records repository with `make artifacts`, or synced from R2.", file=sys.stderr)
        return 2

    try:
        artifacts = load_artifacts(args.corpus)
    except (OSError, ValueError, YAML_ERROR) as error:
        print(f"validate-samples: {error}", file=sys.stderr)
        return 2

    if args.check_corpus:
        # Every side of every stated comparison had to resolve to a file for the artifact
        # to be built at all, so this reports what the audit would run without running it.
        # It is the cheap check that the tree and the records still agree.
        counts: dict[str, int] = {}
        for artifact in artifacts:
            for kind, _, _ in transitions_of(artifact):
                key = "before->before" if kind.startswith("bb") else {
                    "bd": "before->during", "da": "during->after", "ba": "before->after",
                }[kind]
                counts[key] = counts.get(key, 0) + 1
        if args.json:
            print(json.dumps({"artifacts": len(artifacts), "comparisons": counts}, sort_keys=True))
        else:
            print(f"{len(artifacts)} artifacts, {sum(counts.values())} comparisons")
            for key in sorted(counts):
                print(f"  {counts[key]:6d}  {key}")
        return 0
    if args.limit:
        artifacts = artifacts[: args.limit]
    if not artifacts:
        # Pointing at the records repository instead of the tree is the likely mistake, and
        # it looks identical to an empty corpus unless the message says so.
        if not any(args.corpus.glob("*/pairs.yaml")):
            print(f"validate-samples: no pairs.yaml under {args.corpus}\n"
                  f"  this is the artifact tree, not the records repository.", file=sys.stderr)
        else:
            print(f"validate-samples: no comparisons under {args.corpus}", file=sys.stderr)
        return 2

    timeout = args.timeout or None
    # Every transition is an independent isomer run, so schedule all of them as
    # one flat queue rather than three serial runs per artifact. A single run
    # only saturates a couple of cores, and the corpus holds a few archives that
    # cost minutes on their own; queueing per transition lets that long pole
    # overlap the rest of the corpus instead of leaving the machine idle.
    work = [(i, kind, old, new)
            for i, art in enumerate(artifacts)
            for kind, old, new in transitions_of(art)]
    jobs = args.jobs or default_jobs()
    print(f"auditing {len(artifacts)} artifacts ({len(work)} comparisons, {jobs} at a "
          f"time) against {args.isomer} (detect = fail-on {args.fail_on})…",
          file=sys.stderr)

    runs: dict[tuple[int, str], Transition] = {}
    with tempfile.TemporaryDirectory(prefix="isomer-audit-traits-") as staging:
        try:
            detector = snapshot_executable(args.isomer, Path(staging) / "detector")
        except (OSError, ValueError) as error:
            print(f"validate-samples: cannot snapshot executable: {error}", file=sys.stderr)
            return 2
        try:
            traits = snapshot_traits(args.traits, Path(staging) / "traits")
        except OSError as error:
            print(f"validate-samples: cannot snapshot traits: {error}", file=sys.stderr)
            return 2
        stream = None
        try:
            if args.stream_results:
                stream = args.stream_results.open("x", encoding="utf-8")
            try:
                snapshots = snapshot_samples(
                    [sample for _, _, old, new in work for sample in (old, new)],
                    Path(staging) / "inputs")
            except (OSError, ValueError) as error:
                print(f"validate-samples: cannot snapshot inputs: {error}", file=sys.stderr)
                return 2
            if stream:
                stream.write(json.dumps({
                    "event": "run", "schema": 1, "comparisons": len(work),
                    "isomer": args.isomer, "traits_source": args.traits,
                    "detector_snapshot": {"path": str(detector.path),
                                          "sha256": detector.sha256, "size": detector.size},
                    "traits_snapshot": traits, "corpus": str(args.corpus),
                    "fail_on": args.fail_on, "offline": True,
                    "input_snapshot": "independent-copies",
                }) + "\n")
                stream.flush()
            def copied(sample: SampleFile) -> SampleFile:
                return SampleFile(snapshots[sample.path].path, sample.logical_name)

            with cf.ThreadPoolExecutor(max_workers=jobs) as ex:
                futs = {ex.submit(run_transition, str(detector.path), traits, args.fail_on,
                                  copied(old), copied(new), timeout): (i, kind, old, new)
                        for i, kind, old, new in work}
                for n, fut in enumerate(cf.as_completed(futs), 1):
                    i, kind, old, new = futs[fut]
                    key = (i, kind)
                    try:
                        transition = fut.result()
                    except Exception as error:
                        transition = Transition(None, "?", f"worker failed: {error}")
                    runs[key] = transition
                    if stream:
                        write_stream_record(stream, key, artifacts[i], old, new, transition,
                                            snapshots)
                    print(f"\r  {n}/{len(work)}", end="", file=sys.stderr, flush=True)
        except OSError as error:
            print(f"validate-samples: cannot write result stream: {error}", file=sys.stderr)
            return 2
        finally:
            if stream:
                stream.close()
    print("", file=sys.stderr)
    results = [audit(art, {k: runs[(i, k)] for k, _, _ in transitions_of(art)})
               for i, art in enumerate(artifacts)]
    results.sort(key=lambda r: (r.year, r.name))

    # Tallies.
    bd_ok = sum(1 for r in results if r.bd and r.bd.detected)
    bd_total = sum(1 for r in results if r.bd and r.bd.detected is not None)
    da_seen = [r for r in results if r.da and r.da.detected is not None]
    ba_seen = [r for r in results if r.ba and r.ba.detected is not None]
    da_fp = sum(1 for r in da_seen if r.da.detected)
    ba_fp = sum(1 for r in ba_seen if r.ba.detected)
    bb_seen = [t for r in results for t in r.bb if t.detected is not None]
    bb_fp = sum(1 for t in bb_seen if t.detected)
    violations = [r for r in results if r.violations]
    errors = sum(1 for r in results
                 for t in (r.bd, r.da, r.ba, *r.bb) if t and t.error)

    if args.json:
        print(json.dumps({
            "artifacts": len(results),
            "before_during_detected": bd_ok, "before_during_total": bd_total,
            "during_after_false_positives": da_fp, "during_after_total": len(da_seen),
            "before_after_false_positives": ba_fp, "before_after_total": len(ba_seen),
            "before_before_false_positives": bb_fp, "before_before_total": len(bb_seen),
            "errors": errors,
            "evidence_warnings": [{"artifact": r.name, "transitions": r.evidence_warnings}
                                  for r in results if r.evidence_warnings],
            "violations": [{"artifact": r.name, "issues": r.violations,
                            "diagnostics": violation_diagnostics(r)} for r in violations],
        }, indent=2))
        return 1 if violations else 0

    qualified = [r for r in results if r.evidence_warnings]
    if qualified:
        print("\nEVIDENCE WARNINGS (expectations and gates unchanged):")
        for r in qualified:
            for kind, warnings in r.evidence_warnings.items():
                for warning in warnings:
                    print(f"  {r.name} {kind} {warning['side']}: "
                          f"{warning['message']} (classification={warning['classification']})")

    if violations:
        print(f"\nVIOLATIONS ({sum(len(r.violations) for r in violations)}):")
        for r in violations:
            for v in r.violations:
                kind, _, detail = v.partition(" ")
                print(f"  {kind:<15} {r.name:<48} {detail}")
            print("    diagnostics: " + json.dumps(violation_diagnostics(r), sort_keys=True))

    print("\nsummary:")
    print(f"  before -> during   {bd_ok}/{bd_total} detected"
          f"   ({bd_total - bd_ok} missed)")
    print(f"  during -> after    {da_fp}/{len(da_seen)} detected"
          f"   ({da_fp} false positive{'s' * (da_fp != 1)}; want 0)")
    print(f"  before -> after    {ba_fp}/{len(ba_seen)} detected"
          f"   ({ba_fp} false positive{'s' * (ba_fp != 1)}; want 0)")
    print(f"  before -> before   {bb_fp}/{len(bb_seen)} detected"
          f"   ({bb_fp} false positive{'s' * (bb_fp != 1)}; want 0)")
    if errors:
        print(f"  errors             {errors}")

    total = sum(len(r.violations) for r in violations)
    print(f"\n  -> {'FAIL' if total else 'PASS'}"
          + (f" ({total} violation{'s' * (total != 1)})" if total else ""))
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
