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
import tarfile
import tempfile
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
class SampleFile:
    path: Path
    logical_name: str


@dataclass
class Artifact:
    name: str
    year: int
    before: SampleFile
    during: SampleFile
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


@dataclass
class Result:
    name: str
    year: int
    bd: Transition
    da: Transition | None = None
    ba: Transition | None = None
    bb: list[Transition] = field(default_factory=list)
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
            r"^    (artifact_id|phase|classification|version|filename|path|sha256):(?:\s*(.*))?$",
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


def file_form(path: Path) -> str:
    """Return a cheap content form for comparator selection.

    Recovered archives are often content-addressed as ``*.sample``. Requiring
    their suffix to match ``*.tgz`` silently drops valid old/new pairs even
    though both files are gzip streams. Magic is stable across reconstruction
    and renaming; the suffix remains a conservative fallback for plain source
    and unknown formats where these few bytes cannot identify a language.
    """
    try:
        with path.open("rb") as stream:
            head = stream.read(512)
    except OSError:
        return path.suffix.lower()
    signatures = (
        (b"\x1f\x8b", "gzip"),
        (b"\xfd7zXZ\x00", "xz"),
        (b"BZh", "bzip2"),
        (b"\x28\xb5\x2f\xfd", "zstd"),
        (b"PK\x03\x04", "zip"),
        (b"7z\xbc\xaf\x27\x1c", "7z"),
        (b"Rar!\x1a\x07", "rar"),
        (b"\x7fELF", "elf"),
        (b"MZ", "pe"),
    )
    for magic, form in signatures:
        if head.startswith(magic):
            return form
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    if head[:4] in (
        b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
    ):
        return "macho"
    return path.suffix.lower()


def sample_logical_name(sample: dict, path: Path) -> str:
    """Recover a content-appropriate basename for an Isomer comparison.

    A quarantine's SHA-named ``.sample`` is provenance, not file identity.
    Isomer must still receive a path whose package form can be identified;
    otherwise an npm tarball is analyzed as generic gzip and produces false
    identity removal. Prefer the corpus's preserved original name, then infer
    only the archive suffix needed for content detection.
    """
    source = sample.get("source")
    if isinstance(source, dict):
        chain = source.get("chain")
        if isinstance(chain, dict) and chain.get("original_filename"):
            return Path(str(chain["original_filename"])).name

    declared = Path(str(sample.get("filename") or "")).name
    if declared and Path(declared).suffix.lower() != ".sample":
        return declared
    if path.suffix.lower() != ".sample":
        return path.name

    artifact = re.sub(r"[^A-Za-z0-9._-]+", "-", str(sample.get("artifact_id") or "sample"))
    version = re.sub(r"[^A-Za-z0-9._-]+", "-", str(sample.get("version") or "recovered"))
    stem = f"{artifact}-{version}"
    form = file_form(path)
    if form == "gzip":
        # npm's package/package.json layout is a stronger form signal than the
        # original extension; generic gzip tarballs keep the wider .tar.gz.
        try:
            with tarfile.open(path, "r:gz") as archive:
                if any(member.name == "package/package.json" for member in archive):
                    return f"{stem}.tgz"
        except (OSError, tarfile.TarError):
            pass
        return f"{stem}.tar.gz"
    extensions = {
        "xz": ".xz", "bzip2": ".bz2", "zstd": ".zst",
        "zip": ".zip", "7z": ".7z", "rar": ".rar",
        "elf": ".elf", "pe": ".exe", "macho": ".macho",
        "tar": ".tar",
    }
    return f"{stem}{extensions.get(form, '.sample')}"


def version_components(sample: dict | None) -> tuple[int, ...] | None:
    """Return a simple numeric release tuple from metadata or its filename.

    Corpus versions are overwhelmingly semver-like, but requiring a packaging
    library here would defeat this script's dependency-free fallback. The
    manifest's explicit version wins; the basename is only a recovery path.
    """
    if not sample:
        return None
    values = [sample.get("version"), Path(sample.get("path", "")).name]
    for value in values:
        if not value:
            continue
        matches = re.findall(r"(?<!\d)(\d+(?:\.\d+){1,3})(?!\d)", str(value))
        if matches:
            return tuple(int(part) for part in matches[-1].split("."))
    return None


def version_affinity(sample: dict, reference: tuple[int, ...] | None) -> tuple[int, int]:
    """Prefer the nearest release line without pretending to order semver.

    Same major+minor beats merely same-major, which beats a cross-major pair.
    The numeric distance is only a tie-breaker inside that compatibility tier.
    """
    candidate = version_components(sample)
    if not reference or not candidate:
        return 3, sys.maxsize
    common = 0
    for old, new in zip(reference, candidate):
        if old != new:
            break
        common += 1
    line = 0 if common >= 2 else 1 if common >= 1 else 2
    width = max(len(reference), len(candidate))
    old = reference + (0,) * (width - len(reference))
    new = candidate + (0,) * (width - len(candidate))
    distance = sum(abs(a - b) * (1000 ** (width - i - 1))
                   for i, (a, b) in enumerate(zip(old, new)))
    return line, distance


def pick(samples: list[dict], prefer: tuple[str, ...], root: Path,
         match_path: str | None = None,
         match_version: tuple[int, ...] | None = None,
         exclude_sha256: str | None = None) -> dict | None:
    """Pick a present sample, preferring class and matching file form.

    A preserved incident report or source fragment is evidence, but it is not
    a meaningful old/new comparator for a release archive. Once a reference
    path exists, require the same content form before pairing another phase;
    this lets a content-addressed ``.sample`` gzip pair with ``.tgz`` while a
    loose ``.js`` payload or incident report still cannot impersonate it.
    """
    candidates = [
        (i, s) for i, s in enumerate(samples)
        if s.get("path") and (root / s["path"]).is_file()
        and (exclude_sha256 is None or s.get("sha256") != exclude_sha256)
    ]
    if not candidates:
        return None

    if match_path:
        reference_form = file_form(root / match_path)
        matching = [
            item for item in candidates
            if file_form(root / item[1]["path"]) == reference_form
        ]
        if not matching:
            return None
        candidates = matching

    def rank(item: tuple[int, dict]) -> tuple[int, int, int, int, int]:
        i, sample = item
        cls = sample.get("classification")
        class_rank = prefer.index(cls) if cls in prefer else len(prefer)
        form_rank = (
            0 if match_path and file_form(root / sample["path"])
            == file_form(root / match_path) else 1
        )
        version_line, version_distance = version_affinity(sample, match_version)
        return class_rank, form_rank, version_line, version_distance, i

    return min(candidates, key=rank)[1]


def baseline_chain(samples: list[dict], root: Path, reference: dict) -> list[dict]:
    """The clean pre-compromise releases, in version order, that pair honestly.

    Only same-content-form samples qualify, for the reason ``pick`` gives: a
    preserved incident report or loose source fragment is evidence, not a
    release comparator. Byte-identical entries are dropped too — a few incidents
    record the same tarball twice under different provenance, and diffing a file
    against itself proves nothing. ``reference`` (the chosen ``before``) fixes
    the form and is always a member of the result when it survives that filter.
    """
    form = file_form(root / reference["path"])
    seen: set[str] = set()
    chain: list[dict] = []
    for sample in samples:
        path = sample.get("path")
        if (
            not path
            or sample.get("classification") not in CLEAN
            or not (root / path).is_file()
            or file_form(root / path) != form
        ):
            continue
        key = sample.get("sha256") or path
        if key in seen:
            continue
        seen.add(key)
        chain.append(sample)
    # Unparseable versions sort last, stable in manifest order, so a chain that
    # is only partly versioned still pairs its known releases in release order.
    chain.sort(key=lambda s: version_components(s) or (sys.maxsize,))
    return chain if len(chain) > 1 else []


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
            before_version = version_components(before)
            during = pick(
                phases.get("during", []), COMPROMISED, base,
                match_path=before_path,
                match_version=before_version,
                exclude_sha256=before.get("sha256") if before else None,
            )
            # Some incidents preserve the clean archive alongside a payload
            # fragment or extracted source file. Fall back across formats only
            # when a same-format candidate exists but is byte-identical to the
            # clean baseline (as in W3 Total Cache). Without that guard,
            # historical HTML/TXT/diff reports would masquerade as release
            # comparators. In the fallback case incomparable after phases stay
            # unset below.
            if not during:
                duplicate = pick(
                    phases.get("during", []), COMPROMISED, base, before_path,
                    match_version=before_version,
                )
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
            after = pick(
                phases.get("after", []), REMEDIATED, base,
                match_path=during_path,
                match_version=version_components(during),
            )
            if not (before and during):
                continue

            def sample_file(sample: dict | None) -> SampleFile | None:
                if not sample:
                    return None
                p = base / sample.get("path", "")
                if not p.is_file():
                    return None
                return SampleFile(p, sample_logical_name(sample, p))

            bp, dp, ap = sample_file(before), sample_file(during), sample_file(after)
            if bp and dp:
                chain = baseline_chain(phases.get("before", []), base, before)
                baseline = [f for f in map(sample_file, chain) if f]
                out.append(Artifact(f"{attack}/{art}", year, bp, dp, ap, baseline))
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
    with tempfile.TemporaryDirectory(prefix="isomer-samples-") as staging:
        def staged(sample: SampleFile, side: str) -> Path:
            if sample.path.name == sample.logical_name:
                return sample.path
            parent = Path(staging) / side
            parent.mkdir()
            alias = parent / Path(sample.logical_name).name
            alias.symlink_to(sample.path)
            return alias

        cmd = [isomer, "--offline", "fs", str(staged(old, "old")),
               str(staged(new, "new")), "--format", "json",
               "--fail-on", fail_on]
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


def transitions_of(art: Artifact) -> list[tuple[str, SampleFile, SampleFile]]:
    """The isomer runs this artifact needs, as (kind, old, new)."""
    work = [("bd", art.before, art.during)]
    if art.after:
        work.append(("da", art.during, art.after))
        work.append(("ba", art.before, art.after))
    # Adjacent pairs only: the chain is a release history, and consecutive
    # releases are the upgrades a user actually performs. Every pair would be
    # quadratic for no new ground truth.
    for i, (old_side, new_side) in enumerate(zip(art.baseline, art.baseline[1:])):
        work.append((f"bb{i}", old_side, new_side))
    return work


def audit(art: Artifact, runs: dict[str, Transition]) -> Result:
    """Judge one artifact from its already-executed transitions."""
    bd, da, ba = runs["bd"], runs.get("da"), runs.get("ba")
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
    ap.add_argument("--jobs", type=int, default=0,
                    help="concurrent isomer runs (0 = one per CPU; the report stays "
                         "deterministic either way, since runs are independent and "
                         "results are sorted before printing)")
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

    timeout = args.timeout or None
    # Every transition is an independent isomer run, so schedule all of them as
    # one flat queue rather than three serial runs per artifact. A single run
    # only saturates a couple of cores, and the corpus holds a few archives that
    # cost minutes on their own; queueing per transition lets that long pole
    # overlap the rest of the corpus instead of leaving the machine idle.
    work = [(i, kind, old, new)
            for i, art in enumerate(artifacts)
            for kind, old, new in transitions_of(art)]
    jobs = args.jobs or (os.cpu_count() or 4)
    print(f"auditing {len(artifacts)} artifacts ({len(work)} comparisons, {jobs} at a "
          f"time) against {args.isomer} (detect = fail-on {args.fail_on})…",
          file=sys.stderr)

    runs: dict[tuple[int, str], Transition] = {}
    with cf.ThreadPoolExecutor(max_workers=jobs) as ex:
        futs = {ex.submit(run_transition, args.isomer, args.traits, args.fail_on,
                          old, new, timeout): (i, kind)
                for i, kind, old, new in work}
        for n, fut in enumerate(cf.as_completed(futs), 1):
            runs[futs[fut]] = fut.result()
            print(f"\r  {n}/{len(work)}", end="", file=sys.stderr, flush=True)
    print("", file=sys.stderr)
    results = [audit(art, {k: runs[(i, k)] for k, _, _ in transitions_of(art)})
               for i, art in enumerate(artifacts)]
    results.sort(key=lambda r: (r.year, r.name))

    # Tallies.
    bd_ok = sum(1 for r in results if r.bd.detected)
    bd_total = sum(1 for r in results if r.bd.detected is not None)
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
