# isomer

**Supply-chain attack detection at a molecular level.**

> The version string says nothing changed; the behavior says otherwise.

NOTE: HIGHLY EXPERIMENTAL - EARLY BUILD - MAY EAT YOUR CAT

isomer detects whether a *change* is malicious — whether it was introduced by a
human, an AI, or the dependency supply chain. It is a differential analyzer: it
compares two states of the same thing (a directory, a git ref, a package, an
OCI image) and judges the delta in context — behavioral disassembly, software
classification, version drift, commit intent, and time/size deltas.

Powered by [Atomdrift Scan](https://github.com/atomdrift-project/scan) and a
differential ML model (**Valence**). Offline command-line tool with optional
LLM support. Designed for CI pipelines and local development.

Licensed Apache-2.0.

### Behavioral-change calibration

JSON `features.trait_shift` separates `micro-behaviors/` and `objectives/`
from other trait namespaces. It records old/new weight and directional gains
and losses, weighted by criticality × confidence, taking the maximum per ID
to avoid counting inherited or repeated matches twice. Unchanged traits remain
in the denominator. This measures capability presence, not where it executes
or relationships between capabilities; it is diagnostic-only, not a new gate.
`population` describes the analyzed pairs (whole archives, but only touched
files for directory comparisons); `complete: false` indicates an analysis
failure. Neither field guarantees coverage beyond the scanner's output.

The sample audit retains this profile, the archive-normalized `judged_summary`,
raw aggregate scope totals, and topology, without retaining bulky per-file
evidence. These allow threshold experiments without rescanning. A >33% shift
alone is not proof of increased risk: removals, broad legitimate releases,
and tiny model-score movements need separate treatment.

To inspect the pinned scan model's decisions independently of the differential
verdict, run `cargo run --profile quick --example risk-evidence -- OLD NEW`.
It emits JSON per file with calibrated classification, cutoff, route scores,
and model version; global feature importance is not a causal explanation.
An absolute probability alone cannot raise a benign model decision to an
independent alarm. JSON verdicts retain `risk.new_classification` alongside
the score delta; behavioral and structural evidence can still raise severity.

## Surface

```
isomer ci                                  # zero-config in CI: derives base..head from the environment
isomer fs   <old-path> <new-path>          # compare two trees; follows the dependency graph
isomer git  --repo <url> <old> <new>       # compare two commits/branches/tags of a remote repo   (planned)
isomer purl <purl@a> <purl@b>              # compare two published package versions               (planned)
isomer oci  <old-image> <new-image>        # compare two container images                         (planned)
```

`ci` and `fs` are implemented. Output formats: `terminal` (default), `json`,
`sarif`, `markdown`.

Argument order is always **old, then new** (like `diff`). `--base`/`--head`
named flags are accepted everywhere for order-proof CI invocations.

Composer Git exports with `repo-<commit>` versus `owner-repo-<commit>` wrappers
are paired when both root-level `composer.json` declarations name the same
package and agree with those wrappers. Relative member paths remain exact and
case-sensitive; ambiguous mappings stay unpaired. This uses package claims only
to align the comparison, not to authenticate a publisher or lower risk. Raw
archive paths and actual content, manifest, and behavior changes remain visible.

Registry metadata checks are enabled by default for recognized npm packages
and declared package dependencies (including unchanged declarations). They use
current registry evidence, not a reconstruction of historical dependency
resolution. JSON output preserves both sides' records, findings, and lookup
errors under `registry`; `--gate new` excludes findings already present on the
baseline. An unavailable lookup is reported as unknown, not as a missing or
clean package. Use `--no-follow` to skip these checks, or `--offline` to prohibit
all network access. `--deps` additionally fetches and analyzes newly added
dependency payloads; registry following itself does not download those payloads.

Dependency additions alone remain Medium. With `--deps`, changed dependency
versions and single-removal/single-addition replacements within one manifest
are profiled on both sides: equivalent behavioral categories and risk are
Medium; reduced profiles are Low; new categories or increased risk are High
(Critical evidence stays Critical). Ambiguous replacements and failed lookups
remain explicitly unknown, not equivalent or safer. Other independent findings
can still raise the overall verdict; `--gate any` retains absolute current risk.
Npm ranges resolve within the declared constraint, using current registry data.

New or increased registry findings of Medium or higher against a successfully
checked baseline also reach High in a patch release, including a newly removed
package version. Unchanged registry findings and lookup failures do not establish
a new regression. Registry following alone does not compare payload behaviors.

## Exit codes

| Code | Meaning |
|------|---------|
| 0    | clean — no findings at or above `--fail-on` |
| 1    | findings at or above `--fail-on` |
| 2    | operational error (never conflated with findings) |

## CI quickstart (GitHub Actions)

```yaml
permissions:
  contents: read
  pull-requests: write   # sticky PR comment
  security-events: write # SARIF annotations

steps:
  - uses: actions/checkout@v4
  - uses: atomdrift/isomer-action@v1
    with:
      fail-on: high
```

Findings are suppressed in a committed `.isomer.toml`, one reviewable line
each, with a mandatory reason:

```toml
[[allow]]
id = "objectives/command-and-control/*"
reason = "vendored socket.io client; reviewed in #482"
expires = "2026-11-09"   # optional
```

## Testing

For directly paired local ELF, PE and Mach-O files, the normal comparison combines
native structural evidence with traits. No extra flag or analysis mode is needed.
The structural detector itself needs neither trait matches nor disassembly. It
detects entry-point redirects into appended or newly executable mappings while
the original executable code remains byte-identical, plus new mappings or
permission changes that introduce writable+executable memory. Resolved ELF
initializer/finalizer and PE TLS callback additions into these new mappings also
produce High findings, even without an entry-point change. Universal Mach-O
slices are paired by architecture, not their position in the file.

ELF build IDs, Mach-O UUIDs and PE CodeView GUID+age identities may match, differ,
or be absent; they are corroboration, not a gate on graft detection. Retaining
one of these identities while adding or altering executable code produces a
Medium review finding. Code removal alone does not trigger that rule. Debug or
signing payloads outside executable code do not count as code changes.
Code retention uses executable sections when available (excluding Mach-O loader
headers), falling back to executable mappings for sectionless images. It requires
stable virtual addresses and byte ranges, but tolerates file-offset relocation;
it does not normalize instructions or relocation fixups.

Both sources of evidence feed the same report and gate. A retained build ID plus at least
40% weighted trait churn and three distinct notable-or-higher additions/removals
(including at least one addition) produces a Medium review finding, not an
automatic High based on a percentage. Byte-identical inputs do not trigger it.
An unavailable identity remains unknown; Isomer does not equate extraction
failure with a changed ID.
Whole-file traits are not correlated with an individual universal Mach-O slice's
identity, because those traits are not currently attributed per architecture.

These byte-retention checks do not yet cover archive-member bytes, Mach-O
initialization callbacks, arbitrary in-place control-flow redirection, or
normalized instruction matching. ELF callbacks are limited to addresses
resolved by filefacts (currently 64-bit little-endian init/fini arrays).
Universal Mach-O support currently uses the 32-bit fat-header container.
Other normal analysis remains enabled; absence of a structural finding is not
proof of safety.

Production scoring must not depend on local trait IDs (`hierarchy::local-id`),
including suffix or substring tests of local names. Prefer differential facts,
severity, and behavioral shifts; when a taxonomy-specific predicate is needed,
match hierarchy levels with namespace boundaries. Local IDs are not stable.
`make lint-trait-ids` (also part of `make lint`) checks production Rust for
concrete ID literals and direct local-name predicates. Explicitly `cfg(test)`
modules may use concrete IDs as fixtures. There is no legacy allowlist. This
source lint is not dataflow analysis: aliases and dynamically assembled names
still need review. Migrations require scoring regressions, not merely broader
prefixes that silently change verdicts. Scoring also ignores local names and
descriptions when deriving binary capability families; archive encryption,
executable-member counts, and extension mismatches use structural metrics.

The working traits checkout separates platform comparisons, script loading,
HTML insertion, plugin-install requests, and missing entrypoints from their
broader neighbors. These categories preserve distinctions needed by differential
rules without depending on any particular local ID. Script-loading combinations
remain release-pressure review signals, not assertions of hostile dataflow.

Run `make test-simulations` for fast detector regressions. Small synthetic
differentials exercise the production rubric, release-pressure rules, model
score changes, and final verdict combination. The suite includes positive and
negative controls and needs no corpus, model bundle, or trait checkout.
They are also included in `make test`.

Run `make validate-samples` for the slower end-to-end audit against the supply-chain
attack corpus's artifact tree, `~/data/supplychain-attack-data` by default. Simulations
check decision logic; the corpus audit also checks extraction, trait matching, and model
integration.

The comparisons come from the corpus. Each record in the tree ships a `pairs.yaml`
naming every comparison it supports and what a detector should conclude from each, so the
audit reads them rather than deriving them from sample manifests. `make validate-manifests`
resolves every stated comparison against the tree without running the scanner; it requires
PyYAML and fails explicitly if unavailable. For an isolated environment, run
`uv run --with pyyaml python scripts/validate-samples.py --check-corpus`.

The tree is generated from the records repository (`make artifacts` there) and published
to R2. It is not the records repository, which holds the text and no payload bytes.
The detector executable is copied once before workers start, so rebuilding it
cannot mix versions within an audit. Its captured SHA-256 and size are recorded
in the streaming run header. Runtime model bundles are not snapshotted.
Explicit trait directories are snapshotted once per audit, including working-tree
edits, so later edits cannot change rules between comparisons. Selected inputs are
also copied once into temporary storage before comparisons start; later corpus
renames, replacements, or edits cannot change the captured bytes. This requires
temporary disk space for the selected files and executable, and snapshots each file rather
than atomically freezing the entire corpus. Copy failures or changes detected
during copying abort the run. Failures include
the verdict and change summary from the original run, so a later rerun does not
erase intermittent evidence.
The default worker count leaves room for each scanner's own threads and memory;
use the audit script's `--jobs` option to override it.

For long runs, add `--stream-results /tmp/isomer-audit.jsonl` when invoking
`python3 scripts/validate-samples.py --isomer ./target/quick/isomer`.
With make, use `ISOMER_AUDIT_STREAM_RESULTS=/tmp/isomer-audit.jsonl make validate-samples`.
The path must be new. Each completed comparison is flushed immediately with its
artifact name, original input paths, captured SHA-256 digests and sizes, expected
detection, verdict, issue code, and diagnostics. Digests identify scanned bytes;
the runner does not independently verify them against manifest integrity claims.
Each input also retains its selection-time manifest path, phase, classification,
version, verification status, and declared digest under `provenance`. These are
corpus claims, not scanner findings. In particular, an `affected` capture need not
contain the attack; the audit currently still requires detection of selected
`during` samples, so such failures need ground-truth review, not automatic rule
escalation. Provenance reporting does not change selection or pass/fail policy.
Qualified labels (`affected`, `carrier`, and `baseline_candidate`) also produce
explicit `evidence_warnings` in completion rows and the final JSON/text report,
including for detections that pass their expected gate. Warnings neither excuse
misses nor remove comparisons; they identify evidence requiring adjudication.
Rows arrive in completion order; the final report remains sorted. The first row
records run settings. Completed rows survive a process interruption, but automatic
resume is not implemented. The audit is offline; live registry checks require a
separate comparison.
If the scanner warns that it skipped unparseable trait files, the comparison
is an audit error even when its verdict matches the expected outcome.
When multiple captures tie on classification, format, and version proximity,
selection prefers verified complete captures over partial reconstructions.
The fallback manifest reader retains verification status and original archive
filenames as well as sample identity fields, so selection and archive staging
also work without PyYAML. Inline comments do not change those values.

## Warts

Heuristics are all generic, but hardcoded. The plan is to migrate to a new ML model (valence) once
we prove the ideas behind our heuristics and acquire more supply-chain attack testdata.
