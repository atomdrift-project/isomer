# isomer — design

Status: planning (2026-08-07), with the CI path implemented (2026-08-09).
This document captures the product/technical plan; nothing here is implemented
unless noted.

**Implemented since the original draft:** `isomer ci` (environment-derived
base..head, sparse materialization of the changed files, multi-sink emission),
`--format sarif`, `--format markdown`, the `.isomer.toml` suppression policy,
and a one-analysis-many-renderers split (`src/analysis.rs` judges;
`src/terminal.rs`, `src/markdown.rs`, `src/sarif.rs`, and the JSON envelope
render). See "The `ci` verb" below.

## Pitch

Supply-chain attack detection at a molecular level. isomer detects whether a
change is malicious — introduced by a human, an AI, or the dependency supply
chain — by judging the *delta* between two states in context, rather than
scoring one tree in isolation.

Tagline: *"The version string says nothing changed; the behavior says
otherwise."*

- Offline CLI, designed for CI/CD pipelines and local development.
- Optional LLM support (commit-intent analysis; never required).
- Powered by Atomdrift Scan as a library; new differential ML model: **Valence**.
- Open source, Apache-2.0.
- Revenue: paid tier for more responsive rule updates, and support.

## Why differential

- **Signal.** "This package gained network + process-spawn between 1.2.3 and
  1.2.4 and the changelog says 'fix typo'" is a far higher-signal alert than
  any absolute score on a whole tree. Capability drift mismatched against
  stated intent is exactly the xz / event-stream / ua-parser-js shape.
- **Speed.** Bloom-aware known-good skipping plus only-deep-analyze-the-delta
  means seconds per dependency bump in CI, which is the difference between a
  tool teams keep enabled and one they rip out.
- **False-positive budget.** CI security tools die by alert fatigue. The
  differential frame plus a first-class suppression story keeps the budget
  tiny.

## Surfaces

Argument order is always **old, then new** (matching `diff`). Every verb also
accepts `--base` / `--head` named flags so CI invocations are order-proof.

| Verb | Form | Notes |
|------|------|-------|
| `ci` | `isomer ci` | Zero-argument CI entry point. Reads `GITHUB_ACTIONS` / `github.event.pull_request.base.sha` / `GITHUB_BASE_REF` (and GitLab equivalents) to derive base..head, resolves lockfile diffs to purl pairs, and composes the verbs below. |
| `fs` | `isomer fs <old> <new>` | Two local trees. Assesses version/time/LoC deltas, diffs capabilities, follows the dependency graph. If the paths are git repos, also diffs commits. |
| `git` | `isomer git --repo <url> <old> <new>` | Remote repo, two commits/branches/tags. |
| `purl` | `isomer purl <purl@a> <purl@b>` | Two published versions; fetches via scan's registry machinery. Also assesses whether the shipped artifact's capabilities match an open-source build of the source tree (optional; see below). |
| `oci` | `isomer oci <old> <new>` | Two container images. |

`ci` is the product; the other verbs are the plumbing it composes.

## Detection model

Context signals, combined by Valence:

1. **Capability diff** — scan/cleave trait extraction on both sides; the delta
   set (gained/lost capabilities) is the core feature.
2. **Version-drift proportionality** — minor/patch version changes shouldn't
   produce huge capability shifts. Version, time, and LoC deltas calibrate
   what "proportional" means.
3. **Class-vs-capability mismatch** — software classification vs observed
   capabilities: JPEG libraries shouldn't be talking to the internet.
   Model-driven; LLM optional for richer classification.
4. **Commit intent** — flags commits introducing security degradations that
   don't match the commit message. Technique validated by
   [ucd](https://github.com/tstromberg/ucd). LLM-backed when available;
   without an LLM this signal is heuristic-only and the report says so.
5. **Behavioral disassembly** — rizin-derived behavior for binaries, so the
   diff works on compiled artifacts too.

### Artifact-vs-source comparison

If a dependency fetched from a registry/download site is suspicious, it is
optionally compared *behaviorally* against a build of its source tree (the
xz case: release tarball ≠ git tag). Capability-set comparison, not byte
comparison, to dodge the reproducible-builds problem. Bundlers/minifiers
legitimately shift capability sets (a webpack bundle "gains" every inlined
dep's capabilities) — v1 scopes this feature to source-distributed
ecosystems (npm/PyPI tarball vs repo) and treats compiled targets as
best-effort.

### Valence

Differential ML model over delta features: capability-set diff, cleave score
shift per side, new critical-trait appearances, size/LoC/time anomalies,
version-bump magnitude, class-vs-capability mismatch.

- v1 strategy: score both sides with the existing cleave ML; Valence is a
  model (initially a transparent rubric) over the *delta features*, not a
  from-scratch classifier. Upgrade to a trained model as labeled pairs
  accumulate.
- **v0 rubric — behavioral-change tolerance by change class.** While training
  deltas are collected, ship observation-based rules for how much behavioral
  change to tolerate per change class: single commit < patch release < minor
  release < major release (a commit that adds `exec` + network to a JPEG
  library trips at any class; a major release absorbs large drift). Calibrate
  the bands empirically, not by hand: run the differ over known-good version
  pairs already in the dataset/hopper and take per-class percentiles of
  capability drift — the benign corpus is unlimited even while malicious
  pairs are scarce, and every rubric run in the wild doubles as
  training-delta collection.
- Training data: labeled malicious version-*pairs* are scarce publicly
  (OpenSSF malicious-packages, DataDog dataset, Backstabber's Knife
  Collection ≈ low thousands, skewed to crude npm/PyPI stealers). But we have
  ~30 years of open-source attacks already represented in our own dataset —
  the work is writing the queries to unearth the pairs, i.e. mining, not
  collection.

## Status of `isomer fs` (v0)

Implemented and validated. `isomer fs <old> <new>` runs cleave's `diff_paths`
(all six scopes measured), applies the v0 rubric over trait + identity drift,
and renders an impact-first verdict header (`HOSTILE`/`SUSPICIOUS`/`NOTABLE`/
`CLEAN` badge, one-line summary, top reasons) above cleave's full diff ledger.
Exit code honors `--fail-on`. `--format json` emits a versioned envelope
(`schema_version: 1`, `verdict`, embedded cleave report); `sarif`/`markdown`
are stubbed.

Validated against `/Users/t/data/supplychain/cases` (no provenance/commits,
fine for `fs`):

- `javascript/rand-user-agent` clean vs compromised `index.js` → **HOSTILE**
  (RATatouille trojan, dev-popper loader).
- `javascript/node-ipc` 12.0.0 vs 12.0.1 tarballs → **HOSTILE**, plus
  **identity drift** surfaced as its own reason; archive members diff as
  `<root>!!package/node-ipc.cjs`.

Also validated against `supplychain-trenches/2024.xzutils` (compiled
`liblzma.so`, the hardest case — stripped shared objects, not source):

| diff | verdict | exit | notes |
|------|---------|------|-------|
| 5.4.5 → 5.6.0 | HOSTILE | 1 | backdoor introduced |
| 5.4.5 → 5.6.3 | NOTABLE | 0 | clean → fixed; no false HOSTILE |
| 5.6.0 → 5.6.3 | NOTABLE | 0 | backdoor **removed** — ledger shows the `●●●` sigs as `-` |

**Catching xz without the signature (implemented).** The 5.6.0 HOSTILE verdict
*could* rest entirely on cleave signatures (elastic `Linux_Trojan_XZBackdoor`,
CRAIU, SigBase CVE-2024-3094) — i.e. detection because the backdoor is *known*.
To catch a *novel* xz-shaped attack, the rubric judges a second, independent
axis (see below). On 5.4.5 → 5.6.0 the **behavioral axis alone reads `high`**
(`ifunc-resolver-hijack`, plus medium runtime-linkage / hidden-byte-strings /
xor-encoding) with every signature ignored — enough to fail `--fail-on high`
on release day.

### Detection signals (the expert system → Valence)

The verdict folds several signals; the hand-coded rubric is a stand-in for
**Valence**, the eventual ML engine that will score the whole change vector
(size, entropy, traits, metrics, facts) directly.

- **ML risk is the primary detector.** Azoth scores both sides; a **jump into a
  worse band** (benign→malware) drives the verdict on its own — `verdict =
  max(rubric axes, risk_band(new))`, and a band jump counts as newly-introduced
  risk for the `--gate new` exit. So an xz-class attack fires from the risk
  jump alone, with no trait or signature. Falls back to the rubric when no model
  is present.
- **Structure axis** (`rubric::structural_facts`) — raw ELF/Mach-O/PE kv facts,
  not rule matches: a new **loader dependency** (High), functions turned into
  **ifunc resolvers** (High), **new imports** (Medium). These fold into the
  verdict and `new_severity`, so xz fires on structure alone too. Verified:
  strip every trait and signature and xz still reads Critical (risk) / High
  (structure).
- **Version distance** — `5.4.5 → 5.6.0` is stated as **"2 minor releases"**,
  not "a minor release"; the proportionality tolerance is keyed on the moved
  component, not the distance (two minors still don't license an execution
  primitive).

### The v0 rubric — three axes (`src/rubric.rs`)

The verdict is the worst of three independently-computed axes. Everything
cleave measures still renders below; the rubric only sets the headline and exit
code.

1. **signature** — cleave criticality of gained known-bad traits
   (`third_party/*`, `*malware/*`, `hidden-payload`, `trojanized`). Catches
   *known* attacks; the axis a plain scanner already has.
2. **behavioral** — capability-drift risk keyed on the trait *namespace*, not
   its criticality. A curated table maps taxonomy segments to severity:
   `command-and-control`/`exfiltration`/`impact` → Critical;
   `linking/runtime::ifunc`, `process/create`, `communications/`,
   `credential-access`, `install-hook` → High; runtime-linkage, obfuscation,
   xor/base64, hidden-byte-strings, host-recon → Medium. Known-bad signature
   ids carry no capability segments, so this axis is *automatically* independent
   of the signature axis — which is what lets the demo prove release-day
   detection honestly. Only **gained or promoted** traits are judged; removals
   and demotions (a backdoor coming *out*, as in 5.6.0 → 5.6.3) are security
   improvements and never raise severity.
3. **identity** — a drifted signer/publisher forces at least High on its own.

Validated verdicts (`make demo`): xz 5.4.5→5.6.0 **HOSTILE** (behavioral High
standalone); xz 5.4.5→5.6.3 **CLEAN** (no false positive on the fixed release);
rand-user-agent **HOSTILE** (behavioral High); node-ipc **HOSTILE** (behavioral
Critical C2 + identity High).

**Still the next lever — proportionality by version class.** The behavioral
axis scores *what* capability was gained, not yet *how much drift is
proportionate to the version bump*. A minor release earns far less tolerance
than a major one; calibrate the bands empirically against known-good pairs in
hopper (per-class percentiles of trait ROC — cleave's severity-weighted
`scope_roc.traits`). This is what turns "gained an ifunc" into "gained an ifunc
*in a patch bump*, which is anomalous."

### Output philosophy — UNIX diff

isomer behaves like `diff`: **silent, exit 0, when there is no noticeable
behavioral change** (the fixed xz release 5.4.5 → 5.6.3 prints nothing). It
speaks only when there is something to say — and then concisely, in the
"signal-first" layout:

```
● HOSTILE    liblzma.so   5.4.5 → 5.6.0   minor bump
  disproportionate — a minor bump gained a high-severity capability

  ●●  behavioral  execution-hijack — gained an ifunc resolver
                 +runtime-linkage, hidden-byte-strings, xor-encoding (6 total)
  ●●● signature   4 known-bad rules matched (CVE-2024-3094)

  deps 1→2 · init_array 2→1 · code +37%
```

Rules that keep it scannable:

- **Speech gate** — speak iff the verdict fails `--fail-on`, reaches High, or
  is disproportionate for the bump. Otherwise silent.
- **No noise** — no `<root>` placeholder (single-file diffs have no path), no
  zero-valued counts, no un-fired axes. Behavioral axis leads (isomer's
  differentiator), then signature (summarized as a count + any CVE), then
  identity.
- **Proportionality line** — states drift-vs-bump directly ("a patch bump
  gained a critical-severity capability"). Bump tolerance: patch → None,
  minor → Medium, major → High; behavioral severity above tolerance is
  disproportionate. Versions come from the input paths (or `--base-version` /
  `--head-version`); undetectable versions yield no proportionality claim
  rather than a wrong one (`src/version.rs`).
- **Substantial metrics** — the biggest relative metric movers (≥15% floor,
  top 3) render as a dim trailer on single-file diffs (`code +37%`,
  `init_array 2→1`).
- **One view** — isomer stays silent when nothing noticeable changed and draws
  a single, complete verdict when it speaks: masthead, capabilities, the
  differential hunks (the root-cause code behind each gained trait), metrics,
  and the touched-file list. No `--explain` / compact split — the proof a
  reviewer needs is never a flag away. cleave's raw per-file ledger remains
  available from `cleave diff` directly. Broken-pipe-safe (`| head` no longer
  panics); `--color auto|always|never` controls ANSI.

### Header — masthead + grid (`src/fs.rs::header`)

The shipped terminal layout (chosen over the Command Rail after a mockup
series). A **masthead** carries what a human reads first, then a single
**pill grid** carries the detail:

```
  HOSTILE   node-ipc  12.0.0 → 12.0.1 · patch release · 3 of 14 files · disproportionate
 ✨ Supply chain compromise with data stealer payload        (only with --llm)
 📊 malware risk
    was  0.40  ████████░░░░░░░░░░░░  elevated
    now  0.97  ███████████████████░  malware   ▲ +0.57

  new        ●●● C2                  command-and-control/channel/websocket · …  2 new
  expanded   ●●  network             communications/dns/label · lookup/txt  +2
  signature  ●●● obfuscated-bundle-dns-and-exec
  metrics        deps 1→2 · init_array 2→1 · code ↑37%

  evidence
   📄 package/node-ipc.cjs
    1265  eton = new IPCModule();  Obfuscated stealer toolkit (host-fingerprint + base64)
```

- **Twin-bar risk** — `was`/`now` each on a benign→malware bar, the jump and
  new severity word dominant (a single bar read as "risk is 0.40").
- **One grid** — `pill · dots · name · locator`; behavioral (new/expanded),
  signature, metrics, and identity all share the columns. Sections with nothing
  (no metrics on a multi-file diff, no identity when only the version changed)
  are simply not drawn.
- **✨ read** sits in the masthead (only under `--llm`); the emoji pairs with
  📊 so neither floats alone. No rail.
- **Evidence** is its own `locator · code · description` table under a member
  header, ranked **hostile-first** and de-duplicated by description
  (`evidence::windows`), so the backdoor bytes lead, not the ELF header.

(The Command Rail below is retired.)

### (retired) Header — the Command Rail

The shipped terminal verdict (chosen from a set of colored mockups). It adopts
cleave's diff color language: a cyan brand rule, bold names over dimmed
connectives, numbers tinted by magnitude, background pills for section headers,
and scan's bold-white-on-color verdict badge.

```
 isomer ───────────────────────────── supply-chain differential

  HOSTILE   liblzma.so   5.4.5 → 5.6.0 · minor release
 risk   5.4.5  0.00  ▏░░░░░░░░░░░░░░░░░░░░▏  benign
        5.6.0  0.98  ▏████████████████████▏  malware   ▲ +0.98

 ┃ liblzma.so gained new execution hijack behavior — disproportionate…
 ┃
 ┃  behavioral   new · absent in 5.4.5
 ┃   ●●  binary/linking/runtime   execution hijack   4 new
 ┃   ●   data/encode/xor          xor encoding       1 new
 ┃  signature    ●●● 4 known-bad rules · CVE-2024-3094
 ┃  metrics      deps 1→2 · init_array 2→1 · code ↑37%
 └  evidence
```

- **Two-bar risk gauge** — each version on a benign→malware scale, so the delta
  is visual; azoth scores drive the fill and the word (benign/elevated/
  suspicious/malware).
- **Behavioral grouped by capability class, split new vs expanded** — see below.
- **Pills** (equal width) for behavioral · signature · metrics · evidence;
  **metrics** tinted by magnitude with ↑/↓.

### Behavioral: capability class, new vs expanded

The behavioral block groups gained traits by **capability class**
(`execution-hijack`, `network`, `C2`, `obfuscation`, …) — *not* taxonomy
segment. Class is the right granularity: every ELF has `binary/*` structural
traits, so a segment-level "new category" is meaningless, but the *class*
`execution-hijack` (the ifunc) is genuinely new while `runtime-linkage` (loader
deps) is not. Two subsections:

```
 ┃  behavioral
 ┃    new behavior · absent in 5.4.5
 ┃      ●●  execution hijack   binary/linking/runtime   1 new
 ┃      ●   xor encoding       data/encode/xor          1 new
 ┃    expanded · already in 5.4.5
 ┃      ●   runtime linkage    binary/linking/runtime   +3
```

- **new behavior** — classes with *no* trait in the base version (the strong
  signal). **expanded** — classes the base already had, now with more traits.
- The split needs the base's classes, so isomer does one cached
  `analyze_file(old)` (`evidence::base_classes`) and counts a class present
  only at **notable+** criticality — a baseline substring match doesn't mean
  the base "did C2", and erring toward notable+ keeps genuinely new
  capabilities flagged as new rather than dismissed as expanded.
- Within a class, the **common namespace prefix** is shown once and only
  divergent tails are listed — no stutter (`communications/dns/label ·
  lookup/txt`). Real result: node-ipc's C2/process-execution read **new**
  (it never phoned home) while network/install-hook read **expanded** (it was
  always an IPC library); xz's ifunc is **new**, its loaders **expanded**.

### Signature and identity tell the story, not a count

- **signature** lists the matched rules by name (`obfuscated-bundle-dns-and-exec`,
  `CRAIU/Backdoor`, …) under a count/CVE header, capped with `+N more` — not an
  opaque "6 known-bad rules".
- **identity** shows the actual field delta (`signer: X → unsigned`,
  `authors: A → A, B`) and — critically — only fires on **meaningful** fields.
  Version is excluded: a version bump is not a publisher change. This fixed a
  real false positive where node-ipc read "signer/publisher changed" when the
  *only* difference was `12.0.0 → 12.0.1`; the protestware was shipped by the
  same trusted maintainer, which is itself the correct (quieter) story.
- **evidence** renders the code/bytes **plain** (no match highlighting), with a
  full `// SEV description (trait-id)` annotation per window — the rail and the
  annotation carry emphasis, the code stays readable.

### New-vs-existing exit gate (`--gate`)

isomer is inherently differential — a finding present *unchanged* in both
versions never enters the diff, so it never affects the verdict. `--gate`
controls the rest:

- `--gate new` (default) — the exit code fails only on **newly-introduced**
  risk (`Assessment::new_severity()`: namespaces with new traits, newly-matched
  signatures, identity drift). A pre-existing issue isn't re-litigated every CI
  run.
- `--gate any` — also fails on **escalations** of findings that existed in the
  base version.

`--fail-on` sets the threshold within the gate. Both are stable CI contract.

### No-change, existing-risk note (`evidence::existing_risk`)

When the diff surfaces nothing but the new artifact still carries
suspicious/hostile traits, isomer prints a concise note instead of staying
fully silent — "nothing changed, but heads up" — and still exits 0 (it's not
new risk):

```
 liblzma.so · no behavioral change · existing hostile traits:
   ●●● CRAIU/Unk/Liblzma/Backdoor
   ●●● SigBase/BKDR/Xzutil/Binary/CVE/2024/3094/Mar24
```

A genuinely clean artifact still prints nothing at all.

### (historical) Incident Brief

The terminal verdict is written as an analyst's note (mockup direction #3):

```
 isomer · supply-chain differential

   liblzma.so   5.4.5 ──▶ 5.6.0   · minor release   [ HOSTILE ]
   risk         0.00 ──▶ 0.98    ▲ +0.98   azoth malware probability

   ┃ liblzma.so gained an ifunc resolver — disproportionate for a
   ┃ minor release.

   smoking gun  execution-hijack — an ifunc resolver
                metadata/binary/linking/runtime::ifunc   ●●  high
   also new     runtime-linkage · hidden-byte-strings · xor-encoding (6 …)
   confirmed    4 known-bad rules · CVE-2024-3094   ●●● critical
   metrics      deps 1→2 · init_array 2→1 · code +37%
```

- The **smoking gun** names the single worst gained capability in full — its
  complete hierarchical trait id — so the engineer can grep for it directly.
- **metrics** highlights the largest relative movers (labeled: `code`, `deps`,
  `init_array`, `relocs`).
- Evidence windows (below) follow the brief.

### Risk scoring via azoth (`src/risk.rs`)

isomer scores **both sides** with the same azoth ML model scan uses
(`scan::Analyzer` over `scan::models_repo::model_dir()`), and reports the pair
plus the delta: `risk 0.00 ──▶ 0.98  ▲ +0.98`. Because both sides are the same
artifact on the same classifier route, the scores are directly comparable and
the delta is meaningful — the model's opinion of *how much more dangerous the
new release is*. (True featurize-the-delta scoring isn't supported by a model
trained on whole artifacts; new − old is the honest v0.) Scoring degrades
gracefully: no model bundle → risk simply absent, never an error. Observed:
xz 0.00→0.98, rand-user-agent 0.00→1.00, node-ipc 0.40→0.97 (the base package
already scored 0.40; the protestware added +0.57).

### Evidence — the proof (`src/evidence.rs`)

Extraordinary claims need extraordinary evidence: after the impact header,
isomer shows the actual code/hex where each gained capability lives, so an
engineer never has to reach for another tool to investigate. The diff report
carries only trait *ids*, not their matched bytes — so isomer re-analyzes the
new side (cached, cheap), keeps only the context windows whose notes reference
a **gained** trait (evidence = the delta, not the whole file), and hands them
to cleave's own `output::format_context`. The windows are therefore
byte-identical to what scan/cleave render: hex+ascii for binaries, source
lines for scripts, `📄 member` headers for archives.

```
  evidence — where the change lives

 47e9   41 5c c3 0f 1f 40 00 f3 0f 1e fa  A\...@.....  // liblzma backdoored
 2ddf9  00 00 00 00 00 00 00 04 00 10 08  ...........  // liblzma backdoor, encoded strings
```
```
 52  global["_V"] = "7-randuser84";   // DEV#POPPER obfuscated package loader
 53  global["r"] = require;           // Global campaign identifier with require alias
```

The view is tight (top gained traits, hit rows only, focus on Notable+) and
draws its evidence only from the files the diff actually changed. node-ipc
drills into the archive member `node-ipc.cjs` and surfaces the `/etc/hosts`
string co-located with the DNS-lookup + shell-exec payload.

### Testdata + demo

`testdata/supplychain/` holds the curated old→new pairs (xz-utils,
rand-user-agent, node-ipc; ~740 KB, provenance in its README). `make demo`
runs `scripts/demo.sh` over them and narrates each verdict in scan/cleave's
visual idiom. `make {build,release,install,lint,fix,test,demo,clean}` mirror
scan's Makefile.

Next: proportionality bands, then the `purl` verb (fetch + bloom skip via
scan) and the markdown report body for the PR comment.

## The `ci` verb (implemented)

`isomer ci` derives the range, analyzes only the delta, and writes every sink
from one scan.

- **Range.** `--base`/`--head` win; otherwise the GitHub event payload
  (`pull_request.base.sha`/`head.sha`, or a push's `before`/`after`) and the
  GitLab equivalents. The base is then narrowed to `git merge-base base head`
  so commits that landed on the base branch after the change was branched are
  not attributed to it. A head commit absent from a shallow checkout falls back
  to `HEAD` (the merge commit), which is the only honest answer available
  there; a missing *base* is a hard error naming the fetch command to run.
- **Scope.** `git diff --no-renames --name-status -z` lists the change, and
  each side of each changed path is streamed out of git into
  `<tmp>/{base,head}/<repo-relative-path>`. Cost is proportional to the change,
  not the repository, and every reported path is the path the reviewer sees on
  the forge. `-z` framing means a filename containing a newline cannot hide a
  file from the scan; paths are handled as OS bytes on Unix for the same
  reason. Rename detection is off: to a differential analyzer a rename is a
  delete plus an add, and the added content is what needs judging.
- **Refusal over silent truncation.** More than `--max-files` (default 1000)
  changed files aborts the run rather than analyzing a subset — a scanner that
  quietly skips files reports "clean" for a change it never read. Blobs over
  128 MiB are skipped with a loud note for the same reason.
- **Sinks.** stdout gets `--format`'s output; `--out-dir` gets
  `report.{json,sarif,md}`; `$GITHUB_STEP_SUMMARY` gets the markdown (the one
  surface that works with a fork's read-only token); `$GITHUB_OUTPUT` gets
  `verdict`/`severity`/`new-severity`/`fail`/`findings`/`suppressed`, so the
  action needs no JSON parsing and stays thin. A failing run also emits a
  `::error::` annotation, with workflow-command metacharacters escaped so
  attacker-controlled text cannot forge a command.

### Policy file (implemented)

`.isomer.toml` carries suppressions and exclusions only — thresholds stay on
the command line so there is exactly one place to look when asking why a run
failed. A `reason` is required (isomer refuses to start otherwise), `expires`
makes an acceptance temporary, and every suppressed finding is *listed* in
every report, so a silenced run can never be mistaken for a clean one. The
suppression id space is exactly the finding id space: trait ids, `identity`,
and `structure/<slug>` — the same strings the SARIF rule ids use, so a report
tells the reader precisely what to paste.

## Ecosystem scope

Everything scan supports — including binaries. (Artifact-vs-source is the
only feature with a narrower v1 scope; see above.)

## Implementation

- Rust, using `atomdrift-scan` (lib name `scan`, edition 2024, MSRV 1.94) as a
  path/git dependency — the orchestration layer is thin; rewriting or FFI-ing
  the extraction stack would both be worse.
- Bloom-aware like scan: known-good versions (PURL+SHA256) are never
  rescanned.
- **rizin question (unresolved):** behavioral disassembly currently needs
  rizin. Options: vendor it, or degrade gracefully with a loud note in output
  that disassembly-derived checks were skipped. The "single static binary,
  works offline" story depends on the answer.

## CI contract

The CI user isn't watching a terminal. The primary UI is the **exit code**,
the **SARIF annotations**, and the **PR comment / step summary**; terminal
rendering is secondary.

### Exit codes

- `0` — clean (no findings at or above `--fail-on`)
- `1` — findings at or above `--fail-on`
- `2` — operational error. Never conflated with `1`: users gate merges on the
  exit code and must distinguish "malicious dep" from "registry timeout".
- `--fail-on none|low|medium|high|critical` tunes strictness in one flag.

### Output formats

- `--format terminal` — human output; TTY detection, color, `NO_COLOR`.
- `--format json` — stable, versioned (`schema_version` field,
  additive-only changes).
- `--format sarif` — non-negotiable; pipes to
  `github/codeql-action/upload-sarif` for PR annotations and Security-tab
  integration with zero UI work on our side.
- `--format markdown` — the risk-report comment body (see below).
- When `GITHUB_ACTIONS` is set: auto-write a verdict table to
  `$GITHUB_STEP_SUMMARY`, auto-enable annotation-friendly behavior.

### PR comment (differential risk report)

The CLI stays GitHub-API-ignorant and offline-pure: it *emits* the report;
posting is the action's job.

1. `isomer ci --format markdown` writes the report. The body embeds a hidden
   marker: `<!-- isomer-report -->`.
2. The official action (`atomdrift/isomer-action@v1`, JS, using
   `@actions/github`) lists the PR's comments, finds the one carrying the
   marker, and **updates it in place** (create if absent) — a "sticky
   comment", so every push edits one comment instead of spamming the thread.
   Requires `permissions: pull-requests: write` on the default
   `GITHUB_TOKEN`.
3. Raw-workflow alternative (documented for non-action users): `gh pr comment
   "$PR" --body-file report.md --edit-last --create-if-none` on runners where
   `gh` is preinstalled.
4. **Fork PRs:** `pull_request` events from forks get a read-only token — the
   comment step must be `continue-on-error` there, with the two-workflow
   pattern (`pull_request` uploads the report as an artifact; a `workflow_run`
   workflow with write perms posts it) documented for public repos.
   `pull_request_target` is explicitly discouraged (checkout-of-untrusted-code
   footgun — and isomer's whole audience knows it).

Report content: verdict badge (CLEAN / SUSPICIOUS / HOSTILE), capability
delta table (gained/lost, with severity), proportionality assessment
(version bump vs change magnitude), top findings with file:line, and a
one-line suppression hint.

### Caching

One XDG-respecting directory (`~/.cache/isomer`) holding bloom filters,
verdict cache, and rules snapshots. Safe to restore cross-branch. The
official action wires `actions/cache` automatically; the documented key is
public API. This is what makes run two take seconds instead of minutes.

### Policy file

`.isomer.toml` at repo root, committed:

- fail threshold, scope excludes
- allowlisted findings — each requires a `reason`, supports `expires`
- precedence: flags > env > repo config

A false positive must be suppressible in one reviewable line of config.

### Offline honesty

`--offline` is a hard guarantee: no registry fetch, no rule update, no LLM.
Default posture prints what network it intends to use. `HTTPS_PROXY`
respected and documented (air-gapped/proxied enterprise runners are a large
share of the paying audience).

## Distribution

- Single static binary: musl-static Linux, macOS, x86_64 + arm64. No runtime
  deps (modulo the rizin question).
- Official action: `atomdrift/isomer-action@v1` — downloads the
  pinned-by-checksum binary for the runner arch, runs `isomer ci`, uploads
  SARIF, posts the sticky comment. ~4 inputs: `fail-on`, `format`, `deep`,
  `rules-version`. Quickstart is five lines of YAML.
- OCI image for `container:` jobs and non-GitHub CIs.
- Release hygiene must be exemplary — isomer is a supply-chain security tool
  and will be judged harder than anyone else on this: sigstore-signed
  releases, SLSA provenance, reproducible builds if attainable. "isomer scans
  its own releases in CI" is both dogfood and marketing.

## Open questions

- rizin vendoring vs graceful degradation (blocks the static-binary story).
- Rules distribution: two live streams (paid fast / free slow) must stay
  coherent; isomer pins versioned rule snapshots.
- Where Valence's rubric→model cutover happens, and what telemetry (opt-in)
  feeds it.
- GitLab/other CI auto-detection scope for `isomer ci` v1.
