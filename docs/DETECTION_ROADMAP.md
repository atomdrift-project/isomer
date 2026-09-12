# Detecting an xz-utils copycat — roadmap

Goal: make isomer **obviously** flag a backdoor that reuses the xz *technique*
(hidden payload assembled at build time, activated via a subtle load-time /
linker hijack) but matches **none** of the existing traits or signatures.

## Principles

1. **Dual path, always.** Every new signal ships in two forms:
   - a **cleave trait** — absolute detection, fires on a single-artifact scan
     ("this library has a linker-audit hook");
   - an **isomer differential** — the same underlying fact enters the diff's kv
     scope and isomer's *structure axis* flags it when it **appears between
     versions**, *independent of whether any trait matched*. This is the path
     that catches a novel copycat: the trait may not fire, but "a compression
     library **gained** `ptrace` + a high-entropy region + an audit hook in a
     minor release" still lights up.
2. **One extraction feeds both.** Confirmed flow: a `filefacts` fact →
   `cleave` (a composite rule can reference it via the kv evaluator; it also
   rides into `report.kv`/`filefacts_metrics`) → `isomer` diff (`scopes.kv`
   structure axis + `scopes.traits` behavioral axis). So each item below is
   *one* filefacts change that automatically arms both paths.
3. **Win on the conjunction × disproportion.** No single property is damning —
   ifuncs are normal, entropy happens. What has no benign story is a
   *compression* library exhibiting **three of these at once, in a minor bump**.
   isomer's rubric must score the co-occurrence and the software-class mismatch,
   not just each axis.
4. **Everything is a Valence feature.** The hand-coded rubric scores these as an
   expert system now; each extracted fact is also a feature the eventual ML
   engine learns to combine, so no one has to hand-write "the xz rule".

## The kill-chain → signals

| xz invariant | signal | filefacts | cleave trait | isomer differential | status |
|---|---|---|---|---|---|
| carry hidden payload | new high-entropy region | per-section entropy → kv | `high-entropy region in odd section` | "new N-KB high-entropy region" | have raw; surface |
| execute at load time | linker **audit hook** (`DT_AUDIT`) | already extracted (`has_dt_audit`) | `library installs a linker auditor` | "gained DT_AUDIT" | **extracted, not surfaced** |
| " | ifunc **resolver does more than dispatch** | disassemble resolver body | `ifunc resolver calls external / touches GOT` | "resolver complexity jumped" | new (rizin) |
| " | RWX / `mprotect(PROT_EXEC)` | RWX seg + mprotect-to-exec | `writable+executable region` | "gained RWX / runtime exec" | partial (Mach-O has it) |
| abnormal syscalls | **syscall inventory** | enumerate `syscall`/`svc` + number | `library issues ptrace/process_vm/memfd/mprotect` | "gained syscall X" | **missing entirely** |
| find/hijack target | cross-domain symbol reach | symbol-domain tag | `compression lib references crypto/ssh domain` | "reaches a foreign domain" | new (hardest) |
| " | dynamic resolution machinery | `__tls_get_addr`, `dlsym`, `_dl_*` | (expand sensitive-import lexicon) | "gained linker-internal imports" | have `__tls_get_addr`; expand |

## Phasing (signal-per-effort order)

> **Finding (verified on the xz sample).** xz injected its payload as **code**
> (`.text` +38%), *not* a high-entropy blob, and uses **no RWX** and **no static
> `DT_AUDIT`** (it patched the GOT at runtime). So the entropy / RWX / audit-hook
> facts below do **not** fire on xz — they arm *sibling* shapes (packed
> payloads, self-decrypting stubs, static-audit backdoors). What tightens
> xz-*specifically* is Phase 1–2 (syscalls, resolver bodies). The always-true
> xz tells we already surface: loader dependency, ifunc resolvers, new imports.

**Phase 0 — surface what we already extract (days, mostly plumbing).** ✅ isomer
half **done** (`rubric::structural_facts` now reads the `sections`/`metrics`
scopes): `DT_AUDIT`/`DT_DEPAUDIT` → "linker audit hook" (High), writable+executable
section → "writable+executable" (High), a section that turned high-entropy and grew
→ "high-entropy region" (Medium). All differential, all feed the verdict, none
false-fire on the corpus. The cleave-trait half waits on cleave compiling. Remaining
Phase-0 idea: per-section entropy is in the `sections` scope; a dedicated cleave trait
for "high-entropy region in an odd section" is still worth adding.
- `has_dt_audit`/`has_dt_depaudit` into the kv scope → isomer structure axis
  (`linker audit hook` fact, High) + a cleave trait. Highest signal for least
  work: a normal library gaining `DT_AUDIT` is near-certain malice, and the xz
  interception surface *is* the auditor interface.
- Per-section entropy into kv → isomer "new high-entropy region {section,size}".
- (Structure axis already covers new dependency / ifunc presence / new imports.)

**Phase 1 — syscall inventory (filefacts; highest new-signal-per-effort).**
- rizin/iced: enumerate direct syscall instructions and their number (`rax`
  immediate) plus libc syscall wrappers; emit `binary.syscalls[]`.
- Trait: a library issuing `ptrace`, `process_vm_readv/writev`, `memfd_create`,
  `mprotect(PROT_EXEC)`, or opening `/proc/self/maps`.
- Differential: isomer diffs the syscall set → "gained `mprotect`". Generalizes
  far beyond xz.

**Phase 2 — ifunc-resolver body analysis (filefacts; most xz-specific).**
- Disassemble the ifunc resolver targets. A benign CRC resolver is ~10
  instructions of `cpuid` dispatch; a hijacking one calls out, touches the GOT,
  writes memory. Emit `ifunc.resolver_insn_count`, `resolver_calls_external`,
  `resolver_touches_got`, `resolver_makes_syscall`.
- Trait + differential on resolver complexity.

**Phase 3 — RWX / self-modifying (filefacts).**
- ELF RWX-segment fact + `mprotect`→`PROT_EXEC` detection (Mach-O already has
  `VM_PROT_EXECUTE`); trait + differential.

**Phase 4 — cross-domain symbol reach (cleave; hardest, biggest generalization).**
- Symbol/string domain lexicon + the software classification cleave already has;
  flag a mismatch ("compression library references `RSA_*`/ssh"). **Caveat from
  real xz:** the target string was *obfuscated* (no plaintext
  `RSA_public_decrypt`), so string matching fails — the robust version detects
  the *behavior* of resolving symbols dynamically by hash / walking the link
  map, which lives in the disassembly layer.

## isomer differential design (the part traits can't cover)

The structure axis already scores kv-added facts. Extend it so a copycat that
dodges every trait still fires:

1. **Fact → severity map** for each new category (audit hook = High, foreign
   syscall = High/Medium by syscall, RWX = High, resolver-complexity jump =
   High, high-entropy region = Medium…).
2. **Conjunction escalation.** Co-occurrence of ≥3 independent binary-anomaly
   axes → escalate the structure axis to Critical regardless of individual
   severities. This is where "obvious" comes from.
3. **Software-class disproportion.** Pull the artifact's class; for a
   non-system-tool class (compression, image, parser…), *any* of these is
   near-certain — score it as such. (Generalizes "a JPEG library shouldn't talk
   to the internet" to "…shouldn't hold a linker audit hook".)
4. Because these fire on the *fact appearing in the diff* — not on a trait
   match — this is the signature-independent detector. The trait path is the
   bonus for known shapes.

## Measuring signature independence (rule ablation)

The corpus cannot, on its own, show whether a detection would survive a *novel*
attack: every attack in it is old enough that traits-dev already names it. What
it can show is what happens when those rules are taken away. Judge each attack
comparison again with progressively more of the rule set ablated from the
traits it gained:

| level | what is removed | detected |
|---|---|---|
| L0 | nothing | 934 / 941 |
| L1 | known-bad signatures (`third_party/*`, `well-known/malware/*`) | 934 / 941 |
| L2 | L1 + hostile `objectives/*` composites — the campaign-shaped rules | 930 / 941 |
| L3 | L2 + every `objectives/*` trait | 916 / 941 |
| L4 | L3 + suspicious `micro-behaviors/*`: only ordinary capability left | 860 / 941 |

(941 attack transitions measured 2026-09-12; "detected" means at least one of
the behavioral, structure, identity, model, or behavior-quantity axes still
reaches the gate. L4's survivors are almost entirely the model's, and the model
would itself degrade if the rules it was trained on vanished, so read L4 as an
upper bound.)

The reading that matters: **losing every rule that names an attack costs 2% of
detection** (L0 -> L3). What carries it is the capability taxonomy itself plus
the structure and quantity axes — not the campaign rules.

L2 and below cannot be evaluated for the behavior-*quantity* axis from retained
diagnostics, because ablating a trait also shrinks the denominator it is
measured against; that is exactly the regime the axis's counted branch
(`ids_gained` / `id_share`, criticality-blind) exists for.

## The floor: source-vs-artifact

Binary forensics raises the bar and catches lazy copycats (most of them). A
*careful* copycat can tune each signal toward "plausible". The signal robust to
that — and the one binary-only analysis structurally cannot see — is
**source-vs-artifact divergence**: the xz payload was not in the git repo. The
`purl`/`git` build-and-capability-compare path (see DESIGN.md) is the floor no
injected-at-build-time backdoor clears; ship it alongside.

## Cost / gating

Deep rizin (resolver bodies, syscall enumeration) is expensive; the existing
timeout / mute machinery applies. Gate on: binary target ∧ bloom-miss ∧
(suspicion or `--deep`). Cheap facts (DT_AUDIT, entropy, imports) are always-on.

## Retraining

Each new fact is an azoth feature; adding them requires a retrain, and is a step
toward Valence scoring the full change vector (size, entropy, traits, metrics,
facts, syscalls, resolver complexity) directly.
