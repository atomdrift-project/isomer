# Syscall inventory — extraction spec (filefacts)

> **Status: implemented + validated (2026-08-08).** `filefacts/src/formats/
> elf_syscalls.rs` (Tier 1 imports + Tier 2 `memmem` scan + bounded local
> decode; x86-64 + aarch64; 3 unit tests). Real-world check: the compromised
> kong-ingress-controller Go binary makes **85 direct syscalls vs the clean
> 76**; both name the Go-runtime set (`clone, kill, mmap, tgkill`); liblzma
> correctly shows none (dynamically linked, no direct syscalls). The isomer arm
> (`rubric::structural_facts`) consumes both — gained named syscalls (exec/
> process = High, else Medium) and a `direct_syscall_count` jump (≥4 → Medium).
> **End-to-end pending:** cleave must rebuild against the new filefacts to carry
> `elf.syscalls[]`/`elf.direct_syscall_count` into its report (cleave uses a
> *git* filefacts dep + is mid-refactor, so this needs a path-dep override or a
> filefacts push, plus cleave green).


Phase 1 of DETECTION_ROADMAP.md. Emit the set of syscalls a binary can make so
isomer can diff it ("gained `mprotect`/`ptrace`") and cleave can trait on it
("library issues `process_vm_writev`"). This is the highest signal-per-effort
binary-forensics signal and generalizes far beyond xz.

## Performance is the design, not an afterthought

The naive approach — full rizin disassembly + register dataflow over every
function — is exactly the expensive path filefacts already fences behind
timeouts. For a differential scanner over many artifacts we **never** pay that
for syscalls. Three tiers, cheapest first, and we stop when the cheap tier
already answers:

### Tier 1 — imports (free, always-on)

Most code reaches syscalls through libc wrappers via the PLT/dynsym, which we
**already extract**. Map imported symbol names → syscall names through a static
lexicon: `mprotect`, `ptrace`, `process_vm_readv`/`writev`, `memfd_create`,
`prctl`, `personality`, `seccomp`, `execve`/`execveat`, `socket`/`connect`,
`clone`/`fork`, `mmap`. Cost: O(imports) — microseconds, no decoding. This
alone covers the vast majority of real binaries.

### Tier 2 — direct syscall instructions (bounded scan, gated)

A backdoor that wants to dodge import-based detection issues syscalls
*directly*, bypassing the PLT — which is itself a signal. Detect it **without
disassembling the whole binary**:

1. **SIMD byte scan for the opcode, over executable sections only.** `syscall`
   is `0F 05` (x86-64), `svc #0` is `01 00 00 D4` (arm64, LE), `int 0x80` is
   `CD 80` (x86-32 compat). Use `memchr::memmem` (SIMD) to find candidate
   offsets in the bytes of `alloc,executable` sections *only* (we have the
   section table + perms). Cost: O(text bytes), a few ms even for large `.so`s.
   This is the whole performance trick — you pay decode cost at only the tiny
   fraction of bytes that are candidate sites, never the whole `.text`.
2. **Resolve the number with a bounded backward decode at each candidate.** The
   syscall number is in a register set shortly before (`eax`/`rax` on x86,
   `x8` on arm64). Decode *backward* a small window (≤ ~24 bytes / ≤ 8
   instructions) with the decoder filefacts already vendors (`iced_x86` for
   x86; arm64 is fixed-width 4-byte so hand-match the `movz x8, #imm` word).
   Look for `mov eax, imm32` (`B8 …`), `mov rax, imm` (`48 C7 C0 …`), or
   `movz x8`. Cost: O(candidates × small-window) — candidates are dozens.
3. **Only emit when the number resolves to a valid NR.** A `0F 05` that landed
   in data or mid-instruction won't have a clean preceding `mov eax,
   <valid-nr>`, so it self-filters. Unresolved sites bump a counter
   (`direct_syscall_count`) but add no name.

### What we deliberately do NOT do

- No rizin function/CFG analysis for syscalls (that's Phase 2 resolver-body
  work, separately gated).
- No global linear disassembly of `.text` (the slow thing). Scan-then-
  local-decode instead.
- No dataflow for computed syscall numbers (`syscall(nr, …)` with a runtime
  `nr`) — we flag its *presence* (`has_indirect_syscall`) and move on.

### Gating & caching

- Tier 1 always-on. Tier 2 for ELF/Mach-O with executable sections, under the
  same byte cap rizin already respects; skip on absurdly large text.
- Pure function of file bytes → **cache by content hash** in filefacts' existing
  analysis cache; re-scans are free, and isomer's bloom skips known-good.
- Single pass: one memmem sweep per opcode pattern over exec sections, collect
  offsets, bounded-decode each. O(text) + O(candidates), zero global analysis.

## Emitted facts

Into the same scopes isomer already diffs (kv + metrics):

- `binary.syscalls[]` — sorted, deduped syscall names (union of Tier 1 + Tier 2).
  Diffs like `elf.needed[]`/`elf.ifuncs[]` → isomer "gained `mprotect` · `ptrace`".
- `binary.direct_syscall_count` (metric) — count of *direct* (non-PLT) syscall
  sites. A library going 0 → N direct syscalls is the evasion tell.
- `binary.has_indirect_syscall` (bool) — a `syscall()`-style computed-number
  site is present.

### The NR → name tables

Static per-arch const tables (x86-64 ≈ 350 entries, arm64 differs), generated
once from the kernel syscall tables; small, stable, no runtime cost. Arch comes
from the ELF/Mach-O header we already read. Ship x86-64 + arm64 first (covers
the overwhelming majority); arm32/riscv later.

## Dual-path consumption

- **cleave trait** (absolute, single-scan): fires on the *presence* of a
  sensitive syscall for the software class — e.g. `library issues
  ptrace/process_vm_*/memfd_create`, or `mprotect(PROT_EXEC)` paired with the
  RWX section fact. References `binary.syscalls[]` via the kv evaluator.
- **isomer differential** (novel, no trait needed): `rubric::structural_facts`
  adds a `syscalls` fact when the set grows — "gained `mprotect`, `ptrace`" —
  scored by a sensitivity lexicon (execution/memory & process-manipulation =
  High; introspection/anti-analysis = Medium; benign = ignored), and escalated
  by software-class disproportion (a *compression* library gaining *any* of
  these). Slots straight into the structure axis and the conjunction rule.

## Sensitivity lexicon (scoring)

| tier | syscalls | why |
|---|---|---|
| High | `mprotect`(+EXEC), `mmap`(+EXEC), `memfd_create`, `execve`/`execveat`, `ptrace`, `process_vm_readv`/`writev` | runtime code exec / process hijack |
| Medium | `prctl`, `personality`, `seccomp`, `/proc/self/maps` access, `clone` | anti-analysis / introspection |
| context | `socket`/`connect`/`sendto` | High for a compression/parser class, normal for a net tool |

## Effort

Tier 1 ≈ trivial (lexicon over existing imports). Tier 2 ≈ the real work: the
memmem scan + bounded x86/arm64 number-resolution + NR tables. All lives in
filefacts; no new heavy dependency (memchr + the existing iced_x86). Then a
one-line kv fact into cleave, a `structural_facts` arm + lexicon in isomer, and
an azoth retrain to pick up the new feature.
