# Changelog

All notable changes to isomer. Versions follow [semantic versioning](https://semver.org/spec/v2.0.0.html).

## 0.6.0-beta.1 (unreleased)

### Features

- Detect binary grafts: entry-point redirects, new writable-executable mappings, and callbacks into newly added code.
- Flag a retained build ID, UUID or CodeView identity alongside added or altered executable code.
- Flag npm install hooks a release starts running, especially ones targeting new or missing scripts.
- Flag native binaries and top-level code that a package release never shipped before.
- Flag execution injected by a change's own lines, such as decoded strings or request data reaching dynamic calls.
- Gate on the quantity of behavior a release adds, reported as `verdict.behavior_mass`.
- Treat registry takedowns and npm security tombstones as malware, whatever content change came with them.
- Check registry metadata for packages and declared dependencies by default; `--no-follow` skips it.
- Profile changed and replaced dependencies with `--deps`, raising new categories or higher risk to High.
- Connect to Atomdrift Uplink with `--uplink` for zero-hour rules, remote dependency verdicts and a hosted LLM.
- Accept a comma-separated chain of LLM endpoints, failing over when one is unusable.
- Name the MITRE ATT&CK and MBC techniques a change moved, without network access.
- Pair Composer Git exports whose wrapper directories differ but name the same package.
- Refuse CI runs touching more than `--max-files` files instead of reporting a subset as the whole.
- Expose isomer as a library; the CLI is a thin wrapper behind the default cli feature.
- Breaking: read the LLM bearer token only from `ISOMER_LLM_KEY`, keeping it out of process listings.
- Breaking: remove the `--llm-timeout` flag.
- Minimum Rust version raised from 1.94 to 1.97.

### Fixes

- Report unavailable registry lookups as unknown, never as a missing or clean package.
- Show the LLM only a change's relevant lines, so broad benign matches no longer bury the real change.
- Stop an absolute model probability alone from raising a benign classification to an alarm.
- Stop reading a new call site of an existing capability as newly arrived execution.

### Optimizations

- Decode each archive once per comparison; xz 5.6.0's 756-entry release previously took over fifteen minutes.

## 0.5.0 (2026-08-14)

- Normalize Git snapshots and Python sdist/wheel layouts before diffing.
- Extract changed source from archives and show its line-level delta.
- Preserve composite findings and rank evidence across the complete change.
- Recognize prerelease transitions and apply a tight behavioral budget.
- Detect public APIs backed by floating young dependencies.
- Detect auto-loaded source or scripts that download, write, and execute payloads.
- Improve npm entrypoint discovery and local LLM guidance.
- Detect 132/132 corpus attacks with no false positives across 98 clean transitions.

## 0.4.1 (2026-08-14)

### Version comparison

- Four-part versions are now parsed and compared in full.
- `Bump::classify` rewritten as a component-wise walk to the deeper of the two versions: the first differing component decides.

### Build & CI

- `cargo test --locked --lib` → `cargo test --locked` across native, FreeBSD, and OpenBSD jobs; isomer is a binary crate.
- Release matrix split into fast (native, Windows, cross — ~30 min) and slow (emulated/VM platforms — up to 75 min) waves.
- New `.cargo/config.toml`: `-lstdc++` for illumos (`unrar_sys` via cleave compiles C++ and rustc links `-nodefaultlibs`), `-lgcc` for 32-bit ARM musl (jemalloc's `__ffsdi2` / byte-width CAS intrinsics).

### Dependencies

- cleave 2.7.1 → 2.7.2, atomdrift-scan 2.7.0 → 2.7.1, plus filefacts, fletch, stng 1.8.0 → 1.9.0, libredox 0.1.19 → 0.1.20.

## 0.4.0 (2026-08-14)

### Three new detectors, none rule-dependent

- Same-version binary repacks where the metrics move but the version doesn't.
- Encoded single-line payloads newly wired into a package entrypoint.
- Readable implants grafted in, caught by timestamp outliers rather than obfuscation.

### Sharper judgment

- Reads versions from artifact metadata; without one, every release-pressure check was silently off.
- `--deps` findings now change the verdict instead of just printing.
- Dependency ranges resolve to current, not their floor — pinning to the floor is how you miss event-stream.

### Fixes

- `isomer ci --deps` silently skipped both dependency folding and LLM interpretation.
- `--offline` didn't actually suppress the LLM.
- An unreadable base file could fabricate the signal that lowers a verdict.
- CI hardening: a caller-supplied `--base` could forge GitHub workflow outputs.
- Rules now auto-update like scan does.

### Output

- Versioned features block in JSON for ML consumers.
- Trait grid ranked by criticality × confidence, capped at 24.
- Terminal row caps no longer truncate the data the verdict is computed from.

## 0.3.0 (2026-08-14)

### Detection

- Shape signals: a dense capability jump in few files, or a package that deletes its own tree, now escalates alone.
- A patch or same-version repack that gains behavior is raised to High. Disproportion is the signal.
- Source archives read whole — build macros, fixtures, payload carriers stay in the diff.
- Two new shapes named: a build macro growing a joined shell eval, and an unchanged loader over a changed compressed carrier. The xz shape.
- Archive roots normalized, so `pkg-1.2.3/` and `pkg-1.2.4/` pair as one member.
- Cleanups score as cleanups: disabled handlers, removed traits, falling risk read Notable, not hostile.

### False positives, gone

- absent → present identity is not drift. Only stripped identity is.
- Filename-only identity never compared against manifest identity.
- Empty identity objects likewise.
- Absolute ML risk no longer condemns. Only a worsening band moves the verdict.

### The model

- Its verdict now raises displayed severity, and the risk bar with it. It never lowers.
- The gate stays deterministic. A hallucination must not fail your build.
- Raised numbers are labeled `azoth+llm`.
- Prompt rewritten around an evidence order, and taught what remediation looks like.
- `--format interpret` prints the exact payload and never calls out.

### Output

- `--explain` removed. One view. If isomer speaks, it shows everything.
- Gained capabilities render as a tree: `+` new class, `↑` grown.
- Removed high-risk behavior gets its own section.
- Hunks name the member, dim the path, wrap instead of truncate.

### Distribution

- 20 targets: Linux gnu/musl (x86_64 → riscv64, s390x, ppc64le, loongarch64, arm), macOS, Windows, the BSDs, illumos, Solaris, Haiku, Hurd.
- macOS binaries signed and notarized; a preflight proves the credentials before any build.
- Sigstore provenance attestation, checksums, per-target retry, dry runs.
- Runtime smoke tests on OpenIndiana, Tribblix, GhostBSD, openEuler, BlissOS.

### Build

- New `release-lto` profile — fat LTO, one codegen unit — for shipped binaries. Everyday `cargo build --release` gets thin LTO.
- cleave and atomdrift-scan rev pins dropped; `Cargo.lock` holds the commit.

## 0.2.0 (2026-08-11)

### Added

- Rename-aware artifact pairing.
- git rename detection in `ci`.
- Scope reporting (source only / source + build output) so a run whose base build failed can't read as a clean full comparison.
- `make validate-samples`.

### Removed

- `.isomer.toml` suppression policy; unnecessary for differential analysis.

### Changed

- Clean CI runs emit a one-line step summary instead of a full report.

## 0.1.0 (2026-08-11)

First release!
