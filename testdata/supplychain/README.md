# isomer supply-chain testdata

Curated real-world supply-chain compromises, each shipped as an **old → new**
pair so `isomer fs` can be exercised end to end. These samples carry no
provenance or commit history — fine for the `fs` verb, which judges the
artifact delta alone. Larger corpora with provenance live outside the repo.

Sourced from the atomdrift supply-chain corpora (`data/supplychain/cases`,
`supplychain-trenches`). **The compromised halves contain live malicious
code and backdoored binaries — never execute them; isomer only reads them.**

| Case | old → new | Attack |
|------|-----------|--------|
| `xz-utils/` | `liblzma.so.5.4.5` → `liblzma.so.5.6.0` | CVE-2024-3094 — ifunc-hijack backdoor in a compiled shared object. `5.6.3` is the fixed release (for false-positive and removal checks). |
| `rand-user-agent/` | `clean/index.js` → `compromised/index.js` | RATatouille — obfuscated RAT loader hidden in an npm package. |
| `node-ipc/` | `node-ipc-12.0.0.tgz` → `node-ipc-12.0.1.tgz` | protestware — geo-targeted destructive payload; also exercises archive-member diffing. |
| `wordpress-addthis/` | `before/addthis.tar.xz` → `during/addthis.tar.xz` | WordPress plugin-repo compromise (r399309→r399310): an `@assert(wp_get_referer())` webshell hidden in a language array — assert() runs the Referer as code. Behavioral detection only; no signature. |
| `wordpress-wptouch/` | `before/wptouch.tar.xz` → `during/wptouch.tar.xz` | WordPress plugin-repo compromise (r399279→r399585): a `$_COOKIE`-driven dynamic dispatch (`$matches[1]($matches[2])`) — the callee and its argument are both attacker-supplied. |
| `node-ipc-protestware/` | `node-ipc-10.1.0.tar.xz` → `node-ipc-11.0.0.tar.xz` | protestware — the earlier geo-targeted file-overwrite payload, pulled in via a **new runtime dependency** (`peacenotwar`). No behavioral trait fires on the package itself; isomer surfaces it from the manifest as a `dependency` structural fact (Medium — it speaks, but stays below `--fail-on high`). |
| `openapi-react-query-codegen/` | `before/…-3.0.2.tgz` → `during/…-3.0.3.tgz` | Mini Shai-Hulud — an unauthenticated `issue_comment` publish trigger let a fork's `preinstall` run inside a job holding `id-token: write`, and it published ten signed releases. `3.0.3` is wave 1: **no install script at all**, so detection has to come from the files — an 828-byte `binding.gyp` whose `conditions` block reaches `os.system` through `().__class__.__base__.__subclasses__()` in `\U000000xx` escapes, plus a 6.4 MB single-line loader `3FWCvzduYZg.js`. npm hands any package with a `binding.gyp` to `node-gyp rebuild`, which `--ignore-scripts` does not cover. |
| `openapi-react-query-codegen/` (control) | `before/…-2.2.0.tgz` → `before/…-3.0.2.tgz` | **Not an attack** — the same package's own cross-major upgrade, and the demo's only `clean` case. `dist/` goes 17 → 41 files, the emitter moves into a new `dist/tsmorph/` tree, `.d.mts` declarations appear throughout, and `peerDependencies` gains `@tanstack/react-query`. Must stay under `--fail-on high`: same package, publisher, and packaging as the row above, no payload. |
| `unrealircd/` | `Unreal3.2.8.1.tar.xz` → `Unreal3.2.8.1_backdoor.tar.xz` | CVE-2010-2075 — a backdoored *repack* of the same version (3.2.8.1). Buried in a 475-file source tree, `src/s_bsd.c` gains a magic-byte check (`memcmp(readbuf, DEBUGMODE3_INFO, 2)`) that routes matching socket data into a `system()`-calling macro (`struct.h`). No version bump licenses the new capability, so proportionality escalates the two medium traits. The `.tar.xz` is the corpus `.tar.gz` with its gzip layer swapped for xz (same tar, ~2.3 MB/side); the largest fixture, kept for the archive-member-at-scale case. |

The `.tar.xz` cases are corpus samples (`~/src/supplychain-attack-data`) small
enough (< 1 MB) to vendor compressed. Each side wraps its file under a **stable
inner path** (`pkg/<name>`) so `isomer fs` diffs the members as *changed*, not
as add+remove — repack more with `scripts/pack-corpus-sample.sh`. The
`openapi-react-query-codegen` `.tgz` files need none of that: they are the
untouched npm tarballs (SHA-256s match that attack's `samples/manifest.yaml`,
which in turn matches npm's retained `dist.integrity`), and npm's own
`package/` prefix is already the stable inner path.

That case is the only one vendored with a **negative** control beside its
attack, because it is the only incident here that preserved more than one
pre-compromise release. `make validate-samples` generalizes the idea: wherever
the corpus holds several clean `before` releases, every adjacent pair must stay
under the gate (`FP-BASELINE`), since each one is an upgrade a real user
performed. That audit runs the full 0.5.3 → 1.6.2 → 2.2.0 → 3.0.2 chain; the
demo vendors just the last link of it.

The xz-utils case is the flagship: with its *known* backdoor signatures
suppressed, isomer must still flag `5.4.5 → 5.6.0` on **behavioral capability
drift alone** (a compression library gaining an ifunc resolver + loader deps +
obfuscated byte strings in a minor bump). See `make demo`.
