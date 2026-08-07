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

The xz-utils case is the flagship: with its *known* backdoor signatures
suppressed, isomer must still flag `5.4.5 → 5.6.0` on **behavioral capability
drift alone** (a compression library gaining an ifunc resolver + loader deps +
obfuscated byte strings in a minor bump). See `make demo`.
