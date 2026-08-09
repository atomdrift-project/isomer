#!/bin/sh
# isomer demo — run the curated supply-chain pairs and narrate what isomer
# catches on each. Every case is a real compromise shipped as an old → new
# pair under testdata/supplychain. Read-only: isomer never executes a sample.
#
# Usage: scripts/demo.sh [path-to-isomer-binary]
# Defaults to `cargo run -q --`, so `make demo` works from a clean checkout.
set -eu

ISOMER="${1:-cargo run -q --}"
DATA="testdata/supplychain"

# Palette — matches scan/cleave: bold heading, dim rationale.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    B='\033[1m'; DIM='\033[2m'; R='\033[0m'
else
    B=''; DIM=''; R=''
fi

case_header() {
    printf '\n%b━━━ %s %b\n' "$B" "$1" "$R"
    printf '%b%s%b\n\n' "$DIM" "$2" "$R"
}

run() {
    # run <old> <new> — show the invocation, then isomer's verdict. isomer is
    # silent like `diff` when there's no noticeable behavioral change, so make
    # that visible when it happens. --fail-on none keeps the demo running;
    # --color always keeps the theme colored even when captured.
    printf '%b$ isomer fs %s %s%b\n' "$DIM" "$1" "$2" "$R"
    out=$($ISOMER --color always --fail-on none fs "$1" "$2" 2>&1) || true
    if [ -z "$out" ]; then
        printf '%b  (silent — no noticeable behavioral change; exit 0)%b\n' "$DIM" "$R"
    else
        printf '%s\n' "$out"
    fi
}

printf '%bisomer — differential supply-chain detection over real compromises%b\n' "$B" "$R"

case_header "xz-utils / CVE-2024-3094" \
    "Backdoor in a compiled shared object. The flagship case: even with the known
signature ignored, the BEHAVIORAL axis flags it — a compression library that
gains an ifunc resolver + loader deps + obfuscated byte strings in a minor bump."
run "$DATA/xz-utils/liblzma.so.5.4.5" "$DATA/xz-utils/liblzma.so.5.6.0"

case_header "xz-utils / fixed release (false-positive check)" \
    "5.4.5 → 5.6.3 is clean → patched-clean. Must NOT read HOSTILE."
run "$DATA/xz-utils/liblzma.so.5.4.5" "$DATA/xz-utils/liblzma.so.5.6.3"

case_header "rand-user-agent / RATatouille" \
    "Obfuscated RAT loader hidden in an npm package (source, not binary)."
run "$DATA/rand-user-agent/clean/index.js" "$DATA/rand-user-agent/compromised/index.js"

case_header "node-ipc / protestware" \
    "Geo-targeted destructive payload across two published tarballs; also
exercises archive-member diffing."
run "$DATA/node-ipc/node-ipc-12.0.0.tgz" "$DATA/node-ipc/node-ipc-12.0.1.tgz"

printf '\n%bDone. Full evidence for any case: isomer fs <old> <new> (no sed).%b\n' "$DIM" "$R"
