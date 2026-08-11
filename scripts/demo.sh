#!/bin/sh
# isomer demo — the curated real-world supply-chain attacks, each shipped as an
# old → new pair under testdata/supplychain. Read-only: isomer never executes a
# sample. Output is exactly the command run and isomer's verdict, nothing else.
#
# Doubles as a smoke test: every case must register at least NOTABLE
# (`--fail-on medium`). The demo exits non-zero — and `make demo` fails — if any
# attack slips under that bar. The gate is deterministic, so the LLM read below
# never changes the pass/fail; it only enriches the verdict.
#
# The model's read is on by default (the ✨ line in each verdict). Point it
# elsewhere with LLM_URL=…; disable it — and go fully hermetic, no network — with
# LLM_URL="".
#
# Usage: scripts/demo.sh [path-to-isomer-binary]   (default: cargo run -q --)
set -eu

ISOMER="${1:-cargo run -q --}"
D="testdata/supplychain"
DIV="────────────────────────────────────────────────────────────────────────────────"

LLM_URL="${LLM_URL-http://10.9.8.149:8000/v1}"
if [ -n "$LLM_URL" ]; then
    ISOMER_LLM="$LLM_URL"
    export ISOMER_LLM
    NET=""
else
    NET="--offline"
fi

failures=0

run() { # run <old> <new>
    printf '%s\n$ isomer fs %s %s\n%s\n' "$DIV" "$1" "$2" "$DIV"
    if $ISOMER $NET --color always --fail-on medium fs "$1" "$2"; then
        # Exit 0 at --fail-on medium means nothing reached notable — a miss.
        printf 'NOT DETECTED — below notable (demo failure)\n'
        failures=$((failures + 1))
    fi
    printf '\n\n'
}

run "$D/xz-utils/liblzma.so.5.4.5"              "$D/xz-utils/liblzma.so.5.6.0"
run "$D/rand-user-agent/clean/index.js"         "$D/rand-user-agent/compromised/index.js"
run "$D/node-ipc/node-ipc-12.0.0.tgz"           "$D/node-ipc/node-ipc-12.0.1.tgz"
run "$D/unrealircd/before/Unreal3.2.8.1.tar.xz" "$D/unrealircd/during/Unreal3.2.8.1_backdoor.tar.xz"

exit "$failures"
