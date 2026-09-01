#!/bin/sh
# isomer demo — the curated real-world supply-chain attacks, each shipped as an
# old → new pair under testdata/supplychain. Read-only: isomer never executes a
# sample. Output is exactly the command run and isomer's verdict, nothing else.
#
# Doubles as a smoke test, in both directions:
#
#   run    an attack must register at least NOTABLE (`--fail-on medium`)
#   clean  a legitimate upgrade of the same package must stay under HIGH
#          (`--fail-on high`, the bar `make validate-samples` audits on)
#
# The demo exits non-zero — and `make demo` fails — if any attack slips under
# its bar or any clean upgrade trips one. Both gates are deterministic, so the
# LLM read below never changes the pass/fail; it only enriches the verdict.
#
# The demo runs fully offline by default. Pass LLM_URL=… to point isomer at an
# OpenAI-compatible endpoint and add the model's read (the ✨ line in each
# verdict); the deterministic pass/fail is unaffected either way.
#
# Usage: scripts/demo.sh [path-to-isomer-binary]   (default: cargo run -q --)
set -eu

ISOMER="${1:-cargo run -q --}"
D="testdata/supplychain"
O="openapi-react-query-codegen"   # the one case name too long to inline twice
DIV="────────────────────────────────────────────────────────────────────────────────"

LLM_URL="${LLM_URL-}"
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

clean() { # clean <old> <new> — two honest releases of the same package
    printf '%s\n$ isomer fs %s %s\n%s\n' "$DIV" "$1" "$2" "$DIV"
    # Exit 1 at --fail-on high means a legitimate upgrade failed the gate — the
    # false positive that costs a scanner its credibility.
    if ! $ISOMER $NET --color always --fail-on high fs "$1" "$2"; then
        printf 'FALSE POSITIVE — clean upgrade tripped --fail-on high (demo failure)\n'
        failures=$((failures + 1))
    fi
    printf '\n\n'
}

run "$D/xz-utils/liblzma.so.5.4.5"              "$D/xz-utils/liblzma.so.5.6.0"
run "$D/rand-user-agent/clean/index.js"         "$D/rand-user-agent/compromised/index.js"
run "$D/node-ipc/node-ipc-12.0.0.tgz"           "$D/node-ipc/node-ipc-12.0.1.tgz"
run "$D/unrealircd/before/Unreal3.2.8.1.tar.xz" "$D/unrealircd/during/Unreal3.2.8.1_backdoor.tar.xz"
run "$D/$O/before/openapi-react-query-codegen-3.0.2.tgz"     "$D/$O/during/openapi-react-query-codegen-3.0.3.tgz"

# The counter-example, and the sharper half of this case: the same package's own
# cross-major upgrade, 2.2.0 -> 3.0.2, is a large honest diff — dist/ goes from
# 17 files to 41, the emitter is restructured into a new dist/tsmorph/ tree,
# .d.mts declarations appear throughout, and peerDependencies gains
# @tanstack/react-query — and none of it may read as an attack. Same package,
# same publisher, same packaging as the pair above, no payload: exactly the
# upgrade a false positive here would block.
clean "$D/$O/before/openapi-react-query-codegen-2.2.0.tgz"   "$D/$O/before/openapi-react-query-codegen-3.0.2.tgz"

exit "$failures"
