#!/bin/sh
# Pack a before/during pair from the supply-chain corpus into the two
# `.tar.xz` archives isomer's testdata expects. Each side is wrapped under a
# STABLE inner path (`pkg/<name>`) so cleave pairs the members as *changed*
# (a content diff), never as add+remove — a bare `foo.php.xz` gives the member
# an unstable name and cleave then reads the whole file as new, manufacturing
# a false "everything gained" verdict.
#
# Usage: scripts/pack-corpus-sample.sh <out-dir> <case> <inner-name> <before-file> <during-file>
#   out-dir     testdata/supplychain/<case>
#   case        archive basename both sides share (drives isomer's display name)
#   inner-name  the member path both sides share, e.g. addthis_social_widget.php
#
# Emits <out>/before/<case>.tar.xz and <out>/during/<case>.tar.xz. Both sides
# share the archive name and inner path, so `isomer fs` reads one artifact
# changing (a clean `<case>` header) rather than two unrelated files.
set -eu

OUT="$1"; CASE="$2"; INNER="$3"; BEFORE="$4"; DURING="$5"

pack() { # <src> <side>
    mkdir -p "$OUT/$2"
    tmp="$(mktemp -d)"
    mkdir -p "$tmp/pkg"
    cp "$1" "$tmp/pkg/$INNER"
    # Fixed owner metadata keeps the archive byte-stable across re-runs.
    ( cd "$tmp" && tar --uid 0 --gid 0 --numeric-owner -cf - pkg ) \
        | xz -9 > "$OUT/$2/$CASE.tar.xz"
    rm -rf "$tmp"
}

pack "$BEFORE" before
pack "$DURING" during
printf 'packed %s (%s)\n' "$OUT" "$(du -h "$OUT/before/$CASE.tar.xz" "$OUT/during/$CASE.tar.xz" | awk '{print $1}' | paste -sd/ -)"
