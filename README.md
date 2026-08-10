# isomer

**Supply-chain attack detection at a molecular level.**

> The version string says nothing changed; the behavior says otherwise.

NOTE: HIGHLY EXPERIMENTAL - EARLY BUILD - MAY EAT YOUR CAT

isomer detects whether a *change* is malicious — whether it was introduced by a
human, an AI, or the dependency supply chain. It is a differential analyzer: it
compares two states of the same thing (a directory, a git ref, a package, an
OCI image) and judges the delta in context — behavioral disassembly, software
classification, version drift, commit intent, and time/size deltas.

Powered by [Atomdrift Scan](https://github.com/atomdrift-project/scan) and a
differential ML model (**Valence**). Offline command-line tool with optional
LLM support. Designed for CI pipelines and local development.

Licensed Apache-2.0.

## Surface

```
isomer ci                                  # zero-config in CI: derives base..head from the environment
isomer fs   <old-path> <new-path>          # compare two trees; follows the dependency graph
isomer git  --repo <url> <old> <new>       # compare two commits/branches/tags of a remote repo   (planned)
isomer purl <purl@a> <purl@b>              # compare two published package versions               (planned)
isomer oci  <old-image> <new-image>        # compare two container images                         (planned)
```

`ci` and `fs` are implemented. Output formats: `terminal` (default), `json`,
`sarif`, `markdown`.

Argument order is always **old, then new** (like `diff`). `--base`/`--head`
named flags are accepted everywhere for order-proof CI invocations.

## Exit codes

| Code | Meaning |
|------|---------|
| 0    | clean — no findings at or above `--fail-on` |
| 1    | findings at or above `--fail-on` |
| 2    | operational error (never conflated with findings) |

## CI quickstart (GitHub Actions)

```yaml
permissions:
  contents: read
  pull-requests: write   # sticky PR comment
  security-events: write # SARIF annotations

steps:
  - uses: actions/checkout@v4
  - uses: atomdrift/isomer-action@v1
    with:
      fail-on: high
```

Findings are suppressed in a committed `.isomer.toml`, one reviewable line
each, with a mandatory reason:

```toml
[[allow]]
id = "objectives/command-and-control/*"
reason = "vendored socket.io client; reviewed in #482"
expires = "2026-11-09"   # optional
```

See [docs/DESIGN.md](docs/DESIGN.md) for the full design.
