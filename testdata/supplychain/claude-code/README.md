# Claude Code Cursor Marketplace compromise

The demo compares the original extension entrypoints without executing them:

| Side | Version | Artifact source |
| --- | --- | --- |
| `before/extension.js` | 2.1.312 | Unmodified `extension/extension.js` from the Open VSX darwin-arm64 VSIX published October 27, 2026. |
| `during/extension.js` | 2.1.313 | Actual compromised entrypoint recovered with Forager's PURL-plus-SHA-256 fallback through MalwareBazaar. |
| `after/extension.js` | 2.1.314 | Unmodified entrypoint from the Open VSX darwin-arm64 VSIX published October 30, 2026. |

The recovered malicious file is **exactly the complete 2.1.312 entrypoint with
a 7,386-byte loader prepended**. This is a byte comparison, not a reconstruction.
The loader plants an SSH key, enables SSH services, establishes a reverse SSH
tunnel, installs persistence, and reports host information. Only the Cursor
Marketplace distribution of 2.1.313 is established as affected by
[Cursor's notice](https://cursor.com/blog/claude-code-extension-security-notice).
The benign controls come from Open VSX; their origin is not evidence that Open
VSX distributed the compromised package.

`make demo` runs the attack comparison, the benign 2.1.312 → 2.1.314 upgrade,
and the 2.1.313 → 2.1.314 removal direction. The attack must reach the medium
gate; the two controls must remain below high. The shared `extension.js` path
keeps the comparison focused on the changed entrypoint. Original VSIXs include
more than 120 MiB each of platform tooling; they are retained locally under
ignored `downloads/`, while the entrypoints and package metadata are tracked.

## Provenance and recovery limits

[provenance.json](provenance.json) records artifact hashes, original archive
hashes, exact download URLs, publication times, and expected comparisons.
`before/registry.json` and `after/registry.json` preserve the registry responses.
Both original benign VSIX SHA-256s matched the checksums published by Open VSX.
`during/extension.js.forage.json` preserves Forager's recovery evidence.

The full compromised VSIX was not recovered. Both archive hashes from Cursor's
notice were absent from Forager's configured MalwareBazaar, Triage, and Malshare
sources. PURL recovery through Microsoft Marketplace, Open VSX, and Wayback, and
direct Cursor Marketplace downloads also failed. No VSIX was synthesized or
relabeled as an original package.

The successful recovery command was:

```sh
forager fetch -o recovered \
  --hash ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15 \
  'pkg:vscode-extension/Anthropic/claude-code@2.1.313'
```

The original benign archives can be fetched again from the `source_url` fields
in `provenance.json`; verify each against its recorded `original_vsix.sha256`
before extracting `extension/extension.js`.
