#!/usr/bin/env python3
"""Reject local trait-ID literals in production Rust (no legacy allowlist).

This is a source lint, not dataflow analysis: deliberately constructing an ID
from fragments can evade it. Keep scoring predicates hierarchy-based in review.
Test-only modules may contain concrete IDs as input fixtures.
"""

import argparse
from dataclasses import dataclass
from pathlib import Path
import re

RAW_STRING = re.compile(r'(?:br|cr|r)(#*)"')
STRING = re.compile(r'(?:b|c)?"')
CHAR = re.compile(r"(?:b)?'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|.)|[^'\\\n])'")
IDENT = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")


@dataclass
class Token:
    value: str
    line: int
    literal: bool = False


def tokens(source):
    """Lex strings separately from comments, Rust paths, and punctuation."""
    i = 0
    line = 1
    result = []
    while i < len(source):
        start = i
        literal = False
        if source.startswith("//", i):
            end = source.find("\n", i)
            i = len(source) if end < 0 else end
        elif source.startswith("/*", i):
            depth = 1
            i += 2
            while i < len(source) and depth:
                if source.startswith("/*", i):
                    depth += 1
                    i += 2
                elif source.startswith("*/", i):
                    depth -= 1
                    i += 2
                else:
                    i += 1
        elif match := RAW_STRING.match(source, i):
            terminator = '"' + match[1]
            end = source.find(terminator, match.end())
            if end < 0:
                raise ValueError(f"line {line}: unterminated raw string")
            value = source[match.end():end]
            i = end + len(terminator)
            literal = True
        elif match := STRING.match(source, i):
            i = match.end()
            begin = i
            while i < len(source) and source[i] != '"':
                i += 2 if source[i] == "\\" else 1
            if i >= len(source):
                raise ValueError(f"line {line}: unterminated string")
            value = source[begin:i]
            # Decode Rust escapes which could conceal the ID separator.
            value = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m[1], 16)), value)
            value = re.sub(r"\\u\{([0-9a-fA-F_]+)\}",
                           lambda m: chr(int(m[1].replace('_', ''), 16)), value)
            value = re.sub(r"\\\n\s*", "", value)
            i += 1
            literal = True
        elif match := CHAR.match(source, i):
            i = match.end()  # Character literals aren't block delimiters.
        elif source[i].isspace():
            i += 1
        else:
            match = IDENT.match(source, i)
            i = match.end() if match else i + 1
            result.append(Token(source[start:i], line))
        if literal:
            result.append(Token(value, line, True))
        line += source[start:i].count("\n")
    return result


def production_tokens(source):
    """Skip only explicitly cfg(test) items, not the rest of their file."""
    stream = tokens(source)
    output = []
    external_tests = []
    i = 0
    while i < len(stream):
        if [t.value for t in stream[i:i + 7]] == ['#', '[', 'cfg', '(', 'test', ')', ']']:
            i += 7
            # The usual forms are test modules and test-only helper functions.
            header = []
            while i < len(stream) and stream[i].value not in ('{', ';'):
                header.append(stream[i].value)
                i += 1
            if i < len(stream) and stream[i].value == ';':
                if 'mod' in header:
                    external_tests.append(header[header.index('mod') + 1])
                i += 1
            else:
                depth = 1
                i += 1
                while i < len(stream) and depth:
                    if not stream[i].literal:
                        depth += (stream[i].value == '{') - (stream[i].value == '}')
                    i += 1
        else:
            output.append(stream[i])
            i += 1
    return output, external_tests


def violations(source):
    stream, _ = production_tokens(source)
    errors = []
    for i, token in enumerate(stream):
        local_predicate = token.value in ('contains', 'ends_with') or (
            token.value == 'eq' and i + 2 < len(stream) and stream[i + 2].literal)
        if ([t.value for t in stream[max(0, i - 2):i]] == ['id', '.']
                and local_predicate and not token.literal):
            errors.append((token.line, "local trait-ID predicate; match a hierarchy instead", token.value))
        if not token.literal:
            continue
        value = token.value
        # Bare ::suffix is just as unstable as hierarchy::suffix. Rust paths
        # outside literals were separated by the lexer; delimiter-only "::"
        # and hierarchy prefixes ending in :: remain valid.
        if (re.search(r"[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)+::[a-zA-Z0-9_-]", value)
                or re.fullmatch(r"::[a-zA-Z0-9_-]+", value)):
            errors.append((token.line, "local trait-ID literal", value))
            continue
    return errors


def check_tree(root):
    sources = {path: path.read_text() for path in sorted((root / 'src').rglob('*.rs'))}
    excluded = set()
    for path, source in sources.items():
        _, modules = production_tokens(source)
        module_dir = path.parent if path.name in ('main.rs', 'lib.rs', 'mod.rs') else path.with_suffix('')
        for module in modules:
            excluded.add(module_dir / (module + '.rs'))
            directory = module_dir / module
            excluded.update(directory.rglob('*.rs'))
    return [(path, line, reason, value)
            for path, source in sources.items() if path not in excluded
            for line, reason, value in violations(source)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    errors = check_tree(args.root)
    for path, line, reason, value in errors:
        print(f'{path}:{line}: {reason}: {value!r}')
    if errors:
        print(f'{len(errors)} violation(s): local trait IDs are not stable; use hierarchy boundaries.')
    return bool(errors)


if __name__ == '__main__':
    raise SystemExit(main())
