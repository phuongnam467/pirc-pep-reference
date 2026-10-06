#!/usr/bin/env python3
"""
Independent cross-language verification of the PiProof Canonical Profile.

This is a from-scratch Python implementation of docs/CANONICALIZATION.md —
it shares NO code with the Node implementation and exists purely to prove
the interop vectors in vectors/canonical/index.json are language-neutral.
Byte-exact agreement on every vector is the pass condition.

Usage:  python scripts/cross-canonical.py
"""
import json
import sys
import unicodedata
from pathlib import Path

MAX_SAFE_INT = 2**53 - 1
MAX_DEPTH = 64


class CanonicalProfileError(ValueError):
    """Rejection inside the profile — mirrors Node's CanonicalError."""


def _reject_float(text):
    raise CanonicalProfileError(f"non-canonical number: {text}")


def _load(raw_text):
    return json.loads(raw_text, parse_float=_reject_float)


def _js_string(s):
    # Matches JavaScript JSON.stringify escaping for this profile's inputs:
    # minimal escaping, control chars as \uXXXX, non-ASCII kept literal.
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == '\\':
            out.append('\\\\')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\r':
            out.append('\\r')
        elif ch == '\t':
            out.append('\\t')
        elif ch == '\b':
            out.append('\\b')
        elif ch == '\f':
            out.append('\\f')
        elif o < 0x20:
            out.append(f'\\u{o:04x}')
        else:
            out.append(ch)
    out.append('"')
    return ''.join(out)


def _utf16_key(s):
    # JavaScript sorts object keys by UTF-16 code units; comparing big-endian
    # UTF-16 byte strings reproduces that order exactly (incl. astral chars).
    return s.encode('utf-16-be')


def canonicalize(value, depth=0):
    if depth > MAX_DEPTH:
        raise CanonicalProfileError(f"canonicalization depth exceeded {MAX_DEPTH}")
    if value is None:
        return 'null'
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, int):
        if value < 0 or value > MAX_SAFE_INT:
            raise CanonicalProfileError(f"non-canonical number: {value}")
        return str(value)
    if isinstance(value, str):
        return _js_string(unicodedata.normalize('NFC', value))
    if isinstance(value, list):
        return '[' + ','.join(canonicalize(v, depth + 1) for v in value) + ']'
    if isinstance(value, dict):
        seen = set()
        for raw in value.keys():
            norm = unicodedata.normalize('NFC', raw)
            if norm in seen:
                raise CanonicalProfileError(f"normalized key collision under NFC: {json.dumps(raw)}")
            seen.add(norm)
        # Profile v1.1 (since piproof v0.15): sort the NFC FORMS, not the raw
        # keys — canon(parse(canon(x))) must be a fixed point. Mirrors
        # sdk/python/piproof_sdk.py and src/canonical.js.
        parts = []
        for raw in sorted(value.keys(), key=lambda k: _utf16_key(unicodedata.normalize('NFC', k))):
            parts.append(_js_string(unicodedata.normalize('NFC', raw)) + ':' + canonicalize(value[raw], depth + 1))
        return '{' + ','.join(parts) + '}'
    raise CanonicalProfileError(f"unsupported type: {type(value).__name__}")


def main() -> int:
    index = Path(__file__).resolve().parent.parent / 'vectors' / 'canonical' / 'index.json'
    data = json.loads(index.read_text(encoding='utf-8'))
    passed = failed = 0
    for vec in data['vectors']:
        try:
            actual = {'canonical': canonicalize(_load(vec['input']))}
        except CanonicalProfileError as err:
            actual = {'error': str(err)}
        want = vec['expected']
        if 'canonical' in want:
            ok = actual.get('canonical') == want['canonical']
        else:
            ok = 'error' in actual  # any profile rejection satisfies an error vector
        if ok:
            passed += 1
        else:
            failed += 1
            print(f"FAIL {vec['id']}\n  want {want!r}\n  got  {actual!r}")
    total = len(data['vectors'])
    print(f"[cross-canonical.py] {passed}/{total} vectors agree byte-for-byte")
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
