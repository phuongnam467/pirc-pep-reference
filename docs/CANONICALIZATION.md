# PiProof Canonical Profile v1.1

**Status:** normative companion to [SPEC.md](../SPEC.md). This document does
not change the wire format for schema-valid envelopes; it makes an existing
design decision explicit and interoperable. **v1.1 (2026-08)** amends one rule —
key sorting happens on NFC *forms*, not raw keys — after the property-fuzzing
suite proved raw-sort breaks canonicalization idempotence. See §v1.1 amendment.

## The relationship in one sentence

PiProof uses a **protocol-specific canonicalization profile** that is *inspired
by* RFC 8785 (JCS) but is **not** a conforming JCS implementation, and must
never be described as one.

| Aspect | RFC 8785 JCS | PiProof Canonical Profile v1.1 |
|---|---|---|
| Numbers | IEEE-754 doubles, ECMAScript serialization | **non-negative safe integers only** (`0 … 2^53−1`); everything else is a hard error |
| Strings | Unicode characters, no normalization mandated beyond JSON | **NFC-normalized** before serialization |
| Object keys | sorted by UTF-16 code units of the raw key | sorted by UTF-16 code units of the **NFC form** of the key; serialization emits the NFC form |
| NFC key collisions | unspecified | **hard error** — two distinct raw keys folding to the same NFC key are rejected (`normalized key collision under NFC`) |
| Input model | assumes parsed JSON values | assumes parsed JSON values produced by a parser with **duplicate-key rejection or last-wins semantics documented by the platform** |

### Why each deviation exists

1. **Safe non-negative integers only.** PEP/1 fields (`weight`, `timestamp`,
   `version`, `created_at`) are conceptually integers. ECMAScript number
   serialization (the hardest part of implementing JCS correctly) exists to
   round-trip arbitrary doubles; the protocol never needs them. Deleting the
   problem deletes the entire JCS ES6-number algorithm — and every
   cross-language rounding hazard with it.
2. **NFC string normalization.** Evidence payloads carry human-origin strings
   (`action_id`, `subject`). Two byte-different but visually identical strings
   must produce one signature, not two.
3. **NFC-form sort, normalized-serialize (v1.1).** The emitted key text IS the
   sort key, so canonicalization is a fixed point: `canon(parse(c)) === c`
   for every canonical `c`. The v1.0 rule (sort raw keys, emit NFC forms)
   was deterministic per document but not idempotent — re-canonicalizing an
   already-canonical document could reorder keys whenever normalization
   changed a key's sort position, silently breaking `isCanonical()` on
   documents the protocol itself produced. Found by the property-fuzzing
   suite; see §v1.1 amendment below.
4. **Collision rejection.** `"e\u0301"` and `"\u00e9"` are different raw keys
   but one NFC key. Silent merging would let two distinct documents share one
   canonical form; the profile refuses instead of guessing.

## v1.1 amendment: why raw-sort had to go

Property tested by `scripts/fuzz.mjs` (canonical-property suite):

```
c = canon(parse(text))
canon(parse(c)) === c        // FAILED under v1.0 for some inputs
```

Failure mode: with raw-sort + NFC-serialize, normalization can move a key
across its neighbors' sort positions between the sort pass and the serialize
pass of the *next* canonicalization round. The result stayed deterministic —
same input always gave same output — but the transformation was no longer
idempotent, which `isCanonical()` (defined as fixed-point equality) requires.

Design choice frozen in v1.1:

- **Sort on the NFC form.** Emission order equals serialization text, so the
  second pass sees exactly what the first pass sorted. Idempotence holds by
  construction, in every language.
- Wire compatibility: schema-valid envelopes never contained NFC-unstable
  key pairs (the collision rule rejects them outright), so no previously
  signed payload changes meaning. Only synthetic documents mixing
  pre-composed and decomposed forms of *different* keys could reorder.

Two vectors pin the sort rule from both sides:

- **`canon-012` (orders coincide):** keys `U+212B` (ANGSTROM SIGN → NFC
  `U+00C5`) and `U+FB03` (FF LIGATURE). A subtle Unicode fact matters here:
  ligatures have *no canonical decomposition* — `NFC(U+FB03)` stays `U+FB03`
  (only compatibility normalization NFKC maps it to `"ffi"`). Both orders
  therefore agree: raw `212B < FB03` and NFC-form `00C5 < FB03` both emit
  Å-sign first. The vector documents this invariance so implementers do not
  "helpfully" apply compatibility normalization and break byte-exactness.
- **`canon-016` (the true v1.1 discriminator):** keys `U+00C7` (Ç) and
  `U+212B`. Raw order puts Ç first (`00C7 < 212B`); NFC forms put Å first
  (`00C5 < 00C7`). v1.1 emits `{"Å":2,"Ç":1}` — a raw-sort implementation
  emits the opposite and fails this vector. This is the pair class that made
  v1.0 non-idempotent.

## Interop vectors

`vectors/canonical/index.json` contains 16 vectors covering integer bounds,
rejections (negative/float/exponent/unsafe), NFC equivalence, astral
characters, minimal escaping, key ordering (both coincidence and flip cases
above), NFC collisions, nesting and empty containers.

Each vector provides the **raw JSON text** as input; an implementation must
parse it, canonicalize it, and either reproduce `expected.canonical`
byte-for-byte (UTF-8) or reject with an error for `expected.error` cases.

Two independent implementations already agree on all vectors:

- Node (`src/canonical.js`) — checked by `npm run gen:canonical`;
- Python stdlib (`scripts/cross-canonical.py`) — checked in CI across
  Python 3.10/3.12 on Linux and Windows.

Adding a third-language implementation is deliberately boring: implement the
table above, run the vectors, match all 16.

## Implementation requirements (normative)

An implementation is *PiProof Canonical Profile v1.1 conformant* if and only if:

1. it rejects any parsed number outside `[0, 2^53−1]` ∪ ℤ;
2. it NFC-normalizes every string value and every object key before output;
3. it emits object keys sorted by the UTF-16 code-unit order of the keys'
   **NFC forms**;
4. it rejects documents where two raw keys NFC-fold to the same key;
5. it reproduces every vector in `vectors/canonical/index.json` exactly;
6. it satisfies the fixed-point property: `canon(parse(canon(parse(t)))) ===
   canon(parse(t))` for every accepted input `t`;
7. it describes itself as "PiProof Canonical Profile v1.1", never as "JCS".
