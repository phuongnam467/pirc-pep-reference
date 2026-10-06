#!/usr/bin/env node
/**
 * Generates the PiProof Canonical Profile interop vectors.
 *
 * These vectors pin down the EXACT behavior of the protocol-specific
 * canonicalization used by PEP/1 (see docs/CANONICALIZATION.md). They are
 * deliberately NOT RFC 8785 JCS vectors: this profile restricts numbers to
 * non-negative safe integers, NFC-normalizes strings, sorts on the NFC FORMS
 * of keys (Profile v1.1) and rejects NFC key collisions. Any independent
 * implementation that reproduces every vector byte-for-byte is interoperable
 * with this codebase.
 *
 * Regenerate with: npm run gen:canonical
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize, CanonicalError } from '../src/canonical.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const outDir = path.join(here, '..', 'vectors', 'canonical');

const CASES = [
  {
    id: 'canon-001-int-zero',
    description: 'zero is a legal non-negative safe integer',
    input: '{"z":0}'
  },
  {
    id: 'canon-002-safe-int-max',
    description: 'Number.MAX_SAFE_INTEGER (2^53-1) is representable exactly',
    input: '{"n":9007199254740991}'
  },
  {
    id: 'canon-003-unsafe-int',
    description: '2^53 exceeds the safe-integer bound — rejected',
    input: '{"n":9007199254740992}'
  },
  {
    id: 'canon-004-negative-int',
    description: 'negative integers are outside the profile — rejected',
    input: '{"n":-1}'
  },
  {
    id: 'canon-005-float',
    description: 'fractional values are outside the profile — rejected',
    input: '{"n":1.5}'
  },
  {
    id: 'canon-006-exponent-form',
    description: 'exponent notation parses to a non-safe-integer double — rejected',
    input: '{"n":1e21}'
  },
  {
    id: 'canon-007-nfc-string-equivalence',
    description: 'decomposed accents normalize to composed NFC form',
    input: '{"word":"re\\u0301sume\\u0301"}'
  },
  {
    id: 'canon-008-astral-plane',
    description: 'astral-plane characters survive as proper surrogate pairs',
    input: '{"emoji":"\\ud83d\\ude00"}'
  },
  {
    id: 'canon-009-control-char-escape',
    description: 'control characters are minimally escaped as \\uXXXX',
    input: '{"c":"a\\u0001b"}'
  },
  {
    id: 'canon-010-quote-backslash-escape',
    description: 'quote and backslash follow standard JSON escaping',
    input: '{"q":"say \\"hi\\" \\\\"}'
  },
  {
    id: 'canon-011-key-order-basic',
    description: 'object keys are emitted in ascending order',
    input: '{"b":2,"a":1,"c":3}'
  },
  {
    id: 'canon-012-ligature-nfc-invariance',
    description: 'NFC leaves the FF ligature U+FB03 intact (ligatures have no canonical decomposition, only compatibility): ANGSTROM SIGN U+212B normalizes to U+00C5 and both sort orders coincide, so raw-sort and NFC-form-sort agree here',
    input: '{"\\u212b":1,"\\ufb03":2}'
  },
  {
    id: 'canon-013-nfc-key-collision-rejected',
    description: 'two distinct raw keys that NFC-fold to the same key are a hard error, never a silent merge',
    input: '{"e\\u0301":1,"\\u00e9":2}'
  },
  {
    id: 'canon-014-nested-mixed',
    description: 'nested containers mix all legal value kinds deterministically',
    input: '{"arr":[{"k":false},{"k":true},null],"s":"x","top":{"deep":{"i":42}}}'
  },
  {
    id: 'canon-015-empty-containers',
    description: 'empty array and object serialize compactly',
    input: '{"a":[],"o":{}}'
  },
  {
    id: 'canon-016-nfc-sort-flip',
    description: 'Profile v1.1 discriminator: C-CEDILLA U+00C7 sorts before ANGSTROM SIGN U+212B raw, but NFC(U+212B)=U+00C5 sorts before NFC(U+00C7)=U+00C7 — so the emitted order flips versus raw-key sorting, and canon(parse(canon(x))) stays a fixed point',
    input: '{"\\u00c7":1,"\\u212b":2}'
  }
];

const vectors = [];
for (const c of CASES) {
  const entry = { id: c.id, description: c.description, profile: 'piproof-canonical-v1', input: c.input };
  let parsed;
  try {
    parsed = JSON.parse(c.input);
  } catch (err) {
    throw new Error(`vector ${c.id}: input must be valid JSON text: ${err.message}`);
  }
  try {
    entry.expected = { canonical: canonicalize(parsed) };
  } catch (err) {
    if (!(err instanceof CanonicalError)) throw err;
    entry.expected = { error: err.message };
  }
  vectors.push(entry);
}

fs.mkdirSync(outDir, { recursive: true });
const outFile = path.join(outDir, 'index.json');
fs.writeFileSync(outFile, JSON.stringify({
  profile: 'piproof-canonical-v1',
  spec: 'docs/CANONICALIZATION.md',
  note: 'input is RAW JSON text; implementations must parse then canonicalize. expected.error = substring of the rejection reason.',
  vectors
}, null, 2) + '\n', 'utf8');
console.log(`wrote ${vectors.length} canonical interop vectors to ${path.relative(process.cwd(), outFile)}`);
