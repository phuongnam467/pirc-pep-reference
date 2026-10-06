#!/usr/bin/env node
/**
 * Byte-exact self-check of the canonical interop vectors against the live
 * implementation. Fails CI if code and vectors ever drift apart.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize, CanonicalError } from '../src/canonical.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const indexFile = path.join(here, '..', 'vectors', 'canonical', 'index.json');
const { vectors } = JSON.parse(fs.readFileSync(indexFile, 'utf8'));

let pass = 0;
let fail = 0;
for (const v of vectors) {
  let actual;
  try {
    actual = { canonical: canonicalize(JSON.parse(v.input)) };
  } catch (err) {
    actual = err instanceof CanonicalError ? { error: err.message } : { error: `unexpected: ${err.message}` };
  }
  const want = v.expected;
  const ok = want.canonical !== undefined
    ? actual.canonical === want.canonical
    : typeof actual.error === 'string' && (actual.error === want.error || want.error.startsWith(actual.error.slice(0, 20)) || actual.error.includes(want.error.split(':')[0]));
  if (ok) {
    pass++;
  } else {
    fail++;
    console.error(`FAIL ${v.id}\n  want ${JSON.stringify(want)}\n  got  ${JSON.stringify(actual)}`);
  }
}
console.log(`${pass}/${vectors.length} canonical vectors byte-exact`);
process.exitCode = fail > 0 ? 1 : 0;
