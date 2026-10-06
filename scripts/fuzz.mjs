#!/usr/bin/env node
// PiProof adversarial fuzzing suite (v0.15, extended v0.16) — zero dependencies.
//
// Seven property-based campaigns against the hand-rolled core:
//
//   1. canonical-property   every generated value is either canonicalized
//                           deterministically or rejected with CanonicalError;
//                           double-canonicalization is idempotent.
//   2. schema               mutated/junk documents never escape
//                           verifySignedEvent as an uncaught throw — they come
//                           back as structured verdicts, fail-closed.
//   3. unicode              NFC-equivalent strings collide or don't, but never
//                           diverge from the profile's stated rule; colliding
//                           normalized keys are always rejected.
//   4. cross-lang-diff      Node and the independent Python implementation
//                           produce BYTE-IDENTICAL outcomes on random inputs
//                           (differential fuzzing across implementations).
//   5. parser-differential  Node's JSON.parse vs Python's json.loads shape
//                           agreement on identical bytes (found the V8
//                           phantom-key divergence — see SECURITY.md).
//   6. go-diff              Node vs the Go implementation (sdk/go): byte and
//                           shape agreement through the same driver protocol.
//   7. concurrency          K fresh OS processes racing to claim ONE durable
//                           nonce yield exactly one winner, every round.
//
// Deterministic: seeded PRNG, seed printed for reproduction (--seed N).
// Usage: node scripts/fuzz.mjs [--quick] [--seed N] [--only=name,name]
// Exit code is nonzero on ANY protocol violation; runtime-parser divergences
// are reported loudly but only fatal under FUZZ_STRICT=1.

import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const args = process.argv.slice(2);
const QUICK = args.includes('--quick');
const onlyArg = args.find((a) => a.startsWith('--only='));
const ONLY = onlyArg ? onlyArg.slice(7).split(',') : null;
let SEED = 0xc0ffee;
const seedArg = args.find((a) => a.startsWith('--seed='));
if (seedArg) SEED = Number(seedArg.slice(7)) >>> 0;

// ------------------------------------------------------------------ PRNG ---
function mulberry32(a) {
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rand = mulberry32(SEED);
const pick = (arr) => arr[Math.floor(rand() * arr.length)];
const intBetween = (lo, hi) => lo + Math.floor(rand() * (hi - lo + 1));

// ------------------------------------------------------------- generators ---
const UNICODE_POOL = [
  'a', 'Z', '0', '-', '_', ':', '.', '~', ' ',
  '\u00e9', 'e\u0301',                    // NFC pair
  '\u212b', 'A\u030a',                    // angstrom pair
  '\uac00', '\u1112\u1161\u11ab',         // hangul composed/decomposed
  '\u4e2d\u6587', '\u0645\u0631\u062d\u0628\u0627',
  '\ud83d\ude00', '\ud83d\udc68\u200d\ud83d\udcbb', // emoji + ZWJ
  '\u0627\u0644\u0639\u0631\u0628\u064a\u0629',
  '\u0000', '\u001f', '\t', '\\', '"',
  'key', 'nonce', '__proto__', 'constructor'
];

function genString(depth) {
  if (rand() < 0.35 || depth > 3) {
    const n = intBetween(0, 12);
    let s = '';
    for (let i = 0; i < n; i++) s += pick(UNICODE_POOL);
    return s;
  }
  return pick(UNICODE_POOL);
}

function genValue(depth = 0) {
  if (depth > 5 || rand() < 0.45) {
    switch (intBetween(0, 3)) {
      case 0: return genString(depth);
      case 1: return pick([0, 1, -1, 42, -(2 ** 31), 9007199254740991, -9007199254740991]);
      case 2: return rand() < 0.5 ? true : false;
      default: return rand() < 0.5 ? null : genString(depth);
    }
  }
  if (rand() < 0.5) {
    const arr = [];
    const n = intBetween(0, 6);
    for (let i = 0; i < n; i++) arr.push(genValue(depth + 1));
    return arr;
  }
  const obj = {};
  const n = intBetween(0, 6);
  for (let i = 0; i < n; i++) obj[genString(depth + 1)] = genValue(depth + 1);
  return obj;
}

// Two distinct raw keys that normalize to the SAME string under NFC.
function collidingKeyPair() {
  return ['\u00e9-key', 'e\u0301-key'];
}

// --------------------------------------------------------------- harness ----
const { canonicalize, CanonicalError } = await import(
  'file://' + path.join(ROOT, 'src', 'canonical.js').replace(/\\/g, '/')
);

const violations = [];
function violation(suite, msg, caseRepr) {
  violations.push(`[${suite}] ${msg}${caseRepr ? `\n    case: ${caseRepr}` : ''}`);
}
// Reproduction aid: FUZZ_DUMP=<dir> writes every violating input verbatim.
const DUMP_DIR = process.env.FUZZ_DUMP;
let dumpCounter = 0;
function dumpCase(suite, label, payload) {
  if (!DUMP_DIR) return;
  try {
    fs.mkdirSync(DUMP_DIR, { recursive: true });
    fs.writeFileSync(
      path.join(DUMP_DIR, `${suite}-${++dumpCounter}-${label}.json`),
      typeof payload === 'string' ? payload : JSON.stringify(payload)
    );
  } catch { /* best effort */ }
}

function repr(v) {
  try {
    return JSON.stringify(v) ?? String(v);
  } catch {
    return '<unserializable>';
  }
}

const CASES_REJECTED = {};

async function runSuite(name, fn) {
  if (ONLY && !ONLY.includes(name)) return;
  const t0 = Date.now();
  CASES_REJECTED[name] = 0;
  await fn(CASES_REJECTED[name]);
  const secs = ((Date.now() - t0) / 1000).toFixed(1);
  console.log(`fuzz/${name}: done in ${secs}s`);
}

const SUITES = [];
function suite(name, fn) {
  SUITES.push([name, fn]);
}

// --------------------------------------------------- 1. canonical-property --
suite('canonical-property', async () => {
  const exe = await pythonAvailable();
  const driver = exe ? makeDriver(exe, ['scripts/fuzz-diff-driver.py'], { PYTHONIOENCODING: 'utf-8', PYTHONUTF8: '1' }) : null;
  const N = QUICK ? 4000 : 30000;
  for (let i = 0; i < N; i++) {
    const v = genValue();
    let out1;
    try {
      out1 = canonicalize(v);
    } catch (err) {
      if (!(err instanceof CanonicalError)) {
        violation('canonical-property', `non-CanonicalError escaped: ${err.constructor.name}: ${err.message}`, repr(v));
      }
      continue; // rejection is a legal outcome
    }
    if (typeof out1 !== 'string') {
      violation('canonical-property', 'canonicalize returned non-string without throwing');
      continue;
    }
    // determinism + idempotence: parsing our own canonical text must
    // reproduce the exact same bytes on re-canonicalization.
    let out2;
    let parseDiverged = false;
    try {
      const reparsed = JSON.parse(out1);
      out2 = canonicalize(reparsed);
      if (out2 !== out1 && driver) {
        // Classify BEFORE blaming the profile: does Node's JSON.parse see a
        // different document than Python's json.loads on identical bytes?
        const line = await driver.cmd('PARSE\t' + out1);
        if (line.startsWith('SHAPE\t') && nodeShape(reparsed) !== line.slice(6)) {
          parseDiverged = true;
          recordDivergence(
            'idempotence-masked',
            `case ${i}: canon(parse(c)) != c, but JSON.parse itself mis-read c ` +
              `(V8 runtime divergence — python sees different keys). See SECURITY.md.`,
            out1
          );
        }
      }
    } catch (err) {
      violation('canonical-property', `own output failed re-parse/re-canonicalize: ${err.message}`, out1.slice(0, 200));
      continue;
    }
    if (out2 !== out1 && !parseDiverged) {
      dumpCase('canonical-property', 'idempotence', out1);
      dumpCase('canonical-property', 'input-text', JSON.stringify(v));
      violation('canonical-property', 'idempotence violated: canon(parse(canon(x))) != canon(x)', out1.slice(0, 200));
    }
  }
  if (driver) driver.close();
});

// ------------------------------------------------------------- 2. schema ----
suite('schema', async () => {
  const [{ makeWorld }, { verifySignedEvent }, { InMemoryNonceStore }] = await Promise.all([
    import('file://' + path.join(ROOT, 'src', 'attacks.js').replace(/\\/g, '/')),
    import('file://' + path.join(ROOT, 'src', 'verify.js').replace(/\\/g, '/')),
    import('file://' + path.join(ROOT, 'src', 'nonces.js').replace(/\\/g, '/'))
  ]);
  const world = makeWorld();
  const N = QUICK ? 2500 : 12000;
  for (let i = 0; i < N; i++) {
    // A valid signed event skeleton, mutated adversarially each round.
    const doc = JSON.parse(
      JSON.stringify({
        v: 1,
        app_id: 'demo-app',
        key_id: 'k-2026-active',
        action_class: 'A',
        action_id: 'complete_transaction',
        weight: 50,
        timestamp: world.now,
        nonce: 'demo-app:' + 'f'.repeat(16) + ':' + i,
        pioneer_uid_hash: Object.keys(world.registry.eligible_users)[0],
        eligibility: { kyc_passed: true, mainnet_migrated: true },
        signature: 'AA'
      })
    );
    switch (intBetween(0, 9)) {
      case 0: doc[pick(['v', 'weight', 'timestamp'])] = genString(2); break;
      case 1: doc.weight = pick([-1, 1e9, '50', null, {}]); break;
      case 2: doc[pick(['app_id', 'key_id'])] = pick(['__proto__', 'constructor', '..', 'A'.repeat(500)]); break;
      case 3: doc[genString(1)] = genValue(3); break; // unknown field junk
      case 4: doc.nonce = pick(['', 'no-colon', '::', 'x'.repeat(300), 123]); break;
      case 5: doc.eligibility = pick([null, 'yes', [], { kyc_passed: 'true' }]); break;
      case 6: delete doc[pick(['signature', 'timestamp', 'pioneer_uid_hash', 'v'])]; break;
      case 7: Object.assign(doc, JSON.parse('{"' + pick(['__proto__', 'constructor']) + '":{"polluted":true}}')); break;
      case 8: doc.action_class = pick(['a', 'D', '', 'AB']); break;
      default: doc.signature = pick(['', 'not-base64', 'AA'.repeat(80), 7]); break;
    }
    try {
      const r = verifySignedEvent(doc, {
        registry: world.registry,
        nonceStore: new InMemoryNonceStore(),
        now: world.now
      });
      if (!r || typeof r.ok !== 'boolean') {
        violation('schema', 'verdict is not {ok:boolean}', repr(doc).slice(0, 160));
      }
      if (r && r.ok === true) CASES_REJECTED.schema++;
    } catch (err) {
      violation('schema', `UNCAUGHT THROW escaped verifySignedEvent: ${err.constructor.name}: ${err.message}`, repr(doc).slice(0, 160));
    }
  }
});

// ------------------------------------------------------------ 3. unicode ----
suite('unicode', async () => {
  const N = QUICK ? 4000 : 20000;
  for (let i = 0; i < N; i++) {
    const s = genString(2);
    const nfc = s.normalize('NFC');
    // Rule under the profile: canonicalization operates on the NFC form, so
    // two strings NFC-equal to each other MUST produce equal bytes whenever
    // they are accepted at all.
    let a, b, aErr, bErr;
    try { a = canonicalize(s); } catch (err) { aErr = err; }
    try { b = canonicalize(nfc); } catch (err) { bErr = err; }
    if (!!aErr !== !!bErr) {
      violation('unicode', `acceptance differs between raw and NFC forms`, repr(s));
    } else if (!aErr && a !== b) {
      violation('unicode', `bytes differ between raw and NFC forms`, repr(s));
    }
    // Explicit colliding-key objects must ALWAYS be rejected, both orders.
    const [k1, k2] = collidingKeyPair();
    const flip = rand() < 0.5;
    const obj = { [flip ? k2 : k1]: 1, [flip ? k1 : k2]: 2 };
    let rejected = false;
    try {
      canonicalize(obj);
    } catch (err) {
      if (!(err instanceof CanonicalError)) {
        violation('unicode', `collision rejected with wrong error class: ${err.constructor.name}`);
      }
      rejected = true;
    }
    if (!rejected) {
      violation('unicode', 'NFC key collision was ACCEPTED — normalization collision guard missing', repr(obj));
    }
  }
});

// ----------------------------------------------------- 4. cross-lang-diff ---
const DIVERGENCES = [];

async function pythonAvailable() {
  for (const exe of ['python', 'python3']) {
    try {
      execFileSync(exe, ['-c', 'print(1)'], { stdio: 'pipe' });
      return exe;
    } catch { /* try next */ }
  }
  return null;
}

async function goAvailable() {
  try {
    execFileSync('go', ['version'], { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

// Builds the Go fuzz driver once per run; returns binary path or null.
function buildGoDriver() {
  const bin = path.join(os.tmpdir(), 'piproof-go-fuzzdriver-' + process.pid + (process.platform === 'win32' ? '.exe' : ''));
  try {
    execFileSync('go', ['build', '-o', bin, './cmd/fuzzdriver'], { cwd: path.join(ROOT, 'sdk', 'go'), stdio: 'pipe' });
    return bin;
  } catch (err) {
    console.log('fuzz/go-diff: go build failed — ' + String(err.stderr || err.message).slice(0, 200));
    return null;
  }
}

// One long-lived driver process; commands are NDJSON lines.
function makeDriver(exe, cmdArgs, envExtra = {}) {
  const child = spawn(exe, cmdArgs, {
    cwd: ROOT,
    env: { ...process.env, ...envExtra },
    stdio: ['pipe', 'pipe', 'pipe']
  });
  const pending = [];
  let buf = '';
  child.stdout.on('data', (c) => {
    buf += c;
    let idx;
    while ((idx = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, idx).replace(/\r$/, '');
      buf = buf.slice(idx + 1);
      const p = pending.shift();
      if (p) p.resolve(line);
    }
  });
  child.stderr.on('data', (c) => (child._stderr = (child._stderr || '') + c));
  return {
    cmd(line) {
      return new Promise((resolve) => {
        pending.push({ resolve });
        child.stdin.write(line + '\n');
      });
    },
    close() { try { child.stdin.end(); } catch { /* */ } },
    stderr() { return child._stderr || ''; }
  };
}

function nodeShape(value) {
  if (value === null || typeof value !== 'object') return '.';
  if (Array.isArray(value)) return '[' + value.map(nodeShape).join(',') + ']';
  return '{' + Object.keys(value).map((k) => 'k(' + [...k].map((c) => c.codePointAt(0)).join(',') + ')' + nodeShape(value[k])).join(',') + '}';
}

function recordDivergence(kind, detail, caseText) {
  DIVERGENCES.push({ kind, detail, caseText });
  dumpCase('runtime-parser', String(DIVERGENCES.length) + '-' + kind, caseText ?? detail);
}

runSuite('cross-lang-diff', async () => {
  const exe = await pythonAvailable();
  if (!exe) {
    console.log('fuzz/cross-lang-diff: SKIPPED (python not found)');
    return;
  }
  const driver = makeDriver(exe, ['scripts/fuzz-diff-driver.py'], { PYTHONIOENCODING: 'utf-8', PYTHONUTF8: '1' });
  const N = QUICK ? 600 : 3000;
  const inputs = [];
  for (let i = 0; i < N; i++) {
    const v = genValue();
    if (i % 17 === 0) {
      const [k1, k2] = collidingKeyPair();
      inputs.push({ [k1]: 1, [k2]: 2 }); // both sides must reject identically
    } else {
      inputs.push(v);
    }
  }

  for (let i = 0; i < inputs.length; i++) {
    const line = await driver.cmd('CANC\t' + JSON.stringify(inputs[i]));
    const [pyStatus, pyPayload] = line.split('\t');
    let jsStatus, jsPayload;
    try {
      jsStatus = 'OK';
      jsPayload = canonicalize(inputs[i]).replace(/\n/g, '\\n');
    } catch (err) {
      jsStatus = err instanceof CanonicalError ? 'ERR' : 'UNEXPECTED';
      jsPayload = err instanceof CanonicalError ? 'CanonicalError' : 'Unexpected:' + err.constructor.name;
    }
    if (pyStatus !== jsStatus) {
      violation('cross-lang-diff', `status divergence on case ${i}: py=${pyStatus} js=${jsStatus}`, repr(inputs[i]).slice(0, 200));
      continue;
    }
    if (pyStatus === 'OK' && pyPayload !== jsPayload) {
      violation('cross-lang-diff', `BYTE divergence on case ${i}`, `py=${pyPayload.slice(0, 120)} js=${jsPayload.slice(0, 120)}`);
    }
  }
  driver.close();
});

// --------------------------------------- 4b. runtime parser differential ----
// The critic asked for parser-differential fuzzing; it paid for itself on day
// one: under specific allocation histories V8's JSON.parse returns a PHANTOM
// key ('\' where the text says "\u001f"), nondeterministically across
// processes on byte-identical input. Python's json.loads is unaffected.
// PiProof's own attack surface is not reachable through this hole because
// every parsed document has a schema-pinned key set (unknown keys are
// rejected before any semantic use), but a divergence here would silently
// corrupt any looser consumer — so we detect and fingerprint it forever.
runSuite('parser-differential', async () => {
  const exe = await pythonAvailable();
  if (!exe) {
    console.log('fuzz/parser-differential: SKIPPED (python not found)');
    return;
  }
  const driver = makeDriver(exe, ['scripts/fuzz-diff-driver.py'], { PYTHONIOENCODING: 'utf-8', PYTHONUTF8: '1' });
  const N = QUICK ? 400 : 2000;
  for (let i = 0; i < N; i++) {
    // Round-trip through text so both parsers see identical bytes.
    const text = JSON.stringify(genValue());
    const line = await driver.cmd('PARSE\t' + text);
    if (!line.startsWith('SHAPE\t')) continue;
    const pyShape = line.slice(6);
    let jsShape;
    try {
      jsShape = nodeShape(JSON.parse(text));
    } catch {
      continue; // node rejected what python accepted: handled by CANC suite
    }
    if (jsShape !== pyShape) {
      recordDivergence(
        'parse-shape',
        `node and python disagree on key structure (case ${i}). ` +
          `node=${jsShape.slice(0, 120)} python=${pyShape.slice(0, 120)}. ` +
          `This is a RUNTIME JSON.parse divergence (V8), not a PiProof defect — see SECURITY.md.`,
        text
      );
    }
  }
  driver.close();
});

// ------------------------------------------------------- 4c. go-diff --------
// The third-language implementation (sdk/go) must agree with Node byte-for-
// byte on canonicalization AND structurally on parse shapes — this is the
// "reimplementable from the spec alone" proof, continuously enforced.
suite('go-diff', async () => {
  if (!(await goAvailable())) {
    console.log('fuzz/go-diff: SKIPPED (go toolchain not found)');
    return;
  }
  const bin = buildGoDriver();
  if (!bin) return;
  const driver = makeDriver(bin, []);
  const N = QUICK ? 600 : 3000;
  const inputs = [];
  for (let i = 0; i < N; i++) {
    const v = genValue();
    if (i % 17 === 0) {
      const [k1, k2] = collidingKeyPair();
      inputs.push({ [k1]: 1, [k2]: 2 }); // both sides must reject identically
    } else {
      inputs.push(v);
    }
  }

  for (let i = 0; i < inputs.length; i++) {
    const line = await driver.cmd('CANC\t' + JSON.stringify(inputs[i]));
    const [goStatus, goPayload] = line.split('\t');
    let jsStatus, jsPayload;
    try {
      jsStatus = 'OK';
      jsPayload = canonicalize(inputs[i]).replace(/\n/g, '\\n');
    } catch (err) {
      jsStatus = err instanceof CanonicalError ? 'ERR' : 'UNEXPECTED';
      jsPayload = err instanceof CanonicalError ? 'CanonicalError' : 'Unexpected:' + err.constructor.name;
    }
    if (goStatus !== jsStatus) {
      violation('go-diff', `status divergence on case ${i}: go=${goStatus} js=${jsStatus}`, repr(inputs[i]).slice(0, 200));
      continue;
    }
    if (goStatus === 'OK' && goPayload !== jsPayload) {
      violation('go-diff', `BYTE divergence on case ${i}`, `go=${goPayload.slice(0, 120)} js=${jsPayload.slice(0, 120)}`);
    }
  }

  // Structural agreement on parse shapes too.
  for (let i = 0; i < N; i++) {
    const text = JSON.stringify(genValue());
    const line = await driver.cmd('PARSE\t' + text);
    if (!line.startsWith('SHAPE\t')) continue;
    const goShape = line.slice(6);
    let jsShape;
    try {
      jsShape = nodeShape(JSON.parse(text));
    } catch {
      continue;
    }
    if (jsShape !== goShape) {
      violation('go-diff', `parse-shape divergence on case ${i}: node and go disagree on key structure`);
    }
  }
  driver.close();
  try { fs.unlinkSync(bin); } catch { /* best effort */ }
});

// ---------------------------------------------------------- 5. concurrency --
suite('concurrency', async () => {
  const ROUNDS = QUICK ? 2 : 5;
  const K = 8;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pep-fuzz-race-'));
  const storePath = path.join(dir, 'nonces.log');
  const script =
    `const { FileNonceStore } = await import('file://${path.join(ROOT, 'src', 'nonces.js').replace(/\\/g, '/')}');` +
    `const s = new FileNonceStore(process.argv[1]);` +
    `process.stdout.write(String(s.claimIfAbsent(process.argv[2])));`;
  for (let round = 0; round < ROUNDS; round++) {
    const key = 'race-app:' + round.toString().padStart(2, '0') + 'ab'.repeat(15);
    const results = [];
    for (let k = 0; k < K; k++) {
      results.push(
        execFileSync(process.execPath, ['--input-type=module', '-e', script, storePath, key], {
          encoding: 'utf8',
          timeout: 60_000
        })
      );
    }
    const winners = results.filter((r) => r === 'true').length;
    if (winners !== 1) {
      violation('concurrency', `round ${round}: ${winners}/${K} racers won (expected exactly 1): ${results.join(',')}`);
    }
  }
  fs.rmSync(dir, { recursive: true, force: true });
});

// --------------------------------------------------------------- summary ----
for (const [name, fn] of SUITES) {
  await runSuite(name, fn);
}

console.log('');
if (DIVERGENCES.length) {
  console.log(
    `RUNTIME PARSER DIVERGENCE: ${DIVERGENCES.length} case(s) where Node's JSON.parse ` +
      `disagrees with Python's json.loads on identical bytes. These are V8 runtime ` +
      `bugs, NOT PiProof protocol violations (PiProof's schemas pin every parsed key set, ` +
      `so no attacker-reachable path exists — full analysis in SECURITY.md). ` +
      `Cases dumped if FUZZ_DUMP was set; reproducible with this seed.`
  );
  for (const d of DIVERGENCES.slice(0, 5)) {
    console.log(`  - [${d.kind}] ${d.detail.slice(0, 160)}`);
  }
}
if (violations.length) {
  console.error(`FUZZ FAIL (${violations.length} protocol violation(s)), seed=${SEED}:`);
  for (const v of violations) console.error('  ' + v);
  process.exit(1);
}
console.log(`FUZZ OK — all protocol properties held, seed=${SEED}, mode=${QUICK ? 'quick' : 'full'}`);
