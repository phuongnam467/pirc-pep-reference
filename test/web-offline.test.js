import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { sha512, ed25519Verify } from '../src/web-ed25519.js';
import { verifyEventOffline, parseEd25519SpkiPem } from '../src/offline-verifier.js';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')), '..');

function bytes(...vals) {
  return Uint8Array.from(vals);
}
function hexToBytes(h) {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

test('sha512 agrees with node:crypto across empty/short/block-edge/random inputs', () => {
  const cases = [
    new Uint8Array(0),
    bytes(0x61), // "a"
    bytes(0x61, 0x62, 0x63), // "abc"
    crypto.randomBytes(111),
    crypto.randomBytes(127),
    crypto.randomBytes(128),
    crypto.randomBytes(129),
    crypto.randomBytes(1000)
  ];
  for (const msg of cases) {
    const expected = new Uint8Array(crypto.createHash('sha512').update(msg).digest());
    assert.deepEqual(sha512(msg), expected, `sha512 mismatch on ${msg.length}-byte input`);
  }
});

test('ed25519Verify accepts node-generated signatures and rejects tampering', () => {
  for (let round = 0; round < 4; round++) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const pubRaw = new Uint8Array(publicKey.export({ type: 'spki', format: 'der' })).slice(-32);
    for (const size of [0, 1, 32, 100, 5000]) {
      const msg = new Uint8Array(crypto.randomBytes(size));
      const sig = new Uint8Array(crypto.sign(null, msg, privateKey));
      assert.equal(ed25519Verify(pubRaw, msg, sig), true, `${size}-byte message must verify`);

      // flip one bit of the message
      if (size > 0) {
        const bad = msg.slice();
        bad[size - 1] ^= 0x01;
        assert.equal(ed25519Verify(pubRaw, bad, sig), false);
      }
      // flip one bit of R and of S
      const badR = sig.slice();
      badR[5] ^= 0x10;
      assert.equal(ed25519Verify(pubRaw, msg, badR), false);
      const badS = sig.slice();
      badS[40] ^= 0x01;
      assert.equal(ed25519Verify(pubRaw, msg, badS), false);

      // wrong key
      const other = crypto.generateKeyPairSync('ed25519');
      const otherRaw = new Uint8Array(other.publicKey.export({ type: 'spki', format: 'der' })).slice(-32);
      assert.equal(ed25519Verify(otherRaw, msg, sig), false);
    }
  }
});

test('ed25519Verify enforces canonical S and rejects malformed encodings', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pubRaw = new Uint8Array(publicKey.export({ type: 'spki', format: 'der' })).slice(-32);
  const msg = new Uint8Array(crypto.randomBytes(64));
  const sig = new Uint8Array(crypto.sign(null, msg, privateKey));

  // S = sig+L is mathematically equivalent but non-canonical — MUST reject.
  const L = (1n << 252n) + 27742317777372353535851937790883648493n;
  const sBytes = sig.slice(32);
  let s = 0n;
  for (let i = 31; i >= 0; i--) s = (s << 8n) | BigInt(sBytes[i]);
  const sPlusL = (s + L).toString(16).padStart(64, '0');
  const malleable = sig.slice();
  malleable.set(hexToBytes(sPlusL), 32);
  assert.equal(ed25519Verify(pubRaw, msg, malleable), false, 'non-canonical S must be rejected');

  // garbage keys/signatures fail closed without throwing
  assert.equal(ed25519Verify(new Uint8Array(32).fill(0xff), msg, sig), false);
  assert.equal(ed25519Verify(pubRaw.slice(0, 31), msg, sig), false);
  assert.equal(ed25519Verify(pubRaw, msg, sig.slice(0, 63)), false);
  assert.throws(() => ed25519Verify('nope', msg, sig), TypeError);
});

test('parseEd25519SpkiPem extracts the raw key or fails honestly', async () => {
  const registry = JSON.parse(await readFile(path.join(ROOT, 'vectors', 'registry.json'), 'utf8'));
  const app = Object.values(registry.apps)[0];
  const pem = Object.values(app.keys)[0].public_key_pem;
  const raw = parseEd25519SpkiPem(pem);
  assert.equal(raw.length, 32);

  // node cross-check: same raw key as SPKI DER tail
  const keyObj = crypto.createPublicKey(pem);
  const der = keyObj.export({ type: 'spki', format: 'der' });
  assert.deepEqual(raw, new Uint8Array(der).slice(-32));

  assert.equal(parseEd25519SpkiPem('-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----'), null);
  assert.equal(parseEd25519SpkiPem(null), null);
});

test('offline verifier ACCEPTS the committed valid vector end-to-end', async () => {
  const event = JSON.parse(await readFile(path.join(ROOT, 'vectors', 'valid', 'signed-event.json'), 'utf8'));
  const doc = event.event ?? event; // tolerate envelope wrapping
  const registry = JSON.parse(await readFile(path.join(ROOT, 'vectors', 'registry.json'), 'utf8'));
  // committed vectors carry a fixed past timestamp — verify against their era
  const r = verifyEventOffline(doc, { registry, now: doc.timestamp + 1000 });
  assert.equal(r.ok, true);
  assert.equal(r.verifiedOffline, true);
  assert.deepEqual(
    r.checks.map((c) => [c.check, c.status]),
    [
      ['SCHEMA', 'OK'],
      ['APP_KNOWN', 'OK'],
      ['KEY_ACTIVE', 'OK'],
      ['CANONICALIZATION', 'OK'],
      ['SIGNATURE', 'OK'],
      ['TIMESTAMP_FRESHNESS', 'OK'],
      ['WEIGHT_BOUND', 'OK'],
      ['ELIGIBILITY', 'OK'],
      ['NONCE_REPLAY', 'UNVERIFIABLE']
    ]
  );
});

test('offline verifier tracks the attack matrix with exact codes (replay rows stay honest)', async () => {
  const registry = JSON.parse(await readFile(path.join(ROOT, 'vectors', 'registry.json'), 'utf8'));
  const attacksDir = path.join(ROOT, 'vectors', 'attacks');
  const files = (await import('node:fs')).readdirSync(attacksDir).filter((f) => f.endsWith('.json'));

  let replayRows = 0;
  for (const file of files) {
    const vector = JSON.parse(await readFile(path.join(attacksDir, file), 'utf8'));
    const expected = vector.expected_code ?? vector.expectedCode ?? vector.code;
    const ev = vector.event ?? vector.document ?? vector.proof?.event ?? vector;
    const WINDOW = 300_000;
    let now = ev.timestamp + 1000; // vectors are frozen in the past
    if (expected === 'TIMESTAMP_EXPIRED') now = ev.timestamp + WINDOW * 10;
    if (expected === 'TIMESTAMP_IN_FUTURE') now = ev.timestamp - WINDOW * 10;

    const r = verifyEventOffline(ev, { registry, now });
    if (expected === 'REPLAY_DETECTED') {
      // Offline verification has no shared state — the honest outcome is a
      // passing crypto core with an UNVERIFIABLE replay row, never a claim.
      replayRows++;
      assert.equal(r.ok, true);
      const replay = r.checks.find((c) => c.check === 'NONCE_REPLAY');
      assert.equal(replay.status, 'UNVERIFIABLE');
      continue;
    }
    assert.equal(r.ok, false, `${file} must be rejected`);
    assert.equal(r.code, expected, `${file}: expected ${expected}, got ${r.code}`);
    const failedRow = r.checks[r.checks.length - 1];
    assert.equal(failedRow.status, 'INVALID');
  }
  assert.ok(replayRows >= 1, 'expected at least one REPLAY_DETECTED vector in the matrix');
});
