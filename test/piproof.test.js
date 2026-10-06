import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CanonicalError, canonicalize } from '../src/canonical.js';
import { makeWorld, SUITE_UID_SECRET } from '../src/attacks.js';
import { hashUid, newEvent, signEvent } from '../src/events.js';
import { InMemoryNonceStore } from '../src/nonces.js';
import { markEligible } from '../src/registry.js';
import { PIPROOF_TYPE, PIPROOF_VERSION, registryRootHash, toPiProof, verifyPiProof } from '../src/piproof.js';
import { evaluatePolicy } from '../src/policy.js';

function freshSignedEvent(world, { weight = 50, actionClass = 'A', actionId = 'complete_transaction', uid = 'pioneer-alice' } = {}) {
  const hash = hashUid(uid, SUITE_UID_SECRET);
  markEligible(world.registry, hash);
  const event = newEvent({
    app_id: 'demo-app',
    key_id: 'k-2026-active',
    action_class: actionClass,
    action_id: actionId,
    weight,
    pioneer_uid: 'x',
    uidSecret: SUITE_UID_SECRET,
    now: Date.now()
  });
  event.pioneer_uid_hash = hash;
  return signEvent(event, world.currentKey.private_key_pem);
}

test('PiProof happy path: every step passes and verdict is trusted', () => {
  const world = makeWorld();
  const signed = freshSignedEvent(world);
  const proof = toPiProof(signed, { registry: world.registry });
  const res = verifyPiProof(proof, { registry: world.registry, nonceStore: new InMemoryNonceStore() });

  assert.equal(res.ok, true);
  assert.equal(res.code, null);
  const ids = res.steps.map((s) => s.id);
  for (const expected of ['PROOF_ENVELOPE', 'REGISTRY_ROOT', 'SCHEMA', 'APP_KNOWN', 'KEY_ACTIVE', 'CANONICALIZATION', 'SIGNATURE', 'TIMESTAMP_FRESHNESS', 'WEIGHT_BOUND', 'ELIGIBILITY', 'NONCE_REPLAY']) {
    assert.ok(ids.includes(expected), `missing step ${expected}`);
  }
  assert.ok(res.steps.every((s) => s.pass), JSON.stringify(res.steps));
});

test('envelope tampering is rejected before cryptography runs', () => {
  const world = makeWorld();
  const base = toPiProof(freshSignedEvent(world));

  for (const mutate of [
    (p) => ({ ...p, type: 'OtherProof' }),
    (p) => ({ ...p, version: PIPROOF_VERSION + 1 }),
    (p) => ({ ...p, extra: 1 }),
    (p) => ({ ...p, created_at: -5 }),
    (p) => ({ type: PIPROOF_TYPE, version: PIPROOF_VERSION, created_at: 1 })
  ]) {
    const res = verifyPiProof(mutate(base), { registry: world.registry, nonceStore: new InMemoryNonceStore() });
    assert.equal(res.ok, false);
    assert.equal(res.code, 'PROOF_ENVELOPE');
    assert.ok(res.steps.length >= 1 && res.steps[0].pass === false);
  }
});

test('registry_root mismatch rejects proofs minted against a foreign epoch', () => {
  const world = makeWorld();
  const proof = toPiProof(freshSignedEvent(world), { registry: world.registry });
  proof.registry_root = 'r1:' + 'ab'.repeat(32);

  const res = verifyPiProof(proof, { registry: world.registry, nonceStore: new InMemoryNonceStore() });
  assert.equal(res.ok, false);
  assert.equal(res.code, 'REGISTRY_ROOT');
  assert.match(res.steps[1].detail, /verifier epoch/);
});

test('replaying the same PiProof hits the nonce wall on the second check', () => {
  const world = makeWorld();
  const proof = toPiProof(freshSignedEvent(world));
  const store = new InMemoryNonceStore();

  assert.equal(verifyPiProof(proof, { registry: world.registry, nonceStore: store }).ok, true);
  const replay = verifyPiProof(proof, { registry: world.registry, nonceStore: store });
  assert.equal(replay.ok, false);
  assert.equal(replay.code, 'REPLAY_DETECTED');
  assert.equal(replay.steps.at(-1).id, 'NONCE_REPLAY');
  assert.equal(replay.steps.at(-1).pass, false);
});

test('policy engine narrows acceptance with precise violations', () => {
  const world = makeWorld();
  const signed = freshSignedEvent(world, { weight: 50 });
  const now = Date.now();

  const allow = evaluatePolicy(signed, { now }, { issuer_allowlist: ['demo-app'], min_weight: 10, max_weight: 100, require_kyc: true, require_mainnet: true, action_classes: ['A'] });
  assert.deepEqual(allow.violations, []);

  const issuer = evaluatePolicy(signed, { now }, { issuer_allowlist: ['other-app'] });
  assert.equal(issuer.pass, false);
  assert.equal(issuer.violations[0].rule, 'issuer_allowlist');

  const weight = evaluatePolicy(signed, { now }, { min_weight: 999 });
  assert.equal(weight.violations[0].rule, 'min_weight');

  const age = evaluatePolicy(signed, { now: now + 60_000 }, { max_age_ms: 30_000 });
  assert.equal(age.violations[0].rule, 'max_age');

  const kyc = evaluatePolicy({ ...signed, eligibility: { kyc_passed: false, mainnet_migrated: true } }, { now }, { require_kyc: true });
  assert.equal(kyc.violations[0].rule, 'require_kyc');

  const combined = evaluatePolicy(signed, { now }, { issuer_allowlist: ['other-app'], min_weight: 999 });
  assert.equal(combined.violations.length, 2);
});

test('verifyPiProof surfaces policy failures as POLICY code while crypto stays green', () => {
  const world = makeWorld();
  const proof = toPiProof(freshSignedEvent(world, { weight: 50 }));
  const res = verifyPiProof(proof, {
    registry: world.registry,
    nonceStore: new InMemoryNonceStore(),
    policy: { min_weight: 500 }
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, 'POLICY');
  const sigStep = res.steps.find((s) => s.id === 'SIGNATURE');
  assert.equal(sigStep.pass, true);
});

test('canonicalizer rejects NFC key collisions instead of merging distinct fields', () => {
  const nfc = String.fromCharCode(0xe9);            // é precomposed
  const nfd = String.fromCharCode(0x65, 0x301);     // e + combining acute
  const aRing = String.fromCharCode(0x41, 0x30a);   // A + combining ring
  const aRingPre = String.fromCharCode(0xc5);       // Å precomposed
  assert.notEqual(nfc, nfd);
  assert.throws(() => canonicalize({ [nfc]: 1, [nfd]: 2 }), CanonicalError);
  assert.throws(() => canonicalize({ a: { [aRingPre]: 1, [aRing]: 2 } }), CanonicalError);
  // plain ASCII objects are unaffected
  assert.equal(canonicalize({ b: 1, a: 2 }), '{"a":2,"b":1}');
});
