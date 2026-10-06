import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeWorld, SUITE_UID_SECRET } from '../src/attacks.js';
import { hashUid, newEvent, signEvent } from '../src/events.js';
import { InMemoryNonceStore } from '../src/nonces.js';
import { markEligible } from '../src/registry.js';
import { toPiProof, verifyPiProof } from '../src/piproof.js';
import {
  PASSPORT_TYPE,
  PASSPORT_VERSION,
  PassportError,
  createPassport,
  evidenceRootHash,
  verifyPassport
} from '../src/passport.js';

function prepareUid(world, uid = 'pioneer-alice') {
  markEligible(world.registry, hashUid(uid, SUITE_UID_SECRET));
}

function mintProof(world, { weight = 50, actionClass = 'A', actionId = 'complete_transaction', uid = 'pioneer-alice' } = {}) {
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
  event.pioneer_uid_hash = hashUid(uid, SUITE_UID_SECRET);
  return toPiProof(signEvent(event, world.currentKey.private_key_pem), { registry: world.registry });
}

test('passport happy path: single proof verifies end to end', () => {
  const world = makeWorld();
  prepareUid(world);
  const proof = mintProof(world);
  const passport = createPassport({ proofs: [proof], subject: 'alice-demo' });

  assert.equal(passport.type, PASSPORT_TYPE);
  assert.equal(passport.version, PASSPORT_VERSION);
  assert.equal(passport.evidence_root, evidenceRootHash([proof]));

  const res = verifyPassport(passport, { registry: world.registry, nonceStore: new InMemoryNonceStore() });
  assert.equal(res.ok, true, JSON.stringify(res));
  const ids = res.steps.map((s) => s.id);
  for (const expected of ['PASSPORT_ENVELOPE', 'EVIDENCE_ROOT', 'PROOFS_VERIFIED']) {
    assert.ok(ids.includes(expected), `missing step ${expected}`);
  }
  assert.equal(res.summary.proofs_valid, 1);
  assert.equal(res.summary.proofs_total, 1);
  assert.equal(res.summary.subject, 'alice-demo');
});

test('multi-proof passport: all proofs must pass', () => {
  const world = makeWorld();
  prepareUid(world, 'pioneer-alice');
  prepareUid(world, 'pioneer-bob');
  const p1 = mintProof(world, { actionClass: 'A', actionId: 'complete_transaction' });
  const p2 = mintProof(world, { actionClass: 'B', actionId: 'finish_kyc_flow', weight: 5, uid: 'pioneer-bob' });

  const passport = createPassport({ proofs: [p1, p2], subject: 'bob-demo' });
  const res = verifyPassport(passport, { registry: world.registry, nonceStore: new InMemoryNonceStore() });
  assert.equal(res.ok, true, JSON.stringify(res.results?.map((r) => r.code)));
  assert.equal(res.summary.proofs_valid, 2);
  assert.ok(res.results[0].steps.every((s) => s.label.startsWith('#1 ') || s.label.startsWith('#')));
});

test('evidence root tampering is caught before any signature work', () => {
  const world = makeWorld();
  prepareUid(world);
  const proof = mintProof(world);
  const passport = createPassport({ proofs: [proof] });

  const mutated = structuredClone(passport);
  mutated.proofs[0].event.weight = 99999;
  const res = verifyPassport(mutated, { registry: world.registry, nonceStore: new InMemoryNonceStore() });
  assert.equal(res.ok, false);
  assert.equal(res.code, 'EVIDENCE_ROOT');

  const forgedRoot = { ...passport, evidence_root: 'e1:' + '0'.repeat(64) };
  const res2 = verifyPassport(forgedRoot, { registry: world.registry, nonceStore: new InMemoryNonceStore() });
  assert.equal(res2.ok, false);
  assert.equal(res2.code, 'EVIDENCE_ROOT');
});

test('passport envelope validation rejects malformed containers', () => {
  const world = makeWorld();
  prepareUid(world);
  const proof = mintProof(world);

  for (const bad of [
    null,
    'nope',
    [],
    { type: 'OtherPassport', version: 1, created_at: 1, proofs: [proof], evidence_root: 'e1:x' },
    { type: PASSPORT_TYPE, version: PASSPORT_VERSION + 1, created_at: 1, proofs: [proof], evidence_root: 'e1:x' },
    { type: PASSPORT_TYPE, version: PASSPORT_VERSION, created_at: -1, proofs: [proof], evidence_root: 'e1:x' },
    { type: PASSPORT_TYPE, version: PASSPORT_VERSION, created_at: 1, proofs: [], evidence_root: 'e1:x' },
    { type: PASSPORT_TYPE, version: PASSPORT_VERSION, created_at: 1, proofs: [{ nope: 1 }], evidence_root: 'e1:x', extra: true }
  ]) {
    const res = verifyPassport(bad, { registry: world.registry, nonceStore: new InMemoryNonceStore() });
    assert.equal(res.ok, false);
    assert.equal(res.code, 'PASSPORT_ENVELOPE');
    assert.equal(res.steps[0].pass, false);
  }

  const res = verifyPassport(
    { type: PASSPORT_TYPE, version: PASSPORT_VERSION, created_at: 1, proofs: [proof], evidence_root: 'e1:x', subject: 'bad tag!' },
    { registry: world.registry, nonceStore: new InMemoryNonceStore() }
  );
  assert.equal(res.ok, false);
  assert.equal(res.code, 'PASSPORT_ENVELOPE');
});

test('createPassport guards its own inputs', () => {
  assert.throws(() => createPassport({ proofs: [] }), PassportError);
  assert.throws(() => createPassport({ proofs: [{ type: 'nope' }] }), PassportError);
  assert.throws(() => createPassport({ proofs: [validish()], subject: 'spaces inside' }), PassportError);
  assert.throws(() => createPassport({ proofs: [validish()], createdAt: 0 }), PassportError);
  function validish() {
    return { type: 'PiProof', version: 1, created_at: 1, event: {} };
  }
});

test('replay detection propagates from embedded proofs to the passport verdict', () => {
  const world = makeWorld();
  const store = new InMemoryNonceStore();
  prepareUid(world);
  const passport = createPassport({ proofs: [mintProof(world)] });

  const first = verifyPassport(passport, { registry: world.registry, nonceStore: store });
  assert.equal(first.ok, true);

  const second = verifyPassport(passport, { registry: world.registry, nonceStore: store });
  assert.equal(second.ok, false);
  assert.equal(second.code, 'REPLAY_DETECTED');
  const replayStep = second.results[0].steps.find((s) => s.id === 'NONCE_REPLAY');
  assert.equal(replayStep.pass, false);
});

test('passport-stored policy narrows acceptance per holder', () => {
  const world = makeWorld();
  prepareUid(world);
  const proof = mintProof(world, { weight: 60 });
  const strictPolicy = { max_weight: 50 };
  const passport = createPassport({ proofs: [proof], policy: strictPolicy });

  const res = verifyPassport(passport, { registry: world.registry, nonceStore: new InMemoryNonceStore() });
  assert.equal(res.ok, false);
  assert.equal(res.code, 'POLICY');
  assert.equal(res.policy.pass, false);
  assert.ok(res.policy.violations.some((v) => v.rule === 'max_weight'));

  const override = verifyPassport(passport, {
    registry: world.registry,
    nonceStore: new InMemoryNonceStore(),
    policyOverride: { max_weight: 10000 }
  });
  assert.equal(override.ok, true);
});

test('verifier can independently re-derive the evidence root', () => {
  const world = makeWorld();
  prepareUid(world, 'pioneer-alice');
  prepareUid(world, 'pioneer-bob');
  const proofs = [mintProof(world), mintProof(world, { uid: 'pioneer-bob' })];
  const passport = createPassport({ proofs });
  assert.equal(verifyPiProof(proofs[0], { registry: world.registry, nonceStore: new InMemoryNonceStore() }).ok, true);
  assert.equal(evidenceRootHash(passport.proofs), passport.evidence_root);
});
