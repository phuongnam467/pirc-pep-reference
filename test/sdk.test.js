import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeWorld, SUITE_UID_SECRET } from '../src/attacks.js';
import { hashUid, newEvent, signEvent } from '../src/events.js';
import { InMemoryNonceStore } from '../src/nonces.js';
import { markEligible, registerApp, registerKey } from '../src/registry.js';
import { generateKeyPair } from '../src/keys.js';
import { toPiProof } from '../src/piproof.js';
import { createPassport } from '../src/passport.js';
import {
  createVerifier,
  formatDecision,
  parseProofUri,
  toProofUri
} from '../src/sdk.js';
import { POLICY_PRESETS, listPolicyPresets, resolvePolicy } from '../src/policy-presets.js';

function preparedWorld() {
  const world = makeWorld();
  markEligible(world.registry, hashUid('pioneer-alice', SUITE_UID_SECRET));
  return world;
}

function mintBound(world, uid = 'pioneer-alice', withRoot = true) {
  const event = newEvent({
    app_id: 'demo-app',
    key_id: 'k-2026-active',
    action_class: 'A',
    action_id: 'complete_transaction',
    weight: 50,
    pioneer_uid: 'x',
    uidSecret: SUITE_UID_SECRET,
    now: Date.now()
  });
  event.pioneer_uid_hash = hashUid(uid, SUITE_UID_SECRET);
  return toPiProof(signEvent(event, world.currentKey.private_key_pem), withRoot ? { registry: world.registry } : {});
}

test('policy presets are frozen, well-formed, and use only known rules', () => {
  const KNOWN = ['issuer_allowlist', 'action_classes', 'min_weight', 'max_weight',
    'max_age_ms', 'require_kyc', 'require_mainnet', 'require_epoch_bound'];
  const names = Object.keys(POLICY_PRESETS);
  assert.ok(names.length >= 5);
  for (const p of Object.values(POLICY_PRESETS)) {
    assert.equal(Object.isFrozen(p), true);
    assert.equal(p.version, 1);
    for (const k of Object.keys(p.policy)) {
      assert.ok(KNOWN.includes(k), `unknown rule ${k} in ${p.name}`);
    }
  }
  const listed = listPolicyPresets();
  assert.equal(listed.length, names.length);
  assert.equal(new Set(listed.map((p) => p.name)).size, names.length);
});

test('resolvePolicy handles names, {"preset":...}, inline objects, null — and rejects junk', () => {
  assert.equal(resolvePolicy('merchant-verification-v1'), POLICY_PRESETS['merchant-verification-v1'].policy);
  assert.equal(resolvePolicy({ preset: 'agent-payment-v1' }), POLICY_PRESETS['agent-payment-v1'].policy);
  assert.deepEqual(resolvePolicy({ require_epoch_bound: true }), { require_epoch_bound: true });
  assert.equal(resolvePolicy(null), null);
  assert.equal(resolvePolicy(undefined), null);
  assert.throws(() => resolvePolicy('nope-v9'), /unknown policy preset/);
  assert.throws(() => resolvePolicy({ preset: 'nope' }), /unknown policy preset/);
});

test('decide ALLOWs a valid epoch-bound proof end-to-end', () => {
  const world = preparedWorld();
  const pi = createVerifier({ registry: world.registry, nonceStore: new InMemoryNonceStore() });
  const d = pi.decide(mintBound(world), { policy: 'reward-eligibility-v1' });
  assert.equal(d.decision, 'ALLOW');
  assert.equal(d.ok, true);
  assert.equal(d.binding, 'EPOCH_BOUND');
  assert.equal(d.policy_used, 'reward-eligibility-v1');
  assert.deepEqual(d.violations, []);
});

test('decide DENYs on protocol failure (ineligible) with the exact code', () => {
  const world = preparedWorld();
  const pi = createVerifier({ registry: world.registry, nonceStore: new InMemoryNonceStore() });
  const d = pi.decide(mintBound(world, 'stranger-uid'));
  assert.equal(d.decision, 'DENY');
  assert.equal(d.code, 'INELIGIBLE_USER');
  assert.match(formatDecision(d), /DENY \[INELIGIBLE_USER\]/);
});

test('decide DENYs LOCAL proofs under an epoch-bound preset', () => {
  const world = preparedWorld();
  const pi = createVerifier({ registry: world.registry, nonceStore: new InMemoryNonceStore() });
  const local = mintBound(world, 'pioneer-alice', false);
  const d = pi.decide(local, { policy: 'merchant-verification-v1' });
  assert.equal(d.decision, 'DENY');
  assert.equal(d.binding, 'LOCAL');
  assert.equal(d.violations[0].rule, 'require_epoch_bound');
});

test('replay through one verifier store is caught on the second decide', () => {
  const world = preparedWorld();
  const store = new InMemoryNonceStore();
  const pi = createVerifier({ registry: world.registry, nonceStore: store });
  const proof = mintBound(world);
  assert.equal(pi.decide(proof).decision, 'ALLOW');
  const second = pi.decide(proof);
  assert.equal(second.decision, 'DENY');
  assert.equal(second.code, 'REPLAY_DETECTED');
});

test('unknown preset is a clean POLICY_PRESET_UNKNOWN denial, never a crash', () => {
  const world = preparedWorld();
  const pi = createVerifier({ registry: world.registry, nonceStore: new InMemoryNonceStore() });
  const d = pi.decide(mintBound(world), { policy: 'ghost-policy-v1' });
  assert.equal(d.decision, 'DENY');
  assert.equal(d.code, 'POLICY_PRESET_UNKNOWN');
});

test('passport decide reports weakest-link binding', () => {
  const world = preparedWorld();
  markEligible(world.registry, hashUid('pioneer-bob', SUITE_UID_SECRET));
  const passport = createPassport({
    proofs: [mintBound(world, 'pioneer-alice', true), mintBound(world, 'pioneer-bob', false)]
  });
  const pi = createVerifier({ registry: world.registry, nonceStore: new InMemoryNonceStore() });
  const d = pi.decide(passport);
  assert.equal(d.binding, 'MIXED');
  assert.equal(d.decision, 'ALLOW'); // no epoch-binding requirement in default path
});

test('proof URI round-trips through build → parse → verify', () => {
  const world = preparedWorld();
  const proof = mintBound(world);
  const uri = toProofUri(proof);
  assert.match(uri, /^piproof:\/\/v1\?p=[A-Za-z0-9_-]+$/);
  const parsed = parseProofUri(uri);
  assert.deepEqual(parsed, proof);
  const pi = createVerifier({ registry: world.registry, nonceStore: new InMemoryNonceStore() });
  assert.equal(pi.decide(parsed).decision, 'ALLOW');

  for (const junk of [null, '', 'https://example.com', 'piproof://v2?p=abc', 'piproof://v1?p=!!!', 'piproof://v1?p=eyJ4IjoxfQ']) {
    assert.equal(parseProofUri(junk), null, String(junk));
  }
  assert.throws(() => toProofUri({ nope: 1 }), /expects a PiProof/);
});
