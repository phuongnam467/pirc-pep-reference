import { test } from 'node:test';
import assert from 'node:assert/strict';
import { InMemoryNonceStore } from '../src/nonces.js';
import { makeWorld } from '../src/attacks.js';
import { hashUid, newEvent, signEvent } from '../src/events.js';
import { registerApp, registerKey, markEligible } from '../src/registry.js';
import { toPiProof, verifyPiProof, registryRootHash } from '../src/piproof.js';

// §11 of SPEC.md: Pi is an adapter, not a dependency. This suite runs the
// ENTIRE protocol against a namespace with no Pi semantics at all — a
// shipping company signing container hand-offs — and requires identical
// behavior: pseudonymization, epoch binding, tamper and replay rejection.

const NOW = 1_755_860_000_000;

function acmeWorld() {
  const world = makeWorld();
  registerApp(world.registry, 'acme-logistics');
  const key = world.currentKey;
  registerKey(world.registry, 'acme-logistics', 'container-key-2026', key.public_key_pem, NOW);
  markEligible(world.registry, hashUid('container-42', SUITE_SECRET));
  return { world, key };
}

const SUITE_SECRET = 'acme-logistics-uid-secret-v1';

test('foreign namespace: container hand-off proof verifies end-to-end (ALLOW)', () => {
  const { world, key } = acmeWorld();
  const event = newEvent({
    app_id: 'acme-logistics',
    key_id: 'container-key-2026',
    action_class: 'C',
    action_id: 'handoff:container-42:pier-7',
    weight: 1,
    pioneer_uid: 'container-42',
    uidSecret: SUITE_SECRET,
    now: NOW,
  });
  const signed = signEvent(event, key.private_key_pem);
  const proof = toPiProof(signed, { registry: world.registry });

  const res = verifyPiProof(proof, {
    registry: world.registry,
    nonceStore: new InMemoryNonceStore(),
    now: NOW,
  });
  assert.equal(res.ok, true, JSON.stringify(res));
  assert.equal(res.binding, 'EPOCH_BOUND');

  // The identity is pseudonymized: only its keyed hash travels; the raw uid
  // never appears as an identity field (caller-chosen action_id text is
  // ordinary business payload and is not identity).
  assert.equal(signed.pioneer_uid, undefined);
  assert.match(signed.pioneer_uid_hash, /^h1:[A-Za-z0-9_-]{43}$/);
  assert.notEqual(
    signed.pioneer_uid_hash,
    hashUid('container-43', SUITE_SECRET)
  );
});

test('foreign namespace: tampering and replay behave identically (DENY)', () => {
  const { world, key } = acmeWorld();
  const base = () => signEvent(newEvent({
    app_id: 'acme-logistics',
    key_id: 'container-key-2026',
    action_class: 'C',
    action_id: 'handoff:container-42:pier-9',
    weight: 1,
    pioneer_uid: 'container-42',
    uidSecret: SUITE_SECRET,
    now: NOW,
  }), key.private_key_pem);

  const tampered = base();
  tampered.weight = 99;
  const r1 = verifyPiProof(toPiProof(tampered), {
    registry: world.registry, nonceStore: new InMemoryNonceStore(), now: NOW,
  });
  assert.equal(r1.ok, false);
  assert.match(r1.code ?? '', /SIGNATURE|WEIGHT_BOUND/);

  const store = new InMemoryNonceStore();
  const good = toPiProof(base());
  assert.equal(verifyPiProof(good, {
    registry: world.registry, nonceStore: store, now: NOW,
  }).ok, true);
  // same bytes again → G9 burn
  const r2 = verifyPiProof(good, {
    registry: world.registry, nonceStore: store, now: NOW + 1000,
  });
  assert.equal(r2.ok, false);
  assert.equal(r2.code, 'REPLAY_DETECTED');
});

test('epoch pinning works for foreign registries too', () => {
  const { world, key } = acmeWorld();
  const signed = signEvent(newEvent({
    app_id: 'acme-logistics', key_id: 'container-key-2026',
    action_class: 'C', action_id: 'audit:x', weight: 1,
    pioneer_uid: 'container-42', uidSecret: SUITE_SECRET, now: NOW,
  }), key.private_key_pem);

  const root = registryRootHash(world.registry);
  const bound = toPiProof(signed, { registry: world.registry });
  assert.equal(bound.registry_root, root);

  const stale = { ...world.registry, version: world.registry.version };
  stale.apps = {}; // a different generation entirely
  const res = verifyPiProof(bound, {
    registry: stale, nonceStore: new InMemoryNonceStore(), now: NOW,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, 'REGISTRY_ROOT');
});
