import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeWorld, SUITE_UID_SECRET } from '../src/attacks.js';
import { hashUid, newEvent, signEvent } from '../src/events.js';
import { InMemoryNonceStore } from '../src/nonces.js';
import { markEligible, registerApp } from '../src/registry.js';
import { BINDING_EPOCH_BOUND, BINDING_LOCAL, toPiProof, verifyPiProof } from '../src/piproof.js';
import { createPassport, verifyPassport } from '../src/passport.js';
import { buildDisputeReport } from '../src/dispute.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CLI = path.join(ROOT, 'src', 'cli.js');

function preparedWorld() {
  const world = makeWorld();
  markEligible(world.registry, hashUid('pioneer-alice', SUITE_UID_SECRET));
  return world;
}

function mint(world, { withRoot = false } = {}) {
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
  event.pioneer_uid_hash = hashUid('pioneer-alice', SUITE_UID_SECRET);
  const signed = signEvent(event, world.currentKey.private_key_pem);
  return toPiProof(signed, withRoot ? { registry: world.registry } : {});
}

function freshVerify(world, proof, extra = {}) {
  return verifyPiProof(proof, {
    registry: world.registry,
    nonceStore: new InMemoryNonceStore(),
    ...extra
  });
}

test('LOCAL proofs verify without a REGISTRY_ROOT step and report binding LOCAL', () => {
  const world = preparedWorld();
  const res = freshVerify(world, mint(world, { withRoot: false }));
  assert.equal(res.ok, true);
  assert.equal(res.binding, BINDING_LOCAL);
  assert.equal(res.steps.some((s) => s.id === 'REGISTRY_ROOT'), false);
});

test('EPOCH_BOUND proofs pin to the verifier epoch and report binding EPOCH_BOUND', () => {
  const world = preparedWorld();
  const res = freshVerify(world, mint(world, { withRoot: true }));
  assert.equal(res.ok, true);
  assert.equal(res.binding, BINDING_EPOCH_BOUND);
  const rootStep = res.steps.find((s) => s.id === 'REGISTRY_ROOT');
  assert.equal(rootStep?.pass, true);
});

test('epoch-bound proofs still fail closed against a different epoch', () => {
  const world = preparedWorld();
  const other = preparedWorld();
  registerApp(other.registry, 'different-epoch-app');
  const res = freshVerify(other, mint(world, { withRoot: true }));
  assert.equal(res.ok, false);
  assert.equal(res.code, 'REGISTRY_ROOT');
  assert.equal(res.binding, BINDING_EPOCH_BOUND);
});

test('require_epoch_bound policy rejects LOCAL and accepts EPOCH_BOUND', () => {
  const world = preparedWorld();
  const policy = { require_epoch_bound: true };
  const local = freshVerify(world, mint(world), { policy });
  assert.equal(local.ok, false);
  assert.equal(local.code, 'POLICY');
  assert.equal(local.policy.violations[0].rule, 'require_epoch_bound');

  const bound = freshVerify(world, mint(world, { withRoot: true }), { policy });
  assert.equal(bound.ok, true);
  assert.equal(bound.binding, BINDING_EPOCH_BOUND);
});

test('passport binding aggregates honestly: EPOCH_BOUND, LOCAL, MIXED', () => {
  const world = preparedWorld();
  const opts = { registry: world.registry, nonceStore: new InMemoryNonceStore() };

  const allBound = createPassport({
    proofs: [mint(world, { withRoot: true }), mint(world, { withRoot: true })]
  });
  assert.equal(verifyPassport(allBound, opts).summary.binding, 'EPOCH_BOUND');

  const allLocal = createPassport({ proofs: [mint(world)] });
  assert.equal(verifyPassport(allLocal, opts).summary.binding, 'LOCAL');

  // Reuse the same signed event twice would burn a nonce; mint distinct uids.
  markEligible(world.registry, hashUid('pioneer-bob', SUITE_UID_SECRET));
  const mixed = createPassport({
    proofs: [mintFor(world, 'pioneer-alice', { withRoot: true }), mintFor(world, 'pioneer-bob', {})]
  });
  assert.equal(verifyPassport(mixed, opts).summary.binding, 'MIXED');

  function mintFor(w, uid, o) {
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
    return toPiProof(signEvent(event, w.currentKey.private_key_pem), o.withRoot ? { registry: w.registry } : {});
  }
});

test('dispute chain asks IS_THE_PROOF_EPOCH_BOUND right after WHICH_EPOCH — full and structural modes', () => {
  const world = preparedWorld();
  const boundProof = mint(world, { withRoot: true });

  const full = buildDisputeReport({ doc: boundProof, registry: world.registry, nonceStore: new InMemoryNonceStore() });
  const questions = full.chain.map((c) => c.question);
  assert.equal(questions.indexOf('IS_THE_PROOF_EPOCH_BOUND'), questions.indexOf('WHICH_EPOCH') + 1);
  const bindAnswer = full.chain.find((c) => c.question === 'IS_THE_PROOF_EPOCH_BOUND');
  assert.deepEqual(bindAnswer.answer.per_proof, ['EPOCH_BOUND']);
  assert.equal(bindAnswer.status, 'OK');

  const structural = buildDisputeReport({ doc: boundProof, registry: null });
  const structuralBinding = structural.chain.find((c) => c.question === 'IS_THE_PROOF_EPOCH_BOUND');
  assert.equal(structuralBinding.status, 'OK', 'binding is document-intrinsic — answerable without a registry');
  assert.deepEqual(structuralBinding.answer.per_proof, ['EPOCH_BOUND']);
});

test('CLI enforces --epoch-bound export and --require-epoch-bound passport creation', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pep-binding-'));

  const world = preparedWorld();
  const localProof = mint(world, {});
  fs.writeFileSync(path.join(dir, 'local-proof.json'), JSON.stringify(localProof));

  const noRegistry = spawnSync(process.execPath, [CLI, 'proof-export', '--event', 'local-proof.json', '--epoch-bound'], {
    cwd: dir,
    encoding: 'utf8'
  });
  assert.equal(noRegistry.status, 1, '--epoch-bound must require --registry');
  assert.match(noRegistry.stderr, /--epoch-bound requires --registry/);

  const rejectLocal = spawnSync(
    process.execPath,
    [CLI, 'passport-create', '--proof', 'local-proof.json', '--require-epoch-bound'],
    { cwd: dir, encoding: 'utf8' }
  );
  assert.equal(rejectLocal.status, 1);
  assert.match(rejectLocal.stderr, /lack registry_root and are LOCAL/);

  fs.rmSync(dir, { recursive: true, force: true });
});
