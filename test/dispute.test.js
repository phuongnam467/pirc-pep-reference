import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeWorld, SUITE_UID_SECRET } from '../src/attacks.js';
import { hashUid, newEvent, signEvent } from '../src/events.js';
import { InMemoryNonceStore } from '../src/nonces.js';
import { markEligible, registerApp, registerKey } from '../src/registry.js';
import { generateKeyPair } from '../src/keys.js';
import { toPiProof } from '../src/piproof.js';
import { createPassport } from '../src/passport.js';
import { buildDisputeReport } from '../src/dispute.js';

function prepare(world, uid = 'pioneer-alice') {
  markEligible(world.registry, hashUid(uid, SUITE_UID_SECRET));
}

function mintProof(world, issuerConfig, uid = 'pioneer-alice', actionId = 'complete_transaction', weight = 50) {
  const pem = issuerConfig.private_key_pem ?? world.currentKey.private_key_pem;
  const event = newEvent({
    app_id: issuerConfig.app_id,
    key_id: issuerConfig.key_id,
    action_class: 'A',
    action_id: actionId,
    weight,
    pioneer_uid: 'x',
    uidSecret: SUITE_UID_SECRET,
    now: Date.now()
  });
  event.pioneer_uid_hash = hashUid(uid, SUITE_UID_SECRET);
  return toPiProof(signEvent(event, pem), { registry: world.registry });
}

function twoIssuerWorld() {
  const world = makeWorld();
  prepare(world);
  prepare(world, 'pioneer-bob');
  const marketKey = generateKeyPair({ seed: Buffer.alloc(32, 0xab) });
  registerApp(world.registry, 'marketplace-demo');
  registerKey(world.registry, 'marketplace-demo', 'mk-key-2026', marketKey.public_key_pem);
  return { world, market: { app_id: 'marketplace-demo', key_id: 'mk-key-2026', private_key_pem: marketKey.private_key_pem } };
}

test('dispute VALID path walks the full question chain in order', () => {
  const { world } = twoIssuerWorld();
  const passport = createPassport({ proofs: [mintProof(world, { app_id: 'demo-app', key_id: 'k-2026-active' })], subject: 'alice-demo' });
  const report = buildDisputeReport({ doc: passport, registry: world.registry, nonceStore: new InMemoryNonceStore() });

  assert.equal(report.verdict, 'VALID');
  assert.equal(report.type, 'AUREVIA-Dispute-Report');
  const questions = report.chain.map((c) => c.question);
  assert.deepEqual(questions, [
    'CLAIM', 'WHO_ISSUED_IT', 'WHAT_WAS_SIGNED', 'WHICH_POLICY', 'WHICH_EPOCH',
    'IS_THE_PROOF_EPOCH_BOUND', 'WAS_IT_REPLAYED', 'IS_THE_KEY_VALID', 'IS_THE_CLAIM_WITHIN_POLICY', 'FINAL_VERDICT'
  ]);
  for (const c of report.chain) {
    if (c.question === 'FINAL_VERDICT') continue;
    assert.equal(c.status, 'OK', `${c.question}: ${JSON.stringify(c.answer)}`);
  }
  assert.equal(report.chain.at(-1).status, 'VALID');
});

test('dispute without a trusted registry is honestly UNVERIFIABLE â€” never a pass', () => {
  const { world } = twoIssuerWorld();
  const proof = mintProof(world, { app_id: 'demo-app', key_id: 'k-2026-active' });
  const report = buildDisputeReport({ doc: proof, registry: null });

  assert.equal(report.verdict, 'UNVERIFIABLE');
  const statuses = report.chain.map((c) => c.status);
  assert.equal(statuses.filter((s) => s === 'UNVERIFIABLE').length >= 4, true);
  assert.equal(statuses.includes('INVALID'), false);
});

test('dispute INVALID on replayed document with precise stage flagging', () => {
  const { world } = twoIssuerWorld();
  const store = new InMemoryNonceStore();
  const proof = mintProof(world, { app_id: 'demo-app', key_id: 'k-2026-active' });
  const first = buildDisputeReport({ doc: proof, registry: world.registry, nonceStore: store });
  assert.equal(first.verdict, 'VALID');

  const second = buildDisputeReport({ doc: proof, registry: world.registry, nonceStore: store });
  assert.equal(second.verdict, 'INVALID');
  const replayed = second.chain.find((c) => c.question === 'WAS_IT_REPLAYED');
  assert.equal(replayed.status, 'INVALID');
  const final = second.chain.find((c) => c.question === 'FINAL_VERDICT');
  assert.equal(final.status, 'INVALID');
});

test('cross-application passport: two independent issuers, one epoch, one verdict', () => {
  const { world, market } = twoIssuerWorld();
  const proofs = [
    mintProof(world, { app_id: 'demo-app', key_id: 'k-2026-active' }),
    mintProof(world, market, 'pioneer-bob')
  ];
  const passport = createPassport({ proofs, subject: 'bob-demo' });
  const report = buildDisputeReport({ doc: passport, registry: world.registry, nonceStore: new InMemoryNonceStore() });

  assert.equal(report.verdict, 'VALID');
  const who = report.chain.find((c) => c.question === 'WHO_ISSUED_IT');
  assert.equal(who.answer.cross_issuer, true);
  assert.ok(who.answer.issuers.includes('demo-app'));
  assert.ok(who.answer.issuers.includes('marketplace-demo'));
});

test('unreadable documents are UNVERIFIABLE at the CLAIM stage', () => {
  for (const junk of ['string', 42, {}, { type: 'Unknown' }, { type: 'AUREVIA-Evidence-Passport' }]) {
    const report = buildDisputeReport({ doc: junk, registry: makeWorld().registry });
    assert.equal(report.verdict, 'UNVERIFIABLE');
    assert.equal(report.chain[0].question, 'CLAIM');
    assert.equal(report.chain[0].status, 'UNVERIFIABLE');
  }
});
