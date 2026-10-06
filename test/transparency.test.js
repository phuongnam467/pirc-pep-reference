import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeWorld, SUITE_UID_SECRET } from '../src/attacks.js';
import { newEvent, signEvent } from '../src/events.js';
import { markEligible } from '../src/registry.js';
import { hashUid } from '../src/events.js';
import { InMemoryNonceStore } from '../src/nonces.js';
import { verifySignedEvent } from '../src/verify.js';
import {
  spotPrice,
  dynamicFloorPrice,
  invariantReport,
  floorIntact
} from '../src/pfloor.js';
import {
  compileManifest,
  engagementScore,
  leaderboard
} from '../src/engagement.js';
import {
  createRevocationAttestation,
  verifyRevocationAttestation,
  escrowSigningBytes
} from '../src/escrow.js';
import { registerApp, registerKey, createRegistry } from '../src/registry.js';
import { generateKeyPair, randomNonce, publicKeyFingerprint } from '../src/keys.js';
import { assembleSnapshot } from '../src/dashboard.js';

const NOW = 1755860000000;

// ---------- pfloor ----------

test('p_floor: full-supply dump lands at k/(R+S)^2 and sits below spot', () => {
  const R = 1_000_000;
  const Q = 2_000_000;
  const S = 5_000_000;

  const floor = dynamicFloorPrice({ tokenReserve: R, quoteReserve: Q, circulatingSupply: S });

  const k = R * Q;
  const expected = k / ((R + S) ** 2);

  assert.equal(floor.invariant_k, k);
  assert.equal(floor.spot_price, Q / R);
  assert.ok(Math.abs(floor.p_floor_marginal - expected) < 1e-9);
  assert.ok(floor.p_floor_marginal < floor.spot_price);
  assert.ok(floor.floor_to_spot_ratio < 1);
  assert.ok(floor.p_floor_average_realized > floor.p_floor_marginal);
});

test('p_floor is dynamic: more circulating supply lowers the floor', () => {
  const a = dynamicFloorPrice({ tokenReserve: 1000, quoteReserve: 4000, circulatingSupply: 500 });
  const b = dynamicFloorPrice({ tokenReserve: 1000, quoteReserve: 4000, circulatingSupply: 5000 });

  assert.ok(b.p_floor_marginal < a.p_floor_marginal);
});

test('p_floor rejects non-numeric or non-positive reserves', () => {
  assert.throws(() => dynamicFloorPrice({ tokenReserve: -1, quoteReserve: 1, circulatingSupply: 0 }), TypeError);
  assert.throws(() => dynamicFloorPrice({ tokenReserve: NaN, quoteReserve: 1, circulatingSupply: 0 }), TypeError);
  assert.throws(() => spotPrice(0, 1), TypeError);
});

test('invariant report flags extraction when k decreases', () => {
  const healthy = invariantReport([
    { t: 1, token_reserve: 100, quote_reserve: 400 },
    { t: 2, token_reserve: 110, quote_reserve: 401 }
  ]);
  assert.equal(healthy.healthy, true);
  assert.equal(healthy.extraction_events, 0);

  const broken = invariantReport([
    { t: 1, token_reserve: 100, quote_reserve: 400 },
    { t: 2, token_reserve: 50, quote_reserve: 300 }
  ]);
  assert.equal(broken.healthy, false);
  assert.equal(broken.extraction_events, 1);
  assert.ok(broken.max_drawdown_pct > 0);
});

test('invariant tolerance: tiny fee-driven dips within tolerance stay healthy', () => {
  const r = invariantReport(
    [
      { t: 1, token_reserve: 100, quote_reserve: 400 },
      { t: 2, token_reserve: 99.995, quote_reserve: 399.999 }
    ],
    { toleranceBps: 10 }
  );
  assert.equal(r.healthy, true);
});

test('floorIntact compares ratios across reserve changes', () => {
  const before = { tokenReserve: 1000, quoteReserve: 4000, circulatingSupply: 2000 };
  const better = { tokenReserve: 1200, quoteReserve: 6000, circulatingSupply: 2000 };

  const res = floorIntact({ before, after: better });
  assert.equal(res.intact, true);
  assert.ok(res.after_ratio > res.before_ratio);
});

// ---------- engagement ----------

function verifiedEntriesFor(world, uidHash, specs) {
  markEligible(world.registry, uidHash);
  return specs.map((spec) => {
    const event = newEvent({
      app_id: spec.appId ?? 'demo-app',
      key_id: 'k-2026-active',
      action_class: spec.klass,
      action_id: spec.actionId,
      weight: 1,
      pioneer_uid: 'x',
      uidSecret: SUITE_UID_SECRET,
      now: spec.t
    });
    event.pioneer_uid_hash = uidHash;
    const signed = signEvent(event, world.currentKey.private_key_pem);
    const verdict = verifySignedEvent(signed, {
      registry: world.registry,
      nonceStore: new InMemoryNonceStore(),
      now: spec.t
    });
    assert.equal(verdict.ok, true);
    return { event: signed, verdict };
  });
}

test('engagement score: PoA vs PoU split with manifest multipliers', () => {
  const world = makeWorld();
  const hash = hashUid('score-alice', SUITE_UID_SECRET);

  const manifest = compileManifest({
    login: { class: 'C' },
    complete_transaction: { class: 'B', multiplier: 0.5 },
    contribute_data: { class: 'A' }
  });

  const entries = verifiedEntriesFor(world, hash, [
    { klass: 'C', actionId: 'login', t: NOW },
    { klass: 'C', actionId: 'unknown_action', t: NOW },
    { klass: 'B', actionId: 'complete_transaction', t: NOW },
    { klass: 'A', actionId: 'contribute_data', t: NOW }
  ]);

  const score = engagementScore(entries, { manifest });

  // login C=1; unknown rejected by manifest; B capped 10*0.5=5; A=100
  assert.equal(score.poa_points, 1);
  assert.equal(score.pou_points, 105);
  assert.equal(score.events_rejected_by_manifest, 1);
  assert.equal(score.events_counted, 3);
  assert.equal(score.total_points, 106);
  assert.ok(score.consistency_factor >= 0.5 && score.consistency_factor <= 1);
  assert.ok(Math.abs(score.score - 106 * score.consistency_factor) < 1e-9);
});

test('consistency factor rewards spread-out activity over single bursts', () => {
  const world = makeWorld();
  const hash = hashUid('burst', SUITE_UID_SECRET);

  const burst = engagementScore(
    verifiedEntriesFor(world, hash, [{ klass: 'A', actionId: 'act', t: NOW }]),
    { windowDays: 30 }
  );

  const spread = engagementScore(
    verifiedEntriesFor(world, hash, [
      { klass: 'A', actionId: 'act', t: NOW },
      { klass: 'A', actionId: 'act', t: NOW + 86_400_000 },
      { klass: 'A', actionId: 'act', t: NOW + 4 * 86_400_000 }
    ]),
    { windowDays: 30 }
  );

  assert.ok(spread.consistency_factor > burst.consistency_factor);
  assert.ok(spread.score > burst.score);
});

test('engagement refuses raw events without passing verdicts', () => {
  assert.throws(
    () => engagementScore([{ event: { app_id: 'x', action_id: 'y', timestamp: 1, action_class: 'A' }, verdict: { ok: false } }]),
    TypeError
  );
  assert.throws(() => engagementScore([{ verdict: { ok: true, checks: [] } }]), TypeError);
});

test('leaderboard ranks deterministically and groups pioneers', () => {
  const world = makeWorld();

  const alice = verifiedEntriesFor(world, hashUid('lb-alice', SUITE_UID_SECRET), [
    { klass: 'A', actionId: 'big', t: NOW },
    { klass: 'B', actionId: 'mid', t: NOW + 86_400_000 * 3 }
  ]);

  const bob = verifiedEntriesFor(world, hashUid('lb-bob', SUITE_UID_SECRET), [
    { klass: 'C', actionId: 'small', t: NOW }
  ]);

  const board = leaderboard([...alice, ...bob], { windowDays: 30 });

  assert.equal(board.length, 2);
  assert.equal(board[0].rank, 1);
  assert.equal(board[0].score, board[1].score ? Math.max(board[0].score, board[1].score) : board[0].score);
  assert.ok(board[0].total_points >= board[1].total_points);
  assert.deepEqual(board.map((r) => r.pioneer_uid_hash).sort(), [hashUid('lb-alice', SUITE_UID_SECRET), hashUid('lb-bob', SUITE_UID_SECRET)].sort());
});

test('manifest validation: multiplier above 1 is rejected (weigh down only)', () => {
  assert.throws(() => compileManifest({ x: { class: 'A', multiplier: 1.01 } }), TypeError);
  assert.throws(() => compileManifest({ x: { class: 'D' } }), TypeError);
  assert.throws(() => compileManifest('nope'), TypeError);
});

// ---------- escrow ----------

function escrowFixture() {
  const oldPair = generateKeyPair();
  const newController = generateKeyPair();
  const registry = createRegistry();
  registerApp(registry, 'launchpad-escrow');
  registerKey(registry, 'launchpad-escrow', 'ctrl-2026', newController.public_key_pem, NOW);
  return { registry, oldPair, newController };
}

test('escrow attestation verifies end-to-end against the registry', () => {
  const { registry, oldPair, newController } = escrowFixture();

  const att = createRevocationAttestation(
    {
      escrowId: 'escrow-tge-1',
      controllerKeyId: 'ctrl-2026',
      previousPublicKeyPem: oldPair.public_key_pem,
      effectiveAt: NOW,
      anchor: 'tx:abc123',
      nonce: randomNonce()
    },
    newController.private_key_pem
  );

  const verdict = verifyRevocationAttestation(att, { registry, now: NOW });
  assert.equal(verdict.ok, true);
  assert.equal(verdict.state, 'SIGNING_AUTHORITY_REVOKED');
  assert.deepEqual(
    verdict.checks.map((c) => c.check),
    ['SCHEMA', 'CANONICALIZATION', 'KEY_ACTIVE', 'SIGNATURE', 'FRESHNESS', 'REPLAY_DETECTED_GUARD']
  );
  assert.equal(verdict.previous_key_fingerprint, publicKeyFingerprint(oldPair.public_key_pem));
});

test('escrow attestation binds to the exact revoked key fingerprint', () => {
  const { registry, newController } = escrowFixture();
  const wrongOldKey = generateKeyPair().public_key_pem;

  const att = createRevocationAttestation(
    {
      escrowId: 'escrow-x',
      controllerKeyId: 'ctrl-2026',
      previousPublicKeyPem: wrongOldKey,
      effectiveAt: NOW,
      nonce: randomNonce()
    },
    newController.private_key_pem
  );

  const verdict = verifyRevocationAttestation(att, { registry, now: NOW });
  assert.equal(verdict.ok, true);
  assert.equal(verdict.previous_key_fingerprint, publicKeyFingerprint(wrongOldKey));
});

test('escrow attestation: tampering breaks signature', () => {
  const { registry, oldPair, newController } = escrowFixture();

  const att = createRevocationAttestation(
    {
      escrowId: 'escrow-t',
      controllerKeyId: 'ctrl-2026',
      previousPublicKeyPem: oldPair.public_key_pem,
      effectiveAt: NOW,
      nonce: randomNonce()
    },
    newController.private_key_pem
  );

  const tampered = { ...att, escrow_id: 'escrow-other' };

  const verdict = verifyRevocationAttestation(tampered, { registry, now: NOW });
  assert.equal(verdict.ok, false);
  assert.equal(verdict.checks.at(-1).check, 'SIGNATURE');
});

test('escrow attestation: unknown controller key fails KEY_ACTIVE', () => {
  const { registry, oldPair } = escrowFixture();
  const stranger = generateKeyPair();

  const att = createRevocationAttestation(
    {
      escrowId: 'escrow-u',
      controllerKeyId: 'ghost-key',
      previousPublicKeyPem: oldPair.public_key_pem,
      effectiveAt: NOW,
      nonce: randomNonce()
    },
    stranger.private_key_pem
  );

  const verdict = verifyRevocationAttestation(att, { registry, now: NOW });
  assert.equal(verdict.ok, false);
  assert.equal(verdict.checks.at(-1).check, 'KEY_ACTIVE');
});

test('escrow attestation: stale effective_at fails freshness', () => {
  const { registry, oldPair, newController } = escrowFixture();

  const att = createRevocationAttestation(
    {
      escrowId: 'escrow-old',
      controllerKeyId: 'ctrl-2026',
      previousPublicKeyPem: oldPair.public_key_pem,
      effectiveAt: NOW - 90 * 86_400_000,
      nonce: randomNonce()
    },
    newController.private_key_pem
  );

  const verdict = verifyRevocationAttestation(att, { registry, now: NOW });
  assert.equal(verdict.ok, false);
  assert.equal(verdict.checks.at(-1).check, 'FRESHNESS');
});

test('escrow attestation: same nonce replayed is rejected', () => {
  const { registry, oldPair, newController } = escrowFixture();
  const store = new InMemoryNonceStore();
  const nonce = randomNonce();

  const att = createRevocationAttestation(
    {
      escrowId: 'escrow-r',
      controllerKeyId: 'ctrl-2026',
      previousPublicKeyPem: oldPair.public_key_pem,
      effectiveAt: NOW,
      nonce
    },
    newController.private_key_pem
  );

  assert.equal(verifyRevocationAttestation(att, { registry, now: NOW, nonceStore: store }).ok, true);
  const again = verifyRevocationAttestation(att, { registry, now: NOW, nonceStore: store });
  assert.equal(again.ok, false);
  assert.equal(again.checks.at(-1).check, 'REPLAY_DETECTED');
});

test('escrow signing bytes use the dedicated ESCROW domain', () => {
  const { oldPair, newController } = escrowFixture();
  const att = createRevocationAttestation(
    {
      escrowId: 'escrow-d',
      controllerKeyId: 'ctrl-2026',
      previousPublicKeyPem: oldPair.public_key_pem,
      effectiveAt: NOW,
      nonce: randomNonce()
    },
    newController.private_key_pem
  );

  const bytes = escrowSigningBytes(att);
  assert.ok(bytes.toString('utf8').startsWith('PiRC1-ESCROW-v1\n'));
});

// ---------- dashboard ----------

const POOL = { tokenReserve: 1_000_000, quoteReserve: 2_500_000, circulatingSupply: 8_000_000 };

const SNAPSHOTS = [
  { t: NOW, token_reserve: 900_000, quote_reserve: 2_200_000 },
  { t: NOW + 60_000, token_reserve: 1_000_000, quote_reserve: 2_500_000 }
];

test('dashboard snapshot fuses all four primitives deterministically', () => {
  const world = makeWorld();
  const entries = verifiedEntriesFor(world, hashUid('dash-user', SUITE_UID_SECRET), [
    { klass: 'A', actionId: 'complete_transaction', t: NOW },
    { klass: 'B', actionId: 'finish_kyc_flow', t: NOW + 86_400_000 }
  ]);

  const snap = assembleSnapshot({
    pool: POOL,
    invariantSnapshots: SNAPSHOTS,
    windowDays: 30,
    verifiedEntries: entries,
    now: NOW
  });

  assert.equal(snap.schema, 'PiRC1-TransparencyDashboard/1');
  assert.ok(snap.price_floor.p_floor_marginal > 0);
  assert.equal(snap.pool_health.healthy, true);
  assert.equal(snap.engagement.leaderboard.length, 1);
  assert.equal(snap.escrow_lock_status, null);

  const again = JSON.parse(JSON.stringify(snap));
  assert.deepEqual(snap, again);
});

test('dashboard embeds a verifiable escrow lock status when attested', () => {
  const world = makeWorld();
  const { registry, oldPair, newController } = escrowFixture();

  const att = createRevocationAttestation(
    {
      escrowId: 'tge-main',
      controllerKeyId: 'ctrl-2026',
      previousPublicKeyPem: oldPair.public_key_pem,
      effectiveAt: NOW,
      anchor: 'tx:deadbeef',
      nonce: randomNonce()
    },
    newController.private_key_pem
  );

  const snap = assembleSnapshot({
    pool: POOL,
    registry,
    attestation: att,
    verifiedEntries: [],
    now: NOW
  });

  assert.equal(snap.escrow_lock_status.verifiable, true);
  assert.equal(snap.escrow_lock_status.state, 'SIGNING_AUTHORITY_REVOKED');
  assert.equal(snap.escrow_lock_status.anchor, 'tx:deadbeef');
});

test('dashboard requires pool input and keeps trust boundary on events', () => {
  assert.throws(() => assembleSnapshot(null), TypeError);
  assert.throws(() => assembleSnapshot({}), TypeError);
  assert.throws(
    () =>
      assembleSnapshot({
        pool: POOL,
        attestation: { v: 1 },
        verifiedEntries: []
      }),
    TypeError
  );
});
