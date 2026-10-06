import { makeWorld, SUITE_UID_SECRET } from '../src/attacks.js';
import { hashUid, newEvent, signEvent } from '../src/events.js';
import { InMemoryNonceStore } from '../src/nonces.js';
import { verifySignedEvent } from '../src/verify.js';
import { markEligible, registerApp, registerKey } from '../src/registry.js';
import { generateKeyPair, randomNonce } from '../src/keys.js';
import { createRevocationAttestation } from '../src/escrow.js';
import { assembleSnapshot } from '../src/dashboard.js';

/**
 * End-to-end Transparency Dashboard demo.
 *
 * Fuses the four endorsed primitives into one verifiable snapshot:
 * dynamic p_floor, x*y=k invariant health, escrow lock status and a
 * PoA/PoU/Consistency engagement leaderboard.
 */

const NOW = Date.now();
const DAY = 86_400_000;

const world = makeWorld();

// --- 1) verified engagement events for two pioneers -------------------
function verified(uidLabel, klass, actionId, t) {
  const hash = hashUid(uidLabel, SUITE_UID_SECRET);
  markEligible(world.registry, hash);
  const event = newEvent({
    app_id: 'demo-app',
    key_id: 'k-2026-active',
    action_class: klass,
    action_id: actionId,
    weight: 1,
    pioneer_uid: 'x',
    uidSecret: SUITE_UID_SECRET,
    now: t
  });
  event.pioneer_uid_hash = hash;
  const signed = signEvent(event, world.currentKey.private_key_pem);
  const verdict = verifySignedEvent(signed, {
    registry: world.registry,
    nonceStore: new InMemoryNonceStore(),
    now: t
  });
  if (!verdict.ok) throw new Error(`demo event unexpectedly rejected: ${verdict.code}`);
  return { event: signed, verdict };
}

const entries = [
  verified('pioneer-alice', 'A', 'complete_transaction', NOW - 5 * DAY),
  verified('pioneer-alice', 'B', 'finish_kyc_flow', NOW - 3 * DAY),
  verified('pioneer-alice', 'C', 'daily_login', NOW - DAY),
  verified('pioneer-bob', 'C', 'daily_login', NOW - DAY)
];

// --- 2) escrow lock attestation ---------------------------------------
const oldEscrowKey = generateKeyPair({ seed: Buffer.alloc(32, 7) });
const newController = generateKeyPair({ seed: Buffer.alloc(32, 9) });

registerApp(world.registry, 'launchpad-escrow');
registerKey(world.registry, 'launchpad-escrow', 'ctrl-v2', newController.public_key_pem, NOW);

const attestation = createRevocationAttestation(
  {
    escrowId: 'tge-escrow-main',
    controllerKeyId: 'ctrl-v2',
    previousPublicKeyPem: oldEscrowKey.public_key_pem,
    effectiveAt: NOW,
    anchor: 'tx-demo:0000000000000000',
    nonce: randomNonce()
  },
  newController.private_key_pem
);

// --- 3) assemble -------------------------------------------------------
const snapshot = assembleSnapshot({
  pool: {
    tokenReserve: 4_200_000,
    quoteReserve: 6_300_000,
    circulatingSupply: 12_500_000
  },
  invariantSnapshots: [
    { t: NOW - 7 * DAY, token_reserve: 4_000_000, quote_reserve: 6_000_000 },
    { t: NOW - 3 * DAY, token_reserve: 4_100_000, quote_reserve: 6_150_000 },
    { t: NOW, token_reserve: 4_200_000, quote_reserve: 6_300_000 }
  ],
  manifest: {
    complete_transaction: { class: 'A' },
    finish_kyc_flow: { class: 'B', multiplier: 0.8 },
    daily_login: { class: 'C' }
  },
  windowDays: 30,
  verifiedEntries: entries,
  attestation,
  registry: world.registry,
  now: NOW
});

console.log(JSON.stringify(snapshot, null, 2));
