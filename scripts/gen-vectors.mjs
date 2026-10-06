import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ATTACKS, SUITE_NOW, SUITE_UID_SECRET, makeWorld } from '../src/attacks.js';
import { hashUid, signEvent } from '../src/events.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const VECTORS = path.join(ROOT, 'vectors');

// Selective cleanup: this generator owns valid/, attacks/ and registry.json.
// vectors/canonical/ belongs to gen-canonical-vectors.mjs and MUST survive
// this regeneration untouched.
fs.rmSync(path.join(VECTORS, 'valid'), { recursive: true, force: true });
fs.rmSync(path.join(VECTORS, 'attacks'), { recursive: true, force: true });
fs.rmSync(path.join(VECTORS, 'registry.json'), { force: true });
fs.mkdirSync(path.join(VECTORS, 'valid'), { recursive: true });
fs.mkdirSync(path.join(VECTORS, 'attacks'), { recursive: true });

const world = makeWorld();
fs.writeFileSync(path.join(VECTORS, 'registry.json'), JSON.stringify(world.registry, null, 2) + '\n');

const baselineEvent = {
  v: 1,
  app_id: 'demo-app',
  key_id: 'k-2026-active',
  action_class: 'A',
  action_id: 'complete_transaction',
  weight: 50,
  timestamp: SUITE_NOW,
  nonce: '11'.repeat(16),
  pioneer_uid_hash: hashUid('alice', SUITE_UID_SECRET),
  eligibility: { kyc_passed: true, mainnet_migrated: true }
};

const signedBaseline = signEvent(baselineEvent, world.currentKey.private_key_pem);
fs.writeFileSync(
  path.join(VECTORS, 'valid', 'signed-event.json'),
  JSON.stringify(signedBaseline, null, 2) + '\n'
);

const index = { now: SUITE_NOW, valid: ['valid/signed-event.json'], attacks: [] };

for (const attack of ATTACKS) {
  const { event } = attack.build(world);
  const file = `attacks/${attack.name}.json`;
  fs.writeFileSync(
    path.join(VECTORS, file),
    JSON.stringify(
      {
        attack: attack.name,
        description: attack.description,
        expected_code: attack.expected_code,
        precondition_verify_once: Boolean(attack.precondition_verify_once),
        event
      },
      null,
      2
    ) + '\n'
  );
  index.attacks.push({ attack: attack.name, file, expected_code: attack.expected_code });
}

fs.writeFileSync(path.join(VECTORS, 'index.json'), JSON.stringify(index, null, 2) + '\n');
console.log(`vectors generated: ${index.valid.length} valid, ${index.attacks.length} attacks`);
