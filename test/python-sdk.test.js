import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeWorld, SUITE_UID_SECRET } from '../src/attacks.js';
import { hashUid, newEvent, signEvent } from '../src/events.js';
import { markEligible } from '../src/registry.js';
import { toPiProof } from '../src/piproof.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SDK = path.join(ROOT, 'sdk', 'python', 'piproof_sdk.py');

function pythonBin() {
  for (const bin of ['python', 'python3']) {
    const r = spawnSync(bin, ['--version'], { encoding: 'utf8' });
    if (r.status === 0) return bin;
  }
  return null;
}

function fixture(dir, name, data) {
  const p = path.join(dir, name);
  fs.writeFileSync(p, JSON.stringify(data));
  return p;
}

test('Python SDK agrees with the Node pipeline: ALLOW, tamper DENY, replay DENY, epoch policy DENY', () => {
  const py = pythonBin();
  if (!py) {
    console.log('python not available — skipping Python SDK test');
    return;
  }

  const world = makeWorld();
  markEligible(world.registry, hashUid('pioneer-alice', SUITE_UID_SECRET));

  function mint(uid, withRoot) {
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

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'py-sdk-'));
  const regFile = path.join(dir, 'registry.json');
  fs.writeFileSync(regFile, JSON.stringify(world.registry));

  // 1. valid EPOCH_BOUND proof → ALLOW
  const boundFile = fixture(dir, 'bound.json', mint('pioneer-alice', true));
  let r = spawnSync(py, [SDK, boundFile, '--registry', regFile], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  const verdict = JSON.parse(r.stdout);
  assert.equal(verdict.decision, 'ALLOW');
  assert.equal(verdict.binding, 'EPOCH_BOUND');

  // 2. LOCAL proof under require_epoch_bound → POLICY denial
  const localFile = fixture(dir, 'local.json', mint('pioneer-alice', false));
  r = spawnSync(py, [SDK, localFile, '--registry', regFile,
    '--policy', '{"require_epoch_bound":true}'], { encoding: 'utf8' });
  assert.equal(r.status, 1);
  const policyVerdict = JSON.parse(r.stdout);
  assert.equal(policyVerdict.code, 'POLICY');
  assert.equal(policyVerdict.violations[0].rule, 'require_epoch_bound');

  // 3. preset reference resolves identically
  r = spawnSync(py, [SDK, localFile, '--registry', regFile, '--policy', 'merchant-verification-v1'], { encoding: 'utf8' });
  assert.equal(r.status, 1);
  assert.equal(JSON.parse(r.stdout).violations[0].rule, 'require_epoch_bound');

  // 4. tampered weight after signing → SIGNATURE failure
  const tampered = mint('pioneer-alice', true);
  tampered.event.weight += 1;
  const tamperedFile = fixture(dir, 'tampered.json', tampered);
  r = spawnSync(py, [SDK, tamperedFile, '--registry', regFile], { encoding: 'utf8' });
  assert.equal(r.status, 1);
  assert.equal(JSON.parse(r.stdout).code, 'INVALID_SIGNATURE');

  // 5. replay across runs via --state file → REPLAY_DETECTED
  const stateFile = path.join(dir, 'state.json');
  r = spawnSync(py, [SDK, boundFile.replace('bound.json', 'bound2.json'), '--registry', regFile, '--state', stateFile], { encoding: 'utf8' });

  const secondBound = fixture(dir, 'bound2.json', mint('pioneer-alice', true));
  const firstRun = spawnSync(py, [SDK, secondBound, '--registry', regFile, '--state', stateFile], { encoding: 'utf8' });
  assert.equal(firstRun.status, 0, firstRun.stdout + firstRun.stderr);
  const secondRun = spawnSync(py, [SDK, secondBound, '--registry', regFile, '--state', stateFile], { encoding: 'utf8' });
  assert.equal(secondRun.status, 1);
  assert.equal(JSON.parse(secondRun.stdout).code, 'REPLAY_DETECTED');

  fs.rmSync(dir, { recursive: true, force: true });
});
