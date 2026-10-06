import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { hashUid } from '../src/events.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CLI = path.join(ROOT, 'src', 'cli.js');
const DEV_UID_SECRET = 'cli-e2e-uid-secret-0123456789abcdef';

function tmpdir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'pep-cli-'));
}

function runCli(args, cwd) {
  return spawnSync(process.execPath, [CLI, ...args], {
    cwd,
    encoding: 'utf8'
  });
}

test('attacks command exits 0 and reports 20/20 rejected', () => {
  const r = runCli(['attacks']);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /20\/20 attacks rejected/);
});

test('demo command exits 0', () => {
  const r = runCli(['demo']);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /VERDICT: PASS/);
});

test('end-to-end: keygen, registry, sign, verify accept then replay reject', () => {
  const dir = tmpdir();

  execFileSync(process.execPath, [CLI, 'keygen', '--out', 'keys/dev.json'], { cwd: dir });
  execFileSync(process.execPath, [CLI, 'init-reg', '--out', 'registry.json', '--app', 'acme-app'], { cwd: dir });
  execFileSync(
    process.execPath,
    [CLI, 'add-key', '--registry', 'registry.json', '--app', 'acme-app', '--key-id', 'k1', '--pub', 'keys/dev.json'],
    { cwd: dir }
  );

  const uidHash = hashUid('dev-user', DEV_UID_SECRET);
  const event = {
    v: 1,
    app_id: 'acme-app',
    key_id: 'k1',
    action_class: 'B',
    action_id: 'finish_lesson',
    weight: 7,
    timestamp: Date.now(),
    nonce: 'ab'.repeat(16),
    pioneer_uid_hash: uidHash,
    eligibility: { kyc_passed: true, mainnet_migrated: true }
  };
  fs.writeFileSync(path.join(dir, 'event.json'), JSON.stringify(event, null, 2));

  execFileSync(
    process.execPath,
    [CLI, 'eligible', '--registry', 'registry.json', '--uid-hash', uidHash],
    { cwd: dir }
  );

  execFileSync(
    process.execPath,
    [CLI, 'sign', '--event', 'event.json', '--key', 'keys/dev.json', '--out', 'signed.json'],
    { cwd: dir }
  );

  const okRun = runCli(
    ['verify', '--event', 'signed.json', '--registry', 'registry.json', '--nonces', 'nonces.jsonl'],
    dir
  );
  assert.equal(okRun.status, 0, okRun.stdout + okRun.stderr);
  assert.match(okRun.stdout, /VERDICT: PASS/);

  const replayRun = runCli(
    ['verify', '--event', 'signed.json', '--registry', 'registry.json', '--nonces', 'nonces.jsonl'],
    dir
  );
  assert.equal(replayRun.status, 1);
  assert.match(replayRun.stdout, /VERDICT: REJECT \[REPLAY_DETECTED\]/);

  fs.rmSync(dir, { recursive: true, force: true });
});

test('portable proofs & passports verify with positional file arguments', () => {
  const dir = tmpdir();

  execFileSync(process.execPath, [CLI, 'keygen', '--out', 'keys/dev.json'], { cwd: dir });
  execFileSync(process.execPath, [CLI, 'init-reg', '--out', 'registry.json', '--app', 'acme-app'], { cwd: dir });
  execFileSync(
    process.execPath,
    [CLI, 'add-key', '--registry', 'registry.json', '--app', 'acme-app', '--key-id', 'k1', '--pub', 'keys/dev.json'],
    { cwd: dir }
  );

  const uidHash = hashUid('dev-user', DEV_UID_SECRET);
  execFileSync(
    process.execPath,
    [CLI, 'eligible', '--registry', 'registry.json', '--uid-hash', uidHash],
    { cwd: dir }
  );

  const event = {
    v: 1,
    app_id: 'acme-app',
    key_id: 'k1',
    action_class: 'B',
    action_id: 'finish_lesson',
    weight: 7,
    timestamp: Date.now(),
    nonce: 'cd'.repeat(16),
    pioneer_uid_hash: uidHash,
    eligibility: { kyc_passed: true, mainnet_migrated: true }
  };
  fs.writeFileSync(path.join(dir, 'event.json'), JSON.stringify(event, null, 2));

  execFileSync(
    process.execPath,
    [CLI, 'sign', '--event', 'event.json', '--key', 'keys/dev.json', '--out', 'signed.json'],
    { cwd: dir }
  );
  execFileSync(
    process.execPath,
    [CLI, 'proof-export', '--event', 'signed.json', '--registry', 'registry.json', '--out', 'proof.json'],
    { cwd: dir }
  );

  const okProof = runCli(['proof-verify', 'proof.json', '--registry', 'registry.json'], dir);
  assert.equal(okProof.status, 0, okProof.stdout + okProof.stderr);
  assert.match(okProof.stdout, /VERDICT: TRUSTED PROOF/);

  execFileSync(
    process.execPath,
    [CLI, 'passport-create', '--proof', 'proof.json', '--subject', 'alice-demo', '--out', 'passport.json'],
    { cwd: dir }
  );

  const okPassport = runCli(['passport-verify', 'passport.json', '--registry', 'registry.json'], dir);
  assert.equal(okPassport.status, 0, okPassport.stdout + okPassport.stderr);
  assert.match(okPassport.stdout, /VERDICT: PASSPORT VALID/);

  const dispute = runCli(['dispute', 'passport.json', '--registry', 'registry.json'], dir);
  assert.equal(dispute.status, 0, dispute.stdout + dispute.stderr);
  assert.match(dispute.stdout, /DISPUTE VERDICT: VALID/);

  fs.rmSync(dir, { recursive: true, force: true });
});

test('decide + policies: preset ALLOW then replay DENY via shared nonce file', () => {
  const dir = tmpdir();

  execFileSync(process.execPath, [CLI, 'keygen', '--out', 'keys/dev.json'], { cwd: dir });
  execFileSync(process.execPath, [CLI, 'init-reg', '--out', 'registry.json', '--app', 'acme-app'], { cwd: dir });
  execFileSync(
    process.execPath,
    [CLI, 'add-key', '--registry', 'registry.json', '--app', 'acme-app', '--key-id', 'k1', '--pub', 'keys/dev.json'],
    { cwd: dir }
  );

  const uidHash = hashUid('dev-user', DEV_UID_SECRET);
  execFileSync(
    process.execPath,
    [CLI, 'eligible', '--registry', 'registry.json', '--uid-hash', uidHash],
    { cwd: dir }
  );

  const event = {
    v: 1,
    app_id: 'acme-app',
    key_id: 'k1',
    action_class: 'A',
    action_id: 'complete_transaction',
    weight: 50,
    timestamp: Date.now(),
    nonce: 'ef'.repeat(16),
    pioneer_uid_hash: uidHash,
    eligibility: { kyc_passed: true, mainnet_migrated: true }
  };
  fs.writeFileSync(path.join(dir, 'event.json'), JSON.stringify(event));
  execFileSync(process.execPath, [CLI, 'sign', '--event', 'event.json', '--key', 'keys/dev.json', '--out', 'signed.json'], { cwd: dir });
  execFileSync(
    process.execPath,
    [CLI, 'proof-export', '--event', 'signed.json', '--registry', 'registry.json', '--epoch-bound', '--out', 'proof.json'],
    { cwd: dir }
  );

  const list = runCli(['policies'], dir);
  assert.equal(list.status, 0);
  assert.match(list.stdout, /merchant-verification-v1/);
  assert.match(list.stdout, /agent-payment-v1/);

  const allow = runCli(['decide', 'proof.json', '--registry', 'registry.json',
    '--policy', 'reward-eligibility-v1', '--nonces', 'nonces.jsonl'], dir);
  assert.equal(allow.status, 0, allow.stdout + allow.stderr);
  assert.match(allow.stdout, /DECISION: ALLOW/);

  const replay = runCli(['decide', 'proof.json', '--registry', 'registry.json',
    '--policy', 'reward-eligibility-v1', '--nonces', 'nonces.jsonl'], dir);
  assert.equal(replay.status, 1);
  assert.match(replay.stdout, /DECISION: DENY/);
  assert.match(replay.stdout, /REPLAY_DETECTED/);

  fs.rmSync(dir, { recursive: true, force: true });
});
