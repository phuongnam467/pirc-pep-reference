import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { FileNonceStore } from '../src/nonces.js';

const KEY = (h) => 'demo-app:' + h.repeat(16);

function tmpStore() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pep-lock-'));
  // lockTimeoutMs < staleLockMs: a contender must GIVE UP before the stale
  // window opens, so "fresh lock stays protected" is actually observable.
  const store = new FileNonceStore(path.join(dir, 'nonces.log'), {
    lockTimeoutMs: 80,
    staleLockMs: 5000
  });
  return { dir, store, lockPath: path.join(dir, 'nonces.log.lock') };
}

const ANCIENT = 60_000; // far beyond any stale window

function writeLock(lockPath, content, ageMs = 0) {
  fs.writeFileSync(lockPath, typeof content === 'string' ? content : JSON.stringify(content) + '\n', 'utf8');
  if (ageMs > 0) {
    const past = new Date(Date.now() - ageMs);
    fs.utimesSync(lockPath, past, past);
  }
}

function deadPid() {
  // A child process whose exit we waited on synchronously: its pid is
  // guaranteed to be reaped and non-recycled for the duration of this test.
  const child = spawnSync(process.execPath, ['-e', 'process.exit(0)']);
  return child.pid;
}

test('lock files record their owner (pid + hostname + acquisition time)', () => {
  const { dir, store, lockPath } = tmpStore();
  store.claimIfAbsent(KEY('01'));

  // The claim released its lock, so the file is gone; verify ownership by
  // racing two claims through a second store while the first holds it.
  // Simpler observable check: acquire manually and inspect.
  const fd = store._acquireLock();
  const rec = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
  fs.closeSync(fd);
  fs.unlinkSync(lockPath);
  assert.equal(rec.v, 1);
  assert.equal(rec.pid, process.pid);
  assert.equal(rec.host, os.hostname());
  assert.ok(Number.isFinite(rec.acquiredAt));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a stale lock held by a LIVE same-host process is never stolen', () => {
  const { dir, store, lockPath } = tmpStore();
  writeLock(
    lockPath,
    { v: 1, pid: process.pid, host: os.hostname(), acquiredAt: Date.now() - ANCIENT },
    ANCIENT // far beyond the stale window — liveness must still protect it
  );
  assert.throws(
    () => store.claimIfAbsent(KEY('02')),
    /live process \d+.*refusing to steal/
  );
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a stale lock whose owner is provably DEAD is taken over after the window', () => {
  const { dir, store, lockPath } = tmpStore();
  writeLock(
    lockPath,
    { v: 1, pid: deadPid(), host: os.hostname(), acquiredAt: Date.now() - ANCIENT },
    ANCIENT
  );
  assert.equal(store.claimIfAbsent(KEY('03')), true);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('foreign-host locks: fresh ones are protected, stale ones fall back to takeover', () => {
  const { dir, store, lockPath } = tmpStore();

  writeLock(lockPath, { v: 1, pid: 1, host: 'some-other-host', acquiredAt: Date.now() }, 0);
  assert.throws(() => store.claimIfAbsent(KEY('04')), /could not acquire/);

  writeLock(lockPath, { v: 1, pid: 1, host: 'some-other-host', acquiredAt: Date.now() - ANCIENT }, ANCIENT);
  assert.equal(store.claimIfAbsent(KEY('05')), true);

  fs.rmSync(dir, { recursive: true, force: true });
});

test('legacy or corrupt lock files keep the old time-based behavior', () => {
  const { dir, store, lockPath } = tmpStore();

  writeLock(lockPath, '', 0); // crash before ownership record was written
  assert.throws(() => store.claimIfAbsent(KEY('06')), /could not acquire/);

  writeLock(lockPath, 'GARBAGE-NOT-JSON\n', ANCIENT);
  assert.equal(store.claimIfAbsent(KEY('07')), true);

  fs.rmSync(dir, { recursive: true, force: true });
});

test('cross-process property: exactly one of K racers wins the same nonce', () => {
  const { dir, store } = tmpStore();
  const key = KEY('de');
  const K = 8;
  // Each contender is a fresh OS process claiming the SAME key through the
  // shared durable store; exactly one must win.
  const script =
    `const { FileNonceStore } = await import('file://${path.resolve('src/nonces.js').replace(/\\/g, '/')}');` +
    `const s = new FileNonceStore(${JSON.stringify(store.filePath)});` +
    `process.stdout.write(String(s.claimIfAbsent(${JSON.stringify(key)})));`;
  const results = [];
  for (let i = 0; i < K; i++) {
    results.push(
      execFileSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8' })
    );
  }
  assert.equal(results.filter((r) => r === 'true').length, 1, `winners among ${K}: ${results}`);
  assert.equal(results.filter((r) => r === 'false').length, K - 1);
  fs.rmSync(dir, { recursive: true, force: true });
});
