#!/usr/bin/env node
/**
 * PiProof throughput benchmark — reproducible production-scale evidence.
 *
 * Measures the full deterministic 9-step verify pipeline (canonical bytes →
 * Ed25519 → registry gating → atomic nonce claim) plus store-level
 * micro-costs. No mocks: every counted "verified" proof passed every check,
 * including a fresh Ed25519 signature verification and a real nonce claim.
 *
 * Usage:
 *   npm run bench                 # defaults: 3000 pipeline iterations
 *   node scripts/bench.mjs -n 10000
 */
import { performance } from 'node:perf_hooks';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { makeWorld, SUITE_UID_SECRET } from '../src/attacks.js';
import { hashUid, newEvent, signEvent } from '../src/events.js';
import { InMemoryNonceStore, FileNonceStore } from '../src/nonces.js';
import { toPiProof, verifyPiProof } from '../src/piproof.js';
import { markEligible } from '../src/registry.js';

const N = (() => {
  const i = process.argv.indexOf('-n');
  return i !== -1 ? Number(process.argv[i + 1]) || 3000 : 3000;
})();

function pct(sorted, p) {
  const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[Math.max(0, idx)];
}

function fmt(n) {
  return n.toLocaleString('en-US', { maximumFractionDigits: n < 100 ? 2 : 0 });
}

console.log(`PiProof bench — Node ${process.version}, ${os.type()} ${os.arch()} (${os.cpus().length} cores)`);
console.log(`iterations: ${N}\n`);

// ---- world (same shape as app/server.mjs) ---------------------------------
const world = makeWorld();
const uidHash = hashUid('bench-user', SUITE_UID_SECRET);
markEligible(world.registry, uidHash);

function freshProof(now) {
  const event = newEvent({
    app_id: 'demo-app',
    key_id: 'k-2026-active',
    action_class: 'A',
    action_id: 'complete_transaction',
    weight: 50,
    pioneer_uid: 'x',
    uidSecret: SUITE_UID_SECRET,
    now
  });
  event.pioneer_uid_hash = uidHash;
  return toPiProof(signEvent(event, world.currentKey.private_key_pem), { registry: world.registry });
}

// ---- full 9-step pipeline ---------------------------------------------------
{
  const store = new InMemoryNonceStore();
  const latencies = [];
  const base = Date.now() - N - 10;
  const proofs = [];
  for (let i = 0; i < N; i++) proofs.push(freshProof(base + i));

  let okCount = 0;
  const t0 = performance.now();
  for (const proof of proofs) {
    const s = performance.now();
    const r = verifyPiProof(proof, { registry: world.registry, nonceStore: store, now: Date.now() });
    latencies.push(performance.now() - s);
    if (r.ok) okCount++;
  }
  const total = performance.now() - t0;
  const sorted = [...latencies].sort((a, b) => a - b);
  console.log('Full 9-step verify pipeline (canonicalization + Ed25519 + registry gating + nonce claim):');
  console.log(`  verified  : ${fmt(okCount)}/${fmt(N)} (${((okCount / N) * 100).toFixed(2)}%)`);
  console.log(`  throughput: ${fmt(N / (total / 1000))} proofs/sec (single core, sequential)`);
  console.log(`  latency   : p50 ${sorted[Math.floor(sorted.length / 2)].toFixed(3)}ms · p95 ${pct(sorted, 95).toFixed(3)}ms · p99 ${pct(sorted, 99).toFixed(3)}ms\n`);
}

// ---- store micro-benchmarks -------------------------------------------------
{
  const store = new InMemoryNonceStore();
  const keys = Array.from({ length: N }, (_, i) => `demo-app:${i.toString(16).padStart(32, '0')}`);
  const t = performance.now();
  for (const k of keys) store.claimIfAbsent(k);
  const ms = performance.now() - t;
  console.log(`InMemoryNonceStore.claimIfAbsent: ${fmt(N / (ms / 1000))} claims/sec`);
}

{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pep-bench-'));
  try {
    const M = Math.min(N, 2000); // file store is fsync-bound by design
    const store = new FileNonceStore(path.join(dir, 'nonces.jsonl'));
    const keys = Array.from({ length: M }, (_, i) => `demo-app:${i.toString(16).padStart(32, '0')}`);
    const t = performance.now();
    for (const k of keys) store.claimIfAbsent(k);
    const ms = performance.now() - t;
    console.log(`FileNonceStore.claimIfAbsent    : ${fmt(M / (ms / 1000))} claims/sec (durable: lock + append + fsync per claim)`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

console.log('\nReproduce anywhere: npm run bench — numbers scale with single-core CPU speed.');
