import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createMetricsRegistry, timed } from '../src/observability.js';

test('snapshot shape: counters, code breakdown, percentiles, stable key order', () => {
  let now = 1_000;
  const m = createMetricsRegistry({ clock: () => now });

  m.record('proof_verify', { ok: true, durationMs: 0.1 });
  m.record('proof_verify', { ok: true, durationMs: 0.3 });
  m.record('proof_verify', { ok: false, code: 'INVALID_SIGNATURE', durationMs: 0.2 });
  m.record('dispute', { ok: true, code: 'VALID' });
  m.record('dispute', { ok: false, code: 'UNVERIFIABLE' });
  now = 61_000;

  const snap = m.snapshot();
  assert.equal(snap.schema, 'AUREVIA-Metrics/1');
  assert.equal(snap.uptime_ms, 60_000);

  assert.deepEqual(Object.keys(snap.kinds), ['dispute', 'proof_verify']); // sorted
  const pv = snap.kinds.proof_verify;
  assert.equal(pv.total, 3);
  assert.equal(pv.ok, 2);
  assert.equal(pv.fail, 1);
  assert.deepEqual(pv.rejection_codes, { INVALID_SIGNATURE: 1 });
  assert.equal(pv.latency_ms.samples, 3);
  assert.equal(pv.latency_ms.p50, 0.2);
  assert.equal(pv.latency_ms.p99, 0.3);
  assert.equal(snap.kinds.dispute.latency_ms.p50, null);

  // snapshot must be JSON-serializable and repeatable without mutation
  const again = m.snapshot();
  assert.deepEqual(again, snap);
});

test('latency ring buffer is capped (bounded memory under hostile load)', () => {
  const m = createMetricsRegistry();
  for (let i = 0; i < 25_000; i++) {
    m.record('proof_verify', { ok: true, durationMs: i % 7 + 0.001 });
  }
  const pv = m.snapshot().kinds.proof_verify;
  assert.equal(pv.latency_ms.samples, 10_000); // LATENCY_CAP
});

test('timed() wraps a sync fn: outcome, code, duration; throw path records THREW', () => {
  const m = createMetricsRegistry();

  const good = timed(m, 'op', () => ({ ok: true, code: null }));
  assert.equal(good.ok, true);

  assert.throws(() => timed(m, 'op', () => { throw new Error('boom'); }), /boom/);

  const snap = m.snapshot().kinds.op;
  assert.equal(snap.total, 2);
  assert.equal(snap.ok, 1);
  assert.equal(snap.fail, 1);
  assert.equal(snap.rejection_codes.THREW, 1);
  assert.equal(typeof snap.latency_ms.p50, 'number');
});

test('recording never throws into the caller (telemetry is fail-open)', () => {
  const m = createMetricsRegistry();
  // force internal failure paths via hostile inputs — record must still return
  assert.doesNotThrow(() => m.record('x'));
  assert.doesNotThrow(() => m.record('x', { durationMs: NaN }));
  assert.doesNotThrow(() => m.record('x', { code: 123, ok: undefined }));
});
