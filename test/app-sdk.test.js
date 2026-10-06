import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createAppServer } from '../app/server.mjs';
import { parseProofUri } from '../src/sdk.js';

async function withServer(fn) {
  const server = createAppServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const base = `http://127.0.0.1:${port}`;
  try {
    await fn(base);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

const post = async (base, path, body) => {
  const r = await fetch(base + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body)
  });
  return { status: r.status, json: await r.json() };
};

test('GET /api/policies lists the frozen presets', async () => {
  await withServer(async (base) => {
    const r = await fetch(base + '/api/policies');
    assert.equal(r.status, 200);
    const json = await r.json();
    assert.ok(Array.isArray(json.presets) && json.presets.length >= 5);
    const names = new Set(json.presets.map((p) => p.name));
    assert.ok(names.has('merchant-verification-v1'));
    assert.ok(names.has('agent-payment-v1'));
    for (const p of json.presets) {
      assert.equal(p.version, 1);
      assert.equal(typeof p.rules, 'object');
    }
  });
});

test('POST /api/decide: ALLOW then replay DENY through shared verifier state', async () => {
  await withServer(async (base) => {
    const sample = await fetch(base + '/api/sample-proof');
    const { proof } = await sample.json();

    const first = await post(base, '/api/decide', { proof });
    assert.equal(first.status, 200);
    assert.equal(first.json.decision, 'ALLOW');
    assert.equal(first.json.binding, 'EPOCH_BOUND');

    const second = await post(base, '/api/decide', { proof });
    assert.equal(second.status, 200);
    assert.equal(second.json.decision, 'DENY');
    assert.equal(second.json.code, 'REPLAY_DETECTED');
  });
});

test('POST /api/decide accepts preset references and rejects unknown ones', async () => {
  await withServer(async (base) => {
    const sample = await fetch(base + '/api/sample-proof');
    const { proof } = await sample.json();

    // Fresh server process per test → fresh nonce state → ALLOW.
    const byName = await post(base, '/api/decide', { proof: JSON.parse(JSON.stringify(proof)), policy: 'reward-eligibility-v1' });
    assert.equal(byName.json.decision, 'ALLOW');

    const bad = await post(base, '/api/decide', { proof, policy: 'ghost-v1' });
    assert.equal(bad.status, 400);
    assert.match(bad.json.error, /unknown policy preset/);
  });
});

test('POST /api/verify-proof resolves {"preset":"..."} policies', async () => {
  await withServer(async (base) => {
    const issued = await post(base, '/api/passport-issue', {
      action_class: 'A', action_id: 'complete_transaction', weight: 100
    });
    const proof = issued.json.passport.proofs[0];
    const r = await post(base, '/api/verify-proof', {
      proof, policy: { preset: 'reward-eligibility-v1' }
    });
    assert.equal(r.status, 200);
    assert.equal(r.json.ok, true);
  });
});

test('/api/share returns a self-contained piproof:// URI that parses back', async () => {
  await withServer(async (base) => {
    const sample = await fetch(base + '/api/sample-proof');
    const { proof } = await sample.json();
    const shared = await post(base, '/api/share', { doc: proof });
    assert.equal(shared.status, 200);
    assert.match(shared.json.pi_proof_uri, /^piproof:\/\/v1\?p=/);
    const roundTripped = parseProofUri(shared.json.pi_proof_uri);
    assert.deepEqual(roundTripped, proof);
  });
});
