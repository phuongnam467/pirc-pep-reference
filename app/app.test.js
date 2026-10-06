import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createAppServer, buildSnapshot } from './server.mjs';

test('buildSnapshot returns a fully verifiable dashboard snapshot', () => {
  const snap = buildSnapshot(1_755_860_000_000);

  assert.equal(snap.schema, 'PiRC1-TransparencyDashboard/1');
  assert.ok(snap.price_floor.p_floor_marginal > 0);
  assert.equal(snap.pool_health.healthy, true);
  assert.equal(snap.escrow_lock_status.verifiable, true);
  assert.equal(snap.escrow_lock_status.state, 'SIGNING_AUTHORITY_REVOKED');
  assert.ok(snap.engagement.leaderboard.length >= 3);

  const scores = snap.engagement.leaderboard.map((r) => r.score);
  assert.deepEqual([...scores].sort((a, b) => b - a), scores);
});

test('server serves index and snapshot endpoints', async () => {
  const server = createAppServer();
  await new Promise((r) => server.listen(0, r));
  const port = server.address().port;

  try {
    const html = await fetch(`http://127.0.0.1:${port}/`);
    assert.equal(html.status, 200);
    assert.match(await html.text(), /<title>AUREVIA/);

    const api = await fetch(`http://127.0.0.1:${port}/api/snapshot`);
    assert.equal(api.status, 200);
    const snap = await api.json();
    assert.equal(snap.schema, 'PiRC1-TransparencyDashboard/1');

    const missing = await fetch(`http://127.0.0.1:${port}/nope`);
    assert.equal(missing.status, 404);

    const manifest = await fetch(`http://127.0.0.1:${port}/manifest.webmanifest`);
    assert.equal(manifest.status, 200);
    assert.match(await manifest.text(), /"name": "AUREVIA"/);

    const icon = await fetch(`http://127.0.0.1:${port}/assets/icon.svg`);
    assert.equal(icon.status, 200);
    assert.match(icon.headers.get('content-type'), /svg/);

    const brand = await fetch(`http://127.0.0.1:${port}/assets/brand/identity-original.jpeg`);
    assert.equal(brand.status, 200);
    assert.match(brand.headers.get('content-type'), /jpeg/);

    const traversal = await fetch(`http://127.0.0.1:${port}/assets/../server.mjs`);
    assert.equal(traversal.status, 404);
  } finally {
    server.close();
  }
});

test('gateway: strict CSP, healthz, security headers and public registry export', async () => {
  const server = createAppServer();
  await new Promise((r) => server.listen(0, r));
  const port = server.address().port;
  const base = `http://127.0.0.1:${port}`;

  try {
    // healthz
    const health = await fetch(`${base}/healthz`);
    assert.equal(health.status, 200);
    assert.deepEqual(await health.json(), { ok: true });

    // gateway page with strict CSP
    const gw = await fetch(`${base}/gateway`);
    assert.equal(gw.status, 200);
    const csp = gw.headers.get('content-security-policy');
    assert.match(csp, /default-src 'none'/);
    assert.match(csp, /script-src 'self'/);
    assert.doesNotMatch(csp, /unsafe-inline/);

    // global security headers
    assert.equal(gw.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(gw.headers.get('x-frame-options'), 'DENY');
    assert.equal(gw.headers.get('referrer-policy'), 'no-referrer');

    // whitelisted module assets resolve; unknown ones do not
    const mod = await fetch(`${base}/gateway-src/offline-verifier.js`);
    assert.equal(mod.status, 200);
    assert.match(mod.headers.get('content-type'), /javascript/);
    const glue = await fetch(`${base}/gateway-src/gateway.app.mjs`);
    assert.equal(glue.status, 200);
    const css = await fetch(`${base}/gateway-src/gateway.css`);
    assert.equal(css.status, 200);
    const sneaky = await fetch(`${base}/gateway-src/verify.js`);
    assert.equal(sneaky.status, 404);
    const escape = await fetch(`${base}/gateway-src/..%2fserver.mjs`);
    assert.equal(escape.status, 404);

    // registry export: public keys + eligibility hashes only — no secrets exist there
    const reg = await (await fetch(`${base}/registry.json`)).json();
    assert.equal(reg.version, 1);
    const apps = Object.keys(reg.apps);
    assert.ok(apps.includes('demo-app'));
    for (const app of Object.values(reg.apps)) {
      for (const key of Object.values(app.keys)) {
        assert.match(key.public_key_pem, /BEGIN PUBLIC KEY/);
        assert.ok(!('private' in key));
      }
    }
    for (const hash of Object.keys(reg.eligible_users)) {
      assert.match(hash, /^h1:[A-Za-z0-9_-]{43}$/);
    }

    // end-to-end: sample proof verifies OFFLINE through the same module the browser runs
    const { verifyEventOffline } = await import('../src/offline-verifier.js');
    const sample = await (await fetch(`${base}/api/sample-proof`)).json();
    const r = verifyEventOffline(sample.proof.event, { registry: reg });
    assert.equal(r.ok, true);
    assert.equal(r.verifiedOffline, true);
  } finally {
    server.close();
  }
});

test('PiProof explorer endpoints verify, replay-catch and enforce policy', async () => {
  const server = createAppServer();
  await new Promise((r) => server.listen(0, r));
  const port = server.address().port;
  const base = `http://127.0.0.1:${port}`;

  try {
    const sample = await (await fetch(`${base}/api/sample-proof`)).json();
    assert.equal(sample.proof.type, 'PiProof');
    assert.match(sample.proof.registry_root, /^r1:[0-9a-f]{64}$/);

    const post = async (body) =>
      (
        await fetch(`${base}/api/verify-proof`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(body)
        })
      ).json();

    const good = await post({ proof: sample.proof });
    assert.equal(good.ok, true);
    const stepIds = good.steps.map((s) => s.id);
    assert.ok(stepIds.includes('SIGNATURE') && stepIds.includes('NONCE_REPLAY'));

    const replay = await post({ proof: sample.proof });
    assert.equal(replay.ok, false);
    assert.equal(replay.code, 'REPLAY_DETECTED');

    const tampered = structuredClone(sample.proof);
    tampered.event.weight = tampered.event.weight * 1000;
    const bad = await post({ proof: tampered });
    assert.equal(bad.ok, false);
    assert.equal(bad.code, 'INVALID_SIGNATURE');
    const sigStep = bad.steps.find((s) => s.id === 'SIGNATURE');
    assert.equal(sigStep.pass, false);

    const fresh = await (await fetch(`${base}/api/sample-proof`)).json();
    const policy = await post({ proof: fresh.proof, policy: { min_weight: 999 } });
    assert.equal(policy.ok, false);
    assert.equal(policy.code, 'POLICY');
    assert.equal(policy.policy.violations[0].rule, 'min_weight');

    const malformed = await fetch(`${base}/api/verify-proof`, { method: 'POST', body: '{oops' });
    assert.equal(malformed.status, 400);

    // observability: counters watched every verification above
    const metrics = await (await fetch(`${base}/api/metrics`)).json();
    assert.equal(metrics.schema, 'AUREVIA-Metrics/1');
    const pv = metrics.kinds.proof_verify;
    assert.equal(pv.total >= 3, true);
    assert.ok(pv.rejection_codes.REPLAY_DETECTED >= 1);
    assert.ok(pv.rejection_codes.INVALID_SIGNATURE >= 1);
    assert.equal(typeof pv.latency_ms.p50, 'number');

    const html = await (await fetch(base + '/')).text();
    assert.match(html, /PiProof Explorer/);
  } finally {
    server.close();
  }
});

test('share API issues short /p/<id> links that redirect to verifiable documents', async () => {
  const server = createAppServer();
  await new Promise((r) => server.listen(0, r));
  const port = server.address().port;
  const base = `http://127.0.0.1:${port}`;

  try {
    const sample = await (await fetch(`${base}/api/sample-passport`)).json();
    assert.equal(sample.passport.type, 'AUREVIA-Evidence-Passport');

    const checked = await (
      await fetch(`${base}/api/verify-passport`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ passport: sample.passport })
      })
    ).json();
    assert.equal(checked.ok, true);

    const shared = await fetch(`${base}/api/share`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ doc: sample.passport })
    });
    assert.equal(shared.status, 200);
    const { id } = await shared.json();
    assert.match(id, /^[0-9a-f]{12}$/);

    const redir = await fetch(`${base}/p/${id}`, { redirect: 'manual' });
    assert.equal(redir.status, 302);
    const loc = redir.headers.get('location');
    assert.match(loc, /^\/verify#p=[A-Za-z0-9_-]+$/);

    // the redirected fragment must decode back to the exact shared document
    const frag = loc.split('#p=')[1];
    const b64 = frag.replace(/-/g, '+').replace(/_/g, '/');
    const json = Buffer.from(b64, 'base64').toString('utf8');
    assert.deepEqual(JSON.parse(json), sample.passport);

    const missing = await fetch(`${base}/p/deadbeefdead`, { redirect: 'manual' });
    assert.equal(missing.status, 404);
    const malformedId = await fetch(`${base}/p/../../etc`, { redirect: 'manual' });
    assert.equal(malformedId.status, 404);

    const badType = await fetch(`${base}/api/share`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ doc: { type: 'NotAThing' } })
    });
    assert.equal(badType.status, 400);

    const malformed = await fetch(`${base}/api/share`, { method: 'POST', body: '{oops' });
    assert.equal(malformed.status, 400);

    const metrics = await (await fetch(`${base}/api/metrics`)).json();
    assert.ok(metrics.kinds.share.total >= 1);
    assert.ok(metrics.kinds.passport_verify.total >= 1);
  } finally {
    server.close();
  }
});

test('arbitration court: page CSP, roster state, full scenario settles with multi-sig + clean replay', async () => {
  const server = createAppServer();
  await new Promise((r) => server.listen(0, r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const page = await fetch(`${base}/court`);
    assert.equal(page.status, 200);
    const csp = page.headers.get('content-security-policy') ?? '';
    assert.match(csp, /default-src 'none'/);
    assert.ok(!csp.includes('unsafe-inline'));

    const state = await (await fetch(`${base}/api/court/state`)).json();
    assert.equal(state.config.version ?? 1, 1);
    assert.ok(state.judges['judge-ada']);
    assert.equal(state.judges['referee-tesla'].capabilities[0], 'referee');
    assert.ok(state.market.active_judges >= 3);

    const run = await (
      await fetch(`${base}/api/court/demo-case`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{}'
      })
    ).json();
    assert.equal(run.tally_outcome, 'AFFIRM');
    assert.equal(run.certificate.signatures.length, 3);
    assert.equal(run.summary.replay.matches, true);
    assert.deepEqual(run.summary.replay.differences, []);
    assert.equal(run.certificate.anchor_payload.network, 'pi-testnet');

    // the settled case must appear in the public state with a matching replay
    const st2 = await (await fetch(`${base}/api/court/state`)).json();
    const settled = st2.cases.find((c) => c.case_id === run.summary.case_id);
    assert.ok(settled);
    assert.equal(settled.status, 'SETTLED');
    assert.equal(settled.replay.matches, true);

    const missing = await fetch(`${base}/api/court/settle`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ case_id: 'court-1:nope' })
    });
    assert.equal(missing.status, 400);
  } finally {
    server.close();
  }
});
