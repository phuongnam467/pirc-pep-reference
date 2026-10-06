import { createServer } from 'node:http';
import { randomBytes, sign as cryptoSign, createPrivateKey } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { makeWorld, SUITE_UID_SECRET } from '../src/attacks.js';
import { hashUid, newEvent, signEvent } from '../src/events.js';
import { InMemoryNonceStore } from '../src/nonces.js';
import { verifySignedEvent } from '../src/verify.js';
import { createRegistry, markEligible, registerApp, registerKey } from '../src/registry.js';
import { generateKeyPair, randomNonce } from '../src/keys.js';
import { createRevocationAttestation } from '../src/escrow.js';
import { assembleSnapshot } from '../src/dashboard.js';
import { toPiProof, verifyPiProof } from '../src/piproof.js';
import { createPassport, verifyPassport } from '../src/passport.js';
import { buildDisputeReport as disputeReport } from '../src/dispute.js';
import { createMetricsRegistry, timed } from '../src/observability.js';
import { listPolicyPresets, resolvePolicy } from '../src/policy-presets.js';
import { createVerifier, toProofUri } from '../src/sdk.js';
import {
  initCourt, registerJudge, setFeeBook, fileCase, submitEvidence,
  openDeliberation, castBallot, tallyRound, openChallengeWindow,
  settleCase, replayArbitration, marketSnapshot
} from '../src/court.js';

/** Resolve a request-supplied policy reference; throws on unknown presets. */
function effectivePolicy(ref) {
  return resolvePolicy(ref ?? null);
}

/**
 * Pi Transparency App — local preview server.
 *
 * Serves the single-page Transparency Dashboard and one JSON endpoint:
 *   GET /              → app/index.html
 *   GET /api/snapshot  → fresh deterministic snapshot assembled by src/dashboard.js
 *
 * The snapshot is regenerated per request from the same verified-event
 * pipeline used everywhere else in this repository. No chain access,
 * no external calls, no pricing data.
 */

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const DAY = 86_400_000;

// Long-lived verifier state for the PiProof Explorer: the registry epoch and
// the nonce store persist for the whole server lifetime, so a replayed proof
// is rejected on its second submission, exactly like a real deployment.
// Three independent issuers share this one epoch — cross-application proofs
// and agent evidence verify against the same trusted state.
const PROOF_WORLD = makeWorld();
markEligible(PROOF_WORLD.registry, hashUid('pioneer-alice', SUITE_UID_SECRET));
markEligible(PROOF_WORLD.registry, hashUid('pioneer-bob', SUITE_UID_SECRET));

const MARKET_KEY = generateKeyPair({ seed: Buffer.alloc(32, 0xab) });
const AGENT_KEY = generateKeyPair({ seed: Buffer.alloc(32, 0xcd) });
registerApp(PROOF_WORLD.registry, 'marketplace-demo');
registerKey(PROOF_WORLD.registry, 'marketplace-demo', 'mk-key-2026', MARKET_KEY.public_key_pem);
registerApp(PROOF_WORLD.registry, 'demo-agent-service');
registerKey(PROOF_WORLD.registry, 'demo-agent-service', 'ag-key-2026', AGENT_KEY.public_key_pem);

const ISSUER_KEYS = Object.freeze({
  'demo-app': { key_id: 'k-2026-active', private_key_pem: PROOF_WORLD.currentKey.private_key_pem },
  'marketplace-demo': { key_id: 'mk-key-2026', private_key_pem: MARKET_KEY.private_key_pem },
  'demo-agent-service': { key_id: 'ag-key-2026', private_key_pem: AGENT_KEY.private_key_pem }
});

const PROOF_NONCES = new InMemoryNonceStore();

// Process-local observability (v0.12): opt-in counters + latency summaries,
// exposed read-only at GET /api/metrics. Telemetry can never influence a
// verdict — it only watches.
const METRICS = createMetricsRegistry();

// Short public verification links (/p/<id> → /verify#p=<document>).
// Ephemeral by design: the mapping lives only in this process's memory and
// is capped, so nothing about users is persisted anywhere — privacy first.
const SHARE_LIMIT = 5_000;
const SHARE_MAP = new Map();
const SHARE_ID_RE = /^[0-9a-f]{12}$/;

// ---------------------------------------------------------------------------
// v0.18 — AUREVIA Arbitration Court: persistent in-process court world.
// Judge keys are deterministic (seeded) so restarts reproduce the roster.
// The server signs ballots ON BEHALF of judge keys for this demo host only —
// in a real deployment each judge key lives with its human/agent owner.
// ---------------------------------------------------------------------------
const COURT_REG = (() => {
  const reg = createRegistry();
  initCourt(reg);
  const privs = {};
  for (const [id, seed] of [['judge-ada', 0x11], ['judge-boole', 0x22], ['judge-cantor', 0x33]]) {
    const kp = generateKeyPair({ seed: Buffer.alloc(32, seed) });
    registerJudge(reg, id, kp.public_key_pem, { now: Date.now(), stake: 5 });
    setFeeBook(reg, id, {
      general_dispute: id === 'judge-ada' ? 150 : id === 'judge-cantor' ? 175 : 200,
      agent_dispute: id === 'judge-boole' ? 200 : id === 'judge-ada' ? 250 : 300
    });
    privs[id] = kp.private_key_pem;
  }
  const refereeKp = generateKeyPair({ seed: Buffer.alloc(32, 0x44) });
  registerJudge(reg, 'referee-tesla', refereeKp.public_key_pem, { now: Date.now(), capabilities: ['referee'] });
  privs['referee-tesla'] = refereeKp.private_key_pem;
  return { reg, privs };
})();

const COURT_SIGNERS = Object.fromEntries(Object.entries(COURT_REG.privs).map(([id, pem]) => [id,
  (msg) => cryptoSign(null, msg, createPrivateKey(pem)
)]));
const COURT_CASES = new Map();
const COURT_CASES_LIMIT = 200;

function courtSummary(c) {
  return {
    case_id: c.case_id,
    division: c.division,
    parties: c.parties,
    status: c.status,
    provisional_outcome: c.provisional_outcome ?? null,
    rounds: c.rounds.map((r) => ({ round: r.round, ballots: r.ballots.length, tally: r.tally })),
    referee_opinions: c.referee_opinions.length,
    settlement: c.settlement
      ? {
          verdict: c.settlement.certificate.verdict,
          signatures: c.settlement.certificate.signatures.length,
          total_fees: c.settlement.certificate.fees.total,
          anchor_payload: c.settlement.certificate.anchor_payload
        }
      : null,
    replay: replayArbitration(COURT_REG.reg, c),
    history: c.history
  };
}

function runCourtDemoCase({ plaintiff = 'buyer-alice', defendant = 'merchant-mall' } = {}) {
  const now = Date.now();
  const c = fileCase(COURT_REG.reg, {
    division: 'general', plaintiff, defendant,
    disputeReport: { type: 'AUREVIA-Dispute-Report', verdict: 'INVALID', subject: `order-${now % 100000}` }
  }, now);
  submitEvidence(c, { submitter: defendant, kind: 'statement', payload: { text: 'service delivered; logs attached' } }, now + 1);
  openDeliberation(COURT_REG.reg, c, now + 2);
  const votes = [['judge-ada', 'AFFIRM'], ['judge-boole', 'AFFIRM'], ['judge-cantor', 'REVERSE']];
  for (const [id, verdict] of votes) {
    castBallot(COURT_REG.reg, c, { judge_id: id, verdict, reasons: { basis: 'demo scenario' } }, { sign: COURT_SIGNERS[id], now: now + 3 });
  }
  const tally = tallyRound(COURT_REG.reg, c);
  openChallengeWindow(COURT_REG.reg, c, now + 4);
  const cert = settleCase(COURT_REG.reg, c, { signers: COURT_SIGNERS, now: now + 5 });
  COURT_CASES.set(c.case_id, c);
  return { summary: courtSummary(c), tally_outcome: tally.outcome, certificate: cert };
}
const b64u = (buf) => Buffer.from(buf).toString('base64')
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/** Read and parse a bounded JSON request body. */
async function readJsonBody(req) {
  let raw = '';
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 262_144) {
      throw Object.assign(new Error('body too large'), { code: 'BODY_TOO_LARGE' });
    }
  }
  return JSON.parse(raw || '{}');
}

export function makeSampleProof(now = Date.now()) {
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
  event.pioneer_uid_hash = hashUid('pioneer-alice', SUITE_UID_SECRET);
  const signed = signEvent(event, PROOF_WORLD.currentKey.private_key_pem);
  return toPiProof(signed, { registry: PROOF_WORLD.registry });
}

const ACTION_CATALOG = Object.freeze({
  A: ['complete_transaction', 'complete_task'],
  B: ['finish_kyc_flow'],
  C: ['daily_login']
});
const SUBJECT_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;

function issueSignedProof({ issuer = 'demo-app', actionClass, actionId, weight, pioneerUid }, now = Date.now()) {
  const issuerKey = ISSUER_KEYS[issuer];
  if (!issuerKey) throw new Error(`unknown issuer: ${issuer}`);
  const event = newEvent({
    app_id: issuer,
    key_id: issuerKey.key_id,
    action_class: actionClass,
    action_id: actionId,
    weight,
    pioneer_uid: 'x',
    uidSecret: SUITE_UID_SECRET,
    now
  });
  event.pioneer_uid_hash = hashUid(pioneerUid, SUITE_UID_SECRET);
  return toPiProof(signEvent(event, issuerKey.private_key_pem), {
    registry: PROOF_WORLD.registry
  });
}

export function makeSamplePassport(now = Date.now()) {
  const proofs = [
    issueSignedProof({ issuer: 'demo-app', actionClass: 'A', actionId: 'complete_transaction', weight: 50, pioneerUid: 'pioneer-alice' }, now),
    issueSignedProof({ issuer: 'marketplace-demo', actionClass: 'B', actionId: 'finish_kyc_flow', weight: 8, pioneerUid: 'pioneer-alice' }, now)
  ];
  return createPassport({ proofs, subject: 'alice-demo', createdAt: now });
}

const DEMO_HOLDERS = Object.freeze({
  'alice-demo': 'pioneer-alice',
  'bob-demo': 'pioneer-bob'
});

export function issuePassport({ action_class, action_id, weight, subject, issuer } = {}, now = Date.now()) {
  if (!ACTION_CATALOG[action_class]) {
    throw new Error('action_class must be one of A, B or C');
  }
  if (!ACTION_CATALOG[action_class].includes(action_id)) {
    throw new Error(`action_id "${String(action_id)}" is not offered by the demo issuer for class ${action_class}`);
  }
  if (issuer !== undefined && issuer !== null && issuer !== '' && !ISSUER_KEYS[issuer]) {
    throw new Error(`unknown issuer "${String(issuer)}" — demo issuers: ${Object.keys(ISSUER_KEYS).join(', ')}`);
  }
  const w = Number(weight);
  if (!Number.isSafeInteger(w) || w < 1 || w > 10000) {
    throw new Error('weight must be an integer between 1 and 10000');
  }
  if (subject !== undefined && subject !== null && subject !== '' &&
      (typeof subject !== 'string' || !SUBJECT_RE.test(subject))) {
    throw new Error('subject must match [A-Za-z0-9][A-Za-z0-9._:-]{0,63}');
  }
  const subj = subject === undefined || subject === null || subject === '' ? null : String(subject);
  const proof = issueSignedProof({
    issuer: issuer || 'demo-app',
    actionClass: action_class,
    actionId: action_id,
    weight: w,
    pioneerUid: DEMO_HOLDERS[subj] ?? 'pioneer-alice'
  }, now);
  return createPassport({ proofs: [proof], subject: subj, createdAt: now });
}

const AGENT_RE = /^[a-z0-9][a-z0-9_-]{0,31}$/;

export function issueAgentEvidence({ agent = 'alpha', task = 'data_labeling_47', weight = 10 } = {}, now = Date.now()) {
  if (typeof agent !== 'string' || !AGENT_RE.test(agent)) {
    throw new Error('agent must match [a-z0-9][a-z0-9_-]{0,31}');
  }
  if (typeof task !== 'string' || !AGENT_RE.test(task)) {
    throw new Error('task must match [a-z0-9][a-z0-9_-]{0,31}');
  }
  return issuePassport(
    { action_class: 'A', action_id: 'complete_task', weight, subject: `agent-${agent}`, issuer: 'demo-agent-service' },
    now
  );
}

export function buildDispute({ doc, policy } = {}) {
  return disputeReport({ doc, registry: PROOF_WORLD.registry, nonceStore: PROOF_NONCES, now: Date.now(), policy: policy ?? null });
}

export function verifySubmittedPassport(passport, policy) {
  return verifyPassport(passport, {
    registry: PROOF_WORLD.registry,
    nonceStore: PROOF_NONCES,
    now: Date.now(),
    policyOverride: policy ?? null,
    metrics: METRICS
  });
}

function buildWorld(now) {
  const world = makeWorld();

  const escrowOld = generateKeyPair({ seed: Buffer.alloc(32, 7) });
  const escrowController = generateKeyPair({ seed: Buffer.alloc(32, 9) });

  registerApp(world.registry, 'launchpad-escrow');
  registerKey(world.registry, 'launchpad-escrow', 'ctrl-v2', escrowController.public_key_pem);

  const attestation = createRevocationAttestation(
    {
      escrowId: 'tge-escrow-main',
      controllerKeyId: 'ctrl-v2',
      previousPublicKeyPem: escrowOld.public_key_pem,
      effectiveAt: now ?? Date.now(),
      anchor: 'demo-anchor:0000000000000000000000000000000000000000',
      nonce: randomNonce()
    },
    escrowController.private_key_pem
  );

  return { world, attestation };
}

function verifiedEntry(state, uidLabel, klass, actionId, t) {
  const hash = hashUid(uidLabel, SUITE_UID_SECRET);
  markEligible(state.world.registry, hash);
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
  const signed = signEvent(event, state.world.currentKey.private_key_pem);
  const verdict = verifySignedEvent(signed, {
    registry: state.world.registry,
    nonceStore: new InMemoryNonceStore(),
    now: t
  });
  if (!verdict.ok) throw new Error(`fixture event rejected: ${verdict.code}`);
  return { event: signed, verdict };
}

export function buildSnapshot(now = Date.now()) {
  const state = buildWorld(now);

  const entries = [
    verifiedEntry(state, 'pioneer-alice', 'A', 'complete_transaction', now - 6 * DAY),
    verifiedEntry(state, 'pioneer-alice', 'B', 'finish_kyc_flow', now - 4 * DAY),
    verifiedEntry(state, 'pioneer-alice', 'C', 'daily_login', now - 2 * DAY),
    verifiedEntry(state, 'pioneer-alice', 'C', 'daily_login', now - DAY),
    verifiedEntry(state, 'pioneer-bob', 'A', 'complete_transaction', now - DAY),
    verifiedEntry(state, 'pioneer-carol', 'C', 'daily_login', now - DAY),
    verifiedEntry(state, 'pioneer-dave', 'B', 'finish_kyc_flow', now - 3 * DAY)
  ];

  return assembleSnapshot({
    pool: {
      tokenReserve: 4_200_000,
      quoteReserve: 6_300_000,
      circulatingSupply: 12_500_000
    },
    invariantSnapshots: [
      { t: now - 14 * DAY, token_reserve: 3_900_000, quote_reserve: 5_850_000 },
      { t: now - 9 * DAY, token_reserve: 4_000_000, quote_reserve: 6_010_000 },
      { t: now - 5 * DAY, token_reserve: 4_100_000, quote_reserve: 6_150_000 },
      { t: now - 2 * DAY, token_reserve: 4_150_000, quote_reserve: 6_230_000 },
      { t: now, token_reserve: 4_200_000, quote_reserve: 6_300_000 }
    ],
    manifest: {
      complete_transaction: { class: 'A' },
      finish_kyc_flow: { class: 'B', multiplier: 0.8 },
      daily_login: { class: 'C' }
    },
    windowDays: 30,
    verifiedEntries: entries,
    attestation: state.attestation,
    registry: state.world.registry,
    now
  });
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.jpeg': 'image/jpeg',
  '.jpg': 'image/jpeg',
  '.png': 'image/png',
  '.webmanifest': 'application/manifest+json'
};

export function createAppServer() {
  return createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://localhost');

      // v0.17 security headers on every response — the gateway era.
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Referrer-Policy', 'no-referrer');
      res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
      res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
      res.setHeader('X-Frame-Options', 'DENY');

      if (url.pathname === '/healthz') {
        const body = JSON.stringify({ ok: true });
        res.writeHead(200, { 'content-type': MIME['.json'], 'cache-control': 'no-store' });
        res.end(body);
        return;
      }

      if (url.pathname === '/api/snapshot') {
        const body = JSON.stringify(buildSnapshot());
        res.writeHead(200, { 'content-type': MIME['.json'], 'cache-control': 'no-store' });
        res.end(body);
        return;
      }

      if (url.pathname === '/api/sample-proof') {
        const proof = makeSampleProof();
        const body = JSON.stringify({ proof });
        res.writeHead(200, { 'content-type': MIME['.json'], 'cache-control': 'no-store' });
        res.end(body);
        return;
      }

      if (url.pathname === '/api/verify-proof' && req.method === 'POST') {
        let raw = '';
        for await (const chunk of req) {
          raw += chunk;
          if (raw.length > 262_144) {
            res.writeHead(413, { 'content-type': MIME['.json'] });
            res.end('{"error":"proof too large"}');
            return;
          }
        }
        let parsed;
        try {
          parsed = JSON.parse(raw || '{}');
        } catch {
          res.writeHead(400, { 'content-type': MIME['.json'] });
          res.end('{"error":"invalid json"}');
          return;
        }
        let policyForCall;
        try {
          policyForCall = effectivePolicy(parsed.policy);
        } catch (err) {
          res.writeHead(400, { 'content-type': MIME['.json'] });
          res.end(JSON.stringify({ error: err.message }));
          return;
        }
        const result = verifyPiProof(parsed.proof ?? null, {
          registry: PROOF_WORLD.registry,
          nonceStore: PROOF_NONCES,
          now: Date.now(),
          policy: policyForCall,
          metrics: METRICS
        });
        const body = JSON.stringify(result);
        res.writeHead(200, { 'content-type': MIME['.json'], 'cache-control': 'no-store' });
        res.end(body);
        return;
      }

      if (url.pathname === '/api/sample-passport') {
        const passport = makeSamplePassport();
        const body = JSON.stringify({ passport });
        res.writeHead(200, { 'content-type': MIME['.json'], 'cache-control': 'no-store' });
        res.end(body);
        return;
      }

      if (url.pathname === '/api/passport-issue' && req.method === 'POST') {
        let raw = '';
        for await (const chunk of req) {
          raw += chunk;
          if (raw.length > 65_536) {
            res.writeHead(413, { 'content-type': MIME['.json'] });
            res.end('{"error":"request too large"}');
            return;
          }
        }
        let parsed;
        try {
          parsed = JSON.parse(raw || '{}');
        } catch {
          res.writeHead(400, { 'content-type': MIME['.json'] });
          res.end('{"error":"invalid json"}');
          return;
        }
        try {
          const passport = issuePassport(parsed);
          const body = JSON.stringify({ passport });
          res.writeHead(200, { 'content-type': MIME['.json'], 'cache-control': 'no-store' });
          res.end(body);
        } catch (err) {
          res.writeHead(400, { 'content-type': MIME['.json'] });
          res.end(JSON.stringify({ error: err.message }));
        }
        return;
      }

      if (url.pathname === '/api/verify-passport' && req.method === 'POST') {
        let raw = '';
        for await (const chunk of req) {
          raw += chunk;
          if (raw.length > 262_144) {
            res.writeHead(413, { 'content-type': MIME['.json'] });
            res.end('{"error":"passport too large"}');
            return;
          }
        }
        let parsed;
        try {
          parsed = JSON.parse(raw || '{}');
        } catch {
          res.writeHead(400, { 'content-type': MIME['.json'] });
          res.end('{"error":"invalid json"}');
          return;
        }
        let policyOverride;
        try {
          policyOverride = effectivePolicy(parsed.policy);
        } catch (err) {
          res.writeHead(400, { 'content-type': MIME['.json'] });
          res.end(JSON.stringify({ error: err.message }));
          return;
        }
        const result = verifySubmittedPassport(parsed.passport ?? null, policyOverride);
        const body = JSON.stringify(result);
        res.writeHead(200, { 'content-type': MIME['.json'], 'cache-control': 'no-store' });
        res.end(body);
        return;
      }

      if (url.pathname === '/api/agent-evidence' && req.method === 'POST') {
        let raw = '';
        for await (const chunk of req) {
          raw += chunk;
          if (raw.length > 16_384) {
            res.writeHead(413, { 'content-type': MIME['.json'] });
            res.end('{"error":"request too large"}');
            return;
          }
        }
        let parsed;
        try {
          parsed = JSON.parse(raw || '{}');
        } catch {
          res.writeHead(400, { 'content-type': MIME['.json'] });
          res.end('{"error":"invalid json"}');
          return;
        }
        try {
          const passport = issueAgentEvidence(parsed);
          const body = JSON.stringify({ passport });
          res.writeHead(200, { 'content-type': MIME['.json'], 'cache-control': 'no-store' });
          res.end(body);
        } catch (err) {
          res.writeHead(400, { 'content-type': MIME['.json'] });
          res.end(JSON.stringify({ error: err.message }));
        }
        return;
      }

      if (url.pathname === '/api/dispute' && req.method === 'POST') {
        let raw = '';
        for await (const chunk of req) {
          raw += chunk;
          if (raw.length > 262_144) {
            res.writeHead(413, { 'content-type': MIME['.json'] });
            res.end('{"error":"document too large"}');
            return;
          }
        }
        let parsed;
        try {
          parsed = JSON.parse(raw || '{}');
        } catch {
          res.writeHead(400, { 'content-type': MIME['.json'] });
          res.end('{"error":"invalid json"}');
          return;
        }
        const report = buildDispute({ doc: parsed.doc ?? null, policy: parsed.policy ?? null });
        METRICS.record('dispute', {
          ok: report.verdict === 'VALID',
          code: report.verdict
        });
        const body = JSON.stringify(report);
        res.writeHead(200, { 'content-type': MIME['.json'], 'cache-control': 'no-store' });
        res.end(body);
        return;
      }

      if (url.pathname === '/api/policies') {
        const body = JSON.stringify({ presets: listPolicyPresets() });
        res.writeHead(200, { 'content-type': MIME['.json'], 'cache-control': 'no-store' });
        res.end(body);
        return;
      }

      // The Proof Button backend: one call, deterministic ALLOW | DENY.
      // Shares the Explorer's nonce state, so replays are caught everywhere.
      if (url.pathname === '/api/decide' && req.method === 'POST') {
        let raw = '';
        for await (const chunk of req) {
          raw += chunk;
          if (raw.length > 262_144) {
            res.writeHead(413, { 'content-type': MIME['.json'] });
            res.end('{"error":"document too large"}');
            return;
          }
        }
        let parsed;
        try {
          parsed = JSON.parse(raw || '{}');
        } catch {
          res.writeHead(400, { 'content-type': MIME['.json'] });
          res.end('{"error":"invalid json"}');
          return;
        }
        const doc = parsed.proof ?? parsed.passport ?? parsed.doc ?? null;
        let policyRef;
        try {
          policyRef = effectivePolicy(parsed.policy);
        } catch (err) {
          res.writeHead(400, { 'content-type': MIME['.json'] });
          res.end(JSON.stringify({ error: err.message }));
          return;
        }
        const verifier = createVerifier({ registry: PROOF_WORLD.registry, nonceStore: PROOF_NONCES, metrics: METRICS });
        const decision = verifier.decide(doc, { policy: parsed.policy ?? null });
        METRICS.record('decide', { ok: decision.ok, code: decision.code ?? decision.decision });
        const body = JSON.stringify(decision);
        res.writeHead(200, { 'content-type': MIME['.json'], 'cache-control': 'no-store' });
        res.end(body);
        return;
      }

      if (url.pathname === '/api/metrics') {
        const body = JSON.stringify(METRICS.snapshot());
        res.writeHead(200, { 'content-type': MIME['.json'], 'cache-control': 'no-store' });
        res.end(body);
        return;
      }

      if (url.pathname === '/api/share' && req.method === 'POST') {
        let raw = '';
        for await (const chunk of req) {
          raw += chunk;
          if (raw.length > 262_144) {
            res.writeHead(413, { 'content-type': MIME['.json'] });
            res.end('{"error":"document too large"}');
            return;
          }
        }
        let parsed;
        try {
          parsed = JSON.parse(raw || '{}');
        } catch {
          res.writeHead(400, { 'content-type': MIME['.json'] });
          res.end('{"error":"invalid json"}');
          return;
        }
        const doc = parsed.doc ?? null;
        if (!doc || typeof doc !== 'object' ||
            (doc.type !== 'PiProof' && doc.type !== 'AUREVIA-Evidence-Passport')) {
          res.writeHead(400, { 'content-type': MIME['.json'] });
          res.end('{"error":"doc must be a PiProof or AUREVIA-Evidence-Passport"}');
          return;
        }
        const id = randomBytes(6).toString('hex');
        if (SHARE_MAP.size >= SHARE_LIMIT) {
          SHARE_MAP.delete(SHARE_MAP.keys().next().value);
        }
        SHARE_MAP.set(id, doc);
        METRICS.record('share', { ok: true });
        const payload = { id };
        if (doc.type === 'PiProof' || doc.type === 'AUREVIA-Evidence-Passport') {
          try {
            payload.pi_proof_uri = toProofUri(doc);
          } catch { /* uri is best-effort; the short link still works */ }
        }
        const body = JSON.stringify(payload);
        res.writeHead(200, { 'content-type': MIME['.json'], 'cache-control': 'no-store' });
        res.end(body);
        return;
      }

      if (url.pathname.startsWith('/p/')) {
        const id = url.pathname.slice(3);
        if (!SHARE_ID_RE.test(id) || !SHARE_MAP.has(id)) {
          res.writeHead(404, { 'content-type': MIME['.json'] });
          res.end('{"error":"share link not found — links are ephemeral"}');
          return;
        }
        const target = '/verify#p=' + b64u(JSON.stringify(SHARE_MAP.get(id)));
        res.writeHead(302, { location: target, 'cache-control': 'no-store' });
        res.end();
        return;
      }

      // ------------------------------------------------------------------
      // v0.18 — AUREVIA Arbitration Court API.
      // Demo authority note: this host holds the judge keys to make the
      // lifecycle clickable; a real deployment keeps each key with its
      // owner and collects signed ballots instead.
      // ------------------------------------------------------------------
      if (url.pathname === '/api/court/state') {
        res.writeHead(200, { 'content-type': MIME['.json'], 'cache-control': 'no-store' });
        res.end(JSON.stringify({
          config: COURT_REG.reg.court.config,
          judges: Object.fromEntries(Object.entries(COURT_REG.reg.court.judges).map(([id, j]) => [id, {
            capabilities: j.capabilities, stake: j.stake, reputation: j.reputation, status: j.status
          }])),
          market: marketSnapshot(COURT_REG.reg, COURT_CASES.size),
          cases: [...COURT_CASES.values()].map(courtSummary)
        }, null, 2));
        return;
      }

      if (url.pathname === '/api/court/demo-case' && req.method === 'POST') {
        try {
          const body = await readJsonBody(req);
          const run = runCourtDemoCase(body ?? {});
          res.writeHead(200, { 'content-type': MIME['.json'], 'cache-control': 'no-store' });
          res.end(JSON.stringify(run, null, 2));
        } catch (e) {
          res.writeHead(400, { 'content-type': MIME['.json'] });
          res.end(JSON.stringify({ error: e.code ?? e.message }));
        }
        return;
      }

      if (url.pathname === '/api/court/file' && req.method === 'POST') {
        try {
          const body = await readJsonBody(req);
          const now = Date.now();
          const c = fileCase(COURT_REG.reg, {
            division: body.division === 'agent' ? 'agent' : 'general',
            plaintiff: String(body.plaintiff ?? 'anonymous-plaintiff').slice(0, 64),
            defendant: String(body.defendant ?? 'anonymous-defendant').slice(0, 64),
            disputeReport: { type: 'AUREVIA-Dispute-Report', verdict: 'INVALID', subject: String(body.subject ?? '').slice(0, 64) }
          }, now);
          if (body.evidence) submitEvidence(c, { submitter: c.parties.plaintiff, kind: 'statement', payload: { text: String(body.evidence).slice(0, 500) } }, now + 1);
          openDeliberation(COURT_REG.reg, c, now + 2);
          COURT_CASES.set(c.case_id, c);
          if (COURT_CASES.size > COURT_CASES_LIMIT) {
            COURT_CASES.delete(COURT_CASES.keys().next().value);
          }
          res.writeHead(200, { 'content-type': MIME['.json'], 'cache-control': 'no-store' });
          res.end(JSON.stringify({ case_id: c.case_id, summary: courtSummary(c) }, null, 2));
        } catch (e) {
          res.writeHead(400, { 'content-type': MIME['.json'] });
          res.end(JSON.stringify({ error: e.code ?? e.message }));
        }
        return;
      }

      if (url.pathname === '/api/court/ballot' && req.method === 'POST') {
        try {
          const body = await readJsonBody(req);
          const c = COURT_CASES.get(String(body.case_id ?? ''));
          if (!c) throw Object.assign(new Error('CASE_UNKNOWN'), { code: 'CASE_UNKNOWN' });
          const signFn = COURT_SIGNERS[String(body.judge_id)];
          if (!signFn) throw Object.assign(new Error('JUDGE_UNKNOWN'), { code: 'JUDGE_UNKNOWN' });
          castBallot(COURT_REG.reg, c, {
            judge_id: String(body.judge_id),
            verdict: ['AFFIRM', 'REVERSE', 'ABSTAIN'].includes(body.verdict) ? body.verdict : 'ABSTAIN',
            reasons: { basis: String(body.reasons ?? 'panel deliberation').slice(0, 200) }
          }, { sign: signFn });
          // Auto-tally once every panel judge has voted.
          let tally = null;
          if (c.rounds[c.rounds.length - 1].ballots.length >= COURT_REG.reg.court.config.quorum_min_judges) {
            tally = tallyRound(COURT_REG.reg, c);
            if (tally.outcome !== 'QUORUM_FAILED' && tally.outcome !== 'NO_MAJORITY') {
              openChallengeWindow(COURT_REG.reg, c);
            } else {
              openChallengeWindow(COURT_REG.reg, c); // resolves honestly to UNRESOLVED
            }
          }
          res.writeHead(200, { 'content-type': MIME['.json'], 'cache-control': 'no-store' });
          res.end(JSON.stringify({ summary: courtSummary(c), tally }, null, 2));
        } catch (e) {
          res.writeHead(400, { 'content-type': MIME['.json'] });
          res.end(JSON.stringify({ error: e.code ?? e.message }));
        }
        return;
      }

      if (url.pathname === '/api/court/settle' && req.method === 'POST') {
        try {
          const body = await readJsonBody(req);
          const c = COURT_CASES.get(String(body.case_id ?? ''));
          if (!c) throw Object.assign(new Error('CASE_UNKNOWN'), { code: 'CASE_UNKNOWN' });
          const cert = settleCase(COURT_REG.reg, c, { signers: COURT_SIGNERS });
          res.writeHead(200, { 'content-type': MIME['.json'], 'cache-control': 'no-store' });
          res.end(JSON.stringify({ certificate: cert, summary: courtSummary(c) }, null, 2));
        } catch (e) {
          res.writeHead(400, { 'content-type': MIME['.json'] });
          res.end(JSON.stringify({ error: e.code ?? e.message }));
        }
        return;
      }

      if (url.pathname === '/court' || url.pathname === '/court.html') {
        const html = await readFile(path.join(ROOT, 'court.html'));
        res.writeHead(200, {
          'content-type': MIME['.html'],
          'content-security-policy':
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"
        });
        res.end(html);
        return;
      }

      if (url.pathname === '/verify' || url.pathname === '/verify.html') {
        const html = await readFile(path.join(ROOT, 'verify.html'));
        res.writeHead(200, { 'content-type': MIME['.html'] });
        res.end(html);
        return;
      }

      // ------------------------------------------------------------------
      // v0.17 — public offline verification gateway (privacy phase).
      // The browser fetches only this PUBLIC registry export and verifies
      // the document locally; the document itself never reaches any server.
      // ------------------------------------------------------------------
      const GATEWAY_SRC_WHITELIST = Object.freeze({
        'canonical.js': path.join(path.dirname(ROOT), 'src', 'canonical.js'),
        'constants.js': path.join(path.dirname(ROOT), 'src', 'constants.js'),
        'schema.js': path.join(path.dirname(ROOT), 'src', 'schema.js'),
        'registry.js': path.join(path.dirname(ROOT), 'src', 'registry.js'),
        'web-ed25519.js': path.join(path.dirname(ROOT), 'src', 'web-ed25519.js'),
        'offline-verifier.js': path.join(path.dirname(ROOT), 'src', 'offline-verifier.js'),
        'gateway.app.mjs': path.join(ROOT, 'gateway.app.mjs'),
        'gateway.css': path.join(ROOT, 'gateway.css'),
        'court.app.mjs': path.join(ROOT, 'court.app.mjs'),
        'court.css': path.join(ROOT, 'court.css')
      });

      if (url.pathname === '/registry.json') {
        const pub = {
          version: PROOF_WORLD.registry.version,
          apps: PROOF_WORLD.registry.apps,
          eligible_users: PROOF_WORLD.registry.eligible_users
        };
        res.writeHead(200, { 'content-type': MIME['.json'], 'cache-control': 'no-store' });
        res.end(JSON.stringify(pub, null, 2));
        return;
      }

      if (url.pathname.startsWith('/gateway-src/')) {
        const name = url.pathname.slice('/gateway-src/'.length);
        const file = GATEWAY_SRC_WHITELIST[name];
        if (!file) {
          res.writeHead(404, { 'content-type': MIME['.json'] });
          res.end('{"error":"not found"}');
          return;
        }
        const body = await readFile(file);
        res.writeHead(200, {
          'content-type': name.endsWith('.css') ? MIME['.css'] : MIME['.js'],
          'cache-control': 'no-store'
        });
        res.end(body);
        return;
      }

      if (url.pathname === '/gateway') {
        const html = await readFile(path.join(ROOT, 'gateway.html'));
        res.writeHead(200, {
          'content-type': MIME['.html'],
          // strict CSP: no inline script, no remote origins, nothing framed
          'content-security-policy':
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"
        });
        res.end(html);
        return;
      }

      if (url.pathname === '/snapshot.json') {
        try {
          const snap = await readFile(path.join(ROOT, 'snapshot.json'));
          res.writeHead(200, { 'content-type': MIME['.json'] });
          res.end(snap);
        } catch {
          res.writeHead(404, { 'content-type': 'application/json' });
          res.end('{"error":"static snapshot not generated — run npm run gen:snapshot"}');
        }
        return;
      }

      if (url.pathname === '/' || url.pathname === '/index.html') {
        const html = await readFile(path.join(ROOT, 'index.html'));
        res.writeHead(200, { 'content-type': MIME['.html'] });
        res.end(html);
        return;
      }

      if (url.pathname === '/manifest.webmanifest') {
        const mf = await readFile(path.join(ROOT, 'manifest.webmanifest'));
        res.writeHead(200, { 'content-type': MIME['.json'] });
        res.end(mf);
        return;
      }

      if (url.pathname.startsWith('/assets/')) {
        const rel = url.pathname.slice('/assets/'.length);

        if (!/^[\w./-]+$/.test(rel) || rel.includes('..')) {
          res.writeHead(404, { 'content-type': 'application/json' });
          res.end('{"error":"not found"}');
          return;
        }

        const asset = await readFile(path.join(ROOT, 'assets', rel));
        const ext = path.extname(rel).toLowerCase();
        res.writeHead(200, { 'content-type': MIME[ext] || 'application/octet-stream' });
        res.end(asset);
        return;
      }

      res.writeHead(404, { 'content-type': 'application/json' });
      res.end('{"error":"not found"}');
    } catch (err) {
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    }
  });
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);

if (isMain) {
  const port = Number(process.env.PORT || 8787);
  createAppServer().listen(port, () => {
    console.log(`Pi Transparency App → http://localhost:${port}`);
  });
}
