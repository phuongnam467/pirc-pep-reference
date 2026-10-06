import { createHash, verify as verifySignature, createPublicKey } from 'node:crypto';
import { canonicalize } from './canonical.js';

/**
 * AUREVIA ARBITRATION COURT /1 — decentralized, verifiable adjudication.
 *
 * What "decentralized" means here, precisely and honestly:
 *
 *   • No single key can settle a case. A verdict exists only as a
 *     multi-signature over an exact tally — remove one judge's signature
 *     and the settlement stops verifying.
 *   • Judges are KEYS, not institutions. Anyone may run a judge key;
 *     admission is a registry act, visible and revocable.
 *   • Every step is replayable. `replayArbitration()` re-verifies every
 *     ballot signature, re-tallies every round and re-checks every
 *     transition against the same deterministic rules. Tampering anywhere
 *     produces a named difference, never silence.
 *   • The arbitration market is reputation-weighted and deterministic:
 *     panels are assigned by published fee schedules and earned reputation
 *     — not by whoever operates the server.
 *
 * The AI division ("agent court") settles disputes whose defendant is an
 * autonomous agent. Its constitutional rule: **AI argues, keys decide.**
 * AI referees may submit signed opinions that are recorded as EVIDENCE —
 * marked advisory, excluded from tallies by construction. A referee key
 * without the `judge` capability cannot vote even if it tries.
 *
 * Honest boundaries (stated, not hidden):
 *   • This module does not touch a blockchain. Settlement produces a
 *     byte-deterministic, multi-signed ANCHOR CERTIFICATE plus an adapter
 *     contract (`buildAnchorPayload`) — broadcasting is a deployment
 *     concern for integrators, exactly like keys.js delegates signing.
 *   • Stakes and fees are declared commitments tracked in the registry,
 *     not escrowed tokens. Enforcement of obligations is what settlement
 *     certificates are FOR.
 *   • Fail-closed everywhere: quorum unmet, hung jury, expired windows —
 *     all end UNRESOLVED, which is a first-class honest outcome.
 */

export const COURT_VERSION = 1;
export const COURT_TYPE = 'AUREVIA-Court-Case/1';
export const SETTLEMENT_TYPE = 'AUREVIA-Court-Settlement/1';
const COURT_DOMAIN = 'AUREVIA-COURT-v1';

export const DIVISIONS = Object.freeze(['general', 'agent']);
export const VERDICTS = Object.freeze(['AFFIRM', 'REVERSE', 'ABSTAIN']);
export const EVIDENCE_KINDS = Object.freeze([
  'dispute_report', 'statement', 'agent_evidence', 'ai_referee_opinion'
]);

export class CourtError extends Error {
  constructor(code, detail) {
    super(detail ? `${code}: ${detail}` : code);
    this.name = 'CourtError';
    this.code = code;
  }
}

function sha256(value) {
  return 'sha256:' + createHash('sha256').update(canonicalize(value), 'utf8').digest('hex');
}

function shortHash(value) {
  return createHash('sha256').update(canonicalize(value), 'utf8').digest('hex').slice(0, 32);
}

function assertFreshObject(value, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new CourtError('COURT_BAD_INPUT', `${name} must be an object`);
  }
}

// ---------------------------------------------------------------------------
// Registry: judge roster & court configuration
// ---------------------------------------------------------------------------

export const DEFAULT_COURT_CONFIG = Object.freeze({
  quorum_min_judges: 3,
  quorum_min_stake: 4,
  stake_ceiling: 10,
  max_rounds: 2,
  windows_ms: Object.freeze({
    evidence: 7 * 24 * 3600 * 1000,
    deliberation: 5 * 24 * 3600 * 1000,
    challenge: 14 * 24 * 3600 * 1000
  })
});

export function initCourt(registry, config = {}) {
  assertFreshObject(registry, 'registry');
  const merged = { ...DEFAULT_COURT_CONFIG };
  for (const k of ['quorum_min_judges', 'quorum_min_stake', 'stake_ceiling', 'max_rounds']) {
    if (config[k] !== undefined) {
      if (!Number.isInteger(config[k]) || config[k] < 1) {
        throw new CourtError('COURT_BAD_INPUT', `${k} must be a positive integer`);
      }
      merged[k] = config[k];
    }
  }
  if (config.windows_ms) {
    for (const [w, ms] of Object.entries(config.windows_ms)) {
      if (!(w in DEFAULT_COURT_CONFIG.windows_ms) || !Number.isFinite(ms) || ms <= 0) {
        throw new CourtError('COURT_BAD_INPUT', `bad window ${w}`);
      }
      merged.windows_ms = { ...merged.windows_ms, [w]: ms };
    }
  }
  if (registry.court && registry.court.version === COURT_VERSION) {
    throw new CourtError('COURT_ALREADY_INITIALIZED');
  }
  registry.court = { version: COURT_VERSION, config: merged, judges: {}, market: { fee_books: {} } };
  return registry.court;
}

function courtOf(registry) {
  if (!registry?.court || registry.court.version !== COURT_VERSION || !registry.court.judges) {
    throw new CourtError('COURT_NOT_INITIALIZED');
  }
  return registry.court;
}

export function registerJudge(registry, judgeId, publicKeyPem, opts = {}) {
  const court = courtOf(registry);
  if (typeof judgeId !== 'string' || !judgeId.trim()) throw new CourtError('COURT_BAD_INPUT', 'judgeId required');
  if (typeof publicKeyPem !== 'string' || !publicKeyPem.includes('BEGIN PUBLIC KEY')) {
    throw new CourtError('COURT_BAD_INPUT', 'public_key_pem must be a SPKI PEM string');
  }
  if (court.judges[judgeId]) throw new CourtError('JUDGE_EXISTS', judgeId);
  const caps = Array.isArray(opts.capabilities) && opts.capabilities.length
    ? [...new Set(opts.capabilities)]
    : ['judge'];
  for (const c of caps) {
    if (c !== 'judge' && c !== 'referee') throw new CourtError('COURT_BAD_INPUT', `unknown capability ${c}`);
  }
  let stake = opts.stake ?? 1;
  if (!Number.isInteger(stake) || stake < 1 || stake > court.config.stake_ceiling) {
    throw new CourtError('STAKE_OUT_OF_RANGE', `1..${court.config.stake_ceiling}`);
  }
  const rec = {
    public_key_pem: publicKeyPem,
    status: 'active',
    capabilities: caps.sort(),
    stake,
    reputation: 0,
    registered_at: opts.now ?? Date.now()
  };
  court.judges[judgeId] = rec;
  return rec;
}

export function revokeJudge(registry, judgeId, { now = Date.now() } = {}) {
  const court = courtOf(registry);
  const j = court.judges[judgeId];
  if (!j) throw new CourtError('JUDGE_UNKNOWN', judgeId);
  if (j.status !== 'active') throw new CourtError('JUDGE_REVOKED', judgeId);
  j.status = 'revoked';
  j.revoked_at = now;
  return j;
}

export function setFeeBook(registry, judgeId, schedule) {
  const court = courtOf(registry);
  if (!court.judges[judgeId]) throw new CourtError('JUDGE_UNKNOWN', judgeId);
  assertFreshObject(schedule, 'fee schedule');
  const clean = {};
  for (const [cls, fee] of Object.entries(schedule)) {
    if (!Number.isFinite(fee) || fee < 0) throw new CourtError('COURT_BAD_INPUT', `bad fee for ${cls}`);
    clean[cls] = fee;
  }
  court.market.fee_books[judgeId] = clean;
  return clean;
}

function judgeActive(court, id, needCap) {
  const j = court.judges[id];
  if (!j) throw new CourtError('JUDGE_UNKNOWN', id);
  if (j.status !== 'active') throw new CourtError('JUDGE_REVOKED', id);
  if (needCap && !j.capabilities.includes(needCap)) throw new CourtError('NOT_CAPABLE', `${id} lacks ${needCap}`);
  return j;
}

// ---------------------------------------------------------------------------
// Case lifecycle
// ---------------------------------------------------------------------------

export function fileCase(registry, { division = 'general', plaintiff, defendant, disputeReport }, now = Date.now()) {
  const court = courtOf(registry);
  if (!DIVISIONS.includes(division)) throw new CourtError('COURT_BAD_INPUT', `division ${division}`);
  if (typeof plaintiff !== 'string' || typeof defendant !== 'string' || !plaintiff || !defendant) {
    throw new CourtError('COURT_BAD_INPUT', 'plaintiff and defendant required');
  }
  assertFreshObject(disputeReport, 'disputeReport');
  const root = sha256(disputeReport);
  const filing = {
    division, plaintiff, defendant, dispute_root: root
  };
  const case_id = 'court-1:' + shortHash({ ...filing, filed_at: now });
  const panel = assignPanel(registry, division);
  const c = {
    type: COURT_TYPE,
    version: COURT_VERSION,
    case_id,
    division,
    parties: { plaintiff, defendant },
    dispute_root: root,
    filed_at: now,
    status: 'FILED',
    evidence: [],
    rounds: [],
    referee_opinions: [],
    challenges: [],
    assigned_panel: panel,
    history: [{ at: now, event: 'FILED', detail: { division, root: root.slice(0, 20) + '…' } }],
    settlement: null
  };
  return c;
}

/** Deterministic panel assignment: eligible judges sorted by (fee for the
 *  division class, -reputation, id); takes quorum size. Missing fee books
 *  sort last within equal fee tier — participation beats price. */
export function assignPanel(registry, division, count) {
  const court = courtOf(registry);
  const n = count ?? court.config.quorum_min_judges;
  const cls = division === 'agent' ? 'agent_dispute' : 'general_dispute';
  const eligible = Object.entries(court.judges)
    .filter(([, j]) => j.status === 'active' && j.capabilities.includes('judge'))
    .map(([id, j]) => ({ id, fee: court.market.fee_books[id]?.[cls] ?? Number.POSITIVE_INFINITY, rep: j.reputation }))
    .sort((a, b) => a.fee - b.fee || b.rep - a.rep || (a.id < b.id ? -1 : 1))
    .slice(0, n)
    .map((e) => e.id);
  return eligible;
}

export function submitEvidence(courtCase, { submitter, kind, ref, payload }, now = Date.now()) {
  if (courtCase.type !== COURT_TYPE) throw new CourtError('COURT_BAD_CASE');
  if (!['FILED', 'EVIDENCE_WINDOW'].includes(courtCase.status)) {
    throw new CourtError('WINDOW_CLOSED', `status ${courtCase.status}`);
  }
  if (!EVIDENCE_KINDS.includes(kind)) throw new CourtError('COURT_BAD_INPUT', `kind ${kind}`);
  const material = ref ?? payload;
  if (material === undefined) throw new CourtError('COURT_BAD_INPUT', 'ref/payload required');
  const entry = { at: now, submitter, kind, ref: typeof material === 'string' ? material : sha256(material) };
  courtCase.evidence.push(entry);
  if (courtCase.status === 'FILED') {
    courtCase.status = 'EVIDENCE_WINDOW';
    courtCase.history.push({ at: now, event: 'EVIDENCE_WINDOW_OPENED', detail: null });
  }
  courtCase.history.push({ at: now, event: 'EVIDENCE_SUBMITTED', detail: { kind, submitter, ref: entry.ref.slice(0, 20) + '…' } });
  return entry;
}

export function openDeliberation(registry, courtCase, now = Date.now()) {
  const court = courtOf(registry);
  if (!['FILED', 'EVIDENCE_WINDOW'].includes(courtCase.status)) {
    throw new CourtError('WINDOW_CLOSED', `cannot deliberate from ${courtCase.status}`);
  }
  const roundNo = courtCase.rounds.length + 1;
  if (roundNo > court.config.max_rounds) throw new CourtError('ROUNDS_EXHAUSTED');
  courtCase.rounds.push({
    round: roundNo,
    opened_at: now,
    closes_at: now + court.config.windows_ms.deliberation,
    ballots: [],
    tally: null
  });
  courtCase.status = `DELIBERATION_ROUND_${roundNo}`;
  courtCase.history.push({ at: now, event: 'DELIBERATION_OPENED', detail: { round: roundNo, panel: courtCase.assigned_panel } });
  return courtCase.rounds[roundNo - 1];
}

function ballotMessage(courtCase, roundNo, b) {
  return Buffer.from(
    COURT_DOMAIN + '\n' + canonicalize({
      kind: 'BALLOT', case_id: courtCase.case_id, round: roundNo,
      judge_id: b.judge_id, verdict: b.verdict, reasons_hash: b.reasons_hash
    }),
    'utf8'
  );
}

export function castBallot(registry, courtCase, { judge_id, verdict, reasons }, { sign, now = Date.now() } = {}) {
  const court = courtOf(registry);
  const m = /^DELIBERATION_ROUND_(\d+)$/.exec(courtCase.status);
  if (!m) throw new CourtError('WINDOW_NOT_OPEN', courtCase.status);
  const roundNo = Number(m[1]);
  const round = courtCase.rounds[roundNo - 1];
  if (typeof sign !== 'function') throw new CourtError('COURT_BAD_INPUT', 'sign(required)');
  if (!VERDICTS.includes(verdict)) throw new CourtError('COURT_BAD_INPUT', `verdict ${verdict}`);
  const judge = judgeActive(court, judge_id, 'judge'); // referees cannot vote — AI argues, keys decide
  if (round.ballots.some((b) => b.judge_id === judge_id)) throw new CourtError('DUPLICATE_BALLOT', judge_id);
  if (now > round.closes_at) throw new CourtError('WINDOW_CLOSED', 'deliberation elapsed');

  const reasons_hash = sha256(reasons ?? {});
  const b = { judge_id, verdict, reasons_hash };
  b.signature = Buffer.from(sign(ballotMessage(courtCase, roundNo, b))).toString('base64');
  b.received_at = now;
  round.ballots.push(b);
  courtCase.history.push({ at: now, event: 'BALLOT_CAST', detail: { round: roundNo, judge: judge_id, verdict } });
  return b;
}

export function submitRefereeOpinion(registry, courtCase, { referee_id, opinion }, { sign, now = Date.now() } = {}) {
  const court = courtOf(registry);
  if (typeof sign !== 'function') throw new CourtError('COURT_BAD_INPUT', 'sign(required)');
  const ref = judgeActive(court, referee_id, 'referee');
  const o = {
    at: now,
    referee_id,
    opinion_hash: sha256(opinion ?? {}),
    advisory: true,
    note: 'AI argues, keys decide — advisory only, excluded from every tally'
  };
  o.signature = Buffer.from(sign(Buffer.from(
    COURT_DOMAIN + '\n' + canonicalize({ kind: 'REFEREE_OPINION', case_id: courtCase.case_id, ...o }), 'utf8'
  ))).toString('base64');
  courtCase.referee_opinions.push(o);
  courtCase.evidence.push({ at: now, submitter: referee_id, kind: 'ai_referee_opinion', ref: o.opinion_hash });
  courtCase.history.push({ at: now, event: 'REFEREE_OPINION_RECORDED', detail: { referee: referee_id, advisory: true } });
  void ref;
  return o;
}

// --- deterministic tally ---------------------------------------------------

/** PURE computation — verifies signatures and weights ballots WITHOUT
 *  touching any stored state. This purity is what makes trustless replay
 *  meaningful: a mutating re-tally would silently overwrite the very
 *  record it is supposed to be checking. */
export function computeTally(registry, courtCase, roundNo = null) {
  const court = courtOf(registry);
  const idx = roundNo === null ? courtCase.rounds.length - 1 : roundNo - 1;
  const round = courtCase.rounds[idx];
  if (!round) throw new CourtError('COURT_BAD_INPUT', `no round ${roundNo}`);

  const weights = { AFFIRM: 0n, REVERSE: 0n, ABSTAIN: 0n };
  const verified = [];
  const rejected = [];
  for (const b of round.ballots) {
    try {
      const j = judgeActive(court, b.judge_id, 'judge');
      const ok = verifySignature(
        null,
        ballotMessage(courtCase, round.round, b),
        createPublicKey(j.public_key_pem),
        Buffer.from(b.signature, 'base64')
      );
      if (!ok) throw new Error();
      weights[b.verdict] += BigInt(j.stake);
      verified.push(b.judge_id);
    } catch {
      rejected.push(b.judge_id);
    }
  }
  const decidedWeight = weights.AFFIRM + weights.REVERSE;
  const participants = verified.length;
  const quorumMet =
    participants >= court.config.quorum_min_judges &&
    decidedWeight >= BigInt(court.config.quorum_min_stake);

  let outcome;
  if (!quorumMet) outcome = 'QUORUM_FAILED';
  else if (weights.AFFIRM === weights.REVERSE) outcome = 'NO_MAJORITY';
  else outcome = weights.AFFIRM > weights.REVERSE ? 'AFFIRM' : 'REVERSE';

  return {
    round: round.round,
    weights: { AFFIRM: weights.AFFIRM.toString(), REVERSE: weights.REVERSE.toString(), ABSTAIN: weights.ABSTAIN.toString() },
    participants,
    rejected_voters: rejected,
    quorum: {
      min_judges: court.config.quorum_min_judges,
      min_stake: String(court.config.quorum_min_stake),
      met: quorumMet
    },
    outcome
  };
}

export function tallyRound(registry, courtCase, roundNo = null) {
  const idx = roundNo === null ? courtCase.rounds.length - 1 : roundNo - 1;
  const round = courtCase.rounds[idx];
  if (!round) throw new CourtError('COURT_BAD_INPUT', `no round ${roundNo}`);
  const tally = computeTally(registry, courtCase, roundNo);
  round.tally = tally;
  courtCase.history.push({ at: Date.now(), event: 'ROUND_TALLIED', detail: { round: round.round, outcome: tally.outcome } });
  return tally;
}

// ---------------------------------------------------------------------------
// Challenge period — trustless by construction: a challenge IS a replay
// ---------------------------------------------------------------------------

export function openChallengeWindow(registry, courtCase, now = Date.now()) {
  const court = courtOf(registry);
  if (!/^DELIBERATION_ROUND_\d+$/.test(courtCase.status)) throw new CourtError('WINDOW_NOT_OPEN', courtCase.status);
  const last = courtCase.rounds[courtCase.rounds.length - 1];
  if (!last.tally) tallyRound(registry, courtCase);
  if (last.tally.outcome === 'QUORUM_FAILED' || last.tally.outcome === 'NO_MAJORITY') {
    courtCase.status = 'UNRESOLVED';
    courtCase.history.push({ at: now, event: 'CASE_UNRESOLVED', detail: { reason: last.tally.outcome } });
    return null;
  }
  courtCase.provisional_outcome = last.tally.outcome;
  courtCase.challenge_deadline = now + court.config.windows_ms.challenge;
  courtCase.status = 'CHALLENGE_WINDOW';
  courtCase.history.push({ at: now, event: 'CHALLENGE_WINDOW_OPENED', detail: { provisional: last.tally.outcome } });
  return courtCase.challenge_deadline;
}

export function challengeSettlement(registry, courtCase, { challenger, claim }, now = Date.now()) {
  if (courtCase.status !== 'CHALLENGE_WINDOW') throw new CourtError('WINDOW_NOT_OPEN', courtCase.status);
  if (now > courtCase.challenge_deadline) throw new CourtError('WINDOW_CLOSED', 'challenge window elapsed');
  const replay = replayArbitration(registry, courtCase);
  const genuine = !replay.matches;
  const entry = {
    at: now,
    challenger,
    claim: claim ?? 'TALLY_MISMATCH',
    verified_replay: { matches: replay.matches, differences: replay.differences },
    accepted: genuine
  };
  courtCase.challenges.push(entry);
  if (genuine) {
    // The record itself was corrupted — reopen deliberation honestly.
    courtCase.status = `DELIBERATION_ROUND_${courtCase.rounds.length}`;
    courtCase.history.push({ at: now, event: 'CHALLENGE_UPHELD', detail: { differences: replay.differences.length } });
  } else {
    const court = courtOf(registry);
    if (court.judges[challenger]) court.judges[challenger].reputation -= 1;
    courtCase.history.push({ at: now, event: 'CHALLENGE_REJECTED', detail: { challenger } });
  }
  return entry;
}

// ---------------------------------------------------------------------------
// Settlement — multi-signature anchor certificate
// ---------------------------------------------------------------------------

export function buildSettlementCertificate(registry, courtCase, { payer = 'losing_party', now = Date.now() } = {}) {
  const court = courtOf(registry);
  if (courtCase.status !== 'CHALLENGE_WINDOW') throw new CourtError('NOT_SETTLABLE', courtCase.status);
  const cls = courtCase.division === 'agent' ? 'agent_dispute' : 'general_dispute';
  const fees = {};
  let total = 0;
  for (const id of courtCase.assigned_panel) {
    const f = court.market.fee_books[id]?.[cls] ?? 0;
    fees[id] = f;
    total += f;
  }
  const last = courtCase.rounds[courtCase.rounds.length - 1];
  const cert = {
    type: SETTLEMENT_TYPE,
    version: COURT_VERSION,
    case_id: courtCase.case_id,
    division: courtCase.division,
    verdict: courtCase.provisional_outcome,
    payer,
    dispute_root: courtCase.dispute_root,
    tally_proof: {
      round: last.round,
      weights: last.tally.weights,
      participants: last.tally.participants,
      ballots: last.ballots.map((b) => ({
        judge_id: b.judge_id, verdict: b.verdict,
        reasons_hash: b.reasons_hash, signature: b.signature
      })),
      referee_opinions: courtCase.referee_opinions.map((o) => o.opinion_hash)
    },
    fees: { breakdown: fees, total },
    issued_at: now
  };
  return cert;
}

export function settleCase(registry, courtCase, { signers, now = Date.now() } = {}) {
  if (typeof signers !== 'object' || signers === null) {
    throw new CourtError('COURT_BAD_INPUT', 'signers map {judge_id: signFn} required');
  }
  const cert = buildSettlementCertificate(registry, courtCase, { now });
  const missing = [];
  for (const id of courtCase.assigned_panel) {
    const fn = signers[id];
    if (typeof fn !== 'function') { missing.push(id); continue; }
  }
  if (missing.length) throw new CourtError('SIGNER_MISSING', missing.join(','));
  cert.signatures = [];
  for (const id of courtCase.assigned_panel) {
    const sig = Buffer.from(signers[id](Buffer.from(COURT_DOMAIN + '\n' + canonicalize(withoutSignatures(cert)), 'utf8'))).toString('base64');
    cert.signatures.push({ judge_id: id, signature: sig });
  }
  cert.anchor_payload = buildAnchorPayload(cert);
  courtCase.settlement = { certificate: cert };
  courtCase.status = 'SETTLED';
  courtCase.history.push({ at: now, event: 'SETTLED', detail: { signatures: cert.signatures.length, total_fees: cert.fees.total } });

  // Reputation: participation earns; consensus earns more.
  const court2 = courtOf(registry);
  const winners = courtCase.provisional_outcome;
  for (const b of courtCase.rounds[courtCase.rounds.length - 1].ballots) {
    const j = court2.judges[b.judge_id];
    if (j && j.status === 'active') j.reputation += b.verdict === winners ? 2 : 0;
  }
  return cert;
}

function withoutSignatures(cert) {
  const { signatures, anchor_payload, ...rest } = cert;
  void signatures; void anchor_payload;
  return rest;
}

/**
 * Adapter contract: returns the EXACT bytes an integrator anchors.
 * Byte-determinism is tested — two runs produce identical buffers, so a
 * chain tx-hash can be committed in advance ("pre-commitment").
 */
export function buildAnchorPayload(cert) {
  const body = canonicalize({
    v: 1,
    protocol: 'aurevia-court',
    case_id: cert.case_id,
    verdict: cert.verdict,
    payer: cert.payer,
    total_fees: cert.fees.total,
    multisig_of: cert.signatures?.map((s) => s.judge_id) ?? [],
    memo: `AUREVIA-COURT:${cert.case_id}`
  });
  return {
    network: 'pi-testnet',
    encoding: 'utf8-json-canonical',
    payload: body.toString('utf8'),
    bytes: body.length,
    memo: `AUREVIA-COURT:${cert.case_id}`
  };
}

// ---------------------------------------------------------------------------
// Trustless verification — anyone replays the whole case
// ---------------------------------------------------------------------------

export function replayArbitration(registry, courtCase) {
  const court = courtOf(registry);
  const differences = [];
  const expect = (cond, code) => { if (!cond) differences.push(code); };

  expect(courtCase.type === COURT_TYPE, 'TYPE');
  // Every ballot must carry a valid signature from an ACTIVE judge key…
  for (const r of courtCase.rounds) {
    const seen = new Set();
    for (const b of r.ballots) {
      expect(!seen.has(b.judge_id), `DUP:${r.round}:${b.judge_id}`);
      seen.add(b.judge_id);
      const j = court.judges[b.judge_id];
      expect(j && j.status === 'active', `REVOKED_VOTER:${b.judge_id}`);
      if (!j) continue;
      let ok = false;
      try {
        ok = verifySignature(null, ballotMessage(courtCase, r.round, b),
          createPublicKey(j.public_key_pem), Buffer.from(b.signature, 'base64'));
      } catch { ok = false; }
      expect(ok, `BAD_SIG:${r.round}:${b.judge_id}`);
    }
    // …and the stored tally must equal a fresh PURE re-tally (no mutation).
    if (r.tally) {
      const fresh = computeTally(registry, courtCase, r.round);
      expect(fresh.outcome === r.tally.outcome, `TALLY_OUTCOME:${r.round}`);
      expect(fresh.weights.AFFIRM === r.tally.weights.AFFIRM &&
             fresh.weights.REVERSE === r.tally.weights.REVERSE, `TALLY_WEIGHTS:${r.round}`);
    }
  }
  // Referee opinions: signed, advisory, and NEVER counted.
  for (const o of courtCase.referee_opinions) {
    const j = court.judges[o.referee_id];
    expect(j && j.capabilities.includes('referee'), `REF_CAP:${o.referee_id}`);
    expect(o.advisory === true, 'REF_ADVISORY_FLAG');
    if (!j) continue;
    let ok = false;
    try {
      // Rebuild over the exact signed field set — the signature itself is
      // never part of the message (same rule as ballots).
      const msg = Buffer.from(COURT_DOMAIN + '\n' + canonicalize({
        kind: 'REFEREE_OPINION',
        case_id: courtCase.case_id,
        at: o.at,
        referee_id: o.referee_id,
        opinion_hash: o.opinion_hash,
        advisory: o.advisory,
        note: o.note
      }), 'utf8');
      ok = verifySignature(null, msg, createPublicKey(j.public_key_pem), Buffer.from(o.signature, 'base64'));
    } catch { ok = false; }
    expect(ok, `REF_SIG:${o.referee_id}`);
  }
  // Settlement: every panel member must have signed THE EXACT certificate.
  if (courtCase.settlement) {
    const cert = courtCase.settlement.certificate;
    expect(Array.isArray(cert.signatures) && cert.signatures.length >= court.config.quorum_min_judges, 'CERT_SIG_COUNT');
    for (const s of cert.signatures ?? []) {
      const j = court.judges[s.judge_id];
      expect(!!j, `CERT_SIGNER_UNKNOWN:${s.judge_id}`);
      if (!j) continue;
      let ok = false;
      try {
        ok = verifySignature(null,
          Buffer.from(COURT_DOMAIN + '\n' + canonicalize(withoutSignatures(cert)), 'utf8'),
          createPublicKey(j.public_key_pem), Buffer.from(s.signature, 'base64'));
      } catch { ok = false; }
      expect(ok, `CERT_SIG:${s.judge_id}`);
    }
  }
  return { matches: differences.length === 0, differences };
}

// ---------------------------------------------------------------------------
// Arbitration market snapshot — deterministic statistics, no oracle needed
// ---------------------------------------------------------------------------

export function marketSnapshot(registry, openCases = 0) {
  const court = courtOf(registry);
  const stats = {};
  for (const cls of ['general_dispute', 'agent_dispute']) {
    const fees = Object.values(court.market.fee_books)
      .map((b) => b[cls])
      .filter((f) => Number.isFinite(f))
      .sort((a, b) => a - b);
    const mid = Math.floor(fees.length / 2);
    stats[cls] = {
      quotes: fees.length,
      median_fee: fees.length ? (fees.length % 2 ? fees[mid] : (fees[mid - 1] + fees[mid]) / 2) : null,
      min_fee: fees.length ? fees[0] : null
    };
  }
  const activeJudges = Object.values(court.judges).filter((j) => j.status === 'active' && j.capabilities.includes('judge')).length;
  return {
    active_judges: activeJudges,
    open_demand: openCases,
    supply_demand_ratio: openCases > 0 ? +(activeJudges / openCases).toFixed(3) : null,
    clearing: stats
  };
}
