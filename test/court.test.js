import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  initCourt, registerJudge, revokeJudge, setFeeBook,
  fileCase, submitEvidence, openDeliberation, castBallot,
  submitRefereeOpinion, tallyRound, openChallengeWindow,
  challengeSettlement, settleCase, replayArbitration,
  buildAnchorPayload, marketSnapshot, assignPanel, CourtError
} from '../src/court.js';
import { generateKeyPairSync, sign as edSign, createPublicKey, verify as edVerify } from 'node:crypto';
import { createRegistry } from '../src/registry.js';
import { canonicalize } from '../src/canonical.js';

const T0 = 1_750_000_000_000;
const DAY = 24 * 3600 * 1000;

function mkJudge(id, opts = {}) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const signFn = (msg) => edSign(null, msg, privateKey);
  return { id, pem: publicKey.export({ type: 'spki', format: 'pem' }), signFn };
}

// Plain judges carry stake 5 so the default quorum_min_stake (4) is met.
function makeCourt(judges = []) {
  const reg = createRegistry();
  initCourt(reg);
  const keys = {};
  for (const j of judges) {
    const spec = typeof j === 'string' ? { id: j, stake: 5 } : { stake: 5, ...j };
    const k = mkJudge(spec.id);
    registerJudge(reg, k.id, k.pem, {
      now: T0,
      stake: spec.stake,
      capabilities: spec.capabilities
    });
    keys[k.id] = k.signFn;
  }
  return { reg, keys };
}

function signerMap(keys) {
  const m = {};
  for (const [id, fn] of Object.entries(keys)) m[id] = fn;
  return m;
}

function runGeneralCase(reg, keys) {
  const report = { type: 'AUREVIA-Dispute-Report', verdict: 'INVALID', chain: [] };
  const c = fileCase(reg, { plaintiff: 'buyer', defendant: 'merchant', disputeReport: report }, T0);
  submitEvidence(c, { submitter: 'defendant', kind: 'statement', payload: { text: 'was valid' } }, T0 + 1000);
  openDeliberation(reg, c, T0 + 2000);
  for (const [id, verdict] of [['j-A', 'AFFIRM'], ['j-B', 'AFFIRM'], ['j-C', 'REVERSE']]) {
    castBallot(reg, c, { judge_id: id, verdict, reasons: { r: id } }, { sign: keys[id], now: T0 + 3000 });
  }
  return c;
}

test('court: judge roster governance — stakes, capabilities, duplicates, revocation', () => {
  const { reg } = makeCourt();
  assert.throws(() => registerJudge(reg, 'x', 'not-a-pem'), /COURT_BAD_INPUT/);
  assert.throws(() => setFeeBook(reg, 'ghost', { general_dispute: 1 }), /JUDGE_UNKNOWN/);

  const k = mkJudge('j-x');
  assert.throws(() => registerJudge(reg, 'j-x', k.pem, { now: T0, stake: 99 }), /STAKE_OUT_OF_RANGE/); // no silent clamping
  registerJudge(reg, 'j-x', k.pem, { now: T0, stake: 10 });
  assert.equal(reg.court.judges['j-x'].stake, 10);

  assert.throws(() => initCourt(reg), /COURT_ALREADY_INITIALIZED/);
  revokeJudge(reg, 'j-x', { now: T0 + 1 });
  assert.throws(() => revokeJudge(reg, 'j-x', { now: T0 + 2 }), /JUDGE_REVOKED/);
});

test('court: full general lifecycle — evidence → ballots → weighted tally → challenge → multi-sig settlement', async () => {
  const { reg, keys } = makeCourt(['j-A', 'j-B', 'j-C']);
  for (const [id, f] of [['j-A', 150], ['j-B', 200], ['j-C', 200]]) setFeeBook(reg, id, { general_dispute: f });

  const c = runGeneralCase(reg, keys);
  assert.equal(c.status, 'DELIBERATION_ROUND_1');

  // Weighted: A(5)+B(5)=10 AFFIRM vs C(5) REVERSE → AFFIRM wins on weight.
  const tally = tallyRound(reg, c);
  assert.equal(tally.outcome, 'AFFIRM');
  assert.equal(tally.weights.AFFIRM, '10');
  assert.equal(tally.weights.REVERSE, '5');
  assert.equal(tally.quorum.met, true);

  openChallengeWindow(reg, c, T0 + 4000);
  assert.equal(c.status, 'CHALLENGE_WINDOW');

  // An invalid challenge costs reputation; the record stays consistent.
  const beforeRep = reg.court.judges['j-C'].reputation;
  challengeSettlement(reg, c, { challenger: 'j-C', claim: 'TALLY_MISMATCH' }, T0 + 5000);
  assert.equal(c.status, 'CHALLENGE_WINDOW'); // replay matched — no reopen
  assert.equal(reg.court.judges['j-C'].reputation, beforeRep - 1);

  const cert = settleCase(reg, c, { signers: signerMap(keys), now: T0 + 6000 });
  assert.equal(c.status, 'SETTLED');
  assert.equal(cert.verdict, 'AFFIRM');
  assert.equal(cert.fees.total, 550); // integer fee units — canonical-safe
  assert.equal(cert.signatures.length, 3);
  assert.equal(cert.anchor_payload.memo, `AUREVIA-COURT:${c.case_id}`);

  const replay = replayArbitration(reg, c);
  assert.deepEqual(replay, { matches: true, differences: [] });
});

test('court: trustless verification catches tampering — flipped ballot, dropped settlement signature', async () => {
  const { reg, keys } = makeCourt(['j-A', 'j-B', 'j-C']);
  const c = runGeneralCase(reg, keys);
  openChallengeWindow(reg, c, T0 + 4000);
  settleCase(reg, c, { signers: signerMap(keys), now: T0 + 6000 });

  // Adversary flips one stored ballot's verdict after the fact
  // (B "voted" REVERSE): signature breaks AND the tally flips.
  const evil = JSON.parse(JSON.stringify(c));
  evil.rounds[0].ballots[1].verdict = 'REVERSE';
  let rep = replayArbitration(reg, evil);
  assert.equal(rep.matches, false);
  assert.ok(rep.differences.some((d) => d.startsWith('BAD_SIG')));
  assert.ok(rep.differences.some((d) => d.startsWith('TALLY_OUTCOME')));

  // Adversary strips a settlement signature — certificate stops verifying.
  const stripped = JSON.parse(JSON.stringify(c));
  stripped.settlement.certificate.signatures.pop();
  rep = replayArbitration(reg, stripped);
  assert.equal(rep.matches, false);
  assert.ok(rep.differences.includes('CERT_SIG_COUNT'));
});

test('court: fail-closed honesty — quorum failure and hung jury end UNRESOLVED', () => {
  const { reg, keys } = makeCourt(['j-A', 'j-B', 'j-C']);
  const report = { type: 'AUREVIA-Dispute-Report', verdict: 'INVALID', chain: [] };
  const c = fileCase(reg, { plaintiff: 'buyer', defendant: 'merchant', disputeReport: report }, T0);
  openDeliberation(reg, c, T0);
  // Only two of the three required judges ever vote.
  castBallot(reg, c, { judge_id: 'j-A', verdict: 'AFFIRM', reasons: {} }, { sign: keys['j-A'], now: T0 + 1000 });
  castBallot(reg, c, { judge_id: 'j-B', verdict: 'AFFIRM', reasons: {} }, { sign: keys['j-B'], now: T0 + 1000 });
  const tally = tallyRound(reg, c);
  assert.equal(tally.outcome, 'QUORUM_FAILED');
  assert.equal(tally.quorum.met, false);
  openChallengeWindow(reg, c, T0 + 4000);
  assert.equal(c.status, 'UNRESOLVED');

  // Exact weight tie → NO_MAJORITY; a hung jury ends UNRESOLVED (honest).
  const { reg: reg2, keys: keys2 } = makeCourt([{ id: 'j-A', stake: 5 }, { id: 'j-B', stake: 5 }, { id: 'j-C', stake: 5 }]);
  const c2 = fileCase(reg2, { plaintiff: 'p', defendant: 'd', disputeReport: { v: 1 } }, T0);
  openDeliberation(reg2, c2, T0);
  castBallot(reg2, c2, { judge_id: 'j-A', verdict: 'AFFIRM', reasons: {} }, { sign: keys2['j-A'], now: T0 });
  castBallot(reg2, c2, { judge_id: 'j-B', verdict: 'REVERSE', reasons: {} }, { sign: keys2['j-B'], now: T0 });
  castBallot(reg2, c2, { judge_id: 'j-C', verdict: 'ABSTAIN', reasons: {} }, { sign: keys2['j-C'], now: T0 }); // present but not deciding
  assert.equal(tallyRound(reg2, c2).outcome, 'NO_MAJORITY');
  openChallengeWindow(reg2, c2, T0 + DAY); // hung jury → UNRESOLVED (honest)
  assert.equal(c2.status, 'UNRESOLVED');
});

test('court: agent division — AI referees argue but cannot vote ("AI argues, keys decide")', () => {
  const { reg, keys } = makeCourt([
    { id: 'j-A' }, { id: 'j-B' }, { id: 'j-C' },
    { id: 'referee-gpt', capabilities: ['referee'] } // AI referee: no judge cap
  ]);
  setFeeBook(reg, 'referee-gpt', { agent_dispute: 0.25 });

  const c = fileCase(reg, { division: 'agent', plaintiff: 'user', defendant: 'agent://trader-7', disputeReport: { v: 9 } }, T0);
  assert.ok(c.assigned_panel.every((id) => id !== 'referee-gpt')); // AI never assigned as judge

  // The AI submits its signed opinion — recorded as ADVISORY EVIDENCE only.
  const op = submitRefereeOpinion(reg, c, {
    referee_id: 'referee-gpt',
    opinion: { analysis: 'evidence suggests INVALID', confidence_pct: 82 } // integers only — canonical profile
  }, { sign: keys['referee-gpt'], now: T0 + 100 });
  assert.equal(op.advisory, true);

  // …but the same AI key CANNOT cast a deciding ballot.
  openDeliberation(reg, c, T0 + 200);
  assert.throws(
    () => castBallot(reg, c, { judge_id: 'referee-gpt', verdict: 'AFFIRM', reasons: {} }, { sign: keys['referee-gpt'], now: T0 + 300 }),
    (e) => e instanceof CourtError && e.code === 'NOT_CAPABLE'
  );

  for (const [id, v] of [['j-A', 'REVERSE'], ['j-B', 'REVERSE'], ['j-C', 'ABSTAIN']]) {
    castBallot(reg, c, { judge_id: id, verdict: v, reasons: {} }, { sign: keys[id], now: T0 + 400 });
  }
  const tally = tallyRound(reg, c);
  assert.equal(tally.outcome, 'REVERSE'); // ABSTAIN carries no deciding weight
  assert.ok(!JSON.stringify(tally.weights).includes('referee'));

  openChallengeWindow(reg, c, T0 + DAY);
  const cert = settleCase(reg, c, { signers: signerMap(keys), now: T0 + 2 * DAY });
  assert.equal(cert.division, 'agent');
  assert.deepEqual(cert.tally_proof.referee_opinions, [op.opinion_hash]); // AI argument preserved in the record
  assert.deepEqual(replayArbitration(reg, c), { matches: true, differences: [] });
});

test('court: revoked judge ballots are rejected inside the tally, not silently counted', () => {
  const { reg, keys } = makeCourt(['j-A', 'j-B', 'j-C', 'j-D']);
  const c = runGeneralCase(reg, keys);
  castBallot(reg, c, { judge_id: 'j-D', verdict: 'REVERSE', reasons: {} }, { sign: keys['j-D'], now: T0 + 3100 });
  revokeJudge(reg, 'j-D', { now: T0 + 3200 });
  const tally = tallyRound(reg, c);
  assert.deepEqual(tally.rejected_voters, ['j-D']); // signature no longer trusted
  assert.equal(tally.participants, 3);
});

test('court: anchor payload is byte-deterministic (pre-commitment friendly)', () => {
  const { reg, keys } = makeCourt(['j-A', 'j-B', 'j-C']);
  const a = runGeneralCase(reg, keys);
  openChallengeWindow(reg, a, T0 + DAY);
  const certA = settleCase(reg, a, { signers: signerMap(keys), now: T0 + 2 * DAY });

  const p1 = Buffer.from(buildAnchorPayload(certA).payload, 'utf8');
  const p2 = Buffer.from(buildAnchorPayload(JSON.parse(JSON.stringify(certA))).payload, 'utf8');
  assert.deepEqual(p2, p1);
  const h1 = createHash('sha256').update(p1).digest('hex');
  assert.equal(createHash('sha256').update(p2).digest('hex'), h1);
});

test('court: arbitration market — deterministic assignment, clearing stats, reputation rewards consensus', () => {
  const { reg, keys } = makeCourt(['zeta', 'alpha', 'mid']);
  setFeeBook(reg, 'zeta', { general_dispute: 100 });
  setFeeBook(reg, 'alpha', { general_dispute: 300 });
  setFeeBook(reg, 'mid', { general_dispute: 200 });

  // Cheapest first, then fee, then name — fully deterministic.
  assert.deepEqual(assignPanel(reg, 'general', 3), ['zeta', 'mid', 'alpha']);

  const snap = marketSnapshot(reg, 2);
  assert.equal(snap.active_judges, 3);
  assert.equal(snap.open_demand, 2);
  assert.equal(snap.clearing.general_dispute.median_fee, 200);

  // Consensus pays: AFFIRM winners gain +2 reputation at settlement.
  const c = fileCase(reg, { plaintiff: 'buyer', defendant: 'merchant', disputeReport: { v: 2 } }, T0);
  openDeliberation(reg, c, T0);
  for (const [id, v] of [['zeta', 'AFFIRM'], ['mid', 'AFFIRM'], ['alpha', 'REVERSE']]) {
    castBallot(reg, c, { judge_id: id, verdict: v, reasons: {} }, { sign: keys[id], now: T0 + 1000 });
  }
  tallyRound(reg, c);
  openChallengeWindow(reg, c, T0 + DAY);
  settleCase(reg, c, { signers: signerMap(keys), now: T0 + 2 * DAY });
  assert.equal(reg.court.judges.zeta.reputation, 2);
  assert.equal(reg.court.judges.mid.reputation, 2);
  assert.equal(reg.court.judges.alpha.reputation, 0);
});

test('court: every signature cross-verifies against plain node:crypto Ed25519', async () => {
  const { reg, keys } = makeCourt(['j-A', 'j-B', 'j-C']);
  const c = runGeneralCase(reg, keys);
  const b = c.rounds[0].ballots[0];
  const msg = Buffer.concat([
    Buffer.from('AUREVIA-COURT-v1\n', 'utf8'),
    Buffer.from(canonicalize({
      kind: 'BALLOT', case_id: c.case_id, round: 1,
      judge_id: b.judge_id, verdict: b.verdict, reasons_hash: b.reasons_hash
    }), 'utf8')
  ]);
  const pem = reg.court.judges[b.judge_id].public_key_pem;
  assert.equal(edVerify(null, msg, createPublicKey(pem), Buffer.from(b.signature, 'base64')), true);
});
