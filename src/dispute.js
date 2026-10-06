import { createHash } from 'node:crypto';
import { canonicalize } from './canonical.js';
import { PASSPORT_TYPE, verifyPassport } from './passport.js';
import { PIPROOF_TYPE, verifyPiProof } from './piproof.js';

/**
 * AUREVIA Dispute Engine — turns raw cryptography into a human-adjudicable
 * chain of questions. Instead of screenshots and scattered logs, a dispute
 * is answered by walking the exact verification pipeline:
 *
 *   CLAIM → WHO ISSUED IT? → WHAT WAS SIGNED? → WHICH POLICY? →
 *   WHICH EPOCH? → IS IT EPOCH-BOUND? → WAS IT REPLAYED? →
 *   IS THE KEY VALID? → IS THE CLAIM WITHIN POLICY? → FINAL VERDICT
 *
 * Naming honesty: this is a DETERMINISTIC EVIDENCE ADJUDICATION LAYER —
 * the same inputs always yield the same report. It is NOT a decentralized
 * dispute-resolution protocol: no judge quorum, no challenge periods, no
 * arbitration market, no on-chain settlement. Human governance consumes
 * these reports; it does not emerge from them.
 *
 * Three-state outcome, deliberately honest:
 *   VALID        — every layer checked here passed.
 *   INVALID      — at least one layer definitively failed.
 *   UNVERIFIABLE — this verifier lacks the inputs to adjudicate
 *                  (e.g. no trusted registry copy was provided, or the
 *                  document is too malformed to even extract a claim).
 *                  UNVERIFIABLE is NOT a pass and never treated as one.
 */

export const DISPUTE_VERSION = 1;

const QUESTION_ORDER = Object.freeze([
  'CLAIM',
  'WHO_ISSUED_IT',
  'WHAT_WAS_SIGNED',
  'WHICH_POLICY',
  'WHICH_EPOCH',
  'IS_THE_PROOF_EPOCH_BOUND',
  'WAS_IT_REPLAYED',
  'IS_THE_KEY_VALID',
  'IS_THE_CLAIM_WITHIN_POLICY'
]);

function q(id, status, answer) {
  return { question: id, status, answer };
}

function fingerprint(value) {
  return 'sha256:' + createHash('sha256').update(canonicalize(value), 'utf8').digest('hex').slice(0, 32);
}

function collectSteps(results) {
  const byId = new Map();
  for (const r of results) {
    for (const s of r.steps) {
      const prev = byId.get(s.id);
      byId.set(s.id, prev === false || s.pass === false ? false : s.pass !== false);
    }
  }
  return byId;
}

export function buildDisputeReport({ doc, registry = null, nonceStore = null, now = Date.now(), policy = null }) {
  const chain = [];
  let verdict = 'UNVERIFIABLE';

  // --- CLAIM -------------------------------------------------------------
  let kind = null;
  let proofs = null;
  let subject = null;
  let created_at = null;
  let evidence_root = null;

  if (doc && typeof doc === 'object' && !Array.isArray(doc)) {
    if (doc.type === PIPROOF_TYPE) {
      kind = 'PiProof';
      proofs = [doc];
    } else if (doc.type === PASSPORT_TYPE) {
      kind = PASSPORT_TYPE;
      proofs = Array.isArray(doc.proofs) ? doc.proofs : [];
      subject = doc.subject ?? null;
      created_at = doc.created_at ?? null;
      evidence_root = doc.evidence_root ?? null;
    }
  }

  if (kind === null || proofs === null || proofs.length === 0) {
    chain.push(q('CLAIM', 'UNVERIFIABLE', 'document is not a readable PiProof or AUREVIA Evidence Passport'));
    for (const id of QUESTION_ORDER.slice(1)) chain.push(q(id, 'UNVERIFIABLE', 'not reachable — claim unreadable'));
    return { type: 'AUREVIA-Dispute-Report', version: DISPUTE_VERSION, verdict: 'UNVERIFIABLE', document_kind: null, chain };
  }

  const issuers = [...new Set(proofs.map((p) => p?.event?.app_id).filter(Boolean))];
  const actions = proofs.map((p) => ({
    action_class: p?.event?.action_class ?? null,
    action_id: p?.event?.action_id ?? null,
    weight: p?.event?.weight ?? null,
    timestamp: p?.event?.timestamp ?? null
  }));
  chain.push(q('CLAIM', 'OK', {
    document_kind: kind,
    subject,
    issued_at: created_at,
    evidence_root,
    proofs: actions.length,
    actions
  }));

  // --- structural-only mode when no trusted registry is available --------
  if (registry === null || registry === undefined) {
    chain.push(q('WHO_ISSUED_IT', 'OK', { issuers, note: 'self-declared inside the signed payload' }));
    chain.push(q('WHAT_WAS_SIGNED', 'OK', proofs.map((p) => fingerprint(p?.event ?? {}))));
    chain.push(q('WHICH_POLICY', 'OK', policy ?? (kind === PASSPORT_TYPE ? doc.policy : null) ?? null));
    chain.push(q('WHICH_EPOCH', 'UNVERIFIABLE', 'no trusted registry copy supplied to this verifier'));
    chain.push(q('IS_THE_PROOF_EPOCH_BOUND', 'OK', {
      per_proof: proofs.map((p) => (p?.registry_root !== undefined ? 'EPOCH_BOUND' : 'LOCAL')),
      note: 'document-intrinsic — readable without any registry'
    }));
    chain.push(q('WAS_IT_REPLAYED', 'UNVERIFIABLE', 'requires a live nonce store'));
    chain.push(q('IS_THE_KEY_VALID', 'UNVERIFIABLE', 'requires the registry'));
    chain.push(q('IS_THE_CLAIM_WITHIN_POLICY', 'UNVERIFIABLE', 'requires the registry-backed pipeline'));
    chain.push(q('FINAL_VERDICT', 'UNVERIFIABLE', 'this verifier cannot adjudicate without its own trusted state'));
    return { type: 'AUREVIA-Dispute-Report', version: DISPUTE_VERSION, verdict: 'UNVERIFIABLE', document_kind: kind, chain };
  }

  // --- full adjudication against this verifier's own epoch ---------------
  const effectivePolicy = policy ?? (kind === PASSPORT_TYPE ? doc.policy : null);

  // Verify exactly once: a second pass would burn nonces and misreport replay.
  let envelopeSteps = [];
  let results;
  if (kind === PASSPORT_TYPE) {
    const root = verifyPassport(doc, { registry, nonceStore, now, policyOverride: effectivePolicy });
    envelopeSteps = root.steps;
    results = root.results.map((r) => ({ ...r }));
  } else {
    results = [verifyPiProof(proofs[0], { registry, nonceStore, now, policy: effectivePolicy })];
  }
  const steps = collectSteps([...results.map((r) => ({ steps: r.steps })), { steps: envelopeSteps }]);

  chain.push(q('WHO_ISSUED_IT', issuers.length > 0 ? 'OK' : 'INVALID', {
    issuers,
    registered: steps.get('APP_KNOWN') !== false,
    cross_issuer: issuers.length > 1
  }));
  chain.push(q('WHAT_WAS_SIGNED', 'OK', proofs.map((p) => fingerprint(p?.event ?? {}))));
  chain.push(q('WHICH_POLICY', 'OK', effectivePolicy ?? null));

  const rootOk = steps.get('EVIDENCE_ROOT') !== false;
  const epochAnswer = {
    declared_roots: [...new Set(proofs.map((p) => p?.registry_root).filter(Boolean))],
    verifier_epoch: rootOk ? 'matches declared root(s)' : 'evidence root mismatch — see EVIDENCE_ROOT detail'
  };
  const epochStatus = (steps.get('REGISTRY_ROOT') === false || !rootOk) ? 'INVALID' : 'OK';
  chain.push(q('WHICH_EPOCH', epochStatus, epochAnswer));

  // Binding is document-intrinsic (presence of registry_root), so it is
  // reported even when epoch matching failed — the two questions answer
  // different things: WHICH_EPOCH = does the pin match THIS verifier's
  // registry; IS_THE_PROOF_EPOCH_BOUND = was the proof pinned at all.
  chain.push(q('IS_THE_PROOF_EPOCH_BOUND', 'OK', {
    per_proof: proofs.map((p) => (p?.registry_root !== undefined ? 'EPOCH_BOUND' : 'LOCAL')),
    note: 'EPOCH_BOUND proofs are cryptographically tied to one registry generation; LOCAL proofs verify against whatever trusted copy the verifier supplies'
  }));

  const replayed = steps.get('NONCE_REPLAY') === false;
  chain.push(q('WAS_IT_REPLAYED', replayed ? 'INVALID' : 'OK', replayed
    ? 'nonce already claimed — this exact document was accepted before'
    : 'all nonces unused at verification time'));

  const keyValid = steps.get('KEY_ACTIVE') !== false && steps.get('UNKNOWN_KEY') !== false;
  chain.push(q('IS_THE_KEY_VALID', keyValid ? 'OK' : 'INVALID', keyValid
    ? 'signing key registered and active (not revoked)'
    : 'signing key unknown or revoked'));

  const withinPolicy = steps.get('WEIGHT_BOUND') !== false && !(effectivePolicy && steps.get('POLICY') === false);
  const policyViolations = results.flatMap((r) => (r.policy && Array.isArray(r.policy.violations)) ? r.policy.violations : []);
  chain.push(q('IS_THE_CLAIM_WITHIN_POLICY', withinPolicy ? 'OK' : 'INVALID', withinPolicy
    ? (effectivePolicy ? 'within ceilings and policy rules' : 'no policy attached — cryptographic validity only')
    : { violations: policyViolations }));

  const anyInvalid = chain.some((c) => c.status === 'INVALID');
  verdict = anyInvalid ? 'INVALID' : 'VALID';
  chain.push(q('FINAL_VERDICT', verdict, verdict === 'VALID'
    ? `${results.filter((r) => r.ok).length}/${results.length} proof(s) fully verified against this verifier's epoch`
    : 'at least one layer definitively failed — see flagged stages above'));

  return {
    type: 'AUREVIA-Dispute-Report',
    version: DISPUTE_VERSION,
    verdict,
    document_kind: kind,
    subject,
    issuers,
    chain
  };
}
