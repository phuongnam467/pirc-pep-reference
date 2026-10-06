import { createHash } from 'node:crypto';
import { canonicalize } from './canonical.js';
import { verifyPiProof } from './piproof.js';

/**
 * AUREVIA Evidence Passport/1 — one portable evidence record.
 *
 * A passport bundles one or more PiProof envelopes under a single
 * content-addressed evidence root, optionally bound to a Trust Policy,
 * so its holder can carry independently verifiable evidence anywhere:
 *
 *   Don't trust the platform. Verify the claim.
 *
 * The passport carries minimal data by design: pseudonymous subject,
 * signed events, issuer metadata, timestamps, policy reference. It never
 * claims truthfulness — only cryptographic validity under an epoch.
 */

export const PASSPORT_TYPE = 'AUREVIA-Evidence-Passport';
export const PASSPORT_VERSION = 1;

const SUBJECT_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const ENVELOPE_KEYS = Object.freeze(['type', 'version', 'created_at', 'subject', 'policy', 'proofs', 'evidence_root']);

const STEP_LABELS = Object.freeze({
  PASSPORT_ENVELOPE: 'passport envelope well-formed',
  EVIDENCE_ROOT: 'evidence root matches embedded proofs',
  PROOFS_VERIFIED: 'all embedded proofs verified'
});

export class PassportError extends Error {
  constructor(message) {
    super(message);
    this.name = 'PassportError';
  }
}

export function evidenceRootHash(passports) {
  return 'e1:' + createHash('sha256').update(canonicalize(passports), 'utf8').digest('hex');
}

export function createPassport({ proofs, subject = null, policy = null, createdAt = Date.now() }) {
  if (!Array.isArray(proofs) || proofs.length === 0 || proofs.length > 100) {
    throw new PassportError('passports require between 1 and 100 PiProof envelopes');
  }
  for (const p of proofs) {
    if (p === null || typeof p !== 'object' || Array.isArray(p) || p.type !== 'PiProof') {
      throw new PassportError('every entry in proofs must be a PiProof envelope');
    }
  }
  if (subject !== null && (typeof subject !== 'string' || !SUBJECT_RE.test(subject))) {
    throw new PassportError('subject must be a pseudonymous tag matching [A-Za-z0-9][A-Za-z0-9._:-]{0,63}');
  }
  if (!Number.isSafeInteger(createdAt) || createdAt <= 0) {
    throw new PassportError('createdAt must be a positive unix-ms integer');
  }

  const passport = {
    type: PASSPORT_TYPE,
    version: PASSPORT_VERSION,
    created_at: createdAt,
    subject,
    policy: policy ?? null,
    proofs
  };
  if (subject === null) delete passport.subject;
  passport.evidence_root = evidenceRootHash(passport.proofs);
  return passport;
}

function envelopeError(passport) {
  if (passport === null || typeof passport !== 'object' || Array.isArray(passport)) {
    return 'passport must be a JSON object';
  }
  for (const k of Object.keys(passport)) {
    if (!ENVELOPE_KEYS.includes(k)) return `unknown passport field: ${k}`;
  }
  if (passport.type !== PASSPORT_TYPE) return `passport type must be "${PASSPORT_TYPE}"`;
  if (passport.version !== PASSPORT_VERSION) return `unsupported passport version: ${JSON.stringify(passport.version)}`;
  if (!Number.isSafeInteger(passport.created_at) || passport.created_at <= 0) {
    return 'created_at must be a positive unix-ms integer';
  }
  if (passport.subject !== undefined && passport.subject !== null &&
      (typeof passport.subject !== 'string' || !SUBJECT_RE.test(passport.subject))) {
    return 'subject is malformed';
  }
  if (!Array.isArray(passport.proofs)) return 'proofs must be an array of PiProof envelopes';
  if (passport.proofs.length === 0 || passport.proofs.length > 100) {
    return 'passports require between 1 and 100 proofs';
  }
  return null;
}

import { timed } from './observability.js';

export function verifyPassport(passport, opts = {}) {
  const { metrics = null } = opts;
  if (!metrics) return _verifyPassport(passport, opts);
  return timed(metrics, 'passport_verify', () => _verifyPassport(passport, opts));
}

function _verifyPassport(passport, { registry, nonceStore, now = Date.now(), policyOverride = null }) {
  const steps = [];
  const step = (id, pass, detail = '') => steps.push({ id, label: STEP_LABELS[id] ?? id, pass, detail });

  const envErr = envelopeError(passport);
  if (envErr !== null) {
    step('PASSPORT_ENVELOPE', false, envErr);
    return { ok: false, code: 'PASSPORT_ENVELOPE', binding: null, steps, results: [] };
  }
  step('PASSPORT_ENVELOPE', true);

  const actualRoot = evidenceRootHash(passport.proofs);
  if (actualRoot !== passport.evidence_root) {
    step('EVIDENCE_ROOT', false, `expected ${passport.evidence_root}, computed ${actualRoot}`);
    return { ok: false, code: 'EVIDENCE_ROOT', binding: null, steps, results: [] };
  }
  step('EVIDENCE_ROOT', true, actualRoot);

  const policy = policyOverride ?? passport.policy ?? null;

  let allOk = true;
  let firstCode = null;
  const results = passport.proofs.map((proof, i) => {
    const res = verifyPiProof(proof, { registry, nonceStore, now, policy });
    res.index = i;
    for (const s of res.steps) s.label = `#${i + 1} ${s.label}`;
    if (!res.ok) {
      allOk = false;
      if (firstCode === null) firstCode = res.code;
    }
    return res;
  });
  step('PROOFS_VERIFIED', allOk, `${results.filter((r) => r.ok).length}/${results.length} valid`);
  if (!allOk) firstCode = firstCode ?? 'PROOFS_VERIFIED';

  // Binding aggregation: a passport is only as epoch-pinned as its weakest
  // proof. EPOCH_BOUND requires every embedded envelope to carry and match a
  // registry_root; any mix is reported honestly as MIXED.
  const bindings = results.map((r) => r.binding);
  const binding = bindings.every((b) => b === 'EPOCH_BOUND')
    ? 'EPOCH_BOUND'
    : bindings.every((b) => b === 'LOCAL')
      ? 'LOCAL'
      : 'MIXED';

  const summary = {
    subject: passport.subject ?? null,
    created_at: passport.created_at,
    evidence_root: passport.evidence_root,
    proofs_total: results.length,
    proofs_valid: results.filter((r) => r.ok).length,
    binding
  };

  return {
    ok: allOk,
    code: allOk ? null : (firstCode || 'PASSPORT_INVALID'),
    binding,
    steps,
    results,
    summary,
    policy: results[0]?.policy ?? null
  };
}
