import { createHash } from 'node:crypto';
import { canonicalize } from './canonical.js';
import { SPEC_VERSION } from './constants.js';
import { evaluatePolicy } from './policy.js';
import { verifySignedEvent } from './verify.js';

/**
 * PiProof/1 — portable verification envelope.
 *
 * A PiProof wraps exactly one signed PEP/1 event so it can travel between
 * applications, verifiers and storage without the receiving party having to
 * trust the issuing application. Verification is always performed against a
 * registry the verifier controls; the proof itself carries no authority.
 *
 * Binding classes (v0.13, additive — the wire format is unchanged):
 *   EPOCH_BOUND — the envelope carries `registry_root`; any verifier holding
 *                 a different epoch MUST reject it (REGISTRY_ROOT). The claim
 *                 is cryptographically tied to one registry generation.
 *   LOCAL       — no `registry_root`; the proof verifies against whatever
 *                 trusted registry copy the verifier supplies, but carries NO
 *                 commitment to any specific epoch. Portability and state
 *                 trust are different properties; this distinction makes both
 *                 explicit. Relying parties that require epoch pinning SHOULD
 *                 enforce `require_epoch_bound` in their Trust Policy.
 */

export const PIPROOF_TYPE = 'PiProof';
export const PIPROOF_VERSION = 1;

export const BINDING_EPOCH_BOUND = 'EPOCH_BOUND';
export const BINDING_LOCAL = 'LOCAL';

const ENVELOPE_KEYS = Object.freeze(['type', 'version', 'created_at', 'event', 'registry_root']);

export class PiProofError extends Error {
  constructor(message) {
    super(message);
    this.name = 'PiProofError';
  }
}

export function registryRootHash(registry) {
  return 'r1:' + createHash('sha256').update(canonicalize(registry), 'utf8').digest('hex');
}

export function toPiProof(signedEvent, { registry = null } = {}) {
  if (signedEvent === null || typeof signedEvent !== 'object' || Array.isArray(signedEvent)) {
    throw new PiProofError('signed PEP/1 event required');
  }
  if (signedEvent.v !== SPEC_VERSION || typeof signedEvent.signature !== 'string') {
    throw new PiProofError('event does not look like a signed PEP/1 payload');
  }
  const proof = {
    type: PIPROOF_TYPE,
    version: PIPROOF_VERSION,
    created_at: signedEvent.timestamp,
    event: signedEvent
  };
  if (registry !== null) proof.registry_root = registryRootHash(registry);
  return proof;
}

const STEP_LABELS = Object.freeze({
  PROOF_ENVELOPE: 'proof envelope well-formed',
  REGISTRY_ROOT: 'registry root matches verifier epoch',
  SCHEMA: 'claim schema valid',
  APP_KNOWN: 'issuer registered',
  KEY_ACTIVE: 'signing key active (not revoked)',
  CANONICALIZATION: 'deterministic canonical encoding',
  SIGNATURE: 'Ed25519 signature valid',
  TIMESTAMP_FRESHNESS: 'timestamp fresh (within window)',
  WEIGHT_BOUND: 'weight within class ceiling',
  ELIGIBILITY: 'eligibility confirmed against registry',
  NONCE_REPLAY: 'nonce unused — no replay'
});

function envelopeError(proof) {
  if (proof === null || typeof proof !== 'object' || Array.isArray(proof)) {
    return 'proof must be a JSON object';
  }
  for (const k of Object.keys(proof)) {
    if (!ENVELOPE_KEYS.includes(k)) return `unknown proof field: ${k}`;
  }
  if (proof.type !== PIPROOF_TYPE) return `proof type must be "${PIPROOF_TYPE}"`;
  if (proof.version !== PIPROOF_VERSION) return `unsupported proof version: ${JSON.stringify(proof.version)}`;
  if (!Number.isSafeInteger(proof.created_at) || proof.created_at <= 0) {
    return 'created_at must be a positive unix-ms integer';
  }
  if (proof.event === null || typeof proof.event !== 'object' || Array.isArray(proof.event)) {
    return 'proof.event must be a signed PEP/1 object';
  }
  if (proof.registry_root !== undefined && !/^r1:[0-9a-f]{64}$/.test(proof.registry_root)) {
    return 'registry_root must be r1:<64 lowercase hex chars>';
  }
  return null;
}

import { timed } from './observability.js';

export function verifyPiProof(proof, opts = {}) {
  const { metrics = null } = opts;
  if (!metrics) return _verifyPiProof(proof, opts);
  return timed(metrics, 'proof_verify', () => _verifyPiProof(proof, opts));
}

function _verifyPiProof(proof, { registry, nonceStore, now = Date.now(), policy = null, metrics = null }) {
  const steps = [];
  const step = (id, pass, detail = '') => steps.push({ id, label: STEP_LABELS[id] ?? id, pass, detail });
  const binding = proof?.registry_root !== undefined ? BINDING_EPOCH_BOUND : BINDING_LOCAL;

  const envErr = envelopeError(proof);
  if (envErr !== null) {
    step('PROOF_ENVELOPE', false, envErr);
    return { ok: false, code: 'PROOF_ENVELOPE', binding: null, steps, policy: null };
  }
  step('PROOF_ENVELOPE', true);

  if (binding === BINDING_EPOCH_BOUND) {
    const actual = registryRootHash(registry);
    if (actual !== proof.registry_root) {
      step('REGISTRY_ROOT', false, `expected ${proof.registry_root}, verifier epoch is ${actual}`);
      return { ok: false, code: 'REGISTRY_ROOT', binding, steps, policy: null };
    }
    step('REGISTRY_ROOT', true, actual);
  }

  const verdict = verifySignedEvent(proof.event, { registry, nonceStore, now, metrics });
  for (const c of verdict.checks) step(c.check, c.pass);

  let policyResult = null;
  if (verdict.ok && policy !== null && typeof policy === 'object') {
    policyResult = evaluatePolicy(proof.event, { now, binding }, policy);
  }

  const ok = verdict.ok && (policyResult === null || policyResult.pass);
  return {
    ok,
    code: verdict.ok ? (policyResult && !policyResult.pass ? 'POLICY' : null) : verdict.code,
    binding,
    steps,
    policy: policyResult,
    event: verdict.ok
      ? {
          app_id: proof.event.app_id,
          action_class: proof.event.action_class,
          action_id: proof.event.action_id,
          weight: proof.event.weight,
          timestamp: proof.event.timestamp,
          pioneer_uid_hash: proof.event.pioneer_uid_hash
        }
      : undefined
  };
}
