import { canonicalize, CanonicalError } from './canonical.js';
import { verifySignature, signMessage, publicKeyFingerprint } from './keys.js';
import { resolveKey } from './registry.js';
import { InMemoryNonceStore } from './nonces.js';

/**
 * PiRC1 — Transparency Layer: Escrow Lock Attestations.
 *
 * Implements the endorsed idea:
 *   "Escrow Lock Status: A verifiable on-chain proof that the
 *    Escrow Wallet's signing authority is revoked."
 *
 * An attestation is a small, closed-schema, Ed25519-signed object
 * issued by the Launchpad's escrow controller key under a dedicated
 * signature domain (PiRC1-ESCROW-v1). Anyone can verify it offline
 * with the registry alone.
 *
 * The optional `anchor` field carries an on-chain commitment
 * (transaction id / inclusion-proof reference) so verifiers CAN
 * cross-check chain state, but this module never fetches chain data:
 * it proves authenticity and freshness of the revocation CLAIM;
 * chain settlement remains the source of truth.
 */

export const ESCROW_DOMAIN = 'PiRC1-ESCROW-v1';
export const ESCROW_ATTESTATION_VERSION = 1;
export const ESCROW_APP_ID = 'launchpad-escrow';

export const ESCROW_STATES = Object.freeze([
  'ACTIVE',
  'SIGNING_AUTHORITY_REVOKED'
]);

const ATTESTATION_KEYS = Object.freeze([
  'v',
  'escrow_id',
  'state',
  'controller_key_id',
  'previous_key_fingerprint',
  'effective_at',
  'anchor',
  'nonce',
  'signature'
]);

const HEX32 = /^[0-9a-f]{32}$/;
const FINGERPRINT = /^[0-9a-f]{64}$/;

function isPlainObject(v) {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function hasOwn(o, k) {
  return Object.prototype.hasOwnProperty.call(o, k);
}

export function escrowSigningBytes(att) {
  const body = { ...att };
  delete body.signature;
  const c1 = canonicalize(body);
  const c2 = canonicalize(JSON.parse(c1));

  if (c1 !== c2) throw new CanonicalError('canonicalization is not stable');

  return Buffer.from(`${ESCROW_DOMAIN}\n${c1}`, 'utf8');
}

/**
 * Build and sign a SIGNING_AUTHORITY_REVOKED attestation.
 *
 * In production this runs inside the service/HSM that holds the NEW
 * controller key, immediately after broadcasting the on-chain
 * revocation transaction (`anchor` = its tx id).
 */
export function createRevocationAttestation(
  {
    escrowId,
    controllerKeyId,
    previousPublicKeyPem,
    effectiveAt,
    anchor = '',
    nonce
  },
  privateKeyPem
) {
  if (typeof escrowId !== 'string' || !/^[a-z0-9][a-z0-9._:-]{2,64}$/i.test(escrowId)) {
    throw new TypeError('escrowId is malformed');
  }

  if (typeof controllerKeyId !== 'string' || controllerKeyId.length === 0 || controllerKeyId.length > 64) {
    throw new TypeError('controllerKeyId is malformed');
  }

  if (!Number.isSafeInteger(effectiveAt) || effectiveAt <= 0) {
    throw new TypeError('effectiveAt must be a positive unix-ms integer');
  }

  if (typeof anchor !== 'string' || anchor.length > 128) {
    throw new TypeError('anchor must be a short string (tx id / proof ref)');
  }

  if (typeof nonce !== 'string' || !HEX32.test(nonce)) {
    throw new TypeError('nonce must be 16 bytes of lowercase hex');
  }

  const attestation = {
    v: ESCROW_ATTESTATION_VERSION,
    escrow_id: escrowId.toLowerCase(),
    state: 'SIGNING_AUTHORITY_REVOKED',
    controller_key_id: controllerKeyId,
    previous_key_fingerprint: publicKeyFingerprint(previousPublicKeyPem),
    effective_at: effectiveAt,
    anchor,
    nonce,
    signature: ''
  };

  attestation.signature = signMessage(
    privateKeyPem,
    escrowSigningBytes(attestation)
  ).toString('base64');

  return attestation;
}

/**
 * Verify an escrow attestation against the registry.
 *
 * Check order:
 *   SCHEMA → CANONICALIZATION → KEY_ACTIVE → SIGNATURE → FRESHNESS → REPLAY_GUARD
 *
 * @returns {{ok:boolean, checks:Array<{check:string,pass:boolean}>, ...}}
 */
export function verifyRevocationAttestation(
  attestation,
  {
    registry,
    now = Date.now(),
    maxAgeMs = 86_400_000,
    nonceStore = new InMemoryNonceStore()
  } = {}
) {
  const checks = [];
  const record = (check, pass) => checks.push({ check, pass });
  const reject = (check) => {
    record(check, false);
    return { ok: false, checks };
  };

  if (!isPlainObject(attestation)) return reject('SCHEMA');

  for (const k of ATTESTATION_KEYS) {
    if (!hasOwn(attestation, k)) return reject('SCHEMA');
  }
  if (Object.keys(attestation).length !== ATTESTATION_KEYS.length) return reject('SCHEMA');
  if (attestation.v !== ESCROW_ATTESTATION_VERSION) return reject('SCHEMA');
  if (!ESCROW_STATES.includes(attestation.state)) return reject('SCHEMA');

  if (
    typeof attestation.escrow_id !== 'string' ||
    !/^[a-z0-9][a-z0-9._:-]{2,64}$/i.test(attestation.escrow_id) ||
    typeof attestation.controller_key_id !== 'string' ||
    attestation.controller_key_id.length === 0 ||
    attestation.controller_key_id.length > 64 ||
    typeof attestation.previous_key_fingerprint !== 'string' ||
    !FINGERPRINT.test(attestation.previous_key_fingerprint) ||
    !Number.isSafeInteger(attestation.effective_at) ||
    typeof attestation.anchor !== 'string' ||
    attestation.anchor.length > 128 ||
    typeof attestation.signature !== 'string' ||
    attestation.signature.length > 256
  ) {
    return reject('SCHEMA');
  }
  record('SCHEMA', true);

  let msgBytes;
  try {
    msgBytes = escrowSigningBytes(attestation);
  } catch (err) {
    if (err instanceof CanonicalError || err instanceof SyntaxError) {
      return reject('CANONICALIZATION');
    }
    throw err;
  }
  record('CANONICALIZATION', true);

  const keyRecord =
    resolveKey(registry, ESCROW_APP_ID, attestation.controller_key_id);

  if (!keyRecord || keyRecord.status !== 'active') return reject('KEY_ACTIVE');
  record('KEY_ACTIVE', true);

  let sigBytes;
  try {
    sigBytes = Buffer.from(attestation.signature, 'base64');
  } catch {
    return reject('SIGNATURE');
  }

  if (sigBytes.length !== 64 || !verifySignature(keyRecord.public_key_pem, msgBytes, sigBytes)) {
    return reject('SIGNATURE');
  }
  record('SIGNATURE', true);

  const age = now - attestation.effective_at;
  if (age < -maxAgeMs || age > maxAgeMs) return reject('FRESHNESS');
  record('FRESHNESS', true);

  const nonceKey = `${attestation.escrow_id}:${attestation.nonce}`;
  if (nonceStore.has(nonceKey)) return reject('REPLAY_DETECTED');
  nonceStore.add(nonceKey);
  record('REPLAY_DETECTED_GUARD', true);

  return {
    ok: true,
    state: attestation.state,
    escrow_id: attestation.escrow_id,
    previous_key_fingerprint: attestation.previous_key_fingerprint,
    anchor: attestation.anchor,
    checks,
    note:
      'proves authenticity of the revocation claim only — settle finality against the referenced on-chain anchor'
  };
}
