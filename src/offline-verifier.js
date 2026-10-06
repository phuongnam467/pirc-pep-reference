// Offline (in-browser) PiProof verification — L1 protocol core.
//
// This module re-runs the G1–G9 pipeline with NO server round-trip: the
// visitor's browser fetches only the PUBLIC registry export and does every
// check locally. The document itself never leaves the tab.
//
// Honesty is the design center: a browser has no shared replay state and no
// authoritative clock, so NONCE_REPLAY can NEVER be claimed here — it renders
// as 'UNVERIFIABLE', never as OK, and the overall verdict is explicitly
// "verified offline" rather than the full protocol verdict. Anything that
// cannot be checked is gold-labeled, not green-washed.
//
// Browser-safe by construction: TextEncoder instead of Buffer, no node:
// imports anywhere in the dependency closure.

import { canonicalize, CanonicalError } from './canonical.js';
import { DOMAIN, TIMESTAMP_WINDOW_MS, WEIGHT_CEILINGS } from './constants.js';
import { getEligibilityRecord, hasApp, resolveKey } from './registry.js';
import { schemaError } from './schema.js';
import { ed25519Verify } from './web-ed25519.js';

const te = new TextEncoder();

// DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410): the entire
// structure is fixed-length for this algorithm, so a constant-prefix match
// plus a 32-byte tail IS a complete parser — nothing variable to walk.
const ED25519_SPKI_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
]);

function b64ToBytes(b64) {
  const norm = b64.replace(/-/g, '+').replace(/_/g, '/');
  const padded = norm + '='.repeat((4 - (norm.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64StdToBytes(b64) {
  return b64ToBytes(b64); // signature fields use standard base64; tolerant decode
}

/** Extract the raw 32-byte key from an Ed25519 public_key_pem, or null. */
export function parseEd25519SpkiPem(pem) {
  if (typeof pem !== 'string') return null;
  const body = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, '')
    .replace(/-----END PUBLIC KEY-----/, '')
    .replace(/\s+/g, '');
  let der;
  try {
    der = b64ToBytes(body);
  } catch {
    return null;
  }
  if (der.length !== ED25519_SPKI_PREFIX.length + 32) return null;
  for (let i = 0; i < ED25519_SPKI_PREFIX.length; i++) {
    if (der[i] !== ED25519_SPKI_PREFIX[i]) return null;
  }
  return der.slice(ED25519_SPKI_PREFIX.length);
}

/**
 * Run the offline pipeline over one signed event.
 *
 * @param {object} event      parsed signed-event document
 * @param {object} opts.registry  trusted public registry object (same shape
 *        as registry.json exports: {apps:{id:{keys:{...}}}, eligible_users:{…}})
 * @param {number} [opts.now]     clock override (tests); defaults to Date.now()
 * @returns {{ok:boolean, code:string|null, verifiedOffline:boolean,
 *          checks:Array<{check:string,status:'OK'|'INVALID'|'UNVERIFIABLE',
 *                        detail?:string}>}}
 */
export function verifyEventOffline(event, { registry, now = Date.now() } = {}) {
  const checks = [];
  const record = (check, status, detail) => checks.push({ check, status, ...(detail ? { detail } : {}) });
  const reject = (check, code, detail) => {
    record(check, 'INVALID', detail);
    return { ok: false, code, verifiedOffline: false, checks };
  };

  if (!registry || typeof registry !== 'object') {
    throw new TypeError('verifyEventOffline requires the trusted public registry object');
  }

  // G1 — SCHEMA
  if (event === null || typeof event !== 'object' || Array.isArray(event)) {
    return reject('SCHEMA', 'SCHEMA');
  }
  const structural = schemaError(event);
  if (structural !== null) {
    return reject('SCHEMA', 'SCHEMA', structural);
  }
  record('SCHEMA', 'OK');

  // G2 — APP_KNOWN
  if (!hasApp(registry, event.app_id)) {
    return reject('APP_KNOWN', 'UNKNOWN_APP');
  }
  record('APP_KNOWN', 'OK');

  // G3 — KEY_ACTIVE
  const keyRecord = resolveKey(registry, event.app_id, event.key_id);
  if (!keyRecord) {
    return reject('KEY_ACTIVE', 'UNKNOWN_KEY');
  }
  if (keyRecord.status !== 'active') {
    return reject('KEY_ACTIVE', 'REVOKED_KEY');
  }
  record('KEY_ACTIVE', 'OK');

  // G4 — CANONICALIZATION (fixed point, exactly like the Node pipeline)
  let msgBytes;
  try {
    const body = { ...event };
    delete body.signature;
    const c1 = canonicalize(body);
    const c2 = canonicalize(JSON.parse(c1));
    if (c1 !== c2) {
      return reject('CANONICALIZATION', 'CANONICALIZATION');
    }
    msgBytes = te.encode(DOMAIN + '\n' + c1);
  } catch (err) {
    if (err instanceof CanonicalError || err instanceof SyntaxError) {
      return reject('CANONICALIZATION', 'CANONICALIZATION');
    }
    throw err;
  }
  record('CANONICALIZATION', 'OK');

  // G5 — SIGNATURE via pure-JS RFC 8032 verification
  const pubRaw = parseEd25519SpkiPem(keyRecord.public_key_pem);
  let sigBytes;
  try {
    sigBytes = b64StdToBytes(event.signature);
  } catch {
    return reject('SIGNATURE', 'INVALID_SIGNATURE');
  }
  if (pubRaw === null || sigBytes.length !== 64 || !ed25519Verify(pubRaw, msgBytes, sigBytes)) {
    return reject('SIGNATURE', 'INVALID_SIGNATURE');
  }
  record('SIGNATURE', 'OK');

  // G6 — TIMESTAMP_FRESHNESS (visitor's clock; UI surfaces the skew caveat)
  const delta = now - event.timestamp;
  if (delta < -TIMESTAMP_WINDOW_MS) {
    return reject('TIMESTAMP_FRESHNESS', 'TIMESTAMP_IN_FUTURE', `clock delta ${delta}ms`);
  }
  if (delta > TIMESTAMP_WINDOW_MS) {
    return reject('TIMESTAMP_FRESHNESS', 'TIMESTAMP_EXPIRED', `clock delta ${delta}ms`);
  }
  record('TIMESTAMP_FRESHNESS', 'OK', `clock delta ${delta}ms`);

  // G7 — WEIGHT_BOUND
  if (event.weight > WEIGHT_CEILINGS[event.action_class]) {
    return reject('WEIGHT_BOUND', 'WEIGHT_OVERFLOW');
  }
  record('WEIGHT_BOUND', 'OK');

  // G8 — ELIGIBILITY against the published registry snapshot
  const elig = event.eligibility ?? {};
  const selfDeclared = elig.kyc_passed === true && elig.mainnet_migrated === true;
  const eligRecord = getEligibilityRecord(registry, event.pioneer_uid_hash);
  const registryConfirmed =
    eligRecord !== null && eligRecord.kyc_passed === true && eligRecord.mainnet_migrated === true;
  if (!selfDeclared || !registryConfirmed) {
    return reject('ELIGIBILITY', 'INELIGIBLE_USER');
  }
  record('ELIGIBILITY', 'OK');

  // G9 — NONCE_REPLAY: structurally impossible to judge without shared state.
  // This row is the honesty centerpiece: gold, never green, never red.
  record('NONCE_REPLAY', 'UNVERIFIABLE', 'requires shared replay state — verify through a live verifier for replay certainty');

  return { ok: true, code: null, verifiedOffline: true, checks };
}
