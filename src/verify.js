import { canonicalize, CanonicalError } from './canonical.js';
import { DOMAIN, ERROR_CODES, TIMESTAMP_WINDOW_MS, WEIGHT_CEILINGS } from './constants.js';
import { verifySignature } from './keys.js';
import { resolveKey, getEligibilityRecord, hasApp } from './registry.js';
import { schemaError } from './schema.js';

export function signingBytesFromEvent(event) {
  const body = { ...event };
  delete body.signature;
  return Buffer.from(DOMAIN + '\n' + canonicalize(body), 'utf8');
}

import { timed } from './observability.js';

export function verifySignedEvent(event, opts = {}) {
  const { metrics = null } = opts;
  if (!metrics) return _verifySignedEvent(event, opts);
  return timed(metrics, 'signed_event_verify', () => _verifySignedEvent(event, opts));
}

function _verifySignedEvent(event, { registry, nonceStore, now = Date.now() }) {
  const checks = [];
  const record = (check, pass) => checks.push({ check, pass });
  const reject = (check, code) => {
    record(check, false);
    return { ok: false, code, checks };
  };

  if (!nonceStore || typeof nonceStore.claimIfAbsent !== 'function') {
    throw new TypeError('nonceStore with atomic claimIfAbsent() is required (use InMemoryNonceStore or FileNonceStore)');
  }

  if (event === null || typeof event !== 'object' || Array.isArray(event)) {
    return reject('SCHEMA', ERROR_CODES.SCHEMA);
  }
  const structural = schemaError(event);
  if (structural !== null) {
    return reject('SCHEMA', ERROR_CODES.SCHEMA);
  }
  record('SCHEMA', true);

  if (!hasApp(registry, event.app_id)) {
    return reject('APP_KNOWN', ERROR_CODES.UNKNOWN_APP);
  }
  record('APP_KNOWN', true);

  const keyRecord = resolveKey(registry, event.app_id, event.key_id);
  if (!keyRecord) {
    return reject('KEY_ACTIVE', ERROR_CODES.UNKNOWN_KEY);
  }
  if (keyRecord.status !== 'active') {
    return reject('KEY_ACTIVE', ERROR_CODES.REVOKED_KEY);
  }
  record('KEY_ACTIVE', true);

  let msgBytes;
  try {
    const body = { ...event };
    delete body.signature;
    const c1 = canonicalize(body);
    const c2 = canonicalize(JSON.parse(c1));
    if (c1 !== c2) {
      return reject('CANONICALIZATION', ERROR_CODES.CANONICALIZATION);
    }
    msgBytes = Buffer.from(DOMAIN + '\n' + c1, 'utf8');
  } catch (err) {
    if (err instanceof CanonicalError || err instanceof SyntaxError) {
      return reject('CANONICALIZATION', ERROR_CODES.CANONICALIZATION);
    }
    throw err;
  }
  record('CANONICALIZATION', true);

  let sigBytes;
  try {
    sigBytes = Buffer.from(event.signature, 'base64');
  } catch {
    return reject('SIGNATURE', ERROR_CODES.INVALID_SIGNATURE);
  }
  if (!verifySignature(keyRecord.public_key_pem, msgBytes, sigBytes)) {
    return reject('SIGNATURE', ERROR_CODES.INVALID_SIGNATURE);
  }
  record('SIGNATURE', true);

  const delta = now - event.timestamp;
  if (delta < -TIMESTAMP_WINDOW_MS) {
    return reject('TIMESTAMP_FRESHNESS', ERROR_CODES.TIMESTAMP_IN_FUTURE);
  }
  if (delta > TIMESTAMP_WINDOW_MS) {
    return reject('TIMESTAMP_FRESHNESS', ERROR_CODES.TIMESTAMP_EXPIRED);
  }
  record('TIMESTAMP_FRESHNESS', true);

  if (event.weight > WEIGHT_CEILINGS[event.action_class]) {
    return reject('WEIGHT_BOUND', ERROR_CODES.WEIGHT_OVERFLOW);
  }
  record('WEIGHT_BOUND', true);

  const elig = event.eligibility ?? {};
  const selfDeclared = elig.kyc_passed === true && elig.mainnet_migrated === true;
  const eligRecord = getEligibilityRecord(registry, event.pioneer_uid_hash);
  const registryConfirmed =
    eligRecord !== null && eligRecord.kyc_passed === true && eligRecord.mainnet_migrated === true;
  if (!selfDeclared || !registryConfirmed) {
    return reject('ELIGIBILITY', ERROR_CODES.INELIGIBLE_USER);
  }
  record('ELIGIBILITY', true);

  const nonceKey = `${event.app_id}:${event.nonce}`;
  if (!nonceStore.claimIfAbsent(nonceKey)) {
    return reject('NONCE_REPLAY', ERROR_CODES.REPLAY_DETECTED);
  }
  record('NONCE_REPLAY', true);

  return { ok: true, code: null, checks };
}
