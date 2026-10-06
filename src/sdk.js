import { verifyPiProof, PIPROOF_TYPE } from './piproof.js';
import { verifyPassport, PASSPORT_TYPE } from './passport.js';
import { resolvePolicy } from './policy-presets.js';

/**
 * PiProof Developer SDK — the "Verify with PiProof" surface.
 *
 * Goal: a developer adds PiProof to any application in ~5 minutes:
 *
 *   import { createVerifier } from 'piproof/sdk';
 *   const pi = createVerifier({ registry, nonceStore });
 *   const d = pi.decide(proof, { policy: 'merchant-verification-v1' });
 *   if (d.decision === 'ALLOW') allowAction();
 *
 * The SDK is a thin deterministic composition of the same primitives the CLI
 * and dashboard use — no new cryptography, no new state, no global singletons.
 */

export const PROOF_URI_SCHEME = 'piproof';
export const PROOF_URI_VERSION = 1;

function b64uEncode(str) {
  return Buffer.from(str, 'utf8').toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64uDecode(text) {
  const pad = text.length % 4 === 0 ? '' : '='.repeat(4 - (text.length % 4));
  return Buffer.from(text.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64').toString('utf8');
}

/**
 * piproof://v1?p=<base64url document> — a self-contained proof link.
 * The document travels IN the URI (no server, no lookup), so it can be
 * pasted anywhere; verification still requires the verifier's own registry.
 */
export function toProofUri(doc) {
  if (doc === null || typeof doc !== 'object' ||
      (doc.type !== PIPROOF_TYPE && doc.type !== PASSPORT_TYPE)) {
    throw new TypeError('toProofUri expects a PiProof or AUREVIA-Evidence-Passport object');
  }
  return `${PROOF_URI_SCHEME}://v${PROOF_URI_VERSION}?p=${b64uEncode(JSON.stringify(doc))}`;
}

export function parseProofUri(uri) {
  if (typeof uri !== 'string') return null;
  const m = uri.match(/^piproof:\/\/v1\?p=([A-Za-z0-9_-]+)$/);
  if (!m) return null;
  try {
    const doc = JSON.parse(b64uDecode(m[1]));
    return (doc !== null && typeof doc === 'object' &&
      (doc.type === PIPROOF_TYPE || doc.type === PASSPORT_TYPE)) ? doc : null;
  } catch {
    return null;
  }
}

/**
 * Create a verifier bound to YOUR trusted state. Every call re-verifies
 * against this registry + nonce store; nothing is cached between calls.
 */
export function createVerifier({ registry, nonceStore, now = Date.now, metrics = null }) {
  if (registry === null || typeof registry !== 'object') {
    throw new TypeError('createVerifier requires a trusted registry object');
  }
  const at = () => (typeof now === 'function' ? now() : now);

  function run(document, opts) {
    const policyRef = opts?.policy ?? null;
    let inlinePolicy = null;
    try {
      inlinePolicy = resolvePolicy(policyRef);
    } catch (err) {
      return {
        decision: 'DENY', ok: false, code: 'POLICY_PRESET_UNKNOWN',
        binding: null, violations: [{ rule: 'preset', detail: err.message }],
        policy_used: typeof policyRef === 'string' ? policyRef
          : (policyRef && typeof policyRef === 'object' && policyRef.preset) || 'inline',
        result: { ok: false, steps: [] },
        error: err.message
      };
    }
    const res = document !== null && typeof document === 'object' && document.type === PASSPORT_TYPE
      ? verifyPassport(document, { registry, nonceStore, now: at(), policyOverride: inlinePolicy, metrics })
      : verifyPiProof(document, { registry, nonceStore, now: at(), policy: inlinePolicy, metrics });
    const binding = res.binding ?? res.summary?.binding ?? null;
    const presetName = typeof policyRef === 'string' ? policyRef
      : (policyRef && typeof policyRef === 'object' && policyRef.preset) || (inlinePolicy ? 'inline' : null);
    const violations = Array.isArray(res.policy?.violations) ? res.policy.violations : [];
    return {
      decision: res.ok ? 'ALLOW' : 'DENY',
      ok: res.ok,
      code: res.code ?? null,
      binding,
      violations,
      policy_used: presetName,
      result: res
    };
  }

  return {
    /** Verify one PiProof envelope → full step-by-step verdict. */
    verifyProof: (proof, opts = {}) =>
      verifyPiProof(proof, { registry, nonceStore, now: at(), policy: resolvePolicy(opts.policy), metrics }),
    /** Verify an Evidence Passport → per-proof results + summary. */
    verifyPassport: (passport, opts = {}) =>
      verifyPassport(passport, { registry, nonceStore, now: at(), policyOverride: resolvePolicy(opts.policy), metrics }),
    /** One-call decision: 'ALLOW' | 'DENY' with reasons. Proof or Passport. */
    decide: (document, opts = {}) => run(document, opts)
  };
}

export function formatDecision(d) {
  const head = `${d.decision}${d.code ? ` [${d.code}]` : ''}`;
  const bits = [];
  if (d.binding) bits.push(`binding=${d.binding}`);
  if (d.policy_used) bits.push(`policy=${d.policy_used}`);
  for (const v of d.violations ?? []) bits.push(`${v.rule}: ${v.detail}`);
  return `${head}${bits.length ? ' — ' + bits.join(' · ') : ''}`;
}
