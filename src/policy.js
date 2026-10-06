/**
 * Trust Policy Engine — deterministic, pure, zero I/O.
 *
 * A policy constrains WHICH verified proofs a relying party accepts. Policy
 * evaluation never re-runs cryptography; it runs after `verifyPiProof`
 * reports a cryptographically valid event and can only narrow acceptance.
 *
 * Supported rules (all optional):
 *   issuer_allowlist      array of app_ids; empty/absent = any registered issuer
 *   action_classes        array of PEP action classes (A|B|C)
 *   min_weight            integer, inclusive
 *   max_weight            integer, inclusive
 *   max_age_ms            tighter freshness than the protocol window
 *   require_kyc           boolean — registry-confirmed KYC
 *   require_mainnet       boolean — registry-confirmed Mainnet migration
 *   require_epoch_bound   boolean — reject LOCAL (non epoch-pinned) proofs
 *
 * Deliberate v1 scope — this is a flat rule checklist, NOT a policy language:
 * no AND/OR composition, no nested predicates, no issuer groups, no temporal
 * rules beyond `max_age_ms`, no policy signatures or inheritance, no
 * delegation. Rules are evaluated independently and every violation is
 * reported; acceptance is monotone-narrowing by construction. The grammar and
 * its evolution path are documented in docs/POLICY_MODEL.md.
 */

const ACTION_CLASSES = ['A', 'B', 'C'];

export function normalizePolicy(policy) {
  const p = policy === null || typeof policy !== 'object' ? {} : policy;
  const out = {};
  if (Array.isArray(p.issuer_allowlist)) out.issuer_allowlist = [...p.issuer_allowlist];
  if (Array.isArray(p.action_classes)) out.action_classes = p.action_classes.filter((c) => ACTION_CLASSES.includes(c));
  for (const k of ['min_weight', 'max_weight', 'max_age_ms']) {
    if (Number.isSafeInteger(p[k]) && p[k] >= 0) out[k] = p[k];
  }
  for (const k of ['require_kyc', 'require_mainnet', 'require_epoch_bound']) {
    if (typeof p[k] === 'boolean') out[k] = p[k];
  }
  return out;
}

export function evaluatePolicy(event, ctx, policy) {
  const p = normalizePolicy(policy);
  const violations = [];
  const now = ctx && Number.isSafeInteger(ctx.now) ? ctx.now : Date.now();
  const binding = ctx && typeof ctx.binding === 'string' ? ctx.binding : null;

  if (p.require_epoch_bound === true && binding !== 'EPOCH_BOUND') {
    violations.push({
      rule: 'require_epoch_bound',
      detail: `proof is ${binding ?? 'UNBOUND'} — policy requires an epoch-bound envelope (registry_root)`
    });
  }
  if (p.issuer_allowlist && !p.issuer_allowlist.includes(event.app_id)) {
    violations.push({ rule: 'issuer_allowlist', detail: `issuer "${event.app_id}" is not on the accepting list` });
  }
  if (p.action_classes && !p.action_classes.includes(event.action_class)) {
    violations.push({ rule: 'action_class', detail: `class ${event.action_class} not permitted (allowed: ${p.action_classes.join(',') || 'none'})` });
  }
  if (p.min_weight !== undefined && event.weight < p.min_weight) {
    violations.push({ rule: 'min_weight', detail: `weight ${event.weight} < required ${p.min_weight}` });
  }
  if (p.max_weight !== undefined && event.weight > p.max_weight) {
    violations.push({ rule: 'max_weight', detail: `weight ${event.weight} > permitted ${p.max_weight}` });
  }
  if (p.max_age_ms !== undefined && now - event.timestamp > p.max_age_ms) {
    violations.push({ rule: 'max_age', detail: `proof age ${now - event.timestamp}ms exceeds policy maximum ${p.max_age_ms}ms` });
  }

  const elig = event.eligibility ?? {};
  if (p.require_kyc === true && elig.kyc_passed !== true) {
    violations.push({ rule: 'require_kyc', detail: 'KYC confirmation missing' });
  }
  if (p.require_mainnet === true && elig.mainnet_migrated !== true) {
    violations.push({ rule: 'require_mainnet', detail: 'Mainnet migration flag missing' });
  }

  return { pass: violations.length === 0, violations, policy: p };
}
