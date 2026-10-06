/**
 * Named Trust Policy presets — deterministic, versioned, code-frozen.
 *
 * A preset is a plain normalized policy object under a stable name+version,
 * so applications can say `use policy: merchant-verification-v1` instead of
 * hand-rolling rules. Presets are DATA: auditable in source control, frozen
 * per version (a change means a new version, never a silent edit), and
 * evaluated by the same narrowing-only engine as inline policies.
 *
 * This is deliberately NOT a "policy marketplace" — no signing, no registry,
 * no discovery protocol. Just honest, reviewable defaults.
 */

export const PRESET_VERSION = 1;

const HOUR = 3_600_000;

function preset(name, description, policy) {
  return Object.freeze({ name, version: PRESET_VERSION, description, policy: Object.freeze(policy) });
}

export const POLICY_PRESETS = Object.freeze({
  'merchant-verification-v1': preset(
    'merchant-verification-v1',
    'A merchant may transact: KYC + Mainnet pioneer, class A/B activity, recent (24h), epoch-bound proof.',
    {
      action_classes: ['A', 'B'],
      min_weight: 5,
      max_age_ms: 24 * HOUR,
      require_kyc: true,
      require_mainnet: true,
      require_epoch_bound: true
    }
  ),
  'marketplace-seller-v1': preset(
    'marketplace-seller-v1',
    'Seller eligibility for listings: strong class-A history, KYC + Mainnet, epoch-bound, fresh 12h.',
    {
      action_classes: ['A'],
      min_weight: 10,
      max_age_ms: 12 * HOUR,
      require_kyc: true,
      require_mainnet: true,
      require_epoch_bound: true
    }
  ),
  'agent-payment-v1': preset(
    'agent-payment-v1',
    'AI agent payment authorization: class A only, any registered issuer, KYC + Mainnet, epoch-bound, tight 5-minute freshness.',
    {
      action_classes: ['A'],
      min_weight: 1,
      max_age_ms: 5 * 60_000,
      require_kyc: true,
      require_mainnet: true,
      require_epoch_bound: true
    }
  ),
  'community-member-v1': preset(
    'community-member-v1',
    'Community membership signal: any verified activity, KYC required, Mainnet NOT required, week-old evidence acceptable.',
    {
      action_classes: ['B', 'C'],
      min_weight: 1,
      max_age_ms: 7 * 24 * HOUR,
      require_kyc: true
    }
  ),
  'reward-eligibility-v1': preset(
    'reward-eligibility-v1',
    'Reward/airdrop eligibility: any class, KYC + Mainnet, epoch-bound, fresh 24h.',
    {
      min_weight: 1,
      max_age_ms: 24 * HOUR,
      require_kyc: true,
      require_mainnet: true,
      require_epoch_bound: true
    }
  )
});

/**
 * Resolve a policy reference to a concrete policy object.
 *   string        → named preset lookup (throws on unknown)
 *   plain object  → returned as-is (inline policy, caller-owned)
 *   null/undefined→ null (no policy)
 */
export function resolvePolicy(ref) {
  if (ref === null || ref === undefined) return null;
  if (typeof ref === 'string') {
    const presetRef = POLICY_PRESETS[ref];
    if (!presetRef) {
      throw new Error(`unknown policy preset: ${ref} — available: ${Object.keys(POLICY_PRESETS).join(', ')}`);
    }
    return presetRef.policy;
  }
  if (typeof ref === 'object' && !Array.isArray(ref)) {
    if (typeof ref.preset === 'string') {
      const byRef = POLICY_PRESETS[ref.preset];
      if (!byRef) {
        throw new Error(`unknown policy preset: ${ref.preset} — available: ${Object.keys(POLICY_PRESETS).join(', ')}`);
      }
      return byRef.policy;
    }
    return ref;
  }
  throw new Error('policy must be a preset name, {"preset":"name"}, or an inline rule object');
}

export function listPolicyPresets() {
  return Object.values(POLICY_PRESETS).map((p) => ({
    name: p.name,
    version: p.version,
    description: p.description,
    rules: p.policy
  }));
}
