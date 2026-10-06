# Trust Policy Model — v1 Grammar and Deliberate Scope

**Status:** normative companion to [SPEC.md](../SPEC.md); implemented in
`src/policy.js`.

## What the policy engine is

A **flat, deterministic rule checklist** that runs *after* cryptographic
verification and can only **narrow** acceptance. It never re-runs
cryptography, never performs I/O, and can never turn an invalid proof into a
valid one. Monotone-narrowing is a structural property: every rule maps a
verified event + context to either "no opinion" or "violation".

## The complete v1 grammar

| Rule | Type | Semantics |
|---|---|---|
| `issuer_allowlist` | `string[]` | event's `app_id` must appear in the list; empty/absent = any registered issuer |
| `action_classes` | `("A"\|"B"\|"C")[]` | class membership check |
| `min_weight` / `max_weight` | safe int, inclusive | weight bounds |
| `max_age_ms` | safe int ≥ 0 | tighter-than-protocol freshness |
| `require_kyc` | boolean | registry-confirmed KYC flag on the event's uid tag |
| `require_mainnet` | boolean | registry-confirmed Mainnet migration flag |
| `require_epoch_bound` *(v0.13)* | boolean | reject `LOCAL` proofs — the envelope must pin `registry_root` to one registry generation |

All rules are optional and independent; every violated rule is reported in
`violations[]`, and the verdict is pass iff the set is empty.

## What it is NOT (v1 non-goals, stated plainly)

This is a good v1 rules engine. It is **not** a policy language:

- no AND/OR composition or nested predicates — every rule is an independent
  conjunct by construction;
- no issuer groups beyond flat allowlists;
- no temporal rules beyond `max_age_ms` (no validity calendars, no business hours);
- no versioned or signed policy documents — policies are caller-supplied
  objects, trusted by whoever supplies them;
- no policy inheritance or delegation chains;
- no research-grade expressiveness claims.

Naming discipline follows the Dispute Engine precedent: call it a **v1 trust
policy checklist**, not a "policy engine framework", until the grammar grows.
Any extension MUST preserve monotone-narrowing and determinism, and SHOULD
arrive with conformance vectors like everything else.

## Evaluation order

1. `verifyPiProof` completes cryptography + protocol checks (signature,
   schema, freshness, ceilings, eligibility, replay);
2. only if those all pass, `evaluatePolicy(event, { now, binding }, policy)`
   runs;
3. violations surface as verdict code `POLICY` with per-rule details; the
   underlying crypto steps remain green — policy failure never masks a
   cryptographic fact.
