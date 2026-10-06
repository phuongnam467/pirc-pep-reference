# Trust Boundaries — what this system can and cannot prove

This document exists because the most important security question about PEP
is not about cryptography. It is about **what the verifier is allowed to
assume**. Every limitation below is stated plainly; none of them are hidden.

---

## 1. The registry is the largest trust assumption

**Question every security reviewer asks first:** *"How does a verifier know
that registry `R` is authentic?"*

Honest answer for the current reference implementation: **it doesn't, yet.**
The registry (`apps`, public keys, key status, eligibility) is a trusted
input to verification. A perfectly valid Ed25519 verification performed over
a tampered registry proves nothing about the real world.

### What exists today

- **Content addressing.** The registry's canonical form has a deterministic
  root hash: `registryRootHash(registry)` → `r1:<sha256>` (`src/piproof.js`).
  Two parties can now *detect* divergence: if our roots differ, we hold
  different worlds. PiProof envelopes may carry `registry_root`; a verifier
  rejects proofs minted against a foreign epoch (`REGISTRY_ROOT` step).
- **Registry mutations are explicit API calls** (`registerApp`,
  `registerKey`, `revokeKey`, `markEligible`) — there is no accidental state.
- **Key lifecycle is signed-adjacent:** revocation flips status before any
  proof from that key is accepted again.

### Production roadmap (required before any v1.0 deployment claim)

1. **Signed epoch roots.** The launchpad signs `{epoch, root_hash,
   expires_at}` with a long-lived governance key. Verifiers pin the
   governance public key out-of-band and accept only epoch roots under it.
2. **Transparency log.** Epoch roots append to an append-only Merkle log;
   monitors gossip for split-view. Consistency proofs make silent registry
   rewrites detectable by third parties.
3. **Eligibility as claims.** KYC/Mainnet eligibility moves from mutable
   registry rows into individually signed, expiring claims — shrinking the
   blast radius of any single registry compromise.

Until those ship, the correct characterization is: *registry integrity is a
deployment-level property, not a protocol-level guarantee.*

## 2. Nonce stores: single-host primitive vs distributed replay protection

The nonce store contract is exactly one operation:
`claimIfAbsent(key) → boolean`, which must be **atomic** (test-and-set).

| Backend | Atomic? | Crash-durable? | Shared across verifiers? |
|---|---|---|---|
| `InMemoryNonceStore` | yes | no | no |
| `FileNonceStore` (fsync'd JSONL) | per-process | yes | no |
| Redis `SET NX PX` | yes | configurable | yes |
| SQL `UNIQUE` constraint + insert | yes | yes | yes |

`FileNonceStore` does **not** replicate across networked verifiers. Running
verifiers A–D with independent local stores means the same event can be
accepted once *per* store. That is not replay protection at fleet scale.

**Production requirement:** all verifiers in a deployment MUST share one
strongly-consistent nonce state (Redis/SQL class), or replay semantics must
be redesigned around that topology. The store interface here is intentionally
narrow so those backends slot in without touching verification logic.

## 3. Timestamp freshness ≠ replay protection

These are separate mechanisms and both are needed:

- **Freshness window (±5 min)** bounds how long a signature remains
  *submittable*. It limits the replay horizon but proves nothing on its own.
- **Single-use nonce** is what actually prevents replay. If the nonce store
  loses state, then `valid signature + fresh timestamp` alone will be
  accepted again — that is inherent to the design, not a bug, and it is why
  §2 durability requirements exist.

## 4. Supply chain

Runtime has zero npm dependencies (CI-enforced). CI supply chain is a real
surface regardless: all GitHub Actions used by this repo are **pinned to
full commit SHAs** (`ci.yml`, `deploy-pages.yml`). Roadmap: artifact
provenance attestation, SBOM publication, signed releases.

## 5. Audit status — read this before trusting anything

This project is a **security-conscious reference implementation**, not an
externally audited production cryptographic standard.

- "20/20 attacks rejected" means: twenty specific adversarial scenarios are
  covered by tests and each is rejected with its expected error code.
  It does **not** mean twenty vulnerabilities were found and fixed, and it
  does not bound the total attack space.
- No external audit has taken place. A `v1.0` tag is explicitly blocked on
  external review ([issue #2](https://github.com/EslaM-X/piproof/issues/2)).
- Canonicalization hardening note: object keys are sorted raw but serialized
  NFC-normalized; keys that collide after normalization are rejected rather
  than silently merged (`CanonicalError`). Within the current closed PEP/1
  schema (ASCII keys only) this was unreachable — it is tightened anyway so
  the primitive is safe for general reuse.
