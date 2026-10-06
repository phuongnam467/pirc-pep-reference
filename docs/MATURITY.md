# Maturity Register — What This Project Is and Is Not

**Status:** living document; updated with every release. Read this before
quoting any capability of PiProof/AUREVIA in a deck, an article, or an
integration proposal.

## The one-paragraph verdict

PiProof is a **serious security-engineered reference implementation**: a
frozen protocol core, deterministic verification, adversarial test suites,
cross-language conformance vectors, honest trust-boundary documentation. It
is **not proven production infrastructure**, and nothing in this repository
should be read as claiming otherwise. The distinction is the product.

## Maturity levels

| Level | Status | Evidence held |
|---|---|---|
| Cryptographic reference implementation | ✅ **held** | 152 tests (Node), 20/20 named attacks rejected, byte-reproducible vectors, six independent verification implementations (Node + Python + Go + pure-JS browser + Rust + WASM) agreeing on Ed25519 *and* canonicalization |
| Security-engineering prototype | ✅ **held** | frozen PEP/1 core, fail-closed posture everywhere, supply-chain pinning, zero runtime dependencies, documented trust boundaries & audit-status honesty; property-based + differential fuzzing suite; layer-governance checker; engineering formal model (docs/FORMAL_MODEL.md); liveness-aware cross-process nonce locking |
| Production protocol infrastructure | ❌ **not claimed, not yet evidenced** | see the missing-evidence register below |

## Missing-evidence register (v0.15)

Each row names the claim we REFUSE to make until the evidence column is real.

| # | Capability | What would constitute evidence | Current status |
|---|---|---|---|
| 1 | Massive concurrent load | sustained multi-thousand-vCPU-equivalent load tests with saturation behavior documented | single-core benchmark (~7.3k proofs/s full pipeline) only |
| 2 | Multi-region consistency | deployed nonce authority per docs/NONCE_STORES.md with cross-region chaos tests | RedisNonceStore shipped; no production topology exercised |
| 3 | Operational incident history | months of real traffic with postmortems | none — zero production traffic |
| 4 | Key-compromise recovery at scale | rehearsed rotation/revocation runbook executed against live fleets | primitives exist (revocable key_ids); no rehearsal at scale |
| 5 | HSM integration | signing keys generated/held in HSMs, attested | file-based keys only |
| 6 | Registry distribution | signed registry epochs distributed to independent verifiers with freshness guarantees | verifiers hold their own copies by design; no distribution network |
| 7 | Byzantine registry operators | m-of-n witnessed registries or equivalent | TRANSPARENCY_LOG_DESIGN.md draft only — explicitly non-normative |
| 8 | Disaster recovery | tested restore of registry+nonce state under failure injection | not exercised |
| 9 | Long-term migration | a second protocol generation coexisting with the first | binding classes (EPOCH_BOUND/LOCAL) are the first additive step only |
| 10 | Cross-generation compatibility | old verifiers accepting new-generation documents or rejecting them cleanly | untested — no second generation exists |
| 11 | External independent security audit | report from a firm with cryptographic protocol experience | 🔒 v1.0 gate; none performed |
| 12 | Production deployment at meaningful scale | real applications relying on verdicts | none |
| 13 | Independent third-party implementation | a language/stack outside Node+Python reproducing all interop vectors and passing the fuzz property suite, maintained by someone else | **partially held (v0.16)**: a third from-scratch Go implementation (`sdk/go`) passes the full conformance matrix — proving the spec is reimplementable; *author-independence* remains the open half |
| 14 | Mechanized verification | TLA+/Alloy model of the G1–G9 pipeline checked against INV-01…INV-12 | **partially held (v0.16.1)**: `formal/piproof_gates.tla` is **model-checked by TLC on every push/PR** (CI job `formal-tlc`, checksum-pinned tla2tools v1.7.4): the complete 122-state space passes with INV-04/INV-05 + TypeOK/AcceptImpliesBurn holding; coverage beyond this subset toward INV-01…12 remains open |
| 15 | Decentralized dispute resolution | judge quorum, challenge periods, arbitration market, settlement anchoring — each real, replayable, and tamper-evident | **partially held (v0.18)**: the Arbitration Court implements all four mechanically ([docs/COURT.md](COURT.md)) — judges are keys with stakes & fees, verdicts are panel multi-signatures over exact tallies, challenges ARE replays, anchor certificates are byte-deterministic; what remains honest-open: stakes/fees are declared commitments (no token escrow), no chain broadcast ships in-repo (adapter contract only), and judge admission is a registry act, not an open market of humans |

## Language rules for anyone presenting this project

- Say: "reference implementation", "security-engineered prototype",
  "deterministic verification layer".
- Do NOT say: "production-grade cryptographic infrastructure",
  "bank-grade", "proven at scale", "audited" (until #11 lands).
- The attack suite number means exactly what SECURITY.md says: twenty named
  scenarios rejected in CI — not a bound on the attack space.
