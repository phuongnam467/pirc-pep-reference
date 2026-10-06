# External Implementation Kit — build your own verifier

PiProof is designed so that **an implementation written by someone who
never met us** can verify proofs and be proven compatible. This document
is the challenge brief; [`SECURITY_REVIEW.md`](SECURITY_REVIEW.md)
describes what happens when you submit.

## What you must implement

From [`SPEC.md`](../SPEC.md) alone:

1. **Canonical Profile v1.1** (`canonicalize`) — the hardest part.
   Lexical number rules, NFC normalization, UTF-16 key ordering,
   duplicate-key rejection. 16 public vectors in
   `vectors/canonical/index.json` are byte-exact or rejection-exact.
2. **PEP/1 verification** — gates G1–G9 over a pinned registry:
   closed schema → app known → key active → canonicalization → Ed25519
   (RFC 8032, SPKI "raw32") → freshness window → weight ceiling →
   registry-gated eligibility → burn-on-pass nonce. Error codes are
   normative; messages are not.
3. **h1 pseudonyms** — `h1:base64url(HMAC-SHA256(secret, NFC(uid)))`.
4. **(Optional) PiProof/1 envelopes** — `registry_root` epoch pinning via
   `r1:sha256(canonical(registry))`.
5. **(Optional) Passport/1** — signed capability documents with expiry.

The attack corpus (`vectors/attacks/`, 20 cases) is your adversarial test
suite: every case must be rejected with the listed code.

## Ground rules

- **No runtime dependencies on the reference repo.** Your verifier takes
  `(event_text, registry_json, now)` as inputs. Nothing is fetched.
- **G9 honesty**: if you have no state store, you must report
  `NONCE_REPLAY` as UNVERIFIABLE — never silently green. See how the Rust
  crate does it (`sdk/rust/src/lib.rs`).
- **Any language, any license.** We only require that conformance runs
  from this repository's vectors without modification.

## Submission checklist

- [ ] All 16 canonical vectors pass (byte-exact or correct error class).
- [ ] The valid event verifies at `now = 1755860000000` against
      `vectors/registry.json`.
- [ ] All 20 attacks rejected with the expected codes.
- [ ] Tamper matrix: changing any single byte of the canonical body
      yields `INVALID_SIGNATURE`; changing `nonce` alone yields replay
      detection **with state** / UNVERIFIABLE **without**.
- [ ] G9 documented honestly (stateless vs stateful behavior).
- [ ] A README stating dependency policy (what crypto primitives you
      trust and why).
- [ ] CI reproducible from a clean checkout.

## Where to submit

Open a PR adding your implementation under `implementations/<name>/`
with its own tests wired into the checklist above, plus an issue titled
`conformance: <name>`. Maintainers run the differential harness
(`scripts/fuzz-diff-driver.*`) against your binary for 10k generations;
zero divergences + review → listed in [`ADOPTERS.md`](ADOPTERS.md).
