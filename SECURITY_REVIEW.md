# Security Review — process & ledger

PiProof's security posture is **process + evidence**, not assurance
theater. This document defines how review happens and keeps the public
ledger of findings.

## Scope of a review pass

A pass covers, at minimum:

1. **Canonical Profile** — lexical traps: number boundaries (±(2^53−1)),
   exponent forms, NFC collisions (`é` vs `\u0065\u0301`), UTF-16 vs
   code-point ordering, duplicate keys after unescaping, depth bombs.
2. **Signature pipeline** — domain separation bytes, canonical-vs-raw
   confusion, SPKI parsing lengths, malleability handling.
3. **Gate ordering** — no gate may leak information another gate would
   have rejected first; failures are atomic and non-instrumented beyond
   counters.
4. **Replay semantics** — burn-on-pass only after full acceptance;
   stateless verifiers must surface `NONCE_REPLAY=UNVERIFIABLE`.
5. **Registry trust** — `registry_root` pinning, key revocation paths,
   eligibility gating (no client-supplied eligibility is ever trusted).
6. **Court integrity** — ballot message binding (round/case/judge),
   tally purity (no mutation laundering), referee capability checks,
   anchor payload determinism.

## Methods used so far

| Method | Artifact |
|--------|----------|
| Property-based differential fuzzing (JS ↔ Python ↔ Go) | `scripts/fuzz-diff-driver.*`, CI job `fuzz-diff` |
| Formal transition model | `docs/FORMAL_MODEL.md`, TLC runs in CI (`formal-check`) |
| Attack corpus as regression tests | `test/attacks.test.js`, 20 vectors |
| Byte-determinism proofs (court anchors) | `test/court.test.js` |
| Strict browser CSP / header hardening | `test/hardening.test.js`, `test/web-offline.test.js` |

## Findings ledger

Format: ID · date · component · severity · summary · status.
Empty means empty — we do not backfill drama.

| ID | Date | Component | Severity | Summary | Status |
|----|------|-----------|----------|---------|--------|
| *(none open)* | | | | | |

Resolved-in-history examples kept for honesty:

| F-001 | 2026-08 | court tally | low | `tallyRound` mutated shared state making replays order-sensitive | fixed v0.18.0; pure `computeTally` split out + regression test |

## Reporting

Open a security advisory via GitHub "Report a vulnerability" on
EslaM-X/piproof. We acknowledge within 7 days, credit reporters by
default (opt-out), and publish findings here after a fix ships. No bug
bounty yet — reputation and the adopters table are the currency.
