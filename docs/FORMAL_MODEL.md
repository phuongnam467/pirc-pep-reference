# Formal Model (draft)

**Status:** engineering formalization since v0.15. This is a *paper model* of
the shipped implementation — precise enough to review against the code line by
line, not yet a machine-checked proof. It exists so external reviewers can
attack claims one invariant at a time instead of re-deriving the design from
scattered prose. Machine-checkable fragments are referenced under each
invariant (`Verified-by`), which is where confidence actually lives today.

**Scope:** the PEP/1 engagement-event primitive only (`src/events.js`,
`src/verify.js`, `src/nonces.js`, `src/canonical.js`, `src/schema.js`,
`src/registry.js`, `src/keys.js`). Passport/escrow/pfloor reuse the same gate
pattern with their own schemas; their specifics stay out of this draft.

---

## 1. System state

```
NonceSet   ⊆ AppId × Nonce          // set of burned claims, durable
Registry   : AppId → KeySet × Status // verifier-local snapshot, point-in-time
Clock      : → Time                  // verifier wall clock, NTP-assumed skew ≤ W/2
```

An **event** `e` is a closed-schema record
`(v, app_id, key_id, pioneer_uid_hash, action_id, action_class, weight,
timestamp, nonce, eligibility{…}, signature)`.

`accept(e, R, N, now)` is the verifier transition function. It is **total**
(every input yields ACCEPT or exactly one rejection code) and **fail-closed**
(any doubt rejects).

## 2. Verification state machine

Gates execute strictly in order; first failure terminates with that code.
Later gates are therefore *unreachable* until all earlier ones pass — order is
itself part of the security contract (cheap structural checks precede
cryptographic ones; state mutation happens last).

| Gate | Check | Reject codes | Mutates state? |
|---|---|---|---|
| G1 | closed schema: exact key set, types, sizes, depth | `SCHEMA` | no |
| G2 | app known in registry snapshot | `APP_KNOWN` (`UNKNOWN_APP`) | no |
| G3 | key resolves & `status == active` | `KEY_ACTIVE` (`UNKNOWN_KEY`, `REVOKED_KEY`) | no |
| G4 | canonical fixed point: `c1 == canon(parse(c1))` over body w/o `signature` | `CANONICALIZATION` | no |
| G5 | Ed25519 verify over `DOMAIN ‖ "\n" ‖ c1` | `SIGNATURE` | no |
| G6 | freshness: `−W ≤ now − e.timestamp ≤ +W` | `TIMESTAMP_FRESHNESS` (`TIMESTAMP_IN_FUTURE`, `TIMESTAMP_EXPIRED`) | no |
| G7 | class ceiling: `e.weight ≤ C[e.action_class]` | `WEIGHT_BOUND` (`WEIGHT_OVERFLOW`) | no |
| G8 | registry eligibility flags | `ELIGIBILITY` (`INELIGIBLE_USER`) | no |
| G9 | atomic nonce claim `(app_id, nonce)` | `REPLAY_DETECTED` | **yes — burn on pass only** |

Terminal states: `ACCEPT` iff all nine gates pass; otherwise `REJECT(code)`
with a per-gate trace (`checks`) for auditors. G1–G8 are pure; only G9 writes.

## 3. Security invariants

Each invariant lists where it is enforced in code and where it is currently
verified mechanically. An invariant whose `Verified-by` is empty is an honest
gap, not a checked box.

- **INV-01 — Canonical idempotence.** `canon(parse(canon(x))) =
  canon(parse(x))` for every accepted `x`. Without it, `isCanonical()` would
  reject documents the protocol itself produced.
  Enforced-by: Profile v1.1 NFC-form sort (`src/canonical.js`). Verified-by:
  canonical-property fuzz suite (determinism + idempotence + reject-only-
  CanonicalError), 15 interop vectors byte-exact in two implementations.

- **INV-02 — Signature binds content, not presentation.** Any mutation of any
  signed field changes canonical bytes and fails G5.
  Enforced-by: signing over `DOMAIN ‖ canonical(body)`. Verified-by: interop
  vectors (mutation cases), attack harness (`tamper-*` scenarios).

- **INV-03 — Closed-world parsing.** No field outside the pinned key set is
  ever read; unknown/duplicate/oversized/deep documents die at G1.
  Enforced-by: `src/schema.js` exact-key-set checks. Verified-by: schema fuzz
  campaign (fail-closed under random mutation, incl. `__proto__` injection),
  prototype-pollution vector 20.

- **INV-04 — At-most-one acceptance per `(app_id, nonce)`.** Two verifiers can
  never both reach ACCEPT for the same claim.
  Enforced-by: atomic `claimIfAbsent` — in-process synchronous test-and-set;
  cross-process O_EXCL lockfile with liveness-aware ownership, fresh re-read
  under lock, append+fsync, then release. Verified-by: concurrency fuzz
  campaign (K=8 OS processes racing one nonce → exactly one winner),
  `test/nonces.test.js`, `test/lock-semantics.test.js`.

- **INV-05 — Burn-on-pass only.** A rejected event never consumes its nonce.
  Enforced-by: G9 ordering (claim executes after all checks).
  Verified-by: `failed verification does not burn the nonce` unit test.

- **INV-06 — Bounded blast radius under lying issuers.** Even valid signatures
  cannot exceed class ceilings.
  Enforced-by: G7 after G5. Verified-by: `WEIGHT_OVERFLOW` attack scenario +
  trust-boundary test suite (lying-backend case documented by design).

- **INV-07 — Registry authority.** Payload-borne `eligibility` never grants
  access; G8 reads only the verifier-loaded snapshot.
  Verified-by: `registry says kyc_passed=false even though signed event claims
  true -> REJECT` unit test.

- **INV-08 — Revocation is a snapshot operation.** Compromised keys stop
  verifying once verifiers reload the registry; no path accepts a revoked-key
  signature. Verified-by: key-rotation/revocation tests. Known limit: fleet
  propagation is asynchronous (point-in-time registries) — documented, not
  hidden.

- **INV-09 — Symmetric freshness.** Future-stamped and expired events are
  distinct failure modes with distinct codes; both bounded by ±W.
  Enforced-by: G6. Verified-by: `TIMESTAMP_IN_FUTURE`/`TIMESTAMP_EXPIRED`
  attack scenarios.

- **INV-10 — Own-property resolution everywhere.** Registry lookups cannot be
  diverted through prototype chains (`constructor`, `__proto__`).
  Enforced-by: `Object.hasOwn` discipline in `src/registry.js`.
  Verified-by: vector 20.

- **INV-11 — Crash durability of acceptance.** An ACCEPT that returned to a
  caller survives hard restart; a crash mid-write leaves at most one torn log
  line which subsequent readers skip and count, never trust.
  Enforced-by: append-log + `fsyncSync` before unlock; corrupt-line skipping.
  Verified-by: `FileNonceStore` persistence/crash tests.

- **INV-12 — Lock ownership liveness.** A lock held by a live same-host process
  is never stolen regardless of age; takeover requires provable owner death
  plus staleness (or foreign-host fallback). Prevents the classic
  stale-lock-timeout double-entry race.
  Enforced-by: `_acquireLock` PID-liveness rules (v0.15).
  Verified-by: `test/lock-semantics.test.js` (6 cases incl. cross-process
  races).

## 4. Failure semantics of the claim path

| Crash point | Observable result | Safety |
|---|---|---|
| before lock acquired | nothing written; event retryable | safe (no burn) |
| holding lock, before append | nothing written; lock stolen after staleness/liveness rules; retryable | safe |
| mid-append (torn line) | trailing partial line skipped+counted by every reader; claim not burned | fail-closed |
| after append+fsync, before unlock | claim durable; next contender re-reads log under fresh lock and sees it | safe (no double-accept) |
| after unlock | claim durable; replays rejected forever | safe |

The one residual hazard class — multiple hosts sharing a single store volume
without shared locking or synchronized clocks — is out of scope by explicit
contract ([NONCE_STORES.md](NONCE_STORES.md)); multi-host fleets must use a
strongly-consistent shared store (`RedisNonceStore`, DB unique constraint).

## 5. Implementer MUSTs (normative summary)

Any independent implementation claiming PEP/1 conformance MUST:

1. implement Canonical Profile v1.1 and reproduce all 16 interop vectors
   byte-for-byte ([CANONICALIZATION.md](CANONICALIZATION.md));
2. enforce gates G1→G9 **in that order**, rejecting on first failure;
3. make G9 the only state-mutating gate, atomic per `(app_id, nonce)`;
4. treat any parse-level surprise (unknown keys, duplicate keys) as fatal;
5. sign and verify over domain-separated canonical bytes excluding
   `signature`;
6. document — not hide — the deployment boundary of its nonce store.

## 6. Path to stronger guarantees

Deliberately not claimed here: TLA+/Alloy models, mechanized proofs,
symbolic-execution coverage reports. The gap between this document and those
artifacts is precisely what the external audit (issue #2) and the third-party
implementation exercise are meant to measure. Contributions toward either are
welcome and will be gated by the same CI bar as everything else.
