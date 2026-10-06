# Security Policy & Threat Model

## Scope

This repository is a reference implementation of the PEP/1 engagement-event
primitive only. It does not implement token allocation, on-chain contracts, or
oracle aggregation. It is intended as auditable building material for the
engagement-reporting layer discussed in PiRC1 PR #2.

## Threat model

| Adversary | Capability | Mitigation |
|---|---|---|
| Bot farm / Sybil | submits fake engagement events | events without a valid backend signature fail at SIGNATURE; ineligible pioneers fail at ELIGIBILITY (registry-gated KYC/Mainnet) |
| Malicious user | edits weight/action/pioneer fields after capture | any mutation invalidates SIGNATURE (canonical bytes bound) |
| Replay attacker | resubmits captured valid payloads | nonce claimed via **atomic test-and-set** (`claimIfAbsent`): check-and-record is indivisible in memory and lock-protected across processes for `FileNonceStore`; duplicates rejected with REPLAY_DETECTED |
| Stale-data attacker | delays old payloads beyond usefulness | ±5 min timestamp window |
| Compromised/misbehaving backend | signs inflated weights | WEIGHT_BOUND caps per class even for valid signatures; revocation path for compromised keys via key_id rotation |
| Cross-app forgery | uses another app's legitimately-signed payload | APP_KNOWN+KEY_ACTIVE resolve under the claimed app_id; foreign signatures fail |
| Registry tampering | modifies registry.json in transit | out of scope here: production registries MUST be content-addressed and served from launchpad-controlled infrastructure |
| Prototype-pollution embedder | feeds registry objects whose prototype chains carry hostile properties | all registry lookups/writes use own-property semantics (`Object.hasOwn`); inherited names like `constructor` can never resolve as apps, keys, or users (vector 20) |
| Resource-exhaustion signer | submits pathologically deep/oversized structures | closed schema rejects unknown/oversized fields before any recursion; canonicalizer enforces a depth cap (64) as defense-in-depth |
| Unicode-confusion forger | submits NFD/NFC look-alike variants to split identity hashes or signatures | canonicalizer normalizes every string to NFC before hashing/signing; UID HMACs are computed over NFC-normalized identifiers |
| Log corrupter / crash | truncates or garbles the durable nonce log mid-write | torn trailing lines and malformed entries are skipped and counted (`corruptLines`), never trusted, never fatal; `compact()` rewrites via temp-file + atomic rename |

### Identity hashing model

`pioneer_uid_hash` values are **keyed** HMAC-SHA256 tags: `h1:HMAC(secret,
NFC(uid))`, base64url-encoded with an explicit version prefix. The backend
secret MUST be at least 16 chars and kept outside event payloads. Keyed hashing
prevents rainbow-table precomputation over the Pi UID space; the version prefix
allows future rotation to `h2:` without ambiguity. Legacy bare-sha256 tags
(`[0-9a-f]{64}`) remain readable by `markEligible` but SHOULD NOT be issued.

### Pseudonymization is not anonymity (v0.13, stated explicitly)

The `h1:` HMAC design is **pseudonymization**, not unlinkable anonymity:

- **What it buys:** without the per-issuer secret, an observer cannot map a
  tag to a Pi UID, and cannot precompute dictionaries over the UID space.
- **What it does NOT buy:** if two applications share one uid secret, tags
  are identical across them and **cross-application correlation becomes
  trivial**. Unlinkability is therefore a *secret-management* property, not a
  cryptographic guarantee of this scheme.
- Operational rules that follow: each application MUST hold its own
  `uidSecret`; sharing or centralizing secrets re-couples all pseudonyms;
  rotation changes tags wholesale (`h1:` → `h2:` prefix keeps old evidence
  interpretable).
- Any external claim of "privacy-preserving" MUST be read as "keyed,
  non-invertible outside the issuer" — never as "anonymous" or "unlinkable".

### Nonce-store guarantees

- `InMemoryNonceStore.claimIfAbsent` is indivisible within a process
  (synchronous test-and-set on one event-loop turn).
- `FileNonceStore.claimIfAbsent` is atomic **across processes**: exclusive
  O_EXCL lockfile with **liveness-aware ownership** (v0.15) → fresh re-read of
  the log → append → `fsyncSync` → unlock. A claim that returned true survives
  hard restarts; a crash mid-append leaves at most one torn line that fails
  closed. Lock takeover rules, precisely:
  - a lock whose recorded owner PID is **alive on the same host** is never
    stolen, regardless of age;
  - a lock whose owner is provably dead (same host, no such PID) may be taken
    once it is also older than the staleness window;
  - locks from other hosts (or legacy/anonymous locks from v0.14-) fall back
    to the time-based staleness window as the last resort.
  Two verifier instances on one machine therefore cannot both win the same
  claim; the residual risk window is limited to cross-host fleets sharing one
  NFS volume with unsynchronized clocks — which this store explicitly does not
  support.
- Explicit non-goals: no network replication, no TTL/GC beyond `compact()`,
  no sharding. Horizontally scaled fleets still need a shared store (DB unique
  constraint / Redis SETNX); `FileNonceStore` narrows the gap from "demo" to
  "single-host production-grade".

## Explicit limitations (v1)

### Trust boundary: authenticity is not truthfulness

PEP proves **who claimed** an event and that the claim was not altered in
transit or replayed. It does **not** prove the event happened.

```
backend signs "user X completed action A"   →  signature VALID
did action A actually happen?               →  OUT OF SCOPE (issuer trust)
```

A legitimate-but-misbehaving backend can sign false claims that fall inside its
class ceilings; this reference implementation accepts them **by design**, and a
dedicated test (`test/trust-boundary.test.js`) documents exactly that. What the
protocol guarantees even against a lying issuer:

- blast radius is capped by class ceilings (`A≤100`, `B≤10`, `C≤1`) — inflation
  beyond protocol bounds fails with `WEIGHT_OVERFLOW` even under valid
  signatures;
- claims are attributable and non-repudiable (Ed25519 under a registered,
  revocable `key_id`);
- every accepted lie is auditable evidence for slashing/delisting decisions by
  the launchpad.

Truthfulness enforcement (staking/slashing, TEE attestation, multi-party
attestation, on-chain activity proofs) is deliberately out of scope for PEP/1
and belongs to the launchpad governance layer above it.

### Other v1 limitations

- A verifier fleet spanning multiple hosts MUST still share nonce state
  externally; the per-topology guarantees (and the explicit statement that
  `FileNonceStore` is NOT distributed replay protection) are normative in
  [docs/NONCE_STORES.md](docs/NONCE_STORES.md). `FileNonceStore` covers a
  single host with real cross-process locking and crash durability;
  `RedisNonceStore` covers multi-host fleets behind one strongly consistent
  authority.
- The registry is a **point-in-time snapshot**: revocations and eligibility
  flips take effect when verifiers load the updated registry, not
  instantaneously fleet-wide.
- Timestamps rely on synchronized clocks (NTP); skew window is configurable.
- The eligibility registry is a plain map in this reference. Production SHOULD
  derive it from Pi's KYC/Mainnet migration records.
- No confidentiality: envelopes are public data by design. Never place raw Pi
  UIDs inside events; only `h1:` HMAC tags.

## Reporting

Open a GitHub security advisory rather than a public issue.

## Runtime parser divergence (V8 `JSON.parse`) — disclosed v0.15

While building the differential fuzzing suite (`scripts/fuzz.mjs`), we found a
**Node.js runtime defect**, not a PiProof protocol defect. It is documented
here because any consumer parsing untrusted JSON with Node should know about
it.

### What happens

After enough allocation churn (thousands of short-lived strings containing
exotic characters), `JSON.parse` can return an object whose key set differs
from the input text — e.g. a phantom key `"\""` (92) where the text says
`"\" "` escaped differently. We verified this with **byte-identical input**
(hexdump-compared): the same 146 bytes parse correctly in a fresh process and
incorrectly in a churned one, nondeterministically across runs. The behavior
depends on V8's internal allocation/hash-seed state, not on the input alone.
Python's `json.loads` parses the same bytes correctly in every trial; only
exact original key order in that document triggered it — every subset and
permutation parsed fine, which is what made it so hard to isolate.

### Impact on PiProof: none (unreachable)

The divergence is only reachable if attacker-controlled JSON is parsed and its
object keys are then *trusted semantically* without a fixed key set. Every
PiProof document type (`event`, `registry`, `passport`, …) is validated against
a closed schema that pins the exact allowed key set **before** any field is
used; unknown fields are rejected outright. A phantom key cannot become a
protocol field. The fuzz suite confirms: across all campaigns, no protocol
violation was ever produced — every idempotence anomaly traced back to
`JSON.parse` mis-reading bytes Python parsed correctly.

### Advice for other consumers

- If you parse untrusted JSON in Node and iterate object keys without schema
  pinning, treat unexpected keys as fatal (fail closed) — as PiProof does.
- Track upstream V8/Node for a fix; upgrade when available. The issue is not
  yet filed upstream at time of writing; reproduction details live in
  `scripts/fuzz.mjs` (parser-differential + canonical-property suites,
  `FUZZ_DUMP=<dir>` dumps triggering cases).

## Verification instructions

Every claim above is executable:

```
node --test
node src/cli.js attacks
```

CI runs both on Node 18/20/22 across Linux and Windows.

## Audit status (added v0.7.0)

This is a security-conscious reference implementation — it has **not**
received an external audit and must not be presented as one. "20/20 attacks
rejected" means twenty named adversarial scenarios pass in CI; it does not
mean twenty vulnerabilities were found, nor that the attack space is bounded.
A v1.0 tag remains blocked on external review (see issue #2).

Full boundary analysis — registry authenticity, distributed nonce
requirements, timestamp-vs-replay semantics, supply-chain posture — now
lives in [docs/TRUST_BOUNDARIES.md](docs/TRUST_BOUNDARIES.md).