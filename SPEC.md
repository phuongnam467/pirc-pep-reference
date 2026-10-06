# PiProof Protocol Specification — PEP/1 + Canonical Profile v1.1

**Version:** 1.0.0-normative · **Status:** frozen core (additive extensions only)
**Conformance:** `npm run conformance` · vectors in [`vectors/`](vectors/)

This document specifies the **protocol**: wire formats, canonicalization,
signature computation and the verification state machine — completely
independent of any programming language, runtime or ecosystem. The Node
implementation in [`src/`](src/) is merely the *reference* implementation;
the Go ([`sdk/go/`](sdk/go/)), Python ([`sdk/python/`](sdk/python/)) and
Rust ([`sdk/rust/`](sdk/rust/)) packages are independent verifiers that pass
the same vectors. Nothing in this document requires Pi Network; "Pi" is one
deployment adapter among many (see §11).

---

## 1. Terminology

| Term | Meaning |
|---|---|
| **Event** | one signed JSON claim of a completed action |
| **Verifier** | any party running the G1–G9 pipeline against its own registry copy |
| **Registry epoch** | the exact byte-content (`r1:` hash) of a verifier's trusted registry |
| **EPOCH_BOUND / LOCAL** | proof pinned to one registry generation vs verifiable against whatever copy is supplied |
| **UNVERIFIABLE** | honest third verdict: this verifier lacks inputs to decide. Never treated as a pass |

## 2. Cryptographic primitives (fixed)

- Signatures: **Ed25519** per RFC 8032 (PureEdDSA).
- Hashes: **SHA-256**; keyed pseudonyms use **HMAC-SHA-256**.
- All strings are **UTF-8**; UID input is NFC-normalized before hashing.
- Public keys travel as PKIX `SubjectPublicKeyInfo` PEM (`BEGIN PUBLIC KEY`),
  i.e. a 12-byte fixed header `302a300506032b6570032100` followed by the
  raw 32-byte Ed25519 public key.
- Signature encodings in JSON are **base64** (standard alphabet, padding);
  URL-carried documents may additionally use base64url externally, but the
  JSON field values themselves are base64.

## 3. Canonical JSON Profile v1.1 (normative)

The canonical form of any protocol object is defined by these rules,
applied after parsing:

1. Objects: keys sorted by their UTF-16 code-unit sequence (JS `Array#sort`
   semantics), recursively.
2. No whitespace between tokens; `,` and `:` separators only.
3. Strings: minimal JSON escaping — escape only `"`, `\`, and control
   characters `< 0x20` using `\b \f \n \r \t` or `\u00XX`; everything else
   literal UTF-8.
4. Numbers: integers in `[−(2^53−1), 2^53−1]` rendered without exponent or
   fraction. Any other number (non-safe integer, float, NaN/Infinity) is
   **rejected**, not rounded: `non-canonical number: <literal>`.
5. Values `undefined`/functions/non-finite are rejected
   (`unsupported type: …`).
6. Parsing must reject duplicate object keys.

The profile has its own interop suite: 16 vectors in
[`vectors/canonical/index.json`](vectors/canonical/index.json) covering key
ordering, unicode escapes, surrogate pairs, safe-integer bounds and
rejection cases. Implementations MUST reproduce every expected canonical
string byte-for-byte and MUST reject every listed error case.

## 4. PEP/1 Engagement Event

A version-1 event is a JSON object with EXACTLY these top-level keys:

```
v                integer 1                       (required)
app_id           string  ^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$
key_id           string  same grammar
action_class     enum "A" | "B" | "C"
action_id        string  same grammar as app_id
weight           integer ≥ 1
timestamp        integer, Unix ms
nonce            string  ^[A-Za-z0-9]{32}$
pioneer_uid_hash string  ^h[0-9]+:[A-Za-z0-9_-]{43}$   (§7)
eligibility      object { kyc_passed: bool, mainnet_migrated: bool }
signature        base64 Ed25519 signature (68 chars typical)
```

Unknown top-level keys → `SCHEMA`. Missing required keys → `SCHEMA`.
Wrong types/grammar → `SCHEMA`.

**Signature computation (domain-separated):**

```
body    = event object WITHOUT the "signature" member
bytes   = ASCII("PiRC1-PEP-v1") || 0x0A || UTF8(canonical(body))
sig     = Ed25519.sign(private_key, bytes)
```

The domain constant `PiRC1-PEP-v1` and this exact construction are frozen.

## 5. Registry

```
{ "version": 1,
  "apps":  { "<app_id>": { "keys": { "<key_id>": {
      "public_key_pem": "<PKIX PEM>", "status": "active"|"revoked",
      "registered_at": <int ms> } } } },
  "eligible_users": { "<h1:…>": { "kyc_passed": bool,
                                  "mainnet_migrated": bool } } }
```

A registry's **epoch id** is `r1:` + hex(SHA-256(canonical(registry)))[…].
Verifiers treat their own copy as the trust anchor; there is no network
fetch anywhere in the protocol.

## 6. Verification pipeline G1–G9

Checks run in this exact order; the first definitive failure names the
verdict, but implementations SHOULD report all completed steps:

| # | Check | Failure code |
|---|---|---|
| G1 | closed-schema validation | `SCHEMA` |
| G2 | app known in registry | `UNKNOWN_APP` |
| G3 | key known AND status active | `UNKNOWN_KEY` / `REVOKED_KEY` |
| G4 | body re-canonicalizes identically | `CANONICALIZATION` |
| G5 | Ed25519 verify over §4 bytes | `INVALID_SIGNATURE` |
| G6 | `now − window ≤ timestamp ≤ now + window` (window = 300000 ms) | `TIMESTAMP_EXPIRED` / `TIMESTAMP_IN_FUTURE` |
| G7 | weight ≤ ceiling{A:100, B:10, C:1} | `WEIGHT_OVERFLOW` |
| G8 | uid hash eligible AND eligibility flags match registry | `INELIGIBLE_USER` |
| G9 | nonce unseen — atomic claim (stateful verifiers only) | `REPLAY_DETECTED` |

Stateless verifiers (offline gateways, libraries without shared state) MUST
report G9 as **`NONCE_REPLAY: UNVERIFIABLE`** — gold, never green.

## 7. Keyed pseudonyms (`h1:`)

`h1:` value = `base64url(HMAC-SHA-256(uid_secret, NFC(uid)))` (43 chars).
The secret lives only with issuers; verifiers see only pseudonyms. Rotation
to `h2:` is an additive change reserved for future generations; the grammar
`^h[0-9]+:` already accepts it.

## 8. PiProof/1 envelope

```
{ "type": "PiProof", "version": 1, "created_at": <ms>,
  "event": <PEP/1 event>, "registry_root": "r1:…" ? }
```

Binding classes: exporting WITH `registry_root` pins the proof to that
epoch (**EPOCH_BOUND**); without it the proof is **LOCAL**. Policies MAY
require epoch-binding via `{"require_epoch_bound": true}`. Verifying an
EPOCH_BOUND proof whose root differs from the verifier's own → fail-closed
at G-preflight (`REGISTRY_ROOT`).

## 9. AUREVIA Evidence Passport /1

Bundles N proofs under one evidence root:

```
{ "type": "AUREVIA-Evidence-Passport", "version": 1,
  "subject": <string>, "created_at": <ms>,
  "evidence_root": "e1:" + hex(SHA-256(canonical(proofs))),
  "proofs": [ <PiProof/1>… ] }
```

Verification = every contained proof passes its own pipeline AND the
recomputed evidence root matches.

## 10. Dispute report & Arbitration Court (wire summary)

- **Dispute report** `AUREVIA-Dispute-Report`: deterministic question chain
  (CLAIM → WHO_ISSUED_IT → … → FINAL_VERDICT) over the above pipelines.
  It adjudicates evidence; it is NOT arbitration by itself.
- **Court case** `AUREVIA-Court-Case/1`: lifecycle
  `FILED → EVIDENCE_WINDOW → DELIBERATION_ROUND_n → CHALLENGE_WINDOW →
  SETTLED | UNRESOLVED`, judge roster with stake/capabilities, ballots =
  Ed25519 over `"AUREVIA-COURT-v1\n" + canonical(ballot-fields)`, weighted
  quorum tally (pure re-computation), multi-signature settlement
  certificates (`AUREVIA-Court-Settlement/1`) with byte-deterministic
  anchor payloads, referee opinions advisory-only. Full normative text:
  [`docs/COURT.md`](docs/COURT.md).

## 11. Ecosystem neutrality

The protocol binds to **keys and registries**, never to a blockchain or
identity provider. `pioneer_uid_hash` is a keyed pseudonym slot usable for
any subject namespace; `PiRC1-PEP-v1` is a historical domain label, not a
dependency. A deployment where "Pi" does not appear at all is fully
conformant — see [`test/pi-independent.test.js`](test/pi-independent.test.js)
which runs issuance→verification→passport→dispute end-to-end with zero
Pi-specific semantics.

## 12. Versioning policy

- PEP/1, Canonical v1.1, Passport/1, Court/1 are **frozen**. Corrections
  are clarifications; they cannot change any vector's expected bytes.
- New functionality ships additively: new optional fields behind new
  `type`s or new check steps AFTER G9, never mutating existing ones.
- Any breaking change requires a new generation (`v: 2` events coexisting
  with `v: 1` verifiers failing them cleanly).

## 13. Conformance

An implementation is conformant when it:

1. reproduces all 16 canonicalization vectors byte-exactly;
2. verifies `vectors/valid/signed-event.json` VALID against
   `vectors/registry.json` at `now = 1755860000000`;
3. rejects all 20 attack vectors in `vectors/index.json` with exactly the
   listed `expected_code`;
4. reports G9 honestly per §6 when stateless.

Existing passing implementations: Node (`src/`), Python
(`sdk/python/` — pip-installable, self-test included), Go (`sdk/go/`),
Rust (`sdk/rust/`), and WebAssembly (`wasm/` — the Go core compiled for
browsers and edge runtimes). Distribution map:
[docs/DISTRIBUTION.md](docs/DISTRIBUTION.md). The published bar for
third-party implementations: [docs/EXTERNAL_IMPLEMENTATION.md](docs/EXTERNAL_IMPLEMENTATION.md).
Run the matrix: `npm run conformance`.
