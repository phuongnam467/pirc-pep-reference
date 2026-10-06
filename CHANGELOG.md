# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.19.0] - 2026-08-25

### Added — the Open Protocol Phase: prove that others can build

The theme of this release is a role reversal. Every release before it made
the implementation stronger; this one makes the *specification* strong
enough that the implementation stops being special. The measure of success
is no longer "look what we built" but "watch someone build it without us".

- **`SPEC.md`** — the complete standalone protocol specification:
  Canonical Profile v1.1, PEP/1 events, registry format, the G1–G9 gate
  order with normative error codes, `h1:` pseudonyms, PiProof/1 and
  Passport/1 envelopes, court wire format, conformance criteria, and
  versioning policy. Written from the vectors and constants, not from the
  source — §11 states the thesis plainly: **Pi is an adapter, not a
  dependency**.
- **Rust crate (`sdk/rust/`)** — a fourth independent verifier: hand-written
  std-only canonicalizer (UTF-16 key ordering, lexical number rules,
  duplicate-key rejection) plus G1–G9 over `ed25519-dalek`; G9 reported
  honestly as UNVERIFIABLE in stateless use. Conformance tests run the
  repository's public 16-vector suite end-to-end. Verified by the new CI
  job `rust-conformance` on Ubuntu + Windows.
- **Installable Python package (`sdk/python/`)** — `pyproject.toml`,
  console script `piproof-verify`, README; `test_sdk.py` runs all
  canonical vectors plus valid/tamper/revoked/epoch negatives with zero
  test-framework dependencies (CI job `python-package`, Python 3.10/3.12).
  Two error messages aligned to the reference wording so cross-language
  vector matching is exact (`_js_number_str`).
- **WebAssembly channel (`wasm/`)** — the Go verifier compiled to WASM;
  smoke driver proves acceptance, **replay burn across calls** (G9 with
  caller-owned nonce state), and tamper rejection inside Node. CI job
  `wasm-build`.
- **`test/pi-independent.test.js`** — the §11 proof by execution: a full
  lifecycle for `acme-logistics` / `container-42` (registry → signed event
  → epoch-bound proof → ALLOW, tamper DENY, replay-burn DENY, foreign
  epoch REGISTRY_ROOT) with no Pi semantics anywhere in the namespace.
- **Distribution map** ([docs/DISTRIBUTION.md](docs/DISTRIBUTION.md)) —
  one table, seven channels, their contracts and versioning rule.
- **HTTP API reference** ([docs/HTTP_API.md](docs/HTTP_API.md)) — every
  route, body, and convention of the hosted verifier.
- **External Implementation Kit**
  ([docs/EXTERNAL_IMPLEMENTATION.md](docs/EXTERNAL_IMPLEMENTATION.md)) —
  the published bar for third-party verifiers: what to implement from
  SPEC.md alone, ground rules, submission checklist, differential-fuzzing
  gate.
- **`ADOPTERS.md`** — an adopters table where every row links to a re-runnable
  CI job, and the third-party section is honestly empty.
- **`SECURITY_REVIEW.md`** — review scope, methods used, and the public
  findings ledger (one resolved low finding disclosed; nothing backfilled).
- **Agent Evidence reframed** ([docs/EVIDENCE_INFRASTRUCTURE.md](docs/EVIDENCE_INFRASTRUCTURE.md))
  as general proof infrastructure outside any single ecosystem.
- **npm publish-readiness** — `files`, per-module `exports`, dual `bin`
  confirmed, engines pinned; `npm pack --dry-run`: 88 files, ~152 kB.
- **`src/index.js`** — stable public entry point (31 re-exports) backing
  the `"."` export.

### Fixed

- `sdk/python/piproof_sdk.py`: NFC-collision error now quotes the decoded
  raw key (was JSON-escaped); non-canonical-number errors now render in
  JavaScript `Number.toString` form so vector error substrings match
  across languages.
- `docs/MATURITY.md`: corrected stale test count (154 → actual).

### Changed

- package.json: version 0.19.0, distribution metadata (`files`, `exports`),
  refreshed description.
- README: three new feature rows (open spec, multi-platform distribution,
  external kit), roadmap XX shipped, project map extended with
  `sdk/rust`, `wasm/`, `SPEC.md`, `ADOPTERS.md`, `SECURITY_REVIEW.md`.
- CI: two new matrix jobs (`python-package`, `rust-conformance`) and
  `wasm-build` — the verification surface now spans four language
  ecosystems on two operating systems.

### Verification

- `npm run ci`: layers 26 modules / 72 edges · 152/152 tests · attacks
  20/20 · transparency · vectors byte-reproducible · canonical vectors ·
  fuzz (quick, seeded) · conformance matrix green.
- `python sdk/python/test_sdk.py`: ALL GREEN (16 vectors + 4 pipeline cases).
- `node --test test/pi-independent.test.js`: 3/3.
- `wasm/smoke.mjs`: ALL GREEN (accept / replay-burn / tamper).
- Rust crate compiles locally; execution verified in CI (local Application
  Control blocks running fresh binaries — documented in `sdk/rust/README.md`).

## [0.18.0] - 2026-08-24

### Added — the Arbitration Court: decentralized, verifiable adjudication

The Dispute Engine's honest disclaimer — *no judge quorum, no challenge
periods, no arbitration market, no on-chain settlement* — becomes an honest
implementation of exactly those things.

- **`src/court.js` (L2)**: judge roster (Ed25519 keys + stake +
  capabilities), weighted quorum tallies over signed ballots, evidence
  windows, challenge periods, multi-signature settlement certificates,
  reputation-weighted arbitration market with deterministic panel
  assignment, and `replayArbitration()` — trustless auditability where a
  mutating re-tally is structurally impossible (`computeTally` is pure;
  v0.18 tests pin this because the impure version silently laundered
  tampered tallies).
- **AI agent division**: AI referees submit signed advisory opinions that
  are recorded as evidence and hash-pinned into settlements — but a
  referee key can never vote. **AI argues; keys decide**, enforced by the
  capability system, not by policy.
- **Settlement certificates** (`AUREVIA-Court-Settlement/1`): one signature
  per panel judge over canonical certificate bytes; full tally proof inside;
  byte-deterministic anchor payloads (tested for pre-commitment) with an
  explicit adapter contract for chain broadcasting.
- **Surfaces**: `/court` live UI (strict CSP) with one-click scenario ·
  `/api/court/{state,demo-case,file,ballot,settle}` · `pep court-demo` CLI
  walkthrough.
- **Normative spec** — [docs/COURT.md](docs/COURT.md): what "decentralized"
  means here precisely (no single point of decision; judges are keys;
  anyone can replay), lifecycle state machine, tally rules, market rules,
  every error and replay-difference code.

### Governance

Layer map extended: `court.js` classified L2
(`scripts/check-layers.mjs`). New suites `test/court.test.js` (9 tests)
and court integration test in `app/app.test.js`.

### Verification

149 tests green · layers clean (26 modules / 72 edges) · tamper-evidence
pinned by test (flipped ballot → named difference) · multi-sig settlement
reproduced identically on replay · attack matrix unchanged.

## [0.17.0] - 2026-08-24

### Added — public verification gateway & the privacy phase

The killer-use gap closes: anyone can now verify a document with
**cryptographic certainty and zero disclosure** — the document never leaves
the verifier's browser.

- **Pure-JS RFC 8032 core (`src/web-ed25519.js`, L0)**: Ed25519 verification
  + SHA-512 implemented from scratch in BigInt JavaScript, browser-safe,
  verify-only by construction. Every magic constant is *derived*
  (SHA-512 H/K tables from fractional roots of primes; Ed25519's `d`,
  base point, √-1 from `2^255-19` alone) — fewer transcribed hex strings,
  fewer silent bugs. Strict decoding rejects non-canonical `S ≥ L`.
  Cross-checked exhaustively against node:crypto in tests (random keys ×
  message sizes, bit-flips of msg/R/S, wrong-key, malleable S, garbage).
- **In-browser pipeline (`src/offline-verifier.js`, L1)**: the G1–G9 order
  re-run locally against the public registry export — same canonical
  fixed-point rule, same error codes. The honesty centerpiece:
  **NONCE_REPLAY is gold-labeled UNVERIFIABLE offline**, never green-washed;
  epoch binding likewise. Verdicts say "verified offline", not "verified".
- **Gateway surface (`/gateway`)**: CSP-locked page (`default-src 'none';
  script-src 'self'` — no inline script) accepting paste/file/deep-link for
  signed events, PiProof envelopes, and Evidence Passports; gate-by-gate
  table; SHA-256 fingerprint of the exact registry bytes displayed.
- **Host hardening**: global security headers on every response
  (nosniff / DENY framing / no-referrer / Permissions-Policy /
  COOP), `GET /healthz`, public `GET /registry.json` export, and a
  whitelist-only `/gateway-src/` static route (traversal-proof, 404 on
  anything unlisted).
- **Normative privacy model** — [docs/PRIVACY_MODEL.md](docs/PRIVACY_MODEL.md):
  data inventory (who sees what), keyed-pseudonym rotation story (`h1:` →
  `h2:`), the gateway's five-point honesty contract, and the honest limits
  (intra-deployment tag stability, mirror-registries, ZK out of scope for
  frozen PEP/1).

### Governance

Layer map extended: `web-ed25519.js` classified L0,
`offline-verifier.js` L1 (`scripts/check-layers.mjs`). New test suite
`test/web-offline.test.js` + extended `app/app.test.js`.

### Verification

139 tests green · layer check clean · attack matrix parity through the
offline path · live sample proof verified end-to-end via the offline module.

## [0.16.1] - 2026-08-24

### Added — mechanized verification goes live in CI

MATURITY.md row #14 moves from "drafted" to **partially held**: the TLA+
model is no longer hand-checked — TLC now runs it on every push and PR.

- **New CI job `formal-tlc`** (ubuntu): Temurin 21 via pinned
  `actions/setup-java@cf277c60…` + `tla2tools.jar` v1.7.4 verified against
  the **official release SHA1** (`bee4a54f3e…`) before use; CI fails unless
  TLC reports *"Model checking completed. No error has been found."*
- **Verified result**: complete state space of 122 distinct states explored;
  `TypeOK`, `AtMostOneAccept` (INV-04), `AcceptImpliesBurn`, and
  `BurnOnlyOnPass` (INV-05) all hold.

### Fixed — two real modeling flaws caught by the first machine run

The first TLC execution earned its keep immediately:

1. `EXTENDS Naturals` → `EXTENDS Integers`: unary minus (used by the
   `REJ(g)` terminal encoding) is not defined in pure `Naturals`.
2. The G8 environment choice was separable from its consequence — a
   verifier could read a snapshot before the environment committed, and
   TLC's deadlock analysis exposed the resulting stuck path. G8's choice
   and outcome are now one atomic action, and clean termination is an
   explicit `TerminalStutter` action — keeping deadlock detection armed for
   genuinely stuck mid-pipeline states instead of disabling it with
   `-deadlock`.

formal/README.md documents both decisions and how to reproduce locally.

## [0.16.0] - 2026-08-24

### Added — third implementation & normative conformance

MATURITY.md rows #13/#14 move from "open ask" to "partially held / drafted":
the protocol core now exists as **three independent codebases** (Node,
Python, Go) agreeing byte-for-byte, and the stateful heart of the formal
model is machine-checkable with one command.

- **Go protocol core (`sdk/go/`, from scratch)**: Canonical Profile v1.1,
  closed event schema, G1–G9 verification pipeline with exact error-code
  parity, registry/eligibility model, RFC 8032 via stdlib `crypto/ed25519`,
  and a CANC/PARSE fuzz driver speaking the same line protocol as Python's.
  One pinned auxiliary dependency (`golang.org/x/text`) because Go's stdlib
  ships no Unicode normalization tables — it plays the role `unicodedata`
  plays in Python. Ordered JSON parsing preserves key order (Go maps would
  randomize it). Tests: 16 interop vectors byte-exact, fixed-point INV-01
  pin, the valid vector ACCEPTS, all 20 attack vectors reject with exact
  codes, INV-05 burn-on-pass pin, INV-08 snapshot pin.
- **Normative conformance suite** — `scripts/conformance.mjs`
  (`npm run conformance`) + [docs/CONFORMANCE.md](docs/CONFORMANCE.md):
  a four-row matrix (Node vectors / Python canonicalizer / Go protocol
  core / Python Ed25519) that anyone claiming "PiProof compatible" MUST run
  and publish verbatim, with claim-language rules ("passes at commit `<sha>`"
  — never "certified"/"endorsed"). Graceful SKIP for absent toolchains;
  `--strict` turns skips into failures.
- **Fuzzing suite extended to seven campaigns**: new `go-diff` differential
  campaign cross-examines Node vs Go through the driver protocol (canonical
  bytes AND parse shapes); the Go driver binary is built once per run and
  cleaned up; suite SKIPPED cleanly when no Go toolchain is present.
- **TLA+ model of the stateful gate core** (`formal/piproof_gates.tla` +
  `.cfg` + README): two verifiers racing one shared nonce authority; G8
  snapshot eligibility and the atomic G9 test-and-set modeled explicitly;
  INV-04 (at-most-one-accept), INV-05 (burn-on-pass-only) plus TypeOK and
  AcceptImpliesBurn as TLC invariants. Hand-checked pending a CI tooling
  run — honest about that in formal/README.md.

### Corrected — Unicode facts behind the Profile v1.1 story

v0.15 claimed interop vector `canon-012` pins the amended NFC-form sort
order. That was wrong on Unicode details: ligatures have *no canonical
decomposition*, so `NFC(U+FB03)` stays `U+FB03` and canon-012's emission
order is identical under both the v1.0 raw-sort and the v1.1 NFC-sort rules.
The genuine discriminator is **new vector `canon-016`** (Ç U+00C7 vs Å-sign
U+212B): raw order puts Ç first, NFC forms put Å first — v1.1 emits
`{"Å":2,"Ç":1}` and a raw-sort implementation fails. Changes:

- `canon-012` renamed/described accurately (ligature NFC-invariance);
- `canon-016` added → **suite is now 16 vectors**, all regenerated and
  byte-exact across Node, Python, Go;
- `scripts/cross-canonical.py` updated from raw-sort to NFC-form sort —
  it silently disagreed with v1.1 on flip-class pairs while still passing
  the old vector set;
- `docs/CANONICALIZATION.md` amendment section rewritten with correct
  Unicode facts and both pinning vectors explained.

### Verification

132/132 tests · layer check clean · 20/20 attacks · 16/16 canonical vectors
×3 languages · FUZZ OK incl. go-diff · conformance matrix 4/4 · `go vet`
clean.

## [0.15.0] - 2026-08-24

### Added — adversarial depth & formal structure

The external-review hardening phase, part two: instead of adding features,
this release adds the machinery that finds its own bugs and the documents
that make claims checkable. It paid for itself immediately (see Changed).

- **`scripts/fuzz.mjs` — seeded property + differential fuzzing suite**
  (`npm run fuzz`, `fuzz:quick`, `--seed N`, `--only=…`, `FUZZ_DUMP=<dir>`):
  - *canonical-property*: determinism, idempotence
    (`canon(parse(canon(x))) === canon(parse(x))`), reject-only-
    CanonicalError, with Node↔Python cross-examination of every anomaly;
  - *schema*: `verifySignedEvent` fails closed under random mutation of valid
    events — including `__proto__` injection attempts;
  - *unicode*: NFC-equivalent inputs stay signature-equivalent; NFC-colliding
    keys are always rejected;
  - *cross-lang-diff* + *parser-differential*: byte-level Node↔Python
    differential testing through a persistent stdlib driver
    (`scripts/fuzz-diff-driver.py`); structural-shape comparison catches
    parse divergences, not just canonicalization divergences;
  - *concurrency*: K real OS processes race one nonce — exactly one winner,
    every round;
  - runtime-parser anomalies are classified separately from protocol
    violations: V8 quirks are recorded and reported loudly (see SECURITY.md)
    but only `FUZZ_STRICT=1` makes them fatal, so CI stays deterministic
    across Node builds.
- **Layer governance** — `scripts/check-layers.mjs` + normative
  [docs/LAYERS.md](docs/LAYERS.md): modules classified L0 primitives → L4
  presentation; a single mechanical rule (`depLayer <= myLayer`), unclassified
  files are violations, wired into CI. The zero-dependency audit surface is
  now enforced, not just intended.
- **Engineering formal model** — [docs/FORMAL_MODEL.md](docs/FORMAL_MODEL.md):
  the G1–G9 verification pipeline as an ordered fail-closed state machine,
  twelve security invariants (INV-01…INV-12) each with enforced-by /
  verified-by traceability, crash-failure semantics of the claim path, and a
  normative implementer MUST list. A paper model, honestly labeled as one.
- **Liveness-aware nonce-lock ownership** (v0.15 hardening of
  `FileNonceStore`): lockfiles now record `{pid, host, acquiredAt}`; a lock
  held by a live same-host process is **never stolen** regardless of age;
  provably dead owners may be taken after the staleness window; foreign-host
  and legacy locks keep time-based fallback. Closes the classic
  stale-lock-timeout double-entry race. Semantics pinned by
  `test/lock-semantics.test.js` (6 cases incl. K-process races).
- **V8 `JSON.parse` divergence disclosed** in [SECURITY.md](SECURITY.md):
  under allocation churn, Node can mis-parse byte-identical JSON
  (phantom-key shape differences vs Python). Documented as a *runtime* defect
  with the full impact analysis: PiProof's schema-pinned key sets make it
  unreachable in every protocol path.

### Changed — Profile v1.1 (canonicalization amendment)

- **Key sorting now happens on NFC forms, not raw keys**, in both
  implementations (`src/canonical.js`, `sdk/python/piproof_sdk.py`). The v1.0
  rule was deterministic per document but **not a fixed point**: fuzzing found
  inputs where `canon(parse(c)) !== c` for already-canonical `c`, silently
  breaking `isCanonical()` on documents the protocol itself produced. With
  NFC-form sorting the emitted text IS the sort key, so idempotence holds by
  construction. Wire compatibility: schema-valid envelopes never contained
  NFC-unstable key pairs (the collision rule rejects them), so no previously
  signed payload changes meaning. All vectors regenerated and byte-exact
  across languages. *(Correction, v0.16: v0.15 claimed vector `canon-012`
  pins the amended order — wrong on Unicode facts: ligatures have no
  canonical decomposition, so `canon-012`'s order is identical under both
  rules. The true discriminator is new vector `canon-016` {Ç, Å-sign}; see
  docs/CANONICALIZATION.md §Interop vectors.)*
- `docs/CANONICALIZATION.md` retitled to Profile v1.1 with the amendment's
  rationale, a new fixed-point conformance requirement, and the honest story
  of how the bug was found.
- SECURITY.md nonce-store guarantees restated precisely around liveness-aware
  ownership ("two verifiers on one host cannot both win" — with the exact
  takeover rules spelled out); NONCE_STORES.md gains the same semantics.
- MATURITY.md updated: test count 132, fuzzing/formal-model/layers listed as
  held evidence, two new missing-evidence rows (#13 independent third-party
  implementation, #14 mechanized verification) kept deliberately open.
- README roadmap XV, feature rows, and project map extended accordingly.

### Fixed

- Fuzz driver protocol deadlock on Windows pipes: interactive CANC responses
  were block-buffered (`sys.stdout.write` without flush) while PARSE used
  `flush=True`; cross-lang campaigns hung until EOF. Driver now flushes every
  response explicitly.

## [0.14.0] - 2026-08-24

### Added — the developer layer: "Verify with PiProof" in five minutes

The killer-use vision made concrete: applications stop building their own
verification plumbing and call one deterministic surface instead. No new
cryptography, no new trust assumptions — a thin composition of the frozen
core.

- **`src/sdk.js` — JS SDK (zero deps)**:
  - `createVerifier({registry, nonceStore, now?, metrics?})` bound to the
    caller's own trusted state;
  - `verifier.verifyProof()` / `verifier.verifyPassport()` (full verdicts);
  - **`verifier.decide(doc, {policy})`** — one-call `ALLOW | DENY` with
    reasons, violations, binding class and the resolved policy name;
    unknown presets deny cleanly as `POLICY_PRESET_UNKNOWN`, never crash;
  - `toProofUri()` / `parseProofUri()` — self-contained
    **`piproof://v1?p=<base64url>`** proof links: the document travels in
    the URI itself; verification still requires the verifier's registry.
- **`src/policy-presets.js` — named, frozen, versioned policy defaults**:
  `merchant-verification-v1`, `marketplace-seller-v1`, `agent-payment-v1`,
  `community-member-v1`, `reward-eligibility-v1`. Plain auditable data —
  a change means a new version, never a silent edit. Deliberately NOT a
  "policy marketplace": no signing, no discovery protocol.
- **HTTP Decision API**:
  - `POST /api/decide {proof|passport, policy}` → deterministic decision,
    sharing the Explorer's nonce state so replays are caught across every
    endpoint;
  - `GET /api/policies` lists live presets;
  - `/api/verify-proof` & `/api/verify-passport` now resolve
    `{"preset":"name"}` references (`400` on unknown);
  - `/api/share` responses include a `pi_proof_uri` alongside the short link.
- **CLI**: `pep policies` (preset catalog) and
  `pep decide --proof p.json --policy <preset|file>` with ALLOW/DENY exit codes.
- **Python SDK** (`sdk/python/piproof_sdk.py`, stdlib only): independent
  implementation of the same pipeline — Ed25519 from scratch, Canonical
  Profile v1 (raw-key sort parity), envelope + epoch binding, nonce state
  files, preset resolution, narrowing policy subset. Library API
  (`PiProofVerifier.decide`) plus CLI.
- **`docs/SDK.md`** — the five-minute guide across JS / HTTP / CLI / Python.

### Tests

- `test/sdk.test.js` (9) — preset integrity, resolver contract, decide
  ALLOW/DENY paths incl. ineligible + LOCAL-under-epoch-bound-preset +
  replay + unknown-preset, passport MIXED binding, URI round-trips.
- `test/app-sdk.test.js` (5) — `/api/policies`, decide-then-replay over
  shared state, preset acceptance/rejection on both verify endpoints,
  share → `pi_proof_uri` → parse → verify round-trip.
- `test/python-sdk.test.js` — Node↔Python agreement: bound ALLOW, tamper
  SIGNATURE denial, replay via state file, epoch-bound presets identical.
- `test/cli.test.js` (+1) — policies listing + decide ALLOW→replay-DENY e2e.

**126 tests green**, attacks 20/20, canonical vectors 15/15 × 2 languages.

## [0.13.0] - 2026-08-24

### Added — external-review hardening: precision, honesty, and interop evidence

This release converts a professional review's critique into normative
documentation, protocol-level distinctions, and cross-language proof. No
frozen-core semantics changed; everything is additive.

- **Binding classes (`EPOCH_BOUND` vs `LOCAL`)** — the portability/state-trust
  distinction is now explicit in the protocol layer:
  - `verifyPiProof` returns `binding` on every verdict; proofs carrying
    `registry_root` are `EPOCH_BOUND`, proofs without it are `LOCAL`
    (verifiable against whatever trusted registry copy the verifier supplies,
    with no epoch commitment).
  - New policy rule **`require_epoch_bound`** lets relying parties refuse
    LOCAL proofs; violations surface as `POLICY` with a named rule.
  - Passports aggregate honestly: summary `binding` is
    `EPOCH_BOUND` / `LOCAL` / `MIXED` (weakest-link semantics).
  - Dispute chain gains the question **`IS_THE_PROOF_EPOCH_BOUND`** (after
    `WHICH_EPOCH`) — answerable even in structural-only mode because binding
    is document-intrinsic.
  - CLI: `proof-export --epoch-bound` (refuses to emit LOCAL), and
    `passport-create --require-epoch-bound`; verify outputs now print the
    binding class.

### Added — canonicalization as a first-class profile

- **`docs/CANONICALIZATION.md`** — normative companion separating RFC 8785
  (JCS) from the **PiProof Canonical Profile v1**: non-negative safe integers
  only, NFC string normalization, raw-key sort with normalized serialization,
  hard rejection of NFC key collisions — with rationale for every deviation
  and an explicit "never describe this as JCS" implementation requirement.
- **15 canonical interop vectors** (`vectors/canonical/index.json`),
  including the raw-sort-vs-normalized-sort divergence case and the NFC key
  collision rejection. Verified byte-exact by two independent
  implementations:
  - Node self-check (`npm run gen:canonical`);
  - a from-scratch Python canonicalizer (`scripts/cross-canonical.py`,
    stdlib only) wired into CI across Python 3.10/3.12 × Linux/Windows.

### Changed — naming & claims discipline

- **Dispute Engine repositioned** everywhere (docblocks, README, dashboard
  EN/AR): it is a **deterministic evidence adjudication layer** — no judge
  quorum, no challenge periods, no arbitration market, no on-chain
  settlement, and never described as decentralized dispute resolution.
- **Trust Policy scope stated plainly** (`docs/POLICY_MODEL.md` + docblock):
  v1 is a flat narrowing-only checklist, not a policy language — no AND/OR,
  no nested predicates, no delegation; grammar evolution must preserve
  monotone-narrowing.
- **Pseudonymization ≠ anonymity** (SECURITY.md): keyed HMAC tags are
  non-invertible outside the issuer but NOT unlinkable; per-app uid secrets
  are load-bearing for cross-application privacy.
- **Nonce-store deployment matrix** (`docs/NONCE_STORES.md`): normative
  statement that FileNonceStore is shared-filesystem state — *not* distributed
  replay protection — plus Redis authority requirements (single strongly
  consistent logical authority; eventually-consistent backends unsupported;
  multi-region patterns that stay safe).

### Added — maturity honesty

- **`docs/MATURITY.md`** — the evidence register: what "reference
  implementation" and "security-engineering prototype" mean here (held, with
  evidence), what production readiness would require (12 missing-evidence
  rows: load at scale, multi-region ops, incident history, HSM, Byzantine
  registries, DR, migrations, external audit…), and language rules for
  presenting the project. Linked from the top of the README.

### Tests

- `test/binding.test.js` (7 tests) — LOCAL/EPOCH_BOUND verification paths,
  wrong-epoch fail-closed, policy enforcement both ways, passport aggregation
  incl. MIXED, dispute-chain question in full + structural modes, CLI flag
  enforcement end-to-end.
- Canonical vector suite: 15/15 byte-exact in Node, 15/15 agreement in
  independent Python. Full suite: **110 tests green**, attack suite 20/20.

## [0.12.0] - 2026-08-24

### Added — observability hooks and the transparency-log design draft (v1.0 review centerpiece)

- **`src/observability.js`** — opt-in metrics with strict rules: no global
  state (registries are created and passed explicitly, verdicts can never
  depend on whether observation is on), fail-open telemetry (recording
  never throws into the verification path), bounded memory (latency ring
  buffer capped at 10k samples). `timed()` helper wraps sync functions;
  snapshots are stable-keyed JSON (`AUREVIA-Metrics/1`) with rejection-code
  breakdowns and p50/p95/p99.
- **Wired end-to-end**: `verifySignedEvent`, `verifyPiProof` and
  `verifyPassport` accept an optional `metrics` registry; the demo server
  records proof/passport verifications, disputes and shares, exposing a
  read-only `GET /api/metrics`.
- **`docs/TRANSPARENCY_LOG_DESIGN.md`** — the signed registry transparency-
  log design draft that closes Open Question #1 *by design* (implementation
  deliberately deferred to post-review): append-only epoch entries over the
  existing canonical bytes, prev-hash chaining, m-of-n witness cosigning,
  five-step pure verification procedure reusing zero new cryptography,
  split-view detection, explicit migration path from today's
  `registry_root` binding, reserved `TL_*` error codes, privacy analysis,
  and five open questions for reviewers. Marked NON-NORMATIVE until the
  external v1.0 review concludes.

### Tests

- `test/observability.test.js` — snapshot shape & key ordering, percentile
  math, ring-buffer cap under 25k records, `timed()` outcome/THREW paths,
  fail-open recording against hostile inputs.
- App tests assert live `/api/metrics` counters after real verifications,
  disputes and shares.

## [0.11.0] - 2026-08-24

### Added — distributed nonce state, production-scale benchmark, the honest open-questions register

Closes two of the ten hardest open questions and documents all ten:

- **`RedisNonceStore` (`src/redis-nonces.js`)** — horizontally scalable
  replay protection with **zero dependencies**: a minimal RESP2 client
  written from scratch plus a worker-thread bridge that keeps the store's
  interface synchronous (Atomics.wait, same fail-closed pattern as
  FileNonceStore), so `verifySignedEvent`/`verifyPiProof` work unchanged
  across N load-balanced verifier instances. Atomic claims via Redis
  `SET NX`; optional TTL gives safe GC (claims only need to outlive the
  TIMESTAMP_FRESHNESS window). Fail-closed: unreachable server ⇒ throw,
  never allow. Only opaque nonce keys ever leave the process.
- **Reproducible throughput benchmark (`npm run bench`)** — production-
  scale evidence with numbers instead of adjectives: full 9-step pipeline
  at ~7,300 verified proofs/sec single-core sequential (p50 0.125ms,
  p99 0.43ms), ~5.5M InMemory claims/sec, durable FileNonceStore ~700/s.
  No mocks: every counted verification passed every step.
- **`docs/OPEN_QUESTIONS.md`** — the ten hardest questions raised about
  this project (registry authenticity protocol gap, distributed state,
  external audit, adoption, recency, breadth-vs-validation, forked vs
  authored repos, production evidence, agent-evidence depth, complexity
  growth) answered honestly: status, existing mitigations, and exactly
  what closes each one. Linked prominently from README.

### Tests

- `test/redis-nonces.test.js` — canonical RESP2 encoding; parser against
  byte-by-byte split chunks incl. CRLF inside bulk strings; dual-instance
  atomic claim semantics over a real socket; TTL forwarding; fail-closed
  construction. Uses a miniature RESP server running as a separate child
  process (`test/fixtures/mini-redis.mjs`) so the synchronous bridge is
  exercised exactly as in production — an in-process server would deadlock
  by construction.

## [0.10.0] - 2026-08-24

### Added — Killer-demo perfection: guided 60-second demo, issuer picker, short public links, installable CLI

- **Guided 60-second demo** — one button plays the full flagship scenario
  end-to-end with narrated steps: issue a `complete_transaction` proof
  (weight 100, issuer *Demo Marketplace*) → ✓ PROOF CREATED → independent
  verification ✓ VALID → tamper `weight: 100 → 100,000` ✗ INVALID → restore ✓
  VALID again → download `proof-passport.json` with the exact one-line
  verification command anyone can run.
- **Issuer picker** — the passport issue form now exposes all three demo
  issuers (`demo-app`, `marketplace-demo`, `demo-agent-service`), matching
  the cross-application story; the server already accepted `issuer`.
- **Short public verification links** — `POST /api/share` returns an
  ephemeral 12-hex id; `GET /p/<id>` 302-redirects to
  `/verify#p=<document>`. The share button prefers the short link and falls
  back to the pure fragment link on static deployments. The mapping is
  memory-only and capped (5,000 entries) by design: nothing about users is
  ever persisted.
- **Installable CLI** — package now exposes both `pep` and `piproof` bins;
  every document-consuming command (`proof-verify`, `passport-verify`,
  `dispute`) also accepts the file as a positional argument:
  `npx piproof passport-verify proof-passport.json --registry registry.json`.

### Tests

- `app/app.test.js`: share roundtrip (id format, 302 location decodes to the
  exact shared document, unknown id 404, malformed id 404, wrong type 400,
  invalid json 400).
- `test/cli.test.js`: end-to-end portable-proof flow — sign → `proof-export`
  → positional `proof-verify` → `passport-create` → positional
  `passport-verify` → `dispute` verdict VALID.

## [0.9.0] - 2026-08-24

### Added — AUREVIA Evidence Network: public verification, Dispute Mode, cross-application proofs, Agent Evidence

Completes the flagship arc on top of v0.8.0's Proof Passport:

- **Public verification page (`/verify`)** — open a `…/verify#p=<document>`
  link: no account, no trust in the holder, full checklist and a big
  PROOF VERIFIED / INVALID verdict. Static deployments honestly render the
  self-declared structural view plus the exact CLI command to reproduce.
- **Dispute Engine (`src/dispute.js`)** — replaces screenshots and
  scattered logs with one adjudicable chain: CLAIM → WHO ISSUED IT →
  WHAT WAS SIGNED (canonical fingerprints) → WHICH POLICY → WHICH EPOCH →
  WAS IT REPLAYED → IS THE KEY VALID → IS THE CLAIM WITHIN POLICY → FINAL
  VERDICT. Three honest outcomes only — **VALID / INVALID / UNVERIFIABLE**
  — and UNVERIFIABLE is never treated as a pass (no trusted registry ⇒ no
  adjudication). Available as CLI `dispute`, `POST /api/dispute`, and a
  dashboard section with report export.
- **Cross-application proofs** — the demo registry epoch now hosts three
  independent issuers (`demo-app`, `marketplace-demo`,
  `demo-agent-service`), each with its own key; sample passports are
  dual-issuer, proving App-A + App-B evidence verifies against one
  verifier state. `/api/passport-issue` accepts an `issuer` parameter.
- **Agent Evidence (AI accountability)** — when an agent completes a task,
  `demo-agent-service` signs it (`complete_task`, subject `agent-<id>`);
  policy verification turns it into a portable audit trail.
  `POST /api/agent-evidence` + dashboard card.
- **Killer-demo flow wired end-to-end**: Issue & Sign → verify → tamper →
  export → dispute report, each step feeding the next automatically.

### Tests

91 total (was 82): dispute unit suite (chain order, three-state honesty,
replay flagging, cross-issuer verdicts, junk handling) + API coverage for
`/verify`, agent evidence, dispute endpoint.

## [0.8.0] - 2026-08-24

### Added — AUREVIA Proof Passport: one portable evidence record

The killer use case: the holder — not the platform — carries the evidence.
*"Proofs you can carry. Evidence anyone can verify."*

- **`AUREVIA-Evidence-Passport/1`** (`src/passport.js`) — bundles 1–100
  PiProof envelopes under a single content-addressed `evidence_root`
  (`e1:` SHA-256 over the canonical proof array), optionally bound to a
  pseudonymous `subject` tag and a Trust Policy. Envelope validation runs
  before any cryptography; root recomputation happens before signature
  work; embedded proofs reuse the full PiProof checklist with per-proof
  labeled steps; replay detection propagates to the passport verdict;
  passport-stored policies narrow acceptance per holder.
- **CLI**: `passport-create --proof p1.json [--proof p2.json …]
  [--subject tag] [--policy p.json]` and `passport-verify` (full nested
  report, exit code reflects the verdict). Repeated flags are now
  collected into arrays in `parseArgs`.
- **Server endpoints**: `GET /api/sample-passport`,
  `POST /api/passport-issue` (catalog-validated demo issuer: class
  A/B/C action whitelist, weight bounds, subject pattern),
  `POST /api/verify-passport` (shares the live registry epoch + nonce
  store, so replays across submissions are caught).
- **Dashboard section "AUREVIA Proof Passport"** — Issue & Sign form,
  Download `.json`, Copy share link (`#p=<base64url>` fragment — no
  server-side storage, privacy-preserving), Open in Explorer, file
  import that auto-routes proofs vs passports by `type`, and a grouped
  verification report (summary header + top-level steps + per-proof
  checklists). Full EN/AR i18n.
- **Tests**: 82 total (was 69) — passport unit suite + HTTP API suite.

### Fixed

- Passport step labels render correctly in CLI output (top-level steps
  previously printed `undefined` labels).

### Documented

- Epoch-binding lesson captured by tests: minting a second proof mutates
  the registry, so earlier proofs must be minted after all eligibility
  changes — eligibility preparation is separated from minting in tests.

## [0.7.2] - 2026-08-24

### Fixed — blank page root cause + identity rename

- **Critical UI fix**: the dashboard rendered empty in real browsers — the
  i18n block referenced the `$` helper before its `const` initialization
  (TDZ ReferenceError killed the whole script; reveal-CSS then kept every
  card at `opacity:0`). Fixes: `$` defined first, cards are visible by
  default and only animate when JS is confirmed running (`html.js` gate),
  plus a fail-safe force-reveal timer.
- Hero line added under the header: *"Don't trust the app. Verify the
  proof."* with the full positioning sentence (EN/AR).
- Repository renamed to **EslaM-X/piproof** to match the product identity
  (PEP/1 = protocol, PiProof = ecosystem/product, AUREVIA = dashboard);
  all internal references updated; old URLs redirect automatically.

## [0.7.1] - 2026-08-24

- Static hosts (GitHub Pages) fall back to the deploy-time `snapshot.json`
  with a gold STATIC status dot instead of showing OFFLINE.

## [0.7.0] - 2026-08-24

### Added — PiProof: portable proofs + Trust Policy Engine + Proof Explorer

The three signature capabilities, deliberately nothing more:

- **Portable Verifiable Proofs (`PiProof/1`)** — `src/piproof.js`. A proof
  wraps exactly one signed PEP/1 event so any party can verify it against
  their own registry copy without trusting the issuer. Optional
  `registry_root` content-addresses the verifier's epoch; foreign-epoch
  proofs are rejected (`REGISTRY_ROOT`). Human-readable step checklist on
  every verification.
- **Trust Policy Engine** — `src/policy.js`. Deterministic, pure narrowing
  of acceptance after cryptographic validity: `issuer_allowlist`,
  `action_classes`, `min/max_weight`, `max_age_ms`, `require_kyc`,
  `require_mainnet`. Violations come back rule-by-rule.
- **CLI**: `pep proof-export` / `pep proof-verify [--policy policy.json]`
  print the full checklist and a `TRUSTED PROOF` / `INVALID PROOF` verdict.
- **AUREVIA Proof Explorer** — paste a proof, verify it live through the
  exact `src/verify.js` code path server-side; one-click **Tamper Lab**
  (weight ×1000 → `INVALID_SIGNATURE`; signature flip) plus live replay
  catching (persistent nonce store). "Why is this proof trusted?" explains
  every layer in EN/AR.
- **Public deployment path**: `npm run gen:snapshot`, GitHub Pages workflow
  (static dashboard), Dockerfile for any Node host (Fly/Railway/VPS).
- New endpoints `/api/sample-proof`, `/api/verify-proof`, `/snapshot.json`;
  app paths made relative (works under any base URL).

### Hardened — responding to external critique

- **Canonicalizer NFC key-collision rejection**: distinct raw keys that
  normalize to the same string now throw instead of silently merging.
  Unreachable under the closed PEP/1 schema (ASCII keys); fixed at the
  primitive level anyway. Committed vectors unchanged byte-for-byte.
- **CI supply chain**: all GitHub Actions pinned to full commit SHAs.
- **`docs/TRUST_BOUNDARIES.md`**: registry authenticity analysis with
  signed-epoch-root + transparency-log roadmap; nonce-store durability/
  distribution contract table; timestamp-vs-replay clarification;
  explicit non-audited status (also added to SECURITY.md).

### Tests

69/69 across Node 18/20/22 × Linux/Windows (was 61): 7 PiProof/policy/
canonicalization tests + endpoint tests for sample-proof, replay,
tampering, policy and malformed input.

### Explicitly deferred (scope discipline)

Privacy-preserving proofs (ZK), verifiable AI-agent claims, additional
language SDKs, browser extension, reputation scores, adoption counters —
each only after real use cases materialize. No feature creep before
product-market fit.

## [0.6.1] - 2026-08-24

### Changed — product rebrand: AUREVIA + positioning discipline

- The dashboard is now **AUREVIA** — *Trust. Verified. Transparent.* —
  cryptographic transparency infrastructure for decentralized ecosystems.
  Independent brand: navy-black / metallic-gold shield mark (no chain logo in
  the brand), engineering typography, expandable beyond a single ecosystem.
- Pi integration is explicitly positioned as an **ecosystem adapter**; the
  product spine stays Evidence → Verification → Transparency.
- Preview-mode messaging made precise: *"Pi environment unavailable —
  running in preview mode."*
- Claims normalized to **"Pi Browser-ready"**: Mainnet listing is stated as
  pending Developer Portal registration and live-environment testing, and
  nothing more.
- `app/assets/icon.svg` replaced with the AUREVIA cryptographic shield;
  original author artwork remains preserved verbatim at
  `app/assets/brand/identity-original.jpeg`.
- PWA manifest, package description and keywords updated to the AUREVIA
  identity.

## [0.6.0] - 2026-08-24

### Added — Pi SDK integration + full UX/UI overhaul

- **Official Pi SDK integration** (`app/index.html`): dynamic load of
  `pi-sdk.js`, `Pi.init({version:'2.0'})`, `Pi.authenticate(['username',
  'payments'])` rendering the signed-in Pioneer, and a `Pi.createPayment`
  support flow demonstrating the U2A path. Outside Pi Browser the app
  degrades to an honest **preview mode**.
- **Bilingual interface (English / العربية)** with a full RTL layout switch,
  persisted in localStorage — including localized numerals.
- **UX overhaul**: glassmorphism cards over an animated aurora background,
  skeleton loaders, count-up number animations, staggered card reveals,
  toast notification system, medal ranks on the leaderboard, HiDPI canvas
  chart with gradient area fill and glowing endpoint, keyboard focus rings
  and `prefers-reduced-motion` support, PWA manifest for standalone install.
- **Brand assets**: original author artwork preserved verbatim at
  `app/assets/brand/identity-original.jpeg`; vector icon at
  `app/assets/icon.svg` (favicon + maskable PWA icon); palette centralized
  in CSS custom properties for one-block re-theming.
- Server now serves `/assets/*` (with traversal guard) and
  `/manifest.webmanifest`; endpoint test coverage extended accordingly
  (CI total 61).

## [0.5.0] - 2026-08-23

### Added — Pi Transparency App

- **`app/`** — single-page Transparency Dashboard ready for Pi Browser-style
  environments: dynamic p_floor card with floor/spot ratio bar, x·y=k
  invariant chart, escrow lock status with per-check verification badges,
  and the PoA/PoU × Consistency Factor leaderboard. Zero build step, zero
  runtime dependencies.
- **`app/server.mjs`** — zero-dependency Node server exposing
  `GET /` (dashboard) and `GET /api/snapshot` (fresh snapshot assembled from
  the verified-event pipeline on every request). Run with `npm run app`.
- **`app/app.test.js`** — endpoint + snapshot integrity tests (CI total is now 61).

## [0.4.0] - 2026-08-23

### Changed — License

- **Relicensed from `(MIT OR Apache-2.0)` to the PiOS License**, the Pi Open
  Source license that permits development and use of derivative works solely
  within the Pi Network ecosystem. `LICENSE-MIT` and `LICENSE-APACHE` were
  removed; the canonical text now lives in `LICENSE`.
- Added the required trademark notice: *Pi, Pi Network and the Pi logo are
  trademarks of the Pi Community Company*, together with an explicit
  community-built / not-affiliated statement.
- Rationale: this repository is a Pi-ecosystem reference implementation and is
  being submitted to the official PiOS App & Library list; listing requires
  the unaltered PiOS license.

## [0.3.0] - 2026-08-23

Transparency Layer — implements the ideas endorsed in the PiRC1 review:
dynamic `p_floor`, `x·y=k` invariant tracking, verifiable escrow lock status,
and the "Transparency Dashboard" concept.

### Added

- **`src/pfloor.js`** — pure constant-product mathematics: real-time
  theoretical floor `p_floor = (R·Q)/(R+S)²` over circulating supply, average
  realized price of the hypothetical full dump, and an invariant health report
  that flags any decrease of `k` beyond a configurable tolerance (liquidity
  extraction detection).
- **`src/engagement.js`** — composite engagement scoring: Proof-of-Activity /
  Proof-of-Utility split by action class, per-project weight manifests
  clamped to protocol ceilings (projects may weigh down, never up), and a
  Consistency Factor that rewards sustained presence over end-window bursts.
  Inputs are restricted to `{event, verdict}` pairs whose verdict is a
  successful `verifySignedEvent` result.
- **`src/escrow.js`** — offline-verifiable escrow lock attestations: closed
  schema, dedicated signature domain (`PiRC1-ESCROW-v1`), binding to the
  revoked key's fingerprint, freshness window and replay guard. The optional
  `anchor` field carries an on-chain commitment; the module never fetches
  chain state.
- **`src/dashboard.js`** — deterministic Transparency Dashboard snapshot
  assembler fusing price floor, pool health, escrow lock status and the
  engagement leaderboard into one JSON document.
- `npm run transparency` — end-to-end demo; included in `npm run ci`.
- `test/transparency.test.js` — 21 tests covering all four modules.

### Not changed

- PEP/1 wire format, canonicalization rules and committed vectors are
  untouched; all pre-existing vectors verify byte-for-byte.

## [0.2.0] - 2026-08-23

Hardening release addressing the external review: concurrency-safe replay
protection, byte-for-byte reproducible vectors, keyed identity hashing, and
embedder-robustness guarantees.

### Changed — BREAKING

- **`pioneer_uid_hash` is now a versioned HMAC tag** (`h1:<43 base64url
  chars>` = HMAC-SHA256 over the NFC-normalized UID with a backend secret of
  ≥16 chars). Bare sha256 hex no longer passes schema validation. Registries
  may still *read* legacy `[0-9a-f]{64}` tags via `markEligible`.
  Migration: backends must provision `uidSecret` and re-hash.
- **Nonce stores must implement atomic `claimIfAbsent(key)`**; the previous
  non-atomic `has()`+`add()` pair is no longer used by the pipeline. Custom
  stores must migrate to the new interface (a DB unique constraint or Redis
  SETNX satisfies it).
- Canonical JSON now normalizes all strings to NFC before serialization and
  enforces a depth cap of 64. Events containing non-NFC string forms or
  nesting beyond the cap are rejected.

### Added

- Atomic replay protection: `InMemoryNonceStore.claimIfAbsent` (indivisible
  test-and-set) and `FileNonceStore.claimIfAbsent` (cross-process O_EXCL
  lockfile with stale-lock takeover → fresh re-read under lock → fsynced
  append). A claim that returned true survives hard restarts; torn trailing
  log lines and malformed entries fail closed and are counted
  (`corruptLines`); `compact()` rewrites via temp-file + atomic rename.
- Deterministic key material: `generateKeyPair({ seed })` derives Ed25519
  keys from a 32-byte seed via PKCS#8 DER; committed vectors now use fixed
  seeds and fixed nonces and are **byte-for-byte reproducible** across runs,
  enforced in CI with `git diff --exit-code -- vectors/`.
- Attack vector `20_prototype_key_app`: app id set to an inherited object-
  prototype property name — rejected with `UNKNOWN_APP` (suite now 20/20).
- New test suite `test/hardening.test.js` (13 tests): seeded-key RFC 8032
  equivalence, world reproducibility, double-claim exclusion, two-instance
  durable-store contention, crash reload, corrupt-log tolerance, prototype
  probes, depth-cap enforcement, NFC stability, malformed PEM degradation to
  `INVALID_SIGNATURE`, clock-rollback replay rejection.
- Python cross-verifier parity for NFC normalization and the canonicalization
  depth cap.

### Security

- Registry lookups and writes use own-property semantics throughout;
  `__proto__`/`constructor`/`prototype` writes are refused.
- UID hashing upgraded from unkeyed sha256 to keyed HMAC-SHA256 with version
  prefix — precomputation/rainbow-table attacks over the Pi UID space are no
  longer feasible; `h2:` rotation path documented in SECURITY.md.

## [0.1.0] - 2026-08-22

### Added

- Deterministic PEP/1 verification pipeline: fixed 9-step order — `SCHEMA`,
  `APP_KNOWN`, `KEY_ACTIVE`, `CANONICALIZATION`, `SIGNATURE`,
  `TIMESTAMP_FRESHNESS`, `WEIGHT_BOUND`, `ELIGIBILITY`, `NONCE_REPLAY`.
- Closed-profile JSON canonicalization (JCS subset, integers only,
  byte-stable output).
- Ed25519 signing via Node.js stdlib `node:crypto` (RFC 8032).
- App/key registry with key rotation and instant revocation
  (`REVOKED_KEY` path).
- KYC/Mainnet eligibility gating backed by a launchpad-side registry
  cross-check (`INELIGIBLE_USER`), never trusted from signed payloads alone.
- Bounded engagement-weight classes enforced even over valid signatures
  (`WEIGHT_OVERFLOW`).
- Per-application replay protection; nonces are burned only on full pass
  (`REPLAY_DETECTED`). Failed verification never burns the nonce.
- CLI: `keygen`, `init-reg`, `add-key`, `revoke-key`, `eligible`, `sign`,
  `verify`, `attacks`, `demo`.
- Adversarial suite: 19 attacks, each rejected with its exact error code
  (`19/19 rejected`).
- Independent pure-Python cross-verifier (`scripts/cross-verify.py`,
  RFC 8032, standard library only) re-verifying every committed vector.
- Reproducible conformance vectors (`vectors/`) regenerated and re-checked
  on every CI run.
- CI matrix: Node 18/20/22 × Ubuntu/Windows plus Python 3.10/3.12
  cross-verification on both operating systems.
- Documentation: `SPEC.md` (normative wire format), `SECURITY.md`
  (threat model and explicit limitations), `TRACEABILITY.md`
  (PR #2 requirement ↔ code ↔ test ↔ attack mapping).
- Dual licensing under `(MIT OR Apache-2.0)`.

[Unreleased]: https://github.com/EslaM-X/piproof/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/EslaM-X/piproof/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/EslaM-X/piproof/releases/tag/v0.1.0
