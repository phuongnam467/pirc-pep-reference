<div align="center">

# 🛡️ PiProof

### Verifiable proofs for the Pi ecosystem — PEP/1 protocol · Trust Policy Engine · AUREVIA dashboard

**Deterministic. Signed. Replay-proof. Zero dependencies.**

> **Maturity: security-engineered reference implementation.** Not production
> infrastructure, and not presented as one — the full evidence register lives
> in [docs/MATURITY.md](docs/MATURITY.md). v1.0 stays gated on external audit.

[![CI](https://github.com/EslaM-X/piproof/actions/workflows/ci.yml/badge.svg)](https://github.com/EslaM-X/piproof/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-PiOS-teal.svg)](#-license--copyright)
[![Node](https://img.shields.io/badge/node-%E2%89%A518-brightgreen.svg)](https://nodejs.org)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org)
[![Dependencies](https://img.shields.io/badge/dependencies-0-success.svg)](#-zero-dependencies)
[![Tests](https://img.shields.io/badge/tests-38%2F38-brightgreen.svg)](#-run-it-yourself)
[![Attacks](https://img.shields.io/badge/adversarial%20suite-20%2F20%20rejected-red.svg)](https://github.com/EslaM-X/piproof#-adversarial-suite)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-ff69b4.svg)](#-contributing)
[![Made in Egypt](https://img.shields.io/badge/made%20in-Egypt-%F0%9F%87%AA%F0%9F%87%AC-orange.svg)](https://github.com/EslaM-X)

</div>

---

> [!IMPORTANT]
> This is an **independent, community-built reference implementation**.
> It is **not** an official Pi Network product, and it makes no claim of
> endorsement by Pi Network or the Pi Core Team.

Reference implementation of **Programmable Engagement Proofs (PEP/1)** — a
deterministic, independently verifiable primitive for signed engagement
reporting, built from the review discussion in
[PiRC1 PR #2](https://github.com/PiNetwork/PiRC/pull/2).

It implements exactly what was discussed there, nothing more:

> *"it would be beneficial to provide APIs that allow apps to report more
> fine-grained engagement metrics. Apps would authenticate themselves using
> their app-specific API key. Participating users would be KYC-verified and
> migrated to Mainnet, which helps eliminate Sybil attacks."*

---

## 📑 Table of Contents

- [Why this exists](#-why-this-exists)
- [Features](#-features)
- [Run it yourself](#-run-it-yourself)
- [Demo](#-demo)
- [Adversarial suite](#-adversarial-suite)
- [Cross-language verification](#-cross-language-verification)
- [Architecture](#-architecture)
- [Project map](#-project-map)
- [Usage](#-usage)
- [Transparency Layer (v0.3)](#-transparency-layer-v03)
- [PiProof — portable verifiable proofs (v0.7.0)](#-piproof--portable-verifiable-proofs-v070)
- [AUREVIA Proof Passport (v0.8.0)](#-aurevia-proof-passport-v080)
- [AUREVIA Evidence Network (v0.9.0)](#%EF%B8%8F-aurevia-evidence-network-v090)
- [AUREVIA — product identity](#%EF%B8%8F-aurevia--product-identity)
- [Roadmap](#-roadmap)
- [Security](#-security)
- [Contributing](#-contributing)
- [License & Copyright](#-license--copyright)

---

## 🎯 Why this exists

| Review requirement (PR #2) | Where it lives here |
|---|---|
| canonical serialization rules frozen | `src/canonical.js`, SPEC §2 |
| app-specific API keys + rotation | `key_id` registry, `REVOKED_KEY` path |
| KYC / Mainnet eligibility gating | signed `eligibility` block + launchpad-side registry cross-check |
| bounded weights (no utility inflation) | class ceilings enforced even over valid signatures |
| replay protection | per-app nonce store, recorded only on full pass |
| deterministic validation | fixed 9-step pipeline, byte-stable canonical form |
| reproducible evidence | `vectors/` are byte-for-byte reproducible — regenerated and diff-gated in CI |

## ✨ Features

| | Feature | Detail |
|:---:|---|---|
| 🔒 | **Ed25519 signatures** | RFC 8032 via Node stdlib `node:crypto` |
| 🧊 | **Frozen canonical JSON** | PiProof Canonical Profile v1.1 (JCS-*inspired*, deliberately not JCS): non-negative safe integers, NFC strings, NFC-form sort (idempotent canonicalization) — [docs/CANONICALIZATION.md](docs/CANONICALIZATION.md) |
| 🔁 | **Replay protection** | per-app nonce store with **atomic test-and-set** (`claimIfAbsent`); burned only on full pass; durable fsynced file store with cross-process locking; Redis store for multi-host fleets — [docs/NONCE_STORES.md](docs/NONCE_STORES.md) |
| ⚖️ | **Bounded weights** | class ceilings enforced *even over valid signatures* |
| 🪪 | **Registry-gated eligibility** | KYC/Mainnet flags checked server-side, never trusted from the payload |
| 🕵️ | **Keyed pseudonyms** | `pioneer_uid_hash` is a keyed HMAC-SHA256 tag (versioned `h1:`), NFC-normalized — rainbow-table-proof. Pseudonymization ≠ anonymity; per-app secrets are load-bearing ([SECURITY.md](SECURITY.md)) |
| 🎲 | **Deterministic key material** | optional seed → RFC 8032-fixed Ed25519 keys; committed vectors are **byte-for-byte reproducible** (CI-diffed) |
| 🔑 | **Key rotation & revocation** | `key_id` indirection, instant revocation path |
| 🧪 | **Adversarial suite** | 20 attacks, each rejected with its exact error code |
| 🌍 | **Cross-language verification** | every vector re-verified by an independent pure-Python Ed25519 verifier; the canonicalization profile has its own 16-vector interop suite agreed across Node, Python, and Go implementations |
| ✅ | **Conformance suite** *(v0.16)* | one command (`npm run conformance`) runs the normative compatibility matrix across all implementations — [docs/CONFORMANCE.md](docs/CONFORMANCE.md) |
| 🧠 | **Go protocol core** *(v0.16)* | from-scratch third implementation: canonicalization v1.1, closed schema, G1–G9 pipeline, RFC 8032 via `crypto/ed25519` — proof the spec alone is enough to reimplement |
| 📐 | **TLA+ model, TLC-checked in CI** *(v0.16.1)* | the stateful core of the formal model — racing verifiers, atomic nonce claim — verified by TLC over its complete 122-state space on every push: INV-04/INV-05 hold ([formal/](formal/)) |
| 🔒 | **Offline verification gateway** *(v0.17)* | `/gateway` runs the full pipeline in the visitor's browser on a from-scratch pure-JS Ed25519+SHA-512 core — the document never leaves the tab, under a strict CSP; honest gold rows for what offline cannot know ([docs/PRIVACY_MODEL.md](docs/PRIVACY_MODEL.md)) |
| ⚖️ | **Decentralized Arbitration Court** *(v0.18)* | judges are keys with stake and published fees; verdicts exist only as panel multi-signatures over the exact tally; challenge periods where a challenge IS a replay; an AI division where AI referees argue but can never vote; anchor-ready settlement certificates ([docs/COURT.md](docs/COURT.md), live at `/court`) |
| 📜 | **Open protocol spec** *(v0.19)* | [`SPEC.md`](SPEC.md) — the complete protocol (Canonical Profile v1.1, PEP/1, h1 pseudonyms, PiProof/1, Passport/1, court wire format) written to be implemented **without reading any source code**; §11: Pi is an adapter, not a dependency |
| 📦 | **Multi-platform distribution** *(v0.19)* | one pipeline, seven channels: npm · Python package (pip-installable) · Go module · Rust crate · WebAssembly (Go→WASM with cross-call replay burn) · HTTP service · CLI — all validated against the same public vectors ([docs/DISTRIBUTION.md](docs/DISTRIBUTION.md)) |
| 🤝 | **External implementation kit** *(v0.19)* | the bar for third-party verifiers is published, not secret: submission checklist, differential fuzzing gate, honest adopters table ([docs/EXTERNAL_IMPLEMENTATION.md](docs/EXTERNAL_IMPLEMENTATION.md), [ADOPTERS.md](ADOPTERS.md), [SECURITY_REVIEW.md](SECURITY_REVIEW.md)) |
| 🎫 | **Evidence Passports** | 1–100 PiProofs under one content-addressed `evidence_root`, pseudonymous subject, shareable via URL fragment; honest binding aggregation (`EPOCH_BOUND` / `LOCAL` / `MIXED`) |
| 📌 | **Binding classes** *(v0.13)* | every proof is explicitly `EPOCH_BOUND` (pinned to one registry generation) or `LOCAL` (verifies against whatever trusted copy the verifier supplies); policies can require epoch pinning via `require_epoch_bound` |
| ⚖️ | **Dispute Engine** | **deterministic evidence adjudication layer** — claim→verdict chain, three honest outcomes: VALID / INVALID / UNVERIFIABLE — never a false pass. Not a decentralized arbitration protocol, and never described as one |
| 🧾 | **Trust Policy checklist** *(v1 scope)* | flat narrowing-only rules after crypto verification (`issuer_allowlist`, classes, weights, freshness, KYC/Mainnet, epoch-binding) — good v1, not a policy language; [docs/POLICY_MODEL.md](docs/POLICY_MODEL.md) |
| 🔀 | **Cross-application proofs** | independent issuers share one verifier epoch; multi-issuer passports verify against a single trusted state |
| 🤖 | **Agent Evidence** | AI accountability: signed agent actions become portable, independently verifiable audit trails |
| 🧑‍💻 | **Developer SDK** *(v0.14)* | `createVerifier().decide()` in JS + an independent pure-Python verifier + `POST /api/decide` — the "Verify with PiProof" button backend; [docs/SDK.md](docs/SDK.md) |
| 🏷️ | **Named policy presets** *(v0.14)* | frozen versioned defaults (`merchant-verification-v1`, `agent-payment-v1`, …) callable by name from SDK/CLI/HTTP — [docs/SDK.md](docs/SDK.md) |
| 🔗 | **Proof links** *(v0.14)* | self-contained `piproof://v1?p=…` URIs travel with the document; short `/p/<id>` links stay ephemeral |
| 🎰 | **Fuzzing suite** *(v0.15)* | 6 seeded campaigns — canonicalization properties, schema fail-closed mutation, Unicode equivalence, Node↔Python differential parsing, K-process nonce races; found the Profile v1.1 idempotence bug pre-release (`npm run fuzz`) |
| 🏛️ | **Layer governance** *(v0.15)* | mechanical L0…L4 import rules checked in CI — primitives can never reach upward ([docs/LAYERS.md](docs/LAYERS.md)) |
| 📐 | **Formal model** *(v0.15)* | G1–G9 gate pipeline, 12 security invariants with enforced-by/verified-by traceability, crash-failure semantics ([docs/FORMAL_MODEL.md](docs/FORMAL_MODEL.md)) |
| 📦 | **Zero dependencies** | runtime uses Node.js stdlib only — no supply-chain surface |

---

## 🚀 Run it yourself

```bash
git clone https://github.com/EslaM-X/piproof.git
cd piproof

npm test          # unit + integration tests        → 91/91 ✔
npm run attacks   # adversarial suite               → 20/20 rejected ✔
npm run demo      # end-to-end walkthrough          → deterministic verdicts
```

Requires **Node ≥ 18**. Nothing else. No `npm install`.

For the independent Python verifier (standard library only):

```bash
npm run gen:vectors && python scripts/cross-verify.py
# CROSS-VERIFICATION OK (pure Python): 1 valid accepted, 20/20 attacks rejected
```

## 🎬 Demo

```
$ node src/cli.js demo
[1] backend signs a high-value engagement event (class A, weight 50)
[2] verifier checks it against the launchpad registry
  PASS  SCHEMA
  PASS  APP_KNOWN
  PASS  KEY_ACTIVE
  PASS  CANONICALIZATION
  PASS  SIGNATURE
  PASS  TIMESTAMP_FRESHNESS
  PASS  WEIGHT_BOUND
  PASS  ELIGIBILITY
  PASS  NONCE_REPLAY

VERDICT: PASS (deterministic)

[3] attacker replays the exact same payload
  VERDICT: REJECT [REPLAY_DETECTED]

[4] attacker mutates the weight after signing
  VERDICT: REJECT [INVALID_SIGNATURE]
```

## ⚔️ Adversarial suite

Every attack is a committed test vector with an expected rejection code:

| # | Attack | Rejected with |
|---|---|---|
| 01–02 | replay / nonce reuse | `REPLAY_DETECTED` |
| 03–05 | forged signature / weight & user mutation after signing | `INVALID_SIGNATURE` |
| 06–07 | stale timestamp / future timestamp | `TIMESTAMP_EXPIRED` / `TIMESTAMP_IN_FUTURE` |
| 08 | weight inflation beyond class ceiling | `WEIGHT_OVERFLOW` |
| 09 | unknown application | `UNKNOWN_APP` |
| 10 | revoked signing key | `REVOKED_KEY` |
| 11 | cross-app key forgery | `INVALID_SIGNATURE` |
| 12–14 | missing field / unknown field injection / unsupported version | `SCHEMA` |
| 15 | self-declared eligible user | `INELIGIBLE_USER` |
| 16 | unknown key claim | `UNKNOWN_KEY` |
| 17–18 | registry says kyc/mainnet = false despite signed claims | `INELIGIBLE_USER` |
| 19 | unregistered pioneer | `INELIGIBLE_USER` |
| 20 | app id set to an object-prototype property name | `UNKNOWN_APP` |

```
RESULT: 20/20 attacks rejected
```

## 🌍 Cross-language verification

Trust one implementation? No. Every vector produced by the Node pipeline is
re-verified by `scripts/cross-verify.py` — an independent, dependency-free
implementation of RFC 8032 Ed25519 and the verification pipeline, written
from scratch against the Python standard library only.

This catches the bugs that survive inside a single codebase: wrong curve
arithmetic, divergent canonicalization, endianness mistakes. CI runs both
verifiers on Linux and Windows, across Node 18/20/22 and Python 3.10/3.12.

---

## 🏗️ Architecture

```
                 ┌──────────────────────────────────────────────┐
   event.json ──►│  closed schema ─► canonical bytes (frozen)   │
                 │                        │                     │
                 │                        ▼                     │
                 │              "PiRC1-PEP-v1\n" + bytes        │
                 │                        │                     │
                 │                        ▼                     │
   backend key ─►│                  Ed25519 sign                │──► signed envelope
                 └──────────────────────────────────────────────┘

                 ┌──────────────────────────────────────────────┐
 signed envelope►│ 1 SCHEMA          6 TIMESTAMP_FRESHNESS       │
   registry    ─►│ 2 APP_KNOWN       7 WEIGHT_BOUND             │
   nonces      ─►│ 3 KEY_ACTIVE      8 ELIGIBILITY (registry!)  │
   now         ─►│ 4 CANONICALIZATION 9 NONCE_REPLAY            │
                 │ 5 SIGNATURE                                  │
                 └──────────────────────┬───────────────────────┘
                                        ▼
                            { ok, code, checks[] }
                             deterministic verdict
```

The 9 steps always run in this order. A failure short-circuits with its code;
a pass records the nonce exactly once.

## 🗺️ Project map

```
piproof/
├── src/
│   ├── constants.js     protocol parameters & error codes
│   ├── canonical.js     closed-profile JSON canonicalization (JCS subset)
│   ├── schema.js        closed-schema validator (normative)
│   ├── events.js        event construction + Ed25519 signing
│   ├── keys.js          key generation (RFC 8032 via node:crypto)
│   ├── registry.js      app/key registry + eligibility registry
│   ├── nonces.js        InMemory + file-backed nonce stores (atomic claimIfAbsent)
│   ├── redis-nonces.js  ★ distributed nonce store — zero-dep RESP2 client (v0.11)
│   ├── observability.js ★ opt-in metrics hooks — pure, no global state (v0.12)
│   ├── policy-presets.js ★ frozen named policies — merchant/agent/community v1 (v0.14)
│   ├── sdk.js           ★ developer SDK — createVerifier().decide() + proof URIs (v0.14)
│   ├── verify.js        ★ the deterministic 9-step pipeline
│   ├── web-ed25519.js   ★ pure-JS RFC 8032 verification — browser gateway core (v0.17)
│   ├── offline-verifier.js ★ in-browser G1–G9 pipeline — documents never uploaded (v0.17)
│   ├── escrow.js        SIGNING_AUTHORITY_REVOKED attestations (v0.3)
│   ├── pfloor.js        dynamic price floor + invariant health (v0.3)
│   ├── engagement.js    PoA/PoU scoring + consistency factor (v0.3)
│   ├── dashboard.js     deterministic snapshot assembly (v0.3)
│   ├── piproof.js       ★ PiProof/1 portable proof envelope + verifier (v0.7)
│   ├── policy.js        Trust Policy Engine — post-crypto acceptance (v0.7)
│   ├── passport.js      ★ AUREVIA-Evidence-Passport/1 (v0.8)
│   ├── dispute.js       ★ Dispute Engine — claim→verdict chain (v0.9)
│   ├── court.js         ★ Arbitration Court — decentralized verifiable adjudication (v0.18)
│   ├── attacks.js       the adversarial suite
│   └── cli.js           keygen / init-reg / sign / verify / proof-* / passport-* / dispute
├── app/
│   ├── index.html       AUREVIA dashboard · Explorer · Passport · Dispute · Agent Evidence
│   ├── server.mjs       Node host: snapshot + sample/issue/verify/dispute APIs
│   │                    + /gateway offline verification + security headers + healthz (v0.17)
│   ├── verify.html      public verification page (/verify#p=<document>)
│   ├── court.html       ★ Arbitration Court UI — run a full case, watch the multi-sig settle (v0.18)
│   ├── gateway.html     ★ zero-disclosure offline gateway — CSP-locked, client-side crypto (v0.17)
│   ├── gateway.app.mjs  ★ gateway logic module (strict CSP: no inline script) (v0.17)
│   └── gateway.css      gateway styling (v0.17)
├── schema/
│   └── engagement-event.schema.json   JSON Schema description
├── scripts/
│   ├── gen-vectors.mjs  regenerate all vectors byte-for-byte deterministically
│   ├── check-vectors.mjs re-check committed vectors
│   ├── gen-canonical-vectors.mjs ★ canonical interop vectors (Profile v1.1, v0.13+)
│   ├── check-canonical-vectors.mjs ★ byte-exact multi-language canonical check (v0.13+)
│   ├── bench.mjs        ★ reproducible throughput benchmark (v0.11)
│   ├── cross-verify.py  🐍 independent pure-Python RFC 8032 verifier
│   ├── cross-canonical.py 🐍 independent pure-Python canonicalizer (v0.13)
│   ├── fuzz.mjs         ★ property+differential fuzzing suite — 7 campaigns (v0.15+go v0.16)
│   ├── fuzz-diff-driver.py 🐍 CANC/PARSE driver for differential campaigns (v0.15)
│   ├── conformance.mjs  ★ normative compatibility matrix across implementations (v0.16)
│   └── check-layers.mjs ★ layer-governance checker — L0…L4 import rules (v0.15)
├── test/
│   ├── canonical.test.js      canonicalization properties
│   ├── verify.test.js         pipeline incl. registry gating
│   ├── trust-boundary.test.js what a lying issuer can & cannot do
│   ├── attacks.test.js        the full adversarial matrix
│   ├── hardening.test.js      atomicity, durability, reproducibility, pollution
│   ├── cli.test.js            CLI end-to-end
│   ├── transparency.test.js   p_floor / invariant / engagement / escrow / snapshot
│   ├── piproof.test.js        portable proofs + policy engine
│   ├── passport.test.js       Evidence Passport unit suite
│   ├── passport-api.test.js   HTTP APIs incl. cross-issuer & agent evidence
│   ├── dispute.test.js        dispute chain three-state honesty
│   ├── redis-nonces.test.js   distributed store vs RESP fixture (child proc)
│   └── lock-semantics.test.js liveness-aware FileNonceStore locking (v0.15)
├── sdk/
│   ├── python/          🐍 pip-installable package (pyproject + console script,
│   │                       vector-driven selftest) — independent pure-Python core
│   ├── go/              ★ from-scratch Go protocol core — canonical v1.1, schema,
│   │                       G1–G9 pipeline, crypto/ed25519, fuzz driver (v0.16)
│   └── rust/            🦀 Rust crate — std-only canonicalizer, ed25519-dalek,
│                           honest-stateless G9, cargo-test conformance (v0.19)
├── wasm/                ⚙️ Go→WASM build of the verifier + Node smoke driver —
│                           browser/edge channel with caller-owned nonce state (v0.19)
├── formal/
│   ├── piproof_gates.tla ★ TLA+ model — racing verifiers, INV-04/05 as TLC invariants (v0.16)
│   └── README.md         how to run it + modeling decisions + roadmap
├── vectors/
│   ├── valid/signed-event.json        the one true positive vector
│   ├── registry.json                  vector world state
│   ├── canonical/index.json           16 canonical interop vectors (v1.1)
│   └── attacks/*.json                 20 attack vectors + expected codes
├── docs/
│   ├── OPEN_QUESTIONS.md            ★ the honest register — ten hard questions, answered
│   ├── MATURITY.md                  ★ what is proven vs not — evidence register (v0.13)
│   ├── SDK.md                       ★ 5-minute developer guide — JS/Python/HTTP/presets (v0.14)
│   ├── CANONICALIZATION.md          ★ normative: JCS vs PiProof profile v1.1 + interop vectors
│   ├── NONCE_STORES.md              ★ normative: deployment matrix, File≠distributed
│   ├── POLICY_MODEL.md              ★ v1 policy grammar + deliberate non-goals
│   ├── LAYERS.md                    ★ normative since v0.15: L0…L4 import governance
│   ├── FORMAL_MODEL.md              ★ engineering formal model — gates, 12 invariants, failure semantics (v0.15)
│   ├── CONFORMANCE.md               ★ normative since v0.16: how to claim "PiProof compatible"
│   ├── DISTRIBUTION.md              ★ seven channels, one pipeline (v0.19)
│   ├── HTTP_API.md                  ★ hosted-verifier contract (v0.19)
│   ├── EXTERNAL_IMPLEMENTATION.md   ★ the published bar for third-party verifiers (v0.19)
│   ├── EVIDENCE_INFRASTRUCTURE.md   ★ Agent Evidence as general infrastructure (v0.19)
│   └── TRANSPARENCY_LOG_DESIGN.md   ★ signed registry transparency-log draft (v1.0 review input)
├── .github/workflows/ci.yml           Node × OS matrix + Python cross-verify + Go conformance +
│                                        python-package + rust-conformance + wasm-build + TLC
├── SPEC.md             normative specification (implement from this alone)
├── ADOPTERS.md         who builds on PiProof — every row links to re-runnable proof
├── SECURITY_REVIEW.md  review process + public findings ledger
├── SECURITY.md         threat model & explicit limitations
└── TRACEABILITY.md     PR #2 requirement ↔ code ↔ test ↔ attack mapping
```

## 💻 Usage

```bash
# backend side
node src/cli.js keygen    --out keys/dev.json
node src/cli.js init-reg  --out registry.json --app acme-app
node src/cli.js add-key   --registry registry.json --app acme-app --key-id k1 --pub keys/dev.json

# verifier side
node src/cli.js sign   --event event.json --key keys/dev.json --out signed.json
node src/cli.js verify --event signed.json --registry registry.json --nonces nonces.jsonl

# portable proofs (v0.7)
node src/cli.js proof-export --event signed.json --registry registry.json --out proof.json
node src/cli.js proof-verify --proof proof.json --registry registry.json --policy policy.json

# evidence passports (v0.8)
node src/cli.js passport-create --proof proof.json [--proof p2.json …] \
  --subject alice-demo --policy policy.json --out passport.json
node src/cli.js passport-verify --passport passport.json --registry registry.json

# dispute engine (v0.9)
node src/cli.js dispute --doc passport.json --registry registry.json --out dispute-report.json

# developer layer (v0.14): named presets + one-call decisions
node src/cli.js policies
node src/cli.js decide --proof proof.json --registry registry.json \
  --policy merchant-verification-v1 --nonces nonces.jsonl
# JS: createVerifier({registry, nonceStore}).decide(proof, {policy:'agent-payment-v1'})
# HTTP: POST /api/decide {"proof":…,"policy":"reward-eligibility-v1"} → ALLOW | DENY
# Python (stdlib only): python sdk/python/piproof_sdk.py proof.json --registry registry.json

# or, once installed (`npm i -g .`), documents can be passed positionally:
npx piproof passport-verify proof-passport.json --registry registry.json
npx piproof dispute dispute-report.json --registry registry.json

# horizontal scaling (v0.11): share replay state across N verifier instances
import { RedisNonceStore } from './src/redis-nonces.js';
const nonces = new RedisNonceStore({ url: process.env.REDIS_URL, ttlMs: 86_400_000 });
// same synchronous interface — verifySignedEvent/verifyPiProof just work
```

```bash
npm run bench   # reproducible throughput: ~7.3k proofs/sec single-core sequential, p50 0.125ms
```

Observability (v0.12) — opt-in and pure:

```js
import { createMetricsRegistry } from './src/observability.js';
const metrics = createMetricsRegistry();
verifyPiProof(proof, { registry, nonceStore, now, metrics });
metrics.snapshot(); // → { schema, kinds: { proof_verify: { total, ok, fail, rejection_codes, latency_ms } } }
```

```bash
curl -s http://localhost:8787/api/metrics   # the demo server exposes its live counters read-only
```

Library API:

```js
import { newEvent, signEvent } from './src/events.js';
import { verifySignedEvent } from './src/verify.js';
import { InMemoryNonceStore } from './src/nonces.js';

const result = verifySignedEvent(signedEnvelope, {
  registry,              // launchpad-controlled: apps, keys, eligible users
  nonceStore,            // shared state across your verifier fleet
  now                    // injectable clock => fully testable
});
// => { ok, code, checks: [{ check, pass }, ...] }
```

## 📊 Transparency Layer (`v0.3`)

The ideas endorsed in the PiRC1 review — **dynamic `p_floor`**, **`x·y=k`
invariant tracking**, **escrow lock status**, and the **"Transparency
Dashboard"** concept — are implemented as pure, side-effect-free modules on
top of the PEP/1 trust layer:

| Module | Endorsed idea it implements |
|---|---|
| [`src/pfloor.js`](src/pfloor.js) | `p_floor = (R·Q)/(R+S)²` recomputed in real time from circulating supply; invariant health report that flags any liquidity extraction |
| [`src/engagement.js`](src/engagement.js) | PoA/PoU composite × Consistency Factor; per-project weight manifests clamped to protocol ceilings (weigh down, never up) |
| [`src/escrow.js`](src/escrow.js) | offline-verifiable `SIGNING_AUTHORITY_REVOKED` attestations under a dedicated signature domain, bound to the revoked key's fingerprint |
| [`src/dashboard.js`](src/dashboard.js) | one deterministic JSON snapshot fusing all four primitives for any "Transparency Dashboard" client |

```bash
npm run transparency   # end-to-end demo snapshot
npm run app            # live single-page Transparency Dashboard (localhost:8787)
```

### Pi SDK integration & UX highlights (`app/index.html`)

- **Official Pi SDK**: loads `pi-sdk.js`, `Pi.init({version:'2.0'})`, `Pi.authenticate(['username','payments'])` with graceful **preview mode** outside Pi Browser; a support payment flow (`Pi.createPayment`) demonstrates the U2A path.
- **Bilingual EN/العربية** with full RTL layout switch, persisted per user.
- Glassmorphism UI over an animated aurora · skeleton loaders · count-up numbers · reveal animations · toast notifications · medal ranks · HiDPI gradient-area canvas chart · `prefers-reduced-motion` respected · PWA manifest for standalone install.

## 🔐 PiProof — portable verifiable proofs (v0.7.0)

A PiProof wraps exactly one signed PEP/1 event so **any party can verify it
against their own registry copy without trusting the issuing app**.

```bash
# export a proof from a signed event
pep proof-export --event signed.json --registry registry.json --out proof.json

# verify anywhere — full checklist, deterministic verdict
pep proof-verify --proof proof.json --registry registry.json \
  --policy policy.json
```

```
 ✓ proof envelope well-formed
 ✓ registry root matches verifier epoch
 ✓ claim schema valid
 ✓ issuer registered
 ✓ signing key active (not revoked)
 ✓ deterministic canonical encoding
 ✓ Ed25519 signature valid
 ✓ timestamp fresh (within window)
 ✓ weight within class ceiling
 ✓ eligibility confirmed against registry
 ✓ nonce unused — no replay

VERDICT: TRUSTED PROOF — don't trust the app, verify the proof.
```

Optional **Trust Policies** (`src/policy.js`) narrow acceptance after
cryptographic validity: `issuer_allowlist`, `action_classes`,
`min_weight` / `max_weight`, `max_age_ms`, `require_kyc`,
`require_mainnet` — with rule-by-rule violations.

In AUREVIA: the **PiProof Explorer** verifies proofs live through the same
server code path, with a one-click Tamper Lab (mutate weight → invalid;
flip signature → invalid) and live replay catching. "Don't trust the app —
verify the proof."

## 🎫 AUREVIA Proof Passport (v0.8.0)

> **One portable evidence record. Independently verifiable anywhere.**
> *Proofs you can carry. Evidence anyone can verify.*

A passport bundles 1–100 PiProof envelopes under a single
content-addressed `evidence_root`, optionally bound to a pseudonymous
`subject` and a Trust Policy. The holder — not the platform — carries the
evidence: App A issues it, the holder takes it to App B, App C or an
auditor, and each verifies independently against their own trusted state.

```bash
# bundle signed proofs into a passport
pep passport-create --proof p1.json --proof p2.json \
  --subject alice-demo --policy policy.json --out passport.json

# verify anywhere — nested report, deterministic verdict
pep passport-verify --passport passport.json --registry registry.json
```

Verification layers: passport envelope → evidence-root recomputation →
every embedded proof's full checklist → passport-stored policy.
Replay detection propagates from any embedded proof to the final verdict.

In AUREVIA the Passport section lets you **Issue & Sign**, **Download
`.json`**, and share a verification link (`#p=…` URL fragment — no
server-side storage; anyone holding the link can re-verify). The Tamper
Lab applies to passports too: mutate anything inside and the evidence
root breaks before signatures are even checked.

**Trust boundaries are documented, not hidden:** registry authenticity,
nonce-store durability/distribution requirements, and audit status live in
[docs/TRUST_BOUNDARIES.md](docs/TRUST_BOUNDARIES.md). This project is not
externally audited; v1.0 remains blocked on external review.

## 🕸️ AUREVIA Evidence Network (v0.9.0)

> Proofs you can carry. Evidence anyone can verify.

```
                   ┌──────────────┐
                   │    PEP/1     │
                   │  Protocol    │
                   └──────┬───────┘
                   ┌──────▼───────┐
                   │   PiProof    │
                   │ Proof Engine │
                   └──────┬───────┘
        ┌─────────────────┼──────────────────┐
        ▼                 ▼                  ▼
  Proof Passport     Dispute Engine     Agent Evidence
        │                 │                  │
        └─────────────────┼──────────────────┘
                          ▼
                    AUREVIA Explorer
```

- **Public verification** — `/verify#p=<document>`: anyone opens the link;
  no account, no trust in the holder; full checklist → `PROOF VERIFIED ✓`.
- **Dispute Mode** — one adjudicable chain instead of screenshots:
  *CLAIM → who issued it? → what was signed? → which policy? → which epoch?
  → replayed? → key valid? → within policy? → FINAL VERDICT.*
  Three outcomes only: **VALID / INVALID / UNVERIFIABLE** — and
  UNVERIFIABLE (e.g. no trusted registry supplied) is never a pass.
  CLI: `pep dispute --doc passport.json --registry registry.json`.
- **Cross-application proofs** — multiple independent issuers share one
  verifier epoch; a single passport can carry App-A and App-B evidence.
- **Agent Evidence** — AI accountability: an agent's completed task is
  signed by its service, policy-checked, and becomes a portable audit trail.

## 🛡️ AUREVIA — product identity

> ### AUREVIA
> **Trust. Verified. Transparent.**
> Cryptographic transparency infrastructure for decentralized ecosystems.

AUREVIA is an independent product brand: an infrastructure / security-grade
visual language (deep navy-black · metallic gold · cryptographic shield mark ·
engineering typography). It is deliberately **not** a "${chain} fan app":
the Pi integration inside the dashboard is an *ecosystem adapter*, and the
brand can extend to other decentralized ecosystems without renaming.

| Element | Value |
|---|---|
| Brand | AUREVIA |
| Tagline | Trust. Verified. Transparent. |
| Product line | Cryptographic transparency infrastructure for decentralized ecosystems |
| Mark | cryptographic shield — [`app/assets/icon.svg`](app/assets/icon.svg) (favicon + maskable PWA icon) |
| Original artwork | preserved verbatim — [`app/assets/brand/identity-original.jpeg`](app/assets/brand/identity-original.jpeg) |

<p align="center">
  <img src="app/assets/brand/identity-original.jpeg" alt="AUREVIA brand identity" width="320">
</p>

Product focus stays fixed on one spine: **Evidence → Verification →
Transparency**. No tokens, no social features, no feature creep.

**Environment status:** Pi Browser-ready (`npm run app`). Mainnet listing is
pending Developer Portal registration and live-environment testing — claims
are kept at exactly that level until then.

Palette is driven by CSS custom properties (`--a1 #8a63ff`,
`--a2 #5aa7ff`, `--a3 #3ddc97`, `--gold #f5c451`) — re-theming is a
one-block edit.

> Pi, Pi Network and the Pi logo are trademarks of the Pi Community Company.
> This project is community-built and unaffiliated.


**Scope discipline:** these modules describe AMM mathematics over
caller-supplied reserves and verify authenticity of claims. They do not price,
value, endorse or promote any asset, and they never fetch chain state — the
optional attestation `anchor` field is a reference verifiers may resolve
themselves.

## 🧭 Roadmap

| Phase | Version | Scope | Status |
|---|---|---|---|
| I | `v0.1.x` | reference implementation, vectors, adversarial suite, cross-language verification | ✅ shipped |
| II | `v0.2` | conformance harness for third-party implementers, more vectors, fuzzed schema edges, hardening suite | ✅ shipped |
| III | `v0.3` | Transparency Layer: dynamic p_floor, invariant tracking, escrow attestations, dashboard engine, engagement scoring | ✅ shipped |
| — | `v0.5–v0.6` | transparency app hardening, AUREVIA identity & rebrand | ✅ shipped |
| V | `v0.7` | **PiProof**: portable proofs (`PiProof/1`), Trust Policy Engine, Proof Explorer, SHA-pinned CI, Pages deployment | ✅ shipped |
| VI | `v0.8` | **AUREVIA Proof Passport**: Issue/Export/Import/Verify/Share/Tamper/Report, evidence roots | ✅ shipped |
| VII | `v0.9` | **Evidence Network**: public verification page, Dispute Engine (VALID/INVALID/UNVERIFIABLE), cross-application proofs, Agent Evidence | ✅ shipped |
| VIII | `v0.10` | **Killer-demo perfection**: guided 60-second demo, issuer picker, short public links (`/p/<id>`), installable `piproof` CLI with positional args | ✅ shipped |
| IX | `v0.11` | **Distributed nonce state** (`RedisNonceStore` — zero-dep RESP client, atomic `SET NX`, TTL GC), reproducible throughput benchmark (`npm run bench`), honest open-questions register | ✅ shipped |
| X | `v0.12` | observability hooks (`/api/metrics`, opt-in pure metrics), **signed registry transparency-log design draft** (`docs/TRANSPARENCY_LOG_DESIGN.md` — the v1.0 review centerpiece) | ✅ shipped |
| X½ | `v0.13` | **external-review hardening**: normative canonicalization profile + 15-vector two-language interop suite, binding classes (`EPOCH_BOUND`/`LOCAL`) with `require_epoch_bound` policy rule and honest passport aggregation, dispute-chain epoch-binding question, nonce-store deployment matrix, policy-grammar scope doc, pseudonymization-vs-anonymity statement, maturity evidence register | ✅ shipped |
| XII | `v0.14` | **developer layer**: JS SDK (`createVerifier().decide()`), independent pure-Python SDK, named frozen policy presets callable by name, one-call Decision API (`POST /api/decide`) sharing replay state, preset-aware verify endpoints, self-contained `piproof://v1?p=…` proof links | ✅ shipped |
| XV | `v0.15` | **adversarial depth & formal structure**: property+differential fuzzing suite (found & fixed a real canonicalization idempotence bug — Profile v1.1 NFC-form sort), layer-governance checker (`scripts/check-layers.mjs`), liveness-aware nonce-lock ownership (live-PID locks never stolen), engineering formal model with 12 invariants (`docs/FORMAL_MODEL.md`), disclosed V8 `JSON.parse` divergence finding ([SECURITY.md](SECURITY.md)) | ✅ shipped |
| XVI | `v0.16` | **third implementation & conformance**: from-scratch Go protocol core (`sdk/go`) passing the full conformance matrix (16 canonical vectors + valid event + 20 attacks with exact codes), normative conformance suite (`npm run conformance`, [docs/CONFORMANCE.md](docs/CONFORMANCE.md)), TLA+ model of the stateful gate core with INV-04/INV-05 as TLC invariants (`formal/`), Unicode-facts corrections to the v1.1 vector story + new discriminator vector `canon-016` | ✅ shipped |
| XVII | `v0.16.1` | **mechanized verification live**: CI job `formal-tlc` runs TLC on the gate model every push/PR (checksum-pinned tla2tools v1.7.4, Temurin 21) — 122-state space verified; first machine run caught and fixed two real modeling flaws | ✅ shipped |
| XVIII | `v0.17` | **public gateway & privacy phase**: zero-disclosure offline verification (`/gateway`) — full G1–G9 pipeline in the visitor's browser over a from-scratch pure-JS Ed25519+SHA-512 core (cross-checked against node:crypto in tests), strict CSP, security headers + healthz on the host, public registry export with displayed SHA-256 fingerprint, normative privacy model ([docs/PRIVACY_MODEL.md](docs/PRIVACY_MODEL.md)) | ✅ shipped |
| XIX | `v0.18` | **decentralized arbitration**: the Dispute Engine's honest disclaimer becomes an honest implementation — judge roster with stakes & capabilities, weighted quorum tallies (pure re-computation, tamper-evident replay), challenge periods where challenging IS replaying, reputation-weighted fee market with deterministic panel assignment, AI agent division under "AI argues; keys decide", multi-signed anchor certificates ready for chain adapters ([docs/COURT.md](docs/COURT.md), `pep court-demo`, live UI at `/court`) | ✅ shipped |
| XX | `v0.19` | **open protocol phase**: [`SPEC.md`](SPEC.md) — the whole protocol specified for implementers who never read our source; distribution across seven channels (npm · Python pip package · Go module · **Rust crate** · Go→WASM · HTTP · CLI) all conformed against public vectors; pi-independence proven by test (`test/pi-independent.test.js` — acme-logistics/container-42 runs the full pipeline with zero Pi semantics); external implementation kit + honest adopters ledger + security-review process; npm publish-readiness (`files`/`exports`/`bin`, 88-file tarball); CI grows `python-package`, `rust-conformance`, `wasm-build` jobs ([docs/DISTRIBUTION.md](docs/DISTRIBUTION.md), [docs/EXTERNAL_IMPLEMENTATION.md](docs/EXTERNAL_IMPLEMENTATION.md)) | ✅ shipped |
| XI | `v1.0` | frozen after external review & public feedback cycle — the transparency-log draft is its headline artifact | 🔒 gated on review |

> `v1.0` will be tagged **only after** external security review and community
> feedback — not before.

## 🛡️ Security

Threat model, adversary capabilities, and explicit limitations are documented
in [SECURITY.md](SECURITY.md). The normative wire format lives in
[SPEC.md](SPEC.md). Requirement-to-evidence traceability:
[TRACEABILITY.md](TRACEABILITY.md). The ten hardest open questions about
this project — answered honestly, with status and what closes each one:
[OPEN_QUESTIONS.md](docs/OPEN_QUESTIONS.md).

**Trust boundary, in one line:** a valid signature proves authenticity of a
claim — never its truthfulness. Truth comes from the launchpad-controlled
registry; ceilings cap how much damage even a lying issuer can do.

Report vulnerabilities responsibly — see SECURITY.md for contact guidance.
Please do not open public issues for undisclosed vulnerabilities.

## 🤝 Contributing

The `main` branch is **protected**: all changes arrive through pull requests
and must pass the full CI matrix (Node × OS tests, adversarial suite, vector
regeneration, Python cross-verification) before merging.

```bash
git checkout -b feat/your-feature
npm ci 2>/dev/null || npm install   # dev-only tooling if any
npm run ci                          # full local gate before opening a PR
```

Keep PRs focused. If you change behavior, add or update the matching attack
vector and test first.

## 📜 License & Copyright

Licensed under the **[PiOS License](LICENSE)** — the Pi Open Source license that
permits unrestricted development and use of derivative works **within the Pi
Network ecosystem**, keeping this reference implementation dedicated to the
platform it was built for.

> Pi, Pi Network and the Pi logo are trademarks of the Pi Community Company.
> This project is community-built and is not affiliated with, endorsed by, or
> maintained by the Pi Core Team.

Copyright © 2026 **EslaM-X** 🇪🇬 · All rights reserved where applicable by the
chosen license terms.

---

<div align="center">

**Built as evidence, not as advertising.**
*Clone it. Run the suite. Check every claim above.*

⭐ If this reference implementation helped you evaluate PEP/1, consider starring the repo.

</div>
