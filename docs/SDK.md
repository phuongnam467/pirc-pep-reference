# PiProof SDK — Verify in Five Minutes

**Status:** shipped in v0.14. The developer surface over the frozen PEP/1
core: same primitives the CLI and dashboard use — no new cryptography, no
new trust assumptions.

The one-line pitch for any Pi application — store, game, merchant, agent,
community:

```
Apps  →  PiProof  →  deterministic ALLOW | DENY
```

No app needs to trust another app; every app verifies against its own
trusted registry copy.

---

## 1. JavaScript SDK (zero dependencies)

```js
import { createVerifier } from './src/sdk.js';
import fs from 'node:fs';

const pi = createVerifier({
  registry: JSON.parse(fs.readFileSync('registry.json', 'utf8')),
  nonceStore: new InMemoryNonceStore()   // or FileNonceStore / RedisNonceStore
});

const d = pi.decide(proof, { policy: 'merchant-verification-v1' });
if (d.decision === 'ALLOW') allowAction();
// d = { decision, ok, code, binding, violations[], policy_used, result }
```

API:

| Call | Returns |
|---|---|
| `createVerifier({registry, nonceStore, now?, metrics?})` | verifier bound to YOUR trusted state |
| `verifier.verifyProof(proof, {policy?})` | full step-by-step verdict |
| `verifier.verifyPassport(passport, {policy?})` | per-proof results + summary |
| `verifier.decide(doc, {policy?})` | one-call `ALLOW \| DENY` with reasons |
| `toProofUri(doc)` / `parseProofUri(uri)` | `piproof://v1?p=…` self-contained links |

Policy references accept a preset name (`'merchant-verification-v1'`),
`{"preset":"name"}`, an inline rule object, or null.

## 2. Named policy presets

Frozen, versioned, reviewable-in-source defaults — call them by name:

| Preset | Requirements sketch |
|---|---|
| `merchant-verification-v1` | class A/B · weight ≥ 5 · KYC + Mainnet · epoch-bound · ≤ 24h |
| `marketplace-seller-v1` | class A · weight ≥ 10 · KYC + Mainnet · epoch-bound · ≤ 12h |
| `agent-payment-v1` | class A · KYC + Mainnet · epoch-bound · ≤ 5 minutes |
| `community-member-v1` | class B/C · KYC only · week-old evidence acceptable |
| `reward-eligibility-v1` | any class · KYC + Mainnet · epoch-bound · ≤ 24h |

List live presets via `GET /api/policies`, `pep policies`, or
`listPolicyPresets()` / Python `PRESETS`. A change to a preset means a **new
version**, never a silent edit.

## 3. HTTP Decision API (the Proof Button backend)

```bash
curl -X POST http://localhost:3000/api/decide \
  -H 'content-type: application/json' \
  -d '{"proof": <PiProof>, "policy": "merchant-verification-v1"}'
# → {"decision":"ALLOW","ok":true,"binding":"EPOCH_BOUND",...}
```

- Shares nonce state with the Explorer, so a replay caught anywhere is
  caught everywhere.
- Unknown preset ⇒ `400 {"error":"unknown policy preset: …"}`.
- Companion endpoints: `GET /api/policies`, `POST /api/verify-proof`
  (also accepts preset refs), `POST /api/share` (returns both a short link
  `/p/<id>` and a self-contained `pi_proof_uri`).

## 4. CLI

```bash
pep policies                                    # list presets
pep decide proof.json --registry registry.json \
    --policy agent-payment-v1 --nonces nonces.jsonl
# DECISION: ALLOW   (exit 0)   |   DECISION: DENY [CODE]  (exit 1)
```

## 5. Python SDK (standard library only)

`sdk/python/piproof_sdk.py` is an independent implementation of the same
pipeline (Ed25519 from scratch, Canonical Profile v1.1, envelope + binding +
policy subset). It agrees byte-for-byte with Node on every vector.

```python
from piproof_sdk import PiProofVerifier
v = PiProofVerifier(registry)
d = v.decide(proof_dict, policy={"preset": "reward-eligibility-v1"})
print(d["decision"], d["code"], d["violations"])
```

CLI form:

```bash
python sdk/python/piproof_sdk.py proof.json --registry registry.json \
    --policy reward-eligibility-v1 --state nonces.json
```

## Honest boundaries

- `decide()` answers *cryptographic validity under your epoch + your policy*.
  It does not answer truthfulness of the underlying claim (see SECURITY.md).
- Presets are defaults to start from, not legal guarantees; copy and tune
  them as inline policies when needed.
- Replay protection is exactly as distributed as your nonce store
  ([NONCE_STORES.md](NONCE_STORES.md)).
