# HTTP API — the hosted verifier contract

The reference service (`app/server.mjs`) exposes every pipeline over
plain JSON. It is stateless per request except where a nonce store is
injected. Start with `npm start` (default port 8787).

Security headers (CSP, HSTS, X-Content-Type-Options, frame-deny) are set
on every response; see `test/hardening.test.js`.

## Health & metadata

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/healthz` | liveness: `{ ok: true, now }` |
| GET | `/api/snapshot` | current registry snapshot summary |
| GET | `/api/policies` | policy presets and rule vocabulary |
| GET | `/api/metrics` | counters (verifications, decisions, errors) |

## Proofs

| Method | Path | Body | Result |
|--------|------|------|--------|
| POST | `/api/verify-proof` | `{ proof, registry?, now?, nonceState? }` | decision report: ok / code / steps |
| POST | `/api/decide` | `{ proof, policy }` | verify + narrow-only policy evaluation → `ALLOW`/`DENY` + violations |
| GET | `/api/sample-proof` | — | freshly minted sample proof for smoke tests |

## Passports

| Method | Path | Body | Result |
|--------|------|------|--------|
| POST | `/api/passport-issue` | `{ uid, claims }` | signed Passport/1 document (server-held key) |
| POST | `/api/verify-passport` | `{ passport }` | verification report incl. expiry + binding |
| GET | `/api/sample-passport` | — | sample passport |

## Agents & disputes

| Method | Path | Body | Result |
|--------|------|------|--------|
| POST | `/api/agent-evidence` | evidence bundle | Agent Evidence verification (schema, signatures, chain) |
| POST | `/api/dispute` | `{ proofs[], question }` | dispute bundle with per-proof binding analysis |

## Court

| Method | Path | Body | Result |
|--------|------|------|--------|
| GET | `/api/court/state` | — | judges, fee book, open cases, market snapshot |
| POST | `/api/court/demo-case` | — | runs the scripted demo case end-to-end |
| POST | `/api/court/file` | case draft | files a case; validates fees + quorum config |
| POST | `/api/court/ballot` | `{ case_id, round, judge_id, verdict, ... }` | records a signed ballot after deliberation opens |
| POST | `/api/court/settle` | `{ case_id }` | settles if quorum met and challenge window closed |

## Pages & artifacts

| Path | Purpose |
|------|---------|
| `/` | console UI |
| `/verify` | proof verifier UI (offline-capable bundle) |
| `/court` | arbitration court live view |
| `/gateway` | privacy gateway UI |
| `/registry.json` | current registry generation (pinned via `registry_root`) |
| `/snapshot.json` | transparency snapshot artifact |

## Conventions

- All bodies are JSON; malformed JSON → `400 { error: "MALFORMED_JSON" }`.
- Verification endpoints never throw on cryptographic failure — they
  return the structured report with the protocol error code
  (`INVALID_SIGNATURE`, `REPLAY_DETECTED`, …).
- `registry.json` is served byte-stable within a generation so clients can
  pin `registry_root = sha256(canonical(registry))`.
