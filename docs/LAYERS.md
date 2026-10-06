# Layer Governance

**Status:** normative since v0.15. Enforced by
[`scripts/check-layers.mjs`](../scripts/check-layers.mjs) in CI.

## Why this exists

The zero-dependency posture (one runtime, stdlib only) was chosen to make the
audit surface *small*, not merely small-looking. That only holds if the code
itself stays stratified: a primitive must never reach upward, and a
presentation concern must never be load-bearing for protocol correctness.
This document and its checker turn that intent into a mechanical rule any
reviewer can verify in seconds.

## The layers

| Layer | Name | Modules | May import |
|---|---|---|---|
| L0 | primitives | `canonical`, `constants`, `keys`, `web-ed25519`, `schema`, `nonces`, `redis-nonces`, `observability` | nothing above L0 |
| L1 | protocol-core | `events`, `registry`, `verify`, `offline-verifier` | L0 |
| L2 | policy-evidence | `policy`, `policy-presets`, `piproof`, `passport`, `escrow`, `pfloor`, `court` | L0–L1 |
| L3 | application | `dispute`, `sdk`, `attacks`, `engagement`, `dashboard` | L0–L2 |
| L4 | presentation | `cli`, `app/server` | L0–L3 |

Rule (single, mechanical): **a module may only import modules at a strictly
lower-or-equal layer.** Any module not classified in the table is itself a
violation — new files cannot sneak in unreviewed.

## What each stratum means

- **L0 primitives** — no knowledge of PEP/1 semantics. Canonicalization,
  key handling, schema validation, nonce stores. Each is independently
  testable and reusable outside this project.
- **L1 protocol-core** — the wire format and its verification state machine.
  Nothing here knows about HTTP, CLI flags, or product policy; swapping this
  layer out would change the *protocol*.
- **L2 policy-evidence** — interpretive decisions over valid events: weight
  classes, presets, passports, escrow attestations, floor scoring. This is
  where product rules live; the protocol below stays frozen.
- **L3 application** — orchestration: dispute flows, SDK façade, attack
  harnesses, engagement aggregation, dashboard data assembly.
- **L4 presentation** — I/O boundaries: CLI parsing/printing, the HTTP server.

## Deferred work (deliberate)

The *physical* directory layout still mixes some strata inside `src/`.
Regrouping directories now would churn every import path for cosmetic gain;
the checker already delivers the substantive guarantee (no upward edges).
Physical regrouping is scheduled as a mechanical, vector-verified refactor
**after v1.0 freezes**, when the audit trail can absorb a tree-wide diff.

## Running it

```
node scripts/check-layers.mjs
# → layer check OK: N modules across 5 layers, M edges, 0 violations
```

Exit code 1 on any violation or unclassified module. Wired into `npm run ci`
and the GitHub Actions workflow.
