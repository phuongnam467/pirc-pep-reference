# Open Questions — the honest register

Every project has weak points; most bury them. This file exists to do the
opposite: it lists the ten hardest questions raised about PiProof/AUREVIA
and answers each one with its current status, what already mitigates it,
and exactly what would close it. Nothing here is spin.

Status legend: ✅ addressed · 🟡 mitigated, work continues · 🔴 open ·
🔒 deliberate (gated by design)

---

## The ten, at a glance

| # | Question | Status |
|---|----------|--------|
| 1 | Registry authenticity is not settled at protocol level | 🟡 mitigated · transparency-log design is the v1.0 review topic |
| 2 | Distributed nonce state does not exist | ✅ addressed in v0.11 (`RedisNonceStore`, zero-dependency RESP client) |
| 3 | No external security audit yet | 🔒 deliberate — v1.0 cannot be tagged without one |
| 4 | Ecosystem adoption is limited | 🔴 open — this is a go-to-market problem, not a code problem |
| 5 | Most projects in the space are very recent | 🟡 time is the only remedy; full public history since day one |
| 6 | Breadth is huge relative to external validation | 🟡 traceability + adversarial suites narrow it; external validation still wanted |
| 7 | Some repositories are forks, not authored from scratch | ✅ not true of this repo — single-origin history, no vendored crypto |
| 8 | Production-scale evidence is limited | 🟡 now backed by a reproducible benchmark (`npm run bench`); real deployments still wanted |
| 9 | Agent/robotics expertise needs deeper proof | 🟡 Agent Evidence proves protocol fitness; domain pilots invited |
| 10 | Complexity is growing fast (PEP → Passport → Dispute → Agent) | 🟡 contained by strict layering; each layer independently verified |

---

## 1. Registry authenticity at protocol level

**The ask:** signatures prove *who* signed, but who authenticates the
registry itself?

**Where it stands:** the verifier does not trust issuer self-declarations;
truth comes from the trusted registry, whose root hash is bound into every
proof (`registry_root`) and every passport (`evidence_root` binds proofs,
not words). Escrow revocation attestations (v0.3) let a launchpad prove it
*cannot* move funds. But the registry itself is currently a trusted root —
a determined malicious launchpad that controls registry distribution could
feed verifiers a false world state within weight ceilings.

**What closes it:** an append-only, signed registry log (transparency-log
style) with third-party witnesses and consistency proofs between epochs.
This is a protocol change and is deliberately queued as the headline topic
for the v1.0 external security review — not something to rush unreviewed.

## 2. Distributed nonce state

**The ask:** replay protection only guards one process/machine today.

**Where it stands (v0.11):** solved without adding a single dependency.
`src/redis-nonces.js` implements the same synchronous `NonceStore`
interface over a minimal RESP2 client and a worker-thread bridge, so N
verifier instances behind a load balancer share one replay-protection
domain via atomic `SET NX`. TTL support gives safe GC (claims only need to
outlive the TIMESTAMP_FRESHNESS window). Verified against a real socket
path in CI using a miniature RESP server child process; fail-closed on
unreachable servers. The existing zero-config stores remain the default.

## 3. External security audit

**Status: deliberately open.** The roadmap gates `v1.0` on external
security review and public feedback — not before. An audit performed
earlier would just audit a moving target. SECURITY.md documents the threat
model and invites responsible disclosure meanwhile.

## 4. Ecosystem adoption

**Honest answer:** limited, and code alone cannot fix it. What the repo
*has* done to lower the wall: zero dependencies, a conformance harness for
third-party implementers (v0.2), deterministic vectors any language can
reproduce, a pure-Python cross-verifier, and one-command demos. Adoption is
now a distribution question — pilot partners, not pull requests.

## 5. Everything is very recent

True across the entire space, and no changelog fixes youth. Mitigation is
radical traceability instead of tenure: every requirement maps to code,
tests, and attack vectors (TRACEABILITY.md), and the full git history is
public from commit one. Track record accrues automatically from here.

## 6. Breadth vs external validation

The surface is genuinely wide: protocol → portable proofs → policy engine →
passports → disputes → agent evidence. The counterweights: each layer is a
pure composition over one frozen 9-step pipeline; 98 tests, 20 adversarial
vectors, byte-deterministic vectors re-verified in Python, and SHA-pinned
CI. Still, independent third-party validation of the *whole* stack does not
exist yet — which is exactly why v1.0 stays locked until it does.

## 7. Authored vs forked

Not applicable to this repository, verifiably: single-origin git history
from initial commit to tag, no vendored cryptography (Ed25519 comes from
Node's RFC 8032 implementation), no copied boilerplate. Deterministic
vector regeneration makes authorship checkable by anyone in seconds.

## 8. Production-scale evidence

New in v0.11 — reproducible numbers instead of adjectives:

```
$ npm run bench        (Windows_NT x64, Node 24, 12 cores)

Full 9-step verify pipeline:
  verified  : 3,000/3,000 (100.00%)
  throughput: ~7,300 proofs/sec (single core, sequential)
  latency   : p50 0.125ms · p95 0.17ms · p99 0.43ms

InMemoryNonceStore.claimIfAbsent: ~5.5M claims/sec
FileNonceStore.claimIfAbsent    : ~700 claims/sec (lock+append+fsync per claim)
```

Every counted verification passed all nine steps, including a fresh Ed25519
verification and an atomic nonce claim — no mocks, no shortcuts. At p50
latency a single modest core verifies ~8,000 claims/sec sequentially, so a
multi-core deployment comfortably absorbs millions of daily verifications
before any tuning. Run `npm run bench` yourself; that is the point.

What benchmarks do not prove: behavior under hostile multi-tenant load and
years of operational decay. Those need real deployments — see #4.

## 9. Agent-evidence depth

Agent Evidence (v0.9) demonstrates the accountability chain end-to-end:
an agent's completed task becomes a signed, policy-checked, portable proof
that survives into passports and dispute reports. That proves the
*protocol* fitness. It does not yet prove deep operational experience in
robotics/autonomy domains — those pilots are openly invited, and the
design intentionally requires zero changes to PEP/1 to run them.

## 10. Rate of complexity growth

Managed by construction, not by hope:

- PEP/1 (frozen core): closed schema, canonical bytes, 9-step verdict.
- PiProof envelope: pure function of a verified event + registry root.
- Passport / Dispute / Agent Evidence: pure compositions over `verify()`;
  none can widen trust, mint validity, or bypass ceilings — the dispute
  engine itself returns UNVERIFIABLE rather than guessing when inputs are
  missing.

Each layer ships with its own suite, and nothing above the core can amend
it. The discipline to keep refusing features that break this layering
(e.g., ZK until a real need exists) matters more than any diagram.
