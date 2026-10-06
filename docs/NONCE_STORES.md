# Nonce Stores — Deployment Matrix

**Status:** normative companion to [SPEC.md](../SPEC.md) §Replay Protection
and [TRUST_BOUNDARIES.md](TRUST_BOUNDARIES.md).

The replay guarantee of PEP/1 is exactly as strong as the nonce store behind
it: **atomic claim-or-fail under concurrency** (`claimIfAbsent`). This
document states, per store, what deployment topologies preserve that
guarantee — and, just as importantly, which do not.

## The invariant every topology must preserve

Two verifiers processing the same document at the same instant must produce
exactly one `CLAIMED` and one rejection. Anything weaker (check-then-set,
eventual propagation) converts a replay attack from "impossible" to
"race-dependent", which in adversarial terms means *possible*.

## Store matrix

| Store | Single process | Multi-process, one host | Multi-host / K8s replicas | Multi-region |
|---|---|---|---|---|
| `InMemoryNonceStore` | ✅ | ❌ | ❌ | ❌ |
| `FileNonceStore` | ✅ | ✅ (real cross-process locks with liveness-aware ownership, v0.15, + crash durability) | ❌ **not distributed replay protection** | ❌ |
| `RedisNonceStore` | ✅ | ✅ | ✅ **iff** all replicas point at ONE strongly consistent Redis authority | ⚠️ only with one logical authority; see below |

## The honest statement about FileNonceStore

`FileNonceStore` provides *shared-filesystem* state:

```
process A ─┐
           ├─► one filesystem ◄─ atomic rename + lock file
process B ─┘
```

That is **not** distributed replay protection. It assumes one machine, one
durable volume, cooperative locking. Under Kubernetes replicas, multiple
availability zones, replicated or eventually-consistent storage, the
guarantee changes completely and silently — a second replica with its own
volume will happily accept what the first already claimed. This is why the
store matrix above is normative: **never present a FileNonceStore deployment
as multi-host safe.**

### Lock ownership semantics (v0.15)

Within the supported single-host topology, lock takeover is liveness-aware:

- a lock whose recorded owner PID is **alive on this host** is never stolen,
  no matter how old it is — a slow verifier can no longer be double-entered by
  a peer that merely waited out a timeout;
- a provably dead same-host owner (no such PID) may be taken over once the
  staleness window has also passed;
- foreign-host, anonymous, or legacy (v0.14-) lock files fall back to the pure
  time-based window as last resort.

Guarantees are per-host by construction; nothing here relaxes the multi-host
`❌` in the matrix above. Semantics: `test/lock-semantics.test.js`.

## RedisNonceStore requirements

v0.11 added `RedisNonceStore` for real horizontal scale. Its safety depends on
properties that must be provisioned deliberately:

1. **One logical strongly-consistent authority.** Every verifier replica MUST
   point at the same Redis deployment (single primary, or a failover setup
   where loss of an unreplicated write is treated as acceptable downtime —
   NOT as replay tolerance). SET NX semantics are only atomic within one
   shard that holds the key.
2. **No eventually-consistent backends.** Replicated/eventual stores
   (multi-primary databases, CRDT counters, cross-region async replication)
   can observe two successful claims for one nonce during convergence windows.
   They are unsupported by design.
3. **Multi-region deployments** SHOULD either (a) route verification through
   one regional nonce authority per region AND partition nonces so a nonce is
   only ever valid in its home region (encode the region into the nonce), or
   (b) accept the latency cost of a single global authority. Cross-region
   "best effort" replication is explicitly unsafe.
4. **Fail-closed is load-bearing.** If Redis is unreachable,
   `RedisNonceStore.claimIfAbsent` throws and verification fails
   (`NONCE_STORE_UNAVAILABLE` posture). Never swap in an open fallback.

## What would change this document

A genuinely distributed nonce authority without a single-shard bottleneck —
e.g. a consensus-backed service or sharded authorities with globally unique
nonce namespaces — would relax requirement 1/3. Until such a component exists
here and ships with vectors proving it, this matrix stands as written.
