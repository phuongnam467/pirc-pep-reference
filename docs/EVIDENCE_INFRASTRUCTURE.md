# Agent Evidence — general-purpose proof infrastructure

Agent Evidence (introduced v0.16) is often met as "the AI-agent feature".
It is better understood as the moment the protocol stopped being about
any one ecosystem: **evidence chains that any principal — human, service,
or autonomous agent — can carry and any verifier can check.**

## What an evidence bundle is

A bundle is a hash-linked chain of signed PEP/1 events plus a declared
claim:

```
bundle := {
  claim:    string            // what this chain is offered as evidence of
  events:   [signed PEP/1]…   // each event independently G1–G9 checkable
  links:    [sha256]…         // event[i+1] commits to hash(event[i])
}
```

Verification (`src/agent-evidence.js`):

1. every event passes the standard pipeline against a pinned registry;
2. links are byte-exact (`sha256(canonical(prev))`);
3. the claim's `subject_hash` matches the pseudonym shared by the chain
   (an h1 — never a raw uid);
4. verdicts are per-event; a single bad link poisons forward reachability,
   which the report states explicitly rather than averaging away.

## Why this is infrastructure, not a feature

- **Issuer-agnostic**: nothing in the chain knows or cares whether the
  actor was a Pi pioneer, a warehouse robot, or a CI job. §11 of SPEC.md
  (`test/pi-independent.test.js`) proves the pipeline with zero Pi
  semantics.
- **Policy-composable**: bundles feed `verifyBundle → policy.evaluate`
  like single proofs; narrow-only rule subsets apply unchanged.
- **Court-ready**: bundles are admissible as case evidence
  (`court.fileCase`), where judges verify them with the same gates —
  dispute resolution inherits verification instead of inventing its own.

## Design rules

| Rule | Rationale |
|------|-----------|
| Evidence is hashes + signatures, never credentials | carrying identity would recreate the privacy problem the protocol exists to solve |
| Chains are append-only; no trusted aggregator | any party can recompute reachability |
| Claims live outside the crypto envelope | the envelope proves *events*; interpretation stays auditable and versioned |

## Relationship to passports

Passports/1 assert capability ("this principal may do X until T").
Evidence bundles demonstrate history ("these events happened, chained").
Disputes combine both; the court arbitrates when they disagree.
