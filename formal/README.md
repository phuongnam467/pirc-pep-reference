# formal/ — Machine-Checkable Fragment

## What lives here

| File | Purpose |
|---|---|
| `piproof_gates.tla` | TLA+ model of the G1–G9 pipeline: two verifiers racing one shared nonce authority; the stateful core (snapshot eligibility + atomic test-and-set) with INV-04/INV-05 as TLC invariants |
| `piproof_gates.cfg` | TLC configuration (2 verifiers, four invariants) |

## Status: machine-checked in CI

TLC runs this model on every push and PR — job `formal-tlc` downloads a
checksum-pinned `tla2tools.jar` (v1.7.4, SHA1
`bee4a54f3ee3d4afc347c3240ec2d9e93b075104`, matching the official release
checksum) on Temurin 21 and fails CI unless it reports
*"Model checking completed. No error has been found."*

Verified result (TLC 2.19): complete state space of **122 distinct states**,
all four invariants (`TypeOK`, `AtMostOneAccept`, `AcceptImpliesBurn`,
`BurnOnlyOnPass`) satisfied.

To run locally (from this directory — TLC resolves module paths relative
to the spec's directory):

```
java -XX:+UseParallelGC -jar tla2tools.jar -config piproof_gates.cfg piproof_gates.tla
```

Modeling decisions are documented in the module header. Deliberate scope:
pure gates G1–G7 are abstracted to always-pass steps because their failure
semantics are exhaustively pinned by the interop vectors and fuzz suites;
the model exists to explore *concurrency and state* interactions, which is
where vector suites are structurally blind.

Two design notes worth keeping visible:

1. **Terminal stuttering is an explicit action** rather than running TLC
   with `-deadlock`. This preserves deadlock detection for stuck
   mid-pipeline states — a real bug class — while allowing clean
   termination once both verifiers are done.
2. **The G8 environment choice is atomic** (choice + consequence in one
   step). An earlier draft let the verifier read the snapshot before the
   environment committed; TLC's deadlock report exposed that flaw, which is
   exactly the kind of catch this model exists for.

## Roadmap

1. Extend the model with the freshness window as an explicit clock variable
   and re-check INV-09.
2. Grow invariant coverage beyond INV-04/INV-05 toward the full INV-01…12
   set where they are expressible at this abstraction level.
3. Add a PlusCal refinement mapping against `src/verify.js` gate order so
   the code and the model can be diffed mechanically.
