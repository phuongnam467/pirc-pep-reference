# Signed Registry Transparency Log — Design Draft

**Status: NON-NORMATIVE DRAFT (v1).** This document is the design
companion for closing Open Question #1 ("registry authenticity is not
settled at protocol level"). It exists so the external v1.0 security
review has a concrete artifact to attack. Nothing here is implemented in
the frozen PEP/1 core, and nothing here may ship as normative before that
review concludes.

---

## 1. Problem statement

Today a verifier's verdict is only as trustworthy as the registry it was
handed. Signatures prove *who signed*; the registry decides *what their
signature means* (key validity, ceilings, eligibility). A launchpad that
controls registry distribution could present verifiers with a false world
state — bounded in blast radius by weight ceilings and escrow attestations,
but bounded is not eliminated.

**Goal:** let any third party prove that *every verifier is seeing the same
registry history*, without trusting the party serving it.

## 2. Non-goals

- Hiding registry contents (the log contains no user data — see §8).
- Decentralized consensus / tokens / a new chain. This is a transparency
  log in the CT tradition: gossip + consistency proofs, not consensus.
- Changing PEP/1 event semantics. The frozen core stays frozen.

## 3. Model

An append-only sequence of **epoch entries**. Each entry commits to one
registry snapshot (the thing `registry_root` already hashes today).

```
Entry_i = {
  schema:      "AUREVIA-TL-Entry/1",
  index:       i,
  epoch_id:    "e1:<hex32>",          // random 128-bit epoch identifier
  registry_root:"r1:<hex64>",         // exactly what PiProof binds today
  prev_entry:  "<hex64>" | null,      // hash of Entry_{i-1} canonical bytes
  timestamp:   <ms>,
  signers:     [ { key_id, signature } ... ]   // m-of-n witness set
}
```

- `hash(Entry_i)` = SHA-256 over its **canonical bytes**, produced by the
  exact closed-profile canonicalizer already normative in SPEC.md. No new
  serialization rules are introduced anywhere in this design.
- The chain head plus all entries since a checkpoint form a **log proof**
  handed to any verifier alongside the registry itself.

## 4. Verification procedure (pure function)

```
verifyLog(entries, { witnesses, now }) →
  { ok, head } | { ok:false, code: TL_* }
```

Checks, in fixed order:

1. `TL_SCHEMA` — every entry matches the closed entry profile.
2. `TL_CHAIN` — index strictly increments; `prev_entry` equals the hash of
   the previous entry's canonical bytes.
3. `TL_SIGNERS` — each entry carries ≥ m valid Ed25519 signatures from
   distinct keys in the configured witness keyset (keys identified by
   `key_id`, resolved through a pinned witness roster distributed with the
   verifier — the one remaining trusted root, made explicit).
4. `TL_FRESHNESS` — head timestamp within policy window.
5. `TL_REGISTRY_BINDING` — head `registry_root` equals the root hash the
   verifier computes from the registry it was actually given.

Failure ⇒ the verifier refuses to adjudicate (UNVERIFIABLE), never
"probably fine". Reuse rule: steps 1–5 are compositions of existing
primitives (`canonicalize`, RFC 8032 verify, SHA-256) — zero new crypto.

## 5. Inclusion & consistency

- **Inclusion:** a proof referencing epoch i embeds `Entry_i`'s hash; a
  verifier holding entries 0..i re-derives it.
- **Consistency:** two verifiers comparing logs exchange entry vectors;
  identical prefixes must have identical hashes. Divergence at any index ⇒
  split view, surfaced loudly (`TL_SPLIT_VIEW`).
- Gossip is out of scope of this draft; any transport works because trust
  lives in signatures, not channels.

## 6. Witness policy

- Roster ships with the verifier build (pinned keys, published fingerprints).
- Default policy m=2-of-3 for pilot deployments; production target ≥3-of-5
  with geographically/organizationally independent witnesses.
- Key rotation inside the witness roster is itself an entry type
  (`roster_change`), signed by the outgoing quorum — never by the incoming
  one alone.

## 7. Migration path

1. Launchpads publish `Entry_0` alongside today's registry (additive).
2. PiProof gains optional `log_proof` field on passports/proofs — absent
   field keeps current behavior byte-for-byte (no breaking change).
3. Verifiers that receive a log proof run §4; those that don't keep
   today's behavior and say so in dispute reports.
4. After external review, absence of a log proof MAY downgrade to a
   policy-visible warning. That flip is a v1.0 decision, not this draft's.

## 8. Privacy

Entries contain: epoch ids, registry roots (app ids, public key
fingerprints, eligibility counts), timestamps, signatures. No pioneer UIDs,
no UID hashes, no events, no amounts beyond ceiling parameters. The log
learns nothing about individuals — same posture as the passport (minimum
necessary data), extended to infrastructure.

## 9. Error codes (reserved)

`TL_SCHEMA` · `TL_CHAIN` · `TL_SIGNERS` · `TL_FRESHNESS` ·
`TL_REGISTRY_BINDING` · `TL_SPLIT_VIEW`

## 10. Open questions for reviewers

1. Is m-of-n cosigning sufficient, or should witness entries additionally
   be anchored to an external transparency system during bootstrap?
2. Should `TL_FRESHNESS` bound be policy-level or fixed by spec?
3. Roster governance: who signs the initial roster, and under what
   process? (Deliberately unanswered here.)
4. Do we need compact range proofs at log scale >10⁴ epochs, or is linear
   replay acceptable for the expected ecosystem size?
5. Interaction with escrow attestations: fold into the same log, or keep
   separate streams with independent heads?
