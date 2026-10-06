# AUREVIA Arbitration Court /1 — Normative Specification

**Status:** normative since v0.18.0 · **Module:** `src/court.js` (L2) · **CLI:** `pep court-demo`

This document specifies the decentralized arbitration layer built on top of
the deterministic dispute reports of the Dispute Engine. It replaces the old
honest disclaimer ("no judge quorum, no challenge periods, no arbitration
market, no on-chain settlement") with an honest *implementation* of exactly
those things — under one constitutional rule:

> **Verdicts are mathematics, not authority.** No single key can settle a
> case; every ruling carries a multi-signature over the exact tally; and any
> party — including a total stranger — can replay the entire case and detect
> tampering as a named difference.

---

## 1. What "decentralized" means here — precisely

| Property | Mechanism | Where verified |
|---|---|---|
| No single point of decision | settlement = N-of-panel multi-signature over canonical certificate bytes; removing one signature breaks verification (`CERT_SIG_COUNT`, `CERT_SIG:*`) | `replayArbitration()` |
| Judges are keys, not institutions | roster lives in the registry with public key, stake, capabilities, status; admission/revocation are visible registry acts | `registerJudge` / `revokeJudge` |
| Trustless auditability | full replay re-verifies every ballot/opinion/certificate signature and recomputes every tally **purely** (no mutation) | `replayArbitration` + `computeTally` |
| Deterministic market access | panel assignment sorts by published fee, then reputation, then id — never by operator discretion | `assignPanel` |
| Fail-closed outcomes | quorum unmet or hung jury → `UNRESOLVED`, a first-class result, never coerced | `openChallengeWindow` |

Honest boundaries: stakes and fees are declared commitments tracked in the
registry (not escrowed tokens); this module never broadcasts to a blockchain
(it emits anchor-ready certificates — see §6). These limits are stated here,
in code comments, and in every UI that renders them.

## 2. Judge roster

```
registry.court = {
  version: 1,
  config: { quorum_min_judges, quorum_min_stake, stake_ceiling, max_rounds,
            windows_ms: { evidence, deliberation, challenge } },
  judges: { [id]: { public_key_pem, status: "active"|"revoked",
                    capabilities: ["judge","referee"], stake, reputation,
                    registered_at } },
  market: { fee_books: { [id]: { general_dispute?, agent_dispute? } } }
}
```

Rules:
- Stakes are integers in `[1, stake_ceiling]`; out-of-range registration is
  rejected, **never silently clamped**.
- Capabilities gate actions. A key without `judge` cannot cast ballots even
  if it is a referee. This is what enforces §4's constitutional rule.
- Revocation takes effect immediately at tally time: ballots from revoked
  keys fail signature-authority checks and appear in `rejected_voters`.

## 3. Case lifecycle

```
FILED ── evidence ──► EVIDENCE_WINDOW ── openDeliberation ──► DELIBERATION_ROUND_n
   DELIBERATION_ROUND_n ── tallyRound ──┬─ QUORUM_FAILED / NO_MAJORITY ► UNRESOLVED
                                        └─ AFFIRM / REVERSE ► CHALLENGE_WINDOW
CHALLENGE_WINDOW ── settleCase ► SETTLED          (or upheld challenge reopens deliberation)
```

- Every transition appends an immutable `history` entry with timestamp.
- Windows are wall-clock bounds on actions (`WINDOW_CLOSED` /
  `WINDOW_NOT_OPEN` errors otherwise).
- Ballots are Ed25519 signatures over
  `"AUREVIA-COURT-v1\n" + canonical({kind:"BALLOT", case_id, round, judge_id, verdict, reasons_hash})`.
  The signature itself is never part of the signed message.

## 4. The AI division ("agent court")

Division `agent` handles disputes whose defendant is an autonomous agent
(`agent://…`). Its constitution is one line long:

> **AI argues; keys decide.**

- AI referees hold keys with capability `referee`. They submit **signed
  advisory opinions** which are stored as evidence (`ai_referee_opinion`),
  hash-pinned into the settlement certificate's `tally_proof.referee_opinions`,
  and flagged `advisory: true`.
- Referee opinions are **excluded from every tally by construction**: the
  weighting loop only ever consults keys with the `judge` capability, and a
  referee attempting to vote fails with `NOT_CAPABLE`.
- The agent division uses its own fee class (`agent_dispute`) so the market
  prices this expertise separately.

## 5. Tallying — weighted, deterministic, pure

`computeTally(registry, case, round)` is a **pure function** (it mutates
nothing) because trustless replay requires that checking a record can never
rewrite it. (The v0.18 test suite pins this: a mutating re-tally silently
laundered tampered tallies until it was split from the committing path.)

- Each verified ballot contributes its judge's current `stake` to its
  verdict weight (`AFFIRM` / `REVERSE` / `ABSTAIN`; abstention carries no
  deciding weight but counts toward participation).
- Quorum requires BOTH: distinct participating judges ≥ `quorum_min_judges`
  AND decided weight ≥ `quorum_min_stake`. Otherwise `QUORUM_FAILED`.
- Equal decided weights → `NO_MAJORITY`. Both end the case `UNRESOLVED`.

## 6. Challenge period & settlement certificates

- Opening the window publishes the provisional outcome and a deadline.
- A challenge during the window IS a replay: the court runs
  `replayArbitration` against the stored record. If the challenger proves
  genuine corruption (named differences), deliberation reopens; if not, the
  challenger loses reputation. Frivolous challenging costs.
- Settlement produces `AUREVIA-Court-Settlement/1`: verdict, payer rule,
  fee breakdown per assigned panelist (integer units), full tally proof
  (every ballot + signature), referee opinion hashes, and **one signature
  per panel judge** over the canonical certificate bytes.
- `buildAnchorPayload(cert)` returns byte-deterministic anchor material
  (`{network, encoding, payload, bytes, memo}`), tested for pre-commitment:
  two builds are identical buffers. Broadcasting is a deployment concern —
  integrators plug a chain adapter exactly like they plug signing backends.

## 7. Arbitration market

- Judges publish fee books per case class. Missing quotes sort last.
- Panel assignment: `(fee asc, reputation desc, id asc)` → first
  `quorum_min_judges`. Fully reproducible by third parties.
- Reputation: +2 for voting with the final outcome at settlement; −1 for a
  rejected challenge. Reputation feeds future assignment order — skin in
  the game without token escrow.
- `marketSnapshot(registry, openCases)` reports active supply, open demand,
  and median/min clearing fees per class.

## 8. Error codes

`COURT_NOT_INITIALIZED` · `COURT_ALREADY_INITIALIZED` · `COURT_BAD_INPUT` ·
`COURT_BAD_CASE` · `JUDGE_EXISTS` · `JUDGE_UNKNOWN` · `JUDGE_REVOKED` ·
`NOT_CAPABLE` · `STAKE_OUT_OF_RANGE` · `WINDOW_CLOSED` · `WINDOW_NOT_OPEN` ·
`DUPLICATE_BALLOT` · `ROUNDS_EXHAUSTED` · `NOT_SETTLABLE` · `SIGNER_MISSING`

Replay difference codes: `TYPE` · `DUP:r:j` · `REVOKED_VOTER:j` ·
`BAD_SIG:r:j` · `TALLY_OUTCOME:r` · `TALLY_WEIGHTS:r` · `REF_CAP:id` ·
`REF_ADVISORY_FLAG` · `REF_SIG:id` · `CERT_SIG_COUNT` · `CERT_SIG:j` ·
`CERT_SIGNER_UNKNOWN:j`
