------------------------------- MODULE piproof_gates -------------------------------
(***********************************************************************************)
(* PiProof G1–G9 verification pipeline as a step-indexed state machine —           *)
(* the machine-checkable fragment of docs/FORMAL_MODEL.md.                         *)
(*                                                                                 *)
(* WHAT IS MODED AND WHY                                                           *)
(* Two verifiers race ONE event against ONE shared durable nonce authority.        *)
(* Gates G1–G7 are pure functions of the document (their failure semantics are     *)
(* exhaustively pinned by the vector and fuzz suites), so they are modeled as      *)
(* always-pass steps. The STATEFUL heart is what needs a model checker:            *)
(*   • G8 — registry snapshot eligibility (environment choice per verifier)         *)
(*   • G9 — atomic test-and-set on the shared burned flag                           *)
(* TLC explores every interleaving of the two pipelines.                            *)
(*                                                                                 *)
(* INVARIANTS CHECKED                                                              *)
(*   TypeOK            — state stays well-formed                                   *)
(*   AtMostOneAccept   — INV-04: two racing verifiers cannot both reach ACCEPT      *)
(*   AcceptImpliesBurn — acceptance happened exactly through a G9 win               *)
(*   BurnOnlyOnPass    — INV-05: nothing burns the nonce except an acceptor         *)
(*                                                                                 *)
(* RUN (external tooling — Java + tla2tools.jar, from this module's directory):    *)
(*   java -XX:+UseParallelGC -jar tla2tools.jar -config piproof_gates.cfg \         *)
(*       piproof_gates.tla                                                         *)
(* Verified with TLC 2.19 (tla2tools v1.7.4): "Model checking completed.           *)
(* No error has been found." over the complete 122-state space, all four           *)
(* invariants satisfied. CI runs this on every push (job: formal-tlc).             *)
(***********************************************************************************)
EXTENDS Integers

CONSTANT Verifiers    \* model value: {v1, v2} — see piproof_gates.cfg

VARIABLES
    pc,        \* per-verifier program counter: gate index 1..9 while running,
               \* ACCEPTED, or -(gate index) after a rejection at that gate
    burned,    \* shared durable nonce state: TRUE once claimed
    eligSeen   \* per-verifier registry-snapshot verdict at G8 (env choice)

Gates == 1..9
ACCEPTED == 10
REJ(g) == -g
TerminalPCs == {REJ(g) : g \in Gates} \cup {ACCEPTED}
AllPCs == Gates \cup TerminalPCs

TypeOK ==
    /\ pc \in [Verifiers -> AllPCs]
    /\ burned \in BOOLEAN
    /\ eligSeen \in [Verifiers -> BOOLEAN]

Init ==
    /\ pc = [v \in Verifiers |-> 1]
    /\ burned = FALSE
    /\ eligSeen = [v \in Verifiers |-> FALSE]

(* Gates G1–G7: pure checks pass (purity enforced by vectors/fuzzing). *)
PassPure(v) ==
    /\ pc[v] \in 1..7
    /\ pc' = [pc EXCEPT ![v] = pc[v] + 1]
    /\ UNCHANGED <<burned, eligSeen>>

(* G8: the environment atomically commits to a snapshot verdict — the
   chosen value and its consequence happen in one step. *)
PassG8(v) ==
    /\ pc[v] = 8
    /\ eligSeen' = [eligSeen EXCEPT ![v] = TRUE]
    /\ pc' = [pc EXCEPT ![v] = 9]
    /\ UNCHANGED burned

FailG8(v) ==
    /\ pc[v] = 8
    /\ eligSeen' = [eligSeen EXCEPT ![v] = FALSE]
    /\ pc' = [pc EXCEPT ![v] = REJ(8)]
    /\ UNCHANGED burned

(* G9: atomic test-and-set — winner flips burned and ACCEPTS atomically;
   any later contender observes burned and rejects. *)
WinClaim(v) ==
    /\ pc[v] = 9
    /\ ~burned
    /\ burned' = TRUE
    /\ pc' = [pc EXCEPT ![v] = ACCEPTED]
    /\ UNCHANGED eligSeen

LoseClaim(v) ==
    /\ pc[v] = 9
    /\ burned
    /\ pc' = [pc EXCEPT ![v] = REJ(9)]
    /\ UNCHANGED <<burned, eligSeen>>

(* Explicit terminal stuttering: once every verifier is done the run is
   over. Keeping this an ACTION (instead of running TLC with -deadlock)
   preserves deadlock detection for stuck mid-pipeline states — a real
   bug class we still want flagged. *)
TerminalStutter ==
    /\ \A v \in Verifiers : pc[v] \in TerminalPCs
    /\ UNCHANGED <<pc, burned, eligSeen>>

Next ==
    \/ TerminalStutter
    \/ \E v \in Verifiers :
        \/ PassPure(v)
        \/ PassG8(v)
        \/ FailG8(v)
        \/ WinClaim(v)
        \/ LoseClaim(v)

Spec == Init /\ [][Next]_<<pc, burned, eligSeen>>

IsAccept(v) == pc[v] = ACCEPTED

(* INV-04 *)
AtMostOneAccept ==
    \A v1 \in Verifiers :
        \A v2 \in Verifiers :
            (v1 # v2 /\ IsAccept(v1)) => ~IsAccept(v2)

(* acceptance can only be reached through the winning claim *)
AcceptImpliesBurn ==
    \A v \in Verifiers : IsAccept(v) => burned

(* INV-05 *)
BurnOnlyOnPass ==
    burned => (\E v \in Verifiers : IsAccept(v))

=============================================================================
