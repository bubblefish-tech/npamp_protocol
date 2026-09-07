#!/usr/bin/env python3
# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""harness/statelearn/diff_model.py -- the T18.2 (R18.2) load-bearing F3 diff.

Expands harness/statemodel/npamp-state-table.json (the draft-derived reference Mealy
model -- NEVER derived from the Go implementation, see that file's provenance note) into a
COMPLETE per-role machine: every (state, input) cell is filled, either by a table-listed
transition or by the table's own total_default rule, plus ONE documented harness extension
for the ACTION symbol INIT_CLOSE (see EXPAND_INIT_CLOSE_NOTE below -- CLOSING is entered by
SENDING a CLOSE, which the table's receive-only model does not itself cover).

It then compares that expanded reference against the LearnLib-learned machine for the same
role (harness/statelearn/learned-<role>.json, produced by NpampStateLearner.java driving the
REAL Go SDK via sul/statelearn-sul.exe) using simultaneous-traversal Mealy-machine
equivalence checking: a product-construction walk from each machine's initial state that
either confirms a consistent state pairing at every step or reports a mismatch. This is the
standard way to decide FSM equivalence without needing a minimization/isomorphism library,
and it naturally handles the learned machine's opaque state IDs (q0, q1, ...) against the
table's named states (WAIT_SH, ESTABLISHED, ...).

F3 non-circularity: the reference side of this diff comes ONLY from npamp-state-table.json.
This script never reads Go source. A FAIL here means the LEARNED (real SDK) behavior
disagrees with the DRAFT-DERIVED table -- a spec gap or an implementation bug, never a
tautology, because the two sides are built from independent authorities.

Exit 0 iff every requested role's learned machine is fully equivalent to its expanded
reference. Exit 1 (every mismatch printed, plus diff-report.json written) otherwise.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
TABLE_PATH = HERE.parent / "statemodel" / "npamp-state-table.json"

# modeled_exclusions (npamp-state-table.json): "the initiator sends CLIENT_HELLO as its
# opening ACTION... A SUL for the initiator resets into WAIT_SH (CLIENT_HELLO already
# sent)." The responder's own table initial_state (LISTEN) already matches where
# sul/responder.go's reset() lands (nothing exchanged yet).
ROLE_INITIAL = {"initiator": "WAIT_SH", "responder": "LISTEN"}

# START is listed in the table "for completeness" (modeled_exclusions) but is a transient
# pre-CLIENT_HELLO state genuinely UNREACHABLE once the walk starts at WAIT_SH (there is no
# transition back to START from anywhere). Excluding it from the reachability/coverage check
# is a narrow, documented exception -- not a blanket "ignore unreached states" escape hatch;
# every OTHER table state must still be reached or the diff reports it.
EXPECTED_UNREACHABLE = {"initiator": {"START"}, "responder": set()}

INIT_CLOSE = "INIT_CLOSE"

EXPAND_INIT_CLOSE_NOTE = (
    "INIT_CLOSE is a HARNESS EXTENSION, not a table-listed input: the table only models "
    "RECEIVE reactions (role,state,received-frame)->(output,next_state), but CLOSING is "
    "entered by the endpoint itself SENDING a CLOSE (CloseGraceful), which is an action, "
    "not a received frame. This diff adds one explicit rule on top of the table so CLOSING "
    "is still exercised: INIT_CLOSE -> (CLOSING, SILENT) ONLY from ESTABLISHED, the one state "
    "with a live *sdk.Conn the SUL can call CloseGraceful on. NOTE the earlier version keyed "
    "this on key_established[state], which is ALSO true at the handshake states WAIT_SA / "
    "WAIT_CA -- but no *Conn is returned to the caller until ESTABLISHED, so the SUL's "
    "stepInitClose is a no-op there (sutConn == nil): INIT_CLOSE from WAIT_SA/WAIT_CA is a "
    "SILENT self-loop, matching the learned model (this was a real diff bug, T18.2 Cat 3). A "
    "repeat INIT_CLOSE while already CLOSING or CLOSED is likewise a no-op self-loop (sul's "
    "stepInitClose deliberately does not exercise the SDK's own un-guarded concurrent-"
    "CloseGraceful race -- see sul/initiator.go); before ESTABLISHED, INIT_CLOSE is also a "
    "no-op self-loop (there is nothing to close yet)."
)


def load_table(path: Path = TABLE_PATH) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def expand_reference(table: dict[str, Any], role: str) -> dict[str, dict[str, tuple[str, str]]]:
    """Returns ref[state][input] = (output, next_state) for EVERY state x (input_alphabet +
    INIT_CLOSE), for the given role."""
    states: list[str] = table["states"][role]
    key_established: dict[str, Any] = table["total_default"]["key_established_by_state"]
    inputs: list[str] = list(table["input_alphabet"]) + [INIT_CLOSE]
    out_post: str = table["total_default"]["output_post_key"]
    out_pre: str = table["total_default"]["output_pre_key"]

    listed: dict[tuple[str, str], tuple[str, str]] = {}
    for tr in table["transitions"]:
        if tr["role"] not in (role, "both"):
            continue
        listed[(tr["from"], tr["input"])] = (tr["output"], tr["to"])

    # Unauthenticated-input drop-and-survive rule (draft {#record-layer-drops}; table
    # total_default.unauthenticated_inputs). Certain abstract inputs are concretized by the
    # SUL as UNAUTHENTICATED frames once a keyed session with a live *Conn exists: the
    # cleartext handshake-flight symbols (no FlagENC) and the *_BADAUTH symbols (sealed then
    # corrupted so the AEAD open fails). A cleartext or AEAD-failing frame at such a state is
    # silently DROPPED and counted, the association SURVIVES -> (SILENT, self-loop), never the
    # total-default ERROR. Read from the table (F3: the rule + its draft anchor live there).
    unauth = table["total_default"].get("unauthenticated_inputs", {})
    unauth_inputs: set[str] = set(unauth.get("inputs", []))
    unauth_states: set[str] = set(unauth.get("at_states", []))

    # States in which a live *sdk.Conn exists (the record-layer drop path runs, and INIT_CLOSE
    # can actually call CloseGraceful). key_established is TRUE at WAIT_SA/WAIT_CA too, but no
    # *Conn is returned to the caller until ESTABLISHED, so the SUL cannot drive recvLocked,
    # inject an APP frame, or CloseGraceful before then.
    conn_states = {"ESTABLISHED", "CLOSING"}

    ref: dict[str, dict[str, tuple[str, str]]] = {}
    for state in states:
        ref[state] = {}
        for inp in inputs:
            key = (state, inp)
            if key in listed:
                ref[state][inp] = listed[key]
                continue
            if state == "CLOSED":
                # total_default exception: CLOSED is terminal, no frame is processed.
                ref[state][inp] = ("SILENT", "CLOSED")
                continue
            if inp in unauth_inputs and state in unauth_states:
                # Cat 1 (draft {#record-layer-drops}): unauthenticated frame at a live-*Conn
                # keyed state -> dropped and counted, association survives; no output, no move.
                ref[state][inp] = ("SILENT", state)
                continue
            if inp == INIT_CLOSE:
                # A harness ACTION (the SUT itself calls CloseGraceful), not a received frame.
                # It can only enter CLOSING from a state with a live *Conn (ESTABLISHED). At the
                # handshake states (WAIT_SA/WAIT_CA — key_established TRUE but no *Conn yet) and
                # at CLOSING/other states the SUL's stepInitClose is a no-op self-loop.
                if state == "ESTABLISHED":
                    ref[state][inp] = ("SILENT", "CLOSING")
                else:
                    ref[state][inp] = ("SILENT", state)
                continue
            if inp == "APP" and state not in conn_states:
                # APP is only a real received-frame input where a live *Conn can receive it.
                # Before establishment there is no application channel and the SUL cannot inject
                # an APP frame (no *Conn), so it is a harness no-op self-loop (SILENT).
                ref[state][inp] = ("SILENT", state)
                continue
            ke = key_established.get(state, False)
            out = out_post if ke is True else out_pre
            ref[state][inp] = (out, "CLOSED")
    return ref


def compare(
    learned: dict[str, Any],
    ref: dict[str, dict[str, tuple[str, str]]],
    ref_initial: str,
    alphabet: list[str],
    expected_unreachable: set[str] = frozenset(),
) -> list[dict[str, Any]]:
    """Simultaneous-traversal Mealy equivalence check. Returns a list of mismatch records
    (empty == fully equivalent)."""
    ltrans: dict[tuple[str, str], tuple[str, str]] = {}
    for t in learned["transitions"]:
        ltrans[(t["from"], t["input"])] = (t["output"], t["to"])

    learned_initial = learned["initial_state"]

    pair_l2r: dict[str, str] = {learned_initial: ref_initial}
    pair_r2l: dict[str, str] = {ref_initial: learned_initial}
    queue: list[tuple[str, str]] = [(learned_initial, ref_initial)]
    visited: set[tuple[str, str]] = set()
    mismatches: list[dict[str, Any]] = []

    while queue:
        lstate, rstate = queue.pop(0)
        if (lstate, rstate) in visited:
            continue
        visited.add((lstate, rstate))

        for inp in alphabet:
            lkey = (lstate, inp)
            if lkey not in ltrans:
                mismatches.append({
                    "kind": "learned_missing_transition",
                    "learned_state": lstate, "ref_state": rstate, "input": inp,
                })
                continue
            lout, lnext = ltrans[lkey]

            if rstate not in ref or inp not in ref[rstate]:
                mismatches.append({
                    "kind": "table_missing_cell",
                    "ref_state": rstate, "learned_state": lstate, "input": inp,
                    "learned_output": lout,
                })
                continue
            rout, rnext = ref[rstate][inp]

            if lout != rout:
                mismatches.append({
                    "kind": "output_mismatch",
                    "learned_state": lstate, "ref_state": rstate, "input": inp,
                    "learned_output": lout, "ref_output": rout,
                })
                continue

            if lnext in pair_l2r:
                if pair_l2r[lnext] != rnext:
                    mismatches.append({
                        "kind": "next_state_inconsistent",
                        "from_learned": lstate, "from_ref": rstate, "input": inp,
                        "learned_next": lnext,
                        "expected_ref_next": pair_l2r[lnext], "actual_ref_next": rnext,
                    })
                    continue
            elif rnext in pair_r2l:
                if pair_r2l[rnext] != lnext:
                    mismatches.append({
                        "kind": "next_state_inconsistent",
                        "from_learned": lstate, "from_ref": rstate, "input": inp,
                        "ref_next": rnext,
                        "expected_learned_next": pair_r2l[rnext], "actual_learned_next": lnext,
                    })
                    continue
            else:
                pair_l2r[lnext] = rnext
                pair_r2l[rnext] = lnext

            queue.append((lnext, rnext))

    for s in ref:
        if s not in pair_r2l and s not in expected_unreachable:
            mismatches.append({"kind": "ref_state_unreached_by_learner", "ref_state": s})

    return mismatches


def run_role(table: dict[str, Any], learned_path: Path, role: str) -> tuple[list[dict[str, Any]], dict, dict]:
    ref = expand_reference(table, role)
    alphabet = list(table["input_alphabet"]) + [INIT_CLOSE]
    with open(learned_path, "r", encoding="utf-8") as f:
        learned = json.load(f)
    mismatches = compare(learned, ref, ROLE_INITIAL[role], alphabet, EXPECTED_UNREACHABLE[role])
    return mismatches, ref, learned


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dir", default=str(HERE), help="directory containing learned-<role>.json")
    ap.add_argument("--roles", nargs="+", default=["initiator", "responder"])
    ap.add_argument("--table", default=str(TABLE_PATH))
    args = ap.parse_args()

    table = load_table(Path(args.table))
    total_mismatches = 0
    report: dict[str, Any] = {"init_close_extension_note": EXPAND_INIT_CLOSE_NOTE, "roles": {}}

    for role in args.roles:
        learned_path = Path(args.dir) / f"learned-{role}.json"
        if not learned_path.exists():
            print(f"FAIL [{role}]: {learned_path} does not exist (the learn has not run)")
            total_mismatches += 1
            report["roles"][role] = {"verdict": "FAIL", "reason": "learned model missing"}
            continue

        mismatches, ref, learned = run_role(table, learned_path, role)
        if mismatches:
            print(f"FAIL [{role}]: {len(mismatches)} mismatch(es) "
                  f"(learned {len(learned['states'])} states / {len(learned['transitions'])} "
                  f"transitions vs expanded reference {len(ref)} states)")
            for m in mismatches:
                print(f"  {m}")
        else:
            print(f"PASS [{role}]: learned machine ({len(learned['states'])} states, "
                  f"{len(learned['transitions'])} transitions) is fully equivalent to the "
                  f"expanded draft-derived reference ({len(ref)} states)")

        total_mismatches += len(mismatches)
        report["roles"][role] = {
            "verdict": "PASS" if not mismatches else "FAIL",
            "learned_states": len(learned["states"]),
            "learned_transitions": len(learned["transitions"]),
            "reference_states": len(ref),
            "mismatch_count": len(mismatches),
            "mismatches": mismatches,
        }

    out_path = Path(args.dir) / "diff-report.json"
    # newline="\n": emit LF on every platform (Windows text mode would write CRLF), so the
    # committed diff-report matches .gitattributes eol=lf and does not churn on a local run.
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(report, f, indent=2)
    print(f"report written to {out_path}")

    sys.exit(0 if total_mismatches == 0 else 1)


if __name__ == "__main__":
    main()
