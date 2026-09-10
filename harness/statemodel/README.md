# N-PAMP state model (`npamp-state-table.json`)

A machine-readable Mealy model of the N-PAMP handshake + keyed-session state machine,
one per endpoint role. It is the reference authority for two conformance gates:

- **Deviant-trace suite.** A skip/hop/repeat trace generator reads this
  table, enumerates every `(state, illegal-frame)` pair the total default covers, and
  asserts the reference implementation reacts with the exact wire code the table gives
  (`unexpected_message` / `decrypt_failed`).
- **Learned-model diff.** An active-automata-learning run (LearnLib)
  learns the Go stack's actual Mealy machine, and the diff checks it for isomorphism
  against this table. Any learned state or transition absent from the table fails — a
  spec gap or a bug.

## Why it is derived from the draft, not the code

The load-bearing property is **non-circularity**: the diff compares the Go
stack's *learned* machine against this table. If the table were itself generated from the
Go code, the comparison would be Go-vs-Go and could not catch a state-machine bug shared
between them. So every transition here is anchored to the **draft text**
(`ietf/draft-bubblefish-npamp-latest.md`, §State Machine, lines 795–891) — the normative
event-by-state rules and the total default — never to an implementation. The `provenance`
and per-transition `note` fields carry the draft line references.

## Model shape

`(role, state, received-frame) → (output, next_state)`, where `output` is the endpoint's
observable reaction (a sent frame, an `ERROR` with its registered wire code, or `SILENT`).
`total_default` fills every `(state, frame)` cell not listed in `transitions`
(→ `unexpected_message` + teardown), with two exceptions (terminal `CLOSED`; the
`replay_detected` discard). `modeled_exclusions` records what is deliberately outside the
Mealy abstraction (sequence numbers → differential testing; timer-fired transitions;
in-flight frames during close), so the learned-model diff never reports them as coverage gaps.
