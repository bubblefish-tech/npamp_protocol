# N-PAMP IETF hackathon interop-prep kit

This directory packages the project's existing cross-implementation interop
tooling (`impl/go/cmd/npamp-interop`, `impl/rust/examples/interop_{client,server}`)
for use by a party **outside this repository** — the shape an IETF hackathon
interop session needs: "bring your own implementation, connect it to ours, record
what happened."

## What is in here

| File | Purpose |
|---|---|
| [`THIRD-PARTY-QUICKSTART.md`](THIRD-PARTY-QUICKSTART.md) | Step-by-step: how an independent implementer points their own N-PAMP stack at ours (or vice versa) over a real network address, with no dependency on this repo's internals beyond the two published reference crates/modules. |
| [`run-against-peer.sh`](run-against-peer.sh) | A thin runner. It builds one of our two reference stacks (Go or Rust), runs it in the requested role (`server`/`client`) against a given address, and — on a successful live round trip — separately re-runs that stack's own published conformance test suite, reporting **interop** and **conformance** as two distinct, separately-labeled results. It calls existing, already-graded tooling; it introduces no new protocol code. |
| [`IMPLEMENTATION-STATUS-TEMPLATE.md`](IMPLEMENTATION-STATUS-TEMPLATE.md) | An RFC 7942 (BCP 205) "Implementation Status" template plus an interop-results matrix, ready to fill in live at a hackathon or interim interop session. |
| [`HACKATHON-CHECKLIST.md`](HACKATHON-CHECKLIST.md) | What to do before, during, and after an IETF hackathon session: registration (primary-sourced against the current IETF hackathon pages), what to bring, how to run the harness against a genuinely independent peer, and how to publish results. |

## Why this is separate from `impl/go/cmd/npamp-interop`

`impl/go/cmd/npamp-interop` (already built and CI-graded — see
`.github/workflows/interop.yml`) is an **internal** interop matrix: it drives our
own Go, Rust, and Python reference stacks against *each other*, in-repo, on every
push. It is not packaged for a stranger to point at their own code, and its README
is written for a reader who already has this whole repository checked out.

This kit reuses that exact tooling — the same binaries, the same wire behavior,
the same handshake code paths — but frames it for the actual hackathon use case:
"I am not a maintainer of this repo; I have my own N-PAMP implementation; how do I
test it against yours, over a real address, and write down what happened." Nothing
here modifies the frozen wire format, the conformance corpus, `MANIFEST.sha256`/
`PIN.json`, or the behavior of any existing implementation.

## Honest status (read before citing this kit as "interop complete")

**Claude-buildable and graded, as of this session:**
- The reference Go and Rust stacks build and interoperate live, over real TCP
  sockets, both directions (Go server ↔ Rust client, Rust server ↔ Go client),
  through this kit's `run-against-peer.sh` wrapper — see the graded run captured
  in this session's commit message and `HACKATHON-CHECKLIST.md`'s "grading
  provenance" note.
- The wrapper's Stage 3 (independent conformance check) runs the exact CI-graded
  commands from `.github/workflows/conformance.yml` (`go test -C impl/go ./...
  -count=1`) and `.github/workflows/interop.yml`'s Rust leg
  (`cargo test --manifest-path impl/rust/Cargo.toml`).
- The status template and checklist are primary-sourced against the live IETF
  hackathon pages (retrieved 2026-09-06; see citations in
  `HACKATHON-CHECKLIST.md`).

**Event-gated (requires the maintainer; not Claude-buildable):**
- Actually registering for and attending an IETF hackathon.
- Running this kit against a **genuinely independent third-party
  implementation** — one this project did not author. Every interop run
  performed while building this kit was between this project's own Go and Rust
  reference stacks (the same two reference stacks the interop harness already exercises), which is
  necessary-but-not-sufficient for the third-party-interop goal; it is not third-party interop.
- Publishing real event results into `IMPLEMENTATION-STATUS-TEMPLATE.md` and
  submitting/announcing them (e.g. to the relevant IETF list or datatracker).

The interop milestone is recorded in the project's internal task tracker on the
basis of the built-and-graded kit above, with the event-gated residual stated
in the same note — not on a claim that a hackathon happened or that third-party
interop was demonstrated.
