# LearnLib learned-model diff

An active-automata-learning (LearnLib 0.18.0, TTT algorithm + Wp-method equivalence oracle)
conformance check: it **learns** the N-PAMP Go SDK's actual Mealy state machine from its real
behavior — driving the real `sdk.DialRaw` / `sdk.AcceptRaw` / `Conn.Recv` /
`Conn.CloseGraceful` over an in-process `net.Pipe`, never a reimplementation —
and diffs the learned machine against `harness/statemodel/npamp-state-table.json`, the
draft-derived reference model the by-hand deviant-trace suite also uses. Any learned state or
transition the table does not predict is a conformance defect: a spec gap or an implementation bug.

## Why this is F3-independent (and why that is the whole point)

The reference side of the diff (`harness/statemodel/npamp-state-table.json`) is derived from
the **draft text** (`ietf/draft-bubblefish-npamp-latest.md`, §State Machine), never from the
Go implementation — see that file's own `provenance` field. `diff_model.py` reads *only* that
table plus the LearnLib-produced `learned-<role>.json`; it never reads Go source. So a
state-machine bug shared between the table's author and the implementation cannot hide: the
two sides are built from independent authorities, and a real disagreement between them is a
genuine finding, not a tautology.

The by-hand deviant-trace suite (`impl/go/sdk/statetrace_test.go`) checks the SAME table by
hand-driving a short list of specific deviant traces. This learner is the complementary,
EXHAUSTIVE check: LearnLib's active learner does not know in advance which input sequences
matter — it discovers the machine's actual behavior over the full alphabet from scratch, so it
can surface a divergence the by-hand suite never thought to probe.

## Architecture

```
                    stdio line protocol (RESET / <input> -> <output>)
NpampStateLearner.java  <──────────────────────────────────────────>  sul/*.go (package main)
  (LearnLib TTT + Wp)                                                   │
        │                                                               │  drives, over an
        │ writes                                                       │  in-process net.Pipe
        ▼                                                               ▼
  learned-<role>.{dot,json}                                    sdk.DialRaw / sdk.AcceptRaw
        │                                                       Conn.Recv / Conn.CloseGraceful
        │ compared against                                     (the UNMODIFIED, real Go SDK)
        ▼
  harness/statemodel/npamp-state-table.json  ──►  diff_model.py  ──►  PASS/FAIL + diff-report.json
  (draft-derived, NEVER from Go — see its own provenance field)
```

### The Go SUL (`sul/`) — how it drives the REAL SDK without modifying `impl/go/sdk`

`harness/statelearn` may not modify any file outside itself, so the SUL cannot import
`impl/go/sdk`'s unexported test-only helpers the way `impl/go/sdk/statetrace_test.go` (the
deviant-trace suite) does — those live in a different package and Go's package boundary blocks a
direct import regardless of directory layout. Instead:

- The **SUT is always the real, unmodified, exported entry point**: `sdk.DialRaw` (testing the
  initiator/client role) or `sdk.AcceptRaw` (testing the responder/server role), over an
  in-process `net.Pipe` — the TLS-free handshake-over-`net.Conn` seam the SDK exports for
  exactly this in-process/harness use (`impl/go/sdk/dialraw.go`). Authentication is the SDK's
  actual production path (the 1.5-RTT Ed25519 + hybrid-KEM handshake); only the transport-layer
  TLS wrap of `Dial`/`Listen` is dropped, which is sound because both peers are in one process.
- The **driver** (the scripted "deviant peer" on the other end of that same `net.Pipe`, which
  `statetrace_test.go` implements in-package against its own `net.Pipe`) is reimplemented here at the
  wire level using ONLY **exported** building blocks from the root `npamp` package
  (`Frame`, `SealAES256GCM`/`OpenAES256GCM`, `DeriveTrafficSecret`/`DeriveKeyIV`,
  `HandshakeSecret`/`DeriveHandshakeTrafficSecrets`/`DeriveMasterSecret`,
  `SignCertVerify`/`VerifyCertVerify`, `ComputeFinished`/`VerifyFinished`, `NewTranscript`,
  ...). `sul/wire.go`'s `sealFrameWire`/`openFrameWire`/`deriveKeyIV` are the exact same
  three-to-eight-line calls `sdk/conn.go`'s unexported `sealFrame`/`openFrame`/`deriveKeyIV`
  make — reproduced here because Go's package system blocks the import, not because the logic
  differs. This is *not* a parallel state-machine reimplementation: the driver only ever
  builds and sends bytes; every accept/reject DECISION is made by the real, unmodified SDK
  code on the other end of the wire.
- Because `Conn.Recv` only ever reacts when its CALLER invokes it (there is no background
  dispatch loop inside `*sdk.Conn`), the established-phase driver spawns exactly one bounded
  `sutConn.Recv(ctx)` call per injected symbol — the same one-call-per-injection pattern
  `impl/go/sdk/statetrace_test.go`'s `injectAndReadReaction` uses.

### Learnable alphabet

`input_alphabet` from the table (`CLIENT_HELLO`, `SERVER_HELLO`, `SERVER_HELLO_BADSEL`,
`SERVER_AUTH`, `SERVER_AUTH_BADAUTH`, `CLIENT_AUTH`, `CLIENT_AUTH_BADAUTH`, `KEY_UPDATE`,
`KEY_UPDATE_ACK`, `CLOSE`, `CLOSE_ACK`, `APP`, `UNKNOWN`), plus one ACTION symbol
`INIT_CLOSE` this harness adds so CLOSING is learnable at all — see "The `INIT_CLOSE`
extension" below. `UNKNOWN` concretizes to an unassigned reserved Control type (`0x00FE`),
never a ratchet type (`0x0104`-`0x0107`, excluded per the table's `modeled_exclusions`).

Output alphabet: exactly the table's `output_alphabet` (`SILENT`, `SILENT_ABORT`, `SH_SA`,
`CLIENT_AUTH`, `KEY_UPDATE_ACK`, `CLOSE_ACK`, `ACCEPT`, `ERROR:unexpected_message`,
`ERROR:decrypt_failed`).

### The `INIT_CLOSE` extension

The table only models RECEIVE reactions — `(role, state, received-frame) -> (output,
next_state)`. CLOSING is entered by the endpoint itself **sending** a CLOSE
(`Conn.CloseGraceful`), which is an action, not a received frame, so no table row can ever
put a learner in the CLOSING state. `INIT_CLOSE` triggers `CloseGraceful` on the SUT (once a
real `*Conn` exists) so the learner can reach and probe CLOSING at all.
`diff_model.py`'s `EXPAND_INIT_CLOSE_NOTE` documents the ONE rule this harness adds on top of
the table (from any post-handshake state, `INIT_CLOSE` → `(CLOSING, SILENT)`; a repeat while
already CLOSING or before a `*Conn` exists is a no-op self-loop) — clearly separated from,
and never presented as, the table's own draft-derived authority.

A second `INIT_CLOSE` in the same episode is deliberately made a no-op rather than exercised:
`sdk/close.go`'s `sendClose` does not itself guard against a second concurrent
`CloseGraceful` call (it would seal and send a SECOND CLOSE frame, racing the first
`CloseGraceful` goroutine's own lock-held send/ack-wait) — a real, separate concurrency
question this harness does not attempt to answer, and guards against so it cannot become a
SUL-determinism hazard (LearnLib's TTT algorithm assumes `SUL.step` is a pure function of the
reset-to-here input prefix; see "Known non-determinism hazards found and fixed" below).

## Build / run

### Linux / macOS / CI

```bash
./run.sh
```

### Windows (PowerShell)

```powershell
cd sul; $env:GOWORK="off"; go build -o statelearn-sul.exe .; cd ..
mkdir -Force classes | Out-Null
javac -cp lib\learnlib-distribution-0.18.0-dependencies-bundle.jar -d classes `
    GoProcessSUL.java LearnedModel.java NpampStateLearner.java
java -cp "lib\learnlib-distribution-0.18.0-dependencies-bundle.jar;classes" `
    NpampStateLearner sul\statelearn-sul.exe .
python diff_model.py --dir .
```

No Maven build anywhere: the ONE dependency is a single verified uber-jar,
`lib/learnlib-distribution-0.18.0-dependencies-bundle.jar` (LearnLib 0.18.0 + AutomataLib
0.12.0 + Guava + SLF4J-NOP). The jar (7.87 MB) is NOT committed — run `./fetch-jar.sh` once
to download it from Maven Central and SHA-verify it (fail-closed on mismatch). Pinned digests:
SHA-256 `bcee286332a5bb331fe60123fe93158caa1768263c13a9bb21a197833b65e31a`, SHA-1
`9955436f4531f7861c21f16a977d952b6b6c5617` (verify with `sha256sum lib/*.jar`).

## Determinism

Both endpoints' long-term Ed25519 identities are fixed seeds (`sul/identity.go`) purely for
reproducible logs. ML-KEM-768 / X25519 ephemeral key material is real `crypto/mlkem` /
`crypto/ecdh` randomness — **never overridden** — which is safe because every SUL output is
abstracted to a frame-type/error-code symbol (`sul/wire.go` / `common.go`), so nondeterministic
ciphertext bytes never reach the learned model. What DOES have to be deterministic, and is,
is the *reaction* to a given input sequence — see the next section.

## Known non-determinism hazards found and fixed

Building this harness surfaced two real concurrency bugs during development (not merely
harness bugs to note in passing — LearnLib's TTT algorithm crashed with an internal
`NullPointerException` the first time it was run, which is the classic symptom of a SUL that
is not actually a pure function of its input prefix):

1. **Cross-episode channel contamination.** `reset()` originally wrote the background
   `sdk.DialRaw()` / `sdk.AcceptRaw()` goroutine's result via `s.dialCh <- ...` /
   `s.acceptCh <- ...` — a STRUCT FIELD read at send time, not at spawn time. A straggler
   goroutine from a PRIOR episode (still unwinding when RESET was called again) could
   therefore write its stale result into the NEW episode's channel after `reset()`
   reassigned the field, silently corrupting state. Fixed by having the goroutine capture a
   LOCAL channel variable at spawn time and assigning it to the struct field only afterward
   — a straggler can then never see the new channel object.
2. **Un-guarded double `CloseGraceful`.** See "The `INIT_CLOSE` extension" above.

## Files

- `sul/` — the Go stdio SUL driver (its own Go module; `go.mod` replace-points at
  `../../../impl/go`, following the same pattern as `harness/adapters/go`).
- `GoProcessSUL.java` / `LearnedModel.java` / `NpampStateLearner.java` — the Java LearnLib
  harness.
- `diff_model.py` — the F3-independent diff (Deliverable 3); also directly runnable/testable
  standalone (`python diff_model.py --dir <dir-with-learned-*.json>`).
- `learned-initiator.{dot,json}`, `learned-responder.{dot,json}` — the learned models
  (committed as evidence of a real run; regenerate with `run.sh`).
- `learn-config.json` — tool/algorithm/alphabet/statistics record for the run that produced
  the committed learned models.
- `diff-report.json` — the diff's structured output for the run that produced it.

## Durable gate (model-based-testing): two tiers

The learn above is EXPENSIVE (~14 min wallclock; needs Java + the LearnLib jar) and its SUL
reads a timing window over `net.Pipe`, so it is NOT a per-commit gate -- a required gate that
flakes on a loaded shared runner trains alarm-ignoring. The durable conformance gate is
therefore two tiers.

### Fast per-commit tier (deterministic, stdlib-Python, no Java)

The `state-machine` job in `.github/workflows/conformance.yml` and the
`state-machine-conformance` gate run in CI, on every push / PR:

1. `diff_model.py --dir .` -- the committed learned models are equivalent to the CURRENT
   draft-derived `npamp-state-table.json` (model <-> table consistency; F3-independent).
2. `statelearn_freshness.py` -- the committed learned models were learned from the CURRENT
   `impl/go` + SUL + Java harness + `learn-config.json` (INPUT hashes) and were not
   hand-edited (OUTPUT hashes), per `statelearn-provenance.json`. An input change => the
   models are STALE (relearn required); an output change with no relearn => fabricated.

Both are stdlib-only and run in milliseconds. `statelearn-provenance.json` pins the SHA-256 of
LF-normalized content of 72 inputs (the whole `impl/go` module's non-test sources + module
files + the SUL + the Java harness + `learn-config.json`) + the 2 learned models; the models
and the table are ALSO pinned in `MANIFEST.sha256` (the `verify-pins` gate).

### On-demand full-learn tier (the actual model-based test)

Run `./run.sh` locally (or from a manually-triggered CI job) to perform the full
LearnLib re-learn; it produces the refreshed models + provenance + diff for a maintainer to
review and commit (no CI auto-commit). Run it whenever the freshness gate reports
an input change, or on a periodic cadence.

### What "m-complete" does and does NOT mean here

The equivalence oracle is `MealyRandomWpMethodEQOracle` -- a RANDOMIZED Wp-method sample,
probabilistic up to `learn-config.json`'s bound (`eq_rnd_length=4`, `eq_bound_tests_per_query
= 2000`). It is NOT the exhaustive, absolutely m-complete Wp of Chow (1978) / Fujiwara et al.
(1991), which is exponential in the extra-state bound and infeasible here (~145k episodes at
depth 2 over the timeout-probed `net.Pipe`). The gates are named `state-machine` /
`statelearn`, NOT "m-complete", by design: the fast tier proves freshness +
model<->table consistency; the full tier proves randomized-Wp equivalence to the configured
bound. Neither claims absolute completeness.

### Red-evidence (recorded mutations, both on the deterministic Python tier)

* **M1** -- perturb one transition's `output` in `learned-initiator.json` => `diff_model.py`
  reports `output_mismatch` and exits 1 (reverted via `.bak`; re-run exits 0).
* **M2** -- touch a pinned input (`learn-config.json`) => `statelearn_freshness.py` reports
  `[inputs] CHANGED` and exits 1 (reverted via `.bak`; re-run exits 0).
* `statelearn_freshness.py --selftest-only` -- a synthetic failing fixture (inject one hash
  mismatch into a temp-dir baseline) that the gate MUST flag, or it refuses to run (exit 2):
  the gate proves it can fail before it is trusted to pass (inert-check discipline).

## Honest status

The committed `learned-{initiator,responder}.json` were learned in commit `0b362959` (the #97
`net.Pipe` learn) and are provably fresh: `impl/go` + `harness/statelearn` have 0 changes
since, and the fast tier is green. Learn statistics per role are recorded in `learn-config.json`
(5 states / 70 transitions each; ~2554 resets; ~17945 membership queries; ~500 s / ~360 s
wallclock). This section documents the model-based-testing durable-gate wiring that the
initial build of this learner left as follow-up work.
