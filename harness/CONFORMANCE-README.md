# npamp_00 Conformance Tool (`npamp-conform`)

A single-binary, language-agnostic conformance tester for **N-PAMP**
(`draft-bubblefish-npamp-00`). Point it at your implementation and get a graded,
spec-cited PASS/FAIL report.

It checks an implementation against a versioned **vector corpus** covering the wire
format (frame header, CRC32C, TLV rules), the cryptographic suites (AES-256-GCM, HKDF),
and the profile invariants — including the negative cases an implementation MUST reject.

## Quick start

```sh
# Build the runner (Go 1.26+); produces a single static binary.
cd runner && go build -o npamp-conform .

# Option A — test your implementation directly (any language) via a thin adapter:
./npamp-conform run --testee "./my-adapter" --junit report.xml

# Option B — just get the vectors and run them through your own test harness:
./npamp-conform vectors > corpus.json
```

A run prints a per-operation summary, a spec-clause citation for every failure, a
`Pass / Fail / Unimplemented / Non-Strict` tally, and exits non-zero if any MUST fails.

## What's here

| Path | Contents |
|---|---|
| `corpus/conformance-corpus.json` | The conformance vector corpus (the answer key). |
| `corpus/conformance-corpus.schema.json` | JSON Schema the corpus validates against. |
| `runner/` | `npamp-conform`, the Go runner (owns grading; embeds the corpus). |
| `adapters/go/` | Reference adapter — copy it and re-point it at your implementation. |
| `INSTRUCTIONS.md` | Full usage: the adapter contract, the operations, CI integration. |

## How it works

The runner owns all vectors and all grading logic. Your only integration is a small
**adapter** (a "testee") that reads length-prefixed JSON requests on stdin and writes
length-prefixed JSON responses on stdout, performing the npamp_00 primitive for each
request. The reference adapter in `adapters/go/` is ~250 lines and doubles as the
template. Because the contract is a byte pipe, an adapter can be written in any language.

See **[INSTRUCTIONS.md](INSTRUCTIONS.md)** for the operation list and the adapter contract.
