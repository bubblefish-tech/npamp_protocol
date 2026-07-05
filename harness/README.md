# harness/ — cross-implementation conformance runner

Drives every reference implementation in `impl/` against the corpus
(`test-vectors/v1/conformance-corpus.json`) via the subprocess contract: a length-prefixed
JSON request `{op, in}` on stdin → `{out | error | skipped}` on stdout.

- `adapters/<lang>/` — per-language conformance adapters (10 languages).
- `runner/` — the Go runner that spawns an adapter, feeds it the corpus, and grades the
  responses (golden-match / MUST-reject / case-insensitive comparison).
- `INSTRUCTIONS.md`, `CONFORMANCE-README.md` — the harness contract and how to run it.

A consuming product's **own** conformance gate (an in-process conformance test
driving its vendored impl against a pinned corpus copy) lives in that product; this
directory is the cross-implementation runner for the reference impls themselves.
