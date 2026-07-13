# npamp-conform — Instructions

This document explains how to test an N-PAMP (`draft-bubblefish-npamp-01`) implementation
for conformance. There are two ways to use the tool; pick whichever fits your project.

## Tier A — vectors only (no adapter code)

If you already have a test harness, just consume the corpus:

```sh
npamp-conform vectors > conformance-corpus.json
```

Each test case carries a `requirement` (the spec clause it checks), an `in` object, a
`result` of `valid` / `invalid` / `acceptable`, and (for `valid`) an `expected` object.
Loop the cases through your implementation: for `valid`, your output must equal `expected`;
for `invalid`, your implementation MUST reject the input. The corpus format is defined by
`corpus/conformance-corpus.schema.json`.

## Tier B — black-box adapter (language-agnostic certification)

Write a small **adapter** (a "testee") that wraps your implementation, then run:

```sh
npamp-conform run --testee "./my-adapter" --junit report.xml
```

The runner spawns your adapter as a subprocess and drives it. The adapter owns no test
logic — it only translates each request into a call on your implementation.

### The adapter contract

The runner and the adapter speak a length-prefixed framing on stdin/stdout:

```
  4-byte little-endian length N   ->   N bytes of JSON   (repeat until stdin closes)
```

- **Request** (runner → adapter): `{"op": "<operation>", "in": { ... }}`
- **Response** (adapter → runner), exactly one of:
  - `{"out": { ... }}`     — success, with the operation's output fields
  - `{"error": "<reason>"}` — the input was rejected / could not be processed
  - `{"skipped": "<why>"}`  — this operation/feature is not implemented (reported `Unimplemented`, not `Fail`)

All byte-valued fields are lowercase hex strings.

### Operations

| `op` | `in` fields | `out` fields | Checks |
|---|---|---|---|
| `header.encode` | `ver, flags, frameType, channel, seq, payloadLength` | `frame` | Frame header layout |
| `header.decode` | `frame` | `magic, ver, flags, frameType, channel, seq, payloadLength, crc32c, reservedZero` | Header parse + MUST-reject rules |
| `crc32c` | `octets` | `crc32c` | CRC32C (Castagnoli) over header octets 0–20 |
| `tlv.decode` | `tlv` | `type, length, value` | TLV parse; unknown high-bit (0x8000) type MUST be rejected |
| `aead.seal` | `suite, key, nonce, aad, pt` | `sealed` (ciphertext‖tag) | AEAD seal |
| `aead.open` | `suite, key, nonce, aad, sealed` | `pt` | AEAD open; tag mismatch MUST be rejected |
| `hkdf.expand` | `hash, prk, info, length` | `okm` | HKDF-Expand (RFC 5869) |
| `profile.check` | `profile, kem` | (accept) or `error`/`skipped` | Profile KEM-acceptance invariants |

Any `op` your implementation does not cover should return `{"skipped": "..."}`; it is then
reported `Unimplemented` rather than failing the run.

### Writing your adapter

Copy a reference adapter as a template and re-point it at your implementation:

- `adapters/go/` — Go, zero dependencies (standard library only).
- `adapters/python/` — Python; requires `pip install cryptography` for AES-256-GCM.

Both implement every operation above and are run against this corpus, so they are known-good
references in two different languages. To adapt to another language, reproduce: (1) the
length-prefixed read/write loop, (2) a switch on `op`, (3) a call into your implementation
for each operation. An adapter is typically 50–250 lines. (On Windows, use your language's
**binary** stdio and **flush after each response**, or the byte framing will corrupt.)

## Result taxonomy

| Verdict | Meaning |
|---|---|
| **Pass** | Output matched `expected` (valid case) or input was correctly rejected (invalid case). |
| **Fail** | Wrong output, a missing rejection, or an adapter error/crash. Fails CI. |
| **Unimplemented** | The adapter returned `skipped` for an optional operation. Does not fail CI. |
| **Non-Strict** | A SHOULD-level deviation (only graded under a future `--strict` mode). |

The process exits non-zero if and only if there is at least one **Fail**.

## Continuous integration

`npamp-conform run --junit report.xml` writes a JUnit XML report and sets a non-zero exit
code on any MUST failure, so it drops into a CI step with no glue code. A non-responding or
crashing adapter is failed and the run aborted rather than left to hang; set the
per-operation budget with `--timeout <seconds>` (default 30).

## The corpus

The corpus is a single JSON file consumed by the runner (embedded) and available via
`npamp-conform vectors`. Its wire cases derive from the specification's golden vectors and
its cryptographic cases from the Project Wycheproof known-answer test corpora. Negative
(`invalid`) cases encode the specification's MUST-reject rules — they are where real
conformance bugs surface, so they are first-class, not an afterthought.
