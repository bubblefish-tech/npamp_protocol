# N-PAMP draft-01 — TypeScript quickstart

`impl/typescript` is the TypeScript port of the **OPEN-protocol reference library** for N-PAMP
`draft-bubblefish-npamp-01`: the wire-format and cryptographic *primitives*. Standard profile only
(SHA-256, X25519MLKEM768, Ed25519, AES-256-GCM). Zero runtime dependencies — everything is built on
`node:crypto`.

## What this port provides

The single module `src/npamp.ts` exports:

- **Frame codec** — the 36-octet header (magic `NPAM`, version, flags, type, channel, seq, CRC32C) +
  payload: `Frame.marshal` / `Frame.unmarshal` / `Frame.headerPrefix`, plus `crc32c`.
- **AES-256-GCM record layer** — `sealAes256Gcm` / `openAes256Gcm` / `deriveNonce`, using the
  21-octet header prefix as AEAD associated data.
- **HKDF key schedule** — `hkdfExtract`, `hkdfExpand`, `hkdfExpandLabel` (RFC 8446 §7.1 with the
  `"n-pamp "` label prefix), `deriveTrafficSecret`, `deriveKeyIv`.
- **Handshake-binding primitives** (binding `spec/10`) — `Transcript` (§3), the key-schedule trunk
  `deriveHandshakeSecret` / `deriveClientHandshakeSecret` / `deriveServerHandshakeSecret` /
  `deriveMasterSecret` / `deriveFinishedKey` (§5), `computeFinished` / `verifyFinished` (§6.2), and
  `signCertVerify` / `verifyCertVerify` (§6.1, Ed25519 via `node:crypto`).
- **Registry code points** — channel / frame-type / TLV / KEM / AEAD / signature constants.

(High / Sovereign profiles, ML-KEM-1024, and ML-DSA-87 are out of scope for this open module.)

## What this port does NOT provide

- **KEM operations** — no X25519MLKEM768 encapsulation/decapsulation; the key-schedule trunk takes
  the two KEM shared secrets as inputs.
- A **TCP/TLS transport** (ALPN `n-pamp/2`), connection management, or an RPC/MCP client. Those live
  in a consuming product, which composes primitives like these with its own
  handshake + transport.

## Install

A Node.js with built-in TypeScript type-stripping (the sources are run directly, uncompiled;
verified with Node v24.13.1). There is nothing to `npm install` — the port has zero runtime
dependencies.

## Run the tests

From `impl/typescript`:

```
npm test          # = node --test "test/**/*.test.ts"
```

This runs the conformance suite (4 golden vectors + 5 property tests, `test/conformance.test.ts`)
plus the four handshake KATs (`transcript` / `key-schedule` / `finished` / `certverify`, binding
`spec/10` §3, §5, §6.2, §6.1) — three-leg ANCHOR/ORACLE/IMPL tests against the pinned vectors in
`../../test-vectors/v1/`, SHA-256-checked inside each test (fail-loud on a swapped vector).

Two further checks need corpora that are **not included in this open reference repository** and are
runnable only where those corpora are provided:

- `node bin/npamp-kat.ts <aesgcm_kat.tsv>` — Project Wycheproof AES-256-GCM verdicts.
- `npm run vectors` (= `node bin/npamp-vectors.ts`) — emits the cross-language conformance vectors
  as JSON for the byte-compare drift gate (`_conformance-harness/run-all-langs.sh`). The generator
  itself runs anywhere; only the byte-compare needs the externally-provided `vectors.json`.

## Run the example

`examples/secure-record-layer.ts` composes the key schedule + record layer + frame codec into one
send → receive round-trip (a TypeScript mirror of the Go `Example_secureRecordLayer`):

```
node examples/secure-record-layer.ts
```

Expected output:

```
channel=1 seq=0 encrypted=true
recovered: hello over n-pamp
```

## Conformance

The language-agnostic conformance corpus + KAT vectors live in `test-vectors/v1/` (frozen in
`MANIFEST.sha256`). This port is one of the handshake-bearing implementations graded by
`impl/_conformance-harness/kat-handshake-all-langs.sh`; the handshake KATs grade it against NIST/RFC
anchors, non-circularly.

## License

Apache-2.0 — see `LICENSE` / `NOTICE` at the repository root.
