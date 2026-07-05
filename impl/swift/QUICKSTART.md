# N-PAMP draft-00 — Swift quickstart

`impl/swift` is the Swift port of the **OPEN-protocol reference library** for N-PAMP
`draft-bubblefish-npamp-00`: the wire-format and cryptographic *primitives*. Standard profile only
(SHA-256, X25519MLKEM768, Ed25519, AES-256-GCM). Pure Swift on
[swift-crypto](https://github.com/apple/swift-crypto) (portable AES-256-GCM / HKDF / Ed25519 on
Linux and Apple platforms), managed by SwiftPM (`Package.swift`).

## What this port provides

The `Npamp` library target (`Sources/Npamp/`):

- **Frame codec** (`Npamp.swift`) — the 36-octet header (magic `NPAM`, version, flags, type,
  channel, seq, CRC32C) + payload: `Frame.marshal` / `Frame.unmarshal` / `Frame.headerPrefix`,
  plus `crc32c`.
- **AES-256-GCM record layer** — `sealAes256Gcm` / `openAes256Gcm` / `deriveNonce`, using the
  21-octet header prefix as AEAD associated data.
- **HKDF key schedule** — `hkdfExtract`, `hkdfExpand`, `hkdfExpandLabel` (RFC 8446 §7.1 with the
  `"n-pamp "` label prefix), `deriveTrafficSecret`, `deriveKeyIv`, and the key-schedule trunk
  `deriveHandshakeSecret` / `deriveClientHandshakeSecret` / `deriveServerHandshakeSecret` /
  `deriveMasterSecret` / `deriveFinishedKey` (binding `spec/10` §5).
- **Handshake-binding primitives** (`Handshake.swift`, binding `spec/10`) — `Transcript` (§3),
  `computeFinished` / `verifyFinished` (§6.2), `signCertVerify` / `verifyCertVerify` (§6.1,
  Ed25519 via swift-crypto), and the KEM-wire layout helpers `kemShareBytes` / `splitKemShare` /
  `kemCiphertextBytes` / `splitKemCiphertext` (§4, ML-KEM-first).
- **Registry code points** — channel / frame-type / AEAD constants.

(High / Sovereign profiles, ML-KEM-1024, and ML-DSA-87 are out of scope for this open module.)

## What this port does NOT provide

- **ML-KEM operations** — swift-crypto's `Crypto` product exposes no ML-KEM API, so there is no
  X25519MLKEM768 encapsulation/decapsulation; the KEM-wire helpers handle the byte layout only,
  and the key-schedule trunk takes the two KEM shared secrets as inputs.
- A **TCP/TLS transport** (ALPN `n-pamp/2`), connection management, or an RPC/MCP client. Those live
  in a consuming product, which composes primitives like these with its own
  handshake + transport.

## Install

A Swift toolchain (verified with Swift 6.2 on Ubuntu under WSL; `swift-tools-version:5.9`). SwiftPM
fetches swift-crypto (pinned in `Package.resolved`) on first build. On a Windows host the port runs
inside WSL Ubuntu — `run.sh` expects the toolchain at `~/swift-toolchain` (or on `PATH`) and keeps
the build scratch dir OUT of the package tree (`~/npamp-swift-build`, override with
`NPAMP_SWIFT_SCRATCH`).

## Run the tests

From `impl/swift` (each `run.sh <name>` builds the package once and runs the `npamp-<name>`
executable target, keeping the SwiftPM scratch dir out of the source tree):

```
bash run.sh conformance      # 4 golden vectors + 5 property tests — prints ok/FAIL per check,
                             # ends with "ALL PASS (9/9)", exits non-zero on any failure
bash run.sh handshake-kat    # handshake KATs (spec/10 §3, §4, §5, §6.2, §6.1) — three-leg
                             # ANCHOR/ORACLE/IMPL against the pinned ../../test-vectors/v1/
                             # (SHA-256-checked; the two ML-KEM ACVP anchor legs SKIP with reason,
                             # since swift-crypto exposes no ML-KEM API)
```

Two further checks need corpora that are **not included in this open reference repository** and are
runnable only where those corpora are provided:

- `bash run.sh kat <aesgcm_kat.tsv>` — Project Wycheproof AES-256-GCM verdicts.
- `bash run.sh vectors` — emits the cross-language conformance vectors as JSON for the byte-compare
  drift gate (`_conformance-harness/run-all-langs.sh`). The generator itself runs anywhere; only
  the byte-compare needs the externally-provided `vectors.json`.

## Run the example

`Sources/npamp-example/main.swift` composes the key schedule + record layer + frame codec into one
send → receive round-trip (a Swift mirror of the Go `Example_secureRecordLayer`):

```
bash run.sh example
```

Expected output:

```
channel=1 seq=0 encrypted=true
recovered: hello over n-pamp
```

## Conformance

The language-agnostic conformance corpus + KAT vectors live in `test-vectors/v1/` (frozen in
`MANIFEST.sha256`). The cross-language gates in `impl/_conformance-harness/` run this port natively
on Linux/macOS and via WSL Ubuntu on a Windows host.

## License

Apache-2.0 — see `LICENSE` / `NOTICE` at the repository root.
