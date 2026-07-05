# N-PAMP draft-00 — Go SDK quickstart

`github.com/bubblefish-tech/npamp_protocol/impl/go` is the **OPEN-protocol reference library** for N-PAMP
`draft-bubblefish-npamp-00`: the wire-format and cryptographic *primitives*. Standard profile only
(SHA-256, X25519MLKEM768, Ed25519, AES-256-GCM).

## What this module provides

- **Frame codec** — the 36-octet header (magic `NPAM`, version, flags, type, channel, seq, CRC32C) +
  payload: `Frame.MarshalBinary` / `Frame.UnmarshalBinary` / `Frame.HeaderPrefix`.
- **AES-256-GCM record layer** — `SealAES256GCM` / `OpenAES256GCM` / `DeriveNonce`, using the
  21-octet header prefix as AEAD associated data.
- **HKDF key schedule** — `HkdfExpandLabel` (RFC 8446 §7.1 with the `"n-pamp "` label prefix),
  `DeriveTrafficSecret`, `DeriveKeyIV`, and the handshake ladder (`HandshakeSecret`,
  `DeriveHandshakeTrafficSecrets`, `DeriveMasterSecret`, `DeriveFinishedKey`).
- **TLV codec + registries** — `TLV`, `DecodeTLVs`, and the channel / frame-type / TLV / profile /
  KEM / AEAD / signature code-point constants.
- **draft-00 1.5-RTT handshake binding** (`spec/10_handshake_binding.md`, Standard profile) —
  X25519MLKEM768 hybrid KEM (`KEMClient`, `Encapsulate`; `crypto/mlkem` + `crypto/ecdh`), the
  four handshake flights (`ClientHello`, `ServerHello`, `AuthMessage` encode/decode), the per-TLV
  `Transcript`, and Ed25519 `SignCertVerify`/`VerifyCertVerify` + `ComputeFinished`/`VerifyFinished`.
  Verified against the five standards-anchored handshake KATs in `test-vectors/v1/`.

(High / Sovereign profiles, ML-KEM-1024, and ML-DSA-87 are out of scope for this open module.)

## What this module does NOT provide

By design, the module is wire-format + crypto + handshake building blocks. It does **not** include:

- A **TCP/TLS transport** (ALPN `n-pamp/2`), connection management, handshake session state
  machines, or an RPC/MCP client.

Those live in a **consuming product**, which vendors this module and composes the
primitives here with its own transport.

## Run the example

The runnable `Example_secureRecordLayer` (in `example_test.go`) composes the key schedule + record
layer + frame codec into one send → receive round-trip:

```
git clone <this repo>
cd impl/go
go test -run Example -v
```

It derives a traffic key, seals an application payload into an AEAD-protected frame, marshals it to
the wire, then unmarshals + opens it — printing the recovered plaintext. The master secret is a fixed
demo value; in a live session it is the handshake output.

## Run a full draft-00 client against a live endpoint

For an end-to-end client — full handshake, TLS transport, a real memory write/search over `npamp://`
— use a consuming product's CLI against a running daemon's `npamp://` listener:

```
<consumer> npamp status --addr <host:port> --ca <daemon-cert.pem> --server-key <hex>
<consumer> npamp write  --addr <host:port> --ca <daemon-cert.pem> --server-key <hex> --content "hello"
<consumer> npamp search --addr <host:port> --ca <daemon-cert.pem> --server-key <hex> --q hello
```

`--ca` verifies the daemon's TLS certificate; `--server-key` pins its Ed25519 identity. (`--insecure`
exists for loopback development and warns loudly that certificate verification is disabled.)

## Conformance

The language-agnostic conformance corpus + KAT vectors live in `test-vectors/v1/` (frozen in
`MANIFEST.sha256`). `cmd/npamp-kat` runs the AES-256-GCM record layer against Project Wycheproof
vectors; the handshake-layer KATs (KEM-wire, key-schedule, transcript, Finished, CertVerify) grade an
implementation against NIST/RFC anchors, non-circularly. This module's `go test` runs all five
handshake KATs against its own handshake layer (`*_kat_test.go`).

## License

Apache-2.0 — see `LICENSE` / `NOTICE` at the repository root.
