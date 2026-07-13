# N-PAMP draft-01 — Rust quickstart

`impl/rust` is the Rust port of the **OPEN-protocol reference library** for N-PAMP
`draft-bubblefish-npamp-01`: the wire-format and cryptographic *primitives*. Standard profile only
(SHA-256, X25519MLKEM768, Ed25519, AES-256-GCM).

## What this port provides

The `npamp` crate (`src/lib.rs`) exports:

- **Frame codec** — the 36-octet header (magic `NPAM`, version, flags, type, channel, seq, CRC32C) +
  payload: `Frame::marshal` / `Frame::unmarshal` / `Frame::header_prefix`, plus `crc32c`.
- **AES-256-GCM record layer** — `seal_aes256gcm` / `open_aes256gcm` / `derive_nonce`, using the
  21-octet header prefix as AEAD associated data.
- **HKDF key schedule** — `hkdf_extract`, `hkdf_expand`, `hkdf_expand_label` (RFC 8446 §7.1 with the
  `"n-pamp "` label prefix), `derive_traffic_secret`, `derive_key_iv`, and the handshake-secret
  trunk `derive_handshake_secret` / `derive_client_handshake_secret` /
  `derive_server_handshake_secret` / `derive_master_secret` / `finished_key` (binding `spec/10` §5).
- **Handshake-binding layer** (`npamp::handshake` module, binding `spec/10`) — `Transcript` (§3),
  `compute_finished` / `verify_finished` (§6.2), and `sign_cert_verify` / `verify_cert_verify`
  (§6.1, Ed25519 via `ed25519-dalek`, strict RFC 8032 verification).
- **Registry code points** — channel / frame-type / TLV / KEM / AEAD / signature constants.

(High / Sovereign profiles, ML-KEM-1024, and ML-DSA-87 are out of scope for this open module.)

## What this port does NOT provide

- **KEM operations** — no X25519MLKEM768 encapsulation/decapsulation; the key-schedule trunk takes
  the two KEM shared secrets as inputs.
- A **TCP/TLS transport** (ALPN `n-pamp/2`), connection management, or an RPC/MCP client. Those live
  in a consuming product, which composes primitives like these with its own
  handshake + transport.

## Install

A stable Rust toolchain (verified with cargo 1.95.0). Dependencies (`sha2`, `hkdf`, `aes-gcm`,
`hmac`, `ed25519-dalek`) are pinned in `Cargo.lock` and fetched by cargo on first build.

## Run the tests

From `impl/rust`:

```
cargo test
```

This runs the conformance suite (`tests/conformance.rs`: 4 golden vectors + 5 property tests) plus
the handshake KATs (`tests/handshake_kat.rs`: transcript / key-schedule / finished / certverify,
binding `spec/10` §3, §5, §6.2, §6.1) — three-leg ANCHOR/ORACLE/IMPL tests against the pinned
vectors in `../../test-vectors/v1/`, SHA-256-checked inside each test (fail-loud on a swapped
vector). The vector directory is located by walking up from `CARGO_MANIFEST_DIR`, so the run
directory does not matter.

Two further checks need corpora that are **not included in this open reference repository** and are
runnable only where those corpora are provided:

- `cargo run --bin npamp-kat -- <aesgcm_kat.tsv>` — Project Wycheproof AES-256-GCM verdicts
  (`cargo run --bin npamp-hkdf-kat` is the HKDF companion).
- `cargo run --bin npamp-vectors` — emits the cross-language conformance vectors as JSON for the
  byte-compare drift gate (`_conformance-harness/run-all-langs.sh`). The generator itself runs
  anywhere; only the byte-compare needs the externally-provided `vectors.json`.

## Run the example

`examples/secure_record_layer.rs` composes the key schedule + record layer + frame codec into one
send → receive round-trip (a Rust mirror of the Go `Example_secureRecordLayer`):

```
cargo run --example secure_record_layer
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
