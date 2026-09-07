# npamp-interop — Go ↔ Rust N-PAMP handshake interop

A two-implementation interop harness for the N-PAMP 1.5-RTT mutually-authenticated
handshake (`spec/10`). It proves the Go reference (`impl/go`) and the Rust
reference (`impl/rust`) speak the **same wire bytes**: a live X25519MLKEM768 hybrid
handshake, the HKDF key schedule, transcript hashing, Ed25519 CertVerify +
Finished, and the AES-256-GCM record layer — completed cross-process over a TCP
socket, in **both directions**, followed by one application data frame.

## What it exercises

| Direction | Server | Client | Result |
|-----------|--------|--------|--------|
| A | Go (`-role server`) | Rust (`interop_client`) | handshake + echo |
| B | Rust (`interop_server`) | Go (`-role client`) | handshake + echo |

Each side authenticates the other's Ed25519 identity (mutual auth) and the client
verifies the server's echo of its Memory-channel frame byte-for-byte.

## Run it

```sh
# From this directory (impl/go/cmd/npamp-interop):
./run-interop.sh              # both directions, port 47700
./run-interop.sh 8443         # both directions, custom port
```

The script builds the Go harness (`go build ./cmd/npamp-interop`) and the Rust
examples (`cargo build --example interop_client --example interop_server`), then
runs each direction serially. All paths are repo-relative.

Manual, one direction at a time:

```sh
# Terminal 1 — Go server, Rust client:
go run ./cmd/npamp-interop -role server -addr 127.0.0.1:47700
cargo run --manifest-path ../../impl/rust/Cargo.toml --example interop_client -- 127.0.0.1:47700

# Terminal 1 — Rust server, Go client:
cargo run --manifest-path ../../impl/rust/Cargo.toml --example interop_server -- 127.0.0.1:47700
go run ./cmd/npamp-interop -role client -addr 127.0.0.1:47700
```

## Transport note (honest scope)

The N-PAMP handshake defined in `spec/10` is **transport-agnostic** — four frames
over the Control channel — so this harness runs it directly over a raw TCP stream.
The reference SDK (`impl/go/sdk`) additionally wraps these frames in **TLS 1.3
(ALPN `n-pamp/3`)** as its `npamp://` fallback transport binding; that outer TLS
layer is **not** exercised here. What this harness proves is the interoperability
of the N-PAMP protocol core (handshake + record layer) across the two language
implementations. The Go harness reproduces the exact four-frame flow of the
unexported `sdk` driver using the **exported** `impl/go` primitives
(`GenerateKEMClient`, `Encapsulate`, `HandshakeSecret`,
`DeriveHandshakeTrafficSecrets`, `SignCertVerify`/`VerifyCertVerify`,
`ComputeFinished`/`VerifyFinished`, `DeriveMasterSecret`, `SealAES256GCM`, …) —
the same core the `sdk` package calls.

## Grading provenance

This is a live behavioural check, complementary to the byte-pinned KATs:

- **`impl/rust/tests/handshake_flow_kat.rs`** grades every Rust handshake frame
  byte-for-byte against the Go reference's pinned vectors — so a Rust-produced
  frame is already known to equal a Go-produced one for identical inputs.
- **`impl/rust/tests/kem_wire_kat.rs`** grades the X25519MLKEM768 wire against
  independent NIST ACVP (ML-KEM-768 keygen) and RFC 7748 §6.1 (X25519) anchors.
- **This harness** closes the loop with fresh random keys over a real socket,
  cross-language, both directions.

## Interop matrix & the conformance-vs-interop gap

This harness is the project's **interop matrix**: the N-PAMP protocol core exercised
across two *independent, non-shared-codebase* implementations — the Go reference
(`impl/go`, using the Go standard library's `crypto/mlkem`, `crypto/ecdh` and
`crypto/ed25519`) and the Rust reference (`impl/rust`, built on RustCrypto) — in both
the client and server roles.

An interop pass is **necessary but not sufficient** for conformance. Two
implementations can interoperate while both diverge from the specification in the same
way; ETSI has reported that roughly a third of the implementation pairs that
interoperated at an interoperability event were nonetheless non-conformant at their
reference points. This harness therefore does **not** stand alone as evidence of
conformance. Conformance is established separately and non-circularly by the
byte-pinned known-answer tests, whose expected values come from an authority
independent of the code under test:

- `impl/rust/tests/handshake_flow_kat.rs` — every Rust handshake frame graded
  byte-for-byte against the Go reference's pinned vectors.
- `impl/rust/tests/kem_wire_kat.rs` — the X25519MLKEM768 wire graded against NIST ACVP
  (ML-KEM-768 keygen) and RFC 7748 §6.1 (X25519).

The two claims are kept distinct: the KATs establish that each frame equals an
independently-derived expected value (conformance), and this harness establishes that
the two stacks complete a fresh, mutually-authenticated session end-to-end over a real
socket (interop). Reproduce both:

```sh
# interop, both directions (from impl/go/cmd/npamp-interop):
./run-interop.sh

# non-circular conformance KATs (from impl/rust):
cargo test --test handshake_flow_kat --test kem_wire_kat
```

A third independent stack (the Python core in `impl/python`) is an available future
leg of the matrix; two independent stacks satisfy the interop-matrix requirement
today.
