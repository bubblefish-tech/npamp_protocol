# Third-party quickstart: test your N-PAMP implementation against ours

This is for **you**, if you are not a maintainer of this repository and you have
(or are building) your own implementation of the N-PAMP handshake and record
layer (`draft-bubblefish-npamp-01`, spec/10) and want to test it against a
reference stack over a real network.

You do **not** need to check out this whole repository. You need only:

1. A published reference module/crate (either works as your peer):
   - Go: `github.com/bubblefish-tech/npamp_protocol/impl/go`
   - Rust: the `npamp` crate from `impl/rust` in this repository (not yet
     published to crates.io as of this writing — build from source, see below)
2. Network reachability to whichever side you run (loopback for a local smoke
   test; a routable address for a real two-machine/two-network test, e.g. at a
   hackathon venue).

## What the test proves, and what it does not

The N-PAMP handshake (spec/10) is a four-frame, 1.5-RTT, mutually-authenticated
exchange carried directly over a byte stream — it does not depend on TLS, HTTP,
or any other transport framing. This quickstart runs it **directly over raw TCP**,
so the only thing under test is the protocol core: the hybrid KEM handshake, the
HKDF key schedule, transcript hashing, Ed25519/ML-DSA-87 CertVerify + Finished,
and the AES-256-GCM record layer.

It does **not** exercise the reference SDK's TLS 1.3 (ALPN `n-pamp/3`) transport
binding — that is a separate wrapping layer, not the object of this interop test.

A passing round trip means: your implementation and ours agree on the wire bytes
for a real, freshly-keyed handshake and at least one AEAD-protected data frame,
in the role you tested. It is **interop**, not **conformance** — two
implementations can agree with each other while both diverging from the
specification in the same way. This project's separate, non-circular conformance
KATs (anchored to NIST ACVP / FIPS 203-204 and the RFC series, never to the
implementation under test) are what establishes conformance; see the top-level
[`README.md`](../README.md) "Why you can trust this" section and
`impl/go/cmd/npamp-interop/README.md`'s "Interop matrix & the conformance-vs-interop
gap" section for that distinction spelled out in full, including the
ETSI-reported base rate of interoperable-but-non-conformant implementation pairs.

## Fastest path: run our side, point your implementation at it

Whichever language you are not implementing yet, run the corresponding reference
binary in whichever role your implementation is missing, from **this repository**:

```sh
# Go reference, listening as the SERVER — connect your CLIENT to it:
./run-against-peer.sh --stack go --role server --addr 0.0.0.0:47700

# Go reference, dialing as the CLIENT — point your SERVER's address at it:
./run-against-peer.sh --stack go --role client --addr <your-server-host>:47700

# Rust reference, either role, Standard profile (default):
./run-against-peer.sh --stack rust --role server --addr 0.0.0.0:47700
./run-against-peer.sh --stack rust --role client --addr <your-server-host>:47700

# Rust reference also speaks the High / Sovereign profiles (spec/05_profiles.md):
./run-against-peer.sh --stack rust --role server --addr 0.0.0.0:47700 --profile high
./run-against-peer.sh --stack rust --role client --addr <peer-host>:47700 --profile sovereign
```

`run-against-peer.sh` builds the requested stack, runs it, and prints a clearly
labeled PASS/FAIL for the live round trip. See [`run-against-peer.sh`](run-against-peer.sh)
`--help` for every flag.

### What your implementation must do, concretely

For the **client** role your implementation must, over the TCP connection it
opened:
1. Send a `ClientHello` frame (cleartext, Control channel) offering at least
   profile Standard, KEM `X25519MLKEM768`, signature `Ed25519`, AEAD
   `AES-256-GCM`, and a KEM client share.
2. Receive and decode the peer's `ServerHello`, decapsulate the KEM ciphertext,
   derive the handshake traffic secrets, then receive and AEAD-open the peer's
   `SERVER_AUTH` frame; verify its CertVerify and Finished against the running
   transcript hash.
3. Send its own AEAD-sealed `CLIENT_AUTH` frame (IdentityKey + CertVerify +
   Finished) under the client handshake traffic secret.
4. Derive the master secret and send/receive AES-256-GCM-protected application
   frames on the negotiated channel.

The **server** role is the mirror image. The exact frame layout, TLV type
numbers, HKDF labels, and AEAD nonce construction are normative in
`spec/10_handshake.md` and `spec/` generally; `impl/go/cmd/npamp-interop/main.go`
is a complete, minimal, line-by-line reference of this exact sequence built
entirely from the **exported** primitives of `impl/go` (no unexported internals),
which is the same bar your implementation needs to clear.

### If you would rather build a Go/Rust binary yourself (no shell script)

```sh
# Go — this binary IS a self-contained third-party-usable peer:
cd impl/go && go build -o npamp-interop ./cmd/npamp-interop
./npamp-interop -role server -addr 0.0.0.0:47700
./npamp-interop -role client -addr <peer-host>:47700

# Rust:
cd impl/rust && cargo build --example interop_server --example interop_client
./target/debug/examples/interop_server 0.0.0.0:47700
./target/debug/examples/interop_client <peer-host>:47700 --profile standard
```

Both binaries generate a fresh Ed25519 (and, for Rust High/Sovereign, ML-DSA-87)
identity keypair on every run — there is no shared secret material to provision
in advance, and no configuration file to hand-carry between machines beyond the
address/port you agree on with your interop partner.

### A note on networking at a hackathon venue

Hackathon venue networks are frequently NAT'd, and some block inbound
connections to attendee laptops entirely. If direct inbound connectivity is not
available:
- Prefer whichever party has a routable address or a shared tunnel/VPN to be
  the listener (`--role server`).
- A same-subnet link-local test (both laptops on the venue Wi-Fi, one dials the
  other's local address) usually works even when the internet uplink does not
  permit inbound traffic.
- As a fallback that still exercises the real wire protocol end-to-end (just not
  across a physical network boundary), both parties can run their stacks as
  separate processes on one machine over `127.0.0.1`, exactly as the loopback
  examples above do.

## Recording what happened

Copy [`IMPLEMENTATION-STATUS-TEMPLATE.md`](IMPLEMENTATION-STATUS-TEMPLATE.md) and
fill in a row for each direction you tested (which side was the reference, which
was yours, PASS/FAIL, profile negotiated, KEM group, any error text on failure).
That template is the artifact this kit expects to leave a hackathon with.
