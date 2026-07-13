# N-PAMP — Native Post-Quantum Agent Messaging Protocol

**A binary, multi-channel, wire-level protocol for authenticated communication
between autonomous software agents.** N-PAMP sits *beneath* application-layer agent
protocols and gives them one thing they all lack: a single fixed-size frame, a
registry of multiplexed channels, and negotiated post-quantum security — on the wire,
before any application semantics.

This site renders the public reference material for N-PAMP: the Internet-Draft, the
normative core and companion specifications, the code-point registries, the ten
reference implementations with copy-paste quickstarts, the conformance corpus and
harness, and the per-decision record of how the protocol was designed. The
authoritative sources are the Markdown files in the
[`npamp_protocol`](https://github.com/bubblefish-tech/npamp_protocol) repository; this
is a browsable mirror of them.

!!! note "Specification status"
    The current specification is **`draft-bubblefish-npamp-01`** (Internet-Draft,
    Independent Submission stream, Informational). Wire major version **2**, ALPN
    identifier `n-pamp/2`. License: Apache-2.0.

## What N-PAMP provides

- **A single fixed 36-octet frame header** with mandatory authenticated encryption
  (AEAD) and a header CRC32C (Castagnoli) for fast rejection of corrupted frames
  before any cryptographic work.
- **Twenty multiplexed, full-duplex channels**, each with an independent per-direction
  sequence space and independent traffic keys: Control, Memory, Capability, Identity,
  Governance, Immune, Federation, Settlement, Compliance, Sensory, Telemetry, Audit,
  Stream, Bridge, Commerce, Interaction, Discovery, Workflow, Knowledge, and Spatial.
- **Three negotiated security profiles** — Standard, High, and Sovereign — that hold
  the wire format constant while escalating the cryptographic primitives.
- **Hybrid post-quantum key establishment** combining X25519 with ML-KEM (FIPS 203),
  concatenated ML-KEM-first as HKDF-Extract input keying material, aligned to NIST
  SP 800-56C Rev. 2.
- **A 1.5-RTT, mutually-authenticated handshake** with transcript binding, an HKDF key
  schedule, forward secrecy, and downgrade protection.
- **QUIC** as the primary transport and **TCP with TLS 1.3** as a fallback, negotiated
  via the ALPN identifier `n-pamp/2`.

N-PAMP is deliberately scoped as a **transport substrate**. It does not define
application-layer semantics for the data carried on its channels; those are the
subject of the companion specifications and bridge mappings shipped alongside it.

## Start here

- **Read the specification** — the Internet-Draft:
  [`draft-bubblefish-npamp-01`](../ietf/draft-bubblefish-npamp-latest.md).
- **Pick a language and go** — ten reference implementations, each with a copy-paste
  quickstart:
  [Go](../impl/go/QUICKSTART.md) ·
  [Rust](../impl/rust/QUICKSTART.md) ·
  [Python](../impl/python/QUICKSTART.md) ·
  [TypeScript](../impl/typescript/QUICKSTART.md) ·
  [C#](../impl/csharp/QUICKSTART.md) ·
  [Swift](../impl/swift/QUICKSTART.md) ·
  [Java](../impl/java/QUICKSTART.md) ·
  [Kotlin](../impl/kotlin/QUICKSTART.md) ·
  [PHP](../impl/php/QUICKSTART.md) ·
  [Ruby](../impl/ruby/QUICKSTART.md).
- **Understand the wire format** — the core specification:
  [Frame format](../spec/02_frame_format.md),
  [Channels](../spec/03_channels.md),
  [Cryptographic suites](../spec/06_cryptographic_suites.md),
  [Handshake binding](../spec/10_handshake_binding.md).
- **Check conformance** — the
  [conformance requirements](../spec/companion/55_conformance_requirements.md), the
  [test-vector corpus](../test-vectors/README.md), and the
  [harness](../harness/README.md).
- **Understand the design** — the
  [architecture decision records](../decisions/0001-record-architecture-decisions.md).

## Reference implementations at a glance

| Language | Quickstart | Build with |
|---|---|---|
| Go *(primary reference)* | [QUICKSTART](../impl/go/QUICKSTART.md) | `go build` |
| Rust | [QUICKSTART](../impl/rust/QUICKSTART.md) | `cargo build` |
| Python | [QUICKSTART](../impl/python/QUICKSTART.md) | `pip` / `pyproject.toml` |
| TypeScript | [QUICKSTART](../impl/typescript/QUICKSTART.md) | `npm` |
| C# | [QUICKSTART](../impl/csharp/QUICKSTART.md) | `dotnet build` |
| Swift | [QUICKSTART](../impl/swift/QUICKSTART.md) | `swift build` |
| Java | [QUICKSTART](../impl/java/QUICKSTART.md) | JDK |
| Kotlin | [QUICKSTART](../impl/kotlin/QUICKSTART.md) | Kotlin/JVM |
| PHP | [QUICKSTART](../impl/php/QUICKSTART.md) | `src/` |
| Ruby | [QUICKSTART](../impl/ruby/QUICKSTART.md) | `lib/` |

Every SDK implements the same Standard-profile primitives — frame codec, AES-256-GCM
AEAD record layer, HKDF key schedule, TLV codec, and the 1.5-RTT handshake binding —
verified against the shared vectors in the test-vector corpus. See the
[implementation overview](../impl/README.md) for the full matrix.
