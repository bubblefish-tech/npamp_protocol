# N-PAMP™: Native Post-Quantum Agent Messaging Protocol

N-PAMP™ is a binary, multi-channel, wire-level protocol for authenticated
communication between autonomous software agents. It operates beneath
application-layer agent protocols and provides a single fixed-size frame
format, a registry of multiplexed channels, and three escalating security
profiles (Standard, High, and Sovereign) built on standard post-quantum and
classical cryptography.

This repository is the public reference home of N-PAMP™: the Internet-Draft,
the normative companion specs and registries, the multi-language reference
implementations, the language-agnostic conformance corpus, the
cross-implementation test harness, and the durable record of how every spec
decision was made (`decisions/`). N-PAMP is developed as its **own artifact** —
consuming products vendor the reference implementation and pin the conformance
corpus from this repo; they do not develop the protocol. This keeps protocol
design, rationale, and conformance authority in one place with one history.

## Status

| Item | State |
|---|---|
| Specification | `draft-bubblefish-npamp-01` (Internet-Draft, Independent Submission stream, Informational) |
| Wire major version | 2 (ALPN identifier `n-pamp/2`) |
| IETF Datatracker | <https://datatracker.ietf.org/doc/draft-bubblefish-npamp/> |
| ALPN `n-pamp/2` | Registered with IANA (Expert Review, RFC 7301), citing the draft |
| `npamp` URI scheme | Provisionally registered with IANA (First Come First Served, RFC 7595), citing the draft |

## What N-PAMP™ provides

- **A single fixed 36-octet frame header** with mandatory authenticated
  encryption (AEAD) and a header CRC32C for fast rejection of corrupted frames.
- **Twenty multiplexed channels** (Control, Memory, Capability, Identity,
  Governance, Immune, Federation, Settlement, Compliance, Sensory, Telemetry,
  Audit, Stream, Bridge, Commerce, Interaction, Discovery, Workflow, Knowledge,
  Spatial), each with an independent per-direction sequence space and
  independent traffic keys. All channels are full-duplex.
- **Three negotiated security profiles** (Standard / High / Sovereign) that
  hold the wire format constant while escalating the cryptographic primitives
  and operational requirements.
- **Hybrid post-quantum key establishment** combining X25519 with ML-KEM
  (FIPS 203), AEAD record protection, and a forward-secure key schedule.
- **A 1.5-RTT mutually-authenticated handshake** (added in draft-01) with
  transcript binding, an HKDF key schedule, and downgrade protection.
- **QUIC** as the primary transport and **TCP with TLS 1.3** as a fallback,
  negotiated via the ALPN identifier `n-pamp/2`.

N-PAMP™ is deliberately scoped as a transport substrate. It does not define
application-layer semantics for the data carried on its channels; those are the
subject of companion specifications.

## Repository structure

| Path | Holds |
|------|-------|
| `ietf/draft-bubblefish-npamp-latest.md` | The Internet-Draft (single source of truth; kramdown-rfc source) |
| `spec/` | Core normative spec extracts (`01_alpn`…`10_handshake_binding`) |
| `spec/channels/` | Per-channel specifications (20 channel pages, `0000_control`…`0013_spatial`) |
| `spec/companion/` | Companion docs: bridge framework, carriage bindings, protocol registry, discovery, hello bootstrap, peer handle, protocol mappings, worked example |
| `registries/` | Code-point registries (channels, frame types, TLV, profiles, KEM, AEAD, signatures) as CSV |
| `impl/<lang>/` | Multi-language reference implementations |
| `test-vectors/schemas/` | One draft-2020-12 JSON Schema per vector type |
| `test-vectors/v1/` | The language-agnostic conformance corpus + KAT vectors |
| `scripts/` | Gate scripts: `verify-pins.ps1`, `validate-schemas.py` |
| `harness/` | Cross-implementation conformance runner + per-language adapters |
| `formal/` | Formal-methods models/proofs (references) |
| `decisions/` | ADR decision history (MADR 4.0) |
| `.github/` | Issue templates, labels, and the conformance CI workflow |

## Reading the specification

The normative specification is the Internet-Draft in this repository:

- [`ietf/draft-bubblefish-npamp-latest.md`](ietf/draft-bubblefish-npamp-latest.md) — kramdown-rfc source; the build emits the numbered revision `draft-bubblefish-npamp-01`.

Render it locally with the IETF author tools:

```sh
gem install kramdown-rfc
pip install xml2rfc
kramdown-rfc ietf/draft-bubblefish-npamp-latest.md > draft-bubblefish-npamp-01.xml
xml2rfc draft-bubblefish-npamp-01.xml --text --html
```

or use the hosted renderer at <https://author-tools.ietf.org/>.

## Scope

This repository contains the **open** N-PAMP reference surface: the Standard
profile primitives (X25519MLKEM768, Ed25519, SHA-256, AES-256-GCM, HKDF), the
public draft registry code points and profile enums, and the conformance
corpus. High-assurance / controlled material is maintained separately and is
out of scope for this open reference.

## IANA registrations

The registration details are restated in registry-template form in
[`IANA_ALPN_n-pamp-2_registration_request.md`](IANA_ALPN_n-pamp-2_registration_request.md):

- ALPN protocol identifier `n-pamp/2` (RFC 7301, Section 6; Expert Review).
- Provisional `npamp` URI scheme (RFC 7595; First Come First Served).

Both are also stated in the IANA Considerations of the Internet-Draft, which at
draft-01 requests a reference update to the current revision.

## Versioning

- **Protocol wire major version** — the digit in the ALPN label `n-pamp/2`
  equals the value `0x02` carried in the `Ver` field of the frame header. A
  change to this digit means a wire-incompatible major version and a new ALPN
  identifier.
- **Internet-Draft revision** — the `-NN` counter at the end of the draft name
  advances with every published revision; it is independent of the protocol's
  wire major version. The working tree carries the `-latest` source; one
  annotated git tag marks each datatracker `-NN` revision
  (`draft-bubblefish-npamp-00`, `-01`, …), with `rfcdiff` for per-revision deltas.

## License

The repository's code and original content are licensed under the
[Apache License 2.0](LICENSE).

The Internet-Draft and any resulting RFC are additionally subject to the IETF
Trust's Legal Provisions Relating to IETF Documents (BCP 78); see the IPR
notice (`ipr: trust200902`) in the draft front matter and `NOTICE`.

## Contributing and security

- Contribution guidelines: [CONTRIBUTING.md](CONTRIBUTING.md)
- Community standards: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- Reporting a security issue: [SECURITY.md](SECURITY.md)

## Author

Shawn Sammartano, BubbleFish™ Technologies, Inc
