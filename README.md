# N-PAMP™: Native Post-Quantum Agent Messaging Protocol

N-PAMP™ is a binary, multi-channel, wire-level protocol for authenticated
communication between autonomous software agents. It operates beneath
application-layer agent protocols and provides a single fixed-size frame
format, a registry of multiplexed channels, and three escalating security
profiles (Standard, High, and Sovereign) built on standard post-quantum and
classical cryptography.

This repository is the public home of the N-PAMP™ specification: the
Internet-Draft, the IANA registration requests, and supporting material.

## Status

| Item | State |
|---|---|
| Specification | `draft-bubblefish-npamp-00` (Internet-Draft, Independent Submission stream, Informational) |
| Wire major version | 2 (ALPN identifier `n-pamp/2`) |
| IETF Datatracker | Prepared for posting |
| ALPN `n-pamp/2` | Registration requested from IANA (Expert Review, RFC 7301) |
| `npamp` URI scheme | Provisional registration requested from IANA (First Come First Served, RFC 7595) |

Once the draft is posted, it will be available on the IETF Datatracker:
<https://datatracker.ietf.org/doc/draft-bubblefish-npamp/>

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
- **QUIC** as the primary transport and **TCP with TLS 1.3** as a fallback,
  negotiated via the ALPN identifier `n-pamp/2`.

N-PAMP™ is deliberately scoped as a transport substrate. It does not define
application-layer semantics for the data carried on its channels; those are the
subject of companion specifications.

## Reading the specification

The normative specification is the Internet-Draft in this repository:

- [`draft-bubblefish-npamp-00.md`](draft-bubblefish-npamp-00.md) - kramdown-rfc source.

Render it locally with the IETF author tools:

```sh
gem install kramdown-rfc
pip install xml2rfc
kramdown-rfc draft-bubblefish-npamp-00.md > draft-bubblefish-npamp-00.xml
xml2rfc draft-bubblefish-npamp-00.xml --text --html
```

or use the hosted renderer at <https://author-tools.ietf.org/>.

## IANA registrations

The registration requests are restated in registry-template form in
[`IANA_ALPN_n-pamp-2_registration_request.md`](IANA_ALPN_n-pamp-2_registration_request.md):

- ALPN protocol identifier `n-pamp/2` (RFC 7301, Section 6; Expert Review).
- Provisional `npamp` URI scheme (RFC 7595; First Come First Served).

Both actions are also stated in the IANA Considerations of the Internet-Draft.

## Versioning

- **Protocol wire major version** - the digit in the ALPN label `n-pamp/2`
  equals the value `0x02` carried in the `Ver` field of the frame header.
  A change to this digit means a wire-incompatible major version and a new ALPN
  identifier.
- **Internet-Draft revision** - the `-NN` counter at the end of the draft name
  advances with every published revision of the document; it is independent of
  the protocol's wire major version.

## License

The repository's code and original content are licensed under the
[Apache License 2.0](LICENSE).

The Internet-Draft and any resulting RFC are additionally subject to the IETF
Trust's Legal Provisions Relating to IETF Documents (BCP 78); see the IPR
notice (`ipr: trust200902`) in the draft front matter.

## Contributing and security

- Contribution guidelines: [CONTRIBUTING.md](CONTRIBUTING.md)
- Community standards: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- Reporting a security issue: [SECURITY.md](SECURITY.md)

## Author

Shawn Sammartano, BubbleFish™ Technologies, Inc
