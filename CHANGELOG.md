# Changelog

All notable changes to the public N-PAMP specification are recorded here.

Independent version axes apply (see the README "Versioning" section):

- the **crypto generation** (the trailing digit of the ALPN identifier, currently
  `n-pamp/3`) — the cryptographic construction, independent of the wire-format `Ver`
  nibble (`0x2`), which is invariant across generations; and
- the **Internet-Draft revision** (`-NN`), which advances with each published
  revision of the document.

## draft-bubblefish-npamp-02

Revision of the Internet-Draft. Wire-breaking vs draft-01.

**Wire-breaking vs draft-01.**

- **ALPN identifier and crypto-generation bump.** The crypto generation is carried by
  the ALPN identifier, now **`n-pamp/3`** (deprecating `n-pamp/2`), decoupled from the
  wire-format version (the `Ver` nibble, which stays `0x2`). Because the CertVerify
  context string tracks the crypto generation, it moves to `N-PAMP/3, {server,client}
  CertificateVerify`, changing every CertVerify signature and the downstream transcript
  points, Finished MACs, and master secret (decision 0014).
- **KEM code point `0x11ed` corrected.** `0x11ed` now denotes **SecP384r1MLKEM1024**
  (secp384r1 + ML-KEM-1024), matching the IANA TLS Supported-Groups registry and
  `RFC 10024` (formerly `draft-ietf-tls-ecdhe-mlkem`, published August 2026); the
  label `X25519MLKEM1024` is removed everywhere.
- **Hybrid combiner order is per-group.** X25519MLKEM768 (`0x11ec`) remains
  ML-KEM-first; SecP384r1MLKEM1024 (`0x11ed`) is **ECDHE-first (P-384 first)**
  (`ECDHE_SS (48) || ML-KEM-1024_SS (32)`), matching `RFC 10024` (formerly
  `draft-ietf-tls-ecdhe-mlkem`) and NIST SP 800-56C Rev. 2. draft-01's universal
  ML-KEM-first order was wrong for
  the 1024 group; this changes the Sovereign/High derived keys and wire shares
  (KEMShare/KEMCiphertext = 1665 octets).
- **Signature code points re-anchored.** The ML-DSA SignatureScheme code points now
  match the IANA TLS registry (`draft-ietf-tls-mldsa`): `0x0905` denotes ML-DSA-65
  (previously mislabelled ML-DSA-87), ML-DSA-87 moves to `0x0906`, and ML-DSA-44
  (`0x0904`) is listed. High/Sovereign negotiate ML-DSA-87 at its corrected `0x0906`.
- **Deterministic CBOR profile pinned.** The frame-body encoding now cites a
  Deterministic Encoding Profile (RFC 8949 §4.2.1 bytewise map-key order,
  shortest-form, no indefinite lengths, duplicate-key rejection §5.6, the
  integer/float rule §4.2.2, and no tags/floats in sealed bodies). The reference
  comparator (`memory_cbor.go` `byteLess`) is corrected from the length-first
  §4.2.3 order to §4.2.1 bytewise; this changes the canonical order of maps that
  mix a short text-string key with a longer integer key.
- **AEAD: Mandatory-To-Implement suite + per-frame selection defined.** AES-256-GCM
  (`0x0001`) is Mandatory-To-Implement in every profile, guaranteeing a non-empty
  MUST-support intersection (BCP 61). Per-frame AEAD diversification (High/Sovereign)
  is defined as `AEADSelect[seq mod N]` — deterministic from the sequence number with
  no per-frame wire flag, frozen by a selector KAT. AEADSelect (TLV `0x0D`) now carries
  the ordered list of selectable suites (2 octets per suite, primary first); the former
  fixed 2-octet encoding is retired. The Standard 1-suite case is unchanged (2 octets).

**Clarifications (not wire-breaking).**

- **Frame structure is two regions.** The wire diagram and CDDL root drew a phantom
  extension-TLV region; both now describe two regions (header ‖ payload), matching
  the reference implementation, which has always marshalled two regions. Payload
  Length is defined as the octet count of everything after the 36-octet header — the
  frame-type body (including any extension TLVs) and the trailing 16-octet AEAD tag.
  No wire bytes change.
- **Stream framing stated.** Frames are self-delimiting via the Payload Length
  field: over TCP/TLS a reader reads the 36-octet header, takes Payload Length, and
  consumes exactly 36 + Payload Length octets. The reference implementation adds a
  `ReadFrame` stream-boundary helper with a self-delimiting multi-frame round-trip
  test.
- **Inert header-protection key removed.** The key schedule derives an AEAD key and
  IV only; the previously-named header-protection key output (never derived by the
  reference implementation, redundant with the secure transport) is removed.
  ProtectionMode (TLV `0x18`) is kept reserved with no defined values.
- **TLS 1.3 reference updated to RFC 9846.** The normative TLS 1.3 reference moves
  from RFC 8446 to RFC 9846 (which obsoletes 8446); each cited section number is
  re-verified against 9846's renumbering (Transcript Hash §4.4.1 → §4.1,
  CertificateVerify §4.4.3 → §4.5.2, Finished §4.4.4 → §4.5.3, key-share point
  §4.2.8.2 → §4.3.8.2; Key Schedule §7.1 unchanged).
- **CRC and reserved octets are non-security-relevant.** The spec now states that the
  CRC32C (octets 21-24) and reserved octets (25-35) are outside the AEAD
  associated-data range (0-20) and that a receiver MUST NOT make any security
  decision based on them.

## draft-bubblefish-npamp-01

Revision of the Internet-Draft. Wire major version remains 2; ALPN identifier
`n-pamp/2`.

**Wire-breaking vs draft-00.** The hybrid KEM shared-secret concatenation for
both X25519MLKEM768 and X25519MLKEM1024 is now `ML-KEM_SS || X25519_SS`
(ML-KEM-first), replacing draft-00's X25519-first order, so the FIPS-approved
key-establishment output leads the HKDF input per NIST SP 800-56C Rev. 2. This
changes every derived key and is **not interoperable with draft-00**.

Also in this revision:

- **1.5-RTT mutually-authenticated handshake binding** (new normative section):
  the four-frame flow (CLIENT_HELLO / SERVER_HELLO / SERVER_AUTH / CLIENT_AUTH),
  the per-TLV transcript, the single HKDF-Extract key schedule with the
  `"n-pamp "` label prefix, CertVerify, Finished, AUTH-frame sealing, and
  transcript-based downgrade protection.
- **Handshake code points**: Control-channel handshake frame types
  `0x0100`-`0x0103` and handshake TLV tags `0x09`-`0x0D` (IdentityKey,
  CertVerify, Finished, AEADOffer, AEADSelect).
- **ProfileOffer (TLV `0x01`) length** corrected from a fixed 4 to a variable
  list of one-octet profile identifiers, matching the reference implementations.
- **IANA Considerations** updated to reflect that the ALPN identifier `n-pamp/2`
  and the `npamp` URI scheme are already registered, requesting a reference
  update to this revision rather than a new assignment.

## draft-bubblefish-npamp-00 (2026-06-05)

Initial public Internet-Draft of N-PAMP. Wire major version 2; ALPN identifier
`n-pamp/2`.

Specified in this revision:

- A fixed **36-octet frame header**: magic `"NPAM"`, Ver/Flags octet, Frame
  Type, Channel ID, 64-bit Sequence Number, Payload Length, CRC32C over the
  21-octet header prefix, and a reserved-and-zero tail.
- **Twenty core channels** (`0x0000`-`0x0013`), each with an independent
  per-direction sequence space and per-direction traffic keys; all full-duplex.
  Channel `0x000C` (Stream) provides multiplexed full-duplex streaming.
- **Three security profiles** (Standard, High, Sovereign) that hold the wire
  format constant while escalating cryptographic strength and operational
  requirements.
- **Cryptographic suites**: hybrid X25519 + ML-KEM key establishment
  (FIPS 203); AEAD record protection with AES-256-GCM and ChaCha20-Poly1305;
  Ed25519 and ML-DSA-87 (FIPS 204) signatures; an HKDF key schedule using
  SHA-256 at Standard and SHA-384 at High and Sovereign.
- **Extension points**: reserved frame-type ranges, reserved TLV types, and a
  reserved channel-ID range for companion specifications.
- **IANA Considerations**: requests registration of the ALPN identifier
  `n-pamp/2` (Expert Review, RFC 7301) and provisional registration of the
  `npamp` URI scheme (First Come First Served, RFC 7595); other code-point
  spaces are maintained within the specification.
