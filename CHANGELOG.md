# Changelog

All notable changes to the public N-PAMP specification are recorded here.

Two independent counters apply (see the README "Versioning" section):

- the protocol **wire major version** (the digit in `n-pamp/2`); and
- the **Internet-Draft revision** (`-NN`), which advances with each published
  revision of the document.

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
