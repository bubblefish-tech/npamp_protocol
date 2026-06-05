# Changelog

All notable changes to the public N-PAMP specification are recorded here.

Two independent counters apply (see the README "Versioning" section):

- the protocol **wire major version** (the digit in `n-pamp/2`); and
- the **Internet-Draft revision** (`-NN`), which advances with each published
  revision of the document.

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
