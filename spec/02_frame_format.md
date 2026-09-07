# N-PAMP-01 — Wire Format (reference)

> **Derived extract.** Authoritative source: `../ietf/draft-bubblefish-npamp-latest.md`
> (revision draft-bubblefish-npamp-01; integrity pinned in ../PIN.json), §4 "Wire Format". The draft governs on any disagreement.

## Frame structure

```
+--------+------------------------------------------------+
| Header | Payload                                        |
| 36 B   | (var; frame-type body, then 16-octet AEAD tag) |
+--------+------------------------------------------------+
```

- The 36-octet header is fixed-size.
- Everything after the 36-octet header is the **Payload** — a single region whose
  length is the Payload Length field. The Payload carries the frame-type-specific
  body (which, where a frame type uses them, contains extension TLVs decoded per
  that frame type) and ends with the 16-octet AEAD tag.
- There is **no separate extension-TLV region** between the header and the payload:
  extension TLVs are frame-type-specific payload content, not a distinct wire
  region (see Extension TLV encoding). Spec, CDDL, and the reference `Frame` agree
  on this two-region structure (header ‖ payload).
- The payload is AEAD-sealed; **the 16-octet AEAD Tag is the mandatory final
  16 octets of the Payload** and is counted in Payload Length.
- Associated data (AD) covers the **21-octet header prefix (octets 0–20)** — the
  same octets protected by the header CRC32C.
- The **CRC32C (octets 21–24) and reserved octets (25–35) are OUTSIDE the AEAD
  associated-data range (octets 0–20)**. A receiver MUST NOT make any security
  decision based on them: the CRC32C is a non-cryptographic integrity check (an
  on-path attacker who alters a header field can recompute it), and the reserved
  octets carry no meaning beyond the MUST-be-zero rule. Only the AEAD tag, over the
  AD-covered header prefix, authenticates the header.

## Stream framing

N-PAMP frames are **self-delimiting**: each frame carries its own length in the
Payload Length header field, so no inter-frame delimiter or separate total-length
prefix is used. Over a stream transport (TCP with TLS 1.3), a receiver locates each
frame boundary as follows:

1. Read the fixed **36-octet header**.
2. Take **Payload Length** (octets 17–20, big-endian u32).
3. The frame occupies exactly **36 + Payload Length** octets; the next frame begins
   immediately at the following octet.

A receiver that has buffered fewer than 36 octets, or fewer than 36 + Payload Length
octets, MUST wait for more input before parsing the frame. Over QUIC a frame MAY
additionally align to a stream or datagram boundary, but the same Payload-Length
self-delimiting rule applies within any byte run. (Reference implementation:
`impl/go/frame.go` `ReadFrame` parses one frame from the front of a buffered stream
and reports the octet count consumed; a self-delimiting multi-frame round-trip is
exercised by `frame_stream_test.go`.)

## Fixed 36-octet header

Multi-octet integers are **big-endian**.

| Offset | Size | Field | Description |
|---|---|---|---|
| 0–3 | 4 | Magic | ASCII `"NPAM"` (`0x4E 0x50 0x41 0x4D`). |
| 4 | 4 bits | Ver | Wire-format version (high nibble of octet 4). `0x2` designates this frame layout; it is invariant and does not identify the crypto generation. |
| 4 | 4 bits | Flags | Low nibble of octet 4 (see Flags). |
| 5–6 | 2 | Frame Type | Frame type within the channel. |
| 7–8 | 2 | Channel ID | The semantic channel. |
| 9–16 | 8 | Sequence Number | Per-(channel, direction) monotonic, starts at 0. |
| 17–20 | 4 | Payload Length | Octet count of everything following the 36-octet header — the frame-type body (including any extension TLVs) **and** the trailing 16-octet AEAD tag. This single quantity locates the frame boundary on a stream transport. |
| 21–24 | 4 | CRC32C | CRC32C (Castagnoli polynomial `0x1EDC6F41`) over octets 0–20. Receivers MUST validate it **before processing any other header field**. |
| 25–35 | 11 | Reserved | MUST be zero; receivers MUST reject frames whose reserved octets are non-zero. |

The `Ver` field carries the **wire-format version** (the frame layout), which is
`0x02` and is an invariant of the protocol. It does **not** identify the crypto
generation: that is carried out of band by the negotiated ALPN identifier
(currently `n-pamp/3`), or by explicit configuration where frames are exchanged
without TLS. A raw frame is therefore not generation-self-describing; a receiver
MUST reject any frame whose `Ver` nibble is not `0x02` (see decision 0014).

## Flags (low nibble of octet 4)

| Bit | Name | Meaning |
|---|---|---|
| 0 (`0x01`) | (reserved) | Reserved (formerly URG); MUST be 0. A receiver MUST reject a frame that sets this bit. |
| 1 (`0x02`) | ENC | Payload is AEAD-encrypted. |
| 2 (`0x04`) | COMP | Payload is compressed. |
| 3 (`0x08`) | (reserved) | Reserved (formerly FRAG); MUST be 0. A receiver MUST reject a frame that sets this bit. |

## Extension TLV encoding

Where a frame type uses extension TLVs, they appear **inside that frame type's
payload**, decoded per the frame type's grammar; there is no separate ext-TLV
region between the header and the payload. Each TLV is encoded as:

```
+---------+---------+-----------+
| Type    | Length  | Value     |
| 16 bits | 16 bits | Length B  |
+---------+---------+-----------+
```

- Type and Length are 16-bit unsigned, network byte order; Length is the byte
  count of Value (0–65535).
- Unknown TLV, Type high bit (`0x8000`) **clear** → MUST ignore that TLV.
- Unknown TLV, Type high bit (`0x8000`) **set** → MUST treat as forward-incompatible
  and **reject the frame**.

## Payload encoding

Frame-type-specific body; MAY be a binary serialization, deterministic CBOR
(RFC 8949, per the Deterministic Encoding Profile below), or raw octets. The
selected encoding is signaled by the channel-local interpretation of the Frame
Type field.

### Deterministic Encoding Profile

Wherever this specification or a companion specification requires "deterministic
CBOR", the encoding MUST conform to the core deterministic encoding requirements of
RFC 8949 §4.2.1, with these pins:

- Map keys are sorted in **bytewise lexicographic order of their encoded bytes**
  (RFC 8949 §4.2.1), NOT the length-first order of §4.2.3.
- Integers and byte-/text-string lengths use the **shortest form** (§4.2.1).
- **No indefinite-length** items (§4.2.1).
- A decoder MUST reject a map with **duplicate keys** as malformed (§5.6).
- On any CBOR surface admitting numbers, the **integer/float rule** of §4.2.2
  applies: an integer-representable value is not encoded as a float.
- In a **sealed body** (a CBOR value inside an AEAD-protected payload), tags and
  floats MUST NOT appear, so two conformant encoders emit byte-identical sealed input.

A receiver MUST reject a frame whose CBOR body violates this profile, because AEAD
sealing and transcript hashing are computed over the exact octets. (Reference
implementation: `impl/go/memory_cbor.go` `byteLess` implements the §4.2.1 bytewise
ordering; the decoder rejects out-of-order and duplicate map keys.)

## CLOSE frame

A CLOSE frame is authenticated like any other frame. A receiver MUST verify the
AEAD tag before honoring a close. An unauthenticated or forged CLOSE MUST be
dropped and SHOULD be counted as a security event.
