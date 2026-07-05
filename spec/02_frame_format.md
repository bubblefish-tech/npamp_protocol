# N-PAMP-01 — Wire Format (reference)

> **Derived extract.** Authoritative source: `../ietf/draft-bubblefish-npamp-latest.md`
> (revision draft-bubblefish-npamp-01; integrity pinned in ../PIN.json), §4 "Wire Format". The draft governs on any disagreement.

## Frame structure

```
+--------+-------------+-------------------+-----------+
| Header | Extension   | Payload           | AEAD Tag  |
| 36 B   | TLVs (var)  | (var, encrypted)  | (16 B)    |
+--------+-------------+-------------------+-----------+
```

- The 36-octet header is fixed-size.
- Zero or more extension TLVs MAY accompany a frame.
- The payload is AEAD-sealed.
- **The 16-octet AEAD Tag is the mandatory final component of every frame.**
- Associated data (AD) covers the **21-octet header prefix (octets 0–20)** — the
  same octets protected by the header CRC32C.

## Fixed 36-octet header

Multi-octet integers are **big-endian**.

| Offset | Size | Field | Description |
|---|---|---|---|
| 0–3 | 4 | Magic | ASCII `"NPAM"` (`0x4E 0x50 0x41 0x4D`). |
| 4 | 4 bits | Ver | Protocol major version (high nibble of octet 4). `0x2` designates this wire format. |
| 4 | 4 bits | Flags | Low nibble of octet 4 (see Flags). |
| 5–6 | 2 | Frame Type | Frame type within the channel. |
| 7–8 | 2 | Channel ID | The semantic channel. |
| 9–16 | 8 | Sequence Number | Per-(channel, direction) monotonic, starts at 0. |
| 17–20 | 4 | Payload Length | Byte count of the payload following the header. |
| 21–24 | 4 | CRC32C | CRC32C (Castagnoli polynomial `0x1EDC6F41`) over octets 0–20. Receivers MUST validate it **before processing any other header field**. |
| 25–35 | 11 | Reserved | MUST be zero; receivers MUST reject frames whose reserved octets are non-zero. |

The `Ver` field carries the wire major version; the value `0x02` corresponds to
the ALPN identifier `n-pamp/2`.

## Flags (low nibble of octet 4)

| Bit | Name | Meaning |
|---|---|---|
| 0 (`0x01`) | URG | Urgent-priority scheduling. |
| 1 (`0x02`) | ENC | Payload is AEAD-encrypted. |
| 2 (`0x04`) | COMP | Payload is compressed. |
| 3 (`0x08`) | FRAG | Frame is a fragment of a larger logical message. |

## Extension TLV encoding

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
(RFC 8949), or raw octets. The selected encoding is signaled by the channel-local
interpretation of the Frame Type field.

## CLOSE frame

A CLOSE frame is authenticated like any other frame. A receiver MUST verify the
AEAD tag before honoring a close. An unauthenticated or forged CLOSE MUST be
dropped and SHOULD be counted as a security event.
