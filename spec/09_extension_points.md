# N-PAMP-01 — Extension Points & IANA Posture (reference)

> **Derived extract.** Authoritative source: `../ietf/draft-bubblefish-npamp-latest.md`
> (revision draft-bubblefish-npamp-01; integrity pinned in ../PIN.json), §8 "Extension Points" and §9.3/§9.5. The draft governs.

The core protocol neither defines nor requires any extension; it only **reserves
ranges** so companion specifications can be defined without colliding with the
core wire format.

## Reserved frame-type ranges (companion specs)

| Range | Reserved for |
|---|---|
| 0x0035 – 0x0036 | Memory-channel eviction and revive extension frames |
| 0x0060 – 0x0063 | Capability-channel token extension frames |
| 0x0080 – 0x0080 | Control-channel flow-extension frames |
| 0x0090 – 0x0090 | Audit-channel per-frame integrity-extension frames |
| 0x00A0 – 0x00A3 | Settlement/Audit batch-commitment extension frames |
| 0x00B0 – 0x00B4 | Governance-channel quorum extension frames |
| 0x00C0 – 0x00C4 | Immune-channel propagation extension frames |

## Reserved TLV tags (companion specs)

TLV types **`0x0010`, `0x0013`, and `0x0014`** are reserved for extension TLVs
defined in companion specifications. TLV types `0x8000`–`0xFFFF` remain reserved
as forward-incompatible extension points (Type high bit set).

## Reserved channel-ID range

`0x0014`–`0xFFFF` reserved: `0x0014`–`0x001F` future core; `0x0020`–`0xEFFF`
extension channels; `0xF000`–`0xFFFE` GREASE (receivers MUST ignore); `0xFFFF`
MUST NOT appear on the wire.

## IANA posture (Independent Submission stream)

The channel registry, the frame-type registry, and the TLV type registry are
**defined and maintained within the specification itself**. Because -00 is
published through the Independent Submission stream, it does **not** request the
creation of new IANA-hosted registries for these code points; they are normative
within the document and extended by companion specs and future revisions, **not**
by IANA registration actions. The only IANA-registry actions -00 requests are the
**ALPN identifier** (`n-pamp/2`, Expert Review) and the **`npamp://` URI scheme**
(provisional, FCFS).

> **Companion specifications.** The semantics that occupy the reserved ranges above
> — including external-protocol bridge encapsulation on channel `0x000D` and any
> profile-specific extensions — are defined in separate companion specifications.
> draft-00 reserves the code points; it defines none of those semantics.
