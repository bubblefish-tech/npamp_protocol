# N-PAMP-01 — Frame Types (reference)

> **Derived extract.** Authoritative source: `../ietf/draft-bubblefish-npamp-latest.md`
> (revision draft-bubblefish-npamp-01; integrity pinned in ../PIN.json), §4.6 "Reserved Frame Types" and §8.1 "Reserved
> Frame-Type Ranges". The draft governs. Machine-readable:
> `../registries/frame_types_reserved.csv`.

## Reserved frame types (all channels)

Each channel defines its own frame types in the `0x0000–0xFFFF` space. The
following are reserved across **all** channels with the same meaning everywhere:

| Type | Name | Description |
|---|---|---|
| 0x0000 | (reserved) | Reserved; **MUST NOT** be used as a frame type. |
| 0x0001 | PING | Liveness probe. |
| 0x0002 | PONG | Reply to PING. |
| 0x0003 | CLOSE | Authenticated close; AEAD-protected. |
| 0x0004 | CLOSE_ACK | Reply to CLOSE. |
| 0x0005 | ERROR | Error report; AEAD-protected. |
| 0x0006 | KEY_UPDATE | Initiate key update for this (channel, direction). |
| 0x0007 | KEY_UPDATE_ACK | Acknowledge key update. |
| 0x0008 | PATH_CHALLENGE | Path-migration challenge. |
| 0x0009 | PATH_RESPONSE | Path-migration response. |
| 0x000A | FLOW_UPDATE | Connection-level flow-control credit update. |

Channel-specific frame types begin at **`0x0100`** within each channel's frame
namespace. On the Control channel this range carries the four core handshake frame
types `0x0100`–`0x0103` (CLIENT_HELLO / SERVER_HELLO / SERVER_AUTH / CLIENT_AUTH),
enumerated in `../registries/frame_types_reserved.csv` and `../channels/0000_control.md`.

## Reserved frame-type ranges (companion specifications)

The core protocol does not define these; it reserves the ranges so companion
specs can use them without colliding with the core wire format:

| Range | Reserved for |
|---|---|
| 0x0035 – 0x0036 | Memory-channel eviction and revive extension frames |
| 0x0060 – 0x0063 | Capability-channel token extension frames |
| 0x0080 – 0x0080 | Control-channel flow-extension frames |
| 0x0090 – 0x0090 | Audit-channel per-frame integrity-extension frames |
| 0x00A0 – 0x00A3 | Settlement/Audit batch-commitment extension frames |
| 0x00B0 – 0x00B4 | Governance-channel quorum extension frames |
| 0x00C0 – 0x00C4 | Immune-channel propagation extension frames |

> **Known editorial inconsistency in -00 (carried, not corrected here):** §4.6 states
> channel-specific frame types begin at `0x0100`, while the same section also says
> code points "at or above `0x0030`" not reserved are for extensions, and the
> companion ranges above sit below `0x0100` (`0x0035…0x00C4`). This inconsistency
> is **in the submitted draft** and is recorded for a future revision; the reference
> does not silently rewrite the authoritative text.
