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

A frame type is interpreted within the channel on which it appears, scoped by the
Channel ID field of the frame header. Each channel's frame-type namespace is
partitioned into four bands (core specification §4.6): `0x0000`–`0x000A`
all-channel reserved types (the table above); `0x000B`–`0x002F` reserved for
future core additions; `0x0030`–`0x00FF` the companion-extension band (the
per-channel reserved ranges below); and `0x0100`–`0xFFFF` channel-specific
application frame types. On the Control channel the application band carries the
four core handshake frame types `0x0100`–`0x0103` (CLIENT_HELLO / SERVER_HELLO /
SERVER_AUTH / CLIENT_AUTH), enumerated in
`../registries/frame_types_reserved.csv` and `../channels/0000_control.md`.

## Reserved frame-type ranges (companion specifications)

The core protocol does not define these; it reserves the ranges so companion
specs can use them without colliding with the core wire format:

| Range | Channel | Reserved for |
|---|---|---|
| 0x0030 – 0x0034 | Stream (0x000C) | Stream-channel sub-stream lifecycle and flow-control extension frames |
| 0x0035 – 0x0036 | Memory (0x0001) | Memory-channel eviction and revive extension frames |
| 0x0060 – 0x0063 | Capability (0x0002) | Capability-channel token extension frames |
| 0x0080 – 0x0080 | Control (0x0000) | Control-channel flow-extension frames |
| 0x0090 – 0x0090 | Audit (0x000B) | Audit-channel per-frame integrity-extension frames |
| 0x00A0 – 0x00A3 | Settlement/Audit (0x0007/0x000B) | Settlement/Audit batch-commitment extension frames |
| 0x00B0 – 0x00B4 | Governance (0x0004) | Governance-channel quorum extension frames |
| 0x00C0 – 0x00C4 | Immune (0x0005) | Immune-channel propagation extension frames |

> **Resolved in -02.** Earlier drafts described the frame-type namespace with two
> statements that appeared to conflict (channel-specific types "begin at `0x0100`"
> versus companion ranges reserved "at or above `0x0030`", which sit below `0x0100`
> at `0x0035…0x00C4`). draft-02 restates §4.6 as the explicit four-band partition
> above; **no code point moved**. The companion reserved ranges are the
> `0x0030`–`0x00FF` band; channel-specific application frame types are `0x0100`+.
