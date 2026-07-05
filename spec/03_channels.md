# N-PAMP-01 — Channel Architecture (reference)

> **Derived extract.** Authoritative source: `../ietf/draft-bubblefish-npamp-latest.md`
> (revision draft-bubblefish-npamp-01; integrity pinned in ../PIN.json), §5 "Channel Architecture". The draft governs.
> Machine-readable form: `../registries/channels.csv`.

N-PAMP multiplexes traffic over channels identified by a **16-bit Channel ID**.
Each channel carries one class of agent traffic and has an independent
per-direction sequence space and independent traffic keys. A peer that has not
advertised a channel during the handshake MUST NOT receive frames on it; frames
on an unadvertised channel MUST be dropped.

## Core channel registry

| ID | Name | Purpose | Min Profile | Direction |
|---|---|---|---|---|
| 0x0000 | Control | Connection control, handshake completion, capability epoch | Standard | Bidirectional |
| 0x0001 | Memory | Persistent-state create/read/update/delete and retrieval | Standard | Multi-stream |
| 0x0002 | Capability | Capability issuance, delegation, revocation, lookup | Standard | Bidirectional |
| 0x0003 | Identity | Identity resolution, attestation, presence | Standard | Bidirectional |
| 0x0004 | Governance | Policy proposals, votes, quorum closure | High | Bidirectional |
| 0x0005 | Immune | Anomaly reports and defensive gossip | Standard | Bidirectional |
| 0x0006 | Federation | Cross-instance synchronization and gossip | High | Multi-stream |
| 0x0007 | Settlement | Agent-to-agent settlement and receipts | Standard | Bidirectional |
| 0x0008 | Compliance | Attestation and regulatory export | High | Bidirectional |
| 0x0009 | Sensory | Bulk telemetry and low-priority observations | High | Multi-stream |
| 0x000A | Telemetry | Operational metrics and health reporting | Standard | Bidirectional |
| 0x000B | Audit | Audit-epoch commitments and transparency-log entries | Sovereign | Bidirectional |
| 0x000C | Stream | Multiplexed full-duplex streaming (tokens, audio, video, file transfer) | Standard | Multi-stream |
| 0x000D | Bridge | Encapsulation of external agent protocols within N-PAMP frames | Standard | Bidirectional |
| 0x000E | Commerce | Multi-party agentic commerce and payment mandates | Standard | Bidirectional |
| 0x000F | Interaction | Agent-to-human user-interface events | Standard | Bidirectional |
| 0x0010 | Discovery | Agent, tool, and service discovery and capability advertisement | Standard | Bidirectional |
| 0x0011 | Workflow | Multi-agent orchestration and task delegation | Standard | Bidirectional |
| 0x0012 | Knowledge | Retrieval queries with ranked results and provenance | Standard | Multi-stream |
| 0x0013 | Spatial | Physical-world state for robotics and IoT (high-frequency) | High | Multi-stream |

- **Min Profile** = lowest profile at which a channel may be enabled; available at
  that profile and every higher one (a "High" channel is available at High and
  Sovereign).
- The **Audit** channel (0x000B) is enabled by default only at **Sovereign**; other
  profiles MAY enable it.
- **Control** and **Immune** SHOULD be scheduled at higher priority than bulk
  channels (Memory, Sensory, Telemetry) during congestion.

## Directionality

| Direction | Meaning |
|---|---|
| Bidirectional | Both peers send and receive frames on a single stream. |
| Multi-stream | Bidirectional, and the channel MAY open multiple concurrent transport streams within its stream family. |

The Stream channel (0x000C) provides general-purpose multiplexed full-duplex
streaming (token, audio, video, file-transfer sub-streams), each with independent
flow control.

## Reserved channel-ID ranges

`0x0014–0xFFFF` are reserved: `0x0014–0x001F` future core additions;
`0x0020–0xEFFF` extension channels (companion specs); `0xF000–0xFFFE` GREASE
(receivers MUST ignore); `0xFFFF` MUST NOT appear on the wire.
