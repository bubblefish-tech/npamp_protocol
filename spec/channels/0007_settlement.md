# NPAMP-CH-0007 — Settlement Channel (`0x0007`) Interface Reference (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is a **per-channel interface reference** for the N-PAMP
> Settlement channel (`0x0007`), derived from the N-PAMP core specification
> (draft-bubblefish-npamp-01, the "core specification"), §5 Channel Architecture
> and §8 Extension Points. It restates the channel's registry entry and its public
> frame-type reservations and describes the channel's agent-to-agent settlement and
> receipt interface **at the public level only**. It builds on the core
> specification, introduces no change to the core wire format, and defines no
> behavior the core specification does not already reserve. Where the core
> specification supplies only a registry line or reserves a code point without
> defining its semantics, this reference says so and describes the interface at that
> level. **The draft governs**: on any disagreement between this reference and the
> core specification, the core specification is authoritative.

## 1. Purpose

The core specification assigns channel `0x0007` the name **Settlement** and the
purpose **"Agent-to-agent settlement and receipts"** (core specification §5, Core
Channel Registry; `../../registries/channels.csv`). Expanded, the Settlement
channel is the N-PAMP channel over which two peers **settle an obligation between
them and exchange the receipts that evidence a settlement** — the class of traffic
that records that a bilateral agent-to-agent obligation has been met and returns an
acknowledgement of that fact. "Agent-to-agent" scopes the channel to a settlement
between the two peers of the association, as distinct from **Commerce** (`0x000E`,
"Multi-party agentic commerce and payment mandates"), which the core specification
reserves for multi-party commerce and payment-mandate traffic, and from **Audit**
(`0x000B`, "Audit-epoch commitments and transparency-log entries"), which it
reserves for audit-epoch commitment. "Receipts" names the acknowledgement half of
the channel's purpose: the evidence returned for a settlement, as distinct from a
bare transport acknowledgement of a frame.

The core specification defines the Settlement channel **only** as this registry
entry plus a reserved frame-type range for batch-commitment extension frames it
shares with the Audit channel (§3); it does not define a Settlement-specific wire
encoding, message schema, value or amount representation, ledger model, or receipt
format. Accordingly, this reference describes the Settlement interface at the level
the core specification actually fixes — the operation *classes* named by the
registry purpose (§4) — and does not invent frame layouts, field structures, or
semantics that the core specification does not state. The companion specification
NPAMP-SETTLEMENT (`../companion/86_settlement_channel.md`) now defines a concrete
Settlement operation encoding within the code points the core specification reserves;
the core specification itself still neither defines nor requires them, so the public
Settlement interface this reference restates remains exactly the registry-level
surface the core specification fixes.

## 2. Channel identity

The following values are taken verbatim from the core channel registry
(core specification §5; machine-readable form `../../registries/channels.csv`). They
are normative in the core specification; this reference restates them and does not
alter them.

| Attribute | Value |
|---|---|
| Channel ID | `0x0007` |
| Name | Settlement |
| Purpose | Agent-to-agent settlement and receipts |
| Minimum profile | Standard |
| Direction | Bidirectional |

- **Minimum profile — Standard.** The Settlement channel MAY be enabled at the
  Standard profile and is available at Standard and at every higher profile
  (High, Sovereign), per the core specification's min-profile rule (§5: the minimum
  profile is the lowest profile at which a channel may be enabled). See §5 for
  profile applicability.
- **Direction — Bidirectional.** Both peers send and receive frames on a single
  stream of this channel (core specification §5, Channel directionality). As with
  every N-PAMP channel, each peer maintains an independent send and receive
  sequence space and independent per-direction traffic keys, so both peers MAY
  transmit on the channel simultaneously (core specification §5). The Settlement
  channel is **not** classified Multi-stream; it does not open multiple concurrent
  transport sub-streams within a stream family (contrast the Memory channel
  `0x0001` and the Stream channel `0x000C`).
- **Advertisement gate.** A peer that has not advertised the Settlement channel
  during the handshake MUST NOT receive frames on it; frames on an unadvertised
  Settlement channel MUST be dropped (core specification §5, applied to `0x0007`).

## 3. Frame types

Frame types on the Settlement channel are drawn from the same per-channel
`0x0000`–`0xFFFF` frame-type namespace every N-PAMP channel uses
(core specification §4.6; reference `../04_frame_types.md`). Three groups are
relevant to this channel.

### 3.1 Reserved all-channel frame types

The following frame types are reserved across **all** channels with the same
meaning everywhere and retain that meaning on the Settlement channel. An
implementation MUST NOT reuse them for Settlement application traffic.

| Type | Name | Meaning on the Settlement channel |
|---|---|---|
| `0x0001` | PING | Liveness probe. |
| `0x0002` | PONG | Reply to PING. |
| `0x0003` | CLOSE | Authenticated close; AEAD-protected. |
| `0x0004` | CLOSE_ACK | Reply to CLOSE. |
| `0x0005` | ERROR | Error report; AEAD-protected. |
| `0x0006` | KEY_UPDATE | Initiate key update for this (channel, direction). |
| `0x0007` | KEY_UPDATE_ACK | Acknowledge key update. |
| `0x0008` | PATH_CHALLENGE | Path-migration challenge. |
| `0x0009` | PATH_RESPONSE | Path-migration response. |
| `0x000A` | FLOW_UPDATE | Connection-level flow-control credit update. |

(`0x0000` is reserved and MUST NOT be used as a frame type.)

### 3.2 Reserved Settlement/Audit batch-commitment frame range

The core specification reserves one sub-`0x0100` per-channel frame-type range whose
label names the Settlement channel (core specification §8, Reserved Frame-Type
Ranges; references `../04_frame_types.md` and `../09_extension_points.md`):

| Range | Reserved for |
|---|---|
| `0x00A0` – `0x00A3` | Settlement/Audit batch-commitment extension frames |

This range is **reserved, not defined**. The core specification neither defines nor
requires batch-commitment frames; it only reserves the code points so a companion
specification can define them without colliding with the core wire format
(core specification §8). Two honest boundaries apply:

- **The label is shared with the Audit channel.** The core specification reserves
  this single range under the joint label "Settlement/Audit batch-commitment
  extension frames" and does **not** further partition it between the Settlement
  channel (`0x0007`) and the Audit channel (`0x000B`, "Audit-epoch commitments and
  transparency-log entries"). This reference does not manufacture a per-channel
  split the core specification does not state; a companion that defines these frames
  is where any such partition would be fixed.
- **The Settlement companion defines the public half of these frames.** The companion
  specification NPAMP-SETTLEMENT (`../companion/86_settlement_channel.md`) now defines
  the public Settlement batch-commitment frames `0x00A0`–`0x00A1`; the Audit half
  `0x00A2`–`0x00A3` of this shared range remains reserved and undefined for the public
  Settlement channel. The core specification itself neither defines nor requires these
  frames. An implementation therefore MUST NOT treat any batch-commitment behavior as
  specified by the core specification — the public half is defined by NPAMP-SETTLEMENT,
  not the core — and MUST NOT assign `0x00A0`–`0x00A3` to any other purpose.

> **Known editorial inconsistency in -00 (carried, not corrected here).** The core
> specification states that channel-specific frame types begin at `0x0100`
> (§4.6), yet the reserved Settlement/Audit batch-commitment range
> `0x00A0`–`0x00A3` sits below `0x0100`. This inconsistency is present in the
> submitted draft and is recorded in `../04_frame_types.md`; this reference does not
> silently rewrite the authoritative text.

### 3.3 Channel-specific frame types (`0x0100`+ convention)

Channel-specific frame types begin at **`0x0100`** within each channel's frame
namespace (core specification §4.6). This is the range in which a Settlement-specific
operation encoding — for example concrete settlement request/response and receipt
frames (§4) — would be assigned. The core specification defines **no**
Settlement-specific frame type in this range. The companion specification
NPAMP-SETTLEMENT (`../companion/86_settlement_channel.md`) now defines Settlement
operation frames in this `0x0100`+ channel-specific range (settlement-intent and
receipt request/result operations and a structured error, `0x0100`–`0x0104`); the
core specification itself still neither defines nor requires them. §4 describes the
interface at the registry level the core specification actually fixes, and defers the
concrete operation encoding to NPAMP-SETTLEMENT.

## 4. Interface and operations (public level)

The Settlement channel's public interface is the set of operation classes named by
its registry purpose. The core specification fixes these as **names of operation
classes**, not as wire encodings; this section restates them at that level and
states explicitly where the core specification stops. An implementation MUST NOT
read a wire format into this section: no frame layout, field structure, TLV, value
representation, or correlation scheme below is defined by the core specification.

| Operation class | Public meaning (from the registry purpose) |
|---|---|
| Settlement | Record that a bilateral, agent-to-agent obligation between the two peers has been settled. |
| Receipt | Return the acknowledgement that evidences a settlement between the two peers. |

Notes and honest boundaries:

- **"Settlement" versus "receipts".** The registry purpose lists both
  ("agent-to-agent settlement **and receipts**"). The core specification names the
  settlement act and the receipt that evidences it as the channel's two purposes but
  does not further define how a settlement is expressed, what an obligation is over,
  or what a receipt contains; this reference records that both terms appear and does
  not manufacture a structure the core specification does not state. A companion
  specification MAY define them precisely.
- **No value, ledger, or receipt schema is defined here.** The registry purpose does
  not fix a currency, amount, asset, or ledger model, and the core specification
  defines **no** settlement message schema, value or amount encoding, mandate
  reference, or receipt format for this channel. This reference MUST NOT be cited as
  the source of any such encoding.
- **Batch commitment.** The only Settlement-specific extension surface the core
  specification names beyond the registry purpose is the **batch-commitment**
  frame-type range it reserves jointly with the Audit channel
  (`0x00A0`–`0x00A3`, §3.2). Its semantics are undefined by the core specification;
  the public half `0x00A0`–`0x00A1` is defined by the companion NPAMP-SETTLEMENT, not
  by the core, and remains out of scope for this core-level reference (§3.2).
- **No operation encoding is defined here.** Because the core specification assigns
  no Settlement-specific frame type (§3.3), the operation classes above have **no
  core-defined request frame, reply frame, addressing scheme, value encoding,
  receipt encoding, or error model**. This reference describes the interface at the
  registry level only.
- **Correlation and ordering.** The Settlement channel has an independent
  per-direction sequence space (core specification §5), which orders frames within a
  direction. The core specification does not define how a Settlement reply or receipt
  is correlated to the settlement it acknowledges (unlike the Bridge channel, where
  NPAMP-BRIDGE §5 defines a `correlation_id`); a Settlement operation encoding, when
  specified by a companion, is where such correlation would be defined. This
  reference does not define it.
- **Bidirectional single stream.** Because the channel is Bidirectional and not
  Multi-stream (§2), both peers exchange settlement and receipt frames over a single
  stream; either peer MAY originate traffic. The core specification does not assign
  fixed initiator/responder roles at the channel level.

## 5. Profile applicability

The Settlement channel's minimum profile is **Standard** (§2). By the core
specification's min-profile rule (§5), the channel is available at the Standard
profile and at every higher profile; that is, at **Standard, High, and Sovereign**.
There is no profile at which the Settlement channel is unavailable once its minimum
profile is met, and no upper profile bound.

- **Standard profile.** The Settlement channel is available and MAY be enabled. This
  is the profile at which the public Settlement interface described in this reference
  is fully expressible.
- **Higher profiles (High, Sovereign).** The Settlement channel remains available
  with the same wire-level frame namespace and the same public interface. N-PAMP's
  profiles share **one wire format** and differ in the cryptographic primitives and
  operational requirements they mandate (core specification §6, Profile Negotiation).
  The Settlement channel's framing and interface — its identity (§2), its frame-type
  namespace (§3), and the registry-level operation classes (§4) — are
  **profile-invariant**: they do not change across profiles. The specific
  cryptographic suite bound to each profile is defined by the core specification's
  profile-negotiation and cryptographic-suite sections and is **out of scope for this
  interface reference**; this reference describes the channel's public,
  profile-invariant interface only.
- **Scheduling.** The core specification's congestion-scheduling recommendation names
  the Control and Immune channels as ones that SHOULD be scheduled at higher priority
  than the bulk channels (Memory, Sensory, Telemetry) during congestion
  (core specification §5). The Settlement channel is named in **neither** set, so the
  core specification assigns it **no explicit congestion-scheduling class**; this
  reference does not invent one.
- **Publishing scope.** This reference documents only the public **Standard-profile
  interface surface** of the channel — its identity, purpose, direction, minimum
  profile, and public frame-type namespace. High- and Sovereign-profile
  cryptographic internals and parameters are governed by the core specification's
  profile negotiation and are out of scope here.

## 6. Relationship to companion specifications

The Settlement channel is a **native core channel**: unlike the Bridge channel
(`0x000D`; `./000D_bridge.md`), which encapsulates foreign agent protocols and is
elaborated by the NPAMP-BRIDGE companion framework
(`../companion/10_bridge_framework.md`) and its carriage classes, and unlike the
Discovery channel (`0x0010`), elaborated by NPAMP-DISC
(`../companion/40_discovery.md`), the Settlement channel is elaborated by a
**native-core-channel operation companion**, NPAMP-SETTLEMENT
(`../companion/86_settlement_channel.md`), in the current companion set
(`../companion/00_companion_index.md`) — not a bridge companion framework.
It is therefore not a bridge carriage class and does not build on NPAMP-BRIDGE, and
it does not appear in the companion index's "Channel selection for carriage" table —
which routes payment-mandate and multi-party commerce traffic to the **Commerce**
channel (`0x000E`), not to Settlement.

The consequence for an implementer is that the Settlement channel's core-level public
contract is exactly what §2–§5 restate (its concrete operation encoding being defined
by NPAMP-SETTLEMENT, not by the core specification):

- Its **identity** — id `0x0007`, name Settlement, purpose "agent-to-agent
  settlement and receipts", minimum profile Standard, direction Bidirectional (§2);
- Its **public interface** — the settlement and receipt operation classes, described
  at the registry level, with **no core-defined wire encoding** (§4);
- Its **reserved and companion-defined extension surface** — the `0x00A0`–`0x00A3`
  batch-commitment frame-type range, reserved by the core specification under a label
  shared with the Audit channel, whose public half `0x00A0`–`0x00A1` is now defined by
  the companion specification NPAMP-SETTLEMENT (`../companion/86_settlement_channel.md`)
  while the Audit half `0x00A2`–`0x00A3` remains reserved and undefined for the public
  Settlement channel; the core specification itself neither defines nor requires these
  frames, and NPAMP-SETTLEMENT further defines Settlement operation frames in the
  channel-specific `0x0100`+ namespace (§3.2, §3.3).

Richer, interoperable Settlement operations are defined by exactly such a companion:
NPAMP-SETTLEMENT (`../companion/86_settlement_channel.md`) defines a Settlement
operation encoding within the channel-specific `0x0100`+ code points and the public
batch-commitment half `0x00A0`–`0x00A1`, verified against the core specification. An
implementation carries core-level Settlement traffic under the channel identity and
reserved code points above; the core specification itself defines no additional
Settlement behavior, and the concrete operation semantics an implementation conforms
to are those NPAMP-SETTLEMENT defines. This reference documents the core-level public
interface and defines no new behavior.

## 7. Conformance

An implementation conforms to this Settlement-channel interface reference if and only
if, for channel `0x0007`, it:

1. Treats channel `0x0007` as the **Settlement** channel whose purpose is
   agent-to-agent settlement and receipts, consistent with the core channel registry
   (§2), and does not repurpose the channel identifier for other traffic;
2. Enables the Settlement channel only at the **Standard** profile or higher, never
   below Standard, and — once Standard is met — treats the channel as available at
   Standard, High, and Sovereign (§2, §5);
3. Drops any frame received on the Settlement channel that the peer has not advertised
   during the handshake, and does not deliver such frames to settlement processing
   (§2);
4. Preserves the core meaning of the reserved all-channel frame types
   (`0x0001`–`0x000A`) on the Settlement channel and does not reuse any of them for
   Settlement application traffic (§3.1);
5. Treats the frame-type range `0x00A0`–`0x00A3` as **reserved** for Settlement/Audit
   batch-commitment extension frames, assigns it to no other purpose, and does **not**
   claim batch-commitment behavior — or any per-channel partition of the range between
   the Settlement and Audit channels — as specified by the core specification, because
   the core specification reserves that range under a shared label without defining its
   semantics (§3.2);
6. Does not treat any operation description in §4 as a normative wire encoding, and
   does not cite this reference as the source of any Settlement request frame, reply
   frame, receipt frame, addressing scheme, value or amount encoding, correlation
   scheme, or error model, none of which the core specification defines for this
   channel (§3.3, §4);
7. Supports the channel's **Bidirectional** direction — both peers sending and
   receiving settlement and receipt frames over a single stream, each maintaining
   independent per-direction sequence spaces and traffic keys — and does not treat the
   channel as Multi-stream (§2, §4); and
8. Defers all Settlement operation semantics beyond the registry-level interface of §4
   to the NPAMP-SETTLEMENT companion specification
   (`../companion/86_settlement_channel.md`), adding no Settlement behavior of its own
   that neither the core specification reserves nor that companion defines (§6).

A conformance test suite SHOULD assert each clause above, and in particular SHOULD
verify clause 5 by confirming that an implementation does not advertise, emit, or
honor any frame in `0x00A0`–`0x00A3` as a defined batch-commitment operation on the
sole basis of the core specification, and clause 3 by confirming that a Settlement
frame arriving on an unadvertised channel is dropped.
