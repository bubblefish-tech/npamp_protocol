# NPAMP-CH-000D — Bridge Channel Interface Reference (companion to draft-bubblefish-npamp-00)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is a **per-channel interface reference** for the N-PAMP
> **Bridge channel `0x000D`**. It is derived from the core specification
> (draft-bubblefish-npamp-00, the "core specification"), §5 Channel Architecture,
> and its machine-readable registry `../../registries/channels.csv`; **the draft
> governs** and, on any disagreement, the core specification is authoritative. The
> operational framework that occupies this channel is defined by NPAMP-BRIDGE
> (`../companion/10_bridge_framework.md`); this reference consumes only code points
> the core specification reserves and introduces no change to the core wire format
> and no change to NPAMP-BRIDGE. Where the core specification gives this channel
> only a registry line, this document says so and describes the interface at that
> level rather than inventing behavior.

## 1. Purpose

The Bridge channel `0x000D` is reserved by the core specification for the
**encapsulation of external agent protocols within N-PAMP frames** (core
specification §5, Core Channel Registry; `../../registries/channels.csv`). Its role is to let two
peers speak a *foreign* agentic protocol — for example an MCP or A2A dialogue, or
any other agent protocol — end to end over an N-PAMP association, so that the
foreign protocol's own messages travel between the peers while gaining N-PAMP's
authenticated, multiplexed, post-quantum transport and per-channel key isolation
(core specification §5). The channel is the general default for protocol
encapsulation: rather than defining a bespoke channel per foreign protocol, N-PAMP
carries an arbitrary foreign protocol over `0x000D` and lets an off-the-shelf
client or agent of that protocol interoperate with no change to the foreign
protocol itself.

The core specification defines *what the channel is for* (this one registry-line
purpose) but does not itself define the frames, envelope, correlation, error, or
safety semantics used to carry a foreign message. Those are supplied by the
companion framework NPAMP-BRIDGE and the carriage classes that build on it
(§4, §6). This page documents the channel's public interface at the level the core
specification fixes it, and points to the companion documents for the operational
contract.

## 2. Channel identity

The following identity is taken verbatim from the core channel registry
(`../../registries/channels.csv`; core specification §5, Core Channel Registry). A
channel page MUST NOT alter these values; they are reproduced here for reference
only and the registry governs.

| Property | Value |
|---|---|
| Channel ID | `0x000D` |
| Name | Bridge |
| Purpose | Encapsulation of external agent protocols within N-PAMP frames |
| Minimum profile | Standard |
| Direction | Bidirectional |

- **Direction — Bidirectional.** Both peers send and receive frames on a single
  stream of this channel (core specification §5, Channel directionality). As with
  every N-PAMP channel, each peer maintains an independent send and receive
  sequence space and independent per-direction traffic keys, so both peers MAY
  transmit on the channel simultaneously (core specification §5). The Bridge
  channel is **not** classified Multi-stream; it does not open multiple concurrent
  transport sub-streams within a stream family (contrast the Stream channel
  `0x000C`).
- **Advertisement.** A peer that has not advertised `0x000D` during the handshake
  MUST NOT receive frames on it; frames on an unadvertised channel MUST be dropped
  (core specification §5).

## 3. Frame types

Frame types on `0x000D` are governed by the core specification's per-channel
frame-type rules (core specification §4.6, Reserved Frame Types; §8.1, Reserved
Frame-Type Ranges). Each channel defines its own frame types in the
`0x0000`–`0xFFFF` space, subject to the following:

### 3.1 Reserved all-channel frame types

The frame types below are reserved across **all** channels with the same meaning
everywhere and therefore retain that meaning on `0x000D` (core specification §4.6):

| Type | Name | Meaning on this channel |
|---|---|---|
| `0x0000` | (reserved) | MUST NOT be used as a frame type. |
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

An implementation MUST NOT reuse any reserved all-channel frame type for
application (foreign-protocol) traffic on this channel.

### 3.2 Channel-specific frame-type namespace

Channel-specific frame types begin at **`0x0100`** within each channel's frame
namespace (core specification §4.6). Foreign-protocol traffic on the Bridge
channel therefore occupies the `0x0100`+ namespace.

The core specification's Reserved Frame-Type Ranges table (core specification §8.1,
Extension Points) reserves several sub-`0x0100` code-point ranges for companion
extensions — but **none of those ranges is assigned to the Bridge channel**; the
reserved ranges there belong to the Memory, Capability, Control, Audit,
Settlement/Audit, Governance, and Immune channels. The core specification records a
known editorial inconsistency in -00 between the "`0x0100`" channel-specific
boundary and the sub-`0x0100` reserved ranges; that inconsistency is carried, not
corrected, by the core references (`../04_frame_types.md`) and does not affect this
channel, whose operational frames sit at `0x0100`+.

### 3.3 Operational frame types (defined by NPAMP-BRIDGE, not the core)

The core specification does not itself define any channel-specific frame type for
`0x000D`. The channel's operational frame set is defined by the companion framework
NPAMP-BRIDGE within the `0x0100`+ namespace (NPAMP-BRIDGE §2). It is reproduced
here for orientation only; NPAMP-BRIDGE governs their semantics:

| Type | Name | Defined by |
|---|---|---|
| `0x0100` | BRIDGE_REQUEST | NPAMP-BRIDGE §2 |
| `0x0101` | BRIDGE_RESPONSE | NPAMP-BRIDGE §2 |
| `0x0102` | BRIDGE_ERROR | NPAMP-BRIDGE §2 |
| `0x0103` | BRIDGE_NOTIFY | NPAMP-BRIDGE §2 |
| `0x0104` | BRIDGE_STREAM_DATA | NPAMP-BRIDGE §2 |
| `0x0105` | BRIDGE_STREAM_END | NPAMP-BRIDGE §2 |

A carriage class or per-protocol mapping that carries traffic on this channel MUST
use the frame types NPAMP-BRIDGE defines and MUST NOT introduce a conflicting
channel-specific frame type without a companion specification reserving it.

## 4. Interface / operations

At the core-specification level the Bridge channel's public interface is exactly
its registry line: it **encapsulates external agent protocols within N-PAMP
frames** (core specification §5). The core specification defines no channel-specific
operations for it beyond the reserved all-channel control frames of §3.1; it
neither parses nor interprets the foreign protocol carried within.

The operational interface on this channel is supplied by the companion framework
NPAMP-BRIDGE and is summarized below at the interface level only. Each item is
**defined by NPAMP-BRIDGE**, not by this page or by the core specification, and the
cited NPAMP-BRIDGE section governs:

- **Transparent carriage.** A foreign protocol's message is carried octet-for-octet
  as the foreign-message region of the frame payload; an implementation MUST NOT
  re-serialize, summarize, or substitute its own envelope for the foreign message
  (NPAMP-BRIDGE §1, §3). Routing, correlation, and safety metadata are carried
  *around* the foreign message.
- **Request / reply.** A BRIDGE_REQUEST expects exactly one reply — a
  BRIDGE_RESPONSE on success or a BRIDGE_ERROR on failure (NPAMP-BRIDGE §2, §6).
  Because the channel is bidirectional, either peer MAY originate a request; the
  requester/responder roles are assigned per exchange, not per association
  (NPAMP-BRIDGE §5).
- **Correlation.** A BRIDGE_REQUEST carries a non-empty `correlation_id`, unique
  among the originating peer's outstanding requests on the channel in that
  direction; replies echo it verbatim, and a receiver MUST match replies to
  requests by `correlation_id` rather than by frame sequence number
  (NPAMP-BRIDGE §5).
- **Structured error.** A failure within the foreign protocol is reported as
  BRIDGE_ERROR carrying the foreign protocol's own error object verbatim; a failure
  *below* the foreign protocol is reported as BRIDGE_ERROR carrying an N-PAMP
  transport error (NPAMP-BRIDGE §6). An implementation MUST NOT report success for a
  message it could not deliver.
- **One-way notification.** A BRIDGE_NOTIFY carries a foreign one-way message with
  no reply expected or permitted; `corr_len` is `0` (NPAMP-BRIDGE §5, §8).
- **Streaming.** A streamed reply is carried as BRIDGE_STREAM_DATA chunks
  terminated by BRIDGE_STREAM_END (NPAMP-BRIDGE §2).
- **Safety annotation.** A request that can cause side effects carries a SafetyLabel
  TLV, carried unchanged to the foreign endpoint; absence on a state-mutating
  operation is treated as `destructive` (fail-safe) (NPAMP-BRIDGE §7).

The metadata that surrounds the foreign message — the BridgeEnvelope TLV (Type
`0x0010`) and the SafetyLabel TLV (Type `0x0013`) — uses TLV types the core
specification reserves for companion specifications (core specification §8.1,
Reserved TLV Tags) and is defined by NPAMP-BRIDGE §4 and §7. This page does not
redefine those TLVs.

## 5. Profile applicability

The Bridge channel's **minimum profile is Standard** (`../../registries/channels.csv`; core
specification §5). The Minimum-profile column gives the lowest profile at which the
channel may be enabled; the channel is therefore available at **Standard** and at
every higher profile — **Standard, High, and Sovereign** (core specification §5).
The Bridge channel is not gated above Standard: it is a baseline-profile channel.

- The channel MUST be advertised during the handshake for a peer to receive frames
  on it; frames on an unadvertised channel MUST be dropped (core specification §5).
- N-PAMP's three profiles (Standard, High, Sovereign) share **one wire format** and
  differ in the cryptographic primitives and operational requirements they mandate
  (core specification, Profile Negotiation). The Bridge channel's framing and
  interface — its identity (§2), its frame-type namespace (§3), and the
  encapsulation contract it inherits from NPAMP-BRIDGE (§4) — are **profile-
  invariant**: they do not change across profiles. The per-profile cryptographic
  suites are selected by the core specification's profile negotiation and key
  schedule and are out of scope for this per-channel interface reference.
- **Publishing scope.** This reference documents only the public **Standard-profile
  interface surface** of the channel — its identity, purpose, direction, minimum
  profile, and public frame-type namespace. High- and Sovereign-profile
  cryptographic internals and parameters are governed by the core specification's
  profile negotiation and are out of scope here.

## 6. Relationship to companion specifications

The Bridge channel `0x000D` is the substrate on which the bridge companion
specifications operate. The relationships are:

- **NPAMP-BRIDGE** (`../companion/10_bridge_framework.md`) — the protocol-agnostic
  encapsulation framework. It occupies this channel's `0x0100`+ frame namespace and
  defines the frame types (§3.3), the BridgeEnvelope and SafetyLabel TLVs, and the
  correlation, structured-error, notification, streaming, and safety contract that
  every carriage class inherits (§4). NPAMP-BRIDGE is the operational definition of
  this channel's behavior; this reference points to it and does not restate it.
- **The six carriage classes** ride this channel by building on NPAMP-BRIDGE. Each
  covers a whole family of foreign protocols:
  - NPAMP-CC-JSONRPC (`../companion/20_carriage_jsonrpc.md`) — JSON-RPC 2.0
    protocols;
  - NPAMP-CC-HTTP (`../companion/21_carriage_http.md`) — HTTP-semantics protocols;
  - NPAMP-CC-MSG (`../companion/22_carriage_messaging.md`) — message-passing /
    performative protocols;
  - NPAMP-CC-STREAM (`../companion/23_carriage_streaming.md`) — event / streaming
    protocols;
  - NPAMP-CC-DOC (`../companion/24_carriage_documents.md`) — capability / schema
    documents; and
  - NPAMP-CC-OPAQUE (`../companion/25_carriage_opaque.md`) — the universal escape
    hatch that carries any declared-content-type payload with no protocol-specific
    mapping.
- **Registry and discovery.** The `protocol_id` carried in the BridgeEnvelope is
  drawn from the Bridge Protocol Identifier registry NPAMP-REG
  (`../companion/30_protocol_registry.md`); a peer MAY advertise the protocols and
  carriage classes it carries over the Discovery channel `0x0010` per NPAMP-DISC
  (`../companion/40_discovery.md`). Thin per-protocol mappings (for example MCP and
  A2A) select a carriage class and pin protocol specifics; until a mapping is
  authored, a protocol remains carriable via Class OPAQUE.
- **Channel selection.** The Bridge channel is the general default for protocol
  encapsulation. Where a class of foreign traffic corresponds to a more specific
  core channel's purpose — capability/discovery documents to Discovery `0x0010`,
  agent-to-human interaction to Interaction `0x000F`, payment mandates to Commerce
  `0x000E`, full-duplex streaming to Stream `0x000C` — a deployment MAY carry that
  traffic on the more specific core channel instead of, or in addition to, the
  Bridge channel (companion index, "Channel selection for carriage"). A mapping
  document specifies which channel or channels a given protocol's traffic uses.

## 7. Conformance

An implementation that enables the Bridge channel `0x000D` conforms to this
reference if and only if it:

1. Treats the channel with the identity fixed by the core channel registry — ID
   `0x000D`, name Bridge, purpose "encapsulation of external agent protocols within
   N-PAMP frames", minimum profile Standard, direction Bidirectional — and does not
   alter any of these values (§2);
2. Does not deliver frames on `0x000D` to a peer that has not advertised the channel
   during the handshake, and drops frames received on an unadvertised channel (§2;
   core specification §5);
3. Preserves the meaning of every reserved all-channel frame type (`0x0001`–
   `0x000A`) on this channel and does not reuse any of them for foreign-protocol
   traffic (§3.1);
4. Places all foreign-protocol traffic in the channel-specific `0x0100`+ frame-type
   namespace, using the frame types NPAMP-BRIDGE defines, and does not introduce a
   conflicting channel-specific frame type absent a companion specification
   reserving it (§3.2, §3.3);
5. Carries foreign-protocol traffic on this channel only in conformance with
   NPAMP-BRIDGE and the relevant carriage class, treating the foreign message as
   opaque and octet-exact, and does not rely on any channel behavior this page
   defines beyond the core registry line and the companion contracts it references
   (§4, §6); and
6. Does not enable `0x000D` below the Standard profile, and keeps the channel's
   framing and interface invariant across the Standard, High, and Sovereign
   profiles (§5).

This reference defines no frame semantics, envelope, correlation, error, or safety
behavior of its own; conformance for those is governed by NPAMP-BRIDGE §9 and the
§Conformance clause of each carriage class. A per-channel reference MUST NOT be read
to add behavior the core specification and the companion framework do not define.
