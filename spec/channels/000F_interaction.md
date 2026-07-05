# NPAMP-CH-000F — Interaction Channel (`0x000F`) Interface Reference (companion to draft-bubblefish-npamp-00)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is a **per-channel interface reference** for the N-PAMP
> Interaction channel (`0x000F`), derived from the N-PAMP core specification
> (draft-bubblefish-npamp-00, the "core specification"), §5 Channel Architecture
> and §8 Extension Points. It restates the channel's registry entry and its public
> frame-type reservations and describes the channel's agent-to-human
> user-interface-event interface **at the public level only**. It builds on the
> core specification, introduces no change to the core wire format, and defines no
> behavior the core specification does not already reserve. Where the core
> specification supplies only a registry line or reserves a code point without
> defining its semantics, this reference says so and describes the interface at
> that level. **The draft governs**: on any disagreement between this reference and
> the core specification, the core specification is authoritative.

## 1. Purpose

The core specification assigns channel `0x000F` the name **Interaction** and the
purpose **"Agent-to-human user-interface events"** (core specification §5, Core
Channel Registry; `../../registries/channels.csv`). Expanded, the Interaction
channel is the N-PAMP channel over which **user-interface events pass between an
agent and a human party**: the class of traffic in which an agent surfaces events
to a human's user interface and a human's interaction returns to the agent, as
distinct from durable addressable state (Memory `0x0001`), ephemeral connection
control (Control `0x0000`), general-purpose multiplexed media streaming (Stream
`0x000C`), or the encapsulation of a foreign agent protocol (Bridge `0x000D`).
The "agent-to-human" qualifier names the semantic relationship the channel serves
— an agent and a human user interface — and distinguishes this channel from the
agent-to-agent and instance-to-instance traffic of the other core channels.

The core specification defines the Interaction channel **only** as this registry
entry. Unlike the Memory channel — for which the core specification additionally
reserves a per-channel frame-type range (§3) — the core specification reserves
**no** Interaction-specific frame-type range and defines no Interaction-specific
wire encoding, event schema, event vocabulary, message schema, or operation
contract. Accordingly, this reference describes the Interaction interface at the
level the core specification actually fixes — the traffic *class* named by the
registry purpose (§4) — and does not invent frame layouts, event types, field
structures, or semantics that the core specification does not state. A future
companion specification MAY define a concrete Interaction operation encoding
within the channel-specific code points the core specification leaves available;
until then, the public Interaction interface is exactly what this reference
restates, and any richer agent-to-human interaction carried today rides the
bridge framework by deployment choice (§6).

## 2. Channel identity

The following values are taken verbatim from the core channel registry
(core specification §5; machine-readable form `../../registries/channels.csv`). They are
normative in the core specification; this reference restates them and does not
alter them.

| Attribute | Value |
|---|---|
| Channel ID | `0x000F` |
| Name | Interaction |
| Purpose | Agent-to-human user-interface events |
| Minimum profile | Standard |
| Direction | Bidirectional |

- **Minimum profile — Standard.** The Interaction channel MAY be enabled at the
  Standard profile and is available at Standard and at every higher profile
  (High, Sovereign), per the core specification's min-profile rule
  (§5: the minimum profile is the lowest profile at which a channel may be
  enabled). See §5 for profile applicability.
- **Direction — Bidirectional.** Both peers send and receive frames on a single
  stream of this channel (core specification §5, Channel directionality). As with
  every N-PAMP channel, each peer maintains an independent send and receive
  sequence space and independent per-direction traffic keys, so both peers MAY
  transmit on the channel simultaneously — supporting the two-way agent-to-human
  relationship in which an agent emits user-interface events toward the human's
  client and the human's client returns interaction events toward the agent
  (core specification §5). The Interaction channel is **not** classified
  Multi-stream: it does not open multiple concurrent transport sub-streams within a
  stream family (contrast the Multi-stream Stream channel `0x000C`).
- **Advertisement gate.** A peer that has not advertised the Interaction channel
  during the handshake MUST NOT receive frames on it; frames on an unadvertised
  Interaction channel MUST be dropped (core specification §5, applied to `0x000F`).

## 3. Frame types

Frame types on the Interaction channel are drawn from the same per-channel
`0x0000`–`0xFFFF` frame-type namespace every N-PAMP channel uses
(core specification §4.6; reference `../04_frame_types.md`). Two groups are
relevant to this channel, and a third is explicitly empty.

### 3.1 Reserved all-channel frame types

The following frame types are reserved across **all** channels with the same
meaning everywhere and retain that meaning on the Interaction channel. An
implementation MUST NOT reuse them for Interaction application traffic.

| Type | Name | Meaning on the Interaction channel |
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

### 3.2 Reserved Interaction-channel extension frame range

The core specification's Reserved Frame-Type Ranges table (core specification §8.1,
Extension Points; references `../04_frame_types.md` and `../09_extension_points.md`)
reserves several sub-`0x0100` frame-type ranges for companion extensions — but
**none of those ranges is assigned to the Interaction channel**. The reserved
ranges there belong to the Memory, Capability, Control, Audit, Settlement/Audit,
Governance, and Immune channels:

| Range | Reserved for |
|---|---|
| `0x0035` – `0x0036` | Memory-channel eviction and revive extension frames |
| `0x0060` – `0x0063` | Capability-channel token extension frames |
| `0x0080` – `0x0080` | Control-channel flow-extension frames |
| `0x0090` – `0x0090` | Audit-channel per-frame integrity-extension frames |
| `0x00A0` – `0x00A3` | Settlement/Audit batch-commitment extension frames |
| `0x00B0` – `0x00B4` | Governance-channel quorum extension frames |
| `0x00C0` – `0x00C4` | Immune-channel propagation extension frames |

The Interaction channel therefore has **no** core-reserved sub-`0x0100` extension
frame range of its own. An implementation MUST NOT treat any of the ranges above as
Interaction frames, and MUST NOT assign an Interaction-specific meaning to any code
point the core specification reserves for another channel.

> **Known editorial inconsistency in -00 (carried, not corrected here).** The core
> specification states that channel-specific frame types begin at `0x0100`
> (§4.6), yet the reserved companion ranges above sit below `0x0100`
> (`0x0035`–`0x00C4`). This inconsistency is present in the submitted draft and is
> recorded in `../04_frame_types.md`; this reference does not silently rewrite the
> authoritative text. Because no reserved sub-`0x0100` range is assigned to the
> Interaction channel, the inconsistency does not affect this channel.

### 3.3 Channel-specific frame types (`0x0100`+ convention)

Channel-specific frame types begin at **`0x0100`** within each channel's frame
namespace (core specification §4.6). This is the range in which an
Interaction-specific operation encoding — for example concrete user-interface-event
request and reply frames (§4) — would be assigned. The core specification defines
**no** Interaction-specific frame type in this range, and no companion
specification in the current set (`../companion/00_companion_index.md`) defines an
Interaction-**native** frame here. Consequently there is, at present, no core- or
companion-defined native Interaction operation frame; §4 describes the interface at
the registry level the core specification actually fixes.

A deployment that OPTIONALLY carries a foreign agent-to-human interaction protocol
on this channel (per the channel-selection guidance discussed in §6) does so under
the **NPAMP-BRIDGE** frame types, which also occupy the `0x0100`+ namespace
(`../companion/10_bridge_framework.md`). Those are the bridge framework's frames
used on this channel by a deployment choice, **not** a native Interaction encoding;
this reference defines no Interaction-native frame in the `0x0100`+ range.

## 4. Interface and operations (public level)

The Interaction channel's public interface is the traffic class named by its
registry purpose. The core specification fixes this as the **name of a traffic
class**, not as a wire encoding; this section restates it at that level and states
explicitly where the core specification stops. An implementation MUST NOT read a
wire format into this section: no frame layout, field structure, TLV, event schema,
event vocabulary, or correlation scheme below is defined by the core specification.

| Traffic class | Public meaning (from the registry purpose) |
|---|---|
| Agent-to-human user-interface events | Convey user-interface events between an agent and a human party — an agent surfacing events to the human's user interface, and the human's client returning interaction events to the agent. |

Notes and honest boundaries:

- **No event schema or vocabulary is defined here.** The core specification names
  the traffic class ("agent-to-human user-interface events") but defines **no**
  event type, event vocabulary, field set, or encoding for it. This reference does
  not manufacture a taxonomy of user-interface events, and MUST NOT be cited as the
  source of one. A companion specification MAY define such a vocabulary and its
  encoding precisely.
- **No operation encoding is defined here.** Because the core specification assigns
  no Interaction-specific frame type (§3.3) and reserves no Interaction frame-type
  range (§3.2), the traffic class above has **no core-defined request frame, reply
  frame, event identifier scheme, value encoding, correlation scheme, or error
  model**. This reference MUST NOT be cited as the source of any such encoding.
- **Direction and origination.** Because the channel is Bidirectional (§2), the
  agent MAY emit user-interface events toward the human's client and the human's
  client MAY return interaction events toward the agent on the same channel; the
  core specification imposes no fixed originator/consumer assignment at the channel
  level and defines no per-direction event vocabulary.
- **Correlation and ordering.** The Interaction channel has an independent
  per-direction sequence space (core specification §5), which orders frames within a
  direction. The core specification does not define how an Interaction reply (if
  any) is correlated to a request (unlike the Bridge channel, where NPAMP-BRIDGE §5
  defines a `correlation_id`); an Interaction operation encoding, when specified by
  a companion, is where such correlation would be defined. This reference does not
  define it.
- **Foreign interaction protocols ride the bridge framework, not a native
  encoding.** A deployment MAY carry a foreign agent-to-human interaction protocol
  (for example the Agent-User Interaction Protocol, AG-UI) on this channel, but it
  does so under the NPAMP-BRIDGE encapsulation and the relevant carriage class, not
  under a core-defined Interaction encoding (§6). The behavior of such traffic is
  defined by that carriage class and mapping, not by this channel's native
  interface.

## 5. Profile applicability

The Interaction channel's minimum profile is **Standard** (§2). By the core
specification's min-profile rule (§5), the channel is available at the Standard
profile and at every higher profile; that is, at **Standard, High, and Sovereign**.
There is no profile at which the Interaction channel is unavailable once its
minimum profile is met, and no upper profile bound.

- **Standard profile.** The Interaction channel is available and MAY be enabled.
  This is the profile at which the public Interaction interface described in this
  reference is fully expressible.
- **Higher profiles (High, Sovereign).** The Interaction channel remains available
  with the same wire-level frame namespace and the same public interface. N-PAMP's
  three profiles (Standard, High, Sovereign) share **one wire format** and differ in
  the cryptographic primitives and operational requirements they mandate
  (core specification, Profile Negotiation). The Interaction channel's framing and
  interface — its identity (§2), its frame-type namespace (§3), and its
  registry-level traffic-class interface (§4) — are **profile-invariant**: they do
  not change across profiles. The per-profile cryptographic suites are selected by
  the core specification's profile negotiation and key schedule and are **out of
  scope for this per-channel interface reference**.
- **Scheduling.** The core specification's congestion-scheduling recommendation
  names the **Control and Immune** channels as ones that SHOULD be scheduled at
  higher priority than the **bulk** channels (Memory, Sensory, Telemetry) during
  congestion (core specification §5). The Interaction channel is named in **neither**
  set: the core specification places it in neither the higher-priority group nor the
  bulk group, and gives it no specific scheduling classification. This reference does
  not manufacture one.
- **Publishing scope.** This reference documents only the public **Standard-profile
  interface surface** of the channel — its identity, purpose, direction, minimum
  profile, and public frame-type namespace. High- and Sovereign-profile
  cryptographic internals and parameters are governed by the core specification's
  profile negotiation and are out of scope here.

## 6. Relationship to companion specifications

The Interaction channel is a **native core channel**: unlike the Bridge channel
(`0x000D`), which encapsulates foreign agent protocols and is elaborated by the
NPAMP-BRIDGE companion framework (`../companion/10_bridge_framework.md`) and its
carriage classes, and unlike the Discovery channel (`0x0010`), elaborated by
NPAMP-DISC (`../companion/40_discovery.md`), the Interaction channel has **no
dedicated companion specification** that defines a native Interaction operation
encoding, in the current companion set (`../companion/00_companion_index.md`). It is
therefore not itself a bridge carriage class and defines no native interface that
builds on NPAMP-BRIDGE.

The Interaction channel does, however, appear in the companion index's
**"Channel selection for carriage"** guidance (`../companion/00_companion_index.md`).
That guidance names the Interaction channel `0x000F` as the more-specific core
channel whose purpose corresponds to the foreign-traffic class **"agent-to-human
interaction and user-interface events."** Consequently:

- **Optional bridge carriage on this channel.** A deployment MAY carry foreign
  agent-to-human interaction / user-interface-event traffic on the Interaction
  channel `0x000F` **instead of, or in addition to,** the Bridge channel `0x000D`,
  where its deployment model aligns that traffic with this channel's purpose. When it
  does, the traffic is carried under the **NPAMP-BRIDGE** framing
  (`../companion/10_bridge_framework.md`) and the relevant carriage class — for
  event-stream user-interface protocols, the streaming carriage class
  **NPAMP-CC-STREAM** (`../companion/23_carriage_streaming.md`). Such traffic uses
  the NPAMP-BRIDGE `0x0100`+ frame types and envelope on this channel (§3.3); the
  core specification defines **no** native Interaction encoding, so this is a
  carriage choice, not a native Interaction operation set.
- **Concrete example — AG-UI.** The AG-UI mapping NPAMP-MAP-AGUI
  (`../companion/64_map_agui.md`) carries the Agent-User Interaction Protocol under
  NPAMP-CC-STREAM. It rides the Bridge channel `0x000D` by default and, per its §7,
  a deployment MAY instead or additionally carry its traffic on the Interaction
  channel `0x000F` where the deployment aligns AG-UI with this channel's purpose —
  still under the NPAMP-BRIDGE / NPAMP-CC-STREAM framing, not under a distinct
  Interaction-native encoding, and never splitting a single run across the Bridge
  and Interaction channels. This is an example of the carriage choice above, not a
  redefinition of this channel's native interface.

The consequence for an implementer is that the Interaction channel's **native**
public contract is exactly what §2–§5 restate:

- Its **identity** — id `0x000F`, name Interaction, purpose "agent-to-human
  user-interface events", minimum profile Standard, direction Bidirectional (§2);
- Its **public interface** — the agent-to-human user-interface-event traffic class,
  described at the registry level, with **no core-defined wire encoding** (§4); and
- Its **reserved extension surface** — **none** at the frame-type level: the core
  specification reserves no Interaction-specific frame-type range, and no current
  companion defines a native Interaction frame in the `0x0100`+ namespace (§3.2,
  §3.3).

Should richer, interoperable Interaction traffic be wanted, two paths exist, both
already available. A deployment MAY carry a foreign agent-to-human interaction
protocol on this channel today via NPAMP-BRIDGE and a carriage class (or Class
OPAQUE for an unmapped protocol), as above; or a future companion specification MAY
define a native Interaction operation encoding within the channel-specific `0x0100`+
code points, verified against the core specification. Until such a companion exists,
an implementation carries native Interaction traffic under the channel identity
above, and there is no additional core- or companion-defined **native** Interaction
behavior to conform to. This reference documents the interface at that public level
and defines no new behavior.

## 7. Conformance

An implementation conforms to this Interaction-channel interface reference if and
only if, for channel `0x000F`, it:

1. Treats channel `0x000F` as the **Interaction** channel whose purpose is
   agent-to-human user-interface events, consistent with the core channel registry
   (§2), and does not repurpose the channel identifier for other traffic;
2. Enables the Interaction channel only at the **Standard** profile or higher, never
   below Standard, and — once Standard is met — treats the channel as available at
   Standard, High, and Sovereign (§2, §5);
3. Drops any frame received on the Interaction channel that the peer has not
   advertised during the handshake, and does not deliver such frames to the
   interaction consumer (§2);
4. Preserves the core meaning of the reserved all-channel frame types
   (`0x0001`–`0x000A`) on the Interaction channel and does not reuse any of them for
   Interaction application traffic (§3.1);
5. Assigns **no** Interaction-specific meaning to any core-reserved sub-`0x0100`
   frame-type range, because the core specification reserves no such range for the
   Interaction channel (§3.2), and places any future Interaction-native operation
   encoding only in the channel-specific `0x0100`+ namespace (§3.3);
6. Does not treat the traffic-class description in §4 as a normative wire encoding,
   and does not cite this reference as the source of any Interaction event schema,
   event vocabulary, request frame, reply frame, correlation scheme, or error model,
   none of which the core specification defines for this channel (§3.3, §4);
7. Supports the channel's **Bidirectional** direction — both peers sending and
   receiving on a single stream, each maintaining independent per-direction sequence
   spaces and traffic keys — and does not open multiple concurrent transport streams
   within the channel as though it were Multi-stream (§2); and
8. Where it OPTIONALLY carries foreign agent-to-human interaction traffic on this
   channel (§6), does so only under NPAMP-BRIDGE and the relevant carriage class or
   mapping, treating the foreign message as opaque and octet-exact, and does not rely
   on any native Interaction behavior this page defines beyond the core registry
   line — deferring all Interaction-native operation semantics beyond the
   registry-level interface of §4 to a future companion specification and adding no
   native Interaction behavior of its own that the core specification does not
   reserve (§4, §6).

A conformance test suite SHOULD assert each clause above, and in particular SHOULD
verify clause 5 by confirming that an implementation does not emit or honor any
sub-`0x0100` frame as an Interaction-defined operation, and clause 3 by confirming
that an Interaction frame arriving on an unadvertised channel is dropped.
