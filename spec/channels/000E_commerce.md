# NPAMP-CH-000E — Commerce Channel (`0x000E`) Interface Reference (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is a **per-channel interface reference** for the N-PAMP
> Commerce channel (`0x000E`), derived from the N-PAMP core specification
> (draft-bubblefish-npamp-01, the "core specification"), §5 Channel Architecture
> and §8 Extension Points. It restates the channel's registry entry and its public
> frame-type reservations and describes the channel's multi-party agentic commerce
> and payment-mandate interface **at the public level only**. It builds on the core
> specification, introduces no change to the core wire format, and defines no
> behavior the core specification does not already reserve. Where the core
> specification supplies only a registry line or reserves a code point without
> defining its semantics, this reference says so and describes the interface at that
> level. **The draft governs**: on any disagreement between this reference and the
> core specification, the core specification is authoritative.

## 1. Purpose

The core specification assigns channel `0x000E` the name **Commerce** and the
purpose **"Multi-party agentic commerce and payment mandates"** (core specification
§5, Core Channel Registry; `../../registries/channels.csv`). Expanded, the Commerce
channel is the N-PAMP channel over which peers conduct **agentic commerce and carry
payment mandates** — the class of traffic by which agents transact commercially and
by which a **payment mandate** (an authorization-to-pay artifact) is carried between
them. This is distinct from **Settlement** (`0x0007`, "Agent-to-agent settlement and
receipts"; `./0007_settlement.md`), which the core specification reserves for
recording that a bilateral obligation has been settled and returning its receipt,
and from **Audit** (`0x000B`, "Audit-epoch commitments and transparency-log
entries"), which it reserves for audit-epoch commitment. The core specification
names Commerce, Settlement, and Audit as three distinct channels with three distinct
registry purposes; it does not define a handoff or ordering among them, and this
reference does not manufacture one.

The core specification defines the Commerce channel **only** as this registry entry;
unlike the Memory channel (`0x0001`; `./0001_memory.md`) and the Settlement channel
(`0x0007`), it reserves **no** per-channel frame-type range for Commerce at all
(§3). It does not define a Commerce-specific wire encoding, message schema, mandate
format, party model, value or amount representation, or multi-party coordination
mechanism. Accordingly, this reference describes the Commerce interface at the level
the core specification actually fixes — the traffic *classes* named by the registry
purpose (§4) — and does not invent frame layouts, field structures, or semantics
that the core specification does not state. A future companion specification MAY
define a concrete Commerce operation encoding within the code points the core
specification reserves — and the companion specification **NPAMP-COMMERCE**
(`../companion/88_commerce_channel.md`) now does so, defining native
payment-mandate-lifecycle and multi-party settlement-intent operation frames in the
`0x0100`+ channel-specific namespace; the core specification itself still neither
defines nor requires them. Beyond that companion-defined encoding, the public
Commerce interface is exactly what this reference restates, together with the
foreign-protocol carriage the companion set routes onto this channel (§6).

## 2. Channel identity

The following values are taken verbatim from the core channel registry
(core specification §5; machine-readable form `../../registries/channels.csv`). They
are normative in the core specification; this reference restates them and does not
alter them.

| Attribute | Value |
|---|---|
| Channel ID | `0x000E` |
| Name | Commerce |
| Purpose | Multi-party agentic commerce and payment mandates |
| Minimum profile | Standard |
| Direction | Bidirectional |

- **Minimum profile — Standard.** The Commerce channel MAY be enabled at the
  Standard profile and is available at Standard and at every higher profile
  (High, Sovereign), per the core specification's min-profile rule (§5: the minimum
  profile is the lowest profile at which a channel may be enabled). See §5 for
  profile applicability.
- **Direction — Bidirectional.** Both peers send and receive frames on a single
  stream of this channel (core specification §5, Channel directionality). As with
  every N-PAMP channel, each peer maintains an independent send and receive
  sequence space and independent per-direction traffic keys, so both peers MAY
  transmit on the channel simultaneously (core specification §5). The Commerce
  channel is **not** classified Multi-stream; it does not open multiple concurrent
  transport sub-streams within a stream family (contrast the Memory channel
  `0x0001` and the Stream channel `0x000C`). The registry purpose names
  **multi-party** commerce, but the channel's directionality is a two-peer
  bidirectional stream; the core specification defines no multi-party fan-out,
  party model, or coordination mechanism at the channel level (§4).
- **Advertisement gate.** A peer that has not advertised the Commerce channel
  during the handshake MUST NOT receive frames on it; frames on an unadvertised
  Commerce channel MUST be dropped (core specification §5, applied to `0x000E`).

## 3. Frame types

Frame types on the Commerce channel are drawn from the same per-channel
`0x0000`–`0xFFFF` frame-type namespace every N-PAMP channel uses
(core specification §4.6; reference `../04_frame_types.md`). Three groups are
relevant to this channel.

### 3.1 Reserved all-channel frame types

The following frame types are reserved across **all** channels with the same
meaning everywhere and retain that meaning on the Commerce channel. An
implementation MUST NOT reuse them for Commerce application traffic.

| Type | Name | Meaning on the Commerce channel |
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

### 3.2 No reserved Commerce-channel extension frame range

The core specification's Reserved Frame-Type Ranges table (core specification §8,
Reserved Frame-Type Ranges; references `../04_frame_types.md` and
`../09_extension_points.md`) reserves several sub-`0x0100` code-point ranges for
companion extensions — but **none of those ranges is assigned to the Commerce
channel.** The reserved ranges there belong to the Memory, Capability, Control,
Audit, Settlement/Audit, Governance, and Immune channels:

| Range | Reserved for |
|---|---|
| `0x0035` – `0x0036` | Memory-channel eviction and revive extension frames |
| `0x0060` – `0x0063` | Capability-channel token extension frames |
| `0x0080` – `0x0080` | Control-channel flow-extension frames |
| `0x0090` – `0x0090` | Audit-channel per-frame integrity-extension frames |
| `0x00A0` – `0x00A3` | Settlement/Audit batch-commitment extension frames |
| `0x00B0` – `0x00B4` | Governance-channel quorum extension frames |
| `0x00C0` – `0x00C4` | Immune-channel propagation extension frames |

The Commerce channel therefore has **no** core-reserved per-channel extension
frame-type range of its own. An implementation MUST NOT assign any of the ranges
above to Commerce traffic, and MUST NOT treat any code point in them as a
Commerce-channel frame.

> **Known editorial inconsistency in -00 (carried, not corrected here).** The core
> specification states that channel-specific frame types begin at `0x0100`
> (§4.6), yet the reserved ranges above sit below `0x0100` (`0x0035`–`0x00C4`).
> This inconsistency is present in the submitted draft and is recorded in
> `../04_frame_types.md`; it does not affect the Commerce channel, which is assigned
> no sub-`0x0100` reserved range, and this reference does not silently rewrite the
> authoritative text.

### 3.3 Channel-specific frame types (`0x0100`+ convention)

Channel-specific frame types begin at **`0x0100`** within each channel's frame
namespace (core specification §4.6). This is the range in which a Commerce-specific
operation encoding — for example concrete commerce or payment-mandate request and
reply frames (§4) — would be assigned. The core specification defines **no**
Commerce-specific frame type in this range. The companion specification
**NPAMP-COMMERCE** (`../companion/88_commerce_channel.md`) now defines
Commerce-native operation frames in this range — native payment-mandate-lifecycle
and multi-party settlement-intent request/result frames at code points
`0x0100`–`0x010E`; the core specification itself still neither defines nor requires
them. Where a deployment uses those operations they are governed by NPAMP-COMMERCE;
§4 describes the registry-level interface the core specification actually fixes.

Where a deployment carries a **foreign** commerce protocol on this channel by
routing NPAMP-BRIDGE encapsulation onto it (§6), that traffic occupies the
`0x0100`+ namespace using the frame types **NPAMP-BRIDGE** defines
(`../companion/10_bridge_framework.md` §2), not frame types this channel or the core
specification defines. Those frame types are governed by NPAMP-BRIDGE and the
relevant carriage class; this reference does not restate them and does not define a
competing Commerce-native frame type.

## 4. Interface and operations (public level)

The Commerce channel's public interface is the set of traffic classes named by its
registry purpose. The core specification fixes these as **names of traffic
classes**, not as wire encodings; this section restates them at that level and
states explicitly where the core specification stops. An implementation MUST NOT
read a wire format into this section: no frame layout, field structure, TLV, mandate
format, value representation, party model, or correlation scheme below is defined by
the core specification.

| Traffic class | Public meaning (from the registry purpose) |
|---|---|
| Agentic commerce | Commercial interaction conducted among agents — the class of traffic by which agents transact. The registry names it "multi-party". |
| Payment mandate | Carriage of a payment mandate — an authorization-to-pay artifact — between the peers. |

Notes and honest boundaries:

- **"Commerce" versus "payment mandates".** The registry purpose lists both
  ("multi-party agentic commerce **and payment mandates**"). The core specification
  names agentic commerce and the payment mandate as the channel's two traffic
  classes but does not further define how commerce is expressed, what a mandate is
  an authorization over, or what a mandate contains; this reference records that both
  terms appear and does not manufacture a structure the core specification does not
  state. The companion specification **NPAMP-COMMERCE**
  (`../companion/88_commerce_channel.md`) now defines the payment-mandate lifecycle
  precisely; the core specification itself still does not.
- **"Multi-party" is named, not defined.** The registry purpose says **multi-party**,
  yet the channel is a two-peer, Bidirectional single-stream association (§2). The
  core specification defines **no** multi-party fan-out, party enumeration,
  coordination, routing, or settlement-of-multiple-parties mechanism at the channel
  level. This reference MUST NOT be read to define one; multi-party coordination,
  where wanted, is the province of a foreign commerce protocol carried over the
  channel (§6) or of the Commerce-native companion **NPAMP-COMMERCE**
  (`../companion/88_commerce_channel.md`), which defines multi-party settlement-intent
  operations, not of the core Commerce registry line.
- **No mandate, value, or ledger schema is defined here.** The registry purpose does
  not fix a currency, amount, asset, mandate serialization, or ledger model, and the
  core specification defines **no** commerce or payment-mandate message schema, value
  or amount encoding, or receipt format for this channel. This reference MUST NOT be
  cited as the source of any such encoding. Settlement and receipt semantics are the
  registry purpose of the **Settlement** channel (`0x0007`; `./0007_settlement.md`),
  not of this channel; the core specification names the two channels distinctly and
  defines the encoding of neither.
- **No operation encoding is defined here.** Because the core specification assigns
  no Commerce-specific frame type (§3.3), the traffic classes above have **no
  core-defined request frame, reply frame, addressing scheme, mandate encoding, value
  encoding, or error model**. This reference describes the interface at the registry
  level only.
- **Correlation and ordering.** The Commerce channel has an independent per-direction
  sequence space (core specification §5), which orders frames within a direction. The
  core specification does not define how a Commerce reply is correlated to a request
  (unlike the Bridge channel, where NPAMP-BRIDGE §5 defines a `correlation_id`). The
  Commerce-native companion **NPAMP-COMMERCE** (`../companion/88_commerce_channel.md`)
  now defines an in-body correlation token for its operations — or, for a foreign
  commerce protocol routed onto this channel (§6), the NPAMP-BRIDGE correlation
  provides it; the core specification and this reference themselves define neither.
- **Bidirectional single stream.** Because the channel is Bidirectional and not
  Multi-stream (§2), both peers exchange commerce and mandate frames over a single
  stream; either peer MAY originate traffic. The core specification does not assign
  fixed initiator/responder roles at the channel level.
- **Foreign-protocol carriage.** Where commerce is conducted by carrying a foreign
  commerce protocol over this channel (for example AP2, UCP, or AITP; §6), the
  operation semantics are those of that foreign protocol under NPAMP-BRIDGE and the
  relevant carriage class — **not** semantics defined by this channel or the core
  specification. The foreign message is carried transparently; this channel adds no
  commerce semantics of its own.

## 5. Profile applicability

The Commerce channel's minimum profile is **Standard** (§2). By the core
specification's min-profile rule (§5), the channel is available at the Standard
profile and at every higher profile; that is, at **Standard, High, and Sovereign**.
There is no profile at which the Commerce channel is unavailable once its minimum
profile is met, and no upper profile bound.

- **Standard profile.** The Commerce channel is available and MAY be enabled. This
  is the profile at which the public Commerce interface described in this reference
  is fully expressible.
- **Higher profiles (High, Sovereign).** The Commerce channel remains available with
  the same wire-level frame namespace and the same public interface. N-PAMP's
  profiles share **one wire format** and differ in the cryptographic primitives and
  operational requirements they mandate (core specification §6, Profile Negotiation).
  The Commerce channel's framing and interface — its identity (§2), its frame-type
  namespace (§3), and the registry-level traffic classes (§4) — are
  **profile-invariant**: they do not change across profiles. The specific
  cryptographic suite bound to each profile is defined by the core specification's
  profile-negotiation and cryptographic-suite sections and is **out of scope for this
  interface reference**; this reference describes the channel's public,
  profile-invariant interface only.
- **Scheduling.** The core specification's congestion-scheduling recommendation names
  the Control and Immune channels as ones that SHOULD be scheduled at higher priority
  than the bulk channels (Memory, Sensory, Telemetry) during congestion
  (core specification §5). The Commerce channel is named in **neither** set, so the
  core specification assigns it **no explicit congestion-scheduling class**; this
  reference does not invent one.
- **Publishing scope.** This reference documents only the public **Standard-profile
  interface surface** of the channel — its identity, purpose, direction, minimum
  profile, and public frame-type namespace. High- and Sovereign-profile
  cryptographic internals and parameters are governed by the core specification's
  profile negotiation and are out of scope here.

## 6. Relationship to companion specifications

The Commerce channel is a **native core channel**: the core specification defines
the channel's registry entry, not a Commerce-native operation encoding. The
companion specification **NPAMP-COMMERCE** (`../companion/88_commerce_channel.md`)
now provides a dedicated Commerce-native encoding — native payment-mandate-lifecycle
and multi-party settlement-intent operation frames in the `0x0100`+ channel-specific
namespace; the core specification itself still neither defines nor requires them. The
Commerce channel is not itself a bridge carriage class and does not build on
NPAMP-BRIDGE as its native definition.

Unlike the Memory and Settlement channels, however, the Commerce channel **is a
carriage-selection target**. The companion index's "Channel selection for carriage"
table (`../companion/00_companion_index.md`) names the Commerce channel `0x000E` as
the more-specific core channel onto which **payment-mandate and multi-party-commerce
foreign traffic MAY be routed** instead of, or in addition to, the Bridge channel
`0x000D` (`./000D_bridge.md`). When foreign commerce traffic is so routed, it is
carried under **NPAMP-BRIDGE** (`../companion/10_bridge_framework.md`) encapsulation
and the relevant carriage class, occupying the NPAMP-BRIDGE `0x0100`+ frame types
(§3.3); the commerce semantics are the foreign protocol's, and this channel supplies
only the authenticated, post-quantum, per-channel-isolated transport (§4).

The commerce-related thin per-protocol mappings each name the Commerce channel
`0x000E` as this OPTIONAL channel, with the Bridge channel `0x000D` as the default:

- **NPAMP-MAP-AP2** (`../companion/65_map_ap2.md`) — the Agent Payments Protocol
  (AP2): signed payment-mandate documents carried under NPAMP-CC-DOC (or host
  JSON-RPC when AP2 rides A2A), which a deployment MAY carry on the Commerce channel
  `0x000E` for payment-mandate/commerce traffic;
- **NPAMP-MAP-UCP** (`../companion/66_map_ucp.md`) — the Universal Commerce Protocol
  (UCP): REST/HTTP-semantics exchanges carried under NPAMP-CC-HTTP, whose
  payment-mandate/multi-party-commerce traffic MAY use the Commerce channel
  `0x000E`; and
- **NPAMP-MAP-AITP** (`../companion/67_map_aitp.md`) — the Agent Interaction &
  Transaction Protocol (AITP): payment-request/mandate traffic that the mapping
  routes to the Commerce channel `0x000E`.

Each mapping specifies which channel or channels a given protocol's traffic uses; a
mapping document — not this reference and not the core Commerce registry line — is
where the routing of a foreign protocol onto the Commerce channel is fixed, verified
against that protocol's own published specification. A peer MUST NOT send or accept
frames on the Commerce channel it did not advertise during the handshake (core
specification §5). The `protocol_id` a foreign commerce message carries is drawn from
the Bridge Protocol Identifier registry **NPAMP-REG**
(`../companion/30_protocol_registry.md`), and a peer MAY advertise the protocols and
carriage classes it carries over the Discovery channel `0x0010` per **NPAMP-DISC**
(`../companion/40_discovery.md`).

The consequence for an implementer is that the Commerce channel's public contract is
exactly what §2–§5 restate:

- Its **identity** — id `0x000E`, name Commerce, purpose "multi-party agentic
  commerce and payment mandates", minimum profile Standard, direction Bidirectional
  (§2);
- Its **public interface** — the agentic-commerce and payment-mandate traffic
  classes, described at the registry level, with **no core-defined wire encoding**
  (§4); and
- Its **reserved extension surface** — **none**: unlike the Memory and Settlement
  channels, the core specification reserves **no** sub-`0x0100` frame-type range for
  the Commerce channel (§3.2).

Richer, interoperable Commerce operations are available by two paths: carry an
existing foreign commerce protocol over the channel via NPAMP-BRIDGE and its carriage
class under the relevant mapping (as AP2, UCP, and AITP above already provide); or
use the Commerce-native companion specification **NPAMP-COMMERCE**
(`../companion/88_commerce_channel.md`), which defines a commerce operation encoding
within the `0x0100`+ channel-specific namespace, verified against the core
specification. Beyond the registry-level channel identity above, the Commerce-native
operation behavior an implementation conforms to is that defined by NPAMP-COMMERCE;
the core specification itself still neither defines nor requires it. This reference
documents the interface at that public registry level and defines no new behavior of
its own.

## 7. Conformance

An implementation conforms to this Commerce-channel interface reference if and only
if, for channel `0x000E`, it:

1. Treats channel `0x000E` as the **Commerce** channel whose purpose is multi-party
   agentic commerce and payment mandates, consistent with the core channel registry
   (§2), and does not repurpose the channel identifier for other traffic;
2. Enables the Commerce channel only at the **Standard** profile or higher, never
   below Standard, and — once Standard is met — treats the channel as available at
   Standard, High, and Sovereign (§2, §5);
3. Drops any frame received on the Commerce channel that the peer has not advertised
   during the handshake, and does not deliver such frames to commerce processing
   (§2);
4. Preserves the core meaning of the reserved all-channel frame types
   (`0x0001`–`0x000A`) on the Commerce channel and does not reuse any of them for
   Commerce application traffic (§3.1);
5. Recognizes that the core specification reserves **no** sub-`0x0100` per-channel
   frame-type range for the Commerce channel, assigns **none** of the §8 reserved
   ranges (which name the Memory, Capability, Control, Audit, Settlement/Audit,
   Governance, and Immune channels) to Commerce traffic, and treats no code point in
   those ranges as a Commerce-channel frame (§3.2);
6. Does not treat any traffic-class description in §4 as a normative wire encoding,
   does not cite this reference as the source of any Commerce request frame, reply
   frame, mandate encoding, value or amount encoding, party model, multi-party
   coordination mechanism, correlation scheme, or error model — none of which the
   core specification defines for this channel — and does not manufacture multi-party
   commerce semantics the core specification does not state (§3.3, §4);
7. Supports the channel's **Bidirectional** direction — both peers sending and
   receiving commerce and mandate frames over a single stream, each maintaining
   independent per-direction sequence spaces and traffic keys — and does not treat the
   channel as Multi-stream (§2, §4);
8. Where it carries a foreign commerce protocol on this channel, does so only under
   **NPAMP-BRIDGE** and the relevant carriage class as fixed by that protocol's
   mapping (for example NPAMP-MAP-AP2, NPAMP-MAP-UCP, or NPAMP-MAP-AITP), using the
   NPAMP-BRIDGE `0x0100`+ frame types, treating the foreign message's operation
   semantics as the foreign protocol's and not this channel's (§3.3, §6); and
9. Defers all Commerce operation semantics beyond the registry-level interface of §4
   to the Commerce-native companion specification NPAMP-COMMERCE
   (`../companion/88_commerce_channel.md`), adding no Commerce-native behavior of its
   own that the core specification does not reserve (§6).

A conformance test suite SHOULD assert each clause above, and in particular SHOULD
verify clause 5 by confirming that an implementation advertises, emits, or honors no
frame in any of the §8 reserved sub-`0x0100` ranges as a Commerce-channel operation,
and clause 3 by confirming that a Commerce frame arriving on an unadvertised channel
is dropped.
