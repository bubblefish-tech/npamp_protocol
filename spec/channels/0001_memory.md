# NPAMP-CH-0001 — Memory Channel (`0x0001`) Interface Reference (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is a **per-channel interface reference** for the N-PAMP
> Memory channel (`0x0001`), derived from the N-PAMP core specification
> (draft-bubblefish-npamp-01, the "core specification"), §5 Channel Architecture
> and §8 Extension Points. It restates the channel's registry entry and its public
> frame-type reservations and describes the channel's persistent-state
> create/read/update/delete and retrieval interface **at the public level only**.
> It builds on the core specification, introduces no change to the core wire
> format, and defines no behavior the core specification does not already reserve.
> Where the core specification supplies only a registry line or reserves a code
> point without defining its semantics, this reference says so and describes the
> interface at that level. **The draft governs**: on any disagreement between this
> reference and the core specification, the core specification is authoritative.

## 1. Purpose

The core specification assigns channel `0x0001` the name **Memory** and the
purpose **"Persistent-state create/read/update/delete and retrieval"**
(core specification §5, Core Channel Registry). Expanded, the Memory channel is
the N-PAMP channel over which a peer manages **durable, addressable state** held
by another peer: the class of traffic that establishes state, reads it back,
changes it in place, removes it, and retrieves it — as distinct from ephemeral
signalling (Control `0x0000`), streamed media (Stream `0x000C`), or ranked
retrieval with provenance (Knowledge `0x0012`). "Persistent" distinguishes this
channel from transient message exchange: state written on the Memory channel is
intended to outlive the individual frame that wrote it and to remain readable by
subsequent operations until it is updated, deleted, or (via the reserved
extension frames of §3) evicted.

The core specification defines the Memory channel **only** as this registry entry
plus a reserved frame-type range for eviction and revive extension frames
(§3); it does not define a Memory-specific wire encoding, message schema, or
operation contract. Accordingly, this reference describes the Memory interface at
the level the core specification actually fixes — the operation *classes* named by
the registry purpose (§4) — and does not invent frame layouts, field structures,
or semantics that the core specification does not state. A future companion
specification MAY define a concrete Memory operation encoding within the code
points the core specification reserves; until then, the public Memory interface is
exactly what this reference restates.

## 2. Channel identity

The following values are taken verbatim from the core channel registry
(core specification §5; machine-readable form `../../registries/channels.csv`). They are
normative in the core specification; this reference restates them and does not
alter them.

| Attribute | Value |
|---|---|
| Channel ID | `0x0001` |
| Name | Memory |
| Purpose | Persistent-state create/read/update/delete and retrieval |
| Minimum profile | Standard |
| Direction | Multi-stream |

- **Minimum profile — Standard.** The Memory channel MAY be enabled at the
  Standard profile and is available at Standard and at every higher profile
  (High, Sovereign), per the core specification's min-profile rule
  (§5: the minimum profile is the lowest profile at which a channel may be
  enabled). See §5 for profile applicability.
- **Direction — Multi-stream.** Memory is bidirectional, and the channel MAY open
  multiple concurrent transport streams within its stream family
  (core specification §5, Channel directionality). Each peer maintains an
  independent per-direction sequence space and independent per-direction traffic
  keys for the channel (core specification §5).
- **Advertisement gate.** A peer that has not advertised the Memory channel during
  the handshake MUST NOT receive frames on it; frames on an unadvertised Memory
  channel MUST be dropped (core specification §5, applied to `0x0001`).

## 3. Frame types

Frame types on the Memory channel are drawn from the same per-channel
`0x0000`–`0xFFFF` frame-type namespace every N-PAMP channel uses
(core specification §4.6; reference `../04_frame_types.md`). Three groups are
relevant to this channel.

### 3.1 Reserved all-channel frame types

The following frame types are reserved across **all** channels with the same
meaning everywhere and retain that meaning on the Memory channel. An
implementation MUST NOT reuse them for Memory application traffic.

| Type | Name | Meaning on the Memory channel |
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

### 3.2 Reserved Memory-channel extension frame range

The core specification reserves one per-channel frame-type range specifically for
the Memory channel (core specification §8, Reserved Frame-Type Ranges; reference
`../09_extension_points.md`):

| Range | Reserved for |
|---|---|
| `0x0035` – `0x0036` | Memory-channel eviction and revive extension frames |

This range is **reserved, not defined**. The core specification neither defines
nor requires eviction or revive frames; it only reserves the code points so a
companion specification can define them without colliding with the core wire
format (core specification §8). No companion specification in the current set
(`../companion/00_companion_index.md`) defines these frames. An implementation
therefore MUST NOT treat any eviction or revive behavior as specified by the core
specification, and MUST NOT assign `0x0035`–`0x0036` to any other purpose.

> **Known editorial inconsistency in -00 (carried, not corrected here).** The core
> specification states that channel-specific frame types begin at `0x0100`
> (§4.6), yet the reserved Memory extension range `0x0035`–`0x0036` sits below
> `0x0100`. This inconsistency is present in the submitted draft and is recorded
> in `../04_frame_types.md`; this reference does not silently rewrite the
> authoritative text.

### 3.3 Channel-specific frame types (`0x0100`+ convention)

Channel-specific frame types begin at **`0x0100`** within each channel's frame
namespace (core specification §4.6). This is the range in which a Memory-specific
operation encoding — for example concrete create/read/update/delete/retrieval
request and reply frames (§4) — would be assigned. The core specification defines
**no** Memory-specific frame type in this range, and no companion specification in
the current set defines one. Consequently there is, at present, no core- or
companion-defined Memory operation frame; §4 describes the interface at the
registry level the core specification actually fixes.

## 4. Interface and operations (public level)

The Memory channel's public interface is the set of operation classes named by its
registry purpose. The core specification fixes these as **names of operation
classes**, not as wire encodings; this section restates them at that level and
states explicitly where the core specification stops. An implementation MUST NOT
read a wire format into this section: no frame layout, field structure, TLV, or
correlation scheme below is defined by the core specification.

| Operation class | Public meaning (from the registry purpose) |
|---|---|
| Create | Establish a new persistent-state item on the peer's memory store. |
| Read | Return the current state of an identified persistent-state item. |
| Update | Change the state of an existing persistent-state item. |
| Delete | Remove a persistent-state item, ending its persistence. |
| Retrieval | Obtain persistent state, potentially spanning more than one item, as the registry names distinctly from a point Read. |

Notes and honest boundaries:

- **"Read" versus "retrieval".** The registry purpose lists both
  ("create/read/update/delete **and retrieval**"). The core specification does not
  further distinguish a single-item read from a multi-item or query-style
  retrieval; this reference records that both terms appear and does not manufacture
  a distinction the core specification does not state. A companion specification
  MAY define the distinction precisely.
- **Eviction and revive.** The only Memory-specific lifecycle operations the core
  specification names beyond CRUD and retrieval are **eviction** and **revive**,
  and it names them only by reserving frame code points for them
  (`0x0035`–`0x0036`, §3.2). Their semantics are undefined by the core
  specification and out of scope for this reference until a companion defines them.
- **No operation encoding is defined here.** Because the core specification assigns
  no Memory-specific frame type (§3.3), the operation classes above have **no
  core-defined request frame, reply frame, addressing scheme, value encoding, or
  error model**. This reference MUST NOT be cited as the source of any such
  encoding.
- **Correlation and ordering.** The Memory channel has an independent per-direction
  sequence space (core specification §5), which orders frames within a direction.
  The core specification does not define how a Memory reply is correlated to its
  request (unlike the Bridge channel, where NPAMP-BRIDGE §5 defines a
  `correlation_id`); a Memory operation encoding, when specified by a companion,
  is where such correlation would be defined. This reference does not define it.
- **Multi-stream concurrency.** Because the channel is Multi-stream (§2), a
  deployment MAY carry concurrent Memory operations over multiple transport streams
  within the channel's stream family; the core specification permits this at the
  channel level and does not constrain how operations are distributed across those
  streams.

## 5. Profile applicability

The Memory channel's minimum profile is **Standard** (§2). By the core
specification's min-profile rule (§5), the channel is available at the Standard
profile and at every higher profile; that is, at **Standard, High, and
Sovereign**. There is no profile at which the Memory channel is unavailable once
its minimum profile is met, and no upper profile bound.

- **Standard profile.** The Memory channel is available and MAY be enabled. This is
  the profile at which the public Memory interface described in this reference is
  fully expressible.
- **Higher profiles (High, Sovereign).** The Memory channel remains available with
  the same wire-level frame namespace and the same public interface. N-PAMP's
  profiles share one wire format and differ in the cryptographic primitives and
  operational requirements they mandate (core specification §6, Profile
  Negotiation). The specific cryptographic suite bound to each profile is defined
  by the core specification's profile-negotiation and cryptographic-suite sections
  and is **out of scope for this interface reference**; this reference describes
  the channel's public, profile-invariant interface only.
- **Scheduling.** The core specification classes Memory among the **bulk** channels
  and states that the Control and Immune channels SHOULD be scheduled at higher
  priority than the bulk channels (Memory, Sensory, Telemetry) during congestion
  (core specification §5). This is a scheduling recommendation, not a change to the
  Memory interface.

## 6. Relationship to companion specifications

The Memory channel is a **native core channel**: unlike the Bridge channel
(`0x000D`), which encapsulates foreign agent protocols and is elaborated by the
NPAMP-BRIDGE companion framework (`../companion/10_bridge_framework.md`) and its
carriage classes, and unlike the Discovery channel (`0x0010`), elaborated by
NPAMP-DISC (`../companion/40_discovery.md`), the Memory channel has **no
dedicated companion specification** in the current companion set
(`../companion/00_companion_index.md`). It is therefore not a bridge carriage
class and does not build on NPAMP-BRIDGE.

The consequence for an implementer is that the Memory channel's public contract is
exactly what §2–§5 restate:

- Its **identity** — id `0x0001`, name Memory, purpose "persistent-state
  create/read/update/delete and retrieval", minimum profile Standard, direction
  Multi-stream (§2);
- Its **public interface** — the create/read/update/delete and retrieval operation
  classes, described at the registry level, with **no core-defined wire encoding**
  (§4);
- Its **reserved extension surface** — the `0x0035`–`0x0036` eviction/revive
  frame-type range, reserved by the core specification and defined by neither the
  core specification nor any current companion (§3.2).

Should richer, interoperable Memory operations be wanted, the path is the same as
for any N-PAMP extension: author a companion specification that defines a Memory
operation encoding within the reserved code points, verified against the core
specification. Until such a companion exists, an implementation carries Memory
traffic under the channel identity and reserved code points above, and there is no
additional core- or companion-defined Memory behavior to conform to. This
reference documents the interface at that public level and defines no new behavior.

## 7. Conformance

An implementation conforms to this Memory-channel interface reference if and only
if, for channel `0x0001`, it:

1. Treats channel `0x0001` as the **Memory** channel whose purpose is
   persistent-state create/read/update/delete and retrieval, consistent with the
   core channel registry (§2), and does not repurpose the channel identifier
   for other traffic;
2. Enables the Memory channel only at the **Standard** profile or higher, never
   below Standard, and — once Standard is met — treats the channel as available at
   Standard, High, and Sovereign (§2, §5);
3. Drops any frame received on the Memory channel that the peer has not advertised
   during the handshake, and does not deliver such frames to the memory store
   (§2);
4. Preserves the core meaning of the reserved all-channel frame types
   (`0x0001`–`0x000A`) on the Memory channel and does not reuse any of them for
   Memory application traffic (§3.1);
5. Treats the frame-type range `0x0035`–`0x0036` as **reserved** for Memory
   eviction and revive extension frames, assigns it to no other purpose, and does
   **not** claim eviction or revive behavior as specified by the core
   specification, because the core specification reserves that range without
   defining its semantics (§3.2);
6. Does not treat any operation description in §4 as a normative wire encoding, and
   does not cite this reference as the source of any Memory request frame, reply
   frame, addressing scheme, value encoding, correlation scheme, or error model,
   none of which the core specification defines for this channel (§3.3, §4);
7. Supports the channel's **Multi-stream** direction — bidirectional operation with
   the OPTIONAL opening of multiple concurrent transport streams within the
   channel's stream family, each peer maintaining independent per-direction
   sequence spaces and traffic keys (§2, §4); and
8. Defers all Memory operation semantics beyond the registry-level interface of §4
   to a future companion specification, adding no Memory behavior of its own that
   the core specification does not reserve (§6).

A conformance test suite SHOULD assert each clause above, and in particular SHOULD
verify clause 5 by confirming that an implementation does not advertise, emit, or
honor any frame in `0x0035`–`0x0036` as a defined eviction or revive operation on
the sole basis of the core specification, and clause 3 by confirming that a Memory
frame arriving on an unadvertised channel is dropped.
