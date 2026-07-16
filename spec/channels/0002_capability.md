# NPAMP-CH-0002 — Capability Channel (`0x0002`) Interface Reference (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is a **per-channel interface reference** for the N-PAMP
> Capability channel (`0x0002`), derived from the N-PAMP core specification
> (draft-bubblefish-npamp-01, the "core specification"), §5 Channel Architecture
> and §8 Extension Points. It restates the channel's registry entry and its public
> frame-type reservations and describes the channel's capability
> issuance/delegation/revocation/lookup interface **at the public level only**. It
> builds on the core specification, introduces no change to the core wire format,
> and defines no behavior the core specification does not already reserve. Where the
> core specification supplies only a registry line or reserves a code point without
> defining its semantics, this reference says so and describes the interface at that
> level. **The draft governs**: on any disagreement between this reference and the
> core specification, the core specification is authoritative.

## 1. Purpose

The core specification assigns channel `0x0002` the name **Capability** and the
purpose **"Capability issuance, delegation, revocation, lookup"**
(core specification §5, Core Channel Registry). Expanded, the Capability channel is
the N-PAMP channel over which a peer manages **authorizations held by another
peer**: the class of traffic that grants an authority, passes an authority onward,
withdraws an authority, and resolves an authority — as distinct from the
connection-level capability epoch that Control (`0x0000`) carries, and distinct
from the capability *advertisement* that Discovery (`0x0010`) carries. The four
verbs in the registry purpose name four operation classes: **issuance** (grant a
new authority), **delegation** (convey a held authority onward), **revocation**
(withdraw a previously granted authority), and **lookup** (resolve or query an
authority).

The core specification defines the Capability channel **only** as this registry
entry plus a reserved frame-type range for capability token extension frames
(§3); it does not define a Capability-specific wire encoding, capability-token
format, message schema, or operation contract. Accordingly, this reference
describes the Capability interface at the level the core specification actually
fixes — the operation *classes* named by the registry purpose (§4) — and does not
invent frame layouts, field structures, token formats, or semantics that the core
specification does not state. The companion specification NPAMP-CAPABILITY
(`../companion/84_capability_channel.md`) now defines a concrete Capability
operation encoding within the code points the core specification reserves; the
core specification itself still fixes only the registry entry and reserved range
this reference restates.

## 2. Channel identity

The following values are taken verbatim from the core channel registry
(core specification §5; machine-readable form `../../registries/channels.csv`). They are
normative in the core specification; this reference restates them and does not
alter them.

| Attribute | Value |
|---|---|
| Channel ID | `0x0002` |
| Name | Capability |
| Purpose | Capability issuance, delegation, revocation, lookup |
| Minimum profile | Standard |
| Direction | Bidirectional |

- **Minimum profile — Standard.** The Capability channel MAY be enabled at the
  Standard profile and is available at Standard and at every higher profile
  (High, Sovereign), per the core specification's min-profile rule
  (§5: the minimum profile is the lowest profile at which a channel may be
  enabled). See §5 for profile applicability.
- **Direction — Bidirectional.** Both peers send and receive frames on a single
  stream of this channel (core specification §5, Channel directionality). As with
  every N-PAMP channel, each peer maintains an independent send and receive
  sequence space and independent per-direction traffic keys, so both peers MAY
  transmit on the channel simultaneously (core specification §5). The Capability
  channel is **not** classified Multi-stream; it does not open multiple concurrent
  transport sub-streams within a stream family (contrast the Memory channel
  `0x0001` and the Stream channel `0x000C`).
- **Advertisement gate.** A peer that has not advertised the Capability channel
  during the handshake MUST NOT receive frames on it; frames on an unadvertised
  Capability channel MUST be dropped (core specification §5, applied to `0x0002`).

## 3. Frame types

Frame types on the Capability channel are drawn from the same per-channel
`0x0000`–`0xFFFF` frame-type namespace every N-PAMP channel uses
(core specification §4.6; reference `../04_frame_types.md`). Three groups are
relevant to this channel.

### 3.1 Reserved all-channel frame types

The following frame types are reserved across **all** channels with the same
meaning everywhere and retain that meaning on the Capability channel. An
implementation MUST NOT reuse them for Capability application traffic.

| Type | Name | Meaning on the Capability channel |
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

### 3.2 Reserved Capability-channel extension frame range

The core specification reserves one per-channel frame-type range specifically for
the Capability channel (core specification §8, Reserved Frame-Type Ranges;
reference `../09_extension_points.md`):

| Range | Reserved for |
|---|---|
| `0x0060` – `0x0063` | Capability-channel token extension frames |

This range is **reserved, not defined**. The core specification neither defines
nor requires any capability token extension frame; it only reserves the code
points so a companion specification can define them without colliding with the
core wire format (core specification §8). The companion specification NPAMP-CAPABILITY
(`../companion/84_capability_channel.md`) now defines these code points as OPTIONAL
capability token extension frames; the core specification itself still neither defines
nor requires them. An implementation therefore MUST NOT treat any capability token
extension behavior as specified by the core specification — those semantics are defined
by NPAMP-CAPABILITY, not the core — and MUST NOT assign `0x0060`–`0x0063` to any other
purpose.

> **Known editorial inconsistency in -00 (carried, not corrected here).** The core
> specification states that channel-specific frame types begin at `0x0100`
> (§4.6), yet the reserved Capability extension range `0x0060`–`0x0063` sits below
> `0x0100`. This inconsistency is present in the submitted draft and is recorded
> in `../04_frame_types.md`; this reference does not silently rewrite the
> authoritative text.

### 3.3 Channel-specific frame types (`0x0100`+ convention)

Channel-specific frame types begin at **`0x0100`** within each channel's frame
namespace (core specification §4.6). This is the range in which a Capability-specific
operation encoding — for example concrete issuance/delegation/revocation/lookup
request and reply frames (§4) — would be assigned. The core specification defines
**no** Capability-specific frame type in this range; the companion specification
NPAMP-CAPABILITY (`../companion/84_capability_channel.md`) now defines the
issuance/delegation/revocation/lookup request/result frames (`0x0100`–`0x0108`) in
this range, while the core specification itself still defines none. §4 describes the
interface at the registry level the core specification actually fixes; the concrete
operation encoding is defined by NPAMP-CAPABILITY, not by the core specification.

## 4. Interface and operations (public level)

The Capability channel's public interface is the set of operation classes named by
its registry purpose. The core specification fixes these as **names of operation
classes**, not as wire encodings; this section restates them at that level and
states explicitly where the core specification stops. An implementation MUST NOT
read a wire format into this section: no frame layout, field structure, TLV,
capability-token format, or correlation scheme below is defined by the core
specification.

| Operation class | Public meaning (from the registry purpose) |
|---|---|
| Issuance | Grant a new capability — an authority held by the issuer — to a peer. |
| Delegation | Convey a held capability onward to another peer. |
| Revocation | Withdraw a previously issued or delegated capability, ending the authority it conveyed. |
| Lookup | Resolve or query a capability — for example to determine its existence or current status. |

Notes and honest boundaries:

- **Capability tokens are named, not formatted, by the core specification.** The
  core specification's signature-code-point table lists "capability tokens" among
  the usages of its All-profiles signature algorithm (Ed25519), placing capability
  tokens within the protocol's scope (core specification §6, Signatures). It does
  **not** define a capability-token wire format, claims model, delegation-chain
  structure, or validity model. This reference records that the core specification
  names capability tokens as a signature usage and does not manufacture a token
  format the core specification does not state.
- **No operation encoding is defined here.** Because the core specification assigns
  no Capability-specific frame type (§3.3), the operation classes above have **no
  core-defined request frame, reply frame, capability identifier scheme, token
  encoding, or error model**. This reference MUST NOT be cited as the source of any
  such encoding.
- **Delegation, revocation, and lookup scope are undefined by the core
  specification.** The registry purpose names delegation, revocation, and lookup as
  operation classes; the core specification does not define whether delegation may
  attenuate an authority, how a revocation propagates or is bounded in time, or what
  a lookup query returns. Those are semantics a companion specification MAY define;
  this reference does not manufacture them.
- **Token extension frames.** The only Capability-specific extension surface the
  core specification names is the **capability token extension** frame range, and it
  names it only by reserving frame code points for it (`0x0060`–`0x0063`, §3.2).
  Their semantics are undefined by the core specification and out of scope for this
  reference; the companion NPAMP-CAPABILITY (`../companion/84_capability_channel.md`)
  now defines them, not the core specification.
- **Correlation and ordering.** The Capability channel has an independent
  per-direction sequence space (core specification §5), which orders frames within a
  direction. The core specification does not define how a Capability reply is
  correlated to its request (unlike the Bridge channel, where NPAMP-BRIDGE §5
  defines a `correlation_id`); the companion NPAMP-CAPABILITY
  (`../companion/84_capability_channel.md`) defines this correlation (an in-body
  correlation token). This reference does not define it.
- **Bidirectional origination.** Because the channel is Bidirectional (§2), either
  peer MAY originate traffic on it — an issuer MAY grant or revoke, and a holder MAY
  delegate onward or look up — each direction using its own sequence space and
  traffic keys. The core specification does not assign a fixed issuer/holder role to
  a connection endpoint at the channel level.

## 5. Profile applicability

The Capability channel's minimum profile is **Standard** (§2). By the core
specification's min-profile rule (§5), the channel is available at the Standard
profile and at every higher profile; that is, at **Standard, High, and
Sovereign**. There is no profile at which the Capability channel is unavailable
once its minimum profile is met, and no upper profile bound.

- **Standard profile.** The Capability channel is available and MAY be enabled. This
  is the profile at which the public Capability interface described in this
  reference is fully expressible.
- **Higher profiles (High, Sovereign).** The Capability channel remains available
  with the same wire-level frame namespace and the same public interface. N-PAMP's
  profiles share one wire format and differ in the cryptographic primitives and
  operational requirements they mandate (core specification §6, Profile
  Negotiation). The specific cryptographic suite bound to each profile — including
  the signature suite that protects capability tokens — is defined by the core
  specification's profile-negotiation and cryptographic-suite sections and is **out
  of scope for this interface reference**; this reference describes the channel's
  public, profile-invariant interface only.
- **Scheduling.** The core specification's congestion-scheduling note names the
  Control and Immune channels as the channels that SHOULD be scheduled at higher
  priority than the bulk channels (Memory, Sensory, Telemetry) during congestion
  (core specification §5). The Capability channel appears in **neither** list, so the
  core specification fixes **no** scheduling preference for it; this reference does
  not invent one.

## 6. Relationship to companion specifications

The Capability channel is a **native core channel**: unlike the Bridge channel
(`0x000D`), which encapsulates foreign agent protocols and is elaborated by the
NPAMP-BRIDGE companion framework (`../companion/10_bridge_framework.md`) and its
carriage classes, and unlike the Discovery channel (`0x0010`), elaborated by
NPAMP-DISC (`../companion/40_discovery.md`), the Capability channel is elaborated
by its own dedicated companion specification, NPAMP-CAPABILITY
(`../companion/84_capability_channel.md`), in the current companion set
(`../companion/00_companion_index.md`). That companion is a native-operation
framework, not a bridge carriage class: the Capability channel is therefore not a
bridge carriage class and does not build on NPAMP-BRIDGE.

The Capability channel `0x0002` is also distinct from the two other channels whose
registry purposes mention capabilities, and this reference does not conflate them:

- **Control `0x0000`** carries the "capability epoch" as part of connection
  control and handshake completion (core specification §5) — a connection-level
  epoch marker, not the per-authority issuance/delegation/revocation/lookup traffic
  of this channel.
- **Discovery `0x0010`** carries "capability advertisement" — announcing which
  protocols, tools, and agents a peer offers, elaborated by NPAMP-DISC
  (`../companion/40_discovery.md`) — and capability/schema **documents** MAY ride
  Discovery under NPAMP-CC-DOC (`../companion/24_carriage_documents.md`). That is
  advertisement and document carriage, not the granting or withdrawal of an
  authority held by a peer, which is this channel's purpose.

The consequence for an implementer is that the Capability channel's public contract
is exactly what §2–§5 restate:

- Its **identity** — id `0x0002`, name Capability, purpose "capability issuance,
  delegation, revocation, lookup", minimum profile Standard, direction
  Bidirectional (§2);
- Its **public interface** — the issuance/delegation/revocation/lookup operation
  classes, described at the registry level, with **no core-defined wire encoding or
  capability-token format** (§4);
- Its **reserved extension surface** — the `0x0060`–`0x0063` capability token
  extension frame-type range, reserved by the core specification and now defined by
  the companion NPAMP-CAPABILITY (`../companion/84_capability_channel.md`), not by
  the core specification (§3.2).

Richer, interoperable Capability operations follow the same path as any N-PAMP
extension: a companion specification that defines a Capability operation encoding
(and, where needed, the capability token format) within the reserved code points,
verified against the core specification. That companion now exists — NPAMP-CAPABILITY
(`../companion/84_capability_channel.md`) defines the concrete Capability operation
encoding — so an implementation that carries Capability traffic under the channel
identity and reserved code points above conforms to the core-defined interface this
reference restates, while the concrete operation behavior is defined by
NPAMP-CAPABILITY. This reference documents the interface at that public level and
defines no new behavior.

## 7. Conformance

An implementation conforms to this Capability-channel interface reference if and
only if, for channel `0x0002`, it:

1. Treats channel `0x0002` as the **Capability** channel whose purpose is
   capability issuance, delegation, revocation, and lookup, consistent with the
   core channel registry (§2), and does not repurpose the channel identifier for
   other traffic;
2. Enables the Capability channel only at the **Standard** profile or higher, never
   below Standard, and — once Standard is met — treats the channel as available at
   Standard, High, and Sovereign (§2, §5);
3. Drops any frame received on the Capability channel that the peer has not
   advertised during the handshake, and does not deliver such frames to the
   capability subsystem (§2);
4. Preserves the core meaning of the reserved all-channel frame types
   (`0x0001`–`0x000A`) on the Capability channel and does not reuse any of them for
   Capability application traffic (§3.1);
5. Treats the frame-type range `0x0060`–`0x0063` as **reserved** for Capability
   token extension frames, assigns it to no other purpose, and does **not** claim
   any capability token extension behavior as specified by the core specification,
   because the core specification reserves that range without defining its semantics
   (§3.2);
6. Does not treat any operation description in §4 as a normative wire encoding, and
   does not cite this reference as the source of any Capability request frame, reply
   frame, capability identifier scheme, capability-token format, correlation scheme,
   or error model, none of which the core specification defines for this channel
   (§3.3, §4);
7. Supports the channel's **Bidirectional** direction — both peers sending and
   receiving frames on a single stream, each maintaining independent per-direction
   sequence spaces and traffic keys — and does not treat the channel as Multi-stream
   (§2, §4); and
8. Defers all Capability operation semantics beyond the registry-level interface of
   §4 — including any capability-token format, delegation, revocation, and lookup
   semantics — to the companion specification NPAMP-CAPABILITY, adding no Capability
   behavior of its own that the core specification does not reserve (§6).

A conformance test suite SHOULD assert each clause above, and in particular SHOULD
verify clause 5 by confirming that an implementation does not advertise, emit, or
honor any frame in `0x0060`–`0x0063` as a defined capability token extension
operation on the sole basis of the core specification, and clause 3 by confirming
that a Capability frame arriving on an unadvertised channel is dropped.
