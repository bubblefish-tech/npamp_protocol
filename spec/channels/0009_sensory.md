# NPAMP-CH-0009 — Sensory Channel (`0x0009`) Interface Reference (companion to draft-bubblefish-npamp-00)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is a **per-channel interface reference** for the N-PAMP
> Sensory channel (`0x0009`), derived from the N-PAMP core specification
> (draft-bubblefish-npamp-00, the "core specification"), §5 Channel Architecture
> and §8 Extension Points. It restates the channel's registry entry and its public
> frame-type reservations and describes the channel's public interface **at the
> public level only**. The Sensory channel is **firewall-gated**: its minimum
> profile is **High** (§2), so it can be enabled only once a peer has negotiated
> the High or Sovereign profile. This reference publishes only the open-draft
> interface surface — identity, purpose, direction, minimum profile, and public
> frame-type namespace. It builds on the core specification, introduces no change
> to the core wire format, and defines no behavior the core specification does not
> already reserve. Where the core specification supplies only a registry line or
> reserves a code point without defining its semantics, this reference says so and
> describes the interface at that level. **The draft governs**: on any disagreement
> between this reference and the core specification, the core specification is
> authoritative.

## 1. Purpose

The core specification assigns channel `0x0009` the name **Sensory** and the
purpose **"Bulk telemetry and low-priority observations"** (core specification §5,
Core Channel Registry; `../../registries/channels.csv`). The Sensory channel is
the N-PAMP channel over which a peer carries **high-volume, low-priority
observational traffic** — the class of data a sender emits in bulk and that the
receiver is not required to prioritize over interactive or control traffic. The
core specification classes it among the **bulk** channels (Memory, Sensory,
Telemetry) and states that the Control and Immune channels SHOULD be scheduled at
higher priority than the bulk channels during congestion (core specification §5).
Its role is distinct from Telemetry `0x000A` ("operational metrics and health
reporting"), which the core specification places at the Standard profile and does
not describe as low-priority, and from the interactive and control-plane channels;
the Sensory channel names the bulk, deprioritizable observation class specifically.

The core specification defines the Sensory channel **only** as this registry entry;
it does not define a Sensory-specific wire encoding, message schema, or operation
contract, and it reserves no Sensory-specific frame-type range (§3.2). Accordingly,
this reference describes the Sensory interface at the level the core specification
actually fixes — its identity, its bulk/low-priority traffic class, its direction,
and its firewall-gated minimum profile — and does not invent frame layouts, field
structures, operation classes, or semantics that the core specification does not
state. Because the channel is gated at the **High** profile, the operational and
cryptographic internals a peer must negotiate to enable it are out of scope for
this public reference (§5); this page documents only the public surface the open
draft fixes.

## 2. Channel identity

The following values are taken verbatim from the core channel registry
(core specification §5; machine-readable form `../../registries/channels.csv`). They
are normative in the core specification; this reference restates them and does not
alter them.

| Attribute | Value |
|---|---|
| Channel ID | `0x0009` |
| Name | Sensory |
| Purpose | Bulk telemetry and low-priority observations |
| Minimum profile | High |
| Direction | Multi-stream |

- **Minimum profile — High (firewall-gated).** The Sensory channel MAY be enabled
  only at the **High** profile or higher; it is **not** available at the Standard
  profile. By the core specification's min-profile rule, the Min-profile column
  gives the lowest profile at which a channel may be enabled, and a channel is
  available at that profile and at every higher profile — so a High channel is
  available at **High and Sovereign** (core specification §5). See §5 for profile
  applicability and the publishing scope for this firewall-gated channel.
- **Direction — Multi-stream.** Sensory is bidirectional, and the channel MAY open
  multiple concurrent transport streams within its stream family (core
  specification §5, Channel directionality). Each peer maintains an independent
  per-direction sequence space and independent per-direction traffic keys for the
  channel (core specification §5).
- **Advertisement gate.** A peer that has not advertised the Sensory channel during
  the handshake MUST NOT receive frames on it; frames on an unadvertised Sensory
  channel MUST be dropped (core specification §5, applied to `0x0009`). Because the
  channel is gated at High, a peer that has negotiated only the Standard profile
  MUST NOT enable or advertise it.

## 3. Frame types

Frame types on the Sensory channel are drawn from the same per-channel
`0x0000`–`0xFFFF` frame-type namespace every N-PAMP channel uses (core
specification §4.6; reference `../04_frame_types.md`). Two groups are relevant to
this channel, and one group that applies to some channels does **not** apply here.

### 3.1 Reserved all-channel frame types

The following frame types are reserved across **all** channels with the same
meaning everywhere and retain that meaning on the Sensory channel. An
implementation MUST NOT reuse them for Sensory application traffic.

| Type | Name | Meaning on the Sensory channel |
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

### 3.2 No reserved Sensory-channel extension frame range

The core specification's Reserved Frame-Type Ranges table (core specification §8,
Extension Points; reference `../09_extension_points.md`) reserves several
sub-`0x0100` code-point ranges for companion extension frames — but **none of those
ranges is assigned to the Sensory channel**. The reserved ranges there belong to
the Memory, Capability, Control, Audit, Settlement/Audit, Governance, and Immune
channels only. The core specification therefore reserves **no** Sensory-specific
frame-type range, and an implementation MUST NOT treat any code point as a defined
or reserved Sensory extension frame on the basis of the core specification.

> **Known editorial inconsistency in -00 (carried, not corrected here).** The core
> specification states that channel-specific frame types begin at `0x0100`
> (§4.6), yet the sub-`0x0100` reserved ranges (`0x0035`–`0x00C4`) sit below that
> boundary. This inconsistency is present in the submitted draft and is recorded
> in `../04_frame_types.md`; it is carried, not corrected, by this reference and
> does not affect the Sensory channel, for which no sub-`0x0100` range is reserved
> and whose channel-specific frames, were any defined, would sit at `0x0100`+.

### 3.3 Channel-specific frame types (`0x0100`+ convention)

Channel-specific frame types begin at **`0x0100`** within each channel's frame
namespace (core specification §4.6). This is the range in which a Sensory-specific
observation encoding — for example concrete bulk-observation frames (§4) — would be
assigned. The core specification defines **no** Sensory-specific frame type in this
range, and no companion specification in the current set
(`../companion/00_companion_index.md`) defines one. Consequently there is, at
present, no core- or companion-defined Sensory frame; §4 describes the interface at
the registry level the core specification actually fixes.

## 4. Interface and operations (public level)

At the core-specification level the Sensory channel's public interface is exactly
its registry line: it carries **bulk telemetry and low-priority observations**
(core specification §5). Unlike the Memory channel, whose registry purpose names a
set of operation classes (create/read/update/delete and retrieval), the Sensory
registry purpose names a **traffic class**, not a set of operations; the core
specification fixes what kind of data the channel carries and its scheduling
posture, and stops there. This section restates the interface at that level. An
implementation MUST NOT read a wire format into this section: no frame layout,
field structure, TLV, operation, correlation scheme, or error model below is
defined by the core specification.

| Interface property | Public meaning (from the registry line and §5) |
|---|---|
| Traffic class | High-volume observational data emitted in bulk. |
| Priority | **Low priority.** The channel is one of the bulk channels; Control and Immune SHOULD be scheduled ahead of it during congestion (core specification §5). |
| Direction | Multi-stream — bidirectional, with the OPTIONAL opening of multiple concurrent transport streams within the channel's stream family (§2). |

Notes and honest boundaries:

- **No operation encoding is defined here.** Because the core specification assigns
  no Sensory-specific frame type (§3.3) and reserves no Sensory extension range
  (§3.2), the channel has **no core-defined request frame, reply frame, observation
  schema, addressing scheme, value encoding, correlation scheme, or error model**.
  This reference MUST NOT be cited as the source of any such encoding.
- **No named operation classes.** The registry purpose does not enumerate
  operations; this reference does not manufacture create/read/update-style
  operation classes for the Sensory channel, because the core specification does not
  state them. A companion specification MAY define a concrete Sensory observation
  encoding within the `0x0100`+ namespace; until one exists, the public Sensory
  interface is exactly what this reference restates.
- **Correlation and ordering.** The Sensory channel has an independent per-direction
  sequence space (core specification §5), which orders frames within a direction.
  The core specification does not define how, or whether, a Sensory frame is
  correlated to any other; a Sensory encoding, when specified by a companion, is
  where such semantics would be defined. This reference does not define them.
- **Multi-stream concurrency.** Because the channel is Multi-stream (§2), a
  deployment MAY carry concurrent bulk observation traffic over multiple transport
  streams within the channel's stream family; the core specification permits this at
  the channel level and does not constrain how traffic is distributed across those
  streams.
- **Firewall scope.** Because the channel is gated at the High profile, any
  operational or cryptographic internals specific to enabling and operating it under
  the High or Sovereign profile are out of scope for this public reference and are
  not documented here (§5).

## 5. Profile applicability

The Sensory channel's minimum profile is **High** (§2), and the channel is
therefore **firewall-gated**: it is available only once a peer has negotiated the
High or Sovereign profile and is **not** available at the Standard profile. By the
core specification's min-profile rule (§5), the channel is available at High and at
every higher profile — that is, at **High and Sovereign** — and there is no upper
profile bound.

- **Standard profile.** The Sensory channel is **not** available. A peer that has
  negotiated only the Standard profile MUST NOT enable or advertise `0x0009`, and
  frames received on it MUST be dropped (§2).
- **High and Sovereign profiles.** The Sensory channel MAY be enabled. N-PAMP's
  three profiles (Standard, High, Sovereign) share **one wire format** and differ in
  the cryptographic primitives and operational requirements they mandate (core
  specification §6, Profile Negotiation); High and Sovereign each escalate the
  cryptographic strength of the previous profile. The channel's public framing —
  its identity (§2), its frame-type namespace (§3), and the registry-level interface
  (§4) — is invariant across the High and Sovereign profiles.
- **Scheduling.** The core specification classes Sensory among the **bulk** channels
  and states that the Control and Immune channels SHOULD be scheduled at higher
  priority than the bulk channels (Memory, Sensory, Telemetry) during congestion
  (core specification §5). This is a scheduling recommendation consistent with the
  channel's "low-priority observations" purpose, not a change to the interface.
- **Publishing scope.** This reference documents only the public interface surface
  the open draft fixes — the channel's identity, purpose, direction, minimum
  profile (High), and public frame-type namespace. The High- and Sovereign-profile
  cryptographic suites, parameters, and key schedule are selected by the core
  specification's profile negotiation and are **out of scope for this interface
  reference**; and any operational or cryptographic internals specific to this
  firewall-gated channel are likewise out of scope here and governed elsewhere. This
  page describes the channel's public, profile-independent interface only and states
  no High- or Sovereign-profile cryptographic behavior.

## 6. Relationship to companion specifications

The Sensory channel is a **native core channel**: like the Memory channel
(`0x0001`), and unlike the Bridge channel (`0x000D`), which encapsulates foreign
agent protocols and is elaborated by the NPAMP-BRIDGE companion framework
(`../companion/10_bridge_framework.md`) and its carriage classes, the Sensory
channel has **no dedicated companion specification** in the current companion set
(`../companion/00_companion_index.md`). It is therefore not a bridge carriage class
and does not build on NPAMP-BRIDGE; the companion set does not reference it.

The consequence for an implementer is that the Sensory channel's public contract is
exactly what §2–§5 restate:

- Its **identity** — id `0x0009`, name Sensory, purpose "bulk telemetry and
  low-priority observations", minimum profile High, direction Multi-stream (§2);
- Its **public interface** — the bulk, low-priority observation traffic class,
  described at the registry level, with **no core-defined wire encoding** and no
  named operation classes (§4);
- Its **frame-type surface** — the reserved all-channel frame types (§3.1) and the
  `0x0100`+ channel-specific namespace (§3.3), with **no** core-reserved
  Sensory-specific extension range (§3.2); and
- Its **firewall gate** — the High minimum profile, above which the channel's
  operational and cryptographic internals are governed by the core specification's
  profile negotiation and are out of scope for this public reference (§5).

Should richer, interoperable Sensory operations be wanted, the path is the same as
for any N-PAMP extension: author a companion specification that defines a Sensory
observation encoding within the `0x0100`+ namespace, verified against the core
specification and consistent with the channel's firewall gate. Until such a
companion exists, an implementation carries Sensory traffic under the channel
identity and frame-type surface above, and there is no additional core- or
companion-defined Sensory behavior to conform to. This reference documents the
interface at that public level and defines no new behavior.

## 7. Conformance

An implementation conforms to this Sensory-channel interface reference if and only
if, for channel `0x0009`, it:

1. Treats channel `0x0009` as the **Sensory** channel whose purpose is bulk
   telemetry and low-priority observations, consistent with the core channel
   registry (§2), and does not repurpose the channel identifier for other traffic;
2. Enables the Sensory channel only at the **High** profile or higher, **never**
   below High, and — once High is met — treats the channel as available at High and
   Sovereign (§2, §5);
3. Does not enable or advertise `0x0009` when only the Standard profile has been
   negotiated, and drops any frame received on the Sensory channel that the peer has
   not advertised during the handshake (§2, §5);
4. Preserves the core meaning of the reserved all-channel frame types
   (`0x0001`–`0x000A`) on the Sensory channel and does not reuse any of them for
   Sensory application traffic (§3.1);
5. Treats the Sensory channel as having **no** core-reserved sub-`0x0100` extension
   frame range, and does not claim any code point as a defined or reserved Sensory
   extension frame on the basis of the core specification (§3.2);
6. Does not treat any interface description in §4 as a normative wire encoding, and
   does not cite this reference as the source of any Sensory frame, observation
   schema, addressing scheme, value encoding, correlation scheme, or error model,
   none of which the core specification defines for this channel (§3.3, §4);
7. Supports the channel's **Multi-stream** direction — bidirectional operation with
   the OPTIONAL opening of multiple concurrent transport streams within the
   channel's stream family, each peer maintaining independent per-direction sequence
   spaces and traffic keys (§2, §4); and
8. Defers all Sensory operation semantics beyond the registry-level interface of §4
   to a future companion specification, adds no Sensory behavior of its own that the
   core specification does not reserve, and does not publish or rely on any High- or
   Sovereign-profile cryptographic internal or parameter through this public
   reference (§5, §6).

A conformance test suite SHOULD assert each clause above, and in particular SHOULD
verify clause 2 by confirming that an implementation refuses to enable `0x0009`
under the Standard profile, clause 3 by confirming that a Sensory frame arriving on
an unadvertised channel is dropped, and clause 5 by confirming that the
implementation does not advertise, emit, or honor any code point as a defined
Sensory extension frame on the sole basis of the core specification. A per-channel
reference MUST NOT be read to add behavior the core specification does not define.
