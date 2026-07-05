# NPAMP-CH-0013 — Spatial Channel (`0x0013`) Interface Reference (companion to draft-bubblefish-npamp-00)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is a **per-channel interface reference** for the N-PAMP
> Spatial channel (`0x0013`), derived from the N-PAMP core specification
> (draft-bubblefish-npamp-00, the "core specification"), §5 Channel Architecture
> and §8 Extension Points. It restates the channel's registry entry and its public
> frame-type reservations and describes the channel's public interface surface **at
> the public level only**. It builds on the core specification, introduces no
> change to the core wire format, and defines no behavior the core specification
> does not already reserve. The Spatial channel is a **firewall-gated** channel: its
> minimum profile is **High** (`../../registries/channels.csv`), so it is enabled
> only under the High or Sovereign profile, and its operational and cryptographic
> internals are governed above the public Standard-profile surface — they live in
> the controlled track and are **out of scope** for this public reference. Where the
> core specification supplies only a registry line or reserves a code point without
> defining its semantics, this reference says so and describes the interface at that
> level. **The draft governs**: on any disagreement between this reference and the
> core specification, the core specification is authoritative.

## 1. Purpose

The core specification assigns channel `0x0013` the name **Spatial** and the
purpose **"Physical-world state for robotics and IoT (high-frequency)"**
(core specification §5, Core Channel Registry; `../../registries/channels.csv`).
At the public level this registry line is the whole of what the core specification
fixes for the channel: it identifies the *class of traffic* the channel carries —
physical-world state exchanged with robotics and IoT endpoints, characterized by
the registry as high-frequency — and it does so as a High-profile channel. The
core specification defines the Spatial channel **only** as this registry entry; it
reserves no Spatial-specific frame-type range (§3), and it defines no Spatial
wire encoding, message schema, or operation contract.

Accordingly, this reference describes the Spatial interface at the level the core
specification actually fixes — the channel's identity, its public frame-type
namespace, and the profile at which it may be enabled — and does not invent frame
layouts, field structures, operation classes, or semantics that the core
specification does not state. Because the channel is firewall-gated at the High
profile, its operational behavior and the cryptographic material bound to the High
and Sovereign profiles are governed by the core specification's profile
negotiation and by the controlled track, and are **out of scope** for this public
reference. This page documents only the channel's public surface: that it exists,
its identifier and name, its purpose, its direction, its minimum profile, and its
public frame-range reservations. All of these are already public in the core
specification's §5 channel registry.

## 2. Channel identity

The following values are taken verbatim from the core channel registry
(core specification §5; machine-readable form `../../registries/channels.csv`).
They are normative in the core specification; this reference restates them and does
not alter them.

| Attribute | Value |
|---|---|
| Channel ID | `0x0013` |
| Name | Spatial |
| Purpose | Physical-world state for robotics and IoT (high-frequency) |
| Minimum profile | High |
| Direction | Multi-stream |

- **Minimum profile — High.** The Spatial channel MAY be enabled only at the
  **High** profile or higher, per the core specification's min-profile rule (§5:
  The minimum profile is the lowest profile at which a channel may be enabled, and
  a channel is available at that profile and at every higher profile). The channel
  is therefore available at **High and Sovereign** and is **not** available at the
  Standard profile. See §5 for profile applicability.
- **Direction — Multi-stream.** Spatial is bidirectional, and the channel MAY open
  multiple concurrent transport streams within its stream family
  (core specification §5, Channel directionality). Each peer maintains an
  independent per-direction sequence space and independent per-direction traffic
  keys for the channel (core specification §5).
- **Advertisement gate.** A peer that has not advertised the Spatial channel during
  the handshake MUST NOT receive frames on it; frames on an unadvertised Spatial
  channel MUST be dropped (core specification §5, applied to `0x0013`).

## 3. Frame types

Frame types on the Spatial channel are drawn from the same per-channel
`0x0000`–`0xFFFF` frame-type namespace every N-PAMP channel uses
(core specification §4.6; reference `../04_frame_types.md`). Three points are
relevant to this channel.

### 3.1 Reserved all-channel frame types

The following frame types are reserved across **all** channels with the same
meaning everywhere and retain that meaning on the Spatial channel. An
implementation MUST NOT reuse them for Spatial application traffic.

| Type | Name | Meaning on the Spatial channel |
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

### 3.2 No Spatial-channel reserved frame-type range

The core specification's Reserved Frame-Type Ranges table (core specification §8,
Reserved Frame-Type Ranges; references `../04_frame_types.md`,
`../09_extension_points.md`) reserves several sub-`0x0100` code-point ranges for
companion extensions — but **none of those ranges is assigned to the Spatial
channel**. The reserved ranges there belong to the Memory, Capability, Control,
Audit, Settlement/Audit, Governance, and Immune channels. The core specification
therefore reserves **no** Spatial-specific frame-type range, and this reference
introduces none.

> **Known editorial inconsistency in -00 (carried, not corrected here).** The core
> specification states that channel-specific frame types begin at `0x0100`
> (§4.6), while the reserved companion ranges above sit below `0x0100`
> (`0x0035`–`0x00C4`). This inconsistency is present in the submitted draft and is
> recorded in `../04_frame_types.md`; this reference does not silently rewrite the
> authoritative text. It does not affect the Spatial channel, for which the core
> specification reserves no sub-`0x0100` range.

### 3.3 Channel-specific frame types (`0x0100`+ convention)

Channel-specific frame types begin at **`0x0100`** within each channel's frame
namespace (core specification §4.6). This is the range in which a Spatial-specific
operation encoding would be assigned. The core specification defines **no**
Spatial-specific frame type in this range, and no companion specification in the
current public set (`../companion/00_companion_index.md`) defines one. Consequently
there is, at the public level, no core- or public-companion-defined Spatial
operation frame; §4 describes the interface at the registry level the core
specification actually fixes, and the channel's operational frame set is governed
by the controlled track (§5, §6) rather than by this public reference.

## 4. Interface (public level)

At the core-specification level the Spatial channel's public interface is exactly
its registry line: it carries **physical-world state for robotics and IoT
(high-frequency)** (core specification §5). The core specification fixes this as
the channel's *purpose*, not as a wire encoding; it defines no Spatial-specific
operations beyond the reserved all-channel control frames of §3.1, and it neither
parses nor structures the physical-world state carried on the channel. An
implementation MUST NOT read a wire format into this section: no frame layout,
field structure, TLV, correlation scheme, sampling model, or operation contract is
defined by the core specification for this channel.

Honest boundaries at the public level:

- **No operation encoding is defined here.** Because the core specification assigns
  no Spatial-specific frame type (§3.3), the channel has **no core-defined request
  frame, reply frame, state encoding, addressing scheme, or error model** at the
  public level. This reference MUST NOT be cited as the source of any such encoding.
- **"High-frequency" is a registry characterization, not a defined parameter.** The
  parenthetical "(high-frequency)" in the registry purpose describes the class of
  traffic; the core specification states no rate, cadence, sampling, or timing
  parameter for the channel. This reference does not manufacture one.
- **Correlation and ordering.** The Spatial channel has an independent per-direction
  sequence space (core specification §5), which orders frames within a direction.
  The core specification defines no request/reply correlation scheme for the channel
  (unlike the Bridge channel, where NPAMP-BRIDGE §5 defines a `correlation_id`); any
  such scheme, if defined, is governed elsewhere and not by this public reference.
- **Multi-stream concurrency.** Because the channel is Multi-stream (§2), a
  deployment MAY carry concurrent Spatial traffic over multiple transport streams
  within the channel's stream family; the core specification permits this at the
  channel level and does not constrain how traffic is distributed across those
  streams.
- **Operational and cryptographic internals are out of scope.** The Spatial channel
  is firewall-gated at the High profile (§2, §5). Its operational contract and the
  cryptographic material bound to the High and Sovereign profiles are governed by
  the core specification's profile negotiation and by the controlled track; they are
  **not** published in this public reference and MUST NOT be inferred from it.

## 5. Profile applicability

The Spatial channel's minimum profile is **High** (§2;
`../../registries/channels.csv`). By the core specification's min-profile rule
(§5), the channel is available at the High profile and at every higher profile —
that is, at **High and Sovereign** — and is **not** available at the Standard
profile. This is the sense in which the channel is firewall-gated: enabling it, and
therefore any operation on it, **requires the High or Sovereign profile**.

- **Standard profile.** The Spatial channel is **not available** and MUST NOT be
  enabled (§2; core specification §5). A peer operating at the Standard profile does
  not advertise or accept this channel.
- **High and Sovereign profiles.** The Spatial channel MAY be enabled. Its public
  surface — its identity (§2), its frame-type namespace (§3), and the Multi-stream
  direction (§2) — is the same at both profiles. N-PAMP's three profiles share **one
  wire format** and differ in the cryptographic primitives and operational
  requirements they mandate (core specification §6, Profile Negotiation). The
  specific cryptographic suite bound to each profile is defined by the core
  specification's profile-negotiation and cryptographic-suite sections and is **out
  of scope for this interface reference**; this reference names only the public
  profile identifiers (Standard, High, Sovereign) and does not restate per-profile
  cryptographic parameters.
- **Scheduling.** The core specification's congestion-scheduling guidance names the
  Control and Immune channels as higher priority than the enumerated bulk channels
  (Memory, Sensory, Telemetry) during congestion (core specification §5). The
  Spatial channel appears in **neither** list; the core specification states no
  scheduling class for it, and this reference does not assign one.
- **Publishing scope.** This reference documents only the public interface surface
  of the channel — its existence, identifier, name, purpose, direction, minimum
  profile, and public frame-type namespace, all of which are public in the core
  specification's §5 channel registry. The channel's operational internals and the
  High- and Sovereign-profile cryptographic internals and parameters are governed by
  the core specification's profile negotiation and by the controlled track and are
  **out of scope** here; they MUST NOT be read into this document.

## 6. Relationship to companion specifications

The Spatial channel is a **native core channel**: unlike the Bridge channel
(`0x000D`), which encapsulates foreign agent protocols and is elaborated by the
NPAMP-BRIDGE companion framework (`../companion/10_bridge_framework.md`) and its
carriage classes, and unlike the Discovery channel (`0x0010`), elaborated by
NPAMP-DISC (`../companion/40_discovery.md`), the Spatial channel has **no dedicated
companion specification** in the current public companion set
(`../companion/00_companion_index.md`). It is therefore not a bridge carriage class
and does not build on NPAMP-BRIDGE.

The consequence for an implementer is that the Spatial channel's **public** contract
is exactly what §2–§5 restate:

- Its **identity** — id `0x0013`, name Spatial, purpose "physical-world state for
  robotics and IoT (high-frequency)", minimum profile High, direction Multi-stream
  (§2);
- Its **public frame-type surface** — the reserved all-channel frame types
  (`0x0001`–`0x000A`) with their fixed meanings, and the channel-specific `0x0100`+
  convention, with **no** Spatial-specific frame-type range reserved by the core
  specification and **no** core- or public-companion-defined Spatial operation frame
  (§3); and
- Its **profile gate** — availability at High and Sovereign only, never at Standard
  (§2, §5).

Because the channel is firewall-gated at the High profile, its operational
semantics and the cryptographic material bound to the High and Sovereign profiles
are governed by the core specification's profile negotiation and by the controlled
track — not by this public companion set. This public reference documents the
channel at the registry level the core specification fixes and defines no new
behavior. Where the core specification gives this channel only a registry line, this
reference says so; it MUST NOT be read to add any Spatial behavior the core
specification does not reserve.

## 7. Conformance

An implementation conforms to this Spatial-channel interface reference if and only
if, for channel `0x0013`, it:

1. Treats channel `0x0013` as the **Spatial** channel whose purpose is
   "physical-world state for robotics and IoT (high-frequency)", consistent with the
   core channel registry (§2), and does not repurpose the channel identifier for
   other traffic or alter any of its registry values;
2. Enables the Spatial channel only at the **High** profile or higher, **never** at
   the Standard profile, and — once High is met — treats the channel as available at
   High and Sovereign (§2, §5);
3. Drops any frame received on the Spatial channel that the peer has not advertised
   during the handshake, and does not deliver such frames (§2);
4. Preserves the core meaning of the reserved all-channel frame types
   (`0x0001`–`0x000A`) on the Spatial channel and does not reuse any of them for
   Spatial application traffic (§3.1);
5. Relies on **no** core-specification-reserved sub-`0x0100` frame-type range for
   this channel, because the core specification reserves none for Spatial, and places
   any channel-specific frame types in the `0x0100`+ namespace per the core
   convention (§3.2, §3.3);
6. Does not treat any description in §4 as a normative wire encoding, and does not
   cite this reference as the source of any Spatial request frame, reply frame, state
   encoding, addressing scheme, correlation scheme, timing parameter, or error model,
   none of which the core specification defines for this channel (§3.3, §4);
7. Supports the channel's **Multi-stream** direction — bidirectional operation with
   the OPTIONAL opening of multiple concurrent transport streams within the channel's
   stream family, each peer maintaining independent per-direction sequence spaces and
   traffic keys (§2, §4); and
8. Treats the channel's operational and cryptographic internals — including the
   High- and Sovereign-profile cryptographic material — as governed by the core
   specification's profile negotiation and the controlled track, out of scope for
   this public reference, and adds no public Spatial behavior of its own that the
   core specification does not reserve (§5, §6).

A conformance test suite SHOULD assert each clause above, and in particular SHOULD
verify clause 2 by confirming that an implementation neither advertises nor accepts
the Spatial channel at the Standard profile, and clause 3 by confirming that a
Spatial frame arriving on an unadvertised channel is dropped. This reference defines
no frame semantics, state encoding, correlation, timing, or error behavior of its
own; a per-channel reference MUST NOT be read to add behavior the core specification
does not define.
