# NPAMP-CH-0004 — Governance Channel (`0x0004`) Interface Reference (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is a **per-channel interface reference** for the N-PAMP
> Governance channel (`0x0004`), derived from the N-PAMP core specification
> (draft-bubblefish-npamp-01, the "core specification"), §5 Channel Architecture
> and §8 Extension Points. It restates the channel's registry entry and its public
> frame-type reservations and describes the channel's public interface **at the
> public level only**. It builds on the core specification, introduces no change to
> the core wire format, and defines no behavior the core specification does not
> already reserve. Where the core specification supplies only a registry line or
> reserves a code point without defining its semantics, this reference says so and
> describes the interface at that level. The Governance channel is a **firewall-
> gated channel**: its minimum profile is **High**, and its operational and
> cryptographic internals are governed by the controlled track, not this public
> reference (§4, §5). **The draft governs**: on any disagreement between this
> reference and the core specification, the core specification is authoritative.

## 1. Purpose

The core specification assigns channel `0x0004` the name **Governance** and the
purpose **"Policy proposals, votes, quorum closure"** (core specification §5,
Core Channel Registry; `../../registries/channels.csv`). At the public level, the
Governance channel is the N-PAMP channel over which peers conduct the three named
classes of collective decision-making traffic — **policy proposals** (putting a
policy forward for a governance group to decide), **votes** (recording positions
on a proposal), and **quorum closure** (finalizing a decision once the required
threshold of participation is reached) — as distinct from a single peer granting
or revoking authority to another (Capability `0x0002`, "capability issuance,
delegation, revocation, lookup") or a peer producing attestations for regulatory
export (Compliance `0x0008`). The registry phrase names *collective* decision
traffic: the subject is a shared policy decision made across participating peers,
and the channel's purpose is the proposal, voting, and quorum-closure exchange
that carries that decision to conclusion.

The core specification defines the Governance channel **only** as this registry
entry plus a reserved frame-type range for quorum extension frames (§3.2); it
does not define a Governance-specific wire encoding, message schema, or operation
contract. Accordingly, this reference describes the Governance interface at the
level the core specification actually fixes — the operation *classes* named by the
registry purpose (§4) and the reserved code points (§3.2) — and does not invent
frame layouts, field structures, voting rules, or quorum arithmetic that the core
specification does not state. Because the channel's minimum profile is **High**
(§2, §5), its operations are available only to High- and Sovereign-profile
associations; the operational and cryptographic detail of how those operations run
is out of scope for this public reference and belongs to the controlled track.

## 2. Channel identity

The following values are taken verbatim from the core channel registry
(core specification §5; machine-readable form `../../registries/channels.csv`). They are
normative in the core specification; this reference restates them and does not
alter them.

| Attribute | Value |
|---|---|
| Channel ID | `0x0004` |
| Name | Governance |
| Purpose | Policy proposals, votes, quorum closure |
| Minimum profile | High |
| Direction | Bidirectional |

- **Minimum profile — High.** The Governance channel MAY be enabled only at the
  **High** profile or higher; it is available at **High and Sovereign** and is
  **not** available at Standard, per the core specification's min-profile rule
  (core specification §5: the minimum profile is the lowest profile at which a
  channel may be enabled, and the channel is available at that profile and every
  higher profile — a "High" channel is available at High and Sovereign). This makes
  Governance a firewall-gated channel; see §5 for profile applicability and the
  publishing-scope boundary.
- **Direction — Bidirectional.** Both peers send and receive frames on a single
  stream of this channel (core specification §5, Channel directionality). As with
  every N-PAMP channel, each peer maintains an independent send and receive
  sequence space and independent per-direction traffic keys, so both peers MAY
  transmit on the channel simultaneously (core specification §5). The Governance
  channel is **not** classified Multi-stream; it does not open multiple concurrent
  transport sub-streams within a stream family (contrast the Stream channel
  `0x000C`).
- **Advertisement gate.** A peer that has not advertised the Governance channel
  during the handshake MUST NOT receive frames on it; frames on an unadvertised
  Governance channel MUST be dropped (core specification §5, applied to `0x0004`).

## 3. Frame types

Frame types on the Governance channel are drawn from the same per-channel
`0x0000`–`0xFFFF` frame-type namespace every N-PAMP channel uses
(core specification §4.6; reference `../04_frame_types.md`). Three groups are
relevant to this channel.

### 3.1 Reserved all-channel frame types

The following frame types are reserved across **all** channels with the same
meaning everywhere and retain that meaning on the Governance channel. An
implementation MUST NOT reuse them for Governance application traffic.

| Type | Name | Meaning on the Governance channel |
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

### 3.2 Reserved Governance-channel extension frame range

The core specification reserves one per-channel frame-type range specifically for
the Governance channel (core specification §8, Reserved Frame-Type Ranges;
reference `../09_extension_points.md`):

| Range | Reserved for |
|---|---|
| `0x00B0` – `0x00B4` | Governance-channel quorum extension frames |

This range is **reserved, not defined**. The core specification neither defines
nor requires any quorum extension frame; it only reserves the code points so a
companion or controlled-track specification can define them without colliding with
the core wire format (core specification §8). No companion specification in the
current set (`../companion/00_companion_index.md`) defines these frames. An
implementation therefore MUST NOT treat any quorum-extension behavior as specified
by the core specification, and MUST NOT assign `0x00B0`–`0x00B4` to any other
purpose. Because the Governance channel is firewall-gated at the High profile
(§2, §5), any concrete definition of these quorum extension frames belongs to the
**controlled track** and is out of scope for this public reference.

> **Known editorial inconsistency in -00 (carried, not corrected here).** The core
> specification states that channel-specific frame types begin at `0x0100`
> (§4.6), yet the reserved Governance quorum-extension range `0x00B0`–`0x00B4`
> sits below `0x0100`. This inconsistency is present in the submitted draft and is
> recorded in `../04_frame_types.md`; this reference does not silently rewrite the
> authoritative text.

### 3.3 Channel-specific frame types (`0x0100`+ convention)

Channel-specific frame types begin at **`0x0100`** within each channel's frame
namespace (core specification §4.6). This is the range in which a Governance-
specific operation encoding — for example concrete proposal, vote, and
quorum-closure request and reply frames (§4) — would be assigned. The core
specification defines **no** Governance-specific frame type in this range, and no
companion specification in the current set (`../companion/00_companion_index.md`)
defines one. Consequently there is, at present, no core- or companion-defined
Governance operation frame; §4 describes the interface at the registry level the
core specification actually fixes. Any concrete Governance operation encoding is a
matter for the controlled track (§4, §5, §6), consistent with the channel's High
minimum profile, and is out of scope for this public reference.

## 4. Interface and operations (public level)

The Governance channel's public interface is the set of operation classes named by
its registry purpose. The core specification fixes these as **names of operation
classes**, not as wire encodings; this section restates them at that level and
states explicitly where the core specification stops. An implementation MUST NOT
read a wire format into this section: no frame layout, field structure, TLV, or
correlation scheme below is defined by the core specification.

| Operation class | Public meaning (from the registry purpose) |
|---|---|
| Policy proposal | Put a policy forward for the participating peers to decide upon. |
| Vote | Record a peer's position on a pending proposal. |
| Quorum closure | Finalize a decision once the required threshold of participation is reached. |

Notes and honest boundaries:

- **Registry-level only.** The registry purpose lists exactly these three classes
  ("policy proposals, votes, quorum closure"). The core specification does not
  further decompose any class, nor define a voting rule, a quorum threshold, a
  tallying method, or a proposal lifecycle; this reference records the three named
  classes and does not manufacture sub-operations, quorum arithmetic, or a
  decision procedure that the core specification does not state.
- **No operation encoding is defined here.** Because the core specification assigns
  no Governance-specific frame type in the `0x0100`+ namespace (§3.3) and reserves
  the `0x00B0`–`0x00B4` quorum-extension range without defining it (§3.2), the
  operation classes above have **no core-defined request frame, reply frame,
  addressing scheme, value encoding, or error model**. This reference MUST NOT be
  cited as the source of any such encoding.
- **Correlation and ordering.** The Governance channel has an independent
  per-direction sequence space (core specification §5), which orders frames within
  a direction. The core specification does not define how a Governance reply is
  correlated to its request, nor how a vote is bound to a proposal; a Governance
  operation encoding, when specified, is where such correlation would be defined.
  This reference does not define it.
- **Single-stream bidirectional operation.** The channel is Bidirectional, not
  Multi-stream (§2): both peers send and receive on a single stream, each with an
  independent per-direction sequence space and traffic keys, and it does not open
  multiple concurrent transport sub-streams within a stream family (core
  specification §5). Either peer MAY originate a proposal, a vote, or a
  quorum-closure exchange, subject to whatever operation contract the controlled
  track defines; this reference assigns no roles the core specification does not
  state.
- **Firewall boundary — operations require the High or Sovereign profile.** The
  Governance channel's minimum profile is High (§2, §5); an association that has
  not negotiated at least the High profile MUST NOT enable the channel, so these
  operations are unavailable to a Standard-profile association. The operational and
  cryptographic internals that carry these operations at the High and Sovereign
  profiles — including any authentication or integrity applied to proposals, votes,
  and quorum-closure decisions — are governed by the controlled track and are
  **out of scope** for this public reference. This page publishes only the
  channel's public surface — its existence, identifier, name, purpose, direction,
  minimum profile, and public frame-type namespace — and describes no High- or
  Sovereign-profile operational or cryptographic behavior.

## 5. Profile applicability

The Governance channel's minimum profile is **High** (§2). By the core
specification's min-profile rule (§5), the channel is available at the High profile
and at every higher profile; that is, at **High and Sovereign**, and **not** at
Standard. There is no profile below High at which the Governance channel may be
enabled.

- **Standard profile.** The Governance channel is **not available**. An association
  operating at the Standard profile MUST NOT enable channel `0x0004` (core
  specification §5, min-profile rule). This is the firewall gate: Governance is a
  High-minimum, firewall-gated channel, not a baseline-profile channel.
- **High and Sovereign profiles.** The Governance channel MAY be enabled and its
  operations (§4) become available. N-PAMP's three profiles share one wire format
  and differ in the cryptographic primitives and operational requirements they
  mandate (core specification §6, Profile Negotiation). The specific cryptographic
  suite bound to each profile is defined by the core specification's
  profile-negotiation and cryptographic-suite sections and by the controlled track,
  and is **out of scope for this interface reference**; this reference describes the
  channel's public, profile-invariant interface only and reproduces no High- or
  Sovereign-profile cryptographic parameter.
- **Congestion scheduling.** The core specification's congestion-scheduling
  recommendation names the Control and Immune channels as higher-priority and the
  Memory, Sensory, and Telemetry channels as bulk (core specification §5); the
  Governance channel is named in neither group, so the core specification states no
  scheduling priority for it and this reference does not assign one.
- **Publishing scope (firewall).** This reference documents only the **public
  interface surface** of the channel — its identity, purpose, direction, minimum
  profile, and public frame-type namespace, all of which the core specification
  publishes in §5. The channel's operational and cryptographic internals — the way
  its policy-proposal, vote, and quorum-closure operations run at the High and
  Sovereign profiles, and every High/Sovereign cryptographic parameter — live in
  the controlled track and are **out of scope** here. Referencing the public
  profile names (Standard, High, Sovereign) and the identity/code-point facts the
  core specification already publishes is in scope; reproducing High/Sovereign
  cryptographic internals is not.

## 6. Relationship to companion specifications

The Governance channel is a **native core channel**: unlike the Bridge channel
(`0x000D`), which encapsulates foreign agent protocols and is elaborated by the
NPAMP-BRIDGE companion framework (`../companion/10_bridge_framework.md`) and its
carriage classes, and unlike the Discovery channel (`0x0010`), elaborated by
NPAMP-DISC (`../companion/40_discovery.md`), the Governance channel has **no
dedicated companion specification** in the current companion set
(`../companion/00_companion_index.md`). It is therefore not a bridge carriage class
and does not build on NPAMP-BRIDGE.

The consequence for an implementer is that the Governance channel's public contract
is exactly what §2–§5 restate:

- Its **identity** — id `0x0004`, name Governance, purpose "policy proposals,
  votes, quorum closure", minimum profile High, direction Bidirectional (§2);
- Its **public interface** — the policy-proposal, vote, and quorum-closure
  operation classes, described at the registry level, with **no core-defined wire
  encoding** (§4); and
- Its **reserved extension surface** — the `0x00B0`–`0x00B4` Governance quorum
  extension frame-type range, reserved by the core specification and defined by
  neither the core specification nor any current companion (§3.2).

Should richer, interoperable Governance operations be wanted, the path is the same
as for any N-PAMP extension: author a specification that defines a Governance
operation encoding within the reserved `0x00B0`–`0x00B4` quorum-extension code
points or the channel's `0x0100`+ namespace, verified against the core
specification. Because the channel is firewall-gated at the High profile, that
operational definition belongs to the **controlled track**, not this public
reference. Until such a definition exists, an implementation carries Governance
traffic under the channel identity and reserved code points above, and there is no
additional core- or companion-defined Governance behavior in the public track to
conform to. This reference documents the interface at that public level and defines
no new behavior.

## 7. Conformance

An implementation conforms to this Governance-channel interface reference if and
only if, for channel `0x0004`, it:

1. Treats channel `0x0004` as the **Governance** channel whose purpose is policy
   proposals, votes, and quorum closure, consistent with the core channel registry
   (§2), and does not repurpose the channel identifier for other traffic;
2. Enables the Governance channel only at the **High** profile or higher (High or
   Sovereign) and **never** below High, so that a Standard-profile association does
   not enable channel `0x0004` (§2, §5);
3. Drops any frame received on the Governance channel that the peer has not
   advertised during the handshake, and does not deliver such frames (§2);
4. Preserves the core meaning of the reserved all-channel frame types
   (`0x0001`–`0x000A`) on the Governance channel and does not reuse any of them for
   Governance application traffic (§3.1);
5. Treats the frame-type range `0x00B0`–`0x00B4` as **reserved** for Governance
   quorum extension frames, assigns it to no other purpose, and does **not** claim
   any quorum-extension behavior as specified by the core specification, because the
   core specification reserves that range without defining its semantics (§3.2);
6. Does not treat any operation description in §4 as a normative wire encoding, and
   does not cite this reference as the source of any Governance request frame, reply
   frame, addressing scheme, value encoding, correlation scheme, voting rule, quorum
   threshold, or error model, none of which the core specification defines for this
   channel (§3.3, §4);
7. Supports the channel's **Bidirectional** direction — both peers sending and
   receiving on a single stream, each maintaining independent per-direction sequence
   spaces and traffic keys, without opening multiple concurrent transport
   sub-streams within a stream family (§2, §4); and
8. Defers all Governance operation semantics beyond the registry-level interface of
   §4 — and every High/Sovereign operational and cryptographic internal — to the
   controlled track and any future specification, adding no Governance behavior of
   its own that the core specification does not reserve (§4, §5, §6).

A conformance test suite SHOULD assert each clause above, and in particular SHOULD
verify clause 2 by confirming that an implementation refuses to enable channel
`0x0004` on a Standard-profile association, clause 3 by confirming that a Governance
frame arriving on an unadvertised channel is dropped, and clause 5 by confirming
that an implementation does not advertise, emit, or honor any frame in
`0x00B0`–`0x00B4` as a defined quorum operation on the sole basis of the core
specification.
