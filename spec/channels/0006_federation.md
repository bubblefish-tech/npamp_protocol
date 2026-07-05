# NPAMP-CH-0006 — Federation Channel (`0x0006`) Interface Reference (companion to draft-bubblefish-npamp-00)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is a **per-channel interface reference** for the N-PAMP
> Federation channel (`0x0006`), derived from the N-PAMP core specification
> (draft-bubblefish-npamp-00, the "core specification"), §5 Channel Architecture
> and §8 Extension Points. It restates the channel's registry entry and its public
> frame-type reservations and describes the channel's public interface **at the
> public level only**. It builds on the core specification, introduces no change to
> the core wire format, and defines no behavior the core specification does not
> already reserve. Where the core specification supplies only a registry line or
> reserves a code point without defining its semantics, this reference says so and
> describes the interface at that level. The Federation channel is a **firewall-
> gated channel**: its minimum profile is **High**, and its operational and
> cryptographic internals are governed by the controlled track, not this public
> reference (§4, §5). **The draft governs**: on any disagreement between this
> reference and the core specification, the core specification is authoritative.

## 1. Purpose

The core specification assigns channel `0x0006` the name **Federation** and the
purpose **"Cross-instance synchronization and gossip"** (core specification §5,
Core Channel Registry; `../../registries/channels.csv`). At the public level, the
Federation channel is the N-PAMP channel over which separate N-PAMP instances
exchange the two named classes of traffic — **cross-instance synchronization**
(reconciling state that is held across distinct instances) and **gossip**
(instance-to-instance dissemination) — as distinct from a single peer managing
durable state on another peer (Memory `0x0001`) or a peer reporting anomalies and
defensive gossip within an association (Immune `0x0005`). The registry phrase
names *cross-instance* traffic: the participants are instances/deployments, and
the channel's purpose is the synchronization and gossip that crosses between them.

The core specification defines the Federation channel **only** as this registry
entry; it does not define a Federation-specific wire encoding, message schema, or
operation contract, and — unlike the Memory, Capability, Control, Audit,
Settlement/Audit, Governance, and Immune channels — it reserves **no** dedicated
sub-`0x0100` frame-type range for it (§3.2; core specification §8, Reserved
Frame-Type Ranges). Accordingly, this reference describes the Federation interface
at the level the core specification actually fixes — the operation *classes* named
by the registry purpose (§4) — and does not invent frame layouts, field
structures, or semantics that the core specification does not state. Because the
channel's minimum profile is **High** (§2, §5), its operations are available only
to High- and Sovereign-profile associations; the operational and cryptographic
detail of how those operations run is out of scope for this public reference and
belongs to the controlled track.

## 2. Channel identity

The following values are taken verbatim from the core channel registry
(core specification §5; machine-readable form `../../registries/channels.csv`). They are
normative in the core specification; this reference restates them and does not
alter them.

| Attribute | Value |
|---|---|
| Channel ID | `0x0006` |
| Name | Federation |
| Purpose | Cross-instance synchronization and gossip |
| Minimum profile | High |
| Direction | Multi-stream |

- **Minimum profile — High.** The Federation channel MAY be enabled only at the
  **High** profile or higher; it is available at **High and Sovereign** and is
  **not** available at Standard, per the core specification's min-profile rule
  (core specification §5: the minimum profile is the lowest profile at which a
  channel may be enabled, and the channel is available at that profile and every
  higher profile — a "High" channel is available at High and Sovereign). This makes
  Federation a firewall-gated channel; see §5 for profile applicability and the
  publishing-scope boundary.
- **Direction — Multi-stream.** Federation is bidirectional, and the channel MAY
  open multiple concurrent transport streams within its stream family
  (core specification §5, Channel directionality). Each peer maintains an
  independent per-direction sequence space and independent per-direction traffic
  keys for the channel (core specification §5).
- **Advertisement gate.** A peer that has not advertised the Federation channel
  during the handshake MUST NOT receive frames on it; frames on an unadvertised
  Federation channel MUST be dropped (core specification §5, applied to `0x0006`).

## 3. Frame types

Frame types on the Federation channel are drawn from the same per-channel
`0x0000`–`0xFFFF` frame-type namespace every N-PAMP channel uses
(core specification §4.6; reference `../04_frame_types.md`). Three groups are
relevant to this channel.

### 3.1 Reserved all-channel frame types

The following frame types are reserved across **all** channels with the same
meaning everywhere and retain that meaning on the Federation channel. An
implementation MUST NOT reuse them for Federation application traffic.

| Type | Name | Meaning on the Federation channel |
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

### 3.2 No reserved Federation-channel extension frame range

The core specification's Reserved Frame-Type Ranges table (core specification §8,
Reserved Frame-Type Ranges; reference `../09_extension_points.md`) reserves several
sub-`0x0100` code-point ranges for companion extensions — but **none of those
ranges is assigned to the Federation channel**. The reserved ranges there belong to
the Memory (`0x0035`–`0x0036`), Capability (`0x0060`–`0x0063`), Control
(`0x0080`), Audit (`0x0090`), Settlement/Audit (`0x00A0`–`0x00A3`), Governance
(`0x00B0`–`0x00B4`), and Immune (`0x00C0`–`0x00C4`) channels. The core
specification therefore reserves **no** dedicated per-channel frame-type range for
Federation. An implementation MUST NOT assign any of those other channels' reserved
ranges to Federation traffic.

> **Known editorial inconsistency in -00 (carried, not corrected here).** The core
> specification states that channel-specific frame types begin at `0x0100`
> (§4.6), yet the reserved companion ranges above sit below `0x0100`
> (`0x0035`–`0x00C4`). This inconsistency is present in the submitted draft and is
> recorded in `../04_frame_types.md`; because no such range is assigned to
> Federation, the inconsistency does not affect this channel, whose operational
> frames would sit at `0x0100`+.

### 3.3 Channel-specific frame types (`0x0100`+ convention)

Channel-specific frame types begin at **`0x0100`** within each channel's frame
namespace (core specification §4.6). This is the range in which a Federation-
specific operation encoding — for example concrete synchronization and gossip
request and reply frames (§4) — would be assigned. The core specification defines
**no** Federation-specific frame type in this range, and no companion specification
in the current set (`../companion/00_companion_index.md`) defines one. Consequently
there is, at present, no core- or companion-defined Federation operation frame; §4
describes the interface at the registry level the core specification actually
fixes. Any concrete Federation operation encoding is a matter for the controlled
track (§4, §5, §6), consistent with the channel's High minimum profile, and is out
of scope for this public reference.

## 4. Interface and operations (public level)

The Federation channel's public interface is the set of operation classes named by
its registry purpose. The core specification fixes these as **names of operation
classes**, not as wire encodings; this section restates them at that level and
states explicitly where the core specification stops. An implementation MUST NOT
read a wire format into this section: no frame layout, field structure, TLV, or
correlation scheme below is defined by the core specification.

| Operation class | Public meaning (from the registry purpose) |
|---|---|
| Cross-instance synchronization | Reconcile state that is held across distinct N-PAMP instances so that the participating instances converge. |
| Gossip | Disseminate information between instances in the instance-to-instance manner the registry names alongside synchronization. |

Notes and honest boundaries:

- **Registry-level only.** The registry purpose lists exactly these two classes
  ("cross-instance synchronization **and** gossip"). The core specification does not
  further decompose either class, nor distinguish their message flows; this
  reference records the two named classes and does not manufacture sub-operations,
  a state-reconciliation algorithm, or a gossip fan-out policy that the core
  specification does not state.
- **No operation encoding is defined here.** Because the core specification assigns
  no Federation-specific frame type (§3.3), the operation classes above have **no
  core-defined request frame, reply frame, addressing scheme, value encoding, or
  error model**. This reference MUST NOT be cited as the source of any such
  encoding.
- **Correlation and ordering.** The Federation channel has an independent
  per-direction sequence space (core specification §5), which orders frames within a
  direction. The core specification does not define how a Federation reply is
  correlated to its request; a Federation operation encoding, when specified, is
  where such correlation would be defined. This reference does not define it.
- **Multi-stream concurrency.** Because the channel is Multi-stream (§2), a
  deployment MAY carry concurrent Federation operations over multiple transport
  streams within the channel's stream family; the core specification permits this at
  the channel level and does not constrain how operations are distributed across
  those streams.
- **Firewall boundary — operations require the High or Sovereign profile.** The
  Federation channel's minimum profile is High (§2, §5); an association that has not
  negotiated at least the High profile MUST NOT enable the channel, so these
  operations are unavailable to a Standard-profile association. The operational and
  cryptographic internals that carry these operations at the High and Sovereign
  profiles are governed by the controlled track and are **out of scope** for this
  public reference. This page publishes only the channel's public surface — its
  existence, identifier, name, purpose, direction, minimum profile, and public
  frame-type namespace — and describes no High- or Sovereign-profile operational or
  cryptographic behavior.

## 5. Profile applicability

The Federation channel's minimum profile is **High** (§2). By the core
specification's min-profile rule (§5), the channel is available at the High profile
and at every higher profile; that is, at **High and Sovereign**, and **not** at
Standard. There is no profile below High at which the Federation channel may be
enabled.

- **Standard profile.** The Federation channel is **not available**. An association
  operating at the Standard profile MUST NOT enable channel `0x0006` (core
  specification §5, min-profile rule). This is the firewall gate: Federation is a
  High-minimum, firewall-gated channel, not a baseline-profile channel.
- **High and Sovereign profiles.** The Federation channel MAY be enabled and its
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
  Federation channel is named in neither group, so the core specification states no
  scheduling priority for it and this reference does not assign one.
- **Publishing scope (firewall).** This reference documents only the **public
  interface surface** of the channel — its identity, purpose, direction, minimum
  profile, and public frame-type namespace, all of which the core specification
  publishes in §5. The channel's operational and cryptographic internals — the way
  its synchronization and gossip operations run at the High and Sovereign profiles,
  and every High/Sovereign cryptographic parameter — live in the controlled track
  and are **out of scope** here. Referencing the public profile names (Standard,
  High, Sovereign) and the identity/code-point facts the core specification already
  publishes is in scope; reproducing High/Sovereign cryptographic internals is not.

## 6. Relationship to companion specifications

The Federation channel is a **native core channel**: unlike the Bridge channel
(`0x000D`), which encapsulates foreign agent protocols and is elaborated by the
NPAMP-BRIDGE companion framework (`../companion/10_bridge_framework.md`) and its
carriage classes, and unlike the Discovery channel (`0x0010`), elaborated by
NPAMP-DISC (`../companion/40_discovery.md`), the Federation channel has **no
dedicated companion specification** in the current companion set
(`../companion/00_companion_index.md`). It is therefore not a bridge carriage class
and does not build on NPAMP-BRIDGE.

The consequence for an implementer is that the Federation channel's public contract
is exactly what §2–§5 restate:

- Its **identity** — id `0x0006`, name Federation, purpose "cross-instance
  synchronization and gossip", minimum profile High, direction Multi-stream (§2);
- Its **public interface** — the cross-instance synchronization and gossip
  operation classes, described at the registry level, with **no core-defined wire
  encoding** (§4); and
- Its **reserved extension surface** — **none**: the core specification reserves no
  dedicated sub-`0x0100` frame-type range for Federation (§3.2), and any
  Federation-specific frames would occupy the channel's own `0x0100`+ namespace
  (§3.3).

Should richer, interoperable Federation operations be wanted, the path is the same
as for any N-PAMP extension: author a specification that defines a Federation
operation encoding within the channel's `0x0100`+ namespace, verified against the
core specification. Because the channel is firewall-gated at the High profile,
that operational definition belongs to the **controlled track**, not this public
reference. Until such a definition exists, an implementation carries Federation
traffic under the channel identity and code points above, and there is no
additional core- or companion-defined Federation behavior in the public track to
conform to. This reference documents the interface at that public level and defines
no new behavior.

## 7. Conformance

An implementation conforms to this Federation-channel interface reference if and
only if, for channel `0x0006`, it:

1. Treats channel `0x0006` as the **Federation** channel whose purpose is
   cross-instance synchronization and gossip, consistent with the core channel
   registry (§2), and does not repurpose the channel identifier for other traffic;
2. Enables the Federation channel only at the **High** profile or higher (High or
   Sovereign) and **never** below High, so that a Standard-profile association does
   not enable channel `0x0006` (§2, §5);
3. Drops any frame received on the Federation channel that the peer has not
   advertised during the handshake, and does not deliver such frames (§2);
4. Preserves the core meaning of the reserved all-channel frame types
   (`0x0001`–`0x000A`) on the Federation channel and does not reuse any of them for
   Federation application traffic (§3.1);
5. Recognizes that the core specification reserves **no** dedicated sub-`0x0100`
   frame-type range for Federation, assigns none of the other channels' reserved
   ranges (`0x0035`–`0x00C4`) to Federation traffic, and places any Federation-
   specific frame in the channel's own `0x0100`+ namespace (§3.2, §3.3);
6. Does not treat any operation description in §4 as a normative wire encoding, and
   does not cite this reference as the source of any Federation request frame, reply
   frame, addressing scheme, value encoding, correlation scheme, or error model,
   none of which the core specification defines for this channel (§3.3, §4);
7. Supports the channel's **Multi-stream** direction — bidirectional operation with
   the OPTIONAL opening of multiple concurrent transport streams within the
   channel's stream family, each peer maintaining independent per-direction sequence
   spaces and traffic keys (§2, §4); and
8. Defers all Federation operation semantics beyond the registry-level interface of
   §4 — and every High/Sovereign operational and cryptographic internal — to the
   controlled track and any future specification, adding no Federation behavior of
   its own that the core specification does not reserve (§4, §5, §6).

A conformance test suite SHOULD assert each clause above, and in particular SHOULD
verify clause 2 by confirming that an implementation refuses to enable channel
`0x0006` on a Standard-profile association, and clause 3 by confirming that a
Federation frame arriving on an unadvertised channel is dropped.
