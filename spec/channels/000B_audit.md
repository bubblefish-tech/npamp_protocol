# NPAMP-CH-000B — Audit Channel (`0x000B`) Interface Reference (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is a **per-channel interface reference** for the N-PAMP
> Audit channel (`0x000B`), derived from the N-PAMP core specification
> (draft-bubblefish-npamp-01, the "core specification"), §5 Channel Architecture
> and §8 Extension Points. It restates the channel's registry entry and its public
> frame-type reservations and describes the channel's public interface **at the
> registry level only**. The Audit channel's minimum profile is **Sovereign**;
> its operational and cryptographic internals require a firewall-gated profile and
> are **out of scope** for this public reference — they are governed by the
> controlled track, not restated here. This document builds on the core
> specification, introduces no change to the core wire format, and defines no
> behavior the core specification does not already reserve. Where the core
> specification supplies only a registry line or reserves a code point without
> defining its semantics, this reference says so and describes the interface at
> that level. **The draft governs**: on any disagreement between this reference and
> the core specification, the core specification is authoritative.

## 1. Purpose

The core specification assigns channel `0x000B` the name **Audit** and the purpose
**"Audit-epoch commitments and transparency-log entries"** (core specification §5,
Core Channel Registry; `../../registries/channels.csv`). At the registry level, the
Audit channel is the N-PAMP channel over which a peer conveys **audit-epoch
commitments** and **transparency-log entries** — the class of traffic that records
tamper-evident checkpoints of an association's history — as distinct from durable
addressable state (Memory `0x0001`), operational metrics (Telemetry `0x000A`), or
agent-to-agent settlement receipts (Settlement `0x0007`).

The core specification defines the Audit channel **only** as this registry entry
plus reserved frame-type ranges for extension frames (§3); it does not define an
Audit-specific wire encoding, message schema, or operation contract in the public
text. Accordingly, this reference describes the Audit interface at the level the
core specification actually fixes — the registry line and the reserved code points
— and does not invent frame layouts, field structures, or semantics that the core
specification does not state.

**Firewall boundary.** The Audit channel is a **Sovereign-profile** channel
(§2, §5). This reference is a **public interface stub**: it documents the channel's
*existence*, identifier, name, purpose, direction, minimum profile, and public
frame-range reservations — all of which the public draft already states. It does
**not** describe how audit-epoch commitments or transparency-log entries are
constructed, signed, sequenced, or verified. Those operational and cryptographic
internals require the Sovereign profile and live in the **controlled/private
track**; they are out of scope here and are not restated, summarized, or inferred
by this document.

## 2. Channel identity

The following values are taken verbatim from the core channel registry
(core specification §5; machine-readable form `../../registries/channels.csv`). They
are normative in the core specification; this reference restates them and does not
alter them.

| Attribute | Value |
|---|---|
| Channel ID | `0x000B` |
| Name | Audit |
| Purpose | Audit-epoch commitments and transparency-log entries |
| Minimum profile | Sovereign |
| Direction | Bidirectional |

- **Minimum profile — Sovereign.** Sovereign is the highest of the three N-PAMP
  profiles (Standard, High, Sovereign) (core specification §6, Profile
  Negotiation). The core specification states specifically that **"the Audit
  channel is enabled by default only at Sovereign; other profiles MAY enable it"**
  (core specification §5). This reference reproduces that rule exactly and does not
  narrow or broaden it: by default the channel is a Sovereign-profile channel, and
  enabling it at a lower profile is a MAY the core specification permits, not a
  behavior this reference defines. See §5 for profile applicability.
- **Direction — Bidirectional.** Both peers send and receive frames on a single
  stream of this channel (core specification §5, Channel directionality). As with
  every N-PAMP channel, each peer maintains an independent per-direction send and
  receive sequence space and independent per-direction traffic keys, so both peers
  MAY transmit on the channel simultaneously (core specification §5). The Audit
  channel is **not** classified Multi-stream; it does not open multiple concurrent
  transport sub-streams within a stream family (contrast the Memory `0x0001` and
  Stream `0x000C` channels).
- **Advertisement gate.** A peer that has not advertised the Audit channel during
  the handshake MUST NOT receive frames on it; frames on an unadvertised Audit
  channel MUST be dropped (core specification §5, applied to `0x000B`).

## 3. Frame types

Frame types on the Audit channel are drawn from the same per-channel
`0x0000`–`0xFFFF` frame-type namespace every N-PAMP channel uses
(core specification §4.6; reference `../04_frame_types.md`). Three groups are
relevant to this channel.

### 3.1 Reserved all-channel frame types

The following frame types are reserved across **all** channels with the same
meaning everywhere and retain that meaning on the Audit channel. An implementation
MUST NOT reuse them for Audit application traffic.

| Type | Name | Meaning on the Audit channel |
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

### 3.2 Reserved Audit-channel extension frame ranges

The core specification reserves the following per-channel frame-type ranges that
name the Audit channel (core specification §8.1, Reserved Frame-Type Ranges;
references `../04_frame_types.md` and `../09_extension_points.md`):

| Range | Reserved for |
|---|---|
| `0x0090` – `0x0090` | Audit-channel per-frame integrity-extension frames |
| `0x00A0` – `0x00A3` | Settlement/Audit batch-commitment extension frames |

These ranges are **reserved, not defined**. The core specification neither defines
nor requires per-frame integrity-extension frames or batch-commitment extension
frames; it only reserves the code points so a companion specification can define
them without colliding with the core wire format (core specification §8). No
companion specification in the current set (`../companion/00_companion_index.md`)
defines these frames. An implementation therefore MUST NOT treat any
integrity-extension or batch-commitment behavior as specified by the core
specification, and MUST NOT assign `0x0090` or `0x00A0`–`0x00A3` to any other
purpose. The `0x00A0`–`0x00A3` range is a **shared Settlement/Audit** reservation
(it names both the Settlement channel `0x0007` and the Audit channel); this
reference does not resolve which channel a companion would bind it to and records
only that the core specification reserves it under that shared label.

> **Known editorial inconsistency in -00 (carried, not corrected here).** The core
> specification states that channel-specific frame types begin at `0x0100`
> (§4.6), yet the reserved Audit extension ranges `0x0090` and `0x00A0`–`0x00A3`
> sit below `0x0100`. This inconsistency is present in the submitted draft and is
> recorded in `../04_frame_types.md`; this reference does not silently rewrite the
> authoritative text.

### 3.3 Channel-specific frame types (`0x0100`+ convention)

Channel-specific frame types begin at **`0x0100`** within each channel's frame
namespace (core specification §4.6). This is the range in which an Audit-specific
operation encoding — for example concrete audit-epoch-commitment and
transparency-log-entry request and reply frames — would be assigned. The core
specification defines **no** Audit-specific frame type in this range, and no
companion specification in the current set defines one. Consequently there is, at
present, no core- or companion-defined Audit operation frame; §4 describes the
interface at the registry level the core specification actually fixes.

## 4. Interface and operations (public level)

The Audit channel's public interface is exactly its registry line: it carries
**audit-epoch commitments and transparency-log entries** (core specification §5).
The core specification fixes these as **names of the traffic the channel carries**,
not as wire encodings; this section restates them at that level and states
explicitly where the public core specification stops. An implementation MUST NOT
read a wire format into this section: no frame layout, field structure, TLV, or
correlation scheme below is defined by the public core specification.

| Traffic class | Public meaning (from the registry purpose) |
|---|---|
| Audit-epoch commitment | A commitment recording a tamper-evident checkpoint of an audit epoch, as named by the registry purpose. |
| Transparency-log entry | An entry appended to a transparency log of the association's auditable events, as named by the registry purpose. |

Notes and honest boundaries:

- **No operation encoding is defined here.** Because the public core specification
  assigns no Audit-specific frame type (§3.3), the traffic classes above have **no
  public core-defined request frame, reply frame, addressing scheme, value
  encoding, or error model**. This reference MUST NOT be cited as the source of any
  such encoding.
- **Correlation and ordering.** The Audit channel has an independent per-direction
  sequence space (core specification §5), which orders frames within a direction.
  The public core specification does not define how an Audit reply is correlated to
  its request (unlike the Bridge channel, where NPAMP-BRIDGE §5 defines a
  `correlation_id`). This reference does not define it.
- **Operational and cryptographic internals are out of scope (firewall).** How an
  audit-epoch commitment or a transparency-log entry is constructed, sequenced,
  signed, and verified is a **Sovereign-profile** operational concern governed by
  the controlled track, not by this public reference. This document neither
  describes nor implies any such internal behavior, any signing or hashing
  construction, or any profile-specific cryptographic parameter. Referencing the
  public profile names and the code-point tables already published in the core
  specification is the full extent of what this page states about profile; the
  per-profile cryptographic suites themselves are selected by the core
  specification's profile negotiation and key schedule and are out of scope here.

## 5. Profile applicability

The Audit channel's minimum profile is **Sovereign** (§2). Sovereign is the highest
of N-PAMP's three profiles (Standard, High, Sovereign) (core specification §6). The
core specification states specifically that the Audit channel is **enabled by
default only at Sovereign, and that other profiles MAY enable it** (core
specification §5).

- **Sovereign profile (default).** The Audit channel is enabled by default at the
  Sovereign profile. This is the profile the core specification associates with the
  channel by default.
- **Lower profiles (Standard, High).** The core specification permits other profiles
  to enable the Audit channel — "other profiles MAY enable it" (core specification
  §5). This reference reproduces that permission and neither requires nor forbids a
  lower-profile deployment beyond what the core specification states; enabling the
  channel below Sovereign is a deployment choice the core specification allows, not
  a behavior this reference defines.
- **Profile-invariant framing.** N-PAMP's three profiles share **one wire format**
  and differ in the cryptographic primitives and operational requirements they
  mandate (core specification §6, Profile Negotiation). The Audit channel's framing
  and public interface — its identity (§2), its frame-type namespace (§3), and the
  registry-level interface (§4) — are **profile-invariant**: they do not change
  across profiles. The per-profile cryptographic suites are selected by the core
  specification's profile negotiation and key schedule and are **out of scope for
  this per-channel interface reference**.
- **Scheduling.** The core specification's congestion-scheduling recommendation
  names Memory, Sensory, and Telemetry as the **bulk** channels and states that the
  Control and Immune channels SHOULD be scheduled at higher priority than those bulk
  channels during congestion (core specification §5). The Audit channel is **not
  enumerated** in either group; this reference therefore makes no scheduling claim
  for it beyond noting that the core specification does not place it in either set.
- **Publishing scope (firewall).** This reference documents only the channel's
  **public registry-level surface** — its identity, purpose, direction, minimum
  profile, and public frame-type reservations. The channel's Sovereign-profile
  operational and cryptographic internals and parameters are governed by the
  controlled track and are out of scope here; they are not restated, summarized, or
  inferred by this document.

## 6. Relationship to companion specifications

The Audit channel is a **native core channel**: unlike the Bridge channel
(`0x000D`), which encapsulates foreign agent protocols and is elaborated by the
NPAMP-BRIDGE companion framework (`../companion/10_bridge_framework.md`) and its
carriage classes, and unlike the Discovery channel (`0x0010`), elaborated by
NPAMP-DISC (`../companion/40_discovery.md`), the Audit channel has **no dedicated
companion specification** in the current companion set
(`../companion/00_companion_index.md`). It is therefore not a bridge carriage class
and does not build on NPAMP-BRIDGE.

The consequence for an implementer is that the Audit channel's **public** contract
is exactly what §2–§5 restate:

- Its **identity** — id `0x000B`, name Audit, purpose "audit-epoch commitments and
  transparency-log entries", minimum profile Sovereign, direction Bidirectional
  (§2);
- Its **public interface** — the audit-epoch-commitment and transparency-log-entry
  traffic classes, described at the registry level, with **no public core-defined
  wire encoding** (§4); and
- Its **reserved extension surface** — the `0x0090` Audit-channel per-frame
  integrity-extension range and the `0x00A0`–`0x00A3` shared Settlement/Audit
  batch-commitment range, reserved by the core specification and defined by neither
  the core specification nor any current companion (§3.2). The `0x00A0`–`0x00A3`
  range also names the Settlement channel `0x0007`; a companion that binds it would
  state the binding, which this reference does not.

Everything beyond that public surface — the channel's Sovereign-profile
operational semantics and cryptographic internals — is governed by the controlled
track and is deliberately **out of scope** for this public reference (§1, §4, §5).
Should richer, interoperable public Audit operations be wanted, the path is the same
as for any N-PAMP extension: author a companion specification that defines an Audit
operation encoding within the reserved code points, verified against the core
specification. Until such a companion exists, an implementation carries Audit
traffic under the channel identity and reserved code points above, and there is no
additional public core- or companion-defined Audit behavior to conform to. This
reference documents the interface at that public level and defines no new behavior.

## 7. Conformance

An implementation conforms to this Audit-channel interface reference if and only if,
for channel `0x000B`, it:

1. Treats channel `0x000B` as the **Audit** channel whose purpose is "audit-epoch
   commitments and transparency-log entries", consistent with the core channel
   registry (§2), and does not repurpose the channel identifier or alter any of its
   registry values;
2. Treats the channel's minimum profile as **Sovereign** — enabled by default only
   at the Sovereign profile — and, where it enables the channel at a lower profile,
   does so only as the core specification's "other profiles MAY enable it"
   permission allows, adding no requirement this reference does not state (§2, §5);
3. Drops any frame received on the Audit channel that the peer has not advertised
   during the handshake, and does not deliver such frames (§2);
4. Preserves the core meaning of the reserved all-channel frame types
   (`0x0001`–`0x000A`) on the Audit channel and does not reuse any of them for Audit
   application traffic (§3.1);
5. Treats the frame-type range `0x0090` (Audit-channel per-frame integrity-extension
   frames) and the range `0x00A0`–`0x00A3` (shared Settlement/Audit batch-commitment
   extension frames) as **reserved**, assigns them to no other purpose, and does
   **not** claim integrity-extension or batch-commitment behavior as specified by
   the core specification, because the core specification reserves those ranges
   without defining their semantics (§3.2);
6. Does not treat any traffic-class description in §4 as a normative wire encoding,
   and does not cite this reference as the source of any Audit request frame, reply
   frame, addressing scheme, value encoding, correlation scheme, or error model,
   none of which the public core specification defines for this channel (§3.3, §4);
   and
7. Does not read into this reference any Sovereign-profile operational or
   cryptographic internal of the channel, which are out of scope here and governed
   by the controlled track (§1, §4, §5).

A conformance test suite SHOULD assert each clause above, and in particular SHOULD
verify clause 5 by confirming that an implementation does not advertise, emit, or
honor any frame in `0x0090` or `0x00A0`–`0x00A3` as a defined operation on the sole
basis of the core specification, and clause 3 by confirming that an Audit frame
arriving on an unadvertised channel is dropped. This reference defines no frame
semantics, encoding, correlation, or cryptographic behavior of its own; a
per-channel reference MUST NOT be read to add behavior the core specification does
not define.
