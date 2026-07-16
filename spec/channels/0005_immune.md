# NPAMP-CH-0005 — Immune Channel (`0x0005`) Interface Reference (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is a **per-channel interface reference** for the N-PAMP
> Immune channel (`0x0005`), derived from the N-PAMP core specification
> (draft-bubblefish-npamp-01, the "core specification"), §5 Channel Architecture
> and §8 Extension Points. It restates the channel's registry entry and its public
> frame-type reservations and describes the channel's anomaly-report and
> defensive-gossip interface **at the public level only**. It builds on the core
> specification, introduces no change to the core wire format, and defines no
> behavior the core specification does not already reserve. Where the core
> specification supplies only a registry line or reserves a code point without
> defining its semantics, this reference says so and describes the interface at
> that level. **The draft governs**: on any disagreement between this reference and
> the core specification, the core specification is authoritative.

## 1. Purpose

The core specification assigns channel `0x0005` the name **Immune** and the
purpose **"Anomaly reports and defensive gossip"** (core specification §5, Core
Channel Registry; `../../registries/channels.csv`). Expanded, the Immune channel
is the N-PAMP channel over which a peer reports **anomalies** — detected
operational or security irregularities — to another peer, and over which peers
**propagate defensive information** among themselves: the class of traffic that
raises the alarm about an observed irregularity and spreads defensive signal, as
distinct from ordinary operational metrics (Telemetry `0x000A`), bulk observations
(Sensory `0x0009`), or policy decision-making (Governance `0x0004`). It is one of
two channels the core specification singles out for **priority scheduling**
alongside the Control channel `0x0000` (core specification §5; see §5 of this
reference).

The core specification defines the Immune channel **only** as this registry entry
plus a reserved frame-type range for propagation extension frames (§3); it does
not define an Immune-specific wire encoding, message schema, or operation
contract. Accordingly, this reference describes the Immune interface at the level
the core specification actually fixes — the operation *classes* named by the
registry purpose (§4) — and does not invent frame layouts, field structures,
report schemas, gossip mechanisms, or semantics that the core specification does
not state. The companion specification NPAMP-IMMUNE
(`../companion/85_immune_channel.md`) now defines a concrete Immune operation
encoding within the code points the core specification reserves; this reference
documents the channel's public, registry-level interface, while the core
specification itself still defines no Immune operation encoding.

## 2. Channel identity

The following values are taken verbatim from the core channel registry
(core specification §5; machine-readable form `../../registries/channels.csv`).
They are normative in the core specification; this reference restates them and
does not alter them.

| Attribute | Value |
|---|---|
| Channel ID | `0x0005` |
| Name | Immune |
| Purpose | Anomaly reports and defensive gossip |
| Minimum profile | Standard |
| Direction | Bidirectional |

- **Minimum profile — Standard.** The Immune channel MAY be enabled at the
  Standard profile and is available at Standard and at every higher profile
  (High, Sovereign), per the core specification's min-profile rule (§5: the
  minimum profile is the lowest profile at which a channel may be enabled). See
  §5 for profile applicability.
- **Direction — Bidirectional.** Both peers send and receive frames on a single
  stream of this channel (core specification §5, Channel directionality). As with
  every N-PAMP channel, each peer maintains an independent send and receive
  sequence space and independent per-direction traffic keys, so both peers MAY
  transmit on the channel simultaneously (core specification §5). The Immune
  channel is **not** classified Multi-stream; it does not open multiple concurrent
  transport sub-streams within a stream family (contrast the Multi-stream channels
  such as Memory `0x0001` or Sensory `0x0009`).
- **Advertisement gate.** A peer that has not advertised the Immune channel during
  the handshake MUST NOT receive frames on it; frames on an unadvertised Immune
  channel MUST be dropped (core specification §5, applied to `0x0005`).

## 3. Frame types

Frame types on the Immune channel are drawn from the same per-channel
`0x0000`–`0xFFFF` frame-type namespace every N-PAMP channel uses
(core specification §4.6; reference `../04_frame_types.md`). Three groups are
relevant to this channel.

### 3.1 Reserved all-channel frame types

The following frame types are reserved across **all** channels with the same
meaning everywhere and retain that meaning on the Immune channel. An
implementation MUST NOT reuse them for Immune application traffic.

| Type | Name | Meaning on the Immune channel |
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

### 3.2 Reserved Immune-channel extension frame range

The core specification reserves one per-channel frame-type range specifically for
the Immune channel (core specification §8, Reserved Frame-Type Ranges; references
`../04_frame_types.md`, `../09_extension_points.md`):

| Range | Reserved for |
|---|---|
| `0x00C0` – `0x00C4` | Immune-channel propagation extension frames |

This range is **reserved, not defined**. The core specification neither defines
nor requires any propagation frame; it only reserves the code points so a
companion specification can define them without colliding with the core wire
format (core specification §8). The companion specification NPAMP-IMMUNE
(`../companion/85_immune_channel.md`) now defines these code points as the
defensive-gossip propagation exchange; the core specification itself still neither
defines nor requires them. An implementation therefore MUST NOT treat any propagation
behavior as specified by the core specification — those semantics are defined by
NPAMP-IMMUNE, not the core — and MUST NOT assign `0x00C0`–`0x00C4` to any other purpose.

> **Known editorial inconsistency in -00 (carried, not corrected here).** The core
> specification states that channel-specific frame types begin at `0x0100`
> (§4.6), yet the reserved Immune propagation range `0x00C0`–`0x00C4` sits below
> `0x0100`. This inconsistency is present in the submitted draft and is recorded
> in `../04_frame_types.md`; this reference does not silently rewrite the
> authoritative text.

### 3.3 Channel-specific frame types (`0x0100`+ convention)

Channel-specific frame types begin at **`0x0100`** within each channel's frame
namespace (core specification §4.6). This is the range in which an Immune-specific
operation encoding — for example concrete anomaly-report and defensive-gossip
request, reply, or notification frames (§4) — would be assigned. The core
specification defines **no** Immune-specific frame type in this range. The companion
specification NPAMP-IMMUNE (`../companion/85_immune_channel.md`) now defines the
Immune anomaly-report operation frames in this application band —
IMMUNE_REPORT_REQ (`0x0100`), IMMUNE_REPORT_RESULT (`0x0101`), and IMMUNE_ERROR
(`0x0102`) — as its §3.1; the core specification itself still neither defines nor
requires them. §4 describes the interface at the registry level the core
specification actually fixes; the concrete companion-defined frames are normative in
NPAMP-IMMUNE, not in the core specification.

## 4. Interface and operations (public level)

The Immune channel's public interface is the set of operation classes named by its
registry purpose. The core specification fixes these as **names of operation
classes**, not as wire encodings; this section restates them at that level and
states explicitly where the core specification stops. An implementation MUST NOT
read a wire format into this section: no frame layout, field structure, TLV,
correlation scheme, or propagation algorithm below is defined by the core
specification.

| Operation class | Public meaning (from the registry purpose) |
|---|---|
| Anomaly report | Report a detected operational or security irregularity ("anomaly") observed by one peer to another peer. |
| Defensive gossip | Propagate defensive information among peers, spreading signal beyond the pair that first observed or reported it. |

Notes and honest boundaries:

- **No operation encoding is defined here.** Because the core specification assigns
  no Immune-specific frame type (§3.3), the operation classes above have **no
  core-defined request frame, reply frame, report schema, addressing scheme,
  payload encoding, or error model**. This reference MUST NOT be cited as the
  source of any such encoding.
- **"Propagation" is reserved, not defined.** The only Immune-specific extension
  surface the core specification names beyond the registry purpose is the
  **propagation** frame range (`0x00C0`–`0x00C4`, §3.2), and it names it only by
  reserving frame code points. Its semantics — including any fan-out, relay,
  suppression, freshness, or anti-entropy behavior a "defensive gossip"
  propagation might imply — are undefined by the core specification and out of
  scope for this reference; the companion NPAMP-IMMUNE
  (`../companion/85_immune_channel.md`) defines the propagation model (its §7),
  while the core specification itself still neither defines nor requires it. An
  implementation MUST
  NOT infer a propagation mechanism from the registry word "gossip" or from the
  reserved range's name.
- **Correlation and ordering.** The Immune channel has an independent per-direction
  sequence space (core specification §5), which orders frames within a direction.
  The core specification does not define how an Immune reply (if any) is correlated
  to a report (unlike the Bridge channel, where NPAMP-BRIDGE §5 defines a
  `correlation_id`); an Immune operation encoding, when specified by a companion,
  is where such correlation would be defined. This reference does not define it.
- **AnomalyCharge TLV is not part of this channel's interface.** The core
  specification defines a TLV `0x12` "AnomalyCharge" in its TLV type registry as a
  general **per-frame integrity charge** (core specification §9, TLV Type
  Registry). Despite the thematic overlap in name, the core specification does
  **not** bind that TLV to the Immune channel or make it an Immune operation; it
  is a general wire-level mechanism, not an Immune-channel report frame. This
  reference does not claim any relationship the core specification does not state.

## 5. Profile applicability

The Immune channel's minimum profile is **Standard** (§2). By the core
specification's min-profile rule (§5), the channel is available at the Standard
profile and at every higher profile; that is, at **Standard, High, and
Sovereign**. There is no profile at which the Immune channel is unavailable once
its minimum profile is met, and no upper profile bound.

- **Standard profile.** The Immune channel is available and MAY be enabled. This is
  the profile at which the public Immune interface described in this reference is
  fully expressible.
- **Higher profiles (High, Sovereign).** The Immune channel remains available with
  the same wire-level frame namespace and the same public interface. N-PAMP's
  profiles share **one wire format** and differ in the cryptographic primitives and
  operational requirements they mandate (core specification §6, Profile
  Negotiation). The specific cryptographic suite bound to each profile is defined
  by the core specification's profile-negotiation and cryptographic-suite sections
  and is **out of scope for this interface reference**; this reference describes the
  channel's public, profile-invariant interface only.
- **Priority scheduling.** The core specification singles out the **Control and
  Immune channels**, stating they SHOULD be scheduled at higher priority than the
  **bulk** channels (Memory, Sensory, Telemetry) during congestion (core
  specification §5). The Immune channel is therefore not a bulk channel: its
  anomaly-report and defensive-gossip traffic is intended to be delivered promptly
  even when lower-priority channels are congested. This is a scheduling
  recommendation on delivery order, not a change to the Immune interface, its
  identity, or its frame namespace.
- **Publishing scope.** This reference documents only the public **Standard-profile
  interface surface** of the channel — its identity, purpose, direction, minimum
  profile, and public frame-type namespace. High- and Sovereign-profile
  cryptographic internals and parameters are governed by the core specification's
  profile negotiation and are out of scope here.

## 6. Relationship to companion specifications

The Immune channel is a **native core channel**: unlike the Bridge channel
(`0x000D`), which encapsulates foreign agent protocols and is elaborated by the
NPAMP-BRIDGE companion framework (`../companion/10_bridge_framework.md`) and its
carriage classes, and unlike the Discovery channel (`0x0010`), elaborated by
NPAMP-DISC (`../companion/40_discovery.md`), the Immune channel's dedicated
companion specification NPAMP-IMMUNE (`../companion/85_immune_channel.md`) — listed
in the current companion set (`../companion/00_companion_index.md`) — defines a
**native** Immune operation encoding rather than a foreign-protocol carriage. It is
therefore not a bridge carriage class and does not build on NPAMP-BRIDGE.

The consequence for an implementer is that the Immune channel's public,
registry-level contract — what this interface reference documents — is what §2–§5
restate, above which the companion NPAMP-IMMUNE (`../companion/85_immune_channel.md`)
defines the concrete operation encoding:

- Its **identity** — id `0x0005`, name Immune, purpose "anomaly reports and
  defensive gossip", minimum profile Standard, direction Bidirectional (§2);
- Its **public interface** — the anomaly-report and defensive-gossip operation
  classes, described at the registry level, with **no core-defined wire encoding**
  (§4);
- Its **reserved extension surface** — the `0x00C0`–`0x00C4` propagation frame-type
  range, reserved by the core specification and now defined by the companion
  NPAMP-IMMUNE (`../companion/85_immune_channel.md`), not by the core specification
  (§3.2); and
- Its **scheduling posture** — a priority channel alongside Control `0x0000`,
  scheduled above the bulk channels during congestion (§5).

Richer, interoperable Immune operations are now defined by the companion
specification NPAMP-IMMUNE (`../companion/85_immune_channel.md`), authored the same
way as any N-PAMP extension: it defines an Immune operation encoding — anomaly-report
frames in the application band and defensive-gossip propagation frames in the
reserved code points — verified against the core specification. This interface
reference documents the channel's public, registry-level contract; the concrete
operation encoding, in-body correlation discipline, propagation model, and error
model live in NPAMP-IMMUNE, not here, and the core specification itself still neither
defines nor requires them. This reference documents the
interface at that public level and defines no new behavior.

## 7. Conformance

An implementation conforms to this Immune-channel interface reference if and only
if, for channel `0x0005`, it:

1. Treats channel `0x0005` as the **Immune** channel whose purpose is anomaly
   reports and defensive gossip, consistent with the core channel registry (§2),
   and does not repurpose the channel identifier for other traffic;
2. Enables the Immune channel only at the **Standard** profile or higher, never
   below Standard, and — once Standard is met — treats the channel as available at
   Standard, High, and Sovereign (§2, §5);
3. Drops any frame received on the Immune channel that the peer has not advertised
   during the handshake, and does not deliver such frames to the anomaly-report or
   gossip logic (§2);
4. Preserves the core meaning of the reserved all-channel frame types
   (`0x0001`–`0x000A`) on the Immune channel and does not reuse any of them for
   Immune application traffic (§3.1);
5. Treats the frame-type range `0x00C0`–`0x00C4` as **reserved** for Immune
   propagation extension frames, assigns it to no other purpose, and does **not**
   claim any propagation behavior as specified by the core specification, because
   the core specification reserves that range without defining its semantics
   (§3.2);
6. Does not treat any operation description in §4 as a normative wire encoding, and
   does not cite this reference as the source of any Immune report frame, reply
   frame, gossip mechanism, addressing scheme, payload encoding, correlation
   scheme, or error model, none of which the core specification defines for this
   channel (§3.3, §4);
7. Supports the channel's **Bidirectional** direction — both peers sending and
   receiving on a single stream, each maintaining an independent per-direction
   sequence space and traffic keys — and does not treat the channel as Multi-stream
   (§2); and
8. Defers all Immune operation semantics beyond the registry-level interface of §4
   to the companion specification NPAMP-IMMUNE (`../companion/85_immune_channel.md`),
   adding no Immune behavior of its own that the core specification does not reserve
   (§6).

A conformance test suite SHOULD assert each clause above, and in particular SHOULD
verify clause 5 by confirming that an implementation does not advertise, emit, or
honor any frame in `0x00C0`–`0x00C4` as a defined propagation operation on the sole
basis of the core specification, and clause 3 by confirming that an Immune frame
arriving on an unadvertised channel is dropped. A per-channel reference MUST NOT be
read to add behavior the core specification does not define; where the core
specification gives this channel only a registry line and a reserved code-point
range, that is the whole of the public Immune interface.
