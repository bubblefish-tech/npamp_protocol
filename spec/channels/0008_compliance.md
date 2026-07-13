# NPAMP-CH-0008 — Compliance Channel (`0x0008`) Interface Reference (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is a **per-channel interface reference** for the N-PAMP
> Compliance channel (`0x0008`), derived from the N-PAMP core specification
> (draft-bubblefish-npamp-01, the "core specification"), §5 Channel Architecture
> and its Profile Negotiation section. It restates the channel's registry entry,
> its public frame-type reservations, and its public profile gating, and describes
> the channel's attestation and regulatory-export interface **at the public level
> only**. The Compliance channel is a **firewall-gated channel**: its minimum
> profile is **High**, so it is enabled only at the High and Sovereign profiles,
> and its operational and cryptographic internals are controlled-track material
> that is **out of scope** for this public reference. This document builds on the
> core specification, introduces no change to the core wire format, and defines no
> behavior the core specification does not already reserve. Where the core
> specification supplies only a registry line or reserves a code point without
> defining its semantics, this reference says so and describes the interface at
> that level. **The draft governs**: on any disagreement between this reference and
> the core specification, the core specification is authoritative.

## 1. Purpose

The core specification assigns channel `0x0008` the name **Compliance** and the
purpose **"Attestation and regulatory export"** (core specification §5, Core
Channel Registry; `../../registries/channels.csv`). Expanded at the public level,
the Compliance channel is the N-PAMP channel over which a peer carries two named
classes of operation: **attestation** — the production or exchange of assertions
about a peer, its state, or its conduct — and **regulatory export** — the emission
of records for regulatory or compliance purposes. It is one of the **profile-gated**
core channels: unlike the baseline-profile channels (for example Control `0x0000`
and Memory `0x0001`, both minimum profile Standard), the Compliance channel is
reserved at a **minimum profile of High** and therefore cannot be enabled at the
Standard profile at all (core specification §5; §2 and §5 below).

The core specification defines the Compliance channel **only** as this registry
entry; it does not define a Compliance-specific wire encoding, message schema, or
operation contract, and it reserves **no** sub-`0x0100` frame-type range for the
channel (core specification §8; §3 below). Accordingly, this reference describes the
interface at the level the core specification actually fixes — the operation
*classes* named by the registry purpose (§4) — and does not invent frame layouts,
field structures, attestation formats, or export schemas that the core specification
does not state. Because the channel is firewall-gated (minimum profile High), its
operational and cryptographic internals are **controlled/private-track** material
(per the project's firewall/publication policy, ADR-0004/ADR-0003) and are **out of
scope** for this public reference. This page documents only the channel's public
existence, identity, direction, minimum profile, and public frame-type
reservations — all of which the core specification already exposes in §5 — and does
**not** describe any High- or Sovereign-profile cryptographic or operational
behavior.

## 2. Channel identity

The following values are taken verbatim from the core channel registry
(core specification §5, Core Channel Registry; machine-readable form
`../../registries/channels.csv`). They are normative in the core specification;
this reference restates them and does not alter them.

| Attribute | Value |
|---|---|
| Channel ID | `0x0008` |
| Name | Compliance |
| Purpose | Attestation and regulatory export |
| Minimum profile | High |
| Direction | Bidirectional |

- **Minimum profile — High.** The Minimum-profile column gives the lowest profile
  at which a channel may be enabled; a channel is available at that profile and at
  every higher profile (core specification §5: "a 'High' channel is available at
  High and Sovereign"). The Compliance channel is therefore available at the **High**
  and **Sovereign** profiles and **MUST NOT** be enabled at the Standard profile.
  Its operations require the High or Sovereign profile; see §5 for profile
  applicability.
- **Direction — Bidirectional.** Both peers send and receive frames on a single
  stream of this channel (core specification §5, Channel directionality). As with
  every N-PAMP channel, each peer maintains an independent per-direction sequence
  space and independent per-direction traffic keys, so both peers MAY transmit on
  the channel simultaneously (core specification §5). The Compliance channel is
  **not** classified Multi-stream; it does not open multiple concurrent transport
  sub-streams within a stream family (contrast, for example, the Memory channel
  `0x0001`, which is Multi-stream).
- **Advertisement gate.** A peer that has not advertised the Compliance channel
  during the handshake MUST NOT receive frames on it; frames on an unadvertised
  Compliance channel MUST be dropped (core specification §5, applied to `0x0008`).

## 3. Frame types

Frame types on the Compliance channel are drawn from the same per-channel
`0x0000`–`0xFFFF` frame-type namespace every N-PAMP channel uses (core specification
§4.6; reference `../04_frame_types.md`). Two groups are relevant to this channel,
and a third — a channel-specific reserved range — is explicitly **absent** for this
channel.

### 3.1 Reserved all-channel frame types

The following frame types are reserved across **all** channels with the same
meaning everywhere and retain that meaning on the Compliance channel. An
implementation MUST NOT reuse them for Compliance application traffic.

| Type | Name | Meaning on the Compliance channel |
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

### 3.2 No reserved Compliance-channel extension range

The core specification reserves several sub-`0x0100` frame-type ranges for
companion extensions (core specification §8, Reserved Frame-Type Ranges; references
`../04_frame_types.md` and `../09_extension_points.md`) — but **none of those ranges
is assigned to the Compliance channel**. The reserved sub-`0x0100` ranges belong to
the Memory, Capability, Control, Audit, Settlement/Audit, Governance, and Immune
channels; the Compliance channel `0x0008` has **no** reserved extension range of its
own. An implementation therefore MUST NOT assign any sub-`0x0100` code point to
Compliance traffic on the sole basis of the core specification.

> **Known editorial inconsistency in -00 (carried, not corrected here).** The core
> specification states that channel-specific frame types begin at `0x0100`
> (§4.6), while the sub-`0x0100` reserved ranges it lists for other channels sit
> below `0x0100`. This inconsistency is present in the submitted draft and is
> recorded in `../04_frame_types.md`; it does not affect the Compliance channel,
> which has no reserved sub-`0x0100` range, and this reference does not silently
> rewrite the authoritative text.

### 3.3 Channel-specific frame types (`0x0100`+ convention)

Channel-specific frame types begin at **`0x0100`** within each channel's frame
namespace (core specification §4.6). This is the range in which a Compliance-specific
operation encoding — for example concrete attestation and regulatory-export request
and reply frames (§4) — would be assigned. The core specification defines **no**
Compliance-specific frame type in this range, and no public companion specification
in the current set (`../companion/00_companion_index.md`) defines one. Consequently
there is, at present, no public core- or companion-defined Compliance operation
frame; §4 describes the interface at the registry level the core specification
actually fixes. Any concrete operation encoding for this channel is controlled-track
material and out of scope here (§1, §4, §6).

## 4. Interface and operations (public level)

The Compliance channel's public interface is the set of operation classes named by
its registry purpose. The core specification fixes these as **names of operation
classes**, not as wire encodings; this section restates them at that level and
states explicitly where the public specification stops. An implementation MUST NOT
read a wire format into this section: no frame layout, field structure, TLV,
correlation scheme, attestation format, or export schema below is defined by the
core specification.

| Operation class | Public meaning (from the registry purpose) |
|---|---|
| Attestation | Produce or exchange an assertion about a peer, its state, or its conduct. |
| Regulatory export | Emit records for regulatory or compliance purposes. |

Notes and honest boundaries:

- **No operation encoding is defined here.** Because the core specification assigns
  no Compliance-specific frame type (§3.3) and reserves no extension range for the
  channel (§3.2), the operation classes above have **no public core- or
  companion-defined request frame, reply frame, addressing scheme, value encoding,
  correlation scheme, attestation format, export schema, or error model**. This
  reference MUST NOT be cited as the source of any such encoding.
- **Correlation and ordering.** The Compliance channel has an independent
  per-direction sequence space (core specification §5), which orders frames within a
  direction. The core specification does not define how a Compliance reply is
  correlated to its request (unlike the Bridge channel, where NPAMP-BRIDGE §5 defines
  a `correlation_id`; `../companion/10_bridge_framework.md`). This reference does not
  define correlation for the channel.
- **Firewall boundary — operational internals out of scope.** The Compliance channel
  is firewall-gated at minimum profile High (§2, §5). Its operational contract and
  its cryptographic internals — the concrete behavior of attestation and
  regulatory-export operations at the High and Sovereign profiles — are
  **controlled/private-track** material (ADR-0004/ADR-0003) and are deliberately
  **out of scope** for this public reference. This page describes neither the
  channel's High- or Sovereign-profile cryptographic behavior nor any operation
  semantics beyond the two public operation-class names above. An implementation
  MUST obtain the operational contract for this channel from the controlled track,
  not from this public reference.

## 5. Profile applicability

The Compliance channel's minimum profile is **High** (§2). By the core
specification's min-profile rule (§5), the channel is available at the High profile
and at every higher profile — that is, at **High and Sovereign** — and is **not
available at Standard**. This makes the Compliance channel a **firewall-gated**
channel: its operations require the High or Sovereign profile.

- **Standard profile.** The Compliance channel is **unavailable** and MUST NOT be
  enabled. There is no Standard-profile surface for this channel beyond its public
  identity and code-point reservations (§2, §3).
- **High and Sovereign profiles.** The Compliance channel MAY be enabled. N-PAMP's
  three profiles (Standard, High, Sovereign) share **one wire format** and differ in
  the cryptographic primitives and operational requirements they mandate (core
  specification, Profile Negotiation). The specific cryptographic suites bound to the
  High and Sovereign profiles are selected by the core specification's
  profile-negotiation and key-schedule sections and, together with this channel's
  operational internals, are **out of scope for this interface reference**; this
  reference describes the channel's public, profile-invariant surface only and
  intentionally states no High- or Sovereign-profile cryptographic parameter or
  behavior.
- **Advertisement.** The channel MUST be advertised during the handshake for a peer
  to receive frames on it, and frames on an unadvertised channel MUST be dropped
  (core specification §5; §2).
- **Publishing scope (firewall).** This reference documents only the public interface
  surface the core specification already exposes in §5 — the channel's existence,
  identity, purpose, direction, minimum profile, and public frame-type namespace.
  Its operational and cryptographic internals, which require the High or Sovereign
  profile, live in the controlled/private track (ADR-0004/ADR-0003) and are
  **not** published here.
- **Scheduling.** The core specification's congestion-scheduling recommendation names
  the Control and Immune channels as SHOULD-be-higher-priority than the bulk channels
  (Memory, Sensory, Telemetry) during congestion (core specification §5); it does
  **not** classify the Compliance channel for scheduling. This reference therefore
  asserts no scheduling behavior for the channel.

## 6. Relationship to companion specifications

The Compliance channel is a **native core channel**: unlike the Bridge channel
(`0x000D`), which encapsulates foreign agent protocols and is elaborated by the
NPAMP-BRIDGE companion framework (`../companion/10_bridge_framework.md`) and its
carriage classes, and unlike the Discovery channel (`0x0010`), elaborated by
NPAMP-DISC (`../companion/40_discovery.md`), the Compliance channel has **no
dedicated public companion specification** in the current companion set
(`../companion/00_companion_index.md`). It is therefore not a bridge carriage class
and does not build on NPAMP-BRIDGE, and the companion index's channel-selection
table does not route any foreign-traffic class onto it.

The consequence for an implementer is that the Compliance channel's **public**
contract is exactly what §2–§5 restate:

- Its **identity** — id `0x0008`, name Compliance, purpose "attestation and
  regulatory export", minimum profile High, direction Bidirectional (§2);
- Its **public interface** — the attestation and regulatory-export operation classes,
  described at the registry level, with **no public core- or companion-defined wire
  encoding** (§4); and
- Its **frame-type surface** — the reserved all-channel frame types (§3.1), no
  reserved sub-`0x0100` extension range (§3.2), and the `0x0100`+ channel-specific
  convention with no core- or public-companion-defined frame (§3.3).

The channel's operational and cryptographic internals — required at the High and
Sovereign profiles — are **controlled/private-track** material (ADR-0004/ADR-0003)
and are out of scope for this public reference (§1, §4, §5). This reference points to
their existence and profile gating and defines no such behavior of its own. Should a
public, interoperable Compliance operation encoding ever be wanted, the path is the
same as for any N-PAMP extension: author a companion specification that defines a
Compliance operation encoding, verified against the core specification and consistent
with the channel's High-profile gating. Until such a public companion exists, an
implementation carries Compliance traffic under the channel identity and code points
above, and there is no additional public core- or companion-defined Compliance
behavior to conform to at this level.

## 7. Conformance

An implementation conforms to this Compliance-channel interface reference if and only
if, for channel `0x0008`, it:

1. Treats channel `0x0008` as the **Compliance** channel whose purpose is
   "attestation and regulatory export", consistent with the core channel registry
   (§2), and does not alter the channel identity or repurpose the channel identifier
   for other traffic;
2. Enables the Compliance channel only at the **High** or **Sovereign** profile,
   **never** at Standard, consistent with the channel's minimum profile of High
   (§2, §5);
3. Drops any frame received on the Compliance channel that the peer has not
   advertised during the handshake, and does not deliver such frames (§2);
4. Preserves the core meaning of the reserved all-channel frame types
   (`0x0001`–`0x000A`) on the Compliance channel and does not reuse any of them for
   Compliance application traffic (§3.1);
5. Assigns **no** sub-`0x0100` frame-type code point to the Compliance channel on the
   basis of the core specification, because the core specification reserves **no**
   extension range for this channel (§3.2);
6. Does not treat any operation description in §4 as a normative wire encoding, and
   does not cite this reference as the source of any Compliance request frame, reply
   frame, addressing scheme, value encoding, correlation scheme, attestation format,
   export schema, or error model, none of which the core specification defines for
   this channel (§3.3, §4);
7. Supports the channel's **Bidirectional** direction — both peers sending and
   receiving on a single stream, each maintaining independent per-direction sequence
   spaces and traffic keys — and does not treat the channel as Multi-stream (§2); and
8. Obtains this channel's operational and cryptographic contract from the
   controlled/private track rather than from this public reference, and does not read
   into this reference any High- or Sovereign-profile cryptographic or operational
   behavior, which are out of scope here (§1, §4, §5, §6).

A conformance test suite SHOULD assert each clause above, and in particular SHOULD
verify clause 2 by confirming that an implementation refuses to enable the Compliance
channel at the Standard profile, clause 3 by confirming that a Compliance frame
arriving on an unadvertised channel is dropped, and clause 5 by confirming that the
implementation reserves and honors no sub-`0x0100` Compliance extension frame on the
sole basis of the core specification. A per-channel reference MUST NOT be read to add
behavior the core specification does not define.
