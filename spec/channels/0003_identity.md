# NPAMP-CH-0003 — Identity Channel (`0x0003`) Interface Reference (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is a **public per-channel interface reference** for the
> N-PAMP Identity channel (`0x0003`), derived from the N-PAMP core specification
> (draft-bubblefish-npamp-01, the "core specification"), §5 Channel Architecture
> and §8 Extension Points. It restates the channel's registry entry and describes
> the channel's identity-resolution/attestation/presence interface **at the public
> level only**. It builds on the core specification, introduces no change to the
> core wire format, and defines no behavior the core specification does not already
> reserve. Where the core specification supplies only a registry line, or reserves
> a code point without defining its semantics, this reference says so and describes
> the interface at that level. **The draft governs**: on any disagreement between
> this reference and the core specification, the core specification is
> authoritative.

## 1. Purpose

The core specification assigns channel `0x0003` the name **Identity** and the
purpose **"Identity resolution, attestation, presence"** (core specification §5,
Core Channel Registry). Expanded, the Identity channel is the N-PAMP channel over
which a peer establishes and queries **who a party is and whether it is present**:
The class of traffic that resolves an identifier to the identity it names, that
asserts or attests an identity claim, and that signals the presence — the
reachability or availability — of an identity. The three terms in the registry
purpose name three operation classes: **identity resolution** (resolve or look up
the identity associated with an identifier), **attestation** (assert or present an
identity claim for a peer to evaluate), and **presence** (signal the presence state
of an identity). This is application-level identity traffic on an established
association, as distinct from the connection-level peer-identity binding the
handshake performs (core specification), from the authorizations the Capability
channel (`0x0002`) manages, and from the capability *advertisement* the Discovery
channel (`0x0010`) carries.

The core specification defines the Identity channel **only** as this registry
entry; it reserves no Identity-specific frame-type range (§3) and defines no
Identity-specific wire encoding, identifier scheme, attestation or claims format,
presence-state model, message schema, or operation contract. Accordingly, this
reference describes the Identity interface at the level the core specification
actually fixes — the operation *classes* named by the registry purpose (§4) — and
does not invent frame layouts, field structures, identifier or attestation
formats, or semantics that the core specification does not state. A future
companion specification MAY define a concrete Identity operation encoding within
the channel-specific `0x0100`+ namespace the core specification leaves available
(§3); until then, the public Identity interface is exactly what this reference
restates.

## 2. Channel identity

The following values are taken verbatim from the core channel registry
(core specification §5; machine-readable form `../../registries/channels.csv`). They are
normative in the core specification; this reference restates them and does not
alter them.

| Attribute | Value |
|---|---|
| Channel ID | `0x0003` |
| Name | Identity |
| Purpose | Identity resolution, attestation, presence |
| Minimum profile | Standard |
| Direction | Bidirectional |

- **Minimum profile — Standard.** The Identity channel MAY be enabled at the
  Standard profile and is available at Standard and at every higher profile
  (High, Sovereign), per the core specification's min-profile rule
  (§5: the minimum profile is the lowest profile at which a channel may be
  enabled). See §5 for profile applicability.
- **Direction — Bidirectional.** Both peers send and receive frames on a single
  stream of this channel (core specification §5, Channel directionality). As with
  every N-PAMP channel, each peer maintains an independent send and receive
  sequence space and independent per-direction traffic keys, so both peers MAY
  transmit on the channel simultaneously (core specification §5). The Identity
  channel is **not** classified Multi-stream; it does not open multiple concurrent
  transport sub-streams within a stream family (contrast the Memory channel
  `0x0001` and the Stream channel `0x000C`).
- **Advertisement gate.** A peer that has not advertised the Identity channel
  during the handshake MUST NOT receive frames on it; frames on an unadvertised
  Identity channel MUST be dropped (core specification §5, applied to `0x0003`).

## 3. Frame types

Frame types on the Identity channel are drawn from the same per-channel
`0x0000`–`0xFFFF` frame-type namespace every N-PAMP channel uses
(core specification §4.6; reference `../04_frame_types.md`). This reference defines
no new frame types. Three groups are relevant to this channel.

### 3.1 Reserved all-channel frame types

The following frame types are reserved across **all** channels with the same
meaning everywhere and retain that meaning on the Identity channel. An
implementation MUST NOT reuse them for Identity application traffic.

| Type | Name | Meaning on the Identity channel |
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

### 3.2 Channel-specific frame types (`0x0100`+ convention)

Channel-specific frame types begin at **`0x0100`** within each channel's frame
namespace (core specification §4.6). This is the range in which an
Identity-specific operation encoding — for example concrete
resolution/attestation/presence request and reply frames (§4) — would be assigned.
The core specification defines **no** Identity-specific frame type in this range,
and no companion specification in the current set
(`../companion/00_companion_index.md`) defines one. An implementation therefore
MUST NOT treat any `0x0100`+ code point on the Identity channel as having a core-
or companion-defined meaning until a companion specification assigns it; §4
describes the interface at the registry level the core specification actually
fixes.

### 3.3 No Identity-specific reserved companion range

The core specification's Extension Points reserve per-channel frame-type ranges for
several channels' companion extensions — Memory (`0x0035`–`0x0036`), Capability
(`0x0060`–`0x0063`), Control (`0x0080`), Audit (`0x0090`), Settlement/Audit
(`0x00A0`–`0x00A3`), Governance (`0x00B0`–`0x00B4`), and Immune
(`0x00C0`–`0x00C4`) (core specification §8, Reserved Frame-Type Ranges;
`../04_frame_types.md`, `../09_extension_points.md`). **No range is reserved for
the Identity channel.** A companion specification that later defines Identity-channel
frames therefore uses the channel-specific `0x0100`+ namespace (§3.2); this
reference reserves no range and an implementation MUST NOT assume one.

> **Known editorial inconsistency in -00 (carried, not corrected here).** The core
> specification states that channel-specific frame types begin at `0x0100` (§4.6),
> yet the same section also treats non-reserved code points "at or above `0x0030`"
> as extension points, and the reserved companion ranges named above sit below
> `0x0100` (`0x0035`…`0x00C4`). This inconsistency is present in the submitted -00
> draft and is recorded in `../04_frame_types.md`; this reference repeats it rather
> than silently resolving it. The core specification governs its own resolution in a
> future revision. The inconsistency does not affect the Identity channel, for which
> the core specification reserves no companion range at all (§3.3).

## 4. Interface and operations (public level)

The Identity channel's public interface is the set of operation classes named by
its registry purpose. The core specification fixes these as **names of operation
classes**, not as wire encodings; this section restates them at that level and
states explicitly where the core specification stops. An implementation MUST NOT
read a wire format into this section: no frame layout, field structure, TLV,
identifier scheme, attestation format, presence-state model, or correlation scheme
below is defined by the core specification.

| Operation class | Public meaning (from the registry purpose) |
|---|---|
| Identity resolution | Resolve or look up the identity associated with an identifier — obtain the identity or descriptor that an identifier names. |
| Attestation | Assert or present an identity claim for the peer to evaluate — an identity assertion the peer may accept or reject. |
| Presence | Signal the presence state of an identity — its reachability or availability on the association. |

Notes and honest boundaries:

- **Identity is named, not formatted, by the core specification.** The core
  specification's signature-code-point table lists **"Identity"** among the usages
  of its All-profiles signature algorithm (Ed25519), placing identity signatures
  within the protocol's scope (core specification §6, Signatures). It does **not**
  define an identifier scheme, an identity-descriptor format, an attestation/claims
  model, or an evidence format for the Identity channel. This reference records that
  the core specification names identity as a signature usage and does not manufacture
  a format the core specification does not state.
- **No operation encoding is defined here.** Because the core specification assigns
  no Identity-specific frame type (§3.2), the operation classes above have **no
  core-defined request frame, reply frame, identifier scheme, attestation encoding,
  presence-state encoding, or error model**. This reference MUST NOT be cited as the
  source of any such encoding.
- **Presence scope is undefined by the core specification.** The registry purpose
  names presence as an operation class; the core specification does not define a
  presence-state vocabulary (for example online/offline/away), a freshness or
  time-to-live model, or a subscribe/notify mechanism for presence changes. Those are
  semantics a companion specification MAY define; this reference does not manufacture
  them.
- **Correlation and ordering.** The Identity channel has an independent
  per-direction sequence space (core specification §5), which orders frames within a
  direction. The core specification does not define how an Identity reply is
  correlated to its request (unlike the Bridge channel, where NPAMP-BRIDGE §5 defines
  a `correlation_id`); an Identity operation encoding, when specified by a companion,
  is where such correlation would be defined. This reference does not define it.
- **Bidirectional origination.** Because the channel is Bidirectional (§2), either
  peer MAY originate traffic on it — either peer MAY resolve an identity, present an
  attestation, or signal presence — each direction using its own sequence space and
  traffic keys. The core specification does not assign a fixed asserter/verifier role
  to a connection endpoint at the channel level.
- **Liveness, teardown, and control.** Liveness probing, authenticated teardown,
  error signalling, key update, path migration, and flow control on the Identity
  channel use the reserved all-channel frames (§3.1) with their core meaning; they
  are not Identity-specific operations.

## 5. Profile applicability

The Identity channel's minimum profile is **Standard** (§2). By the core
specification's min-profile rule (§5), the channel is available at the Standard
profile and at every higher profile; that is, at **Standard, High, and Sovereign**.
There is no profile at which the Identity channel is unavailable once its minimum
profile is met, and no upper profile bound.

- **Standard profile.** The Identity channel is available and MAY be enabled. This
  is the profile at which the public Identity interface described in this reference
  is fully expressible, and the surface documented here.
- **Higher profiles (High, Sovereign).** The Identity channel remains available with
  the same wire-level frame namespace and the same public interface. N-PAMP's three
  profiles share **one wire format** and differ in the cryptographic primitives and
  operational requirements they mandate (core specification §6, Profile Negotiation).
  The specific cryptographic suite bound to each profile — including the signature
  suite that protects identity signatures — is defined by the core specification's
  profile-negotiation and cryptographic-suite sections and is **out of scope for this
  interface reference**; this reference describes the channel's public,
  profile-invariant interface only, and neither restates nor depends on any High- or
  Sovereign-profile cryptographic parameter.
- **Scheduling.** The core specification's congestion-scheduling note names the
  Control and Immune channels as the channels that SHOULD be scheduled at higher
  priority than the bulk channels (Memory, Sensory, Telemetry) during congestion
  (core specification §5). The Identity channel appears in **neither** list, so the
  core specification fixes **no** scheduling preference for it; this reference does
  not invent one.
- **Publishing scope.** This reference documents only the public **Standard-profile
  interface surface** of the channel — its identity, purpose, direction, minimum
  profile, and public frame-type namespace. High- and Sovereign-profile cryptographic
  internals and parameters are governed by the core specification's profile
  negotiation and are out of scope here.

## 6. Relationship to companion specifications

The Identity channel is a **native core channel**: unlike the Bridge channel
(`0x000D`), which encapsulates foreign agent protocols and is elaborated by the
NPAMP-BRIDGE companion framework (`../companion/10_bridge_framework.md`) and its
carriage classes, and unlike the Discovery channel (`0x0010`), elaborated by
NPAMP-DISC (`../companion/40_discovery.md`), the Identity channel has **no dedicated
companion specification** in the current companion set
(`../companion/00_companion_index.md`). It is therefore not a bridge carriage class
and does not build on NPAMP-BRIDGE. The core specification fixes it by the single
registry line quoted in §1–§2, and this reference does not fill that gap with
invented behavior.

The Identity channel `0x0003` is also distinct from the identity-adjacent
mechanisms elsewhere in N-PAMP, and this reference does not conflate them:

- **The handshake's peer-identity binding.** The core specification binds each
  peer's identity into the handshake transcript, so that substituting a peer identity
  invalidates the Finished MAC and aborts the handshake (core specification,
  handshake and downgrade/identity-substitution protection). That is a
  connection-establishment property of the association, not application-level traffic
  on channel `0x0003`.
- **The companion "identity, bootstrap, and signed discovery" documents.** The
  companion set includes NPAMP-HELLO (`../companion/45_hello_bootstrap.md`), which
  runs on the **Control** channel `0x0000`; NPAMP-DISC-SIGNED
  (`../companion/41_discovery_signed.md`), which extends NPAMP-DISC on the
  **Discovery** channel `0x0010`; and NPAMP-PEERHANDLE
  (`../companion/50_peer_handle.md`), a connection-scoped self-certifying peer name.
  These concern peer identity, naming, and signed advertisement, but they operate on
  the handshake, the Control channel, and the Discovery channel — **not** on channel
  `0x0003` — and this reference makes no claim that any of them runs on the Identity
  channel.
- **Bridged foreign identity/attestation traffic.** The companion index's "channel
  selection for carriage" guidance routes the foreign traffic class **"Identity
  assertion and attestation"** to the Identity channel `0x0003`
  (`../companion/00_companion_index.md`). Accordingly, a deployment MAY carry a
  bridged foreign identity or attestation protocol on this channel — under
  NPAMP-BRIDGE and a mapped carriage class, or under Class OPAQUE
  (`../companion/25_carriage_opaque.md`) when no mapping exists — in addition to, or
  instead of, the default Bridge channel `0x000D`. That is **carriage of a foreign
  protocol**, governed by NPAMP-BRIDGE and the relevant carriage class; it is distinct
  from native Identity-channel traffic and defines no native `0x0003` frame type. A
  mapping document specifies which channel or channels a given protocol's traffic uses.

The consequence for an implementer is that the Identity channel's public contract
is exactly what §2–§5 restate:

- Its **identity** — id `0x0003`, name Identity, purpose "identity resolution,
  attestation, presence", minimum profile Standard, direction Bidirectional (§2);
- Its **public interface** — the identity-resolution/attestation/presence operation
  classes, described at the registry level, with **no core-defined wire encoding,
  identifier scheme, attestation format, or presence-state model** (§4); and
- Its **frame-type posture** — the channel-specific `0x0100`+ namespace, with **no**
  Identity-specific reserved companion range, because the core specification reserves
  none (§3.2, §3.3).

Should richer, interoperable Identity operations be wanted, the path is the same as
for any N-PAMP extension: author a companion specification that defines an Identity
operation encoding within the channel-specific `0x0100`+ namespace, verified against
the core specification. Until such a companion exists, an implementation carries
Identity traffic under the channel identity above, and there is no additional core-
or companion-defined Identity behavior to conform to. This reference documents the
interface at that public level and defines no new behavior.

## 7. Conformance

An implementation conforms to this Identity-channel interface reference if and only
if it conforms to the core specification and, for channel `0x0003`, it:

1. Treats channel `0x0003` as the **Identity** channel whose purpose is identity
   resolution, attestation, and presence, consistent with the core channel registry
   — Min Profile **Standard**, direction **Bidirectional** — and does not repurpose
   the channel identifier for other traffic (§2; core specification §5);
2. Enables the Identity channel only at the **Standard** profile or higher, never
   below Standard, and — once Standard is met — treats the channel as available at
   Standard, High, and Sovereign (§2, §5);
3. Drops any frame received on the Identity channel that the peer has not advertised
   during the handshake, and does not deliver such frames to the identity subsystem
   (§2; core specification §5);
4. Preserves the core meaning of the reserved all-channel frame types
   (`0x0001`–`0x000A`) on the Identity channel and does not reuse any of them for
   Identity application traffic (§3.1; core specification §4.6);
5. Draws any channel-specific (identity) frame type from the channel-specific
   namespace beginning at `0x0100`, and relies on **no** Identity-channel companion
   frame-type range, because the core specification reserves none (§3.2, §3.3; core
   specification §8, Extension Points);
6. Does not treat any operation description in §4 as a normative wire encoding, and
   does not cite this reference as the source of any Identity request frame, reply
   frame, identifier scheme, attestation or claims format, presence-state model,
   correlation scheme, or error model, none of which the core specification defines
   for this channel (§3.2, §4);
7. Supports the channel's **Bidirectional** direction — both peers sending and
   receiving frames on a single stream, each maintaining independent per-direction
   sequence spaces and traffic keys — and does not treat the channel as Multi-stream
   (§2, §4); and
8. Defers all Identity operation semantics beyond the registry-level interface of §4
   to a future companion specification, adds no Identity behavior of its own that the
   core specification does not reserve, and does not conflate the Identity channel
   `0x0003` with the handshake's peer-identity binding or with the identity-adjacent
   companions that operate on the Control and Discovery channels (§6).

A conformance test suite SHOULD assert each clause above by exercising a
Standard-profile association that advertises `0x0003`, and in particular SHOULD
verify clause 3 by confirming that an Identity frame arriving on an unadvertised
channel is dropped, clause 4 by confirming that a reserved all-channel frame (for
example PING/PONG or KEY_UPDATE) behaves identically on this channel as on any
other, and clause 5 — a negative conformance property — by confirming that an
implementation claiming Identity-channel support requires no identifier,
attestation, presence, or channel-specific frame encoding that this reference and
the core specification leave undefined, and assumes no reserved companion frame-type
range for the channel.
