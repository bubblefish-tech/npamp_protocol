# NPAMP-CH-0000 — Control Channel (`0x0000`) Interface Reference (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is a **per-channel interface reference** for the N-PAMP
> **Control channel `0x0000`**. It is derived from the core specification
> (draft-bubblefish-npamp-01, the "core specification"), §5 Channel Architecture
> and §8 Extension Points, and its machine-readable registry
> `../../registries/channels.csv`. It restates the channel's registry entry and its
> public frame-type reservations and describes the channel's connection-control,
> handshake-completion, and capability-epoch interface **at the public level only**.
> It builds on the core specification, introduces no change to the core wire format,
> and defines no behavior the core specification does not already reserve. The
> post-handshake capability exchange that occupies this channel is defined by the
> companion NPAMP-HELLO (`../companion/45_hello_bootstrap.md`); this reference points
> to it and does not restate it. Where the core specification gives this channel only
> a registry line, this document says so and describes the interface at that level
> rather than inventing behavior. **The draft governs**: on any disagreement between
> this reference and the core specification, the core specification is authoritative.

## 1. Purpose

The core specification assigns channel `0x0000` the name **Control** and the
purpose **"Connection control, handshake completion, capability epoch"** (core
specification §5, Core Channel Registry; `../../registries/channels.csv`). Expanded,
the Control channel is the N-PAMP channel over which a peer manages the **established
association itself** — as distinct from the application traffic carried on the other
channels. It groups three related classes of traffic:

- **Connection control.** The ongoing management of a live association: liveness
  probing, authenticated close, error signalling, traffic-key rotation, path
  migration, and flow-control credit. These are expressed by the reserved
  all-channel control frames, which retain their core meaning on this channel (§3.1,
  §4).
- **Handshake completion.** The Control channel becomes usable only once the N-PAMP
  handshake completes and the per-(direction, epoch, suite, channel) traffic keys
  are derived (core specification §3 Protocol Overview; §5). It is the channel on
  which a peer conducts post-handshake control of the connection the handshake
  established.
- **Capability epoch.** The bounded, post-handshake window in which each peer
  advertises the protocols and channels it carries, before either peer emits carried
  application traffic. The core specification **names** this epoch as part of the
  channel's purpose; the concrete exchange that opens and closes it is defined by the
  companion NPAMP-HELLO (§6), whose `HELLO_DONE` frame marks a peer's capability
  epoch complete (NPAMP-HELLO §3).

The core specification defines *what the channel is for* — this one registry-line
purpose — together with the reserved all-channel control frames (§3.1) and one
reserved Control-channel extension range (§3.2). It does **not** define a
Control-specific wire encoding, message schema, or operation contract for
"handshake completion" or for the "capability epoch" beyond naming them. Those
distinctive operations are supplied post-handshake by the companion NPAMP-HELLO
within the code points the core specification reserves (§3.3, §6). This page
documents the channel's public interface at the level the core specification fixes
it and points to the companion document for the operational contract; it does not
invent frame layouts, field structures, or semantics the core specification does not
state.

## 2. Channel identity

The following values are taken verbatim from the core channel registry (core
specification §5, Core Channel Registry; machine-readable form
`../../registries/channels.csv`). They are normative in the core specification; this
reference restates them and does not alter them.

| Attribute | Value |
|---|---|
| Channel ID | `0x0000` |
| Name | Control |
| Purpose | Connection control, handshake completion, capability epoch |
| Minimum profile | Standard |
| Direction | Bidirectional |

- **Minimum profile — Standard.** The Control channel MAY be enabled at the Standard
  profile and is available at Standard and at every higher profile (High, Sovereign),
  per the core specification's min-profile rule (the minimum profile is the lowest
  profile at which a channel may be enabled; core specification §5). See §5 for
  profile applicability.
- **Direction — Bidirectional.** Both peers send and receive frames on a single
  stream of this channel (core specification §5, Channel directionality). As with
  every N-PAMP channel, each peer maintains an independent send and receive sequence
  space and independent per-direction traffic keys, so both peers MAY transmit on the
  channel simultaneously (core specification §5). The Control channel is **not**
  classified Multi-stream; it does not open multiple concurrent transport sub-streams
  within a stream family (contrast the Stream channel `0x000C`).
- **Advertisement gate.** A peer that has not advertised the Control channel during
  the handshake MUST NOT receive frames on it; frames on an unadvertised channel MUST
  be dropped (core specification §5, applied to `0x0000`).

## 3. Frame types

Frame types on the Control channel are drawn from the same per-channel
`0x0000`–`0xFFFF` frame-type namespace every N-PAMP channel uses (core specification
§4.6, Reserved Frame Types; §8.1, Reserved Frame-Type Ranges; references
`../04_frame_types.md` and `../09_extension_points.md`). Three groups are relevant to
this channel.

### 3.1 Reserved all-channel frame types

The following frame types are reserved across **all** channels with the same meaning
everywhere and therefore retain that meaning on the Control channel (core
specification §4.6). An implementation MUST NOT reuse them for Control application
traffic.

| Type | Name | Meaning on the Control channel |
|---|---|---|
| `0x0000` | (reserved) | MUST NOT be used as a frame type. |
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

These reserved control frames are the core-defined mechanism for the "connection
control" element of the channel's purpose (§4). They are defined identically for
every channel; the core specification does not single out the Control channel as
their exclusive carrier. A CLOSE frame is authenticated like any other frame: a
receiver MUST verify the AEAD tag before honoring a close, and an unauthenticated or
forged CLOSE frame MUST be dropped and SHOULD be counted as a security event (core
specification §4, CLOSE Frame).

### 3.2 Reserved Control-channel extension frame range

The core specification reserves one per-channel frame-type range specifically for the
Control channel (core specification §8.1, Reserved Frame-Type Ranges; reference
`../09_extension_points.md` and `../04_frame_types.md`):

| Range | Reserved for |
|---|---|
| `0x0080` – `0x0080` | Control-channel flow-extension frames |

This range is **reserved, not defined**. The core specification neither defines nor
requires a Control-channel flow-extension frame; it only reserves the code point so a
companion specification can define one without colliding with the core wire format
(core specification §8). No companion specification in the current set
(`../companion/00_companion_index.md`) defines this frame. An implementation therefore
MUST NOT treat any Control-channel flow-extension behavior as specified by the core
specification, and MUST NOT assign `0x0080` to any other purpose.

> **Known editorial inconsistency in -00 (carried, not corrected here).** The core
> specification states that channel-specific frame types begin at `0x0100` (§4.6),
> yet the reserved Control-channel flow-extension code point `0x0080` sits below
> `0x0100`. This inconsistency is present in the submitted draft and is recorded in
> `../04_frame_types.md`; this reference does not silently rewrite the authoritative
> text.

### 3.3 Channel-specific frame types (`0x0100`+ convention)

Channel-specific frame types begin at **`0x0100`** within each channel's frame
namespace (core specification §4.6). On the Control channel this range carries the
four core N-PAMP handshake frame types (core specification, Handshake section); the
channel's post-handshake operational frames are defined by the companion NPAMP-HELLO
within the same `0x0100`+ namespace (NPAMP-HELLO §3, reproduced here for orientation
only, with NPAMP-HELLO governing their semantics):

| Type | Name | Defined by |
|---|---|---|
| `0x0100` | CLIENT_HELLO | core specification, Handshake section |
| `0x0101` | SERVER_HELLO | core specification, Handshake section |
| `0x0102` | SERVER_AUTH | core specification, Handshake section |
| `0x0103` | CLIENT_AUTH | core specification, Handshake section |
| `0x0110` | HELLO | NPAMP-HELLO §3 |
| `0x0111` | HELLO_DONE | NPAMP-HELLO §3 |

A companion specification that carries traffic on this channel MUST use the frame
types it reserves within the `0x0100`+ namespace and MUST NOT introduce a conflicting
channel-specific frame type without a companion specification reserving it. Aside from
NPAMP-HELLO, no companion in the current set defines a Control-channel frame type.

## 4. Interface / operations (public level)

At the core-specification level the Control channel's public interface is its
registry line — **connection control, handshake completion, capability epoch** (core
specification §5) — realized by the reserved all-channel control frames of §3.1. The
core specification fixes these as connection-management primitives, not as a
Control-specific application encoding; this section restates them at the interface
level and states explicitly where the core specification stops. An implementation
MUST NOT read a Control-specific wire format into this section beyond the reserved
frame types the core specification defines.

| Operation | Frame(s) | Public meaning (from the core specification) |
|---|---|---|
| Liveness | PING / PONG (`0x0001`/`0x0002`) | Probe that the peer and the association are live; PONG replies to PING. |
| Authenticated close | CLOSE / CLOSE_ACK (`0x0003`/`0x0004`) | Tear down the association; AEAD-protected. A receiver MUST verify the AEAD tag before honoring a close; a forged CLOSE MUST be dropped (core specification §4, CLOSE Frame). |
| Error signalling | ERROR (`0x0005`) | Report an error condition on the association; AEAD-protected. |
| Key rotation | KEY_UPDATE / KEY_UPDATE_ACK (`0x0006`/`0x0007`) | Initiate and acknowledge a traffic-key update for this (channel, direction), advancing the epoch (core specification §4.6; §7 Cryptographic Suites). |
| Path migration | PATH_CHALLENGE / PATH_RESPONSE (`0x0008`/`0x0009`) | Validate a new network path during connection migration. |
| Flow control | FLOW_UPDATE (`0x000A`) | Connection-level flow-control credit update. |

Honest boundaries:

- **These frames are all-channel, not Control-exclusive.** The reserved control
  frames above carry the same meaning on every channel (core specification §4.6). The
  Control channel is the channel the registry designates for connection control, but
  the core specification does not define a Control-only variant of any of these
  frames. This reference records that the connection-control element of the purpose is
  served by these all-channel primitives and does not manufacture Control-specific
  frame semantics.
- **Handshake completion is a precondition, not a Control frame.** The core
  specification defines no "handshake completion" frame on `0x0000`. Handshake
  completion is the event — the handshake succeeds and the Finished MAC verifies (core
  specification §3) — after which the Control channel's post-handshake traffic
  (including the capability epoch) is permitted. NPAMP-HELLO makes this precondition
  explicit: a peer MUST send HELLO only after the handshake completes and the Finished
  MAC verifies (NPAMP-HELLO §2).
- **The capability epoch is named by the core specification and defined by
  NPAMP-HELLO.** The core specification names the "capability epoch" as part of the
  channel's purpose but defines no epoch frame. The concrete capability-epoch
  exchange — each peer advertising an ordered name-list of the protocols and channels
  it carries, computing the usable set, and closing its epoch with `HELLO_DONE` — is
  defined by the companion NPAMP-HELLO (§3.3, §6). This reference MUST NOT be cited as
  the source of any capability-epoch encoding; NPAMP-HELLO governs it.
- **No further operation encoding is defined here.** Beyond the four handshake frame
  types of §3.3, the core specification assigns no Control-specific request frame,
  reply frame, addressing scheme, value encoding, correlation scheme, or error model
  beyond the reserved all-channel frames above.
  The Control channel has an independent per-direction sequence space (core
  specification §5), which orders frames within a direction; the core specification
  does not define a Control-channel reply-to-request correlation identifier.

## 5. Profile applicability

The Control channel's minimum profile is **Standard** (§2). By the core
specification's min-profile rule (§5), the channel is available at the Standard
profile and at every higher profile; that is, at **Standard, High, and Sovereign**.
There is no profile at which the Control channel is unavailable once its minimum
profile is met, and no upper profile bound.

- **Standard profile.** The Control channel is available and MAY be enabled. This is
  the profile at which the public Control interface described in this reference is
  fully expressible.
- **Higher profiles (High, Sovereign).** The Control channel remains available with
  the same wire-level frame namespace and the same public interface. N-PAMP's three
  profiles (Standard, High, Sovereign) share **one wire format** and differ in the
  cryptographic primitives and operational requirements they mandate (core
  specification, Profile Negotiation). The Control channel's framing and interface —
  its identity (§2), its frame-type namespace (§3), and the connection-control
  primitives of §4 — are **profile-invariant**: they do not change across profiles.
  The specific cryptographic suite bound to each profile is selected by the core
  specification's profile-negotiation and cryptographic-suite sections and is **out of
  scope for this interface reference**.
- **Scheduling priority.** The core specification singles out the Control channel
  (with the Immune channel) as one that **SHOULD be scheduled at higher priority than
  the bulk channels** (Memory, Sensory, Telemetry) during congestion (core
  specification §5). This is a scheduling recommendation that reflects the channel's
  connection-control role; it is not a change to the Control interface.
- **Advertisement.** The channel MUST be advertised during the handshake for a peer
  to receive frames on it; frames on an unadvertised channel MUST be dropped (core
  specification §5).
- **Publishing scope.** This reference documents only the public **Standard-profile
  interface surface** of the channel — its identity, purpose, direction, minimum
  profile, and public frame-type namespace. High- and Sovereign-profile cryptographic
  internals and parameters are governed by the core specification's profile
  negotiation and are out of scope here.

## 6. Relationship to companion specifications

The Control channel is a **native core channel** whose connection-control frames are
defined by the core specification itself (§3.1). Unlike a bridge carriage class, it
does not build on NPAMP-BRIDGE and carries no foreign agent protocol. It does,
however, host one companion specification that rides its `0x0100`+ namespace:

- **NPAMP-HELLO — Capability Bootstrap**
  (`../companion/45_hello_bootstrap.md`). NPAMP-HELLO defines the **post-handshake
  capability exchange** that occupies this channel: immediately after the handshake,
  each peer advertises — as an ordered name-list — the foreign-protocol identifiers
  (NPAMP-REG `protocol_id`) and core channels it carries, the peers compute the
  intersection as the usable set in the initiator's preference order, and each peer
  closes its **capability epoch** with `HELLO_DONE` (NPAMP-HELLO §3, §5). It operates
  its `HELLO` (`0x0110`) and `HELLO_DONE` (`0x0111`) frames within the Control
  channel's channel-specific namespace (§3.3). Key properties, all governed by
  NPAMP-HELLO rather than by this page:
  - HELLO is sent only **after** the handshake completes and the Finished MAC verifies,
    and every HELLO frame is therefore AEAD-protected under the established
    per-(direction, epoch, suite, channel) keys and mutually authenticated by the
    handshake (NPAMP-HELLO §2).
  - NPAMP-HELLO is a **selector, not a directory**: it carries identifiers only, never
    per-protocol descriptors, schemas, human metadata, or endpoint locators, and it
    does not persist a peer's advertisement beyond the live association (NPAMP-HELLO
    §8).
  - Forward compatibility is preserved by ignore-unknown handling plus GREASE, and
    downgrade is resisted by binding a digest of the offered `protocols` into the
    handshake transcript (NPAMP-HELLO §4, §7).

  NPAMP-HELLO is the operational definition of the channel's capability-epoch
  behavior; this reference points to it and does not restate it.

- **No other companion** in the current set (`../companion/00_companion_index.md`)
  defines a Control-channel frame. The `0x0080` flow-extension code point (§3.2)
  remains reserved and undefined. Should richer Control-channel operations be wanted,
  the path is the same as for any N-PAMP extension: author a companion specification
  that defines them within the reserved code points, verified against the core
  specification.

## 7. Conformance

An implementation that enables the Control channel `0x0000` conforms to this
reference if and only if, for channel `0x0000`, it:

1. Treats the channel with the identity fixed by the core channel registry — ID
   `0x0000`, name Control, purpose "connection control, handshake completion,
   capability epoch", minimum profile Standard, direction Bidirectional — and does not
   alter any of these values or repurpose the channel identifier for other traffic
   (§2);
2. Enables the Control channel only at the **Standard** profile or higher, never below
   Standard, and — once Standard is met — treats the channel as available at Standard,
   High, and Sovereign (§2, §5);
3. Does not deliver frames on `0x0000` to a peer that has not advertised the channel
   during the handshake, and drops frames received on an unadvertised channel (§2;
   core specification §5);
4. Maintains an independent per-direction sequence space and independent per-direction
   traffic keys for channel `0x0000` (§2; core specification §5);
5. Preserves the core meaning of every reserved all-channel frame type
   (`0x0001`–`0x000A`) on this channel, verifies the AEAD tag of a CLOSE before
   honoring it and drops a forged CLOSE, and does not reuse any reserved all-channel
   frame type for Control application traffic; and does not use `0x0000` as a frame
   type (§3.1, §4);
6. Treats the frame-type code point `0x0080` as **reserved** for Control-channel
   flow-extension frames, assigns it to no other purpose, and does **not** claim
   flow-extension behavior as specified by the core specification, because the core
   specification reserves that code point without defining its semantics (§3.2);
7. Places any channel-specific Control frame in the `0x0100`+ namespace, using the
   frame types a companion specification defines (NPAMP-HELLO `0x0110`/`0x0111`), and
   does not introduce a conflicting channel-specific frame type absent a companion
   specification reserving it (§3.3);
8. Does not treat the registry purpose (handshake completion, capability epoch) as a
   core-defined wire operation, and carries any post-handshake capability-epoch
   exchange on this channel only in conformance with NPAMP-HELLO — sent only after the
   handshake completes and the Finished MAC verifies — citing this reference as the
   source of no capability-epoch encoding of its own (§4, §6); and
9. SHOULD schedule the Control channel at higher priority than the bulk channels
   (Memory, Sensory, Telemetry) during congestion (§5; core specification §5).

This reference defines no frame semantics, envelope, correlation, error, or capability
behavior of its own; conformance for the connection-control frames is governed by the
core specification (§4.6, CLOSE Frame, §7 Cryptographic Suites), and conformance for
the capability-epoch exchange is governed by NPAMP-HELLO §9. A per-channel reference
MUST NOT be read to add behavior the core specification and the companion framework do
not define.
