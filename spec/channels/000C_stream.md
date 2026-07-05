# NPAMP-CH-000C — Stream Channel (`0x000C`) Interface Reference (companion to draft-bubblefish-npamp-00)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is the **public per-channel interface reference** for the
> N-PAMP **Stream channel `0x000C`**. It is derived from the core specification's
> §5 Channel Architecture and the core channel registry (`../03_channels.md`,
> `../../registries/channels.csv`); it restates that channel's public interface and
> introduces no behavior not present in the core specification. It builds on the
> N-PAMP core specification (draft-bubblefish-npamp-00, the "core specification"),
> **which governs**: where this page and the core specification disagree, the core
> specification is authoritative. This page defines no new wire format, no new frame
> type, and no new code point.

## 1. Purpose

The core specification's channel registry assigns channel `0x000C` the purpose
"multiplexed full-duplex streaming (tokens, audio, video, file transfer)" (core
specification §5; `../../registries/channels.csv`). Expanded and grounded in the
draft's Channel Architecture text: the Stream channel provides **general-purpose
multiplexed full-duplex streaming**, carrying concurrent bidirectional sub-streams —
for example token, audio, video, and file-transfer streams — each with independent
flow control (core specification §5, "The Stream channel (0x000C) provides
general-purpose multiplexed full-duplex streaming … each with independent flow
control"). It is the channel a deployment
uses to move raw byte or media streams natively over the authenticated,
post-quantum, key-isolated N-PAMP wire, so that several logically distinct streams
share one association without head-of-line coupling between them.

The Stream channel is **not** a protocol-encapsulation channel. Carrying a *foreign
agentic protocol* (MCP, A2A, and the like) octet-for-octet is the role of the Bridge
channel `0x000D` and its companion NPAMP-BRIDGE (`../companion/10_bridge_framework.md`),
not of channel `0x000C`. Likewise, streamed *foreign-protocol replies* — a sequence
of typed foreign events — are carried on the Bridge channel by the streaming carriage
class NPAMP-CC-STREAM (`../companion/23_carriage_streaming.md`), which explicitly does
not define behavior on channel `0x000C`. The relationship between the two is set out
in §6.

## 2. Channel identity

The channel's identity, exactly as registered (core specification §5;
`../../registries/channels.csv`, read directly):

| Attribute | Value |
|---|---|
| Channel ID | `0x000C` |
| Name | Stream |
| Purpose | Multiplexed full-duplex streaming (tokens, audio, video, file transfer) |
| Min Profile | Standard |
| Direction | Multi-stream |

Interpretation of these attributes under the core specification's Channel
Architecture (§5):

- **Full-duplex.** All N-PAMP channels are full-duplex: each peer maintains an
  independent send and receive sequence space and independent per-direction traffic
  keys, so both peers MAY transmit on the channel simultaneously. This channel
  inherits that property; it defines no exception to it.
- **Multi-stream.** The Direction value "Multi-stream" means the channel is
  bidirectional **and** MAY open multiple concurrent transport streams within its
  stream family (core specification §5, Channel directionality). This is the property
  that lets several sub-streams (for example one audio and one file-transfer stream)
  run concurrently on one association, each independently flow-controlled.
- **Advertisement.** A peer that has not advertised channel `0x000C` during the
  handshake MUST NOT receive frames on it; frames on an unadvertised channel MUST be
  dropped (core specification §5). Enabling the channel is therefore a handshake-time
  capability decision, not an implicit default.
- **Min Profile.** "Standard" is the lowest profile at which the channel MAY be
  enabled; the channel is available at Standard and at every higher profile (§5). Its
  profile applicability is detailed in §5 of this page.

## 3. Frame types

Frame types on the Stream channel are drawn from the core specification's per-channel
frame-type namespace (core specification §4.6; `../04_frame_types.md`). Two categories
apply.

**All-channel reserved frame types.** The following frame types are reserved across
**every** channel with the same meaning everywhere, and they retain that meaning on
the Stream channel; an implementation MUST NOT reuse them to carry stream payload:

| Type | Name | Meaning on this channel |
|---|---|---|
| `0x0000` | (reserved) | MUST NOT be used as a frame type. |
| `0x0001` | PING | Liveness probe. |
| `0x0002` | PONG | Reply to PING. |
| `0x0003` | CLOSE | Authenticated, AEAD-protected close. |
| `0x0004` | CLOSE_ACK | Reply to CLOSE. |
| `0x0005` | ERROR | AEAD-protected error report. |
| `0x0006` | KEY_UPDATE | Initiate key update for this (channel, direction). |
| `0x0007` | KEY_UPDATE_ACK | Acknowledge key update. |
| `0x0008` | PATH_CHALLENGE | Path-migration challenge. |
| `0x0009` | PATH_RESPONSE | Path-migration response. |
| `0x000A` | FLOW_UPDATE | Connection-level flow-control credit update. |

**Channel-specific frame types.** The core specification states that channel-specific
frame types begin at **`0x0100`** within each channel's frame namespace (core
specification §4.6; `../04_frame_types.md`), and that per-channel code points at or
above `0x0100` are the conventional home for a channel's own frame types.

At draft-00, the core specification **defines no channel-specific frame type for the
Stream channel**: the registry line, the all-channel reserved types above, and the
general channel machinery are the whole of what the core specification says about
`0x000C`. In particular, the reserved per-channel companion frame-type ranges the
draft enumerates (`0x0035`–`0x0036`, `0x0060`–`0x0063`, `0x0080`, `0x0090`,
`0x00A0`–`0x00A3`, `0x00B0`–`0x00B4`, `0x00C0`–`0x00C4`; core specification
Extension Points, "Reserved Frame-Type Ranges") are reserved for **other** channels
(Memory, Capability, Control, Audit, Settlement/Audit, Governance, and Immune
respectively). **No reserved frame-type range is assigned to the Stream channel by
the core specification.** Concrete per-sub-stream frame types (for example a
sub-stream open, data, or close) are therefore not defined by the core specification
and would be introduced by a future core revision or by a companion specification;
this page MUST NOT invent them. A companion or future-core frame type for this
channel SHALL be placed in the channel-specific `0x0100+` namespace (core
specification §4.6).

> **Recorded editorial inconsistency in -00 (carried, not corrected here).** The
> core specification's §4.6 says channel-specific frame types begin at `0x0100`,
> while the same section also says code points "at or above `0x0030`" that are not
> otherwise reserved are for extensions, and the companion reserved ranges sit below
> `0x0100` (`0x0035`…`0x00C4`). This inconsistency is present in the submitted draft
> and is noted here for a future revision (see `../04_frame_types.md`); this page
> does not silently rewrite the authoritative text.

## 4. Interface and operations (public level)

Because the core specification describes the Stream channel at the level of a
registry line plus the general channel architecture, this page describes the
channel's interface **at that level** and does not manufacture a frame-level
sub-stream protocol the core specification does not define. The public interface an
implementation obtains by enabling channel `0x000C` is the following:

1. **Enablement.** A peer advertises channel `0x000C` during the handshake. Once
   advertised, and only then, the peer MAY send and receive frames on it (§2; core
   specification §5). Enablement requires the Standard profile or higher (§5).

2. **Full-duplex carriage.** Each peer transmits on its own send sequence space
   under its own per-direction traffic keys; both peers MAY transmit at the same
   time (core specification §5). The channel imposes no request/response turn-taking
   of its own.

3. **Concurrent sub-streams.** As a Multi-stream channel, `0x000C` MAY carry
   multiple concurrent transport sub-streams within its stream family (core
   specification §5), for example separate token, audio, video, and file-transfer
   streams on one association.

4. **Independent flow control.** The core specification describes the Stream
   channel's sub-streams as "each with independent flow control" (§5). At the wire
   level the draft defines the all-channel `FLOW_UPDATE` (`0x000A`) frame as a
   connection-level flow-control credit update (core specification §4.6;
   `../04_frame_types.md`); the concrete per-sub-stream flow-control encoding is a
   property the draft asserts for this channel but does not further enumerate at
   draft-00, and this page does not supply one.

5. **Confidentiality and integrity.** Every frame on the channel is AEAD-protected
   and keyed by the channel's own per-direction traffic keys (core specification §5,
   Cryptographic Suites). Key rotation uses the all-channel `KEY_UPDATE` /
   `KEY_UPDATE_ACK` frames (§3); connection liveness, close, path migration, and
   error signalling use the all-channel reserved frames (§3) with their core meaning.

What the core specification does **not** define for this channel at draft-00, and
what this page therefore does not specify, includes: the octet layout of a sub-stream
open/data/close operation, a sub-stream identifier field, media codecs or container
formats, a file-transfer manifest, and any resumption or cancellation mechanism for a
native stream. Streamed *foreign-protocol* replies do have a resumption/cancellation
mechanism, but that is NPAMP-CC-STREAM on the Bridge channel `0x000D`, not this
channel (§6).

## 5. Profile applicability

The Stream channel's Min Profile is **Standard** (`../../registries/channels.csv`;
core specification §5). Consequently:

- The channel MAY be enabled at the **Standard** profile and at every higher profile
  (High and Sovereign); "Min Profile" is the lowest profile at which a channel may be
  enabled, and a channel available at a given profile is available at every higher one
  (core specification §5). The Stream channel is **not** a profile-gated channel: it
  is a baseline channel available from Standard upward.
- At the Standard profile the association operates under the core specification's
  baseline hybrid post-quantum security (core specification, Profile Negotiation,
  "Standard — baseline hybrid post-quantum security").
- At the High and Sovereign profiles the association applies that profile's stronger,
  **profile-wide** cryptographic requirements to every enabled channel, including this
  one, as fixed by the core specification's profile invariants. Those higher-profile
  parameters are profile-wide properties of the association, not properties this
  channel page defines; they are governed by the core specification and are out of
  scope here.

This page states no channel behavior that varies by profile beyond the enablement
floor above: the Stream channel's public interface (§2–§4) is the same at every
profile at which it is enabled.

## 6. Relationship to companion specifications

The Stream channel `0x000C` sits alongside, and MUST NOT be conflated with, the
Bridge-channel streaming machinery:

- **NPAMP-BRIDGE (`../companion/10_bridge_framework.md`).** Foreign-agentic-protocol
  encapsulation is the role of the Bridge channel `0x000D` and NPAMP-BRIDGE, not of
  channel `0x000C`. An implementation MUST NOT carry a foreign protocol's messages on
  the Stream channel expecting NPAMP-BRIDGE envelope, correlation, error, or
  safety-label semantics; those apply only on the Bridge channel.

- **NPAMP-CC-STREAM (`../companion/23_carriage_streaming.md`).** This is the most
  closely related companion: it defines how a streamed *foreign-protocol* reply (a
  sequence of typed foreign events) is carried over the Bridge channel's
  `BRIDGE_STREAM_DATA` / `BRIDGE_STREAM_END` frames, adding resumption and
  cancellation around the foreign events. NPAMP-CC-STREAM operates on the Bridge
  channel `0x000D`; it **explicitly does not define behavior on channel `0x000C`**
  and does not move Bridge traffic onto it (NPAMP-CC-STREAM §1.2, §3). Its
  resumption, cancellation, and StreamControl-TLV mechanisms are Bridge-channel
  constructs and MUST NOT be assumed to apply to a native stream on channel `0x000C`.

- **Choosing between the two.** NPAMP-CC-STREAM directs a deployment that "needs raw
  full-duplex byte or media streaming, rather than carriage of a foreign event
  protocol," to use the core Stream channel `0x000C` instead of encapsulating it on
  the Bridge channel (NPAMP-CC-STREAM §1.2, §8). Symmetrically, the companion index's
  channel-selection guidance permits carrying the "full-duplex streaming (tokens,
  audio, video, file transfer)" foreign-traffic class on the more specific core
  Stream channel `0x000C` instead of, or in addition to, the Bridge channel, with a
  mapping document specifying which channel a given protocol's traffic uses
  (`../companion/00_companion_index.md`, "Channel selection for carriage"). In short:
  **Native** raw byte/media streams belong on `0x000C` (this page); **foreign-event**
  streams that need octet-for-octet foreign-protocol carriage belong on `0x000D`
  under NPAMP-CC-STREAM.

- **Companion index (`../companion/00_companion_index.md`).** The index is the
  manifest of companion specifications and their statuses and states the "carriage by
  class, not by protocol" principle; this channel page is a reference for a core
  channel and is subordinate to the core specification it derives from.

## 7. Conformance

This page introduces no requirement beyond the core specification; the clauses below
restate, in testable form, the Stream channel's public interface as the core
specification defines it. An implementation conforms to this channel page if and only
if, for channel `0x000C`, it also conforms to the core specification and:

1. Enables the channel only at the Standard profile or higher, and MUST NOT deliver
   frames received on channel `0x000C` unless the channel was advertised during the
   handshake (§2, §5; core specification §5);

2. Treats the channel as full-duplex and Multi-stream: it maintains independent
   per-direction send and receive sequence spaces and independent per-direction
   traffic keys, and it MAY open multiple concurrent transport sub-streams within the
   channel's stream family, each independently flow-controlled (§2, §4; core
   specification §5);

3. Honors the all-channel reserved frame types (`0x0001`–`0x000A`) with their core
   meaning on this channel, MUST NOT reuse any of them to carry stream payload, and
   MUST NOT use `0x0000` as a frame type (§3; core specification §4.6);

4. Places any channel-specific frame type it defines for this channel in the
   `0x0100+` namespace, and does not treat the core specification as defining any
   Stream-specific frame type at draft-00 (the core specification defines none) nor
   assume any reserved frame-type range for this channel (the core specification
   reserves none) (§3; core specification §4.6, Extension Points);

5. Does not use channel `0x000C` for foreign-agentic-protocol encapsulation — that is
   the Bridge channel `0x000D` and NPAMP-BRIDGE — and does not apply NPAMP-CC-STREAM's
   Bridge-channel resumption, cancellation, or StreamControl-TLV semantics to a native
   stream on channel `0x000C` (§1, §6; NPAMP-CC-STREAM §1.2, §3); and

6. Applies the negotiated profile's profile-wide cryptographic requirements (the core
   specification's profile invariants) to the channel, and introduces no channel
   behavior not present in the core specification (§4, §5; core specification, Profile
   Negotiation).

A conformance check SHOULD verify each clause above by inspection of a recorded
handshake that advertises channel `0x000C` and a recorded association that carries at
least two concurrent sub-streams in both directions, and SHOULD confirm that no frame
on the channel uses an all-channel reserved type to carry stream payload and that no
Bridge-channel construct is presented as native Stream-channel behavior.
