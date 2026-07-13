# NPAMP-CH-0010 — Discovery Channel `0x0010` (per-channel interface reference; companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is a **per-channel interface reference** for the N-PAMP
> **Discovery channel `0x0010`**. It is derived from the core specification's
> §5 "Channel Architecture" (draft-bubblefish-npamp-01, the "core specification");
> where this reference and the core specification differ, **the draft governs**. It
> restates the channel's registry facts and public frame-type framing, and it points
> to the companion specifications that define the channel's operations — it does not
> add behavior the core specification does not define. It consumes only code points
> the core specification reserves and introduces no change to the core wire format.

## 1. Purpose

The core specification registers channel `0x0010` under the name **Discovery** with
the purpose "Agent, tool, and service discovery and capability advertisement"
(core specification §5, Core Channel Registry). The Discovery channel is the
N-PAMP surface on which one peer learns **what another peer offers** — which
foreign agent protocols and carriage classes it can carry, which tools it exposes,
and which agents it hosts or fronts — so that a client can select an interoperable
protocol and locate an invocable capability without out-of-band configuration.

Discovery is **advertisement and lookup, not invocation.** A record on this channel
is a claim by the advertising peer about a capability; it names the capability and
the identifiers needed to reach it, but the traffic that *uses* the capability is
carried elsewhere — on the Bridge channel `0x000D` (under NPAMP-BRIDGE and the
applicable carriage class) or on whichever more specific core channel the relevant
mapping document designates. Discovery answers "what do you offer, and how is it
addressed"; the answer is then acted upon on another channel.

Like every N-PAMP channel, Discovery has an independent per-direction sequence
space and independent per-direction traffic keys, and a peer MUST NOT send or
receive Discovery frames unless the channel was advertised for the association
during the handshake; frames on an unadvertised channel MUST be dropped (core
specification §5).

## 2. Channel identity

The following identity is taken verbatim from the channel registry
(`../../registries/channels.csv`, row `0x0010`, and core specification §5,
Core Channel Registry). These values are read from the registry, not inferred.

| Property | Value |
|---|---|
| Channel ID | `0x0010` |
| Name | Discovery |
| Purpose | Agent, tool, and service discovery and capability advertisement |
| Minimum profile | Standard |
| Direction | Bidirectional |

"Minimum profile: Standard" means the Discovery channel MAY be enabled at the
Standard profile and at every higher profile (High, Sovereign); it is part of the
public Standard-profile surface (§5). "Direction: Bidirectional" means both peers
send and receive frames on a single stream (core specification §5, Channel
directionality); either peer MAY originate a discovery request or an unsolicited
announcement.

## 3. Frame types

### 3.1 Reserved all-channel frame types

The frame types the core specification reserves across **all** channels retain
their core meaning on the Discovery channel and MUST NOT be reused for
discovery-specific semantics (core specification §4.6):

| Type | Name | Description |
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

### 3.2 Channel-specific frame-type range (`0x0100`+)

Each channel defines its own frame types in the `0x0000–0xFFFF` space, and
**channel-specific frame types begin at `0x0100`** within each channel's frame
namespace (core specification §4.6). Discovery-channel frame types defined by a
companion specification therefore occupy the Discovery channel's own namespace at
or above `0x0100`.

### 3.3 Reserved per-channel frame ranges for this channel

The core specification's Extension Points section reserves a set of per-channel
frame-type ranges for companion specifications (core specification "Reserved
Frame-Type Ranges"; `../04_frame_types.md`). That table reserves ranges for the
Memory, Capability, Control, Audit, Settlement/Audit, Governance, and Immune
channels; **it reserves no sub-`0x0100` range for the Discovery channel.** The
Discovery channel therefore has no reserved companion frame-type range below
`0x0100`, and Discovery-channel companion frame types use the channel-specific
convention of §3.2 (at or above `0x0100`) exclusively.

> **Carried editorial inconsistency (not corrected here).** The core specification's
> §4.6 states that channel-specific frame types begin at `0x0100`, while the same
> section also reserves, for extensions, code points "at or above `0x0030`" and the
> enumerated per-channel ranges that sit below `0x0100` (`0x0035…0x00C4`). This
> inconsistency is present in the submitted draft; it is recorded, not silently
> rewritten, and the draft governs. It does not affect the Discovery channel, which
> has no reserved sub-`0x0100` range and uses only the `0x0100`+ namespace.

## 4. Interface and operations (public level)

The core specification defines the Discovery channel at the level of a **registry
line**: it assigns the channel ID, name, purpose, minimum profile, and direction
(§2), and it fixes the frame-type framing every channel shares (§3). It does **not**
define discovery-specific frame types, record formats, query semantics, or error
codes; those are out of scope for the core wire format and are defined by companion
specifications (§6). This reference describes the channel's interface only at the
level the core specification provides, and does not invent operations the core
specification does not define.

At the core-specification (public, profile-invariant) level, an implementation that
enables the Discovery channel exposes the following interface:

- **Association-scoped, handshake-gated.** The channel exists for an association
  only if it was advertised during the handshake. Its advertised state is scoped to
  that association and MUST NOT be carried into a new one.
- **Bidirectional, full-duplex.** Both peers may transmit simultaneously; each
  direction has its own sequence space and traffic keys. Either peer MAY act as the
  requesting side of a discovery exchange or as the announcing side.
- **Shared control frames.** The reserved all-channel frame types (§3.1) —
  liveness (PING/PONG), authenticated close (CLOSE/CLOSE_ACK), error (ERROR),
  key update (KEY_UPDATE/KEY_UPDATE_ACK), path migration
  (PATH_CHALLENGE/PATH_RESPONSE), and flow control (FLOW_UPDATE) — apply on the
  Discovery channel with their core meaning.
- **Channel-specific operations are delegated.** The concrete discovery operations —
  advertisement records, enumeration/lookup, one-way announcement, and subscription
  to changes — are frame types in the Discovery channel's `0x0100`+ namespace (§3.2)
  and are defined by the companion specifications in §6, not by this reference and
  not by the core specification.

Because the core specification supplies only the registry line, the authoritative,
testable operational contract for this channel lives in the companion
specifications; a reader who needs the wire encoding of a discovery request, a
record, or a discovery error MUST consult NPAMP-DISC (and NPAMP-DISC-SIGNED for
signed records), referenced in §6.

## 5. Profile applicability

The Discovery channel's minimum profile is **Standard** (§2). It is therefore
available at Standard, High, and Sovereign, and it is part of the public
Standard-profile surface — it is not a High- or Sovereign-gated channel, and its
public interface (§2–§4) carries no profile-restricted operations.

The channel's availability depends on it having been advertised during the
handshake (§1); enabling a channel at a given profile is governed by the core
specification's profile negotiation and per-channel key schedule, which are
profile-invariant with respect to the Discovery channel's public interface.

Where a companion specification layers cryptography over discovery data — for
example NPAMP-DISC-SIGNED, which signs individual Discovery Records so they are
verifiable offline (§6) — the choice of signature suite is drawn from the core
specification's signature registry and, for records carried in a live association,
MUST be a suite permitted by the negotiated profile (NPAMP-DISC-SIGNED §8). The
cryptographic internals and parameters of any High- or Sovereign-profile signature
suite are defined by the core specification's cryptographic registries and are out
of scope for this public per-channel reference; this reference names such suites
only at the code-point level the public draft already publishes.

## 6. Relationship to companion specifications

Two companion specifications define the operational semantics carried on this
channel. Both ride the Discovery channel `0x0010`; neither changes the core wire
format, and both reuse facilities of NPAMP-BRIDGE by reference rather than
restating them.

- **NPAMP-DISC — Discovery and Capability Advertisement** (`../companion/40_discovery.md`).
  Defines runtime advertisement and lookup on this channel: the Discovery-channel
  frame types in the `0x0100`+ namespace (§3.2), the deterministic-CBOR Discovery
  Record (protocol, carriage-class, tool, and agent records), a request/response
  lookup with filtering and pagination, a one-way announcement, and a subscription
  by which a peer is notified when the advertised set changes. NPAMP-DISC reuses
  NPAMP-BRIDGE's **correlation discipline** (NPAMP-BRIDGE §5) by reference — a reply
  echoes its request's correlation identifier verbatim and replies are matched by
  that identifier rather than by frame sequence number — and it carries the
  `protocol_id` and carriage-class values as established by NPAMP-BRIDGE §4 and the
  Bridge Protocol Identifier registry without reassigning them. A Discovery Record
  advertises a capability; invocation of that capability is carried on the Bridge
  channel `0x000D` or another core channel, not on the Discovery channel (§1).

- **NPAMP-DISC-SIGNED — Signed and Offline Discovery** (`../companion/41_discovery_signed.md`).
  Extends NPAMP-DISC so that a Discovery Record is self-authenticating at rest: an
  individually signed record verifiable offline against a deployer-configured trust
  anchor, with `not_after` freshness, and bundled into a distributable Discovery
  Document. It introduces **no change to the NPAMP-DISC frame types** and rides the
  same Discovery channel; the signature is a detached signature over the record's
  canonical (deterministic-CBOR) encoding, carried within the record structure.

For completeness, the companion index's "channel selection for carriage"
(`../companion/00_companion_index.md`) notes that capability and schema documents
(agent cards, tool catalogs, schemas) — the subject of the document carriage class,
NPAMP-CC-DOC — MAY be carried on this more specific Discovery channel where a
deployment prefers it to the general Bridge channel. That routing choice is a
property of the relevant carriage class and mapping document, not of this
per-channel reference.

This reference does not restate the operational rules of NPAMP-DISC or
NPAMP-DISC-SIGNED and adds no requirement on top of them; on any operational
question the companion specifications and the core specification govern.

## 7. Conformance

An implementation conforms to this per-channel interface reference for the Discovery
channel if and only if, on channel `0x0010`, it:

1. Uses the channel identity of §2 exactly as the registry defines it — channel ID
   `0x0010`, minimum profile Standard, direction Bidirectional — and enables the
   channel only at the Standard profile or higher (§2, §5);
2. Sends or accepts Discovery frames only when the Discovery channel was advertised
   for the association during the handshake, drops frames on the channel when it was
   not advertised, and carries no Discovery state across associations (§1);
3. Preserves the core meaning of the reserved all-channel frame types on the
   Discovery channel and never reuses them for discovery-specific semantics (§3.1);
4. Places any channel-specific (discovery) frame type in the Discovery channel's own
   namespace at or above `0x0100`, consuming no sub-`0x0100` frame-type code point,
   consistent with the absence of any reserved Discovery-channel range in the core
   specification's Extension Points table (§3.2, §3.3);
5. Treats the core specification as supplying only the channel's registry line and
   frame-type framing, and derives every discovery-specific operation — record
   encoding, lookup, announcement, subscription, and discovery error — from the
   companion specifications of §6 rather than inventing behavior at this reference
   level (§4, §6); and
6. Where signed discovery is used, selects a signature suite from the core
   specification's signature registry that the negotiated profile permits, and does
   not rely on any High- or Sovereign-profile cryptographic internal that this public
   reference does not publish (§5, §6).

A conformance test suite SHOULD assert clauses 1–4 with a recorded association that
enables the Discovery channel at the Standard profile, exercises a reserved
all-channel control frame (for example PING/PONG) on the channel, and confirms that
a discovery-specific frame occupies the `0x0100`+ namespace; the operational
behavior of clauses 5–6 is exercised by the conformance suites of NPAMP-DISC and
NPAMP-DISC-SIGNED, which this reference does not duplicate.
