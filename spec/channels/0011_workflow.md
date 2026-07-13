# NPAMP-CH-0011 — Workflow Channel (`0x0011`) Interface Reference (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is a **public per-channel interface reference** for the
> N-PAMP Workflow channel (`0x0011`), derived from the N-PAMP core specification
> (draft-bubblefish-npamp-01, the "core specification"), §5 Channel Architecture
> and §8 Extension Points. It restates the channel's registry entry and its public
> frame-type reservations and describes the channel's multi-agent-orchestration and
> task-delegation interface **at the public level only**. It builds on the core
> specification, introduces no change to the core wire format, and defines no
> behavior the core specification does not already reserve. Where the core
> specification supplies only a registry line or reserves a code point without
> defining its semantics, this reference says so and describes the interface at
> that level. **The draft governs**: on any disagreement between this reference and
> the core specification, the core specification is authoritative.

## 1. Purpose

The core specification assigns channel `0x0011` the name **Workflow** and the
purpose **"Multi-agent orchestration and task delegation"** (core specification §5,
Core Channel Registry; `../../registries/channels.csv`). Expanded, the Workflow
channel is the N-PAMP channel over which one peer **coordinates work across agents
and delegates tasks** to another peer: the class of traffic that arranges,
sequences, and hands off units of agentic work, as distinct from durable
addressable state (Memory `0x0001`), ranked retrieval with provenance
(Knowledge `0x0012`), agent-to-human interface events (Interaction `0x000F`), or
the encapsulation of a foreign agent protocol (Bridge `0x000D`). It is the channel
a deployment uses to say *what work is to be done, by whom, and in what order*
between two N-PAMP peers, rather than to read or mutate application state.

The registry purpose names a **traffic class**, not a topology. The core
specification does not define an orchestration model, a task or job schema, a
delegation-authority model, a scheduler, a dependency graph, or any multi-party
routing for this channel; an N-PAMP association is a peer-to-peer association, and
"multi-agent" here is the name of the traffic class the channel carries, not a
statement that the channel itself is multi-party. Accordingly, this reference
describes the Workflow interface at the level the core specification actually fixes
— the coordination *classes* named by the registry purpose (§4) — and does not
invent frame layouts, field structures, task schemas, or semantics that the core
specification does not state.

The core specification defines the Workflow channel **only** as this registry
entry. Unlike the Memory channel — for which the core specification additionally
reserves a per-channel frame-type range (§3) — the core specification reserves
**no** Workflow-specific frame-type range and defines no Workflow-specific wire
encoding, message schema, or operation contract. A future companion specification
MAY define a concrete Workflow operation encoding within the channel-specific code
points the core specification leaves available; until then, the public Workflow
interface is exactly what this reference restates.

## 2. Channel identity

The following values are taken verbatim from the core channel registry
(core specification §5; machine-readable form `../../registries/channels.csv`). They are
normative in the core specification; this reference restates them and does not
alter them.

| Attribute | Value |
|---|---|
| Channel ID | `0x0011` |
| Name | Workflow |
| Purpose | Multi-agent orchestration and task delegation |
| Minimum profile | Standard |
| Direction | Bidirectional |

- **Minimum profile — Standard.** The Workflow channel MAY be enabled at the
  Standard profile and is available at Standard and at every higher profile
  (High, Sovereign), per the core specification's min-profile rule
  (§5: the minimum profile is the lowest profile at which a channel may be
  enabled). See §5 for profile applicability.
- **Direction — Bidirectional.** Both peers send and receive frames on a single
  stream of this channel (core specification §5, Channel directionality). As with
  every N-PAMP channel, each peer maintains an independent send and receive
  sequence space and independent per-direction traffic keys, so both peers MAY
  transmit on the channel simultaneously and either peer MAY orchestrate or
  delegate to the other (core specification §5). The Workflow channel is **not**
  classified Multi-stream: it does not open multiple concurrent transport
  sub-streams within a stream family (contrast the Multi-stream Stream channel
  `0x000C` and Knowledge channel `0x0012`).
- **Advertisement gate.** A peer that has not advertised the Workflow channel
  during the handshake MUST NOT receive frames on it; frames on an unadvertised
  Workflow channel MUST be dropped (core specification §5, applied to `0x0011`).

## 3. Frame types

Frame types on the Workflow channel are drawn from the same per-channel
`0x0000`–`0xFFFF` frame-type namespace every N-PAMP channel uses
(core specification §4.6; reference `../04_frame_types.md`). Two groups are
relevant to this channel, and a third is explicitly empty.

### 3.1 Reserved all-channel frame types

The following frame types are reserved across **all** channels with the same
meaning everywhere and retain that meaning on the Workflow channel. An
implementation MUST NOT reuse them for Workflow application traffic.

| Type | Name | Meaning on the Workflow channel |
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

### 3.2 Reserved Workflow-channel extension frame range

The core specification's Reserved Frame-Type Ranges table (core specification §8.1,
Extension Points; references `../04_frame_types.md` and `../09_extension_points.md`)
reserves several sub-`0x0100` frame-type ranges for companion extensions — but
**none of those ranges is assigned to the Workflow channel**. The reserved ranges
there belong to the Memory, Capability, Control, Audit, Settlement/Audit,
Governance, and Immune channels:

| Range | Reserved for |
|---|---|
| `0x0035` – `0x0036` | Memory-channel eviction and revive extension frames |
| `0x0060` – `0x0063` | Capability-channel token extension frames |
| `0x0080` – `0x0080` | Control-channel flow-extension frames |
| `0x0090` – `0x0090` | Audit-channel per-frame integrity-extension frames |
| `0x00A0` – `0x00A3` | Settlement/Audit batch-commitment extension frames |
| `0x00B0` – `0x00B4` | Governance-channel quorum extension frames |
| `0x00C0` – `0x00C4` | Immune-channel propagation extension frames |

The Workflow channel therefore has **no** core-reserved sub-`0x0100` extension
frame range of its own. An implementation MUST NOT treat any of the ranges above as
Workflow frames, and MUST NOT assign a Workflow-specific meaning to any code point
the core specification reserves for another channel.

> **Known editorial inconsistency in -00 (carried, not corrected here).** The core
> specification states that channel-specific frame types begin at `0x0100`
> (§4.6), yet the reserved companion ranges above sit below `0x0100`
> (`0x0035`–`0x00C4`). This inconsistency is present in the submitted draft and is
> recorded in `../04_frame_types.md`; this reference does not silently rewrite the
> authoritative text. Because no reserved sub-`0x0100` range is assigned to the
> Workflow channel, the inconsistency does not affect this channel.

### 3.3 Channel-specific frame types (`0x0100`+ convention)

Channel-specific frame types begin at **`0x0100`** within each channel's frame
namespace (core specification §4.6). This is the range in which a Workflow-specific
operation encoding — for example concrete task-delegation and orchestration request
and reply frames (§4) — would be assigned. The core specification defines **no**
Workflow-specific frame type in this range, and no companion specification in the
current set (`../companion/00_companion_index.md`) defines one. Consequently there
is, at present, no core- or companion-defined Workflow operation frame; §4
describes the interface at the registry level the core specification actually fixes.

## 4. Interface and operations (public level)

The Workflow channel's public interface is the set of coordination classes named by
its registry purpose. The core specification fixes these as **names of traffic
classes**, not as wire encodings; this section restates them at that level and
states explicitly where the core specification stops. An implementation MUST NOT
read a wire format into this section: no frame layout, field structure, TLV, task
schema, or correlation scheme below is defined by the core specification.

| Coordination class | Public meaning (from the registry purpose) |
|---|---|
| Multi-agent orchestration | Coordinate and sequence agentic work between peers — the class of traffic that arranges what is to be done and in what order. |
| Task delegation | Hand off a unit of agentic work from one peer to another for execution. |

Notes and honest boundaries:

- **"Orchestration" versus "delegation".** The registry purpose lists both
  ("multi-agent orchestration **and** task delegation"). The core specification does
  not further distinguish a coordination/sequencing message from a task hand-off,
  and defines no schema for either; this reference records that both terms appear in
  the registry purpose and does not manufacture a distinction, encoding, or field
  set the core specification does not state. A companion specification MAY define the
  distinction and the encodings precisely.
- **No operation encoding is defined here.** Because the core specification assigns
  no Workflow-specific frame type (§3.3) and reserves no Workflow frame-type range
  (§3.2), the coordination classes above have **no core-defined request frame, reply
  frame, task identifier scheme, work-item encoding, status model, or error model**.
  This reference MUST NOT be cited as the source of any such encoding.
- **No topology or authority model.** The core specification defines no
  orchestration topology, dependency graph, scheduling policy, delegation-authority
  or capability-grant model, or multi-party routing for this channel. Where a
  delegation must be authorized, the authority model is a matter for the Capability
  channel `0x0002` ("Capability issuance, delegation, revocation, lookup", core
  specification §5) or a future companion specification, not for this reference; this
  page introduces none.
- **Direction and origination.** Because the channel is Bidirectional (§2), either
  peer MAY originate an orchestration or delegation message; there is no fixed
  orchestrator/worker assignment at the channel level, and the core specification
  imposes none.
- **Correlation and ordering.** The Workflow channel has an independent
  per-direction sequence space (core specification §5), which orders frames within a
  direction. The core specification does not define how a Workflow reply (if any) is
  correlated to a request (unlike the Bridge channel, where NPAMP-BRIDGE §5 defines a
  `correlation_id`); a Workflow operation encoding, when specified by a companion, is
  where such correlation would be defined. This reference does not define it.
- **Liveness, teardown, and control.** Liveness, teardown, error signalling, key
  update, path migration, and flow control on the channel use the reserved
  all-channel frames (§3.1) with their core meaning; the core specification defines
  no Workflow-specific equivalent.

## 5. Profile applicability

The Workflow channel's minimum profile is **Standard** (§2). By the core
specification's min-profile rule (§5), the channel is available at the Standard
profile and at every higher profile; that is, at **Standard, High, and Sovereign**.
There is no profile at which the Workflow channel is unavailable once its minimum
profile is met, and no upper profile bound.

- **Standard profile.** The Workflow channel is available and MAY be enabled. This
  is the profile at which the public Workflow interface described in this reference
  is fully expressible.
- **Higher profiles (High, Sovereign).** The Workflow channel remains available with
  the same wire-level frame namespace and the same public interface. N-PAMP's three
  profiles (Standard, High, Sovereign) share **one wire format** and differ in the
  cryptographic primitives and operational requirements they mandate
  (core specification, Profile Negotiation). The Workflow channel's framing and
  interface — its identity (§2), its frame-type namespace (§3), and its
  registry-level coordination interface (§4) — are **profile-invariant**: they do not
  change across profiles. The per-profile cryptographic suites are selected by the
  core specification's profile negotiation and key schedule and are **out of scope
  for this per-channel interface reference**.
- **Scheduling.** The core specification's scheduling recommendation states that the
  Control and Immune channels SHOULD be scheduled at higher priority than the bulk
  channels (Memory, Sensory, Telemetry) during congestion (core specification §5).
  The Workflow channel is **not** named in that recommendation — it is neither a
  higher-priority control channel nor one of the enumerated bulk channels — so the
  core specification assigns it no scheduling priority, and this reference does not
  invent one.
- **Publishing scope.** This reference documents only the public **Standard-profile
  interface surface** of the channel — its identity, purpose, direction, minimum
  profile, and public frame-type namespace. High- and Sovereign-profile
  cryptographic internals and parameters are governed by the core specification's
  profile negotiation and are out of scope here.

## 6. Relationship to companion specifications

The Workflow channel is a **native core channel**: unlike the Bridge channel
(`0x000D`), which encapsulates foreign agent protocols and is elaborated by the
NPAMP-BRIDGE companion framework (`../companion/10_bridge_framework.md`) and its
carriage classes, and unlike the Discovery channel (`0x0010`), elaborated by
NPAMP-DISC (`../companion/40_discovery.md`), the Workflow channel has **no
dedicated companion specification** in the current companion set
(`../companion/00_companion_index.md`). It is therefore not a bridge carriage class
and does not build on NPAMP-BRIDGE.

The consequence for an implementer is that the Workflow channel's public contract
is exactly what §2–§5 restate:

- Its **identity** — id `0x0011`, name Workflow, purpose "multi-agent orchestration
  and task delegation", minimum profile Standard, direction Bidirectional (§2);
- Its **public interface** — the multi-agent-orchestration and task-delegation
  coordination classes, described at the registry level, with **no core-defined wire
  encoding** (§4); and
- Its **reserved extension surface** — **none** at the frame-type level: the core
  specification reserves no Workflow-specific frame-type range, and no current
  companion defines a Workflow frame in the `0x0100`+ namespace (§3.2, §3.3).

Orchestration or delegation traffic MAY also reach an N-PAMP peer as a **bridged
foreign protocol** rather than as native Workflow-channel traffic. Consistent with
the companion set's carriage-by-class principle
(`../companion/00_companion_index.md`), a foreign agent-to-agent or orchestration
protocol can be carried over N-PAMP through NPAMP-BRIDGE on the Bridge channel
`0x000D` — under a mapped carriage class, or under Class OPAQUE
(`../companion/25_carriage_opaque.md`) when no mapping exists. That is **carriage of
a foreign protocol** and is governed by NPAMP-BRIDGE and the relevant carriage
class; it is distinct from the native Workflow channel `0x0011` described here, and
this reference makes no claim that any foreign orchestration protocol maps onto the
native channel. The companion index's "channel selection for carriage" guidance
routes certain foreign traffic classes to more specific core channels; it does
**not** list the Workflow channel, so no such routing is asserted here.

Should richer, interoperable Workflow operations be wanted, the path is the same as
for any N-PAMP extension: author a companion specification that defines a Workflow
operation encoding within the channel-specific `0x0100`+ code points, verified
against the core specification. Until such a companion exists, an implementation
carries Workflow traffic under the channel identity above, and there is no
additional core- or companion-defined Workflow behavior to conform to. This
reference documents the interface at that public level and defines no new behavior.

## 7. Conformance

An implementation conforms to this Workflow-channel interface reference if and only
if, for channel `0x0011`, it:

1. Treats channel `0x0011` as the **Workflow** channel whose purpose is multi-agent
   orchestration and task delegation, consistent with the core channel registry
   (§2), and does not repurpose the channel identifier for other traffic;
2. Enables the Workflow channel only at the **Standard** profile or higher, never
   below Standard, and — once Standard is met — treats the channel as available at
   Standard, High, and Sovereign (§2, §5);
3. Drops any frame received on the Workflow channel that the peer has not advertised
   during the handshake, and does not deliver such frames to the workflow consumer
   (§2);
4. Preserves the core meaning of the reserved all-channel frame types
   (`0x0001`–`0x000A`) on the Workflow channel and does not reuse any of them for
   Workflow application traffic (§3.1);
5. Assigns **no** Workflow-specific meaning to any core-reserved sub-`0x0100`
   frame-type range, because the core specification reserves no such range for the
   Workflow channel (§3.2), and places any future Workflow-specific operation
   encoding only in the channel-specific `0x0100`+ namespace (§3.3);
6. Does not treat any coordination-class description in §4 as a normative wire
   encoding, and does not cite this reference as the source of any Workflow request
   frame, reply frame, task identifier scheme, work-item encoding, correlation
   scheme, delegation-authority model, or error model, none of which the core
   specification defines for this channel (§3.3, §4);
7. Supports the channel's **Bidirectional** direction — both peers sending and
   receiving on a single stream, each maintaining independent per-direction sequence
   spaces and traffic keys — and does not open multiple concurrent transport streams
   within the channel as though it were Multi-stream (§2); and
8. Defers all Workflow operation semantics beyond the registry-level interface of §4
   to a future companion specification, adding no Workflow behavior of its own that
   the core specification does not reserve (§6).

A conformance test suite SHOULD assert each clause above, and in particular SHOULD
verify clause 5 by confirming that an implementation does not emit or honor any
sub-`0x0100` frame as a Workflow-defined operation, and clause 3 by confirming that
a Workflow frame arriving on an unadvertised channel is dropped.
