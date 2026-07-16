# NPAMP-CH-0012 — Knowledge Channel `0x0012` Interface Reference (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is a **public per-channel interface reference** for the
> N-PAMP **Knowledge channel `0x0012`**, derived from the N-PAMP core specification
> (draft-bubblefish-npamp-01, the "core specification") §5 "Channel Architecture";
> the **draft governs**, and where this reference and the core specification differ,
> the core specification prevails. It builds on the core specification and, for
> foreign retrieval traffic that is bridged rather than native, on NPAMP-BRIDGE
> (`../companion/10_bridge_framework.md`). It consumes only code points the core
> specification already reserves, introduces no change to the core wire format, and
> defines **no channel behavior that the core specification does not** — where the
> core specification fixes the channel by a single registry line, this reference
> says so and describes the interface only at that level.

## 1. Purpose

The Knowledge channel `0x0012` is one of the twenty channels of the N-PAMP core
channel registry (core specification §5). The core specification assigns it the
purpose **"Retrieval queries with ranked results and provenance"** and fixes it by
that one registry line: a channel dedicated to the retrieval-query traffic class,
in which a peer issues a query for stored or indexed knowledge and receives, in
reply, a set of results that are **ranked** (returned in a relevance order rather
than as an unordered set) and that carry **provenance** (an attribution of where
each result was drawn from). Its **Multi-stream** direction (core specification §5)
lets a peer run several retrieval exchanges concurrently within the channel's stream
family, so that one long-running or large-result query does not head-of-line block
another.

Beyond that registry line, the core specification defines no query language, no
result or ranking schema, no provenance format, and no channel-specific frame body
for the Knowledge channel. This reference therefore describes the channel only at
the level the core specification supports: the channel's identity, its place in the
frame-type and profile model, and the operations implied by its registered purpose.
A concrete retrieval query/result encoding, ranking model, or provenance schema is
**out of scope for the core specification and for this reference**; any such
encoding is defined by the companion specification NPAMP-KNOWLEDGE
(`../companion/8b_knowledge_channel.md`), not by the core specification or by this
reference, and MUST NOT be inferred from this document (§4, §6).

## 2. Channel identity

The following values are the authoritative registry entry for this channel, taken
verbatim from the core channel registry (core specification §5; machine-readable in
`../../registries/channels.csv`):

| Field | Value |
|---|---|
| Channel ID | `0x0012` |
| Name | Knowledge |
| Purpose | Retrieval queries with ranked results and provenance |
| Min Profile | Standard |
| Direction | Multi-stream |

- **Min Profile = Standard** is the lowest profile at which this channel may be
  enabled; the channel is available at Standard and at every higher profile (High,
  Sovereign) (core specification §5). The Knowledge channel is therefore part of the
  public, Standard-profile channel surface and is not profile-gated (§5).
- **Direction = Multi-stream** means the channel is bidirectional and MAY open
  multiple concurrent transport streams within its stream family (core specification
  §5). Like every N-PAMP channel it is full-duplex: each peer maintains an
  independent per-direction sequence space and independent per-direction traffic
  keys, so both peers MAY transmit simultaneously (core specification §5).
- A peer that has not advertised the Knowledge channel during the handshake MUST NOT
  receive frames on it; frames on an unadvertised channel MUST be dropped (core
  specification §5). Enabling and advertising this channel is a per-association
  decision governed by the core specification's channel-advertisement rules, not by
  this reference.

## 3. Frame types

Frame types on the Knowledge channel follow the core specification's frame-type
model unchanged (core specification §4.6; `../04_frame_types.md`). This reference
defines no new frame types.

### 3.1 Reserved all-channel frame types

The frame types reserved across **all** channels retain their core meaning on the
Knowledge channel, and an implementation MUST NOT reuse them for retrieval traffic:

| Type | Name | Meaning (unchanged on this channel) |
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

The code point `0x0000` is reserved and MUST NOT be used as a frame type (core
specification §4.6).

### 3.2 Channel-specific frame types (`0x0100`+)

Channel-specific frame types begin at **`0x0100`** within each channel's frame
namespace (core specification §4.6). Any frame type that carries a retrieval query,
a ranked result, or provenance on the Knowledge channel is a channel-specific frame
type and, under the `0x0100`+ convention, MUST be assigned from that range. The core
specification does **not** define any such frame type for the Knowledge channel, and
this reference does not define one either; the companion specification NPAMP-KNOWLEDGE
(`../companion/8b_knowledge_channel.md`) now defines these code points in the `0x0100`+
band (§6). An implementation MUST NOT treat any `0x0100`+ code point on this channel as
having a *core-defined* meaning — such code points are defined by NPAMP-KNOWLEDGE, not
by the core specification (§4, §6).

### 3.3 No Knowledge-specific reserved companion range

The core specification's Extension Points reserve per-channel frame-type ranges for
several channels' companion extensions — Memory (`0x0035`–`0x0036`), Capability
(`0x0060`–`0x0063`), Control (`0x0080`), Audit (`0x0090`), Settlement/Audit
(`0x00A0`–`0x00A3`), Governance (`0x00B0`–`0x00B4`), and Immune (`0x00C0`–`0x00C4`)
(core specification, Extension Points → Reserved Frame-Type Ranges;
`../04_frame_types.md`). **No range is reserved for the Knowledge channel.** The
companion specification NPAMP-KNOWLEDGE (`../companion/8b_knowledge_channel.md`), which
defines Knowledge-channel frames, therefore uses the channel-specific `0x0100`+
namespace (§3.2); this reference reserves no range and an implementation MUST NOT
assume one.

> **Editorial note (carried, not corrected).** The core specification's §4.6 states
> that channel-specific frame types begin at `0x0100`, while the same section also
> treats non-reserved code points "at or above `0x0030`" as extension points, and the
> reserved companion ranges above sit below `0x0100`. This inconsistency is present
> in the submitted -00 draft and is recorded in `../04_frame_types.md`; this
> reference repeats it rather than silently resolving it. The core specification
> governs its own resolution in a future revision.

## 4. Interface and operations

At the level the core specification fixes, the Knowledge channel exposes a single
operation class — **retrieval query and ranked, provenance-bearing response** — and
nothing more. Described only at that level:

- A peer MAY issue a **retrieval query** on the channel. Because the channel is
  bidirectional and Multi-stream, either peer MAY originate a query, and multiple
  queries MAY be in flight concurrently on separate streams within the channel's
  stream family (§2; core specification §5).
- A **response** to a retrieval query conveys results that are **ranked** — returned
  in a relevance order — and that carry **provenance** — an attribution of the
  source of each result — consistent with the registered purpose (§1). The registry
  line establishes that ranking and provenance are properties of the response class;
  it does not prescribe how either is encoded.
- The channel's ordering and reliability are those of the underlying N-PAMP channel:
  The per-channel, per-direction sequence space orders frames within a stream, and
  multiple concurrent retrieval exchanges are separated by the channel's stream
  family rather than by any query identifier defined here (§2; core specification
  §5).
- Liveness, teardown, error signalling, key update, path migration, and flow control
  on the channel use the reserved all-channel frames (§3.1) with their core meaning.

This reference intentionally does **not** specify a query grammar, a result record
layout, a scoring or ranking algorithm, a provenance/attestation schema, pagination,
or a per-query correlation identifier. The core specification defines none of these
for the Knowledge channel, and this reference MUST NOT be read as introducing them.
An interface at that concrete level is provided by the companion specification
NPAMP-KNOWLEDGE (`../companion/8b_knowledge_channel.md`), authored against a defined
retrieval model (§6); at the level of this reference, only the registry-level
interface described here is normative, and the concrete retrieval interface is
normative in NPAMP-KNOWLEDGE rather than in the core specification or here.

## 5. Profile applicability

The Knowledge channel's **Min Profile is Standard** (§2). It is therefore available
at all three N-PAMP security profiles and is part of the public Standard-profile
surface:

| Profile | Code | Knowledge channel `0x0012` |
|---|---|---|
| Standard | `0x01` | Available (this is the minimum profile). |
| High | `0x02` | Available (every channel available at Standard is available at High). |
| Sovereign | `0x03` | Available (available at every profile at or above its minimum). |

The three profiles share one wire format and one channel model; they differ only in
the cryptographic primitives and operational requirements they mandate (core
specification §6). The Knowledge channel's interface — its identity, direction,
frame-type model, and retrieval-query operation class — is **profile-invariant** and
is fully described by this public reference. The specific cryptographic primitives
that protect the channel at the High and Sovereign profiles are a property of those
profiles rather than of this channel, are governed by the core specification's
profile definitions, and are **out of scope for this public interface reference**;
this document neither restates nor depends on any High- or Sovereign-profile
cryptographic parameter.

## 6. Relationship to companion specifications

**The Knowledge channel has a dedicated operational companion.** Like the
Discovery channel `0x0010` — for which `../companion/40_discovery.md` (NPAMP-DISC)
defines runtime operations — the Knowledge channel is elaborated by the companion
specification NPAMP-KNOWLEDGE (`../companion/8b_knowledge_channel.md`), which defines a
concrete retrieval interface (ranked, provenance-bearing retrieval with streamed
results, plus continuing-query subscription and credit) in the `0x0100`+ application
band. The core specification itself fixes the channel only by the single registry line
quoted in §1–§2; NPAMP-KNOWLEDGE, not the core specification, makes the operational
details above that line normative. This reference introduces no such behavior of its
own and defers to NPAMP-KNOWLEDGE for it.

Retrieval traffic MAY also reach an N-PAMP peer as a **bridged foreign protocol**
rather than as native Knowledge-channel traffic. Consistent with the companion set's
carriage-by-class principle (`../companion/00_companion_index.md`), a foreign
retrieval or RAG protocol can be carried over N-PAMP through NPAMP-BRIDGE on the
Bridge channel `0x000D` — under a mapped carriage class, or under Class OPAQUE
(`../companion/25_carriage_opaque.md`) when no mapping exists. That is **carriage of
a foreign protocol** and is governed by NPAMP-BRIDGE and the relevant carriage class;
it is distinct from the native Knowledge channel `0x0012` described here, and this
reference makes no claim that any foreign retrieval protocol maps onto the native
channel. The companion index's "channel selection for carriage" guidance routes
certain foreign traffic classes to more specific core channels; it does **not** list
the Knowledge channel, so no such routing is asserted here.

## 7. Conformance

An implementation conforms to this Knowledge-channel interface reference if and only
if it conforms to the core specification and, for the channel `0x0012`, it:

1. Treats `0x0012` as the **Knowledge** channel with the registered purpose
   "Retrieval queries with ranked results and provenance", Min Profile **Standard**,
   and direction **Multi-stream**, exactly as recorded in the core channel registry
   (§2; core specification §5);
2. Enables the channel only at the **Standard** profile or a higher profile, and
   never treats it as unavailable at High or Sovereign (§2, §5; core specification
   §5, §6);
3. Does not deliver or accept any frame on the channel unless the channel was
   advertised during the handshake, and drops frames received on an unadvertised
   channel (§2; core specification §5);
4. Maintains an independent per-direction sequence space and independent
   per-direction traffic keys for the channel, and, as a Multi-stream channel, MAY
   open multiple concurrent transport streams within its stream family (§2; core
   specification §5);
5. Honors the reserved all-channel frame types (§3.1) with their unchanged core
   meaning on this channel and never reuses them for retrieval traffic (§3.1; core
   specification §4.6);
6. Draws any channel-specific (retrieval) frame type from the channel-specific
   namespace beginning at `0x0100`, and relies on **no** Knowledge-channel companion
   frame-type range, because the core specification reserves none (§3.2, §3.3; core
   specification Extension Points); and
7. Introduces, as a normative requirement of this reference, **no** query language,
   ranking algorithm, result schema, provenance format, or channel-specific frame
   body — because the core specification defines the Knowledge channel only at the
   registry level — and defers any such interface to the companion specification
   NPAMP-KNOWLEDGE (`../companion/8b_knowledge_channel.md`) (§1, §4, §6).

A conformance test SHOULD assert clauses 1–6 by exercising a Standard-profile
association that advertises `0x0012`, confirming that frames on an unadvertised
Knowledge channel are dropped (clause 3), that concurrent streams may be opened
(clause 4), and that a reserved all-channel frame (for example PING/PONG or
KEY_UPDATE) behaves identically on this channel as on any other (clause 5). Clause 7
is a negative conformance property: a test suite SHOULD confirm that an
implementation claiming Knowledge-channel support does not require any query, result,
ranking, or provenance encoding that this reference and the core specification leave
undefined.
