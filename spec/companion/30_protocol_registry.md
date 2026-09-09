# NPAMP-REG — Bridge Protocol Identifier Registry (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document defines the registry of values for the `protocol_id` field of
> the BridgeEnvelope TLV defined by NPAMP-BRIDGE. It consumes only code points the
> core specification already reserves and the byte space the BridgeEnvelope TLV
> already allocates; it introduces no change to the core wire format and no change
> to NPAMP-BRIDGE.

## 1. Scope

NPAMP-BRIDGE encapsulates a foreign agentic protocol on the N-PAMP Bridge channel
`0x000D`. Every Bridge frame carries a BridgeEnvelope TLV (core-specification TLV
type `0x0010`), and the first two octets of that TLV's value are the `protocol_id`: a
two-octet (`u16`, big-endian), formerly one-octet (`u8`), identifier naming the
foreign protocol whose message is carried verbatim in the frame. A u8-era value
`0xNN` migrates losslessly to the two-octet value `0x00NN` (§8.4). A receiver uses
`protocol_id` to decide which foreign protocol a frame belongs to and which carriage
class governs its interpretation.

This document defines:

1. The structure and partitioning of the two-octet `protocol_id` code-point space
   (§4);
2. The meaning of the **carriage class** associated with each assigned code point
   (§5);
3. The set of assigned code points (§6);
4. The experimental and private-use ranges and the rules for using them (§7);
5. The registration procedure by which new code points are assigned (§8); and
6. The handling requirements an implementation MUST follow when it receives a
   `protocol_id` it does not carry (§9).

This document is a registry specification. It does not define any foreign-protocol
mapping; each mapping is defined in its own companion document, which this registry
references by code point. The structural carriage of foreign messages — envelope,
correlation, error model, safety annotation, notifications, and streaming — is
defined wholly by NPAMP-BRIDGE and is not restated or altered here.

## 2. Relationship to the core specification and to NPAMP-BRIDGE

This document builds on, and does not modify, the following:

| Artifact | Defined by | Use here |
|---|---|---|
| Bridge channel `0x000D` | Core specification (channel registry) | The channel on which `protocol_id`-tagged frames travel. |
| TLV type `0x0010` (BridgeEnvelope) | Core specification (reserved for a companion specification); NPAMP-BRIDGE | The TLV whose first two value octets are `protocol_id`. |
| `protocol_id` field (`u16`, formerly `u8`) and its range partition | NPAMP-BRIDGE | The exact field this registry enumerates. |
| `ProtocolUnsupported` error (transport error code 2) | NPAMP-BRIDGE | The error a receiver returns for an uncarried `protocol_id` (§9). |
| Carriage classes (JSONRPC, HTTP, MSG, STREAM, DOC, OPAQUE) | The carriage-class companion specifications | The interpretation each assigned `protocol_id` selects (§5). |

NPAMP-BRIDGE fixes the `protocol_id` field's width (two octets since the §8.4
widening; one octet before it) and partitions its value space into an assigned
region, an experimental region, and a private-use region. This document does not
itself widen the field — that is a NPAMP-BRIDGE revision, recorded here only as the
consequence §8.4 describes — and does not reassign any value NPAMP-BRIDGE already
names. It enumerates the assigned region, gives normative meaning to the
experimental and private-use regions consistent with NPAMP-BRIDGE, and specifies how
the assigned region grows over time, including the one-time widening event of §8.4.

## 3. Terminology

For the purposes of this document:

Bridge Protocol Identifier (`protocol_id`):
: The two-octet (big-endian) unsigned integer that is the first two octets of the
  BridgeEnvelope TLV value, naming the foreign protocol carried by a Bridge frame.
  One octet before the §8.4 widening.

Carriage class:
: A structural family of foreign protocols that share one generic mapping onto
  NPAMP-BRIDGE frames and the BridgeEnvelope. A carriage class is defined by its own
  companion specification. Every assigned `protocol_id` names exactly one carriage
  class.

Assigned code point:
: A `protocol_id` value listed in §6 of this document with a name, a carriage class,
  and a reference.

Experimental code point:
: A `protocol_id` value in the experimental range (§7.1), usable without registration
  for development and private interoperation, carrying no guarantee of cross-vendor
  meaning.

Private-use code point:
: A `protocol_id` value in the private-use range (§7.2), usable within a single
  administrative domain for a protocol that domain does not wish to register.

## 4. Code-point space and partition

The `protocol_id` field is two octets, giving 65,536 code points
(`0x0000`–`0xFFFF`). Before the §8.4 widening it was one octet, giving 256 code
points (`0x00`–`0xFF`); every value assigned under that narrower field migrates
losslessly to the two-octet value with a zero high-order octet (`0xNN` → `0x00NN`,
§8.4), and every boundary the one-octet partition fixed is preserved unchanged, at
the same numeric values, in the low-order octet below. The space is partitioned as
follows. The four low-order-octet boundaries are those originally fixed by
NPAMP-BRIDGE and this document MUST NOT alter them; the extended range
`0x0100`–`0xFFFF` is the additional standards-assigned space the §8.4 widening opens.

| Range | Size | Class of use | Assignment policy (§8) |
|---|---|---|---|
| `0x0000` | 1 | Reserved (the null identifier). MUST NOT be used as a `protocol_id`. | Not assignable. |
| `0x0001` – `0x000F` | 15 | Standards-assigned protocols (the original one-octet-era range). | First Come First Served (§8). |
| `0x0010` – `0x007F` | 112 | Experimental. | No registration (§7.1). |
| `0x0080` – `0x00FF` | 128 | Private use. | No registration (§7.2). |
| `0x0100` – `0xFFFF` | 65,280 | Standards-assigned protocols (opened by the §8.4 widening). | First Come First Served (§8). |

The value `0x0000` is the null identifier; a BridgeEnvelope whose `protocol_id` is
`0x0000` is malformed, and a receiver MUST reject the frame with `EnvelopeMalformed`
(NPAMP-BRIDGE transport error code 1), exactly as for any other malformed envelope.

A sender MUST NOT place a value from the experimental range (`0x0010`–`0x007F`) or
the private-use range (`0x0080`–`0x00FF`) into a frame intended for interoperation
outside the administrative domain that controls that value's meaning (§7).

## 5. Carriage class

Every assigned `protocol_id` (§6) names exactly one carriage class. The carriage
class determines how the foreign message and its operation namespace are interpreted
within the structure NPAMP-BRIDGE defines; it does not change that structure. The
carriage classes referenced by this registry are:

| Class | Short name | Foreign-protocol family it carries |
|---|---|---|
| JSONRPC | NPAMP-CC-JSONRPC | JSON-RPC 2.0 request/response/notification protocols. |
| HTTP | NPAMP-CC-HTTP | HTTP-semantics (method, path, headers, body) protocols. |
| MSG | NPAMP-CC-MSG | Message-passing / performative (speech-act) protocols. |
| STREAM | NPAMP-CC-STREAM | Event and streaming protocols carried over BRIDGE_STREAM_DATA / BRIDGE_STREAM_END. |
| DOC | NPAMP-CC-DOC | Capability and schema documents (agent cards, tool catalogs, schemas). |
| OPAQUE | NPAMP-CC-OPAQUE | Any declared-content-type payload, carried with no protocol-specific mapping. |

The carriage class named for an assigned code point is the class under which a
conforming peer that carries that `protocol_id` MUST interpret a frame bearing it,
unless a protocol-specific mapping document (referenced from §6) narrows the
interpretation while remaining within that class. A `protocol_id` MUST name a
carriage class that is defined by a published carriage-class companion specification;
this registry MUST NOT assign a code point to a carriage class that does not exist.

Class OPAQUE is the universal carriage: it interprets the foreign message as an
opaque payload of the `content_type` declared in the BridgeEnvelope and applies no
protocol-specific structure. A `protocol_id` whose richer carriage class has not yet
been authored MAY be carried under Class OPAQUE by a peer that supports OPAQUE; this
does not change the code point's assigned class in §6.

## 6. Assigned code points

The following `protocol_id` values are assigned by this document. Each row gives the
code point, the foreign protocol it names, the carriage class (§5) under which a peer
that carries it MUST interpret it, and the mapping document that pins the
protocol-specific detail. A code point whose mapping document is not yet authored is
nonetheless assigned and reserved against reuse; until its mapping is authored, a
peer MAY carry it under Class OPAQUE (§5).

| `protocol_id` | Protocol | Carriage class | Mapping reference |
|---|---|---|---|
| 0x0001 | MCP — Model Context Protocol | JSONRPC | NPAMP-MAP-MCP |
| 0x0002 | A2A — Agent2Agent | JSONRPC (with DOC for the AgentCard) | NPAMP-MAP-A2A |
| 0x0003 | HTTP/2 generic carriage | HTTP | NPAMP-CC-HTTP |
| 0x0004 | WebSocket generic carriage | STREAM | NPAMP-CC-STREAM |
| 0x0005 | gRPC generic carriage | STREAM | NPAMP-CC-STREAM |
| 0x0006 | NLIP — Natural Language Interaction Protocol | HTTP (request/response); STREAM (WebSocket binding) | NPAMP-MAP-NLIP |
| 0x0007 | ANP — Agent Network Protocol | HTTP (request/response); OPAQUE (universal fallback) | NPAMP-MAP-ANP |
| 0x0008 | AGNTCY — Internet of Agents collective | STREAM (SLIM); HTTP (Agent Connect Protocol); DOC (capability documents) | NPAMP-MAP-AGNTCY |
| 0x0009 | AP2 — Agent Payments Protocol | DOC (Mandate documents); JSONRPC via NPAMP-MAP-A2A (host-carried traffic) | NPAMP-MAP-AP2 |
| 0x000A | x402 — internet-native HTTP payments | HTTP | NPAMP-MAP-X402 |

Every value in this table is unchanged, at the same low-order-octet numeric value,
by the §8.4 widening (`0x06` before the widening is `0x0006` after it, and so on);
none of these ten assignments moves or is reassigned by that widening.

Code points `0x0001`–`0x0004` are the values NPAMP-BRIDGE names directly; this
document records them with their carriage class and mapping reference and MUST NOT
reassign them. Code points `0x0005`–`0x000A` are assigned under the §8 registration
procedure — `0x0005` mirroring the `0x0004` WebSocket row's own "generic carriage"
pattern (decisions/adr/0015), and `0x0006`–`0x000A` assigned together as the first
wave of agent-protocol registrations under §8 — and likewise MUST NOT be reassigned.
Code points `0x000B`–`0x000F` are unassigned and available under the registration
procedure of §8, as is the extended range `0x0100`–`0xFFFF` opened by §8.4.

A peer that advertises support for a `protocol_id` in §6 (whether by NPAMP-DISC or by
local configuration) asserts that it carries that protocol under the named carriage
class. A peer that does not carry an assigned `protocol_id` MUST follow §9 when it
receives a frame bearing that value.

The entries in §6 are protocol *identifiers*, not endorsements: assigning a code
point states that frames bearing that value are carried under the named class. It
makes no claim about the security, correctness, or completeness of the foreign
protocol itself, which remains the responsibility of that protocol's own
specification and of the mapping document referenced here.

## 7. Experimental and private-use ranges

### 7.1 Experimental range (`0x0010` – `0x007F`)

Code points in the range `0x0010`–`0x007F` are available for experimental and
development use without registration. A value in this range carries no guaranteed
meaning across administrative domains: two independent parties MAY assign the same
experimental value to different protocols. Therefore:

- A sender MUST NOT use an experimental `protocol_id` on an association unless it has
  out-of-band agreement with the peer on the meaning of that value for that
  association.
- A receiver that has no such agreement MUST treat an experimental `protocol_id` it
  does not recognize exactly as it treats any uncarried protocol: it MUST return
  `ProtocolUnsupported` (§9).
- An implementation MUST NOT ship a production default that emits an experimental
  `protocol_id` for a protocol that has an assigned code point in §6.

Experimental code points MUST NOT be relied upon for interoperation between
independently developed implementations. When an experimentally carried protocol is
ready for general interoperation, a code point SHOULD be obtained under §8 and the
experimental value retired.

### 7.2 Private-use range (`0x0080` – `0x00FF`)

Code points in the range `0x0080`–`0x00FF` are available for private use within a single
administrative domain — for example, a vendor's internal protocol or a deployment's
in-house format — without registration. Values in this range are never assigned by
this registry and carry no cross-domain meaning. Therefore:

- A `protocol_id` in the private-use range has meaning only within the administrative
  domain that defines it; that meaning is established and managed by that domain, not
  by this document.
- A sender MUST NOT emit a private-use `protocol_id` toward a peer outside the
  administrative domain that controls the value's meaning.
- A receiver outside that domain MUST treat a private-use `protocol_id` it does not
  carry as an uncarried protocol and MUST return `ProtocolUnsupported` (§9).
- This registry MUST NOT assign, and an implementation MUST NOT expect IANA or any
  central authority to assign, any value in the private-use range.

A protocol carried under a private-use code point is RECOMMENDED to use Class OPAQUE
(NPAMP-CC-OPAQUE), because Class OPAQUE requires no protocol-specific mapping and
carries the payload under its declared `content_type`, which is sufficient for
private interoperation within one domain.

## 8. Registration procedure

### 8.1 Policy

New assignments in the standards-assigned range `0x0005`–`0x000F` (and, since the
§8.4 widening, the extended standards-assigned range `0x0100`–`0xFFFF`) are made
under a **First Come First Served** policy (RFC 8126). This registry is maintained by
the N-PAMP change controller directly; it is not IANA-hosted, and this policy governs
assignment by that maintainer, not by IANA. A registration request MUST supply the
fields of §8.2, including a stable, publicly available specification that defines
the foreign protocol's carriage with sufficient detail to permit interoperable
implementation — either by reference to an existing carriage-class companion
specification (§5) or by a protocol-specific mapping document built on one. This
stable-specification reference is a required **field** of the registration (§8.2),
not a substantive-review gate: the maintainer assigns the requested code point (or,
absent a specific request, the next available value in `0x0005`–`0x000F`, then in
`0x0100`–`0xFFFF`) once §8.2's fields are complete, names an existing carriage class
(§5), and does not duplicate an existing assignment (§6) or a range boundary fixed by
NPAMP-BRIDGE (§4). The maintainer MUST NOT withhold assignment pending a substantive
evaluation of the foreign protocol's merits, and MUST NOT assign a value outside
`0x0005`–`0x000F` or `0x0100`–`0xFFFF`, or reassign a value in `0x0000`–`0x0004`.

The experimental range (`0x0010`–`0x007F`) and the private-use range
(`0x0080`–`0x00FF`) require no registration and are not subject to this procedure.

### 8.2 Required fields

A registration request for a code point in `0x0005`–`0x000F` or `0x0100`–`0xFFFF`
MUST provide:

| Field | Requirement |
|---|---|
| Protocol name | The human-readable name of the foreign protocol, and its common short name if any. |
| Requested code point | OPTIONAL. A specific value in `0x0005`–`0x000F` or `0x0100`–`0xFFFF`, or "any". Absent a specific request the maintainer assigns the next available value; the maintainer MAY assign a different value only to avoid a collision (§6) or a range boundary fixed by NPAMP-BRIDGE (§4). |
| Carriage class | One of the classes in §5, named by its short name, and identified by a published carriage-class companion specification. |
| Mapping reference | The document that pins the protocol-specific carriage (method/operation namespace and any protocol-specific fields), or a statement that the protocol is carried generically by the named carriage class with no additional mapping. |
| Foreign-protocol reference | A stable, publicly available reference to the foreign protocol's own specification. |
| Change controller | The entity responsible for the registration. |
| Contact | A monitored contact for the registration. |

### 8.3 Exhaustion of the original standards-assigned range

The original one-octet-era standards-assigned range provided fifteen code points
(`0x0001`–`0x000F`), of which `0x0001`–`0x000A` are assigned in §6, leaving
`0x000B`–`0x000F` (five values) available. That range was small by design: it was
intended for protocols that warrant a standards-assigned, cross-domain identifier,
while the experimental and private-use ranges and Class OPAQUE carry everything else
without consuming it. Because the `protocol_id` field was fixed at one octet by
NPAMP-BRIDGE, this document could not, by itself, widen the range; a revision of
NPAMP-BRIDGE was required to widen the field. §8.4 records that revision.

### 8.4 Widening to a two-octet field

NPAMP-BRIDGE has widened `protocol_id` from one octet to two (big-endian), the
revision §8.3 anticipated as the response to standards-range exhaustion. This section
records the effect of that widening on this registry; it does not itself change any
value NPAMP-BRIDGE names or any code point already assigned in §6.

1. **Migration.** Every value assigned under the one-octet field migrates losslessly
   to the two-octet field with a zero high-order octet: a u8-era value `0xNN` becomes
   the u16 value `0x00NN`. This is a pure zero-extension, not a reassignment — the
   same code point continues to name the same protocol under the same carriage class.
2. **Boundaries preserved.** Every boundary the one-octet partition fixed (the null
   identifier, the original standards-assigned range, the experimental range, the
   private-use range) is preserved unchanged, at the same numeric values, in the
   low-order octet of the widened field (§4). None of the ten values assigned in §6
   moves or is reassigned.
3. **Extended range opened.** The newly available two-octet space `0x0100`–`0xFFFF`
   (65,280 values) is opened as additional standards-assigned space under the same
   First Come First Served policy as `0x0005`–`0x000F` (§8.1, §8.2). This is the sole
   substantive change this widening makes to the registry: it removes the fifteen-slot
   ceiling §8.3 described, without altering the meaning of any value already assigned.
4. **No new class of use.** The widening introduces no new class of use beyond the
   four §4 already defines (reserved, standards-assigned, experimental, private-use);
   the extended range is standards-assigned, not a new region with its own rules.

## 9. Handling of an uncarried protocol identifier

A receiver that receives a Bridge frame whose `protocol_id` it does not carry MUST
NOT process the foreign message and MUST reply, for a BRIDGE_REQUEST, with a
BRIDGE_ERROR carrying the NPAMP-BRIDGE transport error `ProtocolUnsupported`
(code 2). This is the behavior NPAMP-BRIDGE already defines for an uncarried
`protocol_id`; this document does not add to it. Specifically:

- A receiver MUST treat an unassigned standards-range value (`0x000B`–`0x000F` or
  `0x0100`–`0xFFFF` not yet in §6), an experimental value it has no agreement on
  (§7.1), and a private-use value it does not define (§7.2) all as "not carried," and
  MUST return `ProtocolUnsupported` for a request bearing any of them.
- A receiver MUST reject `protocol_id` `0x0000` with `EnvelopeMalformed` (code 1), not
  `ProtocolUnsupported`, because `0x0000` is a malformed envelope rather than an
  unsupported protocol.
- A receiver MUST NOT silently discard a BRIDGE_REQUEST bearing an uncarried
  `protocol_id`; under the NPAMP-BRIDGE error model it MUST report the failure rather
  than report success for a message it did not carry. For a BRIDGE_NOTIFY (which
  permits no reply), a receiver that does not carry the `protocol_id` MUST drop the
  notification and MAY record it as an unsupported-protocol event.

A receiver MUST NOT infer a `protocol_id`'s meaning from the frame's `content_type`,
`method`, or any other envelope field. The `protocol_id` is the sole selector of the
foreign protocol; a frame is carried only if its `protocol_id` is one the receiver
carries.

## 10. Security considerations

This document assigns identifiers; it defines no cryptography and changes none. All
confidentiality, integrity, authentication, downgrade resistance, and replay
protection are provided by the core specification's wire format and key schedule and
apply unchanged to every Bridge frame regardless of its `protocol_id`. The
`protocol_id` octets travel inside the BridgeEnvelope TLV, within the AEAD-protected
payload of the frame; it is therefore authenticated and confidentiality-protected to
the same degree as the foreign message it labels, and an on-path attacker cannot
alter it without invalidating the frame's AEAD tag.

Assigning or carrying a `protocol_id` makes no security claim about the foreign
protocol it names. A foreign protocol's own authentication, authorization, and
integrity properties are neither supplied nor strengthened by carriage; where a
foreign protocol binds its security to transport elements that do not exist over
N-PAMP, that mismatch is a property of the protocol's mapping and is addressed in the
mapping document and in NPAMP-BRIDGE's safety-annotation model, not in this registry.

Experimental (§7.1) and private-use (§7.2) code points carry no cross-domain meaning.
An implementation that accepts such a value from a peer outside the domain that
controls its meaning risks misinterpreting the foreign message. A receiver therefore
MUST treat any experimental or private-use `protocol_id` it does not itself define as
uncarried (§9), rather than guessing an interpretation. The fail-safe defaults of
NPAMP-BRIDGE — including its treatment of a missing safety annotation as destructive
— continue to apply to every carried frame and are not relaxed by this document.

## 11. Conformance

An implementation conforms to NPAMP-REG if and only if, for `protocol_id` handling on
the Bridge channel, it:

1. Treats `protocol_id` as the two-octet field NPAMP-BRIDGE defines (§8.4; one octet
   before that widening), honoring the partition of §4 without altering its
   boundaries;
2. Interprets each assigned code point it carries under the carriage class named for
   that code point in §6, or carries it under Class OPAQUE where its mapping is not
   yet authored (§5, §6);
3. Rejects `protocol_id` `0x0000` as a malformed envelope (`EnvelopeMalformed`),
   distinct from an unsupported protocol (§4, §9);
4. Uses experimental code points only under out-of-band agreement and never as a
   production default for a protocol that has an assigned code point (§7.1);
5. Confines private-use code points to the administrative domain that defines them
   and never emits one toward a peer outside that domain (§7.2);
6. Returns `ProtocolUnsupported` (NPAMP-BRIDGE code 2) for a BRIDGE_REQUEST bearing
   any `protocol_id` it does not carry, never reporting success for an uncarried
   protocol, and drops an uncarried BRIDGE_NOTIFY without reply (§9); and
7. Selects the foreign protocol solely from `protocol_id`, never inferring it from
   another envelope field (§9).

A conformance test suite SHOULD assert each clause above with recorded exchanges that
include: a carried assigned `protocol_id`; an unassigned standards-range value; an
experimental value with and without prior agreement; a private-use value from an
outside domain; and the `0x0000` null identifier — verifying the required reply
(carried, `ProtocolUnsupported`, or `EnvelopeMalformed`) for each.

## 12. Normative references

- BCP 14: RFC 2119 and RFC 8174 — requirement key words.
- RFC 8126 — guidelines for writing an IANA Considerations section; source of the
  First Come First Served policy applied in §8.
- draft-bubblefish-npamp-01 — the N-PAMP core specification: Bridge channel `0x000D`,
  the BridgeEnvelope TLV type `0x0010`, the frame format, and the AEAD payload
  protection relied on in §10.
- NPAMP-BRIDGE — the bridge framework: the BridgeEnvelope TLV, the `protocol_id`
  field and its range partition, the carriage transparency rule, the correlation and
  error models (including `ProtocolUnsupported` and `EnvelopeMalformed`), and the
  safety-annotation model.
- The carriage-class companion specifications (NPAMP-CC-JSONRPC, NPAMP-CC-HTTP,
  NPAMP-CC-MSG, NPAMP-CC-STREAM, NPAMP-CC-DOC, NPAMP-CC-OPAQUE) — the carriage classes
  named in §5 and §6.
