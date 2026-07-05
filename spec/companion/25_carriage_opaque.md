# NPAMP-CC-OPAQUE — Opaque Carriage Class (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here.
>
> This document defines the **opaque carriage class** for N-PAMP: the carriage of
> an octet-exact payload of a declared content type under a registered or private
> bridge protocol identifier, with no protocol-specific structural mapping. It
> builds on NPAMP-BRIDGE (`10_bridge_framework.md`) and the N-PAMP core
> specification (draft-bubblefish-npamp-01, the "core specification"). It consumes
> only code points the core specification or NPAMP-BRIDGE already reserves, and it
> introduces no change to the core wire format and no change to the NPAMP-BRIDGE
> frame types, BridgeEnvelope, SafetyLabel, correlation model, or error model.

## 1. Scope

### 1.1 Purpose

NPAMP-CC-OPAQUE is the universal escape hatch of the N-PAMP carriage-class set. It
allows two N-PAMP endpoints to carry the messages of **any** foreign protocol —
including a protocol for which no NPAMP carriage-class mapping has been authored,
and a private or vendor-defined format that has no public specification at all —
over the Bridge channel `0x000D`, immediately and without bespoke per-protocol
work.

An opaque payload is treated as an uninterpreted sequence of octets accompanied by
a declaration of its content type. The opaque carriage class does not parse the
payload, does not validate it against any schema, does not transform it, and does
not assign meaning to any byte of it. Its entire contract is the **byte-exact
delivery** of that payload from sender to receiver, together with the NPAMP-BRIDGE
routing, correlation, error, and safety metadata that surrounds (but never
modifies) it.

### 1.2 Relationship to NPAMP-BRIDGE

NPAMP-CC-OPAQUE is a carriage class layered on NPAMP-BRIDGE. Every requirement of
NPAMP-BRIDGE applies unchanged to an opaque exchange:

- The foreign payload is carried octet-for-octet (NPAMP-BRIDGE §1);
- Each frame carries a BridgeEnvelope TLV (NPAMP-BRIDGE §4);
- Requests and replies are correlated by `correlation_id`, not by sequence number
  (NPAMP-BRIDGE §5);
- A foreign error is carried as the foreign protocol's own error object, and a
  below-foreign-protocol failure is reported with an NPAMP-BRIDGE transport error
  code (NPAMP-BRIDGE §6);
- A state-mutating request carries a SafetyLabel TLV, and its absence on such a
  request is treated as `destructive` (NPAMP-BRIDGE §7);
- One-way messages are carried as BRIDGE_NOTIFY with no reply (NPAMP-BRIDGE §8).

NPAMP-CC-OPAQUE adds exactly one thing to that contract: a normative means of
**declaring the content type of an otherwise uninterpreted payload** so that the
receiver, or the foreign endpoint behind it, can dispatch the payload to the
correct handler without the opaque carriage layer itself parsing it.

### 1.3 What opaque carriage guarantees, and what it does NOT

This section is normative and is the central honesty statement of this document.
Implementers and integrators MUST NOT rely on the opaque carriage class for any
property not listed under "guarantees" below.

**Opaque carriage guarantees, and guarantees only:**

1. **Byte fidelity.** The foreign payload delivered to the receiving application is
   octet-for-octet identical to the payload submitted by the sending application,
   of identical length and identical byte order, with no re-serialization,
   normalization, transcoding, canonicalization, compression substitution, or
   truncation introduced by the opaque carriage layer.
2. **Content-type fidelity.** The content-type declaration supplied by the sender
   is delivered to the receiver verbatim, so the receiver learns how the sender
   labeled the payload.
3. **The inherited NPAMP-BRIDGE metadata contract** of §1.2 (routing identifier,
   correlation, structured error, safety label, notification semantics), and the
   inherited N-PAMP core transport properties (authenticated encryption,
   post-quantum hybrid key establishment, multiplexing, replay protection, and the
   forward-secure key schedule) of the underlying association.

**Opaque carriage does NOT, by itself, provide any of the following.** Each is
explicitly out of scope, and an implementation MUST NOT represent opaque carriage
as delivering any of them:

1. **Transport-bound authentication of the foreign protocol.** A foreign protocol
   that authenticates a message by signing components of its own transport — for
   example HTTP Message Signatures (RFC 9421) over an HTTP request line and
   headers, a request-signing scheme bound to a specific URL, host, or method, or
   a channel-binding or mutual-TLS construction tied to the foreign transport —
   signs components that do not exist on the N-PAMP wire. Opaque carriage delivers
   the payload bytes; it does NOT reconstruct, re-bind, or re-create the foreign
   transport surface those signatures cover, and it does NOT itself verify them.
   Such a signature, if it is carried at all, is carried only as opaque payload
   bytes and remains verifiable only by an entity that can reconstruct the
   original foreign transport context (see §6 and §9).
2. **Signature reconstruction.** Opaque carriage does not regenerate, re-sign, or
   re-bind any foreign-transport signature on egress from an N-PAMP association to
   a native foreign transport. A payload-level signature that is independent of the
   transport (for example a detached signature computed over a canonicalized
   message body) survives opaque carriage precisely because it is part of the
   payload bytes; a transport-level signature does not, because its signed inputs
   are not part of the payload.
3. **Discovery.** Opaque carriage does not advertise, enumerate, or resolve which
   protocols, content types, methods, tools, or agents a peer supports. Discovery
   is provided separately (NPAMP-DISC, `40_discovery.md`); opaque carriage assumes
   the peers have already agreed, by configuration or out of band, that the
   declared protocol identifier and content type are mutually understood.
4. **Out-of-band exchanges.** Opaque carriage does not perform, proxy, or stand in
   for any exchange that leaves the N-PAMP association — for example a webhook or
   callback delivered to a third-party URL, a redirect dereference, a fetch of an
   external credential or key, a multicast or publish/subscribe fan-out, or any
   other interaction whose other endpoint is not the N-PAMP peer. Such exchanges
   are out of scope; if a deployment requires them, they MUST be arranged by a
   component outside the opaque carriage class.
5. **Schema validation or structural interpretation.** Opaque carriage does not
   parse the payload into typed fields, does not validate it against any schema,
   and does not guarantee that the payload is well-formed for its declared content
   type. A receiver that requires structural validity MUST perform that validation
   itself after delivery.

### 1.4 Non-scope

The following are explicitly NOT defined by this document:

- The internal structure or semantics of any foreign payload.
- Any per-protocol field mapping. Those are the subject of the thin per-protocol
  mapping documents and of the structured carriage classes (NPAMP-CC-JSONRPC,
  NPAMP-CC-HTTP, NPAMP-CC-MSG, NPAMP-CC-STREAM, NPAMP-CC-DOC). Opaque carriage is
  the fallback when no such mapping is in use.
- The allocation of bridge protocol identifiers. That is the subject of NPAMP-REG
  (`30_protocol_registry.md`). This document only constrains how an identifier is
  used once allocated (§3).
- Any change to the core wire format, to the NPAMP-BRIDGE frame types, or to the
  BridgeEnvelope, SafetyLabel, correlation, or error definitions of NPAMP-BRIDGE.

## 2. Carriage model

An opaque exchange uses the NPAMP-BRIDGE frame types unchanged. No new frame type
is defined by this document.

| Foreign interaction | NPAMP-BRIDGE frame type | Reply |
|---|---|---|
| Request expecting a reply | BRIDGE_REQUEST (`0x0100`) | BRIDGE_RESPONSE or BRIDGE_ERROR |
| Successful reply | BRIDGE_RESPONSE (`0x0101`) | None |
| Failed reply | BRIDGE_ERROR (`0x0102`) | None |
| One-way message | BRIDGE_NOTIFY (`0x0103`) | None |
| One chunk of a streamed reply | BRIDGE_STREAM_DATA (`0x0104`) | None |
| End of a stream | BRIDGE_STREAM_END (`0x0105`) | None |

A sender MUST choose the frame type according to the foreign interaction pattern
exactly as NPAMP-BRIDGE specifies. Because the opaque carriage layer does not
interpret the payload, the sender — the component that holds the foreign message —
is the only party that knows whether a given message expects a reply; it MUST set
the frame type and the BridgeEnvelope `message_kind` accordingly, and the two MUST
agree (NPAMP-BRIDGE §4).

Either peer MAY originate a BRIDGE_REQUEST on the Bridge channel, per the core
specification's full-duplex channel architecture and NPAMP-BRIDGE §5. Opaque
carriage imposes no additional restriction on which peer originates a request.

## 3. Bridge protocol identifier for opaque carriage

The `protocol_id` field of the BridgeEnvelope TLV (NPAMP-BRIDGE §4) identifies the
foreign protocol. For opaque carriage:

1. A sender MUST set `protocol_id` to a value that the receiving peer is known, by
   prior configuration or by discovery, to associate with the foreign protocol
   being carried. Opaque carriage does NOT define the meaning of any particular
   `protocol_id` value; it only requires that the value be one on which the peers
   have agreed.
2. A sender carrying a private, vendor-defined, or not-yet-registered protocol MUST
   use a `protocol_id` drawn from the experimental range that NPAMP-BRIDGE defines
   for that purpose (`0x10`–`0x7F`), unless and until a value is assigned for the
   protocol by NPAMP-REG. A sender MUST NOT squat on a `protocol_id` that NPAMP-REG
   has assigned to a different protocol.
3. A receiver that does not carry the indicated `protocol_id` MUST reject the frame
   with BRIDGE_ERROR code `ProtocolUnsupported` (NPAMP-BRIDGE §6), exactly as for
   any other carriage class. Opaque carriage does not change this behavior.

The opaque carriage class is selected not by a distinct `protocol_id` but by the
**absence of a structured carriage-class mapping** for the indicated protocol at
the sending and receiving endpoints: when no structured class applies, the payload
is carried opaquely under the agreed `protocol_id` and its declared content type
(§4).

## 4. Content-type declaration

### 4.1 Requirement

Every opaque payload MUST be accompanied by a declaration of its content type. The
content type is an IANA media type (for example `application/json`,
`application/cbor`, `application/grpc+proto`, `application/octet-stream`,
`text/plain; charset=utf-8`, or any registered or vendor-specific media type),
expressed as a US-ASCII string using the `type/subtype` syntax with optional
parameters as defined by the media-type grammar.

The content-type declaration is metadata carried **around** the payload; it is NOT
part of the foreign payload and MUST NOT be prepended to, appended to, or otherwise
mixed into the payload octets. The payload remains byte-exact per §1.3.

### 4.2 Encoding of the content-type declaration

The BridgeEnvelope `content_type` field (NPAMP-BRIDGE §4) is a `u8` enumeration
with a small fixed set of assigned values (`0x01` `application/json`, `0x02`
`application/cbor`, `0x03` `application/grpc+proto`). That enumeration cannot, on
its own, express the open set of media types that opaque carriage MUST be able to
declare. NPAMP-CC-OPAQUE therefore declares the content type as follows, without
redefining the BridgeEnvelope:

1. **When the payload's media type is one already enumerated by the BridgeEnvelope
   `content_type` field**, the sender MUST set that enumerated value in the
   BridgeEnvelope and MUST NOT attach a separate content-type extension TLV. This
   keeps opaque carriage of common encodings identical on the wire to structured
   carriage of the same encoding.

2. **When the payload's media type is NOT one enumerated by the BridgeEnvelope
   `content_type` field**, the sender MUST attach an **OpaqueContentType TLV**
   (§4.3) carrying the full media-type string, and MUST set the BridgeEnvelope
   `content_type` field to the discriminator value defined in §4.4 that directs the
   receiver to read the media type from the OpaqueContentType TLV.

3. A receiver MUST determine the content type as follows: if an OpaqueContentType
   TLV is present, the media type is the string it carries; otherwise the media
   type is the one named by the BridgeEnvelope `content_type` enumerated value. A
   receiver MUST reject (BRIDGE_ERROR, code `EnvelopeMalformed`) a frame that
   carries both an enumerated `content_type` value other than the §4.4
   discriminator **and** an OpaqueContentType TLV, because the two declarations
   would be ambiguous.

### 4.3 OpaqueContentType TLV

The OpaqueContentType TLV uses the core specification's extension-TLV encoding
(Type `u16`, Length `u16`, Value), placed in the Bridge frame payload alongside the
BridgeEnvelope and any SafetyLabel TLV, before the foreign payload. Its value is:

| Field | Size | Meaning |
|---|---|---|
| `media_type` | Var (= Length) | The full IANA media-type string, US-ASCII, `type/subtype` with optional parameters. MUST be non-empty. MUST NOT contain a NUL octet. |

The TLV Length field gives the byte count of `media_type`; no internal length
prefix or terminator is used. A receiver MUST reject (BRIDGE_ERROR, code
`EnvelopeMalformed`) an OpaqueContentType TLV whose value is empty, whose value
contains a NUL octet, or whose value is not a syntactically valid media type.

The Type code point for the OpaqueContentType TLV is a code point that the core
specification or NPAMP-BRIDGE must reserve for this companion. **The exact code
point is an open item for the core-specification maintainer (see §10).** Until that
code point is assigned, this TLV cannot appear on the wire, and an implementation
of NPAMP-CC-OPAQUE is limited to the media types enumerated by the BridgeEnvelope
`content_type` field (§4.2 case 1).

### 4.4 Content-type discriminator value

When an OpaqueContentType TLV is present, the BridgeEnvelope `content_type` field
MUST be set to a discriminator value, distinct from the values NPAMP-BRIDGE already
assigns, whose sole meaning is "the media type is carried in the OpaqueContentType
TLV." Because the BridgeEnvelope `content_type` enumeration is defined and owned by
NPAMP-BRIDGE, this discriminator value MUST be assigned by NPAMP-BRIDGE or by the
core specification, not by this document. **The exact discriminator value is an
open item for the core-specification maintainer (see §10).**

A sender MUST NOT invent an unassigned `content_type` value for this purpose, and a
receiver MUST treat an unrecognized `content_type` value as a malformed envelope
(BRIDGE_ERROR, code `EnvelopeMalformed`), exactly as it would for any other
carriage class.

## 5. Frame payload layout

An opaque Bridge frame's payload (the octets after the 36-octet N-PAMP header and
before the AEAD tag) is, in order:

```
  BridgeEnvelope TLV      (NPAMP-BRIDGE Type, REQUIRED)
  OpaqueContentType TLV   (§4.3 Type, REQUIRED when §4.2 case 2 applies; otherwise absent)
  SafetyLabel TLV         (NPAMP-BRIDGE Type, OPTIONAL; REQUIRED for any state-mutating request, per NPAMP-BRIDGE §7)
  <foreign payload>       (carried octet-for-octet per §1.3 and NPAMP-BRIDGE §1)
```

The foreign payload is the octets following the final TLV. The opaque carriage
layer MUST treat those octets as opaque: it MUST NOT inspect, parse, reorder,
re-encode, or modify them. The sequence of TLVs preceding the payload MUST be
encoded using the core specification's extension-TLV encoding, and a receiver MUST
parse them by walking Type/Length pairs, stopping at the start of the foreign
payload as given by the frame's Payload Length.

## 6. Egress to a native foreign transport

A deployment MAY place a gateway that terminates an N-PAMP association on one side
and speaks the foreign protocol over its native transport on the other. For an
opaquely carried payload at such a gateway:

1. The gateway MUST emit the foreign payload onto the native transport
   octet-for-octet, unchanged from the bytes delivered by opaque carriage.
2. The gateway MUST NOT represent that any transport-bound authentication of the
   foreign protocol has been preserved by opaque carriage. If the native foreign
   transport requires a transport-bound signature, channel binding, or mutual-TLS
   identity (§1.3, item 1), the gateway is responsible for establishing that
   credential as an independent foreign-transport endpoint; opaque carriage neither
   supplies nor reconstructs it.
3. A payload-level, transport-independent signature contained within the payload
   bytes survives this egress unchanged, because it is part of the payload; the
   gateway MUST NOT alter the payload in a way that would invalidate such a
   signature.

This section states obligations on a gateway that chooses to perform egress; it
does not require any deployment to provide a gateway, and it adds no behavior to the
opaque carriage class itself beyond the byte-fidelity guarantee of §1.3.

## 7. Streaming

An opaquely carried reply MAY be delivered as a stream using BRIDGE_STREAM_DATA and
BRIDGE_STREAM_END (NPAMP-BRIDGE §2, §5). When streaming:

1. Each BRIDGE_STREAM_DATA frame carries one chunk of the foreign payload, octet-
   exact, and echoes the originating request's `correlation_id`.
2. The concatenation, in send order, of the foreign payload octets of every
   BRIDGE_STREAM_DATA frame of a stream, followed by the foreign payload octets (if
   any) of the BRIDGE_STREAM_END frame, MUST equal the complete foreign payload the
   sender intended to deliver. The opaque carriage layer MUST NOT insert, drop, or
   reorder payload octets across chunk boundaries.
3. The content-type declaration (§4) describes the **complete** reassembled
   payload, not an individual chunk. A sender MUST declare the content type on the
   first frame of the stream; it MUST NOT vary the declared content type across the
   frames of a single stream, and a receiver MUST reject (BRIDGE_ERROR, code
   `EnvelopeMalformed`) a stream whose later frames declare a content type
   inconsistent with its first frame.
4. The opaque carriage layer assigns no meaning to a chunk boundary. Chunk
   boundaries are a transport convenience and MUST NOT be interpreted as
   delimiting any structure within the payload.

## 8. Errors

Opaque carriage uses the NPAMP-BRIDGE error model (NPAMP-BRIDGE §6) without
addition or change:

1. A failure reported **by** the foreign protocol MUST be carried as a BRIDGE_ERROR
   whose foreign payload is the foreign protocol's own error object, octet-exact,
   with its content type declared per §4. The opaque carriage layer MUST NOT reduce
   a foreign error to free text and MUST NOT collapse distinct foreign error
   representations.
2. A failure **below** the foreign protocol — where the payload could not be
   carried or delivered — MUST be reported as a BRIDGE_ERROR carrying one of the
   NPAMP-BRIDGE transport error codes (`EnvelopeMalformed`, `ProtocolUnsupported`,
   `MethodUnsupported`, `NotDelivered`, `SafetyPolicy`). A sender MUST NOT report
   success (BRIDGE_RESPONSE) for a payload it could not deliver.
3. This document defines no new error codes. A content-type declaration that is
   absent when required, malformed, ambiguous (§4.2), or syntactically invalid
   (§4.3) is an envelope fault and MUST be reported with the existing
   `EnvelopeMalformed` code.

## 9. Security considerations

This section follows the spirit of RFC 3552 and is scoped to what opaque carriage
adds to, and does not add to, the security properties of the underlying N-PAMP
association and of NPAMP-BRIDGE.

### 9.1 Inherited protections

An opaquely carried payload travels inside N-PAMP frames and therefore inherits the
association's authenticated encryption, post-quantum hybrid key establishment,
per-(channel, direction) replay protection, and forward-secure key schedule, as
defined by the core specification. Opaque carriage neither strengthens nor weakens
these properties; it does not bypass the negotiated security profile.

### 9.2 The payload is opaque to the carrier and is not validated

Because the opaque carriage layer does not parse, validate, or interpret the
payload, it provides **no** content-level security property: it does not detect
malformed input, does not enforce any schema, does not sanitize, and does not bound
the payload's internal structure beyond the core specification's frame-size and
flow-control limits. A receiving application MUST treat an opaquely delivered
payload as untrusted input of its declared content type and MUST perform its own
parsing, validation, and authorization before acting on it. The declared content
type (§4) is an advisory label asserted by the sender; a receiver MUST NOT assume
the payload conforms to that media type without validating it.

### 9.3 Transport-bound authentication is NOT provided

As stated normatively in §1.3, opaque carriage does not provide, reconstruct, or
verify any authentication that the foreign protocol binds to its own transport.
Integrators MUST NOT treat the integrity and authenticity that N-PAMP provides for
the **association** as a substitute for a foreign protocol's **message-level or
transport-level** authentication. In particular:

- A foreign transport-bound signature (for example one computed over an HTTP
  request line, authority, path, query, and selected headers) covers inputs that do
  not exist on the N-PAMP wire; carrying the payload opaquely neither verifies that
  signature nor preserves the context needed to verify it. Any party that must
  verify such a signature MUST be able to reconstruct the original foreign
  transport context independently; opaque carriage does not do so.
- A foreign payload-level signature that is computed over the payload bytes alone
  and is independent of the transport (for example a detached signature over a
  canonicalized message body) is preserved by opaque carriage's byte fidelity and
  remains verifiable by any holder of the payload and the verifying key. This is a
  property of the payload, not a property contributed by opaque carriage.

A deployment that relies on a foreign protocol's transport-bound authentication
MUST arrange for that authentication to be re-established by a component outside the
opaque carriage class (for example a gateway acting as an independent foreign-
transport endpoint, §6), and MUST NOT advertise opaque carriage as supplying it.

### 9.4 No discovery and no out-of-band exchange

Opaque carriage performs no discovery (§1.3 item 3) and no out-of-band exchange
(§1.3 item 4). An implementation MUST NOT infer a peer's capabilities from the mere
success of an opaque exchange, and MUST NOT assume that any callback, webhook,
redirect, key fetch, or fan-out implied by a foreign payload will occur as a result
of opaque carriage; such interactions, if required, are out of scope and leave the
association.

### 9.5 Content-type confusion

Because the content type is a sender-asserted label, a receiver that dispatches a
payload to a handler chosen solely by the declared content type is exposed to
content-type confusion if it does not also validate the payload. A receiver SHOULD
constrain the set of content types it will dispatch to the set its application
actually supports, and MUST validate the payload against the chosen handler's
expectations before acting on it.

## 10. Open items requiring a maintainer decision

The following code-point assignments are required for full on-the-wire operation of
this document and are NOT yet reserved by the core specification or by NPAMP-BRIDGE.
They are recorded here for the core-specification maintainer:

1. **OpaqueContentType TLV type code point (§4.3).** A reserved extension-TLV Type
   is required to carry the full media-type string. The core specification reserves
   TLV Types `0x0010`, `0x0013`, and `0x0014` for companion specifications;
   NPAMP-BRIDGE has consumed `0x0010` (BridgeEnvelope) and `0x0013` (SafetyLabel),
   and `0x0014` is constrained to handshake-only use of fixed 32-octet length,
   which does not fit a variable-length media-type string. A new companion-reserved,
   variable-length TLV Type (with the high bit `0x8000` clear, so that endpoints
   that do not implement opaque carriage ignore it rather than rejecting the frame)
   is therefore requested.
2. **BridgeEnvelope `content_type` discriminator value (§4.4).** A single
   additional `u8` value in the BridgeEnvelope `content_type` enumeration, owned by
   NPAMP-BRIDGE, is required to mean "media type is carried in the OpaqueContentType
   TLV." It MUST be distinct from the currently assigned values `0x01`–`0x03`.

Until both assignments are made, a conforming implementation operates only over the
media types already enumerated by the BridgeEnvelope `content_type` field (§4.2
case 1); the open set of declared media types (§4.2 case 2) is unavailable on the
wire. No part of this document requests any change to the core wire format or to the
existing NPAMP-BRIDGE definitions; both items are additive reservations within
ranges the core specification already sets aside for companions.

## 11. Conformance

An implementation conforms to NPAMP-CC-OPAQUE if and only if, when carrying a
payload opaquely on the Bridge channel `0x000D`, it:

1. Conforms to NPAMP-BRIDGE in full for every frame it emits or accepts (§1.2);
2. Carries the foreign payload octet-for-octet, performing no parsing, validation,
   transformation, re-encoding, or truncation of the payload (§1.3 item 1, §5);
3. Declares the content type of every opaque payload, using the BridgeEnvelope
   `content_type` enumerated value when the media type is enumerated, and otherwise
   using the OpaqueContentType TLV with the §4.4 discriminator value, and rejects an
   absent, ambiguous, or malformed content-type declaration with `EnvelopeMalformed`
   (§4);
4. Selects the NPAMP-BRIDGE frame type and `message_kind` from the foreign
   interaction pattern, with the two in agreement, and correlates replies to
   requests by `correlation_id` rather than by sequence number (§2);
5. Uses a `protocol_id` on which the peers have agreed, draws a private or
   unregistered protocol's identifier from the NPAMP-BRIDGE experimental range, and
   rejects an uncarried `protocol_id` with `ProtocolUnsupported` (§3);
6. For a streamed opaque reply, reassembles the chunks into a byte-exact payload,
   declares one consistent content type across the stream, and assigns no meaning to
   chunk boundaries (§7);
7. Uses the NPAMP-BRIDGE error model without addition, preserving a foreign error
   object verbatim and never reporting success for an undelivered payload (§8);
8. Makes no representation that opaque carriage provides transport-bound
   authentication, signature reconstruction, discovery, or out-of-band exchange, and
   re-establishes any such property, where required, in a component outside the
   opaque carriage class (§1.3, §6, §9).

A conformance test suite SHOULD assert each clause above with a recorded exchange
that carries, at minimum: a payload of a BridgeEnvelope-enumerated content type; a
payload of a non-enumerated content type declared via the OpaqueContentType TLV (in
a deployment in which the §10 code points have been assigned); a one-way
notification; a streamed reply reassembled to a byte-exact payload; and a
below-foreign-protocol failure reported with an NPAMP-BRIDGE transport error code.
A test suite SHOULD additionally assert byte fidelity by comparing the delivered
payload octet-for-octet against the submitted payload, including for payloads
containing arbitrary binary content.
