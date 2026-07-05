# NPAMP-CC-HTTP — HTTP-Semantics Carriage Class (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words MUST, MUST NOT, REQUIRED,
> SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL in this document
> are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when,
> they appear in all capitals, as shown here.
>
> This document defines a **carriage class** for HTTP-semantics protocols on the N-PAMP
> Bridge channel `0x000D`. It builds on **NPAMP-BRIDGE** (`10_bridge_framework.md`) and
> consumes only code points the core specification (`draft-bubblefish-npamp-01`, the "core
> specification") and NPAMP-BRIDGE already reserve. It introduces no change to the core
> wire format, defines no new frame type, and defines no new extension TLV.

## 1. Scope

### 1.1 Purpose

Many agent, discovery, and commerce protocols are defined in terms of HTTP semantics:
A request bearing a **method**, a **target** (path and query), a set of **header
fields**, and an optional **body**; answered by a response bearing a **status code**,
its own header fields, and an optional body. REST-style and OpenAPI-described agent
protocols, `.well-known` discovery-document retrieval, and HTTP-bodied invocation
protocols all share this shape regardless of which HTTP version moves the bytes on the
foreign endpoint's own network.

NPAMP-CC-HTTP defines how one such request/response exchange — and its streaming and
notification variants — is carried inside N-PAMP Bridge frames so that two agents
exchange HTTP-semantics messages end-to-end while gaining N-PAMP's post-quantum
transport, multiplexing, correlation, and key schedule. A peer that implements this
class together with NPAMP-BRIDGE and a core-conformant N-PAMP wire can carry an
HTTP-semantics protocol with no protocol-specific framework changes.

### 1.2 Relationship to NPAMP-BRIDGE

This document is a carriage class in the sense of the companion index: it inherits the
entire NPAMP-BRIDGE contract and specializes the **foreign-message region** of a Bridge
frame for HTTP semantics. Specifically, it inherits without modification:

- The Bridge-channel frame types BRIDGE_REQUEST (`0x0100`), BRIDGE_RESPONSE (`0x0101`),
  BRIDGE_ERROR (`0x0102`), BRIDGE_NOTIFY (`0x0103`), BRIDGE_STREAM_DATA (`0x0104`), and
  BRIDGE_STREAM_END (`0x0105`) (NPAMP-BRIDGE §2);
- The BridgeEnvelope TLV (Type `0x0010`) and SafetyLabel TLV (Type `0x0013`)
  (NPAMP-BRIDGE §4, §7);
- The correlation model (NPAMP-BRIDGE §5), the structured-error model (NPAMP-BRIDGE §6),
  and the one-way-notification rule (NPAMP-BRIDGE §8).

This document does not restate those rules except where it narrows them for HTTP
semantics. Where this document and NPAMP-BRIDGE appear to conflict, NPAMP-BRIDGE governs
the envelope, correlation, error, and safety machinery, and this document governs only
the structure and interpretation of the HTTP message it carries.

### 1.3 Foreign protocol identity

An exchange carried under this class MUST set the BridgeEnvelope `protocol_id` to a
value whose registered carriage class is HTTP. The core HTTP/2 identifier `0x03`
(NPAMP-BRIDGE §4) is such a value. A specific HTTP-semantics agent protocol (for
example one carried via the experimental range `0x10`–`0x7F`) selects its own
registered `protocol_id`; the carriage **structure** defined here is identical across
all of them, and the `protocol_id` distinguishes which foreign protocol's method and
header vocabulary applies.

### 1.4 Non-scope

This document does NOT:

- Define or alter any N-PAMP frame type, channel, profile, TLV tag, or other core code
  point; it consumes only code points already reserved by the core specification and
  NPAMP-BRIDGE (§9.1);
- Define a new HTTP version or alter HTTP semantics; the carried message follows the
  semantics of HTTP as the foreign protocol defines them, and this class transports
  those semantics without reinterpreting them;
- Reconstruct any transport-bound HTTP signature (for example an HTTP Message Signature
  computed over `@method`, `@authority`, `@path`, or other derived components) on the
  foreign endpoint's behalf; reconstruction or re-binding of such signatures at an
  egress boundary is out of scope and is left to a credential-carriage or gateway
  specification (§8.4);
- Perform content negotiation, caching, connection management, or any other HTTP
  intermediary behavior; this class is a carriage substrate, not an HTTP cache or proxy;
- Carry HTTP traffic that is not an agent-protocol exchange (general-purpose web
  browsing is a non-goal of N-PAMP per the core specification's Non-Goals).

## 2. Carriage model

### 2.1 No new frame types, no new TLVs

An HTTP-semantics exchange is carried using the existing NPAMP-BRIDGE frame types and
the existing BridgeEnvelope and SafetyLabel TLVs. The HTTP message itself occupies the
**foreign-message region** that NPAMP-BRIDGE §3 places after the final TLV:

```
  BridgeEnvelope TLV   (Type 0x0010, REQUIRED)        -- per NPAMP-BRIDGE §4
  SafetyLabel TLV      (Type 0x0013, conditional)     -- per NPAMP-BRIDGE §7 and §6 below
  <foreign message>    = HTTP-Carriage Object (§4)    -- carried verbatim per NPAMP-BRIDGE §1
```

The HTTP-Carriage Object defined in §4 **is** the foreign message in the NPAMP-BRIDGE
transparency sense: it is produced once by the sender and carried octet-for-octet to the
receiver. An intermediary MUST NOT re-serialize, reorder, summarize, or otherwise alter
it (NPAMP-BRIDGE §1).

### 2.2 Frame-type to HTTP-message mapping

| N-PAMP Bridge frame | HTTP-semantics meaning | `message_kind` |
|---|---|---|
| BRIDGE_REQUEST (`0x0100`) | A complete HTTP request expecting a response. | `0x01` request |
| BRIDGE_RESPONSE (`0x0101`) | A complete, non-streamed HTTP response. | `0x02` response |
| BRIDGE_ERROR (`0x0102`) | A carriage-level failure, or a foreign HTTP error object (§6). | `0x04` error |
| BRIDGE_NOTIFY (`0x0103`) | A one-way HTTP request for which the foreign protocol defines no response. | `0x03` notification |
| BRIDGE_STREAM_DATA (`0x0104`) | One chunk of a streamed HTTP response body (§7). | `0x05` stream_data |
| BRIDGE_STREAM_END (`0x0105`) | Terminates a streamed HTTP response; carries trailers (§7). | `0x06` stream_end |

The BridgeEnvelope `message_kind` MUST agree with the frame type exactly as required by
NPAMP-BRIDGE §4; a receiver MUST reject a contradicting frame with BRIDGE_ERROR code
`EnvelopeMalformed` (NPAMP-BRIDGE §6).

### 2.3 Content type

The HTTP-Carriage Object (§4) is encoded in deterministic CBOR as defined by the core
specification (deterministic CBOR, RFC 8949). The BridgeEnvelope `content_type` field
MUST be set to `0x02` (`application/cbor`) for every frame carrying an HTTP-Carriage
Object. The HTTP body conveyed **inside** the object retains its own media type in the
object's header-field list (§4.4); the `application/cbor` content type describes the
carriage container, not the HTTP payload it transports.

A sender MUST produce, and a receiver MUST accept, deterministic CBOR: byte-identical
output for identical inputs, as the core specification requires for encodings that
participate in transcript and integrity computations.

### 2.4 Envelope method field

The BridgeEnvelope `method` field (NPAMP-BRIDGE §4) carries a routing key for the HTTP
exchange so that a dispatcher can correlate and route without parsing the body. For a
request frame the `method` field MUST be the HTTP method token (for example `GET`,
`POST`) followed by a single U+0020 SPACE and the request target path (the `:path`
pseudo-header value, origin-form, including any query). For a response, error,
stream_data, or stream_end frame the `method` field MUST be empty (`method_len = 0`),
because those frames are correlated by `correlation_id` to a prior request (§3) and do
not introduce a new method. The authoritative method, target, and status remain the
fields of the HTTP-Carriage Object (§4); the envelope `method` field is an advisory
routing key and a receiver MUST NOT treat a discrepancy between it and the object as
authoritative in either direction without rejecting the frame (§4.7).

## 3. Correlation and exchange roles

Correlation is governed entirely by NPAMP-BRIDGE §5 and is not redefined here. For an
HTTP-semantics exchange:

- The peer that emits a BRIDGE_REQUEST carrying an HTTP request is the **requester**;
  the peer that emits the matching BRIDGE_RESPONSE, BRIDGE_ERROR, BRIDGE_STREAM_DATA, or
  BRIDGE_STREAM_END is the **responder**. Roles are assigned per exchange, not per
  association; because the Bridge channel is bidirectional, either peer MAY originate an
  HTTP request, which permits server-to-client HTTP-semantics requests where a foreign
  protocol defines them.
- A BRIDGE_REQUEST MUST carry a non-empty `correlation_id` unique among the
  originator's outstanding requests on the channel in that direction (NPAMP-BRIDGE §5).
- Every response, error, and stream frame MUST echo the originating request's
  `correlation_id` verbatim, and a receiver MUST match by `correlation_id`, not by
  sequence number (NPAMP-BRIDGE §5).
- A single HTTP request maps to exactly one HTTP response, or to one streamed response
  (one or more BRIDGE_STREAM_DATA frames terminated by exactly one BRIDGE_STREAM_END),
  or to one BRIDGE_ERROR. A responder MUST NOT emit more than one terminal outcome for a
  given `correlation_id`.

## 4. HTTP-Carriage Object

### 4.1 Encoding

The HTTP-Carriage Object is a deterministic-CBOR map (RFC 8949) with unsigned-integer
keys. A sender MUST emit map keys in ascending numeric order and MUST omit every
OPTIONAL key whose value is absent rather than encoding a null. A receiver MUST reject,
with BRIDGE_ERROR code `EnvelopeMalformed`, an object that is not well-formed
deterministic CBOR, that repeats a key, that omits a REQUIRED key for its kind, or that
carries a key not defined here unless that key lies in the extension range (§4.6).

### 4.2 Object keys

| Key | Name | Type | Presence | Meaning |
|---|---|---|---|---|
| 1 | `kind` | Uint | REQUIRED | `1` request, `2` response, `3` stream_data, `4` stream_end. MUST agree with the frame type and `message_kind` (§4.7). |
| 2 | `method` | Text | Request only, REQUIRED | The HTTP method token (case-sensitive, e.g. `GET`, `POST`, `DELETE`). |
| 3 | `target` | Text | Request only, REQUIRED | The request target in origin-form: absolute path plus optional `?`-query, percent-encoded per RFC 3986. |
| 4 | `authority` | Text | Request only, OPTIONAL | The `:authority` (host and optional port) the foreign request names, when the foreign protocol carries one. |
| 5 | `scheme` | Text | Request only, OPTIONAL | The URI scheme the foreign request names (for example `https`). Absent means the foreign protocol does not bind a scheme to the message. |
| 6 | `status` | Uint | Response only, REQUIRED | The HTTP status code (100–599). |
| 7 | `reason` | Text | Response only, OPTIONAL | The reason phrase, if the foreign protocol supplies one; advisory only. |
| 8 | `headers` | Array | OPTIONAL | The carried header fields (§4.4). |
| 9 | `body` | Bstr | OPTIONAL | The HTTP message body octets, carried verbatim and unmodified. |
| 10 | `trailers` | Array | stream_end only, OPTIONAL | Trailer fields (§4.4 form) for a streamed response. |
| 11 | `passthrough` | Map | OPTIONAL | The HTTP-metadata passthrough block (§5). |

For `kind = 3` (stream_data), only `kind`, `body`, and optionally extension keys (§4.6)
are permitted; `method`, `target`, `status`, `headers`, and `trailers` MUST be absent,
because a stream_data chunk carries body octets only (§7). For `kind = 4` (stream_end),
`status`, `method`, `target`, and `body` MUST be absent; `trailers` and `passthrough`
MAY be present.

### 4.3 Body integrity

The `body` value (key 9) carries the HTTP message body exactly as the foreign protocol
produced it, including any content coding the foreign endpoint applied (the carriage
class does not decompress, decode, or re-chunk it). The carriage class MUST NOT alter
the body octets. Where the foreign protocol carries a `Content-Length` or
`Content-Digest` header field, that field is carried in `headers` unchanged (§4.4) and
describes the `body` as carried; this class does not recompute either.

### 4.4 Header and trailer fields

`headers` and `trailers` are CBOR arrays of field entries. Each entry is a two-element
array `[ name, value ]` where `name` is a text string and `value` is a byte string. The
field name MUST be carried in lowercase as in the HTTP/2 and HTTP/3 field
representation; a sender MUST lowercase ASCII field names before carriage and a receiver
MUST treat names case-insensitively for matching. A field that legitimately appears more
than once is carried as more than one entry, in the order the foreign protocol emitted
them; the carriage class MUST preserve that order and MUST NOT combine, split, or
reorder fields. Field values are carried as opaque octets so that a value the carriage
class does not understand is transported without loss.

The pseudo-header fields of HTTP/2 and HTTP/3 (`:method`, `:scheme`, `:authority`,
`:path`, `:status`) MUST NOT appear in `headers` or `trailers`; their information is
carried in the typed object keys (`method`, `scheme`, `authority`, `target`, `status`).
A receiver that finds a pseudo-header in `headers` or `trailers` MUST reject the frame
with BRIDGE_ERROR code `EnvelopeMalformed`.

### 4.5 Connection-specific fields

A sender SHOULD NOT carry connection-specific header fields that have no meaning across
the carriage boundary (for example `Connection`, `Keep-Alive`, `Transfer-Encoding`, and
`Upgrade`), because the foreign HTTP hop that those fields govern does not exist over
N-PAMP. A sender that nonetheless carries such a field MUST carry it unchanged, and a
receiver that re-emits the carried message onto a real HTTP hop is responsible for
applying that hop's own connection management; it MUST NOT rely on a carried
connection-specific field to govern the N-PAMP association.

### 4.6 Extension keys

Object keys 64 and above are reserved for extension fields defined by a foreign-protocol
mapping document. A sender MUST NOT emit an extension key the negotiated mapping has not
defined. A receiver that encounters an unknown extension key (64 or above) MUST ignore
that key and process the remainder of the object; a receiver that encounters an unknown
key below 64 MUST reject the frame with BRIDGE_ERROR code `EnvelopeMalformed`. This
mirrors the core specification's forward-compatibility split between ignorable and
forward-incompatible extension points.

### 4.7 Agreement checks

A receiver MUST reject the frame with BRIDGE_ERROR code `EnvelopeMalformed` when:

1. The object's `kind` does not correspond to the frame type and `message_kind` per the
   table in §2.2 and §4.2;
2. A REQUIRED key for the object's `kind` is absent, or a key prohibited for that
   `kind` is present;
3. For a request frame, the envelope `method` field is non-empty and its method token
   does not equal the object's `method`, or its path does not equal the object's
   `target` (the envelope routing key and the authoritative object disagree, §2.4);
4. A pseudo-header appears in `headers` or `trailers` (§4.4).

## 5. HTTP-metadata passthrough

### 5.1 Purpose

Some HTTP-semantics agent and discovery protocols depend on metadata that lives in
specific header fields, trailer fields, or redirect responses, and a real HTTP endpoint
reached through a carriage boundary needs that metadata preserved end-to-end. The
passthrough block (object key 11) is the place to carry the selected items that the
foreign protocol designates as significant, in a typed form, in addition to their
appearance in `headers`/`trailers`. The passthrough does not introduce metadata that is
absent from the HTTP message; it elevates designated items so a receiver can act on them
without re-parsing the full field list, and so a streamed exchange (§7) can convey
trailers and redirect intent at the points where the per-frame object would not
otherwise carry the full field list.

### 5.2 Passthrough map

The `passthrough` value is a deterministic-CBOR map with the following keys; every key
is OPTIONAL and a sender MUST omit a key whose value is absent.

| Key | Name | Type | Meaning |
|---|---|---|---|
| 1 | `selected_headers` | Array | A subset of `headers`, in field-entry form (§4.4), that the foreign mapping designates as significant for the receiver's decision (for example `content-type`, `etag`, `last-modified`, `cache-control`, `content-digest`, `signature`, `signature-input`). Each entry MUST be byte-identical to the corresponding entry in `headers`. |
| 2 | `selected_trailers` | Array | The subset of trailer fields the mapping designates as significant, in field-entry form; present only on a stream_end object or a non-streamed response that carried trailers. |
| 3 | `redirect` | Map | Redirect metadata (§5.3); present only on a response or stream_end object whose `status` is in the 3xx range. |
| 4 | `well_known` | Text | When the request targeted a `.well-known` discovery resource, the registered suffix (for example `ucp`, `agent.json`) the foreign mapping recognizes; advisory routing aid for a discovery consumer. |

A receiver MUST treat the `headers`/`trailers` arrays of §4.4 as authoritative; the
passthrough selections are a convenience view. A receiver MUST reject the frame with
BRIDGE_ERROR code `EnvelopeMalformed` if a `selected_headers` or `selected_trailers`
entry is not byte-identical to a corresponding entry in the object's `headers` or
`trailers`, so that the passthrough can never contradict the carried message.

### 5.3 Redirect metadata

The `redirect` map carries the information a client needs to follow or record an HTTP
redirect without re-parsing the response:

| Key | Name | Type | Meaning |
|---|---|---|---|
| 1 | `location` | Text | The `Location` field value of the redirect, carried unchanged (an absolute or relative URI reference per RFC 3986). |
| 2 | `preserve_method` | Bool | `true` when the redirect status requires the method and body to be preserved on the subsequent request (for example 307 and 308 semantics), `false` when the foreign status permits the client to change method (for example 303 semantics). The sender sets this from the carried `status`; it does not invent redirect behavior. |

A receiver MUST NOT auto-follow a carried redirect on behalf of the foreign endpoint;
following a redirect is the carried protocol client's decision, taken on the carried
`status` and `location`. The redirect block exists so that decision can be made without
re-parsing, not to delegate it to the carriage layer. A redirect's `location` MUST also
appear as a `location` entry in the response object's `headers` (§4.4); the passthrough
copy MUST be byte-identical to it.

## 6. Errors

### 6.1 Foreign HTTP errors versus carriage failures

An HTTP response whose status code denotes a client or server error (4xx or 5xx) is a
**successful carriage of a foreign result**, not a carriage failure. Such a response
MUST be carried as a BRIDGE_RESPONSE (frame type `0x0101`, `message_kind` response) with
the HTTP-Carriage Object's `status` set to the 4xx or 5xx code and the error body, if
any, carried in `body`. A sender MUST NOT translate a 4xx/5xx HTTP response into a
BRIDGE_ERROR; doing so would discard the foreign status and body that the requester is
entitled to receive intact (NPAMP-BRIDGE §6, preserve the foreign result verbatim).

### 6.2 Carriage-level failures

A failure **below** the foreign protocol — where the HTTP request did not reach, or no
HTTP response could be obtained from, the foreign endpoint — MUST be reported as
BRIDGE_ERROR (frame type `0x0102`) carrying an N-PAMP transport error, using the
NPAMP-BRIDGE §6 codes without extension:

| Code | Name | HTTP-carriage meaning |
|---|---|---|
| 1 | EnvelopeMalformed | The BridgeEnvelope or the HTTP-Carriage Object is missing, truncated, or invalid (§4.1, §4.7). |
| 2 | ProtocolUnsupported | The frame's `protocol_id` is not an HTTP-class protocol this peer carries. |
| 3 | MethodUnsupported | The HTTP method or target is recognized but not carried by this peer for the named protocol. |
| 4 | NotDelivered | The HTTP request did not reach the foreign endpoint, or no response was obtained. A sender MUST NOT report a synthesized status in place of a response it never received. |
| 5 | SafetyPolicy | Refused by a local safety policy (§8.2). |

A sender MUST NOT fabricate an HTTP status code (for example a synthetic `502` or `504`)
to stand in for a carriage-level failure; carriage-level failure is signaled by
BRIDGE_ERROR with the codes above, and a fabricated status would misrepresent a
transport failure as a foreign result.

## 7. Streaming responses

A streamed HTTP response is carried as the NPAMP-BRIDGE streaming sequence:

1. The responder MAY begin with a BRIDGE_RESPONSE (`0x0101`) carrying an HTTP-Carriage
   Object with `kind = response`, the `status`, the response `headers`, and any
   `passthrough`, and with `body` absent; this conveys the response head before the body
   streams. Alternatively, when the foreign protocol does not separate head from body,
   the head MAY be omitted and the stream begun directly with BRIDGE_STREAM_DATA.
2. Zero or more BRIDGE_STREAM_DATA (`0x0104`) frames each carry one HTTP-Carriage Object
   with `kind = stream_data` whose `body` is the next chunk of body octets, in order.
   The carriage class MUST preserve chunk order and MUST NOT coalesce or split chunks in
   a way that alters the concatenated body octets.
3. Exactly one BRIDGE_STREAM_END (`0x0105`) frame carries an HTTP-Carriage Object with
   `kind = stream_end`, MUST set the BridgeEnvelope `final` flag (NPAMP-BRIDGE §4), and
   MAY carry `trailers` and a `passthrough` block (for `selected_trailers` and, for a
   3xx streamed response, `redirect`). No `body` appears on the stream_end object.

Every frame of a streamed response MUST echo the request's `correlation_id` (§3). A
streamed response and a non-streamed BRIDGE_RESPONSE are mutually exclusive outcomes for
one request: a responder MUST NOT mix them for a single `correlation_id`.

A BRIDGE_NOTIFY (`0x0103`) carrying an HTTP-Carriage Object expresses a one-way HTTP
request for which the foreign protocol defines no response. It MUST set the
BridgeEnvelope `corr_len = 0` (NPAMP-BRIDGE §8), the object's `kind` MUST be `request`,
the receiver MUST NOT emit any response or error, and the sender MUST NOT await one.

## 8. Safety and security considerations

### 8.1 Safety label derivation

Because HTTP method semantics carry a safety classification, a sender MUST attach a
SafetyLabel TLV (Type `0x0013`, NPAMP-BRIDGE §7) to every HTTP-carriage request that can
cause side effects, and SHOULD set its `effect` field consistently with the carried
method's safety and idempotency:

| HTTP method | SafetyLabel `effect` (RECOMMENDED default) |
|---|---|
| GET, HEAD, OPTIONS, TRACE | `0x00` read_only |
| PUT | `0x01` idempotent_write |
| POST, PATCH | `0x02` non_idempotent_write |
| DELETE | `0x01` idempotent_write |

These are defaults a foreign-protocol mapping MAY tighten (never loosen) when it knows a
given operation is more dangerous than its method's generic class. A sender that knows an
operation is destructive MUST label it `0x03` destructive regardless of method. Per
NPAMP-BRIDGE §7, a receiver MUST NOT treat the absence of a SafetyLabel on a
state-mutating request as `read_only`; absence on such a request MUST be treated as
`destructive` (fail-safe). The label states intent and does not replace authorization at
the foreign endpoint.

### 8.2 Safety policy refusal

A peer MAY refuse to carry a request whose method, target, or safety label its local
policy forbids, by replying BRIDGE_ERROR code `SafetyPolicy` (§6.2). Refusal MUST occur
before the request is delivered to the foreign endpoint, and the sender MUST NOT report
the request as delivered.

### 8.3 Carriage does not re-create HTTP transport security

The confidentiality, integrity, authentication, downgrade resistance, and replay
protection of a carried exchange are provided by the N-PAMP association (core
specification, Security Considerations), not by the carried HTTP message. Carriage of a
header field named for a security mechanism (for example `authorization`,
`set-cookie`, `signature`) transports that field's octets unchanged; it neither
validates nor establishes the property the field names. A receiver that re-emits a
carried message onto a real HTTP hop MUST apply that hop's own transport security and
MUST NOT assume any property of the foreign field merely because it was carried.

### 8.4 Transport-bound HTTP signatures

An HTTP Message Signature, or any credential computed over HTTP message components or
connection state (for example a signature whose base includes `@method`, `@authority`,
`@path`, `@query`, or a content digest), is bound to an HTTP hop that does not exist over
the N-PAMP association. This class carries such a signature's header fields verbatim
(§4.4, §5.2) so that a receiver re-emitting the message onto a real HTTP hop can present
them, but this class does NOT recompute, verify, or re-bind them, and a receiver MUST NOT
infer that a carried signature was verified by the carriage. Re-binding a transport-bound
signature at an egress boundary, or accepting that the foreign endpoint re-authenticates
at a gateway, is out of scope here and is the responsibility of a credential-carriage or
gateway specification.

### 8.5 Body and field-list resource bounds

A carried HTTP body or header-field list can be large. A receiver MUST enforce its own
bounds on `body` length, on the number and aggregate size of `headers`/`trailers`
entries, and on streamed-chunk count, and MUST reject an exchange that exceeds them with
BRIDGE_ERROR (`NotDelivered` when the request was refused before delivery, or
`EnvelopeMalformed` when an individual frame is itself malformed). Carriage of an
attacker-influenced field name or value never causes the carriage layer to act on that
field; it is transported as opaque octets (§4.4).

## 9. Code points consumed

### 9.1 No new code points

This document consumes only code points already reserved by the core specification and
NPAMP-BRIDGE, and reserves none of its own:

| Resource | Origin of reservation | Use by this document |
|---|---|---|
| Bridge channel `0x000D` | Core specification §5 ("encapsulation of external agent protocols") | Carriage channel, inherited from NPAMP-BRIDGE. |
| Frame types `0x0100`–`0x0105` | NPAMP-BRIDGE §2 | Reused unchanged for HTTP request/response/error/notify/stream. |
| BridgeEnvelope TLV `0x0010` | Core specification §9.4 (companion-reserved); defined by NPAMP-BRIDGE §4 | Reused unchanged; `protocol_id` selects an HTTP-class protocol, `content_type = 0x02`. |
| SafetyLabel TLV `0x0013` | Core specification §9.4 (companion-reserved); defined by NPAMP-BRIDGE §7 | Reused unchanged; `effect` derived from HTTP method (§8.1). |
| `protocol_id = 0x03` (HTTP/2) | NPAMP-BRIDGE §4 | One valid HTTP-class identifier; others come from the protocol registry. |

The HTTP-Carriage Object (§4) and its passthrough block (§5) live entirely inside the
foreign-message region that NPAMP-BRIDGE §3 already defines; they are carried as the
foreign message and require no frame type, channel, profile, or TLV code point beyond
those above.

### 9.2 Registry dependency

This document assumes that `protocol_id` values whose carriage class is HTTP are assigned
by the Bridge Protocol Identifier registry. Until a specific HTTP-semantics agent
protocol has an assigned `protocol_id`, it is carried under an experimental
`protocol_id` in the range NPAMP-BRIDGE designates as experimental (`0x10`–`0x7F`), or
under the HTTP/2 identifier `0x03` where that is semantically appropriate.

## 10. Conformance

An implementation conforms to NPAMP-CC-HTTP if and only if, for HTTP-semantics exchanges
on the Bridge channel, it conforms to NPAMP-BRIDGE and additionally:

1. Carries each HTTP request, response, stream chunk, and stream terminus as the
   corresponding NPAMP-BRIDGE frame type with an agreeing `message_kind` and HTTP-Carriage
   Object `kind` (§2.2, §4.7), using no frame type or TLV beyond those NPAMP-BRIDGE
   defines (§2.1, §9.1);
2. Encodes the HTTP-Carriage Object as deterministic CBOR with `content_type = 0x02`,
   carries the body octets verbatim, and carries header and trailer fields in order
   without combining, splitting, reordering, or interpreting them, with pseudo-headers
   excluded from `headers`/`trailers` (§2.3, §4.3, §4.4);
3. Carries the HTTP-metadata passthrough (§5) such that every selected header, selected
   trailer, and redirect `location` is byte-identical to its authoritative occurrence in
   the carried message, and never auto-follows a redirect on the foreign endpoint's
   behalf (§5.2, §5.3);
4. Carries a 4xx/5xx HTTP response as a BRIDGE_RESPONSE preserving the foreign status and
   body, and signals only sub-foreign failures as BRIDGE_ERROR, never fabricating an HTTP
   status for a carriage failure (§6);
5. Derives the SafetyLabel `effect` from the carried HTTP method, never loosening it,
   labels a known-destructive operation `destructive`, and fail-safes on an absent label
   for a state-mutating request (§8.1);
6. Neither recomputes, verifies, nor re-binds any transport-bound HTTP signature, and
   does not assume any carried security field was validated by the carriage (§8.3, §8.4);
7. Enforces local resource bounds on body length, field-list size, and chunk count, and
   rejects exchanges that exceed them with the appropriate BRIDGE_ERROR code (§8.5).

A conformance test suite SHOULD assert each clause above with a recorded exchange for at
least one HTTP-semantics protocol carried under this class, including a non-streamed
request/response, a streamed response with trailers, a 3xx redirect, a 4xx foreign error
carried as a response, a sub-foreign failure carried as BRIDGE_ERROR, and a one-way
notification.
