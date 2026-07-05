# NPAMP-CC-JSONRPC — JSON-RPC 2.0 Carriage Class (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document defines a **carriage class** for any agent protocol whose
> messages are JSON-RPC 2.0 objects. It builds on NPAMP-BRIDGE
> (`10_bridge_framework.md`) and the N-PAMP core specification
> (draft-bubblefish-npamp-01, the "core specification"). It consumes only code
> points those documents already reserve and introduces no change to the core
> wire format and no change to NPAMP-BRIDGE.

## 1. Scope

### 1.1 In scope

This document specifies how a JSON-RPC 2.0 message is carried over an N-PAMP
association as a NPAMP-BRIDGE exchange on the Bridge channel `0x000D`. It defines,
generically and independently of any particular JSON-RPC application protocol:

- The mapping of a JSON-RPC **Request** (`jsonrpc`, `method`, `params`, `id`) onto
  a BRIDGE_REQUEST frame and its BridgeEnvelope TLV (§4);
- The mapping of a JSON-RPC **Response** carrying a `result` onto a BRIDGE_RESPONSE
  frame (§5);
- The mapping of a JSON-RPC **Response** carrying an `error` object
  (`code`, `message`, `data`) onto a BRIDGE_ERROR frame, preserving the foreign
  error verbatim (§6);
- The mapping of a JSON-RPC **Notification** (a Request with no `id` member) onto a
  BRIDGE_NOTIFY frame (§7); and
- Correlation of a Response to its Request using the JSON-RPC `id` (§8).

The mapping is **protocol-agnostic within the JSON-RPC 2.0 class**: it applies to
any concrete agent protocol whose application messages are well-formed JSON-RPC 2.0
objects, regardless of that protocol's method namespace or parameter schemas. A
concrete protocol becomes carriable under this class by registering a
`protocol_id` whose carriage class is JSONRPC; this document does not enumerate or
privilege any such protocol.

### 1.2 Not in scope

The following are explicitly NOT defined by this document:

- **Batch requests and batch responses.** A JSON-RPC batch (a JSON Array of Request
  objects, or the corresponding Array of Response objects) is out of scope. The
  carriage of a single JSON-RPC object per Bridge frame is the only mapping defined
  here. Handling of batch arrays is left to a future revision or companion document;
  see §10 (OPEN QUESTION).
- The method namespace, parameter schema, or result schema of any concrete JSON-RPC
  application protocol. These are fixed by that protocol's own mapping document and
  its source specification.
- Any change to the N-PAMP frame format, to the NPAMP-BRIDGE frame types, or to the
  BridgeEnvelope or SafetyLabel TLVs.
- Transport-layer security, key establishment, and channel multiplexing, which are
  provided by the core specification.
- Streaming of a single logical reply across multiple frames
  (BRIDGE_STREAM_DATA / BRIDGE_STREAM_END). JSON-RPC 2.0 has no streamed-response
  construct; a concrete protocol that layers streaming over JSON-RPC specifies that
  behavior in its own mapping. This document carries the unit JSON-RPC
  Request/Response/Notification only.

## 2. Relationship to NPAMP-BRIDGE

This document does not redefine NPAMP-BRIDGE; it constrains it for the JSON-RPC
case. Every requirement of NPAMP-BRIDGE applies unchanged. In particular:

- The **transparency rule** (NPAMP-BRIDGE §1) governs: the JSON-RPC object is the
  foreign message and MUST be carried octet-for-octet as the foreign-message
  region of the Bridge frame payload (NPAMP-BRIDGE §3). An implementation MUST NOT
  re-serialize, re-key, reorder, canonicalize, or otherwise rewrite the JSON-RPC
  object. The BridgeEnvelope fields defined below are **derived from** the JSON-RPC
  object for routing and correlation; they do not replace it, and on any
  disagreement the carried JSON-RPC object is authoritative for the foreign
  endpoint.
- The Bridge frame payload layout (NPAMP-BRIDGE §3) is used as-is: BridgeEnvelope
  TLV (Type `0x0010`, REQUIRED), then SafetyLabel TLV (Type `0x0013`, OPTIONAL),
  then the JSON-RPC object as the foreign message.
- The correlation model (NPAMP-BRIDGE §5), the structured-error model
  (NPAMP-BRIDGE §6), the SafetyLabel model (NPAMP-BRIDGE §7), and the notification
  model (NPAMP-BRIDGE §8) are inherited and are specialized for JSON-RPC below.

## 3. Encoding and the foreign-message region

A JSON-RPC 2.0 object carried under this class is a single JSON value (an Object)
serialized as defined by JSON-RPC 2.0. The carried octets are placed in the
foreign-message region exactly as produced by the originating JSON-RPC peer.

- The BridgeEnvelope `content_type` field (NPAMP-BRIDGE §4) MUST be `0x01`
  (application/json) for every frame defined by this document.
- A receiver MUST treat the foreign-message octets as opaque with respect to
  transport: it MUST deliver them unchanged to the foreign JSON-RPC endpoint. A
  receiver MAY parse the JSON-RPC object to populate or validate envelope-derived
  fields (§4, §8), but MUST NOT substitute a re-serialization of its parse for the
  carried octets.
- The carried object MUST contain a `jsonrpc` member equal to the string `"2.0"`.
  A sender MUST NOT emit, under a JSONRPC-class `protocol_id`, a foreign message
  whose `jsonrpc` member is absent or unequal to `"2.0"`. A receiver that parses
  the object and finds `jsonrpc` absent or unequal to `"2.0"` MUST reject the frame
  with BRIDGE_ERROR code `EnvelopeMalformed` (NPAMP-BRIDGE §6); the mismatch
  indicates the foreign message does not belong to this carriage class.

## 4. Request carriage (BRIDGE_REQUEST)

A JSON-RPC Request object that includes an `id` member is carried in a
BRIDGE_REQUEST frame (NPAMP-BRIDGE frame type `0x0100`). The BridgeEnvelope TLV
(NPAMP-BRIDGE §4) MUST be populated as follows:

| BridgeEnvelope field | Value for a JSON-RPC Request |
|---|---|
| `protocol_id` | The registered identifier of the concrete JSON-RPC protocol being carried. Its carriage class MUST be JSONRPC. |
| `message_kind` | `0x01` (request). MUST agree with the BRIDGE_REQUEST frame type. |
| `content_type` | `0x01` (application/json). |
| `flags` | `0x00`. The `final` bit has no meaning for a non-streamed Request; the sender MUST set it `0`. |
| `correlation_id` | The correlation token derived from the JSON-RPC `id` member per §8. `corr_len` MUST be non-zero. |
| `method` | The exact UTF-8 octets of the JSON-RPC `method` member's string value. `method_len` MUST equal that string's octet length. |

Constraints:

- The carried JSON-RPC object MUST be a Request object that includes an `id`
  member whose value is a String, a Number, or Null, as required by JSON-RPC 2.0.
  A Request object with no `id` member is a Notification and MUST instead be
  carried per §7.
- The BridgeEnvelope `method` field MUST equal the carried object's `method`
  member byte-for-byte. The `method` field is advisory routing metadata; the
  carried object remains authoritative. A receiver that parses the object and
  finds the two unequal MUST reject the frame with BRIDGE_ERROR code
  `EnvelopeMalformed`.
- A JSON-RPC `params` member, when present, is carried only within the JSON-RPC
  object. This document defines no envelope field for `params`; `params` MUST NOT
  be lifted out of, summarized from, or duplicated outside the carried object.
- A BRIDGE_REQUEST under this class expects exactly one reply: a BRIDGE_RESPONSE
  (§5) on success or a BRIDGE_ERROR (§6) on failure.

Either peer MAY originate a BRIDGE_REQUEST, consistent with the per-exchange
requester/responder roles of NPAMP-BRIDGE §5; this carriage class places no
additional directional restriction on JSON-RPC Request origination.

## 5. Success-response carriage (BRIDGE_RESPONSE)

A JSON-RPC Response object that includes a `result` member (and therefore no
`error` member) is carried in a BRIDGE_RESPONSE frame (NPAMP-BRIDGE frame type
`0x0101`). The BridgeEnvelope TLV MUST be populated as follows:

| BridgeEnvelope field | Value for a JSON-RPC success Response |
|---|---|
| `protocol_id` | The same `protocol_id` as the corresponding BRIDGE_REQUEST. |
| `message_kind` | `0x02` (response). MUST agree with the BRIDGE_RESPONSE frame type. |
| `content_type` | `0x01` (application/json). |
| `flags` | `0x00`. |
| `correlation_id` | The originating Request's `correlation_id`, echoed verbatim per NPAMP-BRIDGE §5 and §8. |
| `method` | `method_len` MUST be `0`; a Response carries no method. |

Constraints:

- The carried object MUST be a JSON-RPC Response with exactly one of `result` or
  `error` present, and for a BRIDGE_RESPONSE it MUST be the `result` member.
  A Response carrying an `error` member MUST instead be carried as BRIDGE_ERROR
  per §6.
- The carried Response's `id` member MUST equal the originating Request's `id`
  member, as required by JSON-RPC 2.0. The `correlation_id` echoed in the envelope
  MUST be the one derived from that same `id` per §8. A receiver MUST match the
  Response to its Request by `correlation_id` (NPAMP-BRIDGE §5), and a receiver
  that parses the object MUST additionally verify that the carried `id` is the one
  it associated with that `correlation_id`; on mismatch it MUST reject the frame
  with BRIDGE_ERROR code `EnvelopeMalformed`.

## 6. Error-response carriage (BRIDGE_ERROR)

A JSON-RPC Response object that includes an `error` member is a **foreign-protocol
failure** in the sense of NPAMP-BRIDGE §6, and is carried in a BRIDGE_ERROR frame
(NPAMP-BRIDGE frame type `0x0102`) whose foreign message is the JSON-RPC Response
object itself, carried verbatim.

| BridgeEnvelope field | Value for a JSON-RPC error Response |
|---|---|
| `protocol_id` | The same `protocol_id` as the corresponding BRIDGE_REQUEST. |
| `message_kind` | `0x04` (error). MUST agree with the BRIDGE_ERROR frame type. |
| `content_type` | `0x01` (application/json). |
| `flags` | `0x00`. |
| `correlation_id` | The originating Request's `correlation_id`, echoed verbatim. |
| `method` | `method_len` MUST be `0`. |

Verbatim-error requirements (specializing NPAMP-BRIDGE §6):

- The carried foreign message MUST be the complete JSON-RPC Response object,
  including its `error` member with the `code` (an integer), `message` (a String),
  and OPTIONAL `data` members exactly as produced by the foreign endpoint. An
  implementation MUST NOT reduce the JSON-RPC error object to free text, MUST NOT
  drop or rewrite the `data` member, and MUST NOT alter, remap, or collapse the
  numeric `code`.
- The JSON-RPC error `code` is a **foreign** code and MUST be preserved unchanged.
  This includes the JSON-RPC pre-defined codes (for example `-32700` parse error,
  `-32600` invalid request, `-32601` method not found, `-32602` invalid params,
  `-32603` internal error) and the JSON-RPC implementation-defined server-error
  range (`-32000` to `-32099`). An implementation MUST NOT translate any of these
  to a NPAMP-BRIDGE transport-error code, and MUST NOT translate a NPAMP-BRIDGE
  transport-error code into a JSON-RPC error code.

Distinction between foreign error and transport error:

- A failure **within** the JSON-RPC protocol — the foreign endpoint received the
  Request and produced a JSON-RPC `error` Response — MUST be carried as BRIDGE_ERROR
  with the JSON-RPC Response as the foreign message, as specified above.
- A failure **below** the JSON-RPC protocol — the Request did not reach the foreign
  JSON-RPC endpoint, or no JSON-RPC Response was produced — MUST be reported as
  BRIDGE_ERROR carrying an N-PAMP transport error (NPAMP-BRIDGE §6 transport-error
  table) in place of a foreign message. In particular, a sender MUST NOT
  manufacture a JSON-RPC `error` object to represent a transport-level delivery
  failure, and MUST NOT report success (BRIDGE_RESPONSE) for a Request it could not
  deliver.

JSON-RPC requires that when a Request `id` cannot be determined (for example a
parse error or invalid Request), the Response `id` be Null. Such an error Response
is still a foreign JSON-RPC Response and is carried per this section; its
`correlation_id` derivation follows §8.4.

## 7. Notification carriage (BRIDGE_NOTIFY)

A JSON-RPC Notification — a Request object with **no** `id` member — is carried in a
BRIDGE_NOTIFY frame (NPAMP-BRIDGE frame type `0x0103`). The BridgeEnvelope TLV MUST
be populated as follows:

| BridgeEnvelope field | Value for a JSON-RPC Notification |
|---|---|
| `protocol_id` | The registered JSONRPC-class `protocol_id` being carried. |
| `message_kind` | `0x03` (notification). MUST agree with the BRIDGE_NOTIFY frame type. |
| `content_type` | `0x01` (application/json). |
| `flags` | `0x00`. |
| `correlation_id` | None. `corr_len` MUST be `0` (NPAMP-BRIDGE §5, §8). |
| `method` | The exact UTF-8 octets of the Notification's `method` member. |

Constraints:

- The carried object MUST be a JSON-RPC Request object that contains **no** `id`
  member. A sender MUST NOT add an `id` member to convert a Notification into a
  Request, and MUST NOT carry, under BRIDGE_NOTIFY, an object that contains an
  `id` member.
- Consistent with NPAMP-BRIDGE §8 and JSON-RPC 2.0, the receiver MUST NOT emit any
  reply to a BRIDGE_NOTIFY (no BRIDGE_RESPONSE and no BRIDGE_ERROR), and the sender
  MUST NOT await one. A foreign-endpoint processing failure of a Notification
  therefore produces no JSON-RPC Response and no Bridge reply; it MAY be recorded
  locally but MUST NOT be carried back to the originator under this class.
- The `method` field of the envelope MUST equal the carried object's `method`
  member byte-for-byte, as in §4.

## 8. Correlation: mapping the JSON-RPC `id`

JSON-RPC correlates a Response to its Request by equality of the `id` member, whose
value is a String, a Number, or Null. NPAMP-BRIDGE correlates by an opaque
`correlation_id` octet string (NPAMP-BRIDGE §5). This section specifies the
deterministic, reversible mapping between the two for a JSON-RPC Request that
carries an `id`.

### 8.1 Requirements

- For a BRIDGE_REQUEST (§4), the originating peer MUST derive a non-empty
  `correlation_id` that is unique among that peer's outstanding JSON-RPC Requests
  on the channel in that direction, consistent with NPAMP-BRIDGE §5.
- For a BRIDGE_RESPONSE (§5) or BRIDGE_ERROR (§6), the responding peer MUST echo
  the originating Request's `correlation_id` verbatim, and the carried JSON-RPC
  Response's `id` MUST equal the originating Request's `id` as required by
  JSON-RPC 2.0. The two correlation facts — the echoed `correlation_id` and the
  echoed JSON-RPC `id` — MUST be consistent: both identify the same exchange.
- A receiver MUST match a reply to its Request by `correlation_id`, not by the
  N-PAMP frame sequence number (NPAMP-BRIDGE §5).

### 8.2 Canonical derivation of `correlation_id` from `id`

To make the JSON-RPC `id` recoverable from the `correlation_id` (so that a peer that
did not retain per-`id` state can still satisfy JSON-RPC's `id`-equality rule), an
implementation that originates JSON-RPC Requests SHOULD derive the
`correlation_id` as the **UTF-8 octets of the canonical JSON serialization of the
`id` value as it appears in the Request**, namely:

- A JSON String `id` maps to the UTF-8 octets of that JSON string token, quotes
  included (so that the string `"7"` and the number `7` map to distinct
  `correlation_id` values, preserving JSON-RPC's type distinction);
- A JSON Number `id` maps to the UTF-8 octets of that number token exactly as it
  appears in the carried Request;
- A JSON Null `id` is addressed in §8.4.

The originating peer MUST ensure the resulting `correlation_id` is unique among its
outstanding Requests (§8.1); if the JSON-RPC application reuses an `id` value while
a prior Request with that `id` is still outstanding, the originator MUST NOT emit
the second Request under this class until the first has been answered, because two
concurrent outstanding exchanges sharing a `correlation_id` cannot be
unambiguously correlated.

This derivation is RECOMMENDED, not REQUIRED: because the JSON-RPC `id` is also
carried verbatim inside the foreign Response object, a responder that retains
per-exchange state MAY instead treat `correlation_id` as an opaque token of its own
choosing, provided it still echoes that token verbatim (§8.1) and the carried
Response `id` still equals the Request `id`. An implementation MUST NOT rely on a
particular `correlation_id` encoding produced by a peer; it MUST treat a received
`correlation_id` as opaque for matching purposes.

### 8.3 Authoritative `id` for the foreign endpoint

Regardless of how `correlation_id` is derived, the JSON-RPC `id` delivered to and
returned by the foreign endpoint is the `id` member carried inside the JSON-RPC
object. The envelope `correlation_id` is N-PAMP routing metadata; it MUST NOT be
substituted for the JSON-RPC `id` in the object delivered to the foreign endpoint,
and the foreign endpoint's `id`-equality obligation (JSON-RPC 2.0) is satisfied by
the carried object, not by the envelope.

### 8.4 Null and undetermined `id`

JSON-RPC permits a Request `id` of Null, and requires a Null Response `id` when the
Request `id` could not be determined (for example on a parse error or invalid
Request). These cases interact with NPAMP-BRIDGE's requirement that a BRIDGE_REQUEST
carry a **non-empty** `correlation_id` (NPAMP-BRIDGE §5):

- An originator that issues a JSON-RPC Request with a Null `id` (a Request, not a
  Notification) MUST still supply a non-empty `correlation_id`. Deriving it from
  the literal token `null` does not guarantee uniqueness across concurrent
  Null-`id` Requests; therefore an originator that uses Null `id` for multiple
  outstanding Requests MUST allocate a distinct, non-empty `correlation_id` per
  exchange by a means of its choosing (the `correlation_id` is opaque to the
  responder, §8.2), while still carrying the Null `id` verbatim inside the object.
- A BRIDGE_ERROR carrying a JSON-RPC error Response whose `id` is Null because the
  originating Request could not be parsed (§6) MUST echo the `correlation_id` of
  the BRIDGE_REQUEST it answers. The responder learns that `correlation_id` from
  the inbound BRIDGE_REQUEST envelope, not from the unparseable JSON-RPC object;
  this is why the envelope `correlation_id` is carried independently of the
  JSON-RPC `id` and remains usable even when the `id` is undetermined.

## 9. SafetyLabel

The SafetyLabel TLV (Type `0x0013`) and its fail-safe semantics are governed
entirely by NPAMP-BRIDGE §7 and are inherited unchanged. JSON-RPC 2.0 does not
itself express whether a method is state-mutating; that property is a function of
the concrete JSON-RPC application protocol and its method namespace. Accordingly:

- When a carried JSON-RPC Request invokes a method that can cause side effects, the
  sender MUST attach a SafetyLabel TLV describing the effect class
  (NPAMP-BRIDGE §7), and an intermediary MUST carry it unchanged.
- A receiver MUST NOT infer `read_only` from the absence of a SafetyLabel on a
  state-mutating JSON-RPC method; absence on such an operation MUST be treated as
  `destructive` (NPAMP-BRIDGE §7, fail-safe).
- The classification of a given JSON-RPC method into an effect class is fixed by
  that protocol's mapping document, not by this carriage class. This document
  neither classifies methods nor overrides any classification a concrete mapping
  establishes.

## 10. Conformance

An implementation conforms to NPAMP-CC-JSONRPC if and only if it conforms to
NPAMP-BRIDGE and, for JSON-RPC 2.0 traffic carried under a `protocol_id` whose
carriage class is JSONRPC, it:

1. Carries each JSON-RPC object octet-for-octet as the foreign message, with
   `content_type = 0x01`, and never re-serializes, reorders, canonicalizes, or
   rewrites it (§2, §3);
2. Carries a JSON-RPC Request bearing an `id` as BRIDGE_REQUEST with
   `message_kind = 0x01`, the envelope `method` equal to the object's `method`
   member, and a non-empty `correlation_id` (§4);
3. Carries a JSON-RPC success Response (with `result`) as BRIDGE_RESPONSE with
   `message_kind = 0x02`, echoing the request `correlation_id` (§5);
4. Carries a JSON-RPC error Response (with `error`) as BRIDGE_ERROR with
   `message_kind = 0x04`, preserving the JSON-RPC `error` object — `code`,
   `message`, and any `data` — verbatim, and never collapsing or remapping the
   JSON-RPC `code` to or from an N-PAMP transport-error code (§6);
5. Reports a below-protocol delivery failure as BRIDGE_ERROR carrying an N-PAMP
   transport error, never manufactures a JSON-RPC `error` for a transport failure,
   and never reports success for an undelivered Request (§6);
6. Carries a JSON-RPC Notification (a Request with no `id`) as BRIDGE_NOTIFY with
   `message_kind = 0x03` and `corr_len = 0`, emits no reply to it, and never adds
   an `id` to it (§7);
7. Correlates replies to Requests by `correlation_id` rather than by frame
   sequence number, preserves the JSON-RPC `id` verbatim inside the carried object,
   and keeps the echoed `correlation_id` and the carried JSON-RPC `id` consistent
   for every exchange, including the Null-`id` and undetermined-`id` cases (§8);
   and
8. Inherits SafetyLabel handling from NPAMP-BRIDGE §7 unchanged, treating a missing
   label on a state-mutating method as `destructive` (§9).

A conformance test suite SHOULD assert each clause above with a recorded exchange
for at least: a Request/success-Response pair; a Request/error-Response pair whose
error object carries a non-empty `data` member and a JSON-RPC pre-defined `code`; a
Notification with no reply; and a below-protocol delivery failure reported as an
N-PAMP transport error rather than a fabricated JSON-RPC error. Batch arrays are
out of scope (§1.2) and are not exercised by this suite.
