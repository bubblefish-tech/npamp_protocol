# NPAMP-MAP-LMOS — Language Model Operating System (LMOS) Protocol Mapping (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document defines the carriage of the **Eclipse LMOS Protocol** — the
> communication protocol of the Language Model Operating System, an event/streaming
> agent protocol built on the W3C Web of Things (WoT) information model — over an
> N-PAMP association. It is a **thin mapping** over the streaming carriage class
> **NPAMP-CC-STREAM** (`23_carriage_streaming.md`): the carriage class does the
> structural work — multi-event replies over `BRIDGE_STREAM_DATA`/`BRIDGE_STREAM_END`,
> per-stream event identity, resumption, cancellation, and full-duplex correlation —
> and this document pins only what is specific to LMOS. It builds on NPAMP-CC-STREAM,
> on NPAMP-BRIDGE (`10_bridge_framework.md`), and on the N-PAMP core specification
> (draft-bubblefish-npamp-01, the "core specification"). It consumes only code points
> those documents already reserve and introduces no change to the core wire format, to
> NPAMP-BRIDGE, or to NPAMP-CC-STREAM.
>
> **Carriage posture — OPAQUE-READY.** At the time of writing the LMOS Protocol is
> published as **work in progress** (its specification "contains empty sections"), it
> mandates **no single wire transport or serialization**, and no N-PAMP `protocol_id`
> is standards-assigned to it. LMOS is therefore **carriable today via Class OPAQUE**
> (`25_carriage_opaque.md`) under a provisional code point, and the native
> NPAMP-CC-STREAM mapping this document specifies (§4–§8) becomes fully normative once
> LMOS's transport binding, serialization, and message set are confirmed and a code
> point is assigned (§2, §3). §3 states precisely what is confirmed and what is not.

## 1. Scope

### 1.1 In scope

This document specifies how LMOS Protocol communication messages are carried over an
N-PAMP association. It defines, and only defines, the LMOS-specific facts a peer needs
in order to carry LMOS under NPAMP-CC-STREAM:

- The provisional `protocol_id` for LMOS and its carriage class, and the OPAQUE-ready
  posture that lets a peer carry LMOS today (§2, §3);
- The LMOS `messageType` operation namespace and its mapping onto NPAMP-BRIDGE frame
  types and `message_kind` values, including how LMOS's one-request-multiple-responses
  and publish-subscribe patterns ride the NPAMP-CC-STREAM stream frames (§5);
- The LMOS message identity and correlation fields (`thingID`, `messageID`,
  `correlationID`, `traceparent`/`tracestate`) and how they relate to the NPAMP-BRIDGE
  `correlation_id` (§5);
- Which LMOS `messageType`s are state-mutating and therefore the SafetyLabel effect
  class a sender attaches, including the derivation of `invokeAction`'s effect class
  from the WoT Thing Description action affordance's `safe`/`idempotent` terms, and the
  fail-safe on absence (§6); and
- Channel selection: the Bridge channel `0x000D` as the default for LMOS communication
  messages, and the conditions under which LMOS Agent/Tool **description documents** MAY
  ride the Discovery channel `0x0010` (§7).

### 1.2 Not in scope

The following are explicitly NOT defined by this document, because NPAMP-CC-STREAM,
NPAMP-BRIDGE, LMOS's own specification, or the W3C Web of Things specifications already
define them:

- The structural streaming carriage — the StreamControl TLV, the per-stream `event_id`
  invariant, resumption, cancellation, and full-duplex correlation. These are inherited
  verbatim from NPAMP-CC-STREAM (§4–§8 of that document) and are not restated here (§4).
- The semantics, JSON-LD/WoT data models, or payload schemas of any LMOS message or of
  any WoT Thing Description. Those are fixed by LMOS's own specification and by the W3C
  WoT specifications and are carried transparently; this document does not summarize,
  validate, or re-encode them.
- LMOS's own transport bindings — its WebSocket sub-protocol (`lmosprotocol`), its HTTP
  (REST) binding, and any other W3C WoT protocol binding (MQTT, AMQP). Over N-PAMP the
  transport is N-PAMP; those bindings do not apply, and there is no WebSocket handshake
  or `Sec-WebSocket-Protocol` header at the N-PAMP layer (§8).
- LMOS's discovery mechanisms (DNS-SD/mDNS on local networks; agent registries on global
  networks) and its W3C DID document-signing. A peer MAY advertise that it carries LMOS
  over NPAMP-DISC (§7); the LMOS discovery substrate itself is out of scope.
- Any change to the N-PAMP frame format, to the NPAMP-BRIDGE frame types, to the
  BridgeEnvelope, SafetyLabel, or StreamControl TLVs, or to the NPAMP-CC-STREAM rules.

## 2. Protocol identity

| Property | Value |
|---|---|
| Protocol | Eclipse LMOS Protocol — the communication protocol of the Language Model Operating System, a WoT-based event/streaming agent protocol. |
| `protocol_id` | `0x11` — **PROVISIONAL.** No standards-assigned code point exists for LMOS in the Bridge Protocol Identifier registry (NPAMP-REG §6 assigns only `0x01`–`0x04`). `0x11` lies in the experimental range `0x10`–`0x7F` (NPAMP-REG §7.1) and carries **no cross-domain guarantee**: it is usable only under out-of-band agreement between peers, and a standards-assigned value obtained under NPAMP-REG §8 supersedes it. A deployment MAY instead use a private-use value (`0x80`–`0xFF`) within one administrative domain (NPAMP-REG §7.2). |
| Carriage class | STREAM (NPAMP-CC-STREAM). See §3 for the OPAQUE-ready posture that applies until LMOS's transport and serialization are confirmed. |
| `content_type` | **UNCONFIRMED.** LMOS does not formally declare its wire serialization; its examples use JSON and it names CBOR as a switchable media type. A sender MUST set `content_type` to the encoding actually carried — `0x01` (application/json) or `0x02` (application/cbor) — and MUST NOT assume a fixed default until LMOS fixes one (§3, §8). |
| Foreign-message form | A single LMOS Protocol message object bearing a `messageType` member, carried octet-for-octet as the foreign message (NPAMP-BRIDGE §1; NPAMP-CC-STREAM §1.1). |

A sender MUST set the agreed `protocol_id` (provisionally `0x11`) on every Bridge frame
carrying an LMOS message. A receiver that does not carry LMOS MUST reply to a
BRIDGE_REQUEST bearing that value with `ProtocolUnsupported` (NPAMP-BRIDGE §6; NPAMP-REG
§9), and MUST NOT infer LMOS from any other envelope field. Because the value is
experimental, a receiver with no out-of-band agreement on its meaning MUST treat it as an
uncarried protocol (NPAMP-REG §7.1, §9).

## 3. Carriage posture — confirmed and unconfirmed

Under the OPAQUE-ready posture (Status blockquote), a peer carries LMOS today via Class
OPAQUE (`25_carriage_opaque.md`): the LMOS message rides octet-for-octet under the
provisional `protocol_id` and its declared `content_type`, with no protocol-specific
structure. The native NPAMP-CC-STREAM mapping specified in §4–§8 pins the following once
the corresponding LMOS facts are confirmed.

**Confirmed from the LMOS Protocol specification (primary sources, §9):**

- LMOS is built on the W3C WoT information model and is **transport-agnostic**, selecting
  a transport via the WoT protocol-binding abstraction rather than mandating one.
- The communication message model: every message carries `thingID` (a URI), `messageID`
  (a UUIDv4), and `messageType`; `correlationID` (a UUIDv4 shared between related
  messages) is OPTIONAL, as are the W3C Trace Context headers `traceparent`/`tracestate`.
- The `messageType` operation namespace is a formally enumerated set (§5.2).
- Four interaction patterns are defined: request-reply, one-request-multiple-responses,
  event/notification, and publish-subscribe — the latter three of which are multi-event
  and map onto NPAMP-CC-STREAM (§5.3).
- The `error` message carries RFC 9457-style problem-details fields (`type`, `title`,
  `status`, `detail`, `instance`).
- LMOS Agent/Tool descriptions use JSON-LD WoT Thing Descriptions, signed with W3C DIDs.

**Unconfirmed at the time of writing (why LMOS is OPAQUE-ready, not DRAFT-native):**

- **Wire serialization / `content_type`.** LMOS does not formally declare its
  serialization (§2); JSON and CBOR are both admissible.
- **Transport binding.** LMOS mandates no single transport; its WebSocket sub-protocol
  identifier is `lmosprotocol`, which the LMOS specification itself marks as pending final
  determination.
- **Message-set stability.** The LMOS specification is "work in progress" and "contains
  empty sections"; it has no formal version number (its namespace is
  `https://eclipse.dev/lmos/protocol/v1`) and is not W3C-standardized.
- **`protocol_id`.** No standards-assigned N-PAMP code point exists (§2).

An implementation MUST NOT treat §4–§8 as interoperable across independently developed
peers until (a) LMOS fixes its serialization and message set, and (b) a `protocol_id` is
assigned under NPAMP-REG §8; until then it carries LMOS via Class OPAQUE or via the
experimental-range mapping of §2 under out-of-band agreement (NPAMP-REG §7.1).

## 4. Relationship to NPAMP-CC-STREAM and NPAMP-BRIDGE

LMOS's native communication is asynchronous, bidirectional message passing in which a
single request can yield a sequence of responses over time (for example an `invokeAction`
answered by multiple `actionStatus` updates) and in which a subscription yields a
continuing sequence of `event`/`propertyReading` messages. This is exactly the multi-event
reply model that NPAMP-CC-STREAM carries, so the entire structural carriage is provided by
NPAMP-CC-STREAM and NPAMP-BRIDGE without modification:

- The transparency rule governs: an LMOS message is carried octet-for-octet and MUST NOT
  be re-serialized, reordered, canonicalized, or rewritten (NPAMP-BRIDGE §1;
  NPAMP-CC-STREAM §1.1).
- A streamed LMOS reply is an ordinary sequence of `BRIDGE_STREAM_DATA` frames terminated
  by one `BRIDGE_STREAM_END`, each frame bearing the StreamControl TLV and a strictly
  monotonic per-stream `event_id`; resumption, cancellation, and the terminal-event-id
  rule are inherited unchanged (NPAMP-CC-STREAM §5–§7). This document adds no stream-control
  rule.
- Correlation of a reply to its request is the NPAMP-BRIDGE `correlation_id` mechanism
  (NPAMP-BRIDGE §5), inherited unchanged; §5 states how the LMOS `correlationID`/`messageID`
  populate it.
- A full-duplex LMOS exchange is carried as two correlated per-direction streams sharing
  the exchange `correlation_id` (NPAMP-CC-STREAM §8), inherited unchanged.

This document therefore pins only LMOS specifics (§2, §3, §5, §6, §7, §8). Where this
document and NPAMP-CC-STREAM could appear to differ on a structural matter, NPAMP-CC-STREAM
governs.

## 5. LMOS message model and frame mapping

LMOS is bidirectional at the application layer: either peer MAY originate a message. This
maps directly onto NPAMP-BRIDGE's per-exchange requester/responder roles — the peer that
emits a BRIDGE_REQUEST is the requester for that exchange (NPAMP-BRIDGE §5). No N-PAMP role
is tied to a particular LMOS Thing.

### 5.1 Message identity and correlation fields

The BridgeEnvelope `method` field carries the exact octets of the LMOS `messageType`
member (NPAMP-BRIDGE §4). The remaining LMOS identity fields ride **inside** the carried
message and are handled as follows:

- **`correlationID` → `correlation_id`.** When a sender carries an LMOS request-like message
  as a BRIDGE_REQUEST it MUST set a non-empty NPAMP-BRIDGE `correlation_id` (NPAMP-BRIDGE
  §5): it MUST derive that value from the LMOS `correlationID` when present and otherwise
  from the required `messageID`. Every stream frame and reply MUST echo that `correlation_id`
  (NPAMP-BRIDGE §5; NPAMP-CC-STREAM §4). The LMOS `correlationID` remains present inside the
  carried message and is not stripped.
- **`messageID`.** Carried verbatim inside the LMOS message; it is not mapped to an envelope
  field beyond its role as the correlation source above.
- **`thingID`.** Carried verbatim inside the LMOS message. N-PAMP addresses the peer and the
  association, not the LMOS Thing; a peer MUST NOT map `thingID` onto any N-PAMP envelope or
  routing field.
- **`traceparent` / `tracestate`.** W3C Trace Context headers carried verbatim inside the
  LMOS message; they are not mapped to any N-PAMP field.

### 5.2 The `messageType` operation namespace

The tables below enumerate the LMOS `messageType` values of the current work-in-progress
specification, grouped by WoT affordance. The `messageType` value in each table is the exact
string carried in both the LMOS message and the BridgeEnvelope `method` field.

**Actions (ActionAffordance):**

| `messageType` | Purpose |
|---|---|
| `invokeAction` | Invoke an action on a Thing (effect class per §6.2). |
| `queryAction` | Query the state of an action. |
| `cancelAction` | Cancel a running action. |
| `actionStatus` | An action-status update (response/notification). |

**Properties (PropertyAffordance):**

| `messageType` | Purpose |
|---|---|
| `readProperty` | Read a property. |
| `writeProperty` | Write a property. |
| `writeMultipleProperties` | Write several properties. |
| `propertyReading` | A single property reading (response). |
| `propertyReadings` | Multiple property readings (response). |
| `observeProperty` | Subscribe to updates of a property. |
| `unobserveProperty` | Cancel a property observation. |

**Events (EventAffordance):**

| `messageType` | Purpose |
|---|---|
| `subscribeEvent` | Subscribe to an event. |
| `unsubscribeEvent` | Cancel an event subscription. |
| `subscribeAllEvents` | Subscribe to all of a Thing's events. |
| `unsubscribeAllEvents` | Cancel an all-events subscription. |
| `event` | An emitted event (notification). |

**Error:**

| `messageType` | Purpose |
|---|---|
| `error` | An error report carrying the LMOS problem-details object (`type`, `title`, `status`, `detail`, `instance`). |

### 5.3 Interaction patterns and frame mapping

Each LMOS interaction pattern maps onto NPAMP-BRIDGE/NPAMP-CC-STREAM frames as follows.
The BridgeEnvelope `message_kind` MUST agree with the frame type (NPAMP-BRIDGE §4).

- **Request-reply (single response).** A request-like message (for example `readProperty`)
  is carried as **BRIDGE_REQUEST** (`0x0100`, `message_kind = 0x01`); its single reply (for
  example `propertyReading`) is carried as **BRIDGE_RESPONSE** (`0x0101`, `0x02`) echoing the
  request's `correlation_id`.
- **One request, multiple responses.** A request-like message whose reply is a sequence over
  time (for example `invokeAction` answered by multiple `actionStatus` updates) is carried as
  **BRIDGE_REQUEST**, and the sequence of response messages is carried as
  **BRIDGE_STREAM_DATA** (`0x0104`, `0x05`) frames — each bearing a StreamControl TLV with a
  strictly monotonic `event_id` (NPAMP-CC-STREAM §5) — terminated by exactly one
  **BRIDGE_STREAM_END** (`0x0105`, `0x06`) with `final` set.
- **Publish-subscribe.** A subscription request (`subscribeEvent`, `subscribeAllEvents`,
  `observeProperty`) is carried as **BRIDGE_REQUEST**; the ensuing continuing sequence of
  `event`/`propertyReading` messages is carried as a **BRIDGE_STREAM_DATA** stream under the
  request's `correlation_id`, terminated by **BRIDGE_STREAM_END** when the corresponding
  `unsubscribeEvent`/`unsubscribeAllEvents`/`unobserveProperty` closes it or when the producer
  ends the stream. Stream cancellation and resumption follow NPAMP-CC-STREAM §6–§7.
- **Event / notification (unsolicited).** An `event` or state-change message that is not a
  response to an outstanding request is carried as **BRIDGE_NOTIFY** (`0x0103`,
  `message_kind = 0x03`, `corr_len = 0`); the receiver MUST NOT reply and the sender MUST NOT
  await a reply (NPAMP-BRIDGE §8).
- **Error.** An LMOS `error` message is carried as **BRIDGE_ERROR** (`0x0102`,
  `message_kind = 0x04`) with the LMOS problem-details object preserved verbatim; its fields
  MUST NOT be collapsed or remapped to or from an N-PAMP transport-error code (NPAMP-BRIDGE
  §6). An LMOS-level error is a foreign error carried verbatim, distinct from the N-PAMP
  transport errors (`ProtocolUnsupported`, `MethodUnsupported`, `NotResumable`, and the rest)
  that report a failure *below* LMOS.

> **Revision note.** The `messageType` set above is that of the current work-in-progress
> LMOS specification (§9). Because the carriage is transparent over the `messageType` string
> and selects nothing on it beyond the BridgeEnvelope `method` field and the SafetyLabel
> guidance of §6, a peer carries a newer or older LMOS revision without a change to this
> mapping. An implementation MUST NOT reject an LMOS message solely because its `messageType`
> is absent from the tables above; the negotiated LMOS version, not this table, fixes the
> message set for a session.

## 6. SafetyLabel and state-mutating messages

The SafetyLabel TLV (Type `0x0013`) and its fail-safe semantics are governed by
NPAMP-BRIDGE §7 and inherited through NPAMP-CC-STREAM unchanged. The WoT information model
does not by itself encode, in every message, whether an operation mutates state; this
section fixes, for LMOS, which `messageType`s a sender MUST label and how.

When a carried LMOS request can cause side effects, the sender MUST attach a SafetyLabel TLV
describing the effect class, an intermediary MUST carry it unchanged, and — the fail-safe — a
receiver MUST NOT treat the **absence** of a SafetyLabel on a state-mutating operation as
`read_only`; absence on such an operation MUST be treated as `destructive` (NPAMP-BRIDGE §7).

### 6.1 Effect class by `messageType`

| LMOS `messageType`(s) | Effect (NPAMP-BRIDGE §7) | Rationale |
|---|---|---|
| `readProperty`, `propertyReading`, `propertyReadings`, `queryAction`, `actionStatus`, `event` | `0x00` read_only | Reads, status queries, and status/event notifications that do not act on external state. A SafetyLabel MAY be omitted; absence is correctly read as read_only for these. |
| `observeProperty`, `unobserveProperty`, `subscribeEvent`, `unsubscribeEvent`, `subscribeAllEvents`, `unsubscribeAllEvents` | `0x01` idempotent_write | Establish or tear down session-scoped observation/subscription state on the responder; repeating with the same arguments yields the same state. The sender SHOULD attach the SafetyLabel; on absence the receiver MUST fail-safe to `destructive`. |
| `writeProperty`, `writeMultipleProperties` | `0x01` idempotent_write (at minimum) | A WoT property models state; writing the same value yields the same state. The sender MUST attach a SafetyLabel reflecting the actual effect where a property's write is not idempotent. |
| `cancelAction` | `0x01` idempotent_write | Changes action lifecycle state; cancelling an already-cancelled action is a no-op. The sender MUST attach a SafetyLabel reflecting the actual effect. |
| `invokeAction` | Variable — derived per §6.2 | An action is arbitrary behavior; its effect is the action's, not LMOS's. |

### 6.2 `invokeAction` effect class from the WoT action affordance

LMOS describes a Thing's actions with W3C WoT Thing Description `ActionAffordance` objects,
which a client learns from the Thing's description (§7). The WoT `ActionAffordance` carries
two boolean terms — `safe` (default `false`) and `idempotent` (default `false`) — that
describe the action's effect. The peer that originates the `invokeAction` BRIDGE_REQUEST MUST
derive the SafetyLabel `effect` from those terms as follows:

| WoT `ActionAffordance` | SafetyLabel `effect` |
|---|---|
| `safe = true` | `0x00` read_only |
| `safe = false`, `idempotent = true` | `0x01` idempotent_write |
| `safe = false`, `idempotent = false` (explicit or by WoT default) | `0x02` non_idempotent_write |
| The action's Thing Description / affordance is unavailable to the sender | `0x03` destructive |

Note a deliberate divergence from the MCP mapping (NPAMP-MAP-MCP §6.2): WoT has no
"destructive" hint. The strongest effect class derivable from WoT's own terms is
`non_idempotent_write` (an unannotated action is `safe = false`, `idempotent = false` by WoT
default). The `destructive` class therefore arises only from the NPAMP-BRIDGE §7 fail-safe —
when the sender cannot obtain the action's affordance at all and so cannot characterize its
effect — not from any WoT term.

The `scope` field of the SafetyLabel (NPAMP-BRIDGE §7) MAY carry the action name or the
`thingID` as an advisory resource hint. A WoT affordance obtained from an untrusted source is
untrusted: consistent with NPAMP-BRIDGE §7, the SafetyLabel "describes intent and does not
replace authorization." A receiver MUST enforce its own authorization at invocation and MUST
NOT treat a favorable (for example `read_only`) SafetyLabel as permission.

## 7. Channel selection

LMOS communication messages ride the **Bridge channel `0x000D`** by default, as required for
NPAMP-BRIDGE encapsulation and NPAMP-CC-STREAM carriage (NPAMP-BRIDGE §1; NPAMP-CC-STREAM
§1.2). Under this mapping, a peer carrying an LMOS session MUST carry that session's messages
on the Bridge channel, and MUST NOT split a single LMOS session (one `correlation_id`) across
channels or associations. NPAMP-CC-STREAM carries streamed LMOS replies on the Bridge channel
and does not move them to the core Stream channel `0x000C` (NPAMP-CC-STREAM §1.2).

Two OPTIONAL uses of the Discovery channel `0x0010` are available around, not in place of,
that session:

- **Advertising LMOS as a carried protocol.** A peer MAY advertise, over NPAMP-DISC on the
  Discovery channel `0x0010`, a protocol Discovery Record (`kind = 1`) whose `protocol_id` is
  the agreed LMOS value (§2), whose `carriage_class` is STREAM, and whose OPTIONAL `methods`
  list names the LMOS `messageType`s it carries (NPAMP-DISC §5.1). This announces that the
  peer carries LMOS; it does not carry LMOS traffic. A peer MUST NOT advertise LMOS if it
  cannot in fact carry the LMOS `protocol_id` over the association.
- **Agent/Tool description documents.** LMOS describes agents and tools as JSON-LD WoT Thing
  Descriptions (DID-signed self-contained documents). Such a description MAY ride the Discovery
  channel `0x0010` under NPAMP-CC-DOC (`24_carriage_documents.md`), the class for capability
  and schema documents and their detached proofs. This is distinct from live LMOS
  communication messages (`readProperty`, `event`, and the rest), which remain STREAM traffic
  on the Bridge channel.

## 8. Transport-binding and version notes

LMOS is transport-agnostic: it selects a transport (WebSocket, HTTP/REST, or another W3C WoT
protocol binding) and a media type (JSON or CBOR) via the WoT protocol-binding abstraction.
Over N-PAMP, **N-PAMP is the transport**: LMOS's WebSocket sub-protocol (`lmosprotocol`), its
HTTP binding, and any other WoT transport binding do not apply, and there is no WebSocket
upgrade or `Sec-WebSocket-Protocol` header at the N-PAMP layer. N-PAMP is, in WoT terms,
simply one further protocol binding — and it supplies authentication, post-quantum
confidentiality and integrity, multiplexing, and the key schedule (core specification); these
replace, and are not layered on top of, LMOS's own transport bindings.

Because LMOS does not fix its serialization, a sender MUST declare the encoding it actually
carries in the BridgeEnvelope `content_type` (§2) and MUST NOT assume a fixed default; a peer
MUST NOT attempt to convey or enforce the LMOS media type or protocol version through any
N-PAMP envelope field. LMOS session state (for example an active subscription) is scoped to
the LMOS session carried on the association; a peer MUST NOT carry LMOS session state from a
prior association into a new one, and re-establishes subscriptions with fresh LMOS messages on
a new association.

The LMOS Protocol is published as work in progress, with no formal version number (namespace
`https://eclipse.dev/lmos/protocol/v1`) and is not yet W3C-standardized. This mapping is
consequently marked OPAQUE-ready (§3); it is promoted to a native DRAFT mapping once LMOS
fixes its serialization and message set and a `protocol_id` is assigned under NPAMP-REG §8.
Because the carriage is transparent over the `messageType` string (§5), such maturation is
carried without a change to §5's frame mapping; only §2's `content_type`/`protocol_id`, §5.2's
illustrative table, and §6's effect-class guidance track the specific LMOS revision.

## 9. References

Normative for the carriage:

- draft-bubblefish-npamp-01 — the N-PAMP core specification (Bridge channel `0x000D`,
  Discovery channel `0x0010`, the frame format, the BridgeEnvelope and SafetyLabel TLV
  reservations, and AEAD payload protection).
- NPAMP-BRIDGE (`10_bridge_framework.md`) — the encapsulation, correlation, error, and
  SafetyLabel contract.
- NPAMP-CC-STREAM (`23_carriage_streaming.md`) — the streaming carriage class that does the
  structural work for LMOS (StreamControl TLV, event-id invariant, resumption, cancellation,
  full-duplex correlation).
- NPAMP-CC-OPAQUE (`25_carriage_opaque.md`) — the universal carriage under which LMOS is
  carried today (§3).
- NPAMP-REG (`30_protocol_registry.md`) — the Bridge Protocol Identifier registry; source of
  the provisional/experimental `protocol_id` handling of §2.
- NPAMP-DISC (`40_discovery.md`) and NPAMP-CC-DOC (`24_carriage_documents.md`) — the
  Discovery-channel advertisement and document-carriage referenced in §7.
- BCP 14: RFC 2119 and RFC 8174 — requirement key words.
- RFC 9457 — Problem Details for HTTP APIs; the field vocabulary (`type`, `title`, `status`,
  `detail`, `instance`) of the LMOS `error` message (§5.2).

LMOS and WoT source specifications (primary sources consulted for §2–§8; LMOS Protocol is
work in progress at the time of writing):

- Eclipse LMOS — Introduction to the LMOS Protocol (transport-agnosticism; JSON-LD WoT Thing
  Descriptions; DNS-SD/mDNS and registry discovery; DID signing) —
  <https://eclipse.dev/lmos/docs/lmos_protocol/introduction/>
- Eclipse LMOS — Communication Protocol (message fields `thingID`, `messageID`, `messageType`,
  `correlationID`, `traceparent`/`tracestate`; the four interaction patterns; the
  `messageType` enumeration; the `error` problem-details fields) —
  <https://eclipse.dev/lmos/docs/lmos_protocol/communication_protocol/>
- Eclipse LMOS — WebSocket Sub-protocol (the `lmosprotocol` subprotocol identifier, marked
  pending final determination; transport handshake) —
  <https://eclipse.dev/lmos/docs/lmos_protocol/websocket_binding/>
- Eclipse LMOS — What is LMOS? / Architecture overview (Internet of Agents; Application vs
  Transport Protocol Layers) — <https://eclipse.dev/lmos/docs/introduction/>
- W3C Web of Things (WoT) Thing Description 1.1 — the `ActionAffordance` `safe` (default
  `false`) and `idempotent` (default `false`) terms used in §6.2 —
  <https://www.w3.org/TR/wot-thing-description11/>

**Limitations of the sources consulted.** The LMOS Protocol specification states that it is
work in progress and "contains empty sections"; it does not formally declare a wire
serialization, does not assign an N-PAMP code point, and marks its own WebSocket subprotocol
name as pending. The frame mapping of §5, the effect classes of §6, and the `content_type` of
§2 are therefore grounded in the message model and `messageType` enumeration as published
above and are subject to change as LMOS matures — which is precisely why this mapping is
OPAQUE-ready (§3) rather than a settled native DRAFT. No claim is made here about LMOS
behavior not covered by the pages cited above (for example the internal semantics of any
specific action or the details of the LMOS registry/discovery substrate).

## 10. Conformance

An implementation conforms to NPAMP-MAP-LMOS if and only if it conforms to NPAMP-CC-STREAM
(and therefore to NPAMP-BRIDGE) and, for LMOS traffic, it:

1. Carries every LMOS message under the agreed LMOS `protocol_id` (provisionally `0x11`, an
   experimental value usable only under out-of-band agreement) with a `content_type` set to
   the encoding actually carried, octet-for-octet, and selects LMOS solely from `protocol_id`,
   never from another envelope field (§2, §3);
2. Treats the mapping as OPAQUE-ready — carrying LMOS via Class OPAQUE where a native STREAM
   binding is not yet agreed — and does not assume cross-implementation interoperability of
   §4–§8 until LMOS fixes its serialization and message set and a `protocol_id` is assigned
   under NPAMP-REG §8 (§3);
3. Maps LMOS messages onto frames per §5.3 — a single-response request to BRIDGE_REQUEST
   /BRIDGE_RESPONSE; a multi-response or publish-subscribe request to a BRIDGE_REQUEST followed
   by a BRIDGE_STREAM_DATA stream terminated by BRIDGE_STREAM_END under NPAMP-CC-STREAM; an
   unsolicited notification to BRIDGE_NOTIFY (`corr_len = 0`); and an `error` message to
   BRIDGE_ERROR with the LMOS problem-details object preserved verbatim — with the
   BridgeEnvelope `method` equal to the LMOS `messageType` (§5);
4. Sets a non-empty NPAMP-BRIDGE `correlation_id` on every carried LMOS request, deriving it
   from the LMOS `correlationID` when present and otherwise from `messageID`, echoing it on
   every reply and stream frame, and carries `thingID`, `messageID`, `traceparent`, and
   `tracestate` verbatim inside the LMOS message without mapping them to N-PAMP fields (§5.1);
5. Attaches a SafetyLabel to every state-mutating LMOS request it originates, using the effect
   classes of §6.1, and — for `invokeAction` — derives the effect class from the WoT action
   affordance's `safe`/`idempotent` terms per §6.2, labelling an action whose affordance is
   unavailable `destructive` (§6.2);
6. Treats a missing SafetyLabel on any `messageType` not listed as read_only in §6.1 as
   `destructive` (NPAMP-BRIDGE §7 fail-safe), and never treats a favorable SafetyLabel as
   authorization, enforcing its own authorization at invocation (§6);
7. Carries an LMOS session's messages on the Bridge channel `0x000D`, does not split a single
   LMOS session across channels, and uses the Discovery channel `0x0010` only for the OPTIONAL
   protocol advertisement (NPAMP-DISC) or WoT Thing Description document carriage (NPAMP-CC-DOC)
   of §7, never for live LMOS communication messages (§7); and
8. Does not apply LMOS's WebSocket, HTTP, or other WoT transport bindings and adds no
   `Sec-WebSocket-Protocol` or LMOS-version N-PAMP header, conveying the LMOS media type and
   version only inside the carried messages, and carries no LMOS session state across
   associations (§8).

A conformance test suite SHOULD assert each clause above with recorded exchanges that include:
A `readProperty`/`propertyReading` single request-reply; an `invokeAction` answered by a
BRIDGE_STREAM_DATA stream of `actionStatus` updates terminated by BRIDGE_STREAM_END, whose
SafetyLabel effect class is derived from the action's WoT `safe`/`idempotent` terms (including
an action whose affordance is unavailable, which MUST be labelled `destructive`); a
`subscribeEvent` yielding a stream of `event` messages closed by `unsubscribeEvent`; an
unsolicited `event` carried as BRIDGE_NOTIFY with no reply; and an LMOS `error` carried as
BRIDGE_ERROR with its problem-details fields preserved verbatim.
