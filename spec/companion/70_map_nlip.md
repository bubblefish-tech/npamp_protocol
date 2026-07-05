# NPAMP-MAP-NLIP — NLIP (Natural Language Interaction Protocol) Mapping (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is a **thin per-protocol mapping**: it pins the specifics of
> the **Natural Language Interaction Protocol (NLIP)** — the open, vendor-neutral
> agent-communication protocol standardized by Ecma International Technical
> Committee TC56 as the standards suite **ECMA-430** (core message format),
> **ECMA-431** (HTTP/HTTPS binding), **ECMA-432** (WebSocket binding), **ECMA-433**
> (AMQP binding), **ECMA-434** (security profiles), and **ECMA TR/113** (explanatory
> guide), published 10 December 2025 (§11) — onto N-PAMP carriage. NLIP is carried
> under **two** carriage classes matching its two interactive transport bindings:
> Its REST-over-HTTP binding rides the HTTP carriage class **NPAMP-CC-HTTP**
> (`21_carriage_http.md`), and its real-time WebSocket binding rides the streaming
> carriage class **NPAMP-CC-STREAM** (`23_carriage_streaming.md`). Those carriage
> classes do the structural work (request/response, streaming, header/body carriage,
> per-stream event identity, correlation, verbatim error carriage); this document
> pins only what is specific to NLIP. It builds on NPAMP-CC-HTTP, NPAMP-CC-STREAM,
> NPAMP-BRIDGE (`10_bridge_framework.md`), and the N-PAMP core specification
> (draft-bubblefish-npamp-01, the "core specification"). It consumes only code points
> those documents already reserve and introduces no new frame type, no new TLV, and
> no change to the core wire format, to NPAMP-BRIDGE, to NPAMP-CC-HTTP, or to
> NPAMP-CC-STREAM.
>
> **Status of this mapping: OPAQUE-READY; `protocol_id` PROVISIONAL.** NLIP is
> carriable over N-PAMP **today** via Class OPAQUE (`25_carriage_opaque.md`) with no
> protocol-specific mapping. This document supplies the native HTTP-class and
> STREAM-class mapping. Unlike some sibling mappings, **NLIP's protocol itself is
> confirmed and ratified**: its message format and its HTTP and WebSocket bindings
> are fixed by the published ECMA standards (§4, §5, §11). The only reason this
> mapping is not yet a settled native DRAFT is that NLIP has **no standards-assigned
> N-PAMP `protocol_id`**: the Bridge Protocol Identifier registry (NPAMP-REG §6)
> assigns `0x01`–`0x04` and reserves `0x05`–`0x0F` unassigned, and NLIP is not among
> them, so a sender carries NLIP under an out-of-band-agreed **experimental-range**
> `protocol_id` (§2). §9 states precisely what is confirmed versus unconfirmed.

## 1. Scope

### 1.1 In scope

This document defines how an NLIP endpoint interoperates over an N-PAMP association
without bespoke adaptation. It pins, against NLIP's own published specification (§11),
only the NLIP specifics that NPAMP-CC-HTTP and NPAMP-CC-STREAM leave to a per-protocol
mapping:

- The NLIP **protocol identifier** (PROVISIONAL) and the foreign-message
  `content_type` for each carriage class (§2);
- The OPAQUE-ready posture, and what is confirmed versus unconfirmed (§3, §9);
- NLIP's **operation surface** — a single well-known envelope endpoint reached by one
  HTTP method, not a per-operation method namespace — and how it rides NPAMP-CC-HTTP
  as a Bridge frame (§4);
- How NLIP's **session, streaming, and control/data model** — the conversation-token
  echo, the synchronous and asynchronous streaming modes, and the WebSocket binding —
  ride the HTTP and STREAM carriage classes (§5);
- The OPTIONAL treatment of NLIP **policy and capability material** as a document (§6);
- Which NLIP operations are state-mutating and therefore the **SafetyLabel effect
  class** a sender attaches, and the NPAMP-BRIDGE §7 fail-safe on absence (§7); and
- **Channel selection** for each NLIP traffic class (§8).

The structural work — octet-exact carriage of the NLIP message, the HTTP-Carriage
Object, the StreamControl TLV, the BridgeEnvelope, correlation, the structured-error
model, streaming, and the SafetyLabel TLV — is done by NPAMP-BRIDGE, NPAMP-CC-HTTP,
and NPAMP-CC-STREAM and is not restated here.

### 1.2 Not in scope

The following are explicitly NOT defined by this document, because NPAMP-CC-HTTP,
NPAMP-CC-STREAM, NPAMP-BRIDGE, or NLIP's own specification already fix them:

- **The structural HTTP-semantics carriage** — the HTTP-Carriage Object (method,
  target, headers, body, status), request/response correlation, and streaming — which
  is inherited verbatim from NPAMP-CC-HTTP and is not restated (§3).
- **The structural streaming carriage** — the StreamControl TLV, the per-stream
  `event_id` invariant, resumption, cancellation, and full-duplex correlation — which
  is inherited verbatim from NPAMP-CC-STREAM and is not restated (§3).
- **The NLIP message schema.** The internal grammar of the NLIP message (its `format`,
  `subformat`, `content`, `submessages`, and `control` fields; the allowed `format`
  values `text`, `token`, `structured`, `binary`, `location`, `generic`; the
  `token`/`conversation` submessage) is fixed by ECMA-430. This document carries the
  NLIP message verbatim (NPAMP-BRIDGE §1) and does not parse, validate, re-encode, or
  act on any of its fields (§4, §7).
- **NLIP's native transport bindings and out-of-band exchanges.** NLIP's own HTTP
  request line and headers are subsumed by the HTTP-Carriage Object (§3); NLIP's
  WebSocket upgrade and `Sec-WebSocket-Protocol` handshake do not exist over N-PAMP
  (§5, §8); and NLIP's alternate endpoint for large-binary upload (ECMA-431 §6.1) and
  any dereference of a `structured`/`uri` content reference to an external URI are
  **not** carried by this mapping (they leave the association; §6, §8, §10).
- **The AMQP binding (ECMA-433).** NLIP's message-passing binding over AMQP is a
  distinct transport; it is not one of the two interactive bindings mapped here and is
  carried today via Class OPAQUE (or, if a native mapping is later wanted, under the
  message-passing class NPAMP-CC-MSG). It is out of scope for this document (§9).
- **NLIP transport-bound and profile-bound security.** NLIP's opaque authentication
  and authorization tokens (ECMA-430; base64 text) and the transport-security,
  authentication, authorization, prompt-injection-prevention, and ethical-by-design
  requirements of the ECMA-434 security profiles bind to an NLIP transport hop that
  does not exist over N-PAMP; they are carried only as opaque octets and are neither
  validated nor re-bound by carriage (§10).
- **Any change to NPAMP-BRIDGE, NPAMP-CC-HTTP, NPAMP-CC-STREAM, or the core wire
  format**, including the BridgeEnvelope, SafetyLabel, and StreamControl TLVs, which
  are used as their defining documents specify.

## 2. Protocol identity

| Property | Value |
|---|---|
| Protocol | NLIP — Natural Language Interaction Protocol (Ecma TC56; ECMA-430/431/432/433/434, ECMA TR/113; `nlip-project.org`, `github.com/nlip-project`; §11). |
| `protocol_id` | **PROVISIONAL.** No standards-assigned code point exists: NPAMP-REG §6 assigns `0x01`–`0x04` and reserves `0x05`–`0x0F` unassigned, and NLIP is not among them. A sender MUST therefore carry NLIP under an **experimental-range** `protocol_id` (`0x10`–`0x7F`) agreed out of band with the peer (NPAMP-REG §7.1), and MUST NOT emit NLIP under a value NPAMP-REG has assigned to another protocol. A deployment MAY instead use a private-use value (`0x80`–`0xFF`) within one administrative domain (NPAMP-REG §7.2). A standards-assigned identifier, if warranted, would be obtained under NPAMP-REG §8 (§9). |
| Carriage class | **HTTP** (NPAMP-CC-HTTP) for the ECMA-431 REST/HTTP binding, and **STREAM** (NPAMP-CC-STREAM) for the ECMA-432 WebSocket binding. Class OPAQUE (`25_carriage_opaque.md`) is the equivalent zero-mapping fallback available today (§3, §9). |
| `content_type` | Per carriage class. For the **HTTP** carriage, `0x02` (`application/cbor`), as required by NPAMP-CC-HTTP §2.3 for the HTTP-Carriage Object container; the NLIP body carried **inside** that object retains its own media type (`application/json`) in the object's header-field list (NPAMP-CC-HTTP §4.4). For the **STREAM** carriage, the NLIP message is itself the foreign event, so `content_type` is the NLIP wire encoding actually carried — `0x01` (`application/json`, the ECMA-432 UTF-8 JSON text frame) or `0x02` (`application/cbor`, the ECMA-432 CBOR binary frame). A sender MUST set `content_type` to the encoding it actually carries and MUST NOT assume the other. |
| Foreign-message form | Under HTTP: one HTTP-Carriage Object (NPAMP-CC-HTTP §4) per Bridge frame, carrying one NLIP HTTP request or response octet-for-octet. Under STREAM: one NLIP message object (bearing the REQUIRED `format`/`subformat`/`content` fields; ECMA-430) per Bridge frame, carried octet-for-octet (NPAMP-BRIDGE §1). |

A sender MUST set the same agreed experimental `protocol_id` on every Bridge frame
carrying an NLIP message. A receiver that does not carry NLIP MUST reply to a
BRIDGE_REQUEST bearing that value with `ProtocolUnsupported` (NPAMP-BRIDGE §6;
NPAMP-REG §9), and MUST NOT infer NLIP from any other envelope field (NPAMP-REG §9).
Because the value is experimental, a receiver with no out-of-band agreement on its
meaning MUST treat it as an uncarried protocol (NPAMP-REG §7.1, §9).

## 3. Carriage posture — confirmed and OPAQUE-ready

Under the OPAQUE-ready posture (Status blockquote), a peer carries NLIP today via
Class OPAQUE (`25_carriage_opaque.md`): the NLIP message rides octet-for-octet under
the provisional `protocol_id` and its declared `content_type`, with no
protocol-specific structure. The native mapping specified in §4–§8 pins the NLIP
carriage over NPAMP-CC-HTTP and NPAMP-CC-STREAM.

NLIP differs from some sibling OPAQUE-ready protocols in that **its own specification
is ratified and stable**: the message format (ECMA-430), the HTTP binding
(ECMA-431), and the WebSocket binding (ECMA-432) are published Ecma standards (§11).
The frame mapping of §4–§5, the effect-class treatment of §7, and the `content_type`
of §2 are therefore grounded in confirmed primary sources, not in a moving target. The
single blocking dependency is the N-PAMP `protocol_id`: until one is assigned under
NPAMP-REG §8, NLIP MUST be carried under an out-of-band-agreed experimental identifier
(§2), and an implementation MUST NOT assume the mapping of §4–§8 is interoperable
across independently developed peers that have not agreed on that identifier (§9). §9
states precisely what is confirmed versus unconfirmed.

## 4. Relationship to the carriage classes, and NLIP's operation surface

NLIP follows a **request-response** paradigm (not remote-procedure-call): a client
initiates, a server waits for and answers requests, and messages are exchanged as
JSON (or, over the WebSocket binding, CBOR) objects (ECMA-430; §11). Its two
interactive bindings map onto two N-PAMP carriage classes:

- The **ECMA-431 HTTP/HTTPS binding** is HTTP-semantics: a client submits an NLIP
  message to a fixed endpoint and receives an NLIP message in the HTTP response.
  Consequently its structural carriage is provided by **NPAMP-CC-HTTP** without
  modification (§4.1).
- The **ECMA-432 WebSocket binding** is a real-time, bidirectional event stream of
  NLIP messages. Consequently its structural carriage is provided by
  **NPAMP-CC-STREAM** without modification (§5).

Under both classes the transparency rule governs: an NLIP message is carried
octet-for-octet and MUST NOT be re-serialized, reordered, canonicalized, or rewritten
(NPAMP-BRIDGE §1; NPAMP-CC-HTTP §2.1; NPAMP-CC-STREAM §1.1). This document therefore
pins only NLIP specifics (§2, §5–§8). Where this document and a carriage class could
appear to differ on a structural matter, the carriage class governs.

### 4.1 The HTTP operation surface is a single envelope endpoint

NLIP is a **universal envelope protocol**: it does not expose a per-operation method
namespace. ECMA-431 fixes a single well-known endpoint — `https://<server>:<port>/nlip`
— which "shall support accepting an NLIP message using the **POST** command of HTTP,"
over HTTP/1.1 or HTTP/2 as the base transfer protocol (HTTP/3 in validated use cases)
(§11). The semantic "operation" is expressed inside the natural-language `content` of
the carried NLIP message, which the carriage does not parse. The mapping is therefore
minimal and fixed:

| NLIP HTTP operation | HTTP method + target | NPAMP-BRIDGE frame(s) | Effect (§7) |
|---|---|---|---|
| Submit an NLIP message to the primary endpoint | `POST /nlip` | BRIDGE_REQUEST → BRIDGE_RESPONSE, **or** streamed (§5) | `0x02` non_idempotent_write (floor; §7) |
| Upload/retrieve large content at an alternate endpoint (ECMA-431 §6.1), when the NLIP server exports one | `POST <upload-target>` / `GET <target>` | BRIDGE_REQUEST → BRIDGE_RESPONSE, or **not carried** when it is an out-of-band URI (§6, §8) | Per HTTP method (NPAMP-CC-HTTP §8.1) |

Carriage requirements:

- The sender MUST populate the HTTP-Carriage Object `method` and `target` keys with
  the HTTP method token (`POST`) and the origin-form target (`/nlip`, plus any query),
  MUST set the BridgeEnvelope `method` routing key to "`<method> <target>`" (for
  example `POST /nlip`), and MUST supply a non-empty `correlation_id` unique among its
  outstanding requests in that direction (NPAMP-CC-HTTP §2.4, §3). The NLIP message is
  carried in the object's `body` key, verbatim (NPAMP-CC-HTTP §4.3).
- Either peer MAY originate a BRIDGE_REQUEST (NPAMP-BRIDGE §5); the NLIP client is the
  requester and the NLIP server the responder for a given exchange, but the carriage
  places no additional directional restriction. This admits the NLIP deployments —
  client-server, proxy, federator, and back-level (§11) — in which either side may act
  as an NLIP server.
- An NLIP HTTP response whose status is a client or server error (`4xx`/`5xx`) — for
  example a server refusing the connection — is a **successful carriage of a foreign
  result** and MUST be carried as a BRIDGE_RESPONSE with that status and any NLIP body
  preserved verbatim, never re-labelled as a BRIDGE_ERROR and never remapped to or from
  an N-PAMP transport-error code (NPAMP-CC-HTTP §6.1). A sub-foreign carriage failure
  (the request did not reach the NLIP endpoint) is a BRIDGE_ERROR with an N-PAMP
  transport-error code (NPAMP-CC-HTTP §6.2); a receiver that carries NLIP but cannot
  reach an NLIP endpoint MUST NOT report success (NPAMP-BRIDGE §6).

> **Surface note.** Because NLIP encodes intent in natural-language content rather than
> in a method/target namespace, there is nothing operation-specific to enumerate beyond
> the single `POST /nlip` envelope endpoint (and the OPTIONAL upload endpoint). A peer
> carries any NLIP message the endpoint accepts; the published ECMA standards, not this
> table, fix the endpoint set. This is the deliberate design difference between NLIP and
> a method-oriented protocol such as MCP (NPAMP-MAP-MCP) or a multi-operation REST
> protocol such as ACP (NPAMP-MAP-ACP), and it is the reason §7 cannot derive a
> fine-grained effect class from the envelope.

## 5. Session, streaming, and the WebSocket binding

### 5.1 Conversation identity and correlation

NLIP maintains a conversation (session) across multiple exchanges by means of a
`token` submessage whose `subformat` is `conversation`: an endpoint that receives a
token submessage "must include the identical token submessage in the next message sent
to the peer" (ECMA-430; §11). This conversation identity is an **application-layer**
construct that lives **inside** the carried NLIP message. Under this mapping:

- The `token`/`conversation` submessage is carried **verbatim** inside the NLIP
  message and MUST NOT be stripped, rewritten, or mapped onto any N-PAMP envelope or
  routing field.
- The N-PAMP `correlation_id` (NPAMP-BRIDGE §5) correlates a single response or stream
  to its originating request at the transport layer; it is distinct from, and narrower
  than, the NLIP conversation token, which spans many request-response exchanges. A
  sender MUST set a non-empty `correlation_id` on each carried NLIP request and MUST
  echo it on every reply and stream frame; it MUST NOT derive the `correlation_id` from,
  nor conflate it with, the NLIP conversation token.
- NLIP's opaque `authentication` tokens are likewise carried verbatim inside the
  message and are not mapped to any N-PAMP field (§10).

### 5.2 Streaming — synchronous and asynchronous

NLIP requires streaming "in an asynchronous mode as well as a synchronous mode"
(ECMA-430; §11). This mapping carries streamed NLIP replies without a new mechanism:

- **Over the HTTP binding (NPAMP-CC-HTTP).** A streamed HTTP response to `POST /nlip`
  is carried by NPAMP-CC-HTTP's streaming sequence (NPAMP-CC-HTTP §7): an OPTIONAL
  BRIDGE_RESPONSE head carrying the response `status` and headers, then one or more
  BRIDGE_STREAM_DATA (`0x0104`) frames each carrying the next chunk of response-body
  octets in order, terminated by exactly one BRIDGE_STREAM_END (`0x0105`) with the
  BridgeEnvelope `final` bit set, all echoing the request's `correlation_id`. Any HTTP
  response-body framing (for example an event-stream body) is carried verbatim as body
  octets; the carriage MUST NOT lift NLIP messages out of the HTTP body into a distinct
  N-PAMP event framing under this class.
- **Over the WebSocket binding (NPAMP-CC-STREAM).** ECMA-432 defines a real-time,
  bidirectional WebSocket binding using CBOR binary frames with a UTF-8 JSON text-frame
  fallback, with session management, streaming, and error handling (§11). Each NLIP
  message is one **foreign event**; a session of NLIP messages is carried as an ordinary
  NPAMP-CC-STREAM stream: BRIDGE_STREAM_DATA frames each bearing a StreamControl TLV with
  a strictly monotonic per-stream `event_id`, terminated by BRIDGE_STREAM_END, with
  resumption and cancellation inherited unchanged (NPAMP-CC-STREAM §5–§7). Because the
  WebSocket binding is bidirectional, an NLIP WebSocket session is carried as **two
  correlated per-direction streams sharing the exchange `correlation_id`**
  (NPAMP-CC-STREAM §8): the client-to-server and server-to-client directions each have
  an independent `event_id` space and per-direction resume and cancel.
- **Unsolicited messages.** An NLIP message a peer emits that is not a response to an
  outstanding request (for example a server pushing a status update in the ECMA-431
  examples) is carried as **BRIDGE_NOTIFY** (`0x0103`, `corr_len = 0`) when it rides the
  HTTP class, or as an event of the server-to-client stream when it rides the STREAM
  class; in the BRIDGE_NOTIFY case the receiver MUST NOT reply and the sender MUST NOT
  await a reply (NPAMP-BRIDGE §8).

### 5.3 Control and data messages

NLIP separates **control** messages (for example a query of server policy or a
parameter/context negotiation) from **data** messages (the substantive interaction) by
means of an OPTIONAL boolean `control` field; when the field is absent the NLIP
endpoint infers the value from the message content (ECMA-430; §11). This distinction is
carried **transparently**: the `control` field rides inside the NLIP message and the
carriage MUST NOT parse it, act on it, or infer its value from the content. In
particular, a receiver MUST NOT use the `control` field (present or inferred) to
downgrade the SafetyLabel effect class of §7.

## 6. Policy and capability documents

NLIP's control-message facility lets a client query a server's operating policies (for
example privacy or data-retention policies) and negotiate configuration (ECMA-430;
§11). Under this mapping:

- **Default carriage.** A live policy query and its answer are ordinary NLIP messages
  and ride the same carriage class and Bridge channel as the rest of the NLIP session
  (§4, §5, §8); no special framing applies.
- **OPTIONAL document carriage.** Where a deployment publishes NLIP policy or
  capability material as a self-contained **document** for advertisement — rather than
  as a live control-message answer — that document MAY be carried under NPAMP-CC-DOC
  (`24_carriage_documents.md`) and MAY ride the Discovery channel `0x0010` (§8; companion
  index, "Channel selection for carriage"). This is the same treatment NPAMP-MAP-A2A
  gives the A2A AgentCard (`61_map_a2a.md` §7) and NPAMP-MAP-ACP gives the ACP manifest
  (`62_map_acp.md` §6). The live control message remains carriage-class traffic on the
  Bridge channel; a single NLIP session MUST NOT be split across the Bridge and Discovery
  channels.

## 7. SafetyLabel and state-mutating operations

The SafetyLabel TLV (Type `0x0013`) and its fail-safe semantics are governed by
NPAMP-BRIDGE §7. For the HTTP carriage the `effect` is derived from the carried HTTP
method (NPAMP-CC-HTTP §8.1); for the STREAM carriage the SafetyLabel is attached to the
initiating BRIDGE_REQUEST that opens a mutating exchange (NPAMP-CC-STREAM §1.1,
inheriting NPAMP-BRIDGE §7). This section pins that derivation for NLIP.

The decisive NLIP-specific fact is that **NLIP expresses the operation in
natural-language `content`, not in the HTTP method/target or in any machine-readable
per-operation effect declaration.** NLIP therefore gives the carriage **no signal from
which to lighten** the effect class below the method default, and (from the ECMA-431
examples) an NLIP data message can cause arbitrary, consequential real-world action —
dispatching a vehicle, depositing a check, purchasing a ticket. Consequently:

| NLIP operation | Carried method | `effect` (NPAMP-BRIDGE §7) | Rationale |
|---|---|---|---|
| Any NLIP message submitted to `POST /nlip` (HTTP), or the BRIDGE_REQUEST opening an NLIP WebSocket session (STREAM) | POST / stream-open | `0x02` non_idempotent_write (**floor**) | POST is state-mutating (NPAMP-CC-HTTP §8.1); the substantive effect is in the natural-language content and is not machine-declared. This is the minimum; it MUST NOT be loosened (below). |
| An NLIP message the originating NLIP endpoint knows triggers a destructive or irreversible action | POST / stream-open | `0x03` destructive | The mapping MAY tighten (never loosen) when the originating endpoint has application knowledge that the effect is destructive (NPAMP-CC-HTTP §8.1). |
| A `GET` on an OPTIONAL read-only alternate endpoint (ECMA-431 §6.1), where the NLIP server exports one and it is carried (not out-of-band) | GET | `0x00` read_only | A genuine HTTP read; the effect follows the carried method (NPAMP-CC-HTTP §8.1). |

Requirements:

- For every NLIP message it submits as a `POST /nlip` BRIDGE_REQUEST, or as the
  BRIDGE_REQUEST that opens an NLIP WebSocket session, the sender MUST attach a
  SafetyLabel TLV (NPAMP-BRIDGE §7), and an intermediary MUST carry it unchanged.
- The sender MUST NOT loosen the effect class below `0x02` non_idempotent_write for such
  a request: NPAMP-CC-HTTP §8.1 forbids loosening below the POST default, and NLIP
  supplies no machine-readable per-message effect declaration on which a lighter class
  could be grounded. In particular, the OPTIONAL `control` field (§5.3) MUST NOT be used
  to claim `read_only` or `idempotent_write`, because it is optional, is content-inferred
  when absent, and is carried transparently (the carriage MUST NOT parse it).
- A receiver MUST NOT treat the **absence** of a SafetyLabel on an NLIP `POST`/stream-open
  request as `read_only`; absence on such a state-mutating operation MUST be treated as
  `destructive` (fail-safe; NPAMP-BRIDGE §7; NPAMP-CC-HTTP §8.1).
- The SafetyLabel `scope` field MAY carry the request target (`/nlip`) or the NLIP
  conversation token as an advisory resource hint (NPAMP-BRIDGE §7). The label states the
  sender's declared intent; it does not replace the NLIP server's own authorization
  decision, which the receiver MUST enforce at invocation. A receiver MUST NOT treat a
  favorable SafetyLabel as permission (NPAMP-CC-HTTP §8.1).

## 8. Channel selection

| NLIP traffic class | Carriage | Channel |
|---|---|---|
| REST/HTTP messages — `POST /nlip` and its response (§4) | NPAMP-CC-HTTP | Bridge `0x000D` |
| Streamed HTTP response (synchronous/asynchronous; §5.2) | NPAMP-CC-HTTP streaming (§7 of that document) | Bridge `0x000D` |
| WebSocket session of NLIP messages (§5.2) | NPAMP-CC-STREAM | Bridge `0x000D` |
| NLIP policy / capability material carried as a document (§6) | NPAMP-CC-HTTP or NPAMP-CC-STREAM (default) or NPAMP-CC-DOC | Bridge `0x000D` default; MAY use Discovery `0x0010` for material carried as a document |
| Advertising that the peer carries NLIP (§9) | NPAMP-DISC protocol Discovery Record | Discovery `0x0010` |
| Large-binary upload alternate endpoint / `structured`+`uri` dereference (ECMA-431 §6.1; §1.2) | Not carried by this mapping | Out of band (native HTTP) |

Under this mapping a peer carrying an NLIP session MUST carry that session's messages on
the Bridge channel `0x000D`, and MUST NOT split a single NLIP session (one
`correlation_id`, or its two per-direction WebSocket streams sharing one exchange
`correlation_id`) across the Bridge and Discovery channels or across associations.

Two OPTIONAL uses of the Discovery channel `0x0010` are available around, not in place
of, that session:

- **Advertising NLIP as a carried protocol.** A peer MAY advertise, over NPAMP-DISC on
  the Discovery channel `0x0010`, a protocol Discovery Record (`kind = 1`) whose
  `protocol_id` is the agreed NLIP value (§2), whose `carriage_class` is HTTP or STREAM,
  and whose OPTIONAL fields describe the endpoint it carries (NPAMP-DISC §5.1). This
  announces that the peer carries NLIP; it does not carry NLIP traffic. A peer MUST NOT
  advertise NLIP if it cannot in fact carry the NLIP `protocol_id` over the association.
- **Policy/capability documents.** Per §6, NLIP policy or capability material published
  as a self-contained document MAY ride the Discovery channel `0x0010` under NPAMP-CC-DOC.

The Bridge channel `0x000D` and the Discovery channel `0x0010` are both minimum-profile
**Standard** (core specification channel registry; `../../registries/channels.csv`); NLIP
carriage requires no channel above the Standard profile. Where a deployment carries NLIP
purely as agent-to-human user-interface interaction, it MAY additionally use the core
Interaction channel `0x000F` (also Standard) whose purpose is "agent-to-human
user-interface events" (companion index, "Channel selection for carriage"); the Bridge
channel remains the default for protocol encapsulation. A peer MUST NOT send or accept
NLIP frames on a channel it did not advertise during the handshake (core specification
§5).

## 9. Protocol status: confirmed versus unconfirmed

This mapping is authored against NLIP's own published specification and marks precisely
what is grounded in a primary source versus what remains open, per the OPAQUE-READY
posture of the companion index.

**Confirmed from NLIP's primary sources (§11):**

- NLIP is a **ratified Ecma standards suite** (ECMA-430/431/432/433/434, ECMA TR/113),
  approved 10 December 2025 by Ecma TC56.
- The **message format** (ECMA-430): the JSON message with REQUIRED `format`,
  `subformat`, `content`; OPTIONAL `control` (boolean) and `submessages` (array); the
  allowed `format` values `text`, `token`, `structured`, `binary`, `location`,
  `generic`; and the `token`/`conversation` submessage echo that maintains a session.
- The **HTTP binding** (ECMA-431): a fixed well-known endpoint `https://<server>:<port>/nlip`
  that "shall support accepting an NLIP message using the POST command of HTTP," over
  HTTP/1.1 or HTTP/2 (HTTP/3 in validated use cases), with an OPTIONAL alternate endpoint
  for large-binary upload (ECMA-431 §6.1). This fixes the HTTP carriage class
  (NPAMP-CC-HTTP) and the `POST /nlip` operation surface of §4.
- The **WebSocket binding** (ECMA-432): a real-time bidirectional binding using CBOR
  binary frames with a UTF-8 JSON text-frame fallback, with session management,
  streaming, and error handling. This fixes the STREAM carriage class (NPAMP-CC-STREAM)
  and the `content_type` treatment of §2.
- The **request-response paradigm**, the **control/data** separation, and the
  **synchronous/asynchronous streaming** requirement (ECMA-430) mapped in §4–§5.

**Unconfirmed, provisional, or externally dependent:**

- **`protocol_id` is PROVISIONAL.** NPAMP-REG §6 assigns NLIP no code point. Until one is
  assigned under NPAMP-REG §8, NLIP MUST be carried under an out-of-band-agreed
  experimental identifier (`0x10`–`0x7F`; §2). This is the sole reason the mapping is
  OPAQUE-ready rather than settled native DRAFT (§3).
- **Endpoint enumeration beyond `POST /nlip`.** The exact set of OPTIONAL endpoints
  (ECMA-431 §6.1) and the precise ECMA-432 WebSocket endpoint paths are fixed by the
  respective standards; this document pins the confirmed primary endpoint and treats the
  rest transparently (§4, §5). The ECMA-432 endpoint paths cited in §11 are taken from
  Ecma's published description of ECMA-432 rather than from the standard's body, which was
  not read in full here.
- **The AMQP binding (ECMA-433)** is a distinct message-passing transport and is out of
  scope (§1.2); it is carried today via Class OPAQUE, and a native mapping (if wanted)
  would use the message-passing class NPAMP-CC-MSG.
- **Serialization per binding.** NLIP is JSON over the HTTP binding and CBOR (or JSON
  fallback) over the WebSocket binding; a sender MUST declare the encoding it carries in
  `content_type` and MUST NOT assume a fixed default across bindings (§2).

**Limitations of the sources consulted (per research discipline).** The message-format
field set and the request-response/streaming model are grounded in the NLIP authors'
published specification overview and the ECMA-430 description; the HTTP method, endpoint,
and version facts are grounded in the body of ECMA-431 directly (§11); the WebSocket
endpoint paths and CBOR/JSON framing are grounded in Ecma's published description of
ECMA-432 (§11). The full normative bodies of ECMA-430, ECMA-432, ECMA-433, and ECMA-434
were not read line-by-line here; no field, method, or code point in this document is
asserted beyond what the cited sources support, and where a fact was not confirmable from
a primary source it is marked above rather than fixed by assumption.

## 10. Security considerations

This mapping introduces no cryptography and changes none. All confidentiality, integrity,
authentication, downgrade resistance, and replay protection are provided by the core
specification's wire format and key schedule and apply unchanged to every NLIP frame,
which travels inside the AEAD-protected Bridge payload; the `protocol_id`, the HTTP
method/target routing key or StreamControl TLV, the SafetyLabel, and the NLIP message are
authenticated and confidentiality-protected to the same degree.

Carrying NLIP over N-PAMP makes no security claim about NLIP itself. In particular:

- **Transport-bound and profile-bound NLIP security.** NLIP defines opaque
  authentication/authorization tokens (ECMA-430; base64 text) and three progressive
  security profiles (ECMA-434) covering transport security, authentication,
  authorization, prompt-injection prevention, and ethical-by-design requirements. Over
  N-PAMP the NLIP transport hop those elements bind to does not exist: such tokens and
  header fields are carried verbatim but are neither validated nor re-bound by carriage,
  and a receiver MUST NOT infer that a carried credential was verified (NPAMP-CC-HTTP
  §8.3, §8.4). A gateway that re-emits a carried NLIP message onto a real HTTP or
  WebSocket hop is responsible for that hop's own transport security and for applying the
  relevant ECMA-434 profile there.
- **Natural-language content is untrusted input.** An NLIP `content` field is
  attacker-influenceable natural language; ECMA-434 itself calls for prompt-injection
  prevention. The carriage transports the content as opaque octets and never acts on it; a
  receiver MUST treat a carried NLIP message as untrusted input of its declared media type
  and MUST apply its own prompt-injection and authorization controls before acting on it.
  A receiver MUST NOT act on the NLIP `control` flag, or on a `structured`/`uri` content
  reference, as a routing or authorization decision at the carriage layer.
- **Out-of-band exchanges are not performed.** The ECMA-431 large-binary upload endpoint,
  a `structured`/`uri` dereference to an external URI, or any exchange NLIP conducts
  outside the primary endpoint is a separate exchange that leaves the N-PAMP association;
  carriage neither performs nor proxies it, and a receiver MUST NOT assume it occurred as
  a result of carriage (NPAMP-CC-OPAQUE §9.4; §1.2, §6).
- **Safety fail-safe.** The effect classification of §7 and the NPAMP-BRIDGE §7 fail-safe
  (absence of a SafetyLabel on a state-mutating operation is `destructive`) apply to every
  NLIP request. Because NLIP does not machine-declare per-message effect, the POST floor
  and the fail-safe are the operative controls; a favorable SafetyLabel is not permission.

## 11. References

Primary sources (NLIP specification — the confirmed basis for §4–§7):

- Ecma International — "Ecma International approves NLIP standards suite for universal AI
  agent communication" (the ECMA-430/431/432/433/434 and ECMA TR/113 suite, approved
  10 December 2025) —
  <https://ecma-international.org/news/ecma-international-approves-nlip-standards-suite-for-universal-ai-agent-communication/>
- ECMA-431, *Binding of NLIP over HTTP* (1st edition, December 2025) — the well-known
  `https://<server>:<port>/nlip` endpoint, the "POST command of HTTP," HTTP/1.1 / HTTP/2 /
  HTTP/3 base transfer, and the §6.1 optional upload endpoint pinned in §4 —
  <https://ecma-international.org/publications-and-standards/standards/ecma-431/>
- ECMA-432, *Binding of NLIP over WebSocket* (1st edition, December 2025) — the CBOR
  binary framing with UTF-8 JSON text fallback, and the WebSocket endpoints
  (`/nlip/ws` for CBOR, `/nlip/ws/text` for JSON text) with session management, streaming,
  and error handling, referenced in §2, §5 —
  <https://ecma-international.org/publications-and-standards/standards/ecma-432/>
- S. Aiyagari et al., "An Overview of the Natural Language Interaction Protocol" (AAAI-25
  workshop) — the NLIP message fields (`control`, `format`, `subformat`, `content`,
  `submessages`), the allowed `format` values, the `token`/`conversation` echo, the
  request-response paradigm, and the exemplar REST binding to the well-known `/nlip`
  endpoint (§4, §5) —
  <https://www.eecis.udel.edu/~mlm/docs/2025-Aiyagari-AAAI-25-AnOverviewOfTheNaturalLanguageInteractionProtocol-Workshop.pdf>
- NLIP Project — official site and source repositories (`nlip-project.org`;
  `github.com/nlip-project`, including the specification documents repository) —
  <https://nlip-project.org/> and <https://github.com/nlip-project>
- Ecma International — "Call for participation and comments on revised NLIP specification
  and new WebSocket binding" (the revised core specification and the WebSocket binding) —
  <https://ecma-international.org/news/call-for-participation-and-comments-on-revised-nlip-specification-and-new-websocket-binding/>

N-PAMP documents built on:

- draft-bubblefish-npamp-01 — the N-PAMP core specification: the frame format, the
  channel registry (Bridge `0x000D`, Discovery `0x0010`, Interaction `0x000F`), the
  frame-type namespace (channel-specific types from `0x0100`), the extension-TLV
  encoding, and the AEAD payload protection.
- NPAMP-BRIDGE (`10_bridge_framework.md`) — the encapsulation, BridgeEnvelope,
  correlation, structured-error, and SafetyLabel contract.
- NPAMP-CC-HTTP (`21_carriage_http.md`) — the HTTP-semantics carriage class that does the
  structural work for the NLIP HTTP binding.
- NPAMP-CC-STREAM (`23_carriage_streaming.md`) — the streaming carriage class that does
  the structural work for the NLIP WebSocket binding (StreamControl TLV, event-id
  invariant, resumption, cancellation, full-duplex correlation).
- NPAMP-CC-OPAQUE (`25_carriage_opaque.md`) — the zero-mapping carriage that carries NLIP
  today, and the out-of-band / transport-bound honesty statements referenced in §10.
- NPAMP-CC-DOC (`24_carriage_documents.md`) — the document carriage referenced for the
  OPTIONAL policy/capability-document case (§6).
- NPAMP-REG (`30_protocol_registry.md`) — the Bridge Protocol Identifier registry, which
  assigns NLIP no code point (the PROVISIONAL status of §2, §9) and defines the
  experimental range and `ProtocolUnsupported` handling.
- NPAMP-DISC (`40_discovery.md`) — the Discovery-channel advertisement referenced in §6, §8.
- NPAMP-MAP-ACP (`62_map_acp.md`) and NPAMP-MAP-A2A (`61_map_a2a.md`) — the HTTP-class and
  document-as-capability precedents referenced in §4, §6.
- BCP 14 (RFC 2119, RFC 8174) — requirement key words.
- RFC 8949 — Concise Binary Object Representation (CBOR), the ECMA-432 binary frame
  encoding and the NPAMP-CC-HTTP object encoding referenced in §2.
- RFC 7230, RFC 9113, RFC 9114 — HTTP/1.1, HTTP/2, and HTTP/3, the ECMA-431 base transfer
  protocols referenced in §4; RFC 7240 (Prefer header) is normatively referenced by
  ECMA-431.

## 12. Conformance

An implementation conforms to NPAMP-MAP-NLIP if and only if it conforms to NPAMP-CC-HTTP
and NPAMP-CC-STREAM (and therefore to NPAMP-BRIDGE) and, for NLIP traffic, it:

1. Carries every NLIP message octet-for-octet under an out-of-band-agreed experimental
   `protocol_id` (`0x10`–`0x7F`) because NPAMP-REG assigns NLIP none, never emitting NLIP
   under a `protocol_id` assigned to another protocol, sets `content_type` to `0x02` for
   the HTTP-Carriage Object container and to the encoding actually carried (`0x01` or
   `0x02`) for a WebSocket-binding NLIP event, and selects NLIP solely from `protocol_id`,
   never from another envelope field (§2, §3);
2. Treats the mapping as OPAQUE-ready — carrying NLIP via Class OPAQUE where a native
   binding is not yet agreed — and does not assume cross-implementation interoperability of
   §4–§8 until a `protocol_id` is assigned under NPAMP-REG §8 (§3, §9);
3. Maps the NLIP HTTP binding onto NPAMP-CC-HTTP — a `POST /nlip` submission to
   BRIDGE_REQUEST with the method token and target in the HTTP-Carriage Object and
   reflected in the BridgeEnvelope `method` routing key, a non-streamed response to
   BRIDGE_RESPONSE, a streamed response to the NPAMP-CC-HTTP streaming sequence, and a
   sub-foreign carriage failure to BRIDGE_ERROR with an N-PAMP transport-error code — and
   carries an NLIP `4xx`/`5xx` HTTP response as a BRIDGE_RESPONSE preserving the foreign
   status and body verbatim, never fabricating an HTTP status for a carriage failure
   (§4; NPAMP-CC-HTTP §6);
4. Maps the NLIP WebSocket binding onto NPAMP-CC-STREAM — an NLIP session as a stream (or,
   bidirectionally, two correlated per-direction streams sharing one exchange
   `correlation_id`) of BRIDGE_STREAM_DATA frames bearing the StreamControl TLV and a
   strictly monotonic `event_id`, terminated by BRIDGE_STREAM_END, with resumption and
   cancellation per NPAMP-CC-STREAM — and carries an unsolicited NLIP message as
   BRIDGE_NOTIFY (`corr_len = 0`) or as a server-to-client stream event as applicable
   (§5);
5. Carries the NLIP `token`/`conversation` submessage, the `authentication` token, and
   the `control` field verbatim inside the NLIP message, sets and echoes a non-empty
   N-PAMP `correlation_id` on each request without conflating it with the NLIP
   conversation token, and does not act on the `control` field at the carriage layer
   (§5);
6. Attaches a SafetyLabel with `effect` at least `0x02` non_idempotent_write to every NLIP
   `POST /nlip` request and every BRIDGE_REQUEST that opens an NLIP WebSocket session,
   never loosening below that floor and never using the `control` field to downgrade it,
   tightening to `0x03` destructive where the originating endpoint knows the effect is
   destructive, and treats a missing SafetyLabel on such a request as `destructive`
   (NPAMP-BRIDGE §7 fail-safe), never treating a favorable SafetyLabel as authorization
   (§7);
7. Carries an NLIP session's traffic on the Bridge channel `0x000D`, does not split a
   single NLIP session across channels or associations, and uses the Discovery channel
   `0x0010` only for the OPTIONAL protocol advertisement (NPAMP-DISC) or policy/capability
   document carriage (NPAMP-CC-DOC) of §6 and §8 — MAY additionally use the Interaction
   channel `0x000F` for agent-to-human NLIP interaction — never splitting live NLIP
   session traffic across channels (§6, §8); and
8. Does not apply NLIP's native HTTP, WebSocket, or AMQP transport bindings and adds no
   `Sec-WebSocket-Protocol` upgrade or NLIP-version N-PAMP header, does not perform the
   ECMA-431 large-binary upload or a `structured`/`uri` dereference as part of carriage,
   conveys the NLIP media type only via `content_type` and the NLIP version only inside
   the carried messages, and carries no NLIP conversation/session state across
   associations (§8, §10), defining no new frame type, TLV, or code point (§1.2, §2).

A conformance test suite SHOULD assert each clause above with recorded exchanges that
include: a `POST /nlip` submission of a `format:text` NLIP message carried as
BRIDGE_REQUEST with a `non_idempotent_write` SafetyLabel, and a second `POST /nlip` with
the SafetyLabel omitted, verified to be treated as `destructive`; the NLIP response
carried as BRIDGE_RESPONSE with a `token`/`conversation` submessage preserved verbatim; a
streamed NLIP response carried as the NPAMP-CC-HTTP streaming sequence terminated by
BRIDGE_STREAM_END with the `final` bit set; a WebSocket-binding NLIP session carried as a
NPAMP-CC-STREAM stream (including a full-duplex exchange of two correlated per-direction
streams) with `event_id` monotonicity, resumption, and cancellation exercised; an
unsolicited NLIP status message carried as BRIDGE_NOTIFY with no reply; and an NLIP HTTP
error response carried as a BRIDGE_RESPONSE with its status and body preserved verbatim.
