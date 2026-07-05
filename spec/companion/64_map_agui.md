# NPAMP-MAP-AGUI — Agent-User Interaction Protocol (AG-UI) Mapping (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document defines the carriage of the **Agent-User Interaction Protocol
> (AG-UI)**, an event-stream agent-to-frontend protocol, over an N-PAMP association.
> It is a **thin mapping** over the streaming carriage class **NPAMP-CC-STREAM**
> (`23_carriage_streaming.md`): the carriage class does the structural work —
> multi-event replies over `BRIDGE_STREAM_DATA`/`BRIDGE_STREAM_END`, the per-stream
> `event_id` invariant, resumption, and cancellation — and this document pins only
> what is specific to AG-UI. It builds on NPAMP-CC-STREAM, on NPAMP-BRIDGE
> (`10_bridge_framework.md`), and on the N-PAMP core specification
> (draft-bubblefish-npamp-01, the "core specification"). It consumes only code points
> those documents already reserve and introduces no change to the core wire format,
> to NPAMP-BRIDGE, or to NPAMP-CC-STREAM.

## 1. Scope

### 1.1 In scope

This document specifies how AG-UI messages are carried over an N-PAMP association. It
defines, and only defines, the AG-UI-specific facts a peer needs in order to carry
AG-UI under NPAMP-CC-STREAM:

- The (provisional) `protocol_id` for AG-UI and its carriage class (§2);
- The AG-UI operation surface — the single client-to-agent **run** request and the
  agent-to-client **event stream** — and its mapping onto NPAMP-BRIDGE frame types and
  `message_kind` values (§4);
- How an AG-UI run's lifecycle — `RUN_STARTED` … `RUN_FINISHED`/`RUN_ERROR`, and the
  in-stream events between them — rides the carriage, and how run resumption and
  cancellation reuse the NPAMP-CC-STREAM mechanisms (§5);
- Which AG-UI operations are state-mutating and therefore the SafetyLabel effect class a
  sender attaches, including the fail-safe on absence (§6); and
- Channel selection: the Bridge channel `0x000D` as the default carriage substrate, the
  correspondence to the Interaction channel `0x000F`, and the OPTIONAL use of the
  Discovery channel `0x0010` (§7).

### 1.2 Not in scope

The following are explicitly NOT defined by this document, because NPAMP-CC-STREAM,
NPAMP-BRIDGE, or AG-UI's own specification already define them:

- The structural streaming carriage — the mapping of a run's reply onto a sequence of
  `BRIDGE_STREAM_DATA` frames terminated by one `BRIDGE_STREAM_END`, the per-stream
  `event_id` invariant, the StreamControl TLV, the resume protocol, and the stream-cancel
  protocol. These are inherited from NPAMP-CC-STREAM (§4–§9 of that document) and are not
  restated here (§3).
- The semantics, field schemas, or payloads of any AG-UI event or of the `RunAgentInput`
  request body. Those are fixed by AG-UI's own specification and are carried
  transparently; this document does not summarize, validate, or re-encode them.
- AG-UI's own transport bindings — the reference HTTP binding (an HTTP `POST` of a
  `RunAgentInput` and a Server-Sent Events reply, `Content-Type: text/event-stream`), the
  WebSocket binding, webhooks, and the optional binary serialization. Over N-PAMP the
  transport is N-PAMP; those bindings do not apply (§8).
- Any change to the N-PAMP frame format, to the NPAMP-BRIDGE frame types, to the
  BridgeEnvelope, StreamControl, or SafetyLabel TLVs, or to the NPAMP-CC-STREAM rules.
- The assignment of a standards-range `protocol_id`. AG-UI has none in NPAMP-REG §6 at the
  time of writing; this document uses an experimental value provisionally (§2) and does
  not register a code point.

## 2. Protocol identity

| Property | Value |
|---|---|
| Protocol | Agent-User Interaction Protocol (AG-UI). |
| `protocol_id` | **`0x35` — PROVISIONAL.** AG-UI has no standards-assigned code point in the Bridge Protocol Identifier registry (NPAMP-REG §6). `0x35` lies in the experimental range `0x10`–`0x7F` (NPAMP-REG §4, §7.1); it carries **no** cross-domain meaning, requires out-of-band agreement between peers, and MUST be retired in favour of a standards-assigned value obtained under NPAMP-REG §8 when AG-UI carriage is ready for general interoperation. |
| Carriage class | STREAM (NPAMP-CC-STREAM). |
| `content_type` | `0x01` (application/json) for the canonical JSON encoding of both the `RunAgentInput` request body and the AG-UI events. A deployment that uses AG-UI's optional binary/Protobuf serialization sets `content_type` accordingly (`0x02` application/cbor or `0x03` application/grpc+proto); this document pins the JSON default. |
| Foreign-message form | For the run request: one `RunAgentInput` JSON object, carried octet-for-octet as the foreign message. For each stream frame: one AG-UI event object (a `BaseEvent`, discriminated by its `type` field), carried octet-for-octet (NPAMP-BRIDGE §1; NPAMP-CC-STREAM §1.1). |

A sender MUST set `protocol_id = 0x35` on every Bridge frame carrying an AG-UI message
**only under out-of-band agreement with the peer** (NPAMP-REG §7.1). A receiver that does
not carry AG-UI MUST reply to a BRIDGE_REQUEST bearing `0x35` with `ProtocolUnsupported`
(NPAMP-BRIDGE §6; NPAMP-REG §9), and MUST NOT infer AG-UI from any other envelope field.
Because `0x35` is experimental, an implementation MUST NOT ship a production default that
emits it toward a peer with which it has no such agreement (NPAMP-REG §7.1).

> **Maturity note.** The AG-UI transport model relied on below — a run request that yields
> an ordered stream of typed JSON events — is **confirmed** against AG-UI's current
> published specification and reference SDK (§9). What is **not** confirmed is a
> cross-domain `protocol_id`: none is assigned, so the code point above is provisional.
> Until a peer supports this native STREAM mapping and a code point is agreed or
> registered, AG-UI remains carriable today via **Class OPAQUE** (NPAMP-CC-OPAQUE) under a
> privately agreed `protocol_id`, with the AG-UI events carried as an opaque
> `application/json` payload and none of the AG-UI-specific structure of §4–§6 applied.

## 3. Relationship to NPAMP-CC-STREAM and NPAMP-BRIDGE

AG-UI is an event-stream protocol: a client asks an agent to run, and the agent's reply is
a sequence of typed events rather than a single message. This is exactly the shape
NPAMP-CC-STREAM carries, so the entire structural carriage of AG-UI is provided by
NPAMP-CC-STREAM without modification:

- The transparency rule governs: a `RunAgentInput` object and every AG-UI event object are
  carried octet-for-octet and MUST NOT be re-serialized, reordered, canonicalized, or
  rewritten (NPAMP-BRIDGE §1; NPAMP-CC-STREAM §1.1).
- A run's event stream is a single NPAMP-CC-STREAM **stream**: a sequence of
  `BRIDGE_STREAM_DATA` frames terminated by exactly one `BRIDGE_STREAM_END`, all echoing
  the run request's `correlation_id` (NPAMP-CC-STREAM §2, §4). Correlation of the stream to
  its run request is the NPAMP-BRIDGE §5 `correlation_id` mechanism, inherited unchanged;
  this document adds no correlation rule.
- Each stream frame carries a StreamControl TLV whose strictly-monotonic `event_id`
  (NPAMP-CC-STREAM §5) orders the AG-UI events within the run. AG-UI events are inherently
  ordered within a run, which satisfies the event-id invariant; this document does not
  redefine `event_id`, resumption (§6 of that document), or cancellation (§7 of that
  document).
- An AG-UI error surfaced **within** a run — a `RUN_ERROR` event — is a foreign event and
  is carried verbatim as an ordinary stream event (§4.2), **not** collapsed into an N-PAMP
  transport error. Only a failure *below* AG-UI — a malformed envelope, an uncarried
  `protocol_id`, or non-delivery of the run request — is reported as a BRIDGE_ERROR
  transport error (NPAMP-BRIDGE §6; §4.3).

This document therefore pins only AG-UI specifics (§2, §4, §5, §6, §7). Where this
document and NPAMP-CC-STREAM could appear to differ on a structural matter, NPAMP-CC-STREAM
governs.

## 4. AG-UI operation surface and frame mapping

AG-UI's operation surface is small and asymmetric: a client initiates a **run**, and the
agent replies with an ordered **event stream**. AG-UI's own client interface expresses this
as a single method, `run(input: RunAgentInput) -> stream of BaseEvent`. This document pins
the operation label and the frame mapping; the event vocabulary inside the stream is
carried transparently.

### 4.1 The run request (client → agent)

A run is a single request that expects a streamed reply. It is carried as **BRIDGE_REQUEST**
(`0x0100`, `message_kind = 0x01`) whose foreign message is the `RunAgentInput` JSON object,
bearing a non-empty `correlation_id` (NPAMP-BRIDGE §5). Because AG-UI names a single
client-to-agent operation, the BridgeEnvelope `method` field is set to the fixed operation
label **`run`** (`method_len = 3`); this label is drawn from AG-UI's own `run(input)`
interface, since AG-UI's HTTP binding identifies the operation by endpoint rather than by an
in-payload method name and there is no method member to carry verbatim.

The `RunAgentInput` object carries AG-UI's run parameters — including `threadId`, `runId`,
`messages`, `tools`, `context`, `state`, and `forwardedProps` — inside the foreign message;
this mapping neither reads nor rewrites them. `threadId` and `runId` are AG-UI application
identifiers and are distinct from, and MUST NOT be conflated with, the NPAMP-BRIDGE
`correlation_id`, which is the sole reply-correlation token (§3).

The agent's reply to the run is the event stream of §4.2; there is no single
`BRIDGE_RESPONSE` for a run.

### 4.2 The event stream (agent → client)

The agent's reply is a stream under NPAMP-CC-STREAM. Each AG-UI event is carried as one
**BRIDGE_STREAM_DATA** frame (`0x0104`, `message_kind = 0x05`) whose foreign message is that
event's JSON object, echoing the run request's `correlation_id` and carrying a StreamControl
TLV with the next `event_id` (NPAMP-CC-STREAM §5). The stream is terminated by exactly one
**BRIDGE_STREAM_END** frame (`0x0105`, `message_kind = 0x06`, `final` set), whose `event_id`
exceeds that of every data frame of the run (NPAMP-CC-STREAM §5.1).

The AG-UI event `type` discriminator lives **inside** the carried event object and is
carried verbatim; a carrying peer MUST NOT copy it into, or select on it from, the
BridgeEnvelope `method` field, which is `method_len = 0` on stream frames (NPAMP-BRIDGE §4).
The event types AG-UI defines at the time of writing are enumerated below for orientation
only; the carriage selects nothing on them:

| AG-UI event `type` | Group | Purpose (AG-UI) |
|---|---|---|
| `RUN_STARTED` | Lifecycle | Marks the start of a run; carries `threadId`/`runId`. |
| `RUN_FINISHED` | Lifecycle | Marks successful completion of a run. |
| `RUN_ERROR` | Lifecycle | Reports an error during a run (in-stream foreign error; §4.3). |
| `STEP_STARTED` | Lifecycle | Marks the start of a named step within a run. |
| `STEP_FINISHED` | Lifecycle | Marks the completion of a step. |
| `TEXT_MESSAGE_START` | Text | Begins a streamed assistant text message. |
| `TEXT_MESSAGE_CONTENT` | Text | A `delta` chunk of message text. |
| `TEXT_MESSAGE_END` | Text | Ends a streamed text message. |
| `TEXT_MESSAGE_CHUNK` | Text | Convenience event (start/content/end in one). |
| `THINKING_TEXT_MESSAGE_START` | Text (thinking) | Begins a streamed "thinking" text message. |
| `THINKING_TEXT_MESSAGE_CONTENT` | Text (thinking) | A chunk of "thinking" text. |
| `THINKING_TEXT_MESSAGE_END` | Text (thinking) | Ends a "thinking" text message. |
| `THINKING_START` | Text (thinking) | Begins a thinking phase. |
| `THINKING_END` | Text (thinking) | Ends a thinking phase. |
| `TOOL_CALL_START` | Tool | The agent begins invoking a tool. |
| `TOOL_CALL_ARGS` | Tool | A chunk of streamed tool-call arguments. |
| `TOOL_CALL_END` | Tool | Completes a tool-call specification. |
| `TOOL_CALL_CHUNK` | Tool | Convenience event (start/args/end in one). |
| `TOOL_CALL_RESULT` | Tool | Delivers the result of a previously invoked tool. |
| `STATE_SNAPSHOT` | State | A complete snapshot of the agent's shared state. |
| `STATE_DELTA` | State | An incremental state update (JSON Patch, RFC 6902). |
| `MESSAGES_SNAPSHOT` | State | A complete snapshot of the conversation messages. |
| `ACTIVITY_SNAPSHOT` | Activity | A complete snapshot of an activity message. |
| `ACTIVITY_DELTA` | Activity | An incremental activity update (JSON Patch). |
| `REASONING_START` | Reasoning | Begins a reasoning process. |
| `REASONING_MESSAGE_START` | Reasoning | Begins a streamed reasoning message. |
| `REASONING_MESSAGE_CONTENT` | Reasoning | A chunk of reasoning text. |
| `REASONING_MESSAGE_END` | Reasoning | Ends a reasoning message. |
| `REASONING_MESSAGE_CHUNK` | Reasoning | Convenience reasoning event. |
| `REASONING_END` | Reasoning | Ends a reasoning context. |
| `REASONING_ENCRYPTED_VALUE` | Reasoning | Carries an encrypted chain-of-thought value (opaque to the carriage). |
| `RAW` | Special | A container for an event from an external system. |
| `CUSTOM` | Special | An extension event for features outside the standard set. |

> **Revision note.** The event set above is AG-UI's `EventType` enumeration at the time of
> writing (§9). AG-UI is an evolving protocol and MAY add, rename, or remove event types.
> Because the carriage is transparent over the event `type` (§3), a peer carries a newer or
> older AG-UI event set without a change to this mapping. An implementation MUST NOT reject
> an AG-UI event solely because its `type` is absent from the table above.

### 4.3 Errors: foreign versus transport

An AG-UI `RUN_ERROR` event is a foreign message and MUST be carried verbatim as a
`BRIDGE_STREAM_DATA` event (or as the terminal event immediately preceding
`BRIDGE_STREAM_END`); it MUST NOT be reduced to free text and MUST NOT be remapped to an
N-PAMP transport error (NPAMP-BRIDGE §6). This is distinct from a failure *below* AG-UI —
a missing or malformed envelope (`EnvelopeMalformed`), an uncarried `protocol_id`
(`ProtocolUnsupported`), or a run request that could not be delivered to an AG-UI endpoint
(`NotDelivered`) — which is reported as a BRIDGE_ERROR carrying the N-PAMP transport error
(NPAMP-BRIDGE §6). AG-UI's connection-level HTTP status errors (for example `401`
`UNAUTHORIZED`, `400` `VALIDATION_ERROR`) belong to AG-UI's HTTP binding, which does not
apply over N-PAMP; the N-PAMP association supplies authentication and the transport-error
model in their place (§8).

## 5. Run lifecycle, resumption, and cancellation

An AG-UI run is a stateful, bounded episode carried entirely as ordinary AG-UI traffic with
no special framing beyond the NPAMP-CC-STREAM mechanisms:

1. The client sends the run **Request** (`RunAgentInput`) as a BRIDGE_REQUEST (§4.1).
2. The agent replies with an event **stream** (§4.2) that opens with `RUN_STARTED`, carries
   any number of step, text, tool, state, activity, and reasoning events, and closes with a
   terminal `RUN_FINISHED` or `RUN_ERROR` event; the stream itself is terminated by
   `BRIDGE_STREAM_END` (NPAMP-CC-STREAM §5.1).
3. Tool results and user responses are delivered to the agent as inputs to a **subsequent**
   run: the client executes any client-side tool the agent requested (via `TOOL_CALL_*`
   events) and issues a new run BRIDGE_REQUEST whose `RunAgentInput.messages` carry the
   result. Each such follow-up run is an independent stream under §4.

Constraints specific to AG-UI that a carrying peer MUST preserve, all satisfied by carrying
the objects transparently and in order:

- **Ordering.** The N-PAMP per-channel sequence space delivers frames on the Bridge channel
  in order per direction (core specification §5), and the NPAMP-CC-STREAM `event_id`
  invariant fixes the AG-UI event order within a run (§3). The carriage MUST NOT reorder a
  run's events.
- **One run per stream.** All events of one AG-UI run are carried on one stream (one
  `correlation_id`); this mapping does not split a single run across streams or associations.
- **Resumption.** If an association migrates or a stream is re-established mid-run, a
  consumer resumes the run using the NPAMP-CC-STREAM resume request (that document's §6),
  supplying the `event_id` of the last event it durably consumed; a producer that advertised
  the stream `resumable` resumes, restarts, or refuses (`NotResumable`) per NPAMP-CC-STREAM
  §6.3. Whether AG-UI's optional Server-Sent-Events `Last-Event-ID` reconnection is mapped
  onto the N-PAMP resume cursor is a transport-binding matter and is OPTIONAL; the N-PAMP
  `event_id` is authoritative for resumption over N-PAMP.
- **Cancellation.** A client that cancels a run uses the NPAMP-CC-STREAM stream cancel (that
  document's §7): an upstream `BRIDGE_STREAM_END` with `control = cancel`, to which the
  agent responds by ceasing production and acknowledging with a single `cancel_ack`
  `BRIDGE_STREAM_END`. A cancelled run is not an error (NPAMP-CC-STREAM §7.3).

## 6. SafetyLabel and state-mutating operations

The SafetyLabel TLV (Type `0x0013`) and its fail-safe semantics are governed by
NPAMP-BRIDGE §7 and inherited through NPAMP-CC-STREAM unchanged. This section fixes, for
AG-UI, which operations a sender MUST label and how.

Starting an AG-UI run is a state-mutating action: the agent executes, MAY invoke tools with
arbitrary external effect, and MAY mutate the client's shared state (`STATE_DELTA`,
`STATE_SNAPSHOT`). AG-UI declares no per-run or per-tool effect annotation on the wire.
Therefore a sender MUST attach a SafetyLabel TLV to every run BRIDGE_REQUEST it originates,
an intermediary MUST carry it unchanged, and — the fail-safe — a receiver MUST NOT treat the
**absence** of a SafetyLabel on a run as `read_only`; absence MUST be treated as
`destructive` (NPAMP-BRIDGE §7).

### 6.1 Effect class by operation

| AG-UI operation | Effect (NPAMP-BRIDGE §7) | Rationale |
|---|---|---|
| Run request (`run`) — default | `0x02` non_idempotent_write, **or** `0x03` destructive as the fail-safe | Running an agent is a fresh action with observable effect (tool invocations, shared-state mutation); repeating the same input runs the agent again. Because AG-UI carries no effect annotation and a run MAY invoke tools of arbitrary or destructive effect, a sender that cannot bound the effect from deployment knowledge MUST label the run `destructive`. |
| Run request (`run`) — bounded deployment | `0x00` read_only or `0x01` idempotent_write | A deployment MAY use a narrower effect **only** when it can guarantee the agent's behaviour for the run — for example a pure text-generation agent that invokes no tool and mutates no state (`read_only`), or a run whose only effect is an idempotent state write. The narrower label MUST reflect the actual effect; a favourable label is never a substitute for authorization (§6.2). |
| Stream resume request (NPAMP-CC-STREAM §6) | Same class as the run it resumes | A resume is a fresh BRIDGE_REQUEST and carries the same SafetyLabel obligation as the original run (NPAMP-CC-STREAM §12). |
| Event-stream frames (`BRIDGE_STREAM_DATA`) | None | Stream data frames are the reply to a run, not requests; NPAMP-BRIDGE §7 attaches SafetyLabels to requests. The mutations an agent performs (tool calls, `STATE_DELTA`) are effects of the run and are covered by the run request's label. |
| Stream cancel (NPAMP-CC-STREAM §7) | None | A cancel stops future production; it is not a state-mutating request and is not an error (NPAMP-CC-STREAM §7.3). |

The SafetyLabel `scope` field (NPAMP-BRIDGE §7) MAY carry the AG-UI `threadId` or an agent
identifier as an advisory resource hint. Where a deployment uses AG-UI's WebSocket
bidirectional binding and the agent issues a distinct reverse **request** to the client
(rather than an in-stream `TOOL_CALL_*` event) to perform a client-side action with side
effect, that reverse BRIDGE_REQUEST is itself state-mutating and MUST carry its own
SafetyLabel under this section, in the reverse direction (NPAMP-BRIDGE §5).

### 6.2 The label is not authorization

The SafetyLabel "describes intent and does not replace authorization" (NPAMP-BRIDGE §7). A
receiver MUST enforce its own authorization at the point it starts a run or executes a
tool, and MUST NOT treat a favourable (for example `read_only`) SafetyLabel as permission.
The label conveys the sender's declared intent; it is not a security guarantee about what
the agent will do.

## 7. Channel selection

AG-UI traffic rides the **Bridge channel `0x000D`** by default, because the NPAMP-BRIDGE and
NPAMP-CC-STREAM framing this mapping depends on — the BridgeEnvelope TLV, the StreamControl
TLV, and the `0x0100`+ Bridge frame types — is defined on that channel (NPAMP-CC-STREAM §1;
NPAMP-BRIDGE §1, §2). Under this mapping, a peer carrying an AG-UI run MUST carry that run's
request and event stream on the Bridge channel.

AG-UI's purpose — agent-to-human user-interface events — corresponds precisely to the core
**Interaction channel `0x000F`** ("Agent-to-human user-interface events";
`../../registries/channels.csv`). Per the channel-selection guidance of the companion index
("Channel selection for carriage") and the Bridge channel reference
(`../channels/000D_bridge.md` §6), a deployment MAY carry AG-UI traffic on the Interaction
channel `0x000F` instead of, or in addition to, the Bridge channel where its deployment
model aligns AG-UI with that channel's purpose. The core specification defines **no** native
AG-UI operation encoding on `0x000F`; a deployment that carries AG-UI there still carries it
under the NPAMP-BRIDGE/NPAMP-CC-STREAM framing of this mapping, not under a distinct
Interaction-channel encoding. A single AG-UI run MUST NOT be split across the Bridge and
Interaction channels.

One OPTIONAL use of the Discovery channel `0x0010` is available around, not in place of, an
AG-UI run: a peer MAY advertise, over NPAMP-DISC on the Discovery channel `0x0010`, a
protocol Discovery Record whose `protocol_id` is the agreed AG-UI value and whose
`carriage_class` is STREAM, announcing that it carries AG-UI (NPAMP-DISC §5.1). This
advertises AG-UI carriage; it does not carry AG-UI traffic. A peer MUST NOT advertise AG-UI
if it cannot in fact carry the AG-UI `protocol_id` over the association (NPAMP-DISC §5.1),
and — because that `protocol_id` is experimental (§2) — MUST scope the advertisement to a
peer with which it has out-of-band agreement on the value (NPAMP-REG §7.1).

## 8. Transport-binding and version notes

AG-UI defines a reference HTTP binding (an HTTP `POST` of a `RunAgentInput` followed by a
Server-Sent Events reply, `Content-Type: text/event-stream`), a WebSocket binding, webhook
delivery, and an optional binary serialization. Over N-PAMP, **N-PAMP is the transport**:
None of these AG-UI transport bindings applies, and there is no SSE framing, HTTP status
code, or `Last-Event-ID` header at the N-PAMP layer. The run request and the event stream
are carried as N-PAMP frames (§4), and the AG-UI JSON objects are carried verbatim within
them. The N-PAMP association supplies authentication, post-quantum confidentiality and
integrity, multiplexing, ordered per-channel delivery, resumption, and the key schedule
(core specification); these replace, and are not layered on top of, AG-UI's transport
bindings.

AG-UI is versioned by its published specification and SDK, and its event vocabulary evolves
(§4.2). Because the carriage is transparent (§3), a peer carries any AG-UI version without a
change to this mapping; only §4.2's illustrative table and §6's effect-class guidance track
the specific event set named in §9. AG-UI run state (a `threadId`/`runId` and the shared
`state`) is AG-UI application state carried inside the foreign messages; a peer MUST NOT
derive it from, or store it in, any N-PAMP envelope field, and MUST NOT carry AG-UI run
state across associations by any means other than the AG-UI messages themselves.

## 9. References

Normative for the carriage:

- draft-bubblefish-npamp-01 — the N-PAMP core specification (Bridge channel `0x000D`,
  Interaction channel `0x000F`, Discovery channel `0x0010`, the frame format, the
  BridgeEnvelope and SafetyLabel TLV reservations, and AEAD payload protection).
- NPAMP-BRIDGE (`10_bridge_framework.md`) — the encapsulation, correlation, error, and
  SafetyLabel contract.
- NPAMP-CC-STREAM (`23_carriage_streaming.md`) — the streaming carriage class that does the
  structural work for AG-UI (stream framing, `event_id` invariant, resumption, cancellation,
  StreamControl TLV).
- NPAMP-REG (`30_protocol_registry.md`) — the Bridge Protocol Identifier registry; AG-UI has
  no standards-assigned code point, and the experimental-range rules (§4, §7.1) govern the
  provisional `protocol_id` of §2.
- NPAMP-DISC (`40_discovery.md`) and NPAMP-CC-OPAQUE (`25_carriage_opaque.md`) — the
  Discovery-channel advertisement and the Class OPAQUE fallback referenced in §2 and §7.
- BCP 14: RFC 2119 and RFC 8174 — requirement key words.
- RFC 6902 — JSON Patch, the format AG-UI's `STATE_DELTA`/`ACTIVITY_DELTA` events carry
  (referenced by AG-UI; carried verbatim here).

AG-UI source specification (primary sources consulted for §2, §4, §5, §6; the confirmed
transport and event model):

- AG-UI documentation — Core architecture (the `run(input: RunAgentInput) -> stream of
  BaseEvent` interface; transport-agnostic delivery over SSE, WebSockets, webhooks, and an
  optional binary protocol) — <https://docs.ag-ui.com/concepts/architecture>
- AG-UI documentation — Events (the event categories and the `BaseEvent` schema:
  `type`, optional `timestamp`, optional `rawEvent`) — <https://docs.ag-ui.com/concepts/events>
- AG-UI SDK — `EventType` enumeration (the verbatim event-type string values enumerated in
  §4.2) — <https://raw.githubusercontent.com/ag-ui-protocol/ag-ui/main/sdks/python/ag_ui/core/events.py>
- AG-UI repository (the protocol overview: "the Agent-User Interaction Protocol", an
  event-based protocol with a reference HTTP implementation) —
  <https://github.com/ag-ui-protocol/ag-ui>
- AWS Bedrock AgentCore — AG-UI protocol contract (an independent confirmation of the wire
  contract: an `/invocations` `POST` of a `RunAgentInput` — `threadId`, `runId`, `messages`,
  `tools`, `context`, `state`, `forwardedProps` — and an SSE reply of JSON events, with
  `RUN_ERROR` delivered in-stream) —
  <https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-agui-protocol-contract.html>

Confirmed versus unconfirmed, stated plainly (anti-shortcut-research discipline): AG-UI's
event-stream transport model, its `RunAgentInput` request shape, its `BaseEvent` schema, and
its `EventType` set are **confirmed** against the sources above and are sufficient to pin the
STREAM mapping of §4–§6. What is **unconfirmed** is a cross-domain `protocol_id` — none is
assigned in NPAMP-REG §6 — so the `0x35` of §2 is provisional and experimental; and the
mapping of AG-UI's optional SSE `Last-Event-ID` onto the N-PAMP resume cursor is left
OPTIONAL (§5) rather than pinned, because AG-UI does not require an in-band SSE `id` field.
Until a code point is agreed or registered, AG-UI is carriable today via Class OPAQUE (§2).

## 10. Conformance

An implementation conforms to NPAMP-MAP-AGUI if and only if it conforms to NPAMP-CC-STREAM
(and therefore to NPAMP-BRIDGE) and, for AG-UI traffic, it:

1. Carries every AG-UI `RunAgentInput` and every AG-UI event under the agreed AG-UI
   `protocol_id` (provisionally `0x35`, experimental, used only under out-of-band agreement)
   with `content_type = 0x01` for the JSON encoding, octet-for-octet, and selects AG-UI
   solely from `protocol_id`, never from another envelope field (§2, §3);
2. Maps a run onto NPAMP-BRIDGE frames per §4 — the `RunAgentInput` to a BRIDGE_REQUEST
   (`message_kind = 0x01`) with the BridgeEnvelope `method` set to `run`, and the reply to a
   sequence of BRIDGE_STREAM_DATA events (`message_kind = 0x05`) terminated by one
   BRIDGE_STREAM_END (`message_kind = 0x06`, `final` set), all echoing the run request's
   `correlation_id` — and leaves the AG-UI event `type` inside the carried event, with
   `method_len = 0` on stream frames (§4.1, §4.2);
3. Carries a `RUN_ERROR` event verbatim as an in-stream foreign event and does not remap it
   to an N-PAMP transport error, while reporting a failure below AG-UI (`EnvelopeMalformed`,
   `ProtocolUnsupported`, `NotDelivered`) as a BRIDGE_ERROR transport error, never reporting
   success for an undelivered run request (§3, §4.3);
4. Carries all events of one run on one stream (one `correlation_id`) in order, does not
   split a run across streams or associations, and neither reads, synthesizes, filters, nor
   rewrites `RunAgentInput` or any event field (§4, §5);
5. Supports run resumption and cancellation through the NPAMP-CC-STREAM mechanisms — a resume
   request carrying the last durably consumed `event_id`, and a stream cancel via an upstream
   BRIDGE_STREAM_END with `control = cancel` acknowledged by a single `cancel_ack`
   BRIDGE_STREAM_END — and treats a cancelled run as normal completion, not an error (§5);
6. Attaches a SafetyLabel to every run BRIDGE_REQUEST it originates (and to every stream
   resume request), using `0x02` non_idempotent_write or `0x03` destructive by default and a
   narrower class only where the deployment can guarantee the run's effect, and treats a
   missing SafetyLabel on a run as `destructive` (NPAMP-BRIDGE §7 fail-safe), never treating
   a favourable SafetyLabel as authorization (§6);
7. Carries an AG-UI run's traffic on the Bridge channel `0x000D` by default, MAY instead or
   additionally carry it on the Interaction channel `0x000F` under the same
   NPAMP-BRIDGE/NPAMP-CC-STREAM framing where its deployment aligns with that channel's
   purpose, does not split a single run across channels, and uses the Discovery channel
   `0x0010` only for the OPTIONAL protocol advertisement of §7, never for live AG-UI traffic
   (§7); and
8. Does not apply AG-UI's HTTP/SSE/WebSocket/binary transport bindings, HTTP status codes, or
   `Last-Event-ID` header at the N-PAMP layer, conveying AG-UI run state only inside the
   carried AG-UI messages, and carries no AG-UI run state across associations by any other
   means (§8).

A conformance test suite SHOULD assert each clause above with recorded exchanges that
include: a run request carried as a BRIDGE_REQUEST with `method = run` and a SafetyLabel;
an event stream that opens with `RUN_STARTED`, carries `TEXT_MESSAGE_*` and `TOOL_CALL_*`
events, and closes with `RUN_FINISHED` on a BRIDGE_STREAM_END; a run that ends in a
`RUN_ERROR` event carried in-stream (and distinctly, a `ProtocolUnsupported` BRIDGE_ERROR for
an uncarried `protocol_id`); a run with a missing SafetyLabel that MUST be treated as
`destructive`; a resumed run from a non-zero `event_id`; and a client-initiated stream cancel
acknowledged by the agent.
