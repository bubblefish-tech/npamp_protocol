# NPAMP-MAP-A2A — A2A (Agent2Agent) Protocol Mapping (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is a **thin per-protocol mapping**: it pins the specifics of
> the **A2A (Agent2Agent) protocol** onto N-PAMP carriage. It carries A2A's JSON-RPC
> 2.0 method calls under **NPAMP-CC-JSONRPC** (`20_carriage_jsonrpc.md`), A2A's
> streaming methods under **NPAMP-CC-STREAM** (`23_carriage_streaming.md`), and A2A's
> AgentCard capability document under **NPAMP-CC-DOC** (`24_carriage_documents.md`).
> It builds on **NPAMP-BRIDGE** (`10_bridge_framework.md`) and the N-PAMP core
> specification (draft-bubblefish-npamp-01, the "core specification"). It consumes
> only code points those documents already reserve; it defines no new frame type, no
> new TLV, and no change to the core wire format or to NPAMP-BRIDGE.

## 1. Scope

### 1.1 In scope

This document defines how an A2A endpoint interoperates over an N-PAMP association
without bespoke adaptation. It pins, against A2A's own published specification (§13),
only the A2A specifics that the carriage classes leave to a per-protocol mapping:

- The A2A **protocol identifier** and foreign-message `content_type` (§3);
- A2A's JSON-RPC 2.0 **method namespace** and how each method rides NPAMP-CC-JSONRPC
  or NPAMP-CC-STREAM (§4);
- The **SafetyLabel effect class** each state-mutating A2A method carries, which
  NPAMP-CC-JSONRPC §9 explicitly defers to this document (§5);
- The carriage of A2A's **streaming** methods — `message/stream` and
  `tasks/resubscribe` — as NPAMP-BRIDGE stream frames under NPAMP-CC-STREAM, and the
  mapping of A2A's stream-terminating event onto `BRIDGE_STREAM_END` (§6);
- The carriage of the A2A **AgentCard** (and its authenticated extended variant) as an
  NPAMP-CC-DOC document set, including its `.well-known` origin and its optional
  signatures as detached proofs (§7);
- The treatment of A2A **push-notification configuration** methods, and the exclusion
  of out-of-band webhook delivery (§8); and
- **Channel selection** for each traffic class (§9).

The structural work — octet-exact carriage, the BridgeEnvelope, correlation, the
structured-error model, streaming, and the safety-annotation TLV — is done by
NPAMP-BRIDGE and the named carriage classes and is not restated here.

### 1.2 Not in scope

The following are explicitly NOT defined by this document:

- **A2A's non-JSON-RPC transport bindings.** A2A v1.0 ships three transport bindings:
  JSON-RPC 2.0 over HTTPS, gRPC, and HTTP+JSON/REST (§13). This mapping carries the
  **JSON-RPC binding** only. A deployment that wishes to carry A2A's gRPC or REST
  binding over N-PAMP uses the HTTP-semantics carriage class (NPAMP-CC-HTTP) or Class
  OPAQUE and is out of scope here.
- **A2A task enumeration.** A2A's task-listing operation has no JSON-RPC method
  binding — it exists only in A2A's gRPC (`ListTask`) and REST (`GET /v1/tasks`)
  bindings (§13) — and is therefore out of scope for this JSON-RPC mapping.
- **The A2A object schemas.** The internal grammar of `Task`, `Message`, `Part`,
  `Artifact`, `AgentCard`, `TaskStatusUpdateEvent`, `TaskArtifactUpdateEvent`, and the
  A2A error objects is fixed by the A2A specification. This document carries these
  objects verbatim (NPAMP-BRIDGE §1) and does not parse, validate, or transform them.
- **Out-of-band webhook delivery of push notifications.** A2A push notifications are
  delivered by the A2A server to a client-registered webhook over plain HTTP, outside
  the A2A request/response connection (§8). Carriage of that webhook callback is not
  defined here; only the JSON-RPC *configuration* methods are carried.
- **Any change to NPAMP-BRIDGE, to the carriage classes, or to the core wire format**,
  including the BridgeEnvelope TLV, the SafetyLabel TLV, the StreamControl TLV, and the
  DocumentBinding TLV, all of which are used as their defining documents specify.
- **JSON-RPC batch arrays**, which NPAMP-CC-JSONRPC §1.2 places out of scope; A2A does
  not require batch carriage.

## 2. Relationship to the carriage classes and the registry

This document is a registration plus a thin mapping, in the sense of the companion
index: it names a `protocol_id`, the carriage classes it uses, A2A's method namespace,
and A2A-specific fields, and it lets the carriage classes do the structural work.

| Facility | Owning document | Use here |
|---|---|---|
| `protocol_id` `0x02` (A2A) | NPAMP-BRIDGE §4; Bridge Protocol Identifier registry (NPAMP-REG §6) | The identifier every A2A Bridge frame carries (§3). |
| JSON-RPC 2.0 carriage | NPAMP-CC-JSONRPC | Carriage of A2A's unary JSON-RPC methods (§4). |
| Streaming carriage | NPAMP-CC-STREAM | Carriage of A2A's `message/stream` and `tasks/resubscribe` (§6). |
| Document carriage | NPAMP-CC-DOC | Carriage of the A2A AgentCard and its detached proofs (§7). |
| BridgeEnvelope / SafetyLabel TLVs | Core specification; NPAMP-BRIDGE | Carried unchanged on every A2A frame (§3, §5). |

Because NPAMP-CC-JSONRPC carries the JSON-RPC `method` string **verbatim** as advisory
routing metadata and never re-serializes the object (NPAMP-CC-JSONRPC §2, §4), the
carriage is robust to A2A's cross-version method-string changes (§11): a receiver
selects the foreign protocol solely by `protocol_id` (NPAMP-REG §9) and delivers the
A2A object octet-for-octet regardless of the exact `method` token. This document
therefore pins the effect class and carriage class **by operation semantics**, and lists
the literal method strings of a pinned A2A version as the confirmed reference (§4, §11),
rather than making the wire format depend on a particular spelling.

## 3. Protocol identifier and content type

- The BridgeEnvelope `protocol_id` for A2A is **`0x02`**, assigned by NPAMP-BRIDGE §4
  and recorded by the Bridge Protocol Identifier registry (NPAMP-REG §6) with carriage
  class "JSONRPC (with DOC for the AgentCard)". This value is **assigned, not
  provisional**; an implementation MUST use `0x02` for A2A JSON-RPC traffic and MUST NOT
  emit A2A traffic under an experimental (`0x10`–`0x7F`) or private-use (`0x80`–`0xFF`)
  identifier in production (NPAMP-REG §7).
- Every A2A JSON-RPC object is carried as a JSON value; the BridgeEnvelope
  `content_type` MUST be **`0x01`** (application/json), as NPAMP-CC-JSONRPC §3 requires.
- Each carried A2A JSON-RPC object MUST contain a `jsonrpc` member equal to `"2.0"`
  (NPAMP-CC-JSONRPC §3); a frame whose foreign object lacks it MUST be rejected with
  BRIDGE_ERROR `EnvelopeMalformed`.
- A2A's JSON-RPC binding is defined over HTTPS in native A2A; over N-PAMP the HTTP
  framing is subsumed by the N-PAMP transport, and **only the JSON-RPC object is the
  foreign message**. An implementation MUST NOT carry A2A's HTTP request line, HTTP
  headers, or SSE `event:`/`data:` framing as part of the foreign message; the JSON-RPC
  object (or, for a stream, each A2A event object — §6) is the sole foreign payload.

## 4. A2A method namespace and carriage

A2A method calls are JSON-RPC 2.0 Request objects whose `method` names an A2A operation.
Each is carried under NPAMP-CC-JSONRPC, except the streaming methods, which are carried
under NPAMP-CC-STREAM (§6). The table lists the A2A **v0.3.0** JSON-RPC method strings
(§11, §13), the carriage, and the correlation model.

| A2A operation | JSON-RPC `method` (v0.3.0) | Carriage | NPAMP-BRIDGE frame(s) |
|---|---|---|---|
| Send a message | `message/send` | NPAMP-CC-JSONRPC | BRIDGE_REQUEST → BRIDGE_RESPONSE / BRIDGE_ERROR |
| Send a message, streamed | `message/stream` | NPAMP-CC-STREAM (§6) | BRIDGE_REQUEST → BRIDGE_STREAM_DATA* + BRIDGE_STREAM_END |
| Get task state | `tasks/get` | NPAMP-CC-JSONRPC | BRIDGE_REQUEST → BRIDGE_RESPONSE / BRIDGE_ERROR |
| Cancel a task | `tasks/cancel` | NPAMP-CC-JSONRPC | BRIDGE_REQUEST → BRIDGE_RESPONSE / BRIDGE_ERROR |
| Reattach to a task's stream | `tasks/resubscribe` | NPAMP-CC-STREAM (§6) | BRIDGE_REQUEST → BRIDGE_STREAM_DATA* + BRIDGE_STREAM_END |
| Set push-notification config | `tasks/pushNotificationConfig/set` | NPAMP-CC-JSONRPC | BRIDGE_REQUEST → BRIDGE_RESPONSE / BRIDGE_ERROR |
| Get push-notification config | `tasks/pushNotificationConfig/get` | NPAMP-CC-JSONRPC | BRIDGE_REQUEST → BRIDGE_RESPONSE / BRIDGE_ERROR |
| List push-notification configs | `tasks/pushNotificationConfig/list` | NPAMP-CC-JSONRPC | BRIDGE_REQUEST → BRIDGE_RESPONSE / BRIDGE_ERROR |
| Delete push-notification config | `tasks/pushNotificationConfig/delete` | NPAMP-CC-JSONRPC | BRIDGE_REQUEST → BRIDGE_RESPONSE / BRIDGE_ERROR |
| Retrieve authenticated extended card | `agent/getAuthenticatedExtendedCard` (v0.3.0; see §7, §11) | NPAMP-CC-DOC (§7) | BRIDGE_REQUEST → BRIDGE_RESPONSE / stream |

Carriage requirements:

- For each unary method, the BridgeEnvelope `method` field MUST equal the carried
  object's `method` member byte-for-byte (NPAMP-CC-JSONRPC §4), and the originating peer
  MUST supply a non-empty `correlation_id` derived from the JSON-RPC `id`
  (NPAMP-CC-JSONRPC §8). Either peer MAY originate a BRIDGE_REQUEST (NPAMP-BRIDGE §5);
  A2A's client role is the requester and the A2A server is the responder for a given
  exchange, but the carriage places no additional directional restriction.
- An A2A method that A2A itself models as a JSON-RPC **Notification** (no `id`) MUST be
  carried as BRIDGE_NOTIFY with `corr_len = 0` (NPAMP-CC-JSONRPC §7); A2A's core
  request/response methods above use an `id` and are Requests.
- An A2A JSON-RPC **error** Response (an object with an `error` member) MUST be carried
  as BRIDGE_ERROR with the A2A error object preserved verbatim (NPAMP-CC-JSONRPC §6),
  including A2A's implementation-defined server-error codes in the JSON-RPC `-32000` to
  `-32099` range (for example `-32001` TaskNotFound, `-32002` TaskNotCancelable,
  `-32003` PushNotificationNotSupported, `-32004` UnsupportedOperation, `-32005`
  ContentTypeNotSupported, `-32006` InvalidAgentResponse; see §13). An implementation
  MUST NOT remap any A2A error code to or from an N-PAMP transport-error code
  (NPAMP-CC-JSONRPC §6).
- A receiver that does not carry a given A2A method (for example an optional streaming
  or push-config method) MUST report `MethodUnsupported` (NPAMP-BRIDGE §6 code 3) for a
  BRIDGE_REQUEST bearing it, and MUST NOT report success for an operation it did not
  perform.

## 5. SafetyLabel effect classes for A2A methods

NPAMP-CC-JSONRPC §9 states that JSON-RPC 2.0 does not itself declare whether a method
mutates state, and defers the classification of each method to the concrete mapping.
This section is that classification for A2A. It uses the SafetyLabel `effect` values of
NPAMP-BRIDGE §7: `0x00` read_only, `0x01` idempotent_write, `0x02` non_idempotent_write,
`0x03` destructive.

| A2A method | `effect` | Rationale |
|---|---|---|
| `message/send` | `0x02` non_idempotent_write | Delivers a message that creates or advances a task and produces new agent work; re-sending is not idempotent. |
| `message/stream` | `0x02` non_idempotent_write | As `message/send`, with a streamed reply (§6). |
| `tasks/get` | `0x00` read_only | Reads task state. |
| `tasks/cancel` | `0x02` non_idempotent_write | Requests an irreversible terminal transition of a running task. A deployment with a stricter policy MAY classify it `0x03` destructive; a sender MUST attach a SafetyLabel either way. |
| `tasks/resubscribe` | `0x00` read_only | Reattaches to an existing task's event stream; produces no new task state (§6). |
| `tasks/pushNotificationConfig/set` | `0x01` idempotent_write | Sets/replaces a task's push-notification configuration; setting the same config yields the same state. |
| `tasks/pushNotificationConfig/get` | `0x00` read_only | Reads a configuration. |
| `tasks/pushNotificationConfig/list` | `0x00` read_only | Enumerates configurations. |
| `tasks/pushNotificationConfig/delete` | `0x03` destructive | Removes a configuration; the configuration data is lost. |
| `agent/getAuthenticatedExtendedCard` (§7) | `0x00` read_only | Serves a capability document (§7, NPAMP-CC-DOC §9). |

Requirements:

- For any A2A method whose `effect` above is not `0x00`, the sender MUST attach a
  SafetyLabel TLV (NPAMP-BRIDGE §7) to the carrying BRIDGE_REQUEST, and an intermediary
  MUST carry it unchanged.
- A receiver MUST NOT treat the absence of a SafetyLabel on a state-mutating A2A method
  as `read_only`; absence on such a method MUST be treated as `destructive` (fail-safe;
  NPAMP-BRIDGE §7, NPAMP-CC-JSONRPC §9).
- The `effect` values above classify intent; they do not replace the A2A server's own
  authorization decision.

## 6. Streaming methods over NPAMP-CC-STREAM

A2A's `message/stream` and `tasks/resubscribe` return a stream of events rather than a
single response. In native A2A's JSON-RPC binding the server replies with HTTP `200` and
`Content-Type: text/event-stream`, and each Server-Sent Event's `data` field is a
complete JSON-RPC 2.0 Response object whose `result` is one of an initial `Task`, a
`Message`, a `TaskStatusUpdateEvent`, or a `TaskArtifactUpdateEvent` (§13). Because
NPAMP-CC-JSONRPC §1.2 carries only the unit JSON-RPC Request/Response/Notification and
delegates streamed replies to a protocol's own mapping, A2A streaming is carried under
**NPAMP-CC-STREAM** as follows:

- The streaming method's initiating call (`message/stream` or `tasks/resubscribe`) is a
  `BRIDGE_REQUEST` (`0x0100`) under `protocol_id 0x02`, carrying the A2A JSON-RPC Request
  object as its foreign message, with the BridgeEnvelope `method` equal to the A2A
  `method` string and a non-empty `correlation_id` (NPAMP-CC-JSONRPC §4, §8).
- Each A2A stream event — the JSON-RPC Response object the server would place in one SSE
  `data` field — is carried as the **foreign event** of one `BRIDGE_STREAM_DATA`
  (`0x0104`) frame, verbatim (NPAMP-BRIDGE §1; NPAMP-CC-STREAM §4). The SSE framing
  (`event:`/`data:` lines, blank-line delimiters) MUST NOT be carried; only the JSON-RPC
  Response object is the foreign event.
- Each such frame carries a StreamControl TLV with a strictly monotonically increasing
  `event_id` per NPAMP-CC-STREAM §5, all echoing the initiating request's
  `correlation_id`.
- The A2A event that terminates the stream — a `TaskStatusUpdateEvent` with `final` set
  `true` (emitted when the task reaches a terminal or interrupted state, e.g. completed,
  failed, canceled, rejected, or input-required; §13) — MUST be carried as the
  `BRIDGE_STREAM_END` (`0x0105`) frame, with the BridgeEnvelope `final` bit set
  (NPAMP-CC-STREAM §4, §5.1). A receiver MUST treat that frame as the end of the A2A
  stream for that `correlation_id`.
- `tasks/resubscribe` is A2A's reattach-to-an-existing-stream operation and maps onto
  NPAMP-CC-STREAM resumption (NPAMP-CC-STREAM §6): the resume request echoes the
  stream's `correlation_id` and carries the resume cursor as the `event_id` of the last
  A2A event the client durably consumed. A producer that cannot resume from the cursor
  MUST respond per NPAMP-CC-STREAM §6.3 (resume, restart, or refuse with `NotResumable`)
  and MUST NOT silently replay already-consumed events.
- SafetyLabel handling for a streaming method follows §5 (`message/stream` is
  `non_idempotent_write`; `tasks/resubscribe` is `read_only`).

A2A streams in this mapping are downstream (server-to-client) event streams; the
full-duplex construction of NPAMP-CC-STREAM §8 is available but not required by A2A's
JSON-RPC binding.

## 7. The AgentCard over NPAMP-CC-DOC

A2A's **AgentCard** is a public JSON capability document — the agent's technical
manifest (identity, version, capabilities, supported interfaces/endpoints, security
schemes, and skills). In native A2A it is served over HTTP GET at a well-known URI. Over
N-PAMP it is carried as an **NPAMP-CC-DOC document set** (NPAMP-CC-DOC §1, §3):

- **Well-known origin.** A2A v0.3.0 recommends serving the AgentCard at
  `https://{server_domain}/.well-known/agent-card.json` (§13). This mapping carries the
  document, not the HTTP GET: a consumer requests it with a `BRIDGE_REQUEST` whose
  `method` names the card-retrieval operation (NPAMP-CC-DOC §7.1), and the producer
  replies with the AgentCard as the document part. (Earlier A2A releases, up to v0.2.x,
  used `/.well-known/agent.json`; see §11.)
- **Channel.** The AgentCard rides NPAMP-CC-DOC on the Bridge channel `0x000D` by
  default, and MAY instead, or in addition, be carried on the Discovery channel `0x0010`
  (NPAMP-CC-DOC §1.1, §3; §9 below). A document and its proofs MUST NOT be split across
  the two channels (NPAMP-CC-DOC §3).
- **Octet exactness.** The AgentCard MUST be delivered byte-identical to the octets the
  producer signed or hashed (NPAMP-CC-DOC §4), so that any digest or signature verifies
  bit-identically at the consumer. An implementation MUST NOT re-serialize, re-indent,
  or canonicalize the card.
- **Signatures as detached proofs.** Where an AgentCard carries signature material, each
  signature is carried as a detached proof bound to the card by `doc_id` and digest
  (NPAMP-CC-DOC §6), with `proof_alg` naming a core-assigned signature code point
  (NPAMP-CC-DOC §6.4). Verification is the consumer's act (NPAMP-CC-DOC §6.5); carriage
  delivers the card and its proofs with the integrity guarantees a verifier needs and
  does not itself decide trust.
- **Authenticated extended card.** A2A also defines retrieval of a richer AgentCard
  after authentication (available only when the base card advertises support for it).
  This variant is likewise a capability document and is carried under NPAMP-CC-DOC; its
  exact retrieval spelling and transport differ across A2A versions (§11), and this
  mapping treats it as a DOC-class document regardless of that spelling.
- **Safety.** Serving an AgentCard is `read_only` (NPAMP-CC-DOC §9); a producer serving
  it SHOULD attach a SafetyLabel with `effect = read_only`. Where a deployment makes card
  retrieval itself state-mutating (for example, generating or signing a fresh card on
  demand), the fail-safe rule of NPAMP-BRIDGE §7 applies.

## 8. Push notifications

A2A lets a client register a webhook so the A2A server can notify it of task updates
out-of-band — useful for long-running tasks and disconnected clients. Regardless of the
A2A transport binding, the A2A server delivers these notifications by calling the
client-registered webhook over plain HTTP, **outside** the A2A request/response
connection (§13). Consequently:

- The push-notification **configuration** methods
  (`tasks/pushNotificationConfig/set`, `.../get`, `.../list`, `.../delete`) are ordinary
  A2A JSON-RPC methods and are carried under NPAMP-CC-JSONRPC per §4, with the effect
  classes of §5.
- The **delivery** of a push notification to the webhook is a separate, server-initiated
  HTTP call to a third-party URL and is NOT carried by this mapping (§1.2). A deployment
  that wishes to carry such a callback over N-PAMP would do so as a separate exchange
  under the HTTP-semantics carriage class (NPAMP-CC-HTTP) or Class OPAQUE; that is out of
  scope here.
- A receiver that does not support push notifications MUST report the A2A-level
  `PushNotificationNotSupported` error (`-32003`, §4, §13) as a BRIDGE_ERROR carrying the
  A2A error object verbatim, not as an N-PAMP transport error.

## 9. Channel selection

| A2A traffic class | Carriage | Channel |
|---|---|---|
| Unary JSON-RPC methods (§4) | NPAMP-CC-JSONRPC | Bridge `0x000D` |
| Streaming methods `message/stream`, `tasks/resubscribe` (§6) | NPAMP-CC-STREAM | Bridge `0x000D` |
| AgentCard and authenticated extended card (§7) | NPAMP-CC-DOC | Bridge `0x000D` default; MAY use Discovery `0x0010` |
| Push-notification webhook delivery (§8) | Not carried by this mapping | Out of band (native HTTP) |

The Bridge channel `0x000D` and the Discovery channel `0x0010` are both minimum-profile
**Standard** (core specification channel registry); A2A carriage requires no channel
above the Standard profile. A peer MUST NOT send or accept A2A frames on a channel it did
not advertise during the handshake (core specification §5).

## 10. Code points consumed

This mapping consumes only code points that the core specification, NPAMP-BRIDGE, and the
carriage classes already define. It defines no new frame type, no new TLV, and no change
to the core wire format.

| Resource | Origin | Use here |
|---|---|---|
| `protocol_id` `0x02` (A2A) | NPAMP-BRIDGE §4; NPAMP-REG §6 | The A2A identifier on every A2A Bridge frame (§3). |
| `content_type` `0x01` (application/json) | NPAMP-BRIDGE §4 | The A2A JSON-RPC foreign-message encoding (§3). |
| Channel `0x000D` (Bridge) | Core specification | Default channel for all A2A carriage (§9). |
| Channel `0x0010` (Discovery) | Core specification | Optional channel for AgentCard advertisement (§7, §9). |
| Bridge frame types `0x0100`–`0x0105` | NPAMP-BRIDGE §2 | Reused unchanged for request/response/error/stream (§4, §6). |
| BridgeEnvelope TLV `0x0010`, SafetyLabel TLV `0x0013` | Core specification; NPAMP-BRIDGE | Carried unchanged (§3, §5). |
| StreamControl TLV (NPAMP-CC-STREAM §5, Type `0x0011` **provisional**) | NPAMP-CC-STREAM | Per-event control for A2A streams (§6). Its provisional status is inherited from NPAMP-CC-STREAM and not resolved here. |
| DocumentBinding TLV (NPAMP-CC-DOC §6, Type `0xTBD-DOCBIND` **provisional**) | NPAMP-CC-DOC | Document-binding metadata for the AgentCard (§7). Its provisional status is inherited from NPAMP-CC-DOC and not resolved here. |

This document requests no IANA action and defines no registry.

## 11. Version considerations and marked uncertainties

A2A is a versioned specification (Major.Minor); the latest released version at the time
of writing is **v1.0.0**, and **v0.3.0** is a stable prior release. This mapping pins its
literal method strings and the AgentCard well-known path to **A2A v0.3.0** (§13), which
this document cross-confirmed against two independent renderings of the A2A source. Two
version-sensitive facts are marked here so that an implementer confirms them against the
exact A2A version they target rather than relying on a single spelling:

1. **JSON-RPC method spellings changed across A2A versions.** The v0.3.0 strings in §4
   are the confirmed reference. A2A **v1.0.0** restructured the specification into three
   transport bindings and, per that version's binding section, renames several JSON-RPC
   methods — reported examples include `tasks/subscribe` in place of `tasks/resubscribe`,
   `tasks/pushNotificationConfig/create` in place of `.../set`, and a renamed extended-card
   method. These v1.0.0 spellings are **reported, not independently confirmed here**, and
   an implementation targeting v1.0.0 MUST verify them against the v1.0.0 specification.
   Because NPAMP-CC-JSONRPC carries the `method` string verbatim and this mapping pins
   effect class and carriage by operation *semantics* (§2, §5), a rename does not change
   the carriage: the same operation keeps the same effect class and rides the same class.
2. **AgentCard well-known path and the extended-card operation.** A2A v0.3.0 recommends
   `/.well-known/agent-card.json` (§7); A2A up to v0.2.x used `/.well-known/agent.json`.
   The authenticated extended-card retrieval is spelled `agent/getAuthenticatedExtendedCard`
   in the v0.3.0 JSON-RPC reference consulted here; one A2A source describes the
   authenticated extended card as an HTTP GET endpoint rather than a JSON-RPC method. This
   mapping treats the extended card as a DOC-class capability document (§7) independent of
   which spelling and transport a given A2A version uses; an implementer MUST confirm the
   exact operation for their target version.

No value in this document is asserted beyond what §13's sources support; where a fact was
version-dependent or not confirmable from the primary source, it is marked above rather
than fixed by assumption.

## 12. Security considerations

This mapping introduces no cryptography and changes none. All confidentiality, integrity,
authentication, downgrade resistance, and replay protection are provided by the core
specification's wire format and key schedule and apply unchanged to every A2A frame, which
travels inside the AEAD-protected Bridge (or Discovery) payload; the `protocol_id`,
`method`, SafetyLabel, and A2A object are authenticated and confidentiality-protected to
the same degree.

Carrying A2A over N-PAMP makes no security claim about A2A itself. In particular:

- **Transport-bound A2A security elements.** A2A's JSON-RPC binding is defined over HTTPS,
  and A2A security schemes advertised in the AgentCard may assume HTTP-level mechanisms
  (for example bearer tokens in HTTP headers). Over N-PAMP the HTTP framing is subsumed;
  where an A2A deployment binds authorization to an HTTP element that does not exist over
  N-PAMP, that mismatch is a property of the deployment and MUST be resolved by carrying
  the A2A-level credential inside the JSON-RPC object or by the association's own
  authentication, not by fabricating a transport element.
- **AgentCard authenticity.** The AgentCard's own signatures (§7), verified by the
  consumer under NPAMP-CC-DOC, carry the card's authenticity independently of the
  transport; carriage delivery of a proof is not verification of it (NPAMP-CC-DOC §6.5).
- **Safety fail-safe.** The effect classification of §5 and the NPAMP-BRIDGE §7 fail-safe
  (absence of a SafetyLabel on a state-mutating method is `destructive`) apply to every
  A2A method; discovery of an A2A method or agent is a claim, not authorization
  (NPAMP-DISC §10).

## 13. References

Primary source (A2A specification):

- Agent2Agent (A2A) Protocol Specification, v0.3.0 — <https://a2a-protocol.org/v0.3.0/specification/>
  (JSON-RPC method strings, AgentCard `.well-known/agent-card.json` path, Task/Message/
  Part/Artifact model, streaming via Server-Sent Events with each `data` field a JSON-RPC
  Response, and A2A error codes).
- Agent2Agent (A2A) Protocol Specification, v1.0.0 (latest) — <https://a2a-protocol.org/v1.0.0/specification/>
  (three transport bindings — JSON-RPC 2.0 over HTTPS, gRPC, HTTP+JSON/REST — and the
  v1.0.0 JSON-RPC method renames noted, but not independently confirmed, in §11).
- A2A Streaming & Asynchronous Operations — <https://a2a-protocol.org/latest/topics/streaming-and-async/>
  (the `final: true` `TaskStatusUpdateEvent` that terminates an SSE stream; §6).
- A2A specification source repository — <https://github.com/a2aproject/A2A/blob/main/docs/specification.md>
  (method mapping and A2A-specific JSON-RPC error codes; consulted for cross-confirmation,
  with the version caveats of §11).

N-PAMP documents built on:

- draft-bubblefish-npamp-01 — the N-PAMP core specification: the 36-octet frame, the
  channel registry (Bridge `0x000D`, Discovery `0x0010`), the frame-type namespace
  (channel-specific types from `0x0100`), the extension-TLV encoding, and the AEAD payload
  protection.
- NPAMP-BRIDGE (`10_bridge_framework.md`) — the encapsulation, BridgeEnvelope, correlation,
  structured-error, and SafetyLabel contract.
- NPAMP-CC-JSONRPC (`20_carriage_jsonrpc.md`) — JSON-RPC 2.0 carriage.
- NPAMP-CC-STREAM (`23_carriage_streaming.md`) — streaming carriage.
- NPAMP-CC-DOC (`24_carriage_documents.md`) — capability/schema document carriage.
- NPAMP-REG (`30_protocol_registry.md`) — the Bridge Protocol Identifier registry
  (`protocol_id 0x02` = A2A).
- NPAMP-DISC (`40_discovery.md`) — Discovery-channel advertisement referenced in §7, §9.
- BCP 14 (RFC 2119, RFC 8174) — requirement key words.

## 14. Conformance

An implementation conforms to NPAMP-MAP-A2A if and only if it conforms to NPAMP-BRIDGE,
NPAMP-CC-JSONRPC, NPAMP-CC-STREAM, and NPAMP-CC-DOC for the frames it emits and parses in
this mapping, and, for A2A traffic, it:

1. Carries A2A JSON-RPC traffic under `protocol_id` `0x02` with `content_type` `0x01`,
   never emitting A2A under an experimental or private-use identifier in production, and
   selects the foreign protocol solely by `protocol_id` (§3);
2. Carries each unary A2A JSON-RPC method (§4) under NPAMP-CC-JSONRPC — the object
   octet-for-octet, the BridgeEnvelope `method` equal to the A2A `method`, a non-empty
   `correlation_id` derived from the JSON-RPC `id`, and A2A error objects (including the
   `-32000`..`-32099` A2A codes) preserved verbatim, never remapped to or from an N-PAMP
   transport-error code (§4);
3. Attaches the correct SafetyLabel `effect` to each state-mutating A2A method per the
   classification of §5, and treats a missing SafetyLabel on a state-mutating method as
   `destructive` (§5);
4. Carries `message/stream` and `tasks/resubscribe` under NPAMP-CC-STREAM — each A2A
   stream event as one `BRIDGE_STREAM_DATA` foreign event with a strictly monotonic
   `event_id`, never carrying SSE line framing, and maps the terminating `final: true`
   `TaskStatusUpdateEvent` to `BRIDGE_STREAM_END` with the `final` bit set (§6);
5. Maps `tasks/resubscribe` onto NPAMP-CC-STREAM resumption, honoring or refusing
   (`NotResumable`) a resume request and never silently replaying consumed events (§6);
6. Carries the A2A AgentCard (and the authenticated extended card) under NPAMP-CC-DOC —
   octet-exact, with any card signatures carried as detached proofs and verification left
   to the consumer — on the Bridge channel `0x000D` by default or the Discovery channel
   `0x0010`, never splitting a card and its proofs across the two channels (§7);
7. Carries the push-notification configuration methods under NPAMP-CC-JSONRPC, reports
   `PushNotificationNotSupported` (`-32003`) as a verbatim A2A error rather than an N-PAMP
   transport error, and does not carry out-of-band webhook delivery under this mapping
   (§8);
8. Uses only the channels of §9, sending or accepting A2A frames only on channels
   advertised during the handshake; and
9. Defines no new frame type, TLV, or code point, consuming only those enumerated in §10,
   and inherits the provisional status of the StreamControl and DocumentBinding TLVs
   without resolving it here (§10).

A conformance test suite SHOULD assert each clause above with recorded exchanges that
include at least: a `message/send` request/response pair; a `tasks/get` read; a
`tasks/cancel` carrying a `non_idempotent_write` SafetyLabel and a second `tasks/cancel`
with the SafetyLabel omitted, verified to be treated as `destructive`; a `message/stream`
exchange whose terminating `final: true` event is carried as `BRIDGE_STREAM_END`; a
`tasks/resubscribe` that resumes from a non-zero cursor and one that is refused with
`NotResumable`; an AgentCard document set with one detached signature proof carried under
NPAMP-CC-DOC on both the Bridge and the Discovery channel; and an A2A JSON-RPC error
(for example `-32001` TaskNotFound) carried verbatim as BRIDGE_ERROR.
