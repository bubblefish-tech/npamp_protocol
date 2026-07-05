# NPAMP-MAP-MCP — Model Context Protocol Mapping (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document defines the carriage of the **Model Context Protocol (MCP)**,
> a JSON-RPC 2.0 protocol, over an N-PAMP association. It is a **thin mapping** over
> the JSON-RPC 2.0 carriage class **NPAMP-CC-JSONRPC** (`20_carriage_jsonrpc.md`):
> The carriage class does the structural work — request/response/notification,
> `id` correlation, verbatim error carriage — and this document pins only what is
> specific to MCP. It builds on NPAMP-CC-JSONRPC, on NPAMP-BRIDGE
> (`10_bridge_framework.md`), and on the N-PAMP core specification
> (draft-bubblefish-npamp-01, the "core specification"). It consumes only code
> points those documents already reserve and introduces no change to the core wire
> format, to NPAMP-BRIDGE, or to NPAMP-CC-JSONRPC.

## 1. Scope

### 1.1 In scope

This document specifies how MCP messages are carried over an N-PAMP association. It
defines, and only defines, the MCP-specific facts a peer needs in order to carry MCP
under NPAMP-CC-JSONRPC:

- The assigned `protocol_id` for MCP and its carriage class (§2);
- The MCP JSON-RPC method namespace and its mapping onto NPAMP-BRIDGE frame types
  and `message_kind` values (§4);
- How MCP's stateful session lifecycle — the `initialize` handshake, capability
  negotiation, and the `notifications/initialized` notification — rides the carriage
  (§5);
- Which MCP methods are state-mutating and therefore the SafetyLabel effect class a
  sender attaches, including the derivation of `tools/call`'s effect class from the
  MCP tool's own annotations, and the fail-safe on absence (§6); and
- Channel selection: the Bridge channel `0x000D` as the default, and the conditions
  under which MCP capability/discovery material MAY ride the Discovery channel
  `0x0010` (§7).

### 1.2 Not in scope

The following are explicitly NOT defined by this document, because NPAMP-CC-JSONRPC,
NPAMP-BRIDGE, or MCP's own specification already define them:

- The structural JSON-RPC 2.0 carriage — the mapping of a Request onto BRIDGE_REQUEST,
  a success Response onto BRIDGE_RESPONSE, an `error` Response onto BRIDGE_ERROR, a
  Notification onto BRIDGE_NOTIFY, and the `id`↔`correlation_id` correlation. These
  are inherited verbatim from NPAMP-CC-JSONRPC (§4, §5, §6, §8 of that document) and
  are not restated here (§3).
- The semantics, parameter schemas, or result schemas of any MCP method. Those are
  fixed by MCP's own specification and are carried transparently; this document does
  not summarize, validate, or re-encode them.
- MCP's stdio and Streamable HTTP transport bindings, and any HTTP-level header such
  as `MCP-Protocol-Version`. Over N-PAMP the transport is N-PAMP; those bindings do
  not apply (§8).
- Any change to the N-PAMP frame format, to the NPAMP-BRIDGE frame types, to the
  BridgeEnvelope or SafetyLabel TLVs, or to the NPAMP-CC-JSONRPC rules.
- Batch requests, which JSON-RPC 2.0 permits but NPAMP-CC-JSONRPC places out of scope
  (NPAMP-CC-JSONRPC §1.2). MCP does not require JSON-RPC batching; a single MCP
  JSON-RPC object per Bridge frame is the only mapping used here.

## 2. Protocol identity

| Property | Value |
|---|---|
| Protocol | Model Context Protocol (MCP). |
| `protocol_id` | `0x01`, assigned by the Bridge Protocol Identifier registry (NPAMP-REG §6). This is a standards-assigned code point, **not** provisional. |
| Carriage class | JSONRPC (NPAMP-CC-JSONRPC). |
| `content_type` | `0x01` (application/json), as required for the JSONRPC class (NPAMP-CC-JSONRPC §3). |
| Foreign-message form | A single MCP JSON-RPC 2.0 object (`"jsonrpc": "2.0"`), carried octet-for-octet as the foreign message (NPAMP-BRIDGE §1; NPAMP-CC-JSONRPC §3). |

A sender MUST set `protocol_id = 0x01` on every Bridge frame carrying an MCP message.
A receiver that does not carry MCP MUST reply to a BRIDGE_REQUEST bearing `0x01` with
`ProtocolUnsupported` (NPAMP-BRIDGE §6; NPAMP-REG §9), and MUST NOT infer MCP from any
other envelope field.

## 3. Relationship to NPAMP-CC-JSONRPC and NPAMP-BRIDGE

MCP is a JSON-RPC 2.0 protocol; every MCP application message is a well-formed
JSON-RPC 2.0 Request, Response, or Notification. Consequently the entire structural
carriage of MCP is provided by NPAMP-CC-JSONRPC without modification:

- The transparency rule governs: an MCP object is carried octet-for-octet and MUST NOT
  be re-serialized, reordered, canonicalized, or rewritten (NPAMP-BRIDGE §1;
  NPAMP-CC-JSONRPC §2, §3).
- Correlation of an MCP Response to its Request is the `id`↔`correlation_id` mapping of
  NPAMP-CC-JSONRPC §8, inherited unchanged. This document adds no correlation rule.
- An MCP JSON-RPC `error` Response is carried as BRIDGE_ERROR with its `code`,
  `message`, and any `data` preserved verbatim, and MCP's error codes — the JSON-RPC
  pre-defined codes and MCP's own — MUST NOT be collapsed or remapped to or from an
  N-PAMP transport-error code (NPAMP-CC-JSONRPC §6).
- The BridgeEnvelope `method` field carries the exact octets of the MCP `method`
  member for a Request or Notification, and `method_len = 0` for a Response
  (NPAMP-CC-JSONRPC §4, §5, §7).

This document therefore pins only MCP specifics (§2, §4, §5, §6, §7). Where this
document and NPAMP-CC-JSONRPC could appear to differ on a structural matter,
NPAMP-CC-JSONRPC governs.

## 4. MCP method namespace and frame mapping

MCP is bidirectional at the application layer: a server issues requests to a client
as well as the reverse. This maps directly onto NPAMP-BRIDGE's per-exchange
requester/responder roles: either peer MAY originate a BRIDGE_REQUEST, and the peer
that emits it is the requester for that exchange (NPAMP-BRIDGE §5). No N-PAMP role is
tied to the MCP client or server role.

The tables below enumerate the MCP methods of protocol revision `2025-11-25` and the
NPAMP-BRIDGE frame type and `message_kind` each uses. The `method` value in each table
is the exact string carried in both the MCP object and the BridgeEnvelope `method`
field (NPAMP-CC-JSONRPC §4).

### 4.1 Requests originated by the MCP client (client → server)

Each is a JSON-RPC Request bearing an `id`, carried as **BRIDGE_REQUEST** (`0x0100`,
`message_kind = 0x01`); its reply is **BRIDGE_RESPONSE** (`0x0101`) on success or
**BRIDGE_ERROR** (`0x0102`) on an MCP `error`.

| MCP `method` | Purpose |
|---|---|
| `initialize` | Open the session; negotiate protocol version and capabilities (§5). |
| `ping` | Liveness probe (also server → client; §4.2). |
| `tools/list` | Enumerate tools. |
| `tools/call` | Invoke a tool (effect class per §6). |
| `resources/list` | Enumerate resources. |
| `resources/templates/list` | Enumerate resource templates. |
| `resources/read` | Read a resource. |
| `resources/subscribe` | Subscribe to updates for a resource. |
| `resources/unsubscribe` | Cancel a resource subscription. |
| `prompts/list` | Enumerate prompts. |
| `prompts/get` | Retrieve a prompt. |
| `completion/complete` | Argument autocompletion (server `completions` capability). |
| `logging/setLevel` | Set the server's minimum log level. |
| `tasks/get` | Retrieve the state of a task. |
| `tasks/result` | Retrieve the result of a completed task. |
| `tasks/list` | Enumerate tasks. |
| `tasks/cancel` | Cancel a task. |

### 4.2 Requests originated by the MCP server (server → client)

Each is carried as **BRIDGE_REQUEST** originated by the peer acting as the MCP server,
in the reverse direction, using the same frame types and correlation as §4.1
(NPAMP-BRIDGE §5). This is exactly the "a server issues a request to a client" case
that NPAMP-BRIDGE's per-exchange roles admit.

| MCP `method` | Purpose |
|---|---|
| `ping` | Liveness probe toward the client. |
| `sampling/createMessage` | Ask the client to perform an LLM completion (effect class per §6). |
| `roots/list` | Ask the client for its filesystem/URI roots. |
| `elicitation/create` | Ask the client to solicit input from the user (effect class per §6). |
| `tasks/get` | Retrieve the state of a client-side task. |
| `tasks/result` | Retrieve the result of a client-side task. |
| `tasks/list` | Enumerate client-side tasks. |
| `tasks/cancel` | Cancel a client-side task. |

### 4.3 Notifications

Each is a JSON-RPC Notification (a Request with **no** `id`), carried as
**BRIDGE_NOTIFY** (`0x0103`, `message_kind = 0x03`, `corr_len = 0`). The receiver MUST
NOT reply and the sender MUST NOT await a reply (NPAMP-BRIDGE §8; NPAMP-CC-JSONRPC §7).

| MCP `method` | Direction | Purpose |
|---|---|---|
| `notifications/initialized` | Client → server | Client is ready after `initialize` (§5). |
| `notifications/cancelled` | Either | Cancel an in-flight request by its `id`. |
| `notifications/progress` | Either | Progress for a long-running request. |
| `notifications/message` | Server → client | A structured log message (server `logging` capability). |
| `notifications/resources/updated` | Server → client | A subscribed resource changed. |
| `notifications/resources/list_changed` | Server → client | The resource list changed. |
| `notifications/tools/list_changed` | Server → client | The tool list changed. |
| `notifications/prompts/list_changed` | Server → client | The prompt list changed. |
| `notifications/roots/list_changed` | Client → server | The client's root list changed. |
| `notifications/elicitation/complete` | Server → client | An elicitation was completed or resolved. |
| `notifications/tasks/status` | Either | A task's status changed. |

A method the receiver does not carry is handled by the NPAMP-BRIDGE error model: a
BRIDGE_REQUEST for an unrecognized MCP method MAY be answered either at the MCP layer
(a JSON-RPC `error` carried as BRIDGE_ERROR, NPAMP-CC-JSONRPC §6) or, where the frame
cannot be delivered to an MCP endpoint at all, with the N-PAMP transport error
`MethodUnsupported` (NPAMP-BRIDGE §6). The two are distinct: an MCP-level "method not
found" is a foreign error carried verbatim, not an N-PAMP transport error (§3).

> **Revision note.** The method set above is that of MCP revision `2025-11-25`, the
> latest ratified revision at the time of writing (§9). MCP is versioned by dated
> revision and negotiates its version in the `initialize` exchange (§5); a later MCP
> revision MAY add, rename, or remove methods. Because the carriage is transparent and
> selects nothing on the method string beyond the BridgeEnvelope `method` field and the
> SafetyLabel guidance of §6, a peer carries a newer or older MCP revision without a
> change to this mapping. An implementation MUST NOT reject an MCP method solely because
> it is absent from the table above; the negotiated MCP version, not this table, fixes
> the method set for a session.

## 5. Session lifecycle and the `initialize` handshake

MCP defines a stateful session that opens with a mandatory handshake. That handshake is
ordinary MCP JSON-RPC traffic and rides the carriage with no special framing:

1. The client sends an `initialize` **Request** — carrying `protocolVersion`,
   `capabilities`, and `clientInfo` — as a BRIDGE_REQUEST (§4.1). The negotiated
   protocol version and the capability objects live **inside** the carried JSON-RPC
   object and are carried verbatim; this mapping neither reads nor rewrites them.
2. The server replies with an `initialize` **Response** — carrying its
   `protocolVersion`, `capabilities`, `serverInfo`, and OPTIONAL `instructions` — as a
   BRIDGE_RESPONSE echoing the request's `correlation_id` (NPAMP-CC-JSONRPC §5, §8).
3. The client then sends the `notifications/initialized` **Notification** as a
   BRIDGE_NOTIFY (§4.3), after which normal operation proceeds.

Constraints specific to MCP that a carrying peer MUST preserve, all of which are
satisfied by carrying the objects transparently and in order:

- **Capability negotiation is end-to-end.** Which optional MCP features (server
  `tools`, `resources`, `prompts`, `logging`, `completions`, `tasks`; client
  `sampling`, `roots`, `elicitation`, `tasks`) are available is decided by the two MCP
  endpoints from the exchanged `capabilities` objects. The carriage MUST NOT synthesize,
  filter, or infer capabilities; a peer that does not carry a given method still carries
  the frame transparently and lets the endpoints negotiate (a capability a peer cannot
  carry SHOULD NOT be advertised — see §7).
- **Ordering.** The N-PAMP per-channel sequence space delivers frames on the Bridge
  channel in order per direction (core specification §5). The handshake ordering above
  is an MCP-layer obligation; the carriage does not reorder frames and MUST NOT reorder
  the handshake.
- **One session per channel direction.** All JSON-RPC messages of one MCP session are
  carried on the Bridge channel of one association (§7); this mapping does not split a
  single MCP session across channels or associations.
- **Pre-initialization traffic.** MCP permits `ping` before the `initialize` response
  and permits `ping` and logging before `notifications/initialized`. These ride the
  carriage as ordinary BRIDGE_REQUEST / BRIDGE_NOTIFY frames; the carriage imposes no
  additional gating.

## 6. SafetyLabel and state-mutating methods

The SafetyLabel TLV (Type `0x0013`) and its fail-safe semantics are governed by
NPAMP-BRIDGE §7 and inherited through NPAMP-CC-JSONRPC §9 unchanged. JSON-RPC 2.0 does
not itself express whether a method mutates state; MCP does. This section fixes, for
MCP, which methods a sender MUST label and how.

When a carried MCP Request can cause side effects, the sender MUST attach a SafetyLabel
TLV describing the effect class, an intermediary MUST carry it unchanged, and — the
fail-safe — a receiver MUST NOT treat the **absence** of a SafetyLabel on a
state-mutating method as `read_only`; absence on such a method MUST be treated as
`destructive` (NPAMP-BRIDGE §7).

### 6.1 Effect class by method

| MCP method(s) | Effect (NPAMP-BRIDGE §7) | Rationale |
|---|---|---|
| `initialize`, `ping`, `tools/list`, `resources/list`, `resources/templates/list`, `resources/read`, `prompts/list`, `prompts/get`, `completion/complete`, `roots/list`, `tasks/get`, `tasks/result`, `tasks/list` | `0x00` read_only | Discovery, reads, and lifecycle/liveness that do not act on external state. A SafetyLabel MAY be omitted; absence is correctly read as read_only for these. |
| `resources/subscribe`, `resources/unsubscribe`, `logging/setLevel` | `0x01` idempotent_write | Mutate session-scoped subscription or logging state on the responder; repeating with the same arguments yields the same state. The sender SHOULD attach the SafetyLabel; on absence the receiver MUST fail-safe to `destructive`. |
| `tasks/cancel` | `0x01` idempotent_write (at minimum) | Changes task lifecycle state; cancelling an already-cancelled task is a no-op. The sender MUST attach a SafetyLabel reflecting the actual effect. |
| `sampling/createMessage`, `elicitation/create` | `0x02` non_idempotent_write | Server-originated requests that cause the client to perform work with observable effect (an LLM completion; a user prompt); each invocation is a fresh action. The sender (the MCP server) MUST attach a SafetyLabel. |
| `tools/call` | Variable — derived per §6.2 | A tool is arbitrary code; its effect is the tool's, not MCP's. |

### 6.2 `tools/call` effect class from MCP tool annotations

MCP describes a tool's behavior with a `ToolAnnotations` object whose hint fields a
client learns from `tools/list`. The client, which originates the `tools/call`
BRIDGE_REQUEST, MUST derive the SafetyLabel `effect` from those hints as follows:

| MCP `ToolAnnotations` | SafetyLabel `effect` |
|---|---|
| `readOnlyHint = true` | `0x00` read_only |
| `readOnlyHint = false`, `destructiveHint = false`, `idempotentHint = true` | `0x01` idempotent_write |
| `readOnlyHint = false`, `destructiveHint = false`, `idempotentHint = false` | `0x02` non_idempotent_write |
| `readOnlyHint = false`, `destructiveHint = true` | `0x03` destructive |
| Annotations absent, or `readOnlyHint` unspecified | `0x03` destructive |

The last row is doubly grounded: MCP's own defaults are `readOnlyHint = false` and
`destructiveHint = true`, so an unannotated tool is destructive under MCP itself, and
NPAMP-BRIDGE §7's fail-safe independently requires `destructive` on an unlabeled
state-mutating operation. The two agree.

The `scope` field of the SafetyLabel (NPAMP-BRIDGE §7) MAY carry the tool `name` as an
advisory resource hint. The `openWorldHint` field has no SafetyLabel counterpart and is
not mapped.

MCP states that tool annotations are **untrusted** unless obtained from a trusted
server. This is consistent with NPAMP-BRIDGE §7: the SafetyLabel "describes intent and
does not replace authorization." A receiver MUST enforce its own authorization at
invocation and MUST NOT treat a favorable (for example `read_only`) SafetyLabel as
permission. The label conveys the sender's declared intent; it is not a security
guarantee about the tool.

## 7. Channel selection

MCP JSON-RPC traffic rides the **Bridge channel `0x000D`** by default, as required for
NPAMP-BRIDGE encapsulation (NPAMP-BRIDGE §1). Under this mapping, a peer carrying an MCP
session MUST carry that session's JSON-RPC messages on the Bridge channel. MCP's own
in-band discovery methods — `tools/list`, `resources/list`, `prompts/list`, and the
`*/templates/list` and `*_list_changed` companions — are ordinary JSON-RPC method
traffic and therefore ride the Bridge channel with the rest of the session; they are
not moved to the Discovery channel by this mapping.

Two OPTIONAL uses of the Discovery channel `0x0010` are available around, not in place
of, that session:

- **Advertising MCP as a carried protocol.** A peer MAY advertise, over NPAMP-DISC on
  the Discovery channel `0x0010`, a protocol Discovery Record (`kind = 1`) whose
  `protocol_id` is `0x01`, whose `carriage_class` is JSONRPC, and whose OPTIONAL
  `methods` list names the MCP methods it carries (NPAMP-DISC §5.1). This announces
  that the peer carries MCP; it does not carry MCP traffic. A peer MUST NOT advertise
  MCP if it cannot in fact carry `protocol_id 0x01` over the association (NPAMP-DISC
  §5.1).
- **Capability/discovery documents.** Where a deployment publishes MCP capability or
  schema material as a self-contained **document** — for example a tool catalog or
  schema rendered as a signed artifact — that document MAY ride the Discovery channel
  `0x0010` under NPAMP-CC-DOC (NPAMP-CC-DOC §1.1, §3), which is the class for capability
  and schema documents and their detached proofs. This is distinct from the live
  `tools/list` method result, which remains JSON-RPC traffic on the Bridge channel. A
  single MCP JSON-RPC session MUST NOT be split across the Bridge and Discovery
  channels.

## 8. Transport-binding and version notes

MCP defines stdio and Streamable HTTP transports and, for the HTTP transport, an
`MCP-Protocol-Version` HTTP header on subsequent requests. Over N-PAMP, **N-PAMP is the
transport**: MCP's stdio and HTTP transport bindings do not apply, and there is no
`MCP-Protocol-Version` header at the N-PAMP layer. Protocol-version agreement is carried
entirely within the `initialize` Request and Response objects (§5), which are carried
verbatim; a peer MUST NOT attempt to convey or enforce the MCP protocol version through
any N-PAMP envelope field. The N-PAMP association supplies authentication, post-quantum
confidentiality and integrity, multiplexing, and the key schedule (core specification);
these replace, and are not layered on top of, MCP's transport bindings.

MCP session state (the negotiated capabilities and version) is scoped to the MCP session
carried on the association and is re-established by a fresh `initialize` handshake on a
new association; a peer MUST NOT carry MCP session state from a prior association into a
new one.

## 9. References

Normative for the carriage:

- draft-bubblefish-npamp-01 — the N-PAMP core specification (Bridge channel `0x000D`,
  Discovery channel `0x0010`, the frame format, the BridgeEnvelope and SafetyLabel TLV
  reservations, and AEAD payload protection).
- NPAMP-BRIDGE (`10_bridge_framework.md`) — the encapsulation, correlation, error, and
  SafetyLabel contract.
- NPAMP-CC-JSONRPC (`20_carriage_jsonrpc.md`) — the JSON-RPC 2.0 carriage class that
  does the structural work for MCP.
- NPAMP-REG (`30_protocol_registry.md`) — the assignment of `protocol_id 0x01` to MCP.
- NPAMP-DISC (`40_discovery.md`) and NPAMP-CC-DOC (`24_carriage_documents.md`) — the
  Discovery-channel advertisement and document-carriage referenced in §7.
- BCP 14: RFC 2119 and RFC 8174 — requirement key words.
- JSON-RPC 2.0 Specification — <https://www.jsonrpc.org/specification>.

MCP source specification (primary sources consulted for §4, §5, §6; MCP revision
`2025-11-25`, the latest ratified revision at the time of writing):

- MCP Specification (index / overview; confirms JSON-RPC 2.0, stateful connections,
  server/client feature set) — <https://modelcontextprotocol.io/specification/2025-11-25>
- MCP Lifecycle (the `initialize` handshake, capability negotiation, version
  negotiation, `notifications/initialized`) —
  <https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle>
- MCP Server / Tools (`tools/list`, `tools/call`, `ToolAnnotations` hint fields and
  their defaults) —
  <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>
- MCP schema `schema.ts` (the single source of truth for the method namespace,
  `LATEST_PROTOCOL_VERSION = "2025-11-25"`, `JSONRPC_VERSION = "2.0"`, and the
  `ToolAnnotations` interface) —
  <https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/schema/2025-11-25/schema.ts>

A later MCP revision (a `2026-07-28` release candidate) was in progress at the time of
writing and is not relied upon here; it may adjust the method set and some error-code
choices. Because this mapping is transparent over the method string (§4), such a revision
is carried without a change to this document; only §4's illustrative table and §6's
effect-class guidance track the specific ratified revision named above.

## 10. Conformance

An implementation conforms to NPAMP-MAP-MCP if and only if it conforms to
NPAMP-CC-JSONRPC (and therefore to NPAMP-BRIDGE) and, for MCP traffic, it:

1. Carries every MCP JSON-RPC object under `protocol_id = 0x01` with
   `content_type = 0x01`, octet-for-octet, and selects MCP solely from `protocol_id`,
   never from another envelope field (§2, §3);
2. Maps MCP messages onto NPAMP-BRIDGE frames per §4 — a Request bearing an `id` to
   BRIDGE_REQUEST (`message_kind = 0x01`), a success Response to BRIDGE_RESPONSE
   (`0x02`), an `error` Response to BRIDGE_ERROR (`0x04`) with the MCP error object
   preserved verbatim, and a Notification (no `id`) to BRIDGE_NOTIFY (`0x03`,
   `corr_len = 0`) — with the BridgeEnvelope `method` equal to the MCP `method` member
   for requests and notifications (§3, §4);
3. Permits either peer to originate a BRIDGE_REQUEST, carrying server-originated MCP
   requests (`sampling/createMessage`, `roots/list`, `elicitation/create`, `ping`, and
   the `tasks/*` requests) in the reverse direction with the same correlation as
   client-originated requests (§4.1, §4.2; NPAMP-BRIDGE §5);
4. Carries the `initialize` Request/Response and the `notifications/initialized`
   Notification transparently and in order, and neither reads, synthesizes, filters, nor
   rewrites the negotiated `protocolVersion` or `capabilities`, which remain end-to-end
   between the MCP endpoints (§5);
5. Attaches a SafetyLabel to every state-mutating MCP Request it originates, using the
   effect classes of §6.1, and — for `tools/call` — derives the effect class from the
   tool's MCP annotations per §6.2, labelling an unannotated or non-`readOnly` tool
   `destructive` (§6.2);
6. Treats a missing SafetyLabel on any method not listed as read_only in §6.1 as
   `destructive` (NPAMP-BRIDGE §7 fail-safe), and never treats a favorable SafetyLabel
   as authorization, enforcing its own authorization at invocation (§6);
7. Carries an MCP session's JSON-RPC traffic on the Bridge channel `0x000D`, does not
   split a single MCP session across channels, and uses the Discovery channel `0x0010`
   only for the OPTIONAL protocol advertisement (NPAMP-DISC) or capability/schema
   document carriage (NPAMP-CC-DOC) of §7, never for live MCP JSON-RPC method traffic
   (§7); and
8. Does not apply MCP's stdio/HTTP transport bindings or any `MCP-Protocol-Version`
   N-PAMP header, conveying the MCP protocol version only inside the carried
   `initialize` objects, and carries no MCP session state across associations (§8).

A conformance test suite SHOULD assert each clause above with recorded exchanges that
include: an `initialize` / `initialize`-Response / `notifications/initialized`
handshake; a `tools/list` followed by a `tools/call` whose SafetyLabel effect class is
derived from the tool's annotations, including an unannotated tool that MUST be labelled
`destructive`; a server-originated `sampling/createMessage` request carried as a reverse
BRIDGE_REQUEST; an MCP `error` Response carried as BRIDGE_ERROR with its code and any
`data` preserved verbatim; and a `notifications/resources/updated` notification carried
as BRIDGE_NOTIFY with no reply.
