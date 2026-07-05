# NPAMP-MAP-MSAGENTFW — Microsoft Agent Framework Mapping (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is a **thin per-protocol mapping** for the **Microsoft Agent
> Framework (MAF)**. It is marked **OPAQUE-READY**: MAF is an agent **framework/SDK,
> not a wire protocol**, and — as confirmed against its own published documentation
> (§9) — it defines **no native message format, no native method namespace, and no
> native error codes** of its own. MAF exposes and consumes agents through **other**
> protocols by way of pluggable "protocol adapters": A2A, an MCP server surface,
> AG-UI, and OpenAI-compatible Chat Completions / Responses HTTP APIs. Consequently
> the substantive carriage of MAF traffic is done by the mapping or carriage class of
> **whichever protocol a given MAF endpoint actually speaks** — NPAMP-MAP-A2A
> (`61_map_a2a.md`), NPAMP-MAP-MCP (`60_map_mcp.md`), NPAMP-CC-HTTP
> (`21_carriage_http.md`), NPAMP-CC-STREAM (`23_carriage_streaming.md`), and where an
> AG-UI mapping is authored, NPAMP-MAP-AGUI (`64_map_agui.md`). This document pins only
> the MAF-specific facts, states precisely what is confirmed versus unconfirmed (§7),
> and provides a **Class OPAQUE** carriage (NPAMP-CC-OPAQUE, `25_carriage_opaque.md`)
> for any residual MAF surface that no existing mapping covers. It builds on
> **NPAMP-BRIDGE** (`10_bridge_framework.md`) and the N-PAMP core specification
> (draft-bubblefish-npamp-01, the "core specification"), consumes only code points those
> documents already reserve, and introduces no new frame type, no new TLV, and no change
> to the core wire format or to NPAMP-BRIDGE.

## 1. Scope

### 1.1 In scope

This document defines how Microsoft Agent Framework traffic is carried over an N-PAMP
association. Because MAF is a framework rather than a protocol, "carrying MAF" means
carrying the protocol a MAF endpoint is configured to expose or consume. This document
pins, and only pins, the MAF-specific facts a peer needs:

- MAF's **status** as a framework with no native wire protocol, its provisional
  `protocol_id`, and its carriage-class set (§2);
- How each MAF **adapter surface** (A2A, MCP server, AG-UI, OpenAI-compatible HTTP,
  and durable/Azure-Functions HTTP) rides an **existing** N-PAMP mapping or carriage
  class rather than a new one (§4);
- The **SafetyLabel effect class** a sender attaches to a MAF **agent-invocation** and
  the fail-safe on absence (§5);
- **Channel selection** for MAF traffic, which follows the carried protocol's own
  channel choice with Bridge `0x000D` as the default (§6); and
- An explicit account of what is **confirmed** by MAF's published documentation and what
  is **unconfirmed** and therefore deferred to Class OPAQUE (§7).

### 1.2 Not in scope

The following are explicitly NOT defined by this document:

- **A native Microsoft Agent Framework wire protocol.** None is defined by MAF (§2, §9),
  so none is mapped here. If a future MAF release publishes a distinct native transport
  and message format, a native mapping is authored against that source at that time (§7).
- **The carriage of A2A, MCP, or AG-UI traffic emitted by MAF.** That carriage is the
  subject of NPAMP-MAP-A2A, NPAMP-MAP-MCP, and NPAMP-MAP-AGUI respectively; when a MAF
  endpoint speaks one of those protocols, that protocol's mapping governs, not this one
  (§4). This document does not restate, summarize, or alter those mappings.
- **The semantics, request/result schemas, or event grammars of any carried protocol.**
  Those are fixed by A2A, MCP, AG-UI, or the OpenAI-compatible API and are carried
  verbatim (NPAMP-BRIDGE §1); this document does not parse, validate, or re-encode them.
- **MAF's internal, in-process constructs** — the `AIAgent` abstraction, graph-based
  workflows, session stores, middleware, and context providers — which are library
  concepts, not on-the-wire messages, and never appear on an N-PAMP association.
- **Any change to NPAMP-BRIDGE, to any carriage class, or to the core wire format**,
  including the BridgeEnvelope and SafetyLabel TLVs, which are used exactly as their
  defining documents specify.
- **The Microsoft Agent Host Protocol (AHP)**, a separate Microsoft project for
  synchronized multi-client agent-session state, whose relationship to MAF is not
  confirmed here (§7); it is out of scope for this mapping.

## 2. Protocol identity and status

| Property | Value |
|---|---|
| Protocol | Microsoft Agent Framework (MAF) — an open-source agent framework/SDK for .NET and Python (successor to Semantic Kernel and AutoGen). |
| Kind | **Framework, not a wire protocol.** MAF defines no native message format, method namespace, or error codes; its hosting libraries are protocol adapters over other protocols (§4, §9). |
| Mapping status | **OPAQUE-READY.** Carriable today via Class OPAQUE; the substantive carriage of any MAF endpoint's traffic is done by the mapping/class of the protocol that endpoint speaks (§4). |
| `protocol_id` | **PROVISIONAL.** NPAMP-REG (`30_protocol_registry.md`) §6 assigns MAF **no** standards code point (it assigns `0x01`–`0x04` only). For the residual OPAQUE case, a sender uses an **experimental-range** value (`0x10`–`0x7F`) agreed out of band; this document names **`0x3F`** as a non-normative development placeholder with no cross-domain meaning (NPAMP-REG §7.1). |
| Carriage class | **JSONRPC / HTTP / STREAM**, with **OPAQUE** as the fallback — one class per adapter surface (§4). |
| `content_type` | Per the carried protocol: `0x01` (application/json) for A2A / MCP / AG-UI / OpenAI-compatible JSON; `text/plain` and others as the OpenAI-compatible or durable HTTP surface declares (carried via NPAMP-CC-OPAQUE content-type declaration where not enumerated). |

Normative consequences of MAF's framework status:

- A sender carrying traffic that a MAF endpoint emits **as A2A** MUST use `protocol_id`
  `0x02` and NPAMP-MAP-A2A; **as MCP** MUST use `protocol_id` `0x01` and NPAMP-MAP-MCP.
  It MUST NOT relabel already-mapped A2A or MCP traffic under a MAF experimental code
  point merely because MAF produced it; the assigned code point of the actual protocol
  governs (NPAMP-REG §7.1, which forbids an experimental default for a protocol that has
  an assigned code point).
- The experimental value `0x3F` (or any `0x10`–`0x7F` value) carries **no** cross-vendor
  meaning. A sender MUST NOT emit it toward a peer without prior out-of-band agreement on
  its meaning, and a receiver with no such agreement MUST treat it as an uncarried
  protocol and reply `ProtocolUnsupported` (NPAMP-REG §7.1, §9).
- A receiver selects the foreign protocol solely from `protocol_id` and MUST NOT infer
  "this is MAF" from any other envelope field (NPAMP-REG §9).

## 3. Relationship to the carriage classes and the registry

This document is a registration-shaped **pointer**: it records MAF's framework status and
directs each MAF adapter surface to the existing mapping or carriage class that already
does the structural work. It defines no structural carriage of its own.

| Facility | Owning document | Use here |
|---|---|---|
| `protocol_id` partition and experimental range | NPAMP-BRIDGE §4; NPAMP-REG §4, §7 | The provisional `0x3F` placeholder and the "use the real protocol's code point" rule (§2). |
| JSON-RPC 2.0 carriage | NPAMP-CC-JSONRPC (`20_carriage_jsonrpc.md`) | Structural carriage of MAF-over-A2A and MAF-over-MCP JSON-RPC (§4), via NPAMP-MAP-A2A / NPAMP-MAP-MCP. |
| HTTP-semantics carriage | NPAMP-CC-HTTP (`21_carriage_http.md`) | Carriage of MAF's OpenAI-compatible and durable/Azure-Functions HTTP request/response surface (§4). |
| Streaming carriage | NPAMP-CC-STREAM (`23_carriage_streaming.md`) | Carriage of MAF's AG-UI and OpenAI-compatible Server-Sent-Event token/response streams (§4). |
| Opaque carriage | NPAMP-CC-OPAQUE (`25_carriage_opaque.md`) | The fallback for any residual MAF surface no mapping covers (§2, §4, §7). |
| BridgeEnvelope / SafetyLabel TLVs | Core specification; NPAMP-BRIDGE §4, §7 | Carried unchanged on every MAF frame (§5). |

Where this document and a carried protocol's own mapping could appear to differ on a
structural matter, the **carried protocol's mapping governs**; this document adds nothing
structural and only classifies effect (§5) and channel (§6) at the framework layer.

## 4. What Microsoft Agent Framework carries

MAF's hosting libraries are described in its documentation as **protocol adapters** that
"bridge external communication protocols and the Agent Framework's internal `AIAgent`
implementation" (§9). Each adapter exposes (or consumes) one existing protocol. The table
maps each **confirmed** MAF adapter surface to the N-PAMP carriage it rides. The MAF
column names the surface as MAF's own documentation names it; the operation strings are
those of the **carried** protocol, not of MAF.

| MAF adapter surface (confirmed, §9) | Carried protocol / transport | N-PAMP carriage | `protocol_id` |
|---|---|---|---|
| A2A hosting (`/a2a/{agent}` HTTP+JSON binding; agent card at `/.well-known/agent.json`) | A2A (JSON-RPC 2.0; SSE streaming; AgentCard document) | **NPAMP-MAP-A2A** (JSONRPC + STREAM + DOC) | `0x02` |
| MCP server surface (expose an agent as an MCP server) | MCP (JSON-RPC 2.0) | **NPAMP-MAP-MCP** (JSONRPC) | `0x01` |
| AG-UI hosting (`MapAGUI` / `AddAGUI`; HTTP POST request, SSE event stream, JSON events, `ConversationId` thread id, `ResponseId` run id) | AG-UI (HTTP POST + Server-Sent Events) | **NPAMP-CC-STREAM** (request + typed event stream); NPAMP-MAP-AGUI when authored | AG-UI has no assigned code point; a future AG-UI assignment (`0x05`–`0x0F`), else experimental by agreement |
| OpenAI-compatible endpoints (expose via Chat Completions / Responses APIs) | OpenAI-compatible HTTP request/response; SSE for streamed tokens | **NPAMP-CC-HTTP** (unary) + **NPAMP-CC-STREAM** (token stream) | `0x03` (HTTP generic carriage) |
| Durable / Azure Functions hosting (`POST /api/agents/{agent}/run`) | HTTP request/response | **NPAMP-CC-HTTP** | `0x03` (HTTP generic carriage) |
| Residual MAF surface not covered above | declared-content-type payload | **NPAMP-CC-OPAQUE** | `0x3F` PROVISIONAL (§2) |

Carriage requirements:

- When a MAF endpoint speaks a protocol that has an N-PAMP mapping (A2A, MCP) or a
  carriage class (HTTP, STREAM, OPAQUE), a peer MUST carry that traffic under **that**
  mapping or class, with that protocol's `protocol_id`, `content_type`, correlation, and
  error model, exactly as the owning document specifies. This mapping introduces no
  alternative framing for A2A, MCP, AG-UI, or OpenAI-compatible traffic.
- The **only cross-adapter primitive** MAF exposes at every surface is **agent
  invocation** — "run the agent" (for example `agent.Run` / `RunStreamingAsync`, an A2A
  `message/send` / `message/stream`, an AG-UI HTTP POST, an OpenAI chat/responses create,
  or `POST /api/agents/{agent}/run`). Its SafetyLabel treatment is fixed in §5; its
  structural carriage is the carried protocol's (a JSON-RPC Request under NPAMP-CC-JSONRPC,
  an HTTP request under NPAMP-CC-HTTP, or an SSE stream under NPAMP-CC-STREAM).
- A receiver that does not carry the indicated protocol MUST reply `ProtocolUnsupported`
  for a BRIDGE_REQUEST and MUST NOT report success for traffic it did not carry
  (NPAMP-BRIDGE §6; NPAMP-REG §9). A foreign error raised by the carried protocol is
  carried verbatim as BRIDGE_ERROR (NPAMP-BRIDGE §6); this mapping defines no error codes.
- Because MAF publishes no native method namespace, an implementation MUST NOT invent MAF
  method strings, MAF error codes, or a MAF `content_type`; the `method`, error object,
  and content type are always the carried protocol's (A3/E4: names are contracts).

## 5. SafetyLabel effect classes for mutating operations

The SafetyLabel TLV (Type `0x0013`) and its fail-safe are governed by NPAMP-BRIDGE §7 and
are unchanged here. When MAF traffic is carried under an existing mapping, that mapping's
effect classification applies unchanged — NPAMP-MAP-A2A §5 for A2A methods and
NPAMP-MAP-MCP §6 for MCP methods (including the `tools/call` derivation from tool
annotations, NPAMP-MAP-MCP §6.2). This section adds only the framework-layer classification
of the cross-adapter primitive and the fail-safe restatement.

| MAF operation | Effect (NPAMP-BRIDGE §7) | Rationale |
|---|---|---|
| Agent invocation — "run" the agent (any adapter: A2A `message/send`/`message/stream`, AG-UI POST, OpenAI chat/responses create, `POST /api/agents/{agent}/run`) | `0x02` non_idempotent_write (at minimum) | Invoking an agent produces new model work and may cause tool side effects; re-running is not idempotent. A deployment MAY classify a specific run `0x03` destructive per its own policy; a sender MUST attach a SafetyLabel. |
| Tool invocation within an agent run | Derived per the carried protocol | When carried as MCP, derive from MCP tool annotations (NPAMP-MAP-MCP §6.2); when carried as A2A, per NPAMP-MAP-A2A §5. An unannotated tool is `0x03` destructive. |
| Session / thread / conversation state change (create/update `ConversationId`/`threadId`, push-notification config) | `0x01` idempotent_write | Mutates session-scoped state; setting the same value yields the same state. Sender SHOULD attach a SafetyLabel. |
| Read / discovery (AgentCard fetch, MCP `tools/list`, A2A `tasks/get`) | `0x00` read_only | Reads or lists; no external state change. A SafetyLabel MAY be omitted. |

Requirements:

- For any MAF-carried operation whose effect above is not `0x00`, the sender MUST attach a
  SafetyLabel TLV to the carrying request, and an intermediary MUST carry it unchanged.
- A receiver MUST NOT treat the **absence** of a SafetyLabel on a state-mutating operation
  — including a bare agent invocation — as `read_only`; absence on such an operation MUST
  be treated as `destructive` (fail-safe; NPAMP-BRIDGE §7).
- The effect value classifies declared intent; it does not replace the MAF endpoint's own
  authorization decision. A receiver MUST enforce its own authorization at invocation and
  MUST NOT treat a favorable SafetyLabel as permission.

## 6. Channel selection

MAF traffic follows the **channel choice of the protocol it is carried as**, with the
Bridge channel `0x000D` the default for all NPAMP-BRIDGE encapsulation (NPAMP-BRIDGE §1).

| MAF traffic class | Carriage | Channel |
|---|---|---|
| A2A / MCP JSON-RPC methods | NPAMP-MAP-A2A / NPAMP-MAP-MCP (JSONRPC) | Bridge `0x000D` |
| A2A streaming; AG-UI and OpenAI SSE token/response streams | NPAMP-CC-STREAM | Bridge `0x000D`; MAY use Stream `0x000C` for full-duplex streaming |
| OpenAI-compatible / durable HTTP request/response | NPAMP-CC-HTTP | Bridge `0x000D` |
| AgentCard, MCP tool listings, capability advertisement | NPAMP-CC-DOC / NPAMP-DISC | Bridge `0x000D` default; MAY use Discovery `0x0010` |
| AG-UI human-facing interaction events | NPAMP-CC-STREAM | Bridge `0x000D`; MAY use Interaction `0x000F` |
| Residual MAF surface | NPAMP-CC-OPAQUE | Bridge `0x000D` |

The Bridge `0x000D`, Discovery `0x0010`, Stream `0x000C`, and Interaction `0x000F`
channels are all minimum-profile **Standard** (core-specification channel registry;
`../../registries/channels.csv`); MAF carriage requires no channel above the Standard
profile. A single carried session (for example one A2A session or one AG-UI run stream)
MUST NOT be split across channels. A peer MUST NOT send or accept MAF frames on a channel
it did not advertise during the handshake (core specification §5).

## 7. What is confirmed versus unconfirmed

This mapping is **OPAQUE-READY** precisely because the substantive facts below are the
carried protocols', not MAF's. The distinction is stated here so an implementer does not
mistake a framework property for a wire property.

**Confirmed** against MAF's published documentation (§9):

1. MAF is a framework/SDK for .NET and Python that hosts and consumes agents; its hosting
   libraries are **protocol adapters** over external protocols, keeping the agent
   implementation "protocol-agnostic."
2. The confirmed adapter surfaces are **A2A** (`/a2a/{agent}`, HTTP+JSON binding, agent
   card at `/.well-known/agent.json`), an **MCP server** surface, **AG-UI** (HTTP POST +
   Server-Sent Events, JSON events, `ConversationId`/`ResponseId`), **OpenAI-compatible**
   Chat Completions / Responses endpoints, and **durable / Azure Functions** HTTP
   (`POST /api/agents/{agent}/run`).
3. MAF publishes **no distinct native wire protocol, message frame, method namespace, or
   error-code set** of its own; the observable wire traffic is always the carried
   protocol's.

**Unconfirmed, and therefore deferred (Class OPAQUE, or the carried protocol's mapping):**

1. **No standards `protocol_id`.** NPAMP-REG assigns MAF none; `0x3F` is a non-normative
   experimental placeholder only (§2). A standards code point would be sought under
   NPAMP-REG §8 only if MAF later publishes a distinct native protocol warranting one.
2. **AG-UI code point and native mapping.** AG-UI's own code point and NPAMP-MAP-AGUI
   (`64_map_agui.md`) are PLANNED, not authored; until then MAF-over-AG-UI rides
   NPAMP-CC-STREAM generically, and the exact AG-UI event set is fixed by AG-UI's own
   specification, not by MAF or this document.
3. **OpenAI-compatible and durable HTTP field mapping.** The precise request/response and
   SSE field mapping is the OpenAI-compatible API's and NPAMP-CC-HTTP/NPAMP-CC-STREAM's,
   confirmed against those sources; this document does not pin those fields.
4. **The Agent Host Protocol (AHP).** A separate Microsoft project (synchronized
   multi-client agent-session state) exists; its relationship to MAF and its wire
   details are **not confirmed here** and are out of scope (§1.2). No AHP field, method,
   or transport is asserted by this document.

No value in this document is asserted beyond what §9's sources support; where a fact was
MAF-external or unconfirmed, it is deferred above rather than fixed by assumption
(honesty over fabrication; NPAMP-CC-OPAQUE §1.3).

## 8. Security considerations

This mapping introduces no cryptography and changes none. All confidentiality, integrity,
authentication, downgrade resistance, and replay protection are provided by the core
specification's wire format and key schedule and apply unchanged to every carried MAF
frame, which travels inside the AEAD-protected Bridge (or other Standard-profile) payload.
Carrying MAF traffic over N-PAMP makes no security claim about MAF or any protocol it
adapts. In particular:

- **Transport-bound credentials.** MAF's adapter surfaces are defined over HTTP/HTTPS in
  native deployments and may bind authorization to HTTP-level mechanisms (for example
  bearer tokens in headers). Over N-PAMP the HTTP framing is subsumed; a credential a MAF
  endpoint binds to an HTTP element that does not exist over N-PAMP MUST be carried inside
  the foreign message or supplied by the association's own authentication, not
  reconstructed by the carrier (NPAMP-CC-OPAQUE §1.3, §9.3).
- **Untrusted payloads.** A carried MAF payload is untrusted input of its declared content
  type; a receiver MUST validate it before acting on it and MUST NOT infer MAF
  capabilities from the mere success of an exchange (NPAMP-CC-OPAQUE §9.2).
- **Safety fail-safe.** The effect classification of §5 and the NPAMP-BRIDGE §7 fail-safe
  (absence of a SafetyLabel on a state-mutating operation is `destructive`) apply to every
  MAF-carried operation, including a bare agent invocation. Discovery of a MAF agent or
  tool is a claim, not authorization (NPAMP-DISC §10).

## 9. References

Primary sources (Microsoft Agent Framework; consulted for §2, §4, §5, §7):

- Microsoft Agent Framework — Overview (framework categories: agents and workflows; model
  clients for chat completions and responses; MCP clients for tool integration) —
  <https://learn.microsoft.com/en-us/agent-framework/overview/>
- Microsoft Agent Framework — Step 6: Host Your Agent (hosting-options table: A2A Protocol,
  OpenAI-Compatible Endpoints, Durable Extension, AG-UI Protocol; "hosting libraries act as
  protocol adapters that bridge external communication protocols and the Agent Framework's
  internal `AIAgent`"; A2A `/a2a/{agent}` and Azure Functions `POST /api/agents/{agent}/run`)
  — <https://learn.microsoft.com/en-us/agent-framework/get-started/hosting>
- Microsoft Agent Framework — A2A Integration / Hosting (`Microsoft.Agents.AI.Hosting.A2A`,
  agent reachable over the A2A HTTP+JSON binding, agent card at `/.well-known/agent.json`) —
  <https://learn.microsoft.com/en-us/agent-framework/integrations/a2a>
- Microsoft Agent Framework — AG-UI Integration / Getting Started (protocol details: HTTP
  POST requests, Server-Sent Events for streaming, JSON event serialization, `ConversationId`
  thread ids, `ResponseId` run ids; `MapAGUI`/`AddAGUI`) —
  <https://learn.microsoft.com/en-us/agent-framework/integrations/ag-ui/getting-started>
- microsoft/agent-framework (repository; open-source SDK for .NET and Python; hosting via
  A2A, Azure Functions, Durable Task; successor to Semantic Kernel and AutoGen; no native
  wire protocol) — <https://github.com/microsoft/agent-framework>
- microsoft/agent-host-protocol (a **separate** Microsoft project — synchronized
  multi-client state for AI agent sessions; relationship to MAF not confirmed; noted as
  out of scope, §1.2, §7) — <https://github.com/microsoft/agent-host-protocol>

N-PAMP documents built on:

- draft-bubblefish-npamp-01 — the N-PAMP core specification (the frame format, the channel
  registry — Bridge `0x000D`, Stream `0x000C`, Interaction `0x000F`, Discovery `0x0010` —
  the extension-TLV encoding, and AEAD payload protection).
- NPAMP-BRIDGE (`10_bridge_framework.md`) — the encapsulation, BridgeEnvelope, correlation,
  structured-error, and SafetyLabel contract.
- NPAMP-REG (`30_protocol_registry.md`) — the Bridge Protocol Identifier registry, its
  range partition, and the experimental-range rules relied on in §2.
- NPAMP-CC-JSONRPC (`20_carriage_jsonrpc.md`), NPAMP-CC-HTTP (`21_carriage_http.md`),
  NPAMP-CC-STREAM (`23_carriage_streaming.md`), NPAMP-CC-DOC (`24_carriage_documents.md`),
  NPAMP-CC-OPAQUE (`25_carriage_opaque.md`) — the carriage classes named in §4.
- NPAMP-MAP-A2A (`61_map_a2a.md`), NPAMP-MAP-MCP (`60_map_mcp.md`), and NPAMP-MAP-AGUI
  (`64_map_agui.md`, PLANNED) — the per-protocol mappings MAF traffic rides (§4).
- NPAMP-DISC (`40_discovery.md`) — Discovery-channel advertisement referenced in §6, §8.
- BCP 14 (RFC 2119, RFC 8174) — requirement key words.

MAF is a versioned, evolving framework (v1.0 for .NET and Python at the time of writing).
Because this mapping selects the foreign protocol by `protocol_id` and defers structural
carriage to the carried protocol's mapping, a MAF version change that adds, renames, or
removes an adapter does not change this document: a new adapter surface is carried by the
mapping or class of the protocol it exposes, and only §4's illustrative table tracks the
specific adapters confirmed above.

## 10. Conformance

An implementation conforms to NPAMP-MAP-MSAGENTFW if and only if it conforms to
NPAMP-BRIDGE and, for Microsoft Agent Framework traffic, it:

1. Treats MAF as a framework with **no native wire protocol**, carrying each MAF adapter
   surface under the existing mapping or carriage class named in §4 — A2A under
   NPAMP-MAP-A2A (`protocol_id 0x02`), an MCP server surface under NPAMP-MAP-MCP
   (`protocol_id 0x01`), OpenAI-compatible / durable HTTP under NPAMP-CC-HTTP, and AG-UI /
   SSE streams under NPAMP-CC-STREAM — and never invents a MAF method string, MAF error
   code, or MAF `content_type` (§2, §4);
2. Does **not** relabel already-mapped A2A or MCP traffic under a MAF experimental
   `protocol_id`, using the assigned code point of the protocol the endpoint actually
   speaks, and never emits an experimental value (`0x3F` or any `0x10`–`0x7F`) without
   prior out-of-band agreement (§2; NPAMP-REG §7.1);
3. Selects the foreign protocol solely from `protocol_id`, never inferring "MAF" from any
   other envelope field, and replies `ProtocolUnsupported` for a request bearing a
   `protocol_id` it does not carry, never reporting success for uncarried traffic (§2, §4;
   NPAMP-REG §9);
4. Attaches a SafetyLabel with effect at least `0x02` non_idempotent_write to every MAF
   agent invocation it originates, derives an in-run tool call's effect from the carried
   protocol (an unannotated tool being `destructive`), and treats a missing SafetyLabel on
   any state-mutating operation as `destructive` (§5; NPAMP-BRIDGE §7), never treating a
   favorable label as authorization;
5. Carries MAF traffic on the channels of §6 — Bridge `0x000D` by default, with Stream
   `0x000C`, Interaction `0x000F`, or Discovery `0x0010` only as §6 permits — never
   splitting a single carried session across channels, and sends or accepts MAF frames only
   on channels advertised during the handshake (§6);
6. Carries any residual MAF surface not covered by clause 1 under Class OPAQUE
   (NPAMP-CC-OPAQUE), with a declared content type and octet-exact payload, and makes no
   claim that Class OPAQUE supplies transport-bound authentication or discovery (§4, §7,
   §8); and
7. Defines no new frame type, TLV, or code point, and introduces no change to the core
   wire format, to NPAMP-BRIDGE, or to any carriage class or mapping it references (§1.2,
   §3).

A conformance test suite SHOULD assert each clause above with recorded exchanges that
include at least: a MAF-hosted A2A `message/send` carried under NPAMP-MAP-A2A with
`protocol_id 0x02`; a MAF MCP-server `tools/call` carried under NPAMP-MAP-MCP with a
SafetyLabel derived from the tool's annotations, including an unannotated tool treated as
`destructive`; a MAF agent invocation carried with the SafetyLabel omitted, verified to be
treated as `destructive`; a MAF AG-UI HTTP-POST-plus-SSE run carried under NPAMP-CC-STREAM;
and a residual MAF payload carried under Class OPAQUE with a declared content type and a
below-foreign-protocol failure reported with an NPAMP-BRIDGE transport error code.
