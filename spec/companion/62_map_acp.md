# NPAMP-MAP-ACP — ACP (Agent Communication Protocol) Mapping (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is a **thin per-protocol mapping**: it pins the specifics of
> the **ACP (Agent Communication Protocol)** — the REST-over-HTTP agent protocol
> published at `agentcommunicationprotocol.dev` (the IBM/BeeAI `i-am-bee/acp`
> project; §11) — onto N-PAMP carriage. ACP is an **HTTP-semantics** protocol, so
> this mapping carries it under the HTTP carriage class **NPAMP-CC-HTTP**
> (`21_carriage_http.md`): that carriage class does the structural work
> (request/response, streaming, header/body carriage, correlation, verbatim error
> carriage), and this document pins only what is specific to ACP. It builds on
> NPAMP-CC-HTTP, on NPAMP-BRIDGE (`10_bridge_framework.md`), and on the N-PAMP core
> specification (draft-bubblefish-npamp-01, the "core specification"). It consumes
> only code points those documents already reserve and introduces no new frame type,
> no new TLV, and no change to the core wire format, to NPAMP-BRIDGE, or to
> NPAMP-CC-HTTP.
>
> **Status of this mapping: OPAQUE-READY; `protocol_id` PROVISIONAL.** ACP is
> carriable over N-PAMP **today** via Class OPAQUE (`25_carriage_opaque.md`) with no
> protocol-specific mapping. This document supplies the native HTTP-class mapping.
> ACP's base transport (REST/HTTP) and its operation surface are **confirmed** from
> ACP's own published OpenAPI specification (§4, §11); its N-PAMP `protocol_id` is
> **not yet assigned** by the Bridge Protocol Identifier registry (NPAMP-REG §6) and
> is therefore PROVISIONAL (§2, §9). The ACP source project has additionally been
> **archived** and folded into A2A under the Linux Foundation; §9 states precisely
> what is confirmed versus unconfirmed and what a deployment carrying live,
> post-archival ACP-derived agents should read instead.

## 1. Scope

### 1.1 In scope

This document defines how an ACP endpoint interoperates over an N-PAMP association
without bespoke adaptation. It pins, against ACP's own published specification (§11),
only the ACP specifics that NPAMP-CC-HTTP leaves to a per-protocol mapping:

- The ACP **protocol identifier** (PROVISIONAL) and the foreign-message
  `content_type` for the HTTP carriage container (§2);
- ACP's REST **operation namespace** — the HTTP method and target of each ACP
  endpoint — and how each rides NPAMP-CC-HTTP as a Bridge frame (§4);
- How ACP's **run lifecycle** — creation, the `awaiting`/resume interaction, and the
  streamed (`text/event-stream`) run mode — rides the HTTP carriage, including the
  mapping of a streamed run onto NPAMP-CC-HTTP's streaming sequence (§5);
- The carriage of ACP's **agent manifest / discovery** reads (`GET /agents`,
  `GET /agents/{name}`) and the OPTIONAL use of the document carriage class for a
  manifest treated as a capability document (§6);
- Which ACP operations are state-mutating and therefore the **SafetyLabel effect
  class** a sender attaches, and the NPAMP-BRIDGE §7 fail-safe on absence (§7); and
- **Channel selection** for each ACP traffic class (§8).

The structural work — octet-exact carriage of the HTTP message, the HTTP-Carriage
Object, the BridgeEnvelope, correlation, the structured-error model, streaming, and
the SafetyLabel TLV — is done by NPAMP-BRIDGE and NPAMP-CC-HTTP and is not restated
here.

### 1.2 Not in scope

The following are explicitly NOT defined by this document, because NPAMP-CC-HTTP,
NPAMP-BRIDGE, or ACP's own specification already fix them:

- **The structural HTTP-semantics carriage** — the HTTP-Carriage Object (method,
  target, headers, body, status), request/response correlation, and streaming — which
  is inherited verbatim from NPAMP-CC-HTTP and is not restated (§3).
- **The ACP object schemas.** The internal grammar of `Run`, `Message`,
  `MessagePart`, the agent `Manifest`, `Event`, `await_request`/`await_resume`, and
  the ACP error objects is fixed by ACP's specification. This document carries these
  objects verbatim inside the HTTP body (NPAMP-BRIDGE §1; NPAMP-CC-HTTP §4.3) and does
  not parse, validate, or transform them.
- **ACP's native HTTP transport bindings and out-of-band exchanges.** ACP's own HTTP
  request line and header fields are subsumed by the HTTP-Carriage Object (§3); ACP's
  mDNS / central-registry agent discovery, its dereference of a `MessagePart`
  `content_url` to an external URI, and any callback delivered outside the N-PAMP
  association are **not** carried by this mapping (they leave the association; §6, §8,
  §10).
- **ACP transport-bound authentication.** ACP's HTTP-level credentials (for example a
  bearer token carried in an `Authorization` header, or mutual TLS) bind to an HTTP
  hop that does not exist over N-PAMP; they are carried only as opaque header/body
  octets and are neither validated nor re-bound by carriage (§10; NPAMP-CC-HTTP §8.3,
  §8.4).
- **The AGNTCY "Agent Connect Protocol."** A separate protocol, also abbreviated
  "ACP," is published by the AGNTCY collective; it is a different specification and is
  NOT the subject of this document (§9, §11). This mapping addresses only the
  Agent **Communication** Protocol at the primary sources cited in §11.
- **Any change to NPAMP-BRIDGE, to NPAMP-CC-HTTP, or to the core wire format**,
  including the BridgeEnvelope TLV and the SafetyLabel TLV, which are used as their
  defining documents specify.

## 2. Protocol identity

| Property | Value |
|---|---|
| Protocol | ACP — Agent Communication Protocol (REST-over-HTTP; `agentcommunicationprotocol.dev`, `github.com/i-am-bee/acp`; §11). |
| `protocol_id` | **PROVISIONAL.** No standards-assigned code point exists: NPAMP-REG §6 assigns `0x01`–`0x04` and reserves `0x05`–`0x0F` unassigned, and ACP is not among them. A sender MUST therefore carry ACP under an **experimental-range** `protocol_id` (`0x10`–`0x7F`) agreed out of band with the peer (NPAMP-REG §7.1; NPAMP-CC-HTTP §9.2), and MUST NOT emit ACP under a value that NPAMP-REG has assigned to another protocol. A standards-assigned identifier, if warranted, would be obtained under NPAMP-REG §8 (§9). |
| Carriage class | **HTTP** (NPAMP-CC-HTTP). Class OPAQUE (`25_carriage_opaque.md`) is the equivalent zero-mapping fallback available today (§3, §9). |
| `content_type` | `0x02` (`application/cbor`), as required by NPAMP-CC-HTTP §2.3 for the HTTP-Carriage Object container. The ACP JSON body carried **inside** that object retains its own media type (for example `application/json`) in the object's header-field list (NPAMP-CC-HTTP §4.4); `0x02` describes the carriage container, not the ACP payload. |
| Foreign-message form | One HTTP-Carriage Object (NPAMP-CC-HTTP §4) per Bridge frame, carrying one ACP HTTP request or response octet-for-octet (NPAMP-BRIDGE §1). |

A sender MUST set the same agreed experimental `protocol_id` on every Bridge frame
carrying an ACP message. A receiver that does not carry ACP MUST reply to a
BRIDGE_REQUEST bearing that value with `ProtocolUnsupported` (NPAMP-BRIDGE §6;
NPAMP-REG §9), and MUST NOT infer ACP from any other envelope field (NPAMP-REG §9).

## 3. Relationship to NPAMP-CC-HTTP and NPAMP-BRIDGE

ACP is defined in terms of HTTP semantics: each operation is an HTTP request bearing a
method and a target, answered by an HTTP response bearing a status code, header fields,
and an optional body. Consequently the entire structural carriage of ACP is provided by
NPAMP-CC-HTTP without modification:

- The transparency rule governs: an ACP HTTP message is carried octet-for-octet inside
  the HTTP-Carriage Object's typed keys and `body`, and MUST NOT be re-serialized,
  reordered, canonicalized, or rewritten (NPAMP-BRIDGE §1; NPAMP-CC-HTTP §2.1, §4.3).
- An ACP request maps to **BRIDGE_REQUEST** (`0x0100`); a non-streamed ACP response to
  **BRIDGE_RESPONSE** (`0x0101`); a streamed ACP response to a
  **BRIDGE_STREAM_DATA**\* / **BRIDGE_STREAM_END** sequence; and a sub-foreign carriage
  failure to **BRIDGE_ERROR** (`0x0102`) with an N-PAMP transport-error code
  (NPAMP-CC-HTTP §2.2, §6). This document adds no frame type.
- An ACP HTTP response whose status is a client or server error (`4xx`/`5xx`) is a
  **successful carriage of a foreign result** and MUST be carried as a BRIDGE_RESPONSE
  with that status and the ACP error body preserved verbatim — never re-labelled as a
  BRIDGE_ERROR, and never remapped to or from an N-PAMP transport-error code
  (NPAMP-CC-HTTP §6.1). A sender MUST NOT fabricate an HTTP status for a carriage-level
  failure (NPAMP-CC-HTTP §6.2).
- The BridgeEnvelope `method` field carries the HTTP routing key — the ACP HTTP method
  token, a single SPACE, and the request target (origin-form path plus any query) — for
  a request, and is empty for a response, stream, or error frame (NPAMP-CC-HTTP §2.4).
  The authoritative method and target remain the HTTP-Carriage Object's own keys.

This document therefore pins only ACP specifics (§2, §4–§8). Where this document and
NPAMP-CC-HTTP could appear to differ on a structural matter, NPAMP-CC-HTTP governs.

## 4. ACP operation namespace and frame mapping

ACP exposes a small, fixed REST surface. The table enumerates the ACP operations of the
published OpenAPI specification (§11), the HTTP method and target each uses, and the
NPAMP-BRIDGE frame(s) each rides under NPAMP-CC-HTTP. The `method`/`target` pair in each
row is the exact value carried in the HTTP-Carriage Object and reflected in the
BridgeEnvelope `method` routing key (NPAMP-CC-HTTP §2.4).

| ACP operation (`operationId`) | HTTP method + target | NPAMP-BRIDGE frame(s) | Effect (§7) |
|---|---|---|---|
| `ping` | `GET /ping` | BRIDGE_REQUEST → BRIDGE_RESPONSE | `0x00` read_only |
| `listAgents` | `GET /agents` | BRIDGE_REQUEST → BRIDGE_RESPONSE | `0x00` read_only |
| `getAgent` | `GET /agents/{name}` | BRIDGE_REQUEST → BRIDGE_RESPONSE (§6) | `0x00` read_only |
| `createRun` | `POST /runs` | BRIDGE_REQUEST → BRIDGE_RESPONSE, **or** streamed (§5) | `0x02` non_idempotent_write |
| `getRun` | `GET /runs/{run_id}` | BRIDGE_REQUEST → BRIDGE_RESPONSE | `0x00` read_only |
| `resumeRun` | `POST /runs/{run_id}` | BRIDGE_REQUEST → BRIDGE_RESPONSE, **or** streamed (§5) | `0x02` non_idempotent_write |
| `cancelRun` | `POST /runs/{run_id}/cancel` | BRIDGE_REQUEST → BRIDGE_RESPONSE | `0x02` non_idempotent_write (§7) |
| `listRunEvents` | `GET /runs/{run_id}/events` | BRIDGE_REQUEST → BRIDGE_RESPONSE | `0x00` read_only |
| `getSession` | `GET /session/{session_id}` | BRIDGE_REQUEST → BRIDGE_RESPONSE | `0x00` read_only |

Carriage requirements:

- For each operation, the sender MUST populate the HTTP-Carriage Object `method` and
  `target` keys with the HTTP method token and the origin-form target (path plus any
  query), MUST set the BridgeEnvelope `method` field to "`<method> <target>`", and MUST
  supply a non-empty `correlation_id` unique among its outstanding requests in that
  direction (NPAMP-CC-HTTP §2.4, §3). The ACP request or response body is carried in the
  object's `body` key, verbatim (NPAMP-CC-HTTP §4.3).
- Either peer MAY originate a BRIDGE_REQUEST (NPAMP-BRIDGE §5); an ACP client is the
  requester and an ACP server the responder for a given exchange, but the carriage
  places no additional directional restriction.
- A receiver that carries ACP but does not implement a recognized ACP operation MUST
  report `MethodUnsupported` (NPAMP-BRIDGE §6 code 3; NPAMP-CC-HTTP §6.2) for a
  BRIDGE_REQUEST bearing it, and MUST NOT report success for an operation it did not
  perform. This is distinct from an ACP-level HTTP error (for example a `404` for an
  unknown `run_id`), which is a foreign result carried as a BRIDGE_RESPONSE (§3).

> **Surface note.** The operation set above is that of the published (archived) ACP
> OpenAPI specification (§9, §11). Because the carriage is transparent over the HTTP
> method and target (NPAMP-CC-HTTP §2.4), a peer carries an ACP endpoint whether or not
> it appears in this table; an implementation MUST NOT reject an ACP request solely
> because its target is absent here. The published specification, not this table, fixes
> the operation set.

## 5. Run lifecycle, streaming, and resume

An ACP **run** is created by `POST /runs` (`createRun`), which starts execution of the
named agent, and progresses through a status the client reads with `GET /runs/{run_id}`
(`getRun`). ACP defines run **modes** `sync`, `async`, and `stream`, and a run status
that includes `created`, `in-progress`, `awaiting`, `cancelling`, `cancelled`,
`completed`, and `failed` (§11). All of this lifecycle lives **inside** the carried ACP
HTTP messages; this mapping neither reads nor rewrites it, and carries each message
transparently and in order:

- **Non-streamed run (`sync`/`async`).** `createRun` and `resumeRun` are carried as an
  ordinary HTTP request/response exchange (§4): one BRIDGE_REQUEST answered by one
  BRIDGE_RESPONSE whose HTTP-Carriage Object `body` is the ACP `Run` object.
- **Streamed run (`stream`).** When a run is requested in stream mode, the ACP server
  replies with an HTTP response of media type `text/event-stream` (Server-Sent Events)
  whose event payloads are the ACP run/message events (§11). This is a **streamed HTTP
  response** and is carried by NPAMP-CC-HTTP's streaming sequence (NPAMP-CC-HTTP §7): an
  OPTIONAL BRIDGE_RESPONSE head carrying the response `status` and headers, then one or
  more BRIDGE_STREAM_DATA (`0x0104`) frames each carrying the next chunk of the SSE
  response-body octets in order, terminated by exactly one BRIDGE_STREAM_END (`0x0105`)
  with the BridgeEnvelope `final` bit set. Every frame echoes the originating request's
  `correlation_id` (NPAMP-CC-HTTP §3, §7).
- **SSE framing is body, not envelope.** Under the HTTP carriage class the SSE framing
  (`event:` / `data:` lines and blank-line delimiters) is part of the HTTP response body
  and MUST be carried verbatim as body octets; a receiver MUST NOT strip or rewrite it,
  and this mapping MUST NOT lift ACP events into a distinct N-PAMP event framing. (This
  differs from a JSON-RPC-plus-SSE protocol carried under NPAMP-CC-STREAM, where each
  event object is the foreign event; ACP rides the HTTP class, where the whole SSE
  stream is the response body.)
- **`awaiting` and resume.** A run may enter the ACP `awaiting` status carrying an
  `await_request`; the client continues it by `POST /runs/{run_id}` (`resumeRun`) with an
  `await_resume` payload and a target mode. This is carried as an ordinary ACP HTTP
  request/response (or streamed response) per §4 and the bullets above; the
  await/resume correlation is an ACP-layer construct inside the carried objects and is
  not an N-PAMP stream resumption. This mapping does not synthesize, gate, or reorder the
  await/resume exchange.

## 6. Agent manifest and discovery

ACP exposes agent discovery as HTTP reads: `GET /agents` (`listAgents`) returns the list
of available agents, and `GET /agents/{name}` (`getAgent`) returns a single agent's
**manifest** — its capability document (identity, capabilities, supported content types /
MIME, and endpoint metadata). Under this mapping:

- **Default carriage.** Both reads are ordinary HTTP GET exchanges and ride NPAMP-CC-HTTP
  on the Bridge channel `0x000D` with the rest of the ACP session (§4, §8). No special
  framing applies; the manifest is carried in the response `body` verbatim.
- **OPTIONAL document carriage.** Where a deployment publishes an agent manifest as a
  self-contained **capability document** for advertisement — rather than as a live GET
  result — that document MAY instead be carried under NPAMP-CC-DOC (`24_carriage_documents.md`)
  and MAY ride the Discovery channel `0x0010` (§8; companion index, "Channel selection
  for carriage"). This is the same treatment NPAMP-MAP-A2A gives the A2A AgentCard
  (`61_map_a2a.md` §7). The live `GET /agents/{name}` result remains HTTP-class traffic
  on the Bridge channel; a single ACP session MUST NOT be split across the Bridge and
  Discovery channels.
- **Native ACP discovery is out of band.** ACP's mDNS / central-registry agent discovery
  and registration operate outside the N-PAMP association and are not carried by this
  mapping (§1.2, §8).

## 7. SafetyLabel and state-mutating operations

The SafetyLabel TLV (Type `0x0013`) and its fail-safe semantics are governed by
NPAMP-BRIDGE §7 and applied to HTTP-carriage requests by NPAMP-CC-HTTP §8.1, which
derives the `effect` from the carried HTTP method. This section pins that derivation for
ACP's specific operations; it tightens where an ACP operation is more consequential than
its bare method class, and never loosens below the method default (NPAMP-CC-HTTP §8.1).

| ACP operation | HTTP method | `effect` (NPAMP-BRIDGE §7) | Rationale |
|---|---|---|---|
| `ping`, `listAgents`, `getAgent`, `getRun`, `listRunEvents`, `getSession` | GET | `0x00` read_only | Liveness, discovery reads, and status/event/session reads that do not act on external state. A SafetyLabel MAY be omitted; absence is correctly read as read_only for these (NPAMP-CC-HTTP §8.1). |
| `createRun` | POST | `0x02` non_idempotent_write | Creates and starts a run; produces new agent work. Re-issuing is not idempotent. The sender MUST attach a SafetyLabel. |
| `resumeRun` | POST | `0x02` non_idempotent_write | Advances an `awaiting` run with new input, producing further agent work. The sender MUST attach a SafetyLabel. |
| `cancelRun` | POST | `0x02` non_idempotent_write (at minimum) | Requests an irreversible terminal transition of a run; cancelling an already-cancelled or terminal run is a no-op. A deployment with a stricter policy MAY classify it `0x03` destructive; a sender MUST attach a SafetyLabel either way. |

Requirements:

- For any ACP operation whose `effect` above is not `0x00`, the sender MUST attach a
  SafetyLabel TLV (NPAMP-BRIDGE §7) to the carrying BRIDGE_REQUEST, and an intermediary
  MUST carry it unchanged.
- A receiver MUST NOT treat the **absence** of a SafetyLabel on a state-mutating ACP
  operation (`createRun`, `resumeRun`, `cancelRun`) as `read_only`; absence on such an
  operation MUST be treated as `destructive` (fail-safe; NPAMP-BRIDGE §7; NPAMP-CC-HTTP
  §8.1).
- The SafetyLabel `scope` field MAY carry the request target (for example the `run_id`
  or agent `name`) as an advisory resource hint (NPAMP-BRIDGE §7). The label states the
  sender's declared intent; it does not replace the ACP server's own authorization
  decision, which the receiver MUST enforce at invocation (NPAMP-CC-HTTP §8.1).

## 8. Channel selection

| ACP traffic class | Carriage | Channel |
|---|---|---|
| REST operations — runs, ping, session, events (§4) | NPAMP-CC-HTTP | Bridge `0x000D` |
| Streamed run, `mode = stream` (§5) | NPAMP-CC-HTTP streaming (§7 of that document) | Bridge `0x000D` |
| Agent manifest / list as a capability document (§6) | NPAMP-CC-HTTP (default) or NPAMP-CC-DOC | Bridge `0x000D` default; MAY use Discovery `0x0010` for a manifest carried as a document |
| MDNS / registry discovery, `content_url` dereference, out-of-band callback (§1.2, §6) | Not carried by this mapping | Out of band (native HTTP) |

Under this mapping a peer carrying an ACP session MUST carry that session's HTTP messages
on the Bridge channel `0x000D`, and MUST NOT split a single ACP session across the Bridge
and Discovery channels. The Bridge channel `0x000D` and the Discovery channel `0x0010`
are both minimum-profile **Standard** (core specification channel registry;
`../../registries/channels.csv`); ACP carriage requires no channel above the Standard
profile. A peer MUST NOT send or accept ACP frames on a channel it did not advertise
during the handshake (core specification §5).

## 9. Protocol status: confirmed versus unconfirmed

This mapping is authored against ACP's own published specification and marks precisely
what is grounded in a primary source versus what remains open, per the OPAQUE-READY
posture of the companion index.

**Confirmed from ACP's primary sources (§11):**

- ACP's **base transport is REST over HTTP** — "well-defined REST endpoints that align
  with standard HTTP patterns" — which fixes the carriage class as HTTP (NPAMP-CC-HTTP).
- The **operation surface** of §4 (`/ping`, `/agents`, `/agents/{name}`, `/runs`,
  `/runs/{run_id}` for both `getRun` and `resumeRun`, `/runs/{run_id}/cancel`,
  `/runs/{run_id}/events`, `/session/{session_id}`) and their HTTP methods, taken from
  ACP's published OpenAPI document.
- The **message model** (a `Message` of typed `MessagePart`s identified by MIME
  `content_type`, with inline `content` or a `content_url`) and the **run lifecycle**
  (status values; `sync`/`async`/`stream` modes; `text/event-stream` streaming;
  `awaiting`/resume) referenced in §5–§7.

**Unconfirmed, provisional, or externally dependent:**

- **`protocol_id` is PROVISIONAL.** NPAMP-REG §6 assigns ACP no code point. Until one is
  assigned under NPAMP-REG §8, ACP MUST be carried under an out-of-band-agreed
  experimental identifier (`0x10`–`0x7F`; §2). Given the project status below, a
  standards assignment may not be pursued at all; this mapping does not presume one.
- **The ACP source project is archived.** The `github.com/i-am-bee/acp` repository was
  archived on 2025-08-27 and is read-only, and the project states that **"ACP is now
  part of A2A under the Linux Foundation,"** with a migration guide (§11). The surface
  pinned in §4–§7 is therefore **frozen at the last published ACP revision** — which
  makes it stable to pin — but ACP's forward evolution is A2A. A deployment carrying
  live agents that have migrated off ACP onto A2A SHOULD use NPAMP-MAP-A2A
  (`61_map_a2a.md`) rather than this mapping; this document remains the correct mapping
  for endpoints that still speak the archived ACP REST surface.
- **Transport-bound authentication specifics** (for example bearer tokens, mutual TLS,
  or per-`MessagePart` JSON Web Signatures) are reported by secondary summaries but are
  not pinned here from the primary OpenAPI; they are treated generically in §10 as
  carried-but-not-validated header/body material.
- **Name collision.** A distinct protocol published by the AGNTCY collective is also
  abbreviated "ACP" (the AGNTCY *Agent Connect Protocol*). It is a different
  specification and is **out of scope** for this document, which addresses only the
  Agent Communication Protocol of §11.

No value in this document is asserted beyond what §11's sources support; where a fact was
version-dependent or not confirmable from the primary source, it is marked here rather
than fixed by assumption.

## 10. Security considerations

This mapping introduces no cryptography and changes none. All confidentiality, integrity,
authentication, downgrade resistance, and replay protection are provided by the core
specification's wire format and key schedule and apply unchanged to every ACP frame,
which travels inside the AEAD-protected Bridge (or Discovery) payload; the `protocol_id`,
the HTTP method/target routing key, the SafetyLabel, and the ACP HTTP message are
authenticated and confidentiality-protected to the same degree.

Carrying ACP over N-PAMP makes no security claim about ACP itself. In particular:

- **Transport-bound ACP security elements.** ACP is defined over HTTP, and an ACP
  deployment may bind authorization to HTTP-level mechanisms (for example a bearer token
  in an `Authorization` header, or mutual TLS). Over N-PAMP the HTTP hop those elements
  bind to does not exist: such header fields are carried verbatim (NPAMP-CC-HTTP §4.4)
  but are neither validated nor re-bound by carriage, and a receiver MUST NOT infer that
  a carried credential was verified (NPAMP-CC-HTTP §8.3, §8.4). A gateway that re-emits a
  carried ACP message onto a real HTTP hop is responsible for that hop's own transport
  security.
- **Message-level versus transport-level signatures.** A signature computed over ACP
  message-body octets alone (for example a JWS over a `MessagePart` payload) survives
  octet-exact carriage and remains verifiable by any holder of the payload and key,
  because it is part of the carried body. A signature bound to the HTTP transport surface
  (method, authority, path, or selected headers) covers inputs that do not exist on the
  N-PAMP wire and is neither reconstructed nor verified by carriage (NPAMP-CC-HTTP §8.4;
  NPAMP-CC-OPAQUE §9.3).
- **Out-of-band exchanges are not performed.** A `MessagePart` `content_url`, an mDNS or
  registry discovery, or any callback ACP implies is a separate exchange that leaves the
  N-PAMP association; carriage neither performs nor proxies it, and a receiver MUST NOT
  assume it occurred as a result of carriage (NPAMP-CC-OPAQUE §9.4; §1.2).
- **Safety fail-safe.** The effect classification of §7 and the NPAMP-BRIDGE §7 fail-safe
  (absence of a SafetyLabel on a state-mutating operation is `destructive`) apply to
  every ACP operation. A receiver MUST validate a carried ACP payload as untrusted input
  of its declared media type before acting on it, and MUST enforce its own authorization;
  a favorable SafetyLabel is not permission (NPAMP-CC-HTTP §8.1).

## 11. References

Primary source (ACP specification — the confirmed basis for §4–§7):

- Agent Communication Protocol — official documentation and specification —
  <https://agentcommunicationprotocol.dev> (confirms REST/HTTP transport, the MIME-typed
  `Message`/`MessagePart` model, and the "ACP is now part of A2A under the Linux
  Foundation" status and migration guide).
- Agent Communication Protocol — source repository (archived 2025-08-27, read-only) —
  <https://github.com/i-am-bee/acp> (the archival status of §9 and the location of the
  OpenAPI specification).
- ACP OpenAPI specification (the operation namespace, HTTP methods, run status enum, run
  modes, and streaming, pinned in §4–§5) —
  <https://github.com/i-am-bee/acp/blob/main/docs/spec/openapi.yaml>.

Distinct protocol out of scope (name collision, §9):

- AGNTCY "Agent Connect Protocol" — a separate specification also abbreviated "ACP",
  not addressed by this document.

N-PAMP documents built on:

- draft-bubblefish-npamp-01 — the N-PAMP core specification: the frame format, the
  channel registry (Bridge `0x000D`, Discovery `0x0010`), the frame-type namespace
  (channel-specific types from `0x0100`), the extension-TLV encoding, and the AEAD
  payload protection.
- NPAMP-BRIDGE (`10_bridge_framework.md`) — the encapsulation, BridgeEnvelope,
  correlation, structured-error, and SafetyLabel contract.
- NPAMP-CC-HTTP (`21_carriage_http.md`) — the HTTP-semantics carriage class that does the
  structural work for ACP.
- NPAMP-CC-OPAQUE (`25_carriage_opaque.md`) — the zero-mapping carriage that carries ACP
  today, and the out-of-band / transport-bound-signature honesty statements referenced in
  §10.
- NPAMP-CC-DOC (`24_carriage_documents.md`) — the document carriage referenced for the
  OPTIONAL manifest-as-document case (§6).
- NPAMP-REG (`30_protocol_registry.md`) — the Bridge Protocol Identifier registry, which
  assigns ACP no code point (the PROVISIONAL status of §2, §9) and defines the
  experimental range and `ProtocolUnsupported` handling.
- NPAMP-MAP-A2A (`61_map_a2a.md`) — the A2A mapping a migrated ACP endpoint SHOULD use
  (§9), and the AgentCard-as-document precedent referenced in §6.
- NPAMP-DISC (`40_discovery.md`) — Discovery-channel advertisement referenced in §6, §8.
- BCP 14 (RFC 2119, RFC 8174) — requirement key words.

## 12. Conformance

An implementation conforms to NPAMP-MAP-ACP if and only if it conforms to NPAMP-CC-HTTP
(and therefore to NPAMP-BRIDGE) and, for ACP traffic, it:

1. Carries every ACP HTTP message as an HTTP-Carriage Object with `content_type = 0x02`,
   octet-for-octet, under an out-of-band-agreed experimental `protocol_id` (`0x10`–`0x7F`)
   because NPAMP-REG assigns ACP none, never emitting ACP under a `protocol_id` assigned
   to another protocol, and selects ACP solely from `protocol_id`, never from another
   envelope field (§2, §3);
2. Maps each ACP operation of §4 onto the NPAMP-BRIDGE frame types per §4 — a request to
   BRIDGE_REQUEST with the HTTP method token and target in the HTTP-Carriage Object and
   reflected in the BridgeEnvelope `method` routing key, a non-streamed response to
   BRIDGE_RESPONSE, and a sub-foreign carriage failure to BRIDGE_ERROR with an N-PAMP
   transport-error code — and reports `MethodUnsupported` for a carried-but-unimplemented
   ACP operation rather than reporting success (§3, §4);
3. Carries an ACP `4xx`/`5xx` HTTP response as a BRIDGE_RESPONSE preserving the foreign
   status and body verbatim, and never fabricates an HTTP status for a carriage failure
   (§3; NPAMP-CC-HTTP §6);
4. Carries a streamed (`mode = stream`) run response as the NPAMP-CC-HTTP streaming
   sequence — an OPTIONAL BRIDGE_RESPONSE head, BRIDGE_STREAM_DATA chunks, and one
   BRIDGE_STREAM_END with the `final` bit set, all echoing the request `correlation_id` —
   carrying the `text/event-stream` (SSE) framing verbatim as body octets and never
   lifting ACP events into a separate N-PAMP event framing (§5);
5. Carries `getAgent`/`listAgents` as ordinary HTTP reads on the Bridge channel, and uses
   NPAMP-CC-DOC and/or the Discovery channel `0x0010` only for a manifest carried as a
   capability document, never splitting a single ACP session across channels (§6, §8);
6. Attaches a SafetyLabel with `effect = non_idempotent_write` (or, for `cancelRun`, at
   least that, MAY be `destructive`) to every `createRun`, `resumeRun`, and `cancelRun` it
   originates, treats a missing SafetyLabel on any of these as `destructive` (NPAMP-BRIDGE
   §7 fail-safe), and never treats a favorable SafetyLabel as authorization (§7);
7. Does not carry ACP's transport-bound authentication as a validated credential, does not
   reconstruct or verify a transport-bound HTTP signature, and does not perform a
   `content_url` dereference, mDNS/registry discovery, or out-of-band callback as part of
   carriage (§1.2, §10); and
8. Defines no new frame type, TLV, or code point, consuming only those the core
   specification, NPAMP-BRIDGE, and NPAMP-CC-HTTP already reserve (§1.2, §2), and treats
   the `protocol_id` as PROVISIONAL pending any NPAMP-REG assignment (§2, §9).

A conformance test suite SHOULD assert each clause above with recorded exchanges that
include: a `GET /agents` and `GET /agents/{name}` read carried as request/response; a
`POST /runs` (`createRun`) carrying a `non_idempotent_write` SafetyLabel and a second
`createRun` with the SafetyLabel omitted, verified to be treated as `destructive`; a
streamed run whose `text/event-stream` body is carried as BRIDGE_STREAM_DATA chunks
terminated by BRIDGE_STREAM_END with the `final` bit set; an `awaiting` run continued by
`POST /runs/{run_id}` (`resumeRun`); a `POST /runs/{run_id}/cancel`; and an ACP `4xx`
error response carried as a BRIDGE_RESPONSE with its status and body preserved verbatim.
