# NPAMP-MAP-AGNTCY — AGNTCY (Internet of Agents) Protocol Mapping (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is a **thin per-protocol mapping** for **AGNTCY** — the Linux
> Foundation "Internet of Agents" collective. AGNTCY is an **ecosystem of several
> distinct protocols**, not a single wire protocol, so this mapping first fixes the
> concrete AGNTCY protocol surface it maps (§2) and then pins how that surface rides
> N-PAMP carriage. **Carriage posture: OPAQUE-READY.** AGNTCY's own wire surfaces —
> the SLIM messaging substrate and the (archived) Agent Connect Protocol — are
> carried **today** under Class OPAQUE (`25_carriage_opaque.md`) with a **PROVISIONAL**
> experimental `protocol_id`; native mappings onto the streaming carriage class
> (`23_carriage_streaming.md`) for SLIM and the HTTP-semantics class
> (`21_carriage_http.md`) for ACP are described here as the confirmed target, to be
> marked DRAFT once a standards `protocol_id` is assigned and the SLIM wire format
> stabilizes (§6, §9). It builds on **NPAMP-BRIDGE** (`10_bridge_framework.md`), the
> named carriage classes, and the N-PAMP core specification
> (draft-bubblefish-npamp-01, the "core specification"). It consumes only code points
> those documents already reserve; it defines no new frame type, no new TLV, and no
> change to the core wire format or to NPAMP-BRIDGE.

## 1. Scope

### 1.1 In scope

This document defines, against AGNTCY's own published specifications (§11), only the
AGNTCY specifics that the carriage classes leave to a per-protocol mapping:

- The concrete AGNTCY **protocol surface** this mapping addresses — the SLIM messaging
  substrate and the Agent Connect Protocol (ACP) — and the AGNTCY components mapped
  elsewhere or out of scope (§2);
- AGNTCY's **carriage posture** — Class OPAQUE today, under a PROVISIONAL experimental
  `protocol_id`, because AGNTCY has no standards-assigned Bridge Protocol Identifier
  and the SLIM wire format is not yet stably specified (§3, §4, §5);
- The **anticipated native carriage** for each AGNTCY surface once its code point and
  wire format are confirmed — SLIM under NPAMP-CC-STREAM, ACP under NPAMP-CC-HTTP,
  OASF under NPAMP-CC-DOC — with an explicit statement of what is **confirmed** versus
  **unconfirmed** (§6);
- The **SafetyLabel effect class** a sender attaches to AGNTCY state-mutating
  operations, grounded in the confirmed ACP run/thread operations and SLIM interaction
  types, and the NPAMP-BRIDGE §7 fail-safe (§7); and
- **Channel selection** for each AGNTCY traffic class (§8).

The structural work — octet-exact carriage, the BridgeEnvelope, correlation, the
structured-error model, streaming, and the safety-annotation TLV — is done by
NPAMP-BRIDGE and the named carriage classes and is not restated here.

### 1.2 Not in scope

- **OASF (Open Agentic Schema Framework).** AGNTCY's agent-schema/capability-document
  surface is a capability document and is mapped separately under NPAMP-CC-DOC by
  `69_map_oasf.md`. This document references it (§2, §8) but does not redefine it.
- **A2A and MCP carried "over SLIM".** SLIM is itself a transport substrate that can
  carry other agent protocols, including JSON-RPC ones such as A2A and MCP (§2). Over
  N-PAMP those protocols are carried by their **own** native mappings — NPAMP-MAP-A2A
  (`protocol_id 0x02`, `61_map_a2a.md`) and NPAMP-MAP-MCP (`protocol_id 0x01`,
  `60_map_mcp.md`) — with the N-PAMP association taking SLIM's transport role. This
  document does not re-map A2A or MCP, and MUST NOT be used to carry them under an
  AGNTCY `protocol_id` (§2, §6).
- **The internal schemas** of SLIM messages, ACP runs/threads objects, OASF records,
  or Agent Directory records. These are fixed by AGNTCY's own specifications; this
  document carries them verbatim (NPAMP-BRIDGE §1) and does not parse, validate, or
  transform them.
- **SLIM's own transport security (MLS group encryption) and SLIM node/network
  routing.** Over N-PAMP, transport security is provided by the N-PAMP association;
  SLIM's MLS-protected payload, where carried, is carried as opaque bytes and is
  neither reconstructed nor verified by carriage (§10).
- **Any change to NPAMP-BRIDGE, to the carriage classes, or to the core wire format,**
  including the BridgeEnvelope TLV, the SafetyLabel TLV, and the StreamControl TLV,
  all of which are used exactly as their defining documents specify.

## 2. The AGNTCY protocol surface

AGNTCY (agntcy.org) is a Linux Foundation collective building an open "Internet of
Agents." It publishes **several independent protocols and services**, each with its
own transport; there is no single "AGNTCY protocol" to pin with one `protocol_id` and
one method namespace. This mapping fixes which AGNTCY surface it addresses, so the
carriage is unambiguous.

| AGNTCY component | What it is | Transport / wire (confirmed, §11) | Carriage in N-PAMP |
|---|---|---|---|
| **SLIM** — Secure Low-latency Interactive Messaging | Secure agent **messaging + RPC substrate**: publish/subscribe, request/reply, streaming, fire-and-forget, MLS group messaging. Provides the transport layer *for* other agent protocols (A2A, MCP). | GRPC over HTTP/2 and HTTP/3; Protocol Buffers (SRPC service/message schemas). | **This document.** Class OPAQUE today; native target NPAMP-CC-STREAM (§6). |
| **ACP** — Agent Connect Protocol | Standard interface to **invoke and configure remote agents**: stateless `/runs` and stateful `/threads/{id}/runs`, with background / wait / stream variants, resume, cancel, delete. | REST API with JSON bodies and Server-Sent Events; OpenAPI (v0.2.3). **Repository archived read-only 2026-04-11.** | **This document.** Class OPAQUE today; native target NPAMP-CC-HTTP (§6). |
| **OASF** — Open Agentic Schema Framework | Vendor-neutral schema describing agent identity, skills, and capabilities (spans A2A, MCP, and more). | Schema / capability documents. | **`69_map_oasf.md`** under NPAMP-CC-DOC. Out of scope here (§1.2). |
| **Agent Directory (dir)** | Federated registry for publishing, verifying, and discovering agents and multi-agent applications. | Discovery / registry service. | Discovery via NPAMP-DISC (`40_discovery.md`); records as DOC. Referenced in §8; not pinned here. |
| **Identity** | Decentralized identity, identifiers, and verifiable credentials for agents and MCP servers. | Identity service. | Out of scope; N-PAMP peer identity is provided by NPAMP-PEERHANDLE (`50_peer_handle.md`). |

**Consequence for the carriage-class family.** The companion index anticipated AGNTCY
under the "JSONRPC / STREAM" family (`00_companion_index.md`). Primary-source
verification refines this: AGNTCY's **own** wire surfaces are **gRPC/protobuf** (SLIM)
and **REST/JSON+SSE** (ACP) — **neither is JSON-RPC** (ACP is explicitly a REST API
with JSON bodies, not JSON-RPC; §11). The "JSONRPC" association is indirect: SLIM is a
*transport* that can carry JSON-RPC agent protocols such as A2A, which over N-PAMP are
carried by their own mappings (§1.2). Accordingly this mapping targets **STREAM** for
SLIM and **HTTP** for ACP, and does **not** define a JSON-RPC method namespace for
AGNTCY, because AGNTCY publishes none.

## 3. Relationship to the carriage classes and the registry

This document is a registration plus a thin mapping, in the sense of the companion
index: it names a `protocol_id`, the carriage classes AGNTCY's surfaces use, and the
AGNTCY-specific facts, and it lets the carriage classes do the structural work.

| Facility | Owning document | Use here |
|---|---|---|
| Class OPAQUE | NPAMP-CC-OPAQUE (`25_carriage_opaque.md`) | Carriage of SLIM and ACP wire today, with declared content type (§5). |
| Streaming carriage | NPAMP-CC-STREAM (`23_carriage_streaming.md`) | Native target for SLIM's streamed / pub-sub messaging (§6). |
| HTTP-semantics carriage | NPAMP-CC-HTTP (`21_carriage_http.md`) | Native target for ACP's REST + SSE surface (§6). |
| Document carriage | NPAMP-CC-DOC (`24_carriage_documents.md`) | OASF and directory records (via `69_map_oasf.md`; §8). |
| Bridge Protocol Identifier registry | NPAMP-REG (`30_protocol_registry.md`) | The `protocol_id` partition and the PROVISIONAL experimental value used here (§4). |
| BridgeEnvelope / SafetyLabel TLVs | Core specification; NPAMP-BRIDGE | Carried unchanged on every AGNTCY frame (§4, §7). |

Because every carriage class carries the foreign message **verbatim** and selects the
foreign protocol solely by `protocol_id` (NPAMP-REG §9), the carriage is robust to
AGNTCY's ongoing evolution: a receiver delivers the AGNTCY payload octet-for-octet
regardless of the exact SLIM message type or ACP path, and this document pins carriage
and effect class **by operation semantics** (§6, §7) rather than by a spelling that a
future AGNTCY revision may change.

## 4. Protocol identity

| Property | Value |
|---|---|
| Protocol | AGNTCY — Internet of Agents collective; concretely, the SLIM messaging substrate and the Agent Connect Protocol (§2). |
| `protocol_id` | **PROVISIONAL.** No value is assigned to AGNTCY by NPAMP-REG §6 (which assigns `0x01`–`0x04` and leaves `0x05`–`0x0F` unassigned). Until a standards value is assigned in `0x05`–`0x0F` under NPAMP-REG §8, AGNTCY traffic MUST use an **experimental** `protocol_id` in the range `0x10`–`0x7F` (NPAMP-REG §7.1), agreed out-of-band between the peers. This document uses `0x10` illustratively; it carries **no** cross-domain meaning and two deployments MAY assign it differently (NPAMP-REG §7.1). |
| `content_type` | `0x03` (application/grpc+proto) for SLIM's protobuf messages; `0x01` (application/json) for ACP's JSON bodies (NPAMP-BRIDGE §4). A payload of a non-enumerated media type MUST be declared via the OpaqueContentType TLV per NPAMP-CC-OPAQUE §4. |
| Carriage class | **OPAQUE today** (NPAMP-CC-OPAQUE); native targets STREAM (SLIM) and HTTP (ACP) once §6 is confirmed. |
| Foreign-message form | A SLIM message (protobuf) or an ACP HTTP request/response with a JSON body, carried octet-for-octet as the foreign message (NPAMP-BRIDGE §1). |

A sender MUST NOT emit AGNTCY traffic under a `protocol_id` that NPAMP-REG has assigned
to a different protocol (for example `0x01` MCP or `0x02` A2A), and MUST NOT use an
experimental AGNTCY `protocol_id` on an association without out-of-band agreement on
its meaning (NPAMP-REG §7.1). A receiver that does not carry the agreed AGNTCY
`protocol_id` MUST reply to a BRIDGE_REQUEST bearing it with `ProtocolUnsupported`
(NPAMP-BRIDGE §6; NPAMP-REG §9), and MUST NOT infer AGNTCY from any other envelope
field (NPAMP-REG §9).

## 5. Carriage today via Class OPAQUE

Until §6 is confirmed and marked DRAFT, an implementation that carries AGNTCY traffic
over N-PAMP MUST do so under **Class OPAQUE** (NPAMP-CC-OPAQUE), which requires no
protocol-specific mapping and carries any declared-content-type payload transparently:

- The AGNTCY payload — a SLIM protobuf message or an ACP JSON body — is the foreign
  message and MUST be carried octet-for-octet (NPAMP-CC-OPAQUE §1.3, §5). The opaque
  layer MUST NOT parse, validate, re-encode, or transform it.
- The sender MUST declare the content type (`0x03` application/grpc+proto for SLIM;
  `0x01` application/json for ACP; otherwise the OpaqueContentType TLV of
  NPAMP-CC-OPAQUE §4).
- The sender MUST choose the NPAMP-BRIDGE frame type from the foreign interaction
  pattern (NPAMP-CC-OPAQUE §2): a request expecting a reply as BRIDGE_REQUEST, a
  one-way SLIM "fire-and-forget" or notification as BRIDGE_NOTIFY (`corr_len = 0`),
  and a streamed reply as BRIDGE_STREAM_DATA / BRIDGE_STREAM_END.
- Correlation, the structured-error model, and the SafetyLabel obligation (§7) are
  inherited from NPAMP-BRIDGE unchanged (NPAMP-CC-OPAQUE §1.2, §8).

Class OPAQUE guarantees byte-fidelity and the inherited N-PAMP transport security; it
does **not** provide discovery, out-of-band exchange, or reconstruction of any
transport-bound authentication the AGNTCY surface binds to its native transport
(NPAMP-CC-OPAQUE §1.3, §9). See §10.

## 6. Anticipated native carriage (confirmed vs unconfirmed)

This section states the target native carriage for each AGNTCY surface and marks
precisely what is confirmed against AGNTCY's published specifications (§11) and what is
not yet confirmable. Nothing in this section is on the wire until a standards
`protocol_id` is assigned (§4) and this section is promoted to DRAFT.

### 6.1 SLIM → NPAMP-CC-STREAM (target)

**Confirmed (§11):** SLIM is a secure messaging and RPC substrate whose interaction
types are publish/subscribe, request/reply, fire-and-forget, group (MLS) messaging,
and — via SLIMRPC (SRPC) — unary, client-streaming, server-streaming, and
bidirectional-streaming calls; its transport is gRPC over HTTP/2 and HTTP/3 with a
Protocol Buffers wire format; a SLIM message carries a channel name, an address
locator, and a data payload.

**Target mapping.** A SLIM streamed or pub-sub exchange is a natural fit for
NPAMP-CC-STREAM: a streaming SRPC call or a subscription is a BRIDGE_REQUEST whose
reply is a sequence of BRIDGE_STREAM_DATA frames terminated by BRIDGE_STREAM_END, each
event carrying a StreamControl TLV with a strictly monotonic `event_id`
(NPAMP-CC-STREAM §5); a unary SRPC call is a BRIDGE_REQUEST → BRIDGE_RESPONSE /
BRIDGE_ERROR; a fire-and-forget publish is a BRIDGE_NOTIFY (NPAMP-BRIDGE §8). The
foreign message is the SLIM protobuf message, carried verbatim with
`content_type = 0x03`. Full-duplex SLIM streams map onto the two correlated
per-direction streams of NPAMP-CC-STREAM §8.

**Unconfirmed / OPAQUE-READY.** The SLIM specification is an **individual, Informational
Internet-Draft** (draft-mpsb-agntcy-slim, February 2026), **not an IETF-endorsed
standard**, and is architectural: it does **not** yet fix a stable per-message wire
encoding, a complete message-type enumeration, or resume/cancel semantics that could be
bound one-to-one to NPAMP-CC-STREAM's `event_id`, resume cursor, and cancel. Until that
detail is published and stable, SLIM MUST be carried under Class OPAQUE (§5) and MUST
NOT be treated as a DRAFT native STREAM mapping.

### 6.2 ACP → NPAMP-CC-HTTP (target)

**Confirmed (§11):** ACP is a REST API with JSON request/response bodies and
Server-Sent Events for streaming (OpenAPI v0.2.3). Its operations are stateless
`/runs` and stateful `/threads/{thread_id}/runs`, each with background-create,
`/wait` (block for output), and `/stream` (SSE) variants, plus resume
(`POST .../runs/{run_id}`), `/cancel`, `DELETE`, run/thread reads and searches, and
`/agents/search`, `/agents/{id}`, `/agents/{id}/descriptor`. It is **not** JSON-RPC.

**Target mapping.** Because ACP is HTTP-semantics (method + path + headers + JSON
body), its native carriage class is **NPAMP-CC-HTTP** (`21_carriage_http.md`), not
JSON-RPC. Each ACP request is an HTTP-semantics request carried under NPAMP-CC-HTTP on
the Bridge channel; each ACP SSE run-stream (`/runs/stream`, `/threads/{id}/runs/stream`)
is a streamed reply whose SSE `data` events are carried under NPAMP-CC-STREAM (the SSE
`event:`/`data:` line framing MUST NOT be carried; only the event body is the foreign
event), exactly as A2A's SSE streams are carried (`61_map_a2a.md` §6).

**Unconfirmed / OPAQUE-READY.** The ACP repository is **archived read-only as of
2026-04-11** and OASF now describes agents "across A2A, MCP, and more," indicating that
AGNTCY's agent-invocation surface is consolidating onto A2A/MCP rather than ACP. A
native ACP HTTP mapping SHOULD therefore be authored only if a deployment still needs
ACP; otherwise ACP is carried under Class OPAQUE (§5), and JSON-RPC agent protocols
that AGNTCY hosts (A2A, MCP) are carried by their own mappings (§1.2).

### 6.3 OASF and Agent Directory → NPAMP-CC-DOC / NPAMP-DISC

OASF records are capability/schema documents carried under NPAMP-CC-DOC by
`69_map_oasf.md` (§1.2). Agent Directory publish/verify/discover operations correspond
to NPAMP-DISC advertisement on the Discovery channel `0x0010` (`40_discovery.md`) and to
DOC-class carriage of the directory records; this document does not pin their fields and
defers them to those documents (§8).

## 7. SafetyLabel effect classes for mutating operations

The SafetyLabel TLV (Type `0x0013`) and its fail-safe are governed by NPAMP-BRIDGE §7
and inherited by Class OPAQUE (NPAMP-CC-OPAQUE §1.2) and by the STREAM/HTTP classes
unchanged. Neither protobuf/gRPC nor REST expresses, by itself, whether an operation
mutates state; AGNTCY's operation semantics do. Because a Class OPAQUE carrier does not
parse the payload, the **sender** — which holds the AGNTCY message and knows the
operation — MUST attach the SafetyLabel; an intermediary MUST carry it unchanged; and a
receiver MUST NOT treat the **absence** of a SafetyLabel on a state-mutating operation
as `read_only` — absence MUST be treated as `destructive` (NPAMP-BRIDGE §7 fail-safe).

The classification below is grounded in the confirmed ACP operations (§6.2) and SLIM
interaction types (§6.1), stated by operation **semantics** so that a spelling change
does not change the effect class. It uses the NPAMP-BRIDGE §7 values: `0x00` read_only,
`0x01` idempotent_write, `0x02` non_idempotent_write, `0x03` destructive.

| AGNTCY operation (semantic) | `effect` | Rationale |
|---|---|---|
| ACP read a run/thread/agent; list/search runs, threads, agents; get history or descriptor; reattach to an existing run stream (`GET .../stream`, `.../wait`) | `0x00` read_only | Reads existing state or reattaches to an already-created stream; produces no new agent work. |
| ACP create a run (`POST /runs`, `.../runs`, `.../runs/wait`, `.../runs/stream`); resume an interrupted run; create or copy a thread | `0x02` non_idempotent_write | Starts new agent work or creates new stateful objects; re-issuing is not idempotent. |
| ACP update a thread (`PATCH /threads/{id}`) | `0x01` idempotent_write | Replaces thread configuration; applying the same update yields the same state. |
| ACP cancel a run (`.../cancel`) | `0x02` non_idempotent_write (at minimum) | Requests a terminal transition of a running run; a deployment with a stricter policy MAY classify it `0x03` destructive. The sender MUST attach a SafetyLabel either way. |
| ACP delete a run or thread (`DELETE ...`); delete a resource | `0x03` destructive | The object and its data are removed. |
| SLIM SRPC unary/streaming call, or publish, that invokes remote work or delivers new content | `0x02` non_idempotent_write | Delivers a message that produces new agent work; each invocation is a fresh action. A SLIMRPC call to a read-only remote method MAY be `0x00` read_only when the sender knows the target method is read-only. |
| SLIM subscribe / join a channel or group | `0x01` idempotent_write | Establishes session-scoped subscription/group state on the responder; repeating yields the same state. |

Requirements:

- For any AGNTCY operation whose `effect` above is not `0x00`, the sender MUST attach a
  SafetyLabel TLV (NPAMP-BRIDGE §7) to the carrying frame; an intermediary MUST carry it
  unchanged.
- A receiver MUST treat a missing SafetyLabel on any operation not classified read_only
  above as `destructive` (fail-safe; NPAMP-BRIDGE §7).
- The `effect` values classify **intent**; they do not replace the AGNTCY endpoint's own
  authorization decision, and a favorable label MUST NOT be treated as permission
  (NPAMP-BRIDGE §7).

## 8. Channel selection

| AGNTCY traffic class | Carriage | Channel |
|---|---|---|
| SLIM messaging / SRPC (§6.1) | Class OPAQUE today; STREAM target | Bridge `0x000D` |
| ACP REST invocation and SSE run-streams (§6.2) | Class OPAQUE today; HTTP + STREAM target | Bridge `0x000D` |
| OASF schema / Agent Directory records (§6.3) | NPAMP-CC-DOC (`69_map_oasf.md`) | Bridge `0x000D` default; MAY use Discovery `0x0010` |
| Agent advertisement / discovery (§6.3) | NPAMP-DISC (`40_discovery.md`) | Discovery `0x0010` |

AGNTCY traffic rides the **Bridge channel `0x000D`** by default, as required for
NPAMP-BRIDGE encapsulation (NPAMP-BRIDGE §1). The Bridge channel and the Discovery
channel `0x0010` are both minimum-profile **Standard** (core specification channel
registry; `../../registries/channels.csv`); AGNTCY carriage requires no channel above
the Standard profile. A single logical AGNTCY exchange (for example one SLIM stream or
one ACP run stream) MUST NOT be split across channels. A peer MUST NOT send or accept
AGNTCY frames on a channel it did not advertise during the handshake (core specification
§5).

## 9. Version considerations and marked uncertainties

AGNTCY is a fast-moving collective; its component surfaces are versioned independently.
The following facts are marked so that an implementer confirms them against the exact
AGNTCY component and version they target rather than relying on a single rendering:

1. **SLIM is an unratified individual draft.** draft-mpsb-agntcy-slim (Informational,
   Network Working Group individual submission, February 2026, expiring 28 August 2026)
   is architectural and does **not** fix a stable per-message wire encoding. Its native
   STREAM mapping (§6.1) is a **target**, not a confirmed DRAFT; SLIM MUST be carried
   under Class OPAQUE until the wire format stabilizes.
2. **ACP is archived.** The `acp-spec` repository is archived read-only (2026-04-11) at
   OpenAPI v0.2.3. An implementer targeting ACP MUST verify operations against that
   frozen specification and SHOULD prefer A2A/MCP (with their own N-PAMP mappings) for
   new agent-invocation work (§6.2).
3. **"JSONRPC" is indirect, not first-party.** AGNTCY publishes no JSON-RPC application
   protocol; ACP is REST/JSON (not JSON-RPC) and SLIM is gRPC/protobuf. JSON-RPC appears
   only when SLIM *transports* a JSON-RPC protocol such as A2A, which over N-PAMP is
   NPAMP-MAP-A2A, not this mapping (§1.2, §2). An implementer MUST NOT invent a JSON-RPC
   method namespace for AGNTCY.
4. **No standards `protocol_id`.** The experimental value used here (§4) is PROVISIONAL
   and carries no cross-domain meaning; a standards assignment in `0x05`–`0x0F`
   (NPAMP-REG §8) is required before AGNTCY interoperates across independent deployments.

No value in this document is asserted beyond what §11's sources support; where a fact
was version-dependent or not confirmable from the primary source, it is marked above
rather than fixed by assumption.

## 10. Security considerations

This mapping introduces no cryptography and changes none. All confidentiality,
integrity, authentication, downgrade resistance, and replay protection are provided by
the core specification's wire format and key schedule and apply unchanged to every
AGNTCY frame, which travels inside the AEAD-protected Bridge payload; the `protocol_id`,
declared content type, SafetyLabel, and AGNTCY payload are authenticated and
confidentiality-protected to the same degree.

Carrying AGNTCY over N-PAMP makes no security claim about AGNTCY itself. In particular:

- **SLIM transport-bound security is not reconstructed.** SLIM binds its security to its
  own substrate — MLS-encrypted groups and gRPC/HTTP-2/3 channels, with OAuth tokens
  reused across RPC and messaging. Over N-PAMP the SLIM transport is subsumed by the
  N-PAMP association; where SLIM's MLS-protected payload is carried, it is carried as
  opaque bytes and is **not** reconstructed or verified by carriage (NPAMP-CC-OPAQUE
  §1.3, §9.3). A deployment that terminates SLIM at a gateway MUST re-establish any
  SLIM transport-bound credential as an independent SLIM endpoint (NPAMP-CC-OPAQUE §6);
  opaque carriage does not supply it.
- **ACP transport-bound security is not reconstructed.** ACP is defined over HTTP; where
  an ACP deployment binds authorization to an HTTP element (for example a bearer token
  in an HTTP header) that does not exist over N-PAMP, that mismatch is a property of the
  deployment and MUST be resolved by carrying the credential inside the ACP message or by
  the association's own authentication, not by fabricating a transport element
  (NPAMP-CC-OPAQUE §9.3).
- **The payload is untrusted and unvalidated by carriage.** Class OPAQUE does not parse
  or validate the AGNTCY payload; a receiver MUST treat it as untrusted input of its
  declared content type and validate it before acting (NPAMP-CC-OPAQUE §9.2, §9.5).
- **Safety fail-safe.** The effect classification of §7 and the NPAMP-BRIDGE §7 fail-safe
  (absence of a SafetyLabel on a state-mutating operation is `destructive`) apply to every
  AGNTCY operation; discovery of an AGNTCY agent or capability is a claim, not
  authorization (NPAMP-DISC §10).

## 11. References

Primary sources (AGNTCY specifications; consulted for §2, §6, §7):

- AGNTCY — Internet of Agents (project overview and component set: OASF, Agent Directory,
  SLIM, Identity, Observability) — <https://agntcy.org/> and <https://docs.agntcy.org/>.
- AGNTCY organization repositories (SLIM, slim-spec, OASF, dir, dir-spec, Identity) —
  <https://github.com/agntcy>.
- SLIM — Secure Low-latency Interactive Messaging, IETF Internet-Draft
  draft-mpsb-agntcy-slim (Informational; individual submission; February 2026; interaction
  types, gRPC over HTTP/2 and HTTP/3, Protocol Buffers, SLIMRPC, and the statement that
  SLIM "provides the transport layer for agent protocols (for example, A2A and MCP)") —
  <https://datatracker.ietf.org/doc/draft-mpsb-agntcy-slim/> and
  <https://spec.slim.agntcy.org/docs/slim-v1-update/draft-mpsb-agntcy-slim.html>.
- SLIM specification repository — <https://github.com/agntcy/slim-spec>.
- Agent Connect Protocol (ACP) — REST API with JSON bodies and Server-Sent Events,
  OpenAPI v0.2.3; stateless `/runs` and stateful `/threads/{id}/runs` operations
  (background / wait / stream, resume, cancel, delete); repository archived read-only
  2026-04-11 — <https://github.com/agntcy/acp-spec>,
  <https://raw.githubusercontent.com/agntcy/acp-spec/main/openapi.json>, and
  <https://spec.acp.agntcy.org/>.
- OASF — Open Agentic Schema Framework — <https://github.com/agntcy/oasf>.

N-PAMP documents built on:

- draft-bubblefish-npamp-01 — the N-PAMP core specification: the 36-octet frame, the
  channel registry (Bridge `0x000D`, Discovery `0x0010`), the frame-type namespace
  (channel-specific types from `0x0100`), the extension-TLV encoding, and the AEAD payload
  protection.
- NPAMP-BRIDGE (`10_bridge_framework.md`) — the encapsulation, BridgeEnvelope, correlation,
  structured-error, and SafetyLabel contract.
- NPAMP-CC-OPAQUE (`25_carriage_opaque.md`) — the opaque carriage class used today (§5).
- NPAMP-CC-STREAM (`23_carriage_streaming.md`) — streaming carriage; SLIM native target (§6.1).
- NPAMP-CC-HTTP (`21_carriage_http.md`) — HTTP-semantics carriage; ACP native target (§6.2).
- NPAMP-CC-DOC (`24_carriage_documents.md`) — capability/schema document carriage; OASF (§6.3).
- NPAMP-REG (`30_protocol_registry.md`) — the Bridge Protocol Identifier registry and its
  experimental range (§4).
- NPAMP-DISC (`40_discovery.md`) — Discovery-channel advertisement referenced in §6.3, §8.
- NPAMP-MAP-A2A (`61_map_a2a.md`) and NPAMP-MAP-MCP (`60_map_mcp.md`) — the mappings that
  carry A2A and MCP, including when hosted over SLIM (§1.2).
- OASF mapping (`69_map_oasf.md`) — the OASF DOC-class mapping (§1.2, §6.3).
- BCP 14 (RFC 2119, RFC 8174) — requirement key words.

## 12. Conformance

An implementation conforms to NPAMP-MAP-AGNTCY if and only if it conforms to
NPAMP-BRIDGE and to the carriage class it uses (NPAMP-CC-OPAQUE today; NPAMP-CC-STREAM,
NPAMP-CC-HTTP, or NPAMP-CC-DOC where a native mapping of §6 is in force), and, for
AGNTCY traffic, it:

1. Carries AGNTCY traffic under a `protocol_id` on which the peers have agreed — a
   standards value once NPAMP-REG assigns one in `0x05`–`0x0F`, otherwise an experimental
   value in `0x10`–`0x7F` agreed out-of-band — never squats on a value NPAMP-REG has
   assigned to another protocol, and selects the foreign protocol solely by `protocol_id`
   (§4);
2. Treats the AGNTCY mapping as **OPAQUE-READY**: absent a native mapping of §6 marked
   DRAFT, it carries SLIM and ACP payloads under Class OPAQUE — octet-for-octet, with the
   content type declared (`0x03` application/grpc+proto for SLIM, `0x01` application/json
   for ACP, or the OpaqueContentType TLV) — and performs no parsing, validation, or
   transformation of the payload (§5);
3. Selects the NPAMP-BRIDGE frame type and `message_kind` from the AGNTCY interaction
   pattern — a request expecting a reply as BRIDGE_REQUEST, a one-way SLIM
   fire-and-forget as BRIDGE_NOTIFY with `corr_len = 0`, and a streamed reply as
   BRIDGE_STREAM_DATA / BRIDGE_STREAM_END — and correlates replies by `correlation_id`,
   not by sequence number (§5);
4. Attaches a SafetyLabel with the correct `effect` to each state-mutating AGNTCY
   operation per §7, and treats a missing SafetyLabel on any operation not classified
   read_only as `destructive` (fail-safe; §7), never treating a favorable label as
   authorization;
5. Does **not** define or emit a JSON-RPC method namespace for AGNTCY, and carries any
   JSON-RPC agent protocol hosted over SLIM (A2A, MCP) under that protocol's own mapping
   (`0x02` / `0x01`), never under the AGNTCY `protocol_id` (§1.2, §2);
6. Carries OASF and Agent Directory material under NPAMP-CC-DOC / NPAMP-DISC per §6.3 and
   `69_map_oasf.md`, not under this document's opaque carriage;
7. Carries AGNTCY traffic only on channels advertised during the handshake — Bridge
   `0x000D` by default, Discovery `0x0010` for advertisement — never splitting one logical
   AGNTCY exchange across channels, and requires no channel above the Standard profile
   (§8); and
8. Makes no representation that carriage reconstructs or verifies SLIM's or ACP's
   transport-bound security, and re-establishes any such property, where required, in a
   component outside the carriage class (§10).

A conformance test suite SHOULD assert each clause above with recorded exchanges that
include at least: a SLIM unary SRPC call carried opaquely as BRIDGE_REQUEST →
BRIDGE_RESPONSE with `content_type = 0x03`; a SLIM streamed call carried as
BRIDGE_STREAM_DATA frames terminated by BRIDGE_STREAM_END; a SLIM fire-and-forget publish
carried as BRIDGE_NOTIFY with no reply; an ACP `POST /runs` carrying a
`non_idempotent_write` SafetyLabel and a second `POST /runs` with the SafetyLabel omitted,
verified to be treated as `destructive`; an ACP `DELETE` carried with a `destructive`
label; and a BRIDGE_REQUEST bearing the AGNTCY `protocol_id` toward a peer that does not
carry it, verified to return `ProtocolUnsupported`.
