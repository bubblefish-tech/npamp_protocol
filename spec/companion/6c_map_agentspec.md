# NPAMP-MAP-AGENTSPEC — Open Agent Specification (Agent Spec) Mapping (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is a **thin per-protocol mapping**: it pins the specifics of the
> **Open Agent Specification (Agent Spec)** — a framework-agnostic *declarative
> document/schema* for defining agents and agentic systems — onto N-PAMP carriage. Agent
> Spec is not a wire protocol: it defines **no transport, no request/response methods,
> and no API of its own** (§7). It is therefore carried as a **capability/schema
> document** under the document carriage class **NPAMP-CC-DOC** (`24_carriage_documents.md`),
> which does the structural work; this document pins only what is specific to Agent Spec.
> It builds on NPAMP-CC-DOC, on NPAMP-BRIDGE (`10_bridge_framework.md`), and on the N-PAMP
> core specification (draft-bubblefish-npamp-01, the "core specification"). It consumes
> only code points those documents already reserve and introduces no change to the core
> wire format, to NPAMP-BRIDGE, or to NPAMP-CC-DOC.
>
> **OPAQUE-READY.** Agent Spec has **no standards-assigned `protocol_id`** (NPAMP-REG §6
> assigns none) and, in the sources consulted (§10), declares no media type of its own. An
> Agent Spec document is therefore **carriable today via Class OPAQUE** as a JSON or YAML
> payload; this document is the **native DOC mapping**, and it pins the Agent-Spec-specific
> facts that become normative **once a `protocol_id` is assigned and the document's media
> type is confirmed** (§7). Until then, the `protocol_id` in §2 is **PROVISIONAL** and
> drawn from the experimental range (NPAMP-REG §7.1).

## 1. Scope

### 1.1 In scope

This document specifies how an Open Agent Specification (Agent Spec) document is carried
over an N-PAMP association as a capability/schema document. It pins, against Agent Spec's
own published specification (§10), only the Agent-Spec-specific facts that NPAMP-CC-DOC
leaves to a per-protocol mapping:

- The **`protocol_id`** used for Agent Spec and its carriage class, and the foreign-message
  `content_type` for the JSON and YAML serializations (§2);
- How an Agent Spec document rides NPAMP-CC-DOC as a **document set** — the (document-only)
  operation namespace, the `doc_id`/digest binding, detached proofs where a deployment signs
  the document, and streaming for a large document (§4);
- The **SafetyLabel effect class** for serving an Agent Spec document, and the NPAMP-BRIDGE
  §7 fail-safe for the one case in which *requesting* a document is itself state-mutating
  (§5); and
- **Channel selection**: the Bridge channel `0x000D` as the default and the Discovery
  channel `0x0010` as the OPTIONAL advertisement channel for a capability document (§6).

### 1.2 Not in scope

The following are explicitly NOT defined by this document, because NPAMP-CC-DOC,
NPAMP-BRIDGE, or Agent Spec's own specification already define them, or because Agent Spec
does not define them at all:

- The **structural document carriage** — octet-exact delivery, the DocumentBinding
  descriptor, digest stability, proof binding, streaming reassembly, and the document-set
  error model. These are inherited verbatim from NPAMP-CC-DOC (§4–§8 of that document) and
  are not restated here (§3).
- The **internal grammar and semantics** of an Agent Spec document — its agents, flows,
  LLMs, tools, properties, memory, guardrails, and audit objects (§4). These are fixed by
  Agent Spec's own specification and are carried verbatim (NPAMP-BRIDGE §1); this mapping
  does not parse, validate, interpret, execute, or re-serialize them.
- Any **Agent Spec request/response protocol, RPC method, or API endpoint.** Agent Spec
  defines none (§7); this mapping does not invent one. The only operations over N-PAMP are
  the NPAMP-CC-DOC document-retrieval patterns (§4).
- **Execution of an Agent Spec document.** Native Agent Spec is executed by framework
  runtime adapters, and its user-facing interaction is carried by a *separate* protocol
  (AG-UI), not by Agent Spec itself (§7, §10). Carriage of that separate interaction traffic
  is out of scope here (it is the subject of AG-UI's own mapping, `64_map_agui.md`).
- Any change to the N-PAMP frame format, to the NPAMP-BRIDGE frame types, to the
  BridgeEnvelope, SafetyLabel, or DocumentBinding TLVs, or to the NPAMP-CC-DOC rules.

## 2. Protocol identity

| Property | Value |
|---|---|
| Protocol | Open Agent Specification (Agent Spec) — a framework-agnostic declarative document/schema for defining agents and agentic systems (§10). |
| `protocol_id` | **`0x3D` — PROVISIONAL.** Agent Spec has no standards-assigned code point (NPAMP-REG §6 assigns only `0x01`–`0x04`; `0x05`–`0x0F` are unassigned). `0x3D` lies in the experimental range `0x10`–`0x7F` (NPAMP-REG §7.1); it carries **no cross-domain meaning**, MUST be used only under out-of-band agreement between the peers, and MUST NOT be a production default (NPAMP-REG §7.1). A standards code point in `0x05`–`0x0F` SHOULD be obtained under NPAMP-REG §8 before general interoperation, and this value then retired (§7). |
| Carriage class | DOC (NPAMP-CC-DOC). |
| `content_type` | `0x01` (application/json) for the JSON serialization. YAML is also a supported serialization but is **not** a BridgeEnvelope-enumerated `content_type`; a YAML document depends on the DocumentBinding `doc_content_type` field and on the (currently unassigned) OpaqueContentType discriminator of NPAMP-CC-OPAQUE §4 — a marked dependency, not a fabricated code point (§4.2, §7). |
| Foreign-message form | A single Agent Spec document — a declarative JSON (or YAML) definition of an agent or agentic system — carried octet-for-octet as the document part of an NPAMP-CC-DOC document set (NPAMP-BRIDGE §1; NPAMP-CC-DOC §4). |

A sender MUST set `protocol_id = 0x3D` (PROVISIONAL) on every Bridge frame carrying an
Agent Spec document only where the peer has agreed that value out of band; absent such
agreement, or in production, the document is carried under Class OPAQUE per §7. A receiver
that does not carry Agent Spec MUST reply to a BRIDGE_REQUEST bearing the value with
`ProtocolUnsupported` (NPAMP-BRIDGE §6; NPAMP-REG §9), and MUST NOT infer Agent Spec from
any other envelope field (NPAMP-REG §9).

## 3. Relationship to NPAMP-CC-DOC and NPAMP-BRIDGE

Agent Spec is a self-contained artifact that one agent publishes so another can discover,
verify, and consume it — exactly the family NPAMP-CC-DOC serves (NPAMP-CC-DOC §1).
Consequently the entire structural carriage of an Agent Spec document is provided by
NPAMP-CC-DOC without modification:

- The transparency rule governs: an Agent Spec document is carried octet-for-octet and MUST
  NOT be canonicalized, re-indented, re-encoded, reordered, minified, or otherwise altered
  by one octet on the path (NPAMP-BRIDGE §1; NPAMP-CC-DOC §4). This is what allows a digest
  or signature computed by the producer to verify bit-identically at the consumer
  (NPAMP-CC-DOC §5).
- The document and any detached proofs over it form a **document set** under one
  `correlation_id`, assembled by the consumer per NPAMP-CC-DOC §6–§7. This document adds no
  correlation or assembly rule.
- The **DocumentBinding** descriptor (NPAMP-CC-DOC §6) — `part_kind`, `doc_id`,
  `doc_content_type`, `digest_alg`, `digest`, `proof_count`, `proof_index`, `proof_alg` —
  is carried around the document octets exactly as NPAMP-CC-DOC defines it; this mapping
  does not add fields to it.

This document therefore pins only Agent Spec specifics (§2, §4, §5, §6). Where this document
and NPAMP-CC-DOC could appear to differ on a structural matter, NPAMP-CC-DOC governs.

## 4. Carriage of an Agent Spec document

### 4.1 Operation namespace (document only)

Agent Spec defines no request/response methods (§7). Its "operation namespace" over N-PAMP
is therefore limited to the NPAMP-CC-DOC document-retrieval patterns:

- **Pull.** A consumer MAY request an Agent Spec document with a `BRIDGE_REQUEST` (`0x0100`)
  whose `method` names the requested document or document family (a document-retrieval
  operation name fixed by the deployment, e.g. an agent-spec retrieval verb), per
  NPAMP-CC-DOC §7.1. The `BRIDGE_REQUEST` carries no document part and therefore no
  DocumentBinding TLV; the producer replies with the document part (and any proof parts) as
  `BRIDGE_RESPONSE` (`0x0101`) frames — or as `BRIDGE_STREAM_DATA`/`BRIDGE_STREAM_END` for a
  large document (§4.4) — echoing the request's `correlation_id`.
- **Push.** A producer MAY advertise an Agent Spec document unsolicited. A single document
  with no detached proofs MAY be carried as one `BRIDGE_NOTIFY` (`0x0103`) with
  `proof_count = 0` and `corr_len = 0` (NPAMP-CC-DOC §7.2). A document that has detached
  proofs, or one large enough to require streaming, MUST be carried under a shared
  `correlation_id` opened by a `BRIDGE_REQUEST`, per NPAMP-CC-DOC §7.2.

Because the Bridge channel is bidirectional, either peer MAY originate the exchange
(NPAMP-BRIDGE §5); no N-PAMP role is tied to which side authors or hosts the Agent Spec
document.

### 4.2 Document identity, media type, and digest

- **`doc_id`.** The DocumentBinding `doc_id` (NPAMP-CC-DOC §6.2) is an opaque identifier
  stable across all parts of one document set; a deployment SHOULD derive it from a stable
  Agent Spec document identity (for example the document's own name/version tuple) so that a
  consumer can pair proofs to the document independently of `correlation_id`.
- **`doc_content_type`.** The DocumentBinding `doc_content_type` (NPAMP-CC-DOC §6.2) carries
  the document part's media type. For the JSON serialization this is the JSON media type
  (`application/json`); for the YAML serialization it is a YAML media type (for example
  `application/yaml`). Agent Spec does **not**, in the sources consulted (§10), register an
  Agent-Spec-specific media type; a sender MUST NOT fabricate one and MUST declare the
  generic serialization media type until an Agent-Spec-specific type is confirmed (§7).
- **`digest`.** The DocumentBinding `digest`/`digest_alg` are computed over the exact
  document octets the producer places on the wire (NPAMP-CC-DOC §5). The consumer MUST
  recompute and match the digest before presenting the document as verified (NPAMP-CC-DOC
  §5), using a constant-time comparison.

### 4.3 Detached proofs

Agent Spec, in the sources consulted (§10), defines **no detached-signature scheme of its
own**; its schema includes an audit object for logging/monitoring, not a document signature.
Therefore:

- Where a deployment does **not** sign the Agent Spec document, the document set is a bare
  document part with `proof_count = 0` (NPAMP-CC-DOC §7.2).
- Where a deployment **does** sign the document (for example a publisher attaching a detached
  signature over the document octets), each signature is carried as an NPAMP-CC-DOC detached
  proof bound to the document by `doc_id` and digest (NPAMP-CC-DOC §6.3), with `proof_alg`
  naming a core-assigned signature code point (NPAMP-CC-DOC §6.4). Verification is the
  consumer's act (NPAMP-CC-DOC §6.5); carriage delivers the document and its proofs with the
  integrity guarantees a verifier needs and does not itself decide trust. This mapping does
  not define a signature format for Agent Spec and MUST NOT be read to require one.

### 4.4 Large documents

An Agent Spec document too large for one frame MUST be carried as an ordered sequence of
`BRIDGE_STREAM_DATA` (`0x0104`) frames terminated by `BRIDGE_STREAM_END` (`0x0105`) with the
`final` flag set, all echoing one `correlation_id`; the digest is computed over the
reassembled octets (NPAMP-CC-DOC §7.4). A consumer MUST NOT compute or compare the digest
until reassembly is complete (NPAMP-CC-DOC §7.4).

## 5. SafetyLabel and effect classes

Serving a capability/schema document is `read_only` under the NPAMP-BRIDGE SafetyLabel model
(NPAMP-BRIDGE §7; NPAMP-CC-DOC §9). Agent Spec defines no state-mutating operations of its
own (§7), so there is no per-method effect classification to pin; the effect classes below
follow directly from NPAMP-CC-DOC §9.

| Operation | Effect (NPAMP-BRIDGE §7) | Rationale |
|---|---|---|
| Serving an Agent Spec document (the document part in a `BRIDGE_RESPONSE`, `BRIDGE_NOTIFY`, or stream) | `0x00` read_only | An advertisement of a static document; it acts on no external state. A producer SHOULD attach a SafetyLabel with `effect = read_only` (NPAMP-CC-DOC §9). |
| Requesting an Agent Spec document (the `BRIDGE_REQUEST`) in a deployment where retrieval is itself state-mutating (for example a request that causes the producer to generate, register, or sign a fresh document) | ≥ `0x01`, per the actual effect | The requester MUST attach a SafetyLabel describing that effect (NPAMP-CC-DOC §9). |

The NPAMP-BRIDGE §7 fail-safe applies unchanged: a receiver MUST NOT treat the **absence** of
a SafetyLabel on a state-mutating request as `read_only`; absence on such a request MUST be
treated as `destructive` (NPAMP-BRIDGE §7; NPAMP-CC-DOC §9). A SafetyLabel describes intent
and does not replace authorization, and it does not replace the document's own detached proofs
(§4.3), which carry the document's authenticity independently of any transport-level
annotation.

## 6. Channel selection

An Agent Spec document rides **NPAMP-CC-DOC on the Bridge channel `0x000D`** by default
(NPAMP-CC-DOC §3). Because an Agent Spec document is a capability/discovery artifact, it MAY
instead, or in addition, be carried on the **Discovery channel `0x0010`**, whose
core-specified purpose is "agent, tool, and service discovery and capability advertisement"
(NPAMP-CC-DOC §1.1, §3; companion index, "Channel selection for carriage"). A document and
its detached proofs MUST NOT be split across the Bridge and Discovery channels; every frame
of one document set MUST be carried on the same channel (NPAMP-CC-DOC §3).

Separately from carrying the document, a peer MAY advertise, over NPAMP-DISC on the Discovery
channel `0x0010`, that it carries Agent Spec — a protocol Discovery Record naming the
Agent Spec `protocol_id` and carriage class DOC (NPAMP-DISC §5.1). A peer MUST NOT advertise
Agent Spec if it cannot in fact carry that `protocol_id` over the association.

The Bridge channel `0x000D` and the Discovery channel `0x0010` are both minimum-profile
**Standard** (core specification channel registry); Agent Spec carriage requires no channel
above the Standard profile. A peer MUST NOT send or accept Agent Spec
frames on a channel it did not advertise during the handshake (core specification §5).

## 7. OPAQUE-READY status: confirmed vs unconfirmed, and version considerations

This mapping is **OPAQUE-READY**: an Agent Spec document is carriable today, and the native
DOC facts above become fully normative once the marked items are confirmed. The following
records precisely what is confirmed against the primary sources (§10) and what is not, so an
implementer confirms the open items against Agent Spec's own specification rather than
relying on assumption.

**Confirmed (against §10):**

1. Agent Spec is a **declarative document/schema**, not a wire protocol. Its own materials
   state it is a declarative/configuration language whose components are a *representation*,
   "not … an implementation of how these … should work" (§10, technical report). It defines
   **no transport, no request/response methods, and no API**; execution is delegated to
   framework runtime adapters, and user-facing interaction is carried by a *separate*
   protocol (AG-UI) via an adapter/endpoint (§10, AG-UI-integration source).
2. The primary serialization is **JSON**; **YAML** is also supported (§10, repository).
3. The document has a component model (agents, flows/workflows, LLMs, tools, properties,
   memory, guardrails, and an audit object) that this mapping carries verbatim and does not
   interpret (§4; §10).
4. Agent Spec is versioned; the latest release at the time of writing is **v26.1.2**
   (2 June 2026), and the technical report describes an earlier language-spec version
   (`25_4_0`) (§10). Because the carriage is a transparent DOC document set, a newer or older
   Agent Spec version is carried without a change to this mapping.

**Unconfirmed / open (marked, not fabricated):**

1. **No standards `protocol_id`.** NPAMP-REG §6 assigns none; the `0x3D` in §2 is PROVISIONAL
   and experimental (NPAMP-REG §7.1). A standards value in `0x05`–`0x0F` SHOULD be obtained
   under NPAMP-REG §8 before general interoperation.
2. **No declared media type.** The sources consulted (§10) declare no Agent-Spec-specific
   media type or file extension; this mapping declares the generic serialization media type
   in `doc_content_type` (§4.2) and MUST be updated if an Agent-Spec-specific type is later
   registered.
3. **YAML `content_type` discriminator.** A YAML document's BridgeEnvelope `content_type`
   depends on the OpaqueContentType discriminator of NPAMP-CC-OPAQUE §4, whose code point is
   not yet assigned by the core specification (NPAMP-CC-OPAQUE §10); until it is, only the
   JSON serialization (`content_type = 0x01`) is expressible on the wire without that
   dependency.
4. **No native document-signature scheme** (§4.3): where present, signing is a deployment
   choice carried as an NPAMP-CC-DOC detached proof, not an Agent Spec feature.

A same-named but **unrelated** academic project — "AgentSpec: Customizable Runtime
Enforcement for Safe and Reliable LLM Agents" (§10) — is a runtime-enforcement DSL
(triggers/predicates/enforcements), **not** a capability/schema document and not a transport;
it is **not** the protocol mapped here. This document maps the Open Agent Specification
(Agent Spec) only.

## 8. Code points consumed

This mapping consumes only code points the core specification, NPAMP-BRIDGE, and NPAMP-CC-DOC
already define or reserve. It defines no new frame type, no new TLV, and no change to the core
wire format.

| Resource | Origin | Use here |
|---|---|---|
| `protocol_id` `0x3D` (**PROVISIONAL**, experimental) | NPAMP-REG §7.1 (experimental range) | The Agent Spec identifier on every Agent Spec Bridge frame, under out-of-band agreement only (§2, §7). |
| `content_type` `0x01` (application/json) | NPAMP-BRIDGE §4 | The JSON Agent Spec document's foreign-message encoding (§2, §4.2). |
| Channel `0x000D` (Bridge) | Core specification | Default channel for Agent Spec document carriage (§6). |
| Channel `0x0010` (Discovery) | Core specification | Optional channel for Agent Spec capability advertisement (§6). |
| Bridge frame types `0x0100`–`0x0105` | NPAMP-BRIDGE §2 | Reused unchanged for document/proof/stream carriage (§4). |
| BridgeEnvelope TLV `0x0010`, SafetyLabel TLV `0x0013` | Core specification; NPAMP-BRIDGE | Carried unchanged (§2, §5). |
| DocumentBinding TLV (NPAMP-CC-DOC §6, Type `0xTBD-DOCBIND` **provisional**) | NPAMP-CC-DOC | Document-binding metadata for the Agent Spec document (§3, §4). Its provisional status is inherited from NPAMP-CC-DOC and not resolved here. |

This document requests no IANA action and defines no registry.

## 9. Security considerations

This mapping introduces no cryptography and changes none. All confidentiality, integrity,
authentication, downgrade resistance, and replay protection are provided by the core
specification's wire format and key schedule and apply unchanged to every Agent Spec frame,
which travels inside the AEAD-protected Bridge (or Discovery) payload; the `protocol_id`, the
DocumentBinding metadata, any SafetyLabel, and the Agent Spec document are authenticated and
confidentiality-protected to the same degree.

Carrying Agent Spec over N-PAMP makes no security claim about Agent Spec itself. In
particular:

- **The document is untrusted input.** The carriage delivers the Agent Spec document
  octet-exact and does not parse or validate it; a consumer MUST validate the document
  against the Agent Spec schema and MUST apply its own authorization before executing,
  instantiating, or otherwise acting on any agent, tool, flow, or guardrail the document
  describes (NPAMP-CC-DOC §6.5; NPAMP-BRIDGE §7). Delivery of a document is not endorsement
  of its contents.
- **Authenticity is carried by proofs, not by transport.** Where an Agent Spec document is
  signed, its detached proof (§4.3), verified by the consumer under NPAMP-CC-DOC, carries the
  document's authenticity independently of the transport; carriage delivery of a proof is not
  verification of it (NPAMP-CC-DOC §6.5). Where a document is unsigned, the N-PAMP association
  authenticates the *peer*, not the document's authorship.
- **Provisional identifier.** Because `0x3D` is experimental (§2), a receiver MUST treat it as
  uncarried unless it has out-of-band agreement on its meaning, and MUST return
  `ProtocolUnsupported` otherwise (NPAMP-REG §7.1, §9); an implementation MUST NOT ship it as
  a production default (NPAMP-REG §7.1).
- **Safety fail-safe.** The NPAMP-BRIDGE §7 fail-safe (absence of a SafetyLabel on a
  state-mutating request is `destructive`) applies to the deployment-defined state-mutating
  retrieval case of §5; discovery of an Agent Spec document is a claim, not authorization
  (NPAMP-DISC §10).

## 10. References

Primary source (the protocol mapped here — Open Agent Specification / Agent Spec):

- Open Agent Specification (Agent Spec) Technical Report — arXiv:2510.04173 —
  <https://arxiv.org/abs/2510.04173> (HTML: <https://arxiv.org/html/2510.04173v1>). Confirms
  Agent Spec is a declarative language, JSON as the designated serialization, the component
  model (Agent, LLM, Tool, Flow, node/edge types), and that it "provides their
  representation," not an implementation — i.e. no transport of its own.
- `oracle/agent-spec` — Open Agent Specification reference repository —
  <https://github.com/oracle/agent-spec>. Confirms the "portable, platform-agnostic
  configuration language" nature, JSON and YAML serialization, execution via runtime adapters
  (WayFlow, LangGraph, AutoGen, CrewAI), dual Apache-2.0 / UPL-1.0 licensing, and the latest
  release (v26.1.2, 2 June 2026).
- Oracle, "Introducing the Open Agent Specification (Agent Spec)" —
  <https://blogs.oracle.com/ai-and-datascience/introducing-open-agent-specification>.
- Oracle, "AG-UI integration for Open Agent Specification" —
  <https://blogs.oracle.com/ai-and-datascience/announcing-ag-ui-integration-for-agent-spec>.
  Confirms Agent Spec is "the contract" (a configuration document) and that user-facing
  interaction is carried by the *separate* AG-UI protocol via an adapter/endpoint — i.e.
  Agent Spec defines no native wire transport.

Disambiguation (same name, NOT the protocol mapped here):

- "AgentSpec: Customizable Runtime Enforcement for Safe and Reliable LLM Agents"
  (Wang, Poskitt, Sun; Singapore Management University) — arXiv:2503.18666 —
  <https://arxiv.org/abs/2503.18666>. A domain-specific language for runtime safety rules
  (triggers, predicates, enforcements). It is a local enforcement DSL, **not** a
  capability/schema document, and defines no transport; it is not the protocol mapped here
  (§7).

N-PAMP documents built on:

- draft-bubblefish-npamp-01 — the N-PAMP core specification (Bridge channel `0x000D`,
  Discovery channel `0x0010`, the frame format, the BridgeEnvelope and SafetyLabel TLV
  reservations, and AEAD payload protection).
- NPAMP-BRIDGE (`10_bridge_framework.md`) — the encapsulation, correlation, error, and
  SafetyLabel contract.
- NPAMP-CC-DOC (`24_carriage_documents.md`) — the document carriage class that does the
  structural work for Agent Spec.
- NPAMP-CC-OPAQUE (`25_carriage_opaque.md`) — the universal carriage under which Agent Spec
  is carriable today, and the source of the media-type discriminator dependency (§4.2, §7).
- NPAMP-REG (`30_protocol_registry.md`) — the Bridge Protocol Identifier registry (Agent Spec
  is unassigned; the experimental range of §7.1 is used provisionally).
- NPAMP-DISC (`40_discovery.md`) — the Discovery-channel advertisement referenced in §6.
- BCP 14: RFC 2119 and RFC 8174 — requirement key words.

## 11. Conformance

An implementation conforms to NPAMP-MAP-AGENTSPEC if and only if it conforms to NPAMP-CC-DOC
(and therefore to NPAMP-BRIDGE) for the frames it emits and parses in this mapping and, for
Agent Spec traffic, it:

1. Carries every Agent Spec document as an NPAMP-CC-DOC document part, octet-for-octet,
   performing no canonicalization, transcoding, re-serialization, or document-layer
   compression, and never parsing, validating, or interpreting the document's internal
   Agent Spec structure (§1.2, §3, §4);
2. Uses the Agent Spec `protocol_id` `0x3D` only as a **PROVISIONAL** experimental value under
   out-of-band agreement, never as a production default, returns `ProtocolUnsupported` for a
   request bearing a `protocol_id` it does not carry, and selects Agent Spec solely from
   `protocol_id`, never from another envelope field (§2, §7; NPAMP-REG §7.1, §9);
3. Sets `content_type = 0x01` for a JSON Agent Spec document, declares the document's media
   type in the DocumentBinding `doc_content_type` without fabricating an Agent-Spec-specific
   media type, and treats the YAML serialization's BridgeEnvelope `content_type` as dependent
   on the unassigned NPAMP-CC-OPAQUE §4 discriminator (§2, §4.2, §7);
4. Carries the document via the NPAMP-CC-DOC pull (`BRIDGE_REQUEST` → document/proof parts) or
   push (`BRIDGE_NOTIFY`, or a streamed set under a `BRIDGE_REQUEST` correlation) patterns,
   binds the document and any proofs by `correlation_id`, `doc_id`, and digest, and
   reassembles a streamed document before computing its digest (§4);
5. Carries a signature over an Agent Spec document, where a deployment supplies one, as an
   NPAMP-CC-DOC detached proof with a core-assigned `proof_alg`, leaving verification to the
   consumer, and carries an unsigned document as a bare document part with `proof_count = 0`,
   inventing no signature scheme for Agent Spec (§4.3);
6. Labels serving an Agent Spec document `read_only`, attaches a SafetyLabel describing the
   effect on any deployment-defined state-mutating retrieval request, and treats a missing
   SafetyLabel on such a request as `destructive` (NPAMP-BRIDGE §7 fail-safe), never treating
   a favorable SafetyLabel as authorization (§5, §9);
7. Carries an Agent Spec document on the Bridge channel `0x000D` by default or the Discovery
   channel `0x0010`, never splitting a document and its proofs across the two channels, and
   sends or accepts Agent Spec frames only on channels advertised during the handshake (§6);
   and
8. Defines no new frame type, TLV, or code point, consuming only those enumerated in §8, and
   inherits the provisional status of the DocumentBinding TLV without resolving it here (§8).

A conformance test suite SHOULD assert each clause above with recorded exchanges that include:
A single-frame JSON Agent Spec document pushed as a `BRIDGE_NOTIFY` with `proof_count = 0`; a
pull `BRIDGE_REQUEST` answered with an Agent Spec document part whose recomputed digest
matches its DocumentBinding `digest`; a streamed multi-frame Agent Spec document whose digest
is computed over the reassembly; an Agent Spec document carried with one detached signature
proof under NPAMP-CC-DOC on both the Bridge and the Discovery channel; a deployment-defined
state-mutating retrieval request carried with a SafetyLabel and a second identical request
with the SafetyLabel omitted, verified to be treated as `destructive`; and a `BRIDGE_REQUEST`
bearing the Agent Spec `protocol_id` toward a peer that has no out-of-band agreement on it,
verified to be answered with `ProtocolUnsupported`.
