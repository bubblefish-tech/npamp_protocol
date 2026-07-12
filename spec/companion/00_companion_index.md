# N-PAMP Companion Specifications — Index

> Companion to **draft-bubblefish-npamp-01** (the "core specification"). N-PAMP is a
> transport substrate that sits beneath application-layer agent protocols and **carries
> any of them** over an authenticated, post-quantum, multi-channel wire (core spec
> Abstract; §5 Bridge channel `0x000D` — "Encapsulation of external agent protocols").
> These companion specifications define that carriage so that an off-the-shelf client
> or agent of a foreign protocol interoperates over N-PAMP with no bespoke adaptation.
>
> **Design principle — carriage by class, not by protocol.** N-PAMP does not enumerate
> a fixed list of supported protocols. It defines (1) a protocol-agnostic **bridge
> framework**, (2) a small set of **carriage classes** that cover whole families of
> protocols, (3) an extensible **protocol registry**, and (4) an **opaque carriage**
> class that carries any payload of any protocol — including protocols not yet defined
> — transparently. Adding native support for a new agent protocol is a short
> registration plus an optional thin mapping, never a new framework.

## Status legend

`DRAFT` — normative text authored. `PLANNED` — code points reserved, scope fixed, text
to be authored. `OPAQUE-READY` — carriable today via Class OPAQUE with no protocol
mapping; a native mapping may be added later.

## Conformance posture

Interoperable carriage requires both a **core-conformant** N-PAMP wire implementation
and a **bridge implementation conforming to NPAMP-BRIDGE** plus the relevant carriage
class. Each document states its requirements in a §Conformance clause; these documents
define required behavior and make no statement about any implementation.

## The specification set

### Framework and carriage classes

| File | Short name | Defines | Status |
|---|---|---|---|
| `10_bridge_framework.md` | NPAMP-BRIDGE | The protocol-agnostic encapsulation on Bridge channel `0x000D`: frame types, transparent-payload carriage, correlation identifier, structured-error model, one-way notifications, streaming, and the safety-annotation TLV. Every carriage class inherits this contract. | **DRAFT** |
| `20_carriage_jsonrpc.md` | NPAMP-CC-JSONRPC | Carriage of any **JSON-RPC 2.0** agent protocol (request/response/notification id, params, result, error mapped generically). | **DRAFT** |
| `21_carriage_http.md` | NPAMP-CC-HTTP | Carriage of any **HTTP-semantics** protocol (method, path, headers, body; for REST/OpenAPI-style agent and discovery-document protocols). | **DRAFT** |
| `22_carriage_messaging.md` | NPAMP-CC-MSG | Carriage of any **message-passing / performative** protocol (performative/speech-act, sender, receiver, conversation-id, ontology, content-language). | **DRAFT** |
| `23_carriage_streaming.md` | NPAMP-CC-STREAM | Carriage of any **event/streaming** protocol (typed events over BRIDGE_STREAM_DATA/END; for interactive and human-in-the-loop flows). | **DRAFT** |
| `24_carriage_documents.md` | NPAMP-CC-DOC | Carriage of **capability/schema documents** (agent cards, tool catalogs, schemas) for advertisement and discovery. | **DRAFT** |
| `25_carriage_opaque.md` | NPAMP-CC-OPAQUE | **Universal escape hatch** — carriage of an opaque, declared-content-type payload under a registered or private protocol id, with no protocol-specific mapping. Makes *any* protocol, including undefined ones, carriable immediately. | **DRAFT** |

### Registry and discovery

| File | Short name | Defines | Status |
|---|---|---|---|
| `30_protocol_registry.md` | NPAMP-REG | The **Bridge Protocol Identifier registry** (the `protocol_id` field of NPAMP-BRIDGE): assigned code points, carriage class, and registration procedure, with experimental and private ranges. | **DRAFT** |
| `40_discovery.md` | NPAMP-DISC | Runtime advertisement and lookup over Discovery channel `0x0010`: which protocols, carriage classes, tools, and agents a peer offers. | **DRAFT** |

### Identity, bootstrap, and signed discovery

| File | Short name | Defines | Status |
|---|---|---|---|
| `45_hello_bootstrap.md` | NPAMP-HELLO | Post-handshake capability exchange on Control channel `0x0000`: each peer advertises an ordered name-list of the protocols/channels it carries; client-preference intersection; ignore-unknown + GREASE; transcript-bound downgrade protection. A selector, never a directory. | **DRAFT** |
| `41_discovery_signed.md` | NPAMP-DISC-SIGNED | Extends NPAMP-DISC: individually ML-DSA-87/Ed25519-signed Discovery Records, offline-verifiable against a deployer-configured trust anchor, with `not_after` freshness. No vendor directory. | **DRAFT** |
| `50_peer_handle.md` | NPAMP-PEERHANDLE | Connection-scoped self-certifying peer name = multibase(multihash(SHA-256, multicodec(`0x1212`, ML-DSA-87 key))); key carried as an RFC 7250 SPKI; optional foreign-identity cross-signature. No tiers, no registry. | **DRAFT** |

### Conformance

| File | Short name | Defines | Status |
|---|---|---|---|
| `55_conformance_requirements.md` | NPAMP-CONFORM | The normative conformance classes for draft-00 — wire-primitives (Class W, graded by the pinned 255-vector corpus), handshake (Class H, graded by the five standards-anchored KATs, Standard profile), and bridge/companion (Class B, specification-audited; no bridge vectors exist yet) — plus the required content of a conformance claim, the prohibited claims, and an explicit statement of what the current corpus does NOT cover. | **DRAFT** |

### Worked examples (informative)

| File | Short name | Defines | Status |
|---|---|---|---|
| `56_worked_example_handshake.md` | NPAMP-EX-HANDSHAKE | Developer walk-through of one complete Standard-profile association: the four handshake flights (CLIENT_HELLO → SERVER_HELLO + SERVER_AUTH → CLIENT_AUTH), the five transcript points, every key-schedule stage, both CertVerify/Finished authentications, and one application frame exchange — every byte grounded in the pinned `test-vectors/v1` KATs, the conformance corpus, and the 2026-06-23 live interop capture, with per-value provenance tags. Informative; defines no wire behavior, consumes no code points. | **DRAFT** |

### Thin per-protocol mappings (one short document each, organized by class)

Each is a brief registration: a `protocol_id`, the carriage class it uses, the foreign
method/operation namespace, and any protocol-specific fields. The carriage class does
the structural work; these only pin protocol specifics. **Until a mapping is authored,
the protocol is still carriable today via Class OPAQUE.** Precise field mappings MUST be
specified against each protocol's own published specification before that mapping is
marked DRAFT.

| Protocol | File | Carriage class | Status |
|---|---|---|---|
| MCP — Model Context Protocol | `60_map_mcp.md` | JSONRPC | **DRAFT** |
| A2A — Agent2Agent | `61_map_a2a.md` | JSONRPC + DOC (AgentCard) | **DRAFT** |
| ACP — Agent Communication Protocol | `62_map_acp.md` | HTTP | **DRAFT** |
| ANP — Agent Network Protocol | `63_map_anp.md` | HTTP / OPAQUE | **DRAFT** |
| AG-UI — Agent-User Interaction | `64_map_agui.md` | STREAM | **DRAFT** |
| AP2 — Agent Payments Protocol | `65_map_ap2.md` | JSONRPC / DOC | **DRAFT** |
| UCP — Universal Commerce Protocol | `66_map_ucp.md` | HTTP | **DRAFT** |
| AITP — Agent Interaction & Transaction Protocol | `67_map_aitp.md` | JSONRPC | **DRAFT** |
| LMOS — Language Model Operating System | `68_map_lmos.md` | STREAM | **DRAFT** |
| OASF — Open Agentic Schema Framework | `69_map_oasf.md` | DOC | **DRAFT** |
| FIPA-ACL — FIPA Agent Communication Language | `6a_map_fipa_acl.md` | MSG | **DRAFT** |
| agents.json | `6b_map_agents_json.md` | DOC | **DRAFT** |
| AgentSpec | `6c_map_agentspec.md` | DOC | **DRAFT** |
| AgentScript | `6d_map_agentscript.md` | DOC | **DRAFT** |
| Microsoft Agent Framework | `6e_map_msagentfw.md` | JSONRPC / HTTP / STREAM | **DRAFT** |
| AGNTCY — agent interoperability collective | `6f_map_agntcy.md` | JSONRPC / STREAM | **DRAFT** |
| NLIP — Natural Language Interaction Protocol | `70_map_nlip.md` | HTTP / STREAM | **DRAFT** |
| Vendor-private / custom | (no file required) | OPAQUE | **Carriable now** — register a private `protocol_id` and use Class OPAQUE. |
| **Any other agent protocol** | (no file required) | OPAQUE | **Carriable now** — Class OPAQUE carries any declared-content-type payload. A native mapping is optional, added when richer interop is wanted. |

> All 17 mappings now have authored DRAFT text, each verified against that protocol's own
> published specification. Each mapping states, in its own text, what is confirmed versus
> provisional: where a protocol's base transport, field set, or `protocol_id` is not yet
> confirmed, the mapping documents an OPAQUE-READY fallback — the protocol is carriable
> today via Class OPAQUE — and marks the unconfirmed points explicitly rather than
> asserting them. Several `protocol_id` values are PROVISIONAL (the experimental range,
> by out-of-band agreement) pending assignment by NPAMP-REG; no mapping fabricates a
> standards code point.

### Per-channel interface references

One public interface reference page per core channel (draft §5 Channel Architecture), under
`../channels/`. The core specification governs channel behavior; each page restates its
channel's public interface (id, name, purpose, direction, minimum profile, reserved frame
ranges) at the registry level and introduces no behavior the core specification lacks. The
six High/Sovereign-gated channels are documented as public **interface stubs** — their
existence and public shape only; their operational and cryptographic internals require the
High/Sovereign profile and are out of scope for this public set.

| Channel | File | Min profile | Status |
|---|---|---|---|
| `0x0000` Control | `../channels/0000_control.md` | Standard | **DRAFT** |
| `0x0001` Memory | `../channels/0001_memory.md` | Standard | **DRAFT** |
| `0x0002` Capability | `../channels/0002_capability.md` | Standard | **DRAFT** |
| `0x0003` Identity | `../channels/0003_identity.md` | Standard | **DRAFT** |
| `0x0004` Governance | `../channels/0004_governance.md` | High (interface stub) | **DRAFT** |
| `0x0005` Immune | `../channels/0005_immune.md` | Standard | **DRAFT** |
| `0x0006` Federation | `../channels/0006_federation.md` | High (interface stub) | **DRAFT** |
| `0x0007` Settlement | `../channels/0007_settlement.md` | Standard | **DRAFT** |
| `0x0008` Compliance | `../channels/0008_compliance.md` | High (interface stub) | **DRAFT** |
| `0x0009` Sensory | `../channels/0009_sensory.md` | High (interface stub) | **DRAFT** |
| `0x000A` Telemetry | `../channels/000A_telemetry.md` | Standard | **DRAFT** |
| `0x000B` Audit | `../channels/000B_audit.md` | Sovereign (interface stub) | **DRAFT** |
| `0x000C` Stream | `../channels/000C_stream.md` | Standard | **DRAFT** |
| `0x000D` Bridge | `../channels/000D_bridge.md` | Standard | **DRAFT** |
| `0x000E` Commerce | `../channels/000E_commerce.md` | Standard | **DRAFT** |
| `0x000F` Interaction | `../channels/000F_interaction.md` | Standard | **DRAFT** |
| `0x0010` Discovery | `../channels/0010_discovery.md` | Standard | **DRAFT** |
| `0x0011` Workflow | `../channels/0011_workflow.md` | Standard | **DRAFT** |
| `0x0012` Knowledge | `../channels/0012_knowledge.md` | Standard | **DRAFT** |
| `0x0013` Spatial | `../channels/0013_spatial.md` | High (interface stub) | **DRAFT** |

## Code points consumed (all reserved by the core specification)

| Resource | Core-spec reservation | Companion use |
|---|---|---|
| Channel `0x000D` (Bridge) | "Encapsulation of external agent protocols" (§5) | NPAMP-BRIDGE frame types (from `0x0100`). |
| Channel `0x0010` (Discovery) | "Agent, tool, and service discovery" (§5) | NPAMP-DISC frame types (from `0x0100`). |
| TLV `0x0010` | "Reserved for a companion specification" (§9.4) | NPAMP-BRIDGE: BridgeEnvelope TLV (includes `protocol_id`). |
| TLV `0x0013` | "Reserved for a companion specification" (§9.4) | NPAMP-BRIDGE: SafetyLabel TLV. |

## Channel selection for carriage

NPAMP-BRIDGE encapsulation rides the Bridge channel `0x000D`, which the core
specification reserves for "encapsulation of external agent protocols." Where a class of
foreign traffic corresponds to a core channel's purpose, a deployment MAY carry that
traffic on the more specific core channel instead of, or in addition to, the Bridge
channel:

| Foreign traffic class | Core channel | Core-spec purpose |
|---|---|---|
| Capability / discovery documents (agent cards, tool catalogs, schemas) | `0x0010` Discovery | "Agent, tool, and service discovery and capability advertisement" |
| Agent-to-human interaction and user-interface events | `0x000F` Interaction | "Agent-to-human user-interface events" |
| Payment mandates and multi-party agentic commerce | `0x000E` Commerce | "Multi-party agentic commerce and payment mandates" |
| Full-duplex streaming (tokens, audio, video, file transfer) | `0x000C` Stream | "Multiplexed full-duplex streaming" |
| Identity assertion and attestation | `0x0003` Identity | "Identity resolution, attestation, presence" |

The Bridge channel `0x000D` remains the general default for protocol encapsulation; a
mapping document specifies which channel or channels a given protocol's traffic uses.

## How a developer carries a protocol over N-PAMP

1. Read the **core specification** (`../ietf/draft-bubblefish-npamp-latest.md`) — the secure
   post-quantum wire.
2. Read **NPAMP-BRIDGE** — the universal envelope/correlation/error/safety contract.
3. Pick the **carriage class** for the protocol family (or **Class OPAQUE** to carry it
   immediately with no mapping).
4. If a native mapping exists, read it; otherwise use Class OPAQUE now and contribute a
   mapping when richer interop is wanted.
5. Register the `protocol_id` (NPAMP-REG) and, for discoverable deployments, advertise it
   over **NPAMP-DISC**.

The result: an agent speaking any protocol — MCP, A2A, a message-passing ACL, a custom
in-house format, or one published next year — rides inside N-PAMP frames and gains the
authentication, post-quantum protection, multiplexing, and provenance of the substrate,
without N-PAMP needing prior knowledge of that protocol.
