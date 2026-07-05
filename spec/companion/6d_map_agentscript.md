# NPAMP-MAP-AGENTSCRIPT — AgentScript Agent-Definition Mapping (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document defines the carriage of **AgentScript** — an open,
> schema-driven, single-file language for defining conversational agents (the
> `.agent` agent-definition document) — over an N-PAMP association. It is a **thin
> mapping** over the capability/schema-document carriage class **NPAMP-CC-DOC**
> (`24_carriage_documents.md`): the carriage class does the structural work —
> octet-exact document delivery, digest stability, detached-proof binding, and the
> document-set correlation — and this document pins only what is specific to
> AgentScript. It builds on NPAMP-CC-DOC, on NPAMP-BRIDGE (`10_bridge_framework.md`),
> and on the N-PAMP core specification (draft-bubblefish-npamp-01, the "core
> specification"). It consumes only code points those documents already reserve and
> introduces no change to the core wire format, to NPAMP-BRIDGE, or to NPAMP-CC-DOC.

## 1. Scope

### 1.1 In scope

AgentScript is a **static agent-definition document**, not a network protocol: it has
no wire format, no transport binding, no serving endpoint, and no request/response or
RPC method of its own (§8). It describes *what* an agent is — its state, its available
actions, and its instructions — not *how* a runtime executes it. Consequently the only
thing a peer needs in order to interoperate is a way to **deliver, advertise, and
verify** the `.agent` document, which is exactly what NPAMP-CC-DOC provides. This
document pins, and only pins, the AgentScript-specific facts a peer needs to carry the
`.agent` document under NPAMP-CC-DOC:

- The `protocol_id` for AgentScript and its carriage class (§2), noting its
  **provisional** status (§2, §8);
- How an AgentScript `.agent` document is carried as an NPAMP-CC-DOC **document set** —
  its `doc_id`, its declared media type, octet-exactness, and its OPTIONAL signatures as
  detached proofs (§4);
- The retrieval (pull), unsolicited-advertisement (push), and Discovery-record patterns
  a peer uses to move an AgentScript document (§5);
- The SafetyLabel treatment for serving an AgentScript document — `read_only` — and the
  NPAMP-BRIDGE §7 fail-safe for any deployment in which retrieving one is itself
  state-mutating (§6); and
- Channel selection: the Bridge channel `0x000D` as the default, and the Discovery
  channel `0x0010` for advertisement (§7).

### 1.2 Not in scope

The following are explicitly NOT defined by this document, because NPAMP-CC-DOC,
NPAMP-BRIDGE, or AgentScript's own specification already define them (or because
AgentScript does not define them at all):

- **The internal grammar of the `.agent` format.** AgentScript's block types
  (`system`, `config`, `variables`, `start_agent`, `subagent`, `connected_subagent`,
  `actions`, and the reasoning-loop blocks), its operators, and its type system are
  fixed by AgentScript's own specification (§10). This document carries a `.agent`
  document octet-for-octet (NPAMP-CC-DOC §4) and does not parse, validate, compile,
  execute, or re-serialize it.
- **The structural document carriage** — octet preservation, digest stability, the
  DocumentBinding descriptor, detached-proof binding, streaming of a large document, and
  the document-set error model. These are inherited verbatim from NPAMP-CC-DOC (§4–§8 of
  that document) and are not restated here (§3).
- **Any AgentScript RPC, wire, or serving protocol.** AgentScript defines none (§8); this
  mapping neither invents one nor carries one. Invoking or executing the agent an
  `.agent` document defines is a separate concern carried, where applicable, by a
  different protocol mapping (for example MCP or A2A) under its own `protocol_id`.
- **A registered media type for `.agent`.** AgentScript's specification declares no IANA
  media type (§8); this document carries the producer-declared media type in the
  DocumentBinding `doc_content_type` field and does not mint or register one (§4.2, §8).
- **Any change to the N-PAMP frame format, the NPAMP-BRIDGE frame types, the
  BridgeEnvelope, the SafetyLabel TLV, or the NPAMP-CC-DOC DocumentBinding TLV.**

## 2. Protocol identity

| Property | Value |
|---|---|
| Protocol | AgentScript — an open, schema-driven, single-file language for defining conversational agents (the `.agent` agent-definition document). |
| `protocol_id` | **PROVISIONAL.** No standards-assigned code point exists: NPAMP-REG §6 assigns only `0x01`–`0x04`, and AgentScript is listed OPAQUE-READY / mapping-planned in the companion index, not assigned. Until a code point is assigned under NPAMP-REG §8 (Specification Required, range `0x05`–`0x0F`), this mapping uses the **experimental** value `0x3E` (range `0x10`–`0x7F`; NPAMP-REG §7.1), which carries **no cross-domain meaning** and MUST be agreed out-of-band (§8). |
| Carriage class | DOC (NPAMP-CC-DOC). |
| Document media type | Carried in the DocumentBinding `doc_content_type` field (NPAMP-CC-DOC §6.2) as a UTF-8 string. AgentScript registers no IANA media type; the value is deployment-declared and **UNCONFIRMED** as a registered type (§8). |
| BridgeEnvelope `content_type` | The one-octet enumerated set (NPAMP-BRIDGE §4: `0x01` application/json, `0x02` application/cbor, `0x03` application/grpc+proto) has **no value** for an opaque custom-text document such as `.agent`; a sender MUST NOT misdeclare a `.agent` document as `application/json` (`0x01`). See §8 (OPEN). The authoritative media type is `doc_content_type`, not this octet. |
| Foreign-message form | The exact octets of one `.agent` document (or one detached proof over it), carried as the NPAMP-CC-DOC foreign message octet-for-octet (NPAMP-BRIDGE §1; NPAMP-CC-DOC §4). |

Because `0x3E` is an experimental code point, a sender MUST NOT emit AgentScript traffic
under it toward a peer with which it has no out-of-band agreement on that value's meaning,
and a receiver with no such agreement MUST treat it as an uncarried protocol and reply
`ProtocolUnsupported` (NPAMP-REG §7.1, §9). An implementation MUST NOT ship a production
default that relies on `0x3E`; when AgentScript is ready for general interoperation, a
standards code point SHOULD be obtained under NPAMP-REG §8 and the experimental value
retired (NPAMP-REG §7.1). A receiver selects AgentScript solely from `protocol_id` and MUST
NOT infer it from any other envelope field (NPAMP-REG §9).

## 3. Relationship to NPAMP-CC-DOC and NPAMP-BRIDGE

An AgentScript `.agent` file is a self-contained capability/definition document, which is
precisely the artifact family NPAMP-CC-DOC serves. The entire structural carriage is
therefore provided by NPAMP-CC-DOC without modification:

- The **transparency rule** governs absolutely: a `.agent` document is carried
  octet-for-octet and MUST NOT be canonicalized, re-indented, re-encoded, reordered,
  transcoded, document-layer-compressed, pretty-printed, minified, Unicode-normalized,
  line-ending-altered, or BOM-stripped/added (NPAMP-BRIDGE §1; NPAMP-CC-DOC §4). Because
  AgentScript is an indentation-sensitive custom syntax, octet exactness is not merely a
  proof requirement but a semantic one: whitespace is significant to the format.
- **Digest stability** and **detached-proof binding** — the recomputed digest over the
  recovered document octets, the constant-time comparison, and the `correlation_id` /
  `doc_id` / digest-triple binding of a proof to its document — are inherited from
  NPAMP-CC-DOC §5 and §6 unchanged. This document adds no digest, binding, or
  verification rule.
- The **document-set correlation, ordering, streaming, and error model** are those of
  NPAMP-CC-DOC §7 and §8; the errors `BindingMalformed`, `DigestMismatch`,
  `DigestUnstable`, `ProofUnbound`, `ProofUnsupported`, and `SetIncomplete` apply
  unchanged.

This document therefore pins only AgentScript specifics (§2, §4, §5, §6, §7). Where this
document and NPAMP-CC-DOC could appear to differ on a structural matter, NPAMP-CC-DOC
governs.

## 4. The AgentScript document as an NPAMP-CC-DOC document set

An AgentScript document is carried as an NPAMP-CC-DOC **document set** (NPAMP-CC-DOC §2,
§6, §7): one **document part** bearing the `.agent` octets, plus zero or more **detached
proof parts** over it, all sharing one `correlation_id`.

### 4.1 Document part

- The document part is a single NPAMP-CC-DOC document part (`part_kind = 0x01`) whose
  foreign message is the exact octets of one `.agent` document (NPAMP-CC-DOC §6.2).
- Its DocumentBinding `doc_id` (NPAMP-CC-DOC §6.2) is a producer-assigned, stable
  identifier for that `.agent` document, identical across the document part and every
  proof part of the set, and independent of `correlation_id`.
- The DocumentBinding `digest_alg`/`digest` are computed over the exact `.agent` octets
  placed on the wire (NPAMP-CC-DOC §5). A `.agent` document too large for one frame MUST
  be streamed per NPAMP-CC-DOC §7.4, with the digest computed over the reassembly.

### 4.2 Declared media type

- The producer MUST place the `.agent` document's media type in the DocumentBinding
  `doc_content_type` field (NPAMP-CC-DOC §6.2). Because AgentScript registers no IANA
  media type (§8), that value is a deployment-declared string agreed between the peers,
  not a registered type; a consumer MUST NOT assume any particular value and MUST rely on
  the value the producer declares.
- The `.agent` format is **not** JSON, CBOR, or gRPC/proto; a sender MUST NOT declare the
  BridgeEnvelope one-octet `content_type` as `0x01` (application/json) or any other value
  that misrepresents the document's encoding (§2, §8).

### 4.3 Signatures as detached proofs

Where an AgentScript document is signed, each signature is carried as a **detached proof
part** (`part_kind = 0x02`) bound to the document by `correlation_id`, `doc_id`, and the
digest triple (NPAMP-CC-DOC §6.3), with `proof_alg` naming a signature whose code point the
core specification already assigns (NPAMP-CC-DOC §6.4). Verification is the **consumer's**
act (NPAMP-CC-DOC §6.5): the carriage delivers the document and its proofs with the
integrity guarantees a verifier needs and does not itself decide trust. A producer MUST NOT
represent the carriage layer's delivery of a proof as verification of it.

## 5. Retrieval and advertisement patterns

AgentScript defines no operation namespace of its own (§8). The only carriage operations
are the NPAMP-CC-DOC document-movement patterns:

- **Pull (a consumer requests an `.agent` document).** A consumer MAY request an
  AgentScript document set with a `BRIDGE_REQUEST` (`0x0100`) whose BridgeEnvelope `method`
  names a deployment-chosen document-retrieval operation (NPAMP-CC-DOC §7.1). This mapping
  fixes **no** canonical retrieval method string, because AgentScript defines none; the
  producer replies with the document part and any proof parts as `BRIDGE_RESPONSE`
  (`0x0101`) frames — or `BRIDGE_STREAM_DATA`/`BRIDGE_STREAM_END` for a large document —
  all echoing the request's `correlation_id`. A soliciting `BRIDGE_REQUEST` carries no
  document part and MUST NOT carry a DocumentBinding TLV (NPAMP-CC-DOC §6.1, §7.1).
- **Push (a producer advertises an `.agent` document unsolicited).** A single `.agent`
  document with no detached proofs MAY be pushed as one `BRIDGE_NOTIFY` (`0x0103`) with
  `corr_len = 0` and `proof_count = 0` (NPAMP-CC-DOC §7.2). A document set that has
  detached proofs, or a document large enough to require streaming, MUST be carried under
  a shared `correlation_id` per NPAMP-CC-DOC §7.2, not as multiple bare notifications.
- **Discovery record (advertising that a peer carries AgentScript).** A peer MAY advertise,
  over NPAMP-DISC on the Discovery channel `0x0010`, a protocol Discovery Record
  (`kind = 1`) whose `protocol_id` is AgentScript's (`0x3E` provisional; §2) and whose
  `carriage_class` is DOC (NPAMP-DISC §5.1). This announces that the peer serves
  AgentScript documents; it does not itself carry one. A peer MUST NOT advertise
  AgentScript if it cannot in fact carry that `protocol_id` over the association
  (NPAMP-DISC §5.1, §11).

A consumer MUST assemble a document set by `correlation_id` and `doc_id`, MUST NOT present
it until it is complete and its digest has been recomputed and matched (NPAMP-CC-DOC §5,
§7.3, §7.5), and MUST NOT present a partial or unverified `.agent` document as a complete
advertisement.

## 6. SafetyLabel and state effects

AgentScript has **no state-mutating operations**: it is a definition document, and this
mapping carries only its delivery and advertisement. Serving an AgentScript document is
therefore `read_only` under the NPAMP-BRIDGE SafetyLabel model (NPAMP-BRIDGE §7;
NPAMP-CC-DOC §9).

- A producer serving an AgentScript document set in response to a request SHOULD attach a
  SafetyLabel TLV (Type `0x0013`) with `effect = 0x00` read_only to the document part
  (NPAMP-CC-DOC §9).
- Where a particular deployment makes the *act of requesting* an AgentScript document
  itself state-mutating — for example a request that causes the producer to **generate,
  register, or sign a fresh** `.agent` document on demand — the requester MUST attach a
  SafetyLabel to the `BRIDGE_REQUEST` describing that effect, and the fail-safe of
  NPAMP-BRIDGE §7 applies: absence of a SafetyLabel on such a state-mutating request MUST
  be treated as `destructive`, never as `read_only` (NPAMP-CC-DOC §9).
- The SafetyLabel describes intent and does not replace authorization, and it does not
  replace the document's own detached proofs, which carry the document's authenticity
  independently of any transport-level annotation (NPAMP-CC-DOC §6.5, §9). A receiver MUST
  enforce its own authorization and MUST NOT treat a favorable SafetyLabel as permission.

## 7. Channel selection

An AgentScript document set rides **NPAMP-CC-DOC on the Bridge channel `0x000D`** by
default (NPAMP-CC-DOC §1.1, §3). Because an `.agent` document is a capability/definition
artifact, it MAY instead, or in addition, be carried on the **Discovery channel `0x0010`**,
whose core-specified purpose is "Agent, tool, and service discovery and capability
advertisement" (NPAMP-CC-DOC §1.1, §3; §5 above). A document and its detached proofs MUST
NOT be split across the Bridge and Discovery channels; a consumer MUST treat frames bearing
the same `correlation_id` on two different channels as unrelated (NPAMP-CC-DOC §3).

| AgentScript traffic class | Carriage | Channel |
|---|---|---|
| `.agent` document set (document + detached proofs) | NPAMP-CC-DOC | Bridge `0x000D` default; MAY use Discovery `0x0010` |
| Advertisement that the peer carries AgentScript (protocol Discovery Record, `kind = 1`) | NPAMP-DISC | Discovery `0x0010` |

The Bridge channel `0x000D` and the Discovery channel `0x0010` are both minimum-profile
**Standard** (core-specification channel registry; `../../registries/channels.csv`);
AgentScript carriage requires no channel above the Standard profile. A peer MUST NOT send or
accept AgentScript frames on a channel it did not advertise during the handshake (core
specification §5).

## 8. Confirmed facts, provisional values, and marked uncertainties

Per the anti-shortcut-research discipline, this section separates what is confirmed against
AgentScript's own current published sources (§10) from what is provisional or unconfirmed.

**Which AgentScript.** This mapping targets **Salesforce AgentScript** — "an open,
schema-driven language for configuring agent orchestration systems" (§10). It is **not**
the same-named **agent-based-modeling** JavaScript library (agentscript.org; Owen Densmore /
RedfishGroup; NetLogo-style turtles/patches/links; GPLv3), which is unrelated to agent
definition; it is **not** the **AgentScript-AI CodeAct Agent SDK**
(github.com/AgentScript-AI/agentscript), which is a runtime/SDK rather than a document
format; and it is distinct from **AgentSpec / the Open Agent Specification**, which is a
separate entry with its own mapping (`6c_map_agentspec.md`).

**Confirmed (from the primary sources in §10, this authoring session):**

1. AgentScript is a single-file, declarative, schema-driven **agent-definition document**;
   its format is a **custom, indentation-sensitive syntax** (not JSON, YAML, CBOR, or
   gRPC/proto), with top-level blocks `system`, `config`, `variables`, `start_agent`,
   `subagent`, `connected_subagent`, and `actions`.
2. AgentScript defines **no network protocol, transport binding, serving endpoint, or RPC
   method**; it "describes what the agent is … not how the runtime executes it" and is
   compiled/executed by a runtime outside the language itself. This is why DOC is the
   correct and sufficient carriage class and why no method namespace is mapped (§1.1, §5).
3. AgentScript is open source under the **Apache 2.0** license, published by Salesforce.

**Provisional / unconfirmed (marked, not fabricated):**

1. **`protocol_id` is PROVISIONAL.** No standards code point is assigned to AgentScript
   (NPAMP-REG §6 assigns only `0x01`–`0x04`). This mapping uses the experimental value
   `0x3E` (§2), which requires out-of-band agreement and MUST be replaced by an assignment
   obtained under NPAMP-REG §8 before production interoperation.
2. **The document media type is UNCONFIRMED as a registered type.** AgentScript's
   specification declares no IANA media type, and — per the primary source — does not even
   formally fix the `.agent` file extension (the extension is a tooling/repository
   convention). The media type is therefore a **deployment-declared** `doc_content_type`
   string (§4.2), and the one-octet BridgeEnvelope `content_type` enumeration has **no
   value** for an opaque custom-text document — an **OPEN** item for the core specification
   / NPAMP-BRIDGE, not resolved here (§2).
3. **AgentScript is a versioned, evolving language** (open-sourced by Salesforce in 2026;
   the specification is the base dialect for dialect-specific extensions). Its block set may
   change across releases. Because NPAMP-CC-DOC carries the document **octet-exact and
   opaque to its internal grammar** (§3, §4), a newer or older AgentScript revision is
   carried without any change to this mapping; only §8's summary of the block model tracks
   the specific revision consulted in §10.

No value in this document is asserted beyond what §10's sources support; where a fact was
version-dependent or not confirmable from the primary source, it is marked above rather than
fixed by assumption.

## 9. Code points consumed

This mapping consumes only code points that the core specification, NPAMP-BRIDGE, and
NPAMP-CC-DOC already define, plus one **provisional experimental** `protocol_id`. It defines
no new frame type, no new TLV, and no change to the core wire format.

| Resource | Origin | Use here |
|---|---|---|
| `protocol_id` `0x3E` (AgentScript, **provisional/experimental**) | NPAMP-REG §7.1 (experimental range `0x10`–`0x7F`) | The AgentScript identifier on every AgentScript Bridge/Discovery frame (§2). Not a standards assignment; retire on a §8 assignment. |
| Channel `0x000D` (Bridge) | Core specification | Default channel for AgentScript document carriage (§7). |
| Channel `0x0010` (Discovery) | Core specification | Optional channel for AgentScript document advertisement (§5, §7). |
| Bridge frame types `0x0100`–`0x0105` | NPAMP-BRIDGE §2 | Reused unchanged for document/proof request, response, notification, and streaming (§4, §5). |
| BridgeEnvelope TLV `0x0010`, SafetyLabel TLV `0x0013` | Core specification; NPAMP-BRIDGE | Carried unchanged (§2, §6). |
| DocumentBinding TLV (NPAMP-CC-DOC §6, Type `0xTBD-DOCBIND` **provisional**) | NPAMP-CC-DOC | Document-binding metadata for the `.agent` document and its proofs (§4). Its provisional status is inherited from NPAMP-CC-DOC and not resolved here. |

This document requests no IANA action and defines no registry.

## 10. References

Normative for the carriage:

- draft-bubblefish-npamp-01 — the N-PAMP core specification (Bridge channel `0x000D`,
  Discovery channel `0x0010`, the frame format, the BridgeEnvelope and SafetyLabel TLV
  reservations, and AEAD payload protection).
- NPAMP-BRIDGE (`10_bridge_framework.md`) — the encapsulation, correlation, error, and
  SafetyLabel contract.
- NPAMP-CC-DOC (`24_carriage_documents.md`) — the capability/schema-document carriage class
  that does the structural work for AgentScript.
- NPAMP-REG (`30_protocol_registry.md`) — the Bridge Protocol Identifier registry; the
  provisional experimental range (§7.1) and the Specification-Required assignment procedure
  (§8) referenced for AgentScript's `protocol_id` (§2, §8).
- NPAMP-DISC (`40_discovery.md`) — the Discovery-channel advertisement referenced in §5, §7.
- BCP 14: RFC 2119 and RFC 8174 — requirement key words.

AgentScript source specification (primary sources consulted for §1, §4, §8; **Salesforce
AgentScript**, the schema-driven agent-definition language):

- AgentScript repository (tagline "An open, schema-driven language for configuring agent
  orchestration systems"; Apache 2.0; `.agent` tooling) —
  <https://github.com/salesforce/agentscript>
- AgentScript formal specification `SPEC.md` (the base grammar and block types `system`,
  `config`, `variables`, `start_agent`, `subagent`, `connected_subagent`, `actions`;
  custom indentation-sensitive syntax; no transport or RPC) —
  <https://github.com/salesforce/agentscript/blob/main/SPEC.md>
- Agent Script — Agentforce Developer Guide (Salesforce), the second independent primary
  rendering (a static definition language compiled/executed by the Agentforce runtime, with
  no network protocol or media type) —
  <https://developer.salesforce.com/docs/ai/agentforce/guide/agent-script.html>
- AgentScript — Open Agent Specification Language (project site) —
  <https://agentforce.guide/>

Distinguished from (not the subject of this mapping):

- AgentScript agent-based-modeling library (Owen Densmore / RedfishGroup; NetLogo-style ABM;
  GPLv3) — <https://agentscript.org/> and <https://github.com/backspaces/agentscript>.
- AgentScript-AI CodeAct Agent SDK (a runtime/SDK, not a document format) —
  <https://github.com/AgentScript-AI/agentscript>.

## 11. Security considerations

This mapping introduces no cryptography and changes none. All confidentiality, integrity,
authentication, downgrade resistance, and replay protection are provided by the core
specification's wire format and key schedule and apply unchanged to every AgentScript frame,
which travels inside the AEAD-protected Bridge (or Discovery) payload; the `protocol_id`, the
DocumentBinding metadata, the SafetyLabel, and the `.agent` octets are authenticated and
confidentiality-protected to the same degree.

Carrying AgentScript over N-PAMP makes no security claim about AgentScript itself. In
particular:

- **Document authenticity is the document's, not the carriage's.** An `.agent` document's own
  signatures (§4.3), verified by the consumer under NPAMP-CC-DOC, carry the document's
  authenticity independently of the transport; carriage delivery of a proof is not
  verification of it (NPAMP-CC-DOC §6.5). A consumer MUST recompute the document digest and
  SHOULD verify each detached proof before relying on a document, and MUST NOT execute or
  trust an unverified `.agent` document as if it were verified.
- **Experimental identifier.** Because AgentScript's `protocol_id` is a provisional
  experimental value (§2), a receiver MUST treat it as uncarried absent out-of-band
  agreement (NPAMP-REG §7.1, §9, §10), rather than guessing an interpretation.
- **Discovery is a claim, not authorization.** Advertising that a peer carries AgentScript
  (§5) is a claim by the advertising peer under the association's authentication; it is not
  authorization to obtain or act on any particular `.agent` document (NPAMP-DISC §10). The
  NPAMP-BRIDGE §7 fail-safe (absence of a SafetyLabel on a state-mutating request is
  `destructive`) applies to any deployment that makes document retrieval state-mutating (§6).

## 12. Conformance

An implementation conforms to NPAMP-MAP-AGENTSCRIPT if and only if it conforms to
NPAMP-CC-DOC (and therefore to NPAMP-BRIDGE) and, for AgentScript traffic, it:

1. Carries every AgentScript `.agent` document as an NPAMP-CC-DOC document set under the
   AgentScript `protocol_id`, selecting AgentScript solely from `protocol_id`; treats that
   `protocol_id` as the **provisional experimental** value `0x3E` requiring out-of-band
   agreement, never ships it as a production default, and treats it as uncarried
   (`ProtocolUnsupported`) toward a peer with no such agreement (§2; NPAMP-REG §7.1, §9);
2. Delivers each `.agent` document and each detached proof **octet-for-octet**, performing no
   canonicalization, re-indentation, transcoding, re-serialization, or document-layer
   compression, and refuses with `DigestUnstable` any document set whose octet preservation
   it cannot guarantee (§3, §4; NPAMP-CC-DOC §4);
3. Carries the document's media type in the DocumentBinding `doc_content_type` field as a
   deployment-declared value, and does not misdeclare a `.agent` document's BridgeEnvelope
   one-octet `content_type` as `application/json` or any other value that misrepresents its
   encoding (§2, §4.2);
4. Recomputes and constant-time-compares the document digest over the exact recovered octets,
   binds each detached proof to its document by `correlation_id`, `doc_id`, and digest triple,
   leaves proof verification to the consumer, and never presents an incomplete or
   digest-mismatched `.agent` document as a verified advertisement (§4; NPAMP-CC-DOC §5, §6,
   §7);
5. Maps no AgentScript operation namespace (AgentScript defines none), carrying only the
   NPAMP-CC-DOC pull, push, and Discovery-record patterns of §5, and fixing no canonical
   retrieval method string (§5);
6. Treats serving an AgentScript document as `read_only`, and treats a missing SafetyLabel on
   any deployment-specific state-mutating retrieval as `destructive` (NPAMP-BRIDGE §7
   fail-safe), never treating a favorable SafetyLabel as authorization (§6);
7. Carries an `.agent` document set on the Bridge channel `0x000D` by default or the Discovery
   channel `0x0010`, never splitting a document and its proofs across the two channels, and
   sends or accepts AgentScript frames only on channels advertised during the handshake (§7);
   and
8. Defines no new frame type, TLV, or standards code point, consuming only those enumerated in
   §9, and inherits the provisional status of the AgentScript `protocol_id` and the
   DocumentBinding TLV without resolving it here (§9).

A conformance test suite SHOULD assert each clause above with recorded exchanges that include:
A single-frame `.agent` document pushed as a `BRIDGE_NOTIFY` with `proof_count = 0`; a pulled
`.agent` document set with one detached signature proof carried under NPAMP-CC-DOC on both the
Bridge and the Discovery channel; a streamed multi-frame `.agent` document whose digest is
computed over the reassembly; a deliberately altered `.agent` octet that MUST produce
`DigestMismatch`; a protocol Discovery Record (`kind = 1`) advertising AgentScript over
NPAMP-DISC; and a frame bearing the provisional `protocol_id` `0x3E` toward a peer with no
out-of-band agreement, verified to be answered `ProtocolUnsupported`.
