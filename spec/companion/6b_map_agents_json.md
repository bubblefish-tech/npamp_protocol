# NPAMP-MAP-AGENTS-JSON — agents.json Discovery-Document Mapping (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is a **thin per-protocol mapping**: it pins the specifics of
> the **agents.json** discovery-document schema (the Wildcard agents.json
> specification, agentsjson.org) onto N-PAMP carriage. agents.json is a static
> **capability/discovery document**, not a request/response wire protocol; it is
> therefore carried under the document carriage class **NPAMP-CC-DOC**
> (`24_carriage_documents.md`) — the class does the structural work (octet-exact
> carriage, document-binding, digest stability, detached proofs, correlation), and
> this document pins only what is specific to agents.json. It builds on NPAMP-CC-DOC,
> on **NPAMP-BRIDGE** (`10_bridge_framework.md`), and on the N-PAMP core specification
> (draft-bubblefish-npamp-01, the "core specification"). It consumes only code points
> those documents already reserve and introduces no change to the core wire format,
> to NPAMP-BRIDGE, or to NPAMP-CC-DOC.
>
> **Provisional status.** agents.json has **no assigned Bridge Protocol Identifier**
> in NPAMP-REG (`30_protocol_registry.md` §6 assigns only `0x01`–`0x04`). This mapping
> is therefore **PROVISIONAL** on its `protocol_id` (§2): its structural carriage over
> NPAMP-CC-DOC is fully specified, but the code point it rides is not yet
> standards-assigned. Until NPAMP-REG assigns one (§2, §8 of that document), agents.json
> is carriable today either under an experimental `protocol_id` by out-of-band agreement
> or under Class OPAQUE (§2). agents.json's base carriage — a static JSON document served
> at a well-known path — **is confirmed** against the primary source (§8, §10); only the
> code-point assignment is provisional.

## 1. Scope

### 1.1 In scope

This document specifies how an **agents.json** document is carried, discovered, and
verified over an N-PAMP association. It pins, against agents.json's own published
specification (§10), only the agents.json specifics that NPAMP-CC-DOC leaves to a
per-protocol mapping:

- The agents.json **`protocol_id`** and its PROVISIONAL status, its carriage class, and
  the foreign-message `content_type` (§2);
- How the agents.json document rides NPAMP-CC-DOC as a **document set**, and the single
  document-retrieval operation this mapping defines for the NPAMP-CC-DOC pull pattern (§4);
- The **document-binding** specifics for agents.json — its media type, the referenced
  OpenAPI **source** documents, and the fact that agents.json v0.1.0 defines **no native
  signature**, so a document set carries zero detached proofs unless a deployment adds
  them out of band (§5);
- The **SafetyLabel effect class** for serving and requesting an agents.json document, and
  the explicit statement that the effect classes of the API operations a flow *describes*
  are **not** expressed by this mapping because those calls are not carried here (§6); and
- **Channel selection**: the Bridge channel `0x000D` default and the Discovery channel
  `0x0010` for which agents.json — being a discovery document — is a natural fit (§7).

The structural work — octet-exact carriage, the BridgeEnvelope, the DocumentBinding
descriptor, digest stability, detached-proof binding, correlation, and the
structured-error model — is done by NPAMP-CC-DOC and NPAMP-BRIDGE and is not restated here.

### 1.2 Not in scope

The following are explicitly NOT defined by this document:

- **Execution of the flows an agents.json document describes.** agents.json is a
  declarative manifest: its `flows` describe sequences of API calls (`actions`) that the
  **calling agent** performs, statelessly, against the **target API's own endpoints**
  (described by the OpenAPI documents its `sources` reference; §5). Those API calls are
  the target API's traffic, not agents.json traffic; they are carried, if at all, under
  their own protocol's mapping (for example NPAMP-CC-HTTP or Class OPAQUE) and are out of
  scope here. This mapping carries the **agents.json document itself**, not the work it
  describes.
- **The internal grammar of agents.json.** The schema of `agentsJson`, `info`, `sources`,
  `flows`, `actions`, `links`, `fields`, and `overrides` is fixed by the agents.json
  specification (§10). This document carries the agents.json octets verbatim
  (NPAMP-CC-DOC §4) and does not parse, validate, canonicalize, or transform them.
- **The internal grammar of the referenced OpenAPI documents.** A `source`'s `path` names
  an OpenAPI 3+ specification; carrying such an OpenAPI document as its own DOC document
  set is OPTIONAL (§5) and, when done, treats the OpenAPI document opaquely.
- **agents.json's HTTP serving binding.** agents.json is natively served by an HTTP GET at
  `/.well-known/agents.json` (§10). Over N-PAMP the HTTP framing is subsumed by the N-PAMP
  transport; the agents.json **document octets** are the sole foreign message, and no HTTP
  request line, header, or status line is carried as part of it (§8).
- **Any change** to NPAMP-BRIDGE, to NPAMP-CC-DOC, to the BridgeEnvelope, SafetyLabel, or
  DocumentBinding TLVs, or to the core wire format.

## 2. Protocol identity

| Property | Value |
|---|---|
| Protocol | agents.json — the Wildcard agents.json discovery-document specification (agentsjson.org). |
| `protocol_id` | **PROVISIONAL.** No standards code point is assigned by NPAMP-REG §6. An experimental value in the range `0x10`–`0x7F` (NPAMP-REG §7.1), fixed by out-of-band agreement for the association, or a private-use value in `0x80`–`0xFF` within one administrative domain (NPAMP-REG §7.2). A standards-assigned value in `0x05`–`0x0F` SHOULD be obtained under NPAMP-REG §8 before general interoperation, after which this row is updated. |
| Carriage class | DOC (NPAMP-CC-DOC). |
| `content_type` | `0x01` (application/json), matching agents.json's JSON serialization (§10). |
| Foreign-message form | The agents.json document, carried octet-for-octet as the document part of an NPAMP-CC-DOC document set (NPAMP-CC-DOC §1, §4). |

Because no standards `protocol_id` is assigned, a sender:

- MUST NOT emit an experimental or private-use `protocol_id` for agents.json toward a peer
  outside the administrative domain (or the out-of-band agreement) that fixes that value's
  meaning (NPAMP-REG §7.1, §7.2);
- SHOULD, where cross-domain interoperation is wanted before a standards code point exists,
  carry agents.json under **Class OPAQUE** (NPAMP-CC-OPAQUE) with `content_type = 0x01`,
  which requires no protocol-specific mapping and is the RECOMMENDED carriage for a
  private-use or as-yet-unregistered `protocol_id` (NPAMP-REG §7.2); and
- Once NPAMP-REG assigns a standards `protocol_id`, MUST use that value and MUST NOT
  continue to emit an experimental value as a production default (NPAMP-REG §7.1).

A receiver that does not carry the agreed agents.json `protocol_id` MUST treat a
BRIDGE_REQUEST bearing it as an uncarried protocol and reply `ProtocolUnsupported`
(NPAMP-BRIDGE §6 code 2; NPAMP-REG §9), and MUST NOT infer agents.json from any other
envelope field.

## 3. Relationship to NPAMP-CC-DOC and NPAMP-BRIDGE

agents.json is a self-contained capability/discovery document of exactly the family
NPAMP-CC-DOC serves (agent capability cards, tool and function catalogs, machine-readable
schemas; NPAMP-CC-DOC §1). Consequently the entire structural carriage of agents.json is
provided by NPAMP-CC-DOC without modification:

| Facility | Owning document | Use here |
|---|---|---|
| `protocol_id` (PROVISIONAL) | NPAMP-BRIDGE §4; NPAMP-REG | The identifier every agents.json Bridge frame carries (§2). |
| Document carriage — octet exactness, digest stability, DocumentBinding, detached-proof binding, streaming, assembly | NPAMP-CC-DOC §4–§7 | Carries the agents.json document set structurally (§4, §5). |
| BridgeEnvelope / SafetyLabel TLVs | Core specification; NPAMP-BRIDGE | Carried unchanged on every agents.json frame (§2, §6). |
| Correlation and structured-error model | NPAMP-BRIDGE §5, §6; NPAMP-CC-DOC §8 | Correlates a document set and reports failures (§4, §5). |

- The **transparency rule** governs: an agents.json document is carried octet-for-octet and
  MUST NOT be re-serialized, re-indented, canonicalized, minified, transcoded, or otherwise
  altered by a single octet, at the producer, the consumer, or any intermediary
  (NPAMP-BRIDGE §1; NPAMP-CC-DOC §4). This is what makes any digest or signature computed
  over the document verify bit-identically at the consumer (NPAMP-CC-DOC §5).
- **Correlation, assembly, streaming, and error reporting** are inherited from NPAMP-CC-DOC
  (§7, §8) and NPAMP-BRIDGE (§5, §6) unchanged; this document adds no correlation, assembly,
  or error rule.

Where this document and NPAMP-CC-DOC could appear to differ on a structural matter,
NPAMP-CC-DOC governs; this document pins only agents.json specifics (§2, §4, §5, §6, §7).

## 4. Operation namespace and frame mapping

agents.json defines **no request/response method namespace of its own**: it is a static
document, and the only N-PAMP operation is *retrieving that document*. This mapping
therefore defines the operation names used by the NPAMP-CC-DOC **pull** pattern
(NPAMP-CC-DOC §7.1); these names are defined by **this mapping**, not by agents.json, and
are carried in the BridgeEnvelope `method` field of the retrieval request.

| Operation | BridgeEnvelope `method` | Carriage | NPAMP-BRIDGE frame(s) |
|---|---|---|---|
| Retrieve the agents.json document | `agents-json/get` | NPAMP-CC-DOC (pull, §7.1) | BRIDGE_REQUEST → BRIDGE_RESPONSE (or BRIDGE_STREAM_DATA* + BRIDGE_STREAM_END for a large document) |
| Retrieve a referenced OpenAPI source document (OPTIONAL, §5) | `agents-json/source/get` | NPAMP-CC-DOC (pull, §7.1) | BRIDGE_REQUEST → BRIDGE_RESPONSE (or stream) |

Carriage requirements:

- **Pull.** A consumer requests the agents.json document with a `BRIDGE_REQUEST` (`0x0100`)
  whose `method` is `agents-json/get` and which carries a non-empty `correlation_id`
  (NPAMP-BRIDGE §5). The `BRIDGE_REQUEST` solicits a document set and therefore carries **no**
  document part and **no** DocumentBinding TLV (NPAMP-CC-DOC §7.1). The producer replies with
  the agents.json document as the document part — one `BRIDGE_RESPONSE` (`0x0101`), or, for a
  large document, an ordered `BRIDGE_STREAM_DATA` (`0x0104`) sequence terminated by
  `BRIDGE_STREAM_END` (`0x0105`) with the `final` bit set — echoing the request's
  `correlation_id` (NPAMP-CC-DOC §7.1, §7.4). Each document part carries a DocumentBinding TLV
  (§5; NPAMP-CC-DOC §6.1).
- **Push.** A producer MAY advertise an agents.json document unsolicited. A single-frame
  agents.json document with no detached proofs MAY be carried as one `BRIDGE_NOTIFY` (`0x0103`)
  with `corr_len = 0` and `proof_count = 0` (NPAMP-CC-DOC §7.2). A document that carries
  detached proofs, or that must be streamed, MUST be carried under a `correlation_id` per
  NPAMP-CC-DOC §7.2 (a producer-originated `BRIDGE_REQUEST` opening the correlation).
- **`method` selection is advisory routing.** A receiver selects the foreign protocol solely
  by `protocol_id` (NPAMP-REG §9); the `method` string names the requested document family and
  does not change the octet-exact carriage of the returned document.
- A receiver that carries agents.json but not a requested retrieval operation MUST report
  `MethodUnsupported` (NPAMP-BRIDGE §6 code 3) and MUST NOT report success for a document set
  it did not deliver (NPAMP-BRIDGE §6; NPAMP-CC-DOC §8).

## 5. Document-binding and detached proofs

The agents.json document is carried as the document part of an NPAMP-CC-DOC document set,
with a DocumentBinding descriptor (NPAMP-CC-DOC §6) supplying the binding metadata *around*
the untouched document octets. agents.json specifics:

- **`part_kind` / media type.** The agents.json document is a document part
  (`part_kind = 0x01`, NPAMP-CC-DOC §6.2). Its `doc_content_type` is a JSON media type
  (`application/json`, matching `content_type 0x01`; §2). A stable `doc_id` identifies the
  document set across all its parts (NPAMP-CC-DOC §6.2).
- **Digest.** The producer asserts a `digest` over the exact agents.json octets it places on
  the wire, and the consumer recomputes it over the recovered octets before treating any proof
  as applicable, rejecting a mismatch with `DigestMismatch` (NPAMP-CC-DOC §5, §8). The
  comparison is constant-time (NPAMP-CC-DOC §5).
- **No native signature.** The agents.json v0.1.0 schema defines **no** signature, digest, or
  cryptographic-proof field, and **no** authentication or security field (§10). A conforming
  agents.json document therefore carries **no in-band proof**, and an agents.json document set
  has `proof_count = 0` by default. Its authenticity, when unproven by a detached proof, rests
  on the N-PAMP association's own peer authentication (§9), not on any element of the document
  format.
- **Optional detached proofs.** Where a deployment wishes to bind an independently verifiable
  proof to an agents.json document, it MAY carry one or more **detached proofs**
  (`part_kind = 0x02`) in the same document set (NPAMP-CC-DOC §6). Such a proof is a deployment
  addition, **not** part of agents.json; its `proof_alg`, where the proof is a signature,
  draws from the core-assigned signature code points named by NPAMP-CC-DOC §6.4, and its
  binding to the document (by `correlation_id`, `doc_id`, and digest triple) and its
  verification (the consumer's act) follow NPAMP-CC-DOC §6.3 and §6.5 unchanged.
- **Referenced OpenAPI source documents.** Each `source` in an agents.json document names,
  by `id` and `path`, an OpenAPI 3+ specification (§10). This mapping does **not** inline or
  rewrite those OpenAPI documents into the agents.json octets. A producer MAY, as a separate
  and OPTIONAL convenience, serve a referenced OpenAPI document as its **own** NPAMP-CC-DOC
  document set (operation `agents-json/source/get`, §4) with its own `doc_id`, media type, and
  digest; a consumer MUST treat each such OpenAPI document as a distinct document set and MUST
  NOT assemble it into the agents.json document set (NPAMP-CC-DOC §3, §7.3).

## 6. SafetyLabel and effect classes

The SafetyLabel TLV (Type `0x0013`) and its fail-safe are governed by NPAMP-BRIDGE §7 and
inherited through NPAMP-CC-DOC §9 unchanged. For agents.json:

- **Serving a document is `read_only`.** Serving an agents.json document set, or a referenced
  OpenAPI source document set, is an advertisement and is `read_only` under the SafetyLabel
  model (NPAMP-CC-DOC §9). A producer serving such a document part SHOULD attach a SafetyLabel
  TLV with `effect = 0x00` read_only.
- **Retrieval is normally `read_only`, with the fail-safe.** A `agents-json/get` (or
  `agents-json/source/get`) `BRIDGE_REQUEST` is normally `read_only`. Where a deployment makes
  retrieval itself state-mutating — for example a request that causes the producer to generate,
  register, or sign a fresh agents.json document — the requester MUST attach a SafetyLabel
  describing that effect, and the fail-safe of NPAMP-BRIDGE §7 applies: **absence** of a
  SafetyLabel on a state-mutating retrieval MUST be treated as `0x03` destructive, never as
  `read_only` (NPAMP-CC-DOC §9).
- **The effect classes of described flows are NOT expressed here.** An agents.json `flow`
  describes `actions` — API calls that the calling agent performs against the target API — and
  some of those calls may create, update, or delete state at that API. This mapping carries the
  agents.json **document**, not those calls; it therefore assigns **no** SafetyLabel to the API
  operations a flow describes. When such a call is actually made over N-PAMP, it is carried
  under the target API's own protocol mapping, where its own SafetyLabel and the NPAMP-BRIDGE §7
  fail-safe govern. A reader MUST NOT infer that this mapping's `read_only` retrieval label
  characterizes the side effects of executing a flow.
- The SafetyLabel describes intent and does not replace authorization, and it does not replace
  a document's detached proofs (§5; NPAMP-CC-DOC §9).

## 7. Channel selection

| agents.json traffic class | Carriage | Channel |
|---|---|---|
| The agents.json document set (§4, §5) | NPAMP-CC-DOC | Bridge `0x000D` default; Discovery `0x0010` RECOMMENDED where advertised as discovery |
| A referenced OpenAPI source document set (OPTIONAL, §5) | NPAMP-CC-DOC | Bridge `0x000D` default; MAY use Discovery `0x0010` |
| Execution of a flow's API `actions` (§1.2) | Not carried by this mapping | Out of scope (target API's own protocol) |

- The agents.json document rides NPAMP-CC-DOC on the **Bridge channel `0x000D`** by default
  (NPAMP-CC-DOC §3). Because agents.json is by its nature a **discovery document**, a deployment
  that advertises it as part of agent, tool, and service discovery MAY instead, or in addition,
  carry it on the **Discovery channel `0x0010`**, whose core-specified purpose is "Agent, tool,
  and service discovery and capability advertisement" (NPAMP-CC-DOC §1.1, §3; companion index,
  "Channel selection for carriage"). Doing so is RECOMMENDED when the document is being offered
  for discovery rather than fetched inside an established Bridge exchange.
- A single agents.json document set — the document part and any detached proofs — MUST NOT be
  split across the Bridge and Discovery channels; a consumer MUST treat same-`correlation_id`
  frames on two channels as unrelated (NPAMP-CC-DOC §3).
- A peer MAY additionally **advertise** that it offers agents.json over NPAMP-DISC on the
  Discovery channel (a protocol Discovery Record, `kind = 1`, whose `protocol_id` is the value
  of §2 and whose `carriage_class` is DOC; NPAMP-DISC §5.1). Such an advertisement announces the
  capability; it does not itself carry the agents.json document. A peer MUST NOT advertise
  agents.json it cannot in fact carry over the association (NPAMP-DISC §5.1, §10).
- Both the Bridge channel `0x000D` and the Discovery channel `0x0010` are minimum-profile
  **Standard** (core specification channel registry); agents.json carriage requires no channel
  above the Standard profile. A peer MUST NOT send or accept agents.json frames on a channel it
  did not advertise during the handshake (core specification §5).

## 8. Transport-binding notes

agents.json is natively a static JSON file served by an HTTP GET at
`/.well-known/agents.json`, returning `Content-Type: application/json` (§10). Over N-PAMP,
**N-PAMP is the transport**: agents.json's HTTP serving binding does not apply, and there is
no HTTP request line, header, or status line at the N-PAMP layer. The agents.json **document
octets** are the sole foreign message (§2, §4); a peer MUST NOT carry any HTTP framing as part
of the document, and MUST NOT depend on the `/.well-known/agents.json` path for carriage — the
well-known path is a native-serving convention, while over N-PAMP the document is named by the
retrieval operation of §4 and identified by its `doc_id` (§5). The N-PAMP association supplies
authentication, post-quantum confidentiality and integrity, multiplexing, and the key schedule
(core specification); these replace, and are not layered on top of, agents.json's HTTP serving.

## 9. Security considerations

This mapping introduces no cryptography and changes none. All confidentiality, integrity,
authentication, downgrade resistance, and replay protection are provided by the core
specification's wire format and key schedule and apply unchanged to every agents.json frame,
which travels inside the AEAD-protected Bridge (or Discovery) payload; the `protocol_id`, the
`method`, the DocumentBinding descriptor, the SafetyLabel, and the agents.json document octets
are authenticated and confidentiality-protected to the same degree.

Carrying agents.json over N-PAMP makes no security claim about agents.json itself. In
particular:

- **No native document authenticity.** agents.json v0.1.0 defines no signature or other
  in-band proof of the document's origin or integrity (§5, §10). Over N-PAMP, a received
  agents.json document is known to have been sent by the **authenticated peer** (the core
  handshake binds both peer identities into the transcript), but that is authenticity of the
  *sender on this association*, not an independently verifiable proof of the document. A
  deployment that requires offline- or third-party-verifiable authenticity MUST supply it as a
  **detached proof** (§5; NPAMP-CC-DOC §6), which agents.json itself does not provide.
- **Discovery is a claim, not authorization.** Advertising or serving an agents.json document —
  and therefore the flows and target APIs it names — is a claim by the advertising peer, not a
  grant of permission (NPAMP-DISC §10). A consumer MUST NOT treat the presence of a flow or a
  referenced source as authorization to invoke the underlying API; the target API's own
  authorization governs each call, which this mapping does not carry (§1.2, §6).
- **Provisional identifier.** Until a standards `protocol_id` is assigned (§2), agents.json
  travels under an experimental or private-use identifier that carries no cross-domain meaning
  (NPAMP-REG §7, §10); a receiver MUST treat an identifier it has no agreement on as uncarried
  (NPAMP-REG §9) rather than guessing agents.json.

## 10. References and confirmed-vs-unconfirmed facts

Primary source (agents.json specification), consulted for §2, §4, §5, §8 (agents.json version
**0.1.0**, the latest published version at the time of writing):

- agents.json Specification — Introduction (agents.json is an open specification built on the
  OpenAPI standard; `/.well-known/agents.json` discovery placement; stateless orchestration by
  the calling agent) — <https://docs.wild-card.ai/agentsjson/introduction>
- agents.json Specification — full schema documentation —
  <https://docs.wild-card.ai/agentsjson/schema>
- agents.json source repository (the specification and its machine-readable JSON Schema) —
  <https://github.com/wild-card-ai/agents-json>
- agents.json JSON Schema — the authoritative field definitions consulted here (top-level
  `agentsJson`, `info`, `sources`, `flows` required and `overrides` optional; a `source` is
  `{id, path}` referencing an OpenAPI 3+ specification; a `flow` is
  `{id, title, description, actions, fields}` with optional `links`; a `link` is
  `{origin, target}` with `{actionId, fieldPath}`; **no** auth/security field and **no**
  signature/digest/proof field) —
  <https://raw.githubusercontent.com/wild-card-ai/agents-json/master/agents_json/agentsJson.schema.json>

**Confirmed** against the primary source: agents.json is a static JSON discovery document
(version 0.1.0) served over HTTP GET at `/.well-known/agents.json` with `Content-Type:
application/json`; its top-level required fields are `agentsJson`, `info`, `sources`, `flows`
(with `overrides` optional); `sources` reference OpenAPI 3+ documents; the calling agent
orchestrates flows statelessly; and the v0.1.0 schema defines no auth, security, signature, or
digest field. These facts ground the DOC carriage, the `content_type` (§2), the document-binding
(§5), and the transport notes (§8).

**Unconfirmed / provisional**, and marked as such rather than fixed by assumption:

1. **`protocol_id` assignment.** NPAMP-REG §6 assigns agents.json **no** standards code point;
   §2 is therefore PROVISIONAL (experimental/private-use, or Class OPAQUE) until NPAMP-REG §8
   assigns one. This is a registry gap, not an agents.json fact.
2. **Retrieval operation names.** `agents-json/get` and `agents-json/source/get` (§4) are
   **defined by this mapping** for the NPAMP-CC-DOC pull pattern; agents.json defines no
   operation namespace of its own. They are advisory routing metadata (§4) and do not affect the
   octet-exact carriage of the returned document.
3. **DocumentBinding TLV tag.** The DocumentBinding descriptor rides the TLV whose tag
   NPAMP-CC-DOC marks provisional (`0xTBD-DOCBIND`, NPAMP-CC-DOC §6.1, §11); that provisional
   status is inherited here and not resolved by this document.
4. **Later agents.json revisions.** A future agents.json version MAY add fields — including an
   in-band signature. Because the carriage is transparent over the document octets (§3), a newer
   or older agents.json revision is carried without a change to this mapping; only §5's "no
   native signature" statement is specific to v0.1.0 and would be revisited if a later revision
   adds one.

N-PAMP documents built on:

- draft-bubblefish-npamp-01 — the N-PAMP core specification (Bridge channel `0x000D`, Discovery
  channel `0x0010`, the frame format, the BridgeEnvelope and SafetyLabel TLV reservations, and
  AEAD payload protection).
- NPAMP-BRIDGE (`10_bridge_framework.md`) — the encapsulation, correlation, error, and
  SafetyLabel contract.
- NPAMP-CC-DOC (`24_carriage_documents.md`) — the capability/schema document carriage class that
  does the structural work for agents.json.
- NPAMP-CC-OPAQUE (`25_carriage_opaque.md`) — the universal carriage referenced as the interim
  cross-domain option in §2.
- NPAMP-REG (`30_protocol_registry.md`) — the Bridge Protocol Identifier registry (the PROVISIONAL
  `protocol_id`, the experimental/private ranges, and the registration procedure of §2).
- NPAMP-DISC (`40_discovery.md`) — the Discovery-channel advertisement referenced in §7.
- BCP 14: RFC 2119 and RFC 8174 — requirement key words.

## 11. Conformance

An implementation conforms to NPAMP-MAP-AGENTS-JSON if and only if it conforms to NPAMP-CC-DOC
(and therefore to NPAMP-BRIDGE) and, for agents.json traffic, it:

1. Carries the agents.json document under the PROVISIONAL `protocol_id` of §2 with
   `content_type = 0x01`, octet-for-octet, selecting the foreign protocol solely from
   `protocol_id` (never from another envelope field), and — absent a standards assignment — uses
   only an experimental or private-use identifier under the constraints of NPAMP-REG §7, or Class
   OPAQUE, never emitting an experimental value as a production default once a standards code
   point exists (§2);
2. Carries the agents.json document as an NPAMP-CC-DOC document set — as a `BRIDGE_RESPONSE` to a
   `agents-json/get` `BRIDGE_REQUEST` (which itself carries no DocumentBinding TLV), as a
   `BRIDGE_NOTIFY` push for a single-part document, or as a streamed `BRIDGE_STREAM_DATA` /
   `BRIDGE_STREAM_END` sequence for a large document — with a DocumentBinding TLV on every
   document and proof part (§4, §5);
3. Delivers the agents.json document octet-for-octet, performing no canonicalization,
   re-indentation, minification, transcoding, or re-serialization, and refuses with
   `DigestUnstable` any document set whose octet preservation it cannot guarantee (§3;
   NPAMP-CC-DOC §4);
4. Recomputes and compares the document digest over the exact recovered octets, constant-time,
   and rejects a mismatch with `DigestMismatch` without presenting the document as verified (§5;
   NPAMP-CC-DOC §5);
5. Treats an agents.json document set as carrying `proof_count = 0` unless a deployment supplies
   detached proofs, and, when proofs are present, binds and verifies them per NPAMP-CC-DOC §6.3
   and §6.5, drawing signature `proof_alg` values from the core-assigned signature code points
   (§5);
6. Carries any referenced OpenAPI source document, when it chooses to serve one, as a **distinct**
   document set with its own `doc_id`, never assembling it into the agents.json document set (§5);
7. Attaches a `read_only` SafetyLabel to a served agents.json (or source) document part, treats a
   missing SafetyLabel on a state-mutating retrieval as `destructive` (fail-safe), and does not
   represent this mapping's `read_only` retrieval label as characterizing the side effects of any
   flow's API `actions`, which this mapping does not carry (§6);
8. Carries an agents.json document set on the Bridge channel `0x000D` by default or the Discovery
   channel `0x0010` for advertisement, never splitting one document set across the two channels,
   and sends or accepts agents.json frames only on a channel advertised during the handshake (§7);
   and
9. Carries no HTTP framing as part of the agents.json foreign message and does not depend on the
   `/.well-known/agents.json` path for carriage, conveying the document by the retrieval operation
   of §4 and its `doc_id` (§8).

A conformance test suite SHOULD assert each clause above with recorded exchanges that include: a
`agents-json/get` pull whose `BRIDGE_REQUEST` carries no DocumentBinding TLV and whose
`BRIDGE_RESPONSE` document part does; a single-frame `BRIDGE_NOTIFY` push with `proof_count = 0`; a
streamed agents.json document whose digest is computed over the reassembly; a deliberately altered
document octet that MUST produce `DigestMismatch`; an agents.json document set to which a
deployment has bound one detached signature proof, carried on both the Bridge and the Discovery
channel; and a referenced OpenAPI source document carried as a distinct document set that MUST NOT
be assembled into the agents.json set.
