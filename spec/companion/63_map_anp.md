# NPAMP-MAP-ANP — Agent Network Protocol (ANP) Mapping (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is a **thin per-protocol mapping**: it pins the specifics of
> the **Agent Network Protocol (ANP)** onto N-PAMP carriage. ANP's confirmed base
> transport is **HTTP** (ANP uses HTTP as its base transport and organizes
> documents using JSON-LD, §11), so ANP's request/response
> traffic is carried under the HTTP-semantics carriage class **NPAMP-CC-HTTP**
> (`21_carriage_http.md`), and any ANP payload is carriable **today, unchanged,**
> under the opaque carriage class **NPAMP-CC-OPAQUE** (`25_carriage_opaque.md`).
> It builds on **NPAMP-BRIDGE** (`10_bridge_framework.md`) and the N-PAMP core
> specification (draft-bubblefish-npamp-01, the "core specification"). It consumes
> only code points those documents already reserve; it defines no new frame type,
> no new TLV, and no change to the core wire format or to NPAMP-BRIDGE.
>
> **Maturity: OPAQUE-READY.** ANP is a newer, still-evolving protocol. This mapping
> pins only the ANP facts that its own current published specification confirms
> (§4, §5, §6), carries ANP over Class OPAQUE and NPAMP-CC-HTTP today, and marks
> every fact that the source leaves unsettled as **unconfirmed** (§2.3, §9) rather
> than fixing it by assumption. A later revision pins the remaining specifics once
> ANP's message framing and its `protocol_id` are confirmed.

## 1. Scope

### 1.1 In scope

This document defines how an ANP endpoint interoperates over an N-PAMP association
without bespoke adaptation. Against ANP's own published specification (§11), it pins
only the ANP specifics the carriage classes leave to a per-protocol mapping:

- The ANP **protocol identifier** and its **PROVISIONAL** status, and the
  foreign-message `content_type` (§2);
- How ANP's **HTTP-semantics** request/response traffic — did:wba-authenticated
  agent invocation, Agent Description retrieval, agent discovery, and meta-protocol
  negotiation — rides NPAMP-CC-HTTP, and how any ANP payload rides Class OPAQUE
  (§3, §4);
- ANP's **did:wba** identity layer, whose HTTP Message Signatures are **bound to the
  HTTP transport** and are therefore neither reconstructed nor verified by carriage,
  contrasted with the AD document's transport-independent `proof` (§5);
- The carriage of ANP's **Agent Description (AD)** document and its **discovery
  CollectionPage** as capability documents (§6);
- The **SafetyLabel effect class** each state-mutating ANP operation carries, derived
  from its HTTP method under NPAMP-CC-HTTP §8.1, and the NPAMP-BRIDGE §7 fail-safe
  (§7); and
- **Channel selection** for each traffic class (§8).

The structural work — octet-exact carriage, the BridgeEnvelope, correlation, the
structured-error model, streaming, and the safety-annotation TLV — is done by
NPAMP-BRIDGE and the named carriage classes and is not restated here.

### 1.2 Not in scope

The following are explicitly NOT defined by this document:

- **ANP's meta-protocol negotiation semantics.** ANP's meta-protocol layer lets two
  agents negotiate, then generate and deploy, an application protocol in natural
  language (§11). This mapping carries the negotiation's HTTP request/response
  messages transparently; it does not perform, evaluate, or stand in for the
  negotiation, the code generation, or the deployment, none of which is an N-PAMP
  concern.
- **The internal grammar of any ANP JSON-LD object** — the Agent Description
  document, the discovery CollectionPage, a negotiation request/response body, or a
  DID document. These are fixed by ANP's own specification, carried verbatim
  (NPAMP-BRIDGE §1), and are not parsed, validated, or transformed here.
- **did:wba signature verification.** did:wba binds its RFC 9421 HTTP Message
  Signature to HTTP request components that do not exist on the N-PAMP wire (§5);
  reconstructing or verifying that signature is out of scope for carriage and is
  addressed only as a security consideration (§5, §10).
- **The application protocols an AD declares.** An AD's `interfaces` may point to an
  OpenRPC/JSON-RPC, MCP, WebRTC, or YAML/OpenAPI interface (§6). Carrying such a
  declared interface's own traffic over N-PAMP is the business of that interface's
  carriage class (for example NPAMP-CC-JSONRPC for a JSON-RPC interface, or
  NPAMP-MAP-MCP for an MCP interface) and is out of scope here.
- **Any change to NPAMP-BRIDGE, to the carriage classes, or to the core wire
  format**, including the BridgeEnvelope TLV, the SafetyLabel TLV, and the
  OpaqueContentType TLV, all of which are used as their defining documents specify.

## 2. Protocol identity

### 2.1 Identity table

| Property | Value |
|---|---|
| Protocol | Agent Network Protocol (ANP). |
| `protocol_id` | **PROVISIONAL.** NPAMP-REG §6 assigns ANP **no** standards code point (`0x01`–`0x0F`). Until one is registered under NPAMP-REG §8, ANP MUST be carried under an **experimental** `protocol_id` (`0x10`–`0x7F`) agreed out of band by the two peers (NPAMP-REG §7.1). This document does not fix a specific value; an experimental value carries no cross-domain meaning. |
| Carriage class | **HTTP** (NPAMP-CC-HTTP) for ANP's HTTP request/response traffic; **OPAQUE** (NPAMP-CC-OPAQUE) as the universal fallback that carries any ANP payload today with no protocol-specific mapping. |
| `content_type` | Under NPAMP-CC-HTTP, `0x02` (application/cbor) for the HTTP-Carriage Object container (NPAMP-CC-HTTP §2.3). Under Class OPAQUE, the payload's own media type: `0x01` (application/json) for a JSON body, or `application/ld+json` declared via the OpaqueContentType TLV once its code point is assigned (NPAMP-CC-OPAQUE §4; §2.3, §9 below). |
| Foreign-message form | An ANP HTTP request/response (method, target, headers, JSON/JSON-LD body), carried as the NPAMP-CC-HTTP HTTP-Carriage Object; or, under Class OPAQUE, the ANP payload octets carried octet-for-octet (NPAMP-BRIDGE §1). |

A sender MUST set the agreed experimental `protocol_id` on every Bridge frame
carrying ANP, and a receiver that does not carry that value MUST reply to a
BRIDGE_REQUEST with `ProtocolUnsupported` (NPAMP-BRIDGE §6; NPAMP-REG §9), never
inferring ANP from any other envelope field. An implementation MUST NOT emit ANP
under a `protocol_id` that NPAMP-REG has assigned to a different protocol
(NPAMP-REG §7.1).

### 2.2 What is confirmed

The following ANP facts are confirmed from ANP's own current published specification
(§11) and are pinned by this mapping:

- ANP's **base transport is HTTP** (ANP uses HTTP as its base transport, §11); ANP
  defines no bespoke binary transport and reuses HTTP semantics throughout
  its identity, description, discovery, and meta-protocol layers.
- ANP's identity layer is **did:wba**, which authenticates an HTTP request with RFC
  9421 HTTP Message Signatures whose coverage set is bound to HTTP components (§5).
- The **Agent Description** document is a JSON-LD capability document carrying an
  `interfaces` array and a `proof` member (§6); the **agent-discovery** document is a
  JSON-LD `CollectionPage` served at `https://{domain}/.well-known/agent-descriptions`
  per RFC 8615 (§6).

### 2.3 What is unconfirmed (OPAQUE-READY)

The following are NOT pinned by this mapping because ANP's source leaves them
unsettled at the time of writing; each is marked, not assumed (§9):

- The **exact media type** ANP assigns its AD/discovery documents. ANP recommends
  JSON and describes JSON-LD but does not formally register a media type; this
  mapping treats the document as JSON-LD without asserting a normative media-type
  string (§6, §9).
- ANP's **meta-protocol method and error vocabulary**. ANP's meta-protocol
  specification is a Draft; the negotiation is carried as ordinary ANP HTTP traffic
  regardless of its exact method names or error codes (§4, §9).
- ANP's **`protocol_id`**, which remains PROVISIONAL until registered (§2.1).

Because Class OPAQUE and NPAMP-CC-HTTP both carry ANP payloads without depending on
any of the above, ANP is carriable today; the unconfirmed items affect only a future
tightening of this mapping, not present interoperability.

## 3. Relationship to the carriage classes and NPAMP-BRIDGE

This document is a registration plus a thin mapping: it names the carriage classes
ANP uses, the shape of ANP's traffic, and ANP-specific fields, and it lets the
carriage classes do the structural work.

| Facility | Owning document | Use here |
|---|---|---|
| Octet-exact carriage, BridgeEnvelope, correlation, error model, SafetyLabel | NPAMP-BRIDGE | Inherited unchanged for every ANP frame (§3–§7). |
| HTTP-semantics carriage (HTTP-Carriage Object, method/target/status, headers, body, streaming) | NPAMP-CC-HTTP | Carriage of ANP's HTTP request/response traffic (§4). |
| Opaque carriage (byte-exact payload of a declared content type) | NPAMP-CC-OPAQUE | Universal fallback for any ANP payload today (§4). |
| Capability/schema document carriage (detached proofs) | NPAMP-CC-DOC (`24_carriage_documents.md`) | OPTIONAL carriage of the AD document and discovery CollectionPage (§6). |

Where this document and a carriage class could appear to differ on a structural
matter, the carriage class governs; this document pins only ANP specifics. Because
NPAMP-CC-HTTP carries the HTTP method and target as advisory routing metadata and
carries the body verbatim (NPAMP-CC-HTTP §2.4, §4.3), the carriage is robust to
ANP's still-evolving method and field spellings: a receiver selects the foreign
protocol solely by `protocol_id` (NPAMP-REG §9) and delivers the ANP message
octet-for-octet regardless of the exact tokens inside it.

## 4. ANP traffic and carriage

ANP's three layers — identity/secure communication, meta-protocol negotiation, and
the application layer (Agent Description and discovery) — all move over HTTP. Each
ANP HTTP exchange is a request bearing a method and target with an optional JSON/
JSON-LD body, answered by a response bearing a status and an optional body; this is
exactly the shape NPAMP-CC-HTTP carries. The table maps ANP's confirmed traffic
classes onto carriage; the HTTP method shown is the ANP-defined or ANP-recommended
method where the source fixes it, and is otherwise the method the deploying interface
uses.

| ANP traffic class | HTTP shape (confirmed facts) | Carriage | NPAMP-BRIDGE frame(s) |
|---|---|---|---|
| DID document resolution | GET `https://{domain}/.well-known/did.json` (did:wba, §5) | NPAMP-CC-HTTP | BRIDGE_REQUEST → BRIDGE_RESPONSE / BRIDGE_ERROR |
| Agent Description retrieval | GET the AD `url` (JSON-LD document, §6) | NPAMP-CC-HTTP; MAY use NPAMP-CC-DOC (§6) | BRIDGE_REQUEST → BRIDGE_RESPONSE / BRIDGE_ERROR |
| Agent discovery | GET `https://{domain}/.well-known/agent-descriptions` (JSON-LD CollectionPage, §6) | NPAMP-CC-HTTP; MAY use NPAMP-CC-DOC (§6) | BRIDGE_REQUEST → BRIDGE_RESPONSE / BRIDGE_ERROR |
| Meta-protocol negotiation | An ANP HTTP request to an ANP endpoint carrying a negotiation body (§11); did:wba-authenticated | NPAMP-CC-HTTP, or Class OPAQUE | BRIDGE_REQUEST → BRIDGE_RESPONSE / BRIDGE_ERROR |
| Agent capability invocation | An HTTP request to an interface the AD declares (§6); did:wba-authenticated | NPAMP-CC-HTTP, or the declared interface's own carriage class (out of scope, §1.2) | BRIDGE_REQUEST → BRIDGE_RESPONSE / BRIDGE_ERROR |

Carriage requirements:

- Each ANP HTTP request is a **BRIDGE_REQUEST** (`0x0100`, `message_kind = 0x01`); its
  reply is **BRIDGE_RESPONSE** (`0x0101`) — including an ANP HTTP `4xx`/`5xx` result,
  which NPAMP-CC-HTTP §6.1 carries as a response with the foreign status preserved,
  **not** as a transport error — or **BRIDGE_ERROR** (`0x0102`) for a failure *below*
  ANP (NPAMP-CC-HTTP §6.2). The BridgeEnvelope `method` field carries the ANP HTTP
  method token and target as the NPAMP-CC-HTTP routing key (NPAMP-CC-HTTP §2.4).
- Either peer MAY originate a BRIDGE_REQUEST (NPAMP-BRIDGE §5); ANP's requesting agent
  is the requester and the addressed agent is the responder for a given exchange, and
  the carriage places no additional directional restriction.
- A streamed ANP response (for example a streamed application interface) is carried as
  the NPAMP-CC-HTTP streaming sequence — BRIDGE_STREAM_DATA chunks terminated by one
  BRIDGE_STREAM_END (NPAMP-CC-HTTP §7).
- Under **Class OPAQUE**, an ANP payload of an already-enumerated media type
  (application/json) is carried with the BridgeEnvelope `content_type` set to that
  value; a `application/ld+json` payload requires the OpaqueContentType TLV, whose
  code point is an open item in NPAMP-CC-OPAQUE (§9). Until that code point is
  assigned, a `application/ld+json` payload carried opaquely is declared as its
  enumerated `application/json` supertype or carried under NPAMP-CC-HTTP instead
  (NPAMP-CC-OPAQUE §4.2, §10).

## 5. Identity: did:wba and transport-bound authentication

ANP's identity layer, **did:wba**, is the single most consequential ANP-specific fact
for carriage, because it binds authentication to the HTTP transport. did:wba
authenticates an HTTP request using **RFC 9421 HTTP Message Signatures**: the client
sends `Signature-Input` and `Signature` header fields (and `Content-Digest`, RFC
9530, when the request has a body), the `keyid` names a DID URL resolvable to a
verification method in the DID document, and the signature's coverage set includes
the HTTP-derived components `@method`, `@target-uri`, and (recommended) `@authority`,
plus `content-digest`, with `created`/`expires`/`nonce` parameters for replay
protection (§11). The DID document itself is resolved by transforming the did:wba
identifier to `https://{domain}/.well-known/did.json` (§11).

The consequences for carriage are exactly those NPAMP-CC-OPAQUE §1.3/§9.3 and
NPAMP-CC-HTTP §8.4 already state for a transport-bound signature:

- A did:wba HTTP Message Signature covers `@method`, `@target-uri`, and `@authority`
  — components of an HTTP hop that **does not exist** on the N-PAMP wire. Carriage
  delivers the ANP message (and, where present, its `Signature`/`Signature-Input`
  header octets) but does **not** reconstruct that HTTP context and does **not**
  verify the signature. An implementation MUST NOT represent a did:wba signature as
  verified merely because the frame carrying it was authenticated by the N-PAMP
  association (NPAMP-CC-HTTP §8.3, §8.4; NPAMP-CC-OPAQUE §9.3).
- A party that must verify a did:wba signature MUST be able to reconstruct the
  original HTTP request context independently; this is the role of a gateway acting
  as an independent foreign-HTTP endpoint (NPAMP-CC-HTTP §8.4; NPAMP-CC-OPAQUE §6),
  not of the carriage layer. A gateway that egresses ANP onto native HTTP MUST emit
  the ANP payload octet-for-octet and MUST NOT claim that transport-bound
  authentication was preserved by carriage (NPAMP-CC-OPAQUE §6.2).
- The N-PAMP association independently supplies authenticated encryption, post-quantum
  key establishment, and replay protection for the frame that carries the ANP message
  (core specification); this protects the **association**, and an integrator MUST NOT
  treat it as a substitute for did:wba's message-level authentication of the ANP
  endpoint (NPAMP-CC-HTTP §8.3).

By contrast, the Agent Description document carries a **`proof`** member (§6). A proof
computed over the document's own octets is a **payload-level, transport-independent**
signature: it survives carriage precisely because it is part of the payload bytes and
remains verifiable by any holder of the document and the verifying key (NPAMP-CC-DOC
§6; NPAMP-CC-OPAQUE §9.3). Carriage delivers such a proof with the integrity a
verifier needs and does not itself decide trust.

## 6. Capability documents: the Agent Description and discovery CollectionPage

ANP's application layer publishes two JSON-LD capability documents:

- The **Agent Description (AD)** — the agent's entry point: a JSON-LD document whose
  members include `protocolType`, `protocolVersion`, `name`, `did`, `url`, `owner`,
  `description`, `securityDefinitions`, `security`, an `interfaces` array, and a
  `proof` (§11). Each `interfaces` entry declares an interface with `type`
  (`NaturalLanguageInterface` or `StructuredInterface`), `protocol` (for example
  `openrpc`, `MCP`, `WebRTC`, or `YAML`), a `url`, and OPTIONAL `version`,
  `description`, and `humanAuthorization` members (§11).
- The **agent-discovery CollectionPage** — a JSON-LD `CollectionPage` served at
  `https://{domain}/.well-known/agent-descriptions` (RFC 8615) whose `items` array
  references agent descriptions, with OPTIONAL `next` for pagination (§11).

Both are retrieved over HTTP GET (§4) and are `read_only` (§7). Because each is a
self-contained capability document with an OPTIONAL detached/embedded `proof`, a
deployment MAY carry either under **NPAMP-CC-DOC** instead of, or in addition to, its
plain NPAMP-CC-HTTP GET, exactly as NPAMP-MAP-A2A carries the A2A AgentCard: the
document is delivered byte-identical to the octets the producer signed or hashed, and
any `proof` is carried as a detached proof whose verification is the consumer's act
(NPAMP-CC-DOC §4, §6). An implementation MUST NOT re-serialize, re-indent, or
canonicalize the document, so that any embedded `proof` verifies bit-identically at
the consumer. A single document and its proofs MUST NOT be split across channels
(NPAMP-CC-DOC §3).

This mapping does not assert a normative media-type string for these documents (§2.3);
under Class OPAQUE a JSON-LD document that must declare `application/ld+json` depends
on the OpaqueContentType TLV code point that NPAMP-CC-OPAQUE §10 leaves open (§4, §9).

## 7. SafetyLabel effect classes

The SafetyLabel TLV (Type `0x0013`) and its fail-safe are governed by NPAMP-BRIDGE §7
and inherited through NPAMP-CC-HTTP §8.1 unchanged. Because ANP's operations are HTTP
requests, a sender derives the SafetyLabel `effect` from the carried HTTP method per
NPAMP-CC-HTTP §8.1, tightened (never loosened) where ANP fixes an operation's effect.

| ANP operation | HTTP method | `effect` (NPAMP-BRIDGE §7) | Rationale |
|---|---|---|---|
| DID document resolution (§5) | GET | `0x00` read_only | Reads a DID document; no side effect. |
| Agent Description retrieval (§6) | GET | `0x00` read_only | Serves a capability document. |
| Agent discovery (§6) | GET | `0x00` read_only | Reads the discovery CollectionPage. |
| Meta-protocol negotiation (§11) | POST (per the carried request) | `0x02` non_idempotent_write | Establishes new negotiated/deployed protocol state; each negotiation is a fresh action. A deployment that treats protocol deployment as more dangerous MAY label it `0x03` destructive; a sender MUST attach a SafetyLabel either way. |
| Agent capability invocation (§4) | Per the declared interface | Derived from the method (NPAMP-CC-HTTP §8.1); `0x03` destructive when known destructive | A declared interface is arbitrary agent code; its effect is the operation's, not ANP's. |

Requirements:

- For any ANP operation whose `effect` is not `0x00`, the sender MUST attach a
  SafetyLabel TLV (NPAMP-BRIDGE §7) to the carrying BRIDGE_REQUEST, and an
  intermediary MUST carry it unchanged.
- A receiver MUST NOT treat the **absence** of a SafetyLabel on a state-mutating ANP
  operation as `read_only`; absence on such an operation MUST be treated as
  `destructive` (fail-safe; NPAMP-BRIDGE §7, NPAMP-CC-HTTP §8.1).
- The `effect` states declared intent; it does not replace the ANP endpoint's own
  authorization decision, which includes did:wba verification the carriage does not
  perform (§5).

## 8. Channel selection

| ANP traffic class | Carriage | Channel |
|---|---|---|
| HTTP request/response traffic (DID resolution, invocation, negotiation) (§4, §5) | NPAMP-CC-HTTP or Class OPAQUE | Bridge `0x000D` |
| Agent Description and discovery CollectionPage (§6) | NPAMP-CC-HTTP; MAY use NPAMP-CC-DOC | Bridge `0x000D` default; MAY use Discovery `0x0010` |

ANP HTTP traffic rides the **Bridge channel `0x000D`** by default, as required for
NPAMP-BRIDGE encapsulation (NPAMP-BRIDGE §1). Because the AD document and the
discovery CollectionPage are capability/discovery documents, a deployment MAY carry
them on the **Discovery channel `0x0010`** under NPAMP-CC-DOC (companion index,
"Channel selection for carriage"); a single document and its proofs MUST NOT be split
across the two channels (§6). The Bridge and Discovery channels are both minimum
profile **Standard** (core specification channel registry; `../../registries/channels.csv`);
ANP carriage requires no channel above the Standard profile. A peer MUST NOT send or
accept ANP frames on a channel it did not advertise during the handshake (core
specification §5).

## 9. Version considerations and marked uncertainties

ANP is a newer, actively evolving protocol published as a set of numbered
specifications (white paper; did:wba method; agent communication meta-protocol; agent
description protocol; agent discovery protocol) plus application-layer drafts (§11).
This mapping pins only what those sources confirm and marks the rest:

1. **`protocol_id` is PROVISIONAL.** NPAMP-REG assigns ANP no standards code point;
   ANP is carried under an out-of-band-agreed experimental `protocol_id` until one is
   registered (§2.1). An implementer MUST NOT rely on any particular experimental
   value for cross-domain interoperation (NPAMP-REG §7.1).
2. **Meta-protocol method and error vocabulary are not pinned.** ANP's meta-protocol
   specification is a Draft; its negotiation is reported to run as request/response
   messages over ANP HTTP endpoints. This mapping deliberately does **not** fix any
   negotiation method name, profile string, or error-code set as a normative N-PAMP
   code point, because the carriage carries those tokens verbatim inside the ANP
   message (§3, §4) and a change to them does not change the carriage. An implementer
   MUST confirm the exact negotiation vocabulary against the ANP meta-protocol
   specification revision they target (§11).
3. **AD/discovery media type is not asserted.** ANP recommends JSON and describes
   JSON-LD but does not, in the sources consulted, register a normative media type;
   this mapping treats the documents as JSON-LD without asserting a media-type string
   (§2.3, §6).
4. **AD retrieval path is not universally fixed.** The DID document
   (`/.well-known/did.json`) and the discovery CollectionPage
   (`/.well-known/agent-descriptions`) have confirmed well-known paths (§5, §6); the
   Agent Description document is retrieved by its declared `url`, and this mapping
   does not assert a single well-known retrieval path for it beyond that.

No value in this document is asserted beyond what §11's sources support; where a fact
was version-dependent or not confirmable from the primary source, it is marked here
rather than fixed by assumption.

## 10. Security considerations

This mapping introduces no cryptography and changes none. All confidentiality,
integrity, authentication, downgrade resistance, and replay protection for a carried
frame are provided by the core specification's wire format and key schedule and apply
unchanged to every ANP frame, which travels inside the AEAD-protected Bridge (or
Discovery) payload.

Carrying ANP over N-PAMP makes no security claim about ANP itself. In particular:

- **did:wba is transport-bound and is NOT reconstructed or verified by carriage**
  (§5). ANP's did:wba authentication signs HTTP request components (`@method`,
  `@target-uri`, `@authority`, `content-digest`) that do not exist on the N-PAMP wire.
  Carriage delivers the ANP message and any signature header octets but neither
  reconstructs the signed HTTP context nor verifies the signature; a deployment that
  relies on did:wba MUST re-establish and verify it in a component outside the
  carriage class (a gateway acting as an independent HTTP endpoint), and MUST NOT
  advertise carriage as supplying it (NPAMP-CC-HTTP §8.3, §8.4; NPAMP-CC-OPAQUE §6,
  §9.3). The association's authentication of the frame is not a substitute for the
  ANP endpoint's authentication of the request.
- **The AD `proof` is payload-level and survives carriage** (§5, §6): a proof
  computed over the document octets remains verifiable by the consumer under
  NPAMP-CC-DOC §6, and carriage delivery of a proof is not verification of it.
- **Untrusted payloads.** Carriage does not parse, validate, or sanitize an ANP
  JSON/JSON-LD payload; a receiving application MUST treat a delivered ANP payload as
  untrusted input of its declared content type and validate it before acting on it
  (NPAMP-CC-OPAQUE §9.2; NPAMP-CC-HTTP §8.5).
- **Safety fail-safe.** The effect classification of §7 and the NPAMP-BRIDGE §7
  fail-safe (absence of a SafetyLabel on a state-mutating operation is `destructive`)
  apply to every ANP operation; discovery of an ANP agent or interface is a claim,
  not authorization (NPAMP-DISC §10).

## 11. References

Primary sources (ANP specification; consulted for §2, §4, §5, §6, §7, §9):

- Agent Network Protocol — Technical White Paper (three-layer architecture; ANP uses
  HTTP as its base transport and organizes documents using JSON-LD; meta-protocol
  negotiation) —
  <https://agent-network-protocol.com/specs/white-paper.html> and
  <https://arxiv.org/html/2508.00007v1>
- AgentNetworkProtocol specification repository (numbered specification set) —
  <https://github.com/agent-network-protocol/AgentNetworkProtocol>
- ANP did:wba Method Design Specification (RFC 9421 `Signature-Input`/`Signature`,
  RFC 9530 `Content-Digest`, `keyid` DID URL, `@method`/`@target-uri`/`@authority`
  coverage, `created`/`expires`/`nonce`, `/.well-known/did.json` resolution) —
  <https://github.com/agent-network-protocol/AgentNetworkProtocol/blob/main/03-did-wba-method-design-specification.md>
- ANP Agent Communication Meta-Protocol Specification (Draft) (natural-language
  protocol negotiation over ANP HTTP endpoints) —
  <https://github.com/agent-network-protocol/AgentNetworkProtocol/blob/main/06-anp-agent-communication-meta-protocol-specification.md>
- ANP Agent Description Protocol Specification (JSON-LD AD document; `interfaces`
  array with `type`/`protocol`/`url`; `proof`) —
  <https://github.com/agent-network-protocol/AgentNetworkProtocol/blob/main/07-anp-agent-description-protocol-specification.md>
  and <https://agent-network-protocol.com/specs/agent-description.html>
- ANP Agent Discovery Protocol Specification (`/.well-known/agent-descriptions`,
  JSON-LD `CollectionPage`, RFC 8615) —
  <https://github.com/agent-network-protocol/AgentNetworkProtocol/blob/main/08-ANP-Agent-Discovery-Protocol-Specification.md>
- RFC 9421 (HTTP Message Signatures), RFC 9530 (Digest Fields), RFC 8615
  (`.well-known` URIs), and the W3C Decentralized Identifiers (DID) data model — the
  external standards did:wba builds on.

N-PAMP documents built on:

- draft-bubblefish-npamp-01 — the N-PAMP core specification: the frame format, the
  channel registry (Bridge `0x000D`, Discovery `0x0010`), the extension-TLV encoding,
  and the AEAD payload protection.
- NPAMP-BRIDGE (`10_bridge_framework.md`) — the encapsulation, BridgeEnvelope,
  correlation, structured-error, and SafetyLabel contract.
- NPAMP-CC-HTTP (`21_carriage_http.md`) — the HTTP-semantics carriage class.
- NPAMP-CC-OPAQUE (`25_carriage_opaque.md`) — the opaque carriage class (universal
  fallback; transport-bound-authentication and content-type-declaration rules).
- NPAMP-CC-DOC (`24_carriage_documents.md`) — capability/schema document carriage
  referenced in §6.
- NPAMP-REG (`30_protocol_registry.md`) — the Bridge Protocol Identifier registry
  (ANP has no standards code point; experimental/private ranges).
- NPAMP-DISC (`40_discovery.md`) — Discovery-channel advertisement referenced in §8.
- BCP 14 (RFC 2119, RFC 8174) — requirement key words.

## 12. Conformance

An implementation conforms to NPAMP-MAP-ANP if and only if it conforms to
NPAMP-BRIDGE and to the carriage class it uses (NPAMP-CC-HTTP, and/or NPAMP-CC-OPAQUE,
and NPAMP-CC-DOC where §6 applies) for the frames it emits and parses, and, for ANP
traffic, it:

1. Carries ANP under an out-of-band-agreed experimental `protocol_id` (`0x10`–`0x7F`)
   because NPAMP-REG assigns ANP no standards code point, never emits ANP under a
   `protocol_id` NPAMP-REG assigned to another protocol, and selects the foreign
   protocol solely by `protocol_id` (§2);
2. Carries each ANP HTTP exchange under NPAMP-CC-HTTP (or Class OPAQUE) — the request
   as a BRIDGE_REQUEST with the HTTP method/target as the BridgeEnvelope routing key,
   an ANP `4xx`/`5xx` result preserved as a BRIDGE_RESPONSE rather than a transport
   error, and a sub-ANP failure as BRIDGE_ERROR — carrying the ANP message
   octet-for-octet (§4);
3. Neither reconstructs nor verifies a did:wba HTTP Message Signature, makes no
   representation that a did:wba signature was verified by carriage, and re-establishes
   did:wba verification, where required, in a component outside the carriage class
   (§5, §10);
4. Carries the Agent Description document and the discovery CollectionPage
   octet-exact — never re-serializing or canonicalizing them — with any `proof`
   carried as a payload-level proof whose verification is the consumer's act, and
   never splits a document and its proofs across channels (§6);
5. Derives each state-mutating ANP operation's SafetyLabel `effect` from its HTTP
   method per §7, attaches a SafetyLabel to every non-`read_only` operation, and treats
   a missing SafetyLabel on a state-mutating operation as `destructive` (§7);
6. Carries ANP HTTP traffic on the Bridge channel `0x000D`, uses the Discovery channel
   `0x0010` only for the OPTIONAL NPAMP-CC-DOC carriage of the AD/discovery documents
   of §6, sends or accepts ANP frames only on channels advertised during the
   handshake, and requires no channel above the Standard profile (§8); and
7. Defines no new frame type, TLV, or code point, consuming only those the core
   specification, NPAMP-BRIDGE, and the named carriage classes already reserve, and
   inherits the OpaqueContentType TLV open item without resolving it here (§4, §9).

A conformance test suite SHOULD assert each clause above with recorded exchanges that
include at least: a GET of the DID document and of the Agent Description carried as
BRIDGE_REQUEST/BRIDGE_RESPONSE with `read_only` SafetyLabels; a did:wba-authenticated
request carried with its `Signature`/`Signature-Input` header octets preserved and
verified to be neither reconstructed nor validated by the carriage; a meta-protocol
negotiation request carrying a `non_idempotent_write` SafetyLabel, and a second with
the SafetyLabel omitted, verified to be treated as `destructive`; an ANP `4xx` result
carried as a BRIDGE_RESPONSE preserving the ANP status and body; and an Agent
Description document set with one detached `proof` carried under NPAMP-CC-DOC on both
the Bridge and the Discovery channel.
</content>
</invoke>
