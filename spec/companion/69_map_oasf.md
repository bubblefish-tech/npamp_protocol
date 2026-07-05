# NPAMP-MAP-OASF — Open Agentic Schema Framework Mapping (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is a **thin per-protocol mapping**: it pins the specifics of
> the **Open Agentic Schema Framework (OASF)** onto N-PAMP carriage. OASF is a
> **schema / document framework**, not a wire protocol: its unit of interoperation
> is the OASF **record**, a self-describing capability/metadata document. This
> mapping therefore carries an OASF record as a document under the document carriage
> class **NPAMP-CC-DOC** (`24_carriage_documents.md`). It builds on **NPAMP-BRIDGE**
> (`10_bridge_framework.md`) and the N-PAMP core specification
> (draft-bubblefish-npamp-01, the "core specification"). It consumes only code points
> those documents already reserve; it defines no new frame type, no new TLV, and no
> change to the core wire format or to NPAMP-BRIDGE.
>
> **Mapping maturity: OPAQUE-READY (§4).** OASF's *document model* maps cleanly onto
> NPAMP-CC-DOC and is pinned here. OASF defines **no native request/response transport,
> API, or method namespace** of its own (§4, §6, §10), and it has **no standards-assigned
> Bridge `protocol_id`** (§3). The transport-dependent parts of this mapping are therefore
> marked provisional: an OASF record is carriable today either as an NPAMP-CC-DOC document
> set (this mapping) or via Class OPAQUE, and the operation namespace is pinned once a native
> OASF exchange is confirmed.

## 1. Scope

### 1.1 In scope

This document defines how an OASF record and its detached signature are carried over an
N-PAMP association as a capability/schema document. It pins, against OASF's own published
specification (§12), only the OASF specifics that NPAMP-CC-DOC leaves to a per-protocol
mapping:

- The OASF **protocol identifier** and its **PROVISIONAL** status, and the foreign-message
  `content_type` for a JSON record (§3);
- The **confirmed-versus-unconfirmed** boundary that makes this mapping OPAQUE-READY (§4);
- How an OASF **record** rides NPAMP-CC-DOC as the *document part* of a document set, and
  how the record's content digest and its Sigstore signature ride as the DOC *digest* and a
  DOC *detached proof* (§5);
- The **operation namespace** for requesting or advertising a record, and the fact that OASF
  supplies none natively (§6);
- The **SafetyLabel effect class** for serving and for any deployment-specific state-mutating
  record request, including the NPAMP-BRIDGE §7 fail-safe (§7); and
- **Channel selection** for OASF record carriage (§8).

The structural work — octet-exact carriage, the BridgeEnvelope, correlation, digest
stability, detached-proof binding, the structured-error model, and the safety-annotation
TLV — is done by NPAMP-BRIDGE and NPAMP-CC-DOC and is not restated here.

### 1.2 Not in scope

The following are explicitly NOT defined by this document:

- **The internal grammar of an OASF record.** The field set and taxonomy of the record —
  its `name`, `description`, `version`, `schema_version`, `authors`, `created_at`, `skills`,
  `domains`, `modules`, and `locators` — are fixed by OASF's own schema (§12). This document
  carries the record octet-for-octet (NPAMP-BRIDGE §1; NPAMP-CC-DOC §4) and does not parse,
  validate, canonicalize, or transform it.
- **OASF's exchange and storage substrate.** OASF records are stored, discovered, and
  transported by the separate **Agent Directory Service (ADS)** using the OCI Distribution
  protocol over HTTP, content-addressed identifiers (CIDs), Sigstore signing, and a DHT, and
  by the OASF HTTP schema server and the Directory MCP server (§12). None of these is an
  OASF-native wire protocol, and none is carried by this mapping; this mapping carries the
  **record document itself**, not the ADS/OCI transport around it (§4, §6).
- **A native OASF method/operation namespace.** OASF defines none (§4, §6); the document
  request/advertise operation of §6 is a NPAMP-CC-DOC operation named by this mapping, not an
  OASF method, and is marked provisional.
- **The Protobuf encoding of a record.** OASF also publishes Protobuf schema definitions for
  records. This mapping pins the **JSON** record encoding (`content_type = 0x01`, §3); a bare
  Protobuf record encoding has no confirmed BridgeEnvelope `content_type` and is not mapped
  here.
- **Verification of a record's signature or CID on behalf of an endpoint.** NPAMP-CC-DOC
  delivers the record and its detached proof with the integrity guarantees a verifier needs
  and assigns the verification act to the consumer (NPAMP-CC-DOC §6.5); this mapping does not
  verify Sigstore material or recompute a CID for an endpoint.
- **Any change to NPAMP-BRIDGE, to NPAMP-CC-DOC, or to the core wire format**, including the
  BridgeEnvelope TLV, the SafetyLabel TLV, and the DocumentBinding TLV, all used as their
  defining documents specify.

## 2. Relationship to NPAMP-CC-DOC and NPAMP-BRIDGE

This document is a registration plus a thin mapping, in the sense of the companion index: it
names a `protocol_id`, the carriage class it uses (DOC), the OASF unit it carries (the
record), and OASF-specific facts, and it lets NPAMP-CC-DOC do the structural work.

| Facility | Owning document | Use here |
|---|---|---|
| `protocol_id` (OASF, **PROVISIONAL**, experimental range) | NPAMP-BRIDGE §4; Bridge Protocol Identifier registry (NPAMP-REG §4, §7) | The identifier an OASF Bridge frame carries (§3). |
| Document carriage | NPAMP-CC-DOC | Carriage of an OASF record as a document set and its detached signature (§5). |
| DocumentBinding TLV | NPAMP-CC-DOC §6 | Binds the record to its digest and to its detached proof (§5). |
| BridgeEnvelope / SafetyLabel TLVs | Core specification; NPAMP-BRIDGE | Carried unchanged on every OASF frame (§3, §7). |
| Channel `0x000D` (Bridge), `0x0010` (Discovery) | Core specification | Carriage channels for OASF documents (§8). |

Because NPAMP-CC-DOC carries a document octet-for-octet and never re-serializes it
(NPAMP-CC-DOC §4), the carriage is robust to OASF schema-version changes: a receiver selects
the foreign protocol solely by `protocol_id` (NPAMP-REG §9) and delivers the record's exact
bytes regardless of the record's internal `schema_version`. Where this document and
NPAMP-CC-DOC could appear to differ on a structural matter, NPAMP-CC-DOC governs.

## 3. Protocol identifier and content type

| Property | Value |
|---|---|
| Protocol | Open Agentic Schema Framework (OASF). |
| `protocol_id` | **PROVISIONAL.** OASF has **no** standards-assigned code point in NPAMP-REG §6 (which assigns only `0x01`–`0x04`). Until one is assigned under NPAMP-REG §8 (Specification Required), an OASF deployment that carries records natively MUST use a code point from the **experimental range `0x10`–`0x7F`** (NPAMP-REG §7.1) by out-of-band agreement. This document uses **`0x1A`** as its provisional reference value; it carries no cross-domain meaning and is **not** a standards assignment. |
| Carriage class | DOC (NPAMP-CC-DOC). |
| `content_type` | `0x01` (application/json) for a JSON OASF record (§1.2 excludes the Protobuf encoding). |
| Foreign-message form | A single OASF record document (or a detached proof over it), carried octet-for-octet as the foreign message (NPAMP-BRIDGE §1; NPAMP-CC-DOC §4). |

Requirements:

- A sender MUST NOT emit the provisional `0x1A` (or any experimental value) toward a peer
  with which it has no out-of-band agreement on that value's meaning; a receiver with no such
  agreement MUST treat it as an uncarried protocol and return `ProtocolUnsupported`
  (NPAMP-REG §7.1, §9).
- When OASF obtains a standards-assigned `protocol_id` under NPAMP-REG §8, that value
  supersedes `0x1A`, and a deployment SHOULD retire the experimental value (NPAMP-REG §7.1).
- A receiver MUST select OASF solely from `protocol_id`, never inferring it from
  `content_type`, `method`, or any other envelope field (NPAMP-REG §9).

## 4. Mapping maturity: confirmed versus unconfirmed (OPAQUE-READY)

This mapping is **OPAQUE-READY**: the OASF *document model* is confirmed and pinned, while the
*transport and operation* dimension is not native to OASF and is left provisional. The
boundary is stated explicitly so an implementer relies on nothing unverified.

**Confirmed from OASF's published specification (§12), and pinned here:**

- OASF is a **schema / document framework** whose unit of interoperation is the **record**, a
  self-describing JSON capability/metadata document (§5).
- A record's public top-level fields are `name`, `description`, `version`, `schema_version`,
  `authors`, `created_at`, `skills`, `domains`, `modules`, and `locators`; `schema_version`
  is a semantic-versioning string (currently `1.0.0`).
- Records are **serialized as JSON** (a Protobuf schema also exists; §1.2).
- In OASF's exchange substrate (ADS), a record is **content-addressed** by a SHA-256 digest
  rendered as a CID, and is **signed** by Sigstore, the signature stored as a **detached**
  artifact (an OCI referrer) over the record's exact octets. These map onto NPAMP-CC-DOC's
  digest (§5) and detached proof (§5) respectively.

**Not defined by OASF, and therefore left provisional here:**

- OASF defines **no native request/response wire protocol, API endpoint, or method
  namespace**. Records are documents exchanged by other services (ADS over OCI/HTTP; the OASF
  HTTP schema server; the Directory MCP server; SLIM for agent-to-agent messaging), not by an
  OASF protocol. The document-request operation of §6 is consequently a NPAMP-CC-DOC operation
  named by this mapping, not an OASF operation.
- OASF has **no standards-assigned N-PAMP `protocol_id`** (§3) and **no registered media type
  string** of its own; the JSON encoding maps to `content_type = 0x01` (§3).

Until a native OASF exchange protocol is confirmed, an OASF record is carriable today (a) as
an NPAMP-CC-DOC document set under this mapping, or (b) via Class OPAQUE (NPAMP-CC-OPAQUE)
under a private-use `protocol_id`. Both carry the record's exact octets; neither depends on an
OASF transport that does not exist.

## 5. The OASF record as an NPAMP-CC-DOC document

An OASF record is a capability/schema document and is carried as the **document part** of an
NPAMP-CC-DOC document set (NPAMP-CC-DOC §1, §2, §7). Its detached Sigstore signature, where
present, is carried as a **detached-proof part** of the same set (NPAMP-CC-DOC §6).

- **Octet exactness.** The record MUST be delivered byte-identical to the octets over which
  its digest and signature were computed (NPAMP-CC-DOC §4). An implementation MUST NOT
  re-serialize, re-indent, canonicalize, minify, alter Unicode form, or change line endings.
  This is load-bearing: OASF's content-addressed identifier is a SHA-256 digest of the exact
  record bytes, and the Sigstore signature is over those same bytes, so any alteration breaks
  both the CID recomputation and the signature (§4).
- **DocumentBinding.** Each record part and each proof part MUST carry a DocumentBinding TLV
  (NPAMP-CC-DOC §6.1). The `part_kind` is `0x01` for the record and `0x02` for a detached
  proof; `doc_content_type` for the record part is the record's JSON media type; `digest_alg`
  names the digest the producer asserts over the record octets, and `digest` is that value
  (NPAMP-CC-DOC §6.2).
- **Digest stability.** A consumer MUST recompute the record digest over the recovered record
  octets and compare it, constant-time, against the asserted `digest` before treating any
  proof as applicable (NPAMP-CC-DOC §5). OASF/OCI content addressing uses **SHA-256**; the
  DOC `digest_alg` identifier for SHA-256 is assigned by the registry companion, not by this
  document (NPAMP-CC-DOC §6.4). A record whose recomputed digest does not match MUST be
  rejected with `DigestMismatch` and MUST NOT be presented as verified (NPAMP-CC-DOC §5, §8).
- **Signature as a detached proof.** An OASF Sigstore signature is a keyless (OIDC-based)
  signature bundle with transparency-log provenance, stored detached from the record. It is
  carried as a detached-proof part bound to the record by `correlation_id`, `doc_id`, and the
  digest triple (NPAMP-CC-DOC §6.3). Its `proof_alg` names a proof scheme **not** expressible
  as a bare core signature code point (it is a transparency-log/key-binding style proof); such
  a `proof_alg` identifier is assigned by the registry companion and is out of scope here
  (NPAMP-CC-DOC §6.4). A consumer that does not recognize it MUST report `ProofUnsupported`
  and MUST NOT treat the record as unsigned (NPAMP-CC-DOC §6.4, §8). **Verification is the
  consumer's act** (NPAMP-CC-DOC §6.5); carriage delivery of the signature is not verification
  of it.
- **Atomicity.** A consumer MUST assemble the document set by `correlation_id` and `doc_id`,
  MUST accept the proof part before or after the record part, and MUST NOT present the set as
  advertised until it is complete and the digest matches (NPAMP-CC-DOC §7.3, §7.5).

## 6. Operation namespace and frame mapping

OASF supplies **no native method/operation namespace** (§4). Record carriage therefore uses
the NPAMP-CC-DOC pull and push patterns unchanged:

- **Pull.** A consumer MAY request a record with a `BRIDGE_REQUEST` (`0x0100`) whose `method`
  names the requested record or record family (NPAMP-CC-DOC §7.1). Because OASF defines no such
  method, the `method` token is a **provisional** NPAMP-CC-DOC operation name fixed by this
  mapping (for example, an OASF-record retrieval operation identified by the record `name` and
  `version`), not an OASF method; it is advisory routing metadata only and carries no OASF
  semantics. The producer replies with the record part and any proof parts as
  `BRIDGE_RESPONSE` (`0x0101`), or as `BRIDGE_STREAM_DATA` (`0x0104`) / `BRIDGE_STREAM_END`
  (`0x0105`) for a large record, all echoing the request's `correlation_id` (NPAMP-CC-DOC
  §7.1, §7.4). A pull `BRIDGE_REQUEST` carries no document part and MUST NOT carry a
  DocumentBinding TLV (NPAMP-CC-DOC §6.1, §7.1).
- **Push.** A producer MAY advertise a record unsolicited. A single record with no detached
  proof MAY be carried as one `BRIDGE_NOTIFY` (`0x0103`) with `corr_len = 0` and
  `proof_count = 0` (NPAMP-CC-DOC §7.2). A record **with** a detached signature, or one large
  enough to stream, needs a shared `correlation_id` and MUST be carried under a
  `BRIDGE_REQUEST`-opened correlation per NPAMP-CC-DOC §7.2.
- A receiver that does not carry OASF MUST return `ProtocolUnsupported` for a `BRIDGE_REQUEST`
  bearing the OASF `protocol_id` (NPAMP-BRIDGE §6; NPAMP-REG §9), and MUST NOT report success
  for a record it did not deliver (NPAMP-CC-DOC §8).

When a native OASF exchange protocol is confirmed, the provisional `method` names above are
replaced by that protocol's operation namespace; the record-as-document carriage of §5 is
unaffected.

## 7. SafetyLabel and effect classes

Serving or advertising an OASF record is, by nature, an advertisement: it is **`read_only`**
under the NPAMP-BRIDGE SafetyLabel model (NPAMP-BRIDGE §7; NPAMP-CC-DOC §9). A producer serving
a record SHOULD attach a SafetyLabel TLV (Type `0x0013`) with `effect = 0x00` read_only to the
record part.

| OASF operation | `effect` (NPAMP-BRIDGE §7) | Rationale |
|---|---|---|
| Serve / advertise a record (pull reply or push, §6) | `0x00` read_only | Delivers an existing capability document; acts on no external state. |
| Request a record (pull `BRIDGE_REQUEST`, §6) | `0x00` read_only | A plain read of an existing record. |
| A deployment-specific request that **mutates** state — for example one that causes the producer to **generate, register, re-sign, or content-address** a fresh record on demand | `0x02` non_idempotent_write (at minimum; `0x03` destructive if it overwrites) | Produces new, signed, content-addressed state; each invocation is a fresh action. |

Requirements:

- Where a record request is itself state-mutating in a particular deployment, the requester
  MUST attach a SafetyLabel describing that effect to the `BRIDGE_REQUEST` (NPAMP-CC-DOC §9).
- A receiver MUST NOT treat the **absence** of a SafetyLabel on a state-mutating record
  request as `read_only`; absence on such a request MUST be treated as `destructive`
  (fail-safe; NPAMP-BRIDGE §7; NPAMP-CC-DOC §9).
- The SafetyLabel describes intent and does not replace the producer's authorization decision,
  and it does not replace the record's own detached signature, which carries the record's
  authenticity independently of any transport annotation (NPAMP-CC-DOC §9).

## 8. Channel selection

| OASF traffic class | Carriage | Channel |
|---|---|---|
| OASF record document set (record + detached proof) | NPAMP-CC-DOC | Bridge `0x000D` default; SHOULD use Discovery `0x0010` where records are published as capability advertisements |

Because an OASF record is precisely a "capability advertisement" document, the Discovery
channel `0x0010` — whose core-specified purpose is "agent, tool, and service discovery and
capability advertisement" — is the natural channel for it (NPAMP-CC-DOC §1.1, §3; companion
index, "Channel selection for carriage"). A record and its detached proofs MUST NOT be split
across the Bridge and Discovery channels; every frame of one document set MUST ride the same
channel, and a consumer MUST treat identical `correlation_id`s on two channels as unrelated
(NPAMP-CC-DOC §3). The Bridge channel `0x000D` and the Discovery channel `0x0010` are both
minimum-profile **Standard** (core specification channel registry); OASF carriage requires no
channel above the Standard profile. A peer MUST NOT send or accept OASF frames on a channel it
did not advertise during the handshake (core specification §5).

## 9. Code points consumed

This mapping consumes only code points that the core specification, NPAMP-BRIDGE, and
NPAMP-CC-DOC already define. It defines no new frame type, no new TLV, and no change to the
core wire format.

| Resource | Origin | Use here |
|---|---|---|
| `protocol_id` (OASF, **PROVISIONAL** `0x1A`, experimental) | NPAMP-REG §4, §7.1 | The OASF identifier on an OASF Bridge/Discovery frame (§3). Not a standards assignment. |
| `content_type` `0x01` (application/json) | NPAMP-BRIDGE §4 | The JSON OASF-record foreign-message encoding (§3). |
| Channel `0x000D` (Bridge) | Core specification | Default channel for OASF document carriage (§8). |
| Channel `0x0010` (Discovery) | Core specification | Recommended channel for OASF record advertisement (§8). |
| Bridge frame types `0x0100`–`0x0105` | NPAMP-BRIDGE §2 | Reused unchanged for request/response/notify/stream (§6). |
| BridgeEnvelope TLV `0x0010`, SafetyLabel TLV `0x0013` | Core specification; NPAMP-BRIDGE | Carried unchanged (§3, §7). |
| DocumentBinding TLV (NPAMP-CC-DOC §6, Type `0xTBD-DOCBIND` **provisional**) | NPAMP-CC-DOC | Record-to-digest-to-proof binding metadata (§5). Its provisional status is inherited from NPAMP-CC-DOC and not resolved here. |

This document requests no IANA action and defines no registry. The DOC `digest_alg` identifier
for SHA-256 and the `proof_alg` identifier for the OASF Sigstore proof scheme are assigned by
the registry companion, not here (NPAMP-CC-DOC §6.4).

## 10. Version considerations and marked uncertainties

OASF is a versioned, evolving specification. The following facts are marked so an implementer
confirms them against the exact OASF version they target rather than relying on a single
spelling:

1. **OASF release and record `schema_version`.** The latest OASF release at the time of
   writing is **v1.0.1** (2026-03-06, §12); the record `schema_version` in the current schema
   is **`1.0.0`** (semantic versioning). Because §5 carries the record octet-for-octet and
   selects nothing on its internal fields, a newer or older OASF record is carried without a
   change to this mapping.
2. **No native transport (the reason this mapping is OPAQUE-READY).** OASF defines only the
   record schema; multiple independent sources confirm it defines no network transport or wire
   protocol of its own (§12). The operation names of §6 are consequently NPAMP-CC-DOC
   operations named by this mapping, **not** OASF methods, and are provisional. An implementer
   MUST NOT treat them as an OASF-defined API.
3. **Provisional `protocol_id`.** OASF has no standards-assigned Bridge `protocol_id` (§3).
   The value `0x1A` is a provisional experimental reference; an implementer MUST confirm the
   assigned value once OASF is registered under NPAMP-REG §8 and MUST NOT rely on `0x1A` for
   cross-domain interoperation (NPAMP-REG §7.1).
4. **Signature/CID algorithm identifiers.** The SHA-256 content digest and the Sigstore proof
   scheme are OASF/ADS facts; their DOC `digest_alg`/`proof_alg` identifiers are assigned
   elsewhere (§9), and an implementer MUST confirm them against the registry companion rather
   than assuming a value here.

No value in this document is asserted beyond what §12's sources support; where a fact was
transport-dependent or not defined by OASF, it is marked provisional above rather than fixed by
assumption.

## 11. Security considerations

This mapping introduces no cryptography and changes none. All confidentiality, integrity,
authentication, downgrade resistance, and replay protection are provided by the core
specification's wire format and key schedule and apply unchanged to every OASF frame, which
travels inside the AEAD-protected Bridge (or Discovery) payload; the `protocol_id`, the
DocumentBinding metadata, the SafetyLabel, and the OASF record are authenticated and
confidentiality-protected to the same degree.

Carrying OASF over N-PAMP makes no security claim about OASF itself. In particular:

- **Record authenticity is independent of transport.** An OASF record's own Sigstore
  signature (§5), verified by the consumer under NPAMP-CC-DOC, and its SHA-256/CID content
  address carry the record's authenticity and integrity independently of N-PAMP. Carriage
  delivery of a proof is **not** verification of it (NPAMP-CC-DOC §6.5); a consumer MUST
  recompute the digest and SHOULD verify the signature before relying on a record.
- **Octet preservation is a security property here.** Because the CID and the signature are
  computed over the record's exact bytes, the octet-preservation rule of NPAMP-CC-DOC §4 is
  what lets a consumer detect tampering; an implementation that cannot guarantee it MUST refuse
  the set with `DigestUnstable` rather than deliver octets a verifier could not reproduce
  (NPAMP-CC-DOC §4, §8).
- **Provisional identifiers carry no cross-domain meaning.** The experimental `protocol_id` of
  §3 is meaningful only under out-of-band agreement; a receiver MUST treat an unrecognized
  experimental value as uncarried (NPAMP-REG §7.1, §9), never guessing OASF from another
  envelope field.
- **Safety fail-safe.** The effect classification of §7 and the NPAMP-BRIDGE §7 fail-safe
  (absence of a SafetyLabel on a state-mutating request is `destructive`) apply to every OASF
  record request; advertisement of a record is a claim, not authorization.

## 12. References

Primary source (OASF specification — consulted for §3, §4, §5, §7, §10):

- Open Agentic Schema Framework — overview and concepts (the record object; skills, domains,
  modules; OCSF derivation) — <https://docs.agntcy.org/oasf/open-agentic-schema-framework/>
- OASF Record Guide (the record's top-level fields — `name`, `description`, `version`,
  `schema_version`, `authors`, `created_at`, `skills`, `domains`, `modules`, `locators` — the
  JSON encoding, `schema_version` semantic-versioning format, and confirmation that OASF
  defines no request/response protocol of its own) —
  <https://docs.agntcy.org/oasf/agent-record-guide/>
- OASF repository (JSON schema files and Protobuf definitions; derivative of the OCSF schema
  server; releases) — <https://github.com/agntcy/oasf>
- OASF releases (latest release v1.0.1, 2026-03-06) — <https://github.com/agntcy/oasf/releases>
- OASF hosted schema server (the latest released schema) — <https://schema.oasf.outshift.com/>

Exchange/transport substrate (confirming OASF is the schema layer and the transport is a
*separate* concern — consulted for §1.2, §4, §5):

- Agent Directory Service (ADS) specification — the OCI Distribution transport over HTTP,
  SHA-256 content addressing rendered as CIDs, Sigstore keyless (OIDC) signing with signatures
  stored as detached OCI referrer artifacts, and DHT discovery; OASF is named as the data-model
  layer — <https://www.ietf.org/archive/id/draft-mp-agntcy-ads-00.html>
- Agent Directory Service overview — <https://docs.agntcy.org/dir/overview/>

N-PAMP documents built on:

- draft-bubblefish-npamp-01 — the N-PAMP core specification: the frame format, the channel
  registry (Bridge `0x000D`, Discovery `0x0010`), the frame-type namespace (channel-specific
  types from `0x0100`), the extension-TLV encoding, and the AEAD payload protection.
- NPAMP-BRIDGE (`10_bridge_framework.md`) — the encapsulation, BridgeEnvelope, correlation,
  structured-error, and SafetyLabel contract.
- NPAMP-CC-DOC (`24_carriage_documents.md`) — the capability/schema document carriage class
  that does the structural work for OASF.
- NPAMP-CC-OPAQUE (`25_carriage_opaque.md`) — the universal carriage referenced in §4 as the
  present-day alternative.
- NPAMP-REG (`30_protocol_registry.md`) — the Bridge Protocol Identifier registry: the absence
  of an OASF assignment, the experimental range, and the registration procedure (§3).
- NPAMP-DISC (`40_discovery.md`) — Discovery-channel advertisement referenced in §8.
- BCP 14 (RFC 2119, RFC 8174) — requirement key words.

## 13. Conformance

An implementation conforms to NPAMP-MAP-OASF if and only if it conforms to NPAMP-BRIDGE and
NPAMP-CC-DOC for the frames it emits and parses in this mapping, and, for OASF traffic, it:

1. Carries OASF records under a single `protocol_id`, using a standards-assigned value once one
   exists and otherwise an experimental value (this document's provisional `0x1A`) only under
   out-of-band agreement, never as a cross-domain default, with `content_type = 0x01` for a
   JSON record, and selects OASF solely from `protocol_id` (§3);
2. Carries an OASF record as the octet-for-octet **document part** of an NPAMP-CC-DOC document
   set, performing no canonicalization, re-serialization, or transcoding, and refuses with
   `DigestUnstable` any set whose octet preservation it cannot guarantee (§5; NPAMP-CC-DOC §4);
3. Emits and parses a well-formed DocumentBinding descriptor on every record and proof part,
   recomputes the record digest over the recovered octets with a constant-time comparison, and
   rejects a mismatch with `DigestMismatch` without presenting the record as verified (§5;
   NPAMP-CC-DOC §5, §6);
4. Carries an OASF Sigstore signature as a **detached proof** bound to the record by
   `correlation_id`, `doc_id`, and digest triple, reports an unbound proof as `ProofUnbound`
   and an unrecognized proof scheme as `ProofUnsupported` rather than treating the record as
   unsigned, and leaves signature verification to the consumer (§5; NPAMP-CC-DOC §6);
5. Uses the NPAMP-CC-DOC pull and push patterns for record request and advertisement, treats
   the `method` token as a provisional, advisory NPAMP-CC-DOC operation name rather than an
   OASF method, and does not claim an OASF-native transport or operation namespace (§4, §6);
6. Attaches `effect = read_only` when serving or requesting an existing record, attaches a
   SafetyLabel describing the effect of any deployment-specific state-mutating record request,
   and treats a missing SafetyLabel on such a request as `destructive` (§7; NPAMP-BRIDGE §7);
7. Carries an OASF record document set on the Bridge channel `0x000D` or the Discovery channel
   `0x0010`, never splitting a record and its proofs across the two channels, and sends or
   accepts OASF frames only on channels advertised during the handshake (§8); and
8. Defines no new frame type, TLV, or code point, consuming only those enumerated in §9,
   inheriting the provisional status of the DocumentBinding TLV and of the OASF `protocol_id`
   without resolving either here (§9, §10).

A conformance test suite SHOULD assert each clause above with recorded exchanges that include:
A single-frame OASF record advertised with no detached proof as a `BRIDGE_NOTIFY`; a pulled
OASF record carried with one detached Sigstore signature proof bound by `doc_id` and digest; a
deliberately altered record octet that MUST produce `DigestMismatch`; an unbound proof that
MUST produce `ProofUnbound`; a state-mutating record request carrying a `non_idempotent_write`
SafetyLabel and a second such request with the SafetyLabel omitted, verified to be treated as
`destructive`; and the same record document set carried on both the Bridge and the Discovery
channel, verified never to be split across them.
