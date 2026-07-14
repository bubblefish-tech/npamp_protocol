# NPAMP-MEMORY — Memory-Channel Operation Framework (companion to draft-bubblefish-npamp-02)

> Status: **DRAFT companion specification.** The key words MUST, MUST NOT,
> REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL
> are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only
> when, they appear in all capitals, as shown here. This document defines a
> **native** operation framing for the N-PAMP **Memory channel `0x0001`**: the
> frame types, the deterministic-CBOR operation bodies, the in-body correlation
> discipline, the operation and state model, and the structured error model by
> which one peer manages durable, addressable memory records held by another peer.
> It builds on the core specification (draft-bubblefish-npamp-02) and does not
> redefine it. Unlike a Bridge carriage class, the Memory channel carries no
> foreign protocol: the operation body **is** N-PAMP's own encoding, so this
> document consumes no extension-TLV code point. It introduces no change to the
> core wire format.

## 1. Scope

### 1.1 In scope

This document specifies, over the Memory channel `0x0001` of the N-PAMP core
specification (the "core specification", draft-bubblefish-npamp-02):

1. A set of Memory-channel frame types, drawn from the channel-specific
   application band that begins at `0x0100` (core specification §4.6,
   frame-type namespace), plus the two reserved companion-band code points
   `0x0035`–`0x0036` this document finally defines;
2. Per-operation request and response frame pairs realizing the five operation
   classes the core registry names for this channel — create, read, update,
   delete, and retrieval of persistent-state memory records — plus a store status
   query and an eviction/revive lifecycle pair;
3. The **deterministic-CBOR** encoding of every operation body (RFC 8949, core
   specification §4.5 and §11.9), keyed by unsigned integers;
4. An **in-body correlation** discipline that matches a reply to its request by a
   correlation token carried inside the CBOR body — consuming no shared TLV tag;
   and
5. A single structured **error frame** whose result set preserves a governance
   escalation (an operation held for approval and NOT executed) as a distinct,
   non-success outcome.

Operations are described generically — write, read, update, delete, list, and
retrieve memory records, plus a store status query — so that any store
implementation and any client interoperate over N-PAMP with no bespoke
adaptation. The document names no product, no vendor, and no application-specific
schema.

### 1.2 Not in scope

This document does NOT:

* **Define the internal representation of a memory record.** The record fields in
  §6 are the *wire* projection an implementation exposes; how a store persists,
  indexes, encrypts, or ranks records is a local matter this document does not
  constrain — it fixes only what crosses the wire.
* **Define a retrieval ranking or scoring algorithm.** A retrieval result is
  ranked best-first by the responder (§6.5); this document carries the ordered
  result and its provenance but assigns no ranking function, embedding model, or
  relevance metric, because those are implementation choices, not interoperability
  contracts.
* **Define authorization, governance, or admission policy.** Whether an operation
  is permitted, denied, or escalated for human approval is the responder's local
  decision; this document defines only how each of those outcomes is *reported*
  on the wire (§8), not the policy that produces them.
* **Define a query language.** Retrieval carries a free-text filter and a small
  set of structured scoping fields (§6.4); it defines no expression grammar,
  because a full query language would exceed a wire-interoperability contract and
  is better layered above this framing.
* **Carry a foreign agent protocol.** The Memory channel is native; it is not a
  Bridge carriage class and does not build on NPAMP-BRIDGE (core specification,
  Memory-channel interface reference). No frame in this document encapsulates a
  foreign message, and this document defines and consumes no extension-TLV tag.
* **Change the core wire format.** It alters no field of the core frame header, no
  reserved all-channel frame type, the extension-TLV encoding, or any code point
  the core specification assigns; it uses only code points the core specification
  reserves for the Memory channel.

## 2. Relationship to the core specification

The Memory channel `0x0001` is registered by the core specification with purpose
**"Persistent-state create/read/update/delete and retrieval"**, minimum profile
**Standard**, and direction **Multi-stream**. Under the core specification's
channel architecture every channel is full-duplex: each peer maintains an
independent per-direction sequence space and independent per-direction traffic
keys, and — because Memory is Multi-stream — a deployment MAY carry concurrent
Memory operations over multiple transport streams within the channel's stream
family. Either peer MAY originate a Memory operation.

**Minimum-profile gate.** A peer MUST enable the Memory channel only at the
**Standard** profile or higher; once Standard is met the channel is available at
Standard, High, and Sovereign, and there is no profile at which it becomes
unavailable. A peer that has not advertised the Memory channel during the
handshake (core specification §5) MUST NOT receive frames on it; a frame arriving
on an unadvertised Memory channel MUST be dropped and MUST NOT be delivered to a
memory store.

**Native, not a carriage class.** A Bridge carriage class carries a *foreign*
protocol's message octet-for-octet and wraps routing and correlation metadata
*around* it in a shared extension TLV. The Memory channel has no foreign protocol:
the operation body is N-PAMP's own deterministic-CBOR encoding, and this document
owns that body in full. Consequently the correlation token, the operation
semantics, and the error object all live **inside** the CBOR body, and this
document reserves and consumes **no extension-TLV code point**. This is the
deliberate structural difference from NPAMP-BRIDGE and is the reason a Memory
operation is routed by its N-PAMP **frame type** (§3) rather than by any
method-name or tool-name field parsed from a body.

**Frame-type namespace bands.** The core specification partitions each channel's
`0x0000`–`0xFFFF` frame-type space into four bands (core specification §4.6,
Frame-Type Namespace): `0x0000`–`0x000A` reserved all-channel frame types with the
same meaning on every channel; `0x000B`–`0x002F` unassigned, reserved to the core
for future all-channel additions; `0x0030`–`0x00FF` the **companion-extension
band**, per-channel extension frame types defined by companion specifications; and
`0x0100`–`0xFFFF` **channel-specific application** frame types. This document
places its operational frames in the application band at `0x0100`+ on the Memory
channel, and additionally defines the two Memory reserved-range code points
`0x0035`–`0x0036` that sit in the companion-extension band (§3.3). Because the
frame-type space is scoped by the Channel ID header field, these code points do
not collide with any other channel's assignments at the same numeric values.

## 3. Memory-channel frame types

Within the Memory channel (`0x0001`) frame-type namespace, this specification
defines seventeen frame types: fifteen in the channel-specific application band at
`0x0100`+, and two in the reserved companion-extension band at `0x0035`–`0x0036`.

### 3.1 Application-band operation frames (`0x0100`+)

| Type | Name | Reply | Purpose |
|---|---|---|---|
| `0x0100` | MEMORY_CREATE_REQ | MEMORY_CREATE_RESULT or MEMORY_ERROR | Write a new persistent-state memory record. |
| `0x0101` | MEMORY_CREATE_RESULT | None | Success reply to a create; echoes the request's correlation token. |
| `0x0102` | MEMORY_READ_REQ | MEMORY_READ_RESULT or MEMORY_ERROR | Return the current state of one identified memory record. |
| `0x0103` | MEMORY_READ_RESULT | None | Success reply to a read; carries the identified record. |
| `0x0104` | MEMORY_UPDATE_REQ | MEMORY_UPDATE_RESULT or MEMORY_ERROR | Change an existing memory record in place. |
| `0x0105` | MEMORY_UPDATE_RESULT | None | Success reply to an update. |
| `0x0106` | MEMORY_DELETE_REQ | MEMORY_DELETE_RESULT or MEMORY_ERROR | Remove a memory record, ending its persistence. |
| `0x0107` | MEMORY_DELETE_RESULT | None | Success reply to a delete. |
| `0x0108` | MEMORY_RETRIEVE_REQ | MEMORY_RETRIEVE_RESULT, MEMORY_RETRIEVE_STREAM_DATA, or MEMORY_ERROR | List/retrieve a ranked, provenance-bearing set of memory records. |
| `0x0109` | MEMORY_RETRIEVE_RESULT | None | A bounded ranked result set delivered in a single frame. |
| `0x010A` | MEMORY_RETRIEVE_STREAM_DATA | None | One page of a large ranked result set; `final` is not set. |
| `0x010B` | MEMORY_RETRIEVE_STREAM_END | None | Terminates a streamed retrieval; `final` is set. |
| `0x010C` | MEMORY_STATUS_REQ | MEMORY_STATUS_RESULT or MEMORY_ERROR | Query store health and advertised capabilities. |
| `0x010D` | MEMORY_STATUS_RESULT | None | Store health and capability reply. |
| `0x010E` | MEMORY_ERROR | None | Structured failure for any request; echoes the correlation token and carries a Memory error code (§8). |

A `*_REQ` frame originates an operation; the corresponding `*_RESULT` frame, or a
MEMORY_ERROR (`0x010E`), replies to it. A `*_RESULT` and a MEMORY_RETRIEVE_STREAM_*
frame are never sent unsolicited: each MUST echo the correlation token of the
request it answers (§5). A responder MUST NOT emit a `*_RESULT` and a MEMORY_ERROR
for the same request.

### 3.2 Reserved all-channel frame types

The reserved all-channel frame types (PING `0x0001`, PONG `0x0002`, CLOSE
`0x0003`, CLOSE_ACK `0x0004`, ERROR `0x0005`, KEY_UPDATE `0x0006`,
KEY_UPDATE_ACK `0x0007`, PATH_CHALLENGE `0x0008`, PATH_RESPONSE `0x0009`, and
FLOW_UPDATE `0x000A`; core specification §4.6) retain their core meaning on the
Memory channel. An implementation MUST NOT reuse them for Memory application
traffic and MUST NOT define Memory operation semantics in the reserved all-channel
range `0x0000`–`0x000A`.

### 3.3 Memory eviction and revive frames (`0x0035`–`0x0036`)

The core specification reserves the range `0x0035`–`0x0036` in the
companion-extension band specifically for Memory-channel **eviction and revive**
extension frames, and states that a companion specification may define them
(core specification, Extension Points, Reserved Frame-Type Ranges). This document
is that companion; it defines those two code points:

| Type | Name | Reply | Purpose |
|---|---|---|---|
| `0x0035` | MEMORY_EVICT | MEMORY_CREATE_RESULT-shaped result or MEMORY_ERROR | Mark an identified record evicted — soft-removed from active retrieval, retained so it can be revived. |
| `0x0036` | MEMORY_REVIVE | MEMORY_CREATE_RESULT-shaped result or MEMORY_ERROR | Restore a previously evicted record to active retrieval. |

These two code points sit in the `0x0030`–`0x00FF` companion-extension band and
are scoped to the Memory channel; an implementation MUST NOT assign them to any
purpose other than the eviction and revive operations defined here, and MUST NOT
treat eviction or revive as behavior defined by the core specification alone (the
core reserves the range; this companion defines it). Eviction and revive are
OPTIONAL to implement; a responder that does not implement them MUST reply
MEMORY_ERROR with code `unknown_operation` (§8).

All seventeen frame types defined above lie within the Memory channel's own
frame-type namespace: fifteen in the application band at or above `0x0100`, and
two in the companion-extension band reserved for this channel. This document
consumes no frame-type code point outside the Memory channel's namespace and
reserves none in the core specification's cross-channel reserved ranges.

## 4. Frame payload encoding

### 4.1 Payload container

A Memory frame's payload (the octets after the core frame header and any
extension TLVs, and before the AEAD tag) is a single **deterministically encoded
CBOR** object as defined by the core specification §4.5 and §11.9 (deterministic
CBOR, RFC 8949). The payload MUST be a CBOR map whose keys are the unsigned
integers defined in §4.2 and §5–§8 for the relevant frame type. A sender MUST
produce the deterministic encoding (core specification §11.9): byte-identical
output for identical inputs, with the canonical key ordering and shortest-form
integer encoding RFC 8949 §4.2 requires, and definite-length maps and arrays.

A receiver MUST reject, with MEMORY_ERROR code `malformed_request` (§8), any
Memory frame whose payload is not a valid deterministic-CBOR map, whose payload
omits a REQUIRED key for its frame type, or whose payload carries a key of the
wrong CBOR major type.

Memory operation bodies are carried in the frame **payload**, not in extension
TLVs. This document defines and consumes no extension-TLV tag, and therefore
claims none of the TLV code points the core specification reserves.

### 4.2 Common envelope fields

Every Memory payload map carries the following two envelope fields. Integer keys
are given in parentheses.

| Field (key) | CBOR type | Meaning |
|---|---|---|
| `frame_kind` (0) | Unsigned int | MUST equal the frame's Memory frame type (one of `0x0035`, `0x0036`, or `0x0100`–`0x010E`). A receiver MUST reject (MEMORY_ERROR, code `malformed_request`) a payload whose `frame_kind` contradicts the frame-header Frame Type. |
| `corr` (1) | Byte string (1–64 B) | Correlation token (§5). Present and non-empty on every `*_REQ`, on MEMORY_EVICT and MEMORY_REVIVE, and on every frame that replies to one of those. |

The per-frame body fields defined in §5–§8 occupy keys `2` and above within the
same map; §6 gives, per frame, the full field table.

### 4.3 Forward compatibility

A receiver MUST ignore an unrecognized integer key it encounters in a Memory
payload map whose key is **not negative**, so that a later revision of this
document MAY add fields without breaking a conformant receiver. A receiver MUST
reject (MEMORY_ERROR, code `malformed_request`) a payload that carries a
**negative** integer key it does not recognize, reserving the negative key space
for forward-incompatible additions. A receiver MUST NOT treat the mere presence of
an unknown non-negative key as an error, and MUST NOT alter its handling of the
keys it does recognize because of it.

## 5. Correlation and operation model

The core specification does not define how a Memory reply is correlated to its
request (unlike the Bridge channel, where NPAMP-BRIDGE §5 defines a correlation
identifier). This document supplies that discipline, carrying the token **inside**
the CBOR body rather than in a shared TLV, because a native channel owns its whole
body (§2).

### 5.1 Correlation discipline

* Every `*_REQ` frame (`0x0100`, `0x0102`, `0x0104`, `0x0106`, `0x0108`,
  `0x010C`) and each of MEMORY_EVICT (`0x0035`) and MEMORY_REVIVE (`0x0036`) MUST
  carry a non-empty `corr` (§4.2) that is unique among the originating peer's
  outstanding Memory requests on the channel in that direction.
* Every MEMORY_*_RESULT, every MEMORY_RETRIEVE_STREAM_DATA and
  MEMORY_RETRIEVE_STREAM_END, and every MEMORY_ERROR MUST echo the originating
  request's `corr` verbatim.
* A receiver MUST match a reply to its request by `corr`, **not** by the
  per-(channel, direction) frame sequence number. Because the Memory channel is
  Multi-stream, concurrent operations may be carried across multiple transport
  streams, where sequence order within any one stream does not identify the
  originating exchange.

### 5.2 Correlation lifetime

A `corr` value associated with a single-reply operation (create, read, update,
delete, status, evict, revive) is consumed when its `*_RESULT` or MEMORY_ERROR is
delivered; the requester MUST treat that exchange as complete and MUST NOT reuse
the value for a new request while the original is outstanding. A `corr` value
associated with a retrieval remains live until the retrieval terminates — with a
single MEMORY_RETRIEVE_RESULT, or with a MEMORY_RETRIEVE_STREAM_END, or with a
MEMORY_ERROR (§7).

### 5.3 Side-effect class (`effect`)

Every state-mutating request — MEMORY_CREATE_REQ, MEMORY_UPDATE_REQ,
MEMORY_DELETE_REQ, MEMORY_EVICT, and MEMORY_REVIVE — MUST carry an `effect` field
(§6) declaring the most severe side effect the operation may cause, drawn from the
side-effect classes below. It is the native-body analogue of a Bridge SafetyLabel,
carried in-body because the Memory channel owns its body (§2).

| Value | Name | Meaning |
|---|---|---|
| `0x00` | read_only | No state change (retrieval and read requests). |
| `0x01` | idempotent_write | A write whose repetition yields the same state (for example an update or a revive). |
| `0x02` | non_idempotent_write | A write that is not safely repeatable (for example a create). |
| `0x03` | destructive | An operation that removes or evicts state (delete and evict). |

**Fail-safe.** A receiver MUST treat a state-mutating request that omits `effect`,
or carries an `effect` value it does not recognize, as `destructive`, and MAY
refuse it (MEMORY_ERROR). A requester MUST NOT rely on a mutating request that
omits `effect` being executed. A read-only request (MEMORY_READ_REQ,
MEMORY_RETRIEVE_REQ, MEMORY_STATUS_REQ) carries `effect` = `read_only`.

## 6. Operation bodies

Each operation body is a deterministic-CBOR map carrying the common envelope
(§4.2, keys `0`–`1`) and the per-frame fields below at keys `2`+. Unless a field
is marked required, it is OPTIONAL and, when absent, carries no value (a producer
omits the key rather than encoding a null placeholder; a producer that does encode
an explicit CBOR `null` for an absent OPTIONAL field is equivalent to omitting it).

### 6.1 MEMORY_CREATE_REQ (`0x0100`) / MEMORY_CREATE_RESULT (`0x0101`)

Write a new persistent-state memory record.

**MEMORY_CREATE_REQ body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `content` (2) | Text string | Yes | The record's content to persist. |
| `source` (3) | Text string | No | Provenance: the origin the content is attributed to. |
| `subject` (4) | Text string | No | Provenance: the entity the content is about. |
| `destination` (5) | Text string | No | The logical store or namespace the record is written to. |
| `collection` (6) | Text string | No | A named grouping within the store. |
| `actor_type` (7) | Text string | No | The kind of actor writing the record (for example `user`, `agent`, or `system`). |
| `actor_id` (8) | Text string | No | An opaque identifier of the writing actor within the requester's namespace. |
| `idempotency_key` (9) | Text string | No | A caller-supplied key that lets the store de-duplicate a retried create. When absent, the responder MAY derive one from the request content. |
| `scope` (10) | Map | No | Isolation scope for the record (for example a workspace or enclave scoping map). Its keys are a local matter; the responder MUST persist it with the record so isolation survives. |
| `effect` (11) | Unsigned int | Yes | Side-effect class (§5.3). A create is normally `0x02` non_idempotent_write. |

**MEMORY_CREATE_RESULT body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `record_id` (2) | Text string | Yes | The identifier the store assigned to the newly written record. |
| `status` (3) | Text string | Yes | A short accepted-state token for the write (for example `accepted`). |

A create that the responder holds for human approval, rather than executing, is
NOT reported as a MEMORY_CREATE_RESULT; it is reported as MEMORY_ERROR with code
`approval_required` (§8). A responder MUST NOT emit a MEMORY_CREATE_RESULT for a
record that did not enter the store.

### 6.2 MEMORY_READ_REQ (`0x0102`) / MEMORY_READ_RESULT (`0x0103`)

Return the current state of one identified record — the point-read the registry
distinguishes from multi-item retrieval.

**MEMORY_READ_REQ body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `record_id` (2) | Text string | Yes | The record to read. |
| `effect` (3) | Unsigned int | Yes | Side-effect class (§5.3); MUST be `0x00` read_only. |

**MEMORY_READ_RESULT body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `record` (2) | Map (a `memory_record`, §6.5) | Yes | The identified record with its provenance. |

A read of an absent record is reported as MEMORY_ERROR with code `not_found` (§8),
not as an empty MEMORY_READ_RESULT.

### 6.3 MEMORY_UPDATE / MEMORY_DELETE

**MEMORY_UPDATE_REQ (`0x0104`) body** — the create body (§6.1, keys `2`–`10`) plus
a required `record_id`, changing an existing record in place.

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `record_id` (2) | Text string | Yes | The record to change. |
| `content` (3) | Text string | No | Replacement content (absent leaves content unchanged). |
| `source` (4) | Text string | No | Replacement provenance origin. |
| `subject` (5) | Text string | No | Replacement provenance subject. |
| `collection` (6) | Text string | No | Replacement grouping. |
| `actor_type` (7) | Text string | No | Actor kind performing the update. |
| `actor_id` (8) | Text string | No | Actor identifier performing the update. |
| `scope` (9) | Map | No | Replacement isolation scope. |
| `effect` (10) | Unsigned int | Yes | Side-effect class (§5.3); `0x01` idempotent_write, or `0x02` where repetition is not safe. |

**MEMORY_UPDATE_RESULT (`0x0105`) body** — `{ record_id (2): tstr, status (3): tstr }`,
shaped as the create result (§6.1).

**MEMORY_DELETE_REQ (`0x0106`) body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `record_id` (2) | Text string | Yes | The record to remove. |
| `effect` (3) | Unsigned int | Yes | Side-effect class (§5.3); MUST be `0x03` destructive. |

**MEMORY_DELETE_RESULT (`0x0107`) body** — `{ record_id (2): tstr, status (3): tstr }`.
A delete of an absent record is reported as MEMORY_ERROR `not_found` (§8).

### 6.4 MEMORY_RETRIEVE_REQ (`0x0108`)

List/retrieve a ranked, provenance-bearing set of records.

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `query` (2) | Text string | No | Free-text filter. Absent requests every record within the other scoping filters. |
| `source` (3) | Text string | No | Restrict to records with this provenance origin. |
| `subject` (4) | Text string | No | Restrict to records with this provenance subject. |
| `destination` (5) | Text string | No | Restrict to records in this store or namespace. |
| `collection` (6) | Text string | No | Restrict to records in this grouping. |
| `limit` (7) | Unsigned int | No | Maximum records to return. Absent or `0` means the responder's default page size. |
| `profile` (8) | Text string | No | A retrieval-effort selector interpreted by the responder (for example `fast`, `balanced`, `deep`). Advisory; it does not change the result schema. |
| `cursor` (9) | Byte string | No | An opaque continuation token from a prior result's `next_cursor` (§6.5), requesting the next page. |
| `effect` (10) | Unsigned int | Yes | Side-effect class (§5.3); MUST be `0x00` read_only. |

Scoping fields are conjunctive: a record is returned only if it satisfies every
present filter. A responder MUST NOT silently ignore a scoping field it does not
support and return an over-broad result; if it cannot honor a present filter it
MUST reply MEMORY_ERROR `malformed_request` rather than mislead the requester into
acting on records that do not satisfy the constraint it asked for.

### 6.5 MEMORY_RETRIEVE_RESULT (`0x0109`) and the `memory_record`

A bounded ranked result set, delivered in a single frame.

**MEMORY_RETRIEVE_RESULT body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `records` (2) | Array of `memory_record` | Yes | The matching records, ranked best-first (possibly empty). |
| `has_more` (3) | Boolean | Yes | True if more records match than are carried here. |
| `next_cursor` (4) | Byte string | No | Present when `has_more` is true: an opaque token a requester echoes as `cursor` (§6.4) to fetch the next page. |
| `retrieval_stage` (5) | Unsigned int | No | An advisory indicator of which retrieval stage answered (for example an exact-match stage versus a semantic stage). |
| `semantic_unavailable` (6) | Boolean | No | True if a semantic-retrieval backend was unavailable and the result was produced by a fallback stage. Absent means false. |

A `memory_record` is the wire projection of one stored record and its provenance:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `record_id` (0) | Text string | Yes | Identity of the record. |
| `content` (1) | Text string | Yes | The record's content. |
| `source` (2) | Text string | No | Provenance: attributed origin. |
| `subject` (3) | Text string | No | Provenance: subject entity. |
| `destination` (4) | Text string | No | The store or namespace the record lives in. |
| `collection` (5) | Text string | No | The record's grouping. |
| `timestamp` (6) | Text string | No | Creation or last-modification time, as an RFC 3339 timestamp. |
| `actor_type` (7) | Text string | No | Actor kind that produced the record. |
| `actor_id` (8) | Text string | No | Actor identifier that produced the record. |
| `classification` (9) | Text string | No | A retrieval-firewall or sensitivity label the store attaches to the record. |
| `cluster_id` (10) | Text string | No | An identifier of a semantic cluster the record belongs to. |
| `cluster_role` (11) | Text string | No | The record's role within its cluster. |
| `signature` (12) | Text string | No | A cryptographic signature over the record's signable envelope, hex-encoded. |
| `signing_key_id` (13) | Text string | No | Identifier of the key that produced `signature`. |
| `signature_alg` (14) | Text string | No | The signature algorithm identifier. |

A retrieval result MUST carry, for each record, the provenance the store holds
(`source`, `subject`, `timestamp`, and any signature fields present): a retrieval
result MUST NOT strip provenance that the store associates with the record. Any of
the OPTIONAL fields above MAY be absent when the store holds no value for it.

### 6.6 MEMORY_STATUS_REQ (`0x010C`) / MEMORY_STATUS_RESULT (`0x010D`)

Query store health and advertised capabilities.

**MEMORY_STATUS_REQ body** carries only the common envelope (§4.2); it takes no
arguments beyond `frame_kind` and `corr`.

**MEMORY_STATUS_RESULT body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `status` (2) | Text string | Yes | A short health token for the store (for example `ready`). |
| `version` (3) | Text string | No | The store implementation's version string. |
| `queue_depth` (4) | Unsigned int | No | The number of operations currently pending in the store's ingest path. |
| `capabilities` (5) | Map | No | A capability document keyed by unsigned integers, advertising which operations, profiles, and features the store supports. A receiver MUST apply the forward-compatibility rule (§4.3) to this nested map. |

The `capabilities` map is advisory and its inner schema is extensible; a producer
MAY carry a nested capability document there, and a consumer that does not
recognize an inner key MUST ignore it (§4.3) rather than fail the status reply.

### 6.7 MEMORY_EVICT (`0x0035`) / MEMORY_REVIVE (`0x0036`)

**MEMORY_EVICT body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `record_id` (2) | Text string | Yes | The record to evict (soft-remove from active retrieval, retain for revive). |
| `reason` (3) | Text string | No | An advisory reason for the eviction. |
| `effect` (4) | Unsigned int | Yes | Side-effect class (§5.3); MUST be `0x03` destructive. |

**MEMORY_REVIVE body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `record_id` (2) | Text string | Yes | The previously evicted record to restore. |
| `effect` (3) | Unsigned int | Yes | Side-effect class (§5.3); MUST be `0x01` idempotent_write. |

Each is answered by a MEMORY_CREATE_RESULT-shaped result
(`{ record_id (2): tstr, status (3): tstr }`) or by MEMORY_ERROR (§8). An evict of
an absent record, or a revive of a record that was never evicted, is reported as
MEMORY_ERROR `not_found`.

## 7. Streamed retrieval

When a matching result set exceeds one frame, a responder MAY deliver it as a
stream instead of a single MEMORY_RETRIEVE_RESULT, exploiting the channel's
Multi-stream direction. Each MEMORY_RETRIEVE_STREAM_DATA (`0x010A`) frame carries
the common envelope (echoing the retrieval's `corr`) and one page of records:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `records` (2) | Array of `memory_record` (§6.5) | Yes | One page of ranked records. |

The stream is terminated by exactly one MEMORY_RETRIEVE_STREAM_END (`0x010B`),
which carries the common envelope and:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `records` (2) | Array of `memory_record` (§6.5) | No | A final page of records (possibly empty). |
| `final` (3) | Boolean | Yes | MUST be `true`; marks the terminal frame of the retrieval. |

A retrieval is delivered *either* as a single MEMORY_RETRIEVE_RESULT *or* as zero
or more MEMORY_RETRIEVE_STREAM_DATA frames followed by exactly one
MEMORY_RETRIEVE_STREAM_END — never both. Every frame of a streamed retrieval MUST
echo the originating MEMORY_RETRIEVE_REQ's `corr`, and the records across all
frames of one retrieval preserve the ranked, best-first order.

## 8. Error model

Every failure of a Memory request is reported in a single MEMORY_ERROR (`0x010E`)
frame — the Memory channel has no foreign protocol, so all errors are native and
carried in one structured frame. A MEMORY_ERROR echoes the failed request's `corr`
and carries:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `code` (2) | Unsigned int | Yes | One of the Memory error codes below. |
| `message` (3) | Text string | Yes | A peer-safe, generic human-readable message for `code`. It MUST NOT carry internal detail (§8.2). |
| `retry_after_s` (4) | Unsigned int | No | When present, the number of seconds after which the requester MAY retry. |
| `approval_id` (5) | Text string | No | Present if and only if `code` is `approval_required`: an identifier of the held-for-approval operation (§8.1). |

| Code | Name | Meaning |
|---|---|---|
| 1 | malformed_request | The CBOR body is not valid deterministic CBOR, omits a REQUIRED field, uses a wrong CBOR major type, carries an unknown negative key (§4.3), or names a scoping filter the responder cannot honor (§6.4). |
| 2 | unknown_operation | The frame type is not a Memory operation the responder implements (for example an OPTIONAL eviction/revive frame at a responder that does not support it). |
| 3 | policy_denied | The operation was refused by the responder's governance or policy: a definitive denial. |
| 4 | approval_required | The operation was escalated for human approval and was **NOT executed** (§8.1). Carries `approval_id`. |
| 5 | not_found | An identified record (read, update, delete, evict, or revive target) does not exist. |
| 6 | internal_error | A store or pipeline failure the responder cannot attribute to the request. Generic; no internal detail crosses the wire. |

### 8.1 Governance escalation is a distinct, non-success outcome

A `policy_denied` (code 3) and an `approval_required` (code 4) are different
results and MUST NOT be conflated. `policy_denied` is a definitive refusal:
the operation will not proceed. `approval_required` means the operation has been
**held for human approval and has NOT been executed** — it is neither a success
nor a definitive denial, but a pending decision.

An implementation MUST report a governance escalation as MEMORY_ERROR with code
`approval_required`, carrying `approval_id`, and MUST NOT report it as a
MEMORY_CREATE_RESULT, MEMORY_UPDATE_RESULT, MEMORY_DELETE_RESULT, or any other
`*_RESULT`. A held-for-approval write MUST NOT be presented to the requester as a
completed write: an operation that did not enter the store is never a success
frame. A requester MUST treat `approval_required` as an operation that has not yet
taken effect, distinct from both a success and a `policy_denied`.

### 8.2 No internal detail on the wire

The `message` field MUST be the generic, peer-safe string for its `code`. The full
internal cause of a failure MUST be handled locally (for example logged by the
responder) and MUST NOT cross the wire: a MEMORY_ERROR MUST NOT carry store
internals, policy topology, configuration or source names, decoder diagnostics, or
any other detail beyond the code and its generic message. This leak-prevention
requirement is normative for interoperability, not merely local hygiene: a
requester MUST be able to rely on the error surface exposing only a code, a generic
message, and the OPTIONAL `retry_after_s` / `approval_id` fields.

## 9. Security and privacy considerations

This section supplements the core specification's Security Considerations; it does
not restate them.

Every Memory frame is AEAD-protected like all N-PAMP frames and is carried under
the association's existing authentication (the core specification's handshake binds
both peer identities into the transcript and the Finished MAC). A responder
therefore knows that an operation was requested by the authenticated peer, but
authentication is not authorization: a responder MUST enforce its own governance
and access policy on every operation regardless of the peer's identity, and MUST
report the outcome per §8 — including preserving the `approval_required` /
`policy_denied` distinction.

A retrieval result exposes stored records and their provenance to the requesting
peer. A responder SHOULD return only the records appropriate to the authenticated
peer and local policy, MAY return a filtered or empty result to a peer it does not
wish to inform, and SHOULD treat any classification or sensitivity label a record
carries (§6.5) as governing what it discloses. Because retrieval can carry
provenance and signature material, an implementation SHOULD treat the retrievable
set as sensitive and scope it per peer.

A responder MUST bound the resources a remote peer can consume through Memory
operations: the size of a result it will assemble, the rate of requests it will
accept, and the number of concurrent streamed retrievals it will maintain. A
responder MAY reply MEMORY_ERROR (with `retry_after_s`, or by paginating a large
result via `next_cursor`) rather than allocate without limit. Because either peer
may originate operations on this Multi-stream channel, both directions are subject
to these limits.

The error surface MUST NOT leak internal detail (§8.2); a MEMORY_ERROR that
carried store internals, policy topology, or configuration names would disclose
the responder's internal structure to the peer and is a conformance violation
(§10).

## 10. Conformance

An implementation conforms to NPAMP-MEMORY if and only if it rests on a
core-conformant N-PAMP wire implementation and, on the Memory channel `0x0001`, it:

1. Treats `0x0001` as the Memory channel with the core registry identity
   (name Memory; purpose persistent-state create/read/update/delete and
   retrieval; direction Multi-stream), does not repurpose the channel identifier,
   enables it only at the **Standard** profile or higher, and drops any frame
   received on an unadvertised Memory channel (§2);
2. Uses only the Memory frame types defined in §3 — the application-band operation
   frames `0x0100`–`0x010E` and the eviction/revive frames `0x0035`–`0x0036` —
   preserves the core meaning of the reserved all-channel frame types
   `0x0000`–`0x000A`, and assigns `0x0035`–`0x0036` to no purpose other than
   eviction and revive (§3);
3. Encodes every operation body as a deterministic-CBOR map (§4.1) with the
   integer keys of §4.2 and §5–§8; rejects a non-deterministically-encoded body, a
   body missing a REQUIRED field, or a body carrying an unknown negative key with
   MEMORY_ERROR `malformed_request`; and ignores an unknown non-negative key
   without altering its handling of recognized keys (§4.3);
4. Carries a non-empty `corr` on every `*_REQ` and on MEMORY_EVICT / MEMORY_REVIVE,
   echoes it verbatim on every reply, and matches replies to requests by `corr`
   rather than by frame sequence number (§5);
5. Carries an `effect` on every state-mutating request and treats a missing or
   unknown `effect` on a mutating operation as `destructive` (§5.3 fail-safe);
6. Reports every failure as MEMORY_ERROR (`0x010E`) with a code from §8 and a
   peer-safe `message`, never leaking internal cause (§8.2); reports a governance
   escalation as `approval_required` carrying `approval_id`, distinct from
   `policy_denied`; and never reports a success `*_RESULT` for an operation that
   did not enter the store (a held-for-approval write is `approval_required`, not a
   MEMORY_CREATE_RESULT) (§6.1, §8.1);
7. Preserves per-record provenance (`source`, `subject`, `timestamp`, and any
   signature fields the store holds) verbatim in retrieval results, applies present
   scoping filters conjunctively, and never returns an over-broad result for a
   filter it cannot honor (§6.4, §6.5); and
8. For a streamed retrieval, delivers the set either as a single
   MEMORY_RETRIEVE_RESULT or as zero or more MEMORY_RETRIEVE_STREAM_DATA frames
   terminated by exactly one MEMORY_RETRIEVE_STREAM_END with `final` set, and
   correlates every frame of the retrieval to the originating MEMORY_RETRIEVE_REQ by
   `corr` (§7).

A conformance test suite SHOULD assert each clause above with a recorded exchange
on the Memory channel: a MEMORY_CREATE_REQ / MEMORY_CREATE_RESULT pair; a
MEMORY_RETRIEVE_REQ / MEMORY_RETRIEVE_RESULT pair whose records carry non-empty
provenance; a MEMORY_ERROR provoked for `policy_denied` and, distinctly, one for
`approval_required` carrying an `approval_id`; a streamed retrieval
(MEMORY_RETRIEVE_STREAM_DATA frames followed by MEMORY_RETRIEVE_STREAM_END with
`final` set); and a rejected malformed body (a non-deterministic encoding, a
missing REQUIRED field, and an unknown negative key), each yielding
`malformed_request`.

A machine-gradable Memory conformance-vector group now exists in the corpus — the
`memory.body.decode` and `memory.body.encode` operation groups in
`test-vectors/v1/conformance-corpus.json`, whose expected values are produced by an
independent RFC 8949 / CDDL byte constructor (`test-vectors/gen/memory_oracle.py`),
not by the reference implementation they grade. An implementation is graded against
this group by `npamp-conform`: it MUST pass the deterministic-encoding case and the
MUST-reject cases of §4.1 / §4.2 / §4.3 (non-deterministic CBOR, missing REQUIRED key,
wrong CBOR major type, frame_kind/header mismatch, unknown negative key). A conformance
claim for those graded clauses MAY therefore be corpus-verified, naming the corpus
SHA-256 it was graded against; clauses not yet exercised by a vector remain clause-audited.
