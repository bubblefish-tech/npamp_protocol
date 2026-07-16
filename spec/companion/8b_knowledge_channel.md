# NPAMP-KNOWLEDGE — Knowledge Channel Retrieval and Subscription Companion (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document defines a **native** operation framing for the N-PAMP
> **Knowledge channel `0x0012`** ("Retrieval queries with ranked results and
> provenance", minimum profile **Standard**, direction **Multi-stream**): the frame
> types, the deterministic-CBOR operation bodies, the in-body correlation
> discipline, the streamed-retrieval and subscription lifecycle, and the structured
> error model by which one peer issues ranked, provenance-bearing knowledge
> retrieval queries against, and subscribes to a continuing query on, another peer.
> It builds on the core specification (draft-bubblefish-npamp-01, the "core
> specification") and does not redefine it. Unlike a Bridge carriage class, the
> Knowledge channel carries no foreign protocol: the operation body **is** N-PAMP's
> own encoding, so this document consumes no extension-TLV code point. It introduces
> no change to the core wire format. **The core specification governs**: on any
> disagreement between this document and the core specification, the core
> specification is authoritative.

## 1. Scope

### 1.1 In scope

This document specifies, over the Knowledge channel `0x0012` of the core
specification (draft-bubblefish-npamp-01):

1. A set of Knowledge-channel frame types (§3), drawn entirely from the
   channel-specific **application band** that begins at `0x0100` (core
   specification §4.6, frame-type namespace) — the core specification reserves
   **no** companion-extension range for this channel (§3.3), so this document
   assigns every frame in the `0x0100`+ band;
2. Per-operation request/result frame pairs realizing the two operation classes the
   channel's registered purpose implies — a **ranked, provenance-bearing retrieval
   query** (delivered as a single result or as a stream), and a **subscription** to
   a continuing query that pushes ranked updates under consumer-driven credit (§6);
3. The **deterministic-CBOR** encoding of every operation body (RFC 8949, core
   specification §4.5 and §11.9), keyed by unsigned integers;
4. An **in-body correlation** discipline that matches a reply, a streamed page, and
   a subscribed update to its request by a correlation token carried inside the CBOR
   body — consuming no shared TLV tag (§5); and
5. A single structured **error frame** (§9) that reports every failure of a query,
   subscribe, or credit request with a peer-safe code and message, leaking no
   internal detail.

Operations are described generically — issue a ranked retrieval query, page a large
result set, subscribe to a standing query, receive ranked updates, replenish
credit, and unsubscribe — so that any knowledge store and any client interoperate
over N-PAMP with no bespoke adaptation. The document names no product, no vendor,
and no application-specific schema.

### 1.2 Not in scope

This document does NOT (each exclusion carries its reason):

* **Define a query language.** A retrieval or subscription request carries a
  free-text query and a small set of structured scoping fields (§6.1, §6.4); it
  defines no expression grammar, boolean operator set, or embedding query syntax —
  reason: a full query language would exceed a wire-interoperability contract and is
  better layered above this framing (as NPAMP-MEMORY §1.2 similarly defers).
* **Define a ranking, scoring, or relevance algorithm.** A result set is ranked
  best-first by the responder (§6.3); this document carries the ordered results and
  their provenance and an OPTIONAL advisory score, but assigns no ranking function,
  embedding model, index structure, or relevance metric — reason: those are
  implementation choices, not interoperability contracts, and the interface page
  fixes ranking only as a property of the response, not as an encoding.
* **Define a provenance or attestation trust model.** This document carries the
  provenance a store holds for each result (`source`, `subject`, `timestamp`, and
  any signature fields; §6.3) and requires that it not be stripped, but it defines
  no trust anchor, signature-verification obligation, or attestation policy —
  reason: verifying provenance is a deploying-application and profile concern, not a
  wire-framing one.
* **Define authorization, governance, or admission policy.** Whether a query is
  answered, denied, or filtered per peer is the responder's local decision; this
  document defines only how each outcome is *reported* on the wire (§9) and permits
  a filtered or empty result (§10), not the policy that produces it.
* **Write, update, or delete stored knowledge.** The Knowledge channel is a
  **retrieval** channel (core registry purpose, §2); every operation in this
  document is non-mutating with respect to stored knowledge. Durable
  create/read/update/delete of records is the Memory channel `0x0001` and
  NPAMP-MEMORY (`81_memory_channel.md`), not this document — reason: the registry
  fixes `0x0012` to the retrieval-query traffic class only.
* **Carry a foreign agent protocol.** The Knowledge channel is native; it is not a
  Bridge carriage class and does not build on NPAMP-BRIDGE (`10_bridge_framework.md`;
  `../channels/0012_knowledge.md` §6). No frame in this document encapsulates a
  foreign message, and this document defines and consumes no extension-TLV tag. A
  foreign RAG or retrieval protocol carried octet-for-octet over N-PAMP travels on
  the Bridge channel `0x000D` under a carriage class (or Class OPAQUE), which is
  distinct from this native channel.
* **Change the core wire format.** It alters no field of the core frame header, no
  reserved all-channel frame type, the extension-TLV encoding, or any code point the
  core specification assigns; it uses only channel-application code points the core
  specification leaves to the channel at `0x0100` and above.

## 2. Relationship to the core specification

The Knowledge channel `0x0012` is registered by the core specification with purpose
**"Retrieval queries with ranked results and provenance"**, minimum profile
**Standard**, and direction **Multi-stream** (core specification §5, Core Channel
Registry; machine-readable in `../../registries/channels.csv`; public interface
reference `../channels/0012_knowledge.md`). Under the core specification's channel
architecture every channel is full-duplex: each peer maintains an independent
per-direction sequence space and independent per-direction traffic keys, and —
because Knowledge is **Multi-stream** — a deployment MAY carry concurrent retrieval
exchanges over multiple transport streams within the channel's stream family, so
that one long-running or large-result query does not head-of-line block another.
Either peer MAY originate a Knowledge operation.

**Minimum-profile gate.** A peer MUST enable the Knowledge channel only at the
**Standard** profile or higher; once Standard is met the channel is available at
Standard, High, and Sovereign, and there is no profile at which it becomes
unavailable. The channel is therefore part of the public, Standard-profile channel
surface and is not profile-gated. A peer that has not advertised the Knowledge
channel during the handshake (core specification §5) MUST NOT receive frames on it;
a frame arriving on an unadvertised Knowledge channel MUST be dropped and MUST NOT
be delivered to a knowledge store.

**Native, not a carriage class.** A Bridge carriage class carries a *foreign*
protocol's message octet-for-octet and wraps routing and correlation metadata
*around* it in a shared extension TLV. The Knowledge channel has no foreign
protocol: the operation body is N-PAMP's own deterministic-CBOR encoding, and this
document owns that body in full. Consequently the correlation token, the query and
result semantics, and the error object all live **inside** the CBOR body, and this
document reserves and consumes **no extension-TLV code point**. This is the
deliberate structural difference from NPAMP-BRIDGE and is the reason a Knowledge
operation is routed by its N-PAMP **frame type** (§3) rather than by any
method-name or tool-name field parsed from a body.

**Concrete encoding the interface reference defers to a companion.** The public
per-channel interface reference (`../channels/0012_knowledge.md`) fixes the channel
at the registry level only and states that a concrete retrieval query/result
encoding "is the subject of a future companion specification" and MUST NOT be
inferred from the interface reference. **This document is that companion**: it
supplies the concrete operation encoding the interface reference deferred, within
the channel-application code points the core specification already leaves to the
channel. It introduces no channel behavior the core specification does not permit;
it fills the deliberately unencoded operation layer the registry line implies.

**Frame-type namespace bands.** The core specification partitions each channel's
`0x0000`–`0xFFFF` frame-type space into four bands (core specification §4.6,
Frame-Type Namespace): `0x0000`–`0x000A` reserved all-channel frame types with the
same meaning on every channel; `0x000B`–`0x002F` unassigned, reserved to the core
for future all-channel additions; `0x0030`–`0x00FF` the **companion-extension
band**, per-channel extension frame types the core reserves for specific channels;
and `0x0100`–`0xFFFF` **channel-specific application** frame types. Because the
frame-type space is scoped by the Channel ID header field, a `0x0100`+ value on the
Knowledge channel does not collide with the same numeric value on any other channel.

## 3. Knowledge-channel frame types

Within the Knowledge channel (`0x0012`) frame-type namespace, this specification
defines ten frame types, **all** in the channel-specific application band at
`0x0100`+. The core specification reserves no companion-extension range for the
Knowledge channel (§3.3), so — like the Telemetry-family native channels whose
companions place every operational frame in the application band — this document
uses only the `0x0100`+ band and reserves nothing below it.

### 3.1 Application-band operation frames (`0x0100`+)

| Type | Name | Reply | Purpose |
|---|---|---|---|
| `0x0100` | KNOWLEDGE_QUERY_REQ | KNOWLEDGE_QUERY_RESULT, KNOWLEDGE_QUERY_STREAM_DATA, or KNOWLEDGE_ERROR | Issue a retrieval query; request a ranked, provenance-bearing result set. |
| `0x0101` | KNOWLEDGE_QUERY_RESULT | None | A bounded ranked result set delivered in a single frame; echoes the request's correlation token. |
| `0x0102` | KNOWLEDGE_QUERY_STREAM_DATA | None | One page of a large ranked result set; `final` is not set. |
| `0x0103` | KNOWLEDGE_QUERY_STREAM_END | None | Terminates a streamed retrieval; `final` is set. |
| `0x0104` | KNOWLEDGE_SUBSCRIBE_REQ | KNOWLEDGE_SUBSCRIBE_ACK or KNOWLEDGE_ERROR | Subscribe to a continuing (standing) query; carries an initial credit grant. |
| `0x0105` | KNOWLEDGE_SUBSCRIBE_ACK | None | Accepts a subscription; echoes `corr`; returns the subscription id and effective credit. |
| `0x0106` | KNOWLEDGE_UPDATE | None | A pushed ranked-result update under a subscription; echoes `corr`, names its `sub_id`, one-way. |
| `0x0107` | KNOWLEDGE_CREDIT | None | Consumer replenishes per-subscription update credit (backpressure); echoes `corr`. |
| `0x0108` | KNOWLEDGE_UNSUBSCRIBE | None | Cancels a subscription; echoes `corr`; no reply (idempotent). |
| `0x0109` | KNOWLEDGE_ERROR | None | Structured failure for any request; echoes the correlation token and carries a Knowledge error code (§9). |

A `*_REQ` frame originates an operation; the corresponding result frame, or a
KNOWLEDGE_ERROR (`0x0109`), replies to it. A KNOWLEDGE_QUERY_RESULT, a
KNOWLEDGE_QUERY_STREAM_* frame, a KNOWLEDGE_SUBSCRIBE_ACK, and every KNOWLEDGE_UPDATE
are never sent unsolicited: each MUST echo the correlation token of the request it
answers or the subscription it serves (§5). A responder MUST NOT emit both a result
(or SUBSCRIBE_ACK) and a KNOWLEDGE_ERROR for the same request.

### 3.2 Reserved all-channel frame types

The reserved all-channel frame types (PING `0x0001`, PONG `0x0002`, CLOSE `0x0003`,
CLOSE_ACK `0x0004`, ERROR `0x0005`, KEY_UPDATE `0x0006`, KEY_UPDATE_ACK `0x0007`,
PATH_CHALLENGE `0x0008`, PATH_RESPONSE `0x0009`, and FLOW_UPDATE `0x000A`; core
specification §4.6) retain their core meaning on the Knowledge channel. An
implementation MUST NOT reuse them for Knowledge application traffic and MUST NOT
define Knowledge operation semantics in the reserved all-channel range
`0x0000`–`0x000A`. The code point `0x0000` MUST NOT be used as a frame type.
Liveness, teardown, error signalling, key update, path migration, and
connection-level flow control on the channel use these frames with their core
meaning.

### 3.3 No reserved companion range for the Knowledge channel

The core specification's Extension Points reserve per-channel frame-type ranges in
the companion-extension band for several channels — Memory (`0x0035`–`0x0036`),
Capability (`0x0060`–`0x0063`), Control (`0x0080`), Audit (`0x0090`),
Settlement/Audit (`0x00A0`–`0x00A3`), Governance (`0x00B0`–`0x00B4`), and Immune
(`0x00C0`–`0x00C4`) (core specification, Extension Points, Reserved Frame-Type
Ranges; `../09_extension_points.md`). **No range is reserved for the Knowledge
channel.** This document therefore defines every operational frame in the
channel-specific application band at `0x0100`+ (§3.1); it defines no frame in the
companion-extension band `0x0030`–`0x00FF`, reserves no range in the core
specification's cross-channel reserved ranges, and an implementation MUST NOT assume
a Knowledge-channel companion range exists.

All ten frame types defined above lie within the Knowledge channel's own
application-band frame-type namespace at or above `0x0100`. This document consumes
no frame-type code point outside the Knowledge channel's application band and defines
no extension TLV.

## 4. Frame payload encoding

### 4.1 Payload container

A Knowledge frame's payload (the octets after the core frame header and any
extension TLVs, and before the AEAD tag) is a single **deterministically encoded
CBOR** object as defined by the core specification §4.5 and §11.9 (deterministic
CBOR, RFC 8949). The payload MUST be a CBOR map whose keys are the unsigned integers
defined in §4.2 and §5–§9 for the relevant frame type. A sender MUST produce the
deterministic encoding (core specification §11.9): byte-identical output for
identical inputs, with the canonical key ordering and shortest-form integer encoding
RFC 8949 §4.2 requires, and definite-length maps and arrays.

A receiver MUST reject, with KNOWLEDGE_ERROR code `malformed_request` (§9), any
Knowledge frame whose payload is not a valid deterministic-CBOR map, whose payload
omits a REQUIRED key for its frame type, or whose payload carries a key of the wrong
CBOR major type.

Knowledge operation bodies are carried in the frame **payload**, not in extension
TLVs. This document defines and consumes no extension-TLV tag, and therefore claims
none of the TLV code points the core specification reserves.

### 4.2 Common envelope fields

Every Knowledge payload map carries the following two envelope fields. Integer keys
are given in parentheses.

| Field (key) | CBOR type | Meaning |
|---|---|---|
| `frame_kind` (0) | Unsigned int | MUST equal the frame's Knowledge frame type (one of `0x0100`–`0x0109`). A receiver MUST reject (KNOWLEDGE_ERROR, code `malformed_request`) a payload whose `frame_kind` contradicts the frame-header Frame Type. |
| `corr` (1) | Byte string (1–64 B) | Correlation token (§5). Present and non-empty on every `*_REQ`, and echoed verbatim on every frame that replies to or serves it. |

The per-frame body fields defined in §5–§9 occupy keys `2` and above within the same
map; §6 gives, per frame, the full field table.

### 4.3 Forward compatibility

A receiver MUST ignore an unrecognized integer key it encounters in a Knowledge
payload map whose key is **not negative**, so that a later revision of this document
MAY add fields without breaking a conformant receiver. A receiver MUST reject
(KNOWLEDGE_ERROR, code `malformed_request`) a payload that carries a **negative**
integer key it does not recognize, reserving the negative key space for
forward-incompatible additions. A receiver MUST NOT treat the mere presence of an
unknown non-negative key as an error, and MUST NOT alter its handling of the keys it
does recognize because of it. This is the same forward-compatibility rule
NPAMP-MEMORY §4.3 and NPAMP-SENSORY §4 apply.

## 5. Correlation and operation model

The core specification does not define how a Knowledge reply is correlated to its
request (unlike the Bridge channel, where NPAMP-BRIDGE §5 defines a correlation
identifier). This document supplies that discipline, carrying the token **inside**
the CBOR body rather than in a shared TLV, because a native channel owns its whole
body (§2).

### 5.1 Correlation discipline

* Every `*_REQ` frame — KNOWLEDGE_QUERY_REQ (`0x0100`) and KNOWLEDGE_SUBSCRIBE_REQ
  (`0x0104`) — MUST carry a non-empty `corr` (§4.2) that is unique among the
  originating peer's outstanding Knowledge requests on the channel in that
  direction.
* Every KNOWLEDGE_QUERY_RESULT, every KNOWLEDGE_QUERY_STREAM_DATA and
  KNOWLEDGE_QUERY_STREAM_END, every KNOWLEDGE_SUBSCRIBE_ACK, every KNOWLEDGE_UPDATE,
  and every KNOWLEDGE_ERROR MUST echo the originating request's `corr` verbatim. A
  KNOWLEDGE_CREDIT and a KNOWLEDGE_UNSUBSCRIBE MUST echo the `corr` of the
  subscription they act on.
* A receiver MUST match a reply, a streamed page, or a subscribed update to its
  originating request by `corr`, **not** by the per-(channel, direction) frame
  sequence number. Because the Knowledge channel is Multi-stream, concurrent
  operations may be carried across multiple transport streams, where sequence order
  within any one stream does not identify the originating exchange.

### 5.2 Correlation and subscription lifetime

A `corr` value associated with a single-reply query is consumed when its
KNOWLEDGE_QUERY_RESULT or KNOWLEDGE_ERROR is delivered; the requester MUST treat that
exchange as complete and MUST NOT reuse the value while the original is outstanding.
A `corr` value associated with a **streamed** query remains live until the retrieval
terminates — with a single KNOWLEDGE_QUERY_RESULT, or with a
KNOWLEDGE_QUERY_STREAM_END, or with a KNOWLEDGE_ERROR (§7). A `corr` value associated
with a **subscription** remains live for the whole subscription: from
KNOWLEDGE_SUBSCRIBE_REQ, through the SUBSCRIBE_ACK and every KNOWLEDGE_UPDATE and
KNOWLEDGE_CREDIT, until the subscription is closed by KNOWLEDGE_UNSUBSCRIBE, a
terminating KNOWLEDGE_ERROR, or association close (§8).

### 5.3 Read-only operation class

Every operation in this document is **non-mutating** with respect to stored
knowledge: a query and a subscription read and observe, and never create, update, or
delete a knowledge record. This document therefore defines no side-effect-class
field (unlike NPAMP-MEMORY §5.3, whose channel performs writes). A responder MUST NOT
treat any frame defined here as authorizing a write to its store; a deployment that
needs durable create/read/update/delete uses the Memory channel `0x0001` and
NPAMP-MEMORY. Establishing and tearing down a subscription creates responder-local
control state (§8) but mutates no knowledge record.

## 6. Operation bodies

Each operation body is a deterministic-CBOR map carrying the common envelope (§4.2,
keys `0`–`1`) and the per-frame fields below at keys `2`+. Unless a field is marked
required, it is OPTIONAL and, when absent, carries no value (a producer omits the key
rather than encoding a null placeholder; a producer that does encode an explicit CBOR
`null` for an absent OPTIONAL field is equivalent to omitting it).

### 6.1 KNOWLEDGE_QUERY_REQ (`0x0100`)

Issue a retrieval query. Because the channel is bidirectional and Multi-stream,
either peer MAY originate a query, and multiple queries MAY be in flight
concurrently on separate streams within the channel's stream family.

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `query` (2) | Text string | No | Free-text query. Absent requests every result within the other scoping filters (a scoped browse). |
| `source` (3) | Text string | No | Restrict to results with this provenance origin. |
| `subject` (4) | Text string | No | Restrict to results with this provenance subject. |
| `collection` (5) | Text string | No | Restrict to results in this named grouping or namespace. |
| `limit` (6) | Unsigned int | No | Maximum results to return. Absent or `0` means the responder's default page size. |
| `min_score` (7) | Float | No | Advisory relevance floor: the requester asks the responder to omit results whose relevance is below this value. Advisory because scoring is a responder-local matter (§1.2). |
| `profile` (8) | Text string | No | A retrieval-effort selector interpreted by the responder (for example `fast`, `balanced`, `deep`). Advisory; it does not change the result schema. |
| `cursor` (9) | Byte string | No | An opaque continuation token from a prior result's `next_cursor` (§6.2), requesting the next page. |

Scoping fields (`source`, `subject`, `collection`) are **conjunctive**: a result is
returned only if it satisfies every present filter. A responder MUST NOT silently
ignore a scoping field it does not support and return an over-broad result; if it
cannot honor a present filter it MUST reply KNOWLEDGE_ERROR `filter_unsupported` (§9)
rather than mislead the requester into acting on results that do not satisfy the
constraint it asked for.

### 6.2 KNOWLEDGE_QUERY_RESULT (`0x0101`) and the `knowledge_result`

A bounded ranked result set, delivered in a single frame.

**KNOWLEDGE_QUERY_RESULT body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `results` (2) | Array of `knowledge_result` | Yes | The matching results, ranked best-first (possibly empty). |
| `has_more` (3) | Boolean | Yes | True if more results match than are carried here. |
| `next_cursor` (4) | Byte string | No | Present when `has_more` is true: an opaque token a requester echoes as `cursor` (§6.1) to fetch the next page. |
| `retrieval_stage` (5) | Unsigned int | No | An advisory indicator of which retrieval stage answered (for example an exact-match stage versus a semantic stage). |
| `semantic_unavailable` (6) | Boolean | No | True if a semantic-retrieval backend was unavailable and the result was produced by a fallback stage. Absent means false. |

A `knowledge_result` is the wire projection of one ranked, provenance-bearing
retrieval hit:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `result_id` (0) | Text string | Yes | Identity of the retrieved item within the responder's namespace. |
| `content` (1) | Text string | Yes | The retrieved knowledge content. |
| `rank` (2) | Unsigned int | No | The result's 0-based rank position (best = `0`). Advisory: the authoritative ranking is the array order of `results` (§6.3); `rank` restates it for convenience and MUST agree with array order when present. |
| `score` (3) | Float | No | Advisory relevance score the responder assigns. Higher is more relevant. Carries no fixed scale; MUST NOT be relied on for cross-responder comparison. |
| `source` (4) | Text string | No | Provenance: the origin the content is attributed to. |
| `subject` (5) | Text string | No | Provenance: the entity the content is about. |
| `collection` (6) | Text string | No | The grouping or namespace the item lives in. |
| `timestamp` (7) | Text string | No | Creation or last-modification time of the item, as an RFC 3339 timestamp. |
| `classification` (8) | Text string | No | A retrieval-firewall or sensitivity label the store attaches to the item. |
| `signature` (9) | Text string | No | A cryptographic signature over the item's signable envelope, hex-encoded. |
| `signing_key_id` (10) | Text string | No | Identifier of the key that produced `signature`. |
| `signature_alg` (11) | Text string | No | The signature algorithm identifier. |

A retrieval result MUST carry, for each result, the provenance the store holds
(`source`, `subject`, `timestamp`, and any signature fields present): consistent with
the registry purpose "Retrieval queries with ranked results and provenance", a
retrieval result MUST NOT strip provenance that the store associates with the item.
Any of the OPTIONAL fields above MAY be absent when the store holds no value for it.

### 6.3 Ranking is response-order

The registry line fixes ranking as a property of the response — results "returned in
a relevance order rather than as an unordered set". This document encodes that
ranking as the **array order** of `results` (and of the per-page arrays in a streamed
retrieval, §7): the first element is the most relevant, and a receiver MUST treat
array order as the authoritative ranking. The OPTIONAL `rank` and `score` fields
(§6.2) are advisory restatements and MUST NOT contradict array order. This document
assigns no ranking function, embedding model, or relevance metric (§1.2); it fixes
only that the wire order *is* the rank.

### 6.4 KNOWLEDGE_SUBSCRIBE_REQ (`0x0104`) / KNOWLEDGE_SUBSCRIBE_ACK (`0x0105`)

Subscribe to a **continuing (standing) query**: a query the responder re-evaluates
as its knowledge changes, pushing ranked updates to the subscriber under
consumer-driven credit (§8).

**KNOWLEDGE_SUBSCRIBE_REQ body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `query` (2) | Text string | No | The standing free-text query. Absent subscribes to every item within the other scoping filters. |
| `source` (3) | Text string | No | Restrict to this provenance origin (conjunctive, §6.1). |
| `subject` (4) | Text string | No | Restrict to this provenance subject. |
| `collection` (5) | Text string | No | Restrict to this grouping or namespace. |
| `min_score` (6) | Float | No | Advisory relevance floor for pushed updates (§6.1). |
| `profile` (7) | Text string | No | Retrieval-effort selector (§6.1). Advisory. |
| `include_snapshot` (8) | Boolean | No | When true, the responder SHOULD deliver the current matching set as an initial burst of KNOWLEDGE_UPDATE frames before streaming subsequent changes. Absent means false: deliver only changes after the subscription is established. |
| `credit` (9) | Unsigned int | Yes | Initial update credit the consumer grants (§8): the number of KNOWLEDGE_UPDATE frames the responder MAY send before it requires a further KNOWLEDGE_CREDIT. MUST be greater than or equal to `1`. |

A responder that cannot honor a present scoping filter MUST reply KNOWLEDGE_ERROR
`filter_unsupported` (§9) rather than accept the subscription and over-deliver.

**KNOWLEDGE_SUBSCRIBE_ACK body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `sub_id` (2) | Byte string (1–32 B) | Yes | The subscription's stable identifier, used by KNOWLEDGE_UPDATE, KNOWLEDGE_CREDIT, and KNOWLEDGE_UNSUBSCRIBE for this stream. |
| `credit` (3) | Unsigned int | Yes | The effective initial credit the responder will honor. MUST be less than or equal to the requested `credit` (§6.4). |
| `snapshot_pending` (4) | Boolean | No | True if an initial snapshot burst will follow (because the request set `include_snapshot`). Absent means false. |

A responder MAY decline a subscription with KNOWLEDGE_ERROR `subscription_refused`
(§9) instead of a SUBSCRIBE_ACK.

### 6.5 KNOWLEDGE_UPDATE (`0x0106`)

A pushed ranked-result update under a subscription. It is one-way: it carries the
common envelope (echoing the subscription's `corr`) plus its `sub_id`, and expects no
reply.

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `sub_id` (2) | Byte string (1–32 B) | Yes | The subscription (from SUBSCRIBE_ACK, §6.4) this update serves. |
| `update_seq` (3) | Unsigned int | Yes | The responder's strictly monotonic update counter for this subscription in this direction. Lets a consumer detect a dropped update. |
| `results` (4) | Array of `knowledge_result` (§6.2) | No | Newly matching or re-ranked results, ordered best-first (§6.3). Present when the update adds or re-ranks items; MAY be absent when the update only removes items. |
| `removed` (5) | Array of Text string | No | `result_id` values of items that no longer match the standing query. Present when the update removes items. |

A KNOWLEDGE_UPDATE MUST carry at least one of `results` or `removed`; an update
carrying neither is malformed (§4.1). Each emitted KNOWLEDGE_UPDATE consumes one unit
of the subscription's credit (§8).

### 6.6 KNOWLEDGE_CREDIT (`0x0107`)

The consumer replenishes or updates a subscription's update credit (backpressure). It
carries the common envelope (echoing the subscription's `corr`) and:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `sub_id` (2) | Byte string (1–32 B) | Yes | The subscription whose credit is being updated. |
| `credit` (3) | Unsigned int | Yes | Additional KNOWLEDGE_UPDATE frames the consumer grants. This value is **added** to the responder's remaining credit. |
| `high_water` (4) | Unsigned int | No | Advisory ceiling: the responder SHOULD NOT let the accumulated outstanding grant exceed this value, for burst control. |

A responder MUST treat `credit` as **additive** to its remaining grant and MUST NOT
deliver beyond the accumulated grant. This per-subscription credit is distinct from,
and layered above, the core connection-level FLOW_UPDATE frame `0x000A`, which this
document neither redefines nor consumes.

### 6.7 KNOWLEDGE_UNSUBSCRIBE (`0x0108`)

The consumer cancels a subscription. It carries the common envelope (echoing the
subscription's `corr`) and:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `sub_id` (2) | Byte string (1–32 B) | Yes | The subscription to cancel. |

The responder MUST stop emitting KNOWLEDGE_UPDATE frames for that `sub_id` upon
receipt. No reply is sent, and a sender MUST NOT await one. A KNOWLEDGE_UNSUBSCRIBE
that names an unknown or already-closed `sub_id` MUST be ignored — it is idempotent.

## 7. Streamed retrieval

When a matching result set exceeds one frame, a responder MAY deliver it as a stream
instead of a single KNOWLEDGE_QUERY_RESULT, exploiting the channel's Multi-stream
direction. Each KNOWLEDGE_QUERY_STREAM_DATA (`0x0102`) frame carries the common
envelope (echoing the query's `corr`) and one page of results:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `results` (2) | Array of `knowledge_result` (§6.2) | Yes | One page of ranked results, best-first. |

The stream is terminated by exactly one KNOWLEDGE_QUERY_STREAM_END (`0x0103`), which
carries the common envelope and:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `results` (2) | Array of `knowledge_result` (§6.2) | No | A final page of results (possibly empty). |
| `final` (3) | Boolean | Yes | MUST be `true`; marks the terminal frame of the retrieval. |

A retrieval is delivered *either* as a single KNOWLEDGE_QUERY_RESULT *or* as zero or
more KNOWLEDGE_QUERY_STREAM_DATA frames followed by exactly one
KNOWLEDGE_QUERY_STREAM_END with `final` set — never both. Every frame of a streamed
retrieval MUST echo the originating KNOWLEDGE_QUERY_REQ's `corr`, and the results
across all frames of one retrieval preserve the ranked, best-first order (§6.3): the
first result of the first page is the most relevant of the whole retrieval.

## 8. Subscription lifecycle and backpressure

A subscription is keyed by its `sub_id`, scoped to the association and to one
direction, and progresses through the states below. Delivery is
**credit-bounded per subscription**: a responder MUST NOT have more KNOWLEDGE_UPDATE
frames in flight for a `sub_id` than the current outstanding credit for that
subscription; it decrements available credit by `1` per KNOWLEDGE_UPDATE it emits;
and, at zero credit, it MUST pause emission for that subscription until it receives
additional credit via KNOWLEDGE_CREDIT (§6.6). This credit mechanism is what bounds a
responder that would otherwise flood a subscriber as its knowledge changes.

```
IDLE
  -> KNOWLEDGE_SUBSCRIBE_REQ sent/received ->        PENDING
       -> KNOWLEDGE_SUBSCRIBE_ACK ->                 ACTIVE (credit = N)
            -> KNOWLEDGE_UPDATE emitted ->           ACTIVE (credit decremented by 1)
                 -> credit reaches 0 ->              PAUSED
                      -> KNOWLEDGE_CREDIT ->         ACTIVE (credit increased)
       -> KNOWLEDGE_ERROR (subscription_refused) ->  CLOSED
  -> KNOWLEDGE_UNSUBSCRIBE or association close ->    CLOSED
```

A KNOWLEDGE_SUBSCRIBE_REQ moves the subscription from IDLE to PENDING. A
KNOWLEDGE_SUBSCRIBE_ACK moves it to ACTIVE with the acknowledged credit; a refusal
(KNOWLEDGE_ERROR `subscription_refused`) moves it from PENDING to CLOSED. In ACTIVE,
each emitted KNOWLEDGE_UPDATE decrements available credit by one; reaching zero credit
moves the subscription to PAUSED, where the responder MUST NOT emit further updates
until a KNOWLEDGE_CREDIT returns it to ACTIVE. A KNOWLEDGE_UNSUBSCRIBE, or the close
of the association, moves the subscription to CLOSED.

All subscription and credit state is **association-scoped** and MUST be discarded on
association close. A peer MUST NOT carry Knowledge subscription or credit state across
associations. Because the Knowledge channel is bidirectional and Multi-stream, a peer
MUST bound the resources a remote peer can consume in **either** direction: the number
of concurrent subscriptions and the rate of KNOWLEDGE_SUBSCRIBE_REQ and
KNOWLEDGE_QUERY_REQ frames it will accept, and MAY reply KNOWLEDGE_ERROR
`subscription_refused` or `resource_exhausted` rather than allocate without limit.

## 9. Error model

Every failure of a Knowledge request is reported in a single KNOWLEDGE_ERROR
(`0x0109`) frame — the Knowledge channel has no foreign protocol, so all errors are
native and carried in one structured frame. A KNOWLEDGE_ERROR echoes the failed
request's `corr` and carries:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `code` (2) | Unsigned int | Yes | One of the Knowledge error codes below. |
| `message` (3) | Text string | Yes | A peer-safe, generic human-readable message for `code`. It MUST NOT carry internal detail (§9.1). |
| `retry_after_s` (4) | Unsigned int | No | When present, the number of seconds after which the requester MAY retry. |
| `sub_id` (5) | Byte string (1–32 B) | No | The affected subscription, when the failure concerns one (for example a KNOWLEDGE_CREDIT for an unknown subscription). |

| Code | Name | Meaning |
|---|---|---|
| 1 | malformed_request | The CBOR body is not valid deterministic CBOR, omits a REQUIRED field, uses a wrong CBOR major type, carries an unknown negative key (§4.3), a `frame_kind` that contradicts the header, or a KNOWLEDGE_UPDATE with neither `results` nor `removed` (§6.5). |
| 2 | unknown_operation | The frame type is not a Knowledge operation the responder implements. |
| 3 | policy_denied | The query or subscription was refused by the responder's governance or policy: a definitive denial. (A responder MAY instead return a filtered or empty result set; see §10.) |
| 4 | filter_unsupported | A present scoping filter (`source`, `subject`, `collection`) is one the responder cannot honor; it MUST reply this rather than over-deliver (§6.1, §6.4). |
| 5 | unknown_subscription | A KNOWLEDGE_CREDIT or KNOWLEDGE_UNSUBSCRIBE named a `sub_id` with no live subscription (an UNSUBSCRIBE for an unknown id is instead ignored, §6.7; this code applies to a CREDIT that cannot be honored). |
| 6 | subscription_refused | The responder declines a KNOWLEDGE_SUBSCRIBE_REQ (unsupported, or a local resource or rate limit reached). |
| 7 | resource_exhausted | The responder cannot allocate the resources the query or subscription requires (for example a result too large to assemble, or a per-association subscription limit reached). MAY carry `retry_after_s`. |
| 8 | internal_error | A store or pipeline failure the responder cannot attribute to the request. Generic; no internal detail crosses the wire. |

### 9.1 No internal detail on the wire

The `message` field MUST be the generic, peer-safe string for its `code`. The full
internal cause of a failure MUST be handled locally (for example logged by the
responder) and MUST NOT cross the wire: a KNOWLEDGE_ERROR MUST NOT carry store
internals, index or ranking topology, policy topology, configuration or source names,
decoder diagnostics, or any other detail beyond the code and its generic message.
This leak-prevention requirement is normative for interoperability, not merely local
hygiene: a requester MUST be able to rely on the error surface exposing only a code, a
generic message, and the OPTIONAL `retry_after_s` / `sub_id` fields.

## 10. Security and privacy considerations

This section supplements the core specification's Security Considerations; it does
not restate them.

Every Knowledge frame is AEAD-protected like all N-PAMP frames and is carried under
the association's existing authentication (the core specification's handshake binds
both peer identities into the transcript and the Finished MAC). A responder therefore
knows that a query was issued by the authenticated peer, but authentication is not
authorization: a responder MUST enforce its own governance and access policy on every
query and subscription regardless of the peer's identity, and MUST report the outcome
per §9.

A retrieval result exposes stored knowledge and its provenance to the requesting
peer. A responder SHOULD return only the results appropriate to the authenticated
peer and local policy, MAY return a filtered or empty result to a peer it does not
wish to inform (an empty `results` array is a valid, non-committal response), and
SHOULD treat any classification or sensitivity label a result carries (§6.2) as
governing what it discloses. Because a result can carry provenance and signature
material, an implementation SHOULD treat the retrievable set as sensitive and scope it
per peer. A subscription is a standing disclosure: a responder SHOULD re-check policy
on every KNOWLEDGE_UPDATE, not only at subscribe time, because the peer's authorization
or a result's classification MAY change while the subscription is live.

A responder MUST bound the resources a remote peer can consume through Knowledge
operations: the size of a result it will assemble, the rate of queries and
subscriptions it will accept, and the number of concurrent streamed retrievals and
live subscriptions it will maintain. A responder MAY reply KNOWLEDGE_ERROR (with
`retry_after_s`, or by paginating a large result via `next_cursor`, or by refusing a
subscription) rather than allocate without limit. The §8 per-subscription credit
mechanism is the primary backpressure control: a consumer MUST NOT be forced to buffer
beyond the credit it granted, and a responder that continues to emit KNOWLEDGE_UPDATE
frames after its credit is exhausted is in violation of §8. Because either peer may
originate operations on this Multi-stream channel, both directions are subject to
these limits.

The error surface MUST NOT leak internal detail (§9.1); a KNOWLEDGE_ERROR that carried
store internals, index or policy topology, or configuration names would disclose the
responder's internal structure to the peer and is a conformance violation (§11).

## 11. Conformance

An implementation conforms to NPAMP-KNOWLEDGE if and only if it rests on a
core-conformant N-PAMP wire implementation and, on the Knowledge channel `0x0012`, it:

1. Treats `0x0012` as the Knowledge channel with the core registry identity (name
   Knowledge; purpose "Retrieval queries with ranked results and provenance"; minimum
   profile Standard; direction Multi-stream), does not repurpose the channel
   identifier, enables it only at the **Standard** profile or higher, and drops any
   frame received on an unadvertised Knowledge channel (§2);
2. Uses only the ten Knowledge frame types defined in §3 — the application-band
   operation frames `0x0100`–`0x0109` — preserves the core meaning of the reserved
   all-channel frame types `0x0000`–`0x000A`, defines no frame in the
   companion-extension band `0x0030`–`0x00FF`, and relies on **no** Knowledge-channel
   companion frame-type range because the core specification reserves none (§3);
3. Encodes every operation body as a deterministic-CBOR map (§4.1) with the integer
   keys of §4.2 and §5–§9; rejects a non-deterministically-encoded body, a body
   missing a REQUIRED field, a wrong-CBOR-major-type key, a `frame_kind` that
   contradicts the header, or a body carrying an unknown negative key with
   KNOWLEDGE_ERROR `malformed_request`; and ignores an unknown non-negative key
   without altering its handling of recognized keys (§4.3);
4. Carries a non-empty `corr` on every `*_REQ`, echoes it verbatim on every result,
   streamed page, SUBSCRIBE_ACK, KNOWLEDGE_UPDATE, KNOWLEDGE_CREDIT,
   KNOWLEDGE_UNSUBSCRIBE, and KNOWLEDGE_ERROR, and matches replies and updates to
   requests by `corr` rather than by frame sequence number (§5);
5. Returns retrieval results ranked best-first by **array order** (§6.3), preserves
   per-result provenance (`source`, `subject`, `timestamp`, and any signature fields
   the store holds) verbatim and never strips it (§6.2), applies present scoping
   filters conjunctively, and replies `filter_unsupported` rather than returning an
   over-broad result for a filter it cannot honor (§6.1, §6.4);
6. Delivers a retrieval either as a single KNOWLEDGE_QUERY_RESULT or as zero or more
   KNOWLEDGE_QUERY_STREAM_DATA frames terminated by exactly one
   KNOWLEDGE_QUERY_STREAM_END with `final` set, correlates every frame of the
   retrieval to the originating KNOWLEDGE_QUERY_REQ by `corr`, and preserves the
   ranked order across all pages (§7);
7. Honors the §8 subscription lifecycle and per-subscription credit mechanism — moves
   a subscription IDLE → PENDING → ACTIVE on SUBSCRIBE_REQ/SUBSCRIBE_ACK, decrements
   credit per KNOWLEDGE_UPDATE, pauses emission at zero credit, resumes only on a
   KNOWLEDGE_CREDIT, stops emitting on KNOWLEDGE_UNSUBSCRIBE, treats an UNSUBSCRIBE
   for an unknown `sub_id` as idempotent, and discards all subscription and credit
   state on association close, carrying none across associations (§6.4–§6.7, §8); and
8. Reports every failure as KNOWLEDGE_ERROR (`0x0109`) with a code from §9 and a
   peer-safe `message`, never leaking internal cause (§9.1), and bounds the result
   size, request rate, and concurrent streams and subscriptions a remote peer can
   consume in both directions (§8, §10).

Machine-gradable conformance vectors exist for the Knowledge channel's payload-decode
surface: the `knowledge.body.decode` operation group in the conformance corpus,
produced by an independent RFC 8949 byte constructor (`test-vectors/gen/knowledge_oracle.py`,
whose expected values derive from RFC 8949 itself and not from the implementation it
grades, so the oracle is non-circular) and graded by `npamp-conform`, covers the
§4.1/§4.2/§4.3 payload-encoding and common-envelope MUST-reject clauses — including the
`frame_kind` (0) / `corr` (1) envelope discipline and the deterministic-CBOR reject
rules — and the Go reference implementation is cross-validated against that oracle by
`impl/go/zz_knowledge_oracle_xval_test.go`. A claim of conformance to those
payload-encoding and common-envelope clauses is therefore graded against the pinned
vector corpus and MAY name the corpus SHA-256 it was graded against. Beyond that
payload surface, the §5–§9 behavioural clauses (the in-body correlation and subscription
lifetime of §5, the ranked best-first ordering and provenance preservation of §6.2–§6.3,
the streamed-retrieval sequence of §7, the subscription lifecycle and per-subscription
credit backpressure of §8, and the structured error model and leak-prevention of §9)
are graded only by a live-exchange harness once one exists, and a conformance claim for
those behavioural clauses MUST NOT be presented as graded against the vector corpus. A
conformance test suite SHOULD assert each clause
above with a recorded exchange on the Knowledge channel `0x0012`: a handshake that
advertises the channel; a KNOWLEDGE_QUERY_REQ / KNOWLEDGE_QUERY_RESULT pair whose
results carry non-empty provenance and are ordered best-first; a streamed retrieval
(KNOWLEDGE_QUERY_STREAM_DATA frames followed by KNOWLEDGE_QUERY_STREAM_END with
`final` set); a KNOWLEDGE_SUBSCRIBE_REQ → KNOWLEDGE_SUBSCRIBE_ACK → KNOWLEDGE_UPDATE
(repeated until credit reaches zero) → KNOWLEDGE_CREDIT → KNOWLEDGE_UPDATE →
KNOWLEDGE_UNSUBSCRIBE sequence, with the responder pausing at zero credit and
resuming only on a KNOWLEDGE_CREDIT; a refused subscription (`subscription_refused`);
a `filter_unsupported` rejection of an unsupported scoping filter; and a rejected
malformed body (a non-deterministic encoding, a missing REQUIRED field, and an
unknown negative key), each yielding `malformed_request`.
