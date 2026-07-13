# NPAMP-DISC — Discovery and Capability Advertisement (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words MUST, MUST NOT, REQUIRED,
> SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL are to be
> interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they
> appear in all capitals, as shown here. This document defines runtime advertisement
> and lookup over the N-PAMP **Discovery channel `0x0010`**: how a peer declares which
> protocols, carriage classes, tools, and agents it offers, and how a peer queries and
> subscribes to those declarations. It builds on **NPAMP-BRIDGE** and does not redefine
> it. It consumes only code points the core specification reserves and introduces no
> change to the core wire format.

## 1. Scope

### 1.1 In scope

This document specifies, over the Discovery channel `0x0010` of the N-PAMP core
specification (the "core specification", draft-bubblefish-npamp-01):

1. A set of Discovery-channel frame types, drawn from the channel-specific frame-type
   namespace that begins at `0x0100` (core specification §4.6);
2. The encoding of a **Discovery Record**, the unit of advertisement, describing the
   protocols, carriage classes, tools, and agents a peer offers;
3. A request/response lookup by which one peer enumerates or filters another peer's
   records;
4. A one-way announcement by which a peer publishes records without solicitation; and
5. A subscription by which a peer is notified when the other peer's advertised set
   changes during an association.

The advertised facts reference identifiers defined elsewhere: the foreign-protocol
identifier (`protocol_id`) and its carriage class are those of NPAMP-BRIDGE and the
Bridge Protocol Identifier registry; this document carries those identifiers, it does
not assign them.

### 1.2 Not in scope

This document does NOT:

* Assign `protocol_id` code points or define a carriage class; those are defined by
  NPAMP-BRIDGE and the Bridge Protocol Identifier registry, and this document only
  carries their values;
* Define the Bridge encapsulation, correlation, error, or safety contract; those are
  defined by NPAMP-BRIDGE and are referenced, not restated, here;
* Define how a tool is invoked or an agent is addressed once discovered; invocation
  rides the Bridge channel `0x000D` or another core channel per the relevant carriage
  class and mapping document, not the Discovery channel;
* Define authentication or authorization of the advertised facts beyond what the core
  specification's handshake and the considerations in §9 provide; an advertisement is
  a claim by the advertising peer, carried under the association's existing
  authentication; and
* Change any field of the 36-octet core frame header, any reserved all-channel frame
  type, the extension-TLV encoding, or any code point the core specification assigns.

## 2. Relationship to the core specification and to NPAMP-BRIDGE

The Discovery channel `0x0010` is registered by the core specification with purpose
"Agent, tool, and service discovery and capability advertisement", minimum profile
**Standard**, and direction **Bidirectional**. Under the core specification's channel
architecture every channel is full-duplex: each peer maintains an independent send and
receive sequence space and independent per-direction traffic keys, so both peers MAY
transmit Discovery frames simultaneously and either peer MAY originate a query or an
announcement. A peer MUST NOT send or accept Discovery frames unless the Discovery
channel was advertised for the association during the handshake (core specification
§5); frames on an unadvertised channel MUST be dropped.

This document reuses two facilities of NPAMP-BRIDGE by reference and does not restate
them:

* The **correlation discipline** of NPAMP-BRIDGE §5 — a reply echoes its request's
  correlation identifier verbatim, and replies are matched to requests by that
  identifier rather than by frame sequence number. The Discovery frames in this
  document carry their own correlation field (§4.2) and apply that same discipline.
* The meaning of `protocol_id` and its carriage class as established by NPAMP-BRIDGE
  §4 and the Bridge Protocol Identifier registry. A Discovery Record that advertises a
  protocol carries the same `protocol_id` octet that a BridgeEnvelope would carry for
  that protocol.

A Discovery Record advertises a capability; it does not invoke it. Once a peer has
discovered a protocol, tool, or agent, traffic to use it is carried on the Bridge
channel `0x000D` (under NPAMP-BRIDGE and the applicable carriage class) or on whichever
core channel the relevant mapping document designates. Nothing in this document carries
foreign application traffic.

## 3. Discovery-channel frame types

Within the Discovery channel (`0x0010`) frame-type namespace — channel-specific types
begin at `0x0100` (core specification §4.6) — this specification defines:

| Type | Name | Reply | Meaning |
|---|---|---|---|
| 0x0100 | DISCO_QUERY | DISCO_RESULT or DISCO_ERROR | A request to enumerate or filter the responder's advertised records. |
| 0x0101 | DISCO_RESULT | None | A successful reply carrying zero or more records; correlation echoes the query. |
| 0x0102 | DISCO_ERROR | None | A failed reply; carries a structured discovery error. Correlation echoes the query. |
| 0x0103 | DISCO_ANNOUNCE | None | An unsolicited publication of one or more records. No reply is expected or permitted. |
| 0x0104 | DISCO_SUBSCRIBE | DISCO_RESULT or DISCO_ERROR | A request to receive DISCO_UPDATE frames when the advertised set changes. |
| 0x0105 | DISCO_UPDATE | None | A notification that advertised records were added, replaced, or withdrawn; correlation echoes the subscription. |
| 0x0106 | DISCO_UNSUBSCRIBE | None | Cancels a prior subscription; correlation echoes the subscription. No reply is expected or permitted. |

The reserved all-channel frame types (PING `0x0001`, PONG `0x0002`, CLOSE `0x0003`,
CLOSE_ACK `0x0004`, ERROR `0x0005`, KEY_UPDATE `0x0006`, and the remainder enumerated
in core specification §4.6) retain their core meaning on the Discovery channel. An
implementation MUST NOT reuse them for discovery traffic and MUST NOT define discovery
semantics in the reserved all-channel range.

All seven frame types defined above lie within the Discovery channel's own
channel-specific namespace at or above `0x0100`; this document consumes no frame-type
code point outside that namespace and reserves none in the core specification's
cross-channel reserved ranges.

## 4. Frame payload encoding

### 4.1 Payload container

A Discovery frame's payload (the octets after the 36-octet core frame header and any
extension TLVs, and before the AEAD tag) is a single **deterministically encoded CBOR**
object as defined by core specification §4.5 and §11.9 (deterministic CBOR, RFC 8949).
The payload MUST be a CBOR map whose keys are the unsigned integers defined in §4.2,
§5, §6, and §7 for the relevant frame type. A sender MUST produce the deterministic
encoding (core specification §11.9): byte-identical output for identical inputs, with
the canonical key ordering and shortest-form integer encoding RFC 8949 §4.2 requires.
A receiver MUST reject (DISCO_ERROR, code `MalformedPayload`) any Discovery frame whose
payload is not a valid deterministic-CBOR map, or whose payload contains a required key
that is absent or of the wrong major type.

Discovery records and queries are carried in the frame **payload**, not in extension
TLVs. This document defines and consumes no extension-TLV tag, and therefore claims
none of the TLV code points the core specification reserves.

A receiver MUST ignore an unrecognized integer key it encounters in a Discovery payload
map whose key is not negative, so that later revisions of this document MAY add fields
without breaking a conformant receiver. A receiver MUST reject (DISCO_ERROR, code
`MalformedPayload`) a payload that carries a negative integer key it does not
recognize, reserving the negative key space for forward-incompatible additions.

### 4.2 Common envelope fields

Every Discovery payload map carries the following fields. Integer keys are given in
parentheses.

| Field (key) | CBOR type | Meaning |
|---|---|---|
| `frame_kind` (0) | Unsigned int | MUST equal the frame's Discovery frame type (`0x0100`–`0x0106`). A receiver MUST reject (DISCO_ERROR, code `KindMismatch`) a payload whose `frame_kind` contradicts the frame-header Frame Type. |
| `corr` (1) | Byte string (1–64 B) | Correlation identifier. Present and non-empty on DISCO_QUERY, DISCO_SUBSCRIBE, DISCO_UNSUBSCRIBE, and on every frame that replies to or follows from one of those (§4.3). Absent on a standalone DISCO_ANNOUNCE. |

A DISCO_QUERY and a DISCO_SUBSCRIBE MUST carry a `corr` that is non-empty and unique
among the originating peer's outstanding queries and subscriptions on the Discovery
channel in that direction. A DISCO_RESULT, DISCO_ERROR, DISCO_UPDATE, and
DISCO_UNSUBSCRIBE MUST echo the originating request's `corr` verbatim. A receiver MUST
match each reply or update to its originating request by `corr`, not by frame sequence
number, exactly as NPAMP-BRIDGE §5 requires for Bridge replies. A standalone
DISCO_ANNOUNCE (one not sent in answer to any request) MUST omit `corr`.

### 4.3 Correlation lifetime

A `corr` value associated with a DISCO_QUERY is consumed when its DISCO_RESULT or
DISCO_ERROR is delivered; a requester MUST treat that exchange as complete and MUST NOT
reuse the value for a new query while the original is outstanding. A `corr` value
associated with a DISCO_SUBSCRIBE remains live for the lifetime of the subscription:
The responder uses it as the correlation of every DISCO_UPDATE it emits for that
subscription, and the subscriber uses it as the correlation of the DISCO_UNSUBSCRIBE
that cancels it. A responder MUST stop emitting DISCO_UPDATE frames for a subscription
once it has received a matching DISCO_UNSUBSCRIBE or once the association closes.

## 5. Discovery Record

A Discovery Record is the unit of advertisement. It is a CBOR map with the following
fields.

| Field (key) | CBOR type | Required | Meaning |
|---|---|---|---|
| `record_id` (0) | Byte string (1–32 B) | Yes | Identifier of this record, unique among the advertising peer's currently advertised records on the association. Stable across a replacement of the record's contents. |
| `kind` (1) | Unsigned int | Yes | Record kind: 1 = protocol, 2 = carriage_class, 3 = tool, 4 = agent. A receiver MUST reject (DISCO_ERROR, code `UnknownRecordKind`) a record whose `kind` it does not recognize, unless the record is delivered within a tolerant enumeration (§6.3), in which case the receiver MUST skip the unrecognized record and retain the rest. |
| `revision` (2) | Unsigned int | Yes | Monotonically non-decreasing revision counter for `record_id`. A later advertisement of the same `record_id` with a strictly greater `revision` replaces the earlier one (§8). |
| `label` (3) | Text string | No | Human-readable name (advisory; not an identifier). |
| `body` (4) | Map | Yes | Kind-specific body, per §5.1–§5.4. |

A record's authoritative identity for replacement and withdrawal is `record_id`; `label`
is advisory and MUST NOT be used to correlate or de-duplicate records.

### 5.1 Protocol record (`kind` = 1)

Advertises that the peer can carry a foreign agent protocol over this association.

| `body` field (key) | CBOR type | Required | Meaning |
|---|---|---|---|
| `protocol_id` (0) | Unsigned int (0–255) | Yes | The Bridge Protocol Identifier (NPAMP-BRIDGE §4; Bridge Protocol Identifier registry). The same octet a BridgeEnvelope carries for this protocol. |
| `carriage_class` (1) | Unsigned int | Yes | The carriage class under which this `protocol_id` is carried, as assigned by the Bridge Protocol Identifier registry. |
| `channels` (2) | Array of unsigned int | No | Core channel IDs on which this protocol's traffic is carried for this peer (for example `0x000D` Bridge, or a more specific core channel per the mapping document). Absent means the Bridge channel `0x000D` default. |
| `content_types` (3) | Array of unsigned int | No | The foreign-message `content_type` values (NPAMP-BRIDGE §4) this peer accepts for this protocol. |
| `methods` (4) | Array of text string | No | Foreign operation names this peer supports (for example `tools/call`). Absent means the peer does not enumerate methods at the discovery layer; a requester learns them through the foreign protocol itself. |

A peer MUST NOT advertise a protocol record whose `protocol_id` it cannot in fact carry
over the association; advertising a protocol the peer would reject at the Bridge channel
is a conformance violation (§10).

### 5.2 Carriage-class record (`kind` = 2)

Advertises that the peer implements a carriage class generically, independent of any one
`protocol_id`. This lets a requester learn that any protocol assigned to that class —
including one for which no native mapping exists — can be carried.

| `body` field (key) | CBOR type | Required | Meaning |
|---|---|---|---|
| `carriage_class` (0) | Unsigned int | Yes | The carriage class implemented, as defined by the companion carriage-class specifications. |
| `content_types` (1) | Array of unsigned int | No | The `content_type` values the class implementation accepts. |

### 5.3 Tool record (`kind` = 3)

Advertises a single invocable tool the peer exposes.

| `body` field (key) | CBOR type | Required | Meaning |
|---|---|---|---|
| `name` (0) | Text string | Yes | The tool's invocation name within its protocol's namespace. |
| `protocol_id` (1) | Unsigned int (0–255) | Yes | The protocol through which the tool is invoked (NPAMP-BRIDGE §4). |
| `effect` (2) | Unsigned int | No | The most severe side effect invoking the tool may cause, using the SafetyLabel `effect` values of NPAMP-BRIDGE §7 (0x00 read_only … 0x03 destructive). Advisory at discovery; it does not replace the SafetyLabel a requester MUST attach at invocation, nor the responder's authorization decision. A requester MUST NOT treat the absence of `effect` as `read_only`. |
| `schema_ref` (3) | Text string | No | An identifier or locator for the tool's input/output schema, interpreted within the tool's protocol. Advisory; this document defines no schema language. |

### 5.4 Agent record (`kind` = 4)

Advertises a single addressable agent the peer hosts or fronts.

| `body` field (key) | CBOR type | Required | Meaning |
|---|---|---|---|
| `agent_id` (0) | Byte string (1–64 B) | Yes | Opaque identifier of the agent within the advertising peer's namespace. |
| `protocols` (1) | Array of unsigned int | Yes | The `protocol_id` values through which the agent may be reached (NPAMP-BRIDGE §4). At least one. |
| `tools` (2) | Array of byte string | No | `record_id` values of tool records (§5.3) this agent exposes, each of which MUST also be advertised as its own tool record on the same association. |

An agent record's `tools` entries are references to tool records; a receiver that
encounters a `tools` entry with no matching advertised tool record MUST treat the
reference as dangling and MUST NOT synthesize a tool record from it.

## 6. Query and result

### 6.1 DISCO_QUERY

A DISCO_QUERY payload carries the common envelope (§4.2) and an OPTIONAL filter:

| Field (key) | CBOR type | Meaning |
|---|---|---|
| `kinds` (2) | Array of unsigned int | If present, restricts the result to records whose `kind` is in the array. Absent means all kinds. |
| `protocol_ids` (3) | Array of unsigned int | If present, restricts protocol, tool, and agent records to those naming a `protocol_id` in the array. |
| `name_prefix` (4) | Text string | If present, restricts tool and agent records to those whose `name` or `agent_id` begins with the given prefix (octet-prefix match on the UTF-8 encoding). |
| `tolerant` (5) | Boolean | If true, the responder returns a partial result rather than an error when some records cannot be represented (§6.3). Default false. |

A filter is conjunctive: a record is returned only if it satisfies every present filter
field. A DISCO_QUERY with no filter field requests every record the responder
advertises.

### 6.2 DISCO_RESULT

A DISCO_RESULT payload carries the common envelope (§4.2, echoing the query's `corr`)
and:

| Field (key) | CBOR type | Meaning |
|---|---|---|
| `records` (2) | Array of Discovery Records (§5) | The records satisfying the query, possibly empty. |
| `complete` (3) | Boolean | True if `records` is the entire matching set; false if the responder paginated and more records follow in subsequent DISCO_RESULT frames bearing the same `corr`. |
| `cursor` (4) | Byte string | Present when `complete` is false; an opaque continuation token a requester echoes in a follow-up DISCO_QUERY (field key 6, `cursor`) to retrieve the next page. |

When a responder paginates, it emits one or more DISCO_RESULT frames with `complete`
false and a `cursor`, followed by a final DISCO_RESULT with `complete` true. A requester
retrieves a subsequent page by issuing a DISCO_QUERY whose `cursor` (key 6) echoes the
prior `cursor` and whose filter fields are unchanged; the responder MUST reject
(DISCO_ERROR, code `StaleCursor`) a cursor it no longer recognizes. An empty result is a
single DISCO_RESULT with an empty `records` array and `complete` true.

### 6.3 Tolerant enumeration

When a DISCO_QUERY sets `tolerant` true, a responder that holds a record it cannot
represent in the requested form (for example a record of a `kind` the responder knows it
cannot encode for this peer) MUST omit that record and set `complete` true for the
records it can return, rather than failing the whole query. When `tolerant` is false or
absent and any matching record cannot be represented, the responder MUST reply
DISCO_ERROR rather than silently dropping records, so that a requester is never misled
into believing it received a complete set.

## 7. Announcement, subscription, and update

### 7.1 DISCO_ANNOUNCE

A DISCO_ANNOUNCE publishes records without solicitation. Its payload carries
`frame_kind` (§4.2), omits `corr`, and carries:

| Field (key) | CBOR type | Meaning |
|---|---|---|
| `records` (2) | Array of Discovery Records (§5) | The records being announced. |

A receiver MUST NOT reply to a DISCO_ANNOUNCE. A sender MUST NOT await a reply. A
DISCO_ANNOUNCE is advisory cache-priming: the authoritative answer to "what do you
offer" is always a DISCO_QUERY/DISCO_RESULT exchange, because an announcement MAY be
missed by a peer that connected after it was sent.

### 7.2 DISCO_SUBSCRIBE and DISCO_UPDATE

A DISCO_SUBSCRIBE requests notification when the responder's advertised set changes. Its
payload carries the common envelope (§4.2, with a live `corr` per §4.3) and the same
OPTIONAL filter fields as a DISCO_QUERY (§6.1, keys 2–4); the filter scopes which
changes generate an update. The responder MUST acknowledge a DISCO_SUBSCRIBE with a
DISCO_RESULT echoing `corr` that carries the current matching record set (a snapshot),
or with a DISCO_ERROR if it declines.

Thereafter, whenever a record within the subscription's filter is added, replaced (a
strictly greater `revision` for an existing `record_id`), or withdrawn, the responder
MUST emit a DISCO_UPDATE echoing the subscription's `corr`:

| Field (key) | CBOR type | Meaning |
|---|---|---|
| `added` (2) | Array of Discovery Records (§5) | Records newly within the subscription's filter, or replacements (carry the full record at its new `revision`). |
| `withdrawn` (3) | Array of byte string | `record_id` values that left the advertised set or the subscription's filter. |

A DISCO_UPDATE MUST carry at least one of `added` or `withdrawn` non-empty. A subscriber
applies an update by replacing or inserting each `added` record by `record_id` and
deleting each `withdrawn` `record_id` (§8).

### 7.3 DISCO_UNSUBSCRIBE

A DISCO_UNSUBSCRIBE cancels a subscription. Its payload carries `frame_kind` and the
subscription's `corr` (§4.2). The responder MUST stop emitting DISCO_UPDATE frames for
that `corr` upon receipt. A receiver MUST NOT reply to a DISCO_UNSUBSCRIBE. A
DISCO_UNSUBSCRIBE that names a `corr` with no live subscription MUST be ignored
(it is idempotent).

## 8. Record lifecycle and consistency

A `record_id` names a logical advertisement across its lifetime. The advertising peer
MUST assign a strictly greater `revision` each time it changes the contents of a
`record_id` it continues to advertise. A receiver that holds a record for a `record_id`
MUST replace it when it receives, by DISCO_RESULT, DISCO_ANNOUNCE, or DISCO_UPDATE, a
record for the same `record_id` with a strictly greater `revision`, and MUST ignore a
received record whose `revision` is less than or equal to the one it already holds (a
reordered or duplicated advertisement). Withdrawal is expressed by a DISCO_UPDATE
`withdrawn` entry; a receiver MUST NOT infer withdrawal from the mere absence of a
`record_id` in a later non-subscription DISCO_RESULT or DISCO_ANNOUNCE, because those
carry only the records matching a query or chosen for announcement, not the full set.

All advertised state is scoped to the association. When the association closes, all
records and subscriptions learned over it are discarded; a peer MUST re-advertise after a
new handshake and MUST NOT carry discovery state from a prior association into a new one.

## 9. Errors

A failure in the discovery exchange itself is reported as DISCO_ERROR, echoing the
originating request's `corr`. Its payload carries the common envelope (§4.2) and:

| Field (key) | CBOR type | Meaning |
|---|---|---|
| `code` (2) | Unsigned int | One of the codes below. |
| `reason` (3) | Text string | Advisory human-readable detail (OPTIONAL). MUST NOT be relied on for control flow. |

| Code | Name | Meaning |
|---|---|---|
| 1 | MalformedPayload | The Discovery payload is not valid deterministic CBOR, omits a required field, or uses a wrong CBOR major type (§4.1). |
| 2 | KindMismatch | The payload's `frame_kind` contradicts the frame-header Frame Type (§4.2). |
| 3 | UnknownRecordKind | A record's `kind` is unrecognized and the query was not tolerant (§5, §6.3). |
| 4 | FilterUnsupported | A filter field is present that the responder does not implement; the responder MUST NOT silently ignore it and return an over-broad result. |
| 5 | StaleCursor | A pagination `cursor` is no longer recognized (§6.2). |
| 6 | SubscriptionRefused | The responder declines a DISCO_SUBSCRIBE (for example it does not support subscriptions, or a local limit is reached). |
| 7 | NotAdvertised | The Discovery channel was not advertised for this association, or discovery is disabled by local policy. |

A responder MUST NOT report success — a DISCO_RESULT with `complete` true — for a query
whose matching set it could not fully and faithfully represent; such a query MUST yield
either a tolerant partial result (§6.3) or a DISCO_ERROR. An over-broad result returned
because an unsupported filter was ignored is a conformance violation (§10): it misleads
the requester into acting on records that do not satisfy the constraint it asked for.

## 10. Security and privacy considerations

This section supplements the core specification's Security Considerations; it does not
restate them.

An advertisement is a **claim by the advertising peer**, carried under the association's
existing authentication (the core specification's handshake binds both peer identities
into the transcript and the Finished MAC). Discovery frames are AEAD-protected like all
N-PAMP frames; a receiver therefore knows that a record was sent by the authenticated
peer, but not that the underlying protocol, tool, or agent behaves as described.
Discovery is not authorization: a requester MUST NOT treat the presence of a tool or
agent record as permission to invoke it, and a responder MUST enforce authorization at
invocation regardless of what it advertised.

The `effect` hint on a tool record (§5.3) is advisory and follows the fail-safe rule of
NPAMP-BRIDGE §7: a requester MUST NOT treat a missing `effect` as `read_only`, and the
SafetyLabel a requester attaches at invocation, together with the responder's
authorization decision, governs — not the discovery hint.

Advertisement exposes a peer's capability surface to the other peer. A peer SHOULD
advertise only the records appropriate to the authenticated peer and local policy, and
MAY return a filtered or empty result to a peer it does not wish to inform; an empty
DISCO_RESULT is a valid and non-committal reply. Because advertised records can disclose
internal structure (tool names, agent identifiers, schema locators), an implementation
SHOULD treat the advertised set as sensitive and scope it per peer.

A peer MUST bound the resources a remote peer can consume through discovery: the number
of concurrent subscriptions, the rate of DISCO_QUERY frames, and the size of a result it
will assemble. A peer MAY reply DISCO_ERROR (`SubscriptionRefused`, or a paginated
result for large sets) rather than allocate without limit. Because either peer may
originate queries and subscriptions on this bidirectional channel, both directions are
subject to these limits.

A peer MUST NOT rely on a DISCO_ANNOUNCE having been received, since a peer that joined
after it was sent will not have seen it; authoritative discovery is always a
query/result exchange (§7.1). A peer MUST NOT carry discovery state across associations
(§8), so that a stale advertisement from a prior association cannot be acted upon under a
new one.

## 11. Conformance

An implementation conforms to NPAMP-DISC if and only if, on the Discovery channel
`0x0010`, it:

1. Uses only the Discovery-channel frame types defined in §3, within the channel's
   own frame-type namespace at or above `0x0100`, and preserves the core meaning of the
   reserved all-channel frame types;
2. Encodes every Discovery payload as a deterministic-CBOR map (§4.1) and rejects a
   malformed or kind-mismatched payload with the corresponding DISCO_ERROR (§4.2, §9);
3. Enforces correlation per §4.2–§4.3 — a DISCO_QUERY and DISCO_SUBSCRIBE carry a unique
   `corr`, every reply and update echoes it verbatim, and replies are matched by `corr`
   rather than by frame sequence number, as NPAMP-BRIDGE §5 requires;
4. Emits and parses Discovery Records (§5) with `record_id`/`revision` replacement
   semantics (§8), carrying `protocol_id` and carriage-class values as defined by
   NPAMP-BRIDGE and the Bridge Protocol Identifier registry without reassigning them;
5. Answers a DISCO_QUERY with a faithful DISCO_RESULT — applying every present filter
   conjunctively (§6.1), never returning an over-broad result for an unsupported filter
   (replying `FilterUnsupported` instead), and never reporting `complete` true for a set
   it could not fully represent (§6.3, §9);
6. Honors subscriptions (§7.2–§7.3): it acknowledges with a snapshot, emits a
   DISCO_UPDATE for each in-filter add/replace/withdraw, and stops on DISCO_UNSUBSCRIBE
   or association close;
7. Treats discovery as a claim and not as authorization (§10): it enforces authorization
   at invocation independently of what it advertised, and applies the NPAMP-BRIDGE §7
   fail-safe to the advisory `effect` hint;
8. Advertises no protocol, tool, or agent it cannot in fact carry or reach over the
   association (§5.1), and carries no discovery state across associations (§8).

A conformance test suite SHOULD assert each clause above with a recorded exchange on the
Discovery channel: a filtered query and its result, a paginated query across at least two
result frames, a subscribe/update/unsubscribe sequence, a record replacement by
`revision`, and each DISCO_ERROR code provoked by a malformed or unsupported input.
