# NPAMP-IMMUNE — Immune-Channel Operation Framework (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words MUST, MUST NOT,
> REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL
> are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only
> when, they appear in all capitals, as shown here. This document defines a
> **native** operation framing for the N-PAMP **Immune channel `0x0005`**: the
> frame types, the deterministic-CBOR operation bodies, the in-body correlation
> discipline, and the structured error model by which one peer reports a detected
> **anomaly** to another peer and by which peers **propagate defensive gossip**
> among themselves. It builds on the core specification
> (draft-bubblefish-npamp-01) and does not redefine it. Unlike a Bridge carriage
> class, the Immune channel carries no foreign protocol: the operation body **is**
> N-PAMP's own encoding, so this document consumes no extension-TLV code point. It
> introduces no change to the core wire format. Where the Immune interface
> reference (`../channels/0005_immune.md`) records that the core specification
> reserves the propagation frame range `0x00C0`–`0x00C4` **without defining its
> semantics**, this document is the companion that finally defines it.

## 1. Scope

### 1.1 In scope

This document specifies, over the Immune channel `0x0005` of the N-PAMP core
specification (the "core specification", draft-bubblefish-npamp-01):

1. A set of Immune-channel frame types, drawn from the channel-specific
   application band that begins at `0x0100` (core specification §4.6, frame-type
   namespace), plus the five reserved companion-band code points
   `0x00C0`–`0x00C4` — the range the core specification reserves for
   "Immune-channel propagation extension frames" (`../09_extension_points.md`) —
   which this document finally defines;
2. Per-operation request and result frame pairs realizing the two operation
   classes the core registry names for this channel — **anomaly report** and
   **defensive gossip** — the anomaly-report pair in the application band and the
   defensive-gossip propagation frames in the reserved propagation band, plus a
   structured error frame;
3. The **deterministic-CBOR** encoding of every operation body (RFC 8949, core
   specification §4.5 and §11.9), keyed by unsigned integers;
4. An **in-body correlation** discipline that matches a reply to its request by a
   correlation token carried inside the CBOR body — consuming no shared TLV tag —
   which the Immune interface reference (`../channels/0005_immune.md` §4)
   explicitly defers to "an Immune operation encoding, when specified by a
   companion"; and
5. The **suppression, freshness, and hop-bound** propagation model that governs
   how a defensive-gossip item spreads beyond the pair that first observed it,
   together with a single structured **error frame**.

Operations are described generically — report an anomaly, acknowledge it,
advertise/pull/retract a defensive-gossip item — so that any anomaly detector and
any peer interoperate over N-PAMP with no bespoke adaptation. The document names
no product, no vendor, and no application-specific detector or threat taxonomy.

### 1.2 Not in scope

This document does NOT:

* **Define an anomaly-detection algorithm or threat taxonomy.** The
  `anomaly_class`, `severity`, and `confidence` fields (§6) are the *wire*
  projection a peer exposes; how a peer detects an irregularity, scores it, or
  classifies a threat is a local matter this document does not constrain. It fixes
  only what crosses the wire.
* **Define the fan-out or peer-selection policy of gossip.** This document defines
  how a single advertise/pull/retract exchange is encoded and the suppression,
  freshness, and hop-bound rules that keep propagation convergent (§7); it assigns
  no fan-out degree, no peer-selection strategy, and no rumor-mongering schedule,
  because how many peers a node gossips to and how often are deployment choices,
  not interoperability contracts.
* **Define authorization, governance, or admission policy.** Whether a peer acts
  on a report, accepts a gossip item, or refuses one is the receiver's local
  decision; this document defines only how each outcome is *reported* on the wire
  (§8), not the policy that produces it.
* **Carry a foreign agent protocol.** The Immune channel is native; it is not a
  Bridge carriage class and does not build on NPAMP-BRIDGE (Immune interface
  reference `../channels/0005_immune.md` §6). No frame in this document
  encapsulates a foreign message, and this document defines and consumes no
  extension-TLV tag.
* **Bind the AnomalyCharge TLV to this channel.** The core specification's TLV
  `0x12` "AnomalyCharge" is a general per-frame integrity charge (Immune interface
  reference §4); despite the thematic name it is not an Immune operation, and no
  frame in this document uses it.
* **Change the core wire format.** It alters no field of the core frame header, no
  reserved all-channel frame type, the extension-TLV encoding, or any code point
  the core specification assigns; it uses only code points the core specification
  reserves for the Immune channel.

## 2. Relationship to the core specification

The Immune channel `0x0005` is registered by the core specification with purpose
**"Anomaly reports and defensive gossip"**, minimum profile **Standard**, and
direction **Bidirectional** (core specification §5; `../../registries/channels.csv`;
Immune interface reference `../channels/0005_immune.md` §2). Under the core
specification's channel architecture every channel is full-duplex: each peer
maintains an independent per-direction sequence space and independent
per-direction traffic keys, so both peers MAY transmit on the channel
simultaneously. Either peer MAY originate an Immune operation. The Immune channel
is **not** Multi-stream: it does not open multiple concurrent transport
sub-streams within a stream family (Immune interface reference §2), so this
document defines no multi-stream retrieval; a single advertise/pull exchange is
carried on the one Immune stream in each direction.

**Minimum-profile gate.** A peer MUST enable the Immune channel only at the
**Standard** profile or higher; once Standard is met the channel is available at
Standard, High, and Sovereign, and there is no profile at which it becomes
unavailable. A peer that has not advertised the Immune channel during the
handshake (core specification §5) MUST NOT receive frames on it; a frame arriving
on an unadvertised Immune channel MUST be dropped and MUST NOT be delivered to the
anomaly-report or gossip logic.

**Priority scheduling.** The core specification singles out the **Control and
Immune channels**, stating they SHOULD be scheduled at higher priority than the
bulk channels (Memory, Sensory, Telemetry) during congestion (core specification
§5; Immune interface reference §5). Immune anomaly-report and defensive-gossip
traffic is therefore intended to be delivered promptly even when lower-priority
channels are congested. This document inherits that posture unchanged; it is a
scheduling recommendation on delivery order, not a change to the interface.

**Native, not a carriage class.** A Bridge carriage class carries a *foreign*
protocol's message octet-for-octet and wraps routing and correlation metadata
*around* it in a shared extension TLV. The Immune channel has no foreign protocol:
the operation body is N-PAMP's own deterministic-CBOR encoding, and this document
owns that body in full. Consequently the correlation token, the operation
semantics, and the error object all live **inside** the CBOR body, and this
document reserves and consumes **no extension-TLV code point**. An Immune
operation is routed by its N-PAMP **frame type** (§3), not by any method-name
field parsed from a body.

**Frame-type namespace bands.** The core specification partitions each channel's
`0x0000`–`0xFFFF` frame-type space into four bands (core specification §4.6,
Frame-Type Namespace): `0x0000`–`0x000A` reserved all-channel frame types with the
same meaning on every channel; `0x000B`–`0x002F` unassigned, reserved to the core
for future all-channel additions; `0x0030`–`0x00FF` the **companion-extension
band**, per-channel extension frame types defined by companion specifications; and
`0x0100`–`0xFFFF` **channel-specific application** frame types. This document
places its anomaly-report frames and its channel-wide error frame in the
application band at `0x0100`+ on the Immune channel, and defines the five Immune
propagation code points `0x00C0`–`0x00C4` that sit in the companion-extension band
(§3.3). Because the frame-type space is scoped by the Channel ID header field,
these code points do not collide with any other channel's assignments at the same
numeric values.

> **Editorial note (carried, not corrected here).** The core specification states
> that channel-specific frame types begin at `0x0100` (§4.6), yet the reserved
> Immune propagation range `0x00C0`–`0x00C4` sits in the companion-extension band
> below `0x0100`. This is the reserved-range placement the core specification and
> the Immune interface reference (`../channels/0005_immune.md` §3.2) record; this
> document defines those reserved code points as authorized and does not rewrite
> the authoritative range.

## 3. Immune-channel frame types

Within the Immune channel (`0x0005`) frame-type namespace, this specification
defines eight frame types: three in the channel-specific application band at
`0x0100`+, and five in the reserved companion-extension propagation band at
`0x00C0`–`0x00C4`.

### 3.1 Application-band operation frames (`0x0100`+)

| Type | Name | Reply | Purpose |
|---|---|---|---|
| `0x0100` | IMMUNE_REPORT_REQ | IMMUNE_REPORT_RESULT or IMMUNE_ERROR | Report a detected operational or security irregularity ("anomaly") to the peer. |
| `0x0101` | IMMUNE_REPORT_RESULT | None | Success reply to a report; carries the receiver's disposition and echoes the request's correlation token. |
| `0x0102` | IMMUNE_ERROR | None | Structured failure for any Immune request; echoes the correlation token and carries an Immune error code (§8). |

An IMMUNE_REPORT_REQ originates the anomaly-report operation; the corresponding
IMMUNE_REPORT_RESULT, or an IMMUNE_ERROR (`0x0102`), replies to it. A `*_RESULT`
frame is never sent unsolicited: it MUST echo the correlation token of the request
it answers (§5). A receiver MUST NOT emit both a `*_RESULT` and an IMMUNE_ERROR for
the same request. IMMUNE_ERROR is the single channel-wide error frame and replies
to a failed request of **either** operation class, application-band or
propagation-band alike (§8).

### 3.2 Reserved all-channel frame types

The reserved all-channel frame types (PING `0x0001`, PONG `0x0002`, CLOSE
`0x0003`, CLOSE_ACK `0x0004`, ERROR `0x0005`, KEY_UPDATE `0x0006`,
KEY_UPDATE_ACK `0x0007`, PATH_CHALLENGE `0x0008`, PATH_RESPONSE `0x0009`, and
FLOW_UPDATE `0x000A`; core specification §4.6) retain their core meaning on the
Immune channel. An implementation MUST NOT reuse them for Immune application
traffic, MUST NOT define Immune operation semantics in the reserved all-channel
range `0x0000`–`0x000A`, and MUST NOT use `0x0000` as a frame type.

### 3.3 Immune defensive-gossip propagation frames (`0x00C0`–`0x00C4`)

The core specification reserves the range `0x00C0`–`0x00C4` in the
companion-extension band specifically for Immune-channel **propagation** extension
frames, and states that a companion specification may define them, defining none
itself (core specification §8, Reserved Frame-Type Ranges;
`../09_extension_points.md`; Immune interface reference `../channels/0005_immune.md`
§3.2). This document is that companion; it defines those five code points as the
defensive-gossip propagation exchange:

| Type | Name | Reply | Purpose |
|---|---|---|---|
| `0x00C0` | IMMUNE_GOSSIP_ADVERTISE | IMMUNE_GOSSIP_ACK or IMMUNE_ERROR | Propagate a set of defensive-gossip item descriptors (each an `item_id` + `version`), either advertising them by digest (pull-mode) or pushing their full bodies inline. |
| `0x00C1` | IMMUNE_GOSSIP_ACK | None | Reply to an ADVERTISE or a RETRACT; echoes the correlation token and reports which advertised items the receiver already holds (suppressed) and which it still wants pulled in full. |
| `0x00C2` | IMMUNE_GOSSIP_PULL_REQ | IMMUNE_GOSSIP_PULL_RESULT or IMMUNE_ERROR | Request the full body of one or more advertised items the receiver lacks or holds at a staler version. |
| `0x00C3` | IMMUNE_GOSSIP_PULL_RESULT | None | Deliver the requested full gossip-item bodies; echoes the PULL_REQ's correlation token. |
| `0x00C4` | IMMUNE_GOSSIP_RETRACT | IMMUNE_GOSSIP_ACK or IMMUNE_ERROR | Withdraw a previously propagated item (for example a false positive), suppressing its further propagation from a stated `version` onward. |

These five code points sit in the `0x0030`–`0x00FF` companion-extension band and
are scoped to the Immune channel; an implementation MUST NOT assign them to any
purpose other than the defensive-gossip propagation operations defined here, MUST
NOT treat propagation as behavior defined by the core specification alone (the core
reserves the range; this companion defines it), and MUST NOT infer any propagation
mechanism the core reserves but does not define beyond what §7 states. The
defensive-gossip operation is OPTIONAL to implement; a receiver that does not
implement it MUST reply IMMUNE_ERROR with code `unknown_operation` (§8) to a
propagation-band frame, and a peer MUST still support the anomaly-report operation
(§3.1) to be conformant (§10).

All eight frame types defined above lie within the Immune channel's own frame-type
namespace: three in the application band at or above `0x0100`, and five in the
companion-extension band reserved for this channel. This document consumes no
frame-type code point outside the Immune channel's namespace and reserves none in
the core specification's cross-channel reserved ranges.

## 4. Frame payload encoding

### 4.1 Payload container

An Immune frame's payload (the octets after the core frame header and any
extension TLVs, and before the AEAD tag) is a single **deterministically encoded
CBOR** object as defined by the core specification §4.5 and §11.9 (deterministic
CBOR, RFC 8949). The payload MUST be a CBOR map whose keys are the unsigned
integers defined in §4.2 and §5–§8 for the relevant frame type. A sender MUST
produce the deterministic encoding (core specification §11.9): byte-identical
output for identical inputs, with the canonical key ordering and shortest-form
integer encoding RFC 8949 §4.2 requires, and definite-length maps and arrays.

A receiver MUST reject, with IMMUNE_ERROR code `malformed_request` (§8), any
Immune frame whose payload is not a valid deterministic-CBOR map, whose payload
omits a REQUIRED key for its frame type, or whose payload carries a key of the
wrong CBOR major type.

Immune operation bodies are carried in the frame **payload**, not in extension
TLVs. This document defines and consumes no extension-TLV tag, and therefore
claims none of the TLV code points the core specification reserves — including the
AnomalyCharge TLV `0x12`, which is a general integrity mechanism and not an Immune
operation (Immune interface reference `../channels/0005_immune.md` §4).

### 4.2 Common envelope fields

Every Immune payload map carries the following two envelope fields. Integer keys
are given in parentheses.

| Field (key) | CBOR type | Meaning |
|---|---|---|
| `frame_kind` (0) | Unsigned int | MUST equal the frame's Immune frame type (one of `0x0100`–`0x0102` or `0x00C0`–`0x00C4`). A receiver MUST reject (IMMUNE_ERROR, code `malformed_request`) a payload whose `frame_kind` contradicts the frame-header Frame Type. |
| `corr` (1) | Byte string (1–64 B) | Correlation token (§5). Present and non-empty on every request (IMMUNE_REPORT_REQ, IMMUNE_GOSSIP_ADVERTISE, IMMUNE_GOSSIP_PULL_REQ, IMMUNE_GOSSIP_RETRACT) and on every frame that replies to one. |

The per-frame body fields defined in §5–§8 occupy keys `2` and above within the
same map; §6 gives, per frame, the full field table.

### 4.3 Forward compatibility

A receiver MUST ignore an unrecognized integer key it encounters in an Immune
payload map whose key is **not negative**, so that a later revision of this
document MAY add fields without breaking a conformant receiver. A receiver MUST
reject (IMMUNE_ERROR, code `malformed_request`) a payload that carries a
**negative** integer key it does not recognize, reserving the negative key space
for forward-incompatible additions. A receiver MUST NOT treat the mere presence of
an unknown non-negative key as an error, and MUST NOT alter its handling of the
keys it does recognize because of it. The same rule applies to the nested
descriptor and item maps of §6 and §7.

## 5. Correlation and operation model

The core specification does not define how an Immune reply is correlated to its
request; the Immune interface reference states that "an Immune operation encoding,
when specified by a companion, is where such correlation would be defined"
(`../channels/0005_immune.md` §4). This document supplies that discipline,
carrying the token **inside** the CBOR body rather than in a shared TLV, because a
native channel owns its whole body (§2).

### 5.1 Correlation discipline

* Every request frame — IMMUNE_REPORT_REQ (`0x0100`), IMMUNE_GOSSIP_ADVERTISE
  (`0x00C0`), IMMUNE_GOSSIP_PULL_REQ (`0x00C2`), and IMMUNE_GOSSIP_RETRACT
  (`0x00C4`) — MUST carry a non-empty `corr` (§4.2) that is unique among the
  originating peer's outstanding Immune requests on the channel in that direction.
* Every reply — IMMUNE_REPORT_RESULT, IMMUNE_GOSSIP_ACK, IMMUNE_GOSSIP_PULL_RESULT,
  and IMMUNE_ERROR — MUST echo the originating request's `corr` verbatim.
* A receiver MUST match a reply to its request by `corr`, **not** by the
  per-(channel, direction) frame sequence number. Although the Immune channel is a
  single stream in each direction (it is Bidirectional, not Multi-stream, §2), a
  peer MAY have several report or gossip exchanges outstanding at once, a reply MAY
  be deferred while intervening Immune frames (a PING, another peer's report, a
  gossip advertise) are interleaved on the stream, and a pull is a **separate later
  exchange** from the advertise that prompted it; sequence position therefore does
  not identify the originating exchange, and `corr` does.

### 5.2 Correlation lifetime

A `corr` value associated with an anomaly report is consumed when its
IMMUNE_REPORT_RESULT or IMMUNE_ERROR is delivered; the requester MUST treat that
exchange as complete and MUST NOT reuse the value for a new request while the
original is outstanding. A `corr` associated with an IMMUNE_GOSSIP_ADVERTISE or an
IMMUNE_GOSSIP_RETRACT is consumed by its IMMUNE_GOSSIP_ACK or IMMUNE_ERROR; a
`corr` associated with an IMMUNE_GOSSIP_PULL_REQ is consumed by its
IMMUNE_GOSSIP_PULL_RESULT or IMMUNE_ERROR. The pull that a receiver issues after an
advertise is a **new request** in the receiver's own direction and carries the
receiver's own fresh `corr`; it does not reuse the advertise's `corr`.

## 6. Operation bodies

Each operation body is a deterministic-CBOR map carrying the common envelope
(§4.2, keys `0`–`1`) and the per-frame fields below at keys `2`+. Unless a field is
marked required, it is OPTIONAL and, when absent, carries no value (a producer
omits the key rather than encoding a null placeholder; a producer that does encode
an explicit CBOR `null` for an absent OPTIONAL field is equivalent to omitting it).

### 6.1 Enumerations

Two small enumerations are shared by the anomaly-report and gossip bodies.

**`anomaly_class`** (unsigned int) — the kind of irregularity:

| Value | Name | Meaning |
|---|---|---|
| `0x00` | operational | An operational irregularity (for example a resource, timing, or availability anomaly). |
| `0x01` | security | A suspected security irregularity (for example an authentication or access anomaly). |
| `0x02` | integrity | A data- or state-integrity irregularity. |
| `0x03` | availability | A liveness or reachability irregularity. |
| `0x04` | other | An irregularity that fits none of the above. |

A receiver MUST treat an `anomaly_class` value it does not recognize as `0x04`
`other` and MUST NOT drop the report or item on that basis alone.

**`severity`** (unsigned int) — the reporter's severity assessment:

| Value | Name |
|---|---|
| `0x00` | info |
| `0x01` | low |
| `0x02` | medium |
| `0x03` | high |
| `0x04` | critical |

**Fail-safe (severity).** A receiver MUST treat a report or gossip item that omits
`severity`, or that carries a `severity` value it does not recognize, as `0x04`
`critical` — the most severe class. Because this is a defensive channel, an unknown
or absent severity MUST NOT be under-prioritized: a peer MUST NOT let a malformed
or forward-incompatible severity cause it to treat a possible threat as low. This
is the Immune analogue of the Memory channel's destructive-by-default fail-safe
(NPAMP-MEMORY §5.3).

### 6.2 IMMUNE_REPORT_REQ (`0x0100`) / IMMUNE_REPORT_RESULT (`0x0101`)

Report a detected operational or security irregularity observed by one peer to
another peer.

**IMMUNE_REPORT_REQ body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `report_id` (2) | Text string | Yes | A stable identifier the reporter assigns to this anomaly report, unique within the reporter's namespace. |
| `anomaly_class` (3) | Unsigned int | Yes | The kind of irregularity (§6.1). |
| `severity` (4) | Unsigned int | Yes | The reporter's severity assessment (§6.1). |
| `detected_at` (5) | Text string | No | When the anomaly was observed, as an RFC 3339 timestamp. |
| `subject` (6) | Text string | No | A peer-safe label for the entity or component the anomaly concerns. |
| `detail` (7) | Text string | No | A peer-safe, human-readable description of the anomaly. It MUST NOT carry internal detail (§8.2, §9). |
| `evidence_digest` (8) | Byte string | No | A digest (for example a hash) over the reporter's local evidence, disclosing that evidence exists and letting the peer correlate reports without disclosing the evidence itself. |
| `confidence` (9) | Unsigned int (0–100) | No | The reporter's confidence in the anomaly, as a percentage. |
| `expires_at` (10) | Text string | No | An RFC 3339 freshness horizon after which the reporter considers the report stale. |

**IMMUNE_REPORT_RESULT body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `disposition` (2) | Unsigned int | Yes | The receiver's disposition of the report (§6.3). |
| `tracking_id` (3) | Text string | No | An identifier the receiver assigns to an accepted report, by which the reporter MAY reference it later. |

A responder MUST reply IMMUNE_REPORT_RESULT (or IMMUNE_ERROR) to every
IMMUNE_REPORT_REQ; a report is never silently dropped by an advertised, conformant
peer. A responder that refuses the report by policy replies IMMUNE_ERROR
`policy_denied` (§8), not a RESULT.

### 6.3 Report disposition

The `disposition` field of IMMUNE_REPORT_RESULT (§6.2) is one of:

| Value | Name | Meaning |
|---|---|---|
| `0x00` | acknowledged | The report was received and recorded; the receiver states no further intent. |
| `0x01` | accepted | The report was received and the receiver intends to act on it. |
| `0x02` | duplicate | The receiver already holds an equivalent report (for example by `report_id` or `evidence_digest`). |
| `0x03` | below_threshold | The report was received but is below the receiver's local action threshold. |

A receiver MUST treat a `disposition` it does not recognize as `0x00`
`acknowledged` for forward compatibility; the reporter MUST NOT infer that a report
was ignored merely because the disposition value is unfamiliar.

### 6.4 IMMUNE_GOSSIP_ADVERTISE (`0x00C0`) / IMMUNE_GOSSIP_ACK (`0x00C1`)

Propagate a set of defensive-gossip item descriptors. The advertiser either
advertises items by digest for the receiver to pull (pull-mode) or pushes their
full bodies inline (push-mode), governed by `inline`.

**IMMUNE_GOSSIP_ADVERTISE body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `items` (2) | Array of `gossip_descriptor` | Yes | The advertised item descriptors, in no required order (possibly empty). |
| `inline` (3) | Boolean | No | True if each descriptor carries its full `body` (§6.6) inline (push-mode); absent or false means digests only, and the receiver pulls the bodies it wants (§6.5). |

A `gossip_descriptor` is a CBOR map:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `item_id` (0) | Byte string | Yes | A stable identifier for the gossip item, the same in every peer that holds it (for example a hash of the item's canonical descriptor). It is the correlation key of propagation. |
| `version` (1) | Unsigned int | Yes | A monotonic freshness counter set by the item's originator; a higher `version` supersedes a lower one for the same `item_id` (§7.1). |
| `anomaly_class` (2) | Unsigned int | No | The kind of irregularity the item concerns (§6.1). |
| `severity` (3) | Unsigned int | No | The item's severity (§6.1; the §6.1 fail-safe applies). |
| `origin` (4) | Byte string | No | An opaque handle for the peer that first originated the item. |
| `first_seen_at` (5) | Text string | No | An RFC 3339 timestamp of when the item was first originated. |
| `expires_at` (6) | Text string | No | An RFC 3339 freshness horizon after which the item MUST NOT be propagated (§7.2). |
| `hops_remaining` (7) | Unsigned int | No | The remaining propagation budget (§7.3). Absent means the receiver applies its local default bound. |
| `digest` (8) | Byte string | No | A content digest over the item body, letting a receiver detect that a held item's body has changed at equal `version`. |
| `body` (9) | Byte string | No | The full defensive-gossip item body — an opaque, peer-safe descriptor of the defensive signal. Present only when `inline` is true (push-mode). |

**IMMUNE_GOSSIP_ACK body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `wanted` (2) | Array of Byte string | No | The `item_id`s the receiver lacks, or holds at a lower `version`, and wishes to pull in full (§6.5). Absent or empty means the receiver wants none. |
| `known` (3) | Array of Byte string | No | The advertised `item_id`s the receiver already holds at greater-than-or-equal `version` and has therefore suppressed (§7.1). |
| `accepted` (4) | Unsigned int | No | The count of advertised items the receiver newly recorded (relevant in push-mode, where bodies arrived inline). |

An IMMUNE_GOSSIP_ACK MUST echo the ADVERTISE's `corr` (§5). In pull-mode a receiver
that lists `item_id`s in `wanted` then issues an IMMUNE_GOSSIP_PULL_REQ (§6.5) in
its own direction to fetch them.

### 6.5 IMMUNE_GOSSIP_PULL_REQ (`0x00C2`) / IMMUNE_GOSSIP_PULL_RESULT (`0x00C3`)

Fetch the full body of advertised items.

**IMMUNE_GOSSIP_PULL_REQ body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `item_ids` (2) | Array of Byte string | Yes | The `item_id`s to fetch in full (non-empty). |

**IMMUNE_GOSSIP_PULL_RESULT body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `items` (2) | Array of `gossip_item` | Yes | The requested full item bodies, in no required order (possibly empty if none are still held). |

A `gossip_item` is a CBOR map with the same identity and metadata keys as a
`gossip_descriptor` (§6.4, keys `0`–`7`) and a REQUIRED body:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `item_id` (0) | Byte string | Yes | Identity of the item (as §6.4). |
| `version` (1) | Unsigned int | Yes | Freshness counter (as §6.4). |
| `anomaly_class` (2) | Unsigned int | No | The kind of irregularity (§6.1). |
| `severity` (3) | Unsigned int | No | Severity (§6.1). |
| `origin` (4) | Byte string | No | Opaque originator handle. |
| `first_seen_at` (5) | Text string | No | RFC 3339 first-origination time. |
| `expires_at` (6) | Text string | No | RFC 3339 freshness horizon (§7.2). |
| `hops_remaining` (7) | Unsigned int | No | Remaining propagation budget (§7.3). |
| `body` (8) | Byte string | Yes | The full defensive-gossip item body. |

A responder MUST return, for a requested `item_id` it no longer holds or that has
expired (§7.2), either a `gossip_item` omitted from `items` or an IMMUNE_ERROR
`not_found` (§8) — it MUST NOT fabricate a body. A PULL_RESULT MUST echo the
PULL_REQ's `corr` (§5).

### 6.6 IMMUNE_GOSSIP_RETRACT (`0x00C4`)

Withdraw a previously propagated item — for example one later found to be a false
positive — so that peers stop propagating it.

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `item_id` (2) | Byte string | Yes | The item to withdraw. |
| `version` (3) | Unsigned int | Yes | The retraction's freshness counter; MUST be greater than or equal to the item's last known `version`, so a retraction is itself freshness-ordered and a stale re-advertise cannot resurrect the item (§7.4). |
| `reason` (4) | Unsigned int | No | Why the item is withdrawn: `0x00` false_positive, `0x01` resolved, `0x02` superseded. A receiver MUST treat an unrecognized value as `0x00` false_positive. |

An IMMUNE_GOSSIP_RETRACT is answered by an IMMUNE_GOSSIP_ACK (echoing the RETRACT's
`corr`; its `wanted`/`known` fields MAY be empty) or by IMMUNE_ERROR. A receiver
that does not hold the item MUST still record the retraction so that a later
advertise at a `version` less than or equal to the retraction's is suppressed
(§7.4).

## 7. Defensive-gossip propagation model

The defensive-gossip operation spreads an item beyond the pair that first observed
it. This section fixes the convergence rules a conformant implementation MUST apply
so that propagation terminates and does not amplify indefinitely. It defines the
**per-exchange** wire behavior and the **suppression/freshness/hop** rules; it does
NOT define fan-out degree, peer selection, or gossip scheduling (§1.2), which are
local matters.

### 7.1 Freshness and suppression

Each item is identified by `item_id` and ordered by `version` (§6.4). A receiver
that is advertised an `item_id` it already holds at a `version` greater than or
equal to the advertised one MUST treat the item as **known**: it MUST NOT request
the item in `wanted`, SHOULD report it in `known` (§6.4), and SHOULD NOT re-offer a
strictly older `version` back to the advertiser. A receiver holding a strictly
lower `version`, or not holding the item at all, MAY request it via `wanted` and a
subsequent IMMUNE_GOSSIP_PULL_REQ (§6.5). This freshness-and-suppression rule is
what makes repeated advertisement of an unchanged item converge rather than loop.

### 7.2 Expiry

An item that carries `expires_at` MUST NOT be propagated (advertised, pushed, or
returned in a pull) once that horizon has passed; a receiver MUST treat an expired
item as absent for the purpose of §6.5 (`not_found`) and SHOULD discard its local
copy. Expiry bounds how long a defensive signal circulates.

### 7.3 Hop bound

An item MAY carry `hops_remaining`, a propagation budget. A peer that re-advertises
or re-pushes an item it received MUST decrement `hops_remaining` by at least one
before propagating it onward, and MUST NOT propagate an item whose
`hops_remaining` has reached `0`. A peer that originates an item sets the initial
budget; a peer that receives an item with no `hops_remaining` applies its local
default bound. The hop bound, together with freshness suppression (§7.1) and expiry
(§7.2), bounds the reach and lifetime of an epidemic so that defensive gossip
saturates its neighborhood and stops, rather than circulating without limit.

### 7.4 Retraction ordering

A retraction (§6.6) at `version` V suppresses its `item_id`: after recording a
retraction at V, a receiver MUST NOT re-accept, request, or re-propagate that
`item_id` at any `version` less than or equal to V, even if subsequently advertised
by another peer. A genuine newer item MAY still supersede the retraction only at a
`version` strictly greater than V. This ordering prevents a stale copy of a
retracted false positive from resurrecting through another propagation path.

## 8. Error model

Every failure of an Immune request is reported in a single IMMUNE_ERROR (`0x0102`)
frame — the Immune channel has no foreign protocol, so all errors are native and
carried in one structured frame that serves both the anomaly-report and the
defensive-gossip operations. An IMMUNE_ERROR echoes the failed request's `corr`
(§5) and carries:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `code` (2) | Unsigned int | Yes | One of the Immune error codes below. |
| `message` (3) | Text string | Yes | A peer-safe, generic human-readable message for `code`. It MUST NOT carry internal detail (§8.2). |
| `retry_after_s` (4) | Unsigned int | No | When present, the number of seconds after which the requester MAY retry (for example under `rate_limited`). |

| Code | Name | Meaning |
|---|---|---|
| 1 | malformed_request | The CBOR body is not valid deterministic CBOR, omits a REQUIRED field, uses a wrong CBOR major type, or carries an unknown negative key (§4). |
| 2 | unknown_operation | The frame type is not an Immune operation the responder implements — in particular a propagation-band frame (`0x00C0`–`0x00C4`) at a responder that implements only the anomaly-report operation (§3.3). |
| 3 | policy_denied | The report or gossip item was refused by the responder's governance or policy: a definitive refusal. |
| 4 | rate_limited | The responder is shedding load and declines the request; the requester MAY retry after `retry_after_s` (§9). |
| 5 | not_found | A requested item does not exist at the responder or has expired (an IMMUNE_GOSSIP_PULL_REQ target; §6.5, §7.2). |
| 6 | internal_error | A responder-side failure it cannot attribute to the request. Generic; no internal detail crosses the wire (§8.2). |

### 8.1 A denied report is an error, not a silent drop

A conformant, advertised peer MUST answer every Immune request with a `*_RESULT`
or an IMMUNE_ERROR; it MUST NOT accept a request at the wire level and then drop it
without a reply. A report the receiver refuses by policy is reported as
IMMUNE_ERROR `policy_denied` (§8), distinct from an IMMUNE_REPORT_RESULT whose
`disposition` is `below_threshold` (§6.3): `policy_denied` is a refusal to accept
the report at all, whereas `below_threshold` is acceptance of a report the receiver
will not act on. A requester MUST distinguish the two.

### 8.2 No internal detail on the wire

The `message` field MUST be the generic, peer-safe string for its `code`. The full
internal cause of a failure MUST be handled locally (for example logged by the
responder) and MUST NOT cross the wire: an IMMUNE_ERROR MUST NOT carry detector
internals, policy topology, configuration or source names, decoder diagnostics, or
any other detail beyond the code and its generic message. This leak-prevention
requirement is normative for interoperability, not merely local hygiene: a
requester MUST be able to rely on the error surface exposing only a code, a generic
message, and the OPTIONAL `retry_after_s` field.

## 9. Security and privacy considerations

This section supplements the core specification's Security Considerations; it does
not restate them.

Every Immune frame is AEAD-protected like all N-PAMP frames and is carried under
the association's existing authentication (the core specification's handshake binds
both peer identities into the transcript and the Finished MAC). A responder
therefore knows that a report or gossip item was sent by the authenticated peer,
but **authentication is not authorization**: a responder MUST enforce its own
governance and access policy on every report and every gossip item regardless of
the peer's identity, and MUST report the outcome per §8 — including the
`policy_denied` refusal.

Anomaly reports and gossip items describe possible threats and can be sensitive.
An implementation MUST NOT place internal detail on the wire (§8.2): the
peer-safe `detail` field and the `evidence_digest` (§6.2) let a reporter share the
existence and shape of an anomaly, and let peers correlate reports, **without**
disclosing raw evidence, detector internals, or the reporter's internal topology. A
receiver SHOULD treat received reports and gossip items as sensitive and disclose
them onward only per local policy.

Because a defensive-gossip item propagates beyond the originating pair, an
implementation MUST bound propagation. The freshness/suppression rule (§7.1), the
expiry horizon (§7.2), and the hop bound (§7.3) together ensure an epidemic
terminates; an implementation MUST enforce them and MUST NOT re-propagate an item
that suppression, expiry, or a zero hop budget forbids. A receiver MUST also be
able to distrust gossip: a gossip item is an assertion by the sending peer, not a
proven fact, and a receiver MUST NOT treat a received item as authoritative solely
because it arrived — it applies its own policy (§8, `policy_denied`), and MAY
retract an item it originated and later finds false (§6.6).

A responder MUST bound the resources a remote peer can consume through Immune
operations: the rate of reports and advertisements it will accept, the size of a
`wanted`/`item_ids` list it will honor, and the size of a pushed or pulled item
body it will buffer. A responder MAY reply IMMUNE_ERROR `rate_limited` (with
`retry_after_s`) rather than allocate without limit. Because either peer may
originate operations on this Bidirectional channel, both directions are subject to
these limits. The Immune channel's priority-scheduling posture (§2) governs
delivery order under congestion; it does not exempt Immune traffic from these
resource bounds, and a peer MUST NOT let the channel's priority be used to amplify
a flood.

## 10. Conformance

An implementation conforms to NPAMP-IMMUNE if and only if it rests on a
core-conformant N-PAMP wire implementation and, on the Immune channel `0x0005`, it:

1. Treats `0x0005` as the Immune channel with the core registry identity
   (name Immune; purpose anomaly reports and defensive gossip; minimum profile
   Standard; direction Bidirectional), does not repurpose the channel identifier,
   enables it only at the **Standard** profile or higher, treats it as available at
   Standard, High, and Sovereign once Standard is met, and drops any frame received
   on an unadvertised Immune channel (§2);
2. Uses only the Immune frame types defined in §3 — the application-band frames
   IMMUNE_REPORT_REQ `0x0100`, IMMUNE_REPORT_RESULT `0x0101`, IMMUNE_ERROR `0x0102`,
   and the propagation-band frames `0x00C0`–`0x00C4` — preserves the core meaning
   of the reserved all-channel frame types `0x0000`–`0x000A`, and assigns
   `0x00C0`–`0x00C4` to no purpose other than the defensive-gossip propagation
   operations defined here (§3);
3. Encodes every operation body as a deterministic-CBOR map (§4.1) with the integer
   keys of §4.2 and §5–§8; rejects a non-deterministically-encoded body, a body
   missing a REQUIRED field, a wrong-major-type key, a `frame_kind` that
   contradicts the frame header, or an unknown negative key with IMMUNE_ERROR
   `malformed_request`; and ignores an unknown non-negative key without altering its
   handling of recognized keys (§4.2, §4.3);
4. Carries a non-empty `corr` on every request (IMMUNE_REPORT_REQ,
   IMMUNE_GOSSIP_ADVERTISE, IMMUNE_GOSSIP_PULL_REQ, IMMUNE_GOSSIP_RETRACT), echoes
   it verbatim on every reply, and matches replies to requests by `corr` rather than
   by frame sequence number (§5);
5. Implements the anomaly-report operation — answering every IMMUNE_REPORT_REQ with
   an IMMUNE_REPORT_RESULT carrying a `disposition` (§6.3) or an IMMUNE_ERROR, never
   a silent drop — and applies the severity fail-safe, treating a missing or unknown
   `severity` as `critical` (§6.1, §6.2, §8.1);
6. If it implements the OPTIONAL defensive-gossip operation, realizes the
   advertise/ack, pull, and retract exchanges of §6.4–§6.6 and enforces the
   propagation-convergence rules of §7 — freshness suppression (§7.1), expiry
   (§7.2), the decrement-and-stop hop bound (§7.3), and retraction ordering
   (§7.4) — and if it does not implement defensive gossip, replies IMMUNE_ERROR
   `unknown_operation` to any propagation-band frame (§3.3);
7. Reports every failure as IMMUNE_ERROR (`0x0102`) with a code from §8 and a
   peer-safe `message`, never leaking internal cause (§8.2), and distinguishes a
   `policy_denied` refusal from a `below_threshold` acceptance (§8.1); and
8. Enforces resource bounds on both directions of this Bidirectional channel,
   MAY shed load with IMMUNE_ERROR `rate_limited` and `retry_after_s`, and does not
   let the channel's priority-scheduling posture be used to amplify a flood or to
   bypass the propagation bounds of §7 (§9).

A conformance test suite SHOULD assert each clause above with a recorded exchange
on the Immune channel `0x0005`: an IMMUNE_REPORT_REQ / IMMUNE_REPORT_RESULT pair
whose result carries each `disposition`; an IMMUNE_REPORT_REQ refused with
IMMUNE_ERROR `policy_denied`, distinct from one accepted `below_threshold`; an
IMMUNE_GOSSIP_ADVERTISE / IMMUNE_GOSSIP_ACK exchange in both pull-mode and
push-mode; an IMMUNE_GOSSIP_PULL_REQ / IMMUNE_GOSSIP_PULL_RESULT pair and a
`not_found` for an expired item; an IMMUNE_GOSSIP_RETRACT that suppresses a later
stale re-advertise (§7.4); a propagation-band frame rejected with
`unknown_operation` at a report-only responder; and a rejected malformed body (a
non-deterministic encoding, a missing REQUIRED field, and an unknown negative key),
each yielding `malformed_request`.

Machine-gradable conformance vectors exist for the Immune channel's payload-decode
surface. The `immune.body.decode` operation group in the conformance corpus —
produced by an independent RFC 8949 byte constructor
(`test-vectors/gen/immune_oracle.py`) and graded by `npamp-conform` against the
reference implementation (`impl/go/immune.go`, `impl/go/immune_bodies.go`,
`impl/go/immune_api.go`) — covers the §4.1 / §4.2 / §4.3 payload-encoding and
common-envelope MUST-reject clauses: the deterministic-CBOR container, the
`frame_kind` / `corr` envelope, and the missing-REQUIRED-field, wrong-major-type,
and unknown-negative-key rejections. Its expected values are produced by that
independent RFC 8949 byte constructor, not by the implementation under test, so the
vectors are non-circular, and they are cross-validated by
`impl/go/zz_immune_oracle_xval_test.go`. That payload-encoding and common-envelope
surface is therefore graded, and `../../.shippable/spec-parity.json` records the
Immune entry accordingly (impl status wired, conformance status graded).

Beyond that payload surface, the §5–§9 behavioural clauses — the correlation and
operation model (§5), the anomaly-report disposition flow (§6), the
defensive-gossip propagation-convergence rules of §7 (freshness suppression,
expiry, hop bound, and retraction ordering), the `policy_denied` /
`below_threshold` distinction (§8.1), and the no-internal-detail leak-prevention
requirement (§8.2) — are graded only by a live-exchange harness once one exists.
Until such a harness is authored, conformance to those clauses is established by a
recorded live exchange on the Immune channel `0x0005` (the clause-by-clause
exchange described above), and a conformance claim for them names that recorded
exchange, not the pinned vector corpus.
