# NPAMP-COMMERCE — Commerce-Channel Operation Framework (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words MUST, MUST NOT,
> REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL
> are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only
> when, they appear in all capitals, as shown here. This document defines a
> **native** operation framing for the N-PAMP **Commerce channel `0x000E`**: the
> frame types, the deterministic-CBOR operation bodies, the in-body correlation
> discipline, the operation and state model, and the structured error model by
> which one peer conducts N-PAMP-native agentic commerce with another — issuing and
> managing **payment mandates** (authorization-to-pay artifacts) and proposing
> **multi-party settlement intents**. It builds on the core specification
> (draft-bubblefish-npamp-01) and does not redefine it. Unlike a Bridge carriage
> class, the Commerce channel carries no foreign protocol: the operation body **is**
> N-PAMP's own encoding, so this document consumes no extension-TLV code point. It
> introduces no change to the core wire format. This encoding is the concrete
> Commerce operation encoding the Commerce-channel interface reference explicitly
> defers to a companion — "a future companion specification MAY define a concrete
> Commerce operation encoding within the code points the core specification reserves"
> (`../channels/000E_commerce.md` §1). This document is that companion.

## 1. Scope

### 1.1 In scope

This document specifies, over the Commerce channel `0x000E` of the N-PAMP core
specification (the "core specification", draft-bubblefish-npamp-01):

1. A set of Commerce-channel frame types, drawn **entirely** from the
   channel-specific application band that begins at `0x0100` (core specification
   §4.6, frame-type namespace) — the Commerce channel has no core-reserved
   companion-extension range of its own (§2, §3.2), so, like the Telemetry-family
   native channels, every Commerce-native frame is assigned in the `0x0100`+ band;
2. Per-operation request and result frame pairs realizing the two native
   operation classes the core registry purpose names for this channel —
   **payment-mandate lifecycle** (the authorization-to-pay artifact the registry
   names) and **multi-party settlement intents** (the multi-party agentic-commerce
   negotiation the registry names);
3. The **deterministic-CBOR** encoding of every operation body (RFC 8949, core
   specification §4.5 and §11.9), keyed by unsigned integers, including a
   scale-and-currency monetary-amount encoding that avoids floating-point
   representation;
4. An **in-body correlation** discipline that matches a result to its request by a
   correlation token carried inside the CBOR body — consuming no shared TLV tag;
   and
5. A single structured **error frame** whose result set preserves a governance
   escalation (a payment or settlement held for human approval and NOT executed) as
   a distinct, non-success outcome.

Operations are described generically — issue, read, revoke, and query the status of
a payment mandate, and propose, respond to, and query the status of a multi-party
settlement intent — so that any commerce implementation and any client interoperate
over N-PAMP with no bespoke adaptation. The document names no product, no vendor,
no payment network, and no application-specific schema.

### 1.2 Not in scope

This document does NOT:

* **Carry a foreign commerce protocol.** The Commerce channel, framed by this
  document, is **native**: it is not a Bridge carriage class and does not build on
  NPAMP-BRIDGE. No frame in this document encapsulates a foreign message, and this
  document defines and consumes no extension-TLV tag. Carriage of a foreign commerce
  protocol — AP2 (`../companion/65_map_ap2.md`), UCP (`../companion/66_map_ucp.md`),
  or AITP (`../companion/67_map_aitp.md`) — over the Commerce channel is a **distinct
  mechanism** under NPAMP-BRIDGE and the relevant carriage class (§2.3), and is NOT
  what this document defines. An N-PAMP-native Commerce operation and a bridged
  foreign-protocol commerce message MUST NOT be conflated (§2.3).
* **Define settlement recording or receipts.** Recording that a bilateral obligation
  has been **settled**, and returning its **receipt**, is the registry purpose of the
  **Settlement** channel `0x0007` (`../channels/0007_settlement.md`), a distinct core
  channel. A *settlement intent* in this document is a commerce-side **proposal and
  authorization to transact** among named parties — it precedes, and is not, the
  Settlement channel's record of a completed settlement. This document defines no
  receipt format, no ledger model, and no settled-obligation record; those belong to
  the Settlement channel, and the core specification names the two channels distinctly
  (§2.2, `../channels/000E_commerce.md` §1).
* **Define multi-party fan-out or channel-level routing.** The registry purpose names
  **multi-party** commerce, but the Commerce channel is a **two-peer, Bidirectional
  single-stream** association (§2.1); the core specification defines no multi-party
  fan-out, party enumeration, or routing at the channel level
  (`../channels/000E_commerce.md` §2, §4). A multi-party settlement intent in this
  document is an **artifact naming multiple parties** exchanged between the two peers
  of one association; how additional parties are reached — a second association, an
  application-layer coordinator — is a local matter this document does not constrain.
  This document MUST NOT be read to define channel-level multi-party fan-out.
* **Define the meaning or legal effect of a mandate.** The mandate fields in §6 are
  the *wire* projection an implementation exchanges; what a mandate authorizes in a
  given jurisdiction, how a payer proves authority, how funds move, and how a mandate
  binds a real-world account are local and legal matters this document does not
  constrain — it fixes only what crosses the wire.
* **Define authorization, governance, or admission policy.** Whether a mandate or
  intent is permitted, denied, or escalated for human approval is the responder's
  local decision; this document defines only how each of those outcomes is *reported*
  on the wire (§8), not the policy that produces them.
* **Change the core wire format.** It alters no field of the core frame header, no
  reserved all-channel frame type, the extension-TLV encoding, or any code point the
  core specification assigns; it uses only channel-specific application-band code
  points the core specification leaves to each channel (§2.2).

## 2. Relationship to the core specification

### 2.1 Channel registration and the minimum-profile gate

The Commerce channel `0x000E` is registered by the core specification with purpose
**"Multi-party agentic commerce and payment mandates"**, minimum profile
**Standard**, and direction **Bidirectional** (core specification §5, Core Channel
Registry; machine-readable form `../../registries/channels.csv`). These values are
taken verbatim from the core channel registry as restated in the Commerce-channel
interface reference (`../channels/000E_commerce.md` §2); this document inherits that
registration and adds no exception to it.

* **Minimum-profile gate.** A peer MUST enable the Commerce channel only at the
  **Standard** profile or higher; once Standard is met the channel is available at
  Standard, High, and Sovereign, and there is no profile at which it becomes
  unavailable. N-PAMP's profiles share one wire format and differ in the
  cryptographic primitives they mandate (core specification §6, Profile
  Negotiation); the Commerce framing defined here is profile-invariant.
* **Advertisement gate.** A peer that has not advertised the Commerce channel during
  the handshake (core specification §5) MUST NOT receive frames on it; a frame
  arriving on an unadvertised Commerce channel MUST be dropped and MUST NOT be
  delivered to commerce processing.
* **Bidirectional, single stream.** Under the core specification's channel
  architecture the channel is full-duplex: each peer maintains an independent
  per-direction sequence space and independent per-direction traffic keys, so both
  peers MAY transmit simultaneously. The Commerce channel is **Bidirectional and not
  Multi-stream** (`../channels/000E_commerce.md` §2): both peers exchange commerce
  frames over a **single** stream, and either peer MAY originate an operation. The
  core specification assigns the channel no fixed initiator/responder role; in this
  document, the peer that emits a `*_REQ` is the **requester** and the peer that
  answers is the **responder**, for that exchange only.

### 2.2 Native, not a carriage class; and the frame-type namespace

A Bridge carriage class carries a *foreign* protocol's message octet-for-octet and
wraps routing and correlation metadata *around* it in a shared extension TLV. The
Commerce channel, as framed here, has no foreign protocol: the operation body is
N-PAMP's own deterministic-CBOR encoding, and this document owns that body in full.
Consequently the correlation token, the operation semantics, and the error object
all live **inside** the CBOR body, and this document reserves and consumes **no
extension-TLV code point**. This is the deliberate structural difference from
NPAMP-BRIDGE and is the reason a Commerce operation is routed by its N-PAMP **frame
type** (§3) rather than by any method-name or tool-name field parsed from a body.

The core specification partitions each channel's `0x0000`–`0xFFFF` frame-type space
into four bands (core specification §4.6, Frame-Type Namespace): `0x0000`–`0x000A`
reserved all-channel frame types with the same meaning on every channel;
`0x000B`–`0x002F` unassigned, reserved to the core for future all-channel additions;
`0x0030`–`0x00FF` the **companion-extension band**, per-channel extension frame types
whose sub-ranges the core reserves to specific channels; and `0x0100`–`0xFFFF`
**channel-specific application** frame types. The core specification's Reserved
Frame-Type Ranges table (core specification §8; `../09_extension_points.md`) assigns
sub-`0x0100` ranges to the Memory, Capability, Control, Audit, Settlement/Audit,
Governance, and Immune channels — but **none to the Commerce channel**
(`../channels/000E_commerce.md` §3.2). The Commerce channel therefore has **no**
core-reserved companion-extension range of its own. Accordingly this document places
**every** Commerce-native frame in the channel-specific application band at `0x0100`+
(§3), assigns none of the §8 reserved sub-`0x0100` ranges to Commerce traffic, and
reserves no code point in the core specification's cross-channel reserved ranges.
Because the frame-type space is scoped by the Channel ID header field, these
`0x0100`+ code points do not collide with any other channel's assignments at the same
numeric values.

### 2.3 Distinction from bridged foreign commerce (AP2 / UCP / AITP)

NPAMP-COMMERCE is a **native** Commerce-channel companion. It is not a Bridge
carriage class. The Commerce channel is also a **carriage-selection target**: the
companion index's "Channel selection for carriage" table
(`../companion/00_companion_index.md`) names Commerce `0x000E` as a more-specific core
channel onto which payment-mandate and multi-party-commerce **foreign** traffic MAY be
routed under NPAMP-BRIDGE, and the AP2, UCP, and AITP mappings each name `0x000E` as an
OPTIONAL channel with Bridge `0x000D` as the default. That bridged carriage and this
native framing are **distinct and MUST NOT be conflated**:

| | NPAMP-COMMERCE (this document) | Bridged foreign commerce (AP2 / UCP / AITP) |
|---|---|---|
| Nature | N-PAMP-native operation encoding | A foreign protocol carried octet-for-octet |
| Body | N-PAMP's own deterministic-CBOR operation body | The foreign protocol's own message, opaque to N-PAMP |
| Framing | Native frames `0x0100`–`0x010E` on `0x000E` | NPAMP-BRIDGE frames (`../companion/10_bridge_framework.md`) with a foreign body |
| Correlation | In-body `corr` token (§5) | NPAMP-BRIDGE `correlation_id` (BridgeEnvelope TLV) |
| Semantics | Defined by this document | Defined by the foreign protocol under its mapping |

An implementation MUST NOT parse a native Commerce frame (`0x0100`+ on `0x000E`, this
document's bodies) as an NPAMP-BRIDGE-encapsulated foreign message, and MUST NOT parse
an NPAMP-BRIDGE frame carrying AP2/UCP/AITP as a native Commerce operation. A
deployment that wants N-PAMP's own commerce operations uses this document; a deployment
that wants to carry an existing foreign commerce protocol uses NPAMP-BRIDGE and the
relevant carriage class (`../companion/65_map_ap2.md`, `../companion/66_map_ucp.md`,
`../companion/67_map_aitp.md`).

## 3. Commerce-channel frame types

Within the Commerce channel (`0x000E`) frame-type namespace, this specification
defines fifteen frame types, **all** in the channel-specific application band at
`0x0100`+. No frame is defined in any sub-`0x0100` range, because the core specification
reserves none to the Commerce channel (§2.2).

### 3.1 Application-band operation frames (`0x0100`+)

| Type | Name | Reply | Purpose |
|---|---|---|---|
| `0x0100` | COMMERCE_MANDATE_CREATE_REQ | COMMERCE_MANDATE_CREATE_RESULT or COMMERCE_ERROR | Issue a new payment mandate (authorization-to-pay artifact). |
| `0x0101` | COMMERCE_MANDATE_CREATE_RESULT | None | Success reply to a mandate issuance; echoes the request's correlation token. |
| `0x0102` | COMMERCE_MANDATE_READ_REQ | COMMERCE_MANDATE_READ_RESULT or COMMERCE_ERROR | Return the current state of one identified payment mandate. |
| `0x0103` | COMMERCE_MANDATE_READ_RESULT | None | Success reply to a read; carries the identified mandate. |
| `0x0104` | COMMERCE_MANDATE_REVOKE_REQ | COMMERCE_MANDATE_REVOKE_RESULT or COMMERCE_ERROR | Revoke an outstanding payment mandate, ending its authorization. |
| `0x0105` | COMMERCE_MANDATE_REVOKE_RESULT | None | Success reply to a revoke. |
| `0x0106` | COMMERCE_MANDATE_STATUS_REQ | COMMERCE_MANDATE_STATUS_RESULT or COMMERCE_ERROR | Query the lifecycle state of one identified mandate. |
| `0x0107` | COMMERCE_MANDATE_STATUS_RESULT | None | Mandate lifecycle-state reply. |
| `0x0108` | COMMERCE_INTENT_PROPOSE_REQ | COMMERCE_INTENT_PROPOSE_RESULT or COMMERCE_ERROR | Propose a multi-party settlement intent (named parties and payment legs). |
| `0x0109` | COMMERCE_INTENT_PROPOSE_RESULT | None | Success reply to a proposal; carries the intent identifier and initial state. |
| `0x010A` | COMMERCE_INTENT_RESPOND_REQ | COMMERCE_INTENT_RESPOND_RESULT or COMMERCE_ERROR | Accept, reject, or counter a previously proposed settlement intent. |
| `0x010B` | COMMERCE_INTENT_RESPOND_RESULT | None | Success reply to a response; carries the resulting intent state. |
| `0x010C` | COMMERCE_INTENT_STATUS_REQ | COMMERCE_INTENT_STATUS_RESULT or COMMERCE_ERROR | Query the state of one identified settlement intent. |
| `0x010D` | COMMERCE_INTENT_STATUS_RESULT | None | Settlement-intent state reply. |
| `0x010E` | COMMERCE_ERROR | None | Structured failure for any request; echoes the correlation token and carries a Commerce error code (§8). |

A `*_REQ` frame originates an operation; the corresponding `*_RESULT` frame, or a
COMMERCE_ERROR (`0x010E`), replies to it. A `*_RESULT` frame is never sent
unsolicited: each MUST echo the correlation token of the request it answers (§5). A
responder MUST NOT emit both a `*_RESULT` and a COMMERCE_ERROR for the same request.

### 3.2 Reserved all-channel frame types

The reserved all-channel frame types (PING `0x0001`, PONG `0x0002`, CLOSE `0x0003`,
CLOSE_ACK `0x0004`, ERROR `0x0005`, KEY_UPDATE `0x0006`, KEY_UPDATE_ACK `0x0007`,
PATH_CHALLENGE `0x0008`, PATH_RESPONSE `0x0009`, and FLOW_UPDATE `0x000A`; core
specification §4.6) retain their core meaning on the Commerce channel. An
implementation MUST NOT reuse them for Commerce application traffic, MUST NOT use
`0x0000` as a frame type, and MUST NOT define Commerce operation semantics in the
reserved all-channel range `0x0000`–`0x000A`.

### 3.3 No Commerce companion-extension range

Unlike the Memory channel — for which the core reserves `0x0035`–`0x0036` in the
companion-extension band — the core specification reserves **no** sub-`0x0100`
frame-type range for the Commerce channel (core specification §8;
`../09_extension_points.md`; `../channels/000E_commerce.md` §3.2). An implementation
MUST NOT assign any of the §8 reserved ranges (which name the Memory, Capability,
Control, Audit, Settlement/Audit, Governance, and Immune channels) to Commerce
traffic, and MUST NOT treat any code point in them as a Commerce-channel frame. All
fifteen frame types defined above lie in the Commerce channel's own application band
at or above `0x0100`; this document consumes no frame-type code point outside that
band.

## 4. Frame payload encoding

### 4.1 Payload container

A Commerce frame's payload (the octets after the core frame header and any extension
TLVs, and before the AEAD tag) is a single **deterministically encoded CBOR** object
as defined by the core specification §4.5 and §11.9 (deterministic CBOR, RFC 8949).
The payload MUST be a CBOR map whose keys are the unsigned integers defined in §4.2
and §5–§8 for the relevant frame type. A sender MUST produce the deterministic
encoding (core specification §11.9): byte-identical output for identical inputs, with
the canonical key ordering and shortest-form integer encoding RFC 8949 §4.2 requires,
and definite-length maps and arrays.

A receiver MUST reject, with COMMERCE_ERROR code `malformed_request` (§8), any
Commerce frame whose payload is not a valid deterministic-CBOR map, whose payload
omits a REQUIRED key for its frame type, or whose payload carries a key of the wrong
CBOR major type.

Commerce operation bodies are carried in the frame **payload**, not in extension
TLVs. This document defines and consumes no extension-TLV tag, and therefore claims
none of the TLV code points the core specification reserves.

### 4.2 Common envelope fields

Every Commerce payload map carries the following two envelope fields. Integer keys
are given in parentheses.

| Field (key) | CBOR type | Meaning |
|---|---|---|
| `frame_kind` (0) | Unsigned int | MUST equal the frame's Commerce frame type (one of `0x0100`–`0x010E`). A receiver MUST reject (COMMERCE_ERROR, code `malformed_request`) a payload whose `frame_kind` contradicts the frame-header Frame Type. |
| `corr` (1) | Byte string (1–64 B) | Correlation token (§5). Present and non-empty on every `*_REQ` and on every frame that replies to one. |

The per-frame body fields defined in §5–§8 occupy keys `2` and above within the same
map; §6 gives, per frame, the full field table.

### 4.3 Monetary amount encoding

A monetary amount is encoded as a CBOR map (the `amount` structure) that avoids
floating-point representation, so that a value is exchanged exactly:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `units` (0) | Integer | Yes | The signed integer number of minor units of the amount, at the scale given by `scale`. For example, `12345` at `scale` `2` is `123.45`. |
| `scale` (1) | Unsigned int | Yes | The number of decimal places by which `units` is divided to obtain the value (the negative base-10 exponent). `scale` `0` denotes an integer amount. |
| `currency` (2) | Text string | Yes | The currency or asset identifier the amount is denominated in (for example an ISO 4217 alphabetic code, or a deployment-agreed asset identifier). This document assigns no currency registry and treats the value as an opaque, deployment-agreed label. |

A receiver MUST reject (COMMERCE_ERROR, `malformed_request`) an `amount` that omits a
REQUIRED sub-field or whose sub-field is of the wrong CBOR major type. This document
does not define currency conversion, rounding policy, or a canonical currency set;
those are local matters above this wire encoding.

### 4.4 Forward compatibility

A receiver MUST ignore an unrecognized integer key it encounters in a Commerce payload
map (or in a nested `amount`, party, or leg map) whose key is **not negative**, so
that a later revision of this document MAY add fields without breaking a conformant
receiver. A receiver MUST reject (COMMERCE_ERROR, code `malformed_request`) a payload
that carries a **negative** integer key it does not recognize, reserving the negative
key space for forward-incompatible additions. A receiver MUST NOT treat the mere
presence of an unknown non-negative key as an error, and MUST NOT alter its handling
of the keys it does recognize because of it.

## 5. Correlation and operation model

The core specification does not define how a Commerce reply is correlated to its
request (unlike the Bridge channel, where NPAMP-BRIDGE §5 defines a correlation
identifier; `../channels/000E_commerce.md` §4). This document supplies that
discipline, carrying the token **inside** the CBOR body rather than in a shared TLV,
because a native channel owns its whole body (§2.2).

### 5.1 Correlation discipline

* Every `*_REQ` frame (`0x0100`, `0x0102`, `0x0104`, `0x0106`, `0x0108`, `0x010A`,
  `0x010C`) MUST carry a non-empty `corr` (§4.2) that is unique among the
  originating peer's outstanding Commerce requests on the channel in that direction.
* Every `*_RESULT` frame and every COMMERCE_ERROR MUST echo the originating request's
  `corr` verbatim.
* A receiver MUST match a reply to its request by `corr`, **not** by the
  per-(channel, direction) frame sequence number. Because either peer may originate
  operations on this Bidirectional single stream, the `corr` token — not sequence
  order — identifies the originating exchange.

### 5.2 Correlation lifetime

Every Commerce operation in this document is a **single-reply** exchange: its `corr`
value is consumed when its `*_RESULT` or COMMERCE_ERROR is delivered. The requester
MUST treat that exchange as complete on receipt of the reply, and MUST NOT reuse the
value for a new request while the original is outstanding.

### 5.3 Side-effect class (`effect`)

Every state-affecting request — COMMERCE_MANDATE_CREATE_REQ,
COMMERCE_MANDATE_REVOKE_REQ, COMMERCE_INTENT_PROPOSE_REQ, and
COMMERCE_INTENT_RESPOND_REQ — MUST carry an `effect` field (§6) declaring the most
severe side effect the operation may cause, drawn from the side-effect classes below.
It is the native-body analogue of a Bridge SafetyLabel, carried in-body because the
Commerce channel owns its body (§2.2).

| Value | Name | Meaning |
|---|---|---|
| `0x00` | read_only | No state change (a read or a status query). |
| `0x01` | idempotent_write | A write whose repetition yields the same state (for example a mandate revoke). |
| `0x02` | non_idempotent_write | A write that is not safely repeatable (for example issuing a new mandate, or proposing a new settlement intent). |
| `0x03` | value_transfer | An operation that authorizes or commits the movement of value (for example a mandate that authorizes payment, or an intent response that commits a party to its legs). |

**Fail-safe.** A receiver MUST treat a state-affecting request that omits `effect`,
or carries an `effect` value it does not recognize, as `value_transfer` (the most
severe class), and MAY refuse it (COMMERCE_ERROR). A requester MUST NOT rely on a
state-affecting request that omits `effect` being executed. A read-only request
(COMMERCE_MANDATE_READ_REQ, COMMERCE_MANDATE_STATUS_REQ, COMMERCE_INTENT_STATUS_REQ)
carries `effect` = `read_only`.

## 6. Operation bodies

Each operation body is a deterministic-CBOR map carrying the common envelope (§4.2,
keys `0`–`1`) and the per-frame fields below at keys `2`+. Unless a field is marked
required, it is OPTIONAL and, when absent, carries no value (a producer omits the key
rather than encoding a null placeholder; a producer that does encode an explicit CBOR
`null` for an absent OPTIONAL field is equivalent to omitting it).

### 6.1 COMMERCE_MANDATE_CREATE_REQ (`0x0100`) / COMMERCE_MANDATE_CREATE_RESULT (`0x0101`)

Issue a new payment mandate — an authorization-to-pay artifact.

**COMMERCE_MANDATE_CREATE_REQ body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `payer` (2) | Text string | Yes | Opaque identifier of the party authorizing payment, within the requester's namespace. |
| `payee` (3) | Text string | Yes | Opaque identifier of the party authorized to be paid. |
| `amount` (4) | Map (`amount`, §4.3) | Yes | The maximum value the mandate authorizes. |
| `purpose` (5) | Text string | No | An advisory human-readable purpose for the mandate. |
| `not_before` (6) | Text string | No | Earliest time the mandate is valid, as an RFC 3339 timestamp. Absent means valid immediately. |
| `not_after` (7) | Text string | No | Expiry time of the mandate, as an RFC 3339 timestamp. Absent means the responder's default validity applies. |
| `constraints` (8) | Map | No | Additional usage constraints (for example a per-use cap or a use count), keyed by unsigned integers. Its inner keys are a local matter; a receiver MUST apply the forward-compatibility rule (§4.4) to this nested map. |
| `idempotency_key` (9) | Text string | No | A caller-supplied key that lets the responder de-duplicate a retried issuance. When absent, the responder MAY derive one from the request content. |
| `signature` (10) | Byte string | No | A cryptographic signature over the mandate's signable content, for non-repudiation beyond the association's transport authentication. |
| `signing_key_id` (11) | Text string | No | Identifier of the key that produced `signature`. |
| `signature_alg` (12) | Text string | No | The signature algorithm identifier for `signature`. |
| `effect` (13) | Unsigned int | Yes | Side-effect class (§5.3). Issuing a mandate is normally `0x03` value_transfer (or `0x02` non_idempotent_write where the mandate only authorizes a later, separately committed payment). |

**COMMERCE_MANDATE_CREATE_RESULT body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `mandate_id` (2) | Text string | Yes | The identifier the responder assigned to the newly issued mandate. |
| `state` (3) | Text string | Yes | The mandate's lifecycle state after issuance (for example `active`; see §6.4). |

A mandate issuance that the responder holds for human approval, rather than executing,
is NOT reported as a COMMERCE_MANDATE_CREATE_RESULT; it is reported as COMMERCE_ERROR
with code `approval_required` (§8). A responder MUST NOT emit a
COMMERCE_MANDATE_CREATE_RESULT for a mandate it did not actually record as authorized.

### 6.2 COMMERCE_MANDATE_READ_REQ (`0x0102`) / COMMERCE_MANDATE_READ_RESULT (`0x0103`)

Return the current state of one identified payment mandate.

**COMMERCE_MANDATE_READ_REQ body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `mandate_id` (2) | Text string | Yes | The mandate to read. |
| `effect` (3) | Unsigned int | Yes | Side-effect class (§5.3); MUST be `0x00` read_only. |

**COMMERCE_MANDATE_READ_RESULT body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `mandate` (2) | Map (a `mandate_record`, §6.5) | Yes | The identified mandate with its terms and lifecycle state. |

A read of an absent mandate is reported as COMMERCE_ERROR with code `not_found` (§8),
not as an empty COMMERCE_MANDATE_READ_RESULT.

### 6.3 COMMERCE_MANDATE_REVOKE_REQ (`0x0104`) / COMMERCE_MANDATE_REVOKE_RESULT (`0x0105`)

Revoke an outstanding payment mandate, ending its authorization.

**COMMERCE_MANDATE_REVOKE_REQ body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `mandate_id` (2) | Text string | Yes | The mandate to revoke. |
| `reason` (3) | Text string | No | An advisory reason for the revocation. |
| `effect` (4) | Unsigned int | Yes | Side-effect class (§5.3); revocation is `0x01` idempotent_write (revoking an already-revoked mandate yields the same state). |

**COMMERCE_MANDATE_REVOKE_RESULT body** — `{ mandate_id (2): tstr, state (3): tstr }`,
where `state` is the mandate's lifecycle state after revocation (normally `revoked`,
§6.4). A revoke of an absent mandate is reported as COMMERCE_ERROR `not_found` (§8).

### 6.4 COMMERCE_MANDATE_STATUS_REQ (`0x0106`) / COMMERCE_MANDATE_STATUS_RESULT (`0x0107`)

Query the lifecycle state of one identified mandate without returning its full terms.

**COMMERCE_MANDATE_STATUS_REQ body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `mandate_id` (2) | Text string | Yes | The mandate whose state is queried. |
| `effect` (3) | Unsigned int | Yes | Side-effect class (§5.3); MUST be `0x00` read_only. |

**COMMERCE_MANDATE_STATUS_RESULT body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `mandate_id` (2) | Text string | Yes | The identified mandate. |
| `state` (3) | Text string | Yes | The mandate's current lifecycle state. |
| `not_after` (4) | Text string | No | The mandate's expiry, as an RFC 3339 timestamp, when the responder holds one. |

A mandate's lifecycle `state` is one of the following text tokens: `active` (issued
and usable), `expired` (its `not_after` has passed), `revoked` (ended by a revoke,
§6.3), or `exhausted` (its authorized value or use count is spent). A responder MUST
report a mandate that is no longer usable with the specific terminal state above and
MUST NOT report a spent, expired, or revoked mandate as `active`.

### 6.5 The `mandate_record`

A `mandate_record` is the wire projection of one payment mandate and its terms:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `mandate_id` (0) | Text string | Yes | Identity of the mandate. |
| `payer` (1) | Text string | Yes | The authorizing party. |
| `payee` (2) | Text string | Yes | The party authorized to be paid. |
| `amount` (3) | Map (`amount`, §4.3) | Yes | The maximum value the mandate authorizes. |
| `state` (4) | Text string | Yes | The mandate's lifecycle state (§6.4). |
| `purpose` (5) | Text string | No | The advisory purpose of the mandate. |
| `not_before` (6) | Text string | No | Earliest validity time, RFC 3339. |
| `not_after` (7) | Text string | No | Expiry time, RFC 3339. |
| `constraints` (8) | Map | No | The usage constraints associated with the mandate. |
| `signature` (9) | Byte string | No | A signature over the mandate's signable content, when the store holds one. |
| `signing_key_id` (10) | Text string | No | Identifier of the key that produced `signature`. |
| `signature_alg` (11) | Text string | No | The signature algorithm identifier. |

A read result MUST carry the mandate's authorizing terms (`payer`, `payee`, `amount`,
`state`) and MUST NOT strip a signature the store associates with the mandate. Any of
the OPTIONAL fields above MAY be absent when the store holds no value for it.

### 6.6 COMMERCE_INTENT_PROPOSE_REQ (`0x0108`) / COMMERCE_INTENT_PROPOSE_RESULT (`0x0109`)

Propose a multi-party settlement intent: a proposed arrangement of who-pays-whom among
named parties. This is a commerce-side **proposal and authorization to transact**, not
a record of a completed settlement (which is the Settlement channel's role; §1.2).

**COMMERCE_INTENT_PROPOSE_REQ body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `parties` (2) | Array of Text string | Yes | The opaque identifiers of the parties the intent names. The registry purpose names multi-party commerce; the array MAY name more than two parties, but the intent is exchanged between the two peers of this association and this document defines no channel-level fan-out to additional parties (§1.2). |
| `legs` (3) | Array of `leg` | Yes | The payment legs comprising the settlement, each a map `{ from (0): tstr, to (1): tstr, amount (2): map(§4.3) }`, where `from` and `to` are members of `parties`. A receiver MUST reject (COMMERCE_ERROR, `malformed_request`) a leg whose `from` or `to` is not a named party. |
| `not_after` (4) | Text string | No | Expiry of the proposal, as an RFC 3339 timestamp, after which it MAY be treated as `expired` (§6.8). |
| `conditions` (5) | Map | No | Advisory conditions on the settlement, keyed by unsigned integers; a receiver MUST apply the forward-compatibility rule (§4.4) to this nested map. |
| `idempotency_key` (6) | Text string | No | A caller-supplied key that lets the responder de-duplicate a retried proposal. |
| `effect` (7) | Unsigned int | Yes | Side-effect class (§5.3); proposing a new intent is normally `0x02` non_idempotent_write. |

**COMMERCE_INTENT_PROPOSE_RESULT body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `intent_id` (2) | Text string | Yes | The identifier the responder assigned to the proposed intent. |
| `state` (3) | Text string | Yes | The intent's state after proposal (normally `proposed`; §6.8). |

An intent proposal held for human approval is reported as COMMERCE_ERROR
`approval_required` (§8), not as a COMMERCE_INTENT_PROPOSE_RESULT.

### 6.7 COMMERCE_INTENT_RESPOND_REQ (`0x010A`) / COMMERCE_INTENT_RESPOND_RESULT (`0x010B`)

Accept, reject, or counter a previously proposed settlement intent.

**COMMERCE_INTENT_RESPOND_REQ body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `intent_id` (2) | Text string | Yes | The intent being responded to. |
| `decision` (3) | Unsigned int | Yes | The response: `0x00` accept, `0x01` reject, or `0x02` counter. A receiver MUST reject (COMMERCE_ERROR, `malformed_request`) a `decision` value it does not recognize. |
| `counter_legs` (4) | Array of `leg` | No | Present only when `decision` is `0x02` counter: the proposed replacement legs (§6.6). A receiver MUST reject (COMMERCE_ERROR, `malformed_request`) a `counter` decision that omits `counter_legs`, or `counter_legs` present when `decision` is not `counter`. |
| `reason` (5) | Text string | No | An advisory reason for a reject or counter. |
| `effect` (6) | Unsigned int | Yes | Side-effect class (§5.3); an `accept` that commits the responding party to its legs is `0x03` value_transfer, a `reject` is `0x01` idempotent_write, and a `counter` is `0x02` non_idempotent_write. |

**COMMERCE_INTENT_RESPOND_RESULT body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `intent_id` (2) | Text string | Yes | The intent responded to. |
| `state` (3) | Text string | Yes | The intent's state after the response (§6.8). |

A response to an absent intent is reported as COMMERCE_ERROR `not_found`; a response
that conflicts with the intent's current state (for example accepting an already
`rejected` intent) is reported as COMMERCE_ERROR `intent_conflict` (§8).

### 6.8 COMMERCE_INTENT_STATUS_REQ (`0x010C`) / COMMERCE_INTENT_STATUS_RESULT (`0x010D`)

Query the state of one identified settlement intent.

**COMMERCE_INTENT_STATUS_REQ body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `intent_id` (2) | Text string | Yes | The intent whose state is queried. |
| `effect` (3) | Unsigned int | Yes | Side-effect class (§5.3); MUST be `0x00` read_only. |

**COMMERCE_INTENT_STATUS_RESULT body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `intent_id` (2) | Text string | Yes | The identified intent. |
| `state` (3) | Text string | Yes | The intent's current state. |
| `parties` (4) | Array of Text string | No | The parties the intent names, when the responder discloses them. |
| `legs` (5) | Array of `leg` | No | The current legs of the intent (as originally proposed or as countered), when the responder discloses them. |

A settlement intent's `state` is one of the following text tokens: `proposed`
(awaiting a response), `accepted` (all responding parties accepted), `countered` (a
counter-proposal is outstanding), `rejected` (declined), or `expired` (its `not_after`
has passed). A responder MUST report the intent's actual state and MUST NOT report a
rejected, expired, or merely proposed intent as `accepted`.

## 7. Operation and state model

Every Commerce operation in this document is a single request answered by exactly one
`*_RESULT` or one COMMERCE_ERROR. There is no streamed or multi-frame result: the
Commerce channel is Bidirectional and **not** Multi-stream (§2.1), so this document
defines no stream-data/stream-end frames and no per-operation flow-control frame
(connection-level flow control uses the all-channel `FLOW_UPDATE` `0x000A` with its
core meaning; §3.2).

* A **mandate** progresses through the lifecycle states of §6.4: it is `active` on
  issuance, and reaches exactly one terminal state — `revoked` (by a revoke, §6.3),
  `expired` (its `not_after` passed), or `exhausted` (its authorized value or use is
  spent). A revoke of an already-terminal mandate is idempotent: the responder
  reports the existing terminal state and does not re-transition it.
* An **intent** progresses through the states of §6.8: `proposed` on proposal, then —
  by a response (§6.7) — `accepted`, `rejected`, or `countered`, or `expired` if its
  `not_after` passes first. A response that would drive an illegal transition (for
  example accepting a `rejected` intent) MUST be rejected with COMMERCE_ERROR
  `intent_conflict` (§8), and a response to an unknown intent with `not_found`.

Because either peer may originate operations on this single Bidirectional stream, a
responder MUST correlate a reply to its request solely by the in-body `corr` (§5), and
MUST NOT assume a fixed initiator/responder role across exchanges.

## 8. Error model

Every failure of a Commerce request is reported in a single COMMERCE_ERROR (`0x010E`)
frame — the Commerce channel, as framed here, has no foreign protocol, so all errors
are native and carried in one structured frame. A COMMERCE_ERROR echoes the failed
request's `corr` and carries:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `code` (2) | Unsigned int | Yes | One of the Commerce error codes below. |
| `message` (3) | Text string | Yes | A peer-safe, generic human-readable message for `code`. It MUST NOT carry internal detail (§8.2). |
| `retry_after_s` (4) | Unsigned int | No | When present, the number of seconds after which the requester MAY retry. |
| `approval_id` (5) | Text string | No | Present if and only if `code` is `approval_required`: an identifier of the held-for-approval operation (§8.1). |

| Code | Name | Meaning |
|---|---|---|
| 1 | malformed_request | The CBOR body is not valid deterministic CBOR, omits a REQUIRED field, uses a wrong CBOR major type, carries an unknown negative key (§4.4), carries a malformed `amount` (§4.3), names a leg party not in `parties`, or carries an unrecognized enumerated value (`decision`, `effect`). |
| 2 | unknown_operation | The frame type is not a Commerce operation the responder implements. |
| 3 | policy_denied | The operation was refused by the responder's governance or policy: a definitive denial. |
| 4 | approval_required | The operation was escalated for human approval and was **NOT executed** (§8.1). Carries `approval_id`. |
| 5 | not_found | An identified mandate or intent (read, revoke, status, or respond target) does not exist. |
| 6 | mandate_invalid | The named mandate exists but is not usable for the requested operation because it is expired, revoked, or exhausted. |
| 7 | intent_conflict | A response conflicts with the intent's current state (for example accepting an already rejected or expired intent). |
| 8 | internal_error | A commerce-processing or pipeline failure the responder cannot attribute to the request. Generic; no internal detail crosses the wire. |

### 8.1 Governance escalation is a distinct, non-success outcome

A `policy_denied` (code 3) and an `approval_required` (code 4) are different results
and MUST NOT be conflated. `policy_denied` is a definitive refusal: the operation will
not proceed. `approval_required` means the operation has been **held for human
approval and has NOT been executed** — it is neither a success nor a definitive
denial, but a pending decision. This distinction is especially load-bearing for a
value-transfer channel: a payment authorization held for approval is not a completed
authorization.

An implementation MUST report a governance escalation as COMMERCE_ERROR with code
`approval_required`, carrying `approval_id`, and MUST NOT report it as a
COMMERCE_MANDATE_CREATE_RESULT, COMMERCE_INTENT_PROPOSE_RESULT,
COMMERCE_INTENT_RESPOND_RESULT, or any other `*_RESULT`. A held-for-approval mandate
issuance or intent acceptance MUST NOT be presented to the requester as a completed
operation: an operation that did not take effect is never a success frame. A requester
MUST treat `approval_required` as an operation that has not yet taken effect, distinct
from both a success and a `policy_denied`.

### 8.2 No internal detail on the wire

The `message` field MUST be the generic, peer-safe string for its `code`. The full
internal cause of a failure MUST be handled locally (for example logged by the
responder) and MUST NOT cross the wire: a COMMERCE_ERROR MUST NOT carry commerce-engine
internals, policy topology, account or ledger identifiers beyond those the request
already named, configuration or source names, decoder diagnostics, or any other detail
beyond the code and its generic message. This leak-prevention requirement is normative
for interoperability, not merely local hygiene: a requester MUST be able to rely on the
error surface exposing only a code, a generic message, and the OPTIONAL `retry_after_s`
/ `approval_id` fields.

## 9. Security and privacy considerations

This section supplements the core specification's Security Considerations; it does not
restate them.

Every Commerce frame is AEAD-protected like all N-PAMP frames and is carried under the
association's existing authentication (the core specification's handshake binds both
peer identities into the transcript and the Finished MAC). A responder therefore knows
that an operation was requested by the authenticated peer, but **authentication is not
authorization**: a responder MUST enforce its own governance and access policy on every
mandate issuance, revoke, and intent operation regardless of the peer's identity, and
MUST report the outcome per §8 — including preserving the `approval_required` /
`policy_denied` distinction. Because this is a value-transfer channel, a responder
SHOULD treat mandate issuance and intent acceptance as operations that warrant
governance review, and MUST NOT treat transport authentication as standing authority to
move value.

A mandate authorizes payment and an accepted intent commits a party to its legs; both
are sensitive. A responder SHOULD disclose a mandate's or intent's terms (§6.5, §6.8)
only to a peer entitled to see them and MAY return a filtered or reduced disclosure to
a peer it does not wish to fully inform. An OPTIONAL mandate-level `signature` (§6.1,
§6.5) supports non-repudiation beyond the association's transport authentication; when
present, a verifier MUST check it against an independently trusted key, never against a
key carried only inside the mandate it is verifying.

A responder MUST bound the resources a remote peer can consume through Commerce
operations: the rate of mandate issuances and intent proposals it will accept, and the
number of outstanding mandates and intents it will maintain per peer. A responder MAY
reply COMMERCE_ERROR (with `retry_after_s`) rather than allocate without limit. Because
either peer may originate operations on this Bidirectional channel, both directions are
subject to these limits.

The error surface MUST NOT leak internal detail (§8.2); a COMMERCE_ERROR that carried
commerce-engine internals, policy topology, or account or ledger identifiers the
request did not already name would disclose the responder's internal structure to the
peer and is a conformance violation (§10).

## 10. Conformance

An implementation conforms to NPAMP-COMMERCE if and only if it rests on a
core-conformant N-PAMP wire implementation and, on the Commerce channel `0x000E`, it:

1. Treats `0x000E` as the Commerce channel with the core registry identity (name
   Commerce; purpose multi-party agentic commerce and payment mandates; minimum
   profile Standard; direction Bidirectional), does not repurpose the channel
   identifier, enables it only at the **Standard** profile or higher, and drops any
   frame received on an unadvertised Commerce channel (§2.1);

2. Uses only the Commerce frame types defined in §3 — the application-band operation
   frames `0x0100`–`0x010E` — assigns **no** frame to any sub-`0x0100` range (the core
   reserves none to the Commerce channel), preserves the core meaning of the reserved
   all-channel frame types `0x0000`–`0x000A`, and treats no code point in the §8
   reserved ranges (which name other channels) as a Commerce frame (§3);

3. Encodes every operation body as a deterministic-CBOR map (§4.1) with the integer
   keys of §4.2 and §5–§8, encodes a monetary amount with the non-floating-point
   `units`/`scale`/`currency` structure (§4.3), rejects a non-deterministically-encoded
   body, a body missing a REQUIRED field, a wrong-major-type key, or a body carrying an
   unknown negative key with COMMERCE_ERROR `malformed_request`, and ignores an unknown
   non-negative key without altering its handling of recognized keys (§4.4);

4. Carries a non-empty `corr` on every `*_REQ`, echoes it verbatim on every reply, and
   matches replies to requests by `corr` rather than by frame sequence number (§5.1);

5. Carries an `effect` on every state-affecting request and treats a missing or unknown
   `effect` on a state-affecting operation as `value_transfer` (§5.3 fail-safe);

6. Realizes the payment-mandate lifecycle — issue, read, revoke, and status — reporting
   a mandate's terminal state (`revoked`, `expired`, or `exhausted`) accurately and
   never reporting a spent, expired, or revoked mandate as `active`, and reports a
   read or operation on an absent mandate as `not_found` and on an unusable mandate as
   `mandate_invalid` (§6.1–§6.5, §8);

7. Realizes the multi-party settlement-intent operations — propose, respond
   (accept/reject/counter), and status — validating that every leg's `from` and `to`
   are named parties, rejecting an illegal state transition with `intent_conflict`, and
   never manufacturing channel-level multi-party fan-out the core specification does not
   define (§6.6–§6.8, §1.2, §8);

8. Reports every failure as COMMERCE_ERROR (`0x010E`) with a code from §8 and a
   peer-safe `message`, never leaking internal cause (§8.2); reports a governance
   escalation as `approval_required` carrying `approval_id`, distinct from
   `policy_denied`; and never reports a success `*_RESULT` for an operation that did not
   take effect (a held-for-approval mandate issuance or intent acceptance is
   `approval_required`, not a `*_RESULT`) (§6.1, §6.6, §8.1); and

9. Carries N-PAMP-native Commerce operations only, does not encapsulate a foreign
   commerce protocol in these native frames, and — where it instead carries AP2, UCP, or
   AITP over the Commerce channel — does so under NPAMP-BRIDGE and the relevant carriage
   class, not as a native Commerce operation, keeping the two mechanisms distinct
   (§2.3).

This document is a **DRAFT** companion specification. Machine-gradable conformance
vectors exist for the Commerce channel's payload-decode surface: the
`commerce.body.decode` operation group in the conformance corpus, produced by an
independent RFC 8949 byte constructor (`test-vectors/gen/commerce_oracle.py`, whose
expected values derive from the standard rather than from the implementation under test)
and graded by `npamp-conform` against the Go reference implementation, cross-validated by
`impl/go/zz_commerce_oracle_xval_test.go`, covers the §4.1/§4.2/§4.3/§4.4 payload-encoding
and common-envelope MUST-reject clauses — including the rejection of a non-deterministic
encoding, a missing REQUIRED field, a wrong-major-type key, a `frame_kind` that
contradicts the frame header, a malformed monetary `amount` (§4.3), and an unknown
negative key (§4.4). A conformance claim to those clauses is therefore graded against the
pinned conformance corpus.

Beyond that payload surface, the §5–§9 behavioural clauses — the `corr` correlation and
single-reply model (§5), the side-effect `effect` fail-safe (§5.3), the mandate and
settlement-intent state machines (§6, §7), the `approval_required`/`policy_denied`
governance distinction (§8.1), and the error-surface leak-prevention rule (§8.2) — are
graded only by a live-exchange harness once one exists. Until such a harness grades them,
those clauses are established by a recorded live exchange on the Commerce channel
`0x000E`, not by the pinned vector corpus: a conformance test suite SHOULD assert each
with a COMMERCE_MANDATE_CREATE_REQ / COMMERCE_MANDATE_CREATE_RESULT pair; a mandate read
whose `mandate_record` carries the authorizing terms and any signature the store holds; a
revoke that transitions the mandate to `revoked`; a COMMERCE_INTENT_PROPOSE_REQ /
COMMERCE_INTENT_PROPOSE_RESULT pair followed by an accept and, distinctly, a counter and a
reject; a COMMERCE_ERROR provoked for `policy_denied` and, distinctly, one for
`approval_required` carrying an `approval_id`; and a COMMERCE_ERROR provoked for
`intent_conflict` on an illegal intent transition.
