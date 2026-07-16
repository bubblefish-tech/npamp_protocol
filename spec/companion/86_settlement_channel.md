# NPAMP-SETTLEMENT — Settlement-Channel Operation Framework (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words MUST, MUST NOT,
> REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL
> are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only
> when, they appear in all capitals, as shown here. This document defines a
> **native** operation framing for the N-PAMP **Settlement channel `0x0007`**: the
> frame types, the deterministic-CBOR operation bodies, the in-body correlation
> discipline, the operation and state model, and the structured error model by
> which two peers record the settlement of a bilateral, agent-to-agent obligation,
> exchange the receipt that evidences it, and commit to a batch of settlements. It
> builds on the core specification (draft-bubblefish-npamp-01) and does not redefine
> it. Unlike a Bridge carriage class, the Settlement channel carries no foreign
> protocol: the operation body **is** N-PAMP's own encoding, so this document
> consumes no extension-TLV code point. It introduces no change to the core wire
> format. This document authors **only the public Settlement half** of the shared
> `0x00A0`–`0x00A3` batch-commitment range; the Audit half of that range is out of
> scope here (§3.3).

## 1. Scope

### 1.1 In scope

This document specifies, over the Settlement channel `0x0007` of the N-PAMP core
specification (the "core specification", draft-bubblefish-npamp-01):

1. A set of Settlement-channel frame types, drawn from the channel-specific
   application band that begins at `0x0100` (core specification §4.6,
   frame-type namespace), plus the two reserved companion-band code points
   `0x00A0`–`0x00A1` — the **public Settlement half** of the reserved
   `0x00A0`–`0x00A3` Settlement/Audit batch-commitment range
   (`../09_extension_points.md`) — this document finally defines;
2. Per-operation request and result frame pairs realizing the operation classes
   the core registry names for this channel — an **agent-to-agent settlement
   intent** that records a bilateral obligation as settled, a **receipt** that
   evidences a settlement, and a **batch commitment** that commits to a set of
   settlements by a single commitment value;
3. The **deterministic-CBOR** encoding of every operation body (RFC 8949, core
   specification §4.5 and §11.9), keyed by unsigned integers;
4. An **in-body correlation** discipline that matches a result to its request by a
   correlation token carried inside the CBOR body — consuming no shared TLV tag;
   and
5. A single structured **error frame** whose code set preserves a governance
   escalation (a settlement held for human approval and NOT executed) as a
   distinct, non-success outcome.

Operations are described generically — record a settlement, request a receipt, and
commit a batch — so that any two settlement peers interoperate over N-PAMP with no
bespoke adaptation. The document names no product, no vendor, no ledger model, and
no currency or asset registry; the `unit` and `amount` fields it carries (§6) are
opaque tokens the two peers agree on out of band.

### 1.2 Not in scope

This document does NOT:

* **Define a ledger, balance, or clearing model.** It fixes only what crosses the
  wire when a settlement is recorded and a receipt returned; how a peer maintains
  balances, nets obligations, clears, or reconciles is a local matter this document
  does not constrain.
* **Define a currency, asset, or value semantics.** The `unit` and `amount` fields
  (§6.1) are opaque strings the two peers interpret by out-of-band agreement; this
  document assigns no currency code registry, no asset taxonomy, and no arithmetic
  or rounding rule over `amount`. `amount` is carried as a decimal **text string**
  precisely so this framing imposes no float representation.
* **Carry multi-party commerce or payment mandates.** Multi-party agentic commerce
  and payment-mandate traffic is the purpose of the **Commerce** channel `0x000E`
  (`../channels/000E_commerce.md`), not of the bilateral Settlement channel. This
  document is scoped to a settlement **between the two peers of the association**
  (Settlement channel interface reference, `../channels/0007_settlement.md`, §1).
* **Define Audit-epoch commitments or transparency-log semantics.** The
  `0x00A0`–`0x00A3` range is reserved under a label **shared with the Audit
  channel** (`0x000B`, "Audit-epoch commitments and transparency-log entries").
  This document defines only the Settlement half (`0x00A0`–`0x00A1`, §3.3); the
  Audit half (`0x00A2`–`0x00A3`) and any audit-epoch or transparency-log behavior
  are out of scope here.
* **Define authorization, governance, or admission policy.** Whether a settlement
  is permitted, denied, or escalated for human approval is the responder's local
  decision; this document defines only how each outcome is *reported* on the wire
  (§8), not the policy that produces it.
* **Carry a foreign agent protocol.** The Settlement channel is native; it is not a
  Bridge carriage class and does not build on NPAMP-BRIDGE (Settlement channel
  interface reference §6). No frame in this document encapsulates a foreign
  message, and this document defines and consumes no extension-TLV tag.
* **Change the core wire format.** It alters no field of the core frame header, no
  reserved all-channel frame type, the extension-TLV encoding, or any code point
  the core specification assigns; it uses only code points the core specification
  reserves for or allocates to the Settlement channel.

## 2. Relationship to the core specification

The Settlement channel `0x0007` is registered by the core specification with
purpose **"Agent-to-agent settlement and receipts"**, minimum profile
**Standard**, and direction **Bidirectional** (core specification §5, Core Channel
Registry; `../../registries/channels.csv`; restated in
`../channels/0007_settlement.md` §2). Under the core specification's channel
architecture the channel is full-duplex: each peer maintains an independent
per-direction sequence space and independent per-direction traffic keys, so both
peers MAY transmit on the channel simultaneously. The Settlement channel is
**Bidirectional but not Multi-stream** (`../channels/0007_settlement.md` §2): both
peers exchange settlement, receipt, and batch-commitment frames over a **single**
stream, and the core specification assigns **no** fixed initiator/responder role at
the channel level. Either peer MAY originate a settlement operation.

**Minimum-profile gate.** A peer MUST enable the Settlement channel only at the
**Standard** profile or higher; once Standard is met the channel is available at
Standard, High, and Sovereign, and there is no profile at which it becomes
unavailable. A peer that has not advertised the Settlement channel during the
handshake (core specification §5) MUST NOT receive frames on it; a frame arriving
on an unadvertised Settlement channel MUST be dropped and MUST NOT be delivered to
settlement processing.

**Native, not a carriage class.** A Bridge carriage class carries a *foreign*
protocol's message octet-for-octet and wraps routing and correlation metadata
*around* it in a shared extension TLV. The Settlement channel has no foreign
protocol: the operation body is N-PAMP's own deterministic-CBOR encoding, and this
document owns that body in full. Consequently the correlation token, the operation
semantics, the receipt object, and the error object all live **inside** the CBOR
body, and this document reserves and consumes **no extension-TLV code point**. This
is the deliberate structural difference from NPAMP-BRIDGE and is the reason a
settlement operation is routed by its N-PAMP **frame type** (§3) rather than by any
method-name field parsed from a body. It mirrors the native Memory channel
(`./81_memory_channel.md`), not a Bridge carriage class.

**Frame-type namespace bands.** The core specification partitions each channel's
`0x0000`–`0xFFFF` frame-type space into four bands (core specification §4.6,
Frame-Type Namespace): `0x0000`–`0x000A` reserved all-channel frame types with the
same meaning on every channel; `0x000B`–`0x002F` unassigned, reserved to the core
for future all-channel additions; `0x0030`–`0x00FF` the **companion-extension
band**, per-channel extension frame types defined by companion specifications; and
`0x0100`–`0xFFFF` **channel-specific application** frame types. This document places
its operational frames in the application band at `0x0100`+ on the Settlement
channel, and additionally defines the two code points `0x00A0`–`0x00A1` — the
public Settlement half of the reserved `0x00A0`–`0x00A3` batch-commitment range,
which sits in the companion-extension band (§3.3). Because the frame-type space is
scoped by the Channel ID header field, these code points do not collide with any
other channel's assignments at the same numeric values.

## 3. Settlement-channel frame types

Within the Settlement channel (`0x0007`) frame-type namespace, this specification
defines seven frame types: five in the channel-specific application band at
`0x0100`+, and two in the reserved companion-extension band at `0x00A0`–`0x00A1`.

### 3.1 Application-band operation frames (`0x0100`+)

| Type | Name | Reply | Purpose |
|---|---|---|---|
| `0x0100` | SETTLE_INTENT_REQ | SETTLE_INTENT_RESULT or SETTLE_ERROR | Record that a bilateral, agent-to-agent obligation between the two peers is settled. |
| `0x0101` | SETTLE_INTENT_RESULT | None | Success reply to a settlement intent; echoes the request's correlation token. |
| `0x0102` | RECEIPT_REQ | RECEIPT_RESULT or SETTLE_ERROR | Return the receipt that evidences an identified settlement. |
| `0x0103` | RECEIPT_RESULT | None | Success reply to a receipt request; carries the settlement receipt. |
| `0x0104` | SETTLE_ERROR | None | Structured failure for any request; echoes the correlation token and carries a Settlement error code (§8). |

A `*_REQ` frame originates an operation; the corresponding `*_RESULT` frame, or a
SETTLE_ERROR (`0x0104`), replies to it. A `*_RESULT` frame is never sent
unsolicited: each MUST echo the correlation token of the request it answers (§5). A
responder MUST NOT emit both a `*_RESULT` and a SETTLE_ERROR for the same request.

### 3.2 Reserved all-channel frame types

The reserved all-channel frame types (PING `0x0001`, PONG `0x0002`, CLOSE
`0x0003`, CLOSE_ACK `0x0004`, ERROR `0x0005`, KEY_UPDATE `0x0006`,
KEY_UPDATE_ACK `0x0007`, PATH_CHALLENGE `0x0008`, PATH_RESPONSE `0x0009`, and
FLOW_UPDATE `0x000A`; core specification §4.6) retain their core meaning on the
Settlement channel. An implementation MUST NOT reuse them for Settlement
application traffic and MUST NOT define Settlement operation semantics in the
reserved all-channel range `0x0000`–`0x000A`. (`0x0000` is reserved and MUST NOT be
used as a frame type.)

### 3.3 Settlement batch-commitment frames (`0x00A0`–`0x00A1`)

The core specification reserves the range `0x00A0`–`0x00A3` in the
companion-extension band under the joint label **"Settlement/Audit batch-commitment
extension frames"** (`../09_extension_points.md`; `../04_frame_types.md`), and
states that a companion specification may define them without colliding with the
core wire format (core specification §8). The core specification reserves this
single range but does **not** partition it between the Settlement channel
(`0x0007`) and the Audit channel (`0x000B`). This document fixes that partition for
the **Settlement half only**, and defines two of the four code points:

| Type | Name | Reply | Purpose |
|---|---|---|---|
| `0x00A0` | SETTLE_BATCH_COMMIT_REQ | SETTLE_BATCH_COMMIT_RESULT or SETTLE_ERROR | Commit to a batch of settlements by a single opaque commitment value. |
| `0x00A1` | SETTLE_BATCH_COMMIT_RESULT | None | Success reply to a batch commitment; echoes the correlation token. |

The remaining two code points of the shared range, `0x00A2`–`0x00A3`, are the
**Audit half** ("Audit-epoch commitments and transparency-log entries",
`../channels/000B_audit.md`). This document defines **no** semantics for
`0x00A2`–`0x00A3`; they remain reserved to the Audit channel, and an implementation
MUST NOT treat any behavior on those two code points as defined by this document.
An implementation MUST NOT assign `0x00A0`–`0x00A1` to any purpose other than the
Settlement batch-commitment operation defined here, and MUST NOT treat batch
commitment as behavior defined by the core specification alone (the core reserves
the range; this companion defines the Settlement half). Batch commitment is
OPTIONAL to implement; a responder that does not implement it MUST reply
SETTLE_ERROR with code `unknown_operation` (§8).

All seven frame types defined above lie within the Settlement channel's own
frame-type namespace: five in the application band at or above `0x0100`, and two in
the companion-extension band reserved (jointly with the Audit channel) for
batch-commitment frames. This document consumes no frame-type code point outside
the Settlement channel's namespace and reserves none in the core specification's
cross-channel reserved ranges.

## 4. Frame payload encoding

### 4.1 Payload container

A Settlement frame's payload (the octets after the core frame header and any
extension TLVs, and before the AEAD tag) is a single **deterministically encoded
CBOR** object as defined by the core specification §4.5 and §11.9 (deterministic
CBOR, RFC 8949). The payload MUST be a CBOR map whose keys are the unsigned
integers defined in §4.2 and §5–§8 for the relevant frame type. A sender MUST
produce the deterministic encoding (core specification §11.9): byte-identical
output for identical inputs, with the canonical key ordering and shortest-form
integer encoding RFC 8949 §4.2 requires, and definite-length maps and arrays.

A receiver MUST reject, with SETTLE_ERROR code `malformed_request` (§8), any
Settlement frame whose payload is not a valid deterministic-CBOR map, whose payload
omits a REQUIRED key for its frame type, or whose payload carries a key of the
wrong CBOR major type.

Settlement operation bodies are carried in the frame **payload**, not in extension
TLVs. This document defines and consumes no extension-TLV tag, and therefore claims
none of the TLV code points the core specification reserves.

### 4.2 Common envelope fields

Every Settlement payload map carries the following two envelope fields. Integer
keys are given in parentheses.

| Field (key) | CBOR type | Meaning |
|---|---|---|
| `frame_kind` (0) | Unsigned int | MUST equal the frame's Settlement frame type (one of `0x00A0`, `0x00A1`, or `0x0100`–`0x0104`). A receiver MUST reject (SETTLE_ERROR, code `malformed_request`) a payload whose `frame_kind` contradicts the frame-header Frame Type. |
| `corr` (1) | Byte string (1–64 B) | Correlation token (§5). Present and non-empty on every `*_REQ` and on every frame that replies to one. |

The per-frame body fields defined in §6–§8 occupy keys `2` and above within the
same map; §6 gives, per frame, the full field table.

### 4.3 Forward compatibility

A receiver MUST ignore an unrecognized integer key it encounters in a Settlement
payload map whose key is **not negative**, so that a later revision of this
document MAY add fields without breaking a conformant receiver. A receiver MUST
reject (SETTLE_ERROR, code `malformed_request`) a payload that carries a
**negative** integer key it does not recognize, reserving the negative key space
for forward-incompatible additions. A receiver MUST NOT treat the mere presence of
an unknown non-negative key as an error, and MUST NOT alter its handling of the
keys it does recognize because of it.

## 5. Correlation and operation model

The core specification does not define how a Settlement result is correlated to its
request (unlike the Bridge channel, where NPAMP-BRIDGE §5 defines a correlation
identifier; see `../channels/0007_settlement.md` §4). This document supplies that
discipline, carrying the token **inside** the CBOR body rather than in a shared
TLV, because a native channel owns its whole body (§2).

### 5.1 Correlation discipline

* Every `*_REQ` frame — SETTLE_INTENT_REQ (`0x0100`), RECEIPT_REQ (`0x0102`), and
  SETTLE_BATCH_COMMIT_REQ (`0x00A0`) — MUST carry a non-empty `corr` (§4.2) that is
  unique among the originating peer's outstanding Settlement requests on the
  channel in that direction.
* Every SETTLE_INTENT_RESULT, RECEIPT_RESULT, SETTLE_BATCH_COMMIT_RESULT, and
  SETTLE_ERROR MUST echo the originating request's `corr` verbatim.
* A receiver MUST match a result to its request by `corr`, **not** by the
  per-(channel, direction) frame sequence number. Because the Settlement channel is
  Bidirectional and either peer MAY originate operations, matching by `corr` keeps
  a result unambiguously bound to the request that provoked it even when both peers
  have requests outstanding at once on the single stream.

### 5.2 Correlation lifetime

A `corr` value is consumed when the operation's `*_RESULT` or SETTLE_ERROR is
delivered; the requester MUST treat that exchange as complete and MUST NOT reuse
the value for a new request while the original is outstanding. Every Settlement
operation defined here is a single-reply exchange (there is no streamed result on
this channel).

### 5.3 Side-effect class (`effect`)

Every state-mutating request — SETTLE_INTENT_REQ and SETTLE_BATCH_COMMIT_REQ — MUST
carry an `effect` field (§6) declaring the most severe side effect the operation
may cause, drawn from the side-effect classes below. It is the native-body analogue
of a Bridge SafetyLabel, carried in-body because the Settlement channel owns its
body (§2). A read-only request (RECEIPT_REQ) carries `effect` = `read_only`.

| Value | Name | Meaning |
|---|---|---|
| `0x00` | read_only | No state change (a receipt request). |
| `0x01` | idempotent_write | A write whose repetition yields the same recorded state (for example a settlement intent guarded by an `idempotency_key`, or a re-commitment of an identical batch). |
| `0x02` | non_idempotent_write | A write that is not safely repeatable (a settlement intent that would double-record an obligation if replayed). |
| `0x03` | destructive | An operation that removes or reverses recorded settlement state. No operation in this document is inherently destructive; the class is reserved for the fail-safe rule below and for future extension. |

**Fail-safe.** A receiver MUST treat a state-mutating request that omits `effect`,
or carries an `effect` value it does not recognize, as `destructive`, and MAY
refuse it (SETTLE_ERROR). A requester MUST NOT rely on a mutating request that omits
`effect` being executed.

## 6. Operation bodies

Each operation body is a deterministic-CBOR map carrying the common envelope
(§4.2, keys `0`–`1`) and the per-frame fields below at keys `2`+. Unless a field
is marked required, it is OPTIONAL and, when absent, carries no value (a producer
omits the key rather than encoding a null placeholder; a producer that does encode
an explicit CBOR `null` for an absent OPTIONAL field is equivalent to omitting it).

### 6.1 SETTLE_INTENT_REQ (`0x0100`) / SETTLE_INTENT_RESULT (`0x0101`)

Record that a bilateral, agent-to-agent obligation between the two peers is
settled.

**SETTLE_INTENT_REQ body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `obligation_ref` (2) | Text string | Yes | An opaque reference to the bilateral obligation the two peers are settling. Its meaning is agreed out of band or established on another channel; this document does not define the obligation itself. |
| `settlement_ref` (3) | Text string | No | A caller-assigned identifier for this settlement act. When absent, the responder assigns one and returns it in the result. |
| `unit` (4) | Text string | No | The unit the obligation is denominated in — an opaque asset or currency token the peers agree on. This document assigns no registry and no semantics to it. |
| `amount` (5) | Text string | No | The magnitude settled, as a decimal text string (never a float, to avoid rounding). Opaque to this document; interpreted only by the peers. |
| `memo` (6) | Text string | No | An advisory free-text memo describing the settlement. Not an identifier. |
| `idempotency_key` (7) | Text string | No | A caller-supplied key that lets the responder de-duplicate a retried settlement intent. When present, a repeat with the same key MUST NOT record the obligation twice. |
| `effect` (8) | Unsigned int | Yes | Side-effect class (§5.3). A settlement intent is normally `0x02` non_idempotent_write, or `0x01` idempotent_write when guarded by `idempotency_key`. |

**SETTLE_INTENT_RESULT body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `settlement_ref` (2) | Text string | Yes | The identifier the responder assigned to (or echoed for) the recorded settlement. |
| `status` (3) | Text string | Yes | A short accepted-state token for the settlement (for example `settled` or `accepted`). |
| `receipt_ref` (4) | Text string | No | Present if the responder issued a receipt for this settlement inline; its identifier, fetchable via RECEIPT_REQ (§6.2). |

A settlement intent that the responder holds for human approval, rather than
recording, is NOT reported as a SETTLE_INTENT_RESULT; it is reported as SETTLE_ERROR
with code `approval_required` (§8.1). A responder MUST NOT emit a
SETTLE_INTENT_RESULT for an obligation it did not record.

### 6.2 RECEIPT_REQ (`0x0102`) / RECEIPT_RESULT (`0x0103`)

Return the receipt that evidences an identified settlement — the acknowledgement
half of the channel's purpose (`../channels/0007_settlement.md` §4).

**RECEIPT_REQ body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `settlement_ref` (2) | Text string | Yes | The settlement whose receipt is requested. |
| `receipt_ref` (3) | Text string | No | A specific receipt identifier, when the requester already knows one. |
| `effect` (4) | Unsigned int | Yes | Side-effect class (§5.3); MUST be `0x00` read_only. |

**RECEIPT_RESULT body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `receipt` (2) | Map (a `settlement_receipt`) | Yes | The receipt evidencing the settlement. |

A receipt request for a settlement the responder has no record of is reported as
SETTLE_ERROR with code `not_found` (§8), not as an empty RECEIPT_RESULT.

A `settlement_receipt` is the wire projection of the evidence for one settlement:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `receipt_ref` (0) | Text string | Yes | Identity of the receipt. |
| `settlement_ref` (1) | Text string | Yes | The settlement this receipt evidences. |
| `obligation_ref` (2) | Text string | No | The obligation that was settled. |
| `unit` (3) | Text string | No | The unit settled (as in §6.1). |
| `amount` (4) | Text string | No | The magnitude settled, as a decimal text string (as in §6.1). |
| `status` (5) | Text string | Yes | The settled state the receipt attests (for example `settled`). |
| `timestamp` (6) | Text string | No | The settlement time, as an RFC 3339 timestamp. |
| `issuer` (7) | Text string | No | An opaque identifier of the peer that issued the receipt. |
| `signature` (8) | Text string | No | A cryptographic signature over the receipt's signable envelope, hex-encoded. |
| `signing_key_id` (9) | Text string | No | Identifier of the key that produced `signature`. |
| `signature_alg` (10) | Text string | No | The signature algorithm identifier. |

A receipt MUST carry the settlement facts the responder holds (`settlement_ref`,
`status`, and any `signature` material present): a RECEIPT_RESULT MUST NOT strip a
signature the responder associates with the receipt. Any OPTIONAL field above MAY
be absent when the responder holds no value for it. This document defines the
receipt's wire projection only; it does not define a signature scheme, a canonical
signable-envelope serialization, or a trust model for verifying `signature`, which
are layered above this framing.

### 6.3 SETTLE_BATCH_COMMIT_REQ (`0x00A0`) / SETTLE_BATCH_COMMIT_RESULT (`0x00A1`)

Commit to a batch of settlements by a single opaque commitment value — the
Settlement half of the reserved batch-commitment range (§3.3).

**SETTLE_BATCH_COMMIT_REQ body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `batch_ref` (2) | Text string | Yes | An identifier for the batch being committed. |
| `commitment` (3) | Byte string | Yes | The commitment value over the batch's member settlements — for example a hash root over their receipt references. Opaque octets to this document: the commitment construction (hash function, tree scheme) is NOT fixed here. |
| `commitment_alg` (4) | Text string | No | An advisory identifier of the commitment construction, so a verifier can select the right algorithm. |
| `member_count` (5) | Unsigned int | No | The number of settlements the commitment covers. |
| `period` (6) | Text string | No | An advisory settlement-period or epoch label the batch covers. This is a bilateral settlement period only; it is NOT an Audit-channel audit epoch (§1.2, §3.3). |
| `effect` (7) | Unsigned int | Yes | Side-effect class (§5.3); `0x02` non_idempotent_write, or `0x01` idempotent_write when a re-commitment of an identical `(batch_ref, commitment)` is intended to be safely repeatable. |

**SETTLE_BATCH_COMMIT_RESULT body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `batch_ref` (2) | Text string | Yes | Echoes the committed batch identifier. |
| `status` (3) | Text string | Yes | A short accepted-state token for the commitment (for example `committed`). |
| `commitment_receipt_ref` (4) | Text string | No | An identifier of a receipt evidencing the batch commitment, fetchable via RECEIPT_REQ (§6.2). |

A re-commitment naming an existing `batch_ref` with a **different** `commitment`
value MUST be reported as SETTLE_ERROR with code `commitment_conflict` (§8), so a
committed batch cannot be silently overwritten by an inconsistent commitment. A
batch commitment held for human approval is reported as `approval_required`
(§8.1), not as a SETTLE_BATCH_COMMIT_RESULT.

## 7. Operation and state model

Each Settlement operation is a single request/result exchange correlated by `corr`
(§5). Because the channel is Bidirectional and not Multi-stream (§2), all frames
travel on one stream in each direction and either peer MAY originate any operation;
the core specification assigns no fixed initiator/responder role.

A well-formed exchange is one of:

1. **Settlement intent** — SETTLE_INTENT_REQ answered by exactly one
   SETTLE_INTENT_RESULT (the obligation was recorded) or one SETTLE_ERROR (it was
   not, including a governance escalation reported as `approval_required`, §8.1).
2. **Receipt** — RECEIPT_REQ answered by exactly one RECEIPT_RESULT carrying the
   receipt, or one SETTLE_ERROR (for example `not_found`).
3. **Batch commitment** — SETTLE_BATCH_COMMIT_REQ answered by exactly one
   SETTLE_BATCH_COMMIT_RESULT or one SETTLE_ERROR.

A responder MUST send exactly one reply frame per request (either the operation's
`*_RESULT` or a SETTLE_ERROR), MUST NOT send both for the same `corr`, and MUST NOT
send an unsolicited `*_RESULT`. A requester that has consumed a `corr` (§5.2) MUST
treat a later frame echoing that same `corr` as a protocol error and MUST NOT act
on it as a fresh result.

There is no partial or streamed settlement result on this channel: unlike the
Multi-stream Memory channel's streamed retrieval (`./81_memory_channel.md` §7) or
the Stream channel's sub-streams (`./80_stream_channel.md`), a Settlement operation
completes in a single result frame.

## 8. Error model

Every failure of a Settlement request is reported in a single SETTLE_ERROR
(`0x0104`) frame — the Settlement channel has no foreign protocol, so all errors
are native and carried in one structured frame. A SETTLE_ERROR echoes the failed
request's `corr` and carries:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `code` (2) | Unsigned int | Yes | One of the Settlement error codes below. |
| `message` (3) | Text string | Yes | A peer-safe, generic human-readable message for `code`. It MUST NOT carry internal detail (§8.2). |
| `retry_after_s` (4) | Unsigned int | No | When present, the number of seconds after which the requester MAY retry. |
| `approval_id` (5) | Text string | No | Present if and only if `code` is `approval_required`: an identifier of the held-for-approval operation (§8.1). |

| Code | Name | Meaning |
|---|---|---|
| 1 | malformed_request | The CBOR body is not valid deterministic CBOR, omits a REQUIRED field, uses a wrong CBOR major type, or carries an unknown negative key (§4). |
| 2 | unknown_operation | The frame type is not a Settlement operation the responder implements (for example the OPTIONAL batch-commitment frame at a responder that does not support it, §3.3). |
| 3 | policy_denied | The operation was refused by the responder's governance or policy: a definitive denial. |
| 4 | approval_required | The operation was escalated for human approval and was **NOT executed** (§8.1). Carries `approval_id`. |
| 5 | not_found | An identified settlement, receipt, or batch reference does not exist. |
| 6 | already_settled | The referenced obligation was already settled under a prior settlement act; the new intent conflicts with the recorded settlement (§6.1). |
| 7 | commitment_conflict | A batch commitment for the same `batch_ref` was already recorded with a different `commitment` value (§6.3). |
| 8 | internal_error | A settlement-store or pipeline failure the responder cannot attribute to the request. Generic; no internal detail crosses the wire. |

### 8.1 Governance escalation is a distinct, non-success outcome

A `policy_denied` (code 3) and an `approval_required` (code 4) are different
results and MUST NOT be conflated. `policy_denied` is a definitive refusal: the
settlement will not proceed. `approval_required` means the operation has been
**held for human approval and has NOT been executed** — it is neither a success nor
a definitive denial, but a pending decision.

An implementation MUST report a governance escalation as SETTLE_ERROR with code
`approval_required`, carrying `approval_id`, and MUST NOT report it as a
SETTLE_INTENT_RESULT, SETTLE_BATCH_COMMIT_RESULT, or any other `*_RESULT`. A
held-for-approval settlement MUST NOT be presented to the requester as a completed
settlement: an obligation that was not recorded is never a success frame. A
requester MUST treat `approval_required` as an operation that has not yet taken
effect, distinct from both a success and a `policy_denied`. This preserves, for
settlement, the same governance-hold discipline the Memory channel fixes
(`./81_memory_channel.md` §8.1).

### 8.2 No internal detail on the wire

The `message` field MUST be the generic, peer-safe string for its `code`. The full
internal cause of a failure MUST be handled locally (for example logged by the
responder) and MUST NOT cross the wire: a SETTLE_ERROR MUST NOT carry settlement-store
internals, policy topology, ledger or balance state, configuration or source names,
decoder diagnostics, or any other detail beyond the code and its generic message.
This leak-prevention requirement is normative for interoperability, not merely local
hygiene: a requester MUST be able to rely on the error surface exposing only a code,
a generic message, and the OPTIONAL `retry_after_s` / `approval_id` fields.

## 9. Security and privacy considerations

This section supplements the core specification's Security Considerations; it does
not restate them.

Every Settlement frame is AEAD-protected like all N-PAMP frames and is carried under
the association's existing authentication (the core specification's handshake binds
both peer identities into the transcript and the Finished MAC). A responder
therefore knows that a settlement operation was requested by the authenticated peer,
but authentication is not authorization: a responder MUST enforce its own governance
and access policy on every operation regardless of the peer's identity, and MUST
report the outcome per §8 — including preserving the `approval_required` /
`policy_denied` distinction. Because settling an obligation is a
consequential, potentially irreversible act, the governance-hold outcome (§8.1) is
especially load-bearing on this channel: a responder that escalates a settlement for
human approval MUST NOT let the requester mistake the hold for a completed
settlement.

A receipt (§6.2) is evidence a peer may retain and present later. The OPTIONAL
`signature` / `signing_key_id` / `signature_alg` fields let an issuer bind a receipt
to a signing key so its authenticity survives outside the association; this document
carries that material but defines no signature scheme or trust model, and a verifier
MUST obtain the signable-envelope serialization and the trust anchor for a
`signing_key_id` from a layer above this framing before relying on a signature. A
responder SHOULD return a receipt only to a peer entitled to it and MAY decline a
RECEIPT_REQ (with `policy_denied` or `not_found`) for a settlement it does not wish
to expose. The `unit`, `amount`, and `memo` fields (§6.1) may be commercially
sensitive; both peers SHOULD treat recorded settlement state as sensitive and scope
its disclosure per peer.

A responder MUST bound the resources a remote peer can consume through Settlement
operations: the rate of requests it will accept, the number of distinct
`settlement_ref` and `batch_ref` values it will record, and the size of a batch
commitment it will store. A responder MAY reply SETTLE_ERROR (with `retry_after_s`)
rather than allocate without limit. Because either peer may originate operations on
this Bidirectional channel, both directions are subject to these limits.

The error surface MUST NOT leak internal detail (§8.2); a SETTLE_ERROR that carried
ledger state, policy topology, or configuration names would disclose the responder's
internal structure to the peer and is a conformance violation (§10).

## 10. Conformance

An implementation conforms to NPAMP-SETTLEMENT if and only if it rests on a
core-conformant N-PAMP wire implementation and, on the Settlement channel `0x0007`,
it:

1. Treats `0x0007` as the Settlement channel with the core registry identity
   (name Settlement; purpose agent-to-agent settlement and receipts; minimum profile
   Standard; direction Bidirectional), does not repurpose the channel identifier,
   enables it only at the **Standard** profile or higher, and drops any frame
   received on an unadvertised Settlement channel (§2);
2. Uses only the Settlement frame types defined in §3 — the application-band
   operation frames `0x0100`–`0x0104` and the batch-commitment frames
   `0x00A0`–`0x00A1` — preserves the core meaning of the reserved all-channel frame
   types `0x0000`–`0x000A`, assigns `0x00A0`–`0x00A1` to no purpose other than
   Settlement batch commitment, and defines and honors **no** semantics on the Audit
   half of the shared range `0x00A2`–`0x00A3` (§3.2, §3.3);
3. Encodes every operation body as a deterministic-CBOR map (§4.1) with the integer
   keys of §4.2 and §5–§8; rejects a non-deterministically-encoded body, a body
   missing a REQUIRED field, a body with a wrong-major-type key, or a body carrying
   an unknown negative key with SETTLE_ERROR `malformed_request`; and ignores an
   unknown non-negative key without altering its handling of recognized keys (§4);
4. Carries a non-empty `corr` on every `*_REQ`, echoes it verbatim on every reply,
   and matches replies to requests by `corr` rather than by frame sequence number
   (§5);
5. Carries an `effect` on every state-mutating request (SETTLE_INTENT_REQ,
   SETTLE_BATCH_COMMIT_REQ), carries `read_only` on RECEIPT_REQ, and treats a
   missing or unknown `effect` on a mutating operation as `destructive` (§5.3
   fail-safe);
6. Reports every failure as SETTLE_ERROR (`0x0104`) with a code from §8 and a
   peer-safe `message`, never leaking internal cause (§8.2); reports a governance
   escalation as `approval_required` carrying `approval_id`, distinct from
   `policy_denied`; and never reports a success `*_RESULT` for a settlement that was
   not recorded (a held-for-approval settlement is `approval_required`, not a
   SETTLE_INTENT_RESULT) (§6.1, §6.3, §8.1);
7. Returns, for a RECEIPT_REQ that resolves, a RECEIPT_RESULT whose
   `settlement_receipt` preserves the settlement facts and any signature material the
   responder holds, and reports a receipt request for an unknown settlement as
   `not_found` rather than an empty result (§6.2); and
8. Sends exactly one reply frame per request, never both a `*_RESULT` and a
   SETTLE_ERROR for the same `corr`, never an unsolicited `*_RESULT`, and rejects a
   batch re-commitment that changes the `commitment` for an existing `batch_ref`
   with `commitment_conflict` (§6.3, §7).

A conformance test suite SHOULD assert each clause above with a recorded exchange on
the Settlement channel: a SETTLE_INTENT_REQ / SETTLE_INTENT_RESULT pair; a
RECEIPT_REQ / RECEIPT_RESULT pair whose receipt carries a non-empty `status` and, if
signed, its signature material; a SETTLE_BATCH_COMMIT_REQ / SETTLE_BATCH_COMMIT_RESULT
pair and a distinct re-commitment provoking `commitment_conflict`; a SETTLE_ERROR
provoked for `policy_denied` and, distinctly, one for `approval_required` carrying an
`approval_id`; and a rejected malformed body (a non-deterministic encoding, a missing
REQUIRED field, and an unknown negative key), each yielding `malformed_request`.

Machine-gradable conformance vectors exist for the Settlement channel's payload-decode
surface: the `settlement.body.decode` operation group in the conformance corpus,
produced by an independent RFC 8949 byte constructor
(`test-vectors/gen/settlement_oracle.py`, whose expected values are constructed
independently of the implementation it grades) and graded by `npamp-conform` against
the Go reference implementation, cross-validated by
`impl/go/zz_settlement_oracle_xval_test.go`, covers the §4.1 / §4.2 / §4.3
payload-encoding and common-envelope MUST-reject clauses — the deterministic-CBOR body
container, the common envelope (`frame_kind` / `corr`), and the forward-compatibility
key rules — so a conformance claim for those clauses is graded against expected values
produced by an independent authority, not by the implementation under test.

Beyond that payload surface, the §5–§9 behavioural clauses — the correlation and
operation model (§5), the operation bodies (§6), the operation and state model (§7),
the error model's governance-escalation distinction and leak-prevention rules (§8), and
the security and privacy requirements (§9) — are graded only by a live-exchange harness
once one exists. The §10 conformance test suite above records the exchanges that would
grade them (a SETTLE_INTENT pair, a RECEIPT pair, a batch-commit pair and a
`commitment_conflict`, a `policy_denied` distinct from an `approval_required`, and the
malformed-body rejections), but no non-circular vector oracle grades those behavioural
clauses yet; a claim of conformance to them is established by such a recorded live
exchange, not by the pinned vector corpus. The live-exchange harness for the §5–§9
behavioural clauses is tracked as an open gap in the project's spec-parity ledger; the
`settlement.body.decode` payload surface is graded today.
