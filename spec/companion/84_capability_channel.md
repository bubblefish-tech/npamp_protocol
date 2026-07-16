# NPAMP-CAP — Capability-Channel Operation Framework (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words MUST, MUST NOT,
> REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL
> are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only
> when, they appear in all capitals, as shown here. This document defines a
> **native** operation framing for the N-PAMP **Capability channel `0x0002`**: the
> frame types, the deterministic-CBOR operation bodies, the in-body correlation
> discipline, the operation and state model, and the structured error model by
> which one peer issues, delegates, revokes, and looks up **authorizations held by
> another peer**. It builds on the core specification (draft-bubblefish-npamp-01)
> and does not redefine it. Unlike a Bridge carriage class, the Capability channel
> carries no foreign protocol: the operation body **is** N-PAMP's own encoding, so
> this document consumes no extension-TLV code point. It introduces no change to the
> core wire format. It is the concrete Capability operation encoding the channel's
> public interface reference (`../channels/0002_capability.md`) defers to a
> companion: "A future companion specification MAY define a concrete Capability
> operation encoding within the code points the core specification reserves."

## 1. Scope

### 1.1 In scope

This document specifies, over the Capability channel `0x0002` of the N-PAMP core
specification (the "core specification", draft-bubblefish-npamp-01):

1. A set of Capability-channel frame types, drawn from the channel-specific
   application band that begins at `0x0100` (core specification §4.6, frame-type
   namespace), plus the four reserved companion-band code points `0x0060`–`0x0063`
   this document finally defines as **capability token extension frames**;
2. Per-operation request and result frame pairs realizing the four operation
   classes the core registry names for this channel — **issuance**, **delegation**,
   **revocation**, and **lookup** — where the registry purpose is "Capability
   issuance, delegation, revocation, lookup";
3. The **deterministic-CBOR** encoding of every operation body (RFC 8949, core
   specification §4.5 and §11.9), keyed by unsigned integers;
4. An **in-body correlation** discipline that matches a reply to its request by a
   correlation token carried inside the CBOR body — consuming no shared TLV tag;
5. A single structured **error frame** whose result set preserves a governance
   escalation (an operation held for approval and NOT executed) as a distinct,
   non-success outcome; and
6. The **capability_token** wire projection an implementation exposes when it issues,
   delegates, or resolves a capability, and the OPTIONAL token-extension exchange
   (present/accept and challenge/proof) carried in the reserved `0x0060`–`0x0063`
   band.

Operations are described generically — grant, delegate, withdraw, and resolve an
authority — so that any authority implementation and any client interoperate over
N-PAMP with no bespoke adaptation. The document names no product, no vendor, and no
application-specific authority schema.

### 1.2 Not in scope

This document does NOT:

* **Define the internal representation of a capability at the responder.** The token
  fields in §6.5 are the *wire* projection an implementation exposes; how an
  authority stores, indexes, or evaluates a capability is a local matter this
  document does not constrain — it fixes only what crosses the wire.
* **Define the capability-token signable-byte construction or its verification
  algorithm.** The core specification's signature-code-point table names capability
  tokens among the usages of its All-profiles signature algorithm (Ed25519), and the
  wire projection (§6.5) carries a `signature`, `signing_key_id`, and
  `signature_alg`; but the exact canonicalization of a token's signable envelope and
  the algorithm by which a verifier checks it are deferred, not fixed here. This
  document carries the signature material; it does not manufacture a signing input
  the core specification does not state.
* **Define an authorization, governance, or admission policy.** Whether an issuance,
  delegation, revocation, or lookup is permitted, denied, or escalated for human
  approval is the responder's local decision; this document defines only how each of
  those outcomes is *reported* on the wire (§8), not the policy that produces them.
* **Define a constraint or caveat language.** A capability carries an opaque
  `constraints` map (§6.5); this document defines no expression grammar for it,
  because a full caveat language would exceed a wire-interoperability contract and is
  better layered above this framing.
* **Carry a foreign agent protocol.** The Capability channel is native; it is not a
  Bridge carriage class and does not build on NPAMP-BRIDGE (Capability-channel
  interface reference, §6). No frame in this document encapsulates a foreign message,
  and this document defines and consumes no extension-TLV tag.
* **Redefine the Control-channel capability epoch or Discovery capability
  advertisement.** The connection-level capability epoch of Control `0x0000` and the
  capability *advertisement* of Discovery `0x0010` are distinct channels with
  distinct purposes (Capability-channel interface reference, §6); this document
  governs only the per-authority issuance/delegation/revocation/lookup traffic of
  channel `0x0002`.
* **Change the core wire format.** It alters no field of the core frame header, no
  reserved all-channel frame type, the extension-TLV encoding, or any code point the
  core specification assigns; it uses only code points the core specification
  reserves for the Capability channel.

## 2. Relationship to the core specification

The Capability channel `0x0002` is registered by the core specification with purpose
**"Capability issuance, delegation, revocation, lookup"**, minimum profile
**Standard**, and direction **Bidirectional** (core specification §5, Core Channel
Registry; machine-readable form `../../registries/channels.csv`; restated by
`../channels/0002_capability.md`). Under the core specification's channel
architecture every channel is full-duplex: each peer maintains an independent
per-direction sequence space and independent per-direction traffic keys, so either
peer MAY originate a Capability operation.

**Bidirectional, not Multi-stream.** Unlike the Memory channel `0x0001` and the
Stream channel `0x000C`, the Capability channel is **not** classified Multi-stream:
it does not open multiple concurrent transport sub-streams within a stream family
(Capability-channel interface reference, §2). Both peers send and receive on a
single stream of the channel, each using its own sequence space and traffic keys.
Consequently this document defines **no** streamed result: a lookup result larger
than one frame is paginated across successive request/reply exchanges by an opaque
`cursor` (§6.4), not carried as concurrent stream frames.

**Minimum-profile gate.** A peer MUST enable the Capability channel only at the
**Standard** profile or higher; once Standard is met the channel is available at
Standard, High, and Sovereign, and there is no profile at which it becomes
unavailable. A peer that has not advertised the Capability channel during the
handshake (core specification §5) MUST NOT receive frames on it; a frame arriving on
an unadvertised Capability channel MUST be dropped and MUST NOT be delivered to a
capability subsystem.

**Native, not a carriage class.** A Bridge carriage class carries a *foreign*
protocol's message octet-for-octet and wraps routing and correlation metadata
*around* it in a shared extension TLV. The Capability channel has no foreign
protocol: the operation body is N-PAMP's own deterministic-CBOR encoding, and this
document owns that body in full. Consequently the correlation token, the operation
semantics, and the error object all live **inside** the CBOR body, and this document
reserves and consumes **no extension-TLV code point**. This is the deliberate
structural difference from NPAMP-BRIDGE and is the reason a Capability operation is
routed by its N-PAMP **frame type** (§3) rather than by any method-name field parsed
from a body.

**Frame-type namespace bands.** The core specification partitions each channel's
`0x0000`–`0xFFFF` frame-type space into four bands (core specification §4.6,
Frame-Type Namespace): `0x0000`–`0x000A` reserved all-channel frame types with the
same meaning on every channel; `0x000B`–`0x002F` unassigned, reserved to the core
for future all-channel additions; `0x0030`–`0x00FF` the **companion-extension band**,
per-channel extension frame types defined by companion specifications; and
`0x0100`–`0xFFFF` **channel-specific application** frame types. This document places
its operation frames in the application band at `0x0100`+ on the Capability channel,
and additionally defines the four Capability reserved-range code points
`0x0060`–`0x0063` that sit in the companion-extension band (§3.3). The Capability
interface reference records an apparent inconsistency — that channel-specific frame
types "begin at `0x0100`" while the reserved band sits below `0x0100`; the four-band
partition above resolves it: `0x0060`–`0x0063` is companion-extension, `0x0100`+ is
application. Because the frame-type space is scoped by the Channel ID header field,
these code points do not collide with any other channel's assignments at the same
numeric values.

## 3. Capability-channel frame types

Within the Capability channel (`0x0002`) frame-type namespace, this specification
defines thirteen frame types: nine in the channel-specific application band at
`0x0100`+, and four in the reserved companion-extension band at `0x0060`–`0x0063`.

### 3.1 Application-band operation frames (`0x0100`+)

| Type | Name | Reply | Purpose |
|---|---|---|---|
| `0x0100` | CAP_ISSUE_REQ | CAP_ISSUE_RESULT or CAP_ERROR | Grant a new authority — a capability held by the issuer — to a peer. |
| `0x0101` | CAP_ISSUE_RESULT | None | Success reply to an issuance; carries the issued `capability_token` and echoes the request's correlation token. |
| `0x0102` | CAP_DELEGATE_REQ | CAP_DELEGATE_RESULT or CAP_ERROR | Convey a held capability onward to another peer, optionally attenuated. |
| `0x0103` | CAP_DELEGATE_RESULT | None | Success reply to a delegation; carries the delegated child `capability_token`. |
| `0x0104` | CAP_REVOKE_REQ | CAP_REVOKE_RESULT or CAP_ERROR | Withdraw a previously issued or delegated capability, ending the authority it conveyed. |
| `0x0105` | CAP_REVOKE_RESULT | None | Success reply to a revocation. |
| `0x0106` | CAP_LOOKUP_REQ | CAP_LOOKUP_RESULT or CAP_ERROR | Resolve or query a capability — its existence, current status, or the set a subject holds. |
| `0x0107` | CAP_LOOKUP_RESULT | None | A bounded, paginated result set delivered in a single frame. |
| `0x0108` | CAP_ERROR | None | Structured failure for any request; echoes the correlation token and carries a Capability error code (§8). |

A `*_REQ` frame originates an operation; the corresponding `*_RESULT` frame, or a
CAP_ERROR (`0x0108`), replies to it. A `*_RESULT` frame is never sent unsolicited:
each MUST echo the correlation token of the request it answers (§5). A responder MUST
NOT emit a `*_RESULT` and a CAP_ERROR for the same request.

### 3.2 Reserved all-channel frame types

The reserved all-channel frame types (PING `0x0001`, PONG `0x0002`, CLOSE `0x0003`,
CLOSE_ACK `0x0004`, ERROR `0x0005`, KEY_UPDATE `0x0006`, KEY_UPDATE_ACK `0x0007`,
PATH_CHALLENGE `0x0008`, PATH_RESPONSE `0x0009`, and FLOW_UPDATE `0x000A`; core
specification §4.6) retain their core meaning on the Capability channel. An
implementation MUST NOT reuse them for Capability application traffic and MUST NOT
define Capability operation semantics in the reserved all-channel range
`0x0000`–`0x000A`.

### 3.3 Capability token extension frames (`0x0060`–`0x0063`)

The core specification reserves the range `0x0060`–`0x0063` in the
companion-extension band specifically for Capability-channel **token extension**
frames, and states that a companion specification may define them (core
specification §8, Reserved Frame-Type Ranges; reference `../09_extension_points.md`,
"`0x0060` – `0x0063` | Capability-channel token extension frames"). This document is
that companion; it defines those four code points as two OPTIONAL token-handling
request/reply pairs:

| Type | Name | Reply | Purpose |
|---|---|---|---|
| `0x0060` | CAP_TOKEN_PRESENT | CAP_TOKEN_ACCEPT or CAP_ERROR | A holder presents a `capability_token` (with its delegation chain) to the peer, out of band from a specific operation. |
| `0x0061` | CAP_TOKEN_ACCEPT | None | Success reply to CAP_TOKEN_PRESENT; records the token as presented and echoes the correlation token. |
| `0x0062` | CAP_TOKEN_CHALLENGE | CAP_TOKEN_PROOF or CAP_ERROR | A verifier challenges the holder to prove current possession of a token by signing a fresh nonce. |
| `0x0063` | CAP_TOKEN_PROOF | None | Success reply to CAP_TOKEN_CHALLENGE; carries the holder's proof over the challenge nonce. |

These four code points sit in the `0x0030`–`0x00FF` companion-extension band and are
scoped to the Capability channel; an implementation MUST NOT assign them to any
purpose other than the token-present and token-challenge operations defined here, and
MUST NOT treat token presentation or possession-proof as behavior defined by the core
specification alone (the core reserves the range; this companion defines it). The
token extension frames are OPTIONAL to implement; a responder that does not implement
them MUST reply CAP_ERROR with code `unknown_operation` (§8).

All thirteen frame types defined above lie within the Capability channel's own
frame-type namespace: nine in the application band at or above `0x0100`, and four in
the companion-extension band reserved for this channel. This document consumes no
frame-type code point outside the Capability channel's namespace and reserves none in
the core specification's cross-channel reserved ranges.

## 4. Frame payload encoding

### 4.1 Payload container

A Capability frame's payload (the octets after the core frame header and any
extension TLVs, and before the AEAD tag) is a single **deterministically encoded
CBOR** object as defined by the core specification §4.5 and §11.9 (deterministic
CBOR, RFC 8949). The payload MUST be a CBOR map whose keys are the unsigned integers
defined in §4.2 and §5–§8 for the relevant frame type. A sender MUST produce the
deterministic encoding (core specification §11.9): byte-identical output for
identical inputs, with the canonical key ordering and shortest-form integer encoding
RFC 8949 §4.2 requires, and definite-length maps and arrays.

A receiver MUST reject, with CAP_ERROR code `malformed_request` (§8), any Capability
frame whose payload is not a valid deterministic-CBOR map, whose payload omits a
REQUIRED key for its frame type, or whose payload carries a key of the wrong CBOR
major type.

Capability operation bodies are carried in the frame **payload**, not in extension
TLVs. This document defines and consumes no extension-TLV tag, and therefore claims
none of the TLV code points the core specification reserves.

### 4.2 Common envelope fields

Every Capability payload map carries the following two envelope fields. Integer keys
are given in parentheses.

| Field (key) | CBOR type | Meaning |
|---|---|---|
| `frame_kind` (0) | Unsigned int | MUST equal the frame's Capability frame type (one of `0x0060`–`0x0063` or `0x0100`–`0x0108`). A receiver MUST reject (CAP_ERROR, code `malformed_request`) a payload whose `frame_kind` contradicts the frame-header Frame Type. |
| `corr` (1) | Byte string (1–64 B) | Correlation token (§5). Present and non-empty on every `*_REQ`, on CAP_TOKEN_PRESENT and CAP_TOKEN_CHALLENGE, and on every frame that replies to one of those. |

The per-frame body fields defined in §5–§8 occupy keys `2` and above within the same
map; §6 and §7 give, per frame, the full field table.

### 4.3 Forward compatibility

A receiver MUST ignore an unrecognized integer key it encounters in a Capability
payload map whose key is **not negative**, so that a later revision of this document
MAY add fields without breaking a conformant receiver. A receiver MUST reject
(CAP_ERROR, code `malformed_request`) a payload that carries a **negative** integer
key it does not recognize, reserving the negative key space for forward-incompatible
additions. A receiver MUST NOT treat the mere presence of an unknown non-negative key
as an error, and MUST NOT alter its handling of the keys it does recognize because of
it.

## 5. Correlation and operation model

The core specification does not define how a Capability reply is correlated to its
request (unlike the Bridge channel, where NPAMP-BRIDGE §5 defines a correlation
identifier; Capability-channel interface reference, §4). This document supplies that
discipline, carrying the token **inside** the CBOR body rather than in a shared TLV,
because a native channel owns its whole body (§2).

### 5.1 Correlation discipline

* Every `*_REQ` frame (`0x0100`, `0x0102`, `0x0104`, `0x0106`) and each of
  CAP_TOKEN_PRESENT (`0x0060`) and CAP_TOKEN_CHALLENGE (`0x0062`) MUST carry a
  non-empty `corr` (§4.2) that is unique among the originating peer's outstanding
  Capability requests on the channel in that direction.
* Every CAP_*_RESULT, CAP_TOKEN_ACCEPT, CAP_TOKEN_PROOF, and CAP_ERROR MUST echo the
  originating request's `corr` verbatim.
* A receiver MUST match a reply to its request by `corr`, **not** by the
  per-(channel, direction) frame sequence number. Because the channel is
  Bidirectional and either peer may originate an operation, a sequence number within
  one direction does not identify the exchange across both directions.

### 5.2 Correlation lifetime

Every Capability operation defined here is a single-reply exchange: a `corr` value is
consumed when its `*_RESULT`, CAP_TOKEN_ACCEPT, CAP_TOKEN_PROOF, or CAP_ERROR is
delivered. The requester MUST treat that exchange as complete and MUST NOT reuse the
value for a new request while the original is outstanding. Pagination of a large
lookup (§6.4) is expressed as a **new** exchange with a fresh `corr` carrying the
prior result's `next_cursor`, not as additional replies to the original `corr`.

### 5.3 Side-effect class (`effect`)

Every state-mutating request — CAP_ISSUE_REQ, CAP_DELEGATE_REQ, CAP_REVOKE_REQ, and
CAP_TOKEN_PRESENT — MUST carry an `effect` field (§6, §7) declaring the most severe
side effect the operation may cause, drawn from the side-effect classes below. It is
the native-body analogue of a Bridge SafetyLabel, carried in-body because the
Capability channel owns its body (§2).

| Value | Name | Meaning |
|---|---|---|
| `0x00` | read_only | No state change (lookup and challenge requests). |
| `0x01` | idempotent_write | A write whose repetition yields the same state (for example a token presentation). |
| `0x02` | non_idempotent_write | A write that is not safely repeatable (for example an issuance or a delegation). |
| `0x03` | destructive | An operation that withdraws state (a revocation). |

**Fail-safe.** A receiver MUST treat a state-mutating request that omits `effect`, or
carries an `effect` value it does not recognize, as `destructive`, and MAY refuse it
(CAP_ERROR). A requester MUST NOT rely on a mutating request that omits `effect`
being executed. A read-only request (CAP_LOOKUP_REQ, CAP_TOKEN_CHALLENGE) carries
`effect` = `read_only`.

## 6. Operation bodies

Each operation body is a deterministic-CBOR map carrying the common envelope (§4.2,
keys `0`–`1`) and the per-frame fields below at keys `2`+. Unless a field is marked
required, it is OPTIONAL and, when absent, carries no value (a producer omits the key
rather than encoding a null placeholder; a producer that does encode an explicit CBOR
`null` for an absent OPTIONAL field is equivalent to omitting it).

### 6.1 CAP_ISSUE_REQ (`0x0100`) / CAP_ISSUE_RESULT (`0x0101`)

Grant a new authority to a peer.

**CAP_ISSUE_REQ body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `subject` (2) | Text string | Yes | The holder the capability is granted to — an opaque holder identifier within the responder's namespace. |
| `authority` (3) | Text string | Yes | An opaque identifier of the authority/right being granted (the capability's scope). |
| `constraints` (4) | Map | No | Caveats or attenuations scoping the authority (for example a resource or time constraint map). Keys are a local matter; the responder MUST persist it with the capability so the constraint survives. |
| `not_before` (5) | Text string | No | RFC 3339 timestamp before which the capability is not valid. |
| `not_after` (6) | Text string | No | RFC 3339 timestamp after which the capability expires. |
| `max_delegation_depth` (7) | Unsigned int | No | The number of further delegations permitted from this capability. Absent means the responder's default; `0` means the capability is not delegable. |
| `idempotency_key` (8) | Text string | No | A caller-supplied key that lets the responder de-duplicate a retried issuance. When absent, the responder MAY derive one from the request. |
| `effect` (9) | Unsigned int | Yes | Side-effect class (§5.3). An issuance is normally `0x02` non_idempotent_write. |

**CAP_ISSUE_RESULT body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `token` (2) | Map (a `capability_token`, §6.5) | Yes | The issued capability with its identity, scope, and any signature the responder attaches. |
| `status` (3) | Text string | Yes | A short accepted-state token for the issuance (for example `issued`). |

An issuance that the responder holds for human approval, rather than executing, is
NOT reported as a CAP_ISSUE_RESULT; it is reported as CAP_ERROR with code
`approval_required` (§8). A responder MUST NOT emit a CAP_ISSUE_RESULT for a
capability that was not created.

### 6.2 CAP_DELEGATE_REQ (`0x0102`) / CAP_DELEGATE_RESULT (`0x0103`)

Convey a held capability onward to another peer. The core specification does not
define whether delegation may attenuate an authority (Capability-channel interface
reference, §4); this document defines that delegation MAY attenuate and MUST NOT
amplify.

**CAP_DELEGATE_REQ body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `token_id` (2) | Text string | Yes | The held capability being delegated onward. |
| `subject` (3) | Text string | Yes | The new holder receiving the delegated authority. |
| `constraints` (4) | Map | No | Additional attenuating caveats applied to the child capability. A delegation MUST NOT grant an authority broader than the parent conveys; a responder MUST reject an amplifying delegation with CAP_ERROR `policy_denied`. |
| `not_after` (5) | Text string | No | RFC 3339 expiry of the child capability. It MUST NOT exceed the parent's `not_after`; a responder MUST reject a later value with CAP_ERROR `policy_denied`. |
| `max_delegation_depth` (6) | Unsigned int | No | Remaining delegation depth granted to the child. It MUST be strictly less than the parent's remaining depth; a responder MUST reject a value that does not attenuate the depth with CAP_ERROR `not_delegable`. |
| `effect` (7) | Unsigned int | Yes | Side-effect class (§5.3); a delegation is normally `0x02` non_idempotent_write. |

**CAP_DELEGATE_RESULT body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `token` (2) | Map (a `capability_token`, §6.5) | Yes | The delegated child capability, carrying `parent_id` set to the delegated-from capability (§6.5). |
| `status` (3) | Text string | Yes | A short accepted-state token (for example `delegated`). |

A delegation of a capability whose remaining delegation depth is `0`, or that is
revoked or expired, is reported as CAP_ERROR — `not_delegable` when depth is
exhausted, `revoked` when the parent is no longer valid (§8) — never as a
CAP_DELEGATE_RESULT.

### 6.3 CAP_REVOKE_REQ (`0x0104`) / CAP_REVOKE_RESULT (`0x0105`)

Withdraw a previously issued or delegated capability. The core specification does not
define how a revocation propagates (Capability-channel interface reference, §4); this
document defines an OPTIONAL `cascade` request.

**CAP_REVOKE_REQ body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `token_id` (2) | Text string | Yes | The capability to revoke. |
| `cascade` (3) | Boolean | No | When true, requests transitive revocation of every capability delegated (directly or transitively) from `token_id`. Absent means false: revoke only the named capability. A responder that does not support cascading revocation MUST reject a `cascade` of true with CAP_ERROR `unknown_operation` rather than silently revoke only the root. |
| `reason` (4) | Text string | No | An advisory reason for the revocation. |
| `effect` (5) | Unsigned int | Yes | Side-effect class (§5.3); a revocation MUST be `0x03` destructive. |

**CAP_REVOKE_RESULT body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `token_id` (2) | Text string | Yes | The revoked capability. |
| `status` (3) | Text string | Yes | A short accepted-state token (for example `revoked`). |
| `revoked_count` (4) | Unsigned int | No | The number of capabilities revoked by this operation; greater than `1` when a `cascade` removed descendants. |

A revocation of an absent capability is reported as CAP_ERROR `not_found` (§8).
Revocation is idempotent at the level of the named capability: a re-revocation of an
already-revoked capability MAY succeed with `status` `revoked` and `revoked_count` `0`.

### 6.4 CAP_LOOKUP_REQ (`0x0106`) / CAP_LOOKUP_RESULT (`0x0107`)

Resolve or query a capability. The core specification does not define what a lookup
returns (Capability-channel interface reference, §4); this document defines a bounded,
cursor-paginated result of `capability_token` projections.

**CAP_LOOKUP_REQ body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `token_id` (2) | Text string | No | Resolve a single capability by identity. |
| `subject` (3) | Text string | No | Restrict to capabilities held by this subject. |
| `authority` (4) | Text string | No | Restrict to capabilities granting this authority. |
| `include_revoked` (5) | Boolean | No | When true, include revoked or expired capabilities in the result. Absent means false: return only currently-valid capabilities. |
| `limit` (6) | Unsigned int | No | Maximum capabilities to return. Absent or `0` means the responder's default page size. |
| `cursor` (7) | Byte string | No | An opaque continuation token from a prior result's `next_cursor`, requesting the next page. |
| `effect` (8) | Unsigned int | Yes | Side-effect class (§5.3); MUST be `0x00` read_only. |

Scoping fields (`token_id`, `subject`, `authority`) are conjunctive: a capability is
returned only if it satisfies every present filter. A lookup with no scoping field
present requests every capability the responder's disclosure policy permits (§9). A
responder MUST NOT silently ignore a scoping field it does not support and return an
over-broad result; if it cannot honor a present filter it MUST reply CAP_ERROR
`malformed_request` rather than mislead the requester.

**CAP_LOOKUP_RESULT body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `capabilities` (2) | Array of `capability_token` (§6.5) | Yes | The matching capabilities (possibly empty). |
| `has_more` (3) | Boolean | Yes | True if more capabilities match than are carried here. |
| `next_cursor` (4) | Byte string | No | Present when `has_more` is true: an opaque token a requester echoes as `cursor` in a new CAP_LOOKUP_REQ (§6.4) to fetch the next page. |

### 6.5 The `capability_token` wire projection

A `capability_token` is the wire projection of one capability an authority issues,
delegates, or resolves. It is the value carried by CAP_ISSUE_RESULT, CAP_DELEGATE_RESULT,
CAP_LOOKUP_RESULT, and CAP_TOKEN_PRESENT (§7).

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `token_id` (0) | Text string | Yes | Identity of the capability. |
| `issuer` (1) | Text string | Yes | The granting authority. |
| `subject` (2) | Text string | Yes | The holder the authority is granted to. |
| `authority` (3) | Text string | Yes | The right or scope the capability conveys. |
| `constraints` (4) | Map | No | The caveats or attenuations scoping the authority. |
| `not_before` (5) | Text string | No | RFC 3339 start of validity. |
| `not_after` (6) | Text string | No | RFC 3339 expiry. |
| `parent_id` (7) | Text string | No | The capability this was delegated from; absent for a root issuance. |
| `delegation_depth` (8) | Unsigned int | No | Distance from the root capability (`0` = root). |
| `max_delegation_depth` (9) | Unsigned int | No | Remaining further delegations this capability permits. |
| `status` (10) | Text string | No | Current status (for example `active`, `revoked`, `expired`). |
| `signature` (11) | Text string | No | A signature over the token's signable envelope, hex-encoded. The core specification names capability tokens among its Ed25519 signature usages (§1.2); this document does not fix the signable-byte construction. |
| `signing_key_id` (12) | Text string | No | Identifier of the key that produced `signature`. |
| `signature_alg` (13) | Text string | No | The signature algorithm identifier. |

A lookup or delegation result MUST carry, for each capability, the provenance the
responder holds (`issuer`, `subject`, `not_after`, `parent_id`, and any signature
fields present): a result MUST NOT strip provenance that the authority associates with
the capability. Any of the OPTIONAL fields above MAY be absent when the responder
holds no value for it.

## 7. Capability token extension frames

The reserved `0x0060`–`0x0063` band (§3.3) carries two OPTIONAL token-handling
exchanges. Each request carries the common envelope (§4.2) plus the fields below; each
reply echoes the request's `corr` (§5). A responder that does not implement these
frames replies CAP_ERROR `unknown_operation`.

### 7.1 CAP_TOKEN_PRESENT (`0x0060`) / CAP_TOKEN_ACCEPT (`0x0061`)

A holder presents a capability it possesses to the peer — for example to pre-register
authority for subsequent operations — out of band from a specific issuance or lookup.

**CAP_TOKEN_PRESENT body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `token` (2) | Map (a `capability_token`, §6.5) | Yes | The capability the holder presents. |
| `chain` (3) | Array of `capability_token` (§6.5) | No | The delegation chain from a root capability to `token`, ordered root-first, letting the peer verify the delegation path. |
| `effect` (4) | Unsigned int | Yes | Side-effect class (§5.3); a presentation is `0x01` idempotent_write (re-presenting the same token is a no-op at the peer). |

**CAP_TOKEN_ACCEPT body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `token_id` (2) | Text string | Yes | The identity of the accepted capability. |
| `status` (3) | Text string | Yes | A short accepted-state token (for example `accepted`). |

A presented token the peer cannot verify — a malformed token, a broken chain, or a
failed signature — is reported as CAP_ERROR `token_invalid` (§8), not as a
CAP_TOKEN_ACCEPT.

### 7.2 CAP_TOKEN_CHALLENGE (`0x0062`) / CAP_TOKEN_PROOF (`0x0063`)

A verifier challenges a holder to prove current possession of a capability by signing
a fresh nonce, distinguishing a presented token from a replayed one.

**CAP_TOKEN_CHALLENGE body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `token_id` (2) | Text string | Yes | The capability whose possession is challenged. |
| `nonce` (3) | Byte string (16–64 B) | Yes | A fresh, unpredictable challenge nonce the holder must prove over. A verifier MUST NOT reuse a nonce across challenges. |
| `effect` (4) | Unsigned int | Yes | Side-effect class (§5.3); MUST be `0x00` read_only. |

**CAP_TOKEN_PROOF body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `token_id` (2) | Text string | Yes | The capability the proof is for. |
| `proof` (3) | Byte string | Yes | The holder's proof of possession over the challenge `nonce`, hex- or byte-encoded per the signature scheme bound to the token. The exact proof construction is deferred (§1.2). |

A challenge for an absent capability is reported as CAP_ERROR `not_found`; a proof
that fails verification is reported by the verifier as CAP_ERROR `token_invalid` (§8).

## 8. Error model

Every failure of a Capability request is reported in a single CAP_ERROR (`0x0108`)
frame — the Capability channel has no foreign protocol, so all errors are native and
carried in one structured frame. A CAP_ERROR echoes the failed request's `corr` and
carries:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `code` (2) | Unsigned int | Yes | One of the Capability error codes below. |
| `message` (3) | Text string | Yes | A peer-safe, generic human-readable message for `code`. It MUST NOT carry internal detail (§8.2). |
| `retry_after_s` (4) | Unsigned int | No | When present, the number of seconds after which the requester MAY retry. |
| `approval_id` (5) | Text string | No | Present if and only if `code` is `approval_required`: an identifier of the held-for-approval operation (§8.1). |

| Code | Name | Meaning |
|---|---|---|
| 1 | malformed_request | The CBOR body is not valid deterministic CBOR, omits a REQUIRED field, uses a wrong CBOR major type, carries an unknown negative key (§4.3), or names a scoping filter the responder cannot honor (§6.4). |
| 2 | unknown_operation | The frame type is not a Capability operation the responder implements (for example an OPTIONAL token extension frame, or a `cascade` revocation, at a responder that does not support it). |
| 3 | policy_denied | The operation was refused by the responder's governance or policy — a definitive denial (including an amplifying delegation, §6.2). |
| 4 | approval_required | The operation was escalated for human approval and was **NOT executed** (§8.1). Carries `approval_id`. |
| 5 | not_found | An identified capability (the delegate, revoke, lookup, or challenge target) does not exist. |
| 6 | not_delegable | The capability may not be delegated: its remaining delegation depth is `0`, or the requested child depth does not attenuate the parent (§6.2). |
| 7 | revoked | The referenced capability is revoked or expired and cannot be delegated or proven (§6.2, §7.2). |
| 8 | token_invalid | A presented token or a possession proof failed verification — a malformed token, a broken delegation chain, or a failed signature (§7). |
| 9 | internal_error | A responder or pipeline failure the responder cannot attribute to the request. Generic; no internal detail crosses the wire. |

### 8.1 Governance escalation is a distinct, non-success outcome

A `policy_denied` (code 3) and an `approval_required` (code 4) are different results
and MUST NOT be conflated. `policy_denied` is a definitive refusal: the operation will
not proceed. `approval_required` means the operation has been **held for human
approval and has NOT been executed** — it is neither a success nor a definitive
denial, but a pending decision.

An implementation MUST report a governance escalation as CAP_ERROR with code
`approval_required`, carrying `approval_id`, and MUST NOT report it as a
CAP_ISSUE_RESULT, CAP_DELEGATE_RESULT, CAP_REVOKE_RESULT, or any other `*_RESULT`. A
held-for-approval issuance or delegation MUST NOT be presented to the requester as a
completed grant: an authority that was not created is never a success frame. A
requester MUST treat `approval_required` as an operation that has not yet taken
effect, distinct from both a success and a `policy_denied`.

### 8.2 No internal detail on the wire

The `message` field MUST be the generic, peer-safe string for its `code`. The full
internal cause of a failure MUST be handled locally (for example logged by the
responder) and MUST NOT cross the wire: a CAP_ERROR MUST NOT carry authority
internals, policy topology, configuration or source names, decoder diagnostics, or
any other detail beyond the code and its generic message. This leak-prevention
requirement is normative for interoperability, not merely local hygiene: a requester
MUST be able to rely on the error surface exposing only a code, a generic message, and
the OPTIONAL `retry_after_s` / `approval_id` fields.

## 9. Security and privacy considerations

This section supplements the core specification's Security Considerations; it does not
restate them.

Every Capability frame is AEAD-protected like all N-PAMP frames and is carried under
the association's existing authentication (the core specification's handshake binds
both peer identities into the transcript and the Finished MAC). A responder therefore
knows that an operation was requested by the authenticated peer, but authentication is
not authorization: a responder MUST enforce its own governance and access policy on
every issuance, delegation, revocation, and lookup regardless of the peer's identity,
and MUST report the outcome per §8 — including preserving the `approval_required` /
`policy_denied` distinction. In particular, a responder MUST NOT let a peer issue,
delegate, revoke, or resolve a capability the peer is not authorized to act on merely
because it holds an authenticated association.

A lookup result exposes capabilities and their provenance — issuer, subject, and any
signature material — to the requesting peer. A responder SHOULD return only the
capabilities appropriate to the authenticated peer and local policy, MAY return a
filtered or empty result to a peer it does not wish to inform, and SHOULD treat the
holder and authority a capability names as sensitive. Because a capability conveys an
authority, an implementation SHOULD treat the resolvable set as sensitive and scope it
per peer.

Delegation and possession-proof are the security-critical operations of this channel.
A responder MUST NOT let a delegation amplify the authority its parent conveys or
outlive the parent's `not_after` (§6.2), and a verifier that relies on a token
possession proof MUST require a fresh, unpredictable, non-reused `nonce` (§7.2) so a
recorded proof cannot be replayed. A responder MUST bound the resources a remote peer
can consume through Capability operations: the size of a lookup result it will
assemble, the rate of requests it will accept, and the depth of a delegation chain it
will verify. A responder MAY reply CAP_ERROR (with `retry_after_s`, or by paginating a
large lookup via `next_cursor`) rather than allocate without limit. Because either
peer may originate operations on this Bidirectional channel, both directions are
subject to these limits.

The error surface MUST NOT leak internal detail (§8.2); a CAP_ERROR that carried
authority internals, policy topology, or configuration names would disclose the
responder's internal structure to the peer and is a conformance violation (§10).

## 10. Conformance

An implementation conforms to NPAMP-CAP if and only if it rests on a core-conformant
N-PAMP wire implementation and, on the Capability channel `0x0002`, it:

1. Treats `0x0002` as the Capability channel with the core registry identity (name
   Capability; purpose capability issuance, delegation, revocation, lookup; direction
   Bidirectional; minimum profile Standard), does not repurpose the channel
   identifier, enables it only at the **Standard** profile or higher, treats it as
   available at Standard, High, and Sovereign, and drops any frame received on an
   unadvertised Capability channel (§2);

2. Uses only the Capability frame types defined in §3 — the application-band operation
   frames `0x0100`–`0x0108` and the token extension frames `0x0060`–`0x0063` —
   preserves the core meaning of the reserved all-channel frame types
   `0x0000`–`0x000A`, and assigns `0x0060`–`0x0063` to no purpose other than the
   token-present and token-challenge operations of §7 (§3);

3. Encodes every operation body as a deterministic-CBOR map (§4.1) with the integer
   keys of §4.2 and §5–§8; rejects a non-deterministically-encoded body, a body
   missing a REQUIRED field, a body with a wrong CBOR major type, a `frame_kind` that
   contradicts the frame header, or a body carrying an unknown negative key with
   CAP_ERROR `malformed_request`; and ignores an unknown non-negative key without
   altering its handling of recognized keys (§4.2, §4.3);

4. Carries a non-empty `corr` on every `*_REQ` and on CAP_TOKEN_PRESENT /
   CAP_TOKEN_CHALLENGE, echoes it verbatim on every reply, and matches replies to
   requests by `corr` rather than by frame sequence number (§5);

5. Carries an `effect` on every state-mutating request and treats a missing or unknown
   `effect` on a mutating operation as `destructive` (§5.3 fail-safe);

6. Reports every failure as CAP_ERROR (`0x0108`) with a code from §8 and a peer-safe
   `message`, never leaking internal cause (§8.2); reports a governance escalation as
   `approval_required` carrying `approval_id`, distinct from `policy_denied`; and never
   reports a success `*_RESULT` for an operation that did not take effect (a
   held-for-approval issuance or delegation is `approval_required`, not a `*_RESULT`)
   (§6.1, §8.1);

7. Enforces the delegation invariants — a delegated capability MUST NOT amplify the
   authority its parent conveys, MUST NOT outlive the parent's `not_after`, and MUST
   attenuate the remaining delegation depth — rejecting a violating delegation with
   `policy_denied` or `not_delegable`, and preserves each capability's provenance
   (`issuer`, `subject`, `parent_id`, and any signature fields the responder holds)
   verbatim in results (§6.2, §6.5); and

8. For the OPTIONAL token extension frames, either implements the present/accept and
   challenge/proof exchanges of §7 — requiring a fresh, non-reused `nonce` on a
   challenge and reporting a failed proof or an unverifiable token as `token_invalid`
   — or replies CAP_ERROR `unknown_operation` and honors no frame in `0x0060`–`0x0063`
   as a defined operation (§3.3, §7).

A conformance test suite SHOULD assert each clause above with a recorded exchange on
the Capability channel: a CAP_ISSUE_REQ / CAP_ISSUE_RESULT pair whose result carries a
`capability_token` with its provenance; a CAP_DELEGATE_REQ that attenuates a parent and
a distinct one rejected for amplifying it; a CAP_REVOKE_REQ / CAP_REVOKE_RESULT pair; a
CAP_LOOKUP_REQ / CAP_LOOKUP_RESULT pair paginated by `next_cursor`; a CAP_ERROR provoked
for `policy_denied` and, distinctly, one for `approval_required` carrying an
`approval_id`; a CAP_TOKEN_CHALLENGE / CAP_TOKEN_PROOF exchange over a fresh nonce and a
replayed proof rejected as `token_invalid`; and a rejected malformed body (a
non-deterministic encoding, a missing REQUIRED field, and an unknown negative key), each
yielding `malformed_request`.

A machine-gradable conformance-vector group for this companion does not yet exist in
the corpus; conformance to the clauses above is therefore established by a recorded
live exchange on the Capability channel, and a conformance claim for these clauses MAY
NOT present them as graded against a pinned vector corpus. When a Capability
payload-decode vector group is added — produced by an independent RFC 8949 byte
constructor, not by the reference implementation it grades — the §4.1 / §4.2 / §4.3
payload-encoding and common-envelope MUST-reject clauses become the graded surface, and
a claim of conformance to those clauses MAY then name the corpus SHA-256 it was graded
against; the §5–§9 behavioural clauses remain graded only by a live-exchange harness.
