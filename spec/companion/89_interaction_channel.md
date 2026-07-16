# NPAMP-INTERACT — Interaction-Channel Operation Framework (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words MUST, MUST NOT,
> REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL
> are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only
> when, they appear in all capitals, as shown here. This document defines a
> **native** operation framing for the N-PAMP **Interaction channel `0x000F`**: the
> frame types, the deterministic-CBOR operation bodies, the in-body correlation
> discipline, the operation and outcome model, and the structured error model by
> which one peer conveys user-interface events to, prompts, and seeks the approval
> of a human party attached to another peer. It builds on the core specification
> (draft-bubblefish-npamp-01) and does not redefine it. Unlike a Bridge carriage
> class, the Interaction channel carries no foreign protocol: the operation body
> **is** N-PAMP's own encoding, so this document consumes no extension-TLV code
> point. It introduces no change to the core wire format.
>
> This document is **graded on its payload surface** in the sense of NPAMP-CONFORM
> (`55_conformance_requirements.md`): its `interaction.body.decode`
> payload-encoding and common-envelope MUST-reject surface is graded by
> `npamp-conform` against an independent RFC 8949 byte constructor
> (`test-vectors/gen/interaction_oracle.py`, non-circular), cross-validated by the
> reference implementation (`impl/go/zz_interaction_oracle_xval_test.go`), with its
> vectors merged into the conformance corpus. Its remaining behavioural clauses
> (flow, correlation state, the approval-hold distinction, and leak prevention) are
> graded only by a live-exchange harness once one exists (§10).

## 1. Scope

### 1.1 In scope

This document specifies, over the Interaction channel `0x000F` of the N-PAMP core
specification (the "core specification", draft-bubblefish-npamp-01):

1. A set of Interaction-channel frame types, drawn entirely from the
   channel-specific application band that begins at `0x0100` (core specification
   §4.6, frame-type namespace) — the Interaction channel has **no** core-reserved
   companion-extension range of its own (§3.3), so every frame this document
   defines lives in the `0x0100`+ band;
2. Per-operation request and result frame pairs realizing the three operation
   classes named by the channel's registry purpose — **agent-to-human
   user-interface events**, **prompts** for human input, and **approval-required
   holds** — plus a withdrawal (cancel) frame and a single structured error frame;
3. The **deterministic-CBOR** encoding of every operation body (RFC 8949, core
   specification §4.5 and §11.9), keyed by unsigned integers;
4. An **in-body correlation** discipline that matches a reply, an acknowledgement,
   or a withdrawal to its request by a correlation token carried inside the CBOR
   body — consuming no shared TLV tag; and
5. A single structured **error frame** whose result set preserves an
   **approval-held** escalation (an action parked for a human decision and NOT
   authorized) as a distinct, non-success outcome, separate both from a completed
   human denial and from an automated policy denial.

Operations are described generically — surface a user-interface event, prompt a
human for input, request a human's approval of an action, and withdraw an
outstanding request — so that any interaction endpoint and any agent interoperate
over N-PAMP with no bespoke adaptation. The document names no product, no vendor,
and no application-specific user-interface schema.

### 1.2 Not in scope

This document does NOT:

* **Define a user-interface toolkit, widget set, layout, or rendering model.** The
  `event_class` (§6.1) and `prompt_kind` (§6.2) enumerations classify the *kind* of
  interaction on the wire; how a client renders, styles, positions, or animates a
  surface is a local matter this document does not constrain.
* **Define the internal schema of an event body, form, or decision context.** The
  nested `body`, `schema`, and `context` maps (§6) are opaque application payloads
  this framing carries and forward-compat-guards (§4.3); their inner field
  semantics are an application matter, not an interoperability contract fixed here.
* **Define authorization, governance, or admission policy.** Whether a human is
  presented an interaction, whether an action is approved, denied, or parked for a
  later human decision is the responder's local decision; this document defines
  only how each of those outcomes is *reported* on the wire (§6.3, §7, §8), not the
  policy or user experience that produces them.
* **Carry a foreign agent protocol.** The Interaction channel is native; it is not
  a Bridge carriage class and does not build on NPAMP-BRIDGE (Interaction-channel
  interface reference, `../channels/000F_interaction.md`). No frame in this document
  encapsulates a foreign message, and this document defines and consumes no
  extension-TLV tag. In particular, this document is **distinct** from the AG-UI
  mapping NPAMP-MAP-AGUI (`64_map_agui.md`), which carries the *foreign* Agent-User
  Interaction Protocol under NPAMP-CC-STREAM; the two MUST NOT be conflated (§2).
* **Redefine the Interaction channel's public interface reference.** The
  registry-level public interface of the channel is restated by
  `../channels/000F_interaction.md`; this document is the concrete native operation
  encoding that reference explicitly defers to a future companion. It adds native
  operation semantics only within the `0x0100`+ code points the core specification
  leaves available, and introduces no behavior the core does not reserve.
* **Change the core wire format.** It alters no field of the core frame header, no
  reserved all-channel frame type, the extension-TLV encoding, or any code point
  the core specification assigns; it uses only code points in the Interaction
  channel's own application band.

## 2. Relationship to the core specification

The Interaction channel `0x000F` is registered by the core specification with
purpose **"Agent-to-human user-interface events"**, minimum profile **Standard**,
and direction **Bidirectional** (core specification §5, Core Channel Registry;
machine-readable form `../../registries/channels.csv`; restated by
`../channels/000F_interaction.md` §2). Under the core specification's channel
architecture every channel is full-duplex: each peer maintains an independent
per-direction sequence space and independent per-direction traffic keys, so both
peers MAY transmit on the channel simultaneously — an agent surfacing
user-interface events toward the human's client while the human's client returns
interaction events toward the agent. Either peer MAY originate an Interaction
operation.

**Not Multi-stream.** Unlike the Memory channel `0x0001` and the Stream channel
`0x000C`, the Interaction channel is **not** classified Multi-stream: it does not
open multiple concurrent transport sub-streams within a stream family
(`../channels/000F_interaction.md` §2). Concurrent outstanding interactions (for
example two prompts awaiting answers) are therefore multiplexed on the single
bidirectional stream and disambiguated by the in-body correlation token (§5), not
by distinct transport sub-streams.

**Minimum-profile gate.** A peer MUST enable the Interaction channel only at the
**Standard** profile or higher; once Standard is met the channel is available at
Standard, High, and Sovereign, and there is no profile at which it becomes
unavailable. A peer that has not advertised the Interaction channel during the
handshake (core specification §5) MUST NOT receive frames on it; a frame arriving
on an unadvertised Interaction channel MUST be dropped and MUST NOT be delivered
to an interaction consumer.

**Native, not a carriage class — and distinct from AG-UI over Bridge.** A Bridge
carriage class carries a *foreign* protocol's message octet-for-octet and wraps
routing and correlation metadata *around* it in a shared extension TLV (the
BridgeEnvelope TLV, `10_bridge_framework.md`). The Interaction channel has no
foreign protocol: the operation body is N-PAMP's own deterministic-CBOR encoding,
and this document owns that body in full. Consequently the correlation token, the
operation semantics, and the error object all live **inside** the CBOR body, and
this document reserves and consumes **no extension-TLV code point**. This is the
deliberate structural difference from NPAMP-BRIDGE, and it is why an Interaction
operation is routed by its N-PAMP **frame type** (§3) rather than by any
method-name or event-name field parsed from a body. A deployment MAY still carry
the foreign AG-UI protocol on this channel by deployment choice, but it does so
under NPAMP-BRIDGE / NPAMP-CC-STREAM framing and the NPAMP-MAP-AGUI mapping
(`64_map_agui.md`), **not** under the native frames of this document; the native
`INTERACT_*` frames defined here are not AG-UI events, carry no BridgeEnvelope TLV,
and MUST NOT be treated as a foreign-protocol carriage.

**Frame-type namespace bands.** The core specification partitions each channel's
`0x0000`–`0xFFFF` frame-type space into four bands (core specification §4.6,
Frame-Type Namespace): `0x0000`–`0x000A` reserved all-channel frame types with the
same meaning on every channel; `0x000B`–`0x002F` unassigned, reserved to the core
for future all-channel additions; `0x0030`–`0x00FF` the **companion-extension
band**, per-channel extension frame types defined by companion specifications; and
`0x0100`–`0xFFFF` **channel-specific application** frame types. The core
specification's Reserved Frame-Type Ranges table (core specification §8.1;
`../09_extension_points.md`) assigns **no** companion-extension range to the
Interaction channel. This document therefore places **all** of its operational
frames in the application band at `0x0100`+ on the Interaction channel, exactly as
the Telemetry-family native companions do, and defines no frame in the
companion-extension band. Because the frame-type space is scoped by the Channel ID
header field, these code points do not collide with any other channel's
assignments at the same numeric values.

## 3. Interaction-channel frame types

Within the Interaction channel (`0x000F`) frame-type namespace, this specification
defines eight frame types, all in the channel-specific application band at
`0x0100`+.

### 3.1 Application-band operation frames (`0x0100`+)

| Type | Name | Reply | Purpose |
|---|---|---|---|
| `0x0100` | INTERACT_EVENT | INTERACT_EVENT_ACK (only when `ack` is set) or INTERACT_ERROR | Convey a user-interface event to the peer: an agent surfacing an event to the human's client, or the human's client returning an interaction event to the agent. |
| `0x0101` | INTERACT_EVENT_ACK | None | Acknowledges an INTERACT_EVENT that requested acknowledgement; echoes the request's correlation token. |
| `0x0102` | INTERACT_PROMPT_REQ | INTERACT_PROMPT_RESULT or INTERACT_ERROR | Prompt the human for input and await the human's response. |
| `0x0103` | INTERACT_PROMPT_RESULT | None | The human's response to a prompt; echoes the correlation token. |
| `0x0104` | INTERACT_APPROVAL_REQ | INTERACT_APPROVAL_RESULT or INTERACT_ERROR | Request a human decision to approve or deny a described action. |
| `0x0105` | INTERACT_APPROVAL_RESULT | None | The human's completed decision (granted or denied); echoes the correlation token. |
| `0x0106` | INTERACT_CANCEL | None | Withdraw an outstanding prompt or approval request, by its correlation token. |
| `0x0107` | INTERACT_ERROR | None | Structured failure or hold for any request; echoes the correlation token and carries an Interaction error code (§8), including the approval-held non-success outcome. |

A `*_REQ` frame originates a request/reply operation; the corresponding `*_RESULT`
frame, or an INTERACT_ERROR (`0x0107`), replies to it. An INTERACT_EVENT is a
notification: it is answered by an INTERACT_EVENT_ACK **only** when it set its
`ack` flag (§6.1), and otherwise expects no reply. A `*_RESULT`, an
INTERACT_EVENT_ACK, and an INTERACT_ERROR are never sent unsolicited: each MUST
echo the correlation token of the frame it answers (§5). A responder MUST NOT emit
both a `*_RESULT` and an INTERACT_ERROR for the same request.

### 3.2 Reserved all-channel frame types

The reserved all-channel frame types (PING `0x0001`, PONG `0x0002`, CLOSE
`0x0003`, CLOSE_ACK `0x0004`, ERROR `0x0005`, KEY_UPDATE `0x0006`,
KEY_UPDATE_ACK `0x0007`, PATH_CHALLENGE `0x0008`, PATH_RESPONSE `0x0009`, and
FLOW_UPDATE `0x000A`; core specification §4.6) retain their core meaning on the
Interaction channel. An implementation MUST NOT reuse them for Interaction
application traffic and MUST NOT define Interaction operation semantics in the
reserved all-channel range `0x0000`–`0x000A`. (`0x0000` is reserved and MUST NOT be
used as a frame type.)

### 3.3 No reserved companion-extension band for this channel

The core specification's Reserved Frame-Type Ranges table (core specification §8.1;
`../09_extension_points.md`) reserves companion-extension sub-`0x0100` ranges for
the Memory, Capability, Control, Audit, Settlement/Audit, Governance, and Immune
channels only. **No** such range is reserved for the Interaction channel
(`../channels/000F_interaction.md` §3.2). This document therefore defines **no**
frame in the companion-extension band `0x0030`–`0x00FF`, assigns no
Interaction-specific meaning to any code point the core specification reserves for
another channel, and places every one of its eight frame types in the Interaction
channel's own application band at or above `0x0100`. This document consumes no
frame-type code point outside the Interaction channel's namespace and reserves none
in the core specification's cross-channel reserved ranges.

## 4. Frame payload encoding

### 4.1 Payload container

An Interaction frame's payload (the octets after the core frame header and any
extension TLVs, and before the AEAD tag) is a single **deterministically encoded
CBOR** object as defined by the core specification §4.5 and §11.9 (deterministic
CBOR, RFC 8949). The payload MUST be a CBOR map whose keys are the unsigned
integers defined in §4.2 and §5–§8 for the relevant frame type. A sender MUST
produce the deterministic encoding (core specification §11.9): byte-identical
output for identical inputs, with the canonical key ordering and shortest-form
integer encoding RFC 8949 §4.2 requires, and definite-length maps and arrays.

A receiver MUST reject, with INTERACT_ERROR code `malformed_request` (§8), any
Interaction frame whose payload is not a valid deterministic-CBOR map, whose
payload omits a REQUIRED key for its frame type, or whose payload carries a key of
the wrong CBOR major type.

Interaction operation bodies are carried in the frame **payload**, not in extension
TLVs. This document defines and consumes no extension-TLV tag, and therefore claims
none of the TLV code points the core specification reserves.

### 4.2 Common envelope fields

Every Interaction payload map carries the following two envelope fields. Integer
keys are given in parentheses.

| Field (key) | CBOR type | Meaning |
|---|---|---|
| `frame_kind` (0) | Unsigned int | MUST equal the frame's Interaction frame type (one of `0x0100`–`0x0107`). A receiver MUST reject (INTERACT_ERROR, code `malformed_request`) a payload whose `frame_kind` contradicts the frame-header Frame Type. |
| `corr` (1) | Byte string (1–64 B) | Correlation token (§5). Present and non-empty on every frame this document defines: on every `*_REQ`, on every INTERACT_EVENT, and on every frame that replies to, acknowledges, or withdraws one of those. |

The per-frame body fields defined in §5–§8 occupy keys `2` and above within the
same map; §6 gives, per frame, the full field table.

### 4.3 Forward compatibility

A receiver MUST ignore an unrecognized integer key it encounters in an Interaction
payload map whose key is **not negative**, so that a later revision of this document
MAY add fields without breaking a conformant receiver. A receiver MUST reject
(INTERACT_ERROR, code `malformed_request`) a payload that carries a **negative**
integer key it does not recognize, reserving the negative key space for
forward-incompatible additions. A receiver MUST NOT treat the mere presence of an
unknown non-negative key as an error, and MUST NOT alter its handling of the keys
it does recognize because of it. This same rule applies to every nested `body`,
`schema`, and `context` map (§6).

## 5. Correlation and operation model

The core specification does not define how an Interaction reply is correlated to
its request (unlike the Bridge channel, where NPAMP-BRIDGE §5 defines a correlation
identifier; `../channels/000F_interaction.md` §4). This document supplies that
discipline, carrying the token **inside** the CBOR body rather than in a shared
TLV, because a native channel owns its whole body (§2).

### 5.1 Correlation discipline

* Every INTERACT_PROMPT_REQ (`0x0102`), every INTERACT_APPROVAL_REQ (`0x0104`), and
  every INTERACT_EVENT (`0x0100`) MUST carry a non-empty `corr` (§4.2) that is
  unique among the originating peer's outstanding Interaction requests on the
  channel in that direction.
* Every INTERACT_PROMPT_RESULT, every INTERACT_APPROVAL_RESULT, every
  INTERACT_EVENT_ACK, and every INTERACT_ERROR MUST echo the originating frame's
  `corr` verbatim.
* An INTERACT_CANCEL (`0x0106`) MUST carry, as its `corr`, the `corr` of the
  outstanding request it withdraws (§6.4).
* A receiver MUST match a reply, acknowledgement, or withdrawal to its originating
  frame by `corr`, **not** by the per-(channel, direction) frame sequence number.
  Because either peer may originate operations and several may be outstanding at
  once on the single bidirectional stream, sequence order does not identify the
  originating exchange.

### 5.2 Correlation lifetime

A `corr` value associated with a request/reply operation (prompt or approval) is
consumed when its `*_RESULT` or INTERACT_ERROR is delivered; the requester MUST
treat that exchange as complete and MUST NOT reuse the value for a new request while
the original is outstanding. A `corr` value on an INTERACT_EVENT that set `ack` is
consumed when its INTERACT_EVENT_ACK (or an INTERACT_ERROR) is delivered; a `corr`
on an INTERACT_EVENT that did not set `ack` is consumed on transmission (the event
is fire-and-forget, §6.1). An INTERACT_CANCEL does not create a new correlation: it
references, and helps retire, the exchange named by the `corr` it carries (§6.4).

### 5.3 Origination and direction

Because the channel is Bidirectional (§2), the core specification imposes no fixed
originator/consumer assignment at the channel level. In the common deployment an
agent originates INTERACT_EVENT (surfacing UI events), INTERACT_PROMPT_REQ, and
INTERACT_APPROVAL_REQ toward the peer that fronts the human, and the
human-fronting peer returns INTERACT_EVENT (input events), INTERACT_PROMPT_RESULT,
and INTERACT_APPROVAL_RESULT. This document fixes no such assignment: either peer
MAY originate any request, and a conformant implementation MUST correlate replies
to requests by `corr` regardless of which peer originated the exchange.

## 6. Operation bodies

Each operation body is a deterministic-CBOR map carrying the common envelope
(§4.2, keys `0`–`1`) and the per-frame fields below at keys `2`+. Unless a field is
marked required, it is OPTIONAL and, when absent, carries no value (a producer omits
the key rather than encoding a null placeholder; a producer that does encode an
explicit CBOR `null` for an absent OPTIONAL field is equivalent to omitting it).

### 6.1 INTERACT_EVENT (`0x0100`) / INTERACT_EVENT_ACK (`0x0101`)

Convey a user-interface event to the peer. An INTERACT_EVENT is a notification: an
agent surfacing a UI event toward the human's client, or the human's client
returning an interaction (input) event toward the agent. It is fire-and-forget
unless it sets `ack`, in which case the peer replies INTERACT_EVENT_ACK.

**INTERACT_EVENT body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `event_class` (2) | Unsigned int (0–255) | Yes | Advisory classification of the event: `0x00` display (render or update a surface), `0x01` notice (a transient notification), `0x02` status (agent progress or state), `0x03` input (a human interaction event returned to the agent — for example a click, keypress, or selection), `0x04` lifecycle (a surface opened, closed, focused, or blurred). Values `0x05`–`0x7F` require specification to assign; `0x80`–`0xFF` are for private use. A receiver that does not recognize the value MUST treat the event as `0x00` display and MUST NOT fail the event on that basis alone. |
| `event_name` (3) | Text string | No | Advisory free-text event name or descriptor (for example a component or event identifier). Not a correlation key; MUST NOT be used to correlate or de-duplicate events. |
| `body` (4) | Map | No | Structured event payload keyed by unsigned integers, opaque to this document; its inner schema is an application matter. A receiver MUST apply the forward-compatibility rule (§4.3) to this nested map. |
| `ack` (5) | Boolean | No | When `true`, the sender requests an INTERACT_EVENT_ACK echoing `corr`. Absent means `false`: the event is fire-and-forget and the peer MUST NOT reply. |

**INTERACT_EVENT_ACK body** carries only the common envelope (§4.2): it echoes the
event's `corr` and takes no arguments beyond `frame_kind` and `corr`. It confirms
receipt only, not that the human observed or acted on the event.

An INTERACT_EVENT that a responder cannot deliver (for example because no human
party is attached) MAY be reported with INTERACT_ERROR `no_human` (§8) only when the
event set `ack`; a fire-and-forget event provokes no error frame.

### 6.2 INTERACT_PROMPT_REQ (`0x0102`) / INTERACT_PROMPT_RESULT (`0x0103`)

Prompt the human for input and await the human's response.

**INTERACT_PROMPT_REQ body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `prompt_kind` (2) | Unsigned int (0–255) | Yes | The kind of response solicited: `0x00` acknowledge (dismiss/OK, no value), `0x01` text (free text), `0x02` choice (select exactly one of `options`), `0x03` multi_choice (select zero or more of `options`), `0x04` confirm (a boolean yes/no), `0x05` form (structured fields described by `schema`). Values `0x06`–`0x7F` require specification; `0x80`–`0xFF` are for private use. A receiver that cannot present the requested kind MUST reply INTERACT_ERROR `unsupported_prompt` (§8). |
| `prompt` (3) | Text string | Yes | The human-readable prompt text to present. |
| `options` (4) | Array of text string | No | The selectable options for a `choice` or `multi_choice` prompt. REQUIRED when `prompt_kind` is `0x02` or `0x03`; a receiver MUST reply INTERACT_ERROR `malformed_request` for a `choice`/`multi_choice` prompt that omits or empties it. |
| `schema` (5) | Map | No | For a `form` prompt: a field-descriptor map keyed by unsigned integers, opaque to this document (§4.3 applies). Ignored for other prompt kinds. |
| `deadline_s` (6) | Unsigned int | No | Advisory: the number of seconds within which the originator seeks a response. Advisory only; it is not a correlation-lifetime guarantee. On expiry the originator MAY withdraw the prompt with INTERACT_CANCEL (§6.4). |

**INTERACT_PROMPT_RESULT body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `outcome` (2) | Unsigned int | Yes | How the human resolved the prompt: `0x00` answered (a `value` follows), `0x01` dismissed (the human declined to answer without providing a value), `0x02` deferred (the human-fronting client could not obtain an answer, for example its own local deadline elapsed). |
| `value` (3) | Varies by `prompt_kind` | No | The human's response, present if and only if `outcome` is `0x00` answered. Its CBOR type is fixed by the request's `prompt_kind`: absent for `acknowledge`; a text string for `text`; an unsigned int index into `options` for `choice`; an array of unsigned int indices for `multi_choice`; a boolean for `confirm`; a map for `form`. A receiver MUST reject a `value` whose CBOR type does not match the request's `prompt_kind` by treating the exchange as failed and reporting INTERACT_ERROR `malformed_request`. |

A prompt `dismissed` by the human is a completed interaction that returned no value;
it is **not** an error and MUST NOT be reported as INTERACT_ERROR. A prompt for
which no human answer could be obtained is reported either as an
INTERACT_PROMPT_RESULT with `outcome` = `deferred` (the client chose to answer with
a deferral) or, where the responder has no human party at all, as INTERACT_ERROR
`no_human` (§8).

### 6.3 INTERACT_APPROVAL_REQ (`0x0104`) / INTERACT_APPROVAL_RESULT (`0x0105`)

Request a human decision to approve or deny a described action. This is the
human-in-the-loop authorization operation of the channel; its held outcome is a
distinct non-success result (§7, §8.1).

**INTERACT_APPROVAL_REQ body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `action` (2) | Text string | Yes | A human-readable description of the action requiring the human's authorization. |
| `severity` (3) | Unsigned int (0–255) | No | Advisory severity of the action being approved: `0x00` advisory, `0x01` normal, `0x02` sensitive, `0x03` critical. Values `0x04`–`0x7F` require specification; `0x80`–`0xFF` are for private use. Advisory only; a receiver MUST NOT reject an approval request solely because `severity` is unrecognized (it treats an unrecognized value as `0x01` normal). |
| `context` (4) | Map | No | Structured supporting context for the human's decision, keyed by unsigned integers, opaque to this document (§4.3 applies). |
| `deadline_s` (5) | Unsigned int | No | Advisory: the number of seconds within which a decision is sought. Advisory only; on expiry the originator MAY withdraw the request with INTERACT_CANCEL (§6.4). |

**INTERACT_APPROVAL_RESULT body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `decision` (2) | Unsigned int | Yes | The human's completed decision: `0x00` granted or `0x01` denied. A `denied` decision is a **completed human decision** (the interaction succeeded and returned a refusal); it is DISTINCT from an `approval_held` non-success outcome (§8.1), in which no human decision was obtained, and from a `policy_denied` error (§8.1), in which the responder's automated policy refused to present the request to a human at all. |
| `reason` (3) | Text string | No | An OPTIONAL human- or client-supplied reason accompanying the decision. Unlike an INTERACT_ERROR `message` (§8.2), this is human-authored content of the interaction, not a responder-internal diagnostic. |

An INTERACT_APPROVAL_RESULT is emitted **only** for a completed human decision. An
approval that the responder parks for a human decision it did not obtain, rather
than deciding, is NOT reported as an INTERACT_APPROVAL_RESULT; it is reported as
INTERACT_ERROR with code `approval_held` (§8.1). A responder MUST NOT present a held
or undecided action to the requester as `granted`.

### 6.4 INTERACT_CANCEL (`0x0106`)

Withdraw an outstanding INTERACT_PROMPT_REQ or INTERACT_APPROVAL_REQ that the
originator no longer needs (for example its advisory deadline elapsed). The cancel
carries, as its `corr`, the `corr` of the request it withdraws (§5.1).

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `reason` (2) | Unsigned int | No | Advisory withdrawal reason: `0x00` no_longer_needed, `0x01` deadline_elapsed, `0x02` superseded. A receiver MUST NOT alter its handling based on an unrecognized value. |

On receiving an INTERACT_CANCEL for an outstanding request, the peer SHOULD stop
presenting the prompt or approval to the human and SHOULD NOT subsequently emit a
`*_RESULT` for that `corr`. Cancellation is best-effort and races the human: if a
`*_RESULT` for the same `corr` was already in flight when the cancel was sent, the
originator MUST tolerate receiving it and MUST treat the `corr` as consumed on the
first of the crossing frames it processes. An INTERACT_CANCEL for an unknown or
already-completed `corr` MUST be ignored; it MUST NOT itself provoke an
INTERACT_ERROR. INTERACT_CANCEL is not itself answered by a `*_RESULT` or an ACK.

## 7. Delivery, ordering, and the approval hold

Each direction of the Interaction channel is an independent, ordered frame
sequence (core specification §5). Because the channel is not Multi-stream (§2),
concurrent outstanding interactions share the one bidirectional stream and are
disambiguated solely by `corr` (§5). A responder MAY interleave the delivery of a
`*_RESULT` for one exchange with `INTERACT_EVENT`s or other results; a requester
MUST NOT assume that results arrive in request order, and MUST use `corr` to route
each reply to its originating exchange.

The central non-success outcome of this channel is the **approval hold**: an
approval request that has been parked for a human decision that was not obtained
synchronously. A hold is neither an authorization nor a denial — it is a *pending
human decision* — and it MUST be preserved as its own distinct outcome, never
collapsed into a success result and never collapsed into an automated denial
(§8.1). This mirrors the governance-escalation outcome the Memory channel
preserves as `approval_required` (`81_memory_channel.md` §8.1): an operation held
for human approval is reported as a distinct error outcome, not as a completed
operation.

## 8. Error model

Every failure or hold of an Interaction request is reported in a single
INTERACT_ERROR (`0x0107`) frame — the Interaction channel has no foreign protocol,
so all errors are native and carried in one structured frame. An INTERACT_ERROR
echoes the failed request's `corr` and carries:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `code` (2) | Unsigned int | Yes | One of the Interaction error codes below. |
| `message` (3) | Text string | Yes | A peer-safe, generic human-readable message for `code`. It MUST NOT carry internal detail (§8.2). |
| `retry_after_s` (4) | Unsigned int | No | When present, the number of seconds after which the requester MAY retry. |
| `approval_id` (5) | Text string | No | Present if and only if `code` is `approval_held`: an identifier of the held-for-decision approval (§8.1), by which a later out-of-band or subsequent-exchange human decision can be associated with this request. |

| Code | Name | Meaning |
|---|---|---|
| 1 | malformed_request | The CBOR body is not valid deterministic CBOR, omits a REQUIRED field, uses a wrong CBOR major type, carries an unknown negative key (§4.3), omits `options` on a `choice`/`multi_choice` prompt (§6.2), or carries a `value` whose type contradicts the request's `prompt_kind` (§6.2). |
| 2 | unknown_operation | The frame type is not an Interaction operation the responder implements. |
| 3 | unsupported_prompt | The requested `prompt_kind` (§6.2) cannot be presented by the responder's client. |
| 4 | no_human | No human party is attached to the responder to present the interaction, so it cannot be delivered or decided. |
| 5 | policy_denied | The operation was refused by the responder's automated governance or policy — a definitive refusal that was NOT presented to a human (§8.1). |
| 6 | approval_held | An approval request was escalated for a human decision and that decision was **NOT obtained**: the action is neither authorized nor denied, but a pending human decision (§8.1). Carries `approval_id`. |
| 7 | timed_out | The originator's advisory deadline elapsed before a human response, and the responder withdrew the request. |
| 8 | internal_error | A client or pipeline failure the responder cannot attribute to the request. Generic; no internal detail crosses the wire (§8.2). |

### 8.1 The approval hold is a distinct, non-success outcome

A `policy_denied` (code 5), an `approval_held` (code 6), and an
INTERACT_APPROVAL_RESULT with `decision` = `denied` (§6.3) are three different
results and MUST NOT be conflated:

* **`decision` = `granted`** (INTERACT_APPROVAL_RESULT) — a human decided to
  authorize the action. The interaction succeeded.
* **`decision` = `denied`** (INTERACT_APPROVAL_RESULT) — a human decided to refuse
  the action. The interaction succeeded and returned a refusal; the human's
  decision is final.
* **`policy_denied`** (INTERACT_ERROR) — the responder's automated policy refused
  the action and did **not** present it to a human. A definitive refusal, but not a
  human decision.
* **`approval_held`** (INTERACT_ERROR) — the action was escalated for a human
  decision that was **NOT obtained**. It is neither a success nor a definitive
  denial, but a pending decision; the action has **NOT** been authorized and has
  **NOT** taken effect.

An implementation MUST report a held approval as INTERACT_ERROR with code
`approval_held`, carrying `approval_id`, and MUST NOT report it as an
INTERACT_APPROVAL_RESULT (`granted` or `denied`) or as any other `*_RESULT`. A
held-for-decision action MUST NOT be presented to the requester as authorized: an
action that was not approved by a human is never a `granted` result. A requester
MUST treat `approval_held` as an action that has not yet been decided — distinct
from a completed `granted`, a completed `denied`, and a definitive
`policy_denied`.

### 8.2 No internal detail on the wire

The `message` field MUST be the generic, peer-safe string for its `code`. The full
internal cause of a failure MUST be handled locally (for example logged by the
responder) and MUST NOT cross the wire: an INTERACT_ERROR MUST NOT carry client
internals, policy topology, configuration or source names, decoder diagnostics, or
any other detail beyond the code and its generic message. This leak-prevention
requirement is normative for interoperability, not merely local hygiene: a
requester MUST be able to rely on the error surface exposing only a code, a generic
message, and the OPTIONAL `retry_after_s` / `approval_id` fields. (A human-authored
`reason` on an INTERACT_APPROVAL_RESULT, §6.3, is interaction content and is not
constrained by this rule; it is not a responder-internal diagnostic.)

## 9. Security and privacy considerations

This section supplements the core specification's Security Considerations; it does
not restate them.

Every Interaction frame is AEAD-protected like all N-PAMP frames and is carried
under the association's existing authentication (the core specification's handshake
binds both peer identities into the transcript and the Finished MAC). A responder
therefore knows that an interaction was requested by the authenticated peer, but
**authentication is not authorization**: a responder MUST enforce its own
governance and human-in-the-loop policy on every prompt and approval regardless of
the peer's identity, and MUST report the outcome per §8 — including preserving the
`approval_held` / `policy_denied` / `denied` distinctions (§8.1). In particular, a
peer MUST NOT treat an INTERACT_APPROVAL_REQ it received as self-authorizing: the
decision to grant is the human's, mediated by the responder's policy, never the
requester's.

Interaction bodies can carry content destined for a human's screen and content a
human typed back. A responder SHOULD treat prompt text, event bodies, and decision
context as untrusted display data — it MUST NOT interpret an `event_name`,
`prompt`, or nested `body`/`context` map as executable or as a security decision —
and SHOULD apply its own sanitization before rendering. A human's response
(`value`, `reason`) MAY contain sensitive personal input; an implementation SHOULD
scope its retention and disclosure per local policy and MUST NOT place it in an
INTERACT_ERROR (§8.2).

A responder MUST bound the resources a remote peer can consume through Interaction
operations: the number of concurrent outstanding prompts and approvals it will
hold, the rate of INTERACT_EVENT frames it will accept, and the size of an event or
context body it will buffer. A responder MAY reply INTERACT_ERROR (with
`retry_after_s`) rather than allocate without limit. Because either peer may
originate operations on this Bidirectional channel, both directions are subject to
these limits.

The `approval_id` on an `approval_held` outcome is an identifier the requester may
later use to associate a deferred human decision with the original request; a
responder MUST make `approval_id` unguessable enough that a third party cannot forge
a reference to a pending decision, and MUST bind the eventual decision to the
authenticated association, so that a held approval cannot be resolved by an
unauthorized peer.

The error surface MUST NOT leak internal detail (§8.2); an INTERACT_ERROR that
carried client internals, policy topology, or configuration names would disclose
the responder's internal structure to the peer and is a conformance violation
(§10).

## 10. Conformance

An implementation conforms to NPAMP-INTERACT if and only if it rests on a
core-conformant N-PAMP wire implementation and, on the Interaction channel
`0x000F`, it:

1. Treats `0x000F` as the Interaction channel with the core registry identity
   (name Interaction; purpose agent-to-human user-interface events; minimum profile
   Standard; direction Bidirectional), does not repurpose the channel identifier,
   enables it only at the **Standard** profile or higher, treats it as available at
   Standard, High, and Sovereign once Standard is met, and drops any frame received
   on an unadvertised Interaction channel (§2);

2. Uses only the eight Interaction frame types defined in §3 — the application-band
   operation frames `0x0100`–`0x0107` — preserves the core meaning of the reserved
   all-channel frame types `0x0000`–`0x000A`, defines **no** frame in the
   companion-extension band `0x0030`–`0x00FF` (the core reserves no such range for
   this channel), and assigns no Interaction meaning to any code point the core
   reserves for another channel (§3);

3. Encodes every operation body as a deterministic-CBOR map (§4.1) with the integer
   keys of §4.2 and §5–§8; rejects a non-deterministically-encoded body, a body
   missing a REQUIRED field, a wrong-major-type key, a `frame_kind` that contradicts
   the frame header, or a body carrying an unknown negative key with INTERACT_ERROR
   `malformed_request`; and ignores an unknown non-negative key — in the payload map
   and in every nested `body`/`schema`/`context` map — without altering its handling
   of recognized keys (§4.2, §4.3);

4. Carries a non-empty `corr` on every INTERACT_EVENT, INTERACT_PROMPT_REQ, and
   INTERACT_APPROVAL_REQ, echoes it verbatim on every INTERACT_EVENT_ACK,
   `*_RESULT`, and INTERACT_ERROR, carries the target request's `corr` on an
   INTERACT_CANCEL, and matches replies to requests by `corr` rather than by frame
   sequence number (§5);

5. Treats an INTERACT_EVENT as fire-and-forget unless it sets `ack`, replies
   INTERACT_EVENT_ACK (echoing `corr`) exactly when `ack` was set, and never emits
   an unsolicited `*_RESULT`, ACK, or error (§3.1, §6.1);

6. Presents a prompt only when it supports the requested `prompt_kind` (replying
   INTERACT_ERROR `unsupported_prompt` otherwise), requires `options` on a
   `choice`/`multi_choice` prompt, returns the human's resolution as an
   INTERACT_PROMPT_RESULT whose `value` type matches the request's `prompt_kind`,
   and treats a `dismissed` prompt as a completed non-error interaction (§6.2);

7. Reports every failure as INTERACT_ERROR (`0x0107`) with a code from §8 and a
   peer-safe `message`, never leaking internal cause (§8.2); reports an approval
   held for a human decision as `approval_held` carrying `approval_id`, distinct
   from a completed INTERACT_APPROVAL_RESULT `denied` and from a `policy_denied`
   error; and never reports a held or undecided action as a `granted` result
   (§6.3, §8.1); and

8. Honors an INTERACT_CANCEL by ceasing to present the withdrawn prompt or approval
   and tolerating a `*_RESULT` that crossed the cancel, ignores a cancel for an
   unknown or completed `corr`, and does not use the Interaction channel to carry a
   foreign agent protocol under a native encoding — deferring any foreign
   agent-to-human protocol (for example AG-UI) to NPAMP-BRIDGE / NPAMP-CC-STREAM and
   the NPAMP-MAP-AGUI mapping, not to the native frames of this document (§2, §6.4).

A conformance test suite SHOULD assert each clause above with a recorded exchange on
the Interaction channel `0x000F`: an INTERACT_EVENT with `ack` set answered by an
INTERACT_EVENT_ACK, and a fire-and-forget event that provokes none; an
INTERACT_PROMPT_REQ / INTERACT_PROMPT_RESULT pair for each of the `prompt_kind`
values, including a `choice` prompt whose `value` is an option index and a
`dismissed` outcome; an INTERACT_APPROVAL_REQ answered distinctly by a `granted`
result, a `denied` result, an `approval_held` error carrying an `approval_id`, and a
`policy_denied` error; an INTERACT_CANCEL that withdraws an outstanding prompt; and a
rejected malformed body (a non-deterministic encoding, a missing REQUIRED field, a
`choice` prompt missing `options`, and an unknown negative key), each yielding
`malformed_request`.

**Conformance posture (graded on the payload surface).** Conformance vectors exist
for the Interaction channel's payload-decode surface: the `interaction.body.decode`
operation group in the conformance corpus, produced by an independent RFC 8949 byte
constructor (`test-vectors/gen/interaction_oracle.py`) and graded by `npamp-conform`
against the reference implementation (`impl/go/interaction*.go`), covers the §4.1 /
§4.2 / §4.3 payload-encoding and common-envelope MUST-reject clauses — including the
rule that a `frame_kind` (0) contradicting the frame header and an unknown negative
key are each rejected with `malformed_request` — and its expected values derive from
that independent authority, not from the implementation under test. That surface is
cross-validated by `impl/go/zz_interaction_oracle_xval_test.go`, so a claim of
conformance to those clauses is graded against the pinned corpus. Beyond that payload
surface, the §5–§9 behavioural clauses (the operation and correlation state model,
the delivery/ordering discipline, the approval-hold distinction of §7 and §8.1, and
the leak-prevention rule of §8.2) are graded only by a live-exchange harness once one
is authored; a conformance claim MUST NOT present those behavioural clauses as graded
against the corpus until such a harness, or a vector group whose expected values
likewise derive from an independent authority and not from the implementation under
test, exists and this clause is updated to name it.
