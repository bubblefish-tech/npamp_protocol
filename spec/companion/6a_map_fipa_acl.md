# NPAMP-MAP-FIPA-ACL — FIPA Agent Communication Language Mapping (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is a **thin per-protocol mapping**: it pins the specifics of
> the **FIPA Agent Communication Language (FIPA-ACL)** — a mature, standardized
> performative (speech-act) message-passing language — onto N-PAMP carriage. It is a
> thin mapping over the **Messaging carriage class NPAMP-CC-MSG**
> (`22_carriage_messaging.md`): that class does the structural work — verbatim
> carriage of the message, projection of the performative and a dialogue-threading
> token onto the envelope, correlation, the self-asserted-sender model, and the
> safety fail-safe — and this document pins only what is specific to FIPA-ACL. It
> builds on NPAMP-CC-MSG, on NPAMP-BRIDGE (`10_bridge_framework.md`), and on the
> N-PAMP core specification (draft-bubblefish-npamp-01, the "core specification"). It
> consumes only code points those documents already reserve and introduces no change
> to the core wire format, to NPAMP-BRIDGE, or to NPAMP-CC-MSG.
>
> **Carriage status: OPAQUE-READY.** FIPA-ACL is **carriable today** under Class
> OPAQUE (`25_carriage_opaque.md`): a complete ACL message is an opaque,
> declared-content-type payload that Class OPAQUE carries with no protocol-specific
> mapping. This document is the **native MSG mapping** that adds the
> metadata-projection benefits of NPAMP-CC-MSG (performative-as-`method`, dialogue
> threading, per-message safety labelling). Two facts remain **PROVISIONAL / not yet
> confirmed by an N-PAMP registry** and are stated as such below rather than
> fabricated: FIPA-ACL has **no assigned `protocol_id`** (§3.1), and no BridgeEnvelope
> `content_type` code point is assigned for a FIPA ACL message encoding (§3.2). Until
> both are registered, this mapping is used by out-of-band agreement between two peers
> and the row remains OPAQUE-READY in the companion index.

## 1. Scope

### 1.1 In scope

This document defines how a FIPA-ACL agent interoperates over an N-PAMP association
without bespoke adaptation. It pins, against FIPA-ACL's own published specifications
(§12), only the FIPA-ACL specifics that NPAMP-CC-MSG leaves to a per-protocol mapping:

- The FIPA-ACL **protocol identifier** (PROVISIONAL) and the foreign-message
  `content_type` question (§3);
- FIPA-ACL's **performative vocabulary** — the twenty-two communicative acts of the
  FIPA Communicative Act Library — and how each is projected onto the BridgeEnvelope
  `method` field (§4);
- The **reply-discipline classification** — which NPAMP-BRIDGE frame type and
  `message_kind` a given ACL message uses — which NPAMP-CC-MSG §4.2 requires a
  per-protocol mapping to fix, together with the rule that a message's own threading
  parameters govern in preference to any per-performative default (§4);
- How FIPA-ACL's **message parameters** map onto or stay out of the envelope:
  `reply-with`/`in-reply-to` onto the correlation identifier, `conversation-id` kept
  distinct inside the body, and `sender`, `receiver`, `reply-to`, `language`,
  `encoding`, `ontology`, `protocol`, `reply-by`, and `content` carried verbatim
  (§5);
- FIPA-ACL's **self-asserted `sender`** and its OPTIONAL binding to the N-PAMP
  handshake identity (§6);
- The **SafetyLabel effect class** a sender attaches, which for FIPA-ACL is derived
  from the *action in the message content*, never from the performative label, with
  the NPAMP-BRIDGE §7 fail-safe on absence (§7); and
- **Channel selection**: the Bridge channel `0x000D` (§8).

### 1.2 Not in scope

The following are explicitly NOT defined by this document, because NPAMP-CC-MSG,
NPAMP-BRIDGE, or FIPA-ACL's own specifications already define them:

- **The structural carriage of a performative message.** Octet-exact carriage, the
  BridgeEnvelope TLV, the projection mechanism, correlation, the envelope/message
  disagreement rule, and the SafetyLabel TLV are inherited verbatim from NPAMP-CC-MSG
  and NPAMP-BRIDGE and are not restated here (§2).
- **The formal semantics of the communicative acts.** The feasibility preconditions,
  rational effect, and SL formal model of each FIPA communicative act
  ([FIPA00037]) are fixed by FIPA-ACL and are carried inside the verbatim message;
  this document does not interpret, evaluate, or enforce them.
- **The content language, ontology, and content grammar.** The `content` expression,
  the `language` it is encoded in (for example FIPA-SL, [FIPA00008]), and the
  `ontology` it draws on are carried verbatim inside the ACL message; this mapping
  does not parse, validate, translate, or reason over them (NPAMP-CC-MSG §5.4).
- **FIPA message transport and the ACL message envelope.** FIPA carries ACL messages
  over a Message Transport Service (an Agent Communication Channel, [FIPA00067]) that
  wraps each message in a *transport envelope*. Over N-PAMP, **N-PAMP is the
  transport**: the FIPA MTS, its Message Transport Protocols, and the FIPA transport
  envelope do not apply, and only the ACL message itself is the foreign message (§9).
- **The byte grammar of any ACL encoding.** FIPA defines three interchangeable ACL
  message encodings — String ([FIPA00070]), XML ([FIPA00071]), and Bit-Efficient
  ([FIPA00069]). This mapping carries whichever encoding a deployment uses
  octet-for-octet; it does not define, re-encode, or convert between them (§3.2).
- **Any change to the N-PAMP frame format, to NPAMP-BRIDGE, to NPAMP-CC-MSG, or to
  the BridgeEnvelope or SafetyLabel TLVs.** This document introduces no new frame
  type, TLV, or channel.

## 2. Relationship to NPAMP-CC-MSG and NPAMP-BRIDGE

FIPA-ACL is the archetypal member of the message-passing / performative family that
NPAMP-CC-MSG carries; NPAMP-CC-MSG §1.1 names the FIPA Agent Communication Language
family as its motivating example. Consequently the entire structural carriage of
FIPA-ACL is provided by NPAMP-CC-MSG (a profile of NPAMP-BRIDGE) without modification:

- **Carriage by projection plus verbatim body.** A complete ACL message is carried
  octet-for-octet as the foreign message; the performative is projected onto the
  BridgeEnvelope `method` field and a dialogue-threading token onto `correlation_id`
  as a **non-destructive index**, while every message parameter remains present and
  authoritative inside the body (NPAMP-CC-MSG §3). This document adds no re-encoding.
- **Correlation.** The `id`-style correlation is the NPAMP-BRIDGE `correlation_id`
  (NPAMP-BRIDGE §5), derived per NPAMP-CC-MSG §5.2 and kept distinct from FIPA's
  `conversation-id` (§5).
- **Errors.** A FIPA-level failure is carried as BRIDGE_ERROR with the ACL failure
  message preserved verbatim; a failure below the foreign protocol is an N-PAMP
  transport error (NPAMP-CC-MSG §9; NPAMP-BRIDGE §6). This document adds no error
  code.
- **Safety.** The SafetyLabel TLV and its fail-safe are governed by NPAMP-BRIDGE §7
  and inherited through NPAMP-CC-MSG §7 unchanged; this document only fixes FIPA-ACL's
  effect derivation (§7).

This document therefore pins only FIPA-ACL specifics (§3–§8). Where this document and
NPAMP-CC-MSG could appear to differ on a structural matter, NPAMP-CC-MSG governs.

## 3. Protocol identity

### 3.1 protocol_id (PROVISIONAL)

| Property | Value |
|---|---|
| Protocol | FIPA Agent Communication Language (FIPA-ACL). |
| `protocol_id` | **Not assigned.** No standards-range code point (`0x05`–`0x0F`) is assigned to FIPA-ACL by the Bridge Protocol Identifier registry (NPAMP-REG §6), which assigns only `0x01`–`0x04`. This mapping is therefore **PROVISIONAL** on the identifier. |
| Carriage class | MSG (NPAMP-CC-MSG). |

Because no code point is assigned, an implementation carrying FIPA-ACL under this
mapping MUST use a value from the **experimental range `0x10`–`0x7F`** (NPAMP-REG
§4, §7.1) and the two peers MUST agree on that value out of band, exactly as
NPAMP-CC-MSG §4.1 directs for a message-passing protocol whose identifier is not yet
registered. An implementation MUST NOT emit FIPA-ACL under a standards-range value
`0x05`–`0x0F` that NPAMP-REG has not assigned, and MUST NOT rely on an experimental
value for interoperation between independently developed implementations (NPAMP-REG
§7.1). A receiver that does not carry the agreed value MUST reply to a BRIDGE_REQUEST
bearing it with `ProtocolUnsupported` (NPAMP-BRIDGE §6; NPAMP-REG §9).

> **Registration note.** Assigning a stable `protocol_id` to the FIPA-ACL family in
> the standards range is the subject of NPAMP-CC-MSG Appendix A, OPEN QUESTION 1, and
> is a maintainer/registry decision under NPAMP-REG §8 (Specification Required). When
> such a value is registered, this mapping's §3.1 is updated to that value and the
> experimental-range direction above is retired; the rest of this document is
> unchanged, because the carriage does not otherwise depend on the identifier's value.

### 3.2 content_type (UNCONFIRMED)

A FIPA ACL message has three interchangeable FIPA-standard encodings: String
([FIPA00070]), XML ([FIPA00071]), and Bit-Efficient ([FIPA00069]). The BridgeEnvelope
`content_type` field (NPAMP-BRIDGE §4) assigns code points only for `0x01`
application/json, `0x02` application/cbor, and `0x03` application/grpc+proto; **no
`content_type` code point is assigned for any FIPA ACL encoding.** This mapping does
not fabricate one. Therefore:

- The complete ACL message is carried octet-for-octet as the foreign message,
  regardless of which of the three encodings a deployment uses (NPAMP-BRIDGE §1;
  NPAMP-CC-MSG §3).
- Until a `content_type` code point for the chosen ACL encoding is registered, the two
  peers MUST agree out of band on the `content_type` value that labels the encoding,
  or carry FIPA-ACL under Class OPAQUE (`25_carriage_opaque.md`), which carries a
  payload under its declared content type with no protocol-specific mapping. This is
  the OPAQUE-READY posture of this document's Status block.
- The FIPA `encoding` message parameter (§5.4) names the encoding of the *content
  expression* and is distinct from the BridgeEnvelope `content_type`, which labels the
  *whole message* encoding; the two MUST NOT be conflated (NPAMP-CC-MSG §4.3, §5.4).

### 3.3 Foreign-message form

The foreign message is **one complete FIPA ACL message** — in the String encoding, an
`ACLCommunicativeAct` of the form `"(" MessageType MessageParameter* ")"` ([FIPA00070] §2.2)
— carried verbatim (NPAMP-BRIDGE §1). A receiver MUST select FIPA-ACL solely from the
agreed `protocol_id` and MUST NOT infer it from any other envelope field (NPAMP-REG
§9). The ACL message, not the projected envelope, is authoritative for every message
parameter (NPAMP-CC-MSG §3.1).

## 4. Performative vocabulary and frame mapping

### 4.1 The performative is projected onto `method`

FIPA-ACL's only mandatory message parameter is the **performative** — "the only
parameter that is mandatory in all ACL messages is the performative" ([FIPA00061]
§2). Per NPAMP-CC-MSG §4.4, the sender MUST project the performative label onto the
BridgeEnvelope `method` field as a UTF-8 string, exactly as it appears in the ACL
message, with no case folding, abbreviation, or translation. The projected `method` is
an **index only**; the authoritative performative is the one carried in the verbatim
message (NPAMP-CC-MSG §3.1, §4.4). A receiver that does not carry the indicated
performative reports `MethodUnsupported` (NPAMP-BRIDGE §6).

The twenty-two communicative acts of the FIPA Communicative Act Library ([FIPA00037],
Standard, sections 3.1–3.22) are the FIPA-ACL performative vocabulary. Their canonical
String-encoding tokens ([FIPA00070] §2.2, `MessageType` = see [FIPA00037]) are:

| Communicative act | `method` token | Communicative intent ([FIPA00037]) |
|---|---|---|
| Accept Proposal | `accept-proposal` | Accept a previously submitted proposal to perform an action. |
| Agree | `agree` | Agree to perform some action, possibly in the future. |
| Cancel | `cancel` | Inform another agent that the sender no longer intends a previously requested action. |
| Call for Proposal | `cfp` | Call for proposals to perform a given action. |
| Confirm | `confirm` | Inform the receiver that a proposition is true (receiver was uncertain). |
| Disconfirm | `disconfirm` | Inform the receiver that a proposition is false (receiver believed it or was uncertain). |
| Failure | `failure` | Tell another agent that an action was attempted but failed. |
| Inform | `inform` | Inform the receiver that a proposition is true. |
| Inform If | `inform-if` | Macro act: inform the recipient whether or not a proposition is true. |
| Inform Ref | `inform-ref` | Macro act: inform the receiver of the object corresponding to a descriptor. |
| Not Understood | `not-understood` | Inform that the sender perceived an act it did not understand. |
| Propagate | `propagate` | Ask the receiver to treat an embedded message as sent directly, and propagate it further. |
| Propose | `propose` | Submit a proposal to perform an action, given certain preconditions. |
| Proxy | `proxy` | Ask the receiver to select target agents by a description and forward an embedded message. |
| Query If | `query-if` | Ask another agent whether a given proposition is true. |
| Query Ref | `query-ref` | Ask another agent for the object referred to by a referential expression. |
| Refuse | `refuse` | Refuse to perform a given action and explain the reason. |
| Reject Proposal | `reject-proposal` | Reject a proposal to perform an action during negotiation. |
| Request | `request` | Request the receiver to perform some action. |
| Request When | `request-when` | Request the receiver to perform an action when a proposition becomes true. |
| Request Whenever | `request-whenever` | Request the receiver to perform an action whenever a proposition becomes (or stays) true. |
| Subscribe | `subscribe` | Request a persistent intention to be notified of the value of a reference. |

A deployment MAY define non-FIPA performatives; FIPA reserves the `X-` prefix for
user-defined message parameters ([FIPA00061] §2) and, by the same convention, an
implementation SHOULD prefix a non-standard performative accordingly. An
implementation MUST NOT reject an ACL message solely because its performative is absent
from the table above; the token is carried verbatim and classified per §4.2.

### 4.2 Reply discipline (frame type and `message_kind`)

NPAMP-CC-MSG §4.2 requires a per-protocol mapping to classify each performative into
one of three reply disciplines, **and** requires that where the carried protocol's own
per-message parameters determine the reply discipline, an implementation classify the
individual message by those parameters in preference to a per-performative default.
FIPA-ACL is exactly such a protocol: its performative declares communicative intent,
while its `reply-with`, `in-reply-to`, `protocol`, and `reply-by` parameters
([FIPA00061] §2.5) carry the conversation threading that fixes whether a given message
expects, is, or forecloses a reply. Therefore:

1. **Per-message parameters govern (normative).** An ACL message carrying a
   `reply-with` (and/or a `reply-by`, and/or a `protocol` whose flow expects a next
   message) is a message that expects exactly one reply and MUST be carried as
   **BRIDGE_REQUEST** (`0x0100`, `message_kind = 0x01`) with a non-empty
   `correlation_id` derived per §5.2. An ACL message carrying an `in-reply-to` is
   itself a reply and MUST be carried as **BRIDGE_RESPONSE** (`0x0101`,
   `message_kind = 0x02`), or as **BRIDGE_ERROR** (`0x0102`, `message_kind = 0x04`)
   when it is a FIPA-level failure act (§4.3), echoing the originating request's
   `correlation_id` (NPAMP-CC-MSG §5.2; NPAMP-BRIDGE §5). An ACL message that neither
   solicits nor answers — a one-way announcement — MUST be carried as **BRIDGE_NOTIFY**
   (`0x0103`, `message_kind = 0x03`, `corr_len = 0`; NPAMP-BRIDGE §8).
2. **Per-performative default (guidance).** Where an ACL message carries no threading
   parameter that fixes its role, an implementation SHOULD classify it by the primary
   speech-act role of its performative, as follows. This table is guidance for the
   parameter-free case only; rule 1 overrides it whenever a threading parameter is
   present.

| Reply discipline | `message_kind` / frame | Performatives (typical role) |
|---|---|---|
| Expects exactly one reply | `0x01` / BRIDGE_REQUEST | `request`, `request-when`, `request-whenever`, `cfp`, `query-if`, `query-ref`, `propose`, `subscribe`, `proxy` |
| Is a reply to an earlier act | `0x02` / BRIDGE_RESPONSE (success) or `0x04` / BRIDGE_ERROR (failure act, §4.3) | `agree`, `refuse`, `accept-proposal`, `reject-proposal`, `confirm`, `disconfirm`, and `inform` / `inform-if` / `inform-ref` when they answer a prior `query-*`/`subscribe` |
| Expects no reply (one-way) | `0x03` / BRIDGE_NOTIFY | Unsolicited `inform` / `inform-if` / `inform-ref`, `cancel`, `propagate`, `not-understood` when emitted as a standalone report |

The `message_kind` field MUST agree with the frame type (NPAMP-BRIDGE §4). An
implementation MUST NOT treat a performative's presence in one row above as
authoritative when the message's own threading parameters indicate a different
discipline (rule 1). Several FIPA acts are deliberately role-ambiguous — `inform`
answers a query or announces unsolicited; `cancel` may request cancellation or merely
notify — which is precisely why the threading parameters, not the label, are
authoritative.

### 4.3 Failure and refusal acts

A FIPA-level failure carried as an ACL failure act (`failure`, and — as a rejection of
an act or proposal — `refuse`, `reject-proposal`, or `not-understood`) MUST be carried
as **BRIDGE_ERROR** whose foreign message is that ACL act, verbatim (NPAMP-CC-MSG §4.2,
§9). An implementation MUST NOT reduce such an act to free text and MUST NOT collapse
it into an N-PAMP transport error. A failure **below** FIPA-ACL — a malformed envelope,
an uncarried `protocol_id`, an unsupported performative, a message that could not be
delivered to the ACL endpoint, or a local safety refusal — is reported with the
corresponding NPAMP-BRIDGE transport error code (`EnvelopeMalformed`,
`ProtocolUnsupported`, `MethodUnsupported`, `NotDelivered`, `SafetyPolicy`;
NPAMP-CC-MSG §9).

## 5. Message parameters, correlation, and conversation

FIPA-ACL defines thirteen message parameters ([FIPA00061] §2, Table 1). Their
treatment under this mapping is:

### 5.1 Correlation identifier from `reply-with` / `in-reply-to`

FIPA's per-message threading tokens are `reply-with` ("an expression that will be used
by the responding agent to identify this message") and `in-reply-to` ("an expression
that references an earlier action to which this message is a reply") ([FIPA00061]
§2.5.3–§2.5.4): an agent that sends `reply-with <expr>` receives a reply carrying
`in-reply-to <expr>`. This is the reply-with/in-reply-to token pair that NPAMP-CC-MSG
§5.2 maps onto the correlation identifier:

- For a message carried as BRIDGE_REQUEST (§4.2), the originating peer SHOULD use the
  message's `reply-with` value as the BridgeEnvelope `correlation_id`, provided it is
  non-empty and unique among that peer's outstanding requests on the channel in that
  direction; otherwise the peer MUST generate a fresh unique `correlation_id`
  (NPAMP-CC-MSG §5.2).
- A reply (BRIDGE_RESPONSE or BRIDGE_ERROR) MUST echo the originating request's
  `correlation_id` verbatim (NPAMP-BRIDGE §5). Echoing the `correlation_id` at the
  N-PAMP layer does not relieve the responding agent of carrying the ACL `in-reply-to`
  token inside the verbatim message where FIPA requires it; the two are carried
  independently (NPAMP-CC-MSG §5.2).

### 5.2 `conversation-id` stays in the body

FIPA's `conversation-id` "is used to identify the ongoing sequence of communicative
acts that together form a conversation" and is REQUIRED to be globally unique
([FIPA00061] §2.5.2). It groups an arbitrary number of messages across many exchanges
into one dialogue and is **distinct** from the per-reply NPAMP-BRIDGE correlation
identifier (NPAMP-CC-MSG §5.1). An implementation MUST keep `conversation-id` inside
the verbatim ACL message, MUST NOT overload it onto the `correlation_id`, and MUST NOT
assume the two are equal (NPAMP-CC-MSG §5.1). FIPA's `protocol` parameter ([FIPA00061]
§2.5.1), which names the interaction protocol and, when non-null, requires a non-null
`conversation-id`, is likewise carried in the body and not projected.

### 5.3 `receiver` set and `reply-to` are carried, not projected

FIPA's `receiver` "may be a single agent name or a non-empty set of agent names[;] the
latter corresponds to the situation where the message is multicast" ([FIPA00061]
§2.2.2). An N-PAMP association is point-to-point; per NPAMP-CC-MSG §5.3 a multicast ACL
message is carried to the single peer at the other end with its **full receiver set
intact**, and this mapping does not fan the message out to multiple associations. The
`reply-to` parameter, which redirects subsequent messages to a named agent instead of
the `sender` ([FIPA00061] §2.2.3), is likewise carried verbatim in the body and not
projected onto the envelope; it governs FIPA-level addressing, not N-PAMP routing.

### 5.4 `content`, `language`, `encoding`, `ontology`, `reply-by`

The `content`, and its describing parameters `language` ([FIPA00061] §2.4.1),
`encoding` (§2.4.2), and `ontology` (§2.4.3), and the `reply-by` timeout (§2.5.5) are
all carried verbatim inside the ACL message and MUST NOT be projected onto the
BridgeEnvelope (NPAMP-CC-MSG §5.4). This mapping does not require any of them to be
present, supplies no default for an absent one, and does not validate `content` against
a `language` or `ontology`. As noted in §3.2, the FIPA `encoding` parameter (the
content-expression encoding) is not the BridgeEnvelope `content_type` (the whole-message
encoding).

## 6. Sender identity

FIPA's `sender` "denotes the identity of the sender … the name of the agent of the
communicative act," and FIPA explicitly permits omitting it "if … the agent sending the
ACL message wishes to remain anonymous" ([FIPA00061] §2.2.1). FIPA-ACL itself neither
signs nor authenticates the `sender`. Accordingly, per NPAMP-CC-MSG §6:

- The `sender` is **self-asserted** by default. A receiver MUST NOT treat a
  self-asserted `sender` as an authenticated identity and MUST NOT grant an
  authorization decision on the basis of a self-asserted `sender` alone (NPAMP-CC-MSG
  §6.1). An omitted (anonymous) `sender` is carried as omitted; this mapping neither
  supplies nor infers one.
- A deployment MAY, under local policy, treat the N-PAMP handshake-authenticated
  identity of the peer that **originates** a message as a **verified binding** for that
  message's `sender` (NPAMP-CC-MSG §6.2). When such a binding is in force, a receiver
  MAY rely on the bound identity for authorization, MUST reject (or downgrade to
  self-asserted) a message whose self-asserted `sender` contradicts the binding, and
  MUST apply the binding only to the originating peer's own assertion — not to a
  `sender` inside a relayed `proxy` or `propagate` message (NPAMP-CC-MSG §6.2).
- This mapping introduces no identity TLV, frame, or handshake element; the binding is
  an application of the N-PAMP handshake identity governed by local policy
  (NPAMP-CC-MSG §6.3).

## 7. SafetyLabel and side effects

The SafetyLabel TLV (Type `0x0013`) and its fail-safe are governed by NPAMP-BRIDGE §7
and inherited through NPAMP-CC-MSG §7 unchanged. The governing FIPA-specific fact is
that **a FIPA performative does not by itself reveal whether acting on a message mutates
state**: a `request` may ask for a read-only computation or for a destructive action,
and the distinction is in the message `content` (the action expression), not in the
performative (NPAMP-CC-MSG §7). Therefore:

- A sender MUST derive the SafetyLabel `effect` from the **action denoted in the ACL
  message `content`**, not from the performative label. When a carried message, if
  acted upon, can cause a side effect, the sender MUST attach a SafetyLabel TLV
  describing that effect, and an intermediary MUST carry it unchanged (NPAMP-BRIDGE §7).
- A receiver MUST NOT infer `read_only` from any performative. In particular, a
  receiver MUST NOT treat a `request`, `request-when`, `request-whenever`, `cfp`,
  `propose`, or `query-*` as `read_only` on the basis of the label (NPAMP-CC-MSG §7).
- The **absence** of a SafetyLabel on a message that can mutate state MUST be treated as
  `0x03` destructive (fail-safe), never as `read_only` (NPAMP-BRIDGE §7).

The following guidance fixes the *minimum* effect class implied by the communicative act
itself, independent of the `content`'s action; a sender MUST raise it to reflect the
actual action when the `content` demands a higher class. It uses the NPAMP-BRIDGE §7
values `0x00` read_only, `0x01` idempotent_write, `0x02` non_idempotent_write, `0x03`
destructive.

| Communicative act(s) | Minimum `effect` | Rationale |
|---|---|---|
| `inform`, `inform-if`, `inform-ref`, `confirm`, `disconfirm`, `failure`, `not-understood`, `refuse`, `reject-proposal`, `query-if`, `query-ref` | `0x00` read_only | Convey or request information, or decline; acting on them does not itself mutate the receiver's external state. A SafetyLabel MAY be omitted; absence is correctly read as read_only for these. A deployment where a query triggers a side-effecting computation MUST label it accordingly. |
| `subscribe`, `cancel` | `0x01` idempotent_write | Establish or withdraw responder-side conversational state (a persistent notification intention; the cancellation of a prior intention). Repeating with the same arguments yields the same state. The sender SHOULD attach the SafetyLabel; on absence the receiver MUST fail-safe to `destructive`. |
| `proxy`, `propagate` | `0x02` non_idempotent_write (at minimum) | Ask the receiver to perform a communicative action — select targets and forward or propagate an embedded message — with observable effect; each relay is a fresh action, and the embedded message's own effect also applies. The sender MUST attach a SafetyLabel. |
| `request`, `request-when`, `request-whenever`, `cfp`, `propose`, `accept-proposal`, `agree` | Derived from `content` | Request, call for, propose, accept, or commit to an action whose effect is entirely that of the action in the `content`. The sender MUST attach a SafetyLabel reflecting the requested action; on absence the receiver MUST fail-safe to `destructive`. These MUST NOT be defaulted to `read_only`. |

The `scope` field of the SafetyLabel (NPAMP-BRIDGE §7) MAY carry an advisory resource
hint (for example the `ontology` name or a target identifier drawn from the `content`).
The SafetyLabel describes intent and does not replace authorization: a receiver MUST
enforce its own authorization at the point of action and MUST NOT treat a favorable
SafetyLabel, or a verified `sender` binding (§6), as permission (NPAMP-BRIDGE §7;
NPAMP-CC-MSG §7).

## 8. Channel selection

FIPA-ACL message traffic rides the **Bridge channel `0x000D`** by default, as required
for NPAMP-BRIDGE encapsulation (NPAMP-BRIDGE §1; NPAMP-CC-MSG §3). Under this mapping, a
peer carrying a FIPA-ACL dialogue MUST carry that dialogue's ACL messages on the Bridge
channel, and MUST NOT split a single FIPA conversation (one `conversation-id`) across
channels or associations. The Bridge channel is minimum-profile **Standard** (core
specification channel registry; `../../registries/channels.csv`); FIPA-ACL carriage
requires no channel above the Standard profile. A peer MUST NOT send or accept FIPA-ACL
frames on a channel it did not advertise during the handshake (core specification §5).

A peer MAY, OPTIONALLY and around — not in place of — a dialogue, advertise that it
carries FIPA-ACL over NPAMP-DISC on the Discovery channel `0x0010` (a protocol Discovery
Record naming the agreed `protocol_id` and carriage class MSG; NPAMP-DISC §5.1). Such an
advertisement announces carriage; it does not carry ACL traffic, and a peer MUST NOT
advertise FIPA-ACL if it cannot in fact carry the agreed `protocol_id` over the
association (NPAMP-DISC §5.1).

## 9. Transport and encoding notes

FIPA-ACL is defined independently of any single wire transport: FIPA carries ACL
messages over a Message Transport Service provided by an Agent Communication Channel
([FIPA00067]), and different Message Transport Protocols wrap each ACL message in a
FIPA *transport envelope* whose representation varies by MTP. Over N-PAMP, **N-PAMP is
the transport**:

- The FIPA MTS/ACC, its MTPs, and the FIPA transport envelope do not apply, and MUST
  NOT be carried as part of the foreign message. Only the ACL message itself (§3.3) is
  the foreign message; an implementation MUST NOT carry a FIPA transport-envelope header
  as part of it.
- The N-PAMP association supplies authentication, post-quantum confidentiality and
  integrity, multiplexing, and the key schedule (core specification); these replace,
  and are not layered on top of, FIPA's transport bindings.
- FIPA-level conversational state (the `conversation-id`, `protocol`, and outstanding
  `reply-with` tokens) is scoped to the dialogue carried on the association and is not
  N-PAMP session state; a peer MUST NOT carry FIPA conversational state from a prior
  association into a new one at the N-PAMP layer.

Because the carriage is transparent over the message (§2), a deployment carries the
String, XML, or Bit-Efficient encoding without a change to this mapping, subject only to
the `content_type` labelling of §3.2.

## 10. Code points consumed

This mapping consumes only code points that the core specification, NPAMP-BRIDGE, and
NPAMP-CC-MSG already define. It defines no new frame type, no new TLV, and no change to
the core wire format.

| Resource | Origin | Use here |
|---|---|---|
| `protocol_id` (experimental `0x10`–`0x7F`, by out-of-band agreement) | NPAMP-BRIDGE §4; NPAMP-REG §4, §7.1 | The FIPA-ACL identifier on every FIPA-ACL Bridge frame, **PROVISIONAL** pending a standards-range assignment (§3.1). |
| `content_type` | NPAMP-BRIDGE §4 | The ACL message encoding label, **UNCONFIRMED** (no code point assigned for a FIPA ACL encoding); agreed out of band or carried under Class OPAQUE (§3.2). |
| Channel `0x000D` (Bridge) | Core specification | Default and only channel for FIPA-ACL message carriage (§8). |
| Channel `0x0010` (Discovery) | Core specification | OPTIONAL channel for advertising FIPA-ACL carriage via NPAMP-DISC (§8). |
| Bridge frame types `0x0100`–`0x0103` | NPAMP-BRIDGE §2 | Reused unchanged for request / response / error / notification (§4). |
| BridgeEnvelope TLV `0x0010`, SafetyLabel TLV `0x0013` | Core specification; NPAMP-BRIDGE | Carried unchanged on every FIPA-ACL frame (§3, §7). |

This document requests no IANA action and defines no registry.

## 11. Confirmed versus unconfirmed, and security considerations

### 11.1 Confirmed versus unconfirmed

To keep this mapping honest (NPAMP companion index, OPAQUE-READY posture), the
following are stated explicitly:

- **Confirmed against FIPA-ACL's own Standard specifications** ([FIPA00061] Standard;
  [FIPA00037] Standard; both dated 2002/12/03): the thirteen message parameters and
  the mandatory status of the performative (§4.1, §5); the twenty-two communicative
  acts and their intents (§4.1); the `reply-with`/`in-reply-to` threading and the
  `conversation-id` semantics (§5); the multicast `receiver` set and the anonymous /
  self-asserted `sender` (§5.3, §6); and the transport-agnostic, multi-encoding nature
  of ACL (§3.2, §9). FIPA-ACL is a frozen, mature standard (last revised 2002; FIPA
  became an IEEE standards committee in 2005), so its surface is stable.
- **Unconfirmed / PROVISIONAL, and not fabricated here**: the `protocol_id` (no N-PAMP
  registry assignment — §3.1) and the `content_type` code point for a FIPA ACL encoding
  (none assigned — §3.2). Both are resolved by out-of-band agreement today and by an
  NPAMP-REG / core-registry assignment in the future; until then the row is OPAQUE-READY.

No value in this document is asserted beyond what §12's primary sources support.

### 11.2 Security considerations

This mapping introduces no cryptography and changes none. All confidentiality,
integrity, authentication, downgrade resistance, and replay protection are provided by
the core specification's wire format and key schedule and apply unchanged to every
FIPA-ACL frame, which travels inside the AEAD-protected Bridge payload; the
`protocol_id`, the projected performative, the SafetyLabel, and the ACL message are
authenticated and confidentiality-protected to the same degree (NPAMP-CC-MSG §11).
Carrying FIPA-ACL over N-PAMP makes no security claim about FIPA-ACL itself. In
particular:

- **Self-asserted sender.** FIPA's `sender` is unauthenticated by default (§6); treating
  it as an authenticated identity is an authorization vulnerability, because any peer can
  assert any `sender`. A receiver MUST require a verified `sender` binding (§6) or an
  independent authorization input before acting on an asserted identity (NPAMP-CC-MSG
  §11).
- **Performative is not a safety signal.** A performative declares communicative intent,
  not side-effect class; §7 forbids inferring a read-only/destructive judgement from the
  performative and requires fail-safe handling of an absent SafetyLabel (NPAMP-CC-MSG
  §11).
- **Projection integrity and conversation confusion.** The projected `method` and
  `correlation_id` are an index over the authoritative ACL message; a receiver MUST
  reject a frame whose projection disagrees with the carried message
  (`EnvelopeMalformed`; NPAMP-CC-MSG §8), and MUST keep `conversation-id` distinct from
  `correlation_id` to prevent cross-conversation response confusion (§5.2; NPAMP-CC-MSG
  §11).

## 12. References

Primary sources (FIPA specifications consulted for §3–§9; the two Standard documents
are normative for the vocabulary and parameters):

- [FIPA00061] FIPA ACL Message Structure Specification, **SC00061G (Standard,
  2002/12/03)** — the thirteen message parameters, the mandatory performative, and the
  `sender`/`receiver`/`reply-to`/`reply-with`/`in-reply-to`/`conversation-id`/`protocol`/`reply-by`/`language`/`encoding`/`ontology`/`content`
  semantics — <http://www.fipa.org/specs/fipa00061/SC00061G.html>
- [FIPA00037] FIPA Communicative Act Library Specification, **SC00037J (Standard,
  2002/12/03)** — the twenty-two communicative acts (sections 3.1–3.22) and their
  intents — <http://www.fipa.org/specs/fipa00037/SC00037J.html>
- [FIPA00070] FIPA ACL Message Representation in String Specification, SC00070I — the
  String encoding grammar (`Message = "(" MessageType MessageParameter* ")"`) and the
  message parameters (§2.2) — <https://fipa.org/specs/fipa00070/SC00070I.html>
- [FIPA00071] FIPA ACL Message Representation in XML Specification — the XML encoding
  (§3.2) — <http://www.fipa.org/specs/fipa00071/>
- [FIPA00069] FIPA ACL Message Representation in Bit-Efficient Encoding Specification —
  the bit-efficient encoding (§3.2) — <http://www.fipa.org/specs/fipa00069/>
- [FIPA00067] FIPA Agent Message Transport Service Specification — the MTS/ACC and the
  transport envelope that FIPA uses for transport, both subsumed by N-PAMP and out of
  scope here (§9) — <http://www.fipa.org/specs/fipa00067/>
- [FIPA00008] FIPA SL Content Language Specification — an example `language` for the
  `content` (§1.2) — <http://www.fipa.org/specs/fipa00008/>

N-PAMP documents built on:

- draft-bubblefish-npamp-01 — the N-PAMP core specification: the channel registry
  (Bridge `0x000D`, Discovery `0x0010`), the frame-type namespace (channel-specific
  types from `0x0100`), the extension-TLV encoding, and the AEAD payload protection.
- NPAMP-BRIDGE (`10_bridge_framework.md`) — the encapsulation, BridgeEnvelope,
  correlation, structured-error, and SafetyLabel contract.
- NPAMP-CC-MSG (`22_carriage_messaging.md`) — the messaging / performative carriage
  class that does the structural work for FIPA-ACL.
- NPAMP-CC-OPAQUE (`25_carriage_opaque.md`) — the universal carriage under which
  FIPA-ACL is carriable today (Status block; §3.2).
- NPAMP-REG (`30_protocol_registry.md`) — the Bridge Protocol Identifier registry; no
  `protocol_id` is assigned to FIPA-ACL (§3.1).
- NPAMP-DISC (`40_discovery.md`) — Discovery-channel advertisement referenced in §8.
- BCP 14: RFC 2119 and RFC 8174 — requirement key words.

## 13. Conformance

An implementation conforms to NPAMP-MAP-FIPA-ACL if and only if it conforms to
NPAMP-CC-MSG (and therefore to NPAMP-BRIDGE) and, for FIPA-ACL traffic, it:

1. Carries each FIPA ACL message octet-for-octet as the foreign message under the
   out-of-band-agreed experimental `protocol_id`, selecting FIPA-ACL solely from
   `protocol_id`, and never emits FIPA-ACL under a standards-range value NPAMP-REG has
   not assigned nor relies on an experimental value for cross-implementation
   interoperation (§3.1, §3.3);
2. Does not fabricate a `content_type` for a FIPA ACL encoding, carrying the message
   under an out-of-band-agreed `content_type` or under Class OPAQUE, and never conflates
   the FIPA `encoding` parameter with the BridgeEnvelope `content_type` (§3.2, §5.4);
3. Projects the performative onto the BridgeEnvelope `method` field verbatim, carries
   any of the twenty-two communicative acts (and MUST NOT reject a message solely
   because its performative is absent from §4.1's table), and reports an uncarried
   performative as `MethodUnsupported` (§4.1);
4. Classifies each message's reply discipline by its own `reply-with`/`in-reply-to`/
   `protocol`/`reply-by` parameters in preference to any per-performative default —
   BRIDGE_REQUEST for a message that expects a reply, BRIDGE_RESPONSE (or BRIDGE_ERROR
   for a failure act) for a reply echoing the request's `correlation_id`, and
   BRIDGE_NOTIFY (`corr_len = 0`) for a one-way message — with `message_kind` agreeing
   with the frame type (§4.2, §4.3);
5. Derives the BridgeEnvelope `correlation_id` from the `reply-with` token where present
   (else a fresh unique token), keeps FIPA's `conversation-id` distinct inside the body
   and never overloads it onto `correlation_id`, and carries `receiver` (including a
   multicast set), `reply-to`, `content`, `language`, `encoding`, `ontology`, and
   `reply-by` verbatim without projecting them (§5);
6. Treats the `sender` as self-asserted unless a configured policy binds it to the
   originating peer's N-PAMP handshake identity, never treats a self-asserted or omitted
   `sender` as authenticated, and applies any binding only to the originating peer's own
   assertion (§6);
7. Derives every SafetyLabel `effect` from the action in the message `content`, never
   from the performative; attaches a SafetyLabel to every message that can mutate state
   (at least the minimum class of §7 for `subscribe`/`cancel`/`proxy`/`propagate` and a
   content-derived class for the action-requesting acts); treats a missing SafetyLabel on
   any state-mutating message as `destructive`; and never treats a favorable SafetyLabel
   or a verified `sender` binding as authorization (§7);
8. Carries a FIPA conversation on the Bridge channel `0x000D`, does not split one
   `conversation-id` across channels or associations, sends or accepts FIPA-ACL frames
   only on advertised channels, and uses the Discovery channel `0x0010` only for the
   OPTIONAL carriage advertisement of §8 (§8); and
9. Carries only the ACL message as the foreign message — never a FIPA MTS transport
   envelope — and carries no FIPA conversational state across associations at the N-PAMP
   layer (§9), defining no new frame type, TLV, or code point and consuming only those
   enumerated in §10 (§9, §10).

A conformance test suite SHOULD assert each clause above with recorded exchanges that
include: a `request` bearing a `reply-with`, carried as BRIDGE_REQUEST with its
`reply-with` as the `correlation_id`, and its `agree`/`inform` reply carrying the
matching `in-reply-to` and echoing the `correlation_id`; an unsolicited `inform` carried
as BRIDGE_NOTIFY with `corr_len = 0`; a `failure` act carried as BRIDGE_ERROR verbatim;
a `request` whose SafetyLabel effect is derived from a destructive action in its
`content`, and a second identical `request` with the SafetyLabel omitted, verified to be
treated as `destructive`; a `subscribe` carried with an `idempotent_write` SafetyLabel; a
message with a multicast `receiver` set carried with the set intact; a message with a
`conversation-id` verified to remain in the body and distinct from the `correlation_id`;
a self-asserted `sender` and a `sender` under a configured identity binding; and an
envelope whose projected performative disagrees with the carried message, verified to be
rejected as `EnvelopeMalformed`.
