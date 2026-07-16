# NPAMP-CC-MSG — Messaging / Performative Carriage Class (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words MUST, MUST NOT, REQUIRED,
> SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL are to be
> interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they
> appear in all capitals, as shown here. This document defines the **Messaging carriage
> class (NPAMP-CC-MSG)**: the carriage of message-passing and performative (speech-act)
> agent-communication protocols over the N-PAMP Bridge channel `0x000D`. It builds on
> **NPAMP-BRIDGE** (the bridge framework) and **draft-bubblefish-npamp-01** (the core
> specification). It consumes only code points the core specification and NPAMP-BRIDGE
> already reserve, and it introduces no change to the core wire format.

## 1. Scope

### 1.1 What this document carries

A *message-passing* or *performative* protocol communicates by exchanging messages each
of which is labelled with a **performative** — a speech act such as `inform`, `request`,
`query-ref`, `agree`, `refuse`, `propose`, or `failure` — that declares the
communicative intent of the message independently of its content. Protocols in this
family (the FIPA Agent Communication Language family, and message-passing
agent-communication languages with the same shape) carry, alongside the performative, a
small set of well-known message parameters: a **sender**, one or more **receivers**, a
**conversation identifier** that groups related messages into a dialogue, an
**ontology** that names the vocabulary the content is expressed in, a
**content-language** that names the formal language the content is encoded in, and
dialogue-threading parameters such as a **reply-with** token and an **in-reply-to**
token.

This document defines how such a message is carried over N-PAMP: how its performative
and its dialogue-threading parameters are projected onto the NPAMP-BRIDGE envelope, and
how the message itself is carried verbatim. It is a **carriage class**: it specifies the
structural carriage common to the whole family. A per-protocol mapping document (for
example a FIPA-ACL mapping) pins protocol-specific particulars — the protocol's
identifier, its performative vocabulary, and its parameter names — against that
protocol's own published specification; this class does the structural work.

### 1.2 Relationship to NPAMP-BRIDGE

NPAMP-CC-MSG is a **profile of NPAMP-BRIDGE**, not a replacement for it. Every
requirement of NPAMP-BRIDGE applies unchanged to a message carried under this class:
The foreign message is carried octet-for-octet (NPAMP-BRIDGE §1), the BridgeEnvelope TLV
is REQUIRED (NPAMP-BRIDGE §4), correlation is enforced by identifier (NPAMP-BRIDGE §5),
foreign errors are preserved (NPAMP-BRIDGE §6), the SafetyLabel TLV governs side effects
(NPAMP-BRIDGE §7), and one-way messages carry no reply (NPAMP-BRIDGE §8). This document
adds only the rules that are specific to the performative message shape; where this
document is silent, NPAMP-BRIDGE governs.

### 1.3 Not in scope

The following are explicitly NOT defined by this document:

1. **No new wire fields, frame types, TLV types, or channels.** This class reuses the
   NPAMP-BRIDGE frame types and the BridgeEnvelope and SafetyLabel TLVs as the core
   specification and NPAMP-BRIDGE define them. It reserves nothing of its own. (See §9 for
   an OPEN QUESTION on an OPTIONAL future metadata TLV that would require a code point not
   reserved at the time of writing.)
2. **No performative vocabulary.** The set of performatives, their preconditions, and
   their feasibility/rational-effect semantics belong to the carried protocol's own
   specification and to its per-protocol mapping document. This class transports a
   performative label; it does not interpret it.
3. **No content-language or ontology processing.** The message content, the ontology it
   draws on, and the content-language it is encoded in are carried verbatim inside the
   foreign message. This class does not parse, validate, translate, or reason over
   content, ontologies, or content-languages.
4. **No sender authentication of its own.** This class does not establish, attest, or
   verify the identity asserted in a message's sender parameter (§6). It defines only how
   a self-asserted sender is carried and how a verified binding, when one exists, is
   represented.
5. **No multicast or receiver-set fan-out.** An N-PAMP association is point-to-point. A
   message addressed to multiple receivers is carried as defined in §5.3; this document
   does not define fan-out delivery to a receiver set across associations.

## 2. Terminology

In addition to the terms of the core specification and NPAMP-BRIDGE:

Performative:
: The speech-act label of a message, declaring its communicative intent (for example
  `inform`, `request`, `agree`). Carried as the BridgeEnvelope `method` field (§4).

Conversation:
: A sequence of messages exchanged between agents that are grouped, by a shared
  conversation identifier, as one logical dialogue.

Conversation identifier:
: The protocol's own token that groups messages into a conversation. Distinct from the
  per-message correlation identifier of NPAMP-BRIDGE (§5).

Sender:
: The agent identifier that a message asserts as its originator. Self-asserted unless
  bound to an N-PAMP identity (§6).

Receiver:
: An agent identifier that a message asserts as an intended recipient.

Message metadata:
: The well-known message parameters other than content — performative, sender, receiver,
  conversation identifier, ontology, content-language, and dialogue-threading tokens.

## 3. Carriage model

### 3.1 Carriage by projection plus verbatim body

A performative message is carried by **projecting** two of its parameters onto the
NPAMP-BRIDGE envelope and carrying the **entire message verbatim** as the foreign
message:

```
  BridgeEnvelope TLV   (Type 0x0010, REQUIRED)
      protocol_id      = the message-passing protocol's identifier (§4.1)
      message_kind     = derived from the performative class (§4.2)
      content_type     = the foreign-message encoding (§4.3)
      method           = the performative label (§4.4)
      correlation_id   = the dialogue-threading token (§5)
  SafetyLabel TLV      (Type 0x0013, OPTIONAL; REQUIRED per §7)
  <foreign message>    (the complete performative message, carried verbatim)
```

The projection is a **non-destructive index**, not a re-serialization. The performative
and the dialogue-threading token are projected into the envelope so that an N-PAMP
implementation can route, correlate, and apply safety policy **without parsing the
foreign message**; the message's own copy of those parameters, and every other parameter
(sender, receiver, conversation identifier, ontology, content-language, content), remain
present and authoritative inside the verbatim body.

A receiver MUST treat the foreign message as the authoritative source of every message
parameter. Where a projected envelope field and the foreign message's own field disagree,
the foreign message's field is authoritative for protocol semantics; see §8 for the
handling of such a disagreement.

### 3.2 Transparency is preserved

Because the message is carried octet-for-octet (NPAMP-BRIDGE §1), this class does not
canonicalize, reorder, re-encode, or strip any message parameter. A self-asserted sender,
an omitted optional parameter, and the message's own encoding are all preserved exactly
as the originating agent emitted them. An implementation MUST NOT rewrite the foreign
message to add, remove, normalize, or reconcile a projected parameter.

## 4. Mapping onto the BridgeEnvelope

### 4.1 protocol_id

The `protocol_id` field of the BridgeEnvelope identifies the message-passing protocol
being carried, drawn from the Bridge Protocol Identifier value space defined by
NPAMP-BRIDGE (`protocol_id`, §4). A per-protocol mapping document assigns the value used
for a given protocol; until such an assignment is registered, a deployment carrying a
message-passing protocol MUST use a value from the experimental range that NPAMP-BRIDGE
designates for the `protocol_id` field, and the two peers MUST agree on that value out of
band. This document does not assign any `protocol_id` value (§9, OPEN QUESTION 1).

### 4.2 message_kind and frame type

The performative determines the NPAMP-BRIDGE message kind and, with it, the frame type,
according to the performative's **reply discipline**:

| Performative class | message_kind | Frame type | Reply discipline |
|---|---|---|---|
| Expects exactly one reply (for example a `request` or `query-ref` that names a reply token) | 0x01 request | BRIDGE_REQUEST `0x0100` | A single reply, correlated per §5. |
| Is itself a reply to an earlier request (for example `agree`, `refuse`, `inform` answering a `query`, `failure`) | 0x02 response, or 0x04 error | BRIDGE_RESPONSE `0x0101`, or BRIDGE_ERROR `0x0102` | Echoes the originating request's correlation identifier (§5). |
| Expects no reply (a one-way announcement, for example an unsolicited `inform`) | 0x03 notification | BRIDGE_NOTIFY `0x0103` | No reply; `corr_len` MUST be 0 (NPAMP-BRIDGE §8). |

The `message_kind` field MUST agree with the frame type (NPAMP-BRIDGE §4). A per-protocol
mapping document MUST specify, for each performative in the carried protocol's
vocabulary, which class of the table above it falls into, because that classification is
protocol-defined and cannot be inferred from the performative label alone. Where the
carried protocol's own parameters determine the reply discipline of an individual
message (for example, the presence or absence of a reply-with token), an implementation
MUST classify that message by those parameters in preference to a default for the
performative.

A failure reply MUST use BRIDGE_ERROR with `message_kind` 0x04 only when it reports a
**foreign-protocol-level** failure carried as the protocol's own error or failure message
(for example a `failure` performative); a failure *below* the foreign protocol (the
message did not reach the foreign endpoint) is reported as an N-PAMP transport error per
NPAMP-BRIDGE §6 and §4.6 of this document.

### 4.3 content_type

The `content_type` field of the BridgeEnvelope carries the encoding of the foreign
message as a whole (for example `application/json` for a JSON-encoded message), drawn
from the values NPAMP-BRIDGE defines. The content-language and ontology of the *message
content* are message parameters carried inside the verbatim body (§5.4); they are NOT the
BridgeEnvelope `content_type` and MUST NOT be projected onto it.

### 4.4 method (the performative)

The BridgeEnvelope `method` field carries the message's **performative label** as a
UTF-8 string (for example `inform`, `request`, `query-ref`). The value MUST be the
performative exactly as it appears in the foreign message, with no case folding,
abbreviation, or translation. A receiver MUST NOT rely on the projected `method` value as
the authoritative performative for protocol semantics; it is an index into the
authoritative performative carried in the foreign message (§3.1). A receiver that does
not carry the indicated performative reports `MethodUnsupported` per NPAMP-BRIDGE §6.

A message whose protocol carries no performative concept is outside the scope of this
class and SHOULD be carried under a different carriage class.

## 5. Conversation, correlation, and message parameters

### 5.1 Correlation identifier versus conversation identifier

NPAMP-BRIDGE correlation (§5) and a message-passing protocol's conversation identifier
are **distinct**, and this class keeps them distinct:

- The NPAMP-BRIDGE **correlation identifier** correlates exactly one reply to exactly one
  request, within one direction on the Bridge channel. It is consumed by the N-PAMP layer
  to match a BRIDGE_RESPONSE/BRIDGE_ERROR to its BRIDGE_REQUEST.
- The protocol's **conversation identifier** groups an arbitrary number of messages —
  across many request/reply exchanges and in both directions — into one logical dialogue.
  It is a protocol-level concept consumed by the carried protocol's agents.

An implementation MUST NOT overload one onto the other. The conversation identifier MUST
remain inside the verbatim foreign message and MUST NOT be substituted for the
correlation identifier, and the correlation identifier MUST NOT be assumed to equal the
conversation identifier.

### 5.2 Deriving the correlation identifier

For a message carried as BRIDGE_REQUEST (§4.2), the BridgeEnvelope `correlation_id` MUST
be a non-empty token, unique among the originating peer's outstanding requests on the
channel in that direction (NPAMP-BRIDGE §5). The originating peer MUST derive it as
follows, in order of preference:

1. If the message carries a **reply-with** token (the protocol's own per-message token
   that the responder is asked to echo as an in-reply-to), the originating peer SHOULD use
   that token as the `correlation_id`, provided it satisfies the uniqueness requirement
   above.
2. Otherwise, the originating peer MUST generate a fresh `correlation_id` that satisfies
   the uniqueness requirement.

A reply message (BRIDGE_RESPONSE or BRIDGE_ERROR) MUST echo the originating request's
`correlation_id` verbatim (NPAMP-BRIDGE §5), regardless of how that identifier was
derived. Echoing the correlation identifier at the N-PAMP layer does not relieve the
responding agent of carrying the protocol's own in-reply-to token inside the foreign
message when the protocol requires it; the two are carried independently.

### 5.3 Receivers and addressing

The message's receiver parameter (or receiver set) is carried inside the verbatim foreign
message and is NOT projected onto the envelope. Carriage over a point-to-point N-PAMP
association delivers the message to the single peer at the other end of the Bridge
channel; the foreign message's receiver parameter remains authoritative for the carried
protocol's addressing semantics. A message naming more than one receiver is carried with
its full receiver set intact; this class does not fan the message out to multiple
associations (§1.3, item 5).

### 5.4 Ontology and content-language

The ontology and content-language parameters are carried inside the verbatim foreign
message and MUST NOT be projected onto the BridgeEnvelope. This class does not require
either parameter to be present, does not supply a default for an absent parameter, and
does not validate content against an ontology or a content-language. Their presence,
absence, and values are preserved exactly as emitted.

## 6. Sender identity

### 6.1 Sender is self-asserted by default

The sender parameter of a carried message is an identifier that the originating agent
**asserts** about itself. In the general case it is **self-asserted**: the message-passing
protocols in scope carry a sender parameter that the sending agent populates and that the
protocol itself does not authenticate, sign, or bind to any external identity. A receiver
MUST NOT treat a self-asserted sender as an authenticated identity, and MUST NOT grant an
authorization decision on the basis of a self-asserted sender alone.

This class carries the self-asserted sender verbatim inside the foreign message (§3.2). It
neither strengthens nor weakens the assertion: it does not add authentication the
protocol lacks, and it does not strip the parameter.

### 6.2 Binding to an N-PAMP identity

An N-PAMP association authenticates both peers during the handshake (core specification,
Protocol Overview and Security Considerations). A deployment MAY treat the
handshake-authenticated identity of the peer that **originates** a carried message as a
**verified binding** for that message's sender, under a locally configured policy that
maps the carried protocol's sender identifier to the N-PAMP peer identity. When such a
binding is in force:

- A receiver MAY rely on the bound, handshake-authenticated identity for an authorization
  decision in place of the self-asserted sender.
- A receiver MUST reject (or, per local policy, downgrade to self-asserted) a message
  whose self-asserted sender does not match the binding the policy requires for the
  originating peer, because a sender that disagrees with the authenticated origin is an
  identity-spoofing indicator.
- The binding applies only to the **originating peer's own** sender assertion. A message
  that asserts a sender other than the originating peer (for example a relayed or
  forwarded message) MUST NOT be treated as verified by this binding.

In the absence of such a configured binding, the sender remains self-asserted (§6.1) and
this class makes no identity claim about it.

### 6.3 No new identity machinery

This class defines no TLV, frame, or handshake element for sender identity. The verified
binding of §6.2 is an application of the N-PAMP handshake identity that the core
specification already establishes, governed by local policy; it is not a new wire
mechanism, and it introduces no code point.

## 7. Side effects and safety

A performative does not by itself reveal whether acting on a message mutates state: a
`request` may ask for a read-only computation or for a destructive action, and the
distinction is in the content, not the performative. Therefore:

- When a carried message, if acted upon by the receiving agent, can cause a side effect,
  the sender MUST attach a SafetyLabel TLV (NPAMP-BRIDGE §7) describing the effect, exactly
  as NPAMP-BRIDGE requires for any state-mutating request. An intermediary MUST carry the
  SafetyLabel unchanged.
- A receiver MUST NOT infer `read_only` from the performative label. In particular, a
  receiver MUST NOT treat a `request`, `propose`, or `query` performative as read-only on
  the basis of the label.
- Consistent with NPAMP-BRIDGE §7, the absence of a SafetyLabel on a message that can
  mutate state MUST be treated as `destructive` (fail-safe), not as `read_only`.

The SafetyLabel describes intent and does not replace authorization (NPAMP-BRIDGE §7); a
verified sender binding (§6.2) and a SafetyLabel are complementary inputs to a receiver's
authorization decision, not substitutes for it.

## 8. Envelope/message disagreement

Because the performative and the dialogue-threading token appear both as projected
envelope fields (§4.4, §5.2) and inside the authoritative foreign message (§3.1), the two
can disagree if a sender projects incorrectly or an intermediary tampers with the
envelope. A receiver MUST detect and handle such a disagreement:

- The foreign message's parameters are authoritative for protocol semantics (§3.1). A
  receiver MUST act on the performative and parameters carried in the foreign message, not
  on the projected envelope values, when it parses the message.
- A receiver that detects a disagreement between the projected `method` and the message's
  own performative, or between the derived `correlation_id` and a reply-with token the
  message carries, MUST treat the frame as malformed and report `EnvelopeMalformed`
  (NPAMP-BRIDGE §6), because the index does not match the indexed message and routing or
  correlation performed on the projection would be unsound.
- A receiver MUST NOT silently "repair" a disagreement by overwriting either side; it
  rejects the frame so the originator can re-send a consistent one.

## 9. Errors

This class adds no error codes. Failures are reported exactly as NPAMP-BRIDGE §6 defines:

- A **foreign-protocol-level** failure (for example a `failure` or `refuse` performative,
  or the protocol's own error message) is carried as BRIDGE_ERROR whose foreign message is
  the protocol's own failure message, verbatim (NPAMP-BRIDGE §4.2 / §6). An implementation
  MUST NOT reduce such a failure to free text.
- A failure **below** the foreign protocol — a malformed envelope, an unsupported
  protocol, an unsupported performative, a message that could not be delivered to the
  foreign endpoint, or a local safety refusal — is reported with the corresponding
  NPAMP-BRIDGE transport error code (`EnvelopeMalformed`, `ProtocolUnsupported`,
  `MethodUnsupported`, `NotDelivered`, `SafetyPolicy`). An unsupported performative is
  reported as `MethodUnsupported` (§4.4); an envelope/message disagreement is reported as
  `EnvelopeMalformed` (§8).

## 10. Conformance

An implementation conforms to NPAMP-CC-MSG if and only if, on the Bridge channel and in
addition to conforming to NPAMP-BRIDGE, it:

1. Carries each performative message octet-for-octet as the foreign message, with every
   message parameter — performative, sender, receiver(s), conversation identifier,
   ontology, content-language, and content — preserved exactly as emitted (§3, §5.3,
   §5.4);
2. Projects the performative onto the BridgeEnvelope `method` field unchanged, and the
   message kind and frame type from the performative's reply discipline as classified by
   the per-protocol mapping, with `message_kind` agreeing with the frame type (§4);
3. Keeps the NPAMP-BRIDGE correlation identifier distinct from the protocol's
   conversation identifier, never overloading one onto the other, and derives the
   correlation identifier per §5.2;
4. Treats the sender as self-asserted unless a configured policy binds it to the
   handshake-authenticated identity of the originating peer, and never treats a
   self-asserted sender as authenticated (§6);
5. Attaches and honors the SafetyLabel for any message that can mutate state, never
   inferring `read_only` from a performative and fail-safing on an absent label (§7);
6. Detects an envelope/message disagreement and rejects the frame rather than repairing it
   (§8); and
7. Reports foreign-protocol failures as preserved foreign error messages and
   below-protocol failures as the corresponding NPAMP-BRIDGE transport error codes,
   adding no error codes of its own (§9).

A conformance test suite SHOULD assert each clause above with recorded exchanges that
include: a request-bearing performative correlated to its reply; a one-way (no-reply)
performative; a message carrying an ontology and a content-language; a state-mutating
message with and without a SafetyLabel; a self-asserted sender and a sender under a
configured identity binding; and an envelope whose projected performative disagrees with
the carried message.

## 11. Security considerations

This document inherits the security considerations of the core specification and of
NPAMP-BRIDGE and adds the following.

**Self-asserted sender.** The sender parameter of a carried message is self-asserted and
unauthenticated by default (§6.1). Treating it as an authenticated identity is an
authorization vulnerability: any peer can assert any sender. An implementation MUST require
either a verified sender binding (§6.2) or an independent authorization input before acting
on a sender's asserted identity. The N-PAMP handshake authenticates the *peer at the other
end of the association*; binding that authenticated identity to a message's sender is the
only sender authentication this class offers, and it covers only the originating peer's own
assertion, not relayed senders.

**Performative is not a safety signal.** A performative declares communicative intent, not
side-effect class. Deriving a read-only/destructive judgement from the performative would
let a destructive action ride a benign-looking label; §7 forbids it and requires fail-safe
handling of an absent SafetyLabel.

**Projection integrity.** The projected envelope fields (§4, §5.2) are an index over the
authoritative foreign message. A tampered projection could mis-route or mis-correlate a
message whose body is intact. The whole frame, including the BridgeEnvelope TLV, is covered
by the N-PAMP AEAD protection of the core specification, so an off-path attacker cannot
alter the projection undetected; §8 additionally requires a receiver to reject any frame
whose projection disagrees with its carried message, closing the gap against a
mis-projecting originator.

**Conversation-identifier confusion.** Overloading the protocol's conversation identifier
onto the NPAMP-BRIDGE correlation identifier (§5.1) could let one conversation's messages
be correlated as replies to another's, enabling response confusion. Keeping the two
identifiers distinct, as §5.1 requires, prevents this.

**No content processing.** This class does not parse message content, ontologies, or
content-languages (§1.3). It therefore introduces no content-parsing attack surface of its
own; the security of content interpretation is the responsibility of the receiving agent
and the carried protocol's specification.

## 12. Relationship to other companion specifications

NPAMP-CC-MSG is one carriage class of the N-PAMP companion set. It inherits NPAMP-BRIDGE
in full (§1.2). A per-protocol mapping document for a specific message-passing protocol
selects this class, assigns the protocol's `protocol_id`, and pins the protocol's
performative vocabulary and parameter names; that mapping does the protocol-specific work,
while this class does the structural work common to the family. Until a per-protocol
mapping is published, a message-passing protocol remains carriable through the opaque
carriage class, with the metadata-projection benefits of this class becoming available
once its mapping is registered.

---

## Appendix A. Open questions for the maintainer

These items require a maintainer decision and are recorded here, outside the normative
text, so that the normative text consumes no code point that the core specification or
NPAMP-BRIDGE has not already reserved.

**OPEN QUESTION 1 — No `protocol_id` is assigned to any message-passing protocol.** The
BridgeEnvelope `protocol_id` value space (NPAMP-BRIDGE §4: `0x01`–`0x04` assigned,
`0x10`–`0x7F` experimental, `0x80`–`0xFF` private use) assigns no value to a message-passing
protocol, and the protocol-identifier registry (NPAMP-REG) is not yet published. This
document therefore directs deployments to the experimental range with out-of-band
agreement (§4.1). A maintainer decision is needed on whether to assign a stable
`protocol_id` for the first message-passing protocol (for example the FIPA-ACL family) in
NPAMP-REG, and which value.

**OPEN QUESTION 2 — A dedicated MessageEnvelope TLV is intentionally NOT defined.** Sender,
receiver, conversation identifier, ontology, and content-language are carried inside the
verbatim foreign message (§5), not in a dedicated TLV, because routing/correlation/safety
need only the performative (projected to `method`) and a correlation token, and because no
carriage-class TLV code point is available to define one: the core specification reserves
TLV tags `0x0010`, `0x0013`, and `0x0014` for companion specifications, NPAMP-BRIDGE has
consumed `0x0010` (BridgeEnvelope) and `0x0013` (SafetyLabel), and the only remaining
reserved companion tag, `0x0014`, is reserved as **handshake-only** and **fixed
32-octet** in the core TLV registry — unsuitable for a variable-length, per-message
metadata TLV. If a future need arises to project message metadata into a typed TLV (for
example to let an intermediary route on conversation identifier without parsing the body),
the core specification would have to reserve an additional, variable-length,
per-frame-eligible companion TLV tag for it. A maintainer decision is needed on whether to
request that reservation; absent it, the verbatim-body carriage of this document is the
complete and code-point-clean design.

**OPEN QUESTION 3 — Sender-binding policy is deployment-local.** The verified sender
binding (§6.2) is governed by local policy mapping a carried protocol's sender identifier
to an N-PAMP peer identity. Whether the companion set should standardize a binding
descriptor (so two peers can agree on the mapping in band rather than out of band) is a
maintainer decision; standardizing one would require its own representation and, if carried
on the wire, a reserved code point not available today (see OPEN QUESTION 2).
