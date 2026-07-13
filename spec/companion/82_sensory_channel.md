# NPAMP-SENSORY — Sensory Channel Bulk-Telemetry Companion (companion to draft-bubblefish-npamp-02)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document defines a concrete bulk-observation encoding over the N-PAMP
> **Sensory channel `0x0009`** ("Bulk telemetry and low-priority observations",
> minimum profile **High**, direction Multi-stream): how a peer pushes typed sensor
> readings in bulk, how a peer subscribes to a continuing stream of those readings,
> and how a consumer bounds a bulk producer with explicit credit. It is a
> **native-core-channel** operation companion — it does not encapsulate a foreign
> agent protocol and does not build on the Bridge channel `0x000D`. It consumes only
> channel-application frame-type code points the core specification
> (draft-bubblefish-npamp-02, the "core specification") reserves at `0x0100` and
> above on the Sensory channel, introduces no change to the core wire format, and
> defines no extension TLV. **The core specification governs**: on any disagreement
> between this document and the core specification, the core specification is
> authoritative.

## 1. Scope

### 1.1 In scope

This document specifies, over the Sensory channel `0x0009` of the core
specification (draft-bubblefish-npamp-02):

1. A set of Sensory-channel frame types (§3), drawn from the channel-application
   frame-type band that begins at `0x0100` (core specification §4.6);
2. The encoding of an **observation batch** — a deterministically encoded CBOR
   payload carrying one or more typed sensor readings, each with a source
   identifier, timestamp, unit, value, and optional quality (§5);
3. A subscribe / acknowledge / unsubscribe lifecycle scoping which observations a
   peer pushes to a subscriber (§6);
4. A consumer-driven **credit** backpressure mechanism (§7) that bounds a bulk
   producer per subscription, honoring the channel's low-priority, deprioritizable
   posture; and
5. A structured error model for failures of the subscribe and credit exchange (§8),
   together with an operation and state model (§9).

### 1.2 Not in scope

This document does NOT (each exclusion carries its reason):

* **Define, publish, or rely on the High or Sovereign cryptographic suites,
  parameters, or key schedule** — reason: those are selected by the core
  specification's Profile Negotiation and are firewall-gated above the High profile;
  they are out of scope for this public reference (§2).
* **Assign physical meaning, calibration, or provenance to any reading or unit** —
  reason: this document is generic telemetry transport; the sensor domain, its
  calibration, and the trustworthiness of a reading are the deploying application's
  concern (§10).
* **Change any field of the 36-octet core frame header, any reserved all-channel
  frame type, the extension-TLV encoding, or any code point or invariant the core
  specification assigns** — reason: those are fixed by the core specification and
  this document reserves none of them (§3).
* **Provide connection-level flow control** — reason: connection-level flow control
  is the core FLOW_UPDATE frame `0x000A`; the §7 credit mechanism is an
  application-layer, per-subscription control layered above it, not a replacement
  for it.
* **Guarantee delivery, exactly-once delivery, replay of dropped batches, or
  cross-source ordering** — reason: the Sensory channel is explicitly low-priority
  and deprioritizable during congestion (core specification §5); §5.3 provides only
  per-source and per-batch monotonic sequence numbers for gap detection, and nothing
  more.

## 2. Relationship to the core specification and the profile gate

The Sensory channel `0x0009` is registered by the core specification with purpose
"Bulk telemetry and low-priority observations", minimum profile **High**, and
direction **Multi-stream** (core specification §5, Core Channel Registry). Two
consequences bind this companion:

* **Profile gate (firewall).** Because the Sensory channel's minimum profile is
  High, the channel — and therefore this companion — MAY be enabled only once a peer
  has negotiated the **High or Sovereign** profile; it MUST NOT be enabled at the
  Standard profile. A peer that has not advertised the Sensory channel for the
  association during the handshake (core specification §5) MUST NOT accept frames on
  it, and any frame received on an unadvertised Sensory channel MUST be dropped.
* **Multi-stream direction.** The Sensory channel is bidirectional and MAY open
  multiple concurrent transport streams within its stream family; each peer
  maintains an independent per-direction sequence space and independent
  per-direction traffic keys (core specification §5). Either peer MAY originate a
  SENSORY_SUBSCRIBE or push a standalone SENSORY_OBSERVE.

Because the Sensory channel is one of the core specification's **bulk** channels,
the Control and Immune channels SHOULD be scheduled ahead of it during congestion
(core specification §5). Consistent with that low-priority posture, an
implementation **MUST NOT** set the frame header **URG** flag (urgent) on any
Sensory frame: urgent-priority scheduling contradicts the channel's low-priority,
deprioritizable purpose, and a bulk observation stream MUST NOT be allowed to usurp
the scheduling of interactive or control traffic.

This companion is a **native core-channel** operation companion. Unlike the Bridge
channel `0x000D`, which encapsulates foreign agent protocols and is elaborated by
NPAMP-BRIDGE and its carriage classes, the Sensory channel carries no foreign
protocol; this document defines a first-party observation encoding directly in the
channel's own application frame band. It reuses one facility of NPAMP-BRIDGE by
reference — the **correlation discipline** of NPAMP-BRIDGE §5, in which a reply
echoes its request's correlation identifier verbatim and replies are matched by that
identifier rather than by frame sequence number (§4.1) — and otherwise defines its
own contract.

## 3. Sensory-channel frame types

The core specification partitions the per-channel frame-type namespace into four
bands (core specification §4.6):

* `0x0000`–`0x000A` — reserved all-channel frame types (`0x0000` reserved; PING
  `0x0001` … FLOW_UPDATE `0x000A`), with the same meaning on every channel;
* `0x000B`–`0x002F` — reserved for future core use (a gap; unused here);
* `0x0030`–`0x00FF` — the companion-extension band; and
* `0x0100`–`0xFFFF` — the channel-application band, in which a channel's own
  operational frames are defined.

This document defines its operational frames in the **channel-application band**, at
`0x0100` and above on the Sensory channel:

| Type | Name | Reply | Purpose |
|---|---|---|---|
| `0x0100` | SENSORY_OBSERVE | None | A batch of typed sensor observations pushed one-way; no reply is expected or permitted. |
| `0x0101` | SENSORY_SUBSCRIBE | SENSORY_SUB_ACK or SENSORY_ERROR | Request a continuing stream of OBSERVE batches matching a filter, carrying an initial credit grant. |
| `0x0102` | SENSORY_SUB_ACK | None | Accepts a subscription; echoes `corr`; returns the granted terms (subscription id, effective credit, source set). |
| `0x0103` | SENSORY_UNSUBSCRIBE | None | Cancels a subscription; echoes `corr`; no reply (idempotent). |
| `0x0104` | SENSORY_CREDIT | None | Consumer replenishes or updates per-subscription batch credit (backpressure); echoes `corr`. |
| `0x0105` | SENSORY_ERROR | None | Structured failure of a subscribe or credit request; echoes the `corr` of the request it answers. |

The reserved all-channel frame types (`0x0001`–`0x000A`, PING … FLOW_UPDATE) retain
their core meaning on the Sensory channel. An implementation MUST NOT reuse them for
Sensory application traffic, and MUST NOT define Sensory semantics in the reserved
all-channel range, in the future-core gap `0x000B`–`0x002F`, or in the
companion-extension band `0x0030`–`0x00FF`. All six frame types defined above lie
within the Sensory channel's own channel-application band at or above `0x0100`; this
document consumes no frame-type code point outside that band and defines no
extension TLV.

## 4. Payload encoding (deterministic CBOR)

A Sensory frame's payload — the octets after the 36-octet core frame header and
before the AEAD tag — is a single **deterministically encoded CBOR** map, as defined
by the core specification's Payload Encoding clause (core specification §4.5) and
its deterministic-encoding requirement (core specification §11.9; RFC 8949). A
sender MUST produce the deterministic encoding: byte-identical output for identical
inputs, with the canonical key ordering and shortest-form integer encoding RFC 8949
§4.2 requires. The payload MUST be a CBOR map whose keys are the unsigned integers
defined in §4.1, §5, §6, §7, and §8 for the relevant frame type.

A receiver MUST reject — with a SENSORY_ERROR carrying code `MalformedPayload` (§8)
— any Sensory payload that is not a valid deterministic-CBOR map, that omits a
required key, or that uses a key of the wrong CBOR major type.

**Forward compatibility.** A receiver MUST ignore an unrecognized integer key whose
value is **non-negative**, so that later revisions of this document MAY add fields
without breaking a conformant receiver. A receiver MUST reject — with a SENSORY_ERROR
carrying code `MalformedPayload` (§8) — a payload that carries an unrecognized
integer key whose value is **negative**, reserving the negative-key space for
forward-incompatible additions. This document defines and consumes no extension-TLV
tag.

### 4.1 Common envelope

Every Sensory payload map carries the following common envelope fields. Integer keys
are given in parentheses.

| Field (key) | CBOR type | Meaning |
|---|---|---|
| `frame_kind` (0) | Unsigned int | MUST equal the frame's Sensory frame type (`0x0100`–`0x0105`). A receiver MUST reject (SENSORY_ERROR, code `KindMismatch`) a payload whose `frame_kind` contradicts the frame-header Frame Type. |
| `corr` (1) | Byte string (1–64 B) | Correlation identifier. REQUIRED and non-empty on SENSORY_SUBSCRIBE, and unique among the originating peer's outstanding subscriptions in that direction; echoed verbatim by SENSORY_SUB_ACK, SENSORY_CREDIT, SENSORY_UNSUBSCRIBE, SENSORY_ERROR, and by any SENSORY_OBSERVE emitted under that subscription. ABSENT on a standalone (unsolicited) SENSORY_OBSERVE. |

A receiver MUST match each reply, credit update, or subscribed observation to its
originating subscription by `corr`, not by frame sequence number, exactly as
NPAMP-BRIDGE §5 requires for Bridge replies. A standalone SENSORY_OBSERVE — one not
sent under any subscription — MUST omit `corr`.

## 5. SENSORY_OBSERVE body (`0x0100`)

A SENSORY_OBSERVE carries a batch of one or more observations. Its payload carries
the common envelope (§4.1) and:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `frame_kind` (0) | Unsigned int | Yes | MUST equal `0x0100`. |
| `corr` (1) | Byte string (1–64 B) | Cond | Present if and only if this batch answers a subscription; absent on an unsolicited push (§4.1). |
| `sub_id` (2) | Byte string (1–32 B) | Cond | The subscription identifier (from SENSORY_SUB_ACK, §6.2) this batch satisfies. Present if and only if `corr` is present. |
| `batch_seq` (3) | Unsigned int | Yes | The producer's strictly monotonic batch counter for this stream (the subscription, or the unsolicited stream) in this direction. Lets a consumer detect dropped batches. |
| `obs` (4) | Array of Observation (§5.1) | Yes | One or more observations. MUST be non-empty. |

### 5.1 Observation

Each element of the `obs` array is a CBOR map with the following fields.

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `source_id` (0) | Byte string (1–64 B) | Yes | Opaque sensor/source identifier within the emitting peer's namespace. |
| `ts` (1) | Unsigned int | Yes | Observation time, in milliseconds since the Unix epoch (UTC). |
| `seq` (2) | Unsigned int | No | Strictly monotonic per-`source_id` sample counter, for gap detection within a source. Independent of the core per-channel frame sequence number. |
| `unit` (3) | Unsigned int | Yes | Unit-of-measure code point from the Sensory Unit registry (§5.2). `0` denotes dimensionless / count. |
| `unit_str` (4) | Text string | No | Free-form unit label (UCUM-style). Present only when `unit` equals `1` (the unit-not-registered escape). Advisory. |
| `value` (5) | Int / Float / Byte string / Bool | Yes | The reading. A numeric scalar for a scalar sensor; a byte string for a packed or opaque reading; a boolean for a binary sensor. Exactly one CBOR value. |
| `quality` (6) | Unsigned int | No | Reading quality: `0` = good, `1` = uncertain, `2` = stale, `3` = bad / sensor-fault. An absent `quality` MUST be treated as `0` (good) only when the source asserts no quality channel; a consumer MUST NOT infer good for a source known to report quality. |

### 5.2 Sensory Unit registry

This document defines the following unit code points (deterministic small
integers). A `unit` value is advisory metadata over an opaque `value`.

| Code | Unit |
|---|---|
| `0` | dimensionless / count |
| `1` | unregistered (see `unit_str`) |
| `2` | metre |
| `3` | metre per second |
| `4` | metre per second squared |
| `5` | radian |
| `6` | radian per second |
| `7` | kelvin |
| `8` | pascal |
| `9` | volt |
| `10` | ampere |
| `11` | watt |
| `12` | kilogram |
| `13` | percent (0–100) |
| `14` | ratio (0.0–1.0) |
| `15` | lux |
| `16` | decibel |

Code points `17`–`0x7FFF` are reserved for registry growth; `0x8000` and above are
private-use. A receiver that does not recognize a `unit` code point MUST retain the
observation and treat the unit as opaque — it MUST NOT drop the reading, because the
unit is advisory metadata and the `value` stands on its own.

### 5.3 Ordering and loss

`batch_seq` orders batches within a stream, and per-source `seq` orders samples
within a source; both are gap-detection aids only. Because the Sensory channel is
bulk and low-priority (§2), this document does NOT guarantee delivery, cross-source
ordering, or exactly-once semantics. A consumer detects loss from `batch_seq` or
`seq` gaps; there is no replay of dropped batches, and a consumer MAY expect nothing
beyond the producer's future output.

## 6. Subscription lifecycle

### 6.1 SENSORY_SUBSCRIBE body (`0x0101`)

A SENSORY_SUBSCRIBE requests a continuing stream of OBSERVE batches. Its payload
carries the common envelope (§4.1, with a `corr` that is non-empty and unique among
the originating peer's outstanding subscriptions in that direction) and an OPTIONAL
filter plus the initial credit grant:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `frame_kind` (0) | Unsigned int | Yes | MUST equal `0x0101`. |
| `corr` (1) | Byte string (1–64 B) | Yes | Common envelope (§4.1). |
| `sources` (2) | Array of byte string | No | Restrict delivery to these `source_id` values. Absent means all sources the responder offers. |
| `units` (3) | Array of unsigned int | No | Restrict delivery to observations of these unit code points. Absent means all units. |
| `min_quality` (4) | Unsigned int | No | Deliver only observations whose `quality` is less than or equal to this value (`0` good … `3` bad). Absent means no quality restriction. |
| `max_rate_mhz` (5) | Unsigned int | No | Requested maximum delivery rate per source, in milli-hertz. Advisory ceiling; the responder MAY deliver more slowly. |
| `credit` (6) | Unsigned int | Yes | Initial batch credit the consumer grants (§7): the number of OBSERVE batches the producer MAY send before it requires a further SENSORY_CREDIT. MUST be greater than or equal to `1`. |

A filter is **conjunctive**: an observation is delivered only if it satisfies every
present filter field. A responder that cannot honor a present filter field MUST
reply SENSORY_ERROR with code `FilterUnsupported` (§8); it MUST NOT silently ignore
the field and over-deliver.

### 6.2 SENSORY_SUB_ACK body (`0x0102`)

A SENSORY_SUB_ACK accepts a subscription. Its payload carries the common envelope
(§4.1, echoing the subscribe's `corr`) and:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `frame_kind` (0) | Unsigned int | Yes | MUST equal `0x0102`. |
| `corr` (1) | Byte string (1–64 B) | Yes | Echoes the subscribe's `corr` verbatim (§4.1). |
| `sub_id` (2) | Byte string (1–32 B) | Yes | The subscription's stable identifier, used by SENSORY_OBSERVE, SENSORY_CREDIT, and SENSORY_UNSUBSCRIBE for this stream. |
| `credit` (3) | Unsigned int | Yes | The effective initial credit the producer will honor. MUST be less than or equal to the requested `credit` (§6.1). |
| `sources` (4) | Array of byte string | No | The concrete source set the responder will emit, when it chooses to disclose it. |

A responder MAY decline a subscription with SENSORY_ERROR code `SubscriptionRefused`
(§8) instead of a SUB_ACK.

### 6.3 SENSORY_UNSUBSCRIBE (`0x0103`)

A SENSORY_UNSUBSCRIBE cancels a subscription. Its payload carries the common envelope
(§4.1, echoing the subscription's `corr`) and:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `frame_kind` (0) | Unsigned int | Yes | MUST equal `0x0103`. |
| `corr` (1) | Byte string (1–64 B) | Yes | Echoes the subscription's `corr` verbatim (§4.1). |
| `sub_id` (2) | Byte string (1–32 B) | Yes | The subscription to cancel. |

The responder MUST stop emitting OBSERVE batches for that `sub_id` upon receipt. No
reply is sent, and a sender MUST NOT await one. A SENSORY_UNSUBSCRIBE that names an
unknown or already-closed `sub_id` MUST be ignored — it is idempotent.

## 7. Backpressure (SENSORY_CREDIT, `0x0104`)

The credit mechanism is what makes the Sensory channel behave as "low-priority
observations": it lets a consumer bound a bulk producer without tearing down the
stream. Delivery is **credit-bounded per subscription**. A producer MUST NOT have
more OBSERVE batches in flight for a `sub_id` than the current outstanding credit for
that subscription; it decrements available credit by `1` per OBSERVE batch it emits;
and, at zero credit, it MUST pause emission for that subscription until it receives
additional credit.

A SENSORY_CREDIT replenishes or updates credit. Its payload carries the common
envelope (§4.1, echoing the subscription's `corr`) and:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `frame_kind` (0) | Unsigned int | Yes | MUST equal `0x0104`. |
| `corr` (1) | Byte string (1–64 B) | Yes | Echoes the subscription's `corr` verbatim (§4.1). |
| `sub_id` (2) | Byte string (1–32 B) | Yes | The subscription whose credit is being updated. |
| `credit` (3) | Unsigned int | Yes | Additional batches the consumer grants. This value is **added** to the producer's remaining credit. |
| `high_water` (4) | Unsigned int | No | Advisory ceiling: the producer SHOULD NOT let the accumulated outstanding grant exceed this value, for burst control. |

A producer MUST treat `credit` as **additive** to its remaining grant and MUST NOT
deliver beyond the accumulated grant. This per-subscription credit is distinct from,
and layered above, the core connection-level FLOW_UPDATE frame `0x000A`, which this
document neither redefines nor consumes.

## 8. Error model (SENSORY_ERROR, `0x0105`)

A failure of a subscribe or credit request is reported as a SENSORY_ERROR, echoing
the request's `corr` (the NPAMP-BRIDGE §5 / NPAMP-DISC §9 convention). Its payload
carries the common envelope (§4.1) and:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `frame_kind` (0) | Unsigned int | Yes | MUST equal `0x0105`. |
| `corr` (1) | Byte string (1–64 B) | Yes | Echoes the failed request's `corr` verbatim (§4.1). |
| `code` (2) | Unsigned int | Yes | One of the codes below. |
| `reason` (3) | Text string | No | Advisory human-readable detail. MUST NOT be relied on for control flow. |
| `sub_id` (4) | Byte string (1–32 B) | No | The affected subscription, when applicable. |

| Code | Name | Meaning |
|---|---|---|
| `1` | MalformedPayload | The payload is not valid deterministic CBOR, omits a required key, uses a wrong CBOR major type, or carries an unrecognized negative integer key (§4). |
| `2` | KindMismatch | The payload's `frame_kind` contradicts the frame-header Frame Type (§4.1). |
| `3` | FilterUnsupported | A present SENSORY_SUBSCRIBE filter field is not implemented; the responder MUST reply this rather than over-deliver (§6.1). |
| `4` | UnknownSubscription | A SENSORY_CREDIT or subscribed SENSORY_OBSERVE names a `sub_id` with no live subscription. |
| `5` | SubscriptionRefused | The responder declines a SENSORY_SUBSCRIBE (unsupported, or a local resource or rate limit reached). |
| `6` | NotAdvertised | The Sensory channel `0x0009` was not advertised for this association, or the Sensory channel is disabled by local policy (§2). |

A standalone (unsolicited) SENSORY_OBSERVE is one-way and generates no error reply.
A subscribed OBSERVE that a consumer finds malformed is handled at the subscription
level: the consumer MAY cancel with a SENSORY_UNSUBSCRIBE rather than emit a
SENSORY_ERROR.

## 9. Operation and state model

Each subscription is keyed by its `sub_id`, scoped to the association and to one
direction, and progresses through the following states:

```
IDLE
  -> SENSORY_SUBSCRIBE sent/received ->            PENDING
       -> SENSORY_SUB_ACK ->                       ACTIVE (credit = N)
            -> OBSERVE batch emitted ->            ACTIVE (credit decremented by 1)
                 -> credit reaches 0 ->            PAUSED
                      -> SENSORY_CREDIT ->         ACTIVE (credit increased)
       -> SENSORY_ERROR (SubscriptionRefused) ->   CLOSED
  -> SENSORY_UNSUBSCRIBE or association close ->    CLOSED
```

A SENSORY_SUBSCRIBE moves the subscription from IDLE to PENDING. A SENSORY_SUB_ACK
moves it to ACTIVE with the acknowledged credit; a refusal (SENSORY_ERROR
`SubscriptionRefused`) moves it from PENDING to CLOSED. In ACTIVE, each emitted
OBSERVE batch decrements available credit by one; reaching zero credit moves the
subscription to PAUSED, where the producer MUST NOT emit further batches until a
SENSORY_CREDIT returns it to ACTIVE. A SENSORY_UNSUBSCRIBE, or the close of the
association, moves the subscription to CLOSED.

A standalone (unsolicited) SENSORY_OBSERVE is **stateless push**: it carries no
`corr`, participates in no credit accounting, and is best-effort. A receiver MAY drop
an unsolicited SENSORY_OBSERVE at any time without protocol error.

All subscription and credit state is **association-scoped** and MUST be discarded on
association close. A peer MUST NOT carry Sensory subscription or credit state across
associations. Because the Sensory channel is bidirectional, a peer MUST bound the
resources a remote peer can consume in **either** direction: it MUST bound the number
of concurrent subscriptions and the rate of SENSORY_SUBSCRIBE frames it will accept,
and MAY reply SENSORY_ERROR `SubscriptionRefused` rather than allocate without limit.

## 10. Security and privacy considerations

This section supplements the core specification's Security Considerations; it does
not restate them.

Sensory frames are AEAD-protected like all N-PAMP frames. A receiver therefore knows
that a batch was sent by the authenticated peer (the core specification's handshake
binds both peer identities into the transcript and the Finished MAC), **but not that
the underlying sensor is truthful, calibrated, or present**. An observation is a
**claim by the emitting peer**; nothing in this document authenticates the physical
sensor behind a `source_id`.

Telemetry can be sensitive — location, presence, occupancy, and physical state may be
inferable from readings. A peer SHOULD emit only the sources appropriate to the
authenticated peer and to local policy, and MAY return an empty or filtered source
set to a peer it does not wish to inform (an empty `sources` in a SUB_ACK, or a
`SubscriptionRefused`, is a valid and non-committal response).

Because a bulk producer can flood a consumer, the §7 credit mechanism is **REQUIRED**
for subscribed delivery: a consumer MUST NOT be forced to buffer beyond the credit it
granted, and a producer that continues to emit OBSERVE batches after its credit is
exhausted is in violation of §7 and §11. An unsolicited SENSORY_OBSERVE MUST be
droppable by a receiver at any time without protocol error, so that an unsolicited
producer cannot compel buffering either.

The URG flag MUST NOT be set on any Sensory frame (§2). This prevents a bulk
observation stream from usurping the scheduling of interactive or control-plane
traffic, preserving the channel's low-priority posture even under an adversarial or
misbehaving producer.

## 11. Conformance

An implementation conforms to NPAMP-SENSORY if and only if, on the Sensory channel
`0x0009`, it:

1. Enables the Sensory channel only at the **High or Sovereign** profile, never at
   Standard, and drops any frame received on an unadvertised Sensory channel (§2);
2. Uses only the `0x0100`-and-above channel-application frame types of §3, preserves
   the core meaning of the reserved all-channel frame types, defines no Sensory
   semantics in the future-core gap or the companion-extension band, and never sets
   the URG flag on a Sensory frame (§2, §3);
3. Encodes every Sensory payload as a deterministic-CBOR map, ignores unrecognized
   non-negative integer keys, and rejects a malformed, kind-mismatched, or
   unrecognized-negative-key payload with the corresponding SENSORY_ERROR (§4, §8);
4. Emits and parses SENSORY_OBSERVE with a non-empty typed-observation array, each
   observation carrying `source_id`, `ts`, `unit`, and `value`, and honors the
   `quality`, `seq`, and `batch_seq` semantics — including retaining an observation
   whose `unit` it does not recognize, treating that unit as opaque (§5);
5. Enforces correlation (§4.1, per NPAMP-BRIDGE §5): a SENSORY_SUBSCRIBE carries a
   unique-per-direction `corr`; SENSORY_SUB_ACK, SENSORY_CREDIT, SENSORY_UNSUBSCRIBE,
   SENSORY_ERROR, and every subscribed SENSORY_OBSERVE echo it verbatim; and replies
   are matched by `corr`, not by frame sequence number;
6. Applies SENSORY_SUBSCRIBE filters conjunctively, and replies `FilterUnsupported`
   rather than silently over-delivering when it cannot honor a present filter field
   (§6.1);
7. Honors the §7 credit mechanism — never exceeding the accumulated per-subscription
   credit, pausing emission at zero credit, and resuming only on a SENSORY_CREDIT —
   and bounds concurrent subscriptions and the SENSORY_SUBSCRIBE rate in both
   directions (§7, §9);
8. Stops emitting OBSERVE batches for a `sub_id` upon SENSORY_UNSUBSCRIBE, treats an
   UNSUBSCRIBE for an unknown `sub_id` as idempotent, and discards all subscription
   and credit state on association close, carrying none across associations (§6.3,
   §9); and
9. Defers all High and Sovereign cryptographic internals to the core specification's
   Profile Negotiation, and publishes or relies on none of them through this document
   (§1.2, §2).

No machine-gradable conformance vectors exist for the Sensory channel yet: a claim of
conformance to this document is therefore specification-audited and MUST NOT be
represented as corpus-verified. A conformance test suite SHOULD assert each clause above with a recorded Sensory
exchange on channel `0x0009`: an unsolicited OBSERVE batch (no `corr`); a
SENSORY_SUBSCRIBE → SENSORY_SUB_ACK → OBSERVE (repeated until credit reaches zero) →
SENSORY_CREDIT → OBSERVE → SENSORY_UNSUBSCRIBE sequence; a producer that pauses at
zero credit and resumes only on a SENSORY_CREDIT; a refused subscription
(`SubscriptionRefused`); a `FilterUnsupported` rejection of an unsupported filter
field; and each SENSORY_ERROR code provoked by a malformed or unsupported input.
