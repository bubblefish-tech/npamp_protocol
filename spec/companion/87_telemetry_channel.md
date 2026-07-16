# NPAMP-TELEMETRY — Telemetry Channel Operational-Metrics & Health Companion (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document defines a concrete operation encoding over the N-PAMP
> **Telemetry channel `0x000A`** ("Operational metrics and health reporting",
> minimum profile **Standard**, direction **Bidirectional**): how a peer emits its
> own operational metrics, discrete events, and health statements in bulk, how a
> peer subscribes to a continuing stream of those reports, and how a consumer bounds
> a bulk producer with explicit credit. It is a **native-core-channel** operation
> companion — it does not encapsulate a foreign agent protocol and does not build on
> the Bridge channel `0x000D`. It defines the concrete operation encoding the
> Telemetry channel interface reference (`../channels/000A_telemetry.md`, §3.3, §4)
> explicitly defers to a future companion, consuming only channel-application
> frame-type code points the core specification (draft-bubblefish-npamp-01, the
> "core specification") reserves at `0x0100` and above on the Telemetry channel. It
> introduces no change to the core wire format and defines no extension TLV. **The
> core specification governs**: on any disagreement between this document and the
> core specification, the core specification is authoritative.

## 1. Scope

### 1.1 In scope

This document specifies, over the Telemetry channel `0x000A` of the core
specification (draft-bubblefish-npamp-01):

1. A set of Telemetry-channel frame types (§3), drawn entirely from the
   channel-application frame-type band that begins at `0x0100` (core specification
   §4.6) — the Telemetry channel has **no** core-reserved companion-extension range
   of its own (§3, and `../channels/000A_telemetry.md` §3.2);
2. The encoding of a **telemetry report** — a deterministically encoded CBOR payload
   carrying, in one batch, one or more of: operational **metric samples**, discrete
   **events**, and **health statements** (§5), realizing the two reporting classes
   the core registry names for this channel (operational metrics **and** health
   reporting);
3. A subscribe / acknowledge / unsubscribe lifecycle scoping which reports a peer
   pushes to a subscriber (§6);
4. A consumer-driven **credit** backpressure mechanism (§7) that bounds a bulk
   producer per subscription, honoring the channel's bulk, deprioritizable posture;
   and
5. A structured error model for failures of the subscribe and credit exchange (§8),
   together with an operation and state model (§9).

Operations are described generically — emit metrics, events, and health; subscribe;
credit; unsubscribe — so that any producer and any consumer interoperate over N-PAMP
with no bespoke adaptation. The document names no product, no vendor, and no
application-specific metric schema.

### 1.2 Not in scope

This document does NOT (each exclusion carries its reason):

* **Define a metric ontology, a metric-name registry, an event taxonomy, or the
  meaning of any particular metric, unit, event type, or health domain** — reason:
  the `name`, `unit`, event `name`, and health `domain` fields are opaque strings in
  the emitting peer's own namespace; which metrics a peer reports and what they mean
  is the deploying application's concern, not a wire-interoperability contract (§5,
  §10).
* **Define a metrics query, aggregation, roll-up, or alerting language** — reason: a
  subscription carries a small set of structured selector fields (§6.1), not an
  expression grammar; aggregation and alerting are layered above this transport.
* **Define sampling, retention, downsampling, or durable storage of telemetry** —
  reason: this document fixes only what crosses the wire in a report batch; how a
  producer samples, or how a consumer stores or ages telemetry, is a local matter.
* **Guarantee delivery, exactly-once delivery, or replay of dropped reports** —
  reason: the Telemetry channel is one of the core specification's **bulk** channels
  and is deprioritized during congestion (core specification §5;
  `../channels/000A_telemetry.md` §5); §5.4 provides only per-stream and per-name
  monotonic sequence numbers for gap detection, and nothing more.
* **Provide connection-level flow control** — reason: connection-level flow control
  is the core FLOW_UPDATE frame `0x000A`; the §7 credit mechanism is an
  application-layer, per-subscription control layered above it, not a replacement
  for it, and this document neither redefines nor consumes the `0x000A` body.
* **Carry a foreign agent protocol** — reason: the Telemetry channel is native; it
  is not a Bridge carriage class and does not build on NPAMP-BRIDGE
  (`../channels/000A_telemetry.md` §6). No frame in this document encapsulates a
  foreign message, and this document defines and consumes no extension-TLV tag.
* **Carry physical-sensor bulk observations, or open multiple concurrent transport
  sub-streams** — reason: bulk sensor observation is the distinct **Sensory** channel
  `0x0009` (High profile, Multi-stream) and its companion `82_sensory_channel.md`;
  Telemetry `0x000A` is Standard-profile, **Bidirectional** (not Multi-stream), and
  reports a peer's own operational metrics and health, not external sensor readings
  (§2.3; `../channels/000A_telemetry.md` §1).
* **Change any field of the core frame header, any reserved all-channel frame type,
  the extension-TLV encoding, or any code point the core specification assigns** —
  reason: those are fixed by the core specification and this document reserves none
  of them (§3).

## 2. Relationship to the core specification and the profile gate

The Telemetry channel `0x000A` is registered by the core specification with purpose
**"Operational metrics and health reporting"**, minimum profile **Standard**, and
direction **Bidirectional** (core specification §5, Core Channel Registry;
machine-readable form `../../registries/channels.csv`; restated in
`../channels/000A_telemetry.md` §2). These values are normative in the core
specification; this companion restates them and does not alter them. Three
consequences bind this companion.

### 2.1 Minimum-profile and advertisement gates

* **Minimum-profile gate.** A peer MUST enable the Telemetry channel — and therefore
  this companion — only at the **Standard** profile or higher. Once Standard is met
  the channel is available at Standard, High, and Sovereign, and there is no profile
  at which it becomes unavailable (`../channels/000A_telemetry.md` §5). The framing
  and interface of this companion are **profile-invariant**: the three profiles share
  one wire format and differ only in the cryptographic primitives the core
  specification's Profile Negotiation selects, which are out of scope here.
* **Advertisement gate.** A peer that has not advertised the Telemetry channel for
  the association during the handshake (core specification §5) MUST NOT receive
  frames on it; any frame received on an unadvertised Telemetry channel MUST be
  dropped and MUST NOT be delivered to a telemetry consumer.

### 2.2 Bidirectional direction — single stream, not Multi-stream

Under the core specification's channel architecture the Telemetry channel is
full-duplex: each peer maintains an independent per-direction send and receive
sequence space and independent per-direction traffic keys, so both peers MAY
transmit on the channel simultaneously and **either peer MAY originate** a report or
a subscription (core specification §5; `../channels/000A_telemetry.md` §2). The
Telemetry channel is **not** classified Multi-stream: it does not open multiple
concurrent transport sub-streams within a stream family
(`../channels/000A_telemetry.md` §2). Consequently, all Telemetry frames in a given
direction share the **one** per-direction stream and its single sequence space, and
multiple concurrent subscriptions are multiplexed **logically** by their in-body
`corr` / `sub_id` (§4.1) over that one stream — not across separate transport
sub-streams as on the Multi-stream Memory `0x0001`, Sensory `0x0009`, or Stream
`0x000C` channels. A receiver MUST associate a report, acknowledgement, or error with
its subscription by `corr` / `sub_id`, never by the frame sequence number (§4.1).

### 2.3 Native operation companion; distinction from Sensory and from PING/PONG

This companion is a **native core-channel** operation companion. Unlike the Bridge
channel `0x000D`, which encapsulates foreign agent protocols and is elaborated by
NPAMP-BRIDGE (`10_bridge_framework.md`) and its carriage classes, the Telemetry
channel carries no foreign protocol; this document defines a first-party report
encoding directly in the channel's own application frame band, and a report is routed
by its N-PAMP **frame type** (§3), not by any method-name or tool-name field parsed
from a body. It reuses one facility of NPAMP-BRIDGE by reference — the **correlation
discipline** in which a reply echoes its request's correlation token verbatim and
replies are matched by that token rather than by frame sequence number (§4.1) — and
otherwise defines its own contract, consuming **no** extension-TLV code point (§4).

Two distinctions are normative:

* **Telemetry `0x000A` is not Sensory `0x0009`.** The core specification names
  Sensory "Bulk telemetry and low-priority observations" (High profile, Multi-stream)
  and Telemetry "Operational metrics and health reporting" (Standard profile,
  Bidirectional); they are separate registry rows with separate identifiers,
  minimum profiles, and directionalities (`../channels/000A_telemetry.md` §1). This
  companion carries a peer's **own** operational metrics and health; carriage of
  external physical-sensor readings is NPAMP-SENSORY (`82_sensory_channel.md`) on
  channel `0x0009`. An implementation MUST NOT carry Sensory observation semantics on
  channel `0x000A`, nor Telemetry report semantics on channel `0x0009`.
* **Application health reporting is not transport liveness.** The reserved
  all-channel PING and PONG frames (`0x0001` / `0x0002`, §3) provide transport-level
  liveness on every channel, including this one. They are distinct from the
  application-level health statements this companion defines (§5.3). An
  implementation MUST NOT treat a PING/PONG exchange as a health report, and MUST NOT
  treat a health statement as a substitute for transport liveness
  (`../channels/000A_telemetry.md` §4).

### 2.4 Bulk, low-priority scheduling posture

The core specification classes Telemetry among the **bulk** channels and states that
the Control and Immune channels SHOULD be scheduled at higher priority than the bulk
channels (Memory, Sensory, Telemetry) during congestion (core specification §5;
`../channels/000A_telemetry.md` §5). Consistent with that posture, an implementation
**MUST NOT** set the frame header **URG** (urgent) flag on any Telemetry frame:
urgent-priority scheduling contradicts the channel's bulk, deprioritizable purpose,
and an operational-metrics stream MUST NOT be allowed to usurp the scheduling of
interactive or control-plane traffic, even under a misbehaving producer.

## 3. Telemetry-channel frame types

The core specification partitions each channel's `0x0000`–`0xFFFF` frame-type
namespace into four bands (core specification §4.6; `../04_frame_types.md`):

* `0x0000`–`0x000A` — reserved all-channel frame types (`0x0000` reserved; PING
  `0x0001` … FLOW_UPDATE `0x000A`), with the same meaning on every channel;
* `0x000B`–`0x002F` — reserved for future core use (a gap; unused here);
* `0x0030`–`0x00FF` — the companion-extension band; and
* `0x0100`–`0xFFFF` — the channel-application band, in which a channel's own
  operational frames are defined.

**The Telemetry channel has no core-reserved companion-extension range.** The core
specification's Reserved Frame-Type Ranges table (core specification §8.1;
`../09_extension_points.md`) assigns sub-`0x0100` companion ranges to the Memory,
Capability, Control, Audit, Settlement/Audit, Governance, and Immune channels, but
**none** to the Telemetry channel (`../channels/000A_telemetry.md` §3.2). This
document therefore defines **all** of its operational frames in the
channel-application band, at `0x0100` and above on the Telemetry channel, and defines
no frame in the companion-extension band:

| Type | Name | Reply | Purpose |
|---|---|---|---|
| `0x0100` | TELEMETRY_REPORT | None | A batch of operational metric samples, discrete events, and/or health statements pushed one-way — standalone, or under a subscription where it consumes credit. |
| `0x0101` | TELEMETRY_SUBSCRIBE | TELEMETRY_SUB_ACK or TELEMETRY_ERROR | Request a continuing stream of REPORT batches matching a selector, carrying an initial credit grant. |
| `0x0102` | TELEMETRY_SUB_ACK | None | Accepts a subscription; echoes `corr`; returns the granted terms (subscription id, effective credit, accepted reporting classes). |
| `0x0103` | TELEMETRY_UNSUBSCRIBE | None | Cancels a subscription; echoes `corr`; no reply (idempotent). |
| `0x0104` | TELEMETRY_CREDIT | None | Consumer replenishes per-subscription report credit (backpressure); echoes `corr`. |
| `0x0105` | TELEMETRY_ERROR | None | Structured failure of a subscribe or credit request; echoes the `corr` of the request it answers. |

A TELEMETRY_SUBSCRIBE (`0x0101`) originates a subscription; the corresponding
TELEMETRY_SUB_ACK (`0x0102`), or a TELEMETRY_ERROR (`0x0105`), replies to it. A
responder MUST NOT emit both a TELEMETRY_SUB_ACK and a TELEMETRY_ERROR for the same
TELEMETRY_SUBSCRIBE. TELEMETRY_REPORT, TELEMETRY_UNSUBSCRIBE, and TELEMETRY_CREDIT are
one-way frames that expect no reply.

The reserved all-channel frame types (PING `0x0001`, PONG `0x0002`, CLOSE `0x0003`,
CLOSE_ACK `0x0004`, ERROR `0x0005`, KEY_UPDATE `0x0006`, KEY_UPDATE_ACK `0x0007`,
PATH_CHALLENGE `0x0008`, PATH_RESPONSE `0x0009`, and FLOW_UPDATE `0x000A`) retain
their core meaning on the Telemetry channel (core specification §4.6). An
implementation MUST NOT reuse them for Telemetry application traffic, and MUST NOT
define Telemetry semantics in the reserved all-channel range `0x0000`–`0x000A`, in
the future-core gap `0x000B`–`0x002F`, or in the companion-extension band
`0x0030`–`0x00FF`. Note that the frame-type code point `0x000A` (FLOW_UPDATE) is
independent of the Telemetry **channel** identifier `0x000A`: the two live in
separate namespaces and the numeric coincidence carries no additional semantics
(`../channels/000A_telemetry.md` §3.1). All six frame types defined above lie within
the Telemetry channel's own channel-application band at or above `0x0100`; this
document consumes no frame-type code point outside that band and defines no extension
TLV.

## 4. Payload encoding (deterministic CBOR)

A Telemetry frame's payload — the octets after the core frame header and any
extension TLVs, and before the AEAD tag — is a single **deterministically encoded
CBOR** map, as defined by the core specification's Payload Encoding clause (core
specification §4.5) and its deterministic-encoding requirement (core specification
§11.9; RFC 8949). A sender MUST produce the deterministic encoding: byte-identical
output for identical inputs, with the canonical key ordering and shortest-form
integer encoding RFC 8949 §4.2 requires, and definite-length maps and arrays. The
payload MUST be a CBOR map whose keys are the unsigned integers defined in §4.1 and
§5–§8 for the relevant frame type.

A receiver MUST reject — with a TELEMETRY_ERROR carrying code `MalformedPayload` (§8)
— any Telemetry payload that is not a valid deterministic-CBOR map, that omits a
REQUIRED key for its frame type, or that uses a key of the wrong CBOR major type.

**Forward compatibility.** A receiver MUST ignore an unrecognized integer key whose
value is **non-negative**, so that later revisions of this document MAY add fields
without breaking a conformant receiver, and MUST NOT alter its handling of the keys
it does recognize because of it. A receiver MUST reject — with a TELEMETRY_ERROR
carrying code `MalformedPayload` (§8) — a payload that carries an unrecognized
integer key whose value is **negative**, reserving the negative-key space for
forward-incompatible additions. Telemetry operation bodies are carried in the frame
**payload**, not in extension TLVs; this document defines and consumes no
extension-TLV tag, and therefore claims none of the TLV code points the core
specification reserves.

### 4.1 Common envelope

Every Telemetry payload map carries the following common envelope fields. Integer
keys are given in parentheses.

| Field (key) | CBOR type | Meaning |
|---|---|---|
| `frame_kind` (0) | Unsigned int | MUST equal the frame's Telemetry frame type (`0x0100`–`0x0105`). A receiver MUST reject (TELEMETRY_ERROR, code `KindMismatch`) a payload whose `frame_kind` contradicts the frame-header Frame Type. |
| `corr` (1) | Byte string (1–64 B) | Correlation token. REQUIRED and non-empty on TELEMETRY_SUBSCRIBE, and unique among the originating peer's outstanding subscriptions in that direction; echoed verbatim by TELEMETRY_SUB_ACK, TELEMETRY_CREDIT, TELEMETRY_UNSUBSCRIBE, TELEMETRY_ERROR, and by any TELEMETRY_REPORT emitted under that subscription. ABSENT on a standalone (unsolicited) TELEMETRY_REPORT. |

The core specification does not define how a Telemetry reply is correlated to its
request (`../channels/000A_telemetry.md` §4); this document supplies that discipline,
carrying the token **inside** the CBOR body rather than in a shared TLV, because a
native channel owns its whole body (§2.3). A receiver MUST match each reply, credit
update, or subscribed report to its originating subscription by `corr`, **not** by
frame sequence number, exactly as NPAMP-BRIDGE §5 requires for Bridge replies. A
standalone TELEMETRY_REPORT — one not sent under any subscription — MUST omit `corr`.

## 5. TELEMETRY_REPORT body (`0x0100`)

A TELEMETRY_REPORT carries a batch of one or more operational metric samples,
discrete events, and/or health statements. Its payload carries the common envelope
(§4.1) and:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `frame_kind` (0) | Unsigned int | Yes | MUST equal `0x0100`. |
| `corr` (1) | Byte string (1–64 B) | Cond | Present if and only if this batch answers a subscription; absent on an unsolicited push (§4.1). |
| `sub_id` (2) | Byte string (1–32 B) | Cond | The subscription identifier (from TELEMETRY_SUB_ACK, §6.2) this batch satisfies. Present if and only if `corr` is present. |
| `batch_seq` (3) | Unsigned int | Yes | The producer's strictly monotonic batch counter for this stream (the subscription, or the unsolicited stream) in this direction. Lets a consumer detect dropped batches (§5.4). |
| `metrics` (4) | Array of MetricSample (§5.1) | No | Zero or more operational-metric samples. |
| `events` (5) | Array of Event (§5.2) | No | Zero or more discrete telemetry events. |
| `health` (6) | Array of HealthReport (§5.3) | No | Zero or more health statements. |

A TELEMETRY_REPORT MUST carry content: at least one of `metrics`, `events`, or
`health` MUST be present and non-empty. A receiver MUST reject (TELEMETRY_ERROR, code
`MalformedPayload`) a report whose `metrics`, `events`, and `health` are all absent
or empty. A single batch MAY mix all three arrays; the two reporting classes the
registry names — operational metrics and health reporting — are carried by the
`metrics`/`events` arrays and the `health` array respectively.

### 5.1 MetricSample

Each element of the `metrics` array is a CBOR map with the following fields.

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `name` (0) | Text string | Yes | Opaque metric identifier within the emitting peer's namespace (for example a dotted metric name). This document assigns no metric registry (§1.2). |
| `ts` (1) | Unsigned int | Yes | Sample time, in milliseconds since the Unix epoch (UTC). |
| `kind` (2) | Unsigned int | Yes | Metric kind: `0` gauge (instantaneous value), `1` counter (monotonically cumulative), `2` delta (change since the previous sample), `3` histogram-bucket (a bucketed observation). A receiver that does not recognize a `kind` value MUST retain the sample and treat `kind` as `0` gauge. |
| `value` (3) | Int / Float | Yes | The numeric measurement. Exactly one CBOR numeric value. |
| `unit` (4) | Text string | No | Advisory free-form unit label (for example a UCUM-style string). Advisory metadata over an opaque `value`; a receiver MUST NOT drop a sample whose `unit` it does not recognize. |
| `labels` (5) | Map (text→text) | No | Dimension labels (for example an instance or region label). Keys and values are opaque text in the emitter's namespace. |
| `seq` (6) | Unsigned int | No | Strictly monotonic per-`name` sample counter, for gap detection within a metric. Independent of the core per-channel frame sequence number. |

### 5.2 Event

Each element of the `events` array is a CBOR map with the following fields. An event
is a discrete, structured occurrence (as distinct from a numeric metric sample).

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `name` (0) | Text string | Yes | Opaque event-type identifier within the emitting peer's namespace. |
| `ts` (1) | Unsigned int | Yes | Event time, in milliseconds since the Unix epoch (UTC). |
| `severity` (2) | Unsigned int | No | Advisory severity: `0` info, `1` notice, `2` warning, `3` error, `4` critical. Absent means `0` info. A receiver that does not recognize a `severity` value MUST treat the event as `4` critical for filtering purposes, never silently discarding a potentially significant event. |
| `attrs` (3) | Map (text→(text/int/float/bool)) | No | Structured event attributes. Keys are opaque text in the emitter's namespace. |
| `message` (4) | Text string | No | A short, peer-safe human-readable description. It MUST NOT carry internal detail beyond what the emitter intends to disclose (§10). |
| `seq` (5) | Unsigned int | No | Strictly monotonic per-`name` event counter, for gap detection within an event type. |

### 5.3 HealthReport

Each element of the `health` array is a CBOR map with the following fields. A health
statement is the application-level health reporting the channel registry names, and
is distinct from transport-level PING/PONG liveness (§2.3).

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `domain` (0) | Text string | Yes | Opaque identifier of the subsystem or component the statement pertains to, within the emitting peer's namespace. |
| `ts` (1) | Unsigned int | Yes | Statement time, in milliseconds since the Unix epoch (UTC). |
| `status` (2) | Unsigned int | Yes | Health status: `0` healthy, `1` degraded, `2` unhealthy, `3` unknown. A receiver that does not recognize a `status` value MUST treat it as `3` unknown, never as `0` healthy. |
| `message` (3) | Text string | No | A short, peer-safe human-readable description of the condition. It MUST NOT carry internal detail beyond what the emitter intends to disclose (§10). |
| `detail` (4) | Map | No | Advisory structured health detail keyed by unsigned integers or text; a consumer that does not recognize an inner key MUST ignore it rather than fail the report. |

### 5.4 Ordering and loss

`batch_seq` orders batches within a stream, and per-`name` `seq` orders samples or
events within a metric or event type; both are **gap-detection aids only**. Because
the Telemetry channel is bulk and deprioritizable (§2.4), this document does NOT
guarantee delivery, cross-stream ordering, or exactly-once semantics. A consumer
detects loss from a `batch_seq` or `seq` gap; there is no replay of dropped batches,
and a consumer MAY expect nothing beyond the producer's future output.

## 6. Subscription lifecycle

### 6.1 TELEMETRY_SUBSCRIBE body (`0x0101`)

A TELEMETRY_SUBSCRIBE requests a continuing stream of REPORT batches. Its payload
carries the common envelope (§4.1, with a `corr` that is non-empty and unique among
the originating peer's outstanding subscriptions in that direction) and an OPTIONAL
selector plus the initial credit grant:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `frame_kind` (0) | Unsigned int | Yes | MUST equal `0x0101`. |
| `corr` (1) | Byte string (1–64 B) | Yes | Common envelope (§4.1). |
| `classes` (2) | Array of unsigned int | No | Restrict delivery to these reporting classes: `0` metrics, `1` events, `2` health. Absent means all classes the responder offers. |
| `names` (3) | Array of text string | No | Restrict delivery to metric/event `name` values matching these entries (exact match). Absent means no name restriction. |
| `domains` (4) | Array of text string | No | Restrict health statements to these `domain` values. Absent means no domain restriction. |
| `min_severity` (5) | Unsigned int | No | For events, deliver only those whose `severity` is greater than or equal to this value (§5.2). Absent means no severity restriction. |
| `max_rate_mhz` (6) | Unsigned int | No | Requested maximum delivery rate, in milli-hertz. Advisory ceiling; the responder MAY deliver more slowly. |
| `credit` (7) | Unsigned int | Yes | Initial report credit the consumer grants (§7): the number of REPORT batches the producer MAY send before it requires a further TELEMETRY_CREDIT. MUST be greater than or equal to `1`. |

A selector is **conjunctive**: a report item is delivered only if it satisfies every
present selector field. A responder that cannot honor a present selector field MUST
reply TELEMETRY_ERROR with code `FilterUnsupported` (§8); it MUST NOT silently ignore
the field and over-deliver, misleading the consumer into acting on a stream broader
than it requested.

### 6.2 TELEMETRY_SUB_ACK body (`0x0102`)

A TELEMETRY_SUB_ACK accepts a subscription. Its payload carries the common envelope
(§4.1, echoing the subscribe's `corr`) and:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `frame_kind` (0) | Unsigned int | Yes | MUST equal `0x0102`. |
| `corr` (1) | Byte string (1–64 B) | Yes | Echoes the subscribe's `corr` verbatim (§4.1). |
| `sub_id` (2) | Byte string (1–32 B) | Yes | The subscription's stable identifier, used by TELEMETRY_REPORT, TELEMETRY_CREDIT, and TELEMETRY_UNSUBSCRIBE for this stream. MUST be unique among the responder's live subscriptions in that direction. |
| `credit` (3) | Unsigned int | Yes | The effective initial credit the producer will honor. MUST be less than or equal to the requested `credit` (§6.1) and greater than or equal to `1`. |
| `classes` (4) | Array of unsigned int | No | The concrete reporting classes the responder will emit, when it chooses to disclose them (a subset of the requested `classes`). |

A responder MAY decline a subscription with TELEMETRY_ERROR code
`SubscriptionRefused` (§8) instead of a TELEMETRY_SUB_ACK.

### 6.3 TELEMETRY_UNSUBSCRIBE (`0x0103`)

A TELEMETRY_UNSUBSCRIBE cancels a subscription. Its payload carries the common
envelope (§4.1, echoing the subscription's `corr`) and:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `frame_kind` (0) | Unsigned int | Yes | MUST equal `0x0103`. |
| `corr` (1) | Byte string (1–64 B) | Yes | Echoes the subscription's `corr` verbatim (§4.1). |
| `sub_id` (2) | Byte string (1–32 B) | Yes | The subscription to cancel. |

The responder MUST stop emitting REPORT batches for that `sub_id` upon receipt. No
reply is sent, and a sender MUST NOT await one. A TELEMETRY_UNSUBSCRIBE that names an
unknown or already-closed `sub_id` MUST be ignored — it is idempotent.

## 7. Backpressure (TELEMETRY_CREDIT, `0x0104`)

The credit mechanism is what lets a consumer bound a bulk telemetry producer without
tearing down the stream, honoring the channel's bulk, deprioritizable posture (§2.4).
Delivery is **credit-bounded per subscription**. A producer MUST NOT have more REPORT
batches in flight for a `sub_id` than the current outstanding credit for that
subscription; it decrements available credit by `1` per REPORT batch it emits under
that subscription; and, at zero credit, it MUST pause emission for that subscription
until it receives additional credit.

A TELEMETRY_CREDIT replenishes or updates credit. Its payload carries the common
envelope (§4.1, echoing the subscription's `corr`) and:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `frame_kind` (0) | Unsigned int | Yes | MUST equal `0x0104`. |
| `corr` (1) | Byte string (1–64 B) | Yes | Echoes the subscription's `corr` verbatim (§4.1). |
| `sub_id` (2) | Byte string (1–32 B) | Yes | The subscription whose credit is being updated. |
| `credit` (3) | Unsigned int | Yes | Additional REPORT batches the consumer grants. This value is **added** to the producer's remaining credit. |
| `high_water` (4) | Unsigned int | No | Advisory ceiling: the producer SHOULD NOT let the accumulated outstanding grant exceed this value, for burst control. |

A producer MUST treat `credit` as **additive** to its remaining grant and MUST NOT
deliver beyond the accumulated grant. This per-subscription credit is distinct from,
and layered above, the core connection-level FLOW_UPDATE frame `0x000A`, which this
document neither redefines nor consumes (§1.2): every REPORT batch MUST respect both
the per-subscription credit here and the connection-level credit the core owns,
whichever is the tighter ceiling. A TELEMETRY_CREDIT that names an unknown `sub_id`
MUST be answered with TELEMETRY_ERROR code `UnknownSubscription` (§8).

## 8. Error model (TELEMETRY_ERROR, `0x0105`)

A failure of a subscribe or credit request is reported as a TELEMETRY_ERROR, echoing
the request's `corr` (the NPAMP-BRIDGE §5 / NPAMP-DISC §9 convention). Its payload
carries the common envelope (§4.1) and:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `frame_kind` (0) | Unsigned int | Yes | MUST equal `0x0105`. |
| `corr` (1) | Byte string (1–64 B) | Yes | Echoes the failed request's `corr` verbatim (§4.1). |
| `code` (2) | Unsigned int | Yes | One of the codes below. |
| `reason` (3) | Text string | No | Advisory, peer-safe human-readable detail. MUST NOT be relied on for control flow, and MUST NOT carry internal detail (§10). |
| `sub_id` (4) | Byte string (1–32 B) | No | The affected subscription, when applicable. |

| Code | Name | Meaning |
|---|---|---|
| `1` | MalformedPayload | The payload is not valid deterministic CBOR, omits a REQUIRED key, uses a wrong CBOR major type, carries an unrecognized negative integer key (§4), or is a TELEMETRY_REPORT with no metrics, events, or health (§5). |
| `2` | KindMismatch | The payload's `frame_kind` contradicts the frame-header Frame Type (§4.1). |
| `3` | FilterUnsupported | A present TELEMETRY_SUBSCRIBE selector field is not implemented; the responder MUST reply this rather than over-deliver (§6.1). |
| `4` | UnknownSubscription | A TELEMETRY_CREDIT, TELEMETRY_UNSUBSCRIBE-provoked fault, or subscribed TELEMETRY_REPORT names a `sub_id` with no live subscription. |
| `5` | SubscriptionRefused | The responder declines a TELEMETRY_SUBSCRIBE (unsupported class, or a local resource, policy, or rate limit reached). |
| `6` | NotAdvertised | The Telemetry channel `0x000A` was not advertised for this association, or the channel is disabled by local policy (§2.1). |

A standalone (unsolicited) TELEMETRY_REPORT is one-way and generates no error reply.
A subscribed REPORT that a consumer finds malformed is handled at the subscription
level: the consumer MAY cancel with a TELEMETRY_UNSUBSCRIBE rather than emit a
TELEMETRY_ERROR (the error frame answers a subscribe or credit request, not a pushed
report).

## 9. Operation and state model

Each subscription is keyed by its `sub_id`, scoped to the association and to one
direction, and progresses through the following states:

```
IDLE
  -> TELEMETRY_SUBSCRIBE sent/received ->            PENDING
       -> TELEMETRY_SUB_ACK ->                       ACTIVE (credit = N)
            -> REPORT batch emitted ->               ACTIVE (credit decremented by 1)
                 -> credit reaches 0 ->              PAUSED
                      -> TELEMETRY_CREDIT ->         ACTIVE (credit increased)
       -> TELEMETRY_ERROR (SubscriptionRefused) ->   CLOSED
  -> TELEMETRY_UNSUBSCRIBE or association close ->    CLOSED
```

A TELEMETRY_SUBSCRIBE moves the subscription from IDLE to PENDING. A TELEMETRY_SUB_ACK
moves it to ACTIVE with the acknowledged credit; a refusal (TELEMETRY_ERROR
`SubscriptionRefused`) moves it from PENDING to CLOSED. In ACTIVE, each emitted REPORT
batch decrements available credit by one; reaching zero credit moves the subscription
to PAUSED, where the producer MUST NOT emit further batches until a TELEMETRY_CREDIT
returns it to ACTIVE. A TELEMETRY_UNSUBSCRIBE, or the close of the association, moves
the subscription to CLOSED.

A standalone (unsolicited) TELEMETRY_REPORT is **stateless push**: it carries no
`corr`, participates in no credit accounting, and is best-effort. A receiver MAY drop
an unsolicited TELEMETRY_REPORT at any time without protocol error.

All subscription and credit state is **association-scoped** and MUST be discarded on
association close. A peer MUST NOT carry Telemetry subscription or credit state across
associations. Because the Telemetry channel is Bidirectional, a peer MUST bound the
resources a remote peer can consume in **either** direction: it MUST bound the number
of concurrent subscriptions and the rate of TELEMETRY_SUBSCRIBE frames it will
accept, and MAY reply TELEMETRY_ERROR `SubscriptionRefused` rather than allocate
without limit.

## 10. Security and privacy considerations

This section supplements the core specification's Security Considerations; it does
not restate them.

Every Telemetry frame is AEAD-protected like all N-PAMP frames and is carried under
the association's existing authentication (the core specification's handshake binds
both peer identities into the transcript and the Finished MAC). A receiver therefore
knows that a report was sent by the authenticated peer, **but not that the reported
metric, event, or health condition is accurate**: a report is a **claim by the
emitting peer** about its own operation, and nothing in this document attests the
truth of that claim. Authentication is not authorization: a responder MUST enforce
its own policy on every subscribe and report regardless of the peer's identity.

Operational telemetry can be sensitive: metric values, event attributes, and health
statements may disclose a peer's internal load, topology, failure conditions, or
usage. A peer SHOULD emit only the metrics, events, and health appropriate to the
authenticated peer and to local policy, MAY return an empty or filtered stream to a
peer it does not wish to inform (an empty `classes` in a SUB_ACK, or a
`SubscriptionRefused`, is a valid and non-committal response), and MUST keep the
`message`, `reason`, and `detail` fields peer-safe — a `message` or `reason` MUST NOT
carry internal cause beyond what the emitter intends to disclose (§5.2, §5.3, §8), so
that the telemetry surface does not leak the responder's internal structure to a peer.

Because a bulk producer can flood a consumer, the §7 credit mechanism is **REQUIRED**
for subscribed delivery: a consumer MUST NOT be forced to buffer beyond the credit it
granted, and a producer that continues to emit REPORT batches after its credit is
exhausted is in violation of §7 and §11. An unsolicited TELEMETRY_REPORT MUST be
droppable by a receiver at any time without protocol error, so that an unsolicited
producer cannot compel buffering either. Because either peer may originate operations
on this Bidirectional channel, both directions are subject to these limits.

The URG flag MUST NOT be set on any Telemetry frame (§2.4). This prevents a bulk
operational-metrics stream from usurping the scheduling of interactive or control-plane
traffic, preserving the channel's bulk posture even under an adversarial or
misbehaving producer.

## 11. Conformance

An implementation conforms to NPAMP-TELEMETRY if and only if it rests on a
core-conformant N-PAMP wire implementation and, on the Telemetry channel `0x000A`, it:

1. Treats `0x000A` as the Telemetry channel with the core registry identity (name
   Telemetry; purpose operational metrics and health reporting; minimum profile
   Standard; direction Bidirectional), does not repurpose the channel identifier,
   enables it only at the **Standard** profile or higher, and drops any frame
   received on an unadvertised Telemetry channel (§2.1);

2. Treats the channel as **Bidirectional but not Multi-stream** — carrying all frames
   of a direction over the one per-direction stream, multiplexing concurrent
   subscriptions logically by `corr` / `sub_id`, and never opening multiple concurrent
   transport sub-streams as though the channel were Multi-stream (§2.2);

3. Uses only the `0x0100`-and-above channel-application frame types of §3
   (TELEMETRY_REPORT `0x0100` … TELEMETRY_ERROR `0x0105`), preserves the core meaning
   of the reserved all-channel frame types, defines no Telemetry semantics in the
   future-core gap `0x000B`–`0x002F` or the companion-extension band
   `0x0030`–`0x00FF` (the Telemetry channel has no core-reserved extension range), and
   never sets the URG flag on a Telemetry frame (§2.4, §3);

4. Encodes every Telemetry payload as a deterministic-CBOR map, ignores unrecognized
   non-negative integer keys without altering handling of recognized keys, and rejects
   a malformed, kind-mismatched, or unrecognized-negative-key payload with the
   corresponding TELEMETRY_ERROR (§4, §8);

5. Emits and parses TELEMETRY_REPORT with at least one non-empty array among
   `metrics`, `events`, and `health` — each metric carrying `name`, `ts`, `kind`, and
   `value`; each event carrying `name` and `ts`; each health statement carrying
   `domain`, `ts`, and `status` — retains an item whose `unit` it does not recognize,
   and treats an unrecognized `status` as `unknown` and an unrecognized `severity` as
   `critical` rather than silently discarding it (§5);

6. Enforces correlation (§4.1, per NPAMP-BRIDGE §5): a TELEMETRY_SUBSCRIBE carries a
   unique-per-direction `corr`; TELEMETRY_SUB_ACK, TELEMETRY_CREDIT,
   TELEMETRY_UNSUBSCRIBE, TELEMETRY_ERROR, and every subscribed TELEMETRY_REPORT echo
   it verbatim; a standalone TELEMETRY_REPORT omits `corr`; and replies are matched by
   `corr` / `sub_id`, not by frame sequence number;

7. Applies TELEMETRY_SUBSCRIBE selectors conjunctively, and replies `FilterUnsupported`
   rather than silently over-delivering when it cannot honor a present selector field
   (§6.1);

8. Honors the §7 credit mechanism — never exceeding the accumulated per-subscription
   credit, pausing emission at zero credit, resuming only on a TELEMETRY_CREDIT, and
   composing the per-subscription credit with the core connection-level FLOW_UPDATE
   `0x000A` credit without redefining the `0x000A` body — and bounds concurrent
   subscriptions and the TELEMETRY_SUBSCRIBE rate in both directions (§7, §9);

9. Stops emitting REPORT batches for a `sub_id` upon TELEMETRY_UNSUBSCRIBE, treats an
   UNSUBSCRIBE for an unknown `sub_id` as idempotent, discards all subscription and
   credit state on association close, carries none across associations (§6.3, §9), and
   keeps the error/report surface peer-safe, leaking no internal cause (§8, §10); and

10. Carries no foreign agent protocol on channel `0x000A`, defines and consumes no
    extension-TLV tag, does not build on NPAMP-BRIDGE except by reference to its
    correlation discipline, and does not carry Sensory `0x0009` observation semantics
    on this channel (§1.2, §2.3).

Machine-gradable conformance vectors exist for the Telemetry channel's payload-decode
surface: the `telemetry.body.decode` operation group in the conformance corpus, produced
by an independent RFC 8949 byte constructor (`test-vectors/gen/telemetry_oracle.py`, whose
expected values are derived from the RFC 8949 encoding and not from the reference
implementation it grades, so the oracle is non-circular) and graded by `npamp-conform`
against the Go reference implementation, cross-validated by
`impl/go/zz_telemetry_oracle_xval_test.go`, covers the §4 payload-encoding and §4.1
common-envelope MUST-reject clauses — so a claim of conformance to those clauses is graded
on the payload surface. Beyond that payload surface, the §5–§9 behavioural clauses (the
subscription flow, the credit/backpressure state machine, the standalone-versus-subscribed
distinction, and the leak-prevention requirements) are graded only by a live-exchange
harness once one exists; a conformance claim for those clauses MUST NOT present them as
graded until that harness grades them. A conformance test suite SHOULD assert each clause
above with a recorded Telemetry exchange on channel `0x000A`: an unsolicited REPORT
batch carrying metrics, events, and health (no `corr`); a TELEMETRY_SUBSCRIBE →
TELEMETRY_SUB_ACK → REPORT (repeated until credit reaches zero) → TELEMETRY_CREDIT →
REPORT → TELEMETRY_UNSUBSCRIBE sequence; a producer that pauses at zero credit and
resumes only on a TELEMETRY_CREDIT; a refused subscription (`SubscriptionRefused`); a
`FilterUnsupported` rejection of an unsupported selector field; and each
TELEMETRY_ERROR code provoked by a malformed or unsupported input.
