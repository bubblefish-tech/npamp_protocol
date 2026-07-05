# NPAMP-CC-STREAM — Streaming Carriage Class (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words MUST, MUST NOT, REQUIRED,
> SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL in this
> document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when,
> and only when, they appear in all capitals, as shown here. This document defines a
> carriage class for event/streaming protocols over the N-PAMP **Bridge channel
> `0x000D`**. It builds on NPAMP-BRIDGE (the bridge framework) and consumes only code
> points the core specification and NPAMP-BRIDGE already define. It introduces no
> change to the core wire format and redefines no part of NPAMP-BRIDGE.

## 1. Scope

NPAMP-CC-STREAM specifies how an event/streaming foreign protocol — one whose
replies are a sequence of typed events rather than a single message — is carried over
the NPAMP-BRIDGE stream frames `BRIDGE_STREAM_DATA` (`0x0104`) and `BRIDGE_STREAM_END`
(`0x0105`). It addresses three concerns that a multi-event reply raises and that
NPAMP-BRIDGE does not by itself resolve:

1. **Resumption.** When an association migrates, a key update interleaves, or a
   transport stream is re-established, a receiver that has already consumed part of a
   stream needs to request continuation from the first unconsumed event rather than
   from the beginning. This document defines a per-stream monotonic **event identifier**
   and a **resume cursor** that names the last event a receiver durably consumed
   (§5, §6).

2. **Cancellation.** A receiver that no longer wants a stream's remaining events needs
   to tell the sender to stop producing them, without tearing down the channel or the
   association. This document defines an explicit **stream cancel** (§7).

3. **Bidirectionality.** Some streaming protocols are full-duplex: events flow in both
   directions within one logical exchange. This document states how the NPAMP-BRIDGE
   correlation model and the core full-duplex channel architecture carry such streams
   (§8).

This document is a carriage *class*: it specifies structural behavior shared by a
family of streaming protocols. A per-protocol mapping document binds a specific
foreign protocol's event types and resume semantics to the mechanisms defined here.

### 1.1 Relationship to NPAMP-BRIDGE

NPAMP-CC-STREAM inherits the entire NPAMP-BRIDGE contract without modification:
octet-for-octet transparent carriage of the foreign message (NPAMP-BRIDGE §1), the
BridgeEnvelope TLV (NPAMP-BRIDGE §4), the correlation rules (NPAMP-BRIDGE §5), the
structured-error model (NPAMP-BRIDGE §6), and the SafetyLabel TLV (NPAMP-BRIDGE §7).
A stream carried under this document is, at the NPAMP-BRIDGE layer, an ordinary
sequence of `BRIDGE_STREAM_DATA` frames terminated by one `BRIDGE_STREAM_END` frame,
all echoing the originating request's `correlation_id`. This document adds metadata
*around* the foreign events; it never parses, re-serializes, or rewrites a foreign
event, and the `final` bit, `message_kind` agreement, and correlation rules of
NPAMP-BRIDGE continue to apply unchanged.

### 1.2 Relationship to the core Stream channel `0x000C`

The core specification defines a distinct Stream channel `0x000C` for general-purpose
multiplexed full-duplex streaming (tokens, audio, video, file transfer). NPAMP-CC-STREAM
governs streamed *foreign-protocol* replies on the Bridge channel `0x000D`; it does
not define behavior on channel `0x000C` and does not move Bridge traffic onto it. A
deployment MAY carry raw media or bulk byte streams on channel `0x000C` per the core
specification; that carriage is out of scope here (§3).

## 2. Terminology

In addition to the terms of the core specification and NPAMP-BRIDGE:

Stream:
: A single logical multi-event reply identified by one NPAMP-BRIDGE `correlation_id`
  on the Bridge channel, consisting of zero or more `BRIDGE_STREAM_DATA` frames
  followed by exactly one `BRIDGE_STREAM_END` frame in the same direction.

Event:
: The foreign message carried in one `BRIDGE_STREAM_DATA` frame.

Event identifier (event-id):
: A per-stream, strictly monotonically increasing unsigned integer that names an
  event's position within its stream (§5).

Resume cursor:
: A value naming the last event identifier a receiver has durably consumed, supplied
  when requesting continuation of a stream (§6).

Producer:
: The peer emitting `BRIDGE_STREAM_DATA`/`BRIDGE_STREAM_END` for a given stream. Under
  NPAMP-BRIDGE §5 this is the responder for that exchange.

Consumer:
: The peer receiving the stream. Under NPAMP-BRIDGE §5 this is the requester for that
  exchange.

## 3. Non-scope

This document does NOT:

- Define or modify any core channel, frame type, profile, or cryptographic suite —
  reason: those are fixed by the core specification;
- Define or modify the BridgeEnvelope TLV, the SafetyLabel TLV, the NPAMP-BRIDGE frame
  types, or the NPAMP-BRIDGE correlation/error model — reason: NPAMP-BRIDGE owns them
  and this document only builds on them;
- Define behavior on the core Stream channel `0x000C` — reason: §1.2, that channel is
  governed by the core specification;
- Parse, interpret, validate, or transform any foreign event payload — reason: the
  NPAMP-BRIDGE transparency rule forbids it;
- Guarantee delivery, ordering across distinct streams, or exactly-once event
  semantics beyond what the core per-channel sequence space and the mechanisms in this
  document provide — reason: those are transport and application properties; this
  document provides at-least-once resumability and an ordering invariant *within* a
  single stream (§5.1);
- Define the foreign event vocabulary of any specific protocol — reason: that is the
  task of a per-protocol mapping document.

## 4. Stream framing recap and added metadata

A stream is carried exactly as NPAMP-BRIDGE specifies. NPAMP-CC-STREAM adds one
extension TLV, the **StreamControl TLV** (§5), to the Bridge frame payload. With the
StreamControl TLV present, a `BRIDGE_STREAM_DATA` frame's payload is:

```
  BridgeEnvelope TLV   (Type 0x0010, REQUIRED; NPAMP-BRIDGE §4)
  StreamControl TLV    (Type per §5.3, REQUIRED on streams carried under this document)
  SafetyLabel TLV      (Type 0x0013, OPTIONAL; NPAMP-BRIDGE §7)
  <foreign event>      (carried verbatim; NPAMP-BRIDGE §1)
```

The StreamControl TLV uses the core specification's extension-TLV encoding (Type
`u16`, Length `u16`, Value), like every other Bridge TLV. The order of TLVs within a
payload is not significant; a receiver MUST locate each TLV by its Type. A receiver
that does not implement NPAMP-CC-STREAM and encounters the StreamControl TLV applies
the core specification's unknown-TLV rule for the assigned Type (§5.3, §9).

## 5. StreamControl TLV

### 5.1 Purpose and the event-id invariant

The StreamControl TLV carries the per-stream event identifier and the stream's control
signals (resume request and cancel). For every stream carried under this document:

- A producer MUST assign each `BRIDGE_STREAM_DATA` frame of a stream a strictly
  monotonically increasing `event_id`. The first data frame of a stream MUST carry the
  `event_id` value the consumer requested (1 for a fresh stream; see §6 for resume),
  and each subsequent data frame MUST carry an `event_id` greater than the previous
  data frame's `event_id` on that stream.
- `event_id` values within a stream MUST be unique and MUST NOT decrease. A producer
  MAY skip values (the sequence need not be contiguous) but MUST NOT reuse a value
  within a stream.
- `event_id` is scoped to a single stream, identified by the NPAMP-BRIDGE
  `correlation_id`. It carries no meaning across streams and is independent of the
  core per-(channel, direction) sequence number, which orders frames on the wire but
  does not identify a foreign event.
- The `BRIDGE_STREAM_END` frame that terminates a stream MUST carry an `event_id` that
  is greater than the `event_id` of every `BRIDGE_STREAM_DATA` frame of that stream, so
  that a consumer can recognize a complete stream by observing the terminal event-id.

This invariant gives a consumer a stable, producer-assigned name for "the last event I
durably consumed," which is the value it supplies to resume (§6).

### 5.2 Value layout

Multi-octet integers are big-endian, consistent with the core specification and
NPAMP-BRIDGE.

| Field | Size | Meaning |
|---|---|---|
| `version` | u8 | StreamControl format version. This document defines `0x01`. A receiver MUST reject (NPAMP-BRIDGE BRIDGE_ERROR, code `EnvelopeMalformed`) a StreamControl TLV whose `version` it does not implement. |
| `control` | u8 | Control selector: `0x00` = data (an event-bearing frame), `0x01` = resume request, `0x02` = cancel. Values `0x03`–`0xFF` are reserved; a sender MUST set only a defined value and a receiver MUST reject an undefined value with `EnvelopeMalformed`. |
| `flags` | u8 | Bit 0 `resumable` — the producer asserts this stream MAY be resumed (§6). Bit 1 `cancel_ack` — set only on a `BRIDGE_STREAM_END` that acknowledges a cancel (§7). Bits 2–7 reserved; a sender MUST set them 0 and a receiver MUST ignore them. |
| `event_id` | u64 | The event identifier (§5.1) for a data frame or terminating frame; the resume cursor for a resume request (§6); the last produced event-id for a cancel acknowledgement (§7). |

The StreamControl TLV is fixed-length: `version` (1) + `control` (1) + `flags` (1) +
`event_id` (8) = 11 octets. A receiver MUST reject a StreamControl TLV whose Length is
not 11 with `EnvelopeMalformed`.

### 5.3 TLV type assignment

The StreamControl TLV requires a Bridge-payload TLV Type. The core specification's TLV
registry reserves Types `0x0010`, `0x0013`, and `0x0014` for companion specifications;
NPAMP-BRIDGE consumes `0x0010` (BridgeEnvelope) and `0x0013` (SafetyLabel), and the
core specification marks `0x0014` "handshake only," which makes it unavailable for a
per-frame stream TLV. No remaining non-handshake companion TLV Type is reserved by the
core specification at the time of writing.

This document therefore uses TLV Type **`0x0011`** for the StreamControl TLV
**provisionally**, pending an explicit reservation of that Type for companion use by the
core specification (see §10 and §11). `0x0011` is selected because it is unassigned in
the core specification's TLV type registry and is adjacent to the existing
companion-reserved range. Until the core specification reserves `0x0011` for companion
use, an implementation MUST treat the assignment in this document as provisional and
MUST NOT assume interoperability with a peer that has bound `0x0011` to a different
meaning. A sender MUST NOT relocate the StreamControl TLV to a Type in the
forward-incompatible range `0x8000`–`0xFFFF`, because doing so would force every
receiver — including NPAMP-BRIDGE-only receivers that have no need to interpret stream
control — to reject the frame under the core specification's unknown-TLV rule, defeating
graceful carriage of the underlying stream.

## 6. Resumption

### 6.1 Producer obligations

A producer that can re-emit a stream's remaining events from a given event-id MUST set
the `resumable` flag (§5.2, bit 0) on the StreamControl TLV of that stream's data and
terminating frames. A producer that cannot resume a stream MUST NOT set `resumable`; a
consumer MUST NOT attempt to resume a stream whose frames did not assert `resumable`.

A producer MUST retain enough state to re-emit events after a given `event_id` for as
long as it advertises that stream as resumable. The duration and bound of that
retention are a deployment and per-protocol-mapping matter and are out of scope here
(§3); a producer that has discarded the state required to honor a resume request MUST
refuse the resume request as specified in §6.3.

### 6.2 Consumer resume request

To resume a stream, a consumer sends a `BRIDGE_REQUEST` (NPAMP-BRIDGE `0x0100`) that:

- Echoes, in its BridgeEnvelope `correlation_id`, the `correlation_id` of the stream it
  is resuming, so the producer can identify the stream;
- Carries a StreamControl TLV with `control = 0x01` (resume request) and `event_id` set
  to the resume cursor — the `event_id` of the last event the consumer durably
  consumed, or `0` to request the stream from its first event;
- Carries the foreign request body unchanged where the foreign protocol requires the
  original request parameters to re-establish the stream; a per-protocol mapping
  specifies whether the foreign body is re-sent or omitted on resume.

A consumer MUST NOT issue a resume request with an `event_id` greater than the highest
`event_id` it has actually consumed on that stream.

### 6.3 Producer response to a resume request

On receiving a resume request, a producer MUST do exactly one of:

1. **Resume.** Emit a stream whose first `BRIDGE_STREAM_DATA` frame carries the first
   unconsumed event, with an `event_id` strictly greater than the requested resume
   cursor, and continue under the event-id invariant of §5.1. The resumed frames reuse
   the stream's `correlation_id`.

2. **Restart.** If the producer cannot resume from the requested cursor but can re-emit
   the stream from its beginning, it MUST signal this to the consumer by emitting a new
   stream from `event_id` 1. A per-protocol mapping specifies whether a restart reuses
   the original `correlation_id` or requires a fresh request/`correlation_id`; absent
   such a mapping, a producer MUST require a fresh `BRIDGE_REQUEST` and MUST NOT silently
   replay already-consumed events under the same cursor expectation.

3. **Refuse.** If the producer can neither resume nor restart, it MUST reply
   `BRIDGE_ERROR` (NPAMP-BRIDGE `0x0102`) echoing the stream's `correlation_id`, with
   the N-PAMP transport error `NotResumable` (§6.4). A producer MUST NOT report success
   for a resume it cannot honor (this is the NPAMP-BRIDGE §6 prohibition on reporting
   success for an undelivered message, applied to resumption).

A consumer that receives events whose `event_id` does not strictly exceed its resume
cursor MUST discard the duplicate events (they were already consumed) and MUST NOT
present them to the application twice; this makes resumption at-least-once-safe at the
event boundary.

### 6.4 Resume error code

This document defines one additional N-PAMP transport error, carried in a
`BRIDGE_ERROR` exactly as NPAMP-BRIDGE §6 specifies for sub-foreign-protocol failures:

| Code | Name | Meaning |
|---|---|---|
| 6 | NotResumable | The producer cannot continue the named stream from the requested resume cursor and cannot restart it. |

Code `6` continues the NPAMP-BRIDGE transport-error numbering (which assigns `1`–`5`).
This document does not redefine any NPAMP-BRIDGE error code.

## 7. Cancellation

A consumer that no longer wants a stream's remaining events sends an explicit cancel.
The cancel reuses NPAMP-BRIDGE stream framing and introduces no new frame type.

### 7.1 Consumer cancel

To cancel a stream, the consumer sends a `BRIDGE_STREAM_END` frame (NPAMP-BRIDGE
`0x0105`) **in the consumer-to-producer direction**, echoing the stream's
`correlation_id`, carrying a StreamControl TLV with `control = 0x02` (cancel) and
`event_id` set to the highest `event_id` the consumer has consumed (or `0` if none).
Because NPAMP channels are full-duplex (core specification, Channel Architecture), this
upstream `BRIDGE_STREAM_END` travels on the consumer's send sequence space and does not
collide with the producer's downstream stream frames.

A cancel is advisory about *future* events only: the consumer MUST be prepared to
receive and discard data frames already in flight from the producer, up to and
including the producer's acknowledgement (§7.2).

### 7.2 Producer handling of cancel

On receiving a cancel, a producer:

- MUST cease emitting new `BRIDGE_STREAM_DATA` frames for that stream as soon as it
  observes the cancel;
- MUST send exactly one `BRIDGE_STREAM_END` frame in the producer-to-consumer direction,
  echoing the stream's `correlation_id`, with a StreamControl TLV whose `cancel_ack`
  flag (§5.2, bit 1) is set and whose `event_id` is the last event-id the producer
  actually emitted, so the consumer learns the true tail of the stream;
- MUST set the NPAMP-BRIDGE BridgeEnvelope `final` bit on that terminating frame, as for
  any stream termination;
- MUST release any resume state for the stream after acknowledging the cancel, unless a
  per-protocol mapping specifies otherwise; a consumer MUST NOT resume a stream it has
  cancelled.

A producer that has already sent its natural `BRIDGE_STREAM_END` before observing the
cancel MUST NOT send a second terminating frame; the stream is already complete, and
the consumer MUST treat its own cancel as moot.

### 7.3 Cancel is not an error

A cancelled stream has completed normally from the protocol's standpoint. A producer
MUST NOT report a cancelled stream as `BRIDGE_ERROR`, and a consumer MUST NOT treat a
`cancel_ack` `BRIDGE_STREAM_END` as a failure. A foreign-protocol-level cancellation
semantic (where the foreign protocol itself defines a cancel message) is carried as an
ordinary foreign message under NPAMP-BRIDGE and is independent of this transport-level
cancel; a per-protocol mapping states how the two relate.

## 8. Bidirectional and full-duplex streams

Some streaming protocols carry events in both directions within a single logical
exchange. The core specification makes every channel full-duplex — each peer maintains
an independent send and receive sequence space and independent per-direction traffic
keys — and NPAMP-BRIDGE §5 assigns requester/responder roles per exchange rather than
per association. NPAMP-CC-STREAM relies on both properties and adds no new wire
mechanism for bidirectionality:

- A full-duplex foreign stream is carried as **two correlated NPAMP-BRIDGE streams**,
  one in each direction. Each direction is an ordinary stream under §4–§7 with its own
  `event_id` sequence; the two directions MUST share the foreign exchange's
  `correlation_id` so that a peer can associate the two halves. The event-id space of
  each direction is independent: an `event_id` in the consumer-to-producer direction
  has no ordering relationship to an `event_id` in the producer-to-consumer direction.
- Either peer MAY originate the exchange. The peer that emits the initiating
  `BRIDGE_REQUEST` is the requester for that exchange (NPAMP-BRIDGE §5); the other peer
  MAY nonetheless emit its own direction's stream frames concurrently, because the
  channel is full-duplex.
- Resumption (§6) and cancellation (§7) apply **per direction**. Resuming or cancelling
  one direction of a full-duplex stream does not resume or cancel the other; a peer that
  wishes to terminate both directions MUST cancel each direction it consumes.

A deployment that needs raw full-duplex byte or media streaming, rather than carriage of
a foreign event protocol, SHOULD use the core Stream channel `0x000C` (§1.2) instead of
encapsulating it under this document.

## 9. Processing requirements

A receiver implementing NPAMP-CC-STREAM:

- MUST locate the StreamControl TLV by its assigned Type (§5.3) and parse its
  fixed 11-octet Value (§5.2);
- MUST reject, with NPAMP-BRIDGE `BRIDGE_ERROR` code `EnvelopeMalformed`, any
  StreamControl TLV that is truncated, carries an unimplemented `version`, carries an
  undefined `control` value, or carries a Length other than 11;
- MUST enforce the event-id invariant of §5.1 on received streams and MUST reject, with
  `EnvelopeMalformed`, a `BRIDGE_STREAM_DATA` frame whose `event_id` does not strictly
  exceed the previous data frame's `event_id` on the same stream;
- MUST treat the foreign event as opaque and MUST NOT modify it (NPAMP-BRIDGE §1);
- MUST apply the core specification's unknown-TLV rule if it does not implement this
  document and encounters the StreamControl TLV at its assigned Type: for a Type with
  the high bit (`0x8000`) clear, the TLV is ignored and the foreign stream is carried as
  ordinary NPAMP-BRIDGE stream frames without resume or cancel support.

## 10. IANA and code-point considerations

This document defines no new IANA-hosted registry and requests no IANA action. It
consumes code points from registries maintained within the core specification and
NPAMP-BRIDGE, as follows:

| Resource | Source registry | Use in this document | Status |
|---|---|---|---|
| Bridge channel `0x000D` | Core channel registry | Carriage substrate | Already reserved by the core specification |
| Frame types `0x0104` / `0x0105` | NPAMP-BRIDGE frame types | Stream data / stream end (reused, including for upstream cancel) | Already defined by NPAMP-BRIDGE |
| Frame type `0x0100` | NPAMP-BRIDGE frame types | Resume request (reused `BRIDGE_REQUEST`) | Already defined by NPAMP-BRIDGE |
| Transport error code `6` `NotResumable` | NPAMP-BRIDGE transport-error numbering | Resume refusal (§6.4) | Defined by this document, continuing the NPAMP-BRIDGE `1`–`5` sequence |
| TLV Type `0x0011` (StreamControl) | Core TLV type registry | StreamControl TLV (§5) | **Provisional** — not yet reserved for companion use by the core specification (§11) |

No new frame type and no change to the 36-octet header, the channel registry, or any
cryptographic suite is introduced. The single open allocation is the StreamControl TLV
Type, addressed in §11.

## 11. Open allocation requiring a maintainer decision

The StreamControl TLV needs a non-handshake Bridge-payload TLV Type. The core
specification reserves Types `0x0010`, `0x0013`, and `0x0014` for companion
specifications; the first two are consumed by NPAMP-BRIDGE and the third is
handshake-only. There is therefore **no core-reserved, non-handshake companion TLV Type
available** for this document to consume cleanly. This document uses `0x0011`
provisionally (§5.3). Resolving this requires one of the following maintainer decisions:

1. The core specification reserves an additional companion TLV Type (for example
   `0x0011`) for per-frame companion use, after which this document cites that
   reservation and removes the "provisional" qualifier; **or**

2. NPAMP-BRIDGE is extended to carry an event-id and control selector within an
   already-reserved structure it owns, after which this document references that field
   instead of defining a new TLV. (This document deliberately does not redefine
   NPAMP-BRIDGE, per its scope.)

Until one of these is chosen, the StreamControl TLV Type `0x0011` is provisional and
interoperability across independent implementations is not guaranteed.

## 12. Security considerations

This document inherits the security considerations of the core specification and of
NPAMP-BRIDGE; the StreamControl TLV is carried inside the AEAD-protected Bridge frame
payload and is therefore authenticated and confidentiality-protected exactly as the
BridgeEnvelope and SafetyLabel TLVs are. The additional considerations specific to
streaming carriage are:

- **Resume-cursor forgery and over-read.** The resume cursor (§6.2) is an `event_id`
  supplied by the consumer. A producer MUST treat a resume request as a request for
  events *after* the cursor and MUST NOT use the cursor to grant access to events the
  consumer would not otherwise receive; the cursor selects a position, not an
  authorization. A producer MUST re-apply any per-protocol authorization to a resumed
  stream that it would apply to a fresh stream, because the resume request is a fresh
  `BRIDGE_REQUEST` and carries the same SafetyLabel obligations (NPAMP-BRIDGE §7).

- **Replay of resumed events.** Because resumption can legitimately re-deliver events
  at the producer's discretion, a consumer MUST rely on the strict-monotonic event-id
  invariant (§5.1) to detect and discard duplicates (§6.3) rather than assuming
  exactly-once delivery. The core specification's per-(channel, direction) replay window
  protects the wire frames; the event-id invariant protects the *application's* view of
  the event sequence within a stream.

- **Cancellation as a resource-exhaustion control, and its abuse.** Cancellation (§7)
  exists so a consumer can bound a producer's work. A producer MUST cease production
  promptly on cancel to realize that benefit. Conversely, a consumer that repeatedly
  opens and cancels streams imposes setup cost on a producer; a producer SHOULD apply
  the same rate and resource controls to stream creation that it applies to any
  `BRIDGE_REQUEST`, and MUST NOT let outstanding resume state for cancelled or abandoned
  streams accumulate without bound (§7.2).

- **Event-id state retention.** Honoring resume (§6.1) requires a producer to retain
  per-stream state. An attacker that opens many resumable streams and never consumes
  them can drive that retention. A producer MUST bound the number and lifetime of
  retained resumable streams and MUST refuse resumption (`NotResumable`, §6.4) once it
  has reclaimed the state, rather than over-retaining.

## 13. Conformance

An implementation conforms to NPAMP-CC-STREAM if and only if, for streams it carries
under this document on the Bridge channel, it:

1. Inherits and continues to satisfy the NPAMP-BRIDGE conformance clauses (NPAMP-BRIDGE
   §9) for the underlying stream frames (§1.1);
2. Emits and parses the StreamControl TLV with its fixed 11-octet layout, rejecting
   malformed, wrong-length, unimplemented-version, and undefined-control TLVs as
   specified (§5.2, §9);
3. Assigns and enforces the strict-monotonic per-stream `event_id` invariant, including
   the terminal-event-id rule for `BRIDGE_STREAM_END` (§5.1), and rejects out-of-order
   data frames (§9);
4. On a stream it advertises as `resumable`, honors a resume request by resuming,
   restarting, or refusing with `NotResumable`, and never reports success for a resume it
   cannot honor (§6.3);
5. Discards events at or below a resume cursor so that resumption is at-least-once-safe
   at the event boundary (§6.3);
6. Supports explicit cancellation: a consumer can cancel via an upstream
   `BRIDGE_STREAM_END` carrying `control = cancel`, and a producer ceases production and
   acknowledges with a single `cancel_ack` `BRIDGE_STREAM_END` carrying the true tail
   event-id (§7);
7. Carries a full-duplex foreign stream as two correlated per-direction streams sharing
   the exchange `correlation_id`, with independent event-id spaces and per-direction
   resume and cancel (§8);
8. Treats the StreamControl TLV Type as provisional and does not assume cross-
   implementation interoperability until the Type is reserved for companion use by the
   core specification (§5.3, §11).

A conformance test suite SHOULD assert each clause above with a recorded multi-event
stream exchange, including at minimum: a complete stream, a resumed stream from a
non-zero cursor, a refused resume (`NotResumable`), a consumer-initiated cancel with
producer acknowledgement, and a full-duplex stream exercising both directions.
