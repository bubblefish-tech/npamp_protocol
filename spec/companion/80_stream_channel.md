# NPAMP-STREAM — Native Multiplexed Sub-Stream Framing (companion to draft-bubblefish-npamp-02)

> Status: **DRAFT companion specification.** The key words MUST, MUST NOT, REQUIRED,
> SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL are to be
> interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they
> appear in all capitals, as shown here. This document defines native multiplexed
> sub-stream framing over the N-PAMP **Stream channel `0x000C`**: how a peer opens,
> writes, flow-controls, closes, and abruptly tears down concurrent bidirectional
> sub-streams of raw byte or media data on one association. It consumes only frame-type
> code points the core specification (draft-bubblefish-npamp-02) reserves for the Stream
> channel, and it introduces no change to the core wire format, the core frame header,
> or any reserved all-channel frame type.

## 1. Scope

### 1.1 In scope

This document specifies, over the Stream channel `0x000C` of the N-PAMP core
specification (the "core specification", draft-bubblefish-npamp-02):

1. A set of Stream-channel **application frame types**, drawn from the channel-specific
   frame-type namespace that begins at `0x0100` (core specification §4.6), that realize
   the concurrent sub-streams the core specification's channel registry advertises for
   `0x000C` but leaves unencoded;
2. The encoding of each frame's body as a **deterministically encoded CBOR** map
   (core specification §4.5, §11.9; RFC 8949);
3. A **sub-stream identifier** space whose parity is bound to the handshake role, so
   that both peers may open sub-streams concurrently without collision;
4. A **two-level flow-control** model in which every write MUST respect both a
   per-sub-stream absolute-offset credit and the connection-level credit the core
   specification already defines; and
5. A **per-direction half-close lifecycle** with an explicit abrupt-reset path and a
   structured reset error code, and the state model that governs legal transitions.

### 1.2 Not in scope

This document does NOT:

* **Carry a foreign agent protocol.** Encapsulating a foreign agentic protocol
  (for example an RPC or message-passing protocol) octet-for-octet is the role of the
  Bridge channel `0x000D` and NPAMP-BRIDGE, not of channel `0x000C`. Reason: the Stream
  channel is a native byte/media transport, not a protocol-encapsulation channel
  (Stream channel interface reference, §1; NPAMP-BRIDGE §1).
* **Define or reuse the Bridge streaming carriage class.** The carriage of a streamed
  *foreign-protocol reply* (a sequence of typed foreign events, with foreign-event
  resumption and cancellation) is NPAMP-CC-STREAM on the Bridge channel `0x000D`.
  NPAMP-STREAM and NPAMP-CC-STREAM are distinct and MUST NOT be conflated (§2.3).
  Reason: foreign-event resumption is a Bridge-channel construct scoped to a foreign
  protocol; a native byte stream needs none of it (§7.5).
* **Define concrete frames in the reserved `0x0030`–`0x0034` range.** That range is
  reserved by the core specification to the Stream channel for a future standard
  lifecycle/flow-control extension; NPAMP-STREAM references it as reserved only and
  defines every operational frame in the `0x0100`+ application band (§3). Reason: the
  core reserves and a companion defines; this companion places its frames in the
  application band exactly as NPAMP-BRIDGE and NPAMP-DISC do.
* **Define the connection-level flow-control frame body.** The connection-level
  `FLOW_UPDATE` frame (`0x000A`) is an all-channel reserved frame owned by the core
  specification; NPAMP-STREAM states only how a sub-stream's credit composes with the
  connection-level credit (§6.3) and MUST NOT redefine the `0x000A` body. Reason: the
  `0x000A` body is core-owned; a companion that redefined it would fork the wire.
* **Define media codecs, container formats, or a file-transfer manifest.** The `data`
  octets are opaque to this document; a `content_type` hint (§5.1) classifies them but
  this document assigns no codec, container, or manifest schema. Reason: codec and
  container negotiation is an application concern above this framing layer.
* **Provide cross-association stream resumption.** A sub-stream and its absolute
  offsets are scoped to one association; when the association closes, all sub-stream
  state is discarded (§7.4). Reason: within one association the absolute `offset`
  already survives key update, so no in-association resume frame is needed, and
  cross-association resume would require durable identity this framing layer does not own.
* **Change the core frame header, a reserved all-channel frame type, the
  extension-TLV encoding, or any code point the core specification assigns.** Reason:
  NPAMP-STREAM is an application-band companion; it consumes reserved code points and
  redefines none.

## 2. Relationship to the core specification and related companions

### 2.1 Channel registration and the minimum-profile gate

The Stream channel `0x000C` is registered by the core specification with purpose
"multiplexed full-duplex streaming (tokens, audio, video, file transfer)", minimum
profile **Standard**, and direction **Multi-stream** (core specification §5;
`../../registries/channels.csv`). NPAMP-STREAM inherits that registration and adds no
exception to it:

* **Minimum-profile gate.** A peer MUST NOT enable NPAMP-STREAM framing below the
  **Standard** profile. The channel is available at Standard and at every higher
  profile; the higher profiles apply their profile-wide cryptographic requirements to
  every enabled channel, including this one, as fixed by the core specification's
  profile invariants (core specification, Profile Negotiation).
* **Advertisement gate.** A peer MUST NOT send or accept NPAMP-STREAM frames unless the
  Stream channel `0x000C` was advertised for the association during the handshake
  (core specification §5). Frames received on an unadvertised channel MUST be dropped.
* **Full-duplex, Multi-stream.** Under the core specification's channel architecture the
  channel is full-duplex — each peer maintains an independent send and receive sequence
  space and independent per-direction traffic keys — and Multi-stream, meaning it MAY
  carry multiple concurrent transport sub-streams (core specification §5). NPAMP-STREAM
  is the framing that realizes those sub-streams.

### 2.2 Frame-type namespace and the reserved Stream range

The core specification partitions each channel's frame-type namespace into four bands
(core specification §4.6): all-channel reserved types `0x0000`–`0x000A`; a
future-core-additions gap `0x000B`–`0x002F`; the companion-extension band
`0x0030`–`0x00FF`; and channel-specific application frame types `0x0100`–`0xFFFF`. The
frame-type space is channel-local: the same 16-bit type value denotes different frames
on different channels, scoped by the Channel ID header field.

At draft-02 the core specification reserves the range `0x0030`–`0x0034` to the Stream
channel within the companion-extension band. NPAMP-STREAM treats that range as
**reserved only** (§3): it defines no frame there and places all five operational
frames in the `0x0100`+ application band. Because the frame-type space is channel-local,
NPAMP-STREAM's `0x0100`–`0x0104` on channel `0x000C` do not collide with any other
channel's `0x0100`+ assignments (for example NPAMP-BRIDGE's `0x0100`+ on `0x000D` or
the Control channel handshake at `0x0100`–`0x0103`).

### 2.3 Distinction from NPAMP-CC-STREAM (Bridge foreign-reply streaming)

NPAMP-STREAM is a **native** Stream-channel companion. It is not a Bridge carriage
class. It MUST NOT be conflated with NPAMP-CC-STREAM:

| | NPAMP-STREAM (this document) | NPAMP-CC-STREAM |
|---|---|---|
| Channel | Stream `0x000C` | Bridge `0x000D` |
| Carries | Native raw byte / media octets | A streamed foreign-protocol reply (typed foreign events) |
| Framing | Native frames `0x0100`–`0x0104` on `0x000C` | Bridge frames (`BRIDGE_STREAM_DATA` / `BRIDGE_STREAM_END`) with a foreign body |
| Resumption / cancellation | Absolute offset within one association; cancellation = STREAM_RESET (§7) | Foreign-event resumption and cancellation (Bridge StreamControl constructs) |
| Envelope | None; addressed by `sub_stream_id` | BridgeEnvelope TLV around the foreign body |

An implementation MUST NOT apply NPAMP-CC-STREAM's Bridge-channel resumption,
cancellation, or StreamControl semantics to a native sub-stream on channel `0x000C`,
and MUST NOT carry a foreign protocol's messages on channel `0x000C` expecting
NPAMP-BRIDGE envelope, correlation, error, or safety-label semantics (Stream channel
interface reference §6; NPAMP-CC-STREAM §1.2, §3). A deployment that needs raw
full-duplex byte or media streaming rather than carriage of a foreign event protocol
uses NPAMP-STREAM on `0x000C`; a deployment that needs octet-for-octet carriage of a
foreign event protocol uses NPAMP-CC-STREAM on `0x000D`.

## 3. Stream-channel frame types

Within the Stream channel (`0x000C`) frame-type namespace — channel-specific
application types begin at `0x0100` (core specification §4.6) — this specification
defines five frame types:

| Type | Name | Reply | Purpose |
|---|---|---|---|
| `0x0100` | STREAM_OPEN | STREAM_OPEN (peer, opposite direction) or STREAM_RESET | Opens a sub-stream; carries its `sub_stream_id`, the opener's initial receive window, and a content-type hint. |
| `0x0101` | STREAM_DATA | None | Carries one chunk of sub-stream octets at an explicit absolute byte offset; MAY set `fin` to signal end-of-data for this direction. |
| `0x0102` | STREAM_CLOSE | None | Graceful half-close of one direction of a sub-stream, stating that direction's final octet count. |
| `0x0103` | STREAM_RESET | None | Abrupt teardown of BOTH directions of a sub-stream, carrying a reset error code. |
| `0x0104` | STREAM_WINDOW_UPDATE | None | Grants per-sub-stream flow-control credit as a new absolute cumulative receive offset. |

The reserved all-channel frame types (PING `0x0001`, PONG `0x0002`, CLOSE `0x0003`,
CLOSE_ACK `0x0004`, ERROR `0x0005`, KEY_UPDATE `0x0006`, KEY_UPDATE_ACK `0x0007`,
PATH_CHALLENGE `0x0008`, PATH_RESPONSE `0x0009`, and FLOW_UPDATE `0x000A`) retain their
core meaning on the Stream channel (core specification §4.6). An implementation MUST NOT
reuse them to carry sub-stream payload and MUST NOT use `0x0000` as a frame type.
Connection liveness, close, key rotation, path migration, connection-level error
signalling, and connection-level flow control on this channel use those all-channel
frames with their core meaning.

The core specification reserves `0x0030`–`0x0034` to the Stream channel in the
companion-extension band (core specification, Extension Points, "Reserved Frame-Type
Ranges"). NPAMP-STREAM defines **no** frame in that range; it is reserved to a future
standard Stream lifecycle/flow-control extension or a future core revision. All five
frame types above lie in the channel-specific application band at or above `0x0100`;
this document consumes no frame-type code point outside that band and reserves none in
the core specification's cross-channel reserved ranges.

## 4. Frame payload encoding

### 4.1 Payload container

A Stream frame's payload (the octets after the core frame header and any extension TLVs,
and before the AEAD tag) is a single **deterministically encoded CBOR** object as
defined by core specification §4.5 and §11.9 (deterministic CBOR, RFC 8949). The
payload MUST be a CBOR map whose keys are the unsigned integers defined in §4.2 and
§5 for the relevant frame type. A sender MUST produce the deterministic encoding
(core specification §11.9): byte-identical output for identical inputs, with the
canonical key ordering and shortest-form integer encoding RFC 8949 §4.2 requires. A
receiver MUST reject (STREAM_RESET, error code `StreamStateError`, or — where the frame
carries no usable `sub_stream_id` — a connection-level ERROR `0x0005`) any Stream frame
whose payload is not a valid deterministic-CBOR map, or whose payload omits a required
key or carries a key of the wrong CBOR major type.

Sub-stream operations are carried in the frame **payload**, not in extension TLVs. This
document defines and consumes no extension-TLV tag, and therefore claims none of the TLV
code points the core specification reserves.

### 4.2 Common envelope fields

Every NPAMP-STREAM payload map carries the following two fields. Integer keys are given
in parentheses.

| Field (key) | CBOR type | Meaning |
|---|---|---|
| `frame_kind` (0) | Unsigned int | MUST equal the frame's Stream frame type (`0x0100`–`0x0104`). A receiver MUST reject (STREAM_RESET, `StreamStateError`) a payload whose `frame_kind` contradicts the frame-header Frame Type. |
| `sub_stream_id` (1) | Unsigned int | The sub-stream this frame acts on (§5.1, §6.1). This is the correlation key of NPAMP-STREAM: all frames of a sub-stream — in both directions — carry the same `sub_stream_id`, and a receiver associates a frame with its sub-stream by `sub_stream_id`, not by frame sequence number. |

Because a sub-stream is a long-lived multi-frame object rather than a single
request/reply exchange, NPAMP-STREAM uses the `sub_stream_id` as its persistent
correlation key in place of the per-exchange correlation identifier a request/reply
companion (for example NPAMP-DISC §4.2) carries. Every frame of a given sub-stream in
both directions bears the identical `sub_stream_id`; a STREAM_OPEN reply (§7.1) echoes
the id it answers, and a STREAM_RESET (§7.3) names the id it tears down.

### 4.3 Forward compatibility

A receiver MUST ignore an unrecognized integer key it encounters in a Stream payload map
whose key is not negative, so that later revisions of this document MAY add fields
without breaking a conformant receiver. A receiver MUST reject (STREAM_RESET,
`StreamStateError`) a payload that carries a negative integer key it does not recognize,
reserving the negative key space for forward-incompatible additions. This is the same
forward-compatibility rule NPAMP-DISC §4.1 applies: ignore unknown non-negative keys,
reject unknown negative keys.

## 5. Frame bodies

Each frame body below carries the common envelope (`frame_kind`, `sub_stream_id`; §4.2)
plus the fields listed. "Req" is Yes for a field a sender MUST include and a receiver
MUST require, No for an OPTIONAL field. Field keys are unique unsigned integers within a
frame body; keys `0` and `1` are the common-envelope keys and are not reused.

### 5.1 STREAM_OPEN (`0x0100`)

Opens a sub-stream. The opener assigns the `sub_stream_id` under the parity rule of §6.1.
A STREAM_OPEN is answered by a peer STREAM_OPEN in the opposite direction (accepting the
sub-stream and declaring the peer's own initial receive window) or by a STREAM_RESET
(declining it); see §7.1.

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `init_window` (2) | Unsigned int | Yes | The opener's initial per-sub-stream receive credit for this direction, expressed as an absolute cumulative receive offset (§6.2). The peer MUST NOT send STREAM_DATA carrying octets at or beyond this absolute offset until a STREAM_WINDOW_UPDATE (§5.5) raises it. |
| `content_type` (3) | Unsigned int (0–255) | Yes | Advisory classification of the sub-stream's octets: `0x00` opaque, `0x01` token-text, `0x02` audio, `0x03` video, `0x04` file, `0x05` CBOR, `0x06` octet-stream. Values `0x07`–`0x7F` require specification to assign; `0x80`–`0xFF` are for private use. A receiver that does not recognize the value MUST treat the octets as `0x00` opaque and MUST NOT fail the sub-stream on that basis alone; a receiver that cannot accept the sub-stream at all MAY decline with STREAM_RESET (`ContentTypeUnsupported`). |
| `content_hint` (4) | Text string | No | Advisory free-text hint (for example a filename or media descriptor). Not an identifier; MUST NOT be used to correlate or de-duplicate sub-streams. |
| `flags` (5) | Unsigned int (0–255) | No | Bit field. Bit 0 (`fin`) set means the opener will send no STREAM_DATA on this sub-stream — the opener's direction is empty and half-closed from the outset. Bits 1–7 are reserved, MUST be sent as 0, and MUST be ignored on receipt. Absent means no flags. |

A receiver MUST reject a STREAM_OPEN whose `sub_stream_id` violates the parity rule
(§6.1) or names a sub-stream already open, with STREAM_RESET (`SubStreamIdInvalid`). A
receiver MUST reject an `init_window` it deems invalid (for example implausibly large
for local policy) with STREAM_RESET (`InitialWindowInvalid`).

### 5.2 STREAM_DATA (`0x0101`)

Carries one chunk of sub-stream octets for one direction at an explicit absolute byte
offset. Chunks for one direction of a sub-stream are ordered by their `offset`; a
receiver reassembles by offset, not by arrival order.

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `offset` (2) | Unsigned int | Yes | The absolute byte offset, counted from `0`, of the first octet of `data` within this direction of the sub-stream. Offsets are non-overlapping and gap-free for a well-behaved sender; a receiver MUST reject an overlapping or beyond-window offset with STREAM_RESET (`FlowControlError`). |
| `data` (3) | Byte string | Yes | The sub-stream octets carried by this frame. A zero-length `data` is permitted ONLY when `flags` bit 0 (`fin`) is set (an empty terminal frame). |
| `flags` (4) | Unsigned int (0–255) | No | Bit field. Bit 0 (`fin`) set means this is the last STREAM_DATA for this direction: the highest octet offset `offset + len(data)` is this direction's final offset. Bits 1–7 reserved, sent as 0, ignored on receipt. Absent means no flags. |

The highest absolute offset a STREAM_DATA may reach — `offset + len(data)` — MUST NOT
exceed the current per-sub-stream credit granted by the peer (§6.2) NOR the
connection-level credit (§6.3); a sender that would exceed either MUST wait for a
STREAM_WINDOW_UPDATE (per-sub-stream) or a connection-level `FLOW_UPDATE` (connection).

### 5.3 STREAM_CLOSE (`0x0102`)

Gracefully half-closes one direction of a sub-stream. It states that direction's final
octet count, letting the receiver confirm it has all the data. STREAM_CLOSE is normal
completion and MUST NOT be used to signal an error (use STREAM_RESET for that).

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `final_offset` (2) | Unsigned int | Yes | The total number of octets the closing side sent on this direction of the sub-stream, equal to the highest `offset + len(data)` it reached. A receiver MUST reject (STREAM_RESET, `StreamStateError`) a STREAM_CLOSE whose `final_offset` contradicts a `fin` it already observed, or that is followed by further STREAM_DATA. |

STREAM_CLOSE closes only the sending direction of the closing side; the peer's direction
remains open until the peer closes it (§7.2). A STREAM_DATA with `fin` set MAY be used to
half-close without a separate STREAM_CLOSE; a STREAM_CLOSE with a matching `final_offset`
MAY additionally follow to confirm the count.

### 5.4 STREAM_RESET (`0x0103`)

Abruptly tears down BOTH directions of a sub-stream and frees its flow-control state. It
carries an error code and the sender's final offset. STREAM_RESET is the sole
cancellation mechanism (there is no separate cancel frame).

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `error_code` (2) | Unsigned int | Yes | One of the reset error codes in §8. `0` (`NoError`) is a clean cancellation, not a failure. |
| `final_offset` (3) | Unsigned int | Yes | The highest absolute offset the resetting side had sent on its direction at the moment of reset, so the peer can account for what was delivered before teardown. |

On sending or receiving a STREAM_RESET, both peers MUST cease sending STREAM_DATA,
STREAM_CLOSE, and STREAM_WINDOW_UPDATE for that `sub_stream_id`, MUST release the
sub-stream's per-direction flow-control state, and MUST transition the sub-stream to
`closed` (§7.3). A STREAM_RESET for an unknown or already-closed `sub_stream_id` MUST be
ignored (it is idempotent); it MUST NOT itself provoke another STREAM_RESET.

### 5.5 STREAM_WINDOW_UPDATE (`0x0104`)

Grants the peer additional per-sub-stream flow-control credit by raising the absolute
cumulative receive offset the peer may write up to.

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `max_data` (2) | Unsigned int | Yes | The new absolute cumulative receive offset, counted from `0`, up to which (exclusive) the peer MAY now send STREAM_DATA on this direction of the sub-stream. `max_data` MUST be monotonically non-decreasing for a given `sub_stream_id` and direction; a receiver MUST ignore a STREAM_WINDOW_UPDATE whose `max_data` is less than or equal to the largest it has already granted, and MUST reject (STREAM_RESET, `FlowControlError`) a value it can prove violates a prior grant it relied on. |

Because `max_data` is an **absolute** offset rather than a delta, a re-sent or reordered
STREAM_WINDOW_UPDATE cannot double-credit: the receiver takes the maximum of the values
it has seen and a duplicate is idempotent (§6.2). This is the QUIC absolute-offset
flow-control discipline (RFC 9000 §4.1, §19.10), chosen so that credit is idempotent
under the association's dedup and retransmit behavior.

## 6. Sub-stream identifiers and flow control

### 6.1 Sub-stream identifier parity

N-PAMP defines no client/server channel role; the two peers are the two ends of a
handshake. To let both peers open sub-streams concurrently without an id collision,
NPAMP-STREAM binds `sub_stream_id` parity to the **handshake role**:

* The handshake **initiator** — the peer that sent CLIENT_HELLO (core specification §5)
  — MUST open sub-streams with **even** `sub_stream_id` values.
* The handshake **responder** — the peer that sent SERVER_HELLO — MUST open sub-streams
  with **odd** `sub_stream_id` values.

A peer MUST assign `sub_stream_id` values it originates in increasing order and MUST NOT
reuse an id it has already opened on the association. A receiver MUST reject a
STREAM_OPEN whose `sub_stream_id` has the wrong parity for the opening peer's handshake
role, or whose `sub_stream_id` is already in use, with STREAM_RESET
(`SubStreamIdInvalid`). This is the QUIC bidirectional-open parity model (RFC 9000
§2.1) transposed onto the handshake role, giving collision-free concurrent opens in both
directions.

### 6.2 Per-sub-stream flow control (absolute offset)

Each direction of each sub-stream has an independent flow-control credit expressed as an
absolute cumulative offset. The receiver of a direction grants credit: `init_window` in
STREAM_OPEN (§5.1) sets the initial absolute limit, and each STREAM_WINDOW_UPDATE (§5.5)
raises it. The sender of that direction MUST NOT send STREAM_DATA whose highest octet
offset (`offset + len(data)`) exceeds the current absolute limit. Absolute offsets make
the accounting idempotent under retransmission or reordering: a duplicated STREAM_DATA at
a known offset carries no new octets, and a duplicated STREAM_WINDOW_UPDATE grants no new
credit.

### 6.3 Two-level composition with connection-level flow control

Flow control is **two-level**. Every STREAM_DATA frame MUST simultaneously respect:

1. its **per-sub-stream** absolute credit (§6.2), granted by STREAM_OPEN `init_window`
   and STREAM_WINDOW_UPDATE; and
2. the **connection-level** credit the core specification defines through the
   all-channel `FLOW_UPDATE` frame (`0x000A`).

A sender MUST NOT send octets that would exceed EITHER limit; the effective ceiling at
any instant is the smaller of the two. NPAMP-STREAM does **not** define the `FLOW_UPDATE`
(`0x000A`) body — that frame is an all-channel reserved frame owned by the core
specification — and MUST NOT redefine it. NPAMP-STREAM states only the composition
invariant: a per-sub-stream grant never overrides the connection-level ceiling, and a
connection-level grant never overrides a per-sub-stream ceiling. This mirrors the
two-level (stream-level and connection-level) flow control of QUIC (RFC 9000 §4) and
HTTP/2 (RFC 9113 §5.2), with the connection level owned by the core wire.

## 7. Operation and state model

Each direction of a sub-stream is an independent, ordered, flow-controlled byte
sequence. A sub-stream as a whole progresses through the states below; the two
directions half-close independently, and either peer may abruptly reset the whole
sub-stream at any time.

### 7.1 Open

A peer opens a sub-stream by sending STREAM_OPEN (§5.1) with a `sub_stream_id` of the
correct parity (§6.1) and its `init_window`. The peer accepts by replying STREAM_OPEN in
the opposite direction, echoing the same `sub_stream_id` and declaring its own
`init_window` for its direction; the sub-stream is then `open` in both directions. The
peer declines by replying STREAM_RESET (§5.4) naming that `sub_stream_id`, which leaves
the sub-stream `closed`. A STREAM_OPEN that sets `flags` bit 0 (`fin`) declares the
opener's direction empty and half-closed from the outset.

### 7.2 Data transfer and graceful half-close

While `open`, each side sends STREAM_DATA (§5.2) at monotonically advancing offsets
within its granted credit, and grants the peer credit with STREAM_WINDOW_UPDATE (§5.5).
A side half-closes its own direction either by setting `fin` on its last STREAM_DATA or
by sending STREAM_CLOSE (§5.3) with the direction's `final_offset` (or both). When one
direction has half-closed, the sub-stream is `half-closed(local)` or
`half-closed(remote)` from each peer's viewpoint; the still-open direction continues
until it too half-closes, at which point the sub-stream is `closed` gracefully.

### 7.3 Abrupt reset

Either peer MAY send STREAM_RESET (§5.4) at any time to tear down BOTH directions at
once, carrying an `error_code` (§8) and its `final_offset`. Cancellation of an in-flight
sub-stream is expressed as STREAM_RESET with `error_code` `0` (`NoError`); there is no
separate cancel frame. On send or receipt of STREAM_RESET the sub-stream is `closed` and
its flow-control state is released (§5.4).

### 7.4 State machine

The per-sub-stream states and their legal transitions:

```
idle
  --STREAM_OPEN sent/recv-->            open
open
  --local fin / STREAM_CLOSE (local)--> half-closed(local)
  --remote fin / STREAM_CLOSE (remote)->half-closed(remote)
  --STREAM_RESET (either side)-------->  closed
half-closed(local)
  --remote fin / STREAM_CLOSE (remote)->closed
  --STREAM_RESET (either side)-------->  closed
half-closed(remote)
  --local fin / STREAM_CLOSE (local)--> closed
  --STREAM_RESET (either side)-------->  closed
closed
  --STREAM_RESET (idempotent, ignored)->closed
```

A frame that would drive an illegal transition — for example STREAM_DATA after that
direction's `fin`, a second STREAM_OPEN for an id already `open`, or a STREAM_CLOSE whose
`final_offset` contradicts an observed `fin` — MUST be rejected with STREAM_RESET
(`StreamStateError`). All sub-stream state is scoped to the association: when the
association closes, all sub-streams and their flow-control state are discarded, and a
peer MUST NOT carry sub-stream state or offsets from a prior association into a new one
(§1.2, cross-association resumption non-scope).

### 7.5 No cross-association or foreign-event resumption

Within one association the absolute `offset` (§6.2) survives an all-channel `KEY_UPDATE`,
so a mid-stream key rotation needs no resume frame. NPAMP-STREAM provides no
cross-association resumption of a native sub-stream and no foreign-event resumption; the
latter is an NPAMP-CC-STREAM Bridge-channel construct and MUST NOT be reused here (§2.3).

## 8. Error model

A fatal condition on a sub-stream is reported by the STREAM_RESET frame (§5.4), whose
`error_code` field takes one of the following values. STREAM_RESET is the single
structured error frame of this document; there is no separate error frame, and
STREAM_CLOSE (§5.3) is reserved for normal completion.

| Code | Name | Meaning |
|---|---|---|
| `0` | NoError | Clean cancellation of the sub-stream; not a failure. |
| `1` | SubStreamIdInvalid | A `sub_stream_id` had the wrong parity for the opener's handshake role (§6.1), reused an open id, or was otherwise unusable. |
| `2` | FlowControlError | A STREAM_DATA exceeded the granted per-sub-stream or connection-level credit, or an offset overlapped or preceded already-received data (§5.2, §6). |
| `3` | StreamStateError | A frame drove an illegal state transition, or a payload was malformed / mismatched `frame_kind` / carried an unknown negative key (§4, §7.4). |
| `4` | InitialWindowInvalid | A STREAM_OPEN `init_window` was unacceptable to the receiver (§5.1). |
| `5` | ContentTypeUnsupported | The receiver cannot accept the declared `content_type` at all (§5.1). |
| `6` | ResourceExhausted | The receiver cannot allocate the resources the sub-stream requires (for example a per-association sub-stream limit was reached). |

A receiver MUST NOT leak internal detail through a STREAM_RESET: the `error_code` is the
only signalled cause, and any further diagnostic MUST be recorded locally rather than
placed on the wire. A malformed payload that carries no usable `sub_stream_id` (so no
STREAM_RESET can name a sub-stream) MUST instead be reported with the all-channel ERROR
frame (`0x0005`) or by closing the channel, per the core specification.

## 9. Security considerations

This section supplements the core specification's Security Considerations; it does not
restate them.

Every NPAMP-STREAM frame is AEAD-protected and keyed by the Stream channel's own
per-direction traffic keys (core specification §5). A receiver therefore knows each
sub-stream frame was sent by the authenticated peer. NPAMP-STREAM carries opaque octets;
it makes no claim about the meaning or safety of those octets, and a `content_type`
(§5.1) is an advisory hint that a receiver MUST NOT treat as a security guarantee.

A peer MUST bound the resources a remote peer can consume through sub-streams: the number
of concurrent open sub-streams, the per-sub-stream and aggregate buffered-but-unread
octets, and the rate of STREAM_OPEN frames. A peer MAY decline a STREAM_OPEN with
STREAM_RESET (`ResourceExhausted`) rather than allocate without limit, and MUST enforce
its granted flow-control credit strictly — a STREAM_DATA beyond the granted absolute
offset MUST be rejected (`FlowControlError`), never buffered past the limit. Because
either peer may open sub-streams on this Multi-stream channel, both directions are
subject to these limits.

Absolute-offset flow control (§6.2) is chosen partly for safety: because credit is a
non-decreasing absolute limit rather than an additive delta, a replayed or reordered
STREAM_WINDOW_UPDATE cannot inflate a peer's write budget, closing a class of
flow-control-confusion errors that delta-based crediting is prone to under an association
that may legitimately drop and retransmit a frame.

All sub-stream state is scoped to the association (§7.4); a peer MUST NOT carry sub-stream
identifiers or offsets across associations, so a stale sub-stream from a prior association
cannot be acted upon under a new one.

## 10. Conformance

An implementation conforms to NPAMP-STREAM if and only if, on the Stream channel
`0x000C`, it:

1. Enables NPAMP-STREAM framing only at the Standard profile or higher and only when the
   Stream channel `0x000C` was advertised for the association during the handshake, and
   drops frames received on an unadvertised channel (§2.1; core specification §5);

2. Uses only the five Stream-channel frame types defined in §3 — STREAM_OPEN `0x0100`,
   STREAM_DATA `0x0101`, STREAM_CLOSE `0x0102`, STREAM_RESET `0x0103`, and
   STREAM_WINDOW_UPDATE `0x0104` — within the channel's application namespace at or above
   `0x0100`, defines no frame in the reserved `0x0030`–`0x0034` range, and preserves the
   core meaning of the reserved all-channel frame types (§3);

3. Encodes every frame body as a deterministic-CBOR map (§4.1), requires and validates
   the common envelope `frame_kind`/`sub_stream_id` (§4.2), ignores unknown non-negative
   keys, and rejects an unknown negative key, a wrong-major-type key, a missing required
   field, or a `frame_kind` that contradicts the frame header (§4.2, §4.3);

4. Assigns and validates `sub_stream_id` parity by handshake role — initiator even,
   responder odd — rejects a mis-parity or reused id with STREAM_RESET
   (`SubStreamIdInvalid`), and correlates every frame to its sub-stream by
   `sub_stream_id` rather than by frame sequence number (§4.2, §6.1);

5. Enforces per-sub-stream flow control as a monotonically non-decreasing **absolute**
   receive offset — granted by STREAM_OPEN `init_window` and STREAM_WINDOW_UPDATE — and
   never sends STREAM_DATA whose highest octet offset exceeds the current per-sub-stream
   credit, treating a duplicate or lower window update as idempotent (§5.2, §5.5, §6.2);

6. Enforces the **two-level** composition — every STREAM_DATA respects both the
   per-sub-stream credit and the connection-level `FLOW_UPDATE` (`0x000A`) credit,
   whichever is smaller — and does not redefine the core-owned `0x000A` body (§6.3);

7. Implements the per-direction half-close lifecycle and its state machine (§7): opens
   with a STREAM_OPEN reply or declines with STREAM_RESET, half-closes each direction by
   `fin` or STREAM_CLOSE, tears down both directions abruptly with STREAM_RESET
   (cancellation being STREAM_RESET `NoError`), rejects an illegal transition with
   STREAM_RESET (`StreamStateError`), and treats a STREAM_RESET for an unknown or closed
   sub-stream as idempotent (§5.4, §7.4);

8. Reports fatal sub-stream conditions with STREAM_RESET and one of the §8 error codes,
   never leaks internal detail beyond the signalled `error_code`, does not use channel
   `0x000C` for foreign-agentic-protocol encapsulation (that is the Bridge channel
   `0x000D` and NPAMP-BRIDGE), and does not apply NPAMP-CC-STREAM's Bridge-channel
   resumption, cancellation, or StreamControl semantics to a native sub-stream (§1.2,
   §2.3, §8); and

9. Scopes all sub-stream identifiers and offsets to the association and carries no
   sub-stream state across associations (§7.4, §9).

Machine-gradable conformance vectors exist for the Stream channel's payload-decode surface:
the `stream.body.decode` operation group in the npamp_00 conformance corpus, produced by an
independent RFC 8949 byte constructor (`test-vectors/gen/stream_oracle.py`) and graded by
`npamp-conform` against the reference implementation (`impl/go/stream*.go`), covers the
§4.1/§4.2/§4.3 payload-encoding and common-envelope MUST-reject clauses — including the
Stream-specific rule that `sub_stream_id` (1) is an Unsigned int, not a byte string — so a
claim of conformance to those clauses is corpus-verified. Beyond that payload surface, the
§5–§9 behavioural clauses (flow control, the sub-stream state machine, half-close, reset)
are graded only by a live-exchange harness: a conformance test suite SHOULD assert each
clause above with a recorded exchange on the
Stream channel `0x000C`: a handshake that advertises the channel; a bidirectional
STREAM_OPEN/STREAM_OPEN handshake at each parity; at least two concurrent sub-streams
carrying STREAM_DATA in both directions; a STREAM_WINDOW_UPDATE that raises an absolute
limit and a duplicate window update proven idempotent; a graceful half-close of each
direction by `fin` and by STREAM_CLOSE; a STREAM_RESET cancellation (`NoError`) and a
STREAM_RESET provoked by each of the §8 error codes; and a flow-control violation
rejected with `FlowControlError`.
