# NPAMP-SPATIAL — Physical-World Spatial State on the Spatial Channel (companion to draft-bubblefish-npamp-02)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174)
> when, and only when, they appear in all capitals, as shown here. This document
> defines an application interface over the N-PAMP **Spatial channel `0x0013`**: how
> robotics and IoT peers exchange high-frequency physical-world state — coordinate
> frames, rigid-body transforms, pose, kinematic state, and occupancy — and how a
> peer queries another peer's current spatial state. It builds on the core
> specification (draft-bubblefish-npamp-02, the "core specification") and on the
> deterministic-CBOR and correlation conventions of **NPAMP-DISC**
> (`40_discovery.md`); it does not redefine either. It consumes only code points the
> core specification reserves for the channel's application frames and introduces no
> change to the core wire format. Spatial primitives follow the ROS coordinate-frame
> conventions REP-103 (units and coordinate conventions) and REP-105 (coordinate
> frame tree). **The core specification governs**: on any disagreement between this
> document and the core specification, the core specification is authoritative.

## 1. Scope

### 1.1 In scope

This document specifies, over the Spatial channel `0x0013` of the N-PAMP core
specification:

1. A set of Spatial-channel application frame types, drawn from the channel
   application-frame namespace that begins at `0x0100` (core specification §4.6);
2. Deterministic-CBOR bodies for **coordinate-frame definition** (REP-105 tree
   nodes), **timestamped rigid-body transforms** (REP-105 tree edges), **pose**
   (position + orientation, optional covariance) of a tracked body, **kinematic
   state** (twist: linear + angular velocity, optional covariance), and
   **occupancy-grid patches** (2D/2.5D physical-world occupancy);
3. A request/reply **spatial query** by which one peer retrieves another peer's
   current frame tree and last-known body state, correlated by an identifier; and
4. A structured **error model** for the spatial exchange itself.

The one-way state frames model a high-frequency, best-effort stream; the query/reply
pair is the authoritative "current state" mechanism (§6, §7).

### 1.2 Not in scope

This document does NOT:

* Define, mandate, or bind any **cryptographic material** to the High or Sovereign
  profile. The Spatial channel is enabled only at the High profile or higher; the
  cryptographic suite and operational internals bound to a profile are governed by
  the core specification's profile negotiation, not by this document. This companion
  defines an application interface only.
* Change any field of the **36-octet core frame header**, any reserved all-channel
  frame type (`0x0001`–`0x000A`), the future-core reserved band, the
  companion-extension band, or the extension-TLV encoding; it carries no extension
  TLV and claims none of the TLV code points the core specification reserves.
* Define a **rate, cadence, sampling interval, or timing parameter**. "High-frequency"
  is the channel registry's characterization of the traffic class, not a wire
  parameter; this document states no cadence and manufactures none.
* Define **global-map georeferencing** beyond carrying an Earth-fixed (ECEF) or local
  ENU coordinate-frame declaration as an ordinary frame node (§5.1); it defines no
  datum, projection, or geodetic transform.
* Define **occupancy-cell compression** beyond the two cell encodings signaled in
  §5.5 (raw and run-length over the same cell domain).
* Carry any **foreign agent protocol**. The Spatial channel is a native core channel,
  not a Bridge carriage class; it does not build on NPAMP-BRIDGE and encapsulates no
  external protocol.
* Define a **domain-specific robot model, kinematic solver, or hardware profile**.
  This interface is generic: it carries frames, transforms, poses, twists, and
  occupancy for arbitrary robotics/IoT endpoints and interprets none of them
  mechanically.

## 2. Relationship to the core specification and the profile gate

The Spatial channel `0x0013` is registered by the core specification with name
**Spatial**, purpose **"Physical-world state for robotics and IoT (high-frequency)"**,
minimum profile **High**, and direction **Multi-stream** (core specification §5, Core
Channel Registry; interface reference `../channels/0013_spatial.md`). This document
does not alter any of those registry values.

**Profile gate.** The Spatial channel MUST be enabled only at the **High** profile or
higher — that is, at High and Sovereign — and MUST NOT be enabled at the Standard
profile (core specification §5, min-profile rule). A peer operating below the High
profile MUST NOT advertise, send, or accept Spatial frames. A peer that receives a
Spatial frame while the negotiated profile is below High MUST treat it as a profile
violation (SPATIAL_ERROR code `ProfileTooLow`, §7, where a channel is in use) or drop
it. This document adds no cryptographic behavior of its own; the crypto suite bound to
the High or Sovereign profile is the core specification's, referenced here and not
restated.

**Advertisement gate.** A peer that did not advertise the Spatial channel during the
handshake (core specification §5) MUST NOT receive Spatial frames; frames on an
unadvertised Spatial channel MUST be dropped.

**Multi-stream directionality.** Spatial is bidirectional and MAY carry concurrent
traffic over multiple transport streams within the channel's stream family (core
specification §5). Each peer maintains an independent per-direction sequence space and
independent per-direction traffic keys. The per-direction sequence space orders frames
**within** a direction; it does **not** correlate a reply to a request — §6 defines
that. Either peer MAY originate a spatial query.

**Correlation and error conventions by reference.** This document reuses the
deterministic-CBOR payload container and the correlation discipline established by
NPAMP-DISC (`40_discovery.md` §4) and does not restate them beyond the adaptations in
§4 and §6: a reply echoes its request's correlation identifier verbatim, and replies
are matched to requests by that identifier rather than by frame sequence number.

## 3. Spatial-channel frame types

The core specification's application-frame namespace begins at `0x0100` within each
channel (core specification §4.6). Under draft-02 the per-channel frame-type space is
partitioned into four bands: `0x0000`–`0x000A` reserved all-channel control frames;
`0x000B`–`0x002F` reserved for future core use; `0x0030`–`0x00FF` the
companion-extension band; and `0x0100`–`0xFFFF` the channel application frames. This
document places every Spatial operation frame in the `0x0100`+ application band.

| Type | Name | Reply | Purpose |
|---|---|---|---|
| `0x0100` | FRAME_DEF | None | Define or replace a coordinate frame and its parent edge (a REP-105 tree node). |
| `0x0101` | TRANSFORM | None | Timestamped rigid-body transform: the pose of `child_frame` expressed in `coord_frame` (a REP-105 tree edge). |
| `0x0102` | POSE_UPDATE | None | Timestamped pose (position + orientation, optional covariance) of a tracked body in a named frame. |
| `0x0103` | STATE_DELTA | None | Timestamped twist (linear + angular velocity, optional covariance) of a tracked body. |
| `0x0104` | OCCUPANCY_UPDATE | None | Timestamped occupancy-grid patch (2D/2.5D occupancy) in a named frame. |
| `0x0105` | SPATIAL_QUERY | SPATIAL_SNAPSHOT or SPATIAL_ERROR | Request the responder's current frame tree and/or last-known state for named bodies. |
| `0x0106` | SPATIAL_SNAPSHOT | None | Successful reply to SPATIAL_QUERY: a coherent snapshot of frames and poses at a stamp; correlation echoes the query. |
| `0x0107` | SPATIAL_ERROR | None | Structured failure reply; correlation echoes the originating query. |

The reserved all-channel frame types (PING `0x0001`, PONG `0x0002`, CLOSE `0x0003`,
CLOSE_ACK `0x0004`, ERROR `0x0005`, KEY_UPDATE `0x0006`, and the remainder enumerated
in core specification §4.6) retain their core meaning on the Spatial channel. An
implementation MUST NOT reuse them for Spatial application traffic, MUST NOT define
Spatial application semantics in the reserved all-channel band, the future-core band
(`0x000B`–`0x002F`), or the companion-extension band (`0x0030`–`0x00FF`), and MUST
place every Spatial application frame at or above `0x0100`.

Frames `0x0100`–`0x0104` are one-way, best-effort, high-frequency state streams
(fire-and-forget); a receiver MUST NOT reply to them. Only the
`0x0105`/`0x0106`/`0x0107` triple is a correlated request/reply exchange.

## 4. Frame payload encoding

### 4.1 Payload container

A Spatial frame's payload (the octets after the 36-octet core frame header and any
extension TLVs, and before the AEAD tag) is a single **deterministically encoded CBOR**
object as defined by core specification §4.5 and §11.9 (deterministic CBOR, RFC 8949).
The payload MUST be a CBOR map whose keys are the unsigned integers defined in §4.2 and
§5 for the relevant frame type. A sender MUST produce the deterministic encoding (core
specification §11.9): byte-identical output for identical input, with the canonical key
ordering and shortest-form integer encoding RFC 8949 §4.2 requires. A receiver MUST
reject (SPATIAL_ERROR, code `MalformedPayload`) any Spatial frame whose payload is not a
valid deterministic-CBOR map, or whose payload omits a required key or carries a key of
the wrong CBOR major type.

Spatial bodies are carried in the frame **payload**, not in extension TLVs. This
document defines and consumes no extension-TLV tag, and therefore claims none of the TLV
code points the core specification reserves.

A receiver MUST **ignore** an unrecognized integer key it encounters in a Spatial
payload map whose key is **not negative**, so that later revisions of this document MAY
add fields without breaking a conformant receiver. A receiver MUST **reject**
(SPATIAL_ERROR, code `MalformedPayload`) a payload that carries a **negative** integer
key it does not recognize, reserving the negative key space for forward-incompatible
additions. This is the identical forward-compatibility rule NPAMP-DISC §4.1 defines.

### 4.2 Common envelope fields

Every Spatial payload map carries the following fields. Integer keys are given in
parentheses.

| Field (key) | CBOR type | Meaning |
|---|---|---|
| `frame_kind` (0) | Unsigned int | MUST equal the frame-header Frame Type (`0x0100`–`0x0107`). A receiver MUST reject (SPATIAL_ERROR, code `KindMismatch`) a payload whose `frame_kind` contradicts the frame-header Frame Type. |
| `stamp` (1) | Int (int64) | Capture time, nanoseconds since the Unix epoch, on the SI-second base (REP-103). A monotonic capture source is RECOMMENDED; a receiver MUST NOT assume the sender's clock is wall-clock synchronized to its own, and uses `stamp` only for the newest-wins ordering of §6. |
| `corr` (2) | Byte string (1–64 B) | Correlation identifier. Present and non-empty on SPATIAL_QUERY, and echoed verbatim on SPATIAL_SNAPSHOT and SPATIAL_ERROR. Absent on the one-way frames `0x0100`–`0x0104`. |

A SPATIAL_QUERY MUST carry a `corr` that is non-empty and unique among the originating
peer's outstanding queries on the Spatial channel in that direction. A SPATIAL_SNAPSHOT
and a SPATIAL_ERROR MUST echo the originating query's `corr` verbatim. A receiver MUST
match each reply to its originating query by `corr`, not by frame sequence number,
exactly as NPAMP-DISC §4.2 requires. The one-way frames `0x0100`–`0x0104` MUST omit
`corr`.

## 5. Spatial bodies

All geometry follows **REP-103**: coordinate frames are right-handed; body-fixed axes
are **x-forward, y-left, z-up**; geographic frames use **ENU (x-east, y-north, z-up)**;
units are SI (metres, metres per second, radians, radians per second); orientation is
expressed as a **unit quaternion** (REP-103's preferred rotation representation over
Euler angles); and angular velocity is expressed about the **fixed axes (X, Y, Z)**. A
covariance matrix is a **row-major 6×6** matrix ordered **(x, y, z, rotX, rotY, rotZ)**
— the REP-103 pose-covariance convention (a 36-element `float64` array). Each of the
following bodies carries the common envelope (§4.2) in addition to its own fields; the
tables below list only the body-specific keys.

### 5.1 FRAME_DEF (`0x0100`) — REP-105 tree node

| Field (key) | CBOR type | Required | Meaning |
|---|---|---|---|
| `coord_frame` (3) | Text string | Yes | This frame's identifier (for example `base_link`). |
| `parent_frame` (4) | Text string | No | Parent frame identifier. Absent means this frame is a tree root. Enforces the REP-105 single-parent rule: each frame has exactly one parent. |
| `frame_class` (5) | Unsigned int | No | Advisory hint at the frame's REP-105 role: `0` body/base, `1` odom (continuous, may drift), `2` map (non-continuous, non-drifting), `3` earth/ECEF, `4` sensor, `5` world/other. The tree edge, not this hint, is authoritative. |
| `epoch` (6) | Unsigned int | Yes | Monotonically non-decreasing counter for `coord_frame`. A FRAME_DEF whose `epoch` is strictly greater than the one held replaces the prior definition; one whose `epoch` is less than or equal is ignored (reorder- and duplicate-safe). |

A receiver MUST reject (SPATIAL_ERROR, code `FrameTreeConflict`) a FRAME_DEF that would
give a frame a second live parent, or that would close a cycle, so that the REP-105
frame tree remains a single-parent acyclic tree.

### 5.2 TRANSFORM (`0x0101`) — timestamped tree edge

| Field (key) | CBOR type | Required | Meaning |
|---|---|---|---|
| `coord_frame` (3) | Text string | Yes | The reference (parent) frame the transform is expressed in. |
| `child_frame` (4) | Text string | Yes | The frame being located relative to `coord_frame`. |
| `position` (5) | Array of 3 float64 | Yes | Translation `(x, y, z)` in metres, on REP-103 axes. |
| `orientation` (6) | Array of 4 float64 | Yes | Unit quaternion `(x, y, z, w)`; the last element is the scalar part `w` (REP-103 preferred rotation). |
| `pose_cov` (7) | Array of 36 float64 | No | Row-major 6×6 covariance, order `(x, y, z, rotX, rotY, rotZ)`. Absence means the covariance is unknown, NOT that it is zero. |

### 5.3 POSE_UPDATE (`0x0102`)

| Field (key) | CBOR type | Required | Meaning |
|---|---|---|---|
| `coord_frame` (3) | Text string | Yes | The frame the pose is expressed in. |
| `body_id` (4) | Byte string (1–64 B) | Yes | Opaque identifier of the tracked body in the sender's namespace. |
| `position` (5) | Array of 3 float64 | Yes | Position `(x, y, z)` in metres. |
| `orientation` (6) | Array of 4 float64 | Yes | Unit quaternion `(x, y, z, w)`. |
| `pose_cov` (7) | Array of 36 float64 | No | Row-major 6×6 covariance as in §5.2. Absence means unknown, not zero. |
| `seq` (8) | Unsigned int | No | Per-body sample counter, enabling gap detection on a lossy high-frequency stream. |

### 5.4 STATE_DELTA (`0x0103`) — twist

| Field (key) | CBOR type | Required | Meaning |
|---|---|---|---|
| `coord_frame` (3) | Text string | Yes | The frame the velocities are expressed in (REP-105 recommends the odom frame for locally sensed motion). |
| `body_id` (4) | Byte string (1–64 B) | Yes | Opaque identifier of the tracked body. |
| `linear` (5) | Array of 3 float64 | Yes | Linear velocity `(vx, vy, vz)` in metres per second. |
| `angular` (6) | Array of 3 float64 | Yes | Angular velocity about the fixed axes `(X, Y, Z)` in radians per second (REP-103 fixed-axis convention for angular rates). |
| `twist_cov` (7) | Array of 36 float64 | No | Row-major 6×6 covariance, order `(x, y, z, rotX, rotY, rotZ)`. Absence means unknown, not zero. |
| `seq` (8) | Unsigned int | No | Per-body sample counter. |

### 5.5 OCCUPANCY_UPDATE (`0x0104`)

| Field (key) | CBOR type | Required | Meaning |
|---|---|---|---|
| `coord_frame` (3) | Text string | Yes | The frame the grid origin is expressed in. |
| `resolution` (4) | float64 | Yes | Cell edge length in metres per cell. |
| `width` (5) | Unsigned int | Yes | Number of cells along the grid x-axis. |
| `height` (6) | Unsigned int | Yes | Number of cells along the grid y-axis. |
| `origin` (7) | 2-element array: [Array of 3 float64, Array of 4 float64] | Yes | Pose of the grid's `(0,0)` cell in `coord_frame`: element 0 is position `(x, y, z)`, element 1 is the orientation quaternion `(x, y, z, w)`. |
| `encoding` (8) | Unsigned int | Yes | Cell encoding: `0` raw (one signed byte per cell, value `-1` unknown or `0..100` occupancy percent), `1` run-length over the same signed-byte cell domain. |
| `cells` (9) | Byte string | Yes | Cell payload per `encoding`, laid out row-major from the origin cell (REP-103 x then y). For `encoding` `0` the length MUST equal `width × height`; for `encoding` `1` the payload MUST decode to exactly `width × height` cells. A payload that does not satisfy this MUST be rejected (SPATIAL_ERROR, code `MalformedPayload`). |

### 5.6 SPATIAL_QUERY (`0x0105`)

A SPATIAL_QUERY carries the common envelope (§4.2, with a non-empty `corr` unique among
the requester's outstanding Spatial queries in that direction) and an OPTIONAL
conjunctive filter:

| Field (key) | CBOR type | Meaning |
|---|---|---|
| `want_frames` (3) | Boolean | If true, the snapshot includes the responder's current frame tree (as FRAME_DEF-equivalent records). Absent or false means the frame tree is not requested. |
| `body_ids` (4) | Array of byte string | If present, the snapshot includes the last-known pose and state for exactly these bodies; absent means all bodies the responder currently tracks. |
| `cursor` (5) | Byte string | Present only when continuing a paginated snapshot; echoes an opaque continuation token from a prior SPATIAL_SNAPSHOT (§5.7). |

A filter is conjunctive: a record is returned only if it satisfies every present filter
field. A SPATIAL_QUERY with no filter field requests the responder's whole current
spatial state.

### 5.7 SPATIAL_SNAPSHOT (`0x0106`)

A SPATIAL_SNAPSHOT carries the common envelope (§4.2, echoing the query's `corr`) and:

| Field (key) | CBOR type | Meaning |
|---|---|---|
| `frames` (3) | Array of FRAME_DEF-body maps (§5.1) | The responder's current frame tree. Present only when the query set `want_frames` true. |
| `poses` (4) | Array of POSE_UPDATE-body maps (§5.3) | The last-known pose for each requested body, possibly empty. |
| `states` (5) | Array of STATE_DELTA-body maps (§5.4) | The last-known twist for each requested body. OPTIONAL; a responder that does not retain twist state omits this field. |
| `complete` (6) | Boolean | True if the snapshot is the entire matching set; false if the responder paginated and more SPATIAL_SNAPSHOT frames follow, bearing the same `corr`. |
| `cursor` (7) | Byte string | Present only when `complete` is false; an opaque continuation token the requester echoes in a follow-up SPATIAL_QUERY (`cursor`, key 5) to retrieve the next page. |

When a responder paginates, it emits one or more SPATIAL_SNAPSHOT frames with `complete`
false and a `cursor`, followed by a final SPATIAL_SNAPSHOT with `complete` true. The
responder MUST reject (SPATIAL_ERROR, code `StaleCursor`) a `cursor` it no longer
recognizes. An empty snapshot is a single SPATIAL_SNAPSHOT with empty `poses` (and, if
`want_frames` was set, empty `frames`) and `complete` true.

## 6. Correlation, operation, and state model

### 6.1 Correlation

- A SPATIAL_QUERY MUST carry a non-empty `corr` unique among the requester's outstanding
  queries on the Spatial channel in that direction. SPATIAL_SNAPSHOT and SPATIAL_ERROR
  MUST echo it verbatim.
- A receiver MUST match a reply to its request by `corr`, NOT by frame sequence number.
  This is required under the channel's concurrent Multi-stream operation, where replies
  on different streams need not arrive in query order.
- The one-way frames `0x0100`–`0x0104` MUST omit `corr`, and a receiver MUST NOT reply
  to them.

### 6.2 Receiver state model

A receiver maintains an **association-scoped spatial store**, keyed by `coord_frame` for
the frame tree and by `(coord_frame, body_id)` for body state:

- **FRAME_DEF** establishes or replaces a tree edge by `epoch`: a FRAME_DEF whose `epoch`
  is strictly greater than the one held for that `coord_frame` replaces it; one whose
  `epoch` is less than or equal is ignored. This makes frame definitions reorder- and
  duplicate-safe, and it preserves the REP-105 single-parent acyclic tree (a FRAME_DEF
  that would introduce a second live parent or a cycle is rejected, §5.1).
- **TRANSFORM** updates the timestamped transform on a tree edge.
- **POSE_UPDATE** and **STATE_DELTA** update the last-known state of a body by newest
  `stamp`: a receiver MUST ignore a sample whose `stamp` is less than or equal to the
  last-applied `stamp` for that body, so that a late or duplicated sample on a lossy
  high-frequency stream does not overwrite a newer one.

### 6.3 Best-effort streams versus authoritative query

The one-way frames `0x0100`–`0x0104` are best-effort: a sample MAY be lost or arrive out
of order, and delivery is not acknowledged. The SPATIAL_QUERY/SPATIAL_SNAPSHOT exchange
is therefore the **authoritative** mechanism for a peer's current spatial state; a
receiver MUST NOT treat the mere absence of a stream sample as a state change, and a peer
that needs a coherent current view MUST obtain it by query rather than by assuming it
observed every stream frame — exactly as NPAMP-DISC treats an announcement as
non-authoritative relative to a query.

### 6.4 Association scoping

All spatial state is scoped to the association. When the association closes, all frames,
transforms, body state, and outstanding queries learned over it are discarded; a peer
MUST re-advertise spatial state after a new handshake and MUST NOT carry spatial state
from a prior association into a new one.

## 7. Error model (SPATIAL_ERROR `0x0107`)

A failure in the spatial exchange itself is reported as SPATIAL_ERROR, echoing the
originating query's `corr`. Its payload carries the common envelope (§4.2) and:

| Field (key) | CBOR type | Meaning |
|---|---|---|
| `code` (3) | Unsigned int | One of the codes below. |
| `reason` (4) | Text string | Advisory human-readable detail (OPTIONAL). MUST NOT be relied on for control flow. |

| Code | Name | Meaning |
|---|---|---|
| 1 | MalformedPayload | The payload is not valid deterministic CBOR, omits a required field, uses a wrong CBOR major type, carries an unrecognized negative key, or fails the occupancy cell-length check (§4, §5.5). |
| 2 | KindMismatch | The payload's `frame_kind` contradicts the frame-header Frame Type (§4.2). |
| 3 | UnknownFrame | A query references a `coord_frame` or `child_frame` for which no live FRAME_DEF is held (§5.1, §5.2). |
| 4 | FrameTreeConflict | A FRAME_DEF would give a frame a second live parent or would close a cycle (§5.1). |
| 5 | FilterUnsupported | A SPATIAL_QUERY carries a filter field the responder does not implement; the responder MUST NOT silently return an over-broad snapshot (§5.6). |
| 6 | StaleCursor | A pagination `cursor` the responder no longer recognizes (§5.7). |
| 7 | NotAdvertised | The Spatial channel was not advertised for this association, or Spatial is disabled by local policy. |
| 8 | ProfileTooLow | The Spatial channel requires the High profile or higher and the negotiated profile is below High (§2). |

A responder MUST NOT report a `complete` true SPATIAL_SNAPSHOT for a set it could not
fully and faithfully represent; such a query MUST yield either a paginated snapshot
(§5.7) or a SPATIAL_ERROR. An over-broad snapshot returned because an unsupported filter
was ignored is a conformance violation (§8): it misleads the requester into acting on
state that does not satisfy the constraint it asked for.

## 8. Conformance

An implementation conforms to NPAMP-SPATIAL if and only if, on the Spatial channel
`0x0013`, it:

1. Enables the Spatial channel only at the **High** profile or higher, never at the
   Standard profile, and drops (or reports `ProfileTooLow`) Spatial frames arriving under
   a below-High negotiated profile; and does not deliver frames on a Spatial channel the
   peer has not advertised during the handshake, dropping such frames (§2);
2. Uses only the Spatial application frame types defined in §3, all within the channel
   application band at or above `0x0100`, preserves the core meaning of the reserved
   all-channel frame types (`0x0001`–`0x000A`), and defines no Spatial application
   semantics in the future-core band (`0x000B`–`0x002F`) or the companion-extension band
   (`0x0030`–`0x00FF`) (§3);
3. Encodes every Spatial body as a deterministic-CBOR map (§4.1), rejects a malformed or
   kind-mismatched payload with the corresponding SPATIAL_ERROR, ignores an unrecognized
   non-negative key, and rejects an unrecognized negative key (§4);
4. Applies REP-103 geometry exactly — right-handed frames, body axes x-forward/y-left/
   z-up (ENU for geographic frames), unit-quaternion `(x, y, z, w)` orientation,
   fixed-axis `(X, Y, Z)` angular velocity, SI units, and a row-major 6×6 covariance
   ordered `(x, y, z, rotX, rotY, rotZ)` — and treats an absent covariance as unknown,
   not zero (§5);
5. Maintains a REP-105 single-parent acyclic frame tree — replacing a FRAME_DEF only on a
   strictly greater `epoch`, and rejecting a second-parent or cyclic edge with
   `FrameTreeConflict` (§5.1, §6.2);
6. Applies newest-`stamp`-wins for POSE_UPDATE and STATE_DELTA, ignoring a sample whose
   `stamp` is less than or equal to the last applied one and a FRAME_DEF whose `epoch`
   does not advance (§6.2);
7. Enforces correlation per §4.2 and §6.1 — a unique `corr` on SPATIAL_QUERY, a verbatim
   echo on SPATIAL_SNAPSHOT and SPATIAL_ERROR, replies matched by `corr` rather than by
   frame sequence number, and no `corr` and no reply on the one-way frames `0x0100`–
   `0x0104` (§6.1);
8. Never reports a `complete` true snapshot for a set it could not fully represent
   (paginating or replying SPATIAL_ERROR instead), applies each present query filter
   conjunctively, replies `FilterUnsupported` rather than returning an over-broad
   snapshot for an unsupported filter, and treats a stream sample as non-authoritative
   relative to a query (§5.6, §6.3, §7);
9. Carries no Spatial state across associations and re-advertises after a new handshake
   (§6.4); and
10. Adds no cryptographic behavior of its own, treating the crypto suite and operational
    internals bound to the High or Sovereign profile as governed by the core
    specification's profile negotiation, out of scope for this application interface
    (§1.2, §2).

No machine-gradable conformance vectors exist for the Spatial channel yet: a claim of
conformance to this document is therefore specification-audited and MUST NOT be
represented as corpus-verified. A conformance test suite SHOULD assert each clause above with a recorded exchange on the
Spatial channel: a four-frame FRAME_DEF chain (`earth` → `map` → `odom` → `base_link`)
accepted as a tree; a FRAME_DEF that introduces a second parent and one that closes a
cycle, each rejected with `FrameTreeConflict`; a TRANSFORM carrying a quaternion and a
36-element row-major covariance decoded to the expected `(x, y, z, rotX, rotY, rotZ)`
matrix as a byte-exact deterministic-CBOR vector; a POSE_UPDATE stream in which a
stamp-ascending sample is applied and a stamp-regressing replay is ignored; an
OCCUPANCY_UPDATE under encoding `0` whose `cells` length is checked against
`width × height` (with a wrong-length payload rejected `MalformedPayload`) and under
encoding `1` decoded to the same grid; a correlated SPATIAL_QUERY/SPATIAL_SNAPSHOT
exchange in which a reply bearing a different `corr` is left unmatched; a paginated
snapshot across at least two SPATIAL_SNAPSHOT frames followed by a `StaleCursor`
rejection of an expired cursor; each SPATIAL_ERROR code provoked by the corresponding
malformed or unsupported input; a non-negative unknown key ignored while a negative
unknown key is rejected; and a Spatial frame under a below-High negotiated profile
rejected `ProfileTooLow` or dropped.
