# NPAMP-WORKFLOW — Workflow-Channel Operation Framework (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words MUST, MUST NOT,
> REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL
> are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only
> when, they appear in all capitals, as shown here. This document defines a
> **native** operation framing for the N-PAMP **Workflow channel `0x0011`**: the
> frame types, the deterministic-CBOR operation bodies, the in-body correlation
> discipline, the task lifecycle and step-event model, and the structured error
> model by which one peer delegates a unit of agentic work to another peer and
> tracks it to completion. It builds on the core specification
> (draft-bubblefish-npamp-01) and does not redefine it. Unlike a Bridge carriage
> class, the Workflow channel carries no foreign protocol: the operation body **is**
> N-PAMP's own encoding, so this document consumes no extension-TLV code point. It
> introduces no change to the core wire format.

## 1. Scope

### 1.1 In scope

This document specifies, over the Workflow channel `0x0011` of the N-PAMP core
specification (the "core specification", draft-bubblefish-npamp-01):

1. A set of Workflow-channel frame types, drawn entirely from the channel-specific
   application band that begins at `0x0100` (core specification §4.6, frame-type
   namespace). The core specification reserves **no** companion-extension range for
   the Workflow channel (core specification §8.1, Reserved Frame-Type Ranges;
   `../09_extension_points.md`), so every frame this document defines lies in the
   `0x0100`+ application band;
2. Per-operation request and result frame pairs realizing the two coordination
   classes the core registry names for this channel — **multi-agent orchestration
   and task delegation** — expressed as a task lifecycle: submit (delegate) a task,
   query its status, and request its cancellation, plus asynchronous **step events**
   and a terminal **completion** event that report the delegated work's progress and
   outcome;
3. The **deterministic-CBOR** encoding of every operation body (RFC 8949, core
   specification §4.5 and §11.9), keyed by unsigned integers;
4. An **in-body correlation** discipline with two keys — a per-exchange correlation
   token that matches a reply to its request, and a durable **task identifier** that
   binds asynchronous step and completion events to the task they report — both
   carried inside the CBOR body, consuming no shared TLV tag; and
5. A single structured **error frame** whose result set preserves a governance
   escalation (a delegated task held for human approval and NOT executed) as a
   distinct, non-success outcome.

Operations are described generically — delegate a task, query its state, cancel it,
and receive its step and completion events — so that any executor implementation and
any delegator interoperate over N-PAMP with no bespoke adaptation. The document names
no product, no vendor, and no application-specific task schema.

### 1.2 Not in scope

This document does NOT:

* **Define what a task *is*, or its input/output schema.** The `task_type`, `input`,
  `params`, and `output` fields (§6) are opaque, deployment-defined projections that
  cross the wire; how an executor interprets, schedules, or performs the work is a
  local matter this document does not constrain. It fixes only what crosses the wire.
* **Define an orchestration topology, dependency graph, or scheduler.** The core
  specification defines none for this channel (Workflow channel interface reference
  `../channels/0011_workflow.md` §4), and neither does this document. A task is a
  single delegated unit; composing tasks into a graph, assigning priorities beyond an
  advisory hint, or routing among more than two peers is layered above this framing.
* **Define a delegation-authority or capability model.** Whether a peer is *permitted*
  to delegate a task, and under what grant, is a matter for the Capability channel
  `0x0002` or a future companion (Workflow channel interface reference §4); this
  document defines only how an authorization outcome — permitted, denied, or escalated
  for human approval — is *reported* on the wire (§8), not the policy that produces it.
* **Carry a foreign agent protocol.** The Workflow channel is native; it is not a
  Bridge carriage class and does not build on NPAMP-BRIDGE (Workflow channel interface
  reference §6). No frame in this document encapsulates a foreign message, and this
  document defines and consumes no extension-TLV tag. A *foreign* orchestration or
  task protocol is carried instead over the Bridge channel `0x000D` under a mapped
  carriage class, or under Class OPAQUE (`25_carriage_opaque.md`) — that is carriage
  of a foreign protocol and is distinct from the native Workflow operations here.
* **Change the core wire format.** It alters no field of the core frame header, no
  reserved all-channel frame type, the extension-TLV encoding, or any code point the
  core specification assigns; it uses only channel-specific application code points
  the core specification leaves available to the Workflow channel.

## 2. Relationship to the core specification

The Workflow channel `0x0011` is registered by the core specification with purpose
**"Multi-agent orchestration and task delegation"**, minimum profile **Standard**,
and direction **Bidirectional** (core specification §5, Core Channel Registry;
machine-readable form `../../registries/channels.csv`; restated in the Workflow
channel interface reference `../channels/0011_workflow.md` §2). Under the core
specification's channel architecture every channel is full-duplex: each peer
maintains an independent per-direction sequence space and independent per-direction
traffic keys. Because the channel is **Bidirectional** — and, unlike the Memory
`0x0001` or Stream `0x000C` channels, **not** Multi-stream — both peers send and
receive on a single stream per direction, and **either peer MAY originate a task
delegation**; there is no fixed orchestrator/worker assignment at the channel level.
In this document the peer that sends a WORKFLOW_SUBMIT_REQ is the **delegator** and
the peer that executes the task is the **executor**, but the roles are per-task, not
per-association: a peer MAY be delegator for one task and executor for another on the
same association.

**Minimum-profile gate.** A peer MUST enable the Workflow channel only at the
**Standard** profile or higher; once Standard is met the channel is available at
Standard, High, and Sovereign, and there is no profile at which it becomes
unavailable. A peer that has not advertised the Workflow channel during the
handshake (core specification §5) MUST NOT receive frames on it; a frame arriving on
an unadvertised Workflow channel MUST be dropped and MUST NOT be delivered to a
workflow consumer.

**Native, not a carriage class.** A Bridge carriage class carries a *foreign*
protocol's message octet-for-octet and wraps routing and correlation metadata
*around* it in a shared extension TLV. The Workflow channel has no foreign protocol:
the operation body is N-PAMP's own deterministic-CBOR encoding, and this document
owns that body in full. Consequently the correlation token, the task identifier, the
lifecycle model, and the error object all live **inside** the CBOR body, and this
document reserves and consumes **no extension-TLV code point**. This is the
deliberate structural difference from NPAMP-BRIDGE and is the reason a Workflow
operation is routed by its N-PAMP **frame type** (§3) rather than by any method-name
or tool-name field parsed from a body.

**Frame-type namespace bands.** The core specification partitions each channel's
`0x0000`–`0xFFFF` frame-type space into four bands (core specification §4.6,
Frame-Type Namespace): `0x0000`–`0x000A` reserved all-channel frame types with the
same meaning on every channel; `0x000B`–`0x002F` unassigned, reserved to the core
for future all-channel additions; `0x0030`–`0x00FF` the **companion-extension band**,
per-channel extension frame types the core specification reserves range-by-range for
named channels; and `0x0100`–`0xFFFF` **channel-specific application** frame types.
The core specification reserves **no** companion-extension range for the Workflow
channel: its Reserved Frame-Type Ranges table assigns sub-`0x0100` ranges only to the
Memory, Capability, Control, Audit, Settlement/Audit, Governance, and Immune channels
(`../09_extension_points.md`; Workflow channel interface reference §3.2). This
document therefore places **all** of its frames in the application band at `0x0100`+,
in the same manner as a channel with no reserved band (for example the Telemetry
family). Because the frame-type space is scoped by the Channel ID header field, these
code points do not collide with any other channel's assignments at the same numeric
values.

## 3. Workflow-channel frame types

Within the Workflow channel (`0x0011`) frame-type namespace, this specification
defines nine frame types, all in the channel-specific application band at `0x0100`+.

### 3.1 Application-band operation frames (`0x0100`+)

| Type | Name | Reply | Purpose |
|---|---|---|---|
| `0x0100` | WORKFLOW_SUBMIT_REQ | WORKFLOW_SUBMIT_RESULT or WORKFLOW_ERROR | Delegate a unit of agentic work for execution; carries the work descriptor and its declared side-effect class. |
| `0x0101` | WORKFLOW_SUBMIT_RESULT | None | Acceptance reply to a submit; assigns the durable `task_id` and the task's initial lifecycle state. Echoes the request's correlation token. |
| `0x0102` | WORKFLOW_STATUS_REQ | WORKFLOW_STATUS_RESULT or WORKFLOW_ERROR | Query the current lifecycle state of a delegated task. |
| `0x0103` | WORKFLOW_STATUS_RESULT | None | Current-state reply to a status query. |
| `0x0104` | WORKFLOW_CANCEL_REQ | WORKFLOW_CANCEL_RESULT or WORKFLOW_ERROR | Request cancellation of an in-flight task. |
| `0x0105` | WORKFLOW_CANCEL_RESULT | None | Cancellation reply carrying the task's resulting lifecycle state. |
| `0x0106` | WORKFLOW_STEP_EVENT | None | Unsolicited progress event for a running task; correlated to the task by `task_id` (§5). |
| `0x0107` | WORKFLOW_COMPLETE | None | Unsolicited terminal event carrying the task's final state and output; correlated to the task by `task_id` (§5). |
| `0x0108` | WORKFLOW_ERROR | None | Structured failure for a request; echoes the correlation token and carries a Workflow error code (§8). |

A `*_REQ` frame originates an operation; the corresponding `*_RESULT` frame, or a
WORKFLOW_ERROR (`0x0108`), replies to it. A `*_RESULT` frame is never sent
unsolicited: each MUST echo the correlation token of the request it answers (§5). A
responder MUST NOT emit both a `*_RESULT` and a WORKFLOW_ERROR for the same request.
WORKFLOW_STEP_EVENT (`0x0106`) and WORKFLOW_COMPLETE (`0x0107`) are **not** replies to
a request: they are asynchronous, task-scoped notifications the executor emits as the
delegated work progresses, correlated to their task by `task_id` rather than by a
per-exchange correlation token (§5).

### 3.2 Reserved all-channel frame types

The reserved all-channel frame types (PING `0x0001`, PONG `0x0002`, CLOSE `0x0003`,
CLOSE_ACK `0x0004`, ERROR `0x0005`, KEY_UPDATE `0x0006`, KEY_UPDATE_ACK `0x0007`,
PATH_CHALLENGE `0x0008`, PATH_RESPONSE `0x0009`, and FLOW_UPDATE `0x000A`; core
specification §4.6) retain their core meaning on the Workflow channel. An
implementation MUST NOT reuse them for Workflow application traffic and MUST NOT
define Workflow operation semantics in the reserved all-channel range
`0x0000`–`0x000A`. Liveness, teardown, error signalling, key update, path migration,
and connection-level flow control on the channel use those all-channel frames with
their core meaning.

### 3.3 No reserved companion-extension band

Unlike the Memory channel — for which the core specification reserves `0x0035`–`0x0036`
in the companion-extension band — the core specification reserves **no** sub-`0x0100`
range for the Workflow channel (§2; `../09_extension_points.md`). This document
therefore defines no frame in the `0x0030`–`0x00FF` band and claims no code point in
any of the core specification's cross-channel reserved ranges. All nine frame types
defined above lie within the Workflow channel's own application band at or above
`0x0100`; this document consumes no frame-type code point outside that band.

## 4. Frame payload encoding

### 4.1 Payload container

A Workflow frame's payload (the octets after the core frame header and any extension
TLVs, and before the AEAD tag) is a single **deterministically encoded CBOR** object
as defined by the core specification §4.5 and §11.9 (deterministic CBOR, RFC 8949).
The payload MUST be a CBOR map whose keys are the unsigned integers defined in §4.2
and §5–§8 for the relevant frame type. A sender MUST produce the deterministic
encoding (core specification §11.9): byte-identical output for identical inputs, with
the canonical key ordering and shortest-form integer encoding RFC 8949 §4.2 requires,
and definite-length maps and arrays.

A receiver MUST reject, with WORKFLOW_ERROR code `malformed_request` (§8), any
Workflow frame whose payload is not a valid deterministic-CBOR map, whose payload
omits a REQUIRED key for its frame type, or whose payload carries a key of the wrong
CBOR major type.

Workflow operation bodies are carried in the frame **payload**, not in extension
TLVs. This document defines and consumes no extension-TLV tag, and therefore claims
none of the TLV code points the core specification reserves.

### 4.2 Common envelope fields

Every Workflow payload map carries the following envelope fields. Integer keys are
given in parentheses.

| Field (key) | CBOR type | Meaning |
|---|---|---|
| `frame_kind` (0) | Unsigned int | MUST equal the frame's Workflow frame type (one of `0x0100`–`0x0108`). A receiver MUST reject (WORKFLOW_ERROR, code `malformed_request`) a payload whose `frame_kind` contradicts the frame-header Frame Type. |
| `corr` (1) | Byte string (1–64 B) | Per-exchange correlation token (§5.1). Present and non-empty on every `*_REQ` and on every `*_RESULT` and WORKFLOW_ERROR that replies to one. **Absent** on the unsolicited WORKFLOW_STEP_EVENT (`0x0106`) and WORKFLOW_COMPLETE (`0x0107`), which are correlated to their task by `task_id` (§5.2), not by an exchange token. |

The per-frame body fields defined in §5–§8 occupy keys `2` and above within the same
map; §6 gives, per frame, the full field table.

### 4.3 Forward compatibility

A receiver MUST ignore an unrecognized integer key it encounters in a Workflow
payload map whose key is **not negative**, so that a later revision of this document
MAY add fields without breaking a conformant receiver. A receiver MUST reject
(WORKFLOW_ERROR, code `malformed_request`) a payload that carries a **negative**
integer key it does not recognize, reserving the negative key space for
forward-incompatible additions. A receiver MUST NOT treat the mere presence of an
unknown non-negative key as an error, and MUST NOT alter its handling of the keys it
does recognize because of it.

## 5. Correlation and task model

The core specification does not define how a Workflow reply is correlated to its
request, nor how an asynchronous event is bound to the task it reports (Workflow
channel interface reference §4, "Correlation and ordering": the core specification
"does not define how a Workflow reply (if any) is correlated to a request"). This
document supplies that discipline, carrying both correlation keys **inside** the CBOR
body rather than in a shared TLV, because a native channel owns its whole body (§2).
Two distinct keys are used because a task is a long-lived object while each management
operation on it is a short request/reply exchange:

* **`corr`** — a per-exchange token (§5.1) that matches a `*_RESULT` or WORKFLOW_ERROR
  to the `*_REQ` it answers. This is the same in-body correlation discipline the
  Memory channel uses.
* **`task_id`** — a durable, executor-assigned identifier (§5.2) that names the
  delegated task for its whole lifetime. Status and cancel requests reference it, and
  the asynchronous WORKFLOW_STEP_EVENT and WORKFLOW_COMPLETE frames are correlated to
  their task by it. It is the task analogue of the Memory channel's `record_id`.

### 5.1 Per-exchange correlation (`corr`)

* Every `*_REQ` frame (WORKFLOW_SUBMIT_REQ `0x0100`, WORKFLOW_STATUS_REQ `0x0102`,
  WORKFLOW_CANCEL_REQ `0x0104`) MUST carry a non-empty `corr` (§4.2) that is unique
  among the originating peer's outstanding Workflow requests on the channel in that
  direction.
* Every `*_RESULT` frame and every WORKFLOW_ERROR MUST echo the originating request's
  `corr` verbatim.
* A receiver MUST match a reply to its request by `corr`, **not** by the
  per-(channel, direction) frame sequence number. Because either peer may have several
  management exchanges and several tasks concurrently in flight on the single
  bidirectional stream, frame sequence order does not identify the originating
  exchange.
* A `corr` value is consumed when its `*_RESULT` or WORKFLOW_ERROR is delivered; the
  requester MUST treat that exchange as complete and MUST NOT reuse the value for a new
  request while the original is outstanding.

### 5.2 Durable task correlation (`task_id`)

* The executor assigns a `task_id` (a non-empty text string, unique among the
  executor's live tasks for the association) in the WORKFLOW_SUBMIT_RESULT (§6.1) that
  accepts a submit. The delegator learns the `task_id` from that result.
* WORKFLOW_STATUS_REQ and WORKFLOW_CANCEL_REQ carry the `task_id` of the task they act
  on. WORKFLOW_STEP_EVENT and WORKFLOW_COMPLETE carry the `task_id` of the task they
  report.
* An executor MUST send the WORKFLOW_SUBMIT_RESULT that assigns a `task_id` **before**
  it emits any WORKFLOW_STEP_EVENT or WORKFLOW_COMPLETE for that task, so a delegator
  never receives an event for a `task_id` it has not yet been given. A receiver that
  receives a step or completion event for an unknown `task_id` MUST discard it and
  MUST NOT treat it as opening a task.
* Because a `task_id` is durable and a `corr` is per-exchange, a delegator MAY issue
  several status queries against one `task_id` over the task's lifetime, each a
  separate `corr` exchange.

### 5.3 Side-effect class (`effect`)

Delegating a task is inherently a request to *do work*, which may change state. Every
WORKFLOW_SUBMIT_REQ MUST carry an `effect` field (§6.1) declaring the most severe side
effect the delegated task may cause, drawn from the side-effect classes below. It is
the native-body analogue of a Bridge SafetyLabel, carried in-body because the Workflow
channel owns its body (§2), and it lets an executor apply admission policy before it
begins work.

| Value | Name | Meaning |
|---|---|---|
| `0x00` | read_only | The task only reads or computes and makes no external state change. |
| `0x01` | idempotent_write | The task writes, but repeating it yields the same state. |
| `0x02` | non_idempotent_write | The task writes and is not safely repeatable. |
| `0x03` | destructive | The task removes or irreversibly alters state. |

**Fail-safe.** A receiver MUST treat a WORKFLOW_SUBMIT_REQ that omits `effect`, or
carries an `effect` value it does not recognize, as `destructive`, and MAY refuse it
(WORKFLOW_ERROR). A delegator MUST NOT rely on a submit that omits `effect` being
executed.

### 5.4 Task lifecycle states

A task progresses through the lifecycle states below, carried as the `state` field
(an unsigned int) of the frames that report it (§6). States `0x02`–`0x04` are
**terminal**: a task in a terminal state undergoes no further transition and emits no
further step or completion events.

| Value | Name | Terminal | Meaning |
|---|---|---|---|
| `0x00` | accepted | No | The task was accepted by the executor but has not begun. |
| `0x01` | running | No | The task is executing; step events MAY be emitted. |
| `0x02` | succeeded | Yes | The task completed successfully. |
| `0x03` | failed | Yes | The task ran and failed. |
| `0x04` | canceled | Yes | The task was canceled before it reached a success or failure terminal. |

## 6. Operation bodies

Each operation body is a deterministic-CBOR map carrying the common envelope (§4.2)
and the per-frame fields below at keys `2`+. Unless a field is marked required, it is
OPTIONAL and, when absent, carries no value (a producer omits the key rather than
encoding a null placeholder; a producer that does encode an explicit CBOR `null` for
an absent OPTIONAL field is equivalent to omitting it).

### 6.1 WORKFLOW_SUBMIT_REQ (`0x0100`) / WORKFLOW_SUBMIT_RESULT (`0x0101`)

Delegate a unit of agentic work for execution.

**WORKFLOW_SUBMIT_REQ body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `task_type` (2) | Text string | Yes | The kind of work being delegated: an opaque, deployment-defined task-type name. This document assigns it no schema (§1.2). |
| `input` (3) | Byte string | No | Opaque input payload for the task. This document assigns it no schema. |
| `params` (4) | Map | No | Structured parameters keyed by unsigned integers; the inner schema is a local matter and a receiver MUST apply the forward-compatibility rule (§4.3) to it. |
| `priority` (5) | Unsigned int | No | Advisory scheduling-priority hint (a higher value is more urgent). Advisory only; it does not change the result schema and an executor MAY ignore it. |
| `deadline` (6) | Text string | No | An RFC 3339 timestamp by which the delegator wants the task complete. Advisory. |
| `actor_type` (7) | Text string | No | The kind of actor delegating the task (for example `user`, `agent`, or `system`). |
| `actor_id` (8) | Text string | No | An opaque identifier of the delegating actor within the requester's namespace. |
| `idempotency_key` (9) | Text string | No | A caller-supplied key that lets the executor de-duplicate a retried submit. When present and matching a prior submit, the executor MAY return the existing task's `task_id` rather than start a new task. |
| `scope` (10) | Map | No | Isolation scope for the task (for example a workspace or enclave scoping map). Its keys are a local matter; the executor MUST associate it with the task so isolation survives. |
| `effect` (11) | Unsigned int | Yes | Side-effect class (§5.3): the most severe side effect the task may cause. |

**WORKFLOW_SUBMIT_RESULT body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `task_id` (2) | Text string | Yes | The identifier the executor assigned to the accepted task (§5.2). |
| `state` (3) | Unsigned int | Yes | The task's initial lifecycle state (§5.4); normally `0x00` accepted or `0x01` running. |

A submit that the executor holds for human approval, rather than accepting for
execution, is NOT reported as a WORKFLOW_SUBMIT_RESULT; it is reported as
WORKFLOW_ERROR with code `approval_required` (§8.1). A submit the executor definitively
refuses is reported as WORKFLOW_ERROR `policy_denied`. An executor MUST NOT emit a
WORKFLOW_SUBMIT_RESULT for a task it did not accept.

### 6.2 WORKFLOW_STATUS_REQ (`0x0102`) / WORKFLOW_STATUS_RESULT (`0x0103`)

Query the current lifecycle state of a delegated task.

**WORKFLOW_STATUS_REQ body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `task_id` (2) | Text string | Yes | The task to query. |

**WORKFLOW_STATUS_RESULT body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `task_id` (2) | Text string | Yes | Echo of the queried task. |
| `state` (3) | Unsigned int | Yes | The task's current lifecycle state (§5.4). |
| `step` (4) | Unsigned int | No | Advisory index of the current or most recent step. |
| `step_label` (5) | Text string | No | Advisory, peer-safe human-readable label of the current step. |
| `progress` (6) | Unsigned int (0–100) | No | Advisory completion percentage. |
| `detail` (7) | Text string | No | An advisory, peer-safe status note. It MUST NOT carry internal detail (§8.2). |

A status query naming a `task_id` the executor does not recognize is reported as
WORKFLOW_ERROR with code `unknown_task` (§8), not as a WORKFLOW_STATUS_RESULT with an
invented state.

### 6.3 WORKFLOW_CANCEL_REQ (`0x0104`) / WORKFLOW_CANCEL_RESULT (`0x0105`)

Request cancellation of an in-flight task.

**WORKFLOW_CANCEL_REQ body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `task_id` (2) | Text string | Yes | The task to cancel. |
| `reason` (3) | Text string | No | An advisory, peer-safe reason for the cancellation. |

**WORKFLOW_CANCEL_RESULT body**

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `task_id` (2) | Text string | Yes | Echo of the task. |
| `state` (3) | Unsigned int | Yes | The task's lifecycle state after the cancel request was processed (§5.4). |

Cancellation is a **request**, not a guaranteed immediate transition: the
WORKFLOW_CANCEL_RESULT reports the task's *actual* resulting state. If cancellation
took effect, `state` is `0x04` canceled. If the task had **already reached a terminal
state** (`0x02` succeeded or `0x03` failed) before the cancel could take effect, the
executor MUST report that terminal state — it MUST NOT report `0x04` canceled for a
task that in fact succeeded or failed, because a WORKFLOW_CANCEL_RESULT that claimed a
task was canceled while the task actually completed would be a false report of the
task's outcome. A cancel naming an unknown `task_id` is reported as WORKFLOW_ERROR
`unknown_task` (§8). When cancellation takes effect, the executor also emits a
terminal WORKFLOW_COMPLETE with `state` `0x04` canceled (§6.5).

### 6.4 WORKFLOW_STEP_EVENT (`0x0106`)

An asynchronous progress event the executor emits while a task is running. It is
unsolicited, task-scoped (§5.2), and carries no `corr`.

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `task_id` (2) | Text string | Yes | The task this event reports. |
| `seq` (3) | Unsigned int | Yes | A per-task event sequence number starting at `0` and increasing by one for each step event of the task, so a receiver can order events and detect a gap independent of the frame sequence number. |
| `state` (4) | Unsigned int | Yes | The task's lifecycle state at the time of the event (§5.4); on a WORKFLOW_STEP_EVENT this MUST be a non-terminal state (`0x00` accepted or `0x01` running). |
| `step` (5) | Unsigned int | No | Advisory index of the step this event reports. |
| `step_label` (6) | Text string | No | Advisory, peer-safe label of the step. |
| `progress` (7) | Unsigned int (0–100) | No | Advisory completion percentage. |
| `output` (8) | Byte string | No | Opaque incremental output produced by this step. This document assigns it no schema. |
| `detail` (9) | Text string | No | An advisory, peer-safe note. It MUST NOT carry internal detail (§8.2). |

Step events are advisory progress reports: a delegator MUST NOT rely on receiving any
particular step event, and an executor MAY emit none. The authoritative outcome of a
task is its terminal WORKFLOW_COMPLETE (§6.5) or a WORKFLOW_ERROR for the submit.

### 6.5 WORKFLOW_COMPLETE (`0x0107`)

The terminal event for a task. It is unsolicited, task-scoped (§5.2), carries no
`corr`, and is emitted exactly once per accepted task that reaches a terminal state.

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `task_id` (2) | Text string | Yes | The task that terminated. |
| `seq` (3) | Unsigned int | Yes | The task's final per-task event sequence number; it MUST be greater than the `seq` of every WORKFLOW_STEP_EVENT the executor emitted for the task. |
| `state` (4) | Unsigned int | Yes | The task's terminal lifecycle state (§5.4): `0x02` succeeded, `0x03` failed, or `0x04` canceled. |
| `output` (5) | Byte string | No | Opaque final result payload of the task. This document assigns it no schema. Present typically when `state` is `0x02` succeeded. |
| `error_code` (6) | Unsigned int | No | Present when `state` is `0x03` failed: a Workflow error code (§8) classifying the execution failure. |
| `detail` (7) | Text string | No | An advisory, peer-safe note on the outcome. It MUST NOT carry internal detail (§8.2). |

A WORKFLOW_COMPLETE reports the outcome of a task that was **accepted** (a submit that
returned WORKFLOW_SUBMIT_RESULT). It is distinct from a WORKFLOW_ERROR: a
WORKFLOW_ERROR reports the failure of a *request exchange* (for example a submit the
executor never accepted, or a status query for an unknown task) and echoes that
request's `corr`, whereas a WORKFLOW_COMPLETE with `state` `0x03` failed reports that
an accepted task *ran and then failed*, and is correlated by `task_id`. An executor
MUST NOT report a task's failure both as a WORKFLOW_ERROR to the original submit and
as a failed WORKFLOW_COMPLETE: a submit that is accepted is answered by
WORKFLOW_SUBMIT_RESULT, and any later execution failure of that accepted task is a
failed WORKFLOW_COMPLETE.

## 7. Operation and state model

A task is a single unit of delegated work with the lifecycle of §5.4. The exchange
and event sequence over its lifetime is:

1. The delegator sends **WORKFLOW_SUBMIT_REQ** (`0x0100`) with a fresh `corr`, a
   `task_type`, and its declared `effect`.
2. The executor either accepts — replying **WORKFLOW_SUBMIT_RESULT** (`0x0101`) that
   echoes the `corr`, assigns a `task_id`, and states an initial `state` (`accepted`
   or `running`) — or rejects with **WORKFLOW_ERROR** (`0x0108`): `policy_denied` for
   a definitive refusal, or `approval_required` for a governance hold (§8.1), each
   echoing the `corr`.
3. While the accepted task runs, the executor MAY emit any number of
   **WORKFLOW_STEP_EVENT** (`0x0106`) frames carrying the `task_id`, a monotonically
   increasing `seq`, and a non-terminal `state`.
4. At any time the delegator MAY send **WORKFLOW_STATUS_REQ** (`0x0102`) or
   **WORKFLOW_CANCEL_REQ** (`0x0104`) naming the `task_id`, each answered by the
   corresponding `*_RESULT` (or a WORKFLOW_ERROR) echoing that request's `corr`.
5. When the task reaches a terminal state the executor emits exactly one
   **WORKFLOW_COMPLETE** (`0x0107`) carrying the `task_id`, a final `seq`, and the
   terminal `state` (`succeeded`, `failed`, or `canceled`).

The per-task state machine:

```
        WORKFLOW_SUBMIT_REQ
             |
             v
   (submit rejected: WORKFLOW_ERROR policy_denied / approval_required — no task created)
             |
             v  (accepted)
          accepted --------(execution begins)--------> running
          accepted --------(canceled before start)---> canceled (terminal)
          running  --------(step events; stays)------> running
          running  --------(success)------------------> succeeded (terminal)
          running  --------(failure)------------------> failed (terminal)
          running  --------(cancel takes effect)------> canceled (terminal)
        succeeded / failed / canceled  --(no further transition; idempotent)
```

A frame that would drive an illegal transition — a WORKFLOW_STEP_EVENT for a task
already in a terminal state, a second WORKFLOW_COMPLETE for the same task, or a
WORKFLOW_STEP_EVENT whose `state` is terminal — is a protocol error; a receiver MUST
discard such a frame and MAY treat the task's authoritative state as the terminal
state it already recorded. All task state is scoped to the association: when the
association closes, all task state, `task_id` assignments, and event sequences are
discarded, and a peer MUST NOT carry a `task_id` or its state from a prior association
into a new one.

## 8. Error model

A failure of a Workflow **request** is reported in a single WORKFLOW_ERROR (`0x0108`)
frame — the Workflow channel has no foreign protocol, so all request errors are native
and carried in one structured frame. A WORKFLOW_ERROR echoes the failed request's
`corr` (§4.2) and carries:

| Field (key) | CBOR type | Req | Meaning |
|---|---|---|---|
| `code` (2) | Unsigned int | Yes | One of the Workflow error codes below. |
| `message` (3) | Text string | Yes | A peer-safe, generic human-readable message for `code`. It MUST NOT carry internal detail (§8.2). |
| `retry_after_s` (4) | Unsigned int | No | When present, the number of seconds after which the requester MAY retry. |
| `approval_id` (5) | Text string | No | Present if and only if `code` is `approval_required`: an identifier of the held-for-approval task (§8.1). |

| Code | Name | Meaning |
|---|---|---|
| 1 | malformed_request | The CBOR body is not valid deterministic CBOR, omits a REQUIRED field, uses a wrong CBOR major type, or carries an unknown negative key (§4.3). |
| 2 | unknown_operation | The frame type is not a Workflow operation the responder implements. |
| 3 | policy_denied | The delegation or operation was refused by the responder's governance or policy: a definitive denial. |
| 4 | approval_required | The task was escalated for human approval and was **NOT executed** (§8.1). Carries `approval_id`. |
| 5 | unknown_task | A referenced `task_id` (in a status or cancel request, or a stray event) does not exist at the responder. |
| 6 | internal_error | An executor or pipeline failure the responder cannot attribute to the request. Generic; no internal detail crosses the wire. |

### 8.1 Governance escalation is a distinct, non-success outcome

A `policy_denied` (code 3) and an `approval_required` (code 4) are different results
and MUST NOT be conflated. `policy_denied` is a definitive refusal: the task will not
run. `approval_required` means the task has been **held for human approval and has NOT
been executed** — it is neither a success nor a definitive denial, but a pending
decision.

An implementation MUST report a governance escalation of a submit as WORKFLOW_ERROR
with code `approval_required`, carrying `approval_id`, and MUST NOT report it as a
WORKFLOW_SUBMIT_RESULT. A held-for-approval task MUST NOT be presented to the delegator
as an accepted or running task: a task that did not begin execution is never assigned
a running `task_id` and later silently dropped — it is `approval_required`. A delegator
MUST treat `approval_required` as a task that has not started, distinct from both an
accepted task and a `policy_denied`.

### 8.2 No internal detail on the wire

The `message` field, and every advisory `detail` field in §6, MUST be the generic,
peer-safe string for its context. The full internal cause of a failure MUST be handled
locally (for example logged by the responder) and MUST NOT cross the wire: a
WORKFLOW_ERROR, a WORKFLOW_STEP_EVENT, a WORKFLOW_STATUS_RESULT, and a
WORKFLOW_COMPLETE MUST NOT carry executor internals, scheduler topology, configuration
or source names, stack traces, or any other detail beyond the fields defined here and
their generic messages. This leak-prevention requirement is normative for
interoperability, not merely local hygiene: a delegator MUST be able to rely on the
error and event surface exposing only codes, states, generic messages, and the
OPTIONAL fields defined above.

## 9. Security and privacy considerations

This section supplements the core specification's Security Considerations; it does not
restate them.

Every Workflow frame is AEAD-protected like all N-PAMP frames and is carried under the
association's existing authentication (the core specification's handshake binds both
peer identities into the transcript and the Finished MAC). An executor therefore knows
that a task was delegated by the authenticated peer, but **authentication is not
authorization**: an executor MUST enforce its own governance and delegation-authority
policy on every submit regardless of the peer's identity, and MUST report the outcome
per §8 — including preserving the `approval_required` / `policy_denied` distinction. A
task that the executor holds for approval MUST NOT begin work before the approval is
granted.

Delegating and executing arbitrary work is a powerful capability. The `effect` field
(§5.3) lets an executor apply admission control *before* it begins work, and the
fail-safe treats a missing or unknown `effect` as `destructive`. An executor SHOULD
refuse a delegated task whose declared `effect` exceeds what local policy permits the
peer to delegate, reporting `policy_denied`.

A responder MUST bound the resources a remote peer can consume through Workflow
operations: the number of concurrent live tasks it will accept, the rate of submits,
the rate and size of step events it will emit, and the buffering it will devote to a
task's output. A responder MAY reply WORKFLOW_ERROR (with `retry_after_s`) or decline
a submit rather than allocate without limit. Because either peer may originate tasks on
this bidirectional channel, both directions are subject to these limits.

Cancellation is a real control action, not a cosmetic status flip: an executor that
returns `canceled` (in a WORKFLOW_CANCEL_RESULT or a terminal WORKFLOW_COMPLETE) MUST
have actually stopped, or committed to stop, the underlying work — it MUST NOT report a
task as canceled while continuing to execute it, because that would be a false report
of the task's state (§6.3). Where the work had already completed, the true terminal
state is reported instead.

The error and event surface MUST NOT leak internal detail (§8.2); a frame that carried
executor internals, scheduler topology, or configuration names would disclose the
responder's internal structure to the peer and is a conformance violation (§10).

## 10. Conformance

An implementation conforms to NPAMP-WORKFLOW if and only if it rests on a
core-conformant N-PAMP wire implementation and, on the Workflow channel `0x0011`, it:

1. Treats `0x0011` as the Workflow channel with the core registry identity (name
   Workflow; purpose multi-agent orchestration and task delegation; minimum profile
   Standard; direction Bidirectional), does not repurpose the channel identifier,
   enables it only at the **Standard** profile or higher, and drops any frame received
   on an unadvertised Workflow channel (§2);

2. Uses only the nine Workflow frame types defined in §3 — the application-band frames
   `0x0100`–`0x0108` — preserves the core meaning of the reserved all-channel frame
   types `0x0000`–`0x000A`, and, because the core specification reserves no
   companion-extension range for this channel, defines no Workflow frame in the
   `0x0030`–`0x00FF` band and claims no cross-channel reserved code point (§2, §3);

3. Encodes every operation body as a deterministic-CBOR map (§4.1) with the integer
   keys of §4.2 and §5–§8; rejects a non-deterministically-encoded body, a body
   missing a REQUIRED field, a body with a wrong-major-type key, a `frame_kind` that
   contradicts the frame header, or a body carrying an unknown negative key with
   WORKFLOW_ERROR `malformed_request`; and ignores an unknown non-negative key without
   altering its handling of recognized keys (§4.2, §4.3);

4. Carries a non-empty `corr` on every `*_REQ`, echoes it verbatim on every `*_RESULT`
   and WORKFLOW_ERROR, matches replies to requests by `corr` rather than by frame
   sequence number, and omits `corr` from the unsolicited WORKFLOW_STEP_EVENT and
   WORKFLOW_COMPLETE (§5.1, §4.2);

5. Assigns a durable `task_id` in WORKFLOW_SUBMIT_RESULT, references it in status,
   cancel, step, and completion frames, correlates asynchronous events to their task by
   `task_id`, sends the assigning WORKFLOW_SUBMIT_RESULT before any step or completion
   event for the task, and discards an event for an unknown `task_id` (§5.2);

6. Carries an `effect` on every WORKFLOW_SUBMIT_REQ and treats a missing or unknown
   `effect` as `destructive` (§5.3 fail-safe);

7. Reports every request failure as WORKFLOW_ERROR (`0x0108`) with a code from §8 and a
   peer-safe `message`, never leaking internal cause (§8.2); reports a governance
   escalation as `approval_required` carrying `approval_id`, distinct from
   `policy_denied`; and never reports a held-for-approval or refused submit as a
   WORKFLOW_SUBMIT_RESULT (§6.1, §8.1);

8. Drives each task through the lifecycle states of §5.4 and the state machine of §7,
   emits exactly one terminal WORKFLOW_COMPLETE per accepted task, reports a
   cancellation as the task's *true* resulting state (never `canceled` for a task that
   actually succeeded or failed), and distinguishes a failed accepted task (a
   WORKFLOW_COMPLETE with `state` failed) from a rejected request (a WORKFLOW_ERROR)
   (§6.3, §6.5, §7); and

9. Scopes all `task_id` assignments, task state, and event sequences to the
   association, carrying none across associations (§7).

**Conformance status.** Machine-gradable conformance vectors exist for the Workflow
channel's payload-decode surface: the `workflow.body.decode` operation group in the
conformance corpus, produced by an independent RFC 8949 byte constructor
(`test-vectors/gen/workflow_oracle.py`) whose expected bytes are constructed
independently of the reference implementation (non-circular), graded by `npamp-conform`
against the Go reference implementation of the frame bodies, and cross-validated by
`impl/go/zz_workflow_oracle_xval_test.go`. That vector group grades the §4.1 / §4.2 /
§4.3 payload-encoding and common-envelope MUST-reject clauses — the deterministic-CBOR
container, the `frame_kind` / `corr` envelope, and the forward-compatibility
unknown-key rules — so a conformance claim for those clauses is graded on the payload
surface and MAY name the corpus SHA-256 it was graded against. Beyond that payload
surface, the §5–§9 behavioural clauses (the correlation and task model, the task
lifecycle and step/completion flow, the state machine of §7, the
`approval_required` / `policy_denied` governance distinction, and the
no-internal-detail-on-the-wire leak-prevention requirement) are graded only by a
live-exchange harness once one exists; a conformance claim MUST NOT present those
behavioural clauses as graded on the strength of the payload-vector group. Both the
graded payload surface and the tracked live-exchange gap are recorded in the parity
ledger (`../../.shippable/spec-parity.json`, the NPAMP-WORKFLOW entry).

The live-exchange harness SHOULD assert each behavioural clause above with
a recorded exchange on the Workflow channel `0x0011`: a WORKFLOW_SUBMIT_REQ /
WORKFLOW_SUBMIT_RESULT pair that assigns a `task_id`; a sequence of WORKFLOW_STEP_EVENT
frames with monotonically increasing `seq` followed by exactly one WORKFLOW_COMPLETE;
a WORKFLOW_STATUS_REQ / WORKFLOW_STATUS_RESULT pair; a WORKFLOW_CANCEL_REQ whose
WORKFLOW_CANCEL_RESULT reports `canceled` and, distinctly, one whose task had already
terminated and reports the true terminal state; a WORKFLOW_ERROR provoked for
`policy_denied` and, distinctly, one for `approval_required` carrying an `approval_id`;
a WORKFLOW_ERROR `unknown_task` for a status or cancel of an unknown `task_id`; and a
rejected malformed body (a non-deterministic encoding, a missing REQUIRED field, and an
unknown negative key), each yielding `malformed_request`.
