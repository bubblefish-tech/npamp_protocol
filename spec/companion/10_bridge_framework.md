# NPAMP-BRIDGE — Bridge Framework (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words MUST, MUST NOT, REQUIRED,
> SHALL, SHOULD, MAY, and OPTIONAL are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174). This document defines the protocol-agnostic encapsulation of
> external agentic protocols on the N-PAMP **Bridge channel `0x000D`**. Protocol
> mappings (NPAMP-MCP, NPAMP-A2A, and others) build on it. It consumes only code
> points the core specification reserves and introduces no change to the core wire
> format.

## 1. Scope and encapsulation model

The Bridge channel carries a foreign agentic protocol (for example MCP or A2A) so
that two agents speak that protocol end-to-end while gaining N-PAMP's post-quantum
transport, multiplexing, and key schedule. The governing rule:

> **Transparency.** A bridge MUST carry the foreign protocol's message **octet-for-
> octet**. It MUST NOT re-serialize, summarize, or substitute its own envelope for
> the foreign message. Routing, correlation, and safety metadata are carried *around*
> the foreign message; the foreign message itself is never modified.

The remainder of this document defines that surrounding metadata and the frames that
carry it.

## 2. Bridge-channel frame types

Within the Bridge channel (`0x000D`) frame-type namespace (channel-specific types
begin at `0x0100`; core spec §4.6), this specification defines:

| Type | Name | Reply | Meaning |
|---|---|---|---|
| 0x0100 | BRIDGE_REQUEST | RESPONSE or ERROR | A foreign request that expects a reply. |
| 0x0101 | BRIDGE_RESPONSE | None | A successful reply; correlation echoes the request. |
| 0x0102 | BRIDGE_ERROR | None | A failed reply; carries the foreign error object. |
| 0x0103 | BRIDGE_NOTIFY | None | A one-way message; no reply is expected or permitted. |
| 0x0104 | BRIDGE_STREAM_DATA | None | One chunk of a streamed reply; correlation echoes the request. |
| 0x0105 | BRIDGE_STREAM_END | None | Terminates a stream; `final` is set. |

The reserved all-channel frame types (PING `0x0001`, CLOSE `0x0003`, ERROR `0x0005`,
KEY_UPDATE `0x0006`, and so on; core spec §4.6) retain their core meaning on the
Bridge channel; an implementation MUST NOT reuse them for application traffic.

## 3. Frame payload layout

A Bridge frame's payload (the octets after the 36-octet N-PAMP header and before the
AEAD tag) is:

```
  BridgeEnvelope TLV   (Type 0x0010, REQUIRED)
  SafetyLabel TLV      (Type 0x0013, OPTIONAL; REQUIRED for any state-mutating request)
  <foreign message>    (carried verbatim per §1)
```

TLVs use the core specification's extension-TLV encoding (Type `u16`, Length `u16`,
Value). The foreign message is the octets following the final TLV.

## 4. BridgeEnvelope TLV (Type 0x0010)

Value layout (multi-octet integers big-endian):

| Field | Size | Meaning |
|---|---|---|
| `protocol_id` | u8 | Foreign protocol. 0x01 = MCP, 0x02 = A2A, 0x03 = HTTP/2, 0x04 = WebSocket; 0x10–0x7F experimental; 0x80–0xFF reserved. |
| `message_kind` | u8 | 0x01 request, 0x02 response, 0x03 notification, 0x04 error, 0x05 stream_data, 0x06 stream_end. MUST agree with the frame type. |
| `content_type` | u8 | Foreign-message encoding. 0x01 application/json, 0x02 application/cbor, 0x03 application/grpc+proto. |
| `flags` | u8 | Bit 0 `final` (streams). Bits 1–7 reserved; senders MUST set 0 and receivers MUST ignore. |
| `corr_len` | u8 | Length of `correlation_id` (0–255). |
| `correlation_id` | Var | Opaque correlation token (§5). |
| `method_len` | u8 | Length of `method` (0 when not applicable). |
| `method` | Var | UTF-8 operation name (for example `tools/call`, `message/send`). |

A receiver MUST reject (BRIDGE_ERROR, code `EnvelopeMalformed`) any frame whose
envelope is absent or truncated, or whose `message_kind` contradicts the frame type.

## 5. Correlation

The Bridge channel is bidirectional: under the core specification's channel
architecture, both peers maintain independent send and receive sequence spaces, so
either peer MAY originate a BRIDGE_REQUEST. For a given exchange, the peer that emits
the BRIDGE_REQUEST is the *requester* and the peer that replies is the *responder*;
these roles are assigned per exchange, not per association. This permits foreign
protocols in which a server issues a request to a client (for example a model-sampling
or user-elicitation request) and peer-to-peer protocols in which either side initiates.

- A BRIDGE_REQUEST MUST carry a non-empty `correlation_id`, unique among the
  originating peer's outstanding requests on the channel in that direction.
- BRIDGE_RESPONSE, BRIDGE_ERROR, BRIDGE_STREAM_DATA, and BRIDGE_STREAM_END MUST echo
  the originating request's `correlation_id` verbatim.
- A receiver MUST match replies to requests by `correlation_id`, not by frame
  sequence number. The N-PAMP per-channel sequence space orders frames; it does not
  correlate a reply to its request, which is required under concurrent and
  multiplexed exchanges.
- A BRIDGE_NOTIFY MUST set `corr_len = 0`.

## 6. Errors

A failure within the foreign protocol MUST be reported as BRIDGE_ERROR whose foreign
message is the foreign protocol's own error object (for example a JSON-RPC `error`
member with `code`, `message`, and `data`), carried verbatim. An implementation MUST
NOT reduce a foreign error to free text and MUST NOT collapse distinct foreign codes.

A failure *below* the foreign protocol — where the request did not reach the foreign
endpoint — is reported as BRIDGE_ERROR carrying an N-PAMP transport error in place of
a foreign message:

| Code | Name | Meaning |
|---|---|---|
| 1 | EnvelopeMalformed | The BridgeEnvelope TLV is missing or invalid. |
| 2 | ProtocolUnsupported | `protocol_id` is not carried by this peer. |
| 3 | MethodUnsupported | The foreign operation is recognized but not carried. |
| 4 | NotDelivered | The foreign endpoint did not accept the message. A sender MUST NOT report success for a message it could not deliver. |
| 5 | SafetyPolicy | Refused by a local safety policy (§7). |

## 7. SafetyLabel TLV (Type 0x0013)

When a request can cause side effects, the sender MUST attach a SafetyLabel TLV, and
an intermediary MUST carry it unchanged to the foreign endpoint, where the receiver
MAY use it in an authorization decision. Value:

| Field | Size | Meaning |
|---|---|---|
| `effect` | u8 | 0x00 read_only, 0x01 idempotent_write, 0x02 non_idempotent_write, 0x03 destructive. |
| `scope_len` | u8 | Length of `scope`. |
| `scope` | Var | UTF-8 resource/scope hint (advisory). |

A receiver MUST NOT treat the absence of a SafetyLabel on a state-mutating operation
as `read_only`; absence on such an operation MUST be treated as `destructive`
(fail-safe). The label describes intent and does not replace authorization.

## 8. Notifications

A BRIDGE_NOTIFY frame carries a foreign one-way message. The receiver MUST NOT emit a
reply, and the sender MUST NOT await one. `corr_len` MUST be 0.

## 9. Conformance

An implementation conforms to NPAMP-BRIDGE if and only if, on the Bridge channel, it:

1. Carries the foreign message octet-for-octet (§1);
2. Emits and parses the BridgeEnvelope TLV (§4);
3. Enforces correlation (§5): every reply echoes the request's identifier, and
   replies are matched by identifier rather than sequence number;
4. Preserves the foreign error object (§6) and never reports success for an
   undelivered message;
5. Carries the SafetyLabel unchanged and fail-safes on its absence (§7);
6. Carries one-way notifications with no reply (§8).

A conformance test suite SHOULD assert each clause above with a recorded
request/response (and notification, and stream) exchange for each protocol mapping
that builds on this document.
