# NPAMP-MAP-AITP — Agent Interaction & Transaction Protocol (AITP) Mapping (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document defines the carriage of the **Agent Interaction & Transaction
> Protocol (AITP)** — the NEAR AI chat-thread agent protocol published at
> `aitp.dev` — over an N-PAMP association. It is an **OPAQUE-READY thin mapping**:
> AITP is carriable **today** via the opaque carriage class **NPAMP-CC-OPAQUE**
> (`25_carriage_opaque.md`), and this document pins only what AITP's own current
> published specification (v0.1.0, Draft) confirms, marking precisely what is
> confirmed and what a native mapping would pin once AITP's transport stabilizes. It
> builds on NPAMP-BRIDGE (`10_bridge_framework.md`), NPAMP-CC-OPAQUE, and the N-PAMP
> core specification (draft-bubblefish-npamp-01, the "core specification"). It
> consumes only code points those documents already reserve and introduces no change
> to the core wire format, to NPAMP-BRIDGE, or to any carriage class.

## 1. Scope

### 1.1 In scope

This document specifies how AITP messages are carried over an N-PAMP association
today, and what a native mapping will pin once AITP's transport and message schemas
are confirmed. It defines, and only defines, the AITP-specific facts a peer needs:

- The **provisional** `protocol_id` for AITP and its carriage class **today**,
  Class OPAQUE (§2);
- A precise statement of what AITP's own specification **confirms** and what it
  leaves **unconfirmed**, so that no method, field, or code point is fabricated
  (§3);
- How AITP messages ride Class OPAQUE now, and the AITP structure a native mapping
  will pin once confirmed (§4, §5);
- Which AITP capabilities and thread operations are state-mutating, and therefore
  the SafetyLabel effect class a sender attaches, with the NPAMP-BRIDGE §7 fail-safe
  on absence (§6); and
- Channel selection: the Bridge channel `0x000D` as the default, and the more
  specific core channels a native mapping MAY use for AITP's payment, decision/UI,
  and capability-discovery traffic (§7).

### 1.2 Not in scope

The following are explicitly NOT defined by this document, because NPAMP-CC-OPAQUE,
NPAMP-BRIDGE, or AITP's own specification already fix them (or because AITP has not
yet fixed them):

- The structural carriage of an opaque payload — octet-exact delivery, the
  BridgeEnvelope, correlation, the structured-error model, notifications, and
  streaming. These are inherited verbatim from NPAMP-CC-OPAQUE and NPAMP-BRIDGE and
  are not restated here (§4).
- The internal grammar of an AITP Thread, Message, Actor, or any capability payload
  (AITP-01 Payments, AITP-02 Decisions, AITP-03 Data Request, AITP-04/05 wallets).
  These are fixed by AITP's own specification and are carried transparently; this
  document neither parses, validates, nor re-encodes them.
- **A native JSON-RPC 2.0 mapping.** AITP is **not** a JSON-RPC 2.0 protocol (§3);
  NPAMP-CC-JSONRPC (`20_carriage_jsonrpc.md`) therefore does **not** apply to AITP,
  and this document does not build on it. The tentative "JSONRPC" family recorded
  for AITP in the companion index (`00_companion_index.md`) is superseded by AITP's
  own specification, which this document verified (§3, §8).
- AITP's HTTP/REST transport bindings (the AITP-T01 Threads API request line, URL
  paths, and HTTP headers). Over N-PAMP the transport is N-PAMP; those bindings do
  not apply and are not carried as part of the foreign message (§4, §5).
- Any change to the N-PAMP frame format, to the NPAMP-BRIDGE frame types, or to the
  BridgeEnvelope or SafetyLabel TLVs.

## 2. Protocol identity

| Property | Value |
|---|---|
| Protocol | Agent Interaction & Transaction Protocol (AITP), NEAR AI, v0.1.0 (Draft). |
| `protocol_id` | **PROVISIONAL.** AITP has **no assigned code point**: NPAMP-REG §6 assigns only `0x01`–`0x04`, none of which is AITP. Until a standards-assigned value in `0x05`–`0x0F` is obtained under NPAMP-REG §8, AITP MUST be carried under an **experimental** `protocol_id` in the range `0x10`–`0x7F` (NPAMP-REG §7.1), agreed out of band; this document uses **`0x38`** as an illustrative experimental value that carries **no** cross-domain meaning. |
| Carriage class (today) | **OPAQUE** (NPAMP-CC-OPAQUE). AITP is carried as an opaque, declared-content-type payload with no protocol-specific structural mapping (§4). |
| Carriage class (native, once confirmed) | **HTTP** (NPAMP-CC-HTTP), because AITP's confirmed transport AITP-T01 is a REST/JSON HTTP API (§3, §5, §8). **Not** JSONRPC. |
| `content_type` | `0x01` (application/json). AITP's transport is "a JSON API over HTTPS" and its capability payloads are JSON (§3); this is a BridgeEnvelope-enumerated value, so no OpaqueContentType TLV is required (NPAMP-CC-OPAQUE §4.2 case 1). |
| Foreign-message form | A single AITP JSON object — a Thread Message, or a JSON-serialized AITP capability payload carried within a message's `content[]` — carried octet-for-octet as the foreign message (NPAMP-BRIDGE §1; NPAMP-CC-OPAQUE §1.3). |

A sender MUST set `protocol_id` to the value the peers have agreed identifies AITP
on the association (NPAMP-CC-OPAQUE §3), and MUST NOT emit AITP under an experimental
`protocol_id` toward a peer with which it has no out-of-band agreement on that value
(NPAMP-REG §7.1). A receiver that does not carry the indicated `protocol_id` MUST
reply to a BRIDGE_REQUEST with `ProtocolUnsupported` (NPAMP-BRIDGE §6; NPAMP-REG §9)
and MUST NOT infer AITP from any other envelope field.

> **Name-collision note.** "AITP" in this document is exclusively NEAR AI's **Agent
> Interaction & Transaction Protocol** (`aitp.dev`, `github.com/nearai/aitp`). It is
> **not** the unrelated IETF Internet-Draft *Agent Invocation Transport Protocol*
> (`draft-song-anp-aitp-00`), which shares the acronym but is a different protocol
> from a different author. This mapping makes no claim about that draft.

## 3. What is confirmed and what is unconfirmed

This section is the honesty core of an OPAQUE-READY mapping. It records only what
AITP's own current published specification (§9) states, and marks the rest
unconfirmed rather than filling it by assumption.

**Confirmed by AITP v0.1.0:**

- AITP defines two foundational pieces — **Chat Threads** (a communication protocol
  "inspired by and largely compatible with the OpenAI Assistant/Threads API") and
  **Capabilities** (extensible, structured, typed message modules) — carried by a
  **Transport**.
- A **Thread** contains ordered **Messages**. A confirmed Message carries the fields
  `role` (`"user"` for the thread initiator, or `"assistant"`), `content` (an array
  that MAY include JSON-serialized AITP capability payloads), `attachments`,
  `metadata` (with an `actor`), `created_at`, and `thread_id`.
- Capabilities are declared per **Actor** as an array of **JSON-schema URLs**;
  capability payloads travel as JSON serialized into `Thread.messages[].content[]`
  between actors that both support the capability. AITP's **message-passthrough**
  pattern lets an agent forward a capability payload it does not itself handle.
- The single **confirmed transport** is **AITP-T01: Threads API**, "an AITP transport
  using a JSON API over HTTPS" — a REST/JSON HTTP API, **not** JSON-RPC 2.0. Its
  confirmed operations are thread creation, thread retrieval, message creation, and
  message listing (§5).
- The confirmed capability modules are **AITP-01 Payments**, **AITP-02 Decisions**,
  **AITP-03 Data Request**, **AITP-04 NEAR Wallet**, and **AITP-05 EVM Wallet**
  (with AITP-06..09 listed as planned).

**Unconfirmed (a native mapping MUST confirm these against the then-current spec):**

- **Alternative transports.** AITP's overview mentions that threads MAY be carried
  over channels such as long-polling, WebSocket, or mailbox-style relays, but v0.1.0
  specifies **only** AITP-T01. Any streaming transport is unconfirmed; if one is
  later specified, its carriage would build on NPAMP-CC-STREAM
  (`23_carriage_streaming.md`), not on this document as written.
- **The exact wire schemas** of each capability payload (the precise message-type
  names and fields of AITP-01..05). These are versioned and in flux at v0.1.0.
- **The stable method/operation namespace and versioning to v1.0.** AITP is "a spec
  in progress"; method and schema details may change before v1.0.

Because AITP is not JSON-RPC 2.0, this document does **not** enumerate a JSON-RPC
method namespace and does **not** fabricate one. It carries AITP opaquely (§4) and
pins the AITP-T01 HTTP operations only as the surface a native NPAMP-CC-HTTP mapping
will bind (§5).

## 4. Carriage today via Class OPAQUE

Until AITP's transport is confirmed for a native mapping (§8), an AITP message is
carried under NPAMP-CC-OPAQUE with the AITP JSON object as the opaque foreign
payload. The structural carriage is inherited unchanged:

- **Transparency.** The AITP JSON object is carried octet-for-octet and MUST NOT be
  re-serialized, reordered, canonicalized, or rewritten (NPAMP-BRIDGE §1;
  NPAMP-CC-OPAQUE §1.3).
- **Content type.** The BridgeEnvelope `content_type` MUST be `0x01`
  (application/json); no OpaqueContentType TLV is used (NPAMP-CC-OPAQUE §4.2 case 1).
- **Frame selection.** The sender — the only party that knows whether a given AITP
  message expects a reply — chooses the frame type and sets `message_kind` to agree
  with it (NPAMP-CC-OPAQUE §2):

| AITP interaction | NPAMP-BRIDGE frame | `message_kind` |
|---|---|---|
| A thread/message send that expects an agent reply | BRIDGE_REQUEST (`0x0100`) | `0x01` |
| An agent's successful reply message | BRIDGE_RESPONSE (`0x0101`) | `0x02` |
| A failure reported by AITP (an AITP error object) | BRIDGE_ERROR (`0x0102`) | `0x04` |
| A one-way or passthrough capability message (no reply) | BRIDGE_NOTIFY (`0x0103`) | `0x03` |

- **Correlation.** A BRIDGE_REQUEST carries a non-empty `correlation_id`, unique
  among the originating peer's outstanding requests in that direction; replies echo
  it verbatim and are matched by it, not by sequence number (NPAMP-BRIDGE §5). A
  BRIDGE_NOTIFY sets `corr_len = 0` (NPAMP-BRIDGE §8).
- **Errors.** A failure reported **by** AITP is carried as BRIDGE_ERROR with AITP's
  own error object verbatim; a failure **below** AITP (the message did not reach the
  AITP endpoint) is carried as BRIDGE_ERROR with an N-PAMP transport error
  (NPAMP-BRIDGE §6; NPAMP-CC-OPAQUE §8). A sender MUST NOT report success for a
  message it could not deliver.
- **Bidirectionality.** Either peer MAY originate a BRIDGE_REQUEST (NPAMP-BRIDGE §5;
  NPAMP-CC-OPAQUE §2); AITP's initiator (`role = "user"`) and its participants
  (`role = "assistant"`) are AITP-layer roles and impose no N-PAMP directional
  restriction.

Opaque carriage delivers AITP payload bytes only; it does **not** reconstruct AITP's
HTTP transport surface, does **not** perform AITP's out-of-band exchanges, and does
**not** validate any capability payload against its JSON schema (NPAMP-CC-OPAQUE
§1.3, §9). A receiving AITP endpoint MUST validate each delivered payload itself.

## 5. AITP structure a native mapping will pin

Once AITP's transport is confirmed for a native mapping (§8), the mapping binds
AITP-T01's confirmed HTTP operations under NPAMP-CC-HTTP. The table records the
confirmed operations only (§3); it fabricates no field and no operation AITP has not
published. Paths are AITP-T01's; over N-PAMP the HTTP request line and headers are
subsumed by the N-PAMP transport and are not carried as foreign message (§1.2).

| AITP-T01 operation | HTTP method + path (native transport) | Reply |
|---|---|---|
| Create a thread | `POST .../v1/thread` | Thread object |
| Retrieve a thread | `POST .../v1/threads/{thread_id}` | Thread object |
| Create a message | `POST .../v1/threads/{thread_id}/messages` | Message object |
| List messages | `GET .../v1/threads/{thread_id}/messages` | Message list |

A native NPAMP-CC-HTTP mapping would carry each operation's method, path, and JSON
body per that carriage class; the AITP capability payloads within `content[]` remain
carried verbatim regardless. Capability **discovery** — the per-Actor array of
JSON-schema URLs — is a self-contained schema document and MAY instead be carried as
an NPAMP-CC-DOC (`24_carriage_documents.md`) capability document on the Discovery
channel (§7).

## 6. SafetyLabel and state-mutating operations

The SafetyLabel TLV (Type `0x0013`) and its fail-safe semantics are governed by
NPAMP-BRIDGE §7 and inherited through NPAMP-CC-OPAQUE §1.2 unchanged. Neither the
opaque carriage class nor AITP's JSON envelope declares, on the wire, whether a given
AITP message mutates state; the **sender**, which holds the payload, MUST classify
it. This section fixes the effect class by AITP operation and capability, at the
granularity AITP's spec confirms.

When a carried AITP message can cause side effects, the sender MUST attach a
SafetyLabel TLV describing the effect class, an intermediary MUST carry it unchanged,
and — the fail-safe — a receiver MUST NOT treat the **absence** of a SafetyLabel on a
state-mutating message as `read_only`; absence on such a message MUST be treated as
`destructive` (NPAMP-BRIDGE §7).

| AITP operation / capability | Effect (NPAMP-BRIDGE §7) | Rationale |
|---|---|---|
| List messages; retrieve a thread (AITP-T01) | `0x00` read_only | Reads thread state; no mutation. A SafetyLabel MAY be omitted. |
| AITP-03 Data Request (the request itself) | `0x00` read_only | Requests structured data; mutates no state. (Effect class is about state mutation, not the sensitivity of any disclosed data, which the AITP endpoint MUST govern separately.) |
| Create a thread; create a message (AITP-T01) | `0x02` non_idempotent_write | Creates server-side thread/message state and triggers agent work; re-sending is not idempotent. The sender MUST attach a SafetyLabel; on absence the receiver fail-safes to `destructive`. |
| AITP-02 Decisions (request a decision/action) | `0x02` non_idempotent_write | Asks an agent or user to take an action or make a choice; each request is a fresh action. |
| AITP-01 Payments — a payment request/quote | `0x02` non_idempotent_write | Creates a payable obligation that flows upstream; sender MUST label it. |
| AITP-01 Payments — a payment authorization/settlement | `0x03` destructive | Authorizes an irreversible value transfer. |
| AITP-04 NEAR Wallet; AITP-05 EVM Wallet — transaction/message signing | `0x03` destructive | Authorizes signing/broadcast of a blockchain transaction: irreversible on-chain effect and value transfer. |
| Any AITP capability message whose effect the sender cannot determine | `0x03` destructive | Fail-safe (NPAMP-BRIDGE §7): an unclassified state-affecting message MUST be labelled, and its absence MUST be read as `destructive`. |

The `scope` field of the SafetyLabel (NPAMP-BRIDGE §7) MAY carry an advisory hint —
for example the capability identifier (`AITP-01`) or the target `thread_id`. The
SafetyLabel conveys the sender's declared intent and is **not** authorization: a
receiver MUST enforce its own authorization at the point of action (payment
execution, wallet signing) and MUST NOT treat a favorable SafetyLabel as permission
(NPAMP-BRIDGE §7). This is especially load-bearing for AITP-01/04/05, whose effects
move value.

## 7. Channel selection

AITP messages carried opaquely ride the **Bridge channel `0x000D`** by default, as
required for NPAMP-BRIDGE encapsulation (NPAMP-BRIDGE §1; NPAMP-CC-OPAQUE §2). Under
this mapping today, a peer carrying AITP MUST carry its messages on the Bridge
channel, and MUST NOT split one AITP thread across channels.

A native mapping (§5, §8) MAY additionally carry specific AITP traffic classes on the
more specific core channels, each minimum-profile **Standard** (core channel
registry; `../../registries/channels.csv`):

| AITP traffic class | Candidate channel | Core-spec purpose |
|---|---|---|
| AITP-01 payment requests / mandates | Commerce `0x000E` | "Multi-party agentic commerce and payment mandates" |
| AITP-02 decisions and generative-UI events | Interaction `0x000F` | "Agent-to-human user-interface events" |
| Per-Actor capability schema documents | Discovery `0x0010` (NPAMP-CC-DOC) | "Agent, tool, and service discovery and capability advertisement" |

A peer MUST advertise a channel during the handshake before sending or accepting
AITP frames on it; frames on an unadvertised channel MUST be dropped (core
specification §5). A peer MAY advertise AITP as a carried protocol over NPAMP-DISC
(`40_discovery.md`) on the Discovery channel, naming the agreed `protocol_id` and its
carriage class; it MUST NOT advertise AITP if it cannot in fact carry that
`protocol_id` (NPAMP-DISC §5.1). Advertising AITP does not carry AITP traffic.

## 8. Migration from OPAQUE to a native mapping

This document is OPAQUE-READY: AITP works today through Class OPAQUE (§4). A native
mapping supersedes §4 for structured interop once, and only once, all of the
following are confirmed against AITP's then-current published specification:

1. **Transport confirmed and stable.** AITP-T01 (or its successor) is fixed for the
   targeted AITP version; the native carriage class is **HTTP** (NPAMP-CC-HTTP) for
   the Threads API, plus **STREAM** (NPAMP-CC-STREAM) only if AITP later specifies a
   streaming transport. It is **not** JSONRPC.
2. **A `protocol_id` is assigned.** A standards-assigned value in `0x05`–`0x0F` is
   obtained under NPAMP-REG §8 (Specification Required), replacing the provisional
   experimental value of §2; production traffic MUST NOT continue on an experimental
   identifier (NPAMP-REG §7.1).
3. **Capability schemas are pinned.** The wire schemas of AITP-01..05 (and any
   additional modules) are confirmed, so §6's effect classes can be pinned per
   concrete message type rather than per capability.

Until then, a peer MUST carry AITP under Class OPAQUE per §4, MUST honor the
SafetyLabel classification of §6, and MUST NOT represent AITP as natively mapped.

## 9. References

Primary source (AITP specification, NEAR AI; v0.1.0, Draft — consulted for §3, §5,
§6):

- AITP overview (core concepts: Threads, Transports, Capabilities; v0.1.0 Draft
  status) — <https://aitp.dev/>
- AITP Threads (the Thread and Message model; `role`, `content[]`, `attachments`,
  `metadata`/`actor`; OpenAI Assistant/Threads compatibility) —
  <https://aitp.dev/threads>
- AITP-T01: Threads API (the confirmed transport — "a JSON API over HTTPS"; the
  `/v1/thread` and `/v1/threads/{thread_id}/messages` operations; capabilities as
  Actor schema-URL arrays) — <https://aitp.dev/transports/aitp-t01-threads-api>
- AITP Capabilities (AITP-01 Payments, AITP-02 Decisions, AITP-03 Data Request,
  AITP-04 NEAR Wallet, AITP-05 EVM Wallet; capability payloads as JSON in
  `content[]`) — <https://aitp.dev/capabilities>
- AITP-01 Payments (payment request/quote flow) —
  <https://aitp.dev/capabilities/aitp-01-payments>
- AITP source repository (source of truth; v0.1.0 Draft) —
  <https://github.com/nearai/aitp>

Disambiguation (a different protocol sharing the acronym; §2 name-collision note):

- *Agent Invocation Transport Protocol* (`draft-song-anp-aitp-00`), unrelated to NEAR
  AI's AITP — <https://datatracker.ietf.org/doc/draft-song-anp-aitp/>

N-PAMP documents built on:

- draft-bubblefish-npamp-01 — the N-PAMP core specification (Bridge channel `0x000D`,
  Commerce `0x000E`, Interaction `0x000F`, Discovery `0x0010`; the frame format; the
  BridgeEnvelope and SafetyLabel TLV reservations; AEAD payload protection).
- NPAMP-BRIDGE (`10_bridge_framework.md`) — the encapsulation, correlation, error,
  and SafetyLabel contract.
- NPAMP-CC-OPAQUE (`25_carriage_opaque.md`) — the opaque carriage class that carries
  AITP today.
- NPAMP-CC-HTTP (`21_carriage_http.md`) — the HTTP-semantics carriage class a native
  AITP mapping would build on (§5, §8).
- NPAMP-REG (`30_protocol_registry.md`) — the Bridge Protocol Identifier registry;
  AITP is unassigned (§2).
- NPAMP-DISC (`40_discovery.md`) and NPAMP-CC-DOC (`24_carriage_documents.md`) — the
  Discovery-channel advertisement and capability-document carriage of §7.
- BCP 14: RFC 2119 and RFC 8174 — requirement key words.

**Limitations of this mapping.** AITP is at v0.1.0 (Draft) and "a spec in progress."
This document confirms AITP's thread/message model and its single published transport
(AITP-T01, REST/JSON over HTTPS) but does **not** confirm any streaming transport, the
exact wire schemas of AITP-01..05, or a stable v1.0 namespace (§3). It fixes no
JSON-RPC method set, because AITP is not JSON-RPC 2.0. All version-dependent detail
MUST be re-verified against the then-current AITP specification before this mapping is
promoted from OPAQUE-READY to a native DRAFT mapping (§8).

## 10. Conformance

An implementation conforms to NPAMP-MAP-AITP if and only if it conforms to
NPAMP-CC-OPAQUE (and therefore to NPAMP-BRIDGE) and, for AITP traffic, it:

1. Carries every AITP JSON object under the agreed AITP `protocol_id` with
   `content_type = 0x01`, octet-for-octet, treating the payload as opaque and
   validating nothing on the carrier's behalf, and selects AITP solely from
   `protocol_id`, never from another envelope field (§2, §4; NPAMP-REG §9);
2. Uses an experimental `protocol_id` (`0x10`–`0x7F`) only under out-of-band
   agreement, never as a production default, and does not treat the provisional
   value as a standards assignment; it obtains a `0x05`–`0x0F` assignment under
   NPAMP-REG §8 before promoting AITP to a native mapping (§2, §8);
3. Maps AITP messages onto NPAMP-BRIDGE frames per §4 — a reply-expecting message to
   BRIDGE_REQUEST (`message_kind = 0x01`) with a non-empty `correlation_id`, a
   successful reply to BRIDGE_RESPONSE (`0x02`), an AITP error object to BRIDGE_ERROR
   (`0x04`) preserved verbatim, and a one-way/passthrough message to BRIDGE_NOTIFY
   (`0x03`, `corr_len = 0`) — and correlates replies by `correlation_id`, not by
   sequence number (§4; NPAMP-BRIDGE §5, §8);
4. Reports a below-AITP delivery failure as BRIDGE_ERROR carrying an N-PAMP transport
   error, never fabricates an AITP error for a transport failure, and never reports
   success for an undelivered message (§4; NPAMP-BRIDGE §6);
5. Attaches a SafetyLabel to every state-mutating AITP message it originates using
   the effect classes of §6 — labelling AITP-01 settlement and AITP-04/05 wallet
   signing `destructive`, AITP-01 quotes and AITP-02 decisions and thread/message
   creation `non_idempotent_write` — and treats a missing SafetyLabel on any message
   not classified `read_only` in §6 as `destructive` (§6; NPAMP-BRIDGE §7);
6. Never treats a favorable SafetyLabel as authorization, enforcing its own
   authorization at the point of payment execution or wallet signing (§6);
7. Carries a single AITP thread's traffic on the Bridge channel `0x000D`, does not
   split a thread across channels, and uses Commerce `0x000E`, Interaction `0x000F`,
   or Discovery `0x0010` only where §7 permits and only on channels advertised during
   the handshake (§7); and
8. Makes no representation that AITP is natively mapped or that AITP is a JSON-RPC 2.0
   protocol while this document remains OPAQUE-READY, and re-verifies every
   version-dependent fact against the then-current AITP specification before adopting
   a native mapping (§3, §8, §9).

A conformance test suite SHOULD assert each clause above with recorded exchanges that
include: a create-message BRIDGE_REQUEST carrying a `non_idempotent_write`
SafetyLabel and a second with the SafetyLabel omitted, verified to be treated as
`destructive`; an AITP-01 payment-authorization and an AITP-04/05 wallet-signing
message each carried with a `destructive` SafetyLabel; a list-messages read carried
`read_only`; a one-way passthrough capability message carried as BRIDGE_NOTIFY with
no reply; an AITP error object carried verbatim as BRIDGE_ERROR; and a
below-AITP delivery failure reported as an N-PAMP transport error rather than a
fabricated AITP error.
