# NPAMP-MAP-AP2 — Agent Payments Protocol (AP2) Mapping (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is a **thin per-protocol mapping** for the **Agent Payments
> Protocol (AP2)**. AP2 is, by its own specification, an **authorization and
> data-object layer** — a set of cryptographically signed *Mandates* — designed as an
> **extension of a host agent protocol** (A2A, MCP, or UCP); AP2 explicitly places its
> own transport (the "Commerce Protocol": catalog APIs, checkout updates, and the APIs
> by which the roles communicate) **out of scope** (§2). Because AP2 confirms no wire
> protocol of its own, this mapping is **OPAQUE-READY**: AP2's signed Mandate documents
> are carried today under the document carriage class **NPAMP-CC-DOC**
> (`24_carriage_documents.md`), and — when AP2 rides A2A — its Mandate-bearing JSON-RPC
> message traffic is carried under **NPAMP-CC-JSONRPC** (`20_carriage_jsonrpc.md`)
> through the host mapping **NPAMP-MAP-A2A** (`61_map_a2a.md`, `protocol_id 0x02`). Any
> AP2 payload for which no richer carriage is confirmed is carriable immediately under
> **Class OPAQUE** (`25_carriage_opaque.md`). This document builds on **NPAMP-BRIDGE**
> (`10_bridge_framework.md`) and the N-PAMP core specification
> (draft-bubblefish-npamp-01, the "core specification"); it consumes only code points
> those documents already reserve, uses a **PROVISIONAL** experimental `protocol_id`
> for standalone carriage (§3), defines no new frame type or TLV, and introduces no
> change to the core wire format or to NPAMP-BRIDGE.

## 1. Scope

### 1.1 In scope

This document pins, against AP2's own published specification (§10), only the AP2
specifics a peer needs in order to carry AP2 over an N-PAMP association:

- The AP2 **protocol status** — what is confirmed and what is unconfirmed in AP2's
  transport — and the resulting OPAQUE-READY carriage posture (§2);
- The **`protocol_id`** used for standalone AP2 carriage (PROVISIONAL, experimental
  range) and the assigned `protocol_id` under which AP2 travels when it rides a host
  agent protocol (§3);
- How AP2's signed **Mandate documents** ride NPAMP-CC-DOC, and how AP2's Mandate-
  bearing host traffic rides NPAMP-CC-JSONRPC through the host mapping (§4, §5);
- The AP2-specific **object identifiers** a peer keys on — the Mandate `vct`
  (Verifiable Credential Type) values and, for the crypto path, the A2A x402 extension
  metadata keys — treated as opaque, carried verbatim (§5);
- The **SafetyLabel effect class** each AP2 state-mutating operation carries and the
  NPAMP-BRIDGE §7 fail-safe applied to payment authorization (§6); and
- **Channel selection**: the Bridge channel `0x000D` default, the Commerce channel
  `0x000E` for payment-mandate commerce, and the Discovery channel `0x0010` for
  Mandate/capability documents (§7).

The structural work — octet-exact carriage, the BridgeEnvelope, correlation, the
structured-error model, digest-stable document carriage, and the safety-annotation TLV
— is done by NPAMP-BRIDGE and the named carriage classes and is not restated here.

### 1.2 Not in scope

The following are explicitly NOT defined by this document:

- **A native AP2 wire protocol or method namespace.** AP2's specification places the
  "Commerce Protocol" — the APIs and messages by which the roles actually exchange
  Mandates — **out of scope** of AP2 (§2). This document therefore does not, and
  honestly cannot, pin an AP2-native JSON-RPC method namespace; it maps AP2's
  *objects* onto carriage and lets the confirmed host protocol supply the wire
  operations (§4, §5). Any future AP2-native operation set is pinned here only once
  AP2 publishes and confirms it.
- **The internal grammar of any Mandate.** The SD-JWT structure of the Checkout
  Mandate and Payment Mandate, their claim sets, their `vct` schemas, their selective-
  disclosure structure, and their embedded signatures are fixed by AP2's own
  specification and are carried octet-for-octet (NPAMP-BRIDGE §1); this document does
  not parse, validate, canonicalize, or re-encode a Mandate.
- **Verification of a Mandate's signature.** A Mandate is a self-contained signed
  credential (an SD-JWT); its signature verification is the consumer's act, performed
  after octet-exact delivery, against AP2's own rules — not by the carriage layer
  (NPAMP-CC-DOC §6.5). This document delivers the exact octets a verifier needs and
  makes no trust decision.
- **The host protocols' own mappings.** How A2A JSON-RPC, MCP JSON-RPC, or UCP HTTP
  traffic is carried is defined by NPAMP-MAP-A2A (`61_map_a2a.md`), NPAMP-MAP-MCP
  (`60_map_mcp.md`), and the HTTP carriage class respectively; this document references
  them and does not restate them.
- **Out-of-band settlement.** Settlement on a card network, a real-time bank rail, or a
  blockchain — the actual movement of funds a Payment Mandate authorizes — happens
  outside the AP2 message exchange and is not carried by this mapping.
- **Any change to NPAMP-BRIDGE, the carriage classes, or the core wire format**,
  including the BridgeEnvelope TLV, the SafetyLabel TLV, and the DocumentBinding TLV,
  all of which are used exactly as their defining documents specify.

## 2. Protocol status: confirmed and unconfirmed (OPAQUE-READY)

AP2 is a newer, evolving protocol. This section states precisely what is confirmed
from AP2's primary specification (§10) and what is not, so that no field, method, or
code point below is asserted beyond its source.

**Confirmed (from AP2's published specification and the A2A x402 extension, §10):**

- AP2 is positioned as **"an extension of the Agent2Agent (A2A) protocol and Model
  Context Protocol (MCP)"** (and UCP); it is an authorization/evidence layer, not a
  standalone transport.
- AP2 represents an agent purchase as cryptographically signed **Mandates**. In AP2's
  current specification these are the **Checkout Mandate** and the **Payment Mandate**,
  each defined in an **open** and a **closed** variant; each is identified by a `vct`
  (Verifiable Credential Type) claim carrying a numeric schema-version suffix. Confirmed
  `vct` values: `mandate.checkout.open.1` (Open Checkout Mandate), `mandate.checkout.1`
  (Closed Checkout Mandate), `mandate.payment.open.1` (Open Payment Mandate), and
  `mandate.payment.1` (Closed Payment Mandate).
- AP2 **specifies the use of SD-JWTs (Selective Disclosure JWTs)** for securing the
  Payment and Checkout Mandates; Mandates are "tamper-proof, cryptographically-signed"
  verifiable credentials.
- The A2A **x402 extension** (crypto/stablecoin path) rides A2A: it carries payment
  state and payload inside the `metadata` of A2A `Message`/`Task` objects, under the
  keys `x402.payment.status`, `x402.payment.required`, and `x402.payment.payload`, and
  is declared by the extension URI `https://github.com/google-a2a/a2a-x402/v0.1`.

**Unconfirmed / deliberately out of scope in AP2 (marked, not fabricated):**

- AP2's own specification states: **"The exact details of the Commerce Protocol (e.g.,
  catalog APIs, checkout updates, and specific APIs for communication between the
  different roles) are outside the scope of AP2."** AP2 therefore confirms **no native
  method/operation namespace** and **no native message framing** of its own.
- Consequently AP2 has **no `protocol_id` assigned by NPAMP-REG** (`30_protocol_registry.md`
  §6 assigns only `0x01`–`0x04`); an AP2-specific code point is PROVISIONAL (§3).
- **Terminology has evolved.** AP2's original announcement described three Mandates —
  **Intent Mandate**, **Cart Mandate**, and **Payment Mandate**; the current
  specification uses **Checkout Mandate** (open/closed) and **Payment Mandate**. This
  mapping keys on Mandate *semantics* and the confirmed `vct` values above, not on a
  single spelling, so a rename does not change the carriage.

**Resulting posture — OPAQUE-READY.** Because AP2's objects are confirmed but its
transport is not native, AP2 is carried today by three composable, confirmed means,
in order of fidelity: (a) its signed Mandate documents under **NPAMP-CC-DOC** (§4.1);
(b) its Mandate-bearing host traffic under the host protocol's mapping — for A2A,
**NPAMP-CC-JSONRPC via NPAMP-MAP-A2A** under `protocol_id 0x02` (§4.2); and (c) any
payload not covered by (a) or (b) under **Class OPAQUE** (§4.3). A fuller AP2-native
mapping is pinned here only once AP2 confirms a wire protocol of its own.

## 3. Protocol identity

| Property | Value |
|---|---|
| Protocol | Agent Payments Protocol (AP2) — an authorization/Mandate extension layered on a host agent protocol. |
| `protocol_id` (standalone AP2 carriage) | **PROVISIONAL.** AP2 has **no** NPAMP-REG-assigned code point. For carriage of AP2 Mandate documents as a standalone protocol independent of a host, this mapping uses an **experimental** `protocol_id` in the range `0x10`–`0x7F` (NPAMP-REG §7.1); `0x14` is used **provisionally** and by out-of-band agreement only. It is **not** a standards-assigned value and **MUST NOT** be a production default (NPAMP-REG §7.1). A standards-range code point SHOULD be obtained under NPAMP-REG §8 before general interoperation. |
| `protocol_id` (AP2 riding A2A) | `0x02` (A2A), assigned by NPAMP-REG §6. When AP2 Mandates travel inside A2A JSON-RPC messages, the frames carry A2A's `protocol_id 0x02` (NPAMP-MAP-A2A §3); no separate AP2 code point is consumed on that path (§4.2). |
| Carriage class | **DOC** for Mandate documents (NPAMP-CC-DOC); **JSONRPC** for host-carried AP2 traffic via the host mapping (NPAMP-CC-JSONRPC); **OPAQUE** as the universal fallback (NPAMP-CC-OPAQUE). |
| `content_type` | `0x01` (application/json) for AP2 objects carried inside a host JSON-RPC message (NPAMP-CC-JSONRPC §3). For a standalone SD-JWT Mandate document, the precise media type (for example an SD-JWT media type) is named in the DocumentBinding `doc_content_type` (NPAMP-CC-DOC §6.2); the core `content_type` octet registry (NPAMP-BRIDGE §4) does not yet define a dedicated SD-JWT value, which this document notes rather than inventing one. |
| Foreign-message form | A signed AP2 Mandate (an SD-JWT verifiable credential), or a host protocol message that carries one, carried octet-for-octet as the foreign message (NPAMP-BRIDGE §1). |

A sender that carries standalone AP2 under `0x14` MUST have out-of-band agreement with
its peer on that experimental value (NPAMP-REG §7.1); absent such agreement, a receiver
MUST treat it as an uncarried protocol and return `ProtocolUnsupported` (NPAMP-BRIDGE §6;
NPAMP-REG §9). A receiver MUST select the foreign protocol solely from `protocol_id`,
never inferring AP2 from a Mandate `vct` or any other envelope or payload field.

## 4. Carriage model

AP2's objects are carried by the confirmed means below. Each is a full NPAMP-BRIDGE
exchange; this document adds no framing of its own.

### 4.1 Mandate documents under NPAMP-CC-DOC

A Checkout Mandate or Payment Mandate is a self-contained, cryptographically signed
verifiable credential (an SD-JWT). It is a **capability/evidence document** in the sense
of NPAMP-CC-DOC (§1) and is carried as an NPAMP-CC-DOC **document set**:

- The Mandate is delivered **octet-for-octet** (NPAMP-CC-DOC §4), so that the SD-JWT's
  embedded signature and any selective-disclosure digests verify bit-identically at the
  consumer. An implementation MUST NOT canonicalize, re-indent, re-encode, or otherwise
  alter a Mandate.
- The SD-JWT's **own signature is internal to the document** and is carried within the
  Mandate octets; verification of it is the consumer's act (NPAMP-CC-DOC §6.5), done
  against AP2's rules after octet-exact delivery. Where a deployment additionally emits
  a **detached** proof over a Mandate, that proof is carried as an NPAMP-CC-DOC detached
  proof bound to the document by `doc_id` and digest (NPAMP-CC-DOC §6), with `proof_alg`
  naming a core-assigned signature code point (NPAMP-CC-DOC §6.4).
- A Mandate `vct` value (§2) MAY be surfaced in the DocumentBinding `doc_id` or
  `doc_content_type` as an advisory identifier; it MUST NOT be parsed out of, or
  substituted for, the carried Mandate octets.
- Serving a Mandate document is `read_only` (NPAMP-CC-DOC §9); the mutating act is the
  Mandate's *creation/authorization* by the signing role, classified in §6.

### 4.2 Mandate-bearing host traffic under NPAMP-CC-JSONRPC (AP2 over A2A)

In AP2's confirmed dominant deployment it rides **A2A**, whose messages are JSON-RPC
2.0 objects. On that path a Mandate travels **inside** an A2A message (as A2A message
content or `metadata`), and the exchange is carried by **NPAMP-MAP-A2A**
(`61_map_a2a.md`) under `protocol_id 0x02`:

- The A2A JSON-RPC object is the foreign message, carried under NPAMP-CC-JSONRPC with
  `content_type 0x01` (NPAMP-MAP-A2A §3, §4); the AP2 Mandate is a value inside it and
  is carried verbatim with it. This document adds no envelope field for the Mandate.
- The **A2A x402 extension** (crypto path) carries payment state and payload in the
  A2A message `metadata` under `x402.payment.status`, `x402.payment.required`
  (an `x402PaymentRequiredResponse`), and `x402.payment.payload` (a `PaymentPayload`);
  these keys and their objects are carried verbatim as part of the A2A object. This
  mapping does not lift them out of, or duplicate them outside, the carried object.
- Correlation, error carriage (verbatim A2A/JSON-RPC error objects), and streaming for
  this path are exactly those of NPAMP-MAP-A2A and NPAMP-CC-JSONRPC; this document adds
  none.

Where AP2 instead rides MCP or UCP, the corresponding host mapping (NPAMP-MAP-MCP;
the HTTP carriage class) governs by the same principle; only A2A's carriage is
confirmed in detail here.

### 4.3 Class OPAQUE fallback

Any AP2 payload for which neither NPAMP-CC-DOC nor a confirmed host mapping applies —
for example a future AP2-native message whose framing AP2 has not yet published — is
carriable immediately under **Class OPAQUE** (NPAMP-CC-OPAQUE): the payload is carried
under its declared `content_type` with no protocol-specific structure, using the
PROVISIONAL experimental `protocol_id` of §3 under out-of-band agreement. This is the
OPAQUE-READY guarantee: AP2 is carriable now, and a richer mapping is added when AP2's
transport is confirmed.

## 5. AP2-specific identifiers

AP2 defines no method namespace of its own (§2). The AP2-specific values a peer keys on
are **object identifiers**, carried verbatim, never used to select the foreign protocol
(§3):

| AP2 identifier | Confirmed value(s) | Carriage |
|---|---|---|
| Mandate `vct` — Open Checkout Mandate | `mandate.checkout.open.1` | Inside the SD-JWT Mandate (NPAMP-CC-DOC §4) or host object (§4.2). |
| Mandate `vct` — Closed Checkout Mandate | `mandate.checkout.1` | As above. |
| Mandate `vct` — Open Payment Mandate | `mandate.payment.open.1` | As above. |
| Mandate `vct` — Closed Payment Mandate | `mandate.payment.1` | As above. |
| A2A x402 metadata keys | `x402.payment.status`, `x402.payment.required`, `x402.payment.payload` | Inside the A2A message `metadata` (§4.2). |
| A2A x402 extension URI | `https://github.com/google-a2a/a2a-x402/v0.1` | Declared in the A2A AgentCard (carried as an NPAMP-CC-DOC document, NPAMP-MAP-A2A §7). |
| x402 payment states | `payment-required`, `payment-submitted`, `payment-rejected`, `payment-verified`, `payment-completed`, `payment-failed` | Value of `x402.payment.status` inside the A2A object (§4.2). |

An implementation MUST treat every value above as opaque with respect to transport: it
delivers them unchanged and MUST NOT parse, rewrite, or route on them. A later AP2 or
x402 revision MAY add, rename, or version these identifiers; because the carriage is
transparent, such a change is carried without a change to this mapping.

## 6. SafetyLabel effect classes

The SafetyLabel TLV (Type `0x0013`) and its fail-safe are governed by NPAMP-BRIDGE §7
and inherited through the carriage classes unchanged (NPAMP-CC-JSONRPC §9,
NPAMP-CC-DOC §9). AP2 operations are, by their nature, high-consequence: they authorize
purchases and payments. Because AP2 fixes no method strings (§2), this section
classifies by **operation semantics**; a sender MUST label by the actual effect.

| AP2 operation (by semantics) | Effect (NPAMP-BRIDGE §7) | Rationale |
|---|---|---|
| Retrieve / serve a Mandate or agent capability document | `0x00` read_only | Serving a signed document does not mutate state (NPAMP-CC-DOC §9). A SafetyLabel MAY be omitted; absence is correctly read as read_only here. |
| Create / sign an **Open** Checkout Mandate (delegated authorization with constraints) | `0x02` non_idempotent_write | Commits the user to a delegated purchasing authority; each signing is a distinct authorization act. The sender MUST attach a SafetyLabel. |
| Approve / sign a **Closed** Checkout Mandate (user approval of an exact cart and price) | `0x02` non_idempotent_write | Authorizes a specific purchase; not idempotent. The sender MUST attach a SafetyLabel. |
| Sign / submit a **Payment Mandate** (open or closed), or an x402 `payment-submitted` (a signed `PaymentPayload` authorizing a charge) | `0x03` destructive (at minimum `0x02` non_idempotent_write) | Authorizes an **irreversible** movement of funds / settlement. The sender MUST attach a SafetyLabel reflecting the actual effect; a deployment SHOULD label a fund-moving authorization `destructive`. |

Requirements:

- For any AP2 operation whose effect above is not `0x00`, the sender MUST attach a
  SafetyLabel TLV (NPAMP-BRIDGE §7) to the carrying BRIDGE_REQUEST, and an intermediary
  MUST carry it unchanged.
- A receiver MUST NOT treat the **absence** of a SafetyLabel on an AP2 state-mutating
  operation — any Mandate creation/authorization or any payment submission — as
  `read_only`; absence on such an operation MUST be treated as `destructive` (fail-safe;
  NPAMP-BRIDGE §7). Given that AP2's operations move money, this fail-safe is the
  controlling default whenever the operation's effect is not positively known to be
  read-only.
- The `scope` field of the SafetyLabel (NPAMP-BRIDGE §7) MAY carry a Mandate `vct` or a
  transaction reference as an advisory hint. The SafetyLabel describes intent and does
  not replace the paying role's own authorization decision; a receiver MUST enforce its
  own authorization and MUST NOT treat a favorable SafetyLabel as permission to charge.

## 7. Channel selection

| AP2 traffic class | Carriage | Channel |
|---|---|---|
| Mandate documents (Checkout/Payment Mandate SD-JWTs) and agent capability documents | NPAMP-CC-DOC (§4.1) | Bridge `0x000D` default; MAY use Discovery `0x0010` (advertisement) or Commerce `0x000E` (payment mandates) |
| Mandate-bearing host JSON-RPC traffic (AP2 over A2A, incl. x402 metadata) | NPAMP-CC-JSONRPC via NPAMP-MAP-A2A, `protocol_id 0x02` (§4.2) | Bridge `0x000D` |
| Multi-party commerce / payment-mandate exchange | NPAMP-CC-DOC or host JSON-RPC | MAY ride Commerce `0x000E` |
| AP2 payload with no confirmed richer carriage | NPAMP-CC-OPAQUE (§4.3) | Bridge `0x000D` |

The Commerce channel `0x000E` is reserved by the core channel registry for
**"multi-party agentic commerce and payment mandates"** (`../../registries/channels.csv`) —
AP2's exact domain — and a deployment MAY carry AP2 payment-mandate and commerce traffic
on it instead of, or in addition to, the Bridge channel `0x000D`, consistent with the
companion index "Channel selection for carriage" (`00_companion_index.md`). The Bridge
`0x000D`, Commerce `0x000E`, and Discovery `0x0010` channels are all minimum-profile
**Standard** (core channel registry); AP2 carriage requires no channel above Standard.
Within one document set, a Mandate document and its detached proofs MUST NOT be split
across two channels (NPAMP-CC-DOC §3). A peer MUST NOT send or accept AP2 frames on a
channel it did not advertise during the handshake (core specification §5).

## 8. Code points consumed

This mapping consumes only code points the core specification, NPAMP-BRIDGE, and the
carriage classes already define. It defines no new frame type, no new TLV, and no change
to the core wire format.

| Resource | Origin | Use here |
|---|---|---|
| `protocol_id` `0x14` (AP2, **PROVISIONAL**, experimental) | NPAMP-REG §7.1 | Standalone AP2 carriage under out-of-band agreement only; not standards-assigned (§3). |
| `protocol_id` `0x02` (A2A) | NPAMP-REG §6 | The identifier AP2 traffic carries when it rides A2A (§3, §4.2). |
| `content_type` `0x01` (application/json) | NPAMP-BRIDGE §4 | AP2 objects carried inside a host JSON-RPC message (§3, §4.2). |
| Channel `0x000D` (Bridge) | Core specification | Default channel for all AP2 carriage (§7). |
| Channel `0x000E` (Commerce) | Core specification | Optional channel for payment-mandate / commerce traffic (§7). |
| Channel `0x0010` (Discovery) | Core specification | Optional channel for Mandate/capability documents (§7). |
| Bridge frame types `0x0100`–`0x0105` | NPAMP-BRIDGE §2 | Reused unchanged for request/response/error/stream (§4). |
| BridgeEnvelope TLV `0x0010`, SafetyLabel TLV `0x0013` | Core specification; NPAMP-BRIDGE | Carried unchanged (§3, §6). |
| DocumentBinding TLV (NPAMP-CC-DOC §6, Type `0xTBD-DOCBIND` **provisional**) | NPAMP-CC-DOC | Document-binding metadata for Mandate document sets (§4.1). Its provisional status is inherited from NPAMP-CC-DOC and not resolved here. |

This document requests no IANA action and defines no registry.

## 9. Security considerations

This mapping introduces no cryptography and changes none. All confidentiality,
integrity, authentication, downgrade resistance, and replay protection are provided by
the core specification's wire format and key schedule and apply unchanged to every AP2
frame, which travels inside the AEAD-protected Bridge, Commerce, or Discovery payload;
the `protocol_id`, any `method`, the SafetyLabel, and the AP2 Mandate are authenticated
and confidentiality-protected to the same degree.

Carrying AP2 over N-PAMP makes no security claim about AP2 itself. In particular:

- **Mandate authenticity is end-to-end.** A Mandate's authenticity rests on its own
  SD-JWT signature and any detached proof, verified by the consuming role (NPAMP-CC-DOC
  §6.5), not on the transport. Octet-exact carriage (NPAMP-CC-DOC §4) preserves exactly
  the bytes a verifier must check; carriage delivery of a Mandate is not verification
  of it, and a producer MUST NOT represent delivery as verification.
- **Payment authorization fail-safe.** AP2 operations authorize irreversible payments.
  The effect classification of §6 and the NPAMP-BRIDGE §7 fail-safe — absence of a
  SafetyLabel on a state-mutating operation is `destructive` — apply to every AP2
  Mandate-creation and payment-submission operation. A receiver MUST enforce its own
  authorization at the point of charge and MUST NOT rely on a favorable SafetyLabel.
- **Provisional identifier.** The experimental `protocol_id 0x14` (§3) carries no
  cross-domain meaning (NPAMP-REG §7.1, §10). A receiver MUST treat it as uncarried
  absent out-of-band agreement, rather than guessing an AP2 interpretation.
- **Unconfirmed transport.** Because AP2 confirms no native wire protocol (§2), an
  implementation MUST NOT infer AP2 message structure that AP2 has not published; the
  confirmed carriage is that of §4, and anything beyond it is carried opaquely (§4.3)
  until AP2 confirms it.

## 10. References

Primary sources (AP2 and the A2A x402 extension; consulted for §2, §5, §6):

- Agent Payments Protocol (AP2) — Specification —
  <https://ap2-protocol.org/ap2/specification/>
  (Commerce Protocol explicitly out of scope; Mandate `vct` scheme; SD-JWT securing of
  Checkout and Payment Mandates; roles Shopping Agent, Credential Provider, Merchant,
  Merchant Payment Processor, Trusted Surface).
- AP2 — Checkout Mandate — <https://ap2-protocol.org/ap2/checkout_mandate/>
  (`vct` values `mandate.checkout.open.1` and `mandate.checkout.1`; open vs closed
  signing roles; SD-JWT form).
- AP2 — Payment Mandate — <https://ap2-protocol.org/ap2/payment_mandate/>
  (`vct` values `mandate.payment.1` (closed) and `mandate.payment.open.1` (open);
  SD-JWT form).
- AP2 — Overview — <https://ap2-protocol.org/overview/> and
  <https://github.com/google-agentic-commerce/AP2>
  ("designed as an extension for emerging agent-to-agent (A2A), model-context protocols
  (MCP), and Universal Commerce Protocol (UCP)"; Mandates as signed verifiable
  credentials).
- Announcing Agent Payments Protocol (AP2), Google Cloud Blog —
  <https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol>
  ("can be used as an extension of the Agent2Agent (A2A) protocol and Model Context
  Protocol"; Intent/Cart/Payment Mandate lineage; the A2A x402 extension for crypto
  payments with Coinbase, Ethereum Foundation, MetaMask).
- A2A x402 Extension — <https://github.com/google-agentic-commerce/a2a-x402> and
  <https://github.com/google-agentic-commerce/a2a-x402/blob/main/spec/v0.1/spec.md>
  (payment state/payload carried in A2A `Message`/`Task` `metadata` under
  `x402.payment.status`, `x402.payment.required`, `x402.payment.payload`; extension URI
  `https://github.com/google-a2a/a2a-x402/v0.1`; payment states).
- Agent2Agent (A2A) Protocol — <https://a2a-protocol.org> — the confirmed host protocol
  whose carriage AP2 rides (§4.2).

N-PAMP documents built on:

- draft-bubblefish-npamp-01 — the N-PAMP core specification: the channel registry
  (Bridge `0x000D`, Commerce `0x000E`, Discovery `0x0010`), the frame-type namespace
  (channel-specific types from `0x0100`), the extension-TLV encoding, and the AEAD
  payload protection.
- NPAMP-BRIDGE (`10_bridge_framework.md`) — the encapsulation, BridgeEnvelope,
  correlation, structured-error, and SafetyLabel contract.
- NPAMP-CC-JSONRPC (`20_carriage_jsonrpc.md`) — JSON-RPC 2.0 carriage (the host path,
  §4.2).
- NPAMP-CC-DOC (`24_carriage_documents.md`) — capability/schema document carriage (the
  Mandate path, §4.1).
- NPAMP-CC-OPAQUE (`25_carriage_opaque.md`) — universal opaque carriage (the fallback,
  §4.3).
- NPAMP-MAP-A2A (`61_map_a2a.md`) — the confirmed host mapping AP2 rides over A2A (§4.2).
- NPAMP-REG (`30_protocol_registry.md`) — the Bridge Protocol Identifier registry; AP2
  has no assigned code point, and the experimental-range rules of §7.1 govern the
  PROVISIONAL identifier of §3.
- NPAMP-DISC (`40_discovery.md`) — Discovery-channel advertisement referenced in §7.
- BCP 14 (RFC 2119, RFC 8174) — requirement key words.

Where a fact was version-dependent (the Intent/Cart → Checkout Mandate rename, §2) or
not confirmable from AP2's primary source (a native AP2 transport, §2), it is marked as
such above rather than fixed by assumption. No value in this document is asserted beyond
what these sources support.

## 11. Conformance

An implementation conforms to NPAMP-MAP-AP2 if and only if it conforms to NPAMP-BRIDGE
and to the carriage class it uses for a given AP2 exchange (NPAMP-CC-DOC, NPAMP-CC-JSONRPC,
or NPAMP-CC-OPAQUE), and, for AP2 traffic, it:

1. Carries an AP2 Mandate as an NPAMP-CC-DOC document **octet-for-octet**, performing no
   canonicalization or re-encoding, so that the Mandate's SD-JWT signature and any
   selective-disclosure digests verify bit-identically at the consumer, and leaves
   signature verification to the consumer (§4.1);
2. When AP2 rides A2A, carries the Mandate-bearing A2A JSON-RPC object under
   `protocol_id 0x02` via NPAMP-MAP-A2A with `content_type 0x01`, carrying the AP2
   Mandate and any x402 `metadata` (`x402.payment.*`) verbatim inside that object and
   never lifting them into an envelope field (§4.2, §5);
3. Carries any AP2 payload without a confirmed richer carriage under Class OPAQUE, using
   the PROVISIONAL experimental `protocol_id` of §3 only under out-of-band agreement,
   and never emits that experimental identifier as a production default (§3, §4.3;
   NPAMP-REG §7.1);
4. Selects the foreign protocol solely from `protocol_id`, never inferring AP2 from a
   Mandate `vct`, an x402 metadata key, or any other envelope or payload field, and — for
   standalone `0x14` without agreement — returns `ProtocolUnsupported` (§3; NPAMP-REG §9);
5. Attaches a SafetyLabel to every AP2 state-mutating operation using the effect classes
   of §6 — labelling a Mandate creation/authorization at least `non_idempotent_write` and
   a fund-moving payment authorization `destructive` — and treats a **missing** SafetyLabel
   on any AP2 operation not positively known to be read-only as `destructive` (§6;
   NPAMP-BRIDGE §7 fail-safe);
6. Never treats a favorable SafetyLabel as authorization to charge and enforces its own
   authorization at the point of settlement (§6, §9);
7. Carries AP2 traffic only on the channels of §7 — Bridge `0x000D` by default, Commerce
   `0x000E` for payment-mandate/commerce traffic, and Discovery `0x0010` for Mandate/
   capability documents — never splitting a Mandate document set across channels, and only
   on channels advertised during the handshake (§7); and
8. Defines no new frame type, TLV, or code point, consuming only those enumerated in §8,
   and does not assert any AP2 native transport, method, or field that AP2's own
   specification has not published, carrying anything unconfirmed opaquely instead (§2,
   §4.3).

A conformance test suite SHOULD assert each clause above with recorded exchanges that
include at least: a Checkout Mandate SD-JWT carried as an NPAMP-CC-DOC document whose
recovered octets reproduce the producer's digest; a Payment Mandate carried under
`protocol_id 0x02` inside an A2A `message/send` object with x402 `metadata` preserved
verbatim; a payment-authorizing operation carrying a `destructive` SafetyLabel and a
second identical operation with the SafetyLabel omitted, verified to be treated as
`destructive`; a standalone AP2 payload carried under Class OPAQUE with the PROVISIONAL
`protocol_id`; and a standalone `0x14` frame received without prior agreement, verified to
draw `ProtocolUnsupported`.
