# NPAMP-MAP-UCP — Universal Commerce Protocol Mapping (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document is a **thin per-protocol mapping**: it pins the specifics of
> the **Universal Commerce Protocol (UCP)** onto N-PAMP carriage. UCP's core
> transport is a **REST/HTTP-semantics** binding, so this document carries UCP's REST
> exchanges as a thin mapping over the HTTP-semantics carriage class
> **NPAMP-CC-HTTP** (`21_carriage_http.md`): that carriage class does the structural
> work — the HTTP-Carriage Object, correlation, verbatim body and header carriage,
> streaming, and the SafetyLabel derivation from HTTP method — and this document pins
> only what is specific to UCP. It builds on NPAMP-CC-HTTP, on NPAMP-BRIDGE
> (`10_bridge_framework.md`), and on the N-PAMP core specification
> (draft-bubblefish-npamp-01, the "core specification"). It consumes only code points
> those documents already reserve and introduces no change to the core wire format,
> to NPAMP-BRIDGE, or to NPAMP-CC-HTTP.
>
> **Provisional / OPAQUE-READY posture.** UCP has **no standards-assigned
> `protocol_id`** in the Bridge Protocol Identifier registry (NPAMP-REG
> `30_protocol_registry.md`), which assigns only `0x01`–`0x04`. This mapping is
> therefore **PROVISIONAL** on its code point (§2): until a value is assigned under
> NPAMP-REG §8, UCP is carried under an experimental `protocol_id` (`0x10`–`0x7F`)
> agreed out of band, or opaquely via **Class OPAQUE** (NPAMP-CC-OPAQUE,
> `25_carriage_opaque.md`). UCP's REST transport **is** confirmed against the
> protocol's own published specification (§9), so the HTTP mapping below is pinned,
> not deferred; the parts that are version-dependent or not yet confirmed are marked
> as such in §4 and §8, and no method, field, header, or code point is fabricated.

## 1. Scope

### 1.1 In scope

This document specifies how UCP's REST/HTTP-semantics exchanges are carried over an
N-PAMP association. It defines, and only defines, the UCP-specific facts a peer needs
in order to carry UCP under NPAMP-CC-HTTP:

- UCP's `protocol_id` posture and its carriage class, and the `content_type` used
  (§2);
- How UCP's REST operations — its checkout-session lifecycle and the general HTTP
  verb/target contract — map onto NPAMP-BRIDGE frame types through the HTTP-Carriage
  Object (§4);
- How UCP's discovery profile (`/.well-known/ucp`), the `UCP-Agent` request header,
  and UCP's dated version negotiation ride the carriage verbatim (§5);
- Which UCP operations are state-mutating and therefore the SafetyLabel effect class
  a sender attaches, derived from the HTTP method per NPAMP-CC-HTTP §8.1 and tightened
  for UCP's purchase-completion semantics, with the NPAMP-BRIDGE §7 fail-safe on
  absence (§6); and
- Channel selection: the Bridge channel `0x000D` as the default, the Discovery
  channel `0x0010` for the profile document, and the Commerce channel `0x000E` for
  payment-mandate traffic where a deployment prefers the more specific channel (§7).

### 1.2 Not in scope

The following are explicitly NOT defined by this document, because NPAMP-CC-HTTP,
NPAMP-BRIDGE, UCP's own specification, or a sibling mapping already define them:

- **The structural HTTP-semantics carriage** — the HTTP-Carriage Object (method,
  target, status, headers, body, trailers, passthrough), the frame-type mapping,
  `correlation_id` matching, deterministic-CBOR encoding, the redirect and streaming
  rules, and the foreign-vs-carriage error split. These are inherited verbatim from
  NPAMP-CC-HTTP (§2, §3, §4, §5, §6, §7 of that document) and are not restated here
  (§3).
- **UCP's non-REST transports.** UCP additionally defines an **MCP** transport
  (JSON-RPC) and an **A2A** transport (Agent Card) for the same capabilities (§9).
  Those bindings are carried by their own N-PAMP mappings — NPAMP-MAP-MCP
  (`60_map_mcp.md`) and NPAMP-MAP-A2A (`61_map_a2a.md`) respectively — and are out of
  scope here; this document carries UCP's **REST** binding only.
- **UCP's Embedded Protocol (EP).** UCP's embedded/browser checkout surface is an
  in-page interface with event delegation to a host page; its non-N-PAMP delivery
  surface is out of scope, exactly as A2A webhook delivery is out of scope for
  NPAMP-MAP-A2A (§8).
- **The UCP object schemas and capability semantics.** The internal grammar of the
  UCP profile, the Cart / Checkout / Order / Identity-Linking capability objects, the
  AP2-mandate and other extension objects, and the UCP error bodies is fixed by UCP's
  own specification. This document carries these objects verbatim inside the
  HTTP-Carriage Object `body` (NPAMP-CC-HTTP §4.3) and does not parse, validate, or
  transform them.
- **Reconstruction of UCP's transport-bound HTTP Message Signatures.** UCP authorizes
  requests with RFC 9421 HTTP Message Signatures computed over HTTP components that do
  not exist on the N-PAMP wire (§8). This mapping carries those header fields verbatim
  but does not recompute, verify, or re-bind them, exactly as NPAMP-CC-HTTP §8.4
  requires.
- **Any change to the N-PAMP frame format, to NPAMP-BRIDGE, or to NPAMP-CC-HTTP**,
  including the BridgeEnvelope TLV, the SafetyLabel TLV, and the HTTP-Carriage Object.

## 2. Protocol identity

| Property | Value |
|---|---|
| Protocol | Universal Commerce Protocol (UCP), REST/HTTP-semantics binding. |
| `protocol_id` | **PROVISIONAL.** No value is assigned to UCP by NPAMP-REG §6 (which assigns only `0x01`–`0x04`). Until a value is assigned under NPAMP-REG §8, a sender MUST use an **experimental** `protocol_id` (`0x10`–`0x7F`) agreed out of band with the peer (NPAMP-REG §7.1), or a **private-use** value (`0x80`–`0xFF`) within one administrative domain (NPAMP-REG §7.2). This document assigns no value and MUST NOT be read as reserving one. |
| Carriage class | HTTP (NPAMP-CC-HTTP), whose `protocol_id` MUST name an HTTP-class protocol (NPAMP-CC-HTTP §1.3). Where no HTTP-class mapping is negotiated, UCP is instead carriable via Class OPAQUE (NPAMP-CC-OPAQUE) under the same agreed identifier. |
| `content_type` | `0x02` (application/cbor), as NPAMP-CC-HTTP §2.3 requires for every frame carrying an HTTP-Carriage Object; UCP's `application/json` request/response body is carried **inside** the object (§4). Under the Class OPAQUE fallback the raw UCP JSON payload is carried directly with `content_type = 0x01` (application/json). |
| Foreign-message form | Under NPAMP-CC-HTTP, one deterministic-CBOR HTTP-Carriage Object per Bridge frame (NPAMP-CC-HTTP §4), carrying UCP's HTTP method, target, headers, and JSON body octet-for-octet. |

A sender MUST set the agreed `protocol_id` on every Bridge frame carrying a UCP REST
exchange, and MUST NOT emit a UCP exchange under a `protocol_id` the peer has not
agreed carries UCP (NPAMP-REG §7). A receiver that does not carry UCP MUST reply to a
BRIDGE_REQUEST bearing that identifier with `ProtocolUnsupported` (NPAMP-BRIDGE §6;
NPAMP-REG §9), and MUST NOT infer UCP from any other envelope field. When UCP is
promoted to a standards-assigned code point, that value replaces the experimental one
and this section is the only part of the mapping that changes.

## 3. Relationship to NPAMP-CC-HTTP and NPAMP-BRIDGE

UCP's REST binding is HTTP semantics: a request bearing a method, a target
(`/checkout-sessions` and related paths), header fields, and an optional JSON body,
answered by a response bearing a status code, headers, and an optional JSON body.
Consequently the entire structural carriage of UCP-over-REST is provided by
NPAMP-CC-HTTP without modification:

- The transparency rule governs: UCP's HTTP message is carried octet-for-octet inside
  the HTTP-Carriage Object and MUST NOT be re-serialized, reordered, canonicalized, or
  rewritten (NPAMP-BRIDGE §1; NPAMP-CC-HTTP §2.1, §4.3).
- Correlation of a UCP response to its request is the `correlation_id` mapping of
  NPAMP-CC-HTTP §3 (NPAMP-BRIDGE §5), inherited unchanged. This document adds no
  correlation rule.
- A UCP HTTP error response whose status is 4xx or 5xx is a **successful carriage of a
  foreign result** and MUST be carried as a BRIDGE_RESPONSE with that status and body
  preserved verbatim, never as BRIDGE_ERROR (NPAMP-CC-HTTP §6.1). A failure *below*
  UCP — the request did not reach, or no response was obtained from, the UCP endpoint
  — is the only case reported as BRIDGE_ERROR with an N-PAMP transport error
  (NPAMP-CC-HTTP §6.2).
- The BridgeEnvelope `method` field carries the advisory routing key
  "`<HTTP-method> SP <target>`" for a request and is empty for a response
  (NPAMP-CC-HTTP §2.4); the authoritative method, target, and status remain the typed
  keys of the HTTP-Carriage Object.

This document therefore pins only UCP specifics (§2, §4, §5, §6, §7). Where this
document and NPAMP-CC-HTTP could appear to differ on a structural matter,
NPAMP-CC-HTTP governs.

## 4. UCP REST operation namespace and frame mapping

A UCP REST operation is an HTTP request; either peer MAY originate one, and the peer
that emits the BRIDGE_REQUEST is the requester for that exchange (NPAMP-BRIDGE §5). No
N-PAMP role is tied to UCP's platform/agent or business/merchant role.

The table enumerates the REST checkout-session operations confirmed against UCP's
published REST specification (version `2026-04-08`; §9). Each is a complete HTTP
request carried as **BRIDGE_REQUEST** (`0x0100`, `message_kind = 0x01`) with an
HTTP-Carriage Object of `kind = request`; its reply is **BRIDGE_RESPONSE** (`0x0101`)
carrying the UCP status and JSON body — including a 4xx/5xx UCP error body — or, only
for a sub-UCP failure, **BRIDGE_ERROR** (`0x0102`) (§3; NPAMP-CC-HTTP §2.2, §6). The
`target` is the resolved origin-form path from the UCP profile's REST `endpoint` plus
the OpenAPI path (§5).

| UCP operation | HTTP method + target | State impact |
|---|---|---|
| Create checkout session | `POST /checkout-sessions` | Creates a session. |
| Get checkout session | `GET /checkout-sessions/{id}` | Reads session state. |
| Update checkout session | `PUT /checkout-sessions/{id}` | Replaces/updates session state. |
| Complete checkout session | `POST /checkout-sessions/{id}/complete` | Completes the purchase (executes payment). |
| Cancel checkout session | `POST /checkout-sessions/{id}/cancel` | Cancels the session. |

Carriage requirements:

- Every request MUST carry `application/json` request and response bodies (UCP requires
  valid JSON per RFC 8259); the JSON media type is carried in the object's `headers`
  (NPAMP-CC-HTTP §4.4), while the carriage container's `content_type` is `0x02` (§2).
- The BridgeEnvelope `method` field MUST equal "`<method> SP <target>`" for the request
  and MUST be empty on the response (NPAMP-CC-HTTP §2.4); a receiver MUST reject a frame
  whose envelope routing key disagrees with the object's `method`/`target`
  (NPAMP-CC-HTTP §4.7).
- A receiver that does not carry a given UCP operation MUST report `MethodUnsupported`
  (NPAMP-BRIDGE §6 code 3) for a BRIDGE_REQUEST bearing it, and MUST NOT report success
  for an operation it did not perform.

> **Coverage note.** UCP defines further capabilities beyond checkout — for example
> Cart, Order, and Identity Linking — and admits vendor and extension operations
> (e.g. AP2 mandates). Their exact REST verb/target set was not exhaustively confirmed
> from the primary source at the time of writing and is therefore not enumerated here.
> Because NPAMP-CC-HTTP selects nothing on the operation beyond the HTTP method and
> target and carries the message transparently (§3), a peer carries any additional UCP
> REST operation under this same mapping without a change to this document: the HTTP
> method fixes the frame type and the SafetyLabel default (§6), and the object is
> carried verbatim. An implementation MUST NOT reject a UCP operation solely because it
> is absent from the table above.

## 5. Discovery profile, `UCP-Agent` header, and version negotiation

UCP is a discovery-and-negotiation protocol layered on HTTP; the following UCP
mechanisms ride the carriage as ordinary HTTP-semantics traffic, carried verbatim, and
this mapping neither reads nor rewrites them:

- **Discovery profile.** A UCP business publishes a profile document at
  `/.well-known/ucp` declaring its `version`, `services`, `capabilities`, payment
  handlers, and `signing_keys` (JWK). Retrieval of that profile is an HTTP `GET` and is
  carried as a BRIDGE_REQUEST/BRIDGE_RESPONSE under this mapping. Because the target is
  a `.well-known` discovery resource, a sender MAY set the HTTP-Carriage Object
  passthrough `well_known` value to `ucp` (NPAMP-CC-HTTP §5.2, which names `ucp` as a
  recognized suffix) as an advisory routing aid; the profile bytes remain authoritative
  in `body`. The profile MAY additionally be carried as a capability document on the
  Discovery channel (§7).
- **Endpoint resolution.** The profile's REST transport declaration carries a `version`,
  a `transport` of `rest`, an OpenAPI `schema` URI, and an `endpoint` base URI; the
  operation `target` (§4) is the OpenAPI path resolved against that `endpoint`. This
  resolution is performed by the UCP endpoints from the carried profile; the carriage
  does not resolve, rewrite, or validate URLs.
- **`UCP-Agent` header.** A UCP platform/agent announces its own profile URI in the
  `UCP-Agent` request header, an RFC 8941 structured-field dictionary (e.g.
  `UCP-Agent: profile="https://agent.example/profiles/shopping-agent.json"`). This
  header is carried verbatim in the request object's `headers` (NPAMP-CC-HTTP §4.4) and
  MAY be surfaced in `passthrough.selected_headers`; the carriage does not dereference
  the profile URI (NPAMP-CC-OPAQUE §1.3 forbids the carriage from performing such
  out-of-band fetches).
- **Version negotiation.** UCP versions are RFC 3339 dates (`YYYY-MM-DD`; the confirmed
  reference version is `2026-04-08`), negotiated by intersecting both parties' declared
  versions and selecting the highest mutually supported one. This negotiation lives
  entirely inside the carried profile and request/response bodies; a peer MUST NOT
  attempt to convey or enforce the UCP version through any N-PAMP envelope field, and
  MUST NOT carry UCP negotiated state from a prior association into a new one.

## 6. SafetyLabel and state-mutating operations

The SafetyLabel TLV (Type `0x0013`) and its fail-safe semantics are governed by
NPAMP-BRIDGE §7 and inherited through NPAMP-CC-HTTP §8.1 unchanged. For an HTTP-carried
protocol the effect class is derived from the HTTP **method**, which UCP's RESTful
verbs make explicit. This section fixes, for UCP, the effect class each REST operation
carries; a sender MUST attach a SafetyLabel to every UCP request that can cause side
effects, and a receiver MUST NOT treat the **absence** of a SafetyLabel on a
state-mutating operation as `read_only` — absence MUST be treated as `destructive`
(NPAMP-BRIDGE §7 fail-safe).

| UCP operation | HTTP method | Effect (NPAMP-BRIDGE §7) | Rationale |
|---|---|---|---|
| Get checkout session | `GET` | `0x00` read_only | A read; a SafetyLabel MAY be omitted and absence is correctly read as read_only. |
| Update checkout session | `PUT` | `0x01` idempotent_write | Replaces session state; repeating with identical input yields the same state (NPAMP-CC-HTTP §8.1 PUT default). |
| Cancel checkout session | `POST` | `0x02` non_idempotent_write | Cancels the session; carried as a `POST`, whose default class this mapping MUST NOT loosen (NPAMP-CC-HTTP §8.1). A deployment MAY tighten to `0x03` destructive. |
| Create checkout session | `POST` | `0x02` non_idempotent_write | Creates a new session; each call is a fresh action (NPAMP-CC-HTTP §8.1 POST default). |
| Complete checkout session | `POST` | `0x02` non_idempotent_write (floor) | Executes an irreversible purchase/payment. This is the money-moving operation; a sender SHOULD **tighten** the label to `0x03` destructive to reflect its irreversibility, and MUST attach a label. NPAMP-CC-HTTP §8.1 forbids loosening. |

General rules, inherited from NPAMP-CC-HTTP §8.1:

- For any UCP REST operation not listed above, the sender MUST derive the `effect` from
  the HTTP method's default (GET/HEAD/OPTIONS/TRACE → read_only; PUT → idempotent_write;
  DELETE → idempotent_write; POST/PATCH → non_idempotent_write), MUST tighten (never
  loosen) it when it knows the specific operation is more dangerous, and MUST label a
  known-destructive operation `0x03` destructive regardless of method.
- UCP's `Idempotency-Key` request header makes a retried state-mutating operation safe
  to repeat at the UCP layer; it does **not** loosen the SafetyLabel effect class, which
  reflects the method's declared danger, not the client's retry strategy.
- The SafetyLabel `scope` (NPAMP-BRIDGE §7) MAY carry the target path (e.g. the
  checkout-session id) as an advisory resource hint. The label states intent and does
  not replace authorization; a receiver MUST enforce its own authorization at the UCP
  endpoint and MUST NOT treat a favorable label as permission.

## 7. Channel selection

UCP REST traffic rides the **Bridge channel `0x000D`** by default, as required for
NPAMP-CC-HTTP encapsulation (NPAMP-CC-HTTP §9.1; NPAMP-BRIDGE §1). Under this mapping,
a peer carrying a UCP REST exchange MUST carry that exchange's HTTP-Carriage Objects on
the Bridge channel unless a deployment selects a more specific core channel below.

| UCP traffic class | Carriage | Channel |
|---|---|---|
| REST checkout/session and other HTTP operations (§4) | NPAMP-CC-HTTP | Bridge `0x000D` (default) |
| Discovery profile `/.well-known/ucp` (§5) | NPAMP-CC-HTTP (GET) or NPAMP-CC-DOC (as a capability document) | Bridge `0x000D` default; MAY use Discovery `0x0010` |
| Payment-mandate / multi-party commerce traffic (e.g. AP2-mandate extension) | NPAMP-CC-HTTP | Bridge `0x000D` default; MAY use Commerce `0x000E` |

- The **Discovery channel `0x0010`** MAY carry the UCP profile as a capability document
  (its core purpose is "agent, tool, and service discovery and capability
  advertisement"); a document and its proofs MUST NOT be split across channels
  (NPAMP-CC-DOC). A peer MAY also advertise that it carries UCP over NPAMP-DISC
  (`40_discovery.md`), which announces the capability without carrying UCP traffic.
- The **Commerce channel `0x000E`** (core purpose "multi-party agentic commerce and
  payment mandates") MAY carry UCP's payment-mandate and commerce traffic where a
  deployment prefers the more specific channel, per the companion index's channel-
  selection guidance. A single UCP exchange MUST NOT be split across channels.
- The Bridge `0x000D`, Commerce `0x000E`, and Discovery `0x0010` channels are all
  minimum-profile **Standard** (`../../registries/channels.csv`); UCP carriage requires
  no channel above the Standard profile. A peer MUST NOT send or accept UCP frames on a
  channel it did not advertise during the handshake (core specification §5).

## 8. Transport-binding, HTTP Message Signatures, and version notes

UCP mandates HTTPS for its native transport ("All UCP communication MUST occur over
HTTPS"; §9). Over N-PAMP, **N-PAMP is the transport**: UCP's HTTP/TLS hop does not exist
on the N-PAMP wire, and the N-PAMP association supplies authentication, post-quantum
confidentiality and integrity, multiplexing, and the key schedule (core specification),
which replace UCP's TLS hop rather than layering on it.

- **HTTP Message Signatures (RFC 9421) are transport-bound.** UCP authorizes requests
  with RFC 9421 HTTP Message Signatures whose signature base covers HTTP components
  (for example `@method`, `@authority`, `@path`) and a `Content-Digest`, carried in the
  `Signature-Input`, `Signature`, and `Content-Digest` header fields and verified via
  `kid` against the signer's profile `signing_keys`. Those signed components are bound
  to an HTTP hop that does not exist over N-PAMP. This mapping carries the signature
  header fields **verbatim** (NPAMP-CC-HTTP §4.4, §5.2) so a receiver re-emitting the
  message onto a real HTTP hop can present them, but it does **not** recompute, verify,
  or re-bind them, and a receiver MUST NOT infer that a carried UCP signature was
  verified by the carriage (NPAMP-CC-HTTP §8.4). Re-binding such a signature at an
  egress boundary is the responsibility of a gateway acting as an independent
  foreign-transport endpoint, not of this mapping.
- **Other UCP credentials.** UCP's alternative authentication mechanisms — an
  `X-API-Key` header, OAuth bearer tokens in the `Authorization` header, and the
  `UCP-Agent` profile header — are carried as opaque header octets (NPAMP-CC-HTTP §4.4,
  §8.3); the carriage neither validates nor establishes the property any such field
  names.
- **Version and state.** UCP's dated version (§5) is conveyed only inside the carried
  profile and message bodies; a peer MUST NOT convey or enforce it through an N-PAMP
  envelope field, and MUST NOT carry UCP negotiated state across associations.
- **What is confirmed vs. provisional.** Confirmed against UCP's published
  specification (§9): the REST/HTTP transport with mandatory HTTPS and `application/json`
  bodies; the checkout-session operations of §4; the `UCP-Agent`, `Idempotency-Key`, and
  `Request-Id` headers; RFC 9421 HTTP Message Signatures; the `/.well-known/ucp` profile
  and dated version negotiation. **Provisional / unconfirmed:** UCP has no assigned
  `protocol_id` (§2); the full non-checkout operation set (§4 coverage note); and UCP's
  MCP and A2A transports and Embedded Protocol, which are carried by their own mappings
  or out of scope (§1.2). UCP is an active, evolving specification; an implementer MUST
  confirm version-dependent facts against the exact UCP version they target.

## 9. References

Normative for the carriage:

- draft-bubblefish-npamp-01 — the N-PAMP core specification (Bridge channel `0x000D`,
  Commerce channel `0x000E`, Discovery channel `0x0010`, the 36-octet frame, the
  BridgeEnvelope and SafetyLabel TLV reservations, and AEAD payload protection).
- NPAMP-BRIDGE (`10_bridge_framework.md`) — the encapsulation, correlation, error, and
  SafetyLabel contract.
- NPAMP-CC-HTTP (`21_carriage_http.md`) — the HTTP-semantics carriage class that does
  the structural work for UCP's REST binding.
- NPAMP-CC-OPAQUE (`25_carriage_opaque.md`) — the fallback carriage for UCP until a code
  point is assigned (§2).
- NPAMP-REG (`30_protocol_registry.md`) — the Bridge Protocol Identifier registry; UCP
  is unassigned, and the experimental/private ranges of §7 apply (§2).
- NPAMP-DISC (`40_discovery.md`) and NPAMP-CC-DOC (`24_carriage_documents.md`) — the
  Discovery-channel advertisement and document carriage referenced in §7.
- BCP 14: RFC 2119 and RFC 8174 — requirement key words.
- RFC 9421 (HTTP Message Signatures), RFC 8941 (Structured Field Values), RFC 8259
  (JSON), RFC 3986 (URI), RFC 3339 (date/time) — the HTTP-level mechanisms UCP uses,
  referenced where this mapping carries their header fields or values verbatim.

UCP source specification (primary sources consulted for §2, §4, §5, §6, §8; UCP
version `2026-04-08`, the current dated release at the time of writing):

- UCP Specification — Overview (transport list, HTTPS requirement, `UCP-Agent` header,
  versioning) — <http://ucp.dev/2026-04-08/specification/overview/>
- UCP Specification — REST checkout (checkout-session HTTP verbs and paths, headers,
  RFC 9421 signatures) — <http://ucp.dev/2026-04-08/specification/checkout-rest/>
- UCP Specification — MCP transport (JSON-RPC binding; out of scope, carried by
  NPAMP-MAP-MCP) — <http://ucp.dev/2026-04-08/specification/catalog/mcp/>
- UCP Specification — A2A transport (Agent Card binding; out of scope, carried by
  NPAMP-MAP-A2A) — <http://ucp.dev/2026-04-08/specification/checkout-a2a/>
- UCP Specification — Embedded checkout (EP; out of scope) —
  <http://ucp.dev/2026-04-08/specification/embedded-checkout/>
- UCP specification and schema source repository —
  <https://github.com/universal-commerce-protocol/ucp>
- Google for Developers — UCP guide (cross-confirmation of transports and capabilities)
  — <https://developers.google.com/merchant/ucp>

Where a fact was version-dependent or not confirmable from the primary source (the
non-checkout operation set, the absence of an assigned `protocol_id`), it is marked in
§4 and §8 rather than fixed by assumption.

## 10. Conformance

An implementation conforms to NPAMP-MAP-UCP if and only if it conforms to NPAMP-CC-HTTP
(and therefore to NPAMP-BRIDGE) and, for UCP REST traffic, it:

1. Carries every UCP REST exchange under the agreed UCP `protocol_id` with
   `content_type = 0x02`, selects UCP solely from `protocol_id`, and — because no
   standards code point is assigned — uses an experimental (`0x10`–`0x7F`, out-of-band
   agreed) or private-use (`0x80`–`0xFF`) identifier, never emitting UCP under a
   `protocol_id` assigned to another protocol (§2; NPAMP-REG §7, §9);
2. Maps each UCP HTTP request onto a BRIDGE_REQUEST with an HTTP-Carriage Object of
   `kind = request`, carries the UCP status and JSON body (including a 4xx/5xx UCP error
   body) as a BRIDGE_RESPONSE, and signals only a sub-UCP failure as BRIDGE_ERROR with
   an N-PAMP transport error, never fabricating an HTTP status for a carriage failure
   (§3, §4; NPAMP-CC-HTTP §6);
3. Carries the UCP JSON body, the `UCP-Agent`, `Idempotency-Key`, `Request-Id`, and any
   authentication or RFC 9421 signature header fields octet-for-octet and in order,
   without combining, splitting, reordering, or interpreting them, and sets the
   BridgeEnvelope `method` to "`<method> SP <target>`" for requests (§3, §4, §5;
   NPAMP-CC-HTTP §4.4, §2.4);
4. Attaches a SafetyLabel to every state-mutating UCP operation using the effect classes
   of §6 — read_only for `GET`, idempotent_write for `PUT`, non_idempotent_write for the
   `POST` operations, tightening the purchase-completion `POST` toward destructive and
   never loosening a method's default — and treats a missing SafetyLabel on a
   state-mutating operation as `destructive` (§6; NPAMP-BRIDGE §7 fail-safe);
5. Carries the `/.well-known/ucp` profile and UCP's dated version negotiation
   transparently, conveys the UCP version only inside the carried objects (never through
   an N-PAMP envelope field), and carries no UCP negotiated state across associations
   (§5, §8);
6. Neither recomputes, verifies, nor re-binds any UCP RFC 9421 HTTP Message Signature,
   and does not assume any carried UCP credential was validated by the carriage (§8;
   NPAMP-CC-HTTP §8.3, §8.4);
7. Carries UCP REST traffic on the Bridge channel `0x000D` by default, uses the Discovery
   channel `0x0010` only for the profile document/advertisement and the Commerce channel
   `0x000E` only where a deployment selects it for payment-mandate traffic, never splits
   a single UCP exchange across channels, and sends or accepts UCP frames only on
   advertised channels (§7); and
8. Defines no new frame type, TLV, or code point, carries UCP's MCP and A2A transports
   (if at all) under their own mappings rather than this one, and treats UCP's Embedded
   Protocol surface as out of scope (§1.2).

A conformance test suite SHOULD assert each clause above with recorded exchanges that
include: a `GET /checkout-sessions/{id}` read; a `POST /checkout-sessions` create and a
`PUT /checkout-sessions/{id}` update carrying their SafetyLabel effect classes; a
`POST /checkout-sessions/{id}/complete` carrying a `non_idempotent_write` (or tightened
`destructive`) SafetyLabel and a second completion with the SafetyLabel omitted, verified
to be treated as `destructive`; a 4xx UCP error response carried as a BRIDGE_RESPONSE
with its status and JSON body preserved verbatim; a `/.well-known/ucp` profile retrieval
carried with the `well_known = ucp` passthrough; and a request bearing RFC 9421
`Signature`/`Signature-Input`/`Content-Digest` header fields carried verbatim and
neither verified nor re-bound by the carriage.
