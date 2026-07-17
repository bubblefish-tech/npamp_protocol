# N-PAMP Code-Point Registration Request

This is a fill-in template for requesting a code point in an N-PAMP registry. It
is IANA-registration-request style: you copy the relevant section, replace every
`<...>` placeholder, delete the sections you do not need, and submit it (open a
pull request against the `npamp_protocol` repository, or file it with IANA for the
two IANA-hosted actions in Part C).

**Pick the right part first** — the registry you want to touch determines the
policy and the decider:

| You want to register / allocate | Use | Policy | Decided by |
|---|---|---|---|
| A Bridge `protocol_id` in `0x05`–`0x0F` (a new foreign agent protocol carried over the Bridge channel) | **Part A** | Specification Required (RFC 8126) | Designated expert (NPAMP-REG §8.3) |
| A core code point: a new channel, frame type, TLV tag, profile, or KEM/AEAD/signature suite | **Part B** | Maintained in the specification (Independent Submission) | Draft editor via the NEP process |
| The ALPN identifier or the `npamp://` URI scheme | **Part C** | Expert Review / FCFS (IANA) | IANA |

> The whole allocated code-point surface is rendered on the
> [Registries page](registries.md). Experimental (`0x10`–`0x7F`) and private-use
> (`0x80`–`0xFF`) Bridge `protocol_id` ranges require **no registration** and are
> out of scope for this template (NPAMP-REG §7); use them directly under the rules
> in NPAMP-REG §7.1 / §7.2.

---

## Part A — Bridge protocol-ID registration (Specification Required)

Use this to register a foreign agentic protocol so it has a standards-assigned,
cross-domain Bridge `protocol_id` in the range `0x05`–`0x0F`. The policy,
required fields, and designated-expert criteria are normative in
**NPAMP-REG** (`spec/companion/30_protocol_registry.md`), §8. A request that does
not satisfy §8.3 will be rejected.

### A.1 Required fields (NPAMP-REG §8.2)

| Field | Your value |
|---|---|
| **Protocol name** (human-readable, plus common short name if any) | `<e.g. FooAgent Protocol (FAP)>` |
| **Requested code point** (OPTIONAL: a specific value in `0x05`–`0x0F`, or "any") | `<0x05 | any>` |
| **Carriage class** (exactly one of: JSONRPC, HTTP, MSG, STREAM, DOC, OPAQUE — must be a published carriage-class companion spec) | `<e.g. JSONRPC>` |
| **Mapping reference** (the document that pins the protocol-specific carriage — method/operation namespace and any protocol-specific fields — OR the statement "carried generically by the named carriage class, no additional mapping") | `<e.g. NPAMP-MAP-FAP, or "generic under NPAMP-CC-JSONRPC">` |
| **Foreign-protocol reference** (a stable, publicly available reference to the foreign protocol's own specification) | `<URL or citation>` |
| **Change controller** (the entity responsible for the registration) | `<name / organization>` |
| **Contact** (a monitored contact for the registration) | `<email / handle>` |

### A.2 Carriage class — pick one

| Class | Short name | Carries |
|---|---|---|
| JSONRPC | NPAMP-CC-JSONRPC | JSON-RPC 2.0 request/response/notification protocols |
| HTTP | NPAMP-CC-HTTP | HTTP-semantics (method, path, headers, body) protocols |
| MSG | NPAMP-CC-MSG | Message-passing / performative (speech-act) protocols |
| STREAM | NPAMP-CC-STREAM | Event / streaming protocols over BRIDGE_STREAM_DATA / BRIDGE_STREAM_END |
| DOC | NPAMP-CC-DOC | Capability / schema documents (agent cards, tool catalogs, schemas) |
| OPAQUE | NPAMP-CC-OPAQUE | Any declared-`content_type` payload, carried with no protocol-specific mapping |

If the richer carriage class you need has not yet been authored, request **OPAQUE**
now (a peer that supports OPAQUE MAY carry your protocol under its declared
`content_type`); the code point stays assigned and can gain a richer mapping later
without reassignment (NPAMP-REG §5, §6).

### A.3 Designated-expert checklist (NPAMP-REG §8.3 — the expert verifies each)

- [ ] The named carriage class exists as a published carriage-class companion specification (§5).
- [ ] The requested carriage is structurally consistent with that class — the foreign protocol's message model can be carried by that class **without** modifying NPAMP-BRIDGE or the core wire format.
- [ ] The assignment does not duplicate an existing §6 assignment for the same foreign protocol.
- [ ] The foreign-protocol reference is stable and publicly available.
- [ ] The requested code point lies in `0x05`–`0x0F` and is unassigned. (The expert MUST reject any request that would change a §4 boundary, reassign `0x00`–`0x04`, or assign outside `0x05`–`0x0F`.)

### A.4 Worked example (illustrative — not a real assignment)

```
Protocol name:           FooAgent Protocol (FAP)
Requested code point:    any
Carriage class:          JSONRPC (NPAMP-CC-JSONRPC)
Mapping reference:       carried generically by NPAMP-CC-JSONRPC; no additional mapping
Foreign-protocol ref:    https://example.org/fap/spec-v1  (stable, public)
Change controller:       Example Foundation
Contact:                 fap-registry@example.org
```

Expert outcome: if §8.3 is satisfied, the expert assigns the lowest free value in
`0x05`–`0x0F` (or the specific value requested, if free), records the row in
NPAMP-REG §6, and the CSV `registries/bridge_protocol_ids.csv` is updated by pull
request.

---

## Part B — Core code-point registration (channel / frame type / TLV / suite)

The core channel, frame-type, and TLV registries and the profile / KEM / AEAD /
signature suites are **defined and maintained within the specification itself**,
not via an IANA-hosted registry (core spec §8 IANA posture;
`spec/09_extension_points.md`). A new core code point is therefore requested as a
change to the draft, decided through the **NEP process** (`process/NEP-0000`),
**not** by IANA registration.

Route:

1. **Open a `design`-labeled issue** describing the need (`CONTRIBUTING.md`, RFC 8874 practice).
2. **Write a NEP** (`process/NEP-NNNN-slug.md`) if the change is larger than a single ADR — a new channel, a new frame-type range, a new TLV tag, a new suite, or a new registration policy is a NEP-scale change (NEP-0000 §Abstract). A smaller additive registration MAY proceed with a PR + an ADR.
3. **Record an ADR** (MADR 4.0, `decisions/`) capturing the Considered Options, Decision, and Consequences.
4. **Add the CSV row + the spec table + the change-log bullet** in the PR.

> **NEP `Final` gate (NEP-0000 §6):** a Standards-Track NEP MUST NOT reach `Final`
> until it has **at least one working reference implementation AND
> machine-gradable, non-circular conformance vectors**. A code-point request that
> ships prose only is at most `Accepted`.

### B.1 Required fields for a core code-point request

| Field | Your value |
|---|---|
| **Registry** (channel / frame-type / TLV tag / profile / KEM / AEAD / signature) | `<registry>` |
| **Requested code point** (specific value or "any in the additive range") | `<e.g. 0x0014 channel, or "any">` |
| **Name** | `<name>` |
| **Semantics** (what it does on the wire; for a channel: purpose, min profile, direction; for a frame type: the reserved range it occupies; for a suite: the construction and its standards reference) | `<...>` |
| **Additive vs. layout change** (`CONTRIBUTING.md` §Code-point stability: does this change the 36-octet header geometry, magic, header CRC, channel/frame/TLV number spaces? If yes, it is a **major-version** change → new ALPN `n-pamp/N`.) | `<additive | major-version>` |
| **Companion specification** (link, if the code point occupies a reserved companion range) | `<spec/companion/... or N/A>` |
| **Reference implementation** (path; required for NEP `Final`) | `<impl/... or "planned, NEP Accepted">` |
| **Conformance vectors** (path; non-circular — expected values from the underlying RFC/FIPS/NIST/Wycheproof standard, never from the impl under test) | `<test-vectors/... or "planned, NEP Accepted">` |
| **ADR / NEP number** | `<decisions/NNNN-... and/or process/NEP-NNNN-...>` |
| **Change controller / Contact** | `<...>` |

---

## Part C — IANA registry actions (ALPN and `npamp://` URI scheme)

N-PAMP requests exactly two IANA-hosted registry actions. Both are already written
up in full IANA-template form in
`IANA_ALPN_n-pamp-2_registration_request.md` at the repository root; the field
sets are reproduced here for reference. These are submitted to **IANA**, not
decided in this repository.

### C.1 ALPN protocol identifier (RFC 7301 §6 — Expert Review)

| Field | Value |
|---|---|
| **Protocol** | `<protocol name and wire major version>` |
| **Identification Sequence** | `<the ALPN octet string, e.g. "n-pamp/2" — give the hex octets and the UTF-8 string>` |
| **Reference** | `<the Internet-Draft / RFC number>` |

Registered under **Expert Review** (RFC 8126): the designated expert verifies the
identification sequence is unique in the ALPN registry, the specification is
available, and the protocol genuinely benefits from ALPN negotiation.

### C.2 URI scheme (RFC 7595 — provisional / First Come First Served)

| Field | Value |
|---|---|
| **Scheme name** | `<e.g. npamp>` |
| **Status** | `<Provisional | Permanent>` |
| **Applications/protocols that use this scheme** | `<...>` |
| **URI scheme syntax** (RFC 3986 generic syntax) | `<ABNF>` |
| **Encoding considerations** | `<...>` |
| **Interoperability considerations** | `<...>` |
| **Security considerations** | `<...>` |
| **Contact** | `<name, organization>` |
| **Change controller** | `<name, organization>` |
| **Reference** | `<the Internet-Draft / RFC number>` |

---

## Normative references

- **NPAMP-REG** — `spec/companion/30_protocol_registry.md`: Bridge `protocol_id`
  partition (§4), carriage classes (§5), assigned code points (§6), experimental
  and private-use ranges (§7), registration procedure and required fields (§8),
  and handling of an uncarried identifier (§9).
- **Core specification §Extension points / IANA posture** —
  `spec/09_extension_points.md`: the core registries are maintained in the
  specification, not via IANA; only the ALPN identifier and `npamp://` URI scheme
  are IANA actions.
- **NEP-0000** — `process/NEP-0000-nep-process.md`: the enhancement-proposal
  process and the `Final` gate (reference implementation + non-circular
  conformance vectors).
- **CONTRIBUTING.md** — decision layers (ADR / change log / labels), code-point
  stability, and research discipline (vectors derived from the standard, never
  from the implementation they grade).
- **RFC 8126** — assignment-policy definitions (Specification Required, Expert
  Review, First Come First Served).
- **RFC 7301** §6 (ALPN registration template) and **RFC 7595** (URI-scheme
  registration template).
- **IANA_ALPN_n-pamp-2_registration_request.md** — the filled ALPN and
  `npamp://` submissions.
