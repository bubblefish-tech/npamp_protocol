# N-PAMP draft-02 — IANA Actions (T20.2)

One section per IANA-facing action this document requests. Each row states value,
policy, and the normative reference in the draft. This is a repo-local tracking
document; it makes no submission-status claim and records no ISE/IANA decision — see
`GitHub/ietf/draft-bubblefish-npamp-02.xml` §IANA Considerations for the normative text
that would actually be submitted.

**ISE registry-strategy constraint (runbook §A.4, recorded here per T20.2):** because
this document is intended for the Independent Submission stream, any NEW IANA-hosted
registry it created would need RFC-Required or First-Come-First-Served policy (not
Specification-Required / Expert-Review, which presumes IETF-stream review), and code
points cannot be reserved before publication (no RFC 7120 early allocation). N-PAMP's
actual registry strategy (below) avoids the problem entirely: it requests exactly two
actions against **existing** IANA registries (ALPN, URI schemes) and creates **no** new
IANA-hosted registry. Every other code-point space (channel, frame-type, TLV, error/alert
code, KEM/signature-suite selection) is either maintained inside this specification
(Independent stream) or re-anchored to a registry IANA already runs for TLS.

## 1. ALPN Protocol Identifier — existing registry, Expert Review

| Field | Value |
|---|---|
| Registry | TLS Application-Layer Protocol Negotiation (ALPN) Protocol IDs (RFC 7301 §6) |
| Protocol | N-PAMP, crypto generation 3 |
| Identification Sequence | `0x6E 0x2D 0x70 0x61 0x6D 0x70 0x2F 0x33` (UTF-8 "n-pamp/3") |
| Policy | Expert Review (RFC 8126) |
| Reference | This document, §IANA Considerations / ALPN Protocol Identifier |
| Notes | "n-pamp/1" and "n-pamp/2" are prior crypto generations, deprecated (SHOULD NOT negotiate for new associations); not replaced, both remain registered for history. Each future crypto generation gets a new identifier — this is not an on-wire minor-version field (T0.2 decision, D-ADR-0014). |

## 2. URI Scheme — existing registry, provisional/FCFS, reference update only

| Field | Value |
|---|---|
| Registry | Uniform Resource Identifier (URI) Schemes (RFC 7595) |
| Scheme name | `npamp` |
| Status | Provisional (already registered under an earlier revision of this document) |
| Action requested | Update IANA's reference for the "npamp" scheme to this revision — no new registration |
| Policy | First Come First Served (provisional registration procedure, RFC 7595) |
| Reference | This document, §IANA Considerations / URI Scheme Registration |

## 3. Core code-point registries — NOT IANA actions (maintained in this specification)

The channel registry, frame-type registry, TLV type registry, and error/alert code
registry are **defined and maintained within this document** (Independent Submission
stream). No IANA-hosted registry is requested for any of them; they are extended by
companion specifications and by future revisions of this document via the NEP process
(`process/NEP-0000-nep-process.md`), not by IANA registration action. See the draft's
§"Registries Maintained by This Specification".

| Registry | Where defined | IANA action |
|---|---|---|
| Channel registry | draft §channel-registry | None — in-spec |
| Frame-type registry | draft §frame-types | None — in-spec |
| TLV type registry | draft §tlv-registry | None — in-spec |
| Error/alert code registry | draft §error-registry | None — in-spec |

## 4. KEM / signature-suite code points — re-anchored to an existing IANA-run registry, not self-registered

N-PAMP's KEM and signature-algorithm selectors are not a self-issued registry: they are
re-anchored to code points IANA already assigns for TLS.

| Selector | Authority | IANA action |
|---|---|---|
| KEM / hybrid key-share group (e.g. `0x11EC` X25519MLKEM768, `0x11ED` SecP384r1MLKEM1024) | IANA "TLS Supported Groups" registry (values defined by RFC 10024, formerly `draft-ietf-tls-ecdhe-mlkem`, published August 2026 — re-cited throughout this document set this pass) | None — N-PAMP references the existing TLS registry, it does not request new values |
| Signature scheme (e.g. `0x0905` ML-DSA-65, `0x0906` ML-DSA-87, `0x0904` ML-DSA-44) | IANA "TLS SignatureScheme" registry (values defined by `draft-ietf-tls-mldsa`) | None — same pattern: reference, not registration |

## 5. Media type — not applicable to this document

N-PAMP is a transport/session protocol (ALPN-negotiated), not a content-carrying media
format; it defines no `application/vnd.*` media type and requests no media-type
registration. (This differs from N-AALP, which registers
`application/vnd.bubblefish.naalp+cbor` in the standards tree — that registration is
out of scope for this document.)

## Summary: IANA actions requested by this document

Exactly **two** IANA-hosted actions (§1, §2), both against existing registries, both
Expert-Review/FCFS policy, no new registry created, no pre-publication code-point
reservation needed. Sections 3–5 are recorded here to make the *absence* of further
IANA action traceable to a deliberate registry-strategy decision, not an oversight.

## Provenance

- Consolidates the IANA Considerations section already present in
  `draft-bubblefish-npamp-02.xml`/`.md` (normative source of truth) with the
  registry-strategy decision already recorded in `docs/REGISTRATION-REQUEST.md` Part C.
- Cross-checked against `idnits.txt` (T20.3, this pass) for reference-currency issues.
- Written as a reconciliation/tracking artifact (T20.2); it is not itself submitted to
  IANA and states no external decision.
