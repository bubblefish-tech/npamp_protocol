---
status: "accepted"
date: 2026-06-22
decision-makers: [BubbleFish Technologies, Inc.]
consulted: []
informed: []
---

# Align the X25519MLKEM768 hybrid combiner to ML-KEM-first (wire + secret)

## Context and Problem Statement

draft-00 §7.1 specified the hybrid KEM shared secret as `(X25519 ‖ ML-KEM)` — X25519
first — and the reference implementations (Go and TypeScript) followed it on both
the wire (KEMShare/KEMCiphertext layout) and the HKDF-Extract IKM. A primary-source review
of the IETF X25519MLKEM768 definition found the opposite: the codepoint N-PAMP reuses
(`0x11ec`) concatenates **ML-KEM first**. Which order is correct, and how did the divergence
arise?

## Root cause (recorded for the history)

Not a careless oversight and not memory-fabrication — a **wrong-source-of-authority** lapse:
- The order was flagged as an open question during design (spec-sheet item D-B1, status `U`).
- It was resolved by citing `draft-ietf-tls-hybrid-design`, whose §3.3 says "concatenate in
  NamedGroup-name order" → for the name "X25519MLKEM768", X25519 first. That citation was
  applied correctly.
- But the codepoint `0x11ec`/X25519MLKEM768 is defined by `draft-ietf-tls-ecdhe-mlkem`
  (§4.1/§4.3), **not** by the generic hybrid-design framework — and that definition
  **deliberately reversed** the order to ML-KEM-first, because NIST SP 800-56C Rev. 2 requires
  the FIPS-approved key-establishment output (ML-KEM) to be the first input to HKDF. The
  framework citation was one level too general; the codepoint-specific document overrides it.

**Reusable lesson:** when a codepoint has its own defining document, that document — not the
framework it lives under — is the authority for that codepoint's construction.

## Considered Options

* **(A) Align to ML-KEM-first** — match the X25519MLKEM768 definition + SP 800-56C Rev. 2,
  on both the wire layout and the HKDF-Extract IKM.
* **(B) Keep X25519-first as a deliberate N-PAMP divergence** — but then stop reusing the IETF
  codepoint `0x11ec` (assign a distinct N-PAMP codepoint) and drop the "established practice"
  claim.

## Decision Outcome

Chosen option: **(A) align to ML-KEM-first.** The shared secret is `(ML-KEM ‖ X25519)` fed raw
into HKDF-Extract; the on-wire KEMShare is `ML-KEM ek ‖ X25519 pub` and KEMCiphertext is
`ML-KEM ct ‖ X25519 pub`. This makes N-PAMP's `0x11ec` genuinely interoperable with a
standards-conformant X25519MLKEM768 peer and FIPS-ordering-correct, and makes the spec's
conformance claim true rather than stale.

### Consequences

* Good, because N-PAMP's X25519MLKEM768 now means what the codepoint means everywhere else
  (interop) and satisfies the SP 800-56C ordering (FIPS posture).
* Good, because it removes a "consistency-not-correctness" trap: previously the two reference
  implementations agreed with each other but would have failed against any third-party peer.
* Bad, because it changes the derived key material — all handshake KAT golden vectors and any
  recorded "interop verified" run prior to 2026-06-22 are superseded and must be regenerated.
* Bad, because the TypeScript reference implementation must mirror the change before cross-language interop holds again.

### Confirmation

- Go reference implementation updated (KEM wire layout in `kem.go` + IKM order in
  `keyschedule.go`); handshake KAT goldens regenerated; its handshake, transport, and client
  packages all pass (with `-race`). The two low-order-X25519
  rejection tests + the RFC-5869 Extract cross-check were updated to the new layout (they
  caught the change — mutation-surviving).
- Spec updated: draft §7.1 + `spec/06_cryptographic_suites.md`.
- **UNVERIFIED until done:** cross-language interop against the corrected TypeScript reference
  implementation, and a third-party-conformant X25519MLKEM768 peer. Same-implementation
  (self-interop) agreement on the corrected order is proven; standards-interop is not yet.

## Pros and Cons of the Options

### (A) ML-KEM-first
* Good, because interoperable + FIPS-ordered + the spec claim becomes true.
* Bad, because it invalidates prior KATs / interop evidence (one-time regeneration).

### (B) X25519-first under a distinct codepoint
* Good, because no code change.
* Bad, because a permanent interop + FIPS deviation under a name/codepoint that collides with
  the IETF meaning — exactly the kind of stale-spec hazard this ADR exists to remove. Rejected.

## More Information

Primary sources (read this session): `draft-ietf-tls-ecdhe-mlkem` §3/§4.1/§4.3 (ML-KEM-first,
SP 800-56C rationale); `draft-ietf-tls-hybrid-design` §3.3 (the generic "NamedGroup-name order"
that misled the original draft); FIPS 203 (ML-KEM-768 sizes); RFC 7748 (X25519). Related:
ADR-0003 (profiles share one construction). **Follow-ups:** (1) add formal bibliography
entries for `draft-ietf-tls-ecdhe-mlkem` + NIST SP 800-56C Rev. 2 to the draft before the next
build (currently cited descriptively to stay build-safe); (2) the TypeScript reference
implementation mirrors the ML-KEM-first wire+secret and regenerates its KATs; (3) re-run the two-sided interop test and
record the new payload_id; (4) the prior `0x11ec` interop evidence is superseded.
