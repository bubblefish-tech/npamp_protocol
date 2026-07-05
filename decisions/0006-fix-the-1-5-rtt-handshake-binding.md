---
status: "accepted"
date: 2026-06-22
decision-makers: [BubbleFish Technologies, Inc.]
consulted: []
informed: []
---

# Fix the 1.5-RTT handshake binding (spec/10) for draft-01

## Context and Problem Statement

Published draft-00 specifies the handshake *requirements* and *negotiation vocabulary* but
leaves the handshake *wire bytes* — message flow, frame/TLV codepoints, transcript
composition, secret ladder, KEM wire layout, CertVerify/Finished carriage — undefined. Two
reference implementations (Go and TypeScript) built a binding from a
design note; an independent binding-spec review (this session) extracted it, verified it
against RFC 8446 + FIPS 203 + RFC 7748, and corrected the KEM combiner order (ADR-0005). The
binding needs a single normative definition so it is conformance-testable and proof-targetable
rather than only self-interop-testable.

## Decision Drivers

* Conformance vectors must be derivable from the *spec*, not the impl (non-circularity / E8).
* The binding must reuse cited standard constructions where possible and justify every divergence.
* One construction for all profiles (ADR-0003); ML-KEM-first KEM (ADR-0005).

## Considered Options

* **Write a single normative binding spec (`spec/10_handshake_binding.md`)** reusing RFC 8446
  constructions where applicable and marking each N-PAMP-original choice.
* Leave the binding defined only by the design note + the code (status quo).
* Adopt TLS 1.3 wholesale (reject — N-PAMP is not TLS; it has its own frame/TLV envelope and no
  PSK/0-RTT stage).

## Decision Outcome

Chosen option: **write `spec/10_handshake_binding.md`** as the authority, targeted for draft-01
ratification. It reuses RFC 8446 §7.1 (HKDF-Expand-Label, with the `"n-pamp "` prefix), §4.4.3
(CertVerify signing input, with N-PAMP context strings), and §4.4.4 (Finished), and accepts
**three deliberate divergences from TLS 1.3**, each documented in spec §7 with rationale and
flagged for formal-methods review:

1. **Per-TLV transcript** absorbing only the 2-octet frame type + TLV bytes (not full frame
   headers) — required so the bundled AUTH frame hashes at sub-frame boundaries; encrypted-frame
   header integrity comes from the AEAD AAD.
2. **Single HKDF-Extract** key schedule (vs TLS's three-stage chain) — sound because there is
   no PSK/0-RTT stage; master/handshake separation is by label + transcript context.
3. **ML-KEM-first hybrid KEM** (ADR-0005) — SP 800-56C Rev. 2 / draft-ietf-tls-ecdhe-mlkem.

### Consequences

* Good, because the binding now has one normative source; KAT vectors can be derived from it.
* Good, because the three divergences are explicit + bounded (a reviewer/prover knows exactly
  what differs from TLS 1.3).
* Bad, because the divergences mean TLS 1.3's existing formal proofs do not transfer directly —
  the proofs must be re-targeted to this binding (Phase 4 / `formal/`).

### Confirmation

The Go reference implementation matches the spec (self-interop + KAT). Independent
confirmation requires the handshake-layer KATs enumerated in spec §8 (KEM-wire, key-schedule,
transcript, Finished, CertVerify) — standards-derived, non-circular — which are the next
corpus-growth step. Until they exist, handshake conformance is self-interop + review only (so
stated in spec §8).

## Pros and Cons of the Options

### Single normative binding spec
* Good, because it is the prerequisite for non-circular conformance + proof re-targeting.
* Neutral, because the divergences require their own justification (provided in §7).

### Leave it to the design note + code
* Bad, because conformance vectors would be impl-derived (circular) and there is no single
  source of truth.

## More Information

`spec/10_handshake_binding.md`; binding constructions grounded in RFC 8446 §7.1/§4.4,
FIPS 203, RFC 7748, RFC 5869. Related: ADR-0003 (one construction), ADR-0005 (KEM order). The
KEM-wire KAT in spec §8 also closes the wire-byte-order coverage gap surfaced by the TypeScript
ML-KEM-first review (symmetric self-interop cannot catch a symmetric wire bug).
