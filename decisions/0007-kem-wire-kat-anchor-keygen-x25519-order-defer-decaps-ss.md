---
status: "accepted"
date: 2026-06-23
decision-makers: [BubbleFish Technologies, Inc.]
consulted: []
informed: []
---

# KEM-wire KAT: anchor keygen + X25519 + wire order now; defer the NIST decaps shared-secret anchor

## Context and Problem Statement

The X25519MLKEM768 hybrid-KEM wire byte order (ML-KEM-first, ADR-0005) was, until now, verified
only by symmetric self-interop plus code review in both reference implementations — a method that
structurally cannot catch a *symmetric* wire-byte-order bug (both ends agreeing on the wrong order
still interoperate). That is exactly how the original X25519-first combiner defect hid behind green
self-interop. Spec/10 §8 names the **KEM-wire KAT** as required, standards-derived, non-circular
corpus growth. This ADR records how that KAT was realized and the one anchor that could not be.

## Decision Drivers

* Non-circularity (E8): known answers MUST come from the standards, never from an N-PAMP impl.
* Must catch the combiner byte-order bug (both faces: KEMShare/KEMCiphertext wire order and the
  HKDF-Extract IKM order).
* Must be executable by the Go reference impl using the standard-library `crypto/mlkem` +
  `crypto/ecdh` (Go 1.26), whose public API was confirmed this session.

## Considered Options

* **(A) Anchor keygen (seed→ek) + X25519 (RFC 7748) + wire/IKM order now; carry the NIST decaps
  (c→K) vector as data and defer its execution.**
* (B) Use the C2SP/CCTV single-source coherent `(d,z,ek,c,K)` vector for a full keygen→decaps KAT.
* (C) Generate a coherent ciphertext by encapsulating to the NIST ek with Go and pin the result.

## Decision Outcome

Chosen option: **(A)**. The KAT (`test-vectors/v1/kem-wire-kat.json`; consumed by the Go
reference implementation) asserts, all from outside any N-PAMP impl:

1. **ML-KEM keygen** — `NewDecapsulationKey768(d‖z).EncapsulationKey().Bytes() == ek` for NIST
   ACVP (FIPS 203) `d,z,ek` (ML-KEM-768, keyGen tcId 26). Verified reproducing in Go.
2. **X25519** — `crypto/ecdh` reproduces RFC 7748 §6.1 public keys and shared secret from the raw
   private scalars (clamping internal).
3. **KEMShare wire order** — `ShareBytes() == ek ‖ x25519_public` (ML-KEM-first).
4. **KEMCiphertext wire order** — `DeriveSharedSecrets(ct ‖ server_x25519_pub)` recovers an X25519
   shared secret equal to RFC 7748's `K` (the X25519 half is RFC-anchored; the wrong order cannot
   reproduce it).
5. **IKM order** — `handshake_secret == HKDF-Extract(salt, ML-KEM_SS ‖ X25519_SS)` and differs
   from the X25519-first IKM.

Option (B) was **rejected after disconfirmation**: the CCTV intermediate vector is FIPS 203
*initial public draft* era (Dec 2023, Algorithm 12/13 XOF input-ordering swap) and does not
reproduce under final-FIPS-203 `crypto/mlkem` (ek and K both mismatch when run). Option (C) was
rejected as partially circular (a Go-generated ciphertext is not a standards-published value).

### Consequences

* Good: the combiner byte-order bug is now caught by a standards-anchored, mutation-proven KAT in
  the Go reference impl (demonstrated: reverting to X25519-first fails the order assertions while
  the keygen/X25519 anchors still pass).
* Good: language-agnostic vector file → the TypeScript reference implementation and other impls can consume the same oracle.
* Bad / deferred: the ML-KEM **decapsulation shared-secret VALUE** is not NIST-anchored via Go's
  public API. No final-FIPS-203 source pairs a key-generation *seed* with a ciphertext+K under the
  same key, and Go's public `crypto/mlkem` imports only the 64-byte seed (not the 2400-byte
  expanded dk that NIST ACVP encapDecap supplies). The NIST decaps vector (`c`, `K`) is carried in
  the KAT file for impls that can import an expanded dk; closing it in Go awaits a seed-based
  final-FIPS-203 `(d,z,c,K)` vector or use of an expanded-dk import.

### Confirmation

The Go reference implementation's KEM-wire KAT test passes against the ML-KEM-first code and FAILS
when the combiner is reverted to X25519-first (mutation-surviving). The full verification gate passes.

## Pros and Cons of the Options

### (A) Anchor keygen + X25519 + order now, defer decaps-SS
* Good: every executed assertion is standards-anchored and the combiner bug is caught; honest about
  the one unanchored leg.
* Neutral: the ML-KEM decaps-SS NIST anchor is documented growth, not silent absence.

### (B) CCTV single coherent vector
* Bad: it is FIPS 203 ipd-era and does not reproduce under final-FIPS-203 (verified by running it).

### (C) Self-generated ciphertext
* Bad: partially circular — the ciphertext/SS would be an N-PAMP-produced value, not a standard.

## More Information

`test-vectors/v1/kem-wire-kat.json`; spec/10 §8; ADR-0005 (ML-KEM-first), ADR-0006 (binding).
Sources: NIST ACVP-Server (FIPS203 revision) ML-KEM-keyGen / ML-KEM-encapDecap; RFC 7748 §6.1;
Go `crypto/mlkem` + `crypto/ecdh` (1.26).
