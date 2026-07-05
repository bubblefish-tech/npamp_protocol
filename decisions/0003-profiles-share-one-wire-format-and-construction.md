---
status: "accepted"
date: 2026-06-22
decision-makers: [BubbleFish Technologies, Inc.]
consulted: []
informed: []
---

# The three security profiles share one wire format and one handshake construction

## Context and Problem Statement

N-PAMP defines three security profiles — Standard (0x01), High (0x02), Sovereign (0x03).
A natural-but-wrong instinct is to treat them as three different protocols and to write a
separate handshake binding / spec per profile. Are the profiles distinct protocols, or one
protocol parameterized by algorithm strength? This determines whether the handshake binding
spec is written once or per profile.

## Decision Drivers

* The handshake binding spec, the key schedule, and the conformance vectors should not be
  triplicated if the construction is identical.
* The profiles must still be distinguishable and individually enforceable on the wire.
* The decision must be grounded in the draft text, not assumed.

## Considered Options

* **One wire format + one construction, parameterized per profile** (a profile is a row of
  algorithm parameters plugged into a single binding).
* **Three independent per-profile bindings / specs.**

## Decision Outcome

Chosen option: **one wire format + one construction, parameterized per profile.** The draft
(§6, "Profile Negotiation") states verbatim: the profiles *"share one wire format and differ
only in cryptographic primitives and operational requirements. Each is an escalation of the
previous."* The handshake binding, transcript construction, and key-schedule **structure**
are identical across profiles; only a parameter row changes. Therefore the binding is
specified ONCE with a per-profile parameter table.

Verified per-profile invariants (`spec/05_profiles.md`, derived from
`draft-bubblefish-npamp-00.md §6`):

| Property | Standard | High | Sovereign |
|---|---|---|---|
| Minimum KEM | X25519MLKEM768 | X25519MLKEM1024 | X25519MLKEM1024 |
| Allowed signatures | Ed25519 | Ed25519, ML-DSA-87 | ML-DSA-87 |
| KDF hash | SHA-256 | SHA-384 | SHA-384 |
| Per-frame AEAD diversification | Off | On | On |
| Downgrade refusal | Off | Refuses Standard | Refuses below Sovereign |

The single most consequential parameter is the **KDF hash** (SHA-256 vs SHA-384): it changes
secret and transcript-hash *lengths*, but not the *construction* — the binding reads
`Hash = profile.KDFHash()`.

### Consequences

* Good, because the binding spec, key schedule, and conformance harness are written once and
  parameterized — no triplication, no drift between per-profile copies.
* Good, because the profile is carried in the handshake transcript that the Finished MAC
  covers, so stripping or downgrading a profile invalidates the MAC and aborts (§6).
* Bad, because length-dependent code paths (hash output size) must be parameter-driven, not
  hardcoded to SHA-256, or a profile change silently produces wrong-length secrets.

### Confirmation

Grounded in `spec/05_profiles.md:7-9,21-28` and `impl/go/profiles.go` (`KDFHash()`,
`MinKEM()`). Conformance: the `profile.check` corpus op verifies the KEM-acceptance invariant
per profile (a profile MUST NOT accept a KEM below its minimum). The binding spec (forthcoming)
will be authored once with the parameter table above.

## Pros and Cons of the Options

### One construction, parameterized
* Good, because matches the draft's own statement and avoids triplication.
* Neutral, because requires parameter-driven lengths.

### Three per-profile bindings
* Good, because each profile's text is self-contained.
* Bad, because it contradicts §6, triples the spec/vector/proof surface, and invites drift.

## More Information

Draft §6 "Profile Negotiation"; `spec/05_profiles.md`. Note: the Sovereign *profile* and its
ML-KEM-1024 / ML-DSA-87 codepoints are public draft codepoints. Open-edition products implement
the Standard row only; the spec defines all three.
