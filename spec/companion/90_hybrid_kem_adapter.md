# N-PAMP Companion — Hybrid-KEM Combiner Adapter

> **Companion to** `draft-bubblefish-npamp-01` (the core specification) and `spec/06_cryptographic_suites.md`.
> Normative for the adapter's own behavior (Requirement 2 acceptance criterion 2 of the
> Part-2 ecosystem requirements); it defines no NEW wire bytes and consumes no new code points beyond what
> `spec/06_cryptographic_suites.md` already fixes. Where this document and
> `spec/06_cryptographic_suites.md` disagree, `spec/06_cryptographic_suites.md`
> (and beneath it, the core draft) governs.
>
> Short name: **NPAMP-HYBRIDKEM**. Status: **DRAFT**.

## 1. Purpose

The N-PAMP handshake key schedule is fed by the **raw concatenation** of two
component KEM shared secrets — no hybrid-layer KDF sits between the key
exchange and `HKDF-Extract` (`spec/06_cryptographic_suites.md`). Getting that
concatenation's *byte order* wrong is a silent, symmetric-self-interop-proof
bug class: two instances of the same wrong implementation still complete a
handshake with each other, and only a standards-anchored known-answer vector
or an independent peer catches it.

Every one of the ten target languages (Part-2 design, Tier-2 provider map)
obtains its ML-KEM and ECDH/ECDHE shared secrets from a *different* provider —
Go's `crypto/mlkem`/`crypto/ecdh`, Rust's RustCrypto or `liboqs-rust`,
`liboqs` bindings elsewhere, an OpenSSL 3.5/`oqs-provider` binding, and so on.
Re-implementing the per-group ordering rule inside each provider binding would
be exactly the kind of per-language reimplementation this adapter exists
to eliminate. This document specifies
the **one piece we author**: a small, provider-agnostic adapter that performs
only the combiner-order concatenation, so every language binds one shared rule
instead of re-deriving it.

## 2. Scope

**In scope:** the function-level contract for combining two already-computed
raw component shared secrets into the octet string a caller feeds to
`HKDF-Extract`, for the two hybrid-KEM groups N-PAMP defines
(`spec/06_cryptographic_suites.md`).

**Out of scope (non-goals):**

- Key generation, encapsulation, or decapsulation. The adapter never touches a
  private key, a ciphertext, or a public key — it consumes only the two
  already-computed shared-secret octet strings. Producing those is the
  provider's job (Requirement 2 acc.crit.1, the Tier-2 provider map).
- Any hybrid-layer KDF. There is none; `HKDF-Extract` (`RFC 5869`) is the only
  KDF step, and it is the caller's responsibility, not the adapter's.
- Wire encoding of `KEMShare` / `KEMCiphertext` (TLV `0x07`/`0x08`,
  `spec/10_handshake_binding.md` §4). Those orderings happen to match this
  adapter's combiner order for both groups but are a distinct, already-fixed
  concern the adapter does not implement.
- Any code point, channel, or TLV not already reserved by the core
  specification. This document consumes none.

## 3. Interface contract

The contract is stated language-agnostically first (per-language SDKs implement
it in that language's idiom); §3.3 gives the Go reference's concrete signature.

### 3.1 Inputs

| Input | Type | Constraint |
|---|---|---|
| `group` | a group selector | one of the two values in §4 (the N-PAMP KEM code point, reused directly — no separate enumeration) |
| `mlkem_ss` | raw octet string | exactly 32 octets (FIPS 203 ML-KEM shared-secret size, fixed for every ML-KEM parameter set) |
| `classical_ss` | raw octet string | 32 octets for `X25519MLKEM768` (RFC 7748 X25519); 48 octets for `SecP384r1MLKEM1024` (secp384r1 ECDH shared-secret x-coordinate, RFC 9846 §4.3.8.2) |

`mlkem_ss` and `classical_ss` are accepted exactly as any conforming ML-KEM
and ECDH/ECDHE provider produces them (§2 — the adapter performs no key
exchange itself and is indifferent to which provider produced its inputs).

### 3.2 Output and errors

| Output | Type | Constraint |
|---|---|---|
| combined secret | raw octet string | 64 octets for `X25519MLKEM768`; 80 octets for `SecP384r1MLKEM1024` (§4) |

Error conditions, all of which MUST be rejected rather than silently
truncated, padded, or coerced:

- `group` is not one of the two values in §4.
- `mlkem_ss` is not exactly 32 octets.
- `classical_ss` does not match the length §3.1 fixes for the given `group`.

### 3.3 Go reference signature

```go
package hybridkem // github.com/bubblefish-tech/npamp_protocol/impl/go/hybridkem

type Group uint16

const (
    X25519MLKEM768     Group = 0x11ec
    SecP384r1MLKEM1024 Group = 0x11ed
)

func Combine(group Group, mlkemSS, classicalSS []byte) ([]byte, error)
```

`Combine` takes no dependency on `crypto/mlkem`, `crypto/ecdh`, or any other
provider package — it operates on `[]byte` only, matching §2's non-goal that
the adapter never performs key exchange.

## 4. Combiner order (per-group, NOT universal)

Restated from `spec/06_cryptographic_suites.md` (which governs on conflict),
itself derived from `RFC 10024` (formerly `draft-ietf-tls-ecdhe-mlkem`, published
August 2026) applying the FIPS-approved-component-leads rule of NIST SP 800-56C
Rev. 2 per group:

| Group | Code point | Profiles | Combined-secret order | Combined length |
|---|---|---|---|---|
| `X25519MLKEM768` | `0x11ec` | Standard, High | `ML-KEM_ss \|\| X25519_ss` (**ML-KEM-first**) | 64 octets |
| `SecP384r1MLKEM1024` | `0x11ed` | High, Sovereign | `ECDHE_ss \|\| ML-KEM_ss` (**P-384/classical-first**) | 80 octets |

The suite *name* `X25519MLKEM768` lists the classical component first, but
the *bytes* are ML-KEM-first — `RFC 10024` records this
reversed naming as historical. `SecP384r1MLKEM1024` is the reverse: the
classical (FIPS-certified P-384) component leads. **An adapter that applies
one order to both groups is self-consistent and wrong** — it would produce a
Sovereign/High key schedule that diverges from every conformant peer while
still completing handshakes with itself. This is precisely the failure class
§1 describes, and the reason §6's cross-validation is mandatory, not optional.

## 5. Conformance

An implementation of this adapter conforms if, for both groups in §4, given
the RAW component shared secrets as input, it produces the combined secret in
exactly the order and length in §4 — and only in that order.

### 5.1 Vectors and grading (F3, non-circular)

Grading reuses the corpus already anchored to independent standards, rather
than defining a new vector set:

- **`X25519MLKEM768`**: `test-vectors/v1/kem-wire-kat.json` — NIST ACVP
  (FIPS 203 final, ML-KEM-768) decapsulation-reference shared secret, and the
  RFC 7748 §6.1 X25519 known-answer values. Neither is generated by this
  adapter or by the N-PAMP reference implementation.
- **`SecP384r1MLKEM1024`**: RFC 5903 §8.2 (384-Bit Random ECP Group / Group
  20) secp384r1 known-answer values, anchoring the classical component and
  therefore the ordering-critical half of the combined secret. No
  NIST-ACVP-anchored ML-KEM-1024 shared-secret vector exists in this corpus
  yet (tracked as a Part-2 ecosystem-spec gap); the ML-KEM-1024 component is
  exercised by round-trip through a real ML-KEM-1024 provider, matching the
  existing `impl/go/kem1024_kat_test.go` limitation, stated honestly rather
  than silently.

### 5.2 Cross-validation against the Go core

Beyond the standards-anchored vectors, a conforming adapter's output MUST be
byte-identical to the Go reference implementation's inline combiner
(`impl/go/kem.go` `SharedSecrets.Combined()`; `impl/go/kem1024.go`
`SharedSecrets1024.Combined()`) for the same component-secret inputs, for
both groups. `impl/go/hybridkem/hybridkem_kat_test.go` is the Go reference's
own such cross-check.

### 5.3 What this conformance class does NOT cover

Per `spec/companion/55_conformance_requirements.md`'s conformance-class
model: this document defines a narrow, library-level conformance surface (the
combiner ordering function only). It makes no claim about a full-handshake
implementation's conformance — that is Class H (`spec/companion/
55_conformance_requirements.md`) — and no claim about any specific
language's ML-KEM/ECDH provider binding, which is Requirement 2 acc.crit.1's
separate, per-language concern.

## 6. Rationale: why a shared adapter and not per-language reimplementation

`RFC 10024`'s (formerly `draft-ietf-tls-ecdhe-mlkem`) per-group ordering is easy to get right once
and easy to get wrong independently in ten languages, because it LOOKS like
it should be a fixed, memorizable convention ("ML-KEM first") and is not — it
is genuinely per-group. Centralizing the ordering rule in one small,
dependency-free function per language (ported from this same contract, not
reimplemented from memory) turns a class of subtle, symmetric-self-interop-
proof bugs into a single, independently-testable unit with its own
standards-anchored KAT. This is the "protocol helper" the production-gap
literature the Part-2 design cites identifies as missing from the PQC
tooling landscape generally, applied here to N-PAMP specifically.

## References

- `spec/06_cryptographic_suites.md` — the authoritative combiner-order
  statement this document restates.
- `spec/10_handshake_binding.md` §4 — the `KEMShare`/`KEMCiphertext` wire TLV
  layouts (a related but distinct concern; §2).
- `RFC 10024` (formerly `draft-ietf-tls-ecdhe-mlkem`, published August 2026) — the
  hybrid-KEM construction authority.
- NIST SP 800-56C Rev. 2 — the FIPS-approved-component-leads rule the
  per-group ordering applies.
- FIPS 203 (ML-KEM) — component shared-secret size (32 octets, all parameter
  sets).
- RFC 7748 §6.1 — X25519 known-answer vector (`X25519MLKEM768` anchor).
- RFC 5903 §8.2 — secp384r1 (P-384) known-answer vector
  (`SecP384r1MLKEM1024` anchor).
- RFC 9846 §4.3.8.2 — secp384r1 uncompressed point / shared-secret encoding.
- RFC 5869 — `HKDF-Extract`, the caller-side consumer of this adapter's
  output.
- The Part-2 ecosystem requirements (Requirement 2 acceptance criterion 2) and design
  (Tier-2 detail) — the requirement and design framing this document implements.
