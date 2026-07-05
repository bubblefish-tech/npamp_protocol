# N-PAMP-01 — Cryptographic Suites (reference)

> **Derived extract.** Authoritative source: `../ietf/draft-bubblefish-npamp-latest.md`
> (revision draft-bubblefish-npamp-01; integrity pinned in ../PIN.json), §7 "Cryptographic Suites". The draft governs.
> Machine-readable: `../registries/{kem,aead,signatures}.csv`.
>
> All primitives are published standards.

## Key Encapsulation Mechanisms (KEM)

| Code point | Name | Profiles |
|---|---|---|
| 0x11ec | X25519MLKEM768 | Standard, High |
| 0x11ed | X25519MLKEM1024 | High, Sovereign |

Both are hybrid KEMs combining X25519 ECDH with ML-KEM (FIPS 203): ML-KEM-768 and
ML-KEM-1024 respectively. The two shared secrets are concatenated as
`(ML-KEM shared secret || X25519 shared secret)` — ML-KEM first, so the
FIPS-approved key-establishment output leads the HKDF input (NIST SP 800-56C
Rev. 2) — and supplied as input keying material to HKDF-Extract (RFC 5869). This
matches the X25519MLKEM768 construction of draft-ietf-tls-ecdhe-mlkem §4.3: the
suite name lists X25519 first, but the shared-secret concatenation and the on-wire
KEMShare / KEMCiphertext layout are deliberately ML-KEM-first (see ADR-0005).
**The Sovereign profile MUST NOT accept X25519MLKEM768.**

## Authenticated Encryption (AEAD)

| Code point | Name | Key | Nonce | Tag |
|---|---|---|---|---|
| 0x0001 | AES-256-GCM | 32 | 12 | 16 |
| 0x0002 | ChaCha20-Poly1305 | 32 | 12 | 16 |

AES-256-GCM per RFC 5116; ChaCha20-Poly1305 per RFC 8439. High and Sovereign
endpoints **MUST support both** (per-frame AEAD diversification selects between
them). Standard endpoints MUST support at least one.

## Signatures

| Code point | Name | Usage | Profiles |
|---|---|---|---|
| 0x0807 | Ed25519 | Identity, capability tokens | All |
| 0x0905 | ML-DSA-87 | Identity, audit epoch | High, Sovereign |

Ed25519 per RFC 8032; ML-DSA-87 per FIPS 204. The Sovereign profile uses
**ML-DSA-87** for identity and audit signatures.

## Key Derivation and Hashing

All key derivation uses HKDF (RFC 5869). KDF hash is **SHA-256 at Standard** and
**SHA-384 at High and Sovereign**. HKDF-Expand-Label follows TLS 1.3 (RFC 8446)
but **with a protocol-specific label prefix** that provides domain separation from
TLS 1.3, from QUIC, and from earlier N-PAMP versions. (A literal `"tls13 "` prefix
does NOT satisfy this and is non-conformant.)

## Key Schedule and Nonces

Traffic secrets are derived **per (direction, epoch, AEAD suite, channel) tuple**,
so no two distinct contexts share a key. Each traffic secret yields an AEAD key, an
AEAD IV, and a header-protection key via HKDF-Expand-Label.

**The per-frame nonce is the AEAD IV exclusive-ORed with the left-zero-padded
sequence number, identical in form to TLS 1.3 (RFC 8446) and QUIC (RFC 9001).**
(The Channel ID is NOT part of the nonce; a Channel-ID-in-nonce construction is
non-conformant.) This namespace partitioning prevents cross-direction, cross-suite,
and cross-channel nonce reuse and supports forward secrecy: on key update, new-epoch
secrets are derived afresh and the prior epoch's secrets are **zeroized**.

## Random Number Generation

All security-participating randomness MUST come from a cryptographically secure RNG.
Implementations MUST NOT use a non-cryptographic source for any security field.
