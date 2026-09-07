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
| 0x11ed | SecP384r1MLKEM1024 | High, Sovereign |

Both are hybrid KEMs combining an elliptic-curve ECDH with ML-KEM (FIPS 203), per
RFC 10024 (formerly `draft-ietf-tls-ecdhe-mlkem`, published August 2026).
**The concatenation order is per-group** — for each
group it places the FIPS-approved component first as its defining construction
requires (NIST SP 800-56C Rev. 2), so the two groups differ:

- **X25519MLKEM768 (`0x11ec`)** combines X25519 with ML-KEM-768, **ML-KEM-first**:
  shared secret `(ML-KEM-768 SS || X25519 SS)`; KEMShare `ML-KEM-768 ek (1184) ||
  X25519 pub (32)` = 1216; KEMCiphertext `ML-KEM-768 ct (1088) || server X25519 pub
  (32)` = 1120. The suite name lists X25519 first, but the bytes are ML-KEM-first
  (RFC 10024 records this reversed order as historical; ADR-0005).
- **SecP384r1MLKEM1024 (`0x11ed`)** combines secp384r1 (P-384) with ML-KEM-1024,
  **ECDHE-first (P-384 first)**: shared secret `(ECDHE SS (48) || ML-KEM-1024 SS
  (32))` = 80; KEMShare `secp384r1 pub (97) || ML-KEM-1024 ek (1568)` = 1665;
  KEMCiphertext `server secp384r1 pub (97) || ML-KEM-1024 ct (1568)` = 1665.

Both feed the concatenation raw to HKDF-Extract (RFC 5869) as input keying material
(no hybrid-layer KDF). **The Sovereign profile MUST NOT accept X25519MLKEM768.**

## Authenticated Encryption (AEAD)

| Code point | Name | Key | Nonce | Tag |
|---|---|---|---|---|
| 0x0001 | AES-256-GCM | 32 | 12 | 16 |
| 0x0002 | ChaCha20-Poly1305 | 32 | 12 | 16 |

AES-256-GCM per RFC 5116; ChaCha20-Poly1305 per RFC 8439. **AES-256-GCM (`0x0001`)
is Mandatory-To-Implement in every profile**, so two conformant endpoints always
share at least one AEAD — a non-empty MUST-support intersection for every
profile × algorithm class (the Danvers Doctrine, BCP 61). Standard endpoints MUST
support AES-256-GCM and MAY additionally support ChaCha20-Poly1305. High and
Sovereign endpoints **MUST support both** (per-frame AEAD diversification selects
between them).

### Per-frame AEAD selection

At High and Sovereign, per-frame AEAD diversification selects the AEAD suite for
each frame **deterministically from the sequence number, with no per-frame wire
flag**: the suite is `AEADSelect[seq mod N]`, where `AEADSelect` is the negotiated
ordered list of selectable suites (primary first) and `N` is its length. Both peers
derive the same suite from the shared per-(channel, direction) sequence number, so
no per-frame suite indicator is carried on the wire. At Standard, diversification is
off: `AEADSelect` names a single suite and every frame uses it.

Consequently **`AEADSelect` (TLV `0x0D`) carries every suite the selection can index
— a variable-length list of 2-octet AEAD code points, primary first** (one code
point at Standard; both suites at High and Sovereign). The former fixed 2-octet
encoding cannot stand while two suites must be selectable. The selector output is
frozen by a known-answer test (`impl/go/aead_select_test.go`): for the list
`[AES-256-GCM, ChaCha20-Poly1305]`, frames 0, 1, 2, … use AES, ChaCha, AES, ….

## Signatures

| Code point | Name | Usage | Profiles |
|---|---|---|---|
| 0x0807 | Ed25519 | Identity, capability tokens | All |
| 0x0904 | ML-DSA-44 | Reserved (IANA TLS SignatureScheme); unused | — |
| 0x0905 | ML-DSA-65 | Reserved (IANA TLS SignatureScheme); unused | — |
| 0x0906 | ML-DSA-87 | Identity, audit epoch | High, Sovereign |

The ML-DSA code points reference the IANA TLS SignatureScheme registry
(`draft-ietf-tls-mldsa`): 0x0904 = ML-DSA-44, 0x0905 = ML-DSA-65, 0x0906 = ML-DSA-87.
N-PAMP negotiates only **ML-DSA-87 (0x0906)** at High and Sovereign; 0x0904/0x0905 are
listed so N-PAMP's namespace does not shadow the IANA values. Ed25519 per RFC 8032;
ML-DSA-87 per FIPS 204.

**Registry authority.** For every code point it shares with the IANA TLS registries —
the Supported-Groups KEM values (`0x11ec`, `0x11ed`) and the SignatureScheme values
(`0x0807`, `0x0904`–`0x0906`) — N-PAMP references the IANA value with its exact
semantics; it defines no code point that shadows an occupied IANA assignment (R15).

The hybrid-KEM construction authority is `RFC 10024` (formerly the Internet-Draft
`draft-ietf-tls-ecdhe-mlkem`, published August 2026) — cited directly as a published
RFC. The ML-DSA code points `draft-ietf-tls-mldsa` remain an active Internet-Draft;
update that citation to its assigned RFC number on publication.

## Key Derivation and Hashing

All key derivation uses HKDF (RFC 5869). KDF hash is **SHA-256 at Standard** and
**SHA-384 at High and Sovereign**. HKDF-Expand-Label follows TLS 1.3 (RFC 9846)
but **with a protocol-specific label prefix** that provides domain separation from
TLS 1.3, from QUIC, and from earlier N-PAMP versions. (A literal `"tls13 "` prefix
does NOT satisfy this and is non-conformant.)

## Key Schedule and Nonces

Traffic secrets are derived **per (direction, epoch, AEAD suite, channel) tuple**,
so no two distinct contexts share a key. Each traffic secret yields an AEAD key and
an AEAD IV via HKDF-Expand-Label. (Header protection is provided by the secure
transport; N-PAMP derives no separate header-protection key.)

**The per-frame nonce is the AEAD IV exclusive-ORed with the left-zero-padded
sequence number, identical in form to TLS 1.3 (RFC 9846) and QUIC (RFC 9001).**
(The Channel ID is NOT part of the nonce; a Channel-ID-in-nonce construction is
non-conformant.) This namespace partitioning prevents cross-direction, cross-suite,
and cross-channel nonce reuse and supports forward secrecy: on key update, new-epoch
secrets are derived afresh and the prior epoch's secrets are **zeroized**.

Within a single (direction, epoch, AEAD suite, channel) key, **sequence-number
assignment MUST be atomic and single-writer**: each frame MUST be sealed under
exactly the sequence number it was assigned, so a multi-threaded sender cannot reuse
a sequence number (and therefore a nonce) under one key. An endpoint MUST perform a
key update before the negotiated AEAD's usage limit is reached and MUST NOT let the
sequence space wrap within an epoch. Cross-(direction, epoch, suite, channel) reuse
is structurally prevented by the key separation above; this rule covers the
remaining intra-key case.

## Random Number Generation

All security-participating randomness MUST come from a cryptographically secure RNG.
Implementations MUST NOT use a non-cryptographic source for any security field.
