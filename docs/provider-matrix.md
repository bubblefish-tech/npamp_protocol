# N-PAMP cryptographic provider matrix (ML-KEM + classical ECDH)

*Requirement R2.1. Dated 2026-08-21; every version and date below was confirmed against a
primary source (the vendor's own release page, package registry, or standards document) on
that date. Provider ecosystems move quickly — re-confirm any row before it gates a build
decision.*

N-PAMP's two hybrid key-exchange groups each combine a post-quantum ML-KEM component with a
classical elliptic-curve Diffie–Hellman component:

- **X25519MLKEM768** (code point `0x11ec`; Standard/High profiles) — ML-KEM-768 + X25519.
- **SecP384r1MLKEM1024** (code point `0x11ed`; High/Sovereign profiles) — ML-KEM-1024 + P-384.

The [hybrid-KEM combiner adapter](../spec/companion/90_hybrid_kem_adapter.md) is
**provider-agnostic**: it consumes the two *raw* component shared secrets a language's own
ML-KEM and ECDH providers produce, and concatenates them in the per-group order fixed by
Part-1 R1.5. This document records which provider each reference SDK language should use to
produce those two component secrets. It is implementation guidance, not a wire specification —
the wire bytes are fixed by the spec regardless of which library computes them.

## Ecosystem baseline

- **OpenSSL 3.5.0** (released 2025-04-08, an LTS line supported to 2030-04-08) ships native
  ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205) in its default provider, and
  changed its default TLS key shares to offer `X25519MLKEM768`. From 3.5 onward, standard
  ML-KEM needs no add-on provider. **OpenSSL 3.6.0** (2025-10-01) carries the same PQC
  baseline forward.
- **liboqs 0.16.0** (2026-07-09) implements ML-KEM via the PQCP `mlkem-native` project.
  **oqs-provider 0.11.0** (2025-12-24) now *defers to* OpenSSL's own ML-KEM/ML-DSA on hosts
  running OpenSSL ≥ 3.5, rather than shipping a competing implementation. liboqs remains
  useful as an independent cross-check source and for hosts pinned below OpenSSL 3.5.
- **FIPS boundary caveat:** "ML-KEM is present in the OpenSSL 3.5 *library*" is a separate
  claim from "ML-KEM is in a FIPS-140-3-validated OpenSSL *module*" — the two are validated on
  different CMVP timelines. Whether a deployment needs library-level or validated-module-level
  PQC is a per-deployment decision, tracked in the crypto-agility runbook (E0.3), not here.
- **Profile alignment:** the SecP384r1MLKEM1024 group (ML-KEM-1024 + P-384) is the one aligned
  with an ML-KEM-1024-only posture; X25519MLKEM768 (ML-KEM-768) is the broader-interop group.
  This mirrors `RFC 10024`'s (formerly `draft-ietf-tls-ecdhe-mlkem`) own two-suite structure.

## Per-language provider matrix

| Language | Recommended ML-KEM provider | Version / date | Classical half (X25519 / P-384) | Maturity |
|---|---|---|---|---|
| **Go** | stdlib `crypto/mlkem` | Go 1.24 (2025-02-11) | stdlib `crypto/ecdh` | Native — the reference path; no external dependency |
| **Rust** | RustCrypto `ml-kem` (pure Rust) or `aws-lc-rs` | `ml-kem` 0.3.2 (2026-05-10) | `aws-lc-rs` (bundled) or `p384` + `x25519-dalek` | Solid; `ml-kem` `hazmat` exposes deterministic encaps for KATs |
| **Python** | pyca `cryptography` (native, Rust-backed) | 48.0.0 (2026-05-04) | `cryptography` hazmat EC | Solid; ecosystem-standard library, zero new supply-chain surface |
| **JavaScript / TypeScript (Node)** | built-in `node:crypto` | Node 24+ (confirmed on v26.7.0 docs) | `node:crypto` (X25519, secp384r1) | Native; needs Node's linked OpenSSL/BoringSSL ≥ 3.5. Browser/edge fallback: `@noble/post-quantum` |
| **Java** | Bouncy Castle via `javax.crypto.KEM` (Java 17+) | BC 1.84 (2026-05-12); FIPS path BC-FJA 2.1.0 | BC X25519 / secp384r1 | Solid; de-facto JVM PQC standard (no OpenJDK built-in yet) |
| **C# / .NET** | `System.Security.Cryptography.MLKem` (Linux/Windows) | .NET 10 (2025-11) | `ECDiffieHellman` (P-384); BC for X25519 | Native on Linux/Windows; **macOS gap** → BouncyCastle.Cryptography 2.7.0 (self-labeled *experimental*), native macOS deferred to .NET 11 |
| **Ruby** | *no mature native binding yet* | tracked at `ruby/openssl#894` (open) + `bugs.ruby-lang.org` #22068 (open) | `OpenSSL::PKey` (X25519, P-384) | **Gap** — the `ruby/openssl` gem's PQC path (provider-pkey passthrough) will inherit ML-KEM once the tracking issue lands against OpenSSL ≥ 3.5; not shipped as of 2026-08-21. See notes |
| **PHP** | `paragonie/ext-pqcrypto` (Rust-backed extension) | 0.1.0 (2026-04-07) | core `openssl` ext (X25519, P-384) | Workable; core PHP `openssl` does not expose ML-KEM (absent from the PHP 8.6 RFC roster) → a non-core extension is required |
| **Swift** | SwiftKyber (pure Swift, cross-platform) | 3.5.0 (2026-04-21); deterministic `DeriveKeyPair` since 3.4.0 | CryptoKit `Curve25519` / `P384` | Solid; NIST-ACVP-sourced KAT suite (F3-clean). Preferred over Apple CryptoKit (Apple-platform-only) |

## The Go reference provider path (already wired)

The Go reference implementation already sources both component secrets from the standard
library, with no external cryptographic dependency:

- `impl/go/kem.go` — X25519MLKEM768: `crypto/mlkem` (`GenerateKey768` / `Encapsulate` /
  `Decapsulate`) + `crypto/ecdh` (`X25519`).
- `impl/go/kem1024.go` — SecP384r1MLKEM1024: `crypto/mlkem` (`GenerateKey1024` …) +
  `crypto/ecdh` (`P384`).

`impl/go/hybridkem/provider_path_test.go` demonstrates the end-to-end path in isolation: it
runs a live X25519MLKEM768 and a live SecP384r1MLKEM1024 exchange using those stdlib providers,
then feeds the resulting raw component secrets into the standalone combiner adapter
(`hybridkem.Combine`) and asserts the adapter reproduces the reference key-schedule input
byte-for-byte, in the correct per-group order (ML-KEM-first for 0x11ec, P-384-first for
0x11ed). This is the concrete link between the provider (E0.2) and the combiner spec (E0.1).

## Notes, gaps, and pre-E1 checks

- **Ruby is the one language without a mature native ML-KEM path today.** The `ruby/openssl`
  gem (latest 4.0.2, 2026-05-13) tracks PQC support upstream at `ruby/openssl#894`, and the
  broader Ruby-stdlib effort is `bugs.ruby-lang.org` Feature #22068 — both open and in active,
  dated development as of 2026-08-21. There is no OQS-official liboqs-ruby wrapper and no
  dedicated ML-KEM gem was located. The Ruby SDK's live ML-KEM path is therefore an **E1
  prerequisite to re-confirm**, not a settled dependency: re-check whether the tracking issue
  has landed before the Ruby stack is built, since the upstream work is moving.
- **PHP** has no core-`openssl` ML-KEM (confirmed absent from the PHP 8.6 RFC roster); it
  depends on a non-core extension (`paragonie/ext-pqcrypto`, or a liboqs FFI binding). This is
  a deployment-friction note, not a blocker.
- **Deterministic / seed-based keygen** (needed to drive standards-anchored known-answer
  vectors through the real code path) is confirmed present for Go, Rust, Node, and Swift. For
  **Python `cryptography`, Java Bouncy Castle, .NET, and PHP `ext-pqcrypto`**, the exact
  deterministic-keygen call surface was not confirmed in this pass — verify it before wiring
  each language's KAT harness (a pre-E1 to-do, tracked per language).
- **CNSA 2.0 posture** (ML-KEM-1024-only, milestone dates) is recorded from secondary
  summaries in this pass; open the NSA CNSA 2.0 FAQ directly before any CNSA-2.0 conformance
  claim.

*Full research provenance (primary sources, methodology, and the complete limitations list) is
retained in the internal Part-2 build notes.*
