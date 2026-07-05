# N-PAMP wire-version lineage

This file is the **public** narrative of how N-PAMP's wire protocol reached
`draft-bubblefish-npamp-00`. It records what is publishable and orients a reader in the
version history; the authoritative rationale for each change lives in the linked ADRs under
`decisions/`. It is descriptive, not normative — where it and the spec or ADRs differ, the
spec (`ietf/draft-bubblefish-npamp-latest.md`, `spec/`) and the ADRs govern.

## What this file does NOT contain (non-scope)

- **Controlled cryptographic extensions and the controlled protocol generation that carried
  them.** These are maintained privately and are excluded from every public artifact by
  **ADR-0004**; describing their construction here is out of scope by policy, not omission.
- **The proprietary per-profile cryptographic delta for the High and Sovereign profiles**
  (non-standard composites/extensions) beyond the public draft's structure. The published profile
  table — all three profiles — lives in `spec/05_profiles.md`; only the *non-standard* delta is
  excluded (**ADR-0004**). Which profiles a given *product* runs at runtime is a separate edition
  choice (**ADR-0003**), not a publication boundary.
- **A complete internal history.** Because the controlled generation is intentionally omitted,
  this is the *public* lineage, not the full one.

## Public wire-version identifiers (ALPN)

N-PAMP negotiates its application protocol with an ALPN identifier whose trailing digit equals
the wire **major** version carried in the frame header `Ver` field
(draft §"Wire Format"; draft §"IANA Considerations"):

| ALPN | Wire major (`Ver`) | Status |
|---|---|---|
| `n-pamp/1` | 1 | **Deprecated** — implementations SHOULD NOT negotiate it for new associations (draft §IANA, "Requested ALPN registration") |
| `n-pamp/2` | 2 (`0x02`) | **Current** — defined by `draft-bubblefish-npamp-00` |

Future wire major versions will use distinct identifiers (for example `n-pamp/3`) (draft §IANA).

## Protocol generations

The public draft is the latest of several protocol generations:

1. **v1** — the generation associated with the now-deprecated `n-pamp/1` wire identifier
   (draft §IANA).
2. **An intermediate controlled generation** — a controlled-access line between v1 and the
   published draft. It is the earlier protocol that the prior formal-methods artifacts targeted
   (`formal/README.md`). Its material is maintained privately and is **excluded from this public
   repository by ADR-0004**; it is noted here only to place the public draft in sequence, not
   described.
3. **draft-00 (`n-pamp/2`)** — the **first published** generation: `ietf/draft-bubblefish-npamp-latest.md`
   + `spec/` + the reference implementations under `impl/`. Its public design decisions are
   indexed below.

> `formal/README.md` notes only that the **prior proof artifacts modeled that earlier
> protocol, not draft-00** (and that two overstated their results); re-targeting them is
> gated on the draft-01 binding. No intermediate-generation protocol detail is published here.

## Public design decisions at draft-00 (index into `decisions/`)

Each item links to the ADR that records the full rationale:

- **Where N-PAMP is developed, and the public/controlled boundary.** N-PAMP is developed in a
  dedicated repository; a public slice is published here while controlled material is maintained
  separately. Consuming products *vendor* the reference implementation and *pin* the conformance
  corpus. The public/controlled split is structural (publishable slice vs. controlled material)
  and mechanically scanned. **ADR-0004**.
- **One wire format and one construction for all profiles.** The draft's three escalating
  security profiles (Standard, High, Sovereign) share a single handshake construction,
  parameterized per profile: the KDF hash is the consequential parameter (it changes secret and
  transcript-hash lengths, not the construction), and the other parameter rows differ too — see
  ADR-0003's profile table. Open-edition products implement the Standard row. **ADR-0003**.
- **Hybrid KEM combiner aligned to ML-KEM-first.** The `X25519MLKEM768` (`0x11ec`) shared
  secret and on-wire layout were aligned to **ML-KEM-first**, matching the codepoint's defining
  document and the NIST SP 800-56C Rev. 2 ordering (the FIPS-approved output is the first HKDF
  input). Recorded with its root cause — a "wrong source of authority" lapse, where the generic
  hybrid framework was cited in place of the codepoint-specific document. This change superseded
  all handshake KAT golden vectors and "interop verified" runs produced before 2026-06-22.
  **ADR-0005**.
- **A single normative 1.5-RTT handshake binding** (`spec/10_handshake_binding.md`). It reuses
  RFC 8446 constructions (HKDF-Expand-Label with the `"n-pamp "` label prefix; the
  CertificateVerify signing input with N-PAMP context strings; Finished) and accepts three
  documented divergences from TLS 1.3 — a per-TLV transcript, a single HKDF-Extract key
  schedule, and the ML-KEM-first KEM. Targeted for draft-01 ratification. **ADR-0006**.
- **Standards-derived, non-circular conformance KATs.** The handshake layer is graded against
  published standards (FIPS 180-4, RFC 4231, RFC 8032, RFC 8446 / 8448 / 5869, FIPS 203,
  RFC 7748), not against self-interop: KEM-wire, key-schedule, transcript, Finished, and
  CertVerify, against SHA-256-pinned vectors (`MANIFEST.sha256`). The **transcript / Finished /
  CertVerify** KATs are now mirrored non-circularly across **all nine reference implementations** —
  Go as the reference implementation; TypeScript / Python / Java / Kotlin / Ruby / PHP / Rust / C# under
  `impl/` — enforced by `impl/_conformance-harness/kat-handshake-all-langs.sh`. The **KEM-wire** and
  **key-schedule** KATs are anchored on the Go reference; broadening them across the other languages
  is follow-on (the key schedule's HKDF-Extract / secret-ladder is a consumer-layer construction;
  KEM-wire needs a per-language ML-KEM). **ADR-0007 … ADR-0011**.

## Deprecations and supersessions (public)

- **`n-pamp/1` is deprecated** (draft §IANA). New associations SHOULD negotiate `n-pamp/2`.
- **Pre-2026-06-22 handshake KAT goldens and "interop verified" runs are superseded** by the
  ML-KEM-first alignment (**ADR-0005**).
- **The prior formal proofs (targeting the earlier generation) do not transfer to draft-00** and are not claimed
  here; re-targeting is gated on the draft-01 binding (`formal/README.md`, **ADR-0006**).
- **v1-era external tooling is retired and is not part of draft-00.** An earlier (v1) Kotlin adapter
  and the v1-era conformance vectors were superseded by the draft-00 multi-language reference
  implementations under `impl/` (which carry `n-pamp/2`) and the standards-anchored corpus under
  `test-vectors/`. The retired v1 artifacts are held externally/privately and are excluded from this
  public repository by **ADR-0004**; they are not referenced anywhere in this tree. This is distinct
  from the *current* `impl/kotlin/` draft-00 reference implementation, which is active.

## Forward

draft-01 is expected to ratify the handshake binding (`spec/10`) and to provide the precise
target for re-running the formal-methods analysis (`formal/`). Future wire major versions will
take new ALPN identifiers (draft §IANA).

## See also

- `decisions/` — the full ADR log (Nygard-style; ADR-0001 records the decision-recording
  process itself).
- `README.md` — repository model, structure, and versioning.
- `CONTRIBUTING.md` — the change / decision process.
- `ietf/draft-bubblefish-npamp-latest.md`, `spec/` — the normative protocol text.
