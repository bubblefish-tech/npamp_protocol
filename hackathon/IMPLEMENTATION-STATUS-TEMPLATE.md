# N-PAMP implementation status + interop results (template)

This is a fill-in-place template for recording (a) an RFC 7942 (BCP 205)
"Implementation Status" entry per implementation, and (b) the interop-results
matrix from a specific event or test session (a hackathon, an interim interop
call, or an ad-hoc third-party test). **Nothing below is a real result** —
every bracketed field is a placeholder. Copy this file, rename it to the event
(e.g. `results/ietf-127-hackathon.md`), and fill it in as tests actually run.

> RFC 7942 §2 boilerplate (quoted verbatim, primary-sourced 2026-09-06 from
> `rfc-editor.org/rfc/rfc7942.txt`), reproduced here because this section is
> the pattern that section imitates:
>
> "Since this information is necessarily time dependent, it is inappropriate
> for inclusion in a published RFC. The authors should include a note to the
> RFC Editor requesting that the section be removed before publication."
>
> The same caveat applies here: this file is a **living, dated record**, not a
> permanent claim. Each entry below carries its own last-updated date for that
> reason.

---

## Part A — Implementation Status entries (RFC 7942 §2 fields)

One entry per implementation tested, **including implementations this project
does not author**. Add a new `###` block per implementation; do not overwrite
an existing one — append and update its "Last updated" field instead, so the
history of who has implemented N-PAMP over time is preserved.

### Reference implementation: N-PAMP Go (`impl/go`)

- **Organization:** BubbleFish Technologies, Inc.
- **Implementation:** `github.com/bubblefish-tech/npamp_protocol/impl/go` —
  <https://github.com/bubblefish-tech/npamp_protocol> (public reference home)
- **Description:** Reference implementation of the N-PAMP handshake, record
  layer, channel model, and wire codecs, built on Go's standard-library
  `crypto/mlkem`, `crypto/ecdh`, and `crypto/ed25519`.
- **Maturity:** prototype / pre-1.0 reference (tracks an Internet-Draft, not
  yet a shipped product SDK).
- **Coverage:** the full 1.5-RTT mutually-authenticated handshake (Standard
  profile, `X25519MLKEM768` + Ed25519), the AES-256-GCM record layer, channel
  multiplexing, the CBOR-based frame codecs, and the conformance corpus's
  Go-side adapter.
- **Version compatibility:** `draft-bubblefish-npamp-01`; wire-format version
  2, crypto generation 3 (ALPN `n-pamp/3`).
- **Licensing:** Apache-2.0.
- **Implementation experience:** [fill in at event — e.g. any spec ambiguity
  hit while another team implemented against this reference].
- **Contact:** see `MAINTAINERS.md` in the repository root.
- **Last updated:** 2026-09-06.

### Reference implementation: N-PAMP Rust (`impl/rust`)

- **Organization:** BubbleFish Technologies, Inc.
- **Implementation:** `impl/rust` in
  <https://github.com/bubblefish-tech/npamp_protocol> (crate name `npamp`; not
  yet published to crates.io as of this writing — build from source).
- **Description:** Independent (non-shared-codebase) reference implementation
  built on RustCrypto primitives and the `ml-kem` crate; the second
  independent stack required by R2.1/goal 1.
- **Maturity:** prototype / pre-1.0 reference.
- **Coverage:** the same handshake + record layer as the Go reference, plus
  the multi-profile entry points (Standard / High / Sovereign,
  `spec/05_profiles.md`) including `SecP384r1MLKEM1024` + ML-DSA-87 CertVerify
  for High/Sovereign.
- **Version compatibility:** `draft-bubblefish-npamp-01`; wire-format version
  2, crypto generation 3.
- **Licensing:** Apache-2.0.
- **Implementation experience:** [fill in at event].
- **Contact:** see `MAINTAINERS.md` in the repository root.
- **Last updated:** 2026-09-06.

### Third-party implementation: [NAME]

- **Organization:** [org or individual]
- **Implementation:** [name + link, e.g. a GitHub repo]
- **Description:** [one or two sentences]
- **Maturity:** [research / prototype / alpha / beta / production / widely used]
- **Coverage:** [which parts of the handshake/record layer/profiles are
  implemented — be specific; "the whole protocol" is not a coverage statement]
- **Version compatibility:** [which draft revision / wire-format version /
  crypto generation this implementation targets]
- **Licensing:** [terms]
- **Implementation experience:** [anything useful for the community — spec
  ambiguities found, surprises, requests]
- **Contact:** [name + email, or a URL/mailing list]
- **Last updated:** [YYYY-MM-DD]

---

## Part B — Interop results matrix

Fill in one row per direction actually tested. "Reference" = an implementation
from this repository (Go or Rust); "Peer" = the other party's implementation.
An entry with no peer name recorded is not a third-party result — say so.

| # | Date (UTC) | Event / session | Server | Client | Profile | KEM group negotiated | Sig alg negotiated | Result | Notes / error text |
|---|---|---|---|---|---|---|---|---|---|
| 1 | [YYYY-MM-DD] | [e.g. IETF 127 Hackathon] | [impl + org] | [impl + org] | [standard/high/sovereign] | [e.g. X25519MLKEM768 (0x11ec)] | [e.g. Ed25519] | [PASS/FAIL] | [free text; quote the exact error on FAIL] |
| 2 | | | | | | | | | |

### Reading this matrix honestly

- A **PASS** row means: a live, freshly-keyed handshake completed and at least
  one AEAD-protected application frame round-tripped byte-identically, between
  the two named implementations, in the stated roles, over a real network
  connection (not a mock, not an in-process pipe).
- A PASS row is **interop** evidence, not **conformance** evidence. Two
  implementations can interoperate while both diverging from the specification
  identically. Do not describe a PASS row as "conformant" — cross-reference the
  named implementation's own conformance-suite result (Part A "Coverage" +
  whatever the implementer separately ran against an independent oracle, e.g.
  NIST ACVP vectors) before making any conformance claim.
- A row with only this project's own two reference implementations in both the
  Server and Client columns is **not** third-party interop — it duplicates
  what `impl/go/cmd/npamp-interop`'s CI-graded matrix (`.github/workflows/
  interop.yml`) already exercises on every push, and should be labeled as such
  rather than presented as new evidence.

---

## Part C — Session summary (fill in once, at the end)

- **Event:** [name, dates, location — cite the event's official page]
- **Participants:** [organizations/individuals who ran an implementation]
- **Directions tested:** [N]; **third-party directions:** [N of those N]
- **Profiles exercised:** [standard / high / sovereign — which]
- **Honest gaps:** [what was NOT tested — e.g. "no High-profile third-party
  peer was available"; "only loopback, no real network segment was tested";
  "conformance corpus was not re-run against the third-party implementation
  because no adapter for it exists yet in `harness/adapters/`"]
- **Follow-ups filed:** [links to issues/tracker items opened as a result]
