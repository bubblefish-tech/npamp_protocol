---
status: "accepted"
date: 2026-07-11
decision-makers: [BubbleFish Technologies, Inc.]
consulted: []
informed: []
---

# CertVerify context string uses the wire protocol version ("N-PAMP/2"), not a draft number

## Context and Problem Statement

The CertVerify signature (spec/10 §6.1) covers `signing_input = 0x20×64 || context || 0x00 ||
transcript_hash`, adapted from RFC 8446 §4.4.3. The `context` is a domain-separation string. It was
`"N-PAMP draft-00, {server,client} CertificateVerify"` — the RFC 8446 construction with TLS's stable
version substituted by an N-PAMP **draft number**.

A draft number inside a cryptographic domain separator goes stale every revision: it reads "draft-00"
while the document is on draft-01, would read "draft-01" on draft-02, and would still say "draft-00"
in the eventual RFC. The literal value of a domain separator is cryptographically arbitrary — it only
needs to be unique per (protocol, role) and identical across implementations — so the question is
purely one of longevity and clarity, and a draft number is the wrong axis to encode.

Note the three distinct "version" numbers that this decision disentangles:
- **document revision** — `draft-01` (which revision of the written spec); unchanged by this decision.
- **wire protocol major version** — `2`, already advertised on the wire as ALPN `n-pamp/2` and the
  frame-header version nibble `0x2` (analogous to `HTTP/2` or `TLS 1.3`).
- **the CertVerify context string** — the domain-separation label, the subject of this decision.

## Decision Drivers

* Precedent: RFC 8446 §4.4.3 uses `"TLS 1.3, {role} CertificateVerify"` — the **protocol version**,
  not the draft number. TLS 1.3 went through 28 drafts; the label was never "TLS 1.3 draft-28", and
  the final RFC kept "TLS 1.3".
* A domain separator should be stable across document revisions and the eventual RFC.
* It must remain unique and identical across all reference implementations.

## Decision

Use the **wire protocol major version** in the context string:

```
context (server) = "N-PAMP/2, server CertificateVerify"
context (client) = "N-PAMP/2, client CertificateVerify"
```

`/2` ties the separator to the protocol's own wire major version (ALPN `n-pamp/2`), exactly as TLS
uses `"TLS 1.3"`. It is stable across all future draft revisions and the RFC, and changes only on a
genuine wire-major bump (to `/3`). This is NOT a draft version — the document remains N-PAMP draft-01.

## Consequences

* **Wire-breaking**: the context is inside the signed input, so every CertVerify signature changes,
  and the SERVER_AUTH/CLIENT_AUTH frames + downstream transcript points (th_scv, th_cid, th_ccv) +
  Finished MACs + master secret all change. `TH_sId`/`TH_cId` (the pre-CertVerify transcript inputs)
  are unchanged.
* Applied as one coordinated change: the context constants in all ten reference impls (go, csharp,
  java, kotlin, php, python, ruby, rust, swift, typescript); spec/10 §6.1; the IETF draft §6.1; the
  byte-pinned worked example (companion/56, hex + byte math 138 → 131); the regenerated
  `test-vectors/v1/certverify-kat.json` (RFC 8032-anchored Ed25519 recomputed over the new
  signing_input) and `handshake-flow-kat.json` (deterministic generator); and re-pinned MANIFEST.sha256
  + PIN.json + the python inline vector-hash guard.
* Verified: Go module + vet clean; the 9-language cross-implementation KAT gate is ALL PASS against
  the new vectors; verify-pins PINS OK.
* Descriptive prose that names the draft revision ("the draft-00 binding", KAT `spec`/`description`
  fields) is a separate concern and is intentionally left as-is by this decision.
* Any already-deployed consumer pinned to the old signature carries it until it adopts an SDK
  version that includes this change; because the change is wire-breaking, such consumers must
  adopt it together to remain interoperable with each other.

Commit: a94bfd5 (npamp_protocol).
