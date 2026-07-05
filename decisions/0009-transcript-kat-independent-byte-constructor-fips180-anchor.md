---
status: "accepted"
date: 2026-06-24
decision-makers: [BubbleFish Technologies, Inc.]
consulted: []
informed: []
---

# Transcript KAT: non-circularity via an independent per-TLV byte-constructor anchored to FIPS 180-4

## Context and Problem Statement

Spec/10 §8 requires a non-circular transcript KAT covering the five transcript-hash points
(`TH_kem`/`TH_sId`/`TH_sCV`/`TH_cId`/`TH_cCV`). The transcript construction (spec §3) is
N-PAMP-original: it deliberately diverges from RFC 8446 §4.4.1 by absorbing only the
2-octet frame type (not the rest of the 36-octet frame header) and hashing at **per-TLV**
granularity (`Type(2)‖Length(2)‖Value`) so the bundled AUTH frame can be cut at sub-frame
boundaries. Because the construction is N-PAMP-original, no external standard publishes the
`TH_*` output bytes — so, as with the key-schedule KAT (ADR-0008), the KAT cannot anchor its
outputs to a published vector directly. How is it made non-circular?

## Decision Drivers

* Non-circularity (E8): expected `TH_*` must not be produced by the `Transcript` type under test.
* The expected outputs must trace to a standard primitive despite the N-PAMP-original construction.
* Must pin the §3/§7.1 divergence (frame-type-only, per-TLV) so a future header-creep or
  per-message regression is caught.

## Considered Options

* **(A) Independent byte-constructor + FIPS-180-4-anchored SHA-256.** Compute the expected `TH_*`
  with a standalone constructor (frame-type BE2; per-TLV `Type(2)‖Length(2)‖Value`) + SHA-256 that
  does NOT import the handshake package; anchor the SHA-256 primitive itself to FIPS 180-4
  (`SHA-256("abc")`). The consuming test re-derives every point with its own manual oracle AND with
  the real `Transcript`, both of which must equal the stored points.
* (B) Store goldens produced by the reference `Transcript` (circular — rejected).
* (C) Reuse the existing self-generated regression KAT (`kat_test.go` → `kat_vectors.json`), which
  is impl-generated and honestly labelled non-authoritative (rejected — that is the circular
  artifact this KAT upgrades).

## Decision Outcome

Chosen option: **(A)**. The authoritative vector (`test-vectors/v1/transcript-kat.json`; consumed
by the Go reference implementation, pinned testdata copy) carries: the
FIPS 180-4 `SHA-256("abc")` anchor, the fixed frame/TLV inputs for one canonical 4-frame handshake
(deterministic KAT fixtures — the construction is value-agnostic, so realistic sizes exercise the
2-octet Length high byte without needing crypto-real values), and the five expected `TH_*` points
produced by the independent constructor. The test runs three legs:

1. **ANCHOR** — `SHA-256("abc")` reproduces the FIPS 180-4 known answer (the hash primitive is
   trusted before any `TH_*` is).
2. **ORACLE** — an in-test manual constructor (no `Transcript`, no `tlv.Encode`) reproduces every
   `TH_*`, guarding the vector against corruption.
3. **IMPL** — the real `Transcript` (`AddFrameType`/`AddTLV`/`Hash`) reproduces every `TH_*`,
   guarding the implementation; it also asserts the handshake frame-type constants still equal the
   spec §1 code points.

The vector stores the FIPS anchor + inputs + the independently-computed points — not numbers an
N-PAMP `Transcript` produced. It is SHA-256-pinned in `PIN.json`/`MANIFEST.sha256` and gated by
`scripts/verify-pins.ps1`.

### Consequences

* Good: the transcript construction (frame-type-only absorption, per-TLV granularity, the five cut
  points) is anchored to FIPS 180-4 and an independent constructor; mutation-proven (a header-creep
  `AddFrameType` fails the IMPL leg on all five points while the ANCHOR and ORACLE legs still pass).
* Good: same anchor+oracle pattern as ADR-0008; reused next for the Finished and CertVerify KATs.
* Neutral: the `TH_*` bytes are not independently published anywhere; their correctness rests on the
  spec §3 construction rule + FIPS 180-4 SHA-256, which is the strongest available grounding for an
  N-PAMP-original construction.
* Honest scope (D5): the Go side is delivered + mutation-proven. **Update 2026-06-25:** the
  TypeScript mirror is also delivered — `impl/typescript/test/transcript-kat.test.ts` consumes the
  same authoritative vector with the same anchor/oracle/impl legs (`npm test` 18/18, mutation-proven,
  independently reviewed), in the reference implementation at `impl/typescript`.

### Confirmation

The transcript KAT test passes (anchor + oracle + impl); mutation (header-creep `AddFrameType`)
fails only the impl leg; the Go reference implementation's handshake package passes `-race`.

## More Information

`test-vectors/v1/transcript-kat.json`; spec/10 §3/§7.1/§8; ADR-0005, ADR-0007, ADR-0008.
Sources: FIPS 180-4 (SHA-256), RFC 8446 §4.4.1 (the construction N-PAMP diverges from).
