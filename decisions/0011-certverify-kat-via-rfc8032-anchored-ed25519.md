---
status: "accepted"
date: 2026-06-24
decision-makers: [BubbleFish Technologies, Inc.]
consulted: []
informed: []
---

# CertVerify KAT: non-circularity via an RFC-8032-anchored independent Ed25519 signer

## Context and Problem Statement

Spec/10 §8's last pending handshake KAT is CertVerify. The value is
`u16(0x0807) || Ed25519(priv, signing_input)`, where
`signing_input = 0x20×64 || context || 0x00 || transcript_hash` (§6.1; RFC 8446 §4.4.3 with N-PAMP
context strings). As with the Finished KAT (ADR-0010), the signature primitive (Ed25519) is a
standard with published vectors, but the signed message (our `signing_input`) is N-PAMP-specific, so
no external standard publishes the CertVerify signature directly. How is it made non-circular?

## Decision Drivers

* Non-circularity (E8): expected signatures must not come from `SignCertVerify`.
* Anchor the signature primitive to a published standard.
* Cover the §6.1 domain-separation property (server vs client context) and transcript binding.

## Considered Options

* **(A) RFC-8032-anchored independent Ed25519.** Produce expected signatures with `crypto/ed25519`
  directly; anchor the Ed25519 primitive to RFC 8032 §7.1 TEST 1/2 (the test reproduces the
  published public keys + signatures first); build `signing_input` by hand; use the Transcript KAT's
  `TH_sId`/`TH_cId`. Ed25519 is deterministic, so any conforming signer reproduces the result.
* (B) Store goldens from `SignCertVerify` (circular — rejected).
* (C) Anchor only the signature, not the signing-input construction (rejected — the signing-input
  framing, context domain separation, and `0x00` separator are exactly the N-PAMP-original bits a KAT
  must pin).

## Decision Outcome

Chosen option: **(A)**. The vector (`test-vectors/v1/certverify-kat.json`; consumed by the Go
reference implementation, pinned testdata copy) carries the RFC 8032
TEST 1/2 anchors, the RFC 8032 test keypairs (server=TEST1, client=TEST2), the Transcript KAT's
`TH_sId`/`TH_cId`, and the expected `signing_input` + signature + full CertVerify TLV value produced
by an independent `crypto/ed25519`. The test:

1. **ANCHOR** — `crypto/ed25519` reproduces RFC 8032 §7.1 TEST 1/2 public keys + signatures.
2. **ORACLE** — a hand-built `signing_input` + `crypto/ed25519` reproduce the vector (guards it,
   independent of `SignCertVerify`/`certVerifySigningInput`).
3. **IMPL** — `certVerifySigningInput` + `SignCertVerify` reproduce the vector; `VerifyCertVerify`
   accepts the correct value, REJECTS a role/context mismatch (domain separation) and a wrong
   transcript (binding); the context constants are asserted against the spec strings.

### Consequences

* Good: the CertVerify construction (signing-input framing, the `"N-PAMP draft-00, {server,client}
  CertificateVerify"` contexts, the `0x00` separator, Ed25519 = 0x0807) is anchored to RFC 8032/8446;
  mutation-proven (a corrupted separator fails the impl leg while the anchor + oracle legs pass).
* Good: this is the FIFTH and final handshake-layer KAT — KEM-wire, key-schedule, transcript,
  Finished, and CertVerify are now all standards-derived and non-circular for the Go reference impl,
  closing spec/10 §8's pending list.
* Neutral / honest scope (D5): the High/Sovereign signature schemes are out of scope for this
  Standard/Ed25519 vector. **Update 2026-06-25:** the TypeScript mirror is delivered —
  `impl/typescript/test/certverify-kat.test.ts` (RFC-8032-anchored; accept + role-mismatch reject +
  wrong-transcript reject; `npm test` 18/18, mutation-proven), in the reference implementation at
  `impl/typescript`.

### Confirmation

The CertVerify KAT test passes (anchor + oracle + impl + accept/reject); mutation (separator flip)
fails only the impl leg; the Go reference implementation's handshake package passes `-race`; the full verification gate passes.

## More Information

`test-vectors/v1/certverify-kat.json`; spec/10 §6.1/§8; ADR-0008/0009/0010. Sources: RFC 8446
§4.4.3, RFC 8032 §7.1 (Ed25519 test vectors).
