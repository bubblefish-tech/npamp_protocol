---
status: "accepted"
date: 2026-06-24
decision-makers: [BubbleFish Technologies, Inc.]
consulted: []
informed: []
---

# Finished KAT: non-circularity via an RFC-4231-anchored independent HMAC-SHA-256

## Context and Problem Statement

Spec/10 §8 requires a non-circular Finished KAT. The Finished `verify_data` is
`HMAC(finished_key, transcript_hash)` under the profile hash (§6.2; RFC 8446 §4.4.4 with N-PAMP
transcript points). As with the key-schedule and transcript KATs (ADR-0008/0009), the expected
output must not be produced by the implementation under test. The MAC is a standard primitive
(HMAC-SHA-256), so unlike the N-PAMP-original key schedule it CAN anchor to a published vector.

## Decision Drivers

* Non-circularity (E8): expected `verify_data` must not come from `ComputeFinished`.
* Anchor the MAC primitive to a published standard.
* Reuse the Transcript KAT's real `TH_*` so the KAT suite is coherent.

## Considered Options

* **(A) RFC-4231-anchored independent HMAC.** Produce expected `verify_data` with `crypto/hmac`
  directly; anchor the HMAC-SHA-256 primitive to RFC 4231 TC1/TC2 (the test reproduces those
  published MACs first); use the Transcript KAT's `TH_sCV`/`TH_cCV` as inputs.
* (B) Store goldens from `ComputeFinished` (circular — rejected).
* (C) Anchor `finished_key` derivation here too (rejected — that is the key-schedule KAT's job,
  ADR-0008; this KAT covers only the MAC step and treats `finished_key` as a fixed input).

## Decision Outcome

Chosen option: **(A)**. The vector (`test-vectors/v1/finished-kat.json`; consumed by the Go
reference implementation, pinned testdata copy) carries the RFC 4231
TC1/TC2 anchors, fixed `finished_key` fixtures (server/client), the Transcript KAT's
`TH_sCV`/`TH_cCV`, and the expected `verify_data` produced by an independent `crypto/hmac`. The test:

1. **ANCHOR** — `crypto/hmac` reproduces RFC 4231 TC1/TC2 HMAC-SHA-256.
2. **ORACLE** — `crypto/hmac(finished_key, TH)` reproduces `verify_data` (guards the vector).
3. **IMPL** — `ComputeFinished(finished_key, TH, Standard)` reproduces `verify_data`, and
   `VerifyFinished` accepts the correct MAC and rejects a single-bit tamper (guards the impl).

The vector stores the RFC anchors + inputs, not impl-produced goldens.

### Consequences

* Good: the Finished MAC (HMAC-SHA-256, which transcript point it covers, the constant-time verify)
  is anchored to RFC 4231; mutation-proven (a key-independent hash fails the impl leg while the
  RFC anchor + oracle legs pass).
* Good: reuses the Transcript KAT's `TH_*` — one canonical handshake threads through the suite.
* Neutral / honest scope (D5): `finished_key` derivation is NOT covered here (key-schedule KAT,
  ADR-0008). **Update 2026-06-25:** the TypeScript mirror is delivered —
  `impl/typescript/test/finished-kat.test.ts` (RFC-4231-anchored, same anchor/oracle/impl legs,
  `npm test` 18/18, mutation-proven), in the reference implementation at `impl/typescript`.

### Confirmation

The Finished KAT test passes (anchor + oracle + impl + verify accept/reject); mutation
(key-independent hash) fails only the impl leg; the Go reference implementation's handshake package
passes `-race`; the full verification gate passes.

## More Information

`test-vectors/v1/finished-kat.json`; spec/10 §6.2/§8; ADR-0008, ADR-0009. Sources: RFC 8446
§4.4.4, RFC 4231 (HMAC-SHA-256 test vectors), RFC 2104 (HMAC).
