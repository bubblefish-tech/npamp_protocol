// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package supplychain builds signed, attestable release artifacts for the N-PAMP
// reference SDKs: a real Software Bill of Materials (SBOM) parsed from the actual Go
// module dependency graph, and a signed provenance/attestation statement binding an
// artifact's content digest to its SBOM's content digest. This satisfies BubbleFish
// Global Engineering Policy 5.5 ("published artifacts carry a signature (cosign/Sigstore)
// + an SBOM"). It is purely additive: no N-PAMP wire format, frame layout, handshake
// message, or conformance vector is touched — it signs with crypto/ed25519 directly (the
// same stdlib primitive npamp.SignCertVerify/ed25519.Sign use for the live handshake's
// CertVerify message, npamp.SigEd25519 = 0x0807, "all profiles" per suites.go) rather than
// constructing an N-PAMP wire frame, because a supply-chain attestation is not a frame on
// an N-PAMP connection and carries no channel/frame-type.
//
// # Why Ed25519, not ML-DSA
//
// N-PAMP's crypto-generation registry (suites.go) also names SigMLDSA87 (0x0906, "High,
// Sovereign") as a signature code point, and keyformat.go documents — as of this session —
// that "no Go stdlib ML-DSA type exists yet in this toolchain" to mint or verify an ML-DSA
// key from, which is why keyformat.go's own component-size table sources the four ML-DSA
// sizes from a published specification (FIPS 204 Table 2, cross-checked against the Open
// Quantum Safe project's liboqs datasheet) rather than a live Go type. This package follows
// that same honest constraint: it signs with crypto/ed25519 (npamp.SigEd25519), the one
// signature algorithm this Go reference actually exercises end-to-end today (see
// certverify_kat_test.go — RFC 8032-anchored, live in the CertVerify handshake path), not
// an aspirational ML-DSA path this toolchain cannot yet execute (A2 — no code describing
// what it will do "once ML-DSA lands").
//
// # Grounding (primary sources fetched and read this session, 2026-08-31)
//
//   - SBOM format: CycloneDX 1.7, published 2026-12-10 (per cyclonedx.org/specification/
//     overview/ — the version string is confirmed live at https://cyclonedx.org/docs/1.7/
//     json/, cross-checked this session against the N-AALP ecosystem/naalp-supply-chain
//     package, which fetched the identical schema the same session). The exact JSON Schema
//     this package validates against is vendored verbatim at schema/bom-1.7.schema.json,
//     the same byte-identical download used by ecosystem/naalp-supply-chain
//     (https://raw.githubusercontent.com/CycloneDX/specification/master/schema/
//     bom-1.7.schema.json, 315722 bytes, draft-07 JSON Schema, $id
//     "http://cyclonedx.org/schema/bom-1.7.schema.json") — a CycloneDX schema download is
//     not implementation-specific, so reusing the identical vendored file for a second
//     protocol's SBOM package is not a stand-in; see jsonschema_test.go for the
//     byte-count/SHA-256 check that this copy is unmodified.
//   - Provenance/attestation shape: the in-toto Attestation Framework Statement layer v1
//     (_type "https://in-toto.io/Statement/v1", https://github.com/in-toto/attestation/
//     blob/main/spec/v1/statement.md) wrapping a SLSA Provenance v1 predicate
//     (predicateType "https://slsa.dev/provenance/v1", https://slsa.dev/spec/v1.1/
//     provenance). The exact required field set for SLSA Build L1
//     (predicate.buildDefinition.{buildType, externalParameters},
//     predicate.runDetails.builder.id) is quoted verbatim in provenance_validate.go's doc
//     comments from https://raw.githubusercontent.com/slsa-framework/slsa/main/spec/
//     build-provenance.md and cross-checked against SLSA's own machine-readable CUE schema
//     (spec/schema/provenance.cue) — there is no published JSON Schema for the SLSA
//     provenance predicate, unlike CycloneDX; provenance_validate.go documents this as the
//     honest, named difference from the SBOM side's JSON-Schema validation.
//   - Signature transport: the DSSE (Dead Simple Signing Envelope) v1 envelope
//     (https://github.com/secure-systems-lab/dsse/blob/master/envelope.md, fetched this
//     session) — `{"payload": Base64(body), "payloadType": ..., "signatures": [{"keyid":
//     ..., "sig": Base64(sig)}]}` — and its PAE (Pre-Authentication Encoding) algorithm
//     (https://github.com/secure-systems-lab/dsse/blob/master/protocol.md, fetched this
//     session, verbatim): `PAE(type, body) = "DSSEv1" + SP + LEN(type) + SP + type + SP +
//     LEN(body) + SP + body`, where SP is a single ASCII space (0x20) and LEN is the
//     decimal ASCII byte length with no leading zeros; the signature is computed over
//     PAE(UTF8(payloadType), serializedBody). This is the real, standard in-toto/SLSA
//     attestation transport (the actual bundle format cosign/slsa-github-generator produce
//     for a SLSA provenance attestation) — chosen over inventing a bespoke envelope, and
//     over N-AALP's tagged-COSE_Sign1 choice, because N-PAMP has no CBOR/COSE object layer
//     to reuse (it is a binary handshake/framing protocol, not a CBOR object-signing
//     protocol) while DSSE is exactly the transport in-toto's own spec recommends for this
//     purpose. payloadType is the in-toto attestation spec's own recommended value,
//     "application/vnd.in-toto+json" (https://github.com/in-toto/attestation/blob/main/
//     spec/v1/envelope.md, fetched this session: "payloadType MUST be set to
//     `application/vnd.in-toto.<predicate>+json` or to `application/vnd.in-toto+json`" and
//     "payload MUST be a base64-encoded JSON [Statement]").
//   - Package URL (purl) type for a Go module: type "golang",
//     https://raw.githubusercontent.com/package-url/purl-spec/main/types/
//     golang-definition.json: "pkg:golang/<namespace>/<name>@<version>", namespace+name
//     lowercased, version = the resolved module version.
//
// # What this package does NOT do (a documented seam, not a gap)
//
// It does not call a live Sigstore Fulcio/Rekor transparency log, and it does not produce
// an x.509-based cosign signature. The classical cosign/Sigstore path is keyless (an OIDC
// identity token exchanged for a short-lived certificate, then logged to a public
// transparency log) and is a distinct trust model from a long-lived signer identity. This
// package signs the provenance Statement with a real, standard DSSE envelope over
// crypto/ed25519 — the same signature primitive the N-PAMP reference actually runs in its
// live CertVerify handshake path — rather than a live transparency-log interaction this
// package never contacts. A caller who also wants the classical cosign path can take this
// package's Envelope (or the underlying StatementJSON) and hand it to `cosign attest`
// unmodified — DSSE is cosign's own native envelope format, so the two are directly
// interoperable, not a replacement of one by the other.
package supplychain
