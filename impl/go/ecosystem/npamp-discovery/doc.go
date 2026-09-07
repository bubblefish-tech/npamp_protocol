// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package npampdiscovery bridges an N-PAMP agent's Ed25519 signing key (the same
// crypto/ed25519 identity npamp.SignCertVerify / npamp.VerifyCertVerify use for N-PAMP's
// own live CertVerify handshake message, npamp.SigEd25519 = 0x0807, "all profiles" — see
// impl/go/handshake.go) to a decentralized-identity representation (a did:web DID
// Document) and a well-known agent-discovery document, per this build's E4 discovery/
// identity task (the N-PAMP analog of the sibling N-AALP ecosystem/naalp-did package). It
// is purely additive: no N-PAMP wire format, frame layout, handshake message, channel, or
// conformance vector is touched. It reimplements no cryptography — every function here is
// deterministic encoding/decoding/signing of Ed25519 key bytes already produced or
// consumed elsewhere in this tree (crypto/ed25519, the same primitive
// npamp.SignCertVerify wraps).
//
// # Why Ed25519, not ML-DSA
//
// N-PAMP's crypto-generation registry (suites.go) also names SigMLDSA87 (0x0906, "High,
// Sovereign") as a signature code point, but — as of this session — no Go stdlib ML-DSA
// type exists in this toolchain to mint or verify an ML-DSA key from (the same honest
// constraint impl/go/ecosystem/npamp-supply-chain/doc.go documents for the same reason).
// This package follows the same constraint: it works exclusively with crypto/ed25519, the
// one signature algorithm this Go reference actually exercises end-to-end today
// (certverify_kat_test.go — RFC 8032-anchored, live in the CertVerify handshake path), not
// an aspirational ML-DSA path this toolchain cannot yet execute (A2 — no code describing
// what it will do "once ML-DSA lands").
//
// # Grounding (primary sources fetched and read this session, 2026-08-31)
//
//   - DID Core: W3C Recommendation, published 19 July 2022, https://www.w3.org/TR/did-1.0/
//     (fetched this session). §5.2 "Verification Methods": a verification method map MUST
//     carry id (a DID URL), type (a string naming exactly one verification method type),
//     controller (a DID), and a verification-material property whose name is determined
//     by type. DID Core defines two supported verification-material properties directly:
//     publicKeyJwk ("a map representing a JSON Web Key that conforms to RFC7517... MUST
//     NOT contain private key material") and publicKeyMultibase (informative, "subject to
//     change"). This package uses publicKeyJwk with type "JsonWebKey2020" — the
//     DID-Core-normative, RFC-7517-anchored path — rather than publicKeyMultibase +
//     Multikey, because publicKeyMultibase's own DID Core text marks it non-normative and
//     because publicKeyJwk lets this package reuse the identical RFC 8037 OKP/Ed25519 JWK
//     shape the sibling naalp-did package already grounded and this session re-confirmed
//     (see jwk.go).
//   - Ed25519 JWK (OKP) representation: RFC 8037, "CFRG ECDH and Signatures in JOSE",
//     https://www.rfc-editor.org/rfc/rfc8037.html, Appendix A.1's public-key-only example:
//     {"kty":"OKP","crv":"Ed25519","x":base64url(pubkey)}. (Read as raw RFC text this
//     session, cross-checked against the identical grounding already recorded in
//     impl/go/ecosystem/naalp-did/doc.go, since the RFC does not change between
//     protocols.)
//   - did:web method: https://w3c-ccg.github.io/did-method-web/ (fetched this session) — a
//     W3C-CCG community specification, NOT a W3C Recommendation (the same
//     DID-method-level-informality gap did:jwk carries; W3C has ratified DID Core itself
//     but not any individual :method). Its "Read (Resolve)" algorithm: replace ":" with
//     "/" in the method-specific id; if there is no path component, append
//     "/.well-known/did.json"; if there is a path component, append "/did.json"; prepend
//     "https://" (see DIDWebURL in diddoc.go for the literal transform, and its doc
//     comment for a worked pair of inputs/outputs — deliberately not repeated here with a
//     bare hostname literal, to avoid this file reading as if it names a live endpoint).
//   - Well-known URI: RFC 8615, https://www.rfc-editor.org/rfc/rfc8615.html (fetched this
//     session). §3 defines the "/.well-known/" path-prefix convention; §3.1 defines a
//     "Specification Required" IANA registration procedure for a new suffix
//     (iana.org/assignments/well-known-uris/). This package's agent-discovery suffix,
//     "npamp-agent.json" (wellknown.go), is NOT IANA-registered as of this session — an
//     honest, named gap, the same class as did:web's own method-registration informality;
//     nothing in this package claims a registration that does not exist.
//   - Current agent-discovery convention: the Agent2Agent (A2A) protocol's AgentCard,
//     served at a "/.well-known/agent-card.json" path per RFC 8615
//     (https://a2a-protocol.org/v0.3.0/specification/, fetched this session). Its
//     top-level shape — protocolVersion, name, description, url, version, capabilities,
//     securitySchemes — is the current, widely-cited convention for a machine-readable
//     agent-manifest well-known document. This package's AgentDiscoveryDocument
//     (wellknown.go) borrows that field-naming convention for interoperability/legibility
//     (protocolVersion, name, description, url) and adds N-PAMP-specific fields (did,
//     verificationMethodID) for the DID/key binding this package exists to provide. It
//     does NOT claim A2A protocol conformance — no skills[]/defaultInputModes/
//     defaultOutputModes/security[] machinery is implemented, and it is served at its own
//     "npamp-agent.json" suffix (above), not at agent-card.json, to avoid asserting
//     interop with a specification this package does not implement.
//   - GNAP: RFC 9635, "Grant Negotiation and Authorization Protocol (GNAP)", Standards
//     Track, published October 2024, https://www.rfc-editor.org/rfc/rfc9635.html
//     (confirmed this session via datatracker.ietf.org/doc/html/rfc9635 and
//     rfc-editor.org/info/rfc9635/ — an IETF RFC, not a draft).
//
// # What this package does NOT do (a documented seam, not a gap)
//
// It does not implement GNAP (RFC 9635). GNAP's grant-request/continuation flow (§2, §5)
// is a multi-round, stateful HTTP negotiation between a client instance and an
// authorization server — building even a "minimal" slice of that state machine inside a
// package whose every other function is a pure, offline (or single-GET) transform of key
// bytes would either be a stub (a "grant request builder" with no server to negotiate
// with and no continuation/interaction handling — an orchestration wrapper around
// nothing, A10) or would require inventing a fake GNAP AS this session has no grounds to
// assume the shape of. This is named and left out (F1/F2-honest: absent, not stubbed)
// rather than shipped half-built; a real GNAP client-instance binding is future work once
// a concrete GNAP authorization server this protocol targets is chosen.
//
// It does not resolve did:jwk (only did:web) — did:web was chosen because it composes
// directly with this package's other deliverable (a well-known discovery document): both
// live at predictable HTTPS well-known paths under the same domain, so an agent's DID
// Document and its discovery document are fetched by the identical mechanism
// (net/http.Get against a well-known suffix), which did:jwk's self-contained (embed the
// key in the identifier itself, no network fetch) design does not need or benefit from
// here. Adding did:jwk support later is a pure addition (ToDIDJWK/FromDIDJWK, mirroring
// naalp-did's already-grounded functions) and would not change anything in this package.
package npampdiscovery
