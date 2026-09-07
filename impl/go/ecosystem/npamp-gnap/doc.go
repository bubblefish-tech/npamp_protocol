// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package npampgnap implements the CLIENT side of GNAP (RFC 9635, "Grant Negotiation and
// Authorization Protocol") for an N-PAMP agent, per this build's E4.2 discovery/identity
// task (requirements.md Requirement 6 item 2 / R6.2: "The agent identity SHALL have a
// portable representation ... and OAuth/GNAP for delegated authority ... (DES-17 switching
// cost)"). It is purely additive: no N-PAMP wire format, frame layout, handshake message,
// channel, or conformance vector is touched, and no N-PAMP cryptographic primitive is
// reimplemented — key proofing reuses the agent's EXISTING Ed25519 identity key (the same
// crypto/ed25519 keypair npamp.SignCertVerify/VerifyCertVerify use for the live CertVerify
// handshake message, impl/go/handshake.go), and the client-instance key's JWK encoding
// reuses impl/go/ecosystem/npamp-discovery's already-graded RFC 8037 OKP-JWK codec
// (BuildOKPJWK) rather than a second encoder for the same shape (D5/A10).
//
// # Shape reference and grounding correction inherited, re-derived here (verify-relay)
//
// This package structurally mirrors the sibling N-AALP bridge,
// impl/go/ecosystem/naalp-gnap (naalp_draft-01 repo), which grounded RFC 9635 and RFC 9421
// directly and recorded one load-bearing correction to an earlier design sketch: delegation
// evidence a client already holds is carried in the Grant Request's "user.assertions" array
// (RFC 9635 §2.4, "Identifying the User" — data the client instance PUSHES to the AS), NOT
// in "subject.assertion_formats" (§2.2, "Requesting Subject Information" — a REQUEST for
// data the AS should RETURN about the resource owner; its response-side counterpart is
// §3.4's "assertions" array, populated by the AS, not the client). This package carries the
// identical §2.4 placement (UserField.Assertions in BuildGrantRequest, gnapclient.go) —
// re-derived from RFC 9635 §2.2/§2.4 read directly this session, not merely copied from the
// sibling's comment, per this repo's B1/E8 discipline (a grounding note from another repo is
// a lead, not a witness for THIS package's own wire types).
//
// # Scope: Option A (GNAP-client, built) + Option B (delegation-EXPORT, scaffolded)
//
// The sibling naalp-gnap package additionally exports a DelegationGrant chain leaf
// (N-AALP's impl/go/delegation.Resolved, its own C15 object) as a GNAP user.assertions
// payload. N-PAMP's Go core has NO equivalent delegation/authorization object to export:
// grepping impl/go/ for "[Dd]elegation" finds no such type (the two substring hits,
// capability_bodies.go and workflow.go, are unrelated words, confirmed by inspection).
// N-PAMP's own effect-class/audience authorization decision lives in Rust
// (nz-agent's impl/rust/nz-agent/src/waypoint.rs, waypoint::authorize), not in the Go core,
// and carries no serde derive / wire encoding today — so there is nothing for a Go process
// to decode from nz-agent yet.
//
// This package implements Option A in full: the GNAP-client wire types (RFC 9635 §2/§3),
// RFC 9421 httpsig key-proofing, the grant-request builder, and the continuation/polling
// flow (§5) — satisfying R6.2's literal text (a portable-identity evaluation that includes
// "OAuth/GNAP for delegated authority").
//
// gnapexport.go additionally builds Option B's re-check-and-export logic (ExportWaypointEvidence,
// mirroring naalp-gnap's ExportDelegationEvidence and its D15 fail-closed, export-only
// posture) over a DOCUMENTED, CALLER-SUPPLIED input shape (WaypointGrant) — because the
// cross-language TRANSPORT that would let a real nz-agent-resolved grant reach this
// function is a genuinely new design decision, flagged for the maintainer rather than
// invented here (see gnapexport.go's header for the two options and the recommendation).
// BuildGrantRequest accepts an OPTIONAL, already-constructed Assertion (Format/Value) from
// any caller-supplied source — the ExportWaypointEvidence output under Option B, a future
// Rust-bridge payload, or a caller's own already-verified evidence — so the wire-level
// "carry delegated-authority evidence in user.assertions" mechanism this package provides
// is honestly separated from "where that evidence comes from."
//
// # Grounding (primary sources fetched and read this session, 2026-09-02)
//
//   - GNAP core protocol: RFC 9635, https://www.rfc-editor.org/rfc/rfc9635.html — IETF
//     Standards Track, Proposed Standard, published October 2024. Confirmed this session:
//     the Grant Request's top-level fields (access_token/client/subject/user/interact, §2),
//     the access_token.access array shape (§2.1.1: type/actions/locations/datatypes), the
//     client.key object (§2.3: proof + jwk), the directionality of §2.2 ("Requesting Subject
//     Information", a REQUEST) vs §2.4 ("Identifying the User", client-PUSHED data) vs §3.4
//     ("Returning Subject Information", the AS's response), the Grant Response's top-level
//     fields (continue/access_token/interact/subject/instance_id/error, §3), the
//     continuation POST body's "interact_ref" field (§5.1), and the "GNAP Assertion Formats"
//     IANA registry (§10.6, initial values "id_token"/"saml2").
//   - Key proofing: RFC 9421, "HTTP Message Signatures",
//     https://www.rfc-editor.org/rfc/rfc9421.html — IETF Standards Track, published February
//     2024. Confirmed this session: the signature-base line format (one
//     `"<sf-string component-id>": <value>` line per covered component, terminated by an
//     `"@signature-params": (<ordered component list>)<params>` line, §2.3/§2.5), the
//     component-identifier/parameter serialization as RFC 8941 Structured Field values, and
//     the Signature-Input/Signature header shapes (a Dictionary keyed by a signature label,
//     §4.1/§4.2). RFC 9635 §7.3.1 names RFC 9421 ("httpsig") as its key-proofing mechanism
//     and requires covering at least "@method"/"@target-uri" unconditionally plus
//     "content-digest" (RFC 9530) when a body is present and "authorization" when an
//     Authorization header is present — gnapsig.go's RequiredComponents implements exactly
//     that split (the same reasonable-default posture the sibling package documents as not
//     independently re-verified against the RFC's full raw §7.3.1 paragraph text — see
//     Limitations below; unchanged by this re-derivation).
//
// # Honest, named gaps (B5 — what this session did NOT verify)
//
//   - RFC 9635 §7.3.1's exact, unconditional-vs-conditional covered-component requirements
//     for "httpsig" proofing were read via a summarizing pass over the fetched RFC text, not
//     line-by-line against the full raw normative paragraph; RequiredComponents' split
//     (content-digest iff a body is present, authorization iff an Authorization header is
//     present) is this package's own reasonable default, matching the sibling package's
//     identical posture, and should be re-verified before being treated as final.
//   - RFC 9635 §10.6's registration procedure/template fields were not read in full; no
//     "GNAP Assertion Formats" registry value is registered or proposed by this package
//     (Option A carries no format-specific payload of its own — see Scope above).
//   - The RFC 9421 "HTTP Signature Algorithms" IANA registry's exact registered-name rules
//     were not checked; AlgTag's output ("ed25519", "ml-dsa-87") is informational only —
//     Verify never consults it.
//   - draft-ietf-gnap-resource-servers (how an RS validates a GNAP-issued token) was not
//     fetched this session — out of this client-side scope.
//
// # Non-scope
//
// This package implements the CLIENT side of a GNAP exchange only (grant request,
// key-proofing, continuation polling) — it is not a GNAP authorization server, and it
// performs no HTTP transport itself (callers own the actual request/response I/O; this
// package produces and consumes the bytes/headers). Its Option-B export logic
// (ExportWaypointEvidence, gnapexport.go) re-checks and re-serializes a CALLER-SUPPLIED
// grant ceiling only — it does NOT decode a real Rust-produced wire object (see Scope
// above and gnapexport.go's header for the flagged cross-language-contract decision), and
// it reimplements no cryptography: signing/verifying is a thin wrapper over crypto/ed25519
// (the same primitive impl/go/handshake.go's SignCertVerify/VerifyCertVerify already use
// for the live handshake, reused unchanged — not re-derived).
package npampgnap
