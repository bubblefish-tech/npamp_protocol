// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npampgnap

import "errors"

// Named, fail-closed errors, in this repository's ecosystem-package convention (see e.g.
// npampdiscovery.ErrKeySize — a plain errors.New sentinel, not a custom error struct type).
// Every rejection returns exactly one of these — no partial result, no silent fallback.
var (
	// ErrKeyProofMismatch is returned by Verify when the RFC 9421 HTTP Message Signature
	// over a GNAP request does not verify under the presented key — a tampered signature,
	// a tampered covered-component value, or a signature produced by a different key.
	// Fail-closed: the caller MUST treat the request as unauthenticated.
	ErrKeyProofMismatch = errors.New("npamp/gnap: RFC 9421 HTTP message signature does not verify")

	// ErrMalformedRequest is returned when a Grant Request this package is asked to encode
	// is missing a field it requires to be safely sent (no requested access, or a client
	// key-proofing method other than the one this package implements).
	ErrMalformedRequest = errors.New("npamp/gnap: GNAP grant request is missing a required field")

	// ErrMalformedResponse is returned when a GNAP grant/continue response is not
	// well-formed JSON, or is missing a field this bridge requires to proceed safely.
	ErrMalformedResponse = errors.New("npamp/gnap: GNAP response is not well-formed or is missing a required field")

	// ErrContinuationMissing is returned when a grant/continuation response's "continue"
	// object (or a field within it this bridge needs to poll/finish) is absent or
	// incomplete.
	ErrContinuationMissing = errors.New("npamp/gnap: GNAP continue object is absent or incomplete")

	// ErrUnknownComponent is returned when a covered-component identifier requested for a
	// signature base has no value supplied — signing/verifying over a silently-absent
	// component would be worse than refusing (fail-closed).
	ErrUnknownComponent = errors.New("npamp/gnap: no value supplied for a covered signature component")

	// ErrUnknownAlg is returned when AlgTag is asked for the RFC 9421 alg tag of an
	// unrecognized signature algorithm.
	ErrUnknownAlg = errors.New("npamp/gnap: no RFC 9421 alg tag for this signature algorithm")

	// ErrGrantDenied is returned when a Grant Response carries an AS-reported error object
	// (RFC 9635 §3.6) — the response is still returned to the caller (for inspection), but
	// the caller MUST NOT treat the grant as issued.
	ErrGrantDenied = errors.New("npamp/gnap: authorization server returned a grant error")

	// ErrAuthorityExport is returned by ExportWaypointEvidence (gnapexport.go, Option B)
	// when the caller asked to export more authority (audience or effect) than the
	// supplied WaypointGrant actually confers. This is the same D15 fail-closed,
	// export-only posture naalp-gnap's ErrAuthorityExport implements: this bridge never
	// lets an external GNAP AS mint new N-PAMP authority.
	ErrAuthorityExport = errors.New("npamp/gnap: requested export exceeds the waypoint grant's ceiling")

	// ErrMalformedWaypointGrant is returned by DecodeWaypointGrant (gnapexport_decode.go,
	// Option B1) when a Rust-emitted waypoint-grant JSON payload is not valid JSON, is
	// missing signer_id or consuming_authority, or carries a max_grant token this package
	// does not recognize. Fail-closed: an undecodable grant confers NO authority — it is
	// never treated as a wide-open ceiling (unlike EffectClassFromWire's unrecognized-octet
	// rule, which exists for a different field with the opposite fail-closed direction; see
	// gnapexport_decode.go's effectClassFromToken doc comment).
	ErrMalformedWaypointGrant = errors.New("npamp/gnap: waypoint grant JSON is malformed or missing a required field")
)
