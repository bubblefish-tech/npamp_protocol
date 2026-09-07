// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npampgnap

import (
	"encoding/json"
	"fmt"
)

// P2.5 Option B1 (the SHARED JSON WIRE FORMAT — recommended in gnapexport.go's file header
// and maintainer-approved 2026-09-02; NOT Option B2/FFI, no cgo): the Go-side TRANSPORT half
// that decodes the JSON impl/rust/nz-agent/src/waypoint.rs's ResolvedWaypointGrant emits
// (via its to_json method / the print-waypoint-grant-fixture bin) into this package's own
// WaypointGrant, so ExportWaypointEvidence can independently re-check it — never trusting a
// Rust-side "it passed" verdict at face value, mirroring how ExportWaypointEvidence never
// trusts a Go caller's own pass/fail verdict either.
//
// # The wire shape (pinned; matches waypoint.rs's ResolvedWaypointGrant exactly)
//
//	{"signer_id":"agent-b","consuming_authority":"gateway-a","max_grant":"non_idempotent_write"}
//
// Field names and the max_grant string token are the SAME ones this package's own
// WaypointAssertionPayload already uses for its Effect/MaxGrant fields (EffectClass.String())
// — reusing an existing convention rather than inventing a second one. See
// testdata/waypoint_grant.json (this package) — a REAL Rust-run fixture, byte-identical to
// impl/rust/nz-agent/testdata/waypoint_grant.json, produced by actually running
// `cargo run --bin print-waypoint-grant-fixture`, not hand-typed on either side.

// waypointGrantWire is the raw JSON shape decoded off the wire, before any validation.
// Unexported: DecodeWaypointGrant is the only supported entry point, and it never hands
// back a partially-validated value.
type waypointGrantWire struct {
	SignerID           string `json:"signer_id"`
	ConsumingAuthority string `json:"consuming_authority"`
	MaxGrant           string `json:"max_grant"`
}

// effectClassFromToken parses one of the four Display/String tokens this package's own
// EffectClass.String() (and waypoint.rs's Display) emit. Deliberately the OPPOSITE
// fail-closed shape from EffectClassFromWire: EffectClassFromWire maps an unrecognized
// wire OCTET to EffectDestructive (an unrecognized OBJECT EFFECT is treated as maximally
// suspicious, so it is scrutinized hardest). Here the value being decoded is a GRANT
// CEILING, not a requested effect — mapping an unrecognized ceiling token to Destructive
// would GRANT the widest possible authority to input this function could not even parse,
// which is failing OPEN, not closed. So an unrecognized token here returns ok=false and
// DecodeWaypointGrant refuses the whole grant outright (no authority at all), rather than
// guessing a ceiling in either direction.
func effectClassFromToken(s string) (EffectClass, bool) {
	switch s {
	case "read_only":
		return EffectReadOnly, true
	case "idempotent_write":
		return EffectIdempotentWrite, true
	case "non_idempotent_write":
		return EffectNonIdempotentWrite, true
	case "destructive":
		return EffectDestructive, true
	default:
		return EffectClass(0), false
	}
}

// DecodeWaypointGrant parses a P2.5 Option B1 JSON payload (produced by nz-agent's
// waypoint::ResolvedWaypointGrant::to_json) into a WaypointGrant. Fail-closed on any of:
// malformed JSON, a missing/empty signer_id, a missing/empty consuming_authority, or a
// max_grant string that is not one of the four recognized tokens — every failure returns
// the zero WaypointGrant and an error wrapping ErrMalformedWaypointGrant, never a partially
// populated value and never a guessed default for the field that failed to parse.
//
// DecodeWaypointGrant performs NO authorization decision itself — it only produces the
// documented WaypointGrant input shape ExportWaypointEvidence already independently
// re-checks against the requested (audience, effect) pair (see ExportWaypointEvidenceFromJSON
// below for the composed end-to-end entry point).
func DecodeWaypointGrant(jsonBytes []byte) (WaypointGrant, error) {
	var wire waypointGrantWire
	if err := json.Unmarshal(jsonBytes, &wire); err != nil {
		return WaypointGrant{}, fmt.Errorf("npamp/gnap: decoding waypoint grant JSON: %w: %w", err, ErrMalformedWaypointGrant)
	}
	if wire.SignerID == "" {
		return WaypointGrant{}, fmt.Errorf("npamp/gnap: waypoint grant JSON is missing signer_id: %w", ErrMalformedWaypointGrant)
	}
	if wire.ConsumingAuthority == "" {
		return WaypointGrant{}, fmt.Errorf("npamp/gnap: waypoint grant JSON is missing consuming_authority: %w", ErrMalformedWaypointGrant)
	}
	maxGrant, ok := effectClassFromToken(wire.MaxGrant)
	if !ok {
		return WaypointGrant{}, fmt.Errorf("npamp/gnap: waypoint grant JSON has an unrecognized max_grant %q: %w", wire.MaxGrant, ErrMalformedWaypointGrant)
	}
	return WaypointGrant{
		SignerID:           wire.SignerID,
		MaxGrant:           maxGrant,
		ConsumingAuthority: wire.ConsumingAuthority,
	}, nil
}

// ExportWaypointEvidenceFromJSON is the documented end-to-end P2.5 Option B1 entry point: it
// decodes a Rust-emitted waypoint-grant JSON payload (DecodeWaypointGrant) and, only if that
// decode succeeds, re-checks and exports it exactly as ExportWaypointEvidence does for a
// caller-constructed WaypointGrant. A caller with an already-decoded WaypointGrant (e.g. one
// it validated and cached) may still call ExportWaypointEvidence directly — this function
// exists for the common case where the JSON payload just arrived off the wire from nz-agent
// and has not been decoded yet.
func ExportWaypointEvidenceFromJSON(jsonBytes []byte, audience string, requestedEffect EffectClass) (Assertion, error) {
	grant, err := DecodeWaypointGrant(jsonBytes)
	if err != nil {
		return Assertion{}, err
	}
	return ExportWaypointEvidence(grant, audience, requestedEffect)
}
