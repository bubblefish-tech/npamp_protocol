// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npampgnap

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// readWaypointGrantFixture loads testdata/waypoint_grant.json — a REAL Rust-run fixture
// (produced by `cargo run --bin print-waypoint-grant-fixture` in impl/rust/nz-agent, then
// copied byte-for-byte; see impl/rust/nz-agent/testdata/waypoint_grant.json, sha256
// 1467c512d8f03dcb9fb1ec43a18ce1f2b0d9cf06f33ac30b44972e5e4898bfdc on both sides), NOT a
// literal hand-typed independently on this side of the language boundary.
func readWaypointGrantFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/waypoint_grant.json")
	if err != nil {
		t.Fatalf("reading testdata/waypoint_grant.json: %v", err)
	}
	return b
}

// ---- DecodeWaypointGrant: the real Rust->JSON->Go round trip ------------------------------

// TestDecodeWaypointGrantFromRealRustFixture is the load-bearing cross-language proof: the
// bytes decoded here were NOT constructed by this test or by any Go code — they are exactly
// what nz-agent's Rust waypoint::ResolvedWaypointGrant::to_json emitted when actually run.
func TestDecodeWaypointGrantFromRealRustFixture(t *testing.T) {
	grant, err := DecodeWaypointGrant(readWaypointGrantFixture(t))
	if err != nil {
		t.Fatalf("DecodeWaypointGrant(real Rust fixture): %v", err)
	}
	want := WaypointGrant{SignerID: "agent-b", MaxGrant: EffectNonIdempotentWrite, ConsumingAuthority: "gateway-a"}
	if grant != want {
		t.Fatalf("DecodeWaypointGrant(real Rust fixture) = %+v, want %+v", grant, want)
	}
}

func TestDecodeWaypointGrantRejectsMalformedJSON(t *testing.T) {
	_, err := DecodeWaypointGrant([]byte(`{not json`))
	if !errors.Is(err, ErrMalformedWaypointGrant) {
		t.Fatalf("DecodeWaypointGrant(malformed JSON) error = %v, want ErrMalformedWaypointGrant", err)
	}
}

func TestDecodeWaypointGrantRejectsMissingSignerID(t *testing.T) {
	_, err := DecodeWaypointGrant([]byte(`{"consuming_authority":"gateway-a","max_grant":"read_only"}`))
	if !errors.Is(err, ErrMalformedWaypointGrant) {
		t.Fatalf("DecodeWaypointGrant(missing signer_id) error = %v, want ErrMalformedWaypointGrant", err)
	}
}

func TestDecodeWaypointGrantRejectsMissingConsumingAuthority(t *testing.T) {
	_, err := DecodeWaypointGrant([]byte(`{"signer_id":"agent-b","max_grant":"read_only"}`))
	if !errors.Is(err, ErrMalformedWaypointGrant) {
		t.Fatalf("DecodeWaypointGrant(missing consuming_authority) error = %v, want ErrMalformedWaypointGrant", err)
	}
}

// TestDecodeWaypointGrantRejectsUnrecognizedMaxGrant is the primary mutation-surviving test
// for the fail-CLOSED direction of effectClassFromToken: an unrecognized max_grant token
// MUST refuse the whole grant (no authority), never silently resolve to Destructive (which
// would fail OPEN — the opposite of EffectClassFromWire's unrecognized-octet rule, which
// exists for the differently-directioned "requested effect" field, not a grant ceiling).
func TestDecodeWaypointGrantRejectsUnrecognizedMaxGrant(t *testing.T) {
	_, err := DecodeWaypointGrant([]byte(`{"signer_id":"agent-b","consuming_authority":"gateway-a","max_grant":"super_destructive"}`))
	if !errors.Is(err, ErrMalformedWaypointGrant) {
		t.Fatalf("DecodeWaypointGrant(unrecognized max_grant) error = %v, want ErrMalformedWaypointGrant", err)
	}
}

func TestDecodeWaypointGrantAcceptsEveryKnownMaxGrantToken(t *testing.T) {
	cases := map[string]EffectClass{
		"read_only":            EffectReadOnly,
		"idempotent_write":     EffectIdempotentWrite,
		"non_idempotent_write": EffectNonIdempotentWrite,
		"destructive":          EffectDestructive,
	}
	for token, want := range cases {
		payload, err := json.Marshal(map[string]string{
			"signer_id":           "agent-b",
			"consuming_authority": "gateway-a",
			"max_grant":           token,
		})
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		grant, err := DecodeWaypointGrant(payload)
		if err != nil {
			t.Fatalf("DecodeWaypointGrant(max_grant=%q): %v", token, err)
		}
		if grant.MaxGrant != want {
			t.Fatalf("DecodeWaypointGrant(max_grant=%q).MaxGrant = %v, want %v", token, grant.MaxGrant, want)
		}
	}
}

// ---- ExportWaypointEvidenceFromJSON: the composed end-to-end entry point ------------------

// TestExportWaypointEvidenceFromJSONAcceptsWithinCeiling decodes the REAL Rust fixture and
// exports a requested effect strictly within the fixture's max_grant (non_idempotent_write)
// ceiling for the fixture's own consuming_authority — the accept case of the full
// Rust-serialize -> Go-decode -> Go-re-check round trip.
func TestExportWaypointEvidenceFromJSONAcceptsWithinCeiling(t *testing.T) {
	a, err := ExportWaypointEvidenceFromJSON(readWaypointGrantFixture(t), "gateway-a", EffectIdempotentWrite)
	if err != nil {
		t.Fatalf("ExportWaypointEvidenceFromJSON(within ceiling): %v", err)
	}
	if a.Format != AssertionFormatWaypointGrant {
		t.Fatalf("Assertion.Format = %q, want %q", a.Format, AssertionFormatWaypointGrant)
	}
	var payload WaypointAssertionPayload
	if err := json.Unmarshal([]byte(a.Value), &payload); err != nil {
		t.Fatalf("json.Unmarshal(a.Value): %v", err)
	}
	if payload.SignerID != "agent-b" || payload.Audience != "gateway-a" ||
		payload.Effect != "idempotent_write" || payload.MaxGrant != "non_idempotent_write" {
		t.Fatalf("payload = %+v, want SignerID=agent-b Audience=gateway-a Effect=idempotent_write MaxGrant=non_idempotent_write", payload)
	}
}

// TestExportWaypointEvidenceFromJSONAcceptsAtCeilingExactly proves the accept path is not
// merely "any effect strictly below the ceiling" but the full lattice comparison up to and
// including the ceiling itself.
func TestExportWaypointEvidenceFromJSONAcceptsAtCeilingExactly(t *testing.T) {
	if _, err := ExportWaypointEvidenceFromJSON(readWaypointGrantFixture(t), "gateway-a", EffectNonIdempotentWrite); err != nil {
		t.Fatalf("ExportWaypointEvidenceFromJSON(at ceiling): %v", err)
	}
}

// TestExportWaypointEvidenceFromJSONRejectsWrongAudience proves the real-fixture round trip
// still enforces the D15 WrongAudience refusal — decoding a valid grant does not, by itself,
// grant an export for any audience.
func TestExportWaypointEvidenceFromJSONRejectsWrongAudience(t *testing.T) {
	_, err := ExportWaypointEvidenceFromJSON(readWaypointGrantFixture(t), "gateway-b", EffectReadOnly)
	if !errors.Is(err, ErrAuthorityExport) {
		t.Fatalf("ExportWaypointEvidenceFromJSON(wrong audience) error = %v, want ErrAuthorityExport", err)
	}
}

// TestExportWaypointEvidenceFromJSONRejectsEffectExceedingCeiling proves the real-fixture
// round trip still enforces the D15 EffectExceedsGrant refusal — the fixture's ceiling is
// non_idempotent_write, so a requested destructive effect must be denied even though the
// JSON decoded cleanly.
func TestExportWaypointEvidenceFromJSONRejectsEffectExceedingCeiling(t *testing.T) {
	_, err := ExportWaypointEvidenceFromJSON(readWaypointGrantFixture(t), "gateway-a", EffectDestructive)
	if !errors.Is(err, ErrAuthorityExport) {
		t.Fatalf("ExportWaypointEvidenceFromJSON(effect exceeds ceiling) error = %v, want ErrAuthorityExport", err)
	}
}

// TestExportWaypointEvidenceFromJSONPropagatesDecodeFailure proves the composed entry point
// never reaches ExportWaypointEvidence on a malformed payload — decode failure short-circuits
// before any authorization check runs.
func TestExportWaypointEvidenceFromJSONPropagatesDecodeFailure(t *testing.T) {
	_, err := ExportWaypointEvidenceFromJSON([]byte(`{"signer_id":"agent-b"}`), "gateway-a", EffectReadOnly)
	if !errors.Is(err, ErrMalformedWaypointGrant) {
		t.Fatalf("ExportWaypointEvidenceFromJSON(malformed) error = %v, want ErrMalformedWaypointGrant", err)
	}
	if errors.Is(err, ErrAuthorityExport) {
		t.Fatalf("ExportWaypointEvidenceFromJSON(malformed) error also matches ErrAuthorityExport %v; decode failure must not fall through to the authorization check", err)
	}
}
