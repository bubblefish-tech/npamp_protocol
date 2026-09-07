// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npampgnap

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestEffectClassFromWireMapsUnrecognizedToDestructiveNotDefault(t *testing.T) {
	for _, v := range []uint8{4, 5, 200, 255} {
		if got := EffectClassFromWire(v); got != EffectDestructive {
			t.Fatalf("EffectClassFromWire(%d) = %v, want EffectDestructive (fail-closed)", v, got)
		}
	}
	if got := EffectClassFromWire(3); got != EffectDestructive {
		t.Fatalf("EffectClassFromWire(3) = %v, want EffectDestructive", got)
	}
	if got := EffectClassFromWire(0); got != EffectReadOnly {
		t.Fatalf("EffectClassFromWire(0) = %v, want EffectReadOnly", got)
	}
}

func TestEffectClassLatticeOrdersDestructiveAtTop(t *testing.T) {
	if !(EffectReadOnly < EffectIdempotentWrite) {
		t.Fatal("ReadOnly must be < IdempotentWrite")
	}
	if !(EffectIdempotentWrite < EffectNonIdempotentWrite) {
		t.Fatal("IdempotentWrite must be < NonIdempotentWrite")
	}
	if !(EffectNonIdempotentWrite < EffectDestructive) {
		t.Fatal("NonIdempotentWrite must be < Destructive")
	}
}

func TestEffectClassStringMatchesWaypointRsDisplay(t *testing.T) {
	cases := map[EffectClass]string{
		EffectReadOnly:           "read_only",
		EffectIdempotentWrite:    "idempotent_write",
		EffectNonIdempotentWrite: "non_idempotent_write",
		EffectDestructive:        "destructive",
	}
	for e, want := range cases {
		if got := e.String(); got != want {
			t.Fatalf("EffectClass(%d).String() = %q, want %q", e, got, want)
		}
	}
}

// ---- ExportWaypointEvidence: the D15 export-only, fail-closed enforcement -----------------

func TestExportWaypointEvidenceWithinCeilingSucceeds(t *testing.T) {
	grant := WaypointGrant{SignerID: "agent-b", MaxGrant: EffectNonIdempotentWrite, ConsumingAuthority: "gateway-a"}
	a, err := ExportWaypointEvidence(grant, "gateway-a", EffectIdempotentWrite)
	if err != nil {
		t.Fatalf("ExportWaypointEvidence: %v", err)
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

func TestExportWaypointEvidenceAtCeilingExactlySucceeds(t *testing.T) {
	grant := WaypointGrant{SignerID: "agent-b", MaxGrant: EffectDestructive, ConsumingAuthority: "gateway-a"}
	if _, err := ExportWaypointEvidence(grant, "gateway-a", EffectDestructive); err != nil {
		t.Fatalf("ExportWaypointEvidence(at ceiling): %v", err)
	}
}

// TestExportWaypointEvidenceRejectsWrongAudienceBeforeEffect is the primary mutation-
// surviving test for the WrongAudience check: mirrors waypoint.rs's own
// wrong_audience_is_denied_before_effect_is_even_checked test — a request with the WRONG
// audience must be denied even when the requested effect is well within the grant's
// ceiling (proving the audience check runs, not merely the effect check).
func TestExportWaypointEvidenceRejectsWrongAudienceBeforeEffect(t *testing.T) {
	grant := WaypointGrant{SignerID: "agent-b", MaxGrant: EffectDestructive, ConsumingAuthority: "gateway-a"}
	_, err := ExportWaypointEvidence(grant, "gateway-b", EffectReadOnly)
	if !errors.Is(err, ErrAuthorityExport) {
		t.Fatalf("ExportWaypointEvidence(wrong audience) error = %v, want ErrAuthorityExport", err)
	}
}

// TestExportWaypointEvidenceRejectsEffectExceedingCeiling is the primary mutation-surviving
// test for the EffectExceedsGrant check.
func TestExportWaypointEvidenceRejectsEffectExceedingCeiling(t *testing.T) {
	grant := WaypointGrant{SignerID: "agent-b", MaxGrant: EffectReadOnly, ConsumingAuthority: "gateway-a"}
	_, err := ExportWaypointEvidence(grant, "gateway-a", EffectDestructive)
	if !errors.Is(err, ErrAuthorityExport) {
		t.Fatalf("ExportWaypointEvidence(effect exceeds ceiling) error = %v, want ErrAuthorityExport", err)
	}
}

func TestExportWaypointEvidenceRejectsErrorReturnsZeroAssertion(t *testing.T) {
	grant := WaypointGrant{SignerID: "agent-b", MaxGrant: EffectReadOnly, ConsumingAuthority: "gateway-a"}
	a, err := ExportWaypointEvidence(grant, "gateway-a", EffectDestructive)
	if err == nil {
		t.Fatal("expected an error")
	}
	if a != (Assertion{}) {
		t.Fatalf("ExportWaypointEvidence on refusal returned %+v, want zero-value Assertion", a)
	}
}

func TestBuildGrantRequestCarriesWaypointEvidenceInUserAssertionsNotSubject(t *testing.T) {
	pub, priv := clientTestKeypair(t)
	c := NewClientInstance(priv, pub)
	grant := WaypointGrant{SignerID: "agent-b", MaxGrant: EffectDestructive, ConsumingAuthority: "gateway-a"}
	a, err := ExportWaypointEvidence(grant, "gateway-a", EffectNonIdempotentWrite)
	if err != nil {
		t.Fatalf("ExportWaypointEvidence: %v", err)
	}
	req, err := c.BuildGrantRequest([]AccessDescriptor{{Type: "npamp-relay"}}, &a)
	if err != nil {
		t.Fatalf("BuildGrantRequest: %v", err)
	}
	if req.Subject != nil {
		t.Fatalf("BuildGrantRequest set req.Subject = %+v, want nil (evidence goes in user.assertions per RFC 9635 §2.4, not subject.assertion_formats per §2.2)", req.Subject)
	}
	if req.User == nil || len(req.User.Assertions) != 1 || req.User.Assertions[0].Format != AssertionFormatWaypointGrant {
		t.Fatalf("BuildGrantRequest().User = %+v, want one assertion with Format=%s", req.User, AssertionFormatWaypointGrant)
	}
}
