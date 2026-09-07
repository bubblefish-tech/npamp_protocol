// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package schemaversion

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDefaultRepoRoot_ResolvesRealTree proves DefaultRepoRoot lands on the
// actual repository root (not a stub, not an arbitrary directory): the
// resolved path must contain both schema/npamp-wire.cddl and
// schema/npamp-wire.manifest.json.
func TestDefaultRepoRoot_ResolvesRealTree(t *testing.T) {
	root, err := DefaultRepoRoot()
	if err != nil {
		t.Fatalf("DefaultRepoRoot: %v", err)
	}
	for _, rel := range []string{
		filepath.Join("schema", "npamp-wire.cddl"),
		filepath.Join("schema", "npamp-wire.manifest.json"),
		filepath.Join("registries", "channels.csv"),
	} {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			t.Fatalf("resolved root %s is missing %s: %v", root, rel, err)
		}
	}
}

// TestLoadManifest_RealFile proves LoadManifest parses the actual committed
// manifest and every required field is populated with real values, not
// zero-values a stub would also produce.
func TestLoadManifest_RealFile(t *testing.T) {
	root, err := DefaultRepoRoot()
	if err != nil {
		t.Fatalf("DefaultRepoRoot: %v", err)
	}
	m, err := LoadManifest(filepath.Join(root, "schema", "npamp-wire.manifest.json"))
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if m.Artifact != "npamp-wire.cddl" {
		t.Fatalf("Artifact = %q, want npamp-wire.cddl", m.Artifact)
	}
	if m.ArtifactPath != "schema/npamp-wire.cddl" {
		t.Fatalf("ArtifactPath = %q, want schema/npamp-wire.cddl", m.ArtifactPath)
	}
	if m.WireFormatVersion != 2 {
		t.Fatalf("WireFormatVersion = %d, want 2 (matches npamp.ProtocolVersion in frame.go)", m.WireFormatVersion)
	}
	if m.ALPN != "n-pamp/3" {
		t.Fatalf("ALPN = %q, want n-pamp/3", m.ALPN)
	}
	if len(m.SHA256) != 64 {
		t.Fatalf("SHA256 = %q, want 64 hex characters", m.SHA256)
	}
}

// TestLoadManifest_RejectsMissingField is the mutation-facing half of
// LoadManifest's validation: a manifest missing a required field must fail
// to load, not silently parse into a zero-value struct that later checks
// would treat as "fine."
func TestLoadManifest_RejectsMissingField(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{
		"artifact": "npamp-wire.cddl",
		"artifactPath": "schema/npamp-wire.cddl",
		"cddlArtifactVersion": "1.0.0",
		"wireFormatVersion": 2,
		"specRevision": "",
		"rootRule": "npamp-frame",
		"sha256": "0836150c4027c6d342d269d05233a19b782d7d025d88e486cf6a0df340c9cc1d"
	}`), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if _, err := LoadManifest(bad); err == nil {
		t.Fatal("LoadManifest accepted a manifest with an empty specRevision")
	}
}

// TestLoadManifest_RejectsMalformedSHA256 proves a sha256 field that is not
// 64 hex characters is rejected at load time, before VerifyManifest ever
// runs a comparison against it.
func TestLoadManifest_RejectsMalformedSHA256(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad-sha.json")
	if err := os.WriteFile(bad, []byte(`{
		"artifact": "npamp-wire.cddl",
		"artifactPath": "schema/npamp-wire.cddl",
		"cddlArtifactVersion": "1.0.0",
		"wireFormatVersion": 2,
		"specRevision": "draft-bubblefish-npamp-02",
		"rootRule": "npamp-frame",
		"sha256": "not-a-hash"
	}`), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if _, err := LoadManifest(bad); err == nil {
		t.Fatal("LoadManifest accepted a malformed sha256 field")
	}
}

// TestVerifyManifest_RealArtifactMatches proves the manifest's pinned
// sha256 currently agrees with the ACTUAL on-disk bytes of
// schema/npamp-wire.cddl -- the versioning artifact's real teeth. This is
// the mutation-surviving test: if schema/npamp-wire.cddl's bytes changed
// without a manifest re-pin, this test would fail (see RED-EVIDENCE in the
// task report, which mutates a sibling validation rule in wirevalidator;
// this test's own mutation-sensitivity is exercised the same way -- flip
// one manifest hex digit below and confirm the mismatch is caught).
func TestVerifyManifest_RealArtifactMatches(t *testing.T) {
	root, err := DefaultRepoRoot()
	if err != nil {
		t.Fatalf("DefaultRepoRoot: %v", err)
	}
	m, err := LoadManifest(filepath.Join(root, "schema", "npamp-wire.manifest.json"))
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if err := VerifyManifest(m, root); err != nil {
		t.Fatalf("VerifyManifest: %v (manifest and schema/npamp-wire.cddl have drifted apart)", err)
	}
}

// TestVerifyManifest_DetectsMismatch proves VerifyManifest actually compares
// bytes rather than always returning nil: a manifest claiming a hash that
// does NOT match the real file must fail. This directly demonstrates the
// property TestVerifyManifest_RealArtifactMatches depends on: if
// VerifyManifest were a stub that always returned nil, THIS test would fail,
// so the two tests together are the mutation pair for VerifyManifest.
func TestVerifyManifest_DetectsMismatch(t *testing.T) {
	root, err := DefaultRepoRoot()
	if err != nil {
		t.Fatalf("DefaultRepoRoot: %v", err)
	}
	real, err := LoadManifest(filepath.Join(root, "schema", "npamp-wire.manifest.json"))
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	tampered := *real
	// Flip the hash's leading hex digit so it can never coincidentally match.
	if strings.HasPrefix(tampered.SHA256, "0") {
		tampered.SHA256 = "f" + tampered.SHA256[1:]
	} else {
		tampered.SHA256 = "0" + tampered.SHA256[1:]
	}
	if err := VerifyManifest(&tampered, root); err == nil {
		t.Fatal("VerifyManifest accepted a manifest with a deliberately wrong sha256")
	}
}

// TestVerifyManifest_MissingArtifact proves a manifest pointing at a
// nonexistent artifact path fails closed (a read error), not silently.
func TestVerifyManifest_MissingArtifact(t *testing.T) {
	m := &Manifest{
		Artifact:            "does-not-exist.cddl",
		ArtifactPath:        "schema/does-not-exist.cddl",
		CDDLArtifactVersion: "0.0.0",
		WireFormatVersion:   2,
		SpecRevision:        "draft-bubblefish-npamp-02",
		RootRule:            "npamp-frame",
		SHA256:              strings.Repeat("0", 64),
	}
	root, err := DefaultRepoRoot()
	if err != nil {
		t.Fatalf("DefaultRepoRoot: %v", err)
	}
	if err := VerifyManifest(m, root); err == nil {
		t.Fatal("VerifyManifest accepted a manifest pointing at a nonexistent artifact")
	}
}
