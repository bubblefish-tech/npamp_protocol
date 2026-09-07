// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package schemaversion reads and verifies schema/npamp-wire.manifest.json,
// the versioned machine-consumable pin for the N-PAMP wire-format CDDL
// artifact (schema/npamp-wire.cddl; task E2.3, R3.2).
//
// The manifest pairs a semantic cddlArtifactVersion with a sha256 recomputed
// over the CDDL file's actual on-disk bytes, so a consumer that has fetched
// ONLY the manifest (not the whole repository, not MANIFEST.sha256) can
// still detect drift between the CDDL artifact it holds and the version the
// manifest describes. VerifyManifest performs exactly that check: it never
// trusts the manifest's own claims about the CDDL file's content, it
// recomputes the hash from the file bytes and fails closed on any mismatch.
package schemaversion

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Manifest is the parsed form of schema/npamp-wire.manifest.json.
type Manifest struct {
	Artifact            string `json:"artifact"`
	ArtifactPath        string `json:"artifactPath"`
	CDDLArtifactVersion string `json:"cddlArtifactVersion"`
	WireFormatVersion   int    `json:"wireFormatVersion"`
	CryptoGeneration    int    `json:"cryptoGeneration"`
	ALPN                string `json:"alpn"`
	SpecRevision        string `json:"specRevision"`
	CDDLGrammar         string `json:"cddlGrammar"`
	RootRule            string `json:"rootRule"`
	SHA256              string `json:"sha256"`
}

// ErrIncompleteManifest is returned by LoadManifest when a required field is
// empty after parsing -- an honest structural failure rather than silently
// proceeding with a zero-value field that would make every later check
// meaningless.
var ErrIncompleteManifest = errors.New("schemaversion: manifest is missing a required field")

var requiredStringFields = func(m *Manifest) map[string]string {
	return map[string]string{
		"artifact":            m.Artifact,
		"artifactPath":        m.ArtifactPath,
		"cddlArtifactVersion": m.CDDLArtifactVersion,
		"specRevision":        m.SpecRevision,
		"rootRule":            m.RootRule,
		"sha256":              m.SHA256,
	}
}

// LoadManifest parses the manifest JSON at path and validates that every
// required field is present and that sha256 is a well-formed 64-hex-digit
// string. It does NOT touch the CDDL file itself -- that comparison is
// VerifyManifest's job -- so a caller can load and inspect manifest metadata
// (version, spec revision, ALPN) without requiring the CDDL artifact to be
// reachable on disk.
func LoadManifest(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("schemaversion: read manifest %s: %w", path, err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("schemaversion: parse manifest %s: %w", path, err)
	}
	for field, val := range requiredStringFields(&m) {
		if val == "" {
			return nil, fmt.Errorf("%w: %s (in %s)", ErrIncompleteManifest, field, path)
		}
	}
	if len(m.SHA256) != 64 {
		return nil, fmt.Errorf("schemaversion: sha256 field is %d hex characters, want 64 (in %s)", len(m.SHA256), path)
	}
	if _, err := hex.DecodeString(m.SHA256); err != nil {
		return nil, fmt.Errorf("schemaversion: sha256 field is not valid hex (in %s): %w", path, err)
	}
	if m.WireFormatVersion <= 0 {
		return nil, fmt.Errorf("%w: wireFormatVersion must be positive (in %s)", ErrIncompleteManifest, path)
	}
	return &m, nil
}

// VerifyManifest recomputes SHA-256 over the CDDL artifact's on-disk bytes
// (artifactRoot joined with the manifest's ArtifactPath) and compares it,
// case-insensitively, against the manifest's recorded sha256. It returns a
// descriptive error on any mismatch or read failure; nil means the manifest
// and the artifact currently agree.
//
// This is the versioning artifact's actual teeth: a schema/npamp-wire.cddl
// edit that is not accompanied by a manifest re-pin (a bumped
// cddlArtifactVersion and a recomputed sha256) is caught here, not silently
// accepted.
func VerifyManifest(m *Manifest, artifactRoot string) error {
	full := filepath.Join(artifactRoot, filepath.FromSlash(m.ArtifactPath))
	raw, err := os.ReadFile(full)
	if err != nil {
		return fmt.Errorf("schemaversion: read artifact %s: %w", full, err)
	}
	sum := sha256.Sum256(raw)
	got := hex.EncodeToString(sum[:])
	want := m.SHA256
	if !equalFoldHex(got, want) {
		return fmt.Errorf("schemaversion: sha256 mismatch for %s: manifest says %s, on-disk bytes hash to %s (bump cddlArtifactVersion and re-pin sha256)", full, want, got)
	}
	return nil
}

// equalFoldHex compares two hex strings case-insensitively without pulling
// in strings.EqualFold's Unicode machinery for what is always ASCII hex.
func equalFoldHex(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// DefaultRepoRoot resolves the repository root (the directory that directly
// contains schema/ and registries/) relative to THIS source file's location,
// by walking up from runtime.Caller(0). It requires the source tree to be
// present on the running host (true for `go test`/`go run` from a checkout,
// and for any deployment that ships the full repository) -- see the package
// doc and the wirevalidator package's identical, independently documented
// limitation for the honest caveat: a binary shipped WITHOUT the source tree
// must supply its own root via LoadManifest/VerifyManifest directly.
func DefaultRepoRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("schemaversion: runtime.Caller could not resolve this source file's path")
	}
	// This file lives at <root>/impl/go/schemaversion/schemaversion.go.
	root := filepath.Join(filepath.Dir(file), "..", "..", "..")
	root = filepath.Clean(root)
	if _, err := os.Stat(filepath.Join(root, "schema", "npamp-wire.cddl")); err != nil {
		return "", fmt.Errorf("schemaversion: resolved root %s does not contain schema/npamp-wire.cddl: %w", root, err)
	}
	return root, nil
}
