// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	supplychain "github.com/bubblefish-tech/npamp_protocol/impl/go/ecosystem/npamp-supply-chain"
)

// testModuleDir points discoverModules at the REAL impl/go module this CLI lives two
// directories under (impl/go/cmd/npamp-supply-chain -> impl/go), so every test below
// exercises the actual production `go list -m -json all` invocation against this
// repository's real go.mod, not a synthetic fixture. This is the direct demonstration that
// the CLI is a real production caller of the supplychain package (A9/E2): the SBOM it
// builds describes THIS module's real dependency graph.
const testModuleDir = "../.."

// TestDiscoverModulesAgainstRealModule proves discoverModules is wired to the real `go
// list -m -json all` output of this repository's actual Go module, not a hardcoded or
// synthetic list.
func TestDiscoverModulesAgainstRealModule(t *testing.T) {
	mods, err := discoverModules(testModuleDir)
	if err != nil {
		t.Fatalf("discoverModules(%s): %v", testModuleDir, err)
	}
	if len(mods) == 0 {
		t.Fatal("discoverModules returned zero modules — expected at least the main module entry")
	}
	var foundMain bool
	for _, m := range mods {
		if m.Main {
			foundMain = true
			if !strings.HasSuffix(m.Path, "npamp_protocol/impl/go") {
				t.Fatalf("main module Path = %q, want it to end in npamp_protocol/impl/go", m.Path)
			}
		}
	}
	if !foundMain {
		t.Fatal("no module in the graph has Main == true — go list -m -json all always emits the main module first")
	}
}

// TestBuildSignerFromSeedIsDeterministic confirms the seed-hex path produces a stable
// signing identity (A4: same seed twice must produce the same public key; a different seed
// must produce a different one).
func TestBuildSignerFromSeedIsDeterministic(t *testing.T) {
	seedHex := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"[:64]

	s1, fresh1, err := buildSigner(seedHex)
	if err != nil {
		t.Fatalf("buildSigner: %v", err)
	}
	if fresh1 {
		t.Fatal("buildSigner reported freshKey=true for a supplied seed")
	}
	s2, _, err := buildSigner(seedHex)
	if err != nil {
		t.Fatalf("buildSigner (second call): %v", err)
	}
	if string(s1.PublicKey()) != string(s2.PublicKey()) {
		t.Fatal("same seed produced two different public keys")
	}

	s3, fresh3, err := buildSigner("")
	if err != nil {
		t.Fatalf("buildSigner(\"\"): %v", err)
	}
	if !fresh3 {
		t.Fatal("buildSigner reported freshKey=false for an empty seed")
	}
	if string(s1.PublicKey()) == string(s3.PublicKey()) {
		t.Fatal("a generated key coincidentally matched the seed-derived key (statistically impossible unless buildSigner ignores its input)")
	}
}

// TestBuildSignerRejectsWrongSeedLength is the fail-closed check on malformed input.
func TestBuildSignerRejectsWrongSeedLength(t *testing.T) {
	if _, _, err := buildSigner("aabb"); err == nil {
		t.Fatal("buildSigner accepted a too-short seed")
	}
	if _, _, err := buildSigner("not-hex-at-all-zz"); err == nil {
		t.Fatal("buildSigner accepted non-hex input")
	}
}

// runFullPipeline is the shared setup for the end-to-end tests below: a real artifact
// file, the real module graph, a deterministic signer, an out-dir, and a run() call.
// Returns the artifact path and out-dir for further inspection/mutation by the caller.
func runFullPipeline(t *testing.T, artifactContent string) (artifactPath, outDir string) {
	t.Helper()
	dir := t.TempDir()
	artifactPath = filepath.Join(dir, "npamp-impl-go.tar.gz")
	if err := os.WriteFile(artifactPath, []byte(artifactContent), 0o644); err != nil {
		t.Fatalf("writing test artifact: %v", err)
	}
	outDir = filepath.Join(dir, "release-attestation")

	cfg := config{
		artifactPath:  artifactPath,
		moduleDir:     testModuleDir,
		name:          "npamp-impl-go",
		version:       "0.0.0-test",
		componentType: "library",
		builderID:     "https://npamp.dev/builders/test@v1",
		seedHex:       "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"[:64],
		outDir:        outDir,
	}
	if err := run(cfg); err != nil {
		t.Fatalf("run(): %v", err)
	}
	return artifactPath, outDir
}

// TestRunEndToEndProducesVerifiableArtifacts is the A9 isolation demonstration: invoke the
// CLI's full pipeline (build -> write -> independent re-verify) against a real artifact and
// this repository's real module graph, and confirm all three output files exist and the
// pipeline's own built-in re-verification (step 7) already passed (run() returned nil).
func TestRunEndToEndProducesVerifiableArtifacts(t *testing.T) {
	_, outDir := runFullPipeline(t, "a fake but non-empty release artifact for CLI e2e testing")

	for _, name := range []string{"sbom.json", "provenance.json", "pubkey.hex"} {
		p := filepath.Join(outDir, name)
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("expected output file %s to exist: %v", p, err)
		}
		if info.Size() == 0 {
			t.Fatalf("output file %s is empty", p)
		}
	}

	// A second, independent call to reverify (not just trusting run()'s internal call)
	// over the same on-disk files must also pass.
	artifactPath := filepath.Join(filepath.Dir(outDir), "npamp-impl-go.tar.gz")
	if err := reverify(outDir, artifactPath); err != nil {
		t.Fatalf("reverify on untouched output: %v", err)
	}
}

// TestReverifyDetectsTamperedSBOM is the mutation-witness for this CLI's own wiring: it
// proves reverify actually inspects the bytes on disk rather than rubber-stamping whatever
// run() wrote. If reverify were a stub that always returned nil, this test would fail to
// detect the tamper and this test itself would catch that.
func TestReverifyDetectsTamperedSBOM(t *testing.T) {
	artifactPath, outDir := runFullPipeline(t, "artifact A")

	sbomPath := filepath.Join(outDir, "sbom.json")
	original, err := os.ReadFile(sbomPath)
	if err != nil {
		t.Fatalf("reading sbom.json: %v", err)
	}
	tampered := append([]byte{}, original...)
	// Flip one byte inside the JSON body (not the first/last byte, to avoid accidentally
	// producing whitespace that some JSON parsers tolerate).
	mid := len(tampered) / 2
	tampered[mid] ^= 0xff
	if err := os.WriteFile(sbomPath, tampered, 0o644); err != nil {
		t.Fatalf("writing tampered sbom.json: %v", err)
	}

	if err := reverify(outDir, artifactPath); err == nil {
		t.Fatal("reverify did not detect a tampered sbom.json — the re-verification step is not actually checking the bytes on disk")
	}
}

// TestReverifyDetectsTamperedArtifact proves the digest binding is checked against the
// artifact bytes actually on disk at verify time, not merely re-asserted from memory: if
// the artifact changes after the attestation was written (e.g. a corrupted upload), the
// digest binding must fail.
func TestReverifyDetectsTamperedArtifact(t *testing.T) {
	artifactPath, outDir := runFullPipeline(t, "artifact B, the original bytes")

	if err := os.WriteFile(artifactPath, []byte("artifact B, TAMPERED after attestation"), 0o644); err != nil {
		t.Fatalf("tampering artifact: %v", err)
	}

	err := reverify(outDir, artifactPath)
	if err == nil {
		t.Fatal("reverify did not detect a tampered artifact — VerifyBinding is not actually recomputing the digest from the on-disk artifact")
	}
	if !strings.Contains(err.Error(), "digest binding") {
		t.Fatalf("reverify failed for an unexpected reason: %v", err)
	}
}

// TestReverifyDetectsTamperedProvenanceSignature proves a tampered DSSE envelope
// (signature no longer matches the payload it accompanies) is caught, not merely a
// tampered payload.
func TestReverifyDetectsTamperedProvenanceSignature(t *testing.T) {
	artifactPath, outDir := runFullPipeline(t, "artifact C")

	provPath := filepath.Join(outDir, "provenance.json")
	original, err := os.ReadFile(provPath)
	if err != nil {
		t.Fatalf("reading provenance.json: %v", err)
	}
	tampered := append([]byte{}, original...)
	mid := len(tampered) / 2
	tampered[mid] ^= 0xff
	if err := os.WriteFile(provPath, tampered, 0o644); err != nil {
		t.Fatalf("writing tampered provenance.json: %v", err)
	}

	if err := reverify(outDir, artifactPath); err == nil {
		t.Fatal("reverify did not detect a tampered provenance.json")
	}
}

// TestParseFlagsRequiresArtifact is the fail-closed check on the CLI's own argument
// contract.
func TestParseFlagsRequiresArtifact(t *testing.T) {
	if _, err := parseFlags([]string{"-module-dir", "impl/go"}); err == nil {
		t.Fatal("parseFlags accepted missing -artifact")
	}
}

// TestParseFlagsDefaultsNameFromArtifactBasename confirms the -name default is derived
// from the actual -artifact path (A4: changing the artifact path changes the default
// name), not a constant.
func TestParseFlagsDefaultsNameFromArtifactBasename(t *testing.T) {
	cfg, err := parseFlags([]string{"-artifact", "/tmp/foo/npamp-release.tar.gz"})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if cfg.name != "npamp-release.tar.gz" {
		t.Fatalf("name = %q, want npamp-release.tar.gz", cfg.name)
	}

	cfg2, err := parseFlags([]string{"-artifact", "/tmp/bar/other-artifact.zip"})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if cfg2.name != "other-artifact.zip" {
		t.Fatalf("name = %q, want other-artifact.zip", cfg2.name)
	}
}

// TestDefaultBuilderIDUsesGitHubActionsEnvWhenPresent confirms the CI-derived builder ID
// path actually reads the real GitHub Actions environment variables, not a hardcoded
// value.
func TestDefaultBuilderIDUsesGitHubActionsEnvWhenPresent(t *testing.T) {
	t.Setenv("GITHUB_SERVER_URL", "https://github.example")
	t.Setenv("GITHUB_REPOSITORY", "bubblefish-tech/npamp_protocol")
	t.Setenv("GITHUB_RUN_ID", "12345")

	got := defaultBuilderID()
	want := "https://github.example/bubblefish-tech/npamp_protocol/actions/runs/12345"
	if got != want {
		t.Fatalf("defaultBuilderID() = %q, want %q", got, want)
	}
}

// TestDefaultBuilderIDFallsBackOutsideCI confirms the non-CI fallback is a real, resolvable
// URL to this repository's own workflow file, not a placeholder string.
func TestDefaultBuilderIDFallsBackOutsideCI(t *testing.T) {
	t.Setenv("GITHUB_SERVER_URL", "")
	t.Setenv("GITHUB_REPOSITORY", "")
	t.Setenv("GITHUB_RUN_ID", "")

	got := defaultBuilderID()
	if !strings.HasPrefix(got, "https://github.com/bubblefish-tech/npamp_protocol/") {
		t.Fatalf("defaultBuilderID() fallback = %q, not a resolvable repo URL", got)
	}
	if !strings.Contains(got, "release-attest.yml") {
		t.Fatalf("defaultBuilderID() fallback = %q, does not name the real workflow file", got)
	}
}

// TestParseFlagsNoModuleGraphAndPURL confirms -no-module-graph and -purl are actually
// threaded from argv into config (E5.4: the per-language publish-pipeline attach path
// passes both for a non-Go package artifact).
func TestParseFlagsNoModuleGraphAndPURL(t *testing.T) {
	cfg, err := parseFlags([]string{
		"-artifact", "/tmp/npamp-0.1.0.tgz",
		"-no-module-graph",
		"-purl", "pkg:npm/npamp@0.1.0",
	})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if !cfg.noModuleGraph {
		t.Fatal("parseFlags did not set noModuleGraph=true for -no-module-graph")
	}
	if cfg.purl != "pkg:npm/npamp@0.1.0" {
		t.Fatalf("cfg.purl = %q, want pkg:npm/npamp@0.1.0", cfg.purl)
	}

	// Default (flag omitted) must be false/empty — E5.4's Go-artifact release-attest.yml
	// path (which never passes -no-module-graph or -purl) must keep enumerating the real
	// module graph exactly as it did before this change (no behavior change for the
	// existing production caller).
	cfg2, err := parseFlags([]string{"-artifact", "/tmp/foo.tar.gz"})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if cfg2.noModuleGraph {
		t.Fatal("noModuleGraph defaulted to true — the existing release-attest.yml Go path must default to enumerating the module graph")
	}
	if cfg2.purl != "" {
		t.Fatalf("purl defaulted to %q, want empty", cfg2.purl)
	}
}

// TestRunNoModuleGraphSkipsModuleDiscoveryAndCarriesPURL is the E5.4 mutation-witness: it
// proves -no-module-graph actually SKIPS the `go list -m -json all` invocation (discoverModules)
// rather than merely accepting the flag and ignoring it. cfg.moduleDir is set to a directory
// that does not exist and has no go.mod, so if run() still called discoverModules(cfg.moduleDir)
// this test would fail with a "discovering module graph" error — the same way it did before
// -no-module-graph existed. It also confirms the passed -purl value reaches the SBOM's root
// component (metadata.component.purl) and that the resulting zero-component, zero-module-graph
// SBOM still independently re-verifies (reverify), proving BuildSBOM's documented "zero
// non-main entries -> empty Components slice, never an error" behavior actually executes for a
// non-Go artifact end-to-end through this CLI, not just inside the supplychain package's own
// unit tests.
func TestRunNoModuleGraphSkipsModuleDiscoveryAndCarriesPURL(t *testing.T) {
	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "npamp-0.1.0.tgz")
	if err := os.WriteFile(artifactPath, []byte("a fake npm dry-run tarball for CLI testing"), 0o644); err != nil {
		t.Fatalf("writing test artifact: %v", err)
	}
	outDir := filepath.Join(dir, "attestation")
	nonexistentModuleDir := filepath.Join(dir, "no-such-module-dir-here")

	cfg := config{
		artifactPath:  artifactPath,
		moduleDir:     nonexistentModuleDir, // proves discoverModules is never called
		name:          "npamp",
		version:       "0.1.0",
		componentType: supplychain.ComponentTypeLibrary,
		purl:          "pkg:npm/npamp@0.1.0",
		builderID:     "https://npamp.dev/builders/test@v1",
		seedHex:       "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"[:64],
		outDir:        outDir,
		noModuleGraph: true,
	}
	if err := run(cfg); err != nil {
		t.Fatalf("run() with -no-module-graph and a nonexistent -module-dir: %v (discoverModules was likely still invoked)", err)
	}

	sbomJSON, err := os.ReadFile(filepath.Join(outDir, "sbom.json"))
	if err != nil {
		t.Fatalf("reading sbom.json: %v", err)
	}
	var sbom supplychain.BOM
	if err := json.Unmarshal(sbomJSON, &sbom); err != nil {
		t.Fatalf("unmarshaling sbom.json: %v", err)
	}
	if len(sbom.Components) != 0 {
		t.Fatalf("sbom.Components has %d entries, want 0 (no module graph was enumerated)", len(sbom.Components))
	}
	if sbom.Metadata == nil || sbom.Metadata.Component == nil {
		t.Fatal("sbom.Metadata.Component is nil")
	}
	if sbom.Metadata.Component.PURL != "pkg:npm/npamp@0.1.0" {
		t.Fatalf("root component PURL = %q, want pkg:npm/npamp@0.1.0", sbom.Metadata.Component.PURL)
	}

	if err := reverify(outDir, artifactPath); err != nil {
		t.Fatalf("reverify on the no-module-graph attestation: %v", err)
	}
}
