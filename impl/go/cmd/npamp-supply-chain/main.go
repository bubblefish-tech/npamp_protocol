// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Command npamp-supply-chain is the release-time production caller of
// ecosystem/npamp-supply-chain's pipeline.BuildRelease (task E5.1/E5.2, R7.1/R7.2). It is
// the CLI entry point that closes the "nothing exists until wired" gap noted in the
// package's own doc.go: BuildRelease, BuildSBOM, BuildStatement, and the DSSE signer were
// built and unit-tested, but had zero production callers anywhere in the tree (a repo-wide
// grep for `supplychain|BuildRelease` outside the package's own files returned nothing, and
// no .github/workflows/ step invoked it).
//
// Given a release artifact on disk, this binary:
//
//  1. Digests the artifact.
//  2. Enumerates the real Go module dependency graph of -module-dir via `go list -m -json
//     all` (GOWORK=off, the same invocation modgraph.go's own doc comment cites) — never a
//     hardcoded component list.
//  3. Builds and schema-validates a real CycloneDX 1.7 SBOM.
//  4. Builds and validates a SLSA Build L1 provenance Statement binding the artifact digest
//     to the SBOM digest.
//  5. Signs the Statement in a DSSE v1 envelope with an Ed25519 key (a fresh key by
//     default, or a caller-supplied 32-byte seed for a stable release-signing identity —
//     see -seed-hex / NPAMP_RELEASE_SIGNING_SEED_HEX).
//  6. Writes sbom.json, provenance.json (the DSSE envelope), and pubkey.hex to -out-dir.
//  7. Independently RE-VERIFIES all three files by reading them back from disk (not
//     reusing any in-memory value from step 1-5) and calling the package's own
//     independent verifiers: ValidateSBOM (against the vendored CycloneDX schema),
//     ValidateStatement (SLSA Build L1 required-field set), VerifyBinding (recomputes both
//     digests from the artifact/SBOM bytes actually on disk), and
//     VerifyStatementSignature (ed25519.Verify against the on-disk pubkey). This is the
//     non-circular check the plan requires: the verifier path never touches the in-memory
//     BuildResult, only what actually landed on disk.
//
// Exit code is fail-closed: any error at any stage — including a step-7 re-verification
// failure — aborts before printing a success line and exits 1. Step 7 succeeding is not
// optional decoration; it is what makes this CLI trustworthy as a release gate rather than
// a tool that merely "ran without crashing."
//
// Usage:
//
//	npamp-supply-chain -artifact npamp-impl-go.tar.gz -module-dir impl/go -version 0.1.0 -out-dir release-attestation
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	supplychain "github.com/bubblefish-tech/npamp_protocol/impl/go/ecosystem/npamp-supply-chain"
)

// config holds every input the release/verify pipeline needs, resolved from flags/env
// before any I/O runs.
type config struct {
	artifactPath  string
	moduleDir     string
	name          string
	version       string
	componentType string
	purl          string
	builderID     string
	seedHex       string
	outDir        string
	noModuleGraph bool
}

func main() {
	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "npamp-supply-chain: %v\n", err)
		os.Exit(2)
	}
	if err := run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "npamp-supply-chain: %v\n", err)
		os.Exit(1)
	}
}

func parseFlags(args []string) (config, error) {
	fs := flag.NewFlagSet("npamp-supply-chain", flag.ContinueOnError)
	artifact := fs.String("artifact", "", "path to the release artifact to attest (required)")
	moduleDir := fs.String("module-dir", "impl/go", "Go module directory whose dependency graph (go list -m -json all, GOWORK=off) becomes the SBOM's component list (ignored when -no-module-graph is set)")
	name := fs.String("name", "", "SBOM root component / provenance subject name (default: the artifact's base filename)")
	version := fs.String("version", "0.0.0-dev", "SBOM root component version")
	componentType := fs.String("component-type", supplychain.ComponentTypeLibrary, "CycloneDX component type for the SBOM root component")
	purl := fs.String("purl", "", "optional Package URL (purl) for the SBOM root component, e.g. pkg:npm/npamp@0.1.0 (default: none — purl is an optional CycloneDX field)")
	builderID := fs.String("builder-id", "", "SLSA runDetails.builder.id (default: derived from GITHUB_SERVER_URL/GITHUB_REPOSITORY/GITHUB_RUN_ID when running in GitHub Actions, else the repo's own release-attest workflow URL)")
	seedHex := fs.String("seed-hex", "", "32-byte hex-encoded Ed25519 seed for a stable release-signing identity (default: read from NPAMP_RELEASE_SIGNING_SEED_HEX, else a fresh key is generated)")
	outDir := fs.String("out-dir", "release-attestation", "directory to write sbom.json, provenance.json, and pubkey.hex into")
	noModuleGraph := fs.Bool("no-module-graph", false, "skip the Go module dependency-graph enumeration (go list -m -json all) and build an SBOM with only the root component — for attesting a NON-Go release artifact (a per-language SDK package: npm tarball, PyPI sdist, Maven/Gradle jar, NuGet package, RubyGems gem, Composer archive, crates.io package) that has no Go module graph to enumerate at -module-dir")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	if *artifact == "" {
		return config{}, errors.New("-artifact is required")
	}
	resolvedName := *name
	if resolvedName == "" {
		resolvedName = filepath.Base(*artifact)
	}
	resolvedSeed := *seedHex
	if resolvedSeed == "" {
		resolvedSeed = os.Getenv("NPAMP_RELEASE_SIGNING_SEED_HEX")
	}
	resolvedBuilderID := *builderID
	if resolvedBuilderID == "" {
		resolvedBuilderID = defaultBuilderID()
	}
	return config{
		artifactPath:  *artifact,
		moduleDir:     *moduleDir,
		name:          resolvedName,
		version:       *version,
		componentType: *componentType,
		purl:          *purl,
		builderID:     resolvedBuilderID,
		seedHex:       resolvedSeed,
		outDir:        *outDir,
		noModuleGraph: *noModuleGraph,
	}, nil
}

// defaultBuilderID derives a real, non-fabricated builder identity: inside GitHub Actions
// it is the actual run URL (GITHUB_SERVER_URL/GITHUB_REPOSITORY/actions/runs/GITHUB_RUN_ID
// — the three environment variables GitHub Actions itself sets, per its own documented
// default-environment-variables contract); outside CI it falls back to the URL of the real
// workflow file this repository ships (.github/workflows/release-attest.yml), never a
// placeholder string.
func defaultBuilderID() string {
	server := os.Getenv("GITHUB_SERVER_URL")
	repo := os.Getenv("GITHUB_REPOSITORY")
	runID := os.Getenv("GITHUB_RUN_ID")
	if server != "" && repo != "" && runID != "" {
		return server + "/" + repo + "/actions/runs/" + runID
	}
	return "https://github.com/bubblefish-tech/npamp_protocol/blob/main/GitHub/.github/workflows/release-attest.yml"
}

// run executes the full build-then-independently-reverify pipeline and reports a summary
// to stdout on success.
func run(cfg config) error {
	artifactData, err := os.ReadFile(cfg.artifactPath)
	if err != nil {
		return fmt.Errorf("reading artifact %s: %w", cfg.artifactPath, err)
	}

	var mods []supplychain.Module
	if cfg.noModuleGraph {
		// -no-module-graph: the artifact being attested is a non-Go release package (a
		// per-language SDK dry-run build), so there is no Go module graph at -module-dir to
		// enumerate. mods stays nil, and BuildSBOM honestly represents that as a zero-length
		// Components slice (its own doc comment: "A module graph with zero non-main entries
		// ... is honestly represented as an empty Components slice, never as an error or a
		// fabricated entry") — never a hardcoded stand-in dependency list.
	} else {
		var err error
		mods, err = discoverModules(cfg.moduleDir)
		if err != nil {
			return fmt.Errorf("discovering module graph in %s: %w", cfg.moduleDir, err)
		}
	}

	signer, freshKey, err := buildSigner(cfg.seedHex)
	if err != nil {
		return fmt.Errorf("building provenance signer: %w", err)
	}
	pub := signer.PublicKey()

	root := supplychain.Component{Type: cfg.componentType, Name: cfg.name, Version: cfg.version, PURL: cfg.purl}
	artifact := supplychain.ReleaseArtifact{Name: cfg.name, Data: artifactData}
	started := time.Now().UTC()

	result, err := supplychain.BuildRelease(artifact, root, mods, cfg.builderID, signer, started, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("BuildRelease: %w", err)
	}

	if err := writeOutputs(cfg.outDir, result, pub); err != nil {
		return fmt.Errorf("writing release attestation to %s: %w", cfg.outDir, err)
	}

	if err := reverify(cfg.outDir, cfg.artifactPath); err != nil {
		return fmt.Errorf("independent re-verification of the written attestation FAILED (not shipping): %w", err)
	}

	fmt.Printf("npamp-supply-chain: release attestation written and independently re-verified\n")
	fmt.Printf("  artifact:        %s (sha256:%s)\n", cfg.artifactPath, result.ArtifactDigest["sha256"])
	fmt.Printf("  sbom:            %s (%d component(s), sha256:%s)\n", filepath.Join(cfg.outDir, "sbom.json"), len(result.SBOM.Components), result.SBOMDigest["sha256"])
	fmt.Printf("  provenance:      %s (SLSA Build L1, buildType %s)\n", filepath.Join(cfg.outDir, "provenance.json"), supplychain.NPAMPBuildType)
	fmt.Printf("  builder:         %s\n", cfg.builderID)
	if freshKey {
		fmt.Printf("  signing key:     freshly generated this run (pubkey %s) — pass -seed-hex or set NPAMP_RELEASE_SIGNING_SEED_HEX for a stable release identity across releases\n", hex.EncodeToString(pub))
	} else {
		fmt.Printf("  signing key:     seed-derived (pubkey %s)\n", hex.EncodeToString(pub))
	}
	return nil
}

// discoverModules invokes `go list -m -json all` in moduleDir with GOWORK=off (mirroring
// modgraph.go's own documented invocation: "cd impl/go && GOWORK=off go list -m -json
// all") and decodes the real, live module dependency graph. It never hardcodes a component
// list — a change to go.mod changes what this function returns.
func discoverModules(moduleDir string) ([]supplychain.Module, error) {
	cmd := exec.Command("go", "list", "-m", "-json", "all")
	cmd.Dir = moduleDir
	cmd.Env = append(os.Environ(), "GOWORK=off")
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("go list -m -json all: %w\n%s", err, string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("go list -m -json all: %w", err)
	}
	mods, err := supplychain.DecodeGoListModules(bytesReader(out))
	if err != nil {
		return nil, err
	}
	return mods, nil
}

// buildSigner derives a ProvenanceSigner from seedHex when non-empty (a stable
// release-signing identity across releases), or generates a fresh Ed25519 identity from
// crypto/rand otherwise. The bool return reports which path was taken, for the CLI's own
// honest status line.
func buildSigner(seedHex string) (signer *supplychain.ProvenanceSigner, freshKey bool, err error) {
	if seedHex == "" {
		s, err := supplychain.GenerateProvenanceSigner()
		return s, true, err
	}
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return nil, false, fmt.Errorf("decoding -seed-hex: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, false, fmt.Errorf("-seed-hex must decode to %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	s, err := supplychain.NewProvenanceSigner(seed)
	return s, false, err
}

// writeOutputs writes the three release-attestation files a downstream consumer needs:
// the schema-valid SBOM, the DSSE-enveloped signed provenance statement, and the raw
// verifier public key (hex-encoded, one line, no trailing metadata).
func writeOutputs(outDir string, result *supplychain.BuildResult, pub []byte) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "sbom.json"), result.SBOMJSON, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "provenance.json"), result.SignedProvenance, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "pubkey.hex"), []byte(hex.EncodeToString(pub)+"\n"), 0o644); err != nil {
		return err
	}
	return nil
}

// reverify reads sbom.json, provenance.json, and pubkey.hex back from outDir, reads the
// artifact back from artifactPath, and runs every independent check the supplychain
// package exports over those on-disk bytes — never the in-memory BuildResult that produced
// them. This is the F3 non-circular check: a bit flipped in any of the three written files,
// or in the artifact itself, is caught here, not merely trusted because BuildRelease
// returned no error.
func reverify(outDir, artifactPath string) error {
	artifactData, err := os.ReadFile(artifactPath)
	if err != nil {
		return fmt.Errorf("re-reading artifact: %w", err)
	}
	sbomJSON, err := os.ReadFile(filepath.Join(outDir, "sbom.json"))
	if err != nil {
		return fmt.Errorf("re-reading sbom.json: %w", err)
	}
	provenanceJSON, err := os.ReadFile(filepath.Join(outDir, "provenance.json"))
	if err != nil {
		return fmt.Errorf("re-reading provenance.json: %w", err)
	}
	pubHex, err := os.ReadFile(filepath.Join(outDir, "pubkey.hex"))
	if err != nil {
		return fmt.Errorf("re-reading pubkey.hex: %w", err)
	}
	pub, err := hex.DecodeString(trimNewline(string(pubHex)))
	if err != nil {
		return fmt.Errorf("decoding pubkey.hex: %w", err)
	}

	if err := supplychain.ValidateSBOM(sbomJSON); err != nil {
		return fmt.Errorf("sbom.json failed independent schema re-validation: %w", err)
	}

	var env supplychain.Envelope
	if err := json.Unmarshal(provenanceJSON, &env); err != nil {
		return fmt.Errorf("provenance.json is not a well-formed DSSE envelope: %w", err)
	}
	statementJSON, err := decodeEnvelopePayload(&env)
	if err != nil {
		return fmt.Errorf("decoding provenance.json payload: %w", err)
	}
	var statement supplychain.Statement
	if err := json.Unmarshal(statementJSON, &statement); err != nil {
		return fmt.Errorf("provenance.json payload is not a well-formed Statement: %w", err)
	}

	if err := supplychain.ValidateStatement(&statement); err != nil {
		return fmt.Errorf("provenance.json failed independent SLSA Build L1 re-validation: %w", err)
	}
	if err := supplychain.VerifyBinding(&statement, artifactData, sbomJSON); err != nil {
		return fmt.Errorf("digest binding does not match the artifact/SBOM actually on disk: %w", err)
	}
	if err := supplychain.VerifyEnvelope(pub, &env, statementJSON); err != nil {
		return fmt.Errorf("DSSE signature does not verify against pubkey.hex: %w", err)
	}
	return nil
}
