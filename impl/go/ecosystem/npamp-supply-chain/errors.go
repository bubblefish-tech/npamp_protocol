// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package supplychain

import "errors"

// Named, fail-closed errors, in this repository's own convention (see e.g.
// npamp.ErrCertVerifySignature, npamp.ErrReservedNonzero — a plain errors.New sentinel,
// not a custom error struct type; this package introduces no new error-typing convention).
// Every rejection returns exactly one of these — no partial result, no silent fallback.
var (
	// ErrEmptyInput is returned by a digest function given a nil io.Reader argument where
	// bytes are required (DigestBytes accepts an empty []byte; DigestReader rejects a nil
	// Reader before any read is attempted).
	ErrEmptyInput = errors.New("npamp/supplychain: no reader supplied to digest")

	// ErrMalformedModuleList is returned by DecodeGoListModules when the input is not a
	// well-formed stream of JSON objects in the shape `go list -m -json all` emits.
	ErrMalformedModuleList = errors.New("npamp/supplychain: go list -m -json stream is not well-formed JSON")

	// ErrMalformedGoMod is returned by ParseGoModRequires when a `require` line or block
	// entry does not have exactly a module path and a version token.
	ErrMalformedGoMod = errors.New("npamp/supplychain: go.mod require entry is not (path, version)")

	// ErrEmptyModulePath is returned by GoModulePURL when path is empty.
	ErrEmptyModulePath = errors.New("npamp/supplychain: module path must not be empty")

	// ErrInvalidComponentType is returned by BuildSBOM when a component's Type is not one
	// of the fourteen CycloneDX 1.7 component-type enum values.
	ErrInvalidComponentType = errors.New("npamp/supplychain: component type is not a CycloneDX 1.7 enum value")

	// ErrEmptyComponentName is returned by BuildSBOM when the root component's Name is
	// empty ("name" is REQUIRED on every CycloneDX component).
	ErrEmptyComponentName = errors.New("npamp/supplychain: component name must not be empty")

	// ErrSchemaInvalid is returned by ValidateSBOM (wrapping SchemaValidationError) when a
	// generated BOM document fails the vendored CycloneDX 1.7 JSON Schema.
	ErrSchemaInvalid = errors.New("npamp/supplychain: document does not satisfy the CycloneDX 1.7 JSON Schema")

	// ErrEmptyArtifactDigest / ErrEmptySBOMDigest / ErrEmptyBuilderID are returned by
	// BuildStatement when a required binding input is missing — a provenance statement
	// with no artifact digest, no SBOM digest, or no builder identity asserts nothing.
	ErrEmptyArtifactDigest = errors.New("npamp/supplychain: artifact digest set must not be empty")
	ErrEmptySBOMDigest     = errors.New("npamp/supplychain: sbom digest set must not be empty")
	ErrEmptyBuilderID      = errors.New("npamp/supplychain: runDetails.builder.id must not be empty")

	// ErrStatementInvalid is returned by ValidateStatement when a Statement is missing a
	// field SLSA Build L1 requires (spec/build-provenance.md, "REQUIRED for SLSA Build
	// L1: ..." lines) or carries the wrong _type/predicateType URI.
	ErrStatementInvalid = errors.New("npamp/supplychain: statement does not satisfy the SLSA Build L1 required-field set")

	// ErrBindingMismatch is returned by VerifyBinding when a Statement's recorded artifact
	// digest or SBOM digest does not match the digest independently recomputed from the
	// artifact bytes / SBOM bytes actually supplied — the F3 non-circular binding check.
	ErrBindingMismatch = errors.New("npamp/supplychain: statement digest does not match the independently recomputed digest")

	// ErrSeedSize is returned by NewProvenanceSigner when seed is not exactly
	// ed25519.SeedSize bytes.
	ErrSeedSize = errors.New("npamp/supplychain: Ed25519 seed must be 32 bytes")

	// ErrEnvelopeInvalid is returned by VerifyEnvelope when a DSSE envelope is structurally
	// incomplete (missing payload, payloadType, or a signature) before any signature check
	// runs.
	ErrEnvelopeInvalid = errors.New("npamp/supplychain: DSSE envelope is missing a required field")

	// ErrPayloadTypeMismatch is returned by VerifyEnvelope when the envelope's payloadType
	// does not equal the expected in-toto payload type.
	ErrPayloadTypeMismatch = errors.New("npamp/supplychain: DSSE envelope payloadType does not match the expected in-toto type")

	// ErrPayloadMismatch is returned by VerifyEnvelope when the envelope's decoded payload
	// does not equal the expected canonical statement bytes.
	ErrPayloadMismatch = errors.New("npamp/supplychain: DSSE envelope payload does not equal the expected statement bytes")

	// ErrSignatureInvalid is returned by VerifyEnvelope when no signature in the envelope
	// verifies against the supplied public key over PAE(payloadType, payload).
	ErrSignatureInvalid = errors.New("npamp/supplychain: no DSSE signature verifies under the supplied public key")
)
