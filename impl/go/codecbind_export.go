// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npamp

// Exported generic deterministic-CBOR codec surface for the codecbind ecosystem binding
// (requirement R3.1; impl/go/codecbind). This is a NEW, ADDITIVE file — it does not modify
// memory_cbor.go or any other Part-1 file, and it changes no wire behavior.
//
// Every domain body file already in this package (memory_api.go, capability_api.go,
// immune_api.go, stream_api.go, telemetry_api.go, workflow_api.go, commerce_api.go,
// interaction_api.go, knowledge_api.go, settlement_api.go) exports a thin per-domain wrapper
// over the SAME unexported deterministic-CBOR codec defined in memory_cbor.go, so a separate
// package (the conformance adapter, or a downstream consumer) can reach the codec without
// touching unexported internals — e.g. EncodeMemoryBody is exactly `return cborEncode(fields)`.
// Go's package-private visibility means an unexported identifier (cborEncode, cborDecodeTop,
// the sentinel error values) can only be referenced from a file inside THIS package; a
// separate importable package such as codecbind cannot reach them directly, no matter how it
// is named or organized. This file follows the exact same established pattern one level up:
// it exports the one thing none of the per-domain wrappers provide — a fully generic,
// domain-agnostic top-level encode/decode pair with no per-domain schema layered on top,
// because codecbind's job is the wire codec itself, not any one domain's required-key rules.
//
// Every function and variable below is a direct, zero-logic delegation to memory_cbor.go's
// existing unexported implementation. Nothing here re-implements, re-derives, or alters the
// canonical-CBOR algorithm, its accepted Go-type set, or its fail-closed rejection behavior.

// EncodeCanonicalCBOR canonically encodes v as deterministic CBOR (RFC 8949 section 4.2.1
// core-deterministic; the same profile memory_cbor.go documents). Accepted Go types: uint64,
// int (>= 0), int64 (negative allowed), []byte, string, []any, map[uint64]any (nested), bool,
// and nil. This is a direct call to cborEncode — it adds no new encoding logic. As with
// cborEncode, encoding a Go type outside the accepted set panics (wrapping ErrCanonicalCBORBadType);
// this function does not recover that panic, so the exact Part-1 panic behavior is preserved
// unchanged for any caller that reaches this function directly.
func EncodeCanonicalCBOR(v any) []byte {
	return cborEncode(v)
}

// DecodeCanonicalCBOR decodes a single canonical (core-deterministic, RFC 8949 section 4.2.1)
// CBOR item from b and requires that the item consumes the entire input — a direct call to
// cborDecodeTop. It rejects, unchanged, everything cborDecodeTop rejects: indefinite lengths,
// non-shortest integer/length encodings, tags, floats (there is no accepted position for a
// float in this deterministic subset — see memory_cbor.go), and out-of-order or duplicate map
// keys. A decoded map is returned as map[uint64]any (recursively, for nested maps), the same
// conversion memory_api.go's DecodeMemoryBody already performs via the unexported cborToGo
// helper, so the unexported cborMap type never leaks across the package boundary.
func DecodeCanonicalCBOR(b []byte) (any, error) {
	v, err := cborDecodeTop(b)
	if err != nil {
		return nil, err
	}
	return cborToGo(v), nil
}

// Exported sentinel errors — identical values to memory_cbor.go's unexported CBOR-codec
// errors, re-exported (not re-created: each variable below IS the same error value, so
// errors.Is comparisons against these sentinels observe the exact named rejection the Part-1
// codec reports) so a caller outside this package can name the specific rejection reason
// without reaching into unexported internals.
var (
	ErrCanonicalCBORTrailing    = errCBORTrailing
	ErrCanonicalCBORTruncated   = errCBORTruncated
	ErrCanonicalCBORNotShortest = errCBORNotShortest
	ErrCanonicalCBORIndefinite  = errCBORIndefinite
	ErrCanonicalCBORUnsupported = errCBORUnsupported
	ErrCanonicalCBORMapOrder    = errCBORMapOrder
	ErrCanonicalCBORBadType     = errCBORBadType
)
