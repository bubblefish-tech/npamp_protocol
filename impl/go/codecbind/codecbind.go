// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package codecbind

import (
	"fmt"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// Re-exported named errors. Each variable IS the Part-1 codec's own sentinel error value
// (npamp.ErrCanonicalCBOR*, itself the same value as memory_cbor.go's unexported error), so
// errors.Is(err, codecbind.ErrMapKeyOrder) observes the exact rejection the Part-1 codec
// reports — this package neither invents a new error class nor loses the original one behind
// a string comparison.
var (
	// ErrTrailingBytes is returned when a decoded top-level item does not consume the entire
	// input (extra bytes follow a complete CBOR item).
	ErrTrailingBytes = npamp.ErrCanonicalCBORTrailing
	// ErrTruncated is returned when the input ends before a declared length/argument is fully
	// present.
	ErrTruncated = npamp.ErrCanonicalCBORTruncated
	// ErrNotShortestForm is returned for a non-canonical encoding: an integer or a
	// length/count argument encoded with more bytes than the shortest form requires (RFC 8949
	// section 4.2.1).
	ErrNotShortestForm = npamp.ErrCanonicalCBORNotShortest
	// ErrIndefiniteLength is returned for an indefinite-length item (a CBOR feature this
	// deterministic profile does not accept).
	ErrIndefiniteLength = npamp.ErrCanonicalCBORIndefinite
	// ErrUnsupportedItem is returned for a major type or simple value outside the
	// deterministic subset this codec supports — this includes every float (there is no
	// accepted position for a float anywhere in this profile) and every CBOR tag.
	ErrUnsupportedItem = npamp.ErrCanonicalCBORUnsupported
	// ErrMapKeyOrder is returned when a decoded map's keys are not in strict canonical
	// (bytewise-of-encoded-key) ascending order — this is also the rejection a duplicate key
	// produces, since a duplicate key is never strictly greater than the one before it.
	ErrMapKeyOrder = npamp.ErrCanonicalCBORMapOrder
	// ErrUnsupportedGoType is the error Encode returns (recovered from the underlying codec's
	// panic; see Encode) when v is not one of the types this codec can encode.
	ErrUnsupportedGoType = npamp.ErrCanonicalCBORBadType
)

// Encode canonically encodes v as deterministic CBOR (RFC 8949 section 4.2.1
// core-deterministic), delegating entirely to the Part-1 codec (npamp.EncodeCanonicalCBOR —
// this function performs no CBOR encoding of its own). Accepted types for v: uint64, int
// (>= 0), int64 (negative allowed), []byte, string, []any, map[uint64]any (nested), bool, and
// nil.
//
// The underlying Part-1 encoder panics on an unsupported Go type rather than returning an
// error (see memory_cbor.go's cborEncode); an ecosystem-facing API boundary should not panic
// on caller input it can validate, so Encode recovers that specific panic and reports it as
// ErrUnsupportedGoType instead. This does not soften the rejection — an unsupported type is
// still, unconditionally, rejected; only its shape (error return vs. panic) changes at this
// one boundary. Callers that want the exact, unrecovered Part-1 behavior can call MustEncode.
func Encode(v any) (b []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			b, err = nil, fmt.Errorf("codecbind: encode: %w: %v", ErrUnsupportedGoType, r)
		}
	}()
	return npamp.EncodeCanonicalCBOR(v), nil
}

// MustEncode canonically encodes v exactly as Encode does, but is a direct, zero-overhead
// delegation to npamp.EncodeCanonicalCBOR with no panic recovery: like the Part-1 codec it
// wraps, MustEncode panics (wrapping ErrUnsupportedGoType) if v is not one of the accepted
// types. Use this only when the caller already guarantees v is encodable.
func MustEncode(v any) []byte {
	return npamp.EncodeCanonicalCBOR(v)
}

// Decode decodes a single canonical (core-deterministic, RFC 8949 section 4.2.1) CBOR item
// from b, requiring that the item consumes the entire input, by delegating entirely to the
// Part-1 codec (npamp.DecodeCanonicalCBOR — this function performs no CBOR decoding of its
// own). A decoded map is returned as map[uint64]any (recursively, for nested maps); arrays are
// []any; scalars are uint64, int64, []byte, string, bool, or nil.
//
// Decode is fail-closed: it rejects, unchanged, exactly what the Part-1 codec rejects —
// indefinite-length items, non-shortest-form integers/lengths, any float, any CBOR tag, and
// map keys that are out of canonical order or duplicated — and reports the rejection through
// one of the re-exported sentinel errors above (checkable with errors.Is), wrapped with a
// package-identifying prefix for a caller reading the error text directly.
func Decode(b []byte) (any, error) {
	v, err := npamp.DecodeCanonicalCBOR(b)
	if err != nil {
		return nil, fmt.Errorf("codecbind: decode: %w", err)
	}
	return v, nil
}
