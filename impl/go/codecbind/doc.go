// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package codecbind is a blessed, ecosystem-facing binding onto the N-PAMP deterministic
// (core-deterministic, RFC 8949 section 4.2.1) CBOR codec — N-PAMP draft-bubblefish-npamp-02
// requirement R3.1.
//
// This package is ADDITIVE. It does not touch, replace, or reimplement the Part-1 codec that
// the wire format already depends on (impl/go/memory_cbor.go); it delegates every encode and
// decode call to that existing codec through the exported bridge functions
// npamp.EncodeCanonicalCBOR / npamp.DecodeCanonicalCBOR (impl/go/codecbind_export.go, itself a
// new, additive file that changes no existing Part-1 file and no wire behavior). Nothing in
// this package independently parses or serializes CBOR bytes.
//
// # Why a binding, and why it delegates rather than reimplements
//
// Ten N-PAMP operation-channel bodies (Memory, Capability, Commerce, Immune, Interaction,
// Knowledge, Settlement, Stream, Telemetry, Workflow) already each export a domain-specific
// pair of wrapper functions over the same underlying codec (e.g. memory_api.go's
// EncodeMemoryBody / DecodeMemoryBody). Every one of those pairs applies its own domain schema
// (required keys per frame type) on top of the shared codec. codecbind is the missing
// domain-agnostic sibling: a caller building a new NPAMP-* channel, an ecosystem SDK, or a
// tool that needs to speak the exact same canonical CBOR bytes the wire format uses — without
// adopting any one channel's required-key schema — gets a single, stable, documented API
// instead of having to pick one domain's wrapper or re-derive the encoding from the spec.
//
// # Byte-identity guarantee
//
// Because every encode/decode call in this package is a direct delegation to the Part-1
// codec, any value this package decodes and then re-encodes reproduces the identical
// canonical bytes the Part-1 codec would have produced — the same guarantee the wire format
// itself relies on. This is proven, not merely claimed: codecbind_test.go checks decoded and
// re-encoded values against real object vectors from the pinned, independently-generated
// conformance corpus (test-vectors/v1/conformance-corpus.json), whose expected bytes come from
// a from-scratch Python oracle (test-vectors/gen/*_oracle.py), never from this implementation.
//
// # Accepted / produced Go types
//
// Encode accepts, and Decode produces: uint64, int64 (negative), []byte, string, []any,
// map[uint64]any (keys are always unsigned integers on the wire; nested maps decode
// recursively to map[uint64]any), bool, and nil. Encoding a Go value outside this set is a
// programming error in the caller, exactly as it is for the Part-1 codec; see Encode's doc
// comment for how this package reports that case (as an error, not a panic).
//
// # Fail-closed behavior
//
// Decode REJECTS, unchanged, exactly what the Part-1 codec rejects: indefinite-length items,
// non-shortest-form integers or lengths (a non-canonical encoding), any float (there is no
// accepted position for one in this deterministic subset), any CBOR tag, and map keys that are
// out of canonical order or duplicated. Every rejection is reported through one of the named,
// re-exported sentinel errors (Err*) below, so a caller can distinguish rejection reasons with
// errors.Is — this package never softens a Part-1 rejection into an accept.
package codecbind
