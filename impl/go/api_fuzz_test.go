// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npamp

import (
	"bytes"
	"reflect"
	"testing"
)

// This file fuzzes the exported *_api.go body/envelope decoders for every N-PAMP-
// native channel (memory, capability, commerce, immune, interaction, knowledge,
// settlement, telemetry, workflow, stream) plus the structurally different
// NPAMP-BRIDGE TLV-envelope codec (bridge_api.go). Every one of these decoders takes
// a frame type plus an arbitrary octet slice and must never panic; each carries at
// least one internal length field (a CBOR map/array/bstr length, or -- for Bridge -- a
// u8-prefixed correlation_id/method/scope field nested inside an outer TLV Length)
// with no independent bound beyond what the decoder itself enforces, so this is the
// *_api decoder half of the dual-length-parser smuggling class the frame/tlv/errorframe
// fuzzers cover at the lower layers.

// seedEnvelopeBodies adds a handful of seeds per frame type: a syntactically valid
// (if not always schema-complete) CBOR map carrying the required frame_kind/corr
// envelope, an empty body, and a bare empty-map body -- enough to give the mutator a
// foothold into "this decodes as a CBOR map" territory without hand-transcribing every
// per-frame-type required-field schema.
func seedEnvelopeBodies(f *testing.F, fts []FrameType, encode func(map[uint64]any) []byte) {
	for _, ft := range fts {
		f.Add(uint16(ft), encode(map[uint64]any{0: uint64(ft), 1: []byte("corr")}))
		f.Add(uint16(ft), []byte{})
		f.Add(uint16(ft), []byte{0xa0}) // canonical empty CBOR map: decodes, but misses frame_kind
	}
	f.Add(uint16(0xFFFF), []byte{0xff}) // an unrecognized frame type plus a lone garbage byte
}

// assertBodyCodecStable is the shared decode-then-encode-then-decode stability check
// for every N-PAMP-native channel whose body codec follows the DecodeXBody/
// EncodeXBody/DecodeXEnvelope shape (memory_api.go and its eight siblings). On a
// successful DecodeXBody it re-encodes the FULL decoded map (which already carries
// every field the body held, including frame_kind and corr) and requires the result
// decode back to an equal map; it also cross-checks the independent DecodeXEnvelope
// entry point agrees with the body decoder on frame_kind, so the two exported API
// surfaces cannot silently diverge on the same bytes.
func assertBodyCodecStable(
	t *testing.T,
	ft FrameType,
	body []byte,
	decodeBody func(FrameType, []byte) (map[uint64]any, error),
	encodeBody func(map[uint64]any) []byte,
	decodeEnvelope func(FrameType, []byte) (uint64, []byte, error),
) {
	m, err := decodeBody(ft, body)
	if err != nil {
		return
	}

	// The decoder's own documented contract rejects a frame_kind that contradicts
	// ft; a successful decode must therefore never carry a disagreeing frame_kind.
	if v, ok := m[0]; ok {
		if u, ok2 := v.(uint64); ok2 && u != uint64(ft) {
			t.Fatalf("decoder accepted a body whose frame_kind (%d) does not match the requested frame type 0x%04x", u, uint16(ft))
		}
	}

	re := encodeBody(m)
	m2, err2 := decodeBody(ft, re)
	if err2 != nil {
		t.Fatalf("re-encoding a successfully decoded body produced bytes the same decoder then rejected: %v (original body % x, decoded %#v)", err2, body, m)
	}
	if !reflect.DeepEqual(m, m2) {
		t.Fatalf("decode -> encode -> decode is not stable: first %#v, second %#v", m, m2)
	}

	fk, _, eerr := decodeEnvelope(ft, body)
	if eerr != nil {
		t.Fatalf("the envelope-only decoder rejected a body the full-body decoder accepted: %v (body % x)", eerr, body)
	}
	if v, ok := m[0]; ok {
		if u, ok2 := v.(uint64); ok2 && u != fk {
			t.Fatalf("frame_kind mismatch between the body decoder (%d) and the envelope decoder (%d) for the same bytes", u, fk)
		}
	}
}

func FuzzDecodeMemoryBody(f *testing.F) {
	seedEnvelopeBodies(f, []FrameType{FrameMemoryCreateReq, FrameMemoryStatusReq, FrameMemoryRetrieveResult, FrameMemoryError, FrameMemoryEvict}, EncodeMemoryBody)
	f.Fuzz(func(t *testing.T, ftRaw uint16, body []byte) {
		assertBodyCodecStable(t, FrameType(ftRaw), body, DecodeMemoryBody, EncodeMemoryBody, DecodeMemoryEnvelope)
	})
}

func FuzzDecodeCapabilityBody(f *testing.F) {
	seedEnvelopeBodies(f, []FrameType{FrameCapIssueReq, FrameCapLookupReq, FrameCapError, FrameCapTokenPresent}, EncodeCapabilityBody)
	f.Fuzz(func(t *testing.T, ftRaw uint16, body []byte) {
		assertBodyCodecStable(t, FrameType(ftRaw), body, DecodeCapabilityBody, EncodeCapabilityBody, DecodeCapabilityEnvelope)
	})
}

func FuzzDecodeCommerceBody(f *testing.F) {
	seedEnvelopeBodies(f, []FrameType{FrameCommerceMandateCreateReq, FrameCommerceMandateCreateResult, FrameCommerceIntentProposeReq}, EncodeCommerceBody)
	f.Fuzz(func(t *testing.T, ftRaw uint16, body []byte) {
		assertBodyCodecStable(t, FrameType(ftRaw), body, DecodeCommerceBody, EncodeCommerceBody, DecodeCommerceEnvelope)
	})
}

func FuzzDecodeImmuneBody(f *testing.F) {
	seedEnvelopeBodies(f, []FrameType{FrameImmuneReportReq, FrameImmuneError, FrameImmuneGossipAdvertise, FrameImmuneGossipPullResult}, EncodeImmuneBody)
	f.Fuzz(func(t *testing.T, ftRaw uint16, body []byte) {
		assertBodyCodecStable(t, FrameType(ftRaw), body, DecodeImmuneBody, EncodeImmuneBody, DecodeImmuneEnvelope)
	})
}

func FuzzDecodeInteractionBody(f *testing.F) {
	seedEnvelopeBodies(f, []FrameType{FrameInteractEvent, FrameInteractEventAck, FrameInteractApprovalReq, FrameInteractError}, EncodeInteractionBody)
	f.Fuzz(func(t *testing.T, ftRaw uint16, body []byte) {
		assertBodyCodecStable(t, FrameType(ftRaw), body, DecodeInteractionBody, EncodeInteractionBody, DecodeInteractionEnvelope)
	})
}

func FuzzDecodeKnowledgeBody(f *testing.F) {
	seedEnvelopeBodies(f, []FrameType{FrameKnowledgeQueryReq, FrameKnowledgeQueryStreamData, FrameKnowledgeError}, EncodeKnowledgeBody)
	f.Fuzz(func(t *testing.T, ftRaw uint16, body []byte) {
		assertBodyCodecStable(t, FrameType(ftRaw), body, DecodeKnowledgeBody, EncodeKnowledgeBody, DecodeKnowledgeEnvelope)
	})
}

func FuzzDecodeSettlementBody(f *testing.F) {
	seedEnvelopeBodies(f, []FrameType{FrameSettleIntentReq, FrameReceiptReq, FrameSettleError, FrameSettleBatchCommitReq}, EncodeSettlementBody)
	f.Fuzz(func(t *testing.T, ftRaw uint16, body []byte) {
		assertBodyCodecStable(t, FrameType(ftRaw), body, DecodeSettlementBody, EncodeSettlementBody, DecodeSettlementEnvelope)
	})
}

func FuzzDecodeTelemetryBody(f *testing.F) {
	seedEnvelopeBodies(f, []FrameType{FrameTelemetryReport, FrameTelemetrySubscribe, FrameTelemetryError}, EncodeTelemetryBody)
	f.Fuzz(func(t *testing.T, ftRaw uint16, body []byte) {
		assertBodyCodecStable(t, FrameType(ftRaw), body, DecodeTelemetryBody, EncodeTelemetryBody, DecodeTelemetryEnvelope)
	})
}

func FuzzDecodeWorkflowBody(f *testing.F) {
	seedEnvelopeBodies(f, []FrameType{FrameWorkflowSubmitReq, FrameWorkflowStepEvent, FrameWorkflowComplete, FrameWorkflowError}, EncodeWorkflowBody)
	f.Fuzz(func(t *testing.T, ftRaw uint16, body []byte) {
		assertBodyCodecStable(t, FrameType(ftRaw), body, DecodeWorkflowBody, EncodeWorkflowBody, DecodeWorkflowEnvelope)
	})
}

// FuzzDecodeStreamEnvelope covers NPAMP-STREAM, which exports only an envelope-level
// decoder (no DecodeStreamBody): the invariant available without a body decoder is
// that a successful decode's frame_kind always equals the frame type it was decoded
// against (ValidateStreamPayload's own documented contract) -- a decoder that verified
// frame_kind against ft but then returned a different value read back would be exactly
// the kind of internal inconsistency a length- or field-smuggling bug would produce.
func FuzzDecodeStreamEnvelope(f *testing.F) {
	for _, ft := range []FrameType{FrameStreamOpen, FrameStreamData, FrameStreamClose, FrameStreamReset, FrameStreamWindowUpdate} {
		f.Add(uint16(ft), EncodeStreamBody(map[uint64]any{0: uint64(ft), 1: uint64(7)}))
		f.Add(uint16(ft), []byte{})
	}
	f.Add(uint16(0xFFFF), []byte{0xa0})

	f.Fuzz(func(t *testing.T, ftRaw uint16, body []byte) {
		ft := FrameType(ftRaw)
		fk, _, err := DecodeStreamEnvelope(ft, body)
		if err != nil {
			return
		}
		if fk != uint64(ft) {
			t.Fatalf("DecodeStreamEnvelope accepted frame type 0x%04x but returned a disagreeing frame_kind %d", uint16(ft), fk)
		}
	})
}

// FuzzDecodeBridgeFrame covers NPAMP-BRIDGE (bridge_api.go/bridge_bodies.go), whose
// payload layout is a fixed sequence of TLVs each carrying u8-length-prefixed
// sub-fields (correlation_id, method) nested inside the outer TLV Length -- two levels
// of length field over one buffer, and the class of bug this guards is an inner field
// length disagreeing with (overrunning past, or under-consuming short of) the outer
// TLV boundary. On success it re-encodes the decoded BridgeFrame and requires an exact
// byte match: the layout is fully determined (fixed field order, definite lengths), so
// decode -> encode must reproduce the input exactly, or some length was misread.
func FuzzDecodeBridgeFrame(f *testing.F) {
	seed := func(ft FrameType, env BridgeEnvelope, safety *SafetyLabel, foreign []byte) {
		f.Add(uint16(ft), EncodeBridgePayload(env, safety, foreign))
	}
	seed(FrameBridgeRequest, BridgeEnvelope{Protocol: BridgeProtoMCP, Kind: BridgeKindRequest, ContentType: BridgeContentJSON, CorrelationID: []byte("c1"), Method: []byte("tools/call")}, nil, []byte(`{"a":1}`))
	seed(FrameBridgeResponse, BridgeEnvelope{Protocol: BridgeProtoA2A, Kind: BridgeKindResponse, ContentType: BridgeContentCBOR, CorrelationID: []byte("c1")},
		&SafetyLabel{Effect: BridgeEffectReadOnly, Scope: []byte("scope")}, []byte{0x01, 0x02})
	seed(FrameBridgeNotify, BridgeEnvelope{Protocol: BridgeProtoMCP, Kind: BridgeKindNotification, ContentType: BridgeContentJSON}, nil, nil)
	f.Add(uint16(FrameBridgeRequest), []byte{})
	f.Add(uint16(FrameBridgeRequest), []byte{0x00, 0x10, 0xFF, 0xFF}) // envelope TLV claims 65535 octets of value with none present
	f.Add(uint16(FramePing), []byte{0x00, 0x10, 0x00, 0x00})          // not a Bridge frame type at all

	f.Fuzz(func(t *testing.T, ftRaw uint16, payload []byte) {
		ft := FrameType(ftRaw)
		bf, err := DecodeBridgeFrame(ft, payload)
		if err != nil {
			return
		}
		re := EncodeBridgeFrame(bf)
		if !bytes.Equal(re, payload) {
			t.Fatalf("decode-then-encode is not stable for Bridge frame type 0x%04x: input % x, re-encoded % x", uint16(ft), payload, re)
		}

		// The independent envelope-only entry point must agree on the same bytes.
		env, eerr := DecodeBridgeEnvelope(ft, payload)
		if eerr != nil {
			t.Fatalf("DecodeBridgeEnvelope rejected a payload DecodeBridgeFrame accepted: %v", eerr)
		}
		if env.Kind != bf.Envelope.Kind || !bytes.Equal(env.CorrelationID, bf.Envelope.CorrelationID) {
			t.Fatalf("DecodeBridgeEnvelope disagrees with DecodeBridgeFrame's envelope for the same bytes: %+v vs %+v", env, bf.Envelope)
		}
	})
}

// FuzzDecodeBridgeTransportError covers the §6 below-foreign-protocol transport-error
// object codec (a single u8 code, u8 msg_len, then msg -- the length field sits
// directly against the buffer's own remaining length with no outer TLV wrapping it).
func FuzzDecodeBridgeTransportError(f *testing.F) {
	f.Add(EncodeBridgeTransportError(BridgeTransportError{Code: BridgeErrNotDelivered, Message: "unreachable"}))
	f.Add(EncodeBridgeTransportError(BridgeTransportError{Code: BridgeErrEnvelopeMalformed}))
	f.Add([]byte{})
	f.Add([]byte{0x01})             // truncated before msg_len
	f.Add([]byte{0x01, 0xFF})       // msg_len claims 255 octets, none present
	f.Add([]byte{0x01, 0x00, 0xAA}) // msg_len=0 but a trailing stray octet remains

	f.Fuzz(func(t *testing.T, data []byte) {
		te, err := DecodeBridgeTransportError(data)
		if err != nil {
			return
		}
		got := EncodeBridgeTransportError(te)
		if !bytes.Equal(got, data) {
			t.Fatalf("decode-then-encode is not stable for transport error code %d: input % x, re-encoded % x", te.Code, data, got)
		}
	})
}

// TestDecodeMemoryBodyRejectsFrameKindMismatch is a direct (non-fuzz) regression for
// the frame_kind-must-equal-ft invariant assertBodyCodecStable also checks via
// fuzzing: a body whose frame_kind names a DIFFERENT frame type -- one whose schema
// the rest of the body happens to satisfy too -- MUST be rejected, never silently
// accepted under the mismatched ft.
func TestDecodeMemoryBodyRejectsFrameKindMismatch(t *testing.T) {
	body := EncodeMemoryBody(map[uint64]any{0: uint64(FrameMemoryCreateReq), 1: []byte("c")})
	if _, err := DecodeMemoryBody(FrameMemoryStatusReq, body); err == nil {
		t.Fatal("DecodeMemoryBody accepted a body whose frame_kind (CreateReq) does not match the requested frame type (StatusReq)")
	}
}

// A local sanity check that seedEnvelopeBodies' frame-type-in-header expectation
// actually matches how the codecs read it (key 0, big-endian irrelevant since CBOR
// integers are self-delimiting) -- guards against a future codec change silently
// invalidating every seed above without any test noticing.
func TestSeedEnvelopeBodiesFrameKindKeyIsZero(t *testing.T) {
	body := EncodeMemoryBody(map[uint64]any{0: uint64(FrameMemoryStatusReq), 1: []byte("c")})
	fk, _, err := DecodeMemoryEnvelope(FrameMemoryStatusReq, body)
	if err != nil {
		t.Fatalf("DecodeMemoryEnvelope: %v", err)
	}
	if fk != uint64(FrameMemoryStatusReq) {
		t.Fatalf("frame_kind = %d, want %d", fk, uint64(FrameMemoryStatusReq))
	}
}
