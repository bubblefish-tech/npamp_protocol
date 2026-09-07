// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package proxy

import (
	"bytes"
	"encoding/binary"
	"net/http"
	"testing"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// R14 E2.22: a shared corpus proving each carriage class's wrap-then-unwrap
// is octet-exact, graded NON-CIRCULARLY — every "oracle" byte sequence below
// is constructed by hand in THIS file, independent of the encode function it
// grades (matching the existing independent-construction style
// carriage_test.go's own pseudo-header/malformed tests already use:
// npamp.EncodeCanonicalCBOR over a hand-built map, never the codec's own
// wrapper). No oracle value here is derived by calling the function under
// test.
//
// Scope note (honest, per this task's own caution): this file is Go-only.
// impl/rust/src has NO Bridge/carriage implementation at all (grep of
// "Bridge" across impl/rust/src/*.rs finds only the CHAN_BRIDGE channel
// constant, no BridgeEnvelope, no carriage codec) — a larger, newly
// discovered gap than this task's framing assumed ("impl/go/proxy/
// carriage_*.go already has jsonrpc/http/stream carriage — extend to a
// shared corpus test" undercounts the work: extending to Go==Rust==oracle
// requires building the Rust Bridge/carriage layer from nothing first, not
// merely wiring an existing Rust codec into a shared test). That is
// deliberately NOT attempted here — a rushed from-scratch cross-language
// wire-format port risks exactly the fabricated-parity class of defect the
// project's own rules forbid (F3: expected values must never come from the
// implementation under test; a hastily-ported "parity" claim that turns out
// wrong is worse than an honestly-scoped Go-only corpus). See this build's
// report for the recommended follow-up.
//
// This file adds NOTHING to test-vectors/v1/ or harness/runner/corpus/ (the
// hash-pinned cross-language conformance corpus MANIFEST.sha256/PIN.json
// cover) and touches no frozen CDDL/registry/wire byte — confirmed by
// grepping MANIFEST.sha256 for "impl/go/proxy" (zero hits) before this file
// was added. No re-pin is required.

// ---------------------------------------------------------------------------
// Case 1 — MCP/A2A, NPAMP-CC-JSONRPC (spec/companion/20_carriage_jsonrpc.md)
// ---------------------------------------------------------------------------

// jsonrpcOracleRequest is the independently hand-written expected wire bytes
// for encodeJSONRPCRequest("ping", nil, "1"): Go's encoding/json.Marshal of
// a map[string]any sorts object keys lexicographically (a documented,
// already-graded stdlib property this test does not re-verify) — "id" <
// "jsonrpc" < "method" — so the expected byte sequence is fully determined
// independent of running the function under test.
var jsonrpcOracleRequest = []byte(`{"id":"1","jsonrpc":"2.0","method":"ping"}`)

func TestSharedCorpus_JSONRPC_WrapThenUnwrap_ByteIdentical(t *testing.T) {
	wire, corrID, err := encodeJSONRPCRequest("ping", nil, "1")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !bytes.Equal(wire, jsonrpcOracleRequest) {
		t.Fatalf("wrap mismatch:\n got  %s\n want %s (independent oracle)", wire, jsonrpcOracleRequest)
	}
	if string(corrID) != `"1"` {
		t.Fatalf("correlation_id = %q, want %q", corrID, `"1"`)
	}

	// Unwrap the ORACLE bytes (not the encoder's own output) through the real
	// decode path — proves decode agrees with an independently-authored wire
	// value, not merely with whatever this package's own encoder happens to
	// produce.
	obj, err := decodeJSONRPCRequestOrNotification(jsonrpcOracleRequest, false)
	if err != nil {
		t.Fatalf("unwrap of independent oracle bytes: %v", err)
	}
	if obj.Method != "ping" {
		t.Fatalf("unwrapped Method = %q, want ping", obj.Method)
	}
	gotCorrID, err := jsonrpcCorrelationID(obj.ID)
	if err != nil {
		t.Fatalf("jsonrpcCorrelationID: %v", err)
	}
	if string(gotCorrID) != `"1"` {
		t.Fatalf("unwrapped correlation_id = %q, want %q", gotCorrID, `"1"`)
	}
}

// ---------------------------------------------------------------------------
// Case 2 — public-LLM/HTTP, NPAMP-CC-HTTP (spec/companion/21_carriage_http.md)
// ---------------------------------------------------------------------------

func TestSharedCorpus_HTTP_WrapThenUnwrap_ByteIdentical(t *testing.T) {
	// Independent oracle: a hand-built CBOR map literal, bypassing
	// encodeHTTPCarriageRequest's own object-construction entirely (only the
	// already-graded, shared npamp.EncodeCanonicalCBOR primitive is reused —
	// exactly the technique carriage_test.go's own negative tests already use).
	oracleMap := map[uint64]any{
		1: uint64(httpKindRequest),
		2: "GET",
		3: "/v1/ping",
	}
	oracle := npamp.EncodeCanonicalCBOR(oracleMap)

	wire := encodeHTTPCarriageRequest("GET", "/v1/ping", http.Header{}, nil)
	if !bytes.Equal(wire, oracle) {
		t.Fatalf("wrap mismatch:\n got  %x\n want %x (independent oracle)", wire, oracle)
	}

	obj, err := decodeHTTPCarriageObject(oracle, httpKindRequest)
	if err != nil {
		t.Fatalf("unwrap of independent oracle bytes: %v", err)
	}
	if obj.Method != "GET" || obj.Target != "/v1/ping" {
		t.Fatalf("unwrapped object = %+v, want Method=GET Target=/v1/ping", obj)
	}
	if len(obj.Headers) != 0 || len(obj.Body) != 0 {
		t.Fatalf("unwrapped object carries unexpected headers/body: %+v", obj)
	}
}

// ---------------------------------------------------------------------------
// Case 3 — SSE/streaming, NPAMP-CC-STREAM (spec/companion/23_carriage_streaming.md)
// ---------------------------------------------------------------------------

// buildOracleStreamControlTLV independently constructs the exact §5.2/§5.3
// bytes a StreamControl TLV + trailing opaque event must produce: a 4-octet
// TLV header (Type 0x0011 BE, Length 11 BE) followed by the 11-octet fixed
// value (version, control, flags, event_id BE u64), followed by the raw
// event bytes verbatim. Built with encoding/binary directly — it does not
// call encodeStreamControlValue or the TLV type this package composes with.
func buildOracleStreamControlTLV(control, flags uint8, eventID uint64, event []byte) []byte {
	out := make([]byte, 0, 4+11+len(event))
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint16(hdr[0:2], 0x0011) // TLVStreamControl
	binary.BigEndian.PutUint16(hdr[2:4], 11)     // fixed value length, §5.2
	out = append(out, hdr...)
	val := make([]byte, 11)
	val[0] = 0x01 // streamControlVersion
	val[1] = control
	val[2] = flags
	binary.BigEndian.PutUint64(val[3:11], eventID)
	out = append(out, val...)
	out = append(out, event...)
	return out
}

func TestSharedCorpus_STREAM_WrapThenUnwrap_ByteIdentical(t *testing.T) {
	sc := streamControl{Control: streamControlData, Flags: streamFlagResumable, EventID: 42}
	event := []byte("event-payload")

	oracle := buildOracleStreamControlTLV(streamControlData, streamFlagResumable, 42, event)

	wireValue := encodeStreamControlValue(sc)
	wireTLV := npamp.TLV{Type: TLVStreamControl, Value: wireValue}.Encode(nil)
	wire := append(append([]byte(nil), wireTLV...), event...)
	if !bytes.Equal(wire, oracle) {
		t.Fatalf("wrap mismatch:\n got  %x\n want %x (independent oracle)", wire, oracle)
	}

	gotSC, remaining, err := decodeLeadingStreamControl(oracle)
	if err != nil {
		t.Fatalf("unwrap of independent oracle bytes: %v", err)
	}
	if gotSC.Control != streamControlData || gotSC.Flags != streamFlagResumable || gotSC.EventID != 42 {
		t.Fatalf("unwrapped control = %+v, want {Control:%d Flags:%d EventID:42}", gotSC, streamControlData, streamFlagResumable)
	}
	if !gotSC.Resumable() {
		t.Fatalf("unwrapped control must report Resumable() true (flags carried the resumable bit)")
	}
	if !bytes.Equal(remaining, event) {
		t.Fatalf("unwrapped remaining (the opaque event) = %q, want %q — the event MUST be carried verbatim, never re-parsed", remaining, event)
	}
}
