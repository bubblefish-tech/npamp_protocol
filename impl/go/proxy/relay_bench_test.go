// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package proxy

import (
	"crypto/rand"
	"net/http"
	"testing"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// Benchmarks in this file measure the per-carriage-class wire codec cost on the
// relay's hot path -- encoding a foreign request/response into (or decoding it out
// of) the Bridge frame payload a Proxy sends/receives, independent of the network,
// the sdk.Conn handshake, or the AEAD record layer (aead_bench_test.go covers that
// layer separately). Measure with a NON-race build:
// `cd impl/go && GOWORK=off go test -bench=. -benchmem -run=^$` from impl/go, or
// `go test -bench=. -benchmem -run=^$ ./proxy` from impl/go. Do not pin a headline
// ns/op captured under `go test -race`.

// relayBenchBody is a representative 1 KiB request/response body.
var relayBenchBody = func() []byte {
	b := make([]byte, 1024)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}()

// BenchmarkHTTPCarriageEncode / Decode measure the NPAMP-CC-HTTP carriage codec
// (carriage_http.go): a representative POST request with a small header set and a
// 1 KiB body.
func BenchmarkHTTPCarriageEncode(b *testing.B) {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("X-Trace-Id", "bench-trace-id")
	b.ReportAllocs()
	for b.Loop() {
		encodeHTTPCarriageRequest("POST", "/v1/things?x=1", h, relayBenchBody)
	}
}

func BenchmarkHTTPCarriageDecode(b *testing.B) {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("X-Trace-Id", "bench-trace-id")
	wire := encodeHTTPCarriageRequest("POST", "/v1/things?x=1", h, relayBenchBody)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := decodeHTTPCarriageObject(wire, httpKindRequest); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHTTPCarriageRoundTrip measures the combined encode+decode cost -- the
// figure closest to what one relayed HTTP request actually costs this leg.
func BenchmarkHTTPCarriageRoundTrip(b *testing.B) {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("X-Trace-Id", "bench-trace-id")
	b.ReportAllocs()
	for b.Loop() {
		wire := encodeHTTPCarriageRequest("POST", "/v1/things?x=1", h, relayBenchBody)
		if _, err := decodeHTTPCarriageObject(wire, httpKindRequest); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkJSONRPCRequestEncode / Decode measure the NPAMP-CC-JSONRPC carriage codec
// (carriage_jsonrpc.go), which underlies both MCP and A2A carriage.
func BenchmarkJSONRPCRequestEncode(b *testing.B) {
	params := map[string]any{"name": "bench-tool", "arguments": map[string]any{"path": "/tmp/x", "limit": 100}}
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := encodeJSONRPCRequest("tools/call", params, "req-1"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJSONRPCRequestDecode(b *testing.B) {
	params := map[string]any{"name": "bench-tool", "arguments": map[string]any{"path": "/tmp/x", "limit": 100}}
	wire, _, err := encodeJSONRPCRequest("tools/call", params, "req-1")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := decodeJSONRPCRequestOrNotification(wire, false); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGRPCLengthPrefixedMessage measures the gRPC Length-Prefixed-Message codec
// (carriage_grpc.go) at a representative 1 KiB message size.
func BenchmarkGRPCLengthPrefixedMessageEncode(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		encodeGRPCLengthPrefixedMessage(false, relayBenchBody)
	}
}

func BenchmarkGRPCLengthPrefixedMessageDecode(b *testing.B) {
	wire := encodeGRPCLengthPrefixedMessage(false, relayBenchBody)
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := decodeGRPCLengthPrefixedMessage(wire); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkOpaquePayloadRoundTrip measures the NPAMP-CC-OPAQUE carriage codec
// (carriage_opaque.go) on its general case-2 path -- a media type outside the three
// enumerated content types (the raw-TCP / not-otherwise-mapped shape), which attaches
// an OpaqueContentType extension TLV ahead of the raw bytes. It measures the full
// round trip through the Bridge envelope codec (npamp.EncodeBridgePayload /
// npamp.DecodeBridgeFrame), since NPAMP-CC-OPAQUE is defined only as a Bridge payload
// shape, not a standalone wire object.
func BenchmarkOpaquePayloadRoundTrip(b *testing.B) {
	env := npamp.BridgeEnvelope{Protocol: 0x7F, Kind: npamp.BridgeKindNotification}
	const mediaType = "application/octet-stream"
	b.ReportAllocs()
	for b.Loop() {
		wire, err := encodeOpaquePayload(env, mediaType, relayBenchBody)
		if err != nil {
			b.Fatal(err)
		}
		bf, err := npamp.DecodeBridgeFrame(npamp.FrameBridgeNotify, wire)
		if err != nil {
			b.Fatal(err)
		}
		if _, _, err := decodeOpaquePayload(bf.Envelope, bf.Foreign); err != nil {
			b.Fatal(err)
		}
	}
}
