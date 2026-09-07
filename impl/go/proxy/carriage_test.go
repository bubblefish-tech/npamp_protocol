// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package proxy

import (
	"bytes"
	"net/http"
	"testing"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// TestHTTPCarriageObject_RequestRoundTrip proves encodeHTTPCarriageRequest and
// decodeHTTPCarriageObject are inverse operations on a representative request:
// method, target, a multi-value header, and a body all survive byte-exact.
func TestHTTPCarriageObject_RequestRoundTrip(t *testing.T) {
	h := http.Header{}
	h.Add("X-Trace-Id", "abc123")
	h.Add("Accept", "application/json")
	h.Add("Accept", "text/plain") // multi-value: both entries must survive, in order

	body := []byte(`{"hello":"world"}`)
	wire := encodeHTTPCarriageRequest("POST", "/v1/things?x=1", h, body)

	obj, err := decodeHTTPCarriageObject(wire, httpKindRequest)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if obj.Method != "POST" {
		t.Errorf("Method = %q, want POST", obj.Method)
	}
	if obj.Target != "/v1/things?x=1" {
		t.Errorf("Target = %q, want /v1/things?x=1", obj.Target)
	}
	if !bytes.Equal(obj.Body, body) {
		t.Errorf("Body = %q, want %q", obj.Body, body)
	}
	got := toHTTPHeader(obj.Headers)
	if got.Get("X-Trace-Id") != "abc123" {
		t.Errorf("header X-Trace-Id = %q, want abc123", got.Get("X-Trace-Id"))
	}
	if vs := got.Values("Accept"); len(vs) != 2 || vs[0] != "application/json" || vs[1] != "text/plain" {
		t.Errorf("multi-value Accept = %v, want [application/json text/plain] in order", vs)
	}
}

// TestHTTPCarriageObject_ResponseRoundTrip mirrors the request test for the
// response kind (status + headers + body).
func TestHTTPCarriageObject_ResponseRoundTrip(t *testing.T) {
	h := http.Header{"Content-Type": []string{"application/json"}}
	body := []byte(`{"ok":true}`)
	wire := encodeHTTPCarriageResponse(201, h, body)

	obj, err := decodeHTTPCarriageObject(wire, httpKindResponse)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if obj.Status != 201 {
		t.Errorf("Status = %d, want 201", obj.Status)
	}
	if !bytes.Equal(obj.Body, body) {
		t.Errorf("Body = %q, want %q", obj.Body, body)
	}
	if got := toHTTPHeader(obj.Headers).Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
}

// TestHTTPCarriageObject_HeaderNamesLowercased asserts §4.4: "a sender MUST
// lowercase ASCII field names before carriage."
func TestHTTPCarriageObject_HeaderNamesLowercased(t *testing.T) {
	h := http.Header{"X-Custom-Header": []string{"v"}}
	wire := encodeHTTPCarriageRequest("GET", "/", h, nil)
	obj, err := decodeHTTPCarriageObject(wire, httpKindRequest)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(obj.Headers) != 1 || obj.Headers[0].Name != "x-custom-header" {
		t.Fatalf("Headers = %+v, want lowercased x-custom-header", obj.Headers)
	}
}

// TestHTTPCarriageObject_KindMismatch_Rejected is a §4.7 agreement-check
// MUTATION ANCHOR (RED-EVIDENCE): a decoder that fails to compare the decoded
// `kind` against the frame-implied kind would accept a response object
// presented as a request (or vice versa). Mutating the kind check away in
// decodeHTTPCarriageObject flips this test from PASS to FAIL.
func TestHTTPCarriageObject_KindMismatch_Rejected(t *testing.T) {
	wire := encodeHTTPCarriageResponse(200, nil, nil)
	if _, err := decodeHTTPCarriageObject(wire, httpKindRequest); err == nil {
		t.Fatal("decodeHTTPCarriageObject accepted a response object as a request (kind agreement check did not fire)")
	}
}

// TestHTTPCarriageObject_PseudoHeaderRejected asserts §4.4: "A receiver that
// finds a pseudo-header in headers or trailers MUST reject the frame."
func TestHTTPCarriageObject_PseudoHeaderRejected(t *testing.T) {
	m := map[uint64]any{
		1: uint64(httpKindRequest),
		2: "GET",
		3: "/",
		8: []any{[]any{":path", []byte("/evil")}},
	}
	wire := npamp.EncodeCanonicalCBOR(m)
	if _, err := decodeHTTPCarriageObject(wire, httpKindRequest); err == nil {
		t.Fatal("decodeHTTPCarriageObject accepted a pseudo-header in the headers array")
	}
}

// TestHTTPCarriageObject_RequestMissingMethod_Rejected asserts §4.2: `method`
// is REQUIRED for a request object.
func TestHTTPCarriageObject_RequestMissingMethod_Rejected(t *testing.T) {
	m := map[uint64]any{
		1: uint64(httpKindRequest),
		3: "/",
	}
	wire := npamp.EncodeCanonicalCBOR(m)
	if _, err := decodeHTTPCarriageObject(wire, httpKindRequest); err == nil {
		t.Fatal("decodeHTTPCarriageObject accepted a request object with no method (key 2)")
	}
}

// TestHTTPCarriageObject_ResponseBadStatus_Rejected asserts §4.2: `status`
// MUST be a valid HTTP status code (100-599).
func TestHTTPCarriageObject_ResponseBadStatus_Rejected(t *testing.T) {
	m := map[uint64]any{
		1: uint64(httpKindResponse),
		6: uint64(9999),
	}
	wire := npamp.EncodeCanonicalCBOR(m)
	if _, err := decodeHTTPCarriageObject(wire, httpKindResponse); err == nil {
		t.Fatal("decodeHTTPCarriageObject accepted status 9999")
	}
}
