// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package proxy

import (
	"bytes"
	"encoding/json"
	"testing"
)

// TestJSONRPCRequest_RoundTrip proves encodeJSONRPCRequest and
// decodeJSONRPCRequestOrNotification are inverse operations: method, params,
// and the derived correlation_id all survive, and the id token is carried
// byte-exact (§8.2).
func TestJSONRPCRequest_RoundTrip(t *testing.T) {
	wire, corrID, err := encodeJSONRPCRequest("tools/call", map[string]any{"name": "echo"}, "7")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if string(corrID) != `"7"` {
		t.Errorf("correlation_id = %q, want the id token %q (§8.2: quotes included for a string id)", corrID, `"7"`)
	}
	obj, err := decodeJSONRPCRequestOrNotification(wire, false)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if obj.Method != "tools/call" {
		t.Errorf("Method = %q, want tools/call", obj.Method)
	}
	if string(obj.ID) != `"7"` {
		t.Errorf("ID = %q, want %q", obj.ID, `"7"`)
	}
}

// TestJSONRPCRequest_NumberID_CorrelationIDIsExactToken asserts §8.2's number
// case: the id token is carried exactly as it appeared, not re-formatted.
func TestJSONRPCRequest_NumberID_CorrelationIDIsExactToken(t *testing.T) {
	_, corrID, err := encodeJSONRPCRequest("ping", nil, 42)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if string(corrID) != "42" {
		t.Errorf("correlation_id = %q, want 42", corrID)
	}
}

// TestJSONRPCNotification_NoID asserts §7: a Notification carries no id
// member, and decodeJSONRPCRequestOrNotification(..., wantNotify=true)
// requires that.
func TestJSONRPCNotification_RoundTrip(t *testing.T) {
	wire, err := encodeJSONRPCNotification("progress", map[string]any{"pct": 50})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	obj, err := decodeJSONRPCRequestOrNotification(wire, true)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if obj.Method != "progress" {
		t.Errorf("Method = %q, want progress", obj.Method)
	}
	if obj.ID != nil {
		t.Errorf("ID = %q, want absent (nil) for a Notification", obj.ID)
	}
}

// TestJSONRPCNotification_WithID_Rejected is a §7 MUTATION ANCHOR
// (RED-EVIDENCE): a Notification object that carries an id member MUST be
// rejected under BRIDGE_NOTIFY -- a receiver that failed to check this could
// silently treat a live Request as a fire-and-forget Notification, dropping
// the caller's expected reply forever.
func TestJSONRPCNotification_WithID_Rejected(t *testing.T) {
	wire := []byte(`{"jsonrpc":"2.0","method":"x","id":1}`)
	if _, err := decodeJSONRPCRequestOrNotification(wire, true); err == nil {
		t.Fatal("decodeJSONRPCRequestOrNotification(wantNotify=true) accepted an object carrying an id member")
	}
}

// TestJSONRPCRequest_NoID_Rejected is the mirror MUTATION ANCHOR: a Request
// decode path (wantNotify=false) MUST reject an object with no id member
// (that object is a Notification, §7, and belongs on BRIDGE_NOTIFY instead).
func TestJSONRPCRequest_NoID_Rejected(t *testing.T) {
	wire := []byte(`{"jsonrpc":"2.0","method":"x"}`)
	if _, err := decodeJSONRPCRequestOrNotification(wire, false); err == nil {
		t.Fatal("decodeJSONRPCRequestOrNotification(wantNotify=false) accepted an object with no id member")
	}
}

// TestJSONRPCObject_WrongVersion_Rejected asserts §3: a receiver that finds
// jsonrpc absent or unequal to "2.0" MUST reject the frame.
func TestJSONRPCObject_WrongVersion_Rejected(t *testing.T) {
	wire := []byte(`{"jsonrpc":"1.0","method":"x","id":1}`)
	if _, err := parseJSONRPCObject(wire); err == nil {
		t.Fatal("parseJSONRPCObject accepted jsonrpc:\"1.0\"")
	}
	wireMissing := []byte(`{"method":"x","id":1}`)
	if _, err := parseJSONRPCObject(wireMissing); err == nil {
		t.Fatal("parseJSONRPCObject accepted an object with no jsonrpc member")
	}
}

// TestJSONRPCSuccessResponse_WithErrorMember_Rejected is a §5/§6 MUTATION
// ANCHOR: a Response carrying BOTH shapes (or specifically an error member)
// MUST be carried as BRIDGE_ERROR, never accepted by the BRIDGE_RESPONSE
// decode path.
func TestJSONRPCSuccessResponse_WithErrorMember_Rejected(t *testing.T) {
	wire := []byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"x"}}`)
	if _, err := decodeJSONRPCSuccessResponse(wire); err == nil {
		t.Fatal("decodeJSONRPCSuccessResponse accepted an object carrying an error member")
	}
}

// TestJSONRPCSuccessResponse_NoResult_Rejected asserts §5: result is REQUIRED.
func TestJSONRPCSuccessResponse_NoResult_Rejected(t *testing.T) {
	wire := []byte(`{"jsonrpc":"2.0","id":1}`)
	if _, err := decodeJSONRPCSuccessResponse(wire); err == nil {
		t.Fatal("decodeJSONRPCSuccessResponse accepted an object with no result member")
	}
}

// TestJSONRPCErrorResponse_PreservesCodeMessageDataVerbatim asserts §6: the
// error code/message/data MUST be preserved exactly, never collapsed,
// remapped, or reduced to free text -- this is the error-map graded-bar
// assertion for the JSON-RPC leg.
func TestJSONRPCErrorResponse_PreservesCodeMessageDataVerbatim(t *testing.T) {
	wire := []byte(`{"jsonrpc":"2.0","id":9,"error":{"code":-32602,"message":"invalid params","data":{"field":"name"}}}`)
	obj, err := decodeJSONRPCErrorResponse(wire)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	var je JSONRPCError
	if err := json.Unmarshal(obj.Error, &je); err != nil {
		t.Fatalf("unmarshal error object: %v", err)
	}
	if je.Code != -32602 {
		t.Errorf("Code = %d, want -32602 (JSON-RPC pre-defined Invalid params)", je.Code)
	}
	if je.Message != "invalid params" {
		t.Errorf("Message = %q, want %q", je.Message, "invalid params")
	}
	if !bytes.Contains(je.Data, []byte(`"field"`)) {
		t.Errorf("Data = %q, want it to contain the original data member verbatim", je.Data)
	}
}

// TestJSONRPCErrorResponse_NoErrorMember_Rejected asserts the BRIDGE_ERROR
// decode path requires an error member (a success Response reaching this
// path is itself a caller-routing bug, not something the codec should paper
// over).
func TestJSONRPCErrorResponse_NoErrorMember_Rejected(t *testing.T) {
	wire := []byte(`{"jsonrpc":"2.0","id":1,"result":true}`)
	if _, err := decodeJSONRPCErrorResponse(wire); err == nil {
		t.Fatal("decodeJSONRPCErrorResponse accepted an object with no error member")
	}
}

// TestJSONRPCMethodAgrees is the §4 agreement-check MUTATION ANCHOR
// (RED-EVIDENCE): the BridgeEnvelope method field MUST equal the carried
// object's method member byte-for-byte.
func TestJSONRPCMethodAgrees(t *testing.T) {
	wire, _, err := encodeJSONRPCRequest("tools/call", nil, "1")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	obj, err := decodeJSONRPCRequestOrNotification(wire, false)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !jsonrpcMethodAgrees([]byte("tools/call"), obj) {
		t.Fatal("jsonrpcMethodAgrees rejected a matching envelope method")
	}
	if jsonrpcMethodAgrees([]byte("tools/list"), obj) {
		t.Fatal("jsonrpcMethodAgrees accepted a mismatched envelope method")
	}
}

// TestJSONRPCNullID_GetsDistinctCorrelationIDs asserts §8.4: a Null id MUST
// NOT be derived as the literal token `null` for correlation_id (which would
// collide across concurrent Null-id Requests) -- each call gets a distinct,
// non-empty correlation_id.
func TestJSONRPCNullID_GetsDistinctCorrelationIDs(t *testing.T) {
	_, corr1, err := encodeJSONRPCRequest("x", nil, nil)
	if err != nil {
		t.Fatalf("encode 1: %v", err)
	}
	_, corr2, err := encodeJSONRPCRequest("x", nil, nil)
	if err != nil {
		t.Fatalf("encode 2: %v", err)
	}
	if len(corr1) == 0 || len(corr2) == 0 {
		t.Fatal("a Null-id Request MUST still supply a non-empty correlation_id (§8.4)")
	}
	if bytes.Equal(corr1, corr2) {
		t.Fatal("two Null-id Requests got the SAME correlation_id -- §8.4 requires distinct allocation to avoid collision")
	}
}
