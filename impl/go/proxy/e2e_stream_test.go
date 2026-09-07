// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package proxy_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"
)

// TestE2E_GRPC_UnaryCall is the gRPC leg's load-bearing proof: a real N-PAMP
// session carries CallGRPCUnary/GRPCHandler through the full
// BRIDGE_REQUEST -> BRIDGE_STREAM_DATA -> BRIDGE_STREAM_END sequence
// NPAMP-CC-STREAM defines, with the gRPC Length-Prefixed-Message wire framing
// surviving the round trip byte-exact.
//
// Mutation anchor (RED-EVIDENCE): a bug that drops the event, mis-orders
// event_id, or corrupts the LPM framing breaks this test.
func TestE2E_GRPC_UnaryCall(t *testing.T) {
	ingress, egress := twoConnectedProxies(t, nil)
	egress.GRPCHandler = func(ctx context.Context, method string, req []byte) ([]byte, error) {
		if method != "/pkg.Echo/Call" {
			t.Errorf("egress handler saw method = %q, want /pkg.Echo/Call", method)
		}
		return append([]byte("echo:"), req...), nil
	}

	resp, err := ingress.CallGRPCUnary(context.Background(), "/pkg.Echo/Call", []byte("hello n-pamp"))
	if err != nil {
		t.Fatalf("CallGRPCUnary: %v", err)
	}
	if string(resp) != "echo:hello n-pamp" {
		t.Fatalf("resp = %q, want %q", resp, "echo:hello n-pamp")
	}
}

// TestE2E_GRPC_HandlerError_ReportsTransportFailure asserts a below-protocol
// handler failure surfaces as an error to the caller, never a fabricated
// response.
func TestE2E_GRPC_HandlerError_ReportsTransportFailure(t *testing.T) {
	ingress, egress := twoConnectedProxies(t, nil)
	egress.GRPCHandler = func(ctx context.Context, method string, req []byte) ([]byte, error) {
		return nil, fmt.Errorf("backend unavailable")
	}

	if _, err := ingress.CallGRPCUnary(context.Background(), "/pkg.Echo/Call", []byte("x")); err == nil {
		t.Fatal("CallGRPCUnary succeeded despite a GRPCHandler error")
	}
}

// TestE2E_GRPC_NoHandler_ReportsMethodUnsupported mirrors the JSON-RPC/HTTP
// legs' no-egress-backend behavior for gRPC.
func TestE2E_GRPC_NoHandler_ReportsMethodUnsupported(t *testing.T) {
	ingress, _ := twoConnectedProxies(t, nil)
	if _, err := ingress.CallGRPCUnary(context.Background(), "/pkg.Echo/Call", []byte("x")); err == nil {
		t.Fatal("CallGRPCUnary succeeded against a Proxy with no GRPCHandler")
	}
}

// TestE2E_WebSocket_SingleReply is the WebSocket leg's load-bearing proof: a
// real N-PAMP session carries CallWebSocketMessage/WebSocketHandler through
// the same NPAMP-CC-STREAM sequence as the gRPC leg, verbatim (no LPM
// framing -- carriage_websocket.go).
func TestE2E_WebSocket_SingleReply(t *testing.T) {
	ingress, egress := twoConnectedProxies(t, nil)
	egress.WebSocketHandler = func(ctx context.Context, msg []byte) ([][]byte, error) {
		return [][]byte{append([]byte("echo:"), msg...)}, nil
	}

	replies, err := ingress.CallWebSocketMessage(context.Background(), []byte("hi"))
	if err != nil {
		t.Fatalf("CallWebSocketMessage: %v", err)
	}
	if len(replies) != 1 || string(replies[0]) != "echo:hi" {
		t.Fatalf("replies = %q, want [echo:hi]", replies)
	}
}

// TestE2E_WebSocket_MultipleReplies_OrderedEventIDs proves a multi-event
// reply stream is delivered in order with the §5.1 strictly-increasing
// event_id invariant enforced on the consumer side (carriage_stream.go
// streamEventTracker, exercised end to end here).
func TestE2E_WebSocket_MultipleReplies_OrderedEventIDs(t *testing.T) {
	ingress, egress := twoConnectedProxies(t, nil)
	egress.WebSocketHandler = func(ctx context.Context, msg []byte) ([][]byte, error) {
		return [][]byte{[]byte("one"), []byte("two"), []byte("three")}, nil
	}

	replies, err := ingress.CallWebSocketMessage(context.Background(), []byte("go"))
	if err != nil {
		t.Fatalf("CallWebSocketMessage: %v", err)
	}
	want := [][]byte{[]byte("one"), []byte("two"), []byte("three")}
	if len(replies) != len(want) {
		t.Fatalf("got %d replies, want %d", len(replies), len(want))
	}
	for i := range want {
		if !bytes.Equal(replies[i], want[i]) {
			t.Fatalf("replies[%d] = %q, want %q (order not preserved)", i, replies[i], want[i])
		}
	}
}

// TestE2E_WebSocket_ZeroReplies proves an empty reply stream (zero data
// frames, just the terminating BRIDGE_STREAM_END, §2 "Stream: ... zero or
// more BRIDGE_STREAM_DATA frames") completes cleanly rather than hanging.
func TestE2E_WebSocket_ZeroReplies(t *testing.T) {
	ingress, egress := twoConnectedProxies(t, nil)
	egress.WebSocketHandler = func(ctx context.Context, msg []byte) ([][]byte, error) {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	replies, err := ingress.CallWebSocketMessage(ctx, []byte("go"))
	if err != nil {
		t.Fatalf("CallWebSocketMessage: %v", err)
	}
	if len(replies) != 0 {
		t.Fatalf("replies = %q, want none", replies)
	}
}
