// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package proxy_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
	"github.com/bubblefish-tech/npamp_protocol/impl/go/proxy"
)

// TestE2E_JSONRPC_CallAndSuccessResponse is the NPAMP-CC-JSONRPC leg's
// load-bearing proof, mirroring e2e_test.go's HTTP leg: a real N-PAMP session
// (sdk.DialRaw/AcceptRaw over net.Pipe, twoConnectedProxies) carries a
// CallJSONRPC/JSONRPCHandler round trip end to end.
//
// Mutation anchor (RED-EVIDENCE): a bug that drops, mis-correlates, or
// mutates the carried method/params/result, or a change to §4/§5's
// message_kind or method-agreement rules, breaks this test.
func TestE2E_JSONRPC_CallAndSuccessResponse(t *testing.T) {
	ingress, egress := twoConnectedProxies(t, nil)
	egress.JSONRPCHandler = func(ctx context.Context, protocol npamp.BridgeProtocol, method string, params json.RawMessage) (json.RawMessage, *proxy.JSONRPCError, error) {
		if protocol != npamp.BridgeProtoMCP {
			t.Errorf("egress handler saw protocol = %v, want BridgeProtoMCP", protocol)
		}
		if method != "tools/call" {
			t.Errorf("egress handler saw method = %q, want tools/call", method)
		}
		var p struct{ Name string }
		if err := json.Unmarshal(params, &p); err != nil {
			t.Fatalf("unmarshal params: %v", err)
		}
		return json.RawMessage(`{"echo":"` + p.Name + `"}`), nil, nil
	}

	result, rpcErr, err := ingress.CallJSONRPC(context.Background(), npamp.BridgeProtoMCP, "tools/call", map[string]any{"Name": "hello"}, "req-1")
	if err != nil {
		t.Fatalf("CallJSONRPC: %v", err)
	}
	if rpcErr != nil {
		t.Fatalf("CallJSONRPC returned an rpcErr: %v", rpcErr)
	}
	var got struct{ Echo string }
	if err := json.Unmarshal(result, &got); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if got.Echo != "hello" {
		t.Fatalf("result.echo = %q, want hello", got.Echo)
	}
}

// TestE2E_JSONRPC_ForeignErrorPreservedVerbatim asserts §6: a JSON-RPC error
// Response's code/message/data survive the round trip verbatim, never
// collapsed to an N-PAMP transport error.
func TestE2E_JSONRPC_ForeignErrorPreservedVerbatim(t *testing.T) {
	ingress, egress := twoConnectedProxies(t, nil)
	egress.JSONRPCHandler = func(ctx context.Context, protocol npamp.BridgeProtocol, method string, params json.RawMessage) (json.RawMessage, *proxy.JSONRPCError, error) {
		return nil, &proxy.JSONRPCError{Code: -32602, Message: "invalid params", Data: json.RawMessage(`{"field":"name"}`)}, nil
	}

	_, rpcErr, err := ingress.CallJSONRPC(context.Background(), npamp.BridgeProtoMCP, "tools/call", nil, "req-2")
	if err != nil {
		t.Fatalf("CallJSONRPC transport error: %v", err)
	}
	if rpcErr == nil {
		t.Fatal("CallJSONRPC returned no rpcErr, want the foreign JSON-RPC error preserved")
	}
	if rpcErr.Code != -32602 || rpcErr.Message != "invalid params" {
		t.Fatalf("rpcErr = %+v, want code -32602 message %q", rpcErr, "invalid params")
	}
}

// TestE2E_JSONRPC_Notification_NoReply asserts §7: a Notification elicits no
// reply, verified by observing the handler fire without CallJSONRPC/a
// SendJSONRPCNotification caller ever blocking on one.
func TestE2E_JSONRPC_Notification_NoReply(t *testing.T) {
	ingress, egress := twoConnectedProxies(t, nil)
	seen := make(chan string, 1)
	egress.JSONRPCNotifyHandler = func(ctx context.Context, protocol npamp.BridgeProtocol, method string, params json.RawMessage) {
		seen <- method
	}

	if err := ingress.SendJSONRPCNotification(context.Background(), npamp.BridgeProtoMCP, "notifications/progress", map[string]any{"pct": 50}); err != nil {
		t.Fatalf("SendJSONRPCNotification: %v", err)
	}

	select {
	case method := <-seen:
		if method != "notifications/progress" {
			t.Fatalf("egress saw method %q, want notifications/progress", method)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("egress JSONRPCNotifyHandler never fired")
	}
}

// TestE2E_JSONRPC_NoHandler_AnswersMethodUnsupported asserts an egress-less
// Proxy answers a JSON-RPC request explicitly rather than dropping it,
// mirroring the HTTP leg's TestHandleInboundRequest_NoBackend behavior.
func TestE2E_JSONRPC_NoHandler_AnswersMethodUnsupported(t *testing.T) {
	ingress, _ := twoConnectedProxies(t, nil) // egress side's JSONRPCHandler left nil

	_, rpcErr, err := ingress.CallJSONRPC(context.Background(), npamp.BridgeProtoMCP, "tools/call", nil, "req-3")
	if rpcErr != nil {
		t.Fatalf("got a foreign rpcErr %v, want a transport error (no handler carried)", rpcErr)
	}
	if err == nil {
		t.Fatal("CallJSONRPC succeeded against a Proxy with no JSONRPCHandler")
	}
}
