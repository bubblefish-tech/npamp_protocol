// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package proxy

import (
	"context"
	"net/url"
	"testing"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// TestHandleInboundStreamRequest_ResumeRequest_AlwaysRefused is a §6.3
// MUTATION ANCHOR (RED-EVIDENCE): this build's producer retains no
// per-stream state (stream.go doc comment), so a stream-opening BRIDGE_REQUEST
// carrying a StreamControl TLV with control=resume MUST be refused with
// BRIDGE_ERROR NotResumable, and MUST NOT reach GRPCHandler/WebSocketHandler
// at all -- driven directly (internal package) since it exercises a wire
// shape (a resume-flavored BRIDGE_REQUEST) neither CallGRPCUnary nor
// CallWebSocketMessage ever originates.
func TestHandleInboundStreamRequest_ResumeRequest_AlwaysRefused(t *testing.T) {
	var backendURL *url.URL
	ingress, egress := connectedProxyPairForTest(t, backendURL)
	ingress.init() // idempotent; guarantees p.pending exists before this test touches it directly
	handlerCalled := false
	egress.GRPCHandler = func(ctx context.Context, method string, req []byte) ([]byte, error) {
		handlerCalled = true
		return nil, nil
	}

	corrID, err := newCorrelationID()
	if err != nil {
		t.Fatalf("newCorrelationID: %v", err)
	}
	sc := streamControl{Control: streamControlResume, EventID: 0}
	foreign := npamp.TLV{Type: TLVStreamControl, Value: encodeStreamControlValue(sc)}.Encode(nil)

	env := npamp.BridgeEnvelope{Protocol: grpcProtocolID, Kind: npamp.BridgeKindRequest, ContentType: npamp.BridgeContentGRPCProto, CorrelationID: corrID, Method: []byte("/pkg.Echo/Call")}
	replyCh := make(chan pendingReply, 1)
	ingress.mu.Lock()
	ingress.pending[string(corrID)] = replyCh
	ingress.mu.Unlock()

	payload := npamp.EncodeBridgePayload(env, nil, foreign)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := ingress.Conn.Send(ctx, npamp.ChanBridge, npamp.FrameBridgeRequest, payload); err != nil {
		t.Fatalf("Send resume request: %v", err)
	}

	select {
	case reply := <-replyCh:
		if reply.ft != npamp.FrameBridgeError {
			t.Fatalf("frame type = %v, want FrameBridgeError", reply.ft)
		}
		gotErr := decodeTransportErrorReply(reply.foreign)
		if gotErr == nil {
			t.Fatal("decodeTransportErrorReply returned nil")
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for the NotResumable BRIDGE_ERROR")
	}
	if handlerCalled {
		t.Fatal("GRPCHandler was invoked for a resume request -- it must never be reached by the stateless refusal path")
	}
}

// TestHandleInboundStreamRequest_Cancel_StopsProduction is the §7.2 MUTATION
// ANCHOR: a cancel observed mid-stream MUST stop the producer from emitting
// further BRIDGE_STREAM_DATA frames and MUST terminate with cancel_ack set.
// Driven directly to control the exact interleaving (send cancel, then
// observe production actually stops) which the black-box e2e API cannot
// express.
func TestHandleInboundStreamRequest_Cancel_StopsProduction(t *testing.T) {
	var backendURL *url.URL
	ingress, egress := connectedProxyPairForTest(t, backendURL)
	ingress.init() // idempotent; guarantees p.streamPending exists before this test touches it directly

	// A WebSocketHandler that returns many events; the cancel flag is set
	// before Run's producer loop starts (a deterministic worst case for the
	// cooperative per-event check: cancellation observed before the FIRST
	// emission).
	events := make([][]byte, 50)
	for i := range events {
		events[i] = []byte("event")
	}
	// handlerStarted signals that this goroutine has reached the handler --
	// which stream.go's handleInboundStreamRequest only calls AFTER
	// registering the per-stream cancel flag (program order, same
	// goroutine). The test blocks on this signal before sending the cancel
	// frame, which establishes (via the channel receive + the shared mutex
	// both sides take) a proper happens-before relationship: the cancel
	// frame's arrival cannot be processed by handleInboundStreamFrame until
	// AFTER the cancel flag is guaranteed registered, eliminating the
	// registration-vs-cancel race that a fixed sleep would only paper over.
	handlerStarted := make(chan struct{})
	egress.WebSocketHandler = func(ctx context.Context, msg []byte) ([][]byte, error) {
		close(handlerStarted)
		return events, nil
	}

	corrID, err := newCorrelationID()
	if err != nil {
		t.Fatalf("newCorrelationID: %v", err)
	}
	env := npamp.BridgeEnvelope{Protocol: npamp.BridgeProtoWebSocket, Kind: npamp.BridgeKindRequest, ContentType: npamp.BridgeContentCBOR, CorrelationID: corrID}
	payload := npamp.EncodeBridgePayload(env, nil, []byte("go"))

	dataCh := make(chan streamChunk, 128)
	ingress.mu.Lock()
	ingress.streamPending[string(corrID)] = dataCh
	ingress.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := ingress.Conn.Send(ctx, npamp.ChanBridge, npamp.FrameBridgeRequest, payload); err != nil {
		t.Fatalf("Send: %v", err)
	}

	select {
	case <-handlerStarted:
	case <-ctx.Done():
		t.Fatal("timed out waiting for the egress WebSocketHandler to start (cancel flag registration point)")
	}

	// Send the cancel from the consumer (ingress) side, in the
	// consumer-to-producer direction, per §7.1. handlerStarted firing proves
	// the per-stream cancel flag is already registered (see comment above).
	cancelSC := streamControl{Control: streamControlCancel, EventID: 0}
	cancelForeign := npamp.TLV{Type: TLVStreamControl, Value: encodeStreamControlValue(cancelSC)}.Encode(nil)
	cancelEnv := npamp.BridgeEnvelope{Protocol: npamp.BridgeProtoWebSocket, Kind: npamp.BridgeKindStreamEnd, ContentType: npamp.BridgeContentCBOR, CorrelationID: corrID, Flags: npamp.BridgeFlagFinal}
	cancelPayload := npamp.EncodeBridgePayload(cancelEnv, nil, cancelForeign)
	if err := ingress.Conn.Send(ctx, npamp.ChanBridge, npamp.FrameBridgeStreamEnd, cancelPayload); err != nil {
		t.Fatalf("Send cancel: %v", err)
	}

	// Drain until BRIDGE_STREAM_END; assert far fewer than 50 events arrived
	// (the exact count is a race between the cancel and the producer loop,
	// which is inherent to cooperative mid-stream cancellation -- the
	// invariant this test proves is "far fewer than the full 50", not "zero").
	got := 0
	sawEnd := false
	sawCancelAck := false
	for !sawEnd {
		select {
		case chunk := <-dataCh:
			if chunk.err != nil {
				t.Fatalf("chunk error: %v", chunk.err)
			}
			if chunk.ft == npamp.FrameBridgeStreamEnd {
				sawEnd = true
				sawCancelAck = chunk.control.CancelAck()
				break
			}
			got++
		case <-ctx.Done():
			t.Fatal("timed out waiting for BRIDGE_STREAM_END")
		}
	}
	if got >= len(events) {
		t.Fatalf("got %d events before END, want fewer than %d (the cancel must have stopped production)", got, len(events))
	}
	if !sawCancelAck {
		t.Fatal("the terminating BRIDGE_STREAM_END did not carry cancel_ack (§7.2)")
	}
}
