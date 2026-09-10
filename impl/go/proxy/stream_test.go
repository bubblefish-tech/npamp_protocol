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

	// A WebSocketHandler that returns many events. To make the "cancel stops
	// production" property DETERMINISTIC rather than a producer-vs-cancel-delivery
	// race, the handler blocks after signalling handlerStarted until the test has
	// CONFIRMED the per-stream cancel flag is set on the egress side; only then
	// does it return the events into the producer loop. handleInboundStreamRequest
	// runs in its own goroutine (proxy.go dispatches handleInboundBridgeRequest via
	// `go`), so blocking the handler does NOT block the egress Run loop from
	// processing the inbound cancel frame -- the cancel is therefore guaranteed
	// observed BEFORE the first emission, the boundary case of the §7.2 rule
	// "a cancel observed mid-stream MUST stop the producer from emitting further
	// frames" (here: zero further frames).
	events := make([][]byte, 50)
	for i := range events {
		events[i] = []byte("event")
	}
	// handlerStarted signals that this goroutine has reached the handler --
	// which stream.go's handleInboundStreamRequest only calls AFTER registering
	// the per-stream cancel flag (program order, same goroutine) -- so once it
	// fires the flag is registered and an inbound cancel can be routed to it.
	// cancelObserved unblocks the handler once the test has confirmed the flag is
	// set (the atomicBool + shared mu give the happens-before), eliminating the
	// registration-vs-cancel AND the producer-vs-cancel-delivery races that a
	// fixed sleep would only paper over.
	handlerStarted := make(chan struct{})
	cancelObserved := make(chan struct{})
	egress.WebSocketHandler = func(ctx context.Context, msg []byte) ([][]byte, error) {
		close(handlerStarted)
		<-cancelObserved
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

	// Wait until the egress side has actually SET the per-stream cancel flag (the
	// cancel frame above is processed by handleInboundStreamFrame on the free
	// egress Run goroutine), THEN release the handler. This makes the interleaving
	// deterministic: production starts with the flag already set, so the very
	// first per-event check in stream.go stops it before any BRIDGE_STREAM_DATA.
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		egress.mu.Lock()
		cf, ok := egress.streamCancel[string(corrID)]
		egress.mu.Unlock()
		if ok && cf.get() {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("egress never set the per-stream cancel flag after the cancel frame was sent")
		case <-time.After(time.Millisecond):
		}
	}
	close(cancelObserved)

	// Drain until BRIDGE_STREAM_END; assert ZERO data events arrived. The
	// interleaving is now deterministic (the handler was released only after the
	// cancel flag was confirmed set), so the cooperative per-event check stops the
	// producer before its first emission.
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
	// Mutation anchor: the cancel was observed before the first emission, so the
	// producer MUST emit zero BRIDGE_STREAM_DATA frames. If stream.go's producer
	// loop stops honouring the per-event cancel check, all len(events) frames
	// arrive and this fails.
	if got != 0 {
		t.Fatalf("got %d BRIDGE_STREAM_DATA events, want 0 (the cancel was confirmed set before the first emission and MUST stop production)", got)
	}
	if !sawCancelAck {
		t.Fatal("the terminating BRIDGE_STREAM_END did not carry cancel_ack (§7.2)")
	}
}
