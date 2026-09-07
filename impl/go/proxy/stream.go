// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package proxy

import (
	"context"
	"fmt"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// Proxy wiring shared by the two NPAMP-CC-STREAM legs (gRPC, carriage_grpc.go/
// grpc.go; WebSocket, carriage_websocket.go/websocket.go). Composes the same
// already-established impl/go/sdk.Conn and the same Run() receive loop as the
// HTTP and JSON-RPC legs (proxy.go, jsonrpc.go); adds no new wire behavior
// beyond what carriage_stream.go's codec already defines.

// streamCarriageClass distinguishes the two STREAM-class legs this build
// carries, both dispatched by handleInboundBridgeRequest via protocol_id.
type streamCarriageClass uint8

const (
	grpcStreamClass streamCarriageClass = iota
	websocketStreamClass
)

// streamContentType returns the BridgeEnvelope content_type this build uses
// for a class's stream frames. gRPC has an exact, already-reserved Part-1 code
// point (application/grpc+proto, bridge.go). WebSocket generic carriage has no
// purpose-built "opaque octets" content_type in the current Part-1 core (only
// JSON/CBOR/gRPC+proto are defined) -- this is a REPORT-BACK, not something
// this build invents a value for: NPAMP-CC-OPAQUE's content-type
// discriminator model would be the natural fit but that class is out of this
// build's scope (doc.go). Pending that, this build declares CBOR, matching
// the neutral-binary convention this package's own sendBridgeError already
// uses for a below-protocol transport error; a receiver does not reject an
// unregistered content_type value (bridge.go), so this is advisory metadata
// only -- the WebSocket message octets themselves are always carried verbatim
// regardless of the declared value.
func streamContentType(class streamCarriageClass) npamp.BridgeContentType {
	if class == grpcStreamClass {
		return npamp.BridgeContentGRPCProto
	}
	return npamp.BridgeContentCBOR
}

// openConsumerStream is the shared INGRESS primitive: it originates the
// stream-opening BRIDGE_REQUEST (§4 baseline; carrying no StreamControl TLV,
// which is reserved for a resume request per §6.2) and registers a waiter for
// BOTH possible reply shapes -- a BRIDGE_ERROR (delivered via the ordinary
// p.pending map/deliverReply, e.g. MethodUnsupported/NotResumable/
// NotDelivered) and the BRIDGE_STREAM_DATA/BRIDGE_STREAM_END sequence
// (delivered via p.streamPending/handleInboundStreamFrame). Both waiters
// share one correlation_id; whichever fires first is authoritative for that
// exchange, matching NPAMP-BRIDGE §5's single correlation-id-keyed reply
// model.
func (p *Proxy) openConsumerStream(ctx context.Context, protocol npamp.BridgeProtocol, contentType npamp.BridgeContentType, method string, event []byte) (errCh chan pendingReply, dataCh chan streamChunk, corrID []byte, cleanup func(), err error) {
	p.init()
	if p.Conn == nil {
		return nil, nil, nil, nil, ErrNoConn
	}
	corrID, err = newCorrelationID()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	key := string(corrID)
	errCh = make(chan pendingReply, 1)
	dataCh = make(chan streamChunk, 32)
	p.mu.Lock()
	p.pending[key] = errCh
	p.streamPending[key] = dataCh
	p.mu.Unlock()
	cleanup = func() {
		p.mu.Lock()
		delete(p.pending, key)
		delete(p.streamPending, key)
		p.mu.Unlock()
	}

	env := npamp.BridgeEnvelope{Protocol: protocol, Kind: npamp.BridgeKindRequest, ContentType: contentType, CorrelationID: corrID}
	if method != "" {
		env.Method = []byte(method)
	}
	payload := npamp.EncodeBridgePayload(env, nil, event)
	if serr := p.Conn.Send(ctx, npamp.ChanBridge, npamp.FrameBridgeRequest, payload); serr != nil {
		cleanup()
		return nil, nil, nil, nil, fmt.Errorf("npamp/proxy: carrying stream-open request over N-PAMP: %w", serr)
	}
	return errCh, dataCh, corrID, cleanup, nil
}

// collectStream drains dataCh (racing errCh) until BRIDGE_STREAM_END,
// enforcing the §5.1 event-id invariant on the consumer side and returning
// the ordered event payloads.
func collectStream(ctx context.Context, errCh chan pendingReply, dataCh chan streamChunk) ([][]byte, error) {
	var tracker streamEventTracker
	var events [][]byte
	for {
		select {
		case reply := <-errCh:
			return nil, decodeStreamOpenErrorReply(reply)
		case chunk, ok := <-dataCh:
			if !ok {
				return nil, fmt.Errorf("npamp/proxy: stream channel closed unexpectedly")
			}
			if chunk.err != nil {
				return nil, chunk.err
			}
			if err := tracker.accept(chunk.control.EventID); err != nil {
				return nil, err
			}
			if chunk.ft == npamp.FrameBridgeStreamEnd {
				return events, nil
			}
			events = append(events, chunk.event)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// decodeStreamOpenErrorReply turns a BRIDGE_ERROR pendingReply for a
// stream-open request into a Go error. Every BRIDGE_ERROR this package's own
// STREAM-class egress side sends (handleInboundStreamRequest) is an N-PAMP
// transport error (never a foreign error object -- NPAMP-CC-STREAM defines no
// foreign-error carriage of its own, unlike NPAMP-CC-JSONRPC §6), so this is
// simpler than jsonrpc.go's decodeJSONRPCReply.
func decodeStreamOpenErrorReply(reply pendingReply) error {
	if reply.err != nil {
		return reply.err
	}
	return decodeTransportErrorReply(reply.foreign)
}

// handleInboundStreamRequest is the NPAMP-CC-STREAM EGRESS path for the
// stream-opening BRIDGE_REQUEST (§4/§6.2): frame is already decoded
// (handleInboundBridgeRequest). class selects GRPCHandler or WebSocketHandler.
//
// Producer policy (honestly scoped, matching doc.go's own "Not yet built"
// convention): this build's producer retains NO per-stream state, so it never
// asserts `resumable` (§6.1) and answers every resume request (§6.2, detected
// by a leading StreamControl TLV with control=resume) with BRIDGE_ERROR
// NotResumable (§6.3 option 3 -- fully spec-conformant: "If the producer can
// neither resume nor restart, it MUST reply BRIDGE_ERROR ... NotResumable").
// A fresh (non-resume) request's handler-produced events are emitted as an
// ordinary BRIDGE_STREAM_DATA sequence terminated by BRIDGE_STREAM_END,
// checking the per-stream atomicBool cancel flag between emissions so a §7.1
// upstream cancel genuinely stops production (§7.2) rather than merely being
// acknowledged after the fact.
func (p *Proxy) handleInboundStreamRequest(ctx context.Context, frame npamp.BridgeFrame, class streamCarriageClass) {
	protocol := frame.Envelope.Protocol
	corrID := frame.Envelope.CorrelationID
	contentType := streamContentType(class)

	if sc, _, err := decodeLeadingStreamControl(frame.Foreign); err == nil && sc.Control == streamControlResume {
		p.sendBridgeError(ctx, protocol, corrID, BridgeErrNotResumable, "this proxy instance retains no per-stream state and cannot resume or restart (§6.3)")
		return
	}

	// Register the per-stream cancel flag BEFORE invoking the handler (which
	// may itself run for a while) so a §7.1 cancel arriving while the handler
	// is still producing its reply is captured rather than raced against a
	// registration that has not happened yet.
	key := string(corrID)
	cancelFlag := &atomicBool{}
	p.mu.Lock()
	p.streamCancel[key] = cancelFlag
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.streamCancel, key)
		p.mu.Unlock()
	}()

	var events [][]byte
	var handlerErr error
	switch class {
	case grpcStreamClass:
		if p.GRPCHandler == nil {
			p.sendBridgeError(ctx, protocol, corrID, npamp.BridgeErrMethodUnsupported, "this proxy instance carries no gRPC egress backend")
			return
		}
		// GRPCHandler's req/resp are plain protobuf message bytes; the
		// gRPC Length-Prefixed-Message wire framing (carriage_grpc.go) is a
		// wire-carriage detail this dispatch layer handles, not the handler.
		_, reqMsg, lerr := decodeGRPCLengthPrefixedMessage(frame.Foreign)
		if lerr != nil {
			p.sendBridgeError(ctx, protocol, corrID, npamp.BridgeErrEnvelopeMalformed, lerr.Error())
			return
		}
		resp, err := p.GRPCHandler(ctx, string(frame.Envelope.Method), reqMsg)
		if err != nil {
			handlerErr = err
		} else {
			events = [][]byte{encodeGRPCLengthPrefixedMessage(false, resp)}
		}
	case websocketStreamClass:
		if p.WebSocketHandler == nil {
			p.sendBridgeError(ctx, protocol, corrID, npamp.BridgeErrMethodUnsupported, "this proxy instance carries no WebSocket egress backend")
			return
		}
		resp, err := p.WebSocketHandler(ctx, frame.Foreign)
		if err != nil {
			handlerErr = err
		} else {
			events = resp
		}
	}
	if handlerErr != nil {
		p.sendBridgeError(ctx, protocol, corrID, npamp.BridgeErrNotDelivered, handlerErr.Error())
		return
	}

	var eventID uint64 = 1
	for _, ev := range events {
		if cancelFlag.get() {
			break
		}
		env := npamp.BridgeEnvelope{Protocol: protocol, Kind: npamp.BridgeKindStreamData, ContentType: contentType, CorrelationID: corrID}
		payload := encodeStreamFrame(env, streamControl{Control: streamControlData, EventID: eventID}, ev)
		if serr := p.Conn.Send(ctx, npamp.ChanBridge, npamp.FrameBridgeStreamData, payload); serr != nil {
			return
		}
		eventID++
	}

	flags := uint8(0)
	if cancelFlag.get() {
		flags |= streamFlagCancelAck // §7.2: acknowledge the cancel on the terminating frame
	}
	endEnv := npamp.BridgeEnvelope{Protocol: protocol, Kind: npamp.BridgeKindStreamEnd, ContentType: contentType, CorrelationID: corrID, Flags: npamp.BridgeFlagFinal}
	endPayload := encodeStreamFrame(endEnv, streamControl{Control: streamControlData, Flags: flags, EventID: eventID}, nil)
	_ = p.Conn.Send(ctx, npamp.ChanBridge, npamp.FrameBridgeStreamEnd, endPayload)
}

// handleInboundStreamFrame is Run's dispatch point for BRIDGE_STREAM_DATA/
// BRIDGE_STREAM_END (§4-§7): it decodes the generic NPAMP-BRIDGE envelope and
// routes by correlation_id to whichever of the two roles applies -- a
// CONSUMER waiting on a reply to a stream it originated (p.streamPending), or
// a PRODUCER of a stream it is emitting, for which an inbound
// BRIDGE_STREAM_END carrying control=cancel is an upstream cancel signal
// (§7.1, p.streamCancel). An unsolicited frame matching neither is dropped,
// matching deliverReply's own convention (NPAMP-BRIDGE §5: correlation is the
// only dispatch key).
func (p *Proxy) handleInboundStreamFrame(ft npamp.FrameType, payload []byte) {
	frame, err := npamp.DecodeBridgeFrame(ft, payload)
	if err != nil {
		return
	}
	key := string(frame.Envelope.CorrelationID)

	p.mu.Lock()
	waiter, isConsumer := p.streamPending[key]
	cancelFlag, isProducer := p.streamCancel[key]
	p.mu.Unlock()

	sc, event, scErr := decodeLeadingStreamControl(frame.Foreign)

	switch {
	case isConsumer:
		chunk := streamChunk{ft: ft, control: sc, event: event, err: scErr}
		select {
		case waiter <- chunk:
		default:
			// Consumer not currently draining (buffer full or abandoned);
			// dropped rather than blocking the shared receive loop.
		}
	case isProducer && ft == npamp.FrameBridgeStreamEnd && scErr == nil && sc.Control == streamControlCancel:
		cancelFlag.set()
	default:
		// Unsolicited/late stream frame.
	}
}
