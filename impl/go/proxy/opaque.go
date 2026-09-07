// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package proxy

import (
	"context"
	"fmt"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// NPAMP-CC-OPAQUE (spec/companion/25_carriage_opaque.md) Proxy wiring -- the
// n-pamp-proxy carriage leg for raw TCP / any not-otherwise-mapped payload
// (E2.4/R10's sixth and final leg). Modeled as a simple, non-streamed
// BRIDGE_REQUEST/BRIDGE_RESPONSE exchange sharing the same p.pending
// correlation map the HTTP and JSON-RPC legs use (proxy.go) -- matching this
// build's existing scope decision to carry only the non-streamed
// request/response path for every class except the STREAM-class legs that
// have no request/response shape of their own (doc.go). §7's streamed-reply
// variant (BRIDGE_STREAM_DATA/END) is an honest, named gap (doc.go).

// OpaqueHandlerFunc answers an inbound NPAMP-CC-OPAQUE BRIDGE_REQUEST on the
// egress side: mediaType is the declared media type (§4, recovered from
// either the enumerated content_type or the OpaqueContentType TLV), req is
// the raw payload octets, byte-exact and never inspected by this leg (§1.3).
// A non-nil error produces a below-protocol BRIDGE_ERROR NotDelivered (§8.2);
// the handler reports a foreign-protocol-level failure, if any, by choosing
// its own replyMediaType/resp to represent that failure (§8.1: opaque
// carriage has no foreign error object of its own to distinguish -- the
// payload IS the foreign protocol's wire format, whatever it decides to
// carry back).
type OpaqueHandlerFunc func(ctx context.Context, mediaType string, req []byte) (replyMediaType string, resp []byte, err error)

// CallOpaque is the INGRESS path: it sends raw as an NPAMP-CC-OPAQUE
// BRIDGE_REQUEST declaring mediaType (§4) under p.OpaqueProtocolID, and
// blocks for the correlated BRIDGE_RESPONSE (or BRIDGE_ERROR). protocol_id
// comes from p.OpaqueProtocolID, never a default or an experimental value
// this package would choose for the caller (30_protocol_registry.md §7.1: a
// sender MUST NOT use an unregistered protocol_id without out-of-band peer
// agreement -- p.OpaqueProtocolID IS that agreement, configured by the
// operator). Returns ErrOpaqueProtocolIDUnset if it is still the zero value.
func (p *Proxy) CallOpaque(ctx context.Context, mediaType string, raw []byte) (replyMediaType string, resp []byte, err error) {
	p.init()
	if p.Conn == nil {
		return "", nil, ErrNoConn
	}
	if p.OpaqueProtocolID == 0 {
		return "", nil, ErrOpaqueProtocolIDUnset
	}

	corrID, err := newCorrelationID()
	if err != nil {
		return "", nil, err
	}
	env := npamp.BridgeEnvelope{
		Protocol:      p.OpaqueProtocolID,
		Kind:          npamp.BridgeKindRequest,
		CorrelationID: corrID,
	}
	wire, eerr := encodeOpaquePayload(env, mediaType, raw)
	if eerr != nil {
		return "", nil, eerr
	}

	replyCh := make(chan pendingReply, 1)
	key := string(corrID)
	p.mu.Lock()
	p.pending[key] = replyCh
	p.mu.Unlock()
	cleanup := func() {
		p.mu.Lock()
		delete(p.pending, key)
		p.mu.Unlock()
	}

	if p.RequestTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.RequestTimeout)
		defer cancel()
	}

	if serr := p.Conn.Send(ctx, npamp.ChanBridge, npamp.FrameBridgeRequest, wire); serr != nil {
		cleanup()
		return "", nil, fmt.Errorf("npamp/proxy: carrying opaque request over N-PAMP: %w", serr)
	}

	select {
	case reply := <-replyCh:
		return decodeOpaqueReply(reply)
	case <-ctx.Done():
		cleanup()
		return "", nil, ctx.Err()
	}
}

// decodeOpaqueReply turns a pendingReply the Run loop delivered into
// CallOpaque's result: a decoded opaque reply, or a Go error for a
// transport-level, malformed-envelope, or malformed-content-type-declaration
// failure. A BRIDGE_ERROR reply is always a below-protocol transport failure
// for this leg (§8.1's "carried as a BRIDGE_ERROR whose foreign payload is
// the foreign protocol's own error object" is a choice OpaqueHandlerFunc
// makes on the EGRESS side by returning a BRIDGE_RESPONSE whose payload bytes
// happen to represent an error in the foreign protocol's own terms -- opaque
// carriage itself distinguishes only "delivered" from "not delivered").
func decodeOpaqueReply(reply pendingReply) (mediaType string, resp []byte, err error) {
	if reply.err != nil {
		return "", nil, reply.err
	}
	if reply.ft == npamp.FrameBridgeError {
		return "", nil, decodeTransportErrorReply(reply.foreign)
	}
	return decodeOpaquePayload(reply.env, reply.foreign)
}

// handleInboundOpaqueRequest is the NPAMP-CC-OPAQUE EGRESS path for a
// BRIDGE_REQUEST (§4): frame is already decoded by the shared dispatcher
// (proxy.go handleInboundBridgeRequest), which routes here only after
// confirming frame.Envelope.Protocol == p.OpaqueProtocolID. It recovers the
// declared media type and raw payload (decodeOpaquePayload), invokes
// OpaqueHandler, and seals the reply back as BRIDGE_RESPONSE or, on a
// below-protocol failure, BRIDGE_ERROR.
func (p *Proxy) handleInboundOpaqueRequest(ctx context.Context, frame npamp.BridgeFrame) {
	protocol := frame.Envelope.Protocol
	corrID := frame.Envelope.CorrelationID

	if p.OpaqueHandler == nil {
		p.sendBridgeError(ctx, protocol, corrID, npamp.BridgeErrMethodUnsupported, "this proxy instance carries no opaque-carriage egress backend")
		return
	}

	mediaType, raw, derr := decodeOpaquePayload(frame.Envelope, frame.Foreign)
	if derr != nil {
		p.sendBridgeError(ctx, protocol, corrID, npamp.BridgeErrEnvelopeMalformed, derr.Error())
		return
	}

	replyMediaType, resp, herr := p.OpaqueHandler(ctx, mediaType, raw)
	if herr != nil {
		p.sendBridgeError(ctx, protocol, corrID, npamp.BridgeErrNotDelivered, herr.Error())
		return
	}

	env := npamp.BridgeEnvelope{
		Protocol:      protocol,
		Kind:          npamp.BridgeKindResponse,
		CorrelationID: corrID,
	}
	wire, eerr := encodeOpaquePayload(env, replyMediaType, resp)
	if eerr != nil {
		// The handler declared an invalid reply media type -- this proxy
		// instance's own egress bug, not the peer's fault, but there is no
		// third channel to report it on beyond a transport-level failure
		// (mirrors sendBridgeError's own doc: "there is no third channel to
		// report a reporting failure on").
		p.sendBridgeError(ctx, protocol, corrID, npamp.BridgeErrNotDelivered, eerr.Error())
		return
	}
	_ = p.Conn.Send(ctx, npamp.ChanBridge, npamp.FrameBridgeResponse, wire)
}
