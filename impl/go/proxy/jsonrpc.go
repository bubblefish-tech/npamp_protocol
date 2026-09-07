// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package proxy

import (
	"context"
	"encoding/json"
	"fmt"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// NPAMP-CC-JSONRPC (spec/companion/20_carriage_jsonrpc.md) Proxy wiring — the
// n-pamp-proxy carriage leg for Streamable-HTTP+JSON-RPC (MCP/A2A, R10 AC1) and,
// via stdio.go's StdioBackend, the stdio-local-MCP leg. Composes the same
// already-established impl/go/sdk.Conn as the HTTP leg (proxy.go); adds no new
// wire behavior beyond what carriage_jsonrpc.go's codec already defines.

// JSONRPCError is the decoded form of a §6 foreign JSON-RPC error object
// (code, message, OPTIONAL data), preserved verbatim from the wire per §6
// ("MUST NOT reduce the JSON-RPC error object to free text ... MUST NOT alter,
// remap, or collapse the numeric code").
type JSONRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *JSONRPCError) Error() string {
	return fmt.Sprintf("npamp/proxy: JSON-RPC error %d: %s", e.Code, e.Message)
}

// JSONRPCHandlerFunc answers an inbound JSON-RPC Request (§4) on the egress
// side. A non-nil rpcErr produces a §6 BRIDGE_ERROR carrying that foreign
// JSON-RPC error object verbatim (result is ignored when rpcErr != nil). A
// non-nil err (rpcErr nil) instead produces a below-protocol N-PAMP transport
// error (§6.2 NotDelivered) -- the handler could not even be reached/answered,
// which is a DIFFERENT failure than the foreign endpoint producing a JSON-RPC
// error Response.
type JSONRPCHandlerFunc func(ctx context.Context, protocol npamp.BridgeProtocol, method string, params json.RawMessage) (result json.RawMessage, rpcErr *JSONRPCError, err error)

// JSONRPCNotifyFunc handles an inbound Notification (§7). It has no reply
// path -- NPAMP-CC-JSONRPC §7 forbids any BRIDGE_RESPONSE/BRIDGE_ERROR for a
// BRIDGE_NOTIFY, so this signature has no error return to send anywhere.
type JSONRPCNotifyFunc func(ctx context.Context, protocol npamp.BridgeProtocol, method string, params json.RawMessage)

// CallJSONRPC is the INGRESS path: it originates a JSON-RPC Request (§4)
// carrying an id, sends it as a BRIDGE_REQUEST, and blocks for the correlated
// BRIDGE_RESPONSE (§5) or BRIDGE_ERROR (§6). id follows encoding/json's rules
// for the Go value that becomes the JSON-RPC id member (a string, a number, or
// nil for JSON null, §8.4). params, when nil, is omitted from the object.
func (p *Proxy) CallJSONRPC(ctx context.Context, protocol npamp.BridgeProtocol, method string, params any, id any) (result json.RawMessage, rpcErr *JSONRPCError, err error) {
	p.init()
	if p.Conn == nil {
		return nil, nil, ErrNoConn
	}
	wire, corrID, err := encodeJSONRPCRequest(method, params, id)
	if err != nil {
		return nil, nil, err
	}

	replyCh := make(chan pendingReply, 1)
	key := string(corrID)
	p.mu.Lock()
	if _, exists := p.pending[key]; exists {
		p.mu.Unlock()
		// §8.1/§8.2: the originator MUST ensure correlation_id uniqueness among
		// its outstanding requests; a collision here means the caller reused a
		// live id, which this codec refuses rather than silently overwriting the
		// prior waiter (it would never receive its reply).
		return nil, nil, fmt.Errorf("npamp/proxy: correlation_id derived from id %q collides with an outstanding JSON-RPC request", id)
	}
	p.pending[key] = replyCh
	p.mu.Unlock()
	cleanup := func() {
		p.mu.Lock()
		delete(p.pending, key)
		p.mu.Unlock()
	}

	env := jsonrpcEnvelope(protocol, npamp.BridgeKindRequest, corrID, method)
	payload := npamp.EncodeBridgePayload(env, nil, wire)

	if p.RequestTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.RequestTimeout)
		defer cancel()
	}

	if serr := p.Conn.Send(ctx, npamp.ChanBridge, npamp.FrameBridgeRequest, payload); serr != nil {
		cleanup()
		return nil, nil, fmt.Errorf("npamp/proxy: carrying JSON-RPC request over N-PAMP: %w", serr)
	}

	select {
	case reply := <-replyCh:
		return decodeJSONRPCReply(reply)
	case <-ctx.Done():
		cleanup()
		return nil, nil, ctx.Err()
	}
}

// decodeJSONRPCReply turns a pendingReply the Run loop delivered into
// CallJSONRPC's three-way result: a success result, a foreign JSON-RPC error
// (§6, distinguished from a transport error by content_type=JSON per
// sendBridgeError's convention -- see proxy.go decodeTransportErrorReply), or
// a Go error for a transport-level or malformed-reply failure.
func decodeJSONRPCReply(reply pendingReply) (result json.RawMessage, rpcErr *JSONRPCError, err error) {
	if reply.err != nil {
		return nil, nil, reply.err
	}
	if reply.ft == npamp.FrameBridgeError {
		if reply.env.ContentType == npamp.BridgeContentJSON {
			obj, derr := decodeJSONRPCErrorResponse(reply.foreign)
			if derr != nil {
				return nil, nil, derr
			}
			var je JSONRPCError
			if uerr := json.Unmarshal(obj.Error, &je); uerr != nil {
				return nil, nil, fmt.Errorf("npamp/proxy: malformed JSON-RPC error object: %w", uerr)
			}
			return nil, &je, nil
		}
		return nil, nil, decodeTransportErrorReply(reply.foreign)
	}
	obj, derr := decodeJSONRPCSuccessResponse(reply.foreign)
	if derr != nil {
		return nil, nil, derr
	}
	return obj.Result, nil, nil
}

// SendJSONRPCNotification is the INGRESS one-way path (§7): it sends a
// BRIDGE_NOTIFY and returns as soon as the frame is handed to Conn.Send --
// there is no reply to wait for (§7: "the sender MUST NOT await one").
func (p *Proxy) SendJSONRPCNotification(ctx context.Context, protocol npamp.BridgeProtocol, method string, params any) error {
	p.init()
	if p.Conn == nil {
		return ErrNoConn
	}
	wire, err := encodeJSONRPCNotification(method, params)
	if err != nil {
		return err
	}
	env := jsonrpcEnvelope(protocol, npamp.BridgeKindNotification, nil, method)
	payload := npamp.EncodeBridgePayload(env, nil, wire)
	if serr := p.Conn.Send(ctx, npamp.ChanBridge, npamp.FrameBridgeNotify, payload); serr != nil {
		return fmt.Errorf("npamp/proxy: carrying JSON-RPC notification over N-PAMP: %w", serr)
	}
	return nil
}

// handleInboundJSONRPCRequest is the NPAMP-CC-JSONRPC EGRESS path for a
// BRIDGE_REQUEST (§4): frame is already decoded (handleInboundBridgeRequest).
// It parses the carried JSON-RPC object, applies the §4 method-agreement
// check, and invokes JSONRPCHandler, sealing the result back as
// BRIDGE_RESPONSE (§5) or BRIDGE_ERROR (§6).
func (p *Proxy) handleInboundJSONRPCRequest(ctx context.Context, frame npamp.BridgeFrame) {
	protocol := frame.Envelope.Protocol
	corrID := frame.Envelope.CorrelationID

	if p.JSONRPCHandler == nil {
		p.sendBridgeError(ctx, protocol, corrID, npamp.BridgeErrMethodUnsupported, "this proxy instance carries no JSON-RPC egress backend")
		return
	}

	obj, derr := decodeJSONRPCRequestOrNotification(frame.Foreign, false)
	if derr != nil {
		p.sendBridgeError(ctx, protocol, corrID, npamp.BridgeErrEnvelopeMalformed, derr.Error())
		return
	}
	if !jsonrpcMethodAgrees(frame.Envelope.Method, obj) {
		p.sendBridgeError(ctx, protocol, corrID, npamp.BridgeErrEnvelopeMalformed, "envelope method field disagrees with the carried JSON-RPC object's method member")
		return
	}

	result, rpcErr, err := p.JSONRPCHandler(ctx, protocol, obj.Method, jsonrpcParams(obj.Raw))
	if err != nil {
		// Below-protocol: the handler itself could not deliver/answer (§6.2
		// NotDelivered). A sender MUST NOT manufacture a JSON-RPC error object
		// for a transport-level failure (§6), so this is a transport error, not
		// an rpcErr.
		p.sendBridgeError(ctx, protocol, corrID, npamp.BridgeErrNotDelivered, err.Error())
		return
	}
	if rpcErr != nil {
		p.sendJSONRPCErrorResponse(ctx, protocol, corrID, obj.ID, rpcErr)
		return
	}
	p.sendJSONRPCSuccessResponse(ctx, protocol, corrID, obj.ID, result)
}

// handleInboundNotify is the NPAMP-CC-JSONRPC EGRESS path for a BRIDGE_NOTIFY
// (§7): no reply is ever sent, so a malformed or handler-less notification is
// simply dropped after the structural check -- there is no BRIDGE_ERROR
// available for a Notification (§7, corr_len MUST be 0, so there is no
// correlation_id to reply against even if a wire error type existed).
func (p *Proxy) handleInboundNotify(ctx context.Context, payload []byte) {
	frame, err := npamp.DecodeBridgeFrame(npamp.FrameBridgeNotify, payload)
	if err != nil {
		return
	}
	if frame.Envelope.Protocol != npamp.BridgeProtoMCP && frame.Envelope.Protocol != npamp.BridgeProtoA2A {
		return // not a JSONRPC-class protocol_id this build routes Notify for
	}
	if p.JSONRPCNotifyHandler == nil {
		return
	}
	obj, derr := decodeJSONRPCRequestOrNotification(frame.Foreign, true)
	if derr != nil {
		return
	}
	if !jsonrpcMethodAgrees(frame.Envelope.Method, obj) {
		return
	}
	p.JSONRPCNotifyHandler(ctx, frame.Envelope.Protocol, obj.Method, jsonrpcParams(obj.Raw))
}

// jsonrpcParams extracts the raw "params" member (nil if absent) from a
// carried JSON-RPC object without re-serializing the object (§2 transparency).
func jsonrpcParams(raw []byte) json.RawMessage {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil
	}
	return fields["params"]
}

// sendJSONRPCSuccessResponse seals and sends a BRIDGE_RESPONSE carrying a
// JSON-RPC success Response object (§5) that echoes id.
func (p *Proxy) sendJSONRPCSuccessResponse(ctx context.Context, protocol npamp.BridgeProtocol, corrID []byte, id json.RawMessage, result json.RawMessage) {
	if result == nil {
		result = json.RawMessage("null")
	}
	obj := map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(id), "result": result}
	wire, err := json.Marshal(obj)
	if err != nil {
		return // nothing more can be done: the handler's own result did not marshal
	}
	env := jsonrpcEnvelope(protocol, npamp.BridgeKindResponse, corrID, "")
	payload := npamp.EncodeBridgePayload(env, nil, wire)
	_ = p.Conn.Send(ctx, npamp.ChanBridge, npamp.FrameBridgeResponse, payload)
}

// sendJSONRPCErrorResponse seals and sends a BRIDGE_ERROR carrying a foreign
// JSON-RPC error Response object (§6) verbatim -- the numeric code is never
// remapped to or from an N-PAMP transport-error code (§6).
func (p *Proxy) sendJSONRPCErrorResponse(ctx context.Context, protocol npamp.BridgeProtocol, corrID []byte, id json.RawMessage, rpcErr *JSONRPCError) {
	errObj, merr := json.Marshal(rpcErr)
	if merr != nil {
		return
	}
	if id == nil {
		id = json.RawMessage("null")
	}
	obj := map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(id), "error": json.RawMessage(errObj)}
	wire, err := json.Marshal(obj)
	if err != nil {
		return
	}
	env := jsonrpcEnvelope(protocol, npamp.BridgeKindError, corrID, "")
	payload := npamp.EncodeBridgePayload(env, nil, wire)
	_ = p.Conn.Send(ctx, npamp.ChanBridge, npamp.FrameBridgeError, payload)
}
