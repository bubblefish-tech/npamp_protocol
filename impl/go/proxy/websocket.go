// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package proxy

import (
	"context"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// WebSocketHandlerFunc answers an inbound WebSocket-generic-carriage message
// on the egress side: msg is the carried message's raw octets, verbatim
// (carriage_websocket.go). It returns zero or more reply messages, emitted in
// order as a BRIDGE_STREAM_DATA sequence terminated by BRIDGE_STREAM_END
// (stream.go handleInboundStreamRequest) -- modeling a WebSocket exchange as
// "one inbound message, a stream of reply messages" rather than attempting a
// full-duplex live socket abstraction (doc.go non-goal note: a per-direction
// live-streaming WebSocketHandler is future work; NPAMP-CC-STREAM's §8
// full-duplex model composes with this build's request-opened stream shape
// but is not exercised end-to-end here). A non-nil error produces a
// below-protocol BRIDGE_ERROR NotDelivered (§6.2).
type WebSocketHandlerFunc func(ctx context.Context, msg []byte) (replies [][]byte, err error)

// CallWebSocketMessage is the INGRESS path: it sends msg verbatim as a
// WebSocket-generic-carriage stream-opening BRIDGE_REQUEST (stream.go
// openConsumerStream, protocol_id npamp.BridgeProtoWebSocket) and collects
// the peer's ordered reply-message stream up to BRIDGE_STREAM_END.
func (p *Proxy) CallWebSocketMessage(ctx context.Context, msg []byte) (replies [][]byte, err error) {
	p.init()
	if p.Conn == nil {
		return nil, ErrNoConn
	}
	if p.RequestTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.RequestTimeout)
		defer cancel()
	}

	errCh, dataCh, _, cleanup, oerr := p.openConsumerStream(ctx, npamp.BridgeProtoWebSocket, streamContentType(websocketStreamClass), "", msg)
	if oerr != nil {
		return nil, oerr
	}
	defer cleanup()

	return collectStream(ctx, errCh, dataCh)
}
