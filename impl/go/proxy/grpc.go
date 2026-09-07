// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package proxy

import (
	"context"
	"fmt"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// GRPCUnaryHandlerFunc answers an inbound gRPC-carriage unary call on the
// egress side: method is the full gRPC method name (e.g.
// "/pkg.Service/Method", carried in the NPAMP-BRIDGE envelope `method` field,
// §4), req is the plain protobuf request-message bytes (already un-LPM-framed
// by stream.go's dispatch -- carriage_grpc.go's wire framing is transparent
// to this handler). A non-nil error produces a below-protocol BRIDGE_ERROR
// NotDelivered (§6.2); this build carries no gRPC status-code channel of its
// own (doc.go non-goal note -- a richer mapping is future work, matching how
// this package already scopes down NPAMP-CC-HTTP's own trailers/passthrough).
type GRPCUnaryHandlerFunc func(ctx context.Context, method string, req []byte) (resp []byte, err error)

// CallGRPCUnary is the INGRESS path for a gRPC unary call: it LPM-frames req
// (carriage_grpc.go), opens a STREAM-class exchange (stream.go
// openConsumerStream) under grpcProtocolID/application-grpc+proto, and
// collects exactly one reply event -- a unary call's stream is, by
// construction, one BRIDGE_STREAM_DATA event followed by BRIDGE_STREAM_END
// (stream.go's handleInboundStreamRequest emits exactly len(events)==1 for a
// GRPCHandler reply).
func (p *Proxy) CallGRPCUnary(ctx context.Context, method string, req []byte) (resp []byte, err error) {
	p.init()
	if p.Conn == nil {
		return nil, ErrNoConn
	}
	if p.RequestTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.RequestTimeout)
		defer cancel()
	}

	frame := encodeGRPCLengthPrefixedMessage(false, req)
	errCh, dataCh, _, cleanup, oerr := p.openConsumerStream(ctx, grpcProtocolID, npamp.BridgeContentGRPCProto, method, frame)
	if oerr != nil {
		return nil, oerr
	}
	defer cleanup()

	events, cerr := collectStream(ctx, errCh, dataCh)
	if cerr != nil {
		return nil, cerr
	}
	if len(events) != 1 {
		return nil, fmt.Errorf("npamp/proxy: gRPC unary call got %d reply events, want exactly 1", len(events))
	}
	_, msg, derr := decodeGRPCLengthPrefixedMessage(events[0])
	if derr != nil {
		return nil, derr
	}
	return msg, nil
}
