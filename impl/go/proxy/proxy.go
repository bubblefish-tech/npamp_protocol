// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
	"github.com/bubblefish-tech/npamp_protocol/impl/go/sdk"
)

// ErrNoConn is returned when a Proxy method is called before Conn is set, or
// after the underlying sdk.Conn has failed/closed. There is no fallback path:
// a Proxy that cannot reach its N-PAMP peer reports the carriage failure and
// stops -- it never forwards a request in plaintext (doc.go, "Fail-closed by
// construction").
var ErrNoConn = errors.New("npamp/proxy: no established N-PAMP connection")

// ErrOpaqueProtocolIDUnset is returned by CallOpaque when p.OpaqueProtocolID
// is still its zero value (0x00, the reserved null identifier, NPAMP-BRIDGE
// §4). NPAMP-CC-OPAQUE carriage has no assigned or generic protocol_id of its
// own (spec/companion/30_protocol_registry.md §7.1/§7.2: an experimental or
// private-use value requires the operator's own out-of-band peer agreement),
// so this leg refuses to invent or default to one -- see opaque.go.
var ErrOpaqueProtocolIDUnset = errors.New("npamp/proxy: OpaqueProtocolID is unset (0x00); configure the operator-agreed protocol_id for NPAMP-CC-OPAQUE carriage")

// pendingReply is what Run delivers to a call (ServeHTTP, CallJSONRPC, ...)
// waiting on a correlation_id it originated. It is carriage-class-agnostic by
// design: Run/deliverReply decode only the generic NPAMP-BRIDGE envelope
// (common to every class, bridge_bodies.go) and hand the class-specific
// foreign bytes back UNINTERPRETED; each carriage class's own call site
// decodes Foreign per its own companion spec (decodeHTTPCarriageObject for
// NPAMP-CC-HTTP, decodeJSONRPCSuccessResponse/decodeJSONRPCErrorResponse for
// NPAMP-CC-JSONRPC, ...), matching NPAMP-BRIDGE's own layering: the bridge
// framework never interprets a carriage class's payload (10_bridge_framework.md
// §1 Transparency).
type pendingReply struct {
	ft      npamp.FrameType // FrameBridgeResponse or FrameBridgeError
	env     npamp.BridgeEnvelope
	foreign []byte
	err     error // set only for a malformed reply that could not even be decoded
}

// Proxy is the n-pamp-proxy composition unit for the HTTP carriage class
// (doc.go). One Proxy value wraps one already-established impl/go/sdk.Conn and
// can serve as INGRESS (via ServeHTTP), EGRESS (via Run, when Backend is set),
// or both -- see doc.go for the full contract. The zero value is not usable;
// construct with New.
type Proxy struct {
	// Conn is the already-established N-PAMP session this Proxy carries HTTP
	// traffic over. REQUIRED. Proxy never dials or accepts a socket itself
	// (composition, not reimplementation -- doc.go).
	Conn *sdk.Conn

	// Backend, when non-nil, is the LOCAL real HTTP service this Proxy's EGRESS
	// side forwards a decoded BRIDGE_REQUEST to (Run only takes effect for
	// inbound requests when this is set). Nil means this Proxy instance does not
	// serve as an egress endpoint: an inbound BRIDGE_REQUEST is answered
	// BridgeErrMethodUnsupported ("this peer does not carry HTTP egress"),
	// never silently dropped.
	Backend *url.URL

	// HTTPClient issues the real request to Backend on the egress path.
	// Defaults to http.DefaultClient's transport semantics (a fresh
	// *http.Client{} with no cookie jar and no redirect-follow override --
	// following a carried redirect is the ORIGINAL client's decision per
	// NPAMP-CC-HTTP §5.3, not this carriage layer's; doc.go non-goal boundary)
	// when nil.
	HTTPClient *http.Client

	// RequestTimeout bounds how long ServeHTTP/CallJSONRPC/CallGRPCUnary wait
	// for a correlated reply after sending a BRIDGE_REQUEST, in addition to the
	// caller's own context. Zero means no additional bound beyond that context.
	RequestTimeout time.Duration

	// JSONRPCHandler, when non-nil, answers an inbound NPAMP-CC-JSONRPC
	// BRIDGE_REQUEST (protocol_id MCP or A2A, carriage_jsonrpc.go/jsonrpc.go) on
	// this Proxy's egress side. Nil means this Proxy carries no JSON-RPC egress:
	// an inbound JSON-RPC request is answered BridgeErrMethodUnsupported, never
	// silently dropped (mirrors Backend's nil behavior for HTTP).
	JSONRPCHandler JSONRPCHandlerFunc

	// JSONRPCNotifyHandler, when non-nil, is invoked fire-and-forget for an
	// inbound NPAMP-CC-JSONRPC BRIDGE_NOTIFY (§7: no reply is ever sent for a
	// Notification, so there is no failure path to report here).
	JSONRPCNotifyHandler JSONRPCNotifyFunc

	// StdioBackend, when non-nil, makes JSONRPCHandler unnecessary for the
	// stdio-local-MCP leg (stdio.go): every inbound JSON-RPC request/
	// notification for protocol_id MCP is instead forwarded to a local child
	// process's stdin/stdout, newline-delimited, per MCP's stdio transport
	// binding. Composing StdioBackend automatically installs the
	// JSONRPCHandler/JSONRPCNotifyHandler pair that drives it (see
	// NewStdioBackend).
	StdioBackend *StdioBackend

	// GRPCHandler, when non-nil, answers an inbound NPAMP-CC-STREAM
	// gRPC-carriage unary call (carriage_grpc.go/grpc.go) on this Proxy's
	// egress side.
	GRPCHandler GRPCUnaryHandlerFunc

	// WebSocketHandler, when non-nil, answers an inbound NPAMP-CC-STREAM
	// WebSocket-generic-carriage message (carriage_websocket.go/websocket.go)
	// on this Proxy's egress side with zero or more reply messages.
	WebSocketHandler WebSocketHandlerFunc

	// OpaqueProtocolID is the protocol_id this Proxy instance uses for
	// NPAMP-CC-OPAQUE carriage (carriage_opaque.go/opaque.go, E2.4/R10's sixth
	// leg: raw TCP or any not-otherwise-mapped payload). REQUIRED for the
	// OPAQUE leg: the zero value (0x00, the reserved null identifier) never
	// carries OPAQUE traffic, structurally disabling the leg rather than
	// silently squatting on an unassigned/experimental value this package
	// would have to choose on the operator's behalf (30_protocol_registry.md
	// §7.1: any such value needs the peers' own out-of-band agreement -- this
	// field's explicit configuration IS that agreement).
	OpaqueProtocolID npamp.BridgeProtocol

	// OpaqueHandler, when non-nil, answers an inbound NPAMP-CC-OPAQUE
	// BRIDGE_REQUEST (carriage_opaque.go/opaque.go) on this Proxy's egress
	// side.
	OpaqueHandler OpaqueHandlerFunc

	initOnce      sync.Once
	mu            sync.Mutex
	pending       map[string]chan pendingReply // BRIDGE_RESPONSE/ERROR waiters, keyed by string(correlation_id) -- HTTP and JSON-RPC share this map (both reply via those two frame types)
	streamPending map[string]chan streamChunk  // NPAMP-CC-STREAM consumer-side waiters (gRPC/WebSocket), keyed by string(correlation_id)
	streamCancel  map[string]*atomicBool       // NPAMP-CC-STREAM egress-side cancel flags for a stream THIS Proxy is producing, keyed by string(correlation_id)
}

func (p *Proxy) init() {
	p.initOnce.Do(func() {
		p.pending = make(map[string]chan pendingReply)
		p.streamPending = make(map[string]chan streamChunk)
		p.streamCancel = make(map[string]*atomicBool)
		if p.HTTPClient == nil {
			p.HTTPClient = &http.Client{}
		}
		if p.StdioBackend != nil && p.JSONRPCHandler == nil && p.JSONRPCNotifyHandler == nil {
			p.JSONRPCHandler = p.StdioBackend.Call
			p.JSONRPCNotifyHandler = p.StdioBackend.Notify
		}
	})
}

// newCorrelationID generates a fresh 16-octet random correlation_id, unique
// among this Proxy's outstanding requests with overwhelming probability
// (NPAMP-BRIDGE §5: "unique among the originator's outstanding requests").
func newCorrelationID() ([]byte, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("npamp/proxy: generate correlation_id: %w", err)
	}
	return id, nil
}

// Run drives the single receive loop that both DISPATCHES an inbound
// BRIDGE_REQUEST to the egress handler and DELIVERS an inbound reply
// (BRIDGE_RESPONSE/BRIDGE_ERROR) to the ServeHTTP call that is waiting on its
// correlation_id. It must be running (in its own goroutine) for ServeHTTP to
// ever receive a reply, and for this Proxy to serve as an egress endpoint at
// all. Run returns when ctx is done or Conn.Recv returns a non-nil error
// (including sdk.ErrPeerClosed on a graceful peer close); it never retries a
// failed Conn -- reconnection, if wanted, is the caller's to arrange by
// constructing a new Proxy over a new Conn.
func (p *Proxy) Run(ctx context.Context) error {
	p.init()
	if p.Conn == nil {
		return ErrNoConn
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		ch, ft, payload, err := p.Conn.Recv(ctx)
		if err != nil {
			return err
		}
		if ch != npamp.ChanBridge {
			// Not this package's traffic; a real deployment might route other
			// channels elsewhere, but Proxy only ever composes the Bridge
			// channel (doc.go).
			continue
		}
		switch ft {
		case npamp.FrameBridgeRequest:
			// Egress work must not block the receive loop (a slow backend call
			// would stall delivery of every OTHER in-flight reply on this Conn),
			// so it runs in its own goroutine; multiple concurrent egress calls
			// are fine because sdk.Conn.Send/Recv are independently safe for
			// concurrent use per their own doc.
			go p.handleInboundBridgeRequest(ctx, payload)
		case npamp.FrameBridgeResponse, npamp.FrameBridgeError:
			p.deliverReply(ft, payload)
		case npamp.FrameBridgeNotify:
			// NPAMP-CC-JSONRPC §7: a Notification elicits no reply, so this
			// runs fire-and-forget in its own goroutine like a request.
			go p.handleInboundNotify(ctx, payload)
		case npamp.FrameBridgeStreamData, npamp.FrameBridgeStreamEnd:
			// NPAMP-CC-STREAM (gRPC/WebSocket legs): either a reply chunk for a
			// stream THIS Proxy's ingress side originated (delivered to the
			// waiting consumer), or a control frame (cancel) for a stream this
			// Proxy's egress side is producing. handleInboundStreamFrame
			// disambiguates by correlation_id against both maps; it must not
			// block the receive loop for the same reason FrameBridgeRequest
			// does not, so it also dispatches into its own goroutine internally
			// where producer work is involved.
			p.handleInboundStreamFrame(ft, payload)
		default:
			// An out-of-band frame type on the Bridge channel this package does
			// not carry. Dropped, not torn down -- matching the resilience
			// posture the underlying sdk.Conn itself applies to
			// unrecognized-but-well-formed input.
		}
	}
}

// handleInboundBridgeRequest decodes an inbound BRIDGE_REQUEST exactly once
// and routes it to the carriage-class-specific egress handler by the
// envelope's protocol_id (NPAMP-BRIDGE §4) -- the single dispatch point that
// lets one Proxy/Conn carry HTTP, JSON-RPC, gRPC, and WebSocket traffic
// concurrently (doc.go). A protocol_id this Proxy does not carry is answered
// ProtocolUnsupported (§6 table), never silently dropped.
func (p *Proxy) handleInboundBridgeRequest(ctx context.Context, payload []byte) {
	frame, err := npamp.DecodeBridgeFrame(npamp.FrameBridgeRequest, payload)
	if err != nil {
		// Malformed envelope: there is no reliable correlation_id to reply to
		// (NPAMP-BRIDGE requires the envelope to decode before corr is even
		// known), so per §6 this cannot be answered and is dropped -- mirroring
		// how the core SDK drops an unauthenticated frame rather than reacting
		// to attacker-shaped input it cannot trust.
		return
	}
	switch frame.Envelope.Protocol {
	case npamp.BridgeProtoHTTP2:
		p.handleInboundHTTPRequest(ctx, frame)
	case npamp.BridgeProtoMCP, npamp.BridgeProtoA2A:
		p.handleInboundJSONRPCRequest(ctx, frame)
	case npamp.BridgeProtoWebSocket:
		p.handleInboundStreamRequest(ctx, frame, websocketStreamClass)
	case grpcProtocolID:
		p.handleInboundStreamRequest(ctx, frame, grpcStreamClass)
	default:
		// NPAMP-CC-OPAQUE carries no assigned or generic protocol_id (unlike
		// HTTP2/MCP/A2A/WebSocket above): its value is whatever the operator
		// configured out of band (OpaqueProtocolID). Checked last, inside the
		// switch's default case, so an OpaqueProtocolID that happened to
		// collide with one of the well-known values above can never shadow
		// that value's real carriage class -- the well-known cases are always
		// matched first.
		if p.OpaqueProtocolID != 0 && frame.Envelope.Protocol == p.OpaqueProtocolID {
			p.handleInboundOpaqueRequest(ctx, frame)
			return
		}
		p.sendBridgeError(ctx, frame.Envelope.Protocol, frame.Envelope.CorrelationID, npamp.BridgeErrProtocolUnsupported,
			fmt.Sprintf("protocol_id 0x%02x is not carried by this n-pamp-proxy instance", byte(frame.Envelope.Protocol)))
	}
}

// deliverReply decodes a reply frame's envelope, finds the ServeHTTP call
// waiting on its correlation_id, and delivers the decoded object or error to
// it. An unsolicited reply (no waiter -- a stray/duplicate/late frame) is
// dropped: correlation is the ONLY dispatch key (NPAMP-BRIDGE §5), so there is
// nothing else it could mean.
func (p *Proxy) deliverReply(ft npamp.FrameType, payload []byte) {
	frame, err := npamp.DecodeBridgeFrame(ft, payload)
	if err != nil {
		return // malformed reply with no readable correlation_id: nothing to deliver to
	}
	key := string(frame.Envelope.CorrelationID)
	p.mu.Lock()
	waiter, ok := p.pending[key]
	if ok {
		delete(p.pending, key)
	}
	p.mu.Unlock()
	if !ok {
		return // unsolicited reply
	}
	waiter <- pendingReply{ft: ft, env: frame.Envelope, foreign: frame.Foreign}
}

// decodeTransportErrorReply is the shared helper every carriage class uses to
// turn a BRIDGE_ERROR pendingReply carrying an N-PAMP transport error (§6,
// EncodeBridgeTransportError's wire shape — this package's convention is
// content_type=CBOR for a transport error, distinguishing it from a
// class-specific foreign error object; see sendBridgeError) into a Go error.
func decodeTransportErrorReply(foreign []byte) error {
	te, terr := npamp.DecodeBridgeTransportError(foreign)
	if terr != nil {
		return fmt.Errorf("npamp/proxy: malformed BRIDGE_ERROR: %w", terr)
	}
	return fmt.Errorf("npamp/proxy: peer reported carriage failure %s: %s", te.Code.Name(), te.Message)
}

// handleInboundHTTPRequest is the NPAMP-CC-HTTP EGRESS path: a decoded
// BRIDGE_REQUEST is turned into a real *http.Request against Backend, issued
// with HTTPClient, and the real response (or a carriage-level failure) is
// sealed back as BRIDGE_RESPONSE/BRIDGE_ERROR echoing the same correlation_id.
// It never answers a 4xx/5xx HTTP response with BRIDGE_ERROR (§6.1: a foreign
// HTTP error is a SUCCESSFUL carriage of a foreign result). Called by
// handleInboundBridgeRequest after protocol_id dispatch; frame is already
// decoded.
func (p *Proxy) handleInboundHTTPRequest(ctx context.Context, frame npamp.BridgeFrame) {
	corrID := frame.Envelope.CorrelationID

	if p.Backend == nil {
		p.sendBridgeError(ctx, npamp.BridgeProtoHTTP2, corrID, npamp.BridgeErrMethodUnsupported, "this proxy instance carries no HTTP egress backend")
		return
	}

	obj, derr := decodeHTTPCarriageObject(frame.Foreign, httpKindRequest)
	if derr != nil {
		p.sendBridgeError(ctx, npamp.BridgeProtoHTTP2, corrID, npamp.BridgeErrEnvelopeMalformed, derr.Error())
		return
	}
	// §2.4 agreement check: the envelope `method` field, when non-empty, MUST
	// equal "<method> <target>".
	if len(frame.Envelope.Method) > 0 {
		want := obj.Method + " " + obj.Target
		if string(frame.Envelope.Method) != want {
			p.sendBridgeError(ctx, npamp.BridgeProtoHTTP2, corrID, npamp.BridgeErrEnvelopeMalformed, "envelope method routing key disagrees with the HTTP-Carriage Object")
			return
		}
	}

	target := p.Backend.ResolveReference(&url.URL{Path: "/"})
	full := *target
	if u, uerr := url.Parse(obj.Target); uerr == nil {
		full.Path = u.Path
		full.RawQuery = u.RawQuery
	} else {
		full.Path = obj.Target
	}
	req, rerr := http.NewRequestWithContext(ctx, obj.Method, full.String(), bytes.NewReader(obj.Body))
	if rerr != nil {
		p.sendBridgeError(ctx, npamp.BridgeProtoHTTP2, corrID, npamp.BridgeErrEnvelopeMalformed, fmt.Sprintf("could not construct backend request: %v", rerr))
		return
	}
	req.Header = toHTTPHeader(obj.Headers)

	resp, derr2 := p.HTTPClient.Do(req)
	if derr2 != nil {
		// Below-foreign-protocol failure: the request never reached (or no
		// response was obtained from) the real backend (§6.2 NotDelivered). No
		// synthesized HTTP status is ever substituted (§6.2, "MUST NOT fabricate
		// an HTTP status code").
		p.sendBridgeError(ctx, npamp.BridgeProtoHTTP2, corrID, npamp.BridgeErrNotDelivered, derr2.Error())
		return
	}
	defer resp.Body.Close()
	body, rerr2 := io.ReadAll(resp.Body)
	if rerr2 != nil {
		p.sendBridgeError(ctx, npamp.BridgeProtoHTTP2, corrID, npamp.BridgeErrNotDelivered, fmt.Sprintf("reading backend response body: %v", rerr2))
		return
	}

	// §6.1: a 4xx/5xx backend response is a SUCCESSFUL carriage of a foreign
	// result -- always BRIDGE_RESPONSE, never BRIDGE_ERROR, regardless of status.
	obj2 := encodeHTTPCarriageResponse(resp.StatusCode, resp.Header, body)
	env := npamp.BridgeEnvelope{
		Protocol:      npamp.BridgeProtoHTTP2,
		Kind:          npamp.BridgeKindResponse,
		ContentType:   npamp.BridgeContentCBOR,
		CorrelationID: corrID,
	}
	wire := npamp.EncodeBridgePayload(env, nil, obj2)
	_ = p.Conn.Send(ctx, npamp.ChanBridge, npamp.FrameBridgeResponse, wire)
}

// sendBridgeError seals and sends a BRIDGE_ERROR carrying an NPAMP-BRIDGE
// transport-error object (§6.2) under the given protocol_id, echoing corrID.
// Send errors are not further escalated here (there is no third channel to
// report a reporting failure on); the ORIGINAL requester's own
// RequestTimeout/context bound is what surfaces the failure to it. Every
// carriage class in this package (HTTP, JSONRPC, gRPC, WebSocket) reports a
// below-foreign-protocol failure through this one helper, so the wire shape of
// an N-PAMP transport error (content_type=CBOR, EncodeBridgeTransportError's
// layout) is identical across classes and distinguishable from a
// class-specific foreign error object by content_type alone (see
// decodeTransportErrorReply's callers).
func (p *Proxy) sendBridgeError(ctx context.Context, protocol npamp.BridgeProtocol, corrID []byte, code npamp.BridgeErrorCode, msg string) {
	if len(msg) > 255 {
		msg = msg[:255]
	}
	env := npamp.BridgeEnvelope{
		Protocol:      protocol,
		Kind:          npamp.BridgeKindError,
		ContentType:   npamp.BridgeContentCBOR,
		CorrelationID: corrID,
	}
	foreign := npamp.EncodeBridgeTransportError(npamp.BridgeTransportError{Code: code, Message: msg})
	wire := npamp.EncodeBridgePayload(env, nil, foreign)
	_ = p.Conn.Send(ctx, npamp.ChanBridge, npamp.FrameBridgeError, wire)
}

// ServeHTTP is the INGRESS path (implements http.Handler): an unmodified HTTP
// client's request is translated into a BRIDGE_REQUEST HTTP-Carriage Object and
// carried to the peer over Conn; the correlated reply (BRIDGE_RESPONSE decoded
// back to an HTTP status/headers/body, or a carriage failure) is written to w.
// There is no other path by which a request reaches its destination -- see
// doc.go, "Fail-closed by construction": if Conn is nil or Send fails, this
// method reports 502 and returns; it never dials Backend, the request's Host,
// or any other fallback destination.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.init()
	if p.Conn == nil {
		http.Error(w, "npamp/proxy: no established N-PAMP connection", http.StatusBadGateway)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "npamp/proxy: reading request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	target := r.URL.Path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}

	corrID, err := newCorrelationID()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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

	env := npamp.BridgeEnvelope{
		Protocol:      npamp.BridgeProtoHTTP2,
		Kind:          npamp.BridgeKindRequest,
		ContentType:   npamp.BridgeContentCBOR,
		CorrelationID: corrID,
		Method:        []byte(r.Method + " " + target),
	}
	obj := encodeHTTPCarriageRequest(r.Method, target, r.Header, body)
	wire := npamp.EncodeBridgePayload(env, nil, obj)

	ctx := r.Context()
	if p.RequestTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.RequestTimeout)
		defer cancel()
	}

	if err := p.Conn.Send(ctx, npamp.ChanBridge, npamp.FrameBridgeRequest, wire); err != nil {
		cleanup()
		http.Error(w, "npamp/proxy: carrying request over N-PAMP: "+err.Error(), http.StatusBadGateway)
		return
	}

	select {
	case reply := <-replyCh:
		if reply.err != nil {
			http.Error(w, "npamp/proxy: "+reply.err.Error(), http.StatusBadGateway)
			return
		}
		if reply.ft == npamp.FrameBridgeError {
			http.Error(w, "npamp/proxy: "+decodeTransportErrorReply(reply.foreign).Error(), http.StatusBadGateway)
			return
		}
		obj, derr := decodeHTTPCarriageObject(reply.foreign, httpKindResponse)
		if derr != nil {
			http.Error(w, "npamp/proxy: "+derr.Error(), http.StatusBadGateway)
			return
		}
		for _, kv := range obj.Headers {
			w.Header().Add(kv.Name, string(kv.Value))
		}
		w.WriteHeader(obj.Status)
		_, _ = w.Write(obj.Body)
	case <-ctx.Done():
		cleanup()
		http.Error(w, "npamp/proxy: "+ctx.Err().Error(), http.StatusGatewayTimeout)
	}
}
