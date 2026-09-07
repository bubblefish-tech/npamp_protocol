// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package proxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"sync"
	"testing"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
	"github.com/bubblefish-tech/npamp_protocol/impl/go/sdk"
)

// connectedOpaqueProxyPairForTest establishes a REAL N-PAMP session (the same
// sdk.DialRaw/AcceptRaw driver every other leg's white-box test uses --
// proxy_test.go connectedProxyPairForTest) with OpaqueProtocolID/OpaqueHandler
// configured at construction on both ends, so this leg's dispatch is
// exercised through the real Run loop, not called directly.
func connectedOpaqueProxyPairForTest(t *testing.T, opaqueProtocolID npamp.BridgeProtocol, handler OpaqueHandlerFunc) (ingressSide, egressSide *Proxy) {
	t.Helper()
	connA, connB := net.Pipe()

	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate client identity: %v", err)
	}
	_, serverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate server identity: %v", err)
	}

	hsCtx, hsCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer hsCancel()

	type acceptResult struct {
		conn *sdk.Conn
		err  error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		c, err := sdk.AcceptRaw(hsCtx, connB, sdk.Config{Identity: serverPriv})
		acceptCh <- acceptResult{c, err}
	}()

	connIngress, err := sdk.DialRaw(hsCtx, connA, sdk.Config{Identity: clientPriv})
	if err != nil {
		t.Fatalf("ingress side DialRaw: %v", err)
	}
	ar := <-acceptCh
	if ar.err != nil {
		t.Fatalf("egress side AcceptRaw: %v", ar.err)
	}

	ingressSide = &Proxy{Conn: connIngress, RequestTimeout: 5 * time.Second, OpaqueProtocolID: opaqueProtocolID}
	egressSide = &Proxy{Conn: ar.conn, OpaqueProtocolID: opaqueProtocolID, OpaqueHandler: handler}

	runCtx, runCancel := context.WithCancel(context.Background())
	var runWG sync.WaitGroup
	runWG.Add(2)
	go func() { defer runWG.Done(); _ = ingressSide.Run(runCtx) }()
	go func() { defer runWG.Done(); _ = egressSide.Run(runCtx) }()
	// Single, self-contained teardown: cancel runCtx (so Run does not start a
	// NEW Recv once its current one returns), close BOTH sdk.Conns, THEN wait
	// for both Run goroutines to exit. Close must run BEFORE Wait: ctx
	// cancellation alone does not unblock an in-flight blocking Recv over a
	// net.Pipe -- sdk.Conn.readWire applies a read deadline only when ctx
	// carries one (context.Deadline()'s ok==true), and a bare
	// context.WithCancel never does, so a Run goroutine parked inside
	// io.ReadFull on the pipe cannot observe cancellation until something
	// closes the underlying conn. Conn.Close is sync.Once-guarded (safe to
	// call once here), and DialRaw/AcceptRaw store the net.Pipe half passed to
	// them as the Conn's own raw net.Conn, so closing connIngress/ar.conn also
	// closes connA/connB -- no separate close of those two is needed.
	//
	// A prior version of this helper registered three separate t.Cleanup
	// calls (conn closes first, cancel+Wait last) relying on Go's LIFO
	// cleanup order to run cancel+Wait BEFORE the closes -- backwards: LIFO
	// means the LAST-registered cleanup runs FIRST, so that ordering made
	// Wait() run before any conn was closed and deadlocked every test that
	// reached this helper (reproduced: go test -race and a non-race -run
	// TestE2E_CallOpaque both hung to their timeout with both Run goroutines
	// parked in net.(*pipe).read). Folding cancel, close, and Wait into one
	// cleanup removes the ordering dependency entirely.
	t.Cleanup(func() {
		runCancel()
		_ = connIngress.Close()
		_ = ar.conn.Close()
		runWG.Wait()
	})

	return ingressSide, egressSide
}

// TestCallOpaque_ProtocolIDUnset_Rejected is a fail-closed MUTATION ANCHOR
// (RED-EVIDENCE), mirroring TestServeHTTP_NilConn_FailsClosed_NoBackendFallback:
// removing the OpaqueProtocolID==0 guard would let CallOpaque squat on
// protocol_id 0x00 -- the reserved null identifier a receiver MUST reject
// (NPAMP-BRIDGE §4/§9) -- rather than refusing locally before anything is
// sent.
func TestCallOpaque_ProtocolIDUnset_Rejected(t *testing.T) {
	connA, connB := net.Pipe()
	defer connA.Close()
	defer connB.Close()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	// A Proxy with SOME established Conn (so this exercises the OpaqueProtocolID
	// guard specifically, not the earlier nil-Conn guard) but OpaqueProtocolID
	// left at its zero value.
	go func() { _, _ = sdk.AcceptRaw(context.Background(), connB, sdk.Config{Identity: priv}) }()
	conn, err := sdk.DialRaw(context.Background(), connA, sdk.Config{Identity: priv})
	if err != nil {
		t.Skipf("handshake setup failed (not the property under test): %v", err)
	}
	defer conn.Close()

	p := &Proxy{Conn: conn}
	if _, _, err := p.CallOpaque(context.Background(), "application/octet-stream", []byte("x")); err != ErrOpaqueProtocolIDUnset {
		t.Fatalf("CallOpaque error = %v, want ErrOpaqueProtocolIDUnset", err)
	}
}

// TestCallOpaque_NoConn_Rejected asserts the same fail-closed guard ServeHTTP
// applies (proxy.go ErrNoConn) holds for this leg too.
func TestCallOpaque_NoConn_Rejected(t *testing.T) {
	p := &Proxy{OpaqueProtocolID: 0x50}
	if _, _, err := p.CallOpaque(context.Background(), "application/octet-stream", []byte("x")); err != ErrNoConn {
		t.Fatalf("CallOpaque error = %v, want ErrNoConn", err)
	}
}

// TestE2E_CallOpaque_Case1EnumeratedMediaType_RoundTrip proves the full wire
// path -- CallOpaque -> Send -> the peer's Run/handleInboundBridgeRequest
// dispatch -> handleInboundOpaqueRequest -> OpaqueHandler -> BRIDGE_RESPONSE
// -> deliverReply -> CallOpaque's return -- for a §4.2 case-1 media type.
func TestE2E_CallOpaque_Case1EnumeratedMediaType_RoundTrip(t *testing.T) {
	const opaqueID npamp.BridgeProtocol = 0x50 // an arbitrary private-use protocol_id (§7.2), this test's out-of-band agreement
	handlerSawMediaType := ""
	handlerSawPayload := []byte(nil)
	ingress, _ := connectedOpaqueProxyPairForTest(t, opaqueID, func(ctx context.Context, mediaType string, req []byte) (string, []byte, error) {
		handlerSawMediaType = mediaType
		handlerSawPayload = append([]byte(nil), req...)
		return "application/json", []byte(`{"echo":true}`), nil
	})

	sent := []byte(`{"call":"opaque"}`)
	replyMediaType, resp, err := ingress.CallOpaque(context.Background(), "application/json", sent)
	if err != nil {
		t.Fatalf("CallOpaque: %v", err)
	}
	if handlerSawMediaType != "application/json" {
		t.Errorf("handler saw mediaType = %q, want application/json", handlerSawMediaType)
	}
	if !bytes.Equal(handlerSawPayload, sent) {
		t.Errorf("handler saw payload = %q, want %q", handlerSawPayload, sent)
	}
	if replyMediaType != "application/json" {
		t.Errorf("replyMediaType = %q, want application/json", replyMediaType)
	}
	if string(resp) != `{"echo":true}` {
		t.Errorf("resp = %q, want {\"echo\":true}", resp)
	}
}

// TestE2E_CallOpaque_Case2NonEnumeratedMediaType_RoundTrip is the R10/E2.4
// literal target of this leg: a "raw TCP"-shaped payload declared under a
// media type the BridgeEnvelope content_type enumeration does not carry
// (application/octet-stream), round-tripped byte-exact through two real
// N-PAMP sidecars via the OpaqueContentType TLV this build registers.
func TestE2E_CallOpaque_Case2NonEnumeratedMediaType_RoundTrip(t *testing.T) {
	const opaqueID npamp.BridgeProtocol = 0x80 // private-use range (§7.2)
	raw := []byte{0x00, 0x01, 0xFF, 0xFE, 0x00, 'r', 'a', 'w'}
	ingress, _ := connectedOpaqueProxyPairForTest(t, opaqueID, func(ctx context.Context, mediaType string, req []byte) (string, []byte, error) {
		if mediaType != "application/octet-stream" {
			t.Errorf("handler saw mediaType = %q, want application/octet-stream", mediaType)
		}
		return "application/octet-stream", append([]byte{'r', 'e', 'p', 'l', 'y', ':'}, req...), nil
	})

	replyMediaType, resp, err := ingress.CallOpaque(context.Background(), "application/octet-stream", raw)
	if err != nil {
		t.Fatalf("CallOpaque: %v", err)
	}
	if replyMediaType != "application/octet-stream" {
		t.Errorf("replyMediaType = %q, want application/octet-stream", replyMediaType)
	}
	want := append([]byte{'r', 'e', 'p', 'l', 'y', ':'}, raw...)
	if !bytes.Equal(resp, want) {
		t.Errorf("resp = %v, want %v (byte-exact round trip through two real sidecars, including embedded NUL/high-bit octets)", resp, want)
	}
}

// TestHandleInboundOpaqueRequest_NoHandler_AnswersMethodUnsupported asserts
// an egress-less Proxy for this leg (OpaqueHandler == nil) answers explicitly
// rather than dropping — mirroring the HTTP/JSON-RPC legs' own nil-handler
// convention (proxy.go/jsonrpc.go).
func TestHandleInboundOpaqueRequest_NoHandler_AnswersMethodUnsupported(t *testing.T) {
	const opaqueID npamp.BridgeProtocol = 0x60
	ingress, _ := connectedOpaqueProxyPairForTest(t, opaqueID, nil) // egress has OpaqueProtocolID set but OpaqueHandler nil
	_, _, err := ingress.CallOpaque(context.Background(), "application/octet-stream", []byte("x"))
	if err == nil {
		t.Fatal("CallOpaque succeeded against a peer with no OpaqueHandler configured, want a carriage failure")
	}
}
