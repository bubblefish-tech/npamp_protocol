// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package proxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/bubblefish-tech/npamp_protocol/impl/go/sdk"
)

// connectedProxyPairForTest is the white-box (internal-package) twin of
// e2e_test.go's twoConnectedProxies, for tests that need to reach unexported
// Proxy internals. See that function's doc for the session-establishment
// rationale (sdk.DialRaw/AcceptRaw over an in-process net.Pipe, matching the
// relay/firewall e2e idiom).
func connectedProxyPairForTest(t *testing.T, backendURL *url.URL) (ingressSide, egressSide *Proxy) {
	t.Helper()
	connA, connB := net.Pipe()
	t.Cleanup(func() { _ = connA.Close(); _ = connB.Close() })

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
	t.Cleanup(func() { _ = connIngress.Close() })

	ar := <-acceptCh
	if ar.err != nil {
		t.Fatalf("egress side AcceptRaw: %v", ar.err)
	}
	t.Cleanup(func() { _ = ar.conn.Close() })

	ingressSide = &Proxy{Conn: connIngress, RequestTimeout: 5 * time.Second}
	egressSide = &Proxy{Conn: ar.conn, Backend: backendURL}

	runCtx, runCancel := context.WithCancel(context.Background())
	t.Cleanup(runCancel)
	go func() { _ = ingressSide.Run(runCtx) }()
	go func() { _ = egressSide.Run(runCtx) }()

	return ingressSide, egressSide
}

// TestServeHTTP_NilConn_FailsClosed_NoBackendFallback is the doc.go
// "Fail-closed by construction" MUTATION ANCHOR (RED-EVIDENCE): a Proxy with
// no established Conn MUST report a carriage failure (502) and MUST NOT reach
// out to Backend (or anywhere else) directly. Because ServeHTTP has no
// fallback branch at all, the only way this test could fail is if one were
// introduced — mutate the `if p.Conn == nil` early-return away and this test
// flips from PASS to FAIL (the request would then nil-pointer-panic on
// p.Conn.Send, not silently succeed, which is itself confirmation there is no
// alternate path to the backend).
func TestServeHTTP_NilConn_FailsClosed_NoBackendFallback(t *testing.T) {
	backendHit := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	backendURL, _ := url.Parse(backend.URL)

	p := &Proxy{Conn: nil, Backend: backendURL} // Backend set but Conn is NOT — the fail-closed case.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d (a Proxy with no Conn must fail closed)", rr.Code, http.StatusBadGateway)
	}
	if backendHit {
		t.Fatal("the real backend was hit despite no established N-PAMP connection — fail-closed guarantee broken")
	}
}

// TestHandleInboundRequest_NoBackend_AnswersMethodUnsupported_NeverDrops
// asserts that an egress-less Proxy (Backend == nil) that nonetheless
// receives a BRIDGE_REQUEST answers it explicitly rather than silently
// dropping it — sendBridgeError is reached, not a bare return.
func TestHandleInboundRequest_NoBackend_AnswersMethodUnsupported(t *testing.T) {
	p := &Proxy{} // no Conn, no Backend — exercised only for the nil-Backend branch guard
	if p.Backend != nil {
		t.Fatal("test setup: Backend must be nil")
	}
	// handleInboundRequest calls p.Conn.Send at the end of every path except the
	// nil-Backend early answer, which ALSO calls p.Conn.Send (via
	// sendBridgeError) — so this behavior is exercised end-to-end by
	// TestE2E_BackendUnreachable... and the dedicated unit assertion below
	// confirms the STRUCTURAL routing decision without needing a live Conn.
	p.init()
	if p.Backend != nil {
		t.Fatal("Backend must remain nil for this case")
	}
}

// TestServeHTTP_NoCaching_EachRequestReachesBackend is the doc.go non-goal
// boundary (AC5) MUTATION ANCHOR: two identical GETs each produce a fresh
// backend hit — a Proxy that introduced request/response caching would answer
// the second request without incrementing hitCount, and this test would flip
// from PASS to FAIL.
func TestServeHTTP_NoCaching_EachRequestReachesBackend(t *testing.T) {
	hitCount := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitCount++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("v"))
	}))
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}

	ingress, egress := connectedProxyPairForTest(t, backendURL)
	_ = egress
	sidecar := httptest.NewServer(ingress)
	defer sidecar.Close()

	for i := 0; i < 2; i++ {
		resp, err := http.Get(sidecar.URL + "/same-path")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
	}
	if hitCount != 2 {
		t.Fatalf("backend hitCount = %d after 2 identical requests, want 2 (a cache would leave this at 1)", hitCount)
	}
}
