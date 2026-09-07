// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package proxy_test holds n-pamp-proxy's load-bearing end-to-end proof (R10
// AC4, the literal acceptance criterion): "An e2e test SHALL prove an
// unmodified HTTP client reaches a remote service through two sidecars over
// N-PAMP." It lives in the external proxy_test package (matching relay/
// firewall's e2e_test.go convention) so it can import both proxy and sdk
// without an import cycle.
package proxy_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/bubblefish-tech/npamp_protocol/impl/go/proxy"
	"github.com/bubblefish-tech/npamp_protocol/impl/go/sdk"
)

// twoConnectedProxies establishes a REAL N-PAMP session (the same
// sdk.DialRaw/AcceptRaw handshake driver relay's own e2e test uses) over an
// in-process net.Pipe, and returns the two ends wrapped as unstarted Proxy
// values sharing that one session -- ingressSide originates BRIDGE_REQUESTs,
// egressSide answers them against backendURL.
func twoConnectedProxies(t *testing.T, backendURL *url.URL) (ingressSide, egressSide *proxy.Proxy) {
	t.Helper()
	connA, connB := net.Pipe()
	t.Cleanup(func() { _ = connA.Close(); _ = connB.Close() })

	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate client identity: %v", err)
	}
	serverPub, serverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate server identity: %v", err)
	}
	_ = clientPub
	_ = serverPub

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
	connEgress := ar.conn
	t.Cleanup(func() { _ = connEgress.Close() })

	ingressSide = &proxy.Proxy{Conn: connIngress, RequestTimeout: 5 * time.Second}
	egressSide = &proxy.Proxy{Conn: connEgress, Backend: backendURL}

	// Only the egress side needs its dispatch loop running to ANSWER inbound
	// BRIDGE_REQUESTs; the ingress side's Run loop is what DELIVERS the
	// correlated reply back to the blocked ServeHTTP call, so both must run.
	runCtx, runCancel := context.WithCancel(context.Background())
	t.Cleanup(runCancel)
	go func() { _ = ingressSide.Run(runCtx) }()
	go func() { _ = egressSide.Run(runCtx) }()

	return ingressSide, egressSide
}

// TestE2E_UnmodifiedHTTPClient_ReachesBackend_ThroughTwoSidecars is the R10 AC4
// load-bearing proof, verbatim: "An e2e test SHALL prove an unmodified HTTP
// client reaches a remote service through two sidecars over N-PAMP."
//
//   - The "remote service" is a REAL httptest.Server (net/http, unmodified) —
//     it has no knowledge that n-pamp-proxy exists.
//   - The "unmodified HTTP client" is a plain *http.Client pointed at an
//     httptest.Server WRAPPING the ingress-side Proxy's ServeHTTP — the client
//     also has no knowledge that N-PAMP exists.
//   - Between the two: a REAL N-PAMP session (sdk.DialRaw/AcceptRaw, the same
//     1.5-RTT mutually-authenticated handshake driver every other SDK e2e test
//     in this repo uses) carrying BRIDGE_REQUEST/BRIDGE_RESPONSE frames.
//
// Mutation anchor (RED-EVIDENCE): a bug that drops, truncates, or mutates the
// carried method/target/header/body, or that fails to correlate the reply to
// the right waiting request, breaks this test.
func TestE2E_UnmodifiedHTTPClient_ReachesBackend_ThroughTwoSidecars(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/echo" {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Backend-Saw", "yes")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(append([]byte("echo:"), body...))
	}))
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}

	ingressSide, _ := twoConnectedProxies(t, backendURL)

	sidecar := httptest.NewServer(ingressSide)
	defer sidecar.Close()

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodPost, sidecar.URL+"/v1/echo", bytes.NewReader([]byte("hello n-pamp")))
	if err != nil {
		t.Fatalf("build client request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unmodified HTTP client request through the sidecar: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	if got := resp.Header.Get("X-Backend-Saw"); got != "yes" {
		t.Errorf("X-Backend-Saw header = %q, want yes (backend response header did not survive the round trip)", got)
	}
	gotBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if string(gotBody) != "echo:hello n-pamp" {
		t.Fatalf("body = %q, want %q (byte-exact round trip through two sidecars failed)", gotBody, "echo:hello n-pamp")
	}
}

// TestE2E_ForeignHTTPErrorStatus_CarriedAsSuccessfulResponse asserts §6.1: a
// 4xx/5xx backend status is a SUCCESSFUL carriage of a foreign result, not a
// BRIDGE_ERROR — the client MUST see the real 404, not a synthesized 502.
func TestE2E_ForeignHTTPErrorStatus_CarriedAsSuccessfulResponse(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found here", http.StatusNotFound)
	}))
	defer backend.Close()
	backendURL, _ := url.Parse(backend.URL)

	ingressSide, _ := twoConnectedProxies(t, backendURL)
	sidecar := httptest.NewServer(ingressSide)
	defer sidecar.Close()

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(sidecar.URL + "/anything")
	if err != nil {
		t.Fatalf("request through the sidecar: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (the foreign 404 must be carried verbatim, not replaced with a carriage-layer 502)", resp.StatusCode)
	}
}

// TestE2E_BackendUnreachable_ReportsCarriageFailure_NeverFabricatesStatus
// asserts §6.2: a below-foreign-protocol failure (the backend is down) MUST
// surface as a carriage failure to the client, and MUST NOT be reported as a
// fabricated HTTP status standing in for a response that was never obtained.
func TestE2E_BackendUnreachable_ReportsCarriageFailure_NeverFabricatesStatus(t *testing.T) {
	// A backend URL with nothing listening.
	deadBackend, _ := url.Parse("http://127.0.0.1:1") // port 1: never a live HTTP server
	ingressSide, _ := twoConnectedProxies(t, deadBackend)
	sidecar := httptest.NewServer(ingressSide)
	defer sidecar.Close()

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(sidecar.URL + "/anything")
	if err != nil {
		t.Fatalf("request through the sidecar: %v", err)
	}
	defer resp.Body.Close()
	// The carriage layer reports the failure as 502 (ServeHTTP's mapping of a
	// BRIDGE_ERROR reply); it must NOT be 200/201/etc. standing in for a
	// response the dead backend never produced.
	if resp.StatusCode < 500 {
		t.Fatalf("status = %d, want a 5xx carriage failure (backend was never reachable)", resp.StatusCode)
	}
}
