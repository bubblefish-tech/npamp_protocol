// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Command n-pamp-proxy is the reference HTTP<->N-PAMP sidecar (task E2.4,
// requirement R10, "[A+ item 1]"; see impl/go/proxy for the carriage logic and
// the honest scope note on what is and is not yet built). One n-pamp-proxy
// process runs in exactly ONE of two roles per invocation — the two roles are
// deployed as a pair, one per side of the boundary the sidecar carries traffic
// across:
//
//   - INGRESS ("-http-listen" + "-npamp-remote"): listens on localhost for
//     plain HTTP from an unmodified client, dials the peer n-pamp-proxy over a
//     real N-PAMP session (TLS 1.3 + ALPN "n-pamp/3" + the mutually
//     authenticated post-quantum handshake), and carries each request as a
//     BRIDGE_REQUEST HTTP-Carriage Object.
//   - EGRESS ("-npamp-listen" + "-backend"): accepts an N-PAMP session from the
//     peer n-pamp-proxy, and for each BRIDGE_REQUEST it decodes, issues a real
//     HTTP request against -backend and carries the real response back.
//
// Usage (two processes, one per side):
//
//	n-pamp-proxy -npamp-listen 127.0.0.1:47730 -backend http://127.0.0.1:8080
//	n-pamp-proxy -http-listen 127.0.0.1:8090 -npamp-remote 127.0.0.1:47730
//
// A client pointed at :8090 now reaches the real service at :8080, carried
// over N-PAMP, with neither the client nor the service aware N-PAMP exists
// (R10 AC1/AC4). This reference binary generates a FRESH, ephemeral Ed25519
// identity and self-signed TLS certificate on every run (documented as the
// safe loopback-development posture in impl/go/sdk/conn.go's Config doc: N-PAMP's
// own handshake authenticates the peer's Ed25519 identity independently of the
// TLS certificate). A production deployment SHOULD load a persistent identity
// key and pin -expected-peer-key; this binary supports -expected-peer-key but
// leaves persistent key loading out of scope (not part of R10's acceptance
// criteria; packaging/key-management is AC3/AC6, deferred with the rest of the
// supply-chain work per R10 AC6 and impl/go/proxy/doc.go).
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bubblefish-tech/npamp_protocol/impl/go/proxy"
	"github.com/bubblefish-tech/npamp_protocol/impl/go/sdk"
)

func main() {
	httpListen := flag.String("http-listen", "", "INGRESS role: localhost address to accept plain HTTP on")
	npampRemote := flag.String("npamp-remote", "", "INGRESS role: address of the peer n-pamp-proxy's -npamp-listen")
	npampListen := flag.String("npamp-listen", "", "EGRESS role: address to accept an N-PAMP session on")
	backend := flag.String("backend", "", "EGRESS role: base URL of the real local HTTP service")
	expectedPeerKeyHex := flag.String("expected-peer-key", "", "hex-encoded Ed25519 public key to pin as the peer identity (recommended for production; empty accepts any peer identity)")
	handshakeTimeout := flag.Duration("handshake-timeout", 10*time.Second, "bound on the TLS+N-PAMP handshake")
	flag.Parse()

	if err := run(*httpListen, *npampRemote, *npampListen, *backend, *expectedPeerKeyHex, *handshakeTimeout); err != nil {
		fmt.Fprintf(os.Stderr, "n-pamp-proxy: %v\n", err)
		os.Exit(1)
	}
}

func run(httpListen, npampRemote, npampListen, backend, expectedPeerKeyHex string, handshakeTimeout time.Duration) error {
	ingress := httpListen != "" && npampRemote != ""
	egress := npampListen != "" && backend != ""
	switch {
	case ingress && egress:
		return fmt.Errorf("choose exactly one role per process: got both -http-listen/-npamp-remote (ingress) and -npamp-listen/-backend (egress)")
	case !ingress && !egress:
		return fmt.Errorf("either -http-listen and -npamp-remote (ingress), or -npamp-listen and -backend (egress), are required")
	}

	var expectedPeerKey ed25519.PublicKey
	if expectedPeerKeyHex != "" {
		raw, err := hex.DecodeString(expectedPeerKeyHex)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return fmt.Errorf("-expected-peer-key: want %d hex-encoded octets: %v", ed25519.PublicKeySize, err)
		}
		expectedPeerKey = ed25519.PublicKey(raw)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate identity: %w", err)
	}
	tlsCfg, err := loopbackTLSConfig()
	if err != nil {
		return fmt.Errorf("build TLS config: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := sdk.Config{
		TLSConfig:        tlsCfg,
		Identity:         priv,
		ExpectedPeerKey:  expectedPeerKey,
		HandshakeTimeout: handshakeTimeout,
	}

	if ingress {
		return runIngress(ctx, httpListen, npampRemote, cfg)
	}
	backendURL, err := url.Parse(backend)
	if err != nil {
		return fmt.Errorf("-backend: %w", err)
	}
	return runEgress(ctx, npampListen, backendURL, cfg)
}

func runIngress(ctx context.Context, httpListen, npampRemote string, cfg sdk.Config) error {
	hsCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, err := sdk.Dial(hsCtx, npampRemote, cfg)
	if err != nil {
		return fmt.Errorf("dial peer n-pamp-proxy at %s: %w", npampRemote, err)
	}
	defer conn.Close()
	fmt.Fprintf(os.Stderr, "n-pamp-proxy: N-PAMP session established with %s (peer identity %x)\n", npampRemote, conn.PeerIdentity())

	p := &proxy.Proxy{Conn: conn, RequestTimeout: 60 * time.Second}
	runErr := make(chan error, 1)
	go func() { runErr <- p.Run(ctx) }()

	server := &http.Server{Addr: httpListen, Handler: p}
	go func() {
		<-ctx.Done()
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutCancel()
		_ = server.Shutdown(shutCtx)
	}()
	fmt.Fprintf(os.Stderr, "n-pamp-proxy: ingress listening on %s, carrying to %s over N-PAMP\n", httpListen, npampRemote)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("http.Server: %w", err)
	}
	return <-runErr
}

func runEgress(ctx context.Context, npampListen string, backendURL *url.URL, cfg sdk.Config) error {
	ln, err := sdk.Listen(npampListen, cfg)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", npampListen, err)
	}
	defer ln.Close()
	fmt.Fprintf(os.Stderr, "n-pamp-proxy: egress accepting N-PAMP sessions on %s, forwarding to backend %s\n", npampListen, backendURL)

	conn, err := ln.Accept(ctx)
	if err != nil {
		return fmt.Errorf("accept N-PAMP session: %w", err)
	}
	defer conn.Close()
	fmt.Fprintf(os.Stderr, "n-pamp-proxy: N-PAMP session accepted from peer identity %x\n", conn.PeerIdentity())

	p := &proxy.Proxy{Conn: conn, Backend: backendURL}
	return p.Run(ctx)
}

// loopbackTLSConfig builds a fresh, ephemeral self-signed TLS certificate for
// the N-PAMP transport's TLS 1.3 layer, matching the posture impl/go/sdk's own
// tests use (sdk/sdk_test.go loopbackTLS) and the safety rationale documented
// in sdk.Config: the N-PAMP handshake — not this certificate — authenticates
// the peer's Ed25519 identity, so a self-signed cert with InsecureSkipVerify
// does not weaken peer authentication.
func loopbackTLSConfig() (*tls.Config, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "n-pamp-proxy"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
		InsecureSkipVerify: true, //nolint:gosec // peer auth is via the N-PAMP handshake, not this cert
	}, nil
}
