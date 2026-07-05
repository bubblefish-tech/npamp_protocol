// SPDX-License-Identifier: Apache-2.0

package sdk_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
	"github.com/bubblefish-tech/npamp_protocol/impl/go/sdk"
)

// loopbackTLS builds a self-signed Ed25519 TLS config usable by both the
// listener (its Certificates) and the dialer (InsecureSkipVerify). The N-PAMP
// handshake — not this certificate — authenticates the peer's identity, so
// skipping certificate verification on loopback does not weaken peer
// authentication.
func loopbackTLS(t *testing.T) *tls.Config {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "npamp-loopback"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
		InsecureSkipVerify: true, //nolint:gosec // loopback: peer auth is via the N-PAMP handshake
	}
}

// TestLoopbackHandshakeAndRoundTrip runs the full 1.5-RTT post-quantum handshake
// over a real TCP+TLS loopback socket, verifies mutual identity authentication,
// and exchanges application frames in both directions on a real AEAD record
// layer.
func TestLoopbackHandshakeAndRoundTrip(t *testing.T) {
	tlsCfg := loopbackTLS(t)
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	clientPub, clientPriv, _ := ed25519.GenerateKey(rand.Reader)

	ln, err := sdk.Listen("127.0.0.1:0", sdk.Config{TLSConfig: tlsCfg, Identity: serverPriv})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type accepted struct {
		conn *sdk.Conn
		err  error
	}
	accCh := make(chan accepted, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		c, err := ln.Accept(ctx)
		accCh <- accepted{c, err}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := sdk.Dial(ctx, ln.Addr().String(), sdk.Config{
		TLSConfig:       tlsCfg,
		Identity:        clientPriv,
		ExpectedPeerKey: serverPub, // pin the server identity
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	acc := <-accCh
	if acc.err != nil {
		t.Fatalf("accept: %v", acc.err)
	}
	server := acc.conn
	defer server.Close()

	// Mutual authentication: each side proved its identity to the other.
	if !bytes.Equal(client.PeerIdentity(), serverPub) {
		t.Fatal("client did not authenticate the server's identity")
	}
	if !bytes.Equal(server.PeerIdentity(), clientPub) {
		t.Fatal("server did not authenticate the client's identity")
	}

	// client -> server on the Memory channel.
	const ftReq npamp.FrameType = 0x0120
	msg := []byte("hello from the client over a post-quantum channel")
	if err := client.Send(ctx, npamp.ChanMemory, ftReq, msg); err != nil {
		t.Fatalf("client send: %v", err)
	}
	ch, ft, got, err := server.Recv(ctx)
	if err != nil {
		t.Fatalf("server recv: %v", err)
	}
	if ch != npamp.ChanMemory || ft != ftReq || !bytes.Equal(got, msg) {
		t.Fatalf("server got ch=%d ft=%#x msg=%q", ch, ft, got)
	}

	// server -> client (full-duplex, the reverse direction on the same session).
	const ftResp npamp.FrameType = 0x0121
	reply := []byte("hello back from the server")
	if err := server.Send(ctx, npamp.ChanMemory, ftResp, reply); err != nil {
		t.Fatalf("server send: %v", err)
	}
	ch2, ft2, got2, err := client.Recv(ctx)
	if err != nil {
		t.Fatalf("client recv: %v", err)
	}
	if ch2 != npamp.ChanMemory || ft2 != ftResp || !bytes.Equal(got2, reply) {
		t.Fatalf("client got ch=%d ft=%#x msg=%q", ch2, ft2, got2)
	}

	// Two more client->server frames to exercise the per-channel sequence
	// (a nonce-reuse bug would surface as an AEAD open failure here).
	for i, m := range [][]byte{[]byte("second frame"), []byte("third frame")} {
		if err := client.Send(ctx, npamp.ChanMemory, ftReq, m); err != nil {
			t.Fatalf("client send %d: %v", i, err)
		}
		_, _, g, err := server.Recv(ctx)
		if err != nil || !bytes.Equal(g, m) {
			t.Fatalf("sequence frame %d: got %q err %v", i, g, err)
		}
	}
}

// TestPinnedKeyMismatchRejected asserts that a client pinning the wrong server
// identity aborts the handshake rather than authenticating to the peer.
func TestPinnedKeyMismatchRejected(t *testing.T) {
	tlsCfg := loopbackTLS(t)
	_, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)

	ln, err := sdk.Listen("127.0.0.1:0", sdk.Config{TLSConfig: tlsCfg, Identity: serverPriv})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// The server side fails once the client aborts before CLIENT_AUTH; that
		// is the expected outcome, so any returned conn is simply closed.
		if c, err := ln.Accept(ctx); err == nil {
			c.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := sdk.Dial(ctx, ln.Addr().String(), sdk.Config{
		TLSConfig:       tlsCfg,
		ExpectedPeerKey: wrongPub,
	}); err == nil {
		t.Fatal("dial succeeded despite a pinned-key mismatch")
	}
}
