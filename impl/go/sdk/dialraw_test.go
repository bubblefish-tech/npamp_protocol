// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// TestDialRaw_AcceptRaw_RoundTrip proves the TLS-free seam: a DialRaw client and an
// AcceptRaw server over an in-process net.Pipe complete the N-PAMP handshake (mutual
// Ed25519 auth, no TLS), each learns the other's authenticated identity, and application
// frames round-trip both directions. This is the transport the T18.2 state-learning SUL
// uses. Mutation anchor: swapping the two per-direction roles in DialRaw's newConn call
// makes the two ends derive mismatched send/recv keys, so the round-trip AEAD-open fails.
func TestDialRaw_AcceptRaw_RoundTrip(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()

	clientPub, clientPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	type res struct {
		c   *Conn
		err error
	}
	srvCh := make(chan res, 1)
	go func() {
		c, err := AcceptRaw(ctx, b, Config{Identity: serverPriv})
		srvCh <- res{c, err}
	}()

	client, err := DialRaw(ctx, a, Config{Identity: clientPriv})
	if err != nil {
		t.Fatalf("DialRaw: %v", err)
	}
	defer client.Close()
	sr := <-srvCh
	if sr.err != nil {
		t.Fatalf("AcceptRaw: %v", sr.err)
	}
	server := sr.c
	defer server.Close()

	// Identity agreement: each side learned the other's authenticated Ed25519 key.
	if !bytes.Equal(client.PeerIdentity(), serverPub) {
		t.Fatal("client did not learn the server's authenticated identity")
	}
	if !bytes.Equal(server.PeerIdentity(), clientPub) {
		t.Fatal("server did not learn the client's authenticated identity")
	}

	// Round-trip both directions across the raw (TLS-free) pipe.
	const ft npamp.FrameType = 0x0120
	rt := func(from, to *Conn, msg string) {
		t.Helper()
		// net.Pipe is UNBUFFERED — a Send write blocks until a concurrent Read consumes it —
		// so Send runs on its own goroutine while Recv reads (the goroutine-before-blocking-write
		// pattern the SUL uses).
		serr := make(chan error, 1)
		go func() { serr <- from.Send(ctx, npamp.ChanMemory, ft, []byte(msg)) }()
		_, _, got, err := to.Recv(ctx)
		if err != nil {
			t.Fatalf("recv %q: %v", msg, err)
		}
		if err := <-serr; err != nil {
			t.Fatalf("send %q: %v", msg, err)
		}
		if string(got) != msg {
			t.Fatalf("recv %q: got %q", msg, got)
		}
	}
	rt(client, server, "c->s over raw pipe")
	rt(server, client, "s->c over raw pipe")
}

// TestDialRaw_ExpectedPeerKeyMismatchFailsClosed proves the identity pin is enforced over
// the TLS-free seam: a client that pins the wrong server key fails the handshake (the pin
// is checked before the client authenticates itself).
func TestDialRaw_ExpectedPeerKeyMismatchFailsClosed(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()

	_, clientPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		if c, err := AcceptRaw(ctx, b, Config{Identity: serverPriv}); err == nil {
			_ = c.Close()
		}
	}()

	if c, err := DialRaw(ctx, a, Config{Identity: clientPriv, ExpectedPeerKey: wrongPub}); err == nil {
		_ = c.Close()
		t.Fatal("DialRaw accepted a server whose key did not match ExpectedPeerKey — pin not enforced")
	}
}
