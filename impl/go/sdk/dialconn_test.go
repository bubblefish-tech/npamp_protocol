// SPDX-License-Identifier: Apache-2.0

package sdk_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"net"
	"testing"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
	"github.com/bubblefish-tech/npamp_protocol/impl/go/sdk"
)

// rawTCPPair returns a connected pair of RAW (non-TLS) TCP net.Conns on loopback:
// the client end (from net.Dial) and the server end (from ln.Accept). These are
// exactly the "caller-supplied net.Conn" that DialConn/AcceptConn operate on — no
// TLS, no ALPN, no N-PAMP framing has happened yet.
func rawTCPPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	type res struct {
		c   net.Conn
		err error
	}
	accCh := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		accCh <- res{c, err}
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	r := <-accCh
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}
	return client, r.c
}

// TestDialConnAcceptConnRoundTrip covers requirements (1), (2), and (5):
// DialConn on one end of a caller-supplied raw net.Conn and AcceptConn on the
// other complete the full 1.5-RTT mutually-authenticated handshake, honor
// ExpectedPeerKey pinning both ways, round-trip application payloads in BOTH
// directions, and behave as a normal Dial/Listen session (same channels/framing,
// full-duplex, per-channel sequence).
func TestDialConnAcceptConnRoundTrip(t *testing.T) {
	tlsCfg := loopbackTLS(t)
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	clientPub, clientPriv, _ := ed25519.GenerateKey(rand.Reader)

	rawClient, rawServer := rawTCPPair(t)

	type accepted struct {
		conn *sdk.Conn
		err  error
	}
	accCh := make(chan accepted, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		c, err := sdk.AcceptConn(ctx, rawServer, sdk.Config{
			TLSConfig:       tlsCfg,
			Identity:        serverPriv,
			ExpectedPeerKey: clientPub, // pin the client identity (server-side pin over a raw conn)
		})
		accCh <- accepted{c, err}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := sdk.DialConn(ctx, rawClient, sdk.Config{
		TLSConfig:       tlsCfg,
		Identity:        clientPriv,
		ExpectedPeerKey: serverPub, // pin the server identity
	})
	if err != nil {
		t.Fatalf("DialConn: %v", err) // (1) handshake completes
	}
	defer client.Close()

	acc := <-accCh
	if acc.err != nil {
		t.Fatalf("AcceptConn: %v", acc.err) // (1) handshake completes
	}
	server := acc.conn
	defer server.Close()

	// (1) + mutual authentication: each side proved its identity to the other, over
	// a caller-supplied raw conn.
	if !bytes.Equal(client.PeerIdentity(), serverPub) {
		t.Fatal("client did not authenticate the server's identity")
	}
	if !bytes.Equal(server.PeerIdentity(), clientPub) {
		t.Fatal("server did not authenticate the client's identity")
	}

	// (2) + (5) client -> server on the Memory channel.
	const ftReq npamp.FrameType = 0x0120
	msg := []byte("hello over a caller-supplied conn (post-quantum)")
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

	// (2) + (5) server -> client (full-duplex, reverse direction, same session).
	const ftResp npamp.FrameType = 0x0121
	reply := []byte("reply back over the same raw-conn session")
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

	// (5) exercise the per-channel sequence: a nonce-reuse bug surfaces as an AEAD
	// open failure here (same guarantee a Dial/Listen session gives).
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

// TestDialConnWrongPinRejected covers requirement (3): the ExpectedPeerKey pin
// still works over a caller-supplied raw conn — a client pinning the WRONG server
// identity aborts the handshake (before CLIENT_AUTH) rather than authenticating to
// the peer.
//
// MUTATION: this is the mutation guard for DialConn's pin. If DialConn is mutated
// to drop the pin (pass nil instead of cfg.ExpectedPeerKey to runClientHandshake),
// the handshake completes and DialConn returns a non-nil *Conn, flipping this test
// to FAIL — proving the pin is load-bearing on the DialConn path.
func TestDialConnWrongPinRejected(t *testing.T) {
	tlsCfg := loopbackTLS(t)
	_, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)

	rawClient, rawServer := rawTCPPair(t)

	// The server side fails once the client aborts before CLIENT_AUTH; any returned
	// conn is simply closed. It runs in the background so the client Dial is what the
	// test asserts on.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if c, err := sdk.AcceptConn(ctx, rawServer, sdk.Config{
			TLSConfig: tlsCfg,
			Identity:  serverPriv,
		}); err == nil {
			c.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if c, err := sdk.DialConn(ctx, rawClient, sdk.Config{
		TLSConfig:       tlsCfg,
		ExpectedPeerKey: wrongPub, // wrong pin -> must be rejected
	}); err == nil {
		if c != nil {
			c.Close()
		}
		t.Fatal("DialConn succeeded despite a pinned-key mismatch (the pin is not enforced over a raw conn)")
	}
	_ = rawClient.Close()
}

// TestAcceptConnWrongPinRejected is the server-side mirror of requirement (3): the
// ExpectedPeerKey pin of the CLIENT identity is enforced on the AcceptConn path
// over a caller-supplied raw conn. A server pinning the wrong client identity
// rejects the session.
func TestAcceptConnWrongPinRejected(t *testing.T) {
	tlsCfg := loopbackTLS(t)
	_, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, clientPriv, _ := ed25519.GenerateKey(rand.Reader)
	wrongClientPub, _, _ := ed25519.GenerateKey(rand.Reader)

	rawClient, rawServer := rawTCPPair(t)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// The client's handshake fails once the server aborts on the client-pin
		// mismatch; any returned conn is simply closed.
		if c, err := sdk.DialConn(ctx, rawClient, sdk.Config{
			TLSConfig: tlsCfg,
			Identity:  clientPriv,
		}); err == nil {
			c.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if c, err := sdk.AcceptConn(ctx, rawServer, sdk.Config{
		TLSConfig:       tlsCfg,
		Identity:        serverPriv,
		ExpectedPeerKey: wrongClientPub, // wrong client pin -> must be rejected
	}); err == nil {
		if c != nil {
			c.Close()
		}
		t.Fatal("AcceptConn succeeded despite a client pinned-key mismatch")
	}
	_ = rawServer.Close()
}

// TestDialConnHandshakeTimeout covers requirement (4) on the client path:
// Config.HandshakeTimeout bounds a stalled peer over a caller-supplied raw conn.
// The peer never performs a TLS handshake, so DialConn's TLS handshake stalls;
// with a deadline-LESS context the only thing that can end it is HandshakeTimeout.
func TestDialConnHandshakeTimeout(t *testing.T) {
	tlsCfg := loopbackTLS(t)
	rawClient, rawServer := rawTCPPair(t)
	// The server end is deliberately silent: it never speaks TLS. Hold it open so
	// the client's handshake read stalls rather than seeing EOF.
	defer func() { _ = rawServer.Close() }()

	done := make(chan error, 1)
	go func() {
		// Deadline-LESS context: only HandshakeTimeout can bound this DialConn.
		_, err := sdk.DialConn(context.Background(), rawClient, sdk.Config{
			TLSConfig:        tlsCfg,
			HandshakeTimeout: 200 * time.Millisecond,
		})
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("DialConn returned nil; expected a bounded handshake-timeout error")
		}
		t.Logf("DialConn returned a bounded error as expected: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("DialConn did not return within 3s — HandshakeTimeout did not fire; the stalled-peer DoS is not bounded on the client path")
	}
	_ = rawClient.Close()
}

// TestAcceptConnHandshakeTimeout covers requirement (4) on the server path,
// mirroring TestAcceptHandshakeTimeout for the raw-conn API: a client completes
// TCP + TLS with the required ALPN but never sends the N-PAMP CLIENT_HELLO frame.
// Without a per-connection deadline AcceptConn would block forever in the record
// read; with HandshakeTimeout set (and a deadline-LESS context) it returns a
// bounded error.
func TestAcceptConnHandshakeTimeout(t *testing.T) {
	tlsCfg := loopbackTLS(t)
	rawClient, rawServer := rawTCPPair(t)
	defer func() { _ = rawClient.Close() }()

	done := make(chan error, 1)
	go func() {
		// Deadline-LESS context: only HandshakeTimeout can bound this AcceptConn.
		_, err := sdk.AcceptConn(context.Background(), rawServer, sdk.Config{
			TLSConfig:        tlsCfg,
			HandshakeTimeout: 200 * time.Millisecond,
		})
		done <- err
	}()

	// Client: complete TLS with the required ALPN, then stall — never send the
	// N-PAMP CLIENT_HELLO frame.
	cliCfg := tlsCfg.Clone()
	cliCfg.NextProtos = []string{"n-pamp/2"}
	cliCfg.MinVersion = tls.VersionTLS13
	tc := tls.Client(rawClient, cliCfg)
	hctx, hcancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer hcancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		t.Fatalf("client tls handshake: %v", err)
	}
	// Deliberately write nothing further; hold the conn open to stall the server's
	// N-PAMP handshake read.

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("AcceptConn returned nil; expected a bounded handshake-timeout error")
		}
		t.Logf("AcceptConn returned a bounded error as expected: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("AcceptConn did not return within 3s — HandshakeTimeout did not fire; the stalled-handshake DoS is not closed")
	}
}

// TestDialConnClientToListenServer proves wire-compatibility: a DialConn client
// (over a caller-supplied raw conn) interoperates with an ordinary Listen/Accept
// server. No wire/protocol change — the raw-conn client speaks the identical
// handshake and record layer.
func TestDialConnClientToListenServer(t *testing.T) {
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
		c, err := ln.Accept(ctx) // ordinary Listen/Accept server
		accCh <- accepted{c, err}
	}()

	// Client: open a plain TCP conn to the Listen server, then run DialConn on it.
	rawClient, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := sdk.DialConn(ctx, rawClient, sdk.Config{
		TLSConfig:       tlsCfg,
		Identity:        clientPriv,
		ExpectedPeerKey: serverPub,
	})
	if err != nil {
		t.Fatalf("DialConn -> Listen server: %v", err)
	}
	defer client.Close()

	acc := <-accCh
	if acc.err != nil {
		t.Fatalf("Accept: %v", acc.err)
	}
	server := acc.conn
	defer server.Close()

	if !bytes.Equal(client.PeerIdentity(), serverPub) || !bytes.Equal(server.PeerIdentity(), clientPub) {
		t.Fatal("mutual identity mismatch across DialConn-client / Listen-server")
	}

	const ft npamp.FrameType = 0x0130
	msg := []byte("DialConn client -> Listen server")
	if err := client.Send(ctx, npamp.ChanMemory, ft, msg); err != nil {
		t.Fatalf("client send: %v", err)
	}
	_, _, got, err := server.Recv(ctx)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("server recv: got %q err %v", got, err)
	}
}

// TestDialClientToAcceptConnServer proves wire-compatibility the other way: an
// ordinary Dial client interoperates with an AcceptConn server (over a
// caller-supplied raw conn). Together with TestDialConnClientToListenServer this
// establishes that the new raw-conn entrypoints are on the SAME wire as Dial/Listen.
func TestDialClientToAcceptConnServer(t *testing.T) {
	tlsCfg := loopbackTLS(t)
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	clientPub, clientPriv, _ := ed25519.GenerateKey(rand.Reader)

	// Server: a plain TCP listener; each accepted raw conn is driven by AcceptConn.
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer func() { _ = tcpLn.Close() }()

	type accepted struct {
		conn *sdk.Conn
		err  error
	}
	accCh := make(chan accepted, 1)
	go func() {
		rawServer, aerr := tcpLn.Accept()
		if aerr != nil {
			accCh <- accepted{nil, aerr}
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		c, err := sdk.AcceptConn(ctx, rawServer, sdk.Config{
			TLSConfig:       tlsCfg,
			Identity:        serverPriv,
			ExpectedPeerKey: clientPub,
		})
		accCh <- accepted{c, err}
	}()

	// Client: ordinary Dial to the plain TCP listener's address.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := sdk.Dial(ctx, tcpLn.Addr().String(), sdk.Config{
		TLSConfig:       tlsCfg,
		Identity:        clientPriv,
		ExpectedPeerKey: serverPub,
	})
	if err != nil {
		t.Fatalf("Dial -> AcceptConn server: %v", err)
	}
	defer client.Close()

	acc := <-accCh
	if acc.err != nil {
		t.Fatalf("AcceptConn: %v", acc.err)
	}
	server := acc.conn
	defer server.Close()

	if !bytes.Equal(client.PeerIdentity(), serverPub) || !bytes.Equal(server.PeerIdentity(), clientPub) {
		t.Fatal("mutual identity mismatch across Dial-client / AcceptConn-server")
	}

	const ft npamp.FrameType = 0x0131
	msg := []byte("Dial client -> AcceptConn server")
	if err := client.Send(ctx, npamp.ChanMemory, ft, msg); err != nil {
		t.Fatalf("client send: %v", err)
	}
	_, _, got, err := server.Recv(ctx)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("server recv: got %q err %v", got, err)
	}

	// Reverse direction too, to confirm full-duplex across the mixed pair.
	reply := []byte("AcceptConn server -> Dial client")
	if err := server.Send(ctx, npamp.ChanMemory, ft, reply); err != nil {
		t.Fatalf("server send: %v", err)
	}
	_, _, got2, err := client.Recv(ctx)
	if err != nil || !bytes.Equal(got2, reply) {
		t.Fatalf("client recv: got %q err %v", got2, err)
	}
}
