// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package relay_test holds the relay's load-bearing end-to-end proof: a REAL
// N-PAMP session (the same sdk.DialRaw / sdk.AcceptRaw handshake driver
// impl/go/sdk's own tests use) between two agents routed entirely THROUGH a
// relay.Relay, with no direct connection between the agents at all. It lives
// in the external relay_test package (not relay) so it can import both
// relay and sdk without an import cycle.
package relay_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
	"github.com/bubblefish-tech/npamp_protocol/impl/go/relay"
	"github.com/bubblefish-tech/npamp_protocol/impl/go/sdk"
)

// TestE2E_HandshakeAndDataRoundTrip_ThroughRelay is the R1.2 load-bearing
// proof: agent A and agent B each run the REAL 1.5-RTT mutually-authenticated
// N-PAMP handshake (sdk.DialRaw / sdk.AcceptRaw — the exact primitives
// TestDialRaw_AcceptRaw_RoundTrip in impl/go/sdk/dialraw_test.go exercises
// directly against each other) with the relay sitting in between as the ONLY
// path between them: agentA is wired to relay.A, agentB is wired to relay.B,
// and agentA/agentB never share a connection of their own.
//
// It asserts:
//  1. The full handshake COMPLETES through the relay: both sides authenticate
//     each other's Ed25519 identity (PeerIdentity matches the true peer key,
//     not some relay-introduced identity — proving the relay never
//     terminates or re-originates the cryptographic session).
//  2. At least one application-data frame round-trips BYTE-EXACT end to end:
//     agentA sends a payload, agentB receives it unaltered, then echoes it
//     back, and agentA observes the byte-identical echo.
//
// Mutation anchor (RED-EVIDENCE): a bug that drops, misroutes, truncates, or
// mutates a forwarded frame breaks this test — either the handshake never
// completes (Send/Recv time out or error) or the round-tripped payload no
// longer matches what was sent.
func TestE2E_HandshakeAndDataRoundTrip_ThroughRelay(t *testing.T) {
	// agentA <-> relay.A and relay.B <-> agentB: two independent net.Pipe
	// legs. The relay is the ONLY thing connecting agentA to agentB.
	agentAConn, relayAConn := net.Pipe()
	relayBConn, agentBConn := net.Pipe()
	defer func() {
		_ = agentAConn.Close()
		_ = relayAConn.Close()
		_ = relayBConn.Close()
		_ = agentBConn.Close()
	}()

	rl := &relay.Relay{A: relayAConn, B: relayBConn}
	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	runErr := make(chan error, 1)
	go func() { runErr <- rl.Run(runCtx) }()

	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate client identity: %v", err)
	}
	serverPub, serverPriv, err := ed25519.GenerateKey(rand.Reader)
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
		c, err := sdk.AcceptRaw(hsCtx, agentBConn, sdk.Config{Identity: serverPriv})
		acceptCh <- acceptResult{c, err}
	}()

	agentA, err := sdk.DialRaw(hsCtx, agentAConn, sdk.Config{Identity: clientPriv})
	if err != nil {
		t.Fatalf("agentA DialRaw through the relay: %v", err)
	}
	defer agentA.Close()

	ar := <-acceptCh
	if ar.err != nil {
		t.Fatalf("agentB AcceptRaw through the relay: %v", ar.err)
	}
	agentB := ar.conn
	defer agentB.Close()

	// (1) The handshake completed THROUGH the relay and each side
	// authenticated the OTHER AGENT's identity -- not any identity the relay
	// might have introduced (the relay has no identity key of its own; if it
	// had somehow terminated the session, PeerIdentity would not match the
	// true peer's generated key).
	if !bytes.Equal(agentA.PeerIdentity(), serverPub) {
		t.Fatalf("agentA authenticated peer = %x, want agentB's identity %x (relay-through handshake failed to preserve end-to-end auth)",
			agentA.PeerIdentity(), serverPub)
	}
	if !bytes.Equal(agentB.PeerIdentity(), clientPub) {
		t.Fatalf("agentB authenticated peer = %x, want agentA's identity %x (relay-through handshake failed to preserve end-to-end auth)",
			agentB.PeerIdentity(), clientPub)
	}

	// (2) At least one application frame round-trips byte-exact, through the
	// relay, in both directions: agentA -> agentB, then agentB's echo back
	// to agentA. net.Pipe is unbuffered, so each Send runs on its own
	// goroutine ahead of the blocking Recv (the SUL / dialraw_test.go
	// pattern).
	const ft npamp.FrameType = 0x0120
	payload := []byte("hello through the n-pamp-relay, end to end, byte for byte")

	sendErrA := make(chan error, 1)
	go func() { sendErrA <- agentA.Send(hsCtx, npamp.ChanMemory, ft, payload) }()

	rch, rft, got, err := agentB.Recv(hsCtx)
	if err != nil {
		t.Fatalf("agentB Recv through the relay: %v", err)
	}
	if err := <-sendErrA; err != nil {
		t.Fatalf("agentA Send through the relay: %v", err)
	}
	if rch != npamp.ChanMemory {
		t.Fatalf("agentB received on channel %v, want ChanMemory", rch)
	}
	if rft != ft {
		t.Fatalf("agentB received frame type %#04x, want %#04x", uint16(rft), uint16(ft))
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("agentB received payload %q through the relay, want %q (byte-exact end-to-end round-trip failed)", got, payload)
	}

	sendErrB := make(chan error, 1)
	go func() { sendErrB <- agentB.Send(hsCtx, npamp.ChanMemory, ft, got) }()

	_, _, echo, err := agentA.Recv(hsCtx)
	if err != nil {
		t.Fatalf("agentA Recv echo through the relay: %v", err)
	}
	if err := <-sendErrB; err != nil {
		t.Fatalf("agentB Send echo through the relay: %v", err)
	}
	if !bytes.Equal(echo, payload) {
		t.Fatalf("agentA received echo %q through the relay, want %q (byte-exact round-trip failed)", echo, payload)
	}

	// Clean teardown: closing the agent connections ends the relay's
	// forwarding loops (a clean EOF on each leg), and Run must return.
	_ = agentAConn.Close()
	_ = agentBConn.Close()
	select {
	case <-runErr:
	case <-time.After(5 * time.Second):
		t.Fatal("relay.Run did not return after both agent connections closed")
	}
}
