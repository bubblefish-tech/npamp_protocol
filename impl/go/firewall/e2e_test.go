// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package firewall_test holds the firewall's load-bearing end-to-end proof
// (R1.2's E2.1 pattern, reused here for E2.2): a REAL N-PAMP session (the
// same sdk.DialRaw / sdk.AcceptRaw handshake driver impl/go/relay's own e2e
// test and impl/go/sdk's own tests use) between two agents routed entirely
// THROUGH a relay.Relay wrapped by a firewall.Firewall, with no direct
// connection between the agents at all. It lives in the external
// firewall_test package (not firewall) so it can import relay, sdk, AND
// firewall without an import cycle, mirroring impl/go/relay/e2e_test.go's
// own package split.
package firewall_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
	"github.com/bubblefish-tech/npamp_protocol/impl/go/firewall"
	"github.com/bubblefish-tech/npamp_protocol/impl/go/sdk"
	"github.com/bubblefish-tech/npamp_protocol/impl/go/wirevalidator"
)

func loadRegistries(t *testing.T) *wirevalidator.Registries {
	t.Helper()
	reg, err := wirevalidator.LoadDefault()
	if err != nil {
		t.Fatalf("wirevalidator.LoadDefault: %v", err)
	}
	return reg
}

// TestE2E_Firewall_PolicyAllowed_HandshakeAndDataRoundTrip is the R1.2-style
// ALLOW half: agent A and agent B each run the REAL 1.5-RTT
// mutually-authenticated N-PAMP handshake (sdk.DialRaw / sdk.AcceptRaw) with
// a firewall.Firewall-wrapped relay sitting in between as the ONLY path
// between them, and the firewall's Policy is configured with an ACTIVE
// deny-list that does NOT match anything this test sends (it denies
// ChanGovernance, which never appears here) -- so the policy is genuinely
// exercised on every frame, not merely absent.
//
// It asserts:
//  1. The full handshake COMPLETES through the firewall-wrapped relay: both
//     sides authenticate each other's Ed25519 identity, proving the
//     firewall (like the relay it wraps) never terminates or re-originates
//     the cryptographic session.
//  2. An application-data frame on the Memory channel round-trips
//     BYTE-EXACT end to end.
//
// Mutation anchor (RED-EVIDENCE, ALLOW-side sanity): a Firewall.Hook that
// rejected registry-valid, policy-allowed frames would fail this test (the
// handshake would never complete).
func TestE2E_Firewall_PolicyAllowed_HandshakeAndDataRoundTrip(t *testing.T) {
	agentAConn, relayAConn := net.Pipe()
	relayBConn, agentBConn := net.Pipe()
	defer func() {
		_ = agentAConn.Close()
		_ = relayAConn.Close()
		_ = relayBConn.Close()
		_ = agentBConn.Close()
	}()

	fw := &firewall.Firewall{
		Registries: loadRegistries(t),
		Policy: &firewall.ChannelPolicy{
			DeniedChannels: map[npamp.ChannelID]string{npamp.ChanGovernance: "unused in this test"},
		},
	}
	rl, err := fw.Wrap(relayAConn, relayBConn, 0)
	if err != nil {
		t.Fatalf("Firewall.Wrap: %v", err)
	}

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
		t.Fatalf("agentA DialRaw through the firewall-wrapped relay: %v", err)
	}
	defer agentA.Close()

	ar := <-acceptCh
	if ar.err != nil {
		t.Fatalf("agentB AcceptRaw through the firewall-wrapped relay: %v", ar.err)
	}
	agentB := ar.conn
	defer agentB.Close()

	if !bytes.Equal(agentA.PeerIdentity(), serverPub) {
		t.Fatalf("agentA authenticated peer = %x, want agentB's identity %x (firewall-through handshake failed to preserve end-to-end auth)",
			agentA.PeerIdentity(), serverPub)
	}
	if !bytes.Equal(agentB.PeerIdentity(), clientPub) {
		t.Fatalf("agentB authenticated peer = %x, want agentA's identity %x (firewall-through handshake failed to preserve end-to-end auth)",
			agentB.PeerIdentity(), clientPub)
	}

	// A registered Memory-channel application frame type
	// (npamp.FrameMemoryCreateReq, 0x0100) so wirevalidator's registry check
	// accepts it, then round-tripped byte-exact through the firewall.
	payload := []byte("hello through the n-pamp-firewall, policy-allowed, byte for byte")

	sendErrA := make(chan error, 1)
	go func() { sendErrA <- agentA.Send(hsCtx, npamp.ChanMemory, npamp.FrameMemoryCreateReq, payload) }()

	rch, rft, got, err := agentB.Recv(hsCtx)
	if err != nil {
		t.Fatalf("agentB Recv through the firewall: %v", err)
	}
	if err := <-sendErrA; err != nil {
		t.Fatalf("agentA Send through the firewall: %v", err)
	}
	if rch != npamp.ChanMemory {
		t.Fatalf("agentB received on channel %v, want ChanMemory", rch)
	}
	if rft != npamp.FrameMemoryCreateReq {
		t.Fatalf("agentB received frame type %#04x, want %#04x", uint16(rft), uint16(npamp.FrameMemoryCreateReq))
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("agentB received payload %q through the firewall, want %q (byte-exact end-to-end round-trip failed)", got, payload)
	}

	_ = agentAConn.Close()
	_ = agentBConn.Close()
	select {
	case <-runErr:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after both agent connections closed")
	}
}

// TestE2E_Firewall_PolicyDenied_ClientHelloRefusedPrePayload is the
// POLICY-DENIED half, and the load-bearing R1.1 proof: a Policy that denies
// npamp.FrameClientHello on the Control channel -- exactly the "CH/SH
// selections" case R1.1 names -- refuses the session at its VERY FIRST
// frame. Neither side's handshake completes: agentB's AcceptRaw never sees
// CLIENT_HELLO (the relay tears down before forwarding it), and agentA's
// DialRaw, having sent CLIENT_HELLO, then fails waiting for SERVER_HELLO
// because both relay legs were closed. No application payload -- indeed, no
// SESSION at all -- ever reaches agent B: this is "refuse a session
// pre-payload" at the earliest point a session can be refused.
//
// Mutation anchor (RED-EVIDENCE): weakening the policy's deny path (making
// it always-allow) makes this test fail, because the handshake would then
// complete instead of being refused -- see firewall's RED-EVIDENCE record.
func TestE2E_Firewall_PolicyDenied_ClientHelloRefusedPrePayload(t *testing.T) {
	agentAConn, relayAConn := net.Pipe()
	relayBConn, agentBConn := net.Pipe()
	defer func() {
		_ = agentAConn.Close()
		_ = relayAConn.Close()
		_ = relayBConn.Close()
		_ = agentBConn.Close()
	}()

	fw := &firewall.Firewall{
		Registries: loadRegistries(t),
		Policy: &firewall.ChannelPolicy{
			DeniedFrameTypes: map[firewall.ChannelFrameType]string{
				{Channel: npamp.ChanControl, Type: npamp.FrameClientHello}: "CLIENT_HELLO refused by firewall policy (E2E deny case)",
			},
		},
	}
	rl, err := fw.Wrap(relayAConn, relayBConn, 0)
	if err != nil {
		t.Fatalf("Firewall.Wrap: %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	runErr := make(chan error, 1)
	go func() { runErr <- rl.Run(runCtx) }()

	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate client identity: %v", err)
	}
	_, serverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate server identity: %v", err)
	}

	hsCtx, hsCancel := context.WithTimeout(context.Background(), 5*time.Second)
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

	dialErrCh := make(chan error, 1)
	go func() {
		_, err := sdk.DialRaw(hsCtx, agentAConn, sdk.Config{Identity: clientPriv})
		dialErrCh <- err
	}()

	// Both sides of the handshake MUST fail -- neither ever establishes a
	// session, because the firewall refused CLIENT_HELLO before it ever
	// reached agentB.
	select {
	case dialErr := <-dialErrCh:
		if dialErr == nil {
			t.Fatal("agentA DialRaw succeeded through a firewall that denies CLIENT_HELLO -- policy was not enforced")
		}
	case <-time.After(6 * time.Second):
		t.Fatal("agentA DialRaw neither completed nor failed within the timeout")
	}

	select {
	case ar := <-acceptCh:
		if ar.err == nil {
			t.Fatal("agentB AcceptRaw succeeded through a firewall that denies CLIENT_HELLO -- the session was NOT refused pre-payload")
		}
	case <-time.After(6 * time.Second):
		t.Fatal("agentB AcceptRaw neither completed nor failed within the timeout")
	}

	// Run must have torn the flow down and reported the firewall's policy
	// rejection as the reason -- not a generic transport error, so the test
	// proves WHY the session was refused, not merely that it was.
	select {
	case rerr := <-runErr:
		if rerr == nil {
			t.Fatal("Run() = nil, want the firewall's CLIENT_HELLO policy rejection")
		}
		var pe *firewall.PolicyRejectError
		if !errors.As(rerr, &pe) {
			t.Fatalf("Run() error = %v, want it to wrap a *firewall.PolicyRejectError", rerr)
		}
		if pe.Type != npamp.FrameClientHello || pe.Channel != npamp.ChanControl {
			t.Fatalf("PolicyRejectError = %+v, want Type=CLIENT_HELLO Channel=Control", pe)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("relay.Run did not return after the firewall rejected CLIENT_HELLO")
	}

	// No application data -- indeed no session at all -- ever reached
	// agent B: assert nothing is readable on agentBConn (it must be
	// closed/erroring, never delivering forwarded bytes).
	one := make([]byte, 1)
	_ = agentBConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	if n, err := agentBConn.Read(one); err == nil {
		t.Fatalf("agentB received %d byte(s) after the firewall refused the session pre-payload -- forwarded data leaked past a denied CLIENT_HELLO", n)
	}
}
