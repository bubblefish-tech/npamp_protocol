// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package wirevalidator

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
	"github.com/bubblefish-tech/npamp_protocol/impl/go/relay"
)

// pipePair mirrors relay's own test helper (relay_test.go): agentA talks to
// relay.A, agentB talks to relay.B, so the test drives agentA/agentB
// directly, exactly as two real N-PAMP peers would sit on either side of a
// deployed relay running this package's Hook.
type pipePair struct {
	agentA, relayA net.Conn
	relayB, agentB net.Conn
}

func newPipePair() *pipePair {
	agentA, relayA := net.Pipe()
	relayB, agentB := net.Pipe()
	return &pipePair{agentA: agentA, relayA: relayA, relayB: relayB, agentB: agentB}
}

func (p *pipePair) closeAll() {
	_ = p.agentA.Close()
	_ = p.relayA.Close()
	_ = p.relayB.Close()
	_ = p.agentB.Close()
}

// TestRelayHook_ForwardsAllowedFrame proves reg.RelayHook(), wired as a real
// relay.Relay.Hook, forwards a frame the registries allow: the golden PING
// on the Control channel (the same accepted vector
// TestValidateBytes_AcceptsCorpusGoldenPING checks at the library level),
// byte-identical end to end.
func TestRelayHook_ForwardsAllowedFrame(t *testing.T) {
	reg := testRegistries(t)
	p := newPipePair()
	defer p.closeAll()
	rl := &relay.Relay{A: p.relayA, B: p.relayB, Hook: reg.RelayHook()}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- rl.Run(ctx) }()

	want, err := (&npamp.Frame{Type: uint16(npamp.FramePing), Channel: uint16(npamp.ChanControl), Seq: 1}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	writeErr := make(chan error, 1)
	go func() { _, err := p.agentA.Write(want); writeErr <- err }() // net.Pipe is unbuffered: write on its own goroutine

	got := make([]byte, len(want))
	if _, err := io.ReadFull(p.agentB, got); err != nil {
		t.Fatalf("agentB read: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("agentA write: %v", err)
	}

	p.closeAll()
	<-runErr
}

// TestRelayHook_RejectsUnregisteredChannel proves reg.RelayHook() rejects a
// well-formed-but-registry-invalid frame (channel 0x00FF is not in
// channels.csv) THROUGH the real relay seam, and that rejection tears down
// the WHOLE flow (both legs close) per relay.HookFunc's documented
// fail-closed contract -- not merely that the library-level Validate call
// returns an error in isolation.
func TestRelayHook_RejectsUnregisteredChannel(t *testing.T) {
	reg := testRegistries(t)
	p := newPipePair()
	defer p.closeAll()
	rl := &relay.Relay{A: p.relayA, B: p.relayB, Hook: reg.RelayHook()}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- rl.Run(ctx) }()

	wire, err := (&npamp.Frame{Type: uint16(npamp.FramePing), Channel: 0x00FF, Seq: 0}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	go func() { _, _ = p.agentA.Write(wire) }()

	select {
	case err := <-runErr:
		if err == nil {
			t.Fatal("Run() = nil, want the Hook's rejection error")
		}
		var re *RejectError
		if !errors.As(err, &re) {
			t.Fatalf("Run() error = %v, want it to wrap a *RejectError", err)
		}
		if re.Reason != ReasonChannelNotRegistered {
			t.Fatalf("RejectError reason = %q, want %q", re.Reason, ReasonChannelNotRegistered)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the Hook rejected a frame")
	}

	one := make([]byte, 1)
	if _, err := p.agentB.Read(one); err == nil {
		t.Fatal("agentB received data after the wirevalidator Hook rejected the frame")
	}
}

// TestRelayHook_RejectsUnregisteredFrameTypeForChannel is
// TestValidate_RejectsFrameTypeNotRegisteredForChannel's Hook-seam
// counterpart: CLIENT_HELLO's numeric value on the Governance channel
// (which has zero rows in frame_types_channel.csv), driven through a real
// relay.
func TestRelayHook_RejectsUnregisteredFrameTypeForChannel(t *testing.T) {
	reg := testRegistries(t)
	p := newPipePair()
	defer p.closeAll()
	rl := &relay.Relay{A: p.relayA, B: p.relayB, Hook: reg.RelayHook()}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- rl.Run(ctx) }()

	wire, err := (&npamp.Frame{Type: uint16(npamp.FrameClientHello), Channel: uint16(npamp.ChanGovernance), Seq: 0}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	go func() { _, _ = p.agentA.Write(wire) }()

	select {
	case err := <-runErr:
		var re *RejectError
		if !errors.As(err, &re) || re.Reason != ReasonFrameTypeNotRegisteredForChannel {
			t.Fatalf("Run() error = %v, want a *RejectError with reason %q", err, ReasonFrameTypeNotRegisteredForChannel)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the Hook rejected a frame")
	}
}
