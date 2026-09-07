// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package firewall

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
	"github.com/bubblefish-tech/npamp_protocol/impl/go/relay"
	"github.com/bubblefish-tech/npamp_protocol/impl/go/wirevalidator"
)

func testRegistries(t *testing.T) *wirevalidator.Registries {
	t.Helper()
	reg, err := wirevalidator.LoadDefault()
	if err != nil {
		t.Fatalf("wirevalidator.LoadDefault: %v", err)
	}
	return reg
}

// TestHook_NilRegistries_ReturnsErrNoRegistries proves Firewall fails closed
// on its own missing configuration rather than building a Hook that
// silently skips R3.2's registry check.
func TestHook_NilRegistries_ReturnsErrNoRegistries(t *testing.T) {
	fw := &Firewall{}
	if _, err := fw.Hook(); !errors.Is(err, ErrNoRegistries) {
		t.Fatalf("Hook() error = %v, want ErrNoRegistries", err)
	}
	if _, err := fw.Wrap(nil, nil, 0); !errors.Is(err, ErrNoRegistries) {
		t.Fatalf("Wrap() error = %v, want ErrNoRegistries", err)
	}
}

// TestHook_RegistryRejectionRunsBeforePolicy proves the composition order
// doc.go documents: an UNREGISTERED channel is rejected by wirevalidator
// EVEN THOUGH a Policy that would allow everything is installed -- the
// registry layer is not bypassable by a permissive policy.
func TestHook_RegistryRejectionRunsBeforePolicy(t *testing.T) {
	fw := &Firewall{
		Registries: testRegistries(t),
		Policy:     &ChannelPolicy{}, // allows everything itself
	}
	hook, err := fw.Hook()
	if err != nil {
		t.Fatalf("Hook(): %v", err)
	}
	hdr := relay.FrameHeader{Channel: 0x00FF, Type: uint16(npamp.FramePing)} // 0x00FF: not in channels.csv
	err = hook(relay.DirAToB, hdr)
	if err == nil {
		t.Fatal("hook() = nil, want the registry rejection for an unregistered channel")
	}
	var re *wirevalidator.RejectError
	if !errors.As(err, &re) {
		t.Fatalf("hook() error = %v, want it to wrap a *wirevalidator.RejectError", err)
	}
	if re.Reason != wirevalidator.ReasonChannelNotRegistered {
		t.Fatalf("RejectError.Reason = %q, want %q", re.Reason, wirevalidator.ReasonChannelNotRegistered)
	}
}

// TestHook_PolicyRejectsAFrameTheRegistryWouldAllow proves the Policy layer
// is actually consulted (and can deny) a frame that is otherwise
// wirevalidator-valid: PING on the Control channel is registered and would
// pass the registry check alone, but a policy that denies ChanControl still
// rejects it.
func TestHook_PolicyRejectsAFrameTheRegistryWouldAllow(t *testing.T) {
	fw := &Firewall{
		Registries: testRegistries(t),
		Policy:     &ChannelPolicy{DeniedChannels: map[npamp.ChannelID]string{npamp.ChanControl: "control channel closed by policy"}},
	}
	hook, err := fw.Hook()
	if err != nil {
		t.Fatalf("Hook(): %v", err)
	}
	hdr := relay.FrameHeader{Channel: uint16(npamp.ChanControl), Type: uint16(npamp.FramePing)} // registry-valid
	err = hook(relay.DirAToB, hdr)
	if err == nil {
		t.Fatal("hook() = nil, want the policy rejection for a denied channel")
	}
	var pe *PolicyRejectError
	if !errors.As(err, &pe) {
		t.Fatalf("hook() error = %v, want it to wrap a *PolicyRejectError", err)
	}
}

// TestHook_NilPolicy_ForwardsAnythingTheRegistryAllows proves the documented
// "nil Policy denies nothing beyond the registry" default: a registry-valid
// frame passes hook() when fw.Policy is nil.
func TestHook_NilPolicy_ForwardsAnythingTheRegistryAllows(t *testing.T) {
	fw := &Firewall{Registries: testRegistries(t)}
	hook, err := fw.Hook()
	if err != nil {
		t.Fatalf("Hook(): %v", err)
	}
	hdr := relay.FrameHeader{Channel: uint16(npamp.ChanControl), Type: uint16(npamp.FramePing)}
	if err := hook(relay.DirAToB, hdr); err != nil {
		t.Fatalf("hook() with nil Policy on a registry-valid frame = %v, want nil", err)
	}
}

// TestWrap_InstallsAHookThatRejectsPreForwarding is a small, non-e2e proof
// that Wrap() actually wires the composed Hook onto a real relay.Relay: a
// single denied frame written on leg a never appears on leg b, and Run
// returns the rejection error.
func TestWrap_InstallsAHookThatRejectsPreForwarding(t *testing.T) {
	a, relayA := net.Pipe()
	relayB, b := net.Pipe()
	defer func() {
		_ = a.Close()
		_ = relayA.Close()
		_ = relayB.Close()
		_ = b.Close()
	}()

	fw := &Firewall{
		Registries: testRegistries(t),
		Policy:     &ChannelPolicy{DeniedChannels: map[npamp.ChannelID]string{npamp.ChanGovernance: "quarantined"}},
	}
	rl, err := fw.Wrap(relayA, relayB, 0)
	if err != nil {
		t.Fatalf("Wrap(): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- rl.Run(ctx) }()

	wire, err := (&npamp.Frame{Type: uint16(npamp.FramePing), Channel: uint16(npamp.ChanGovernance), Seq: 0}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	go func() { _, _ = a.Write(wire) }() // net.Pipe is unbuffered

	select {
	case err := <-runErr:
		var pe *PolicyRejectError
		if !errors.As(err, &pe) {
			t.Fatalf("Run() error = %v, want it to wrap a *PolicyRejectError", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the firewall's policy rejected the frame")
	}

	one := make([]byte, 1)
	if _, err := b.Read(one); err == nil {
		t.Fatal("b received data after the firewall rejected the frame pre-forwarding")
	}
}
