// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package firewall

import (
	"errors"
	"testing"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
	"github.com/bubblefish-tech/npamp_protocol/impl/go/relay"
)

// TestChannelPolicy_ZeroValueDeniesNothing proves the A3/A4 non-stub bar
// directly: an empty ChannelPolicy{} allows any header, because it has no
// deny rule configured -- not because Decide ignores its input.
func TestChannelPolicy_ZeroValueDeniesNothing(t *testing.T) {
	p := &ChannelPolicy{}
	hdr := relay.FrameHeader{Channel: uint16(npamp.ChanControl), Type: uint16(npamp.FrameClientHello)}
	if err := p.Decide(relay.DirAToB, hdr); err != nil {
		t.Fatalf("Decide() on empty policy = %v, want nil (zero value denies nothing)", err)
	}
}

// TestChannelPolicy_DeniedChannel_RejectsEveryFrameOnThatChannel proves the
// same policy VALUE, given headers that differ only in Channel, returns
// different verdicts depending on which channel is denied -- the verdict is
// a function of the input, not a constant (A4).
func TestChannelPolicy_DeniedChannel_RejectsEveryFrameOnThatChannel(t *testing.T) {
	p := &ChannelPolicy{DeniedChannels: map[npamp.ChannelID]string{npamp.ChanGovernance: "governance quarantined"}}

	deniedHdr := relay.FrameHeader{Channel: uint16(npamp.ChanGovernance), Type: uint16(npamp.FramePing)}
	if err := p.Decide(relay.DirAToB, deniedHdr); err == nil {
		t.Fatal("Decide() on denied channel = nil, want a PolicyRejectError")
	} else {
		var re *PolicyRejectError
		if !errors.As(err, &re) {
			t.Fatalf("Decide() error = %v, want it to wrap a *PolicyRejectError", err)
		}
		if re.Channel != npamp.ChanGovernance || re.Reason != "governance quarantined" {
			t.Fatalf("PolicyRejectError = %+v, want Channel=ChanGovernance Reason=%q", re, "governance quarantined")
		}
	}

	allowedHdr := relay.FrameHeader{Channel: uint16(npamp.ChanMemory), Type: uint16(npamp.FramePing)}
	if err := p.Decide(relay.DirAToB, allowedHdr); err != nil {
		t.Fatalf("Decide() on a DIFFERENT (non-denied) channel = %v, want nil", err)
	}
}

// TestChannelPolicy_DeniedFrameType_ScopesToTheExactPair proves a
// (channel,type) denial does NOT bleed onto the same frame type on a
// different channel, or a different frame type on the same channel -- the
// deny rule is scoped exactly as configured, not approximated.
func TestChannelPolicy_DeniedFrameType_ScopesToTheExactPair(t *testing.T) {
	p := &ChannelPolicy{
		DeniedFrameTypes: map[ChannelFrameType]string{
			{Channel: npamp.ChanControl, Type: npamp.FrameClientHello}: "CLIENT_HELLO refused by policy",
		},
	}

	deniedHdr := relay.FrameHeader{Channel: uint16(npamp.ChanControl), Type: uint16(npamp.FrameClientHello)}
	if err := p.Decide(relay.DirAToB, deniedHdr); err == nil {
		t.Fatal("Decide() on denied (channel,type) = nil, want a PolicyRejectError")
	}

	sameChannelDifferentType := relay.FrameHeader{Channel: uint16(npamp.ChanControl), Type: uint16(npamp.FrameServerHello)}
	if err := p.Decide(relay.DirAToB, sameChannelDifferentType); err != nil {
		t.Fatalf("Decide() on SERVER_HELLO/Control (a different type, same channel) = %v, want nil", err)
	}

	sameTypeDifferentChannel := relay.FrameHeader{Channel: uint16(npamp.ChanMemory), Type: uint16(npamp.FrameClientHello)}
	if err := p.Decide(relay.DirAToB, sameTypeDifferentChannel); err != nil {
		t.Fatalf("Decide() on CLIENT_HELLO's numeric type on ChanMemory (a different channel) = %v, want nil", err)
	}
}

// TestChannelPolicy_DeniedChannelWinsOverDeniedFrameTypeAbsence documents
// Decide's stated check order (DeniedChannels first): a whole-channel
// denial rejects a frame even though no DeniedFrameTypes entry matches it.
func TestChannelPolicy_DeniedChannelWinsOverDeniedFrameTypeAbsence(t *testing.T) {
	p := &ChannelPolicy{
		DeniedChannels:   map[npamp.ChannelID]string{npamp.ChanMemory: "memory channel closed"},
		DeniedFrameTypes: map[ChannelFrameType]string{}, // deliberately empty: only the channel rule should fire
	}
	hdr := relay.FrameHeader{Channel: uint16(npamp.ChanMemory), Type: uint16(npamp.FrameMemoryCreateReq)}
	err := p.Decide(relay.DirBToA, hdr)
	if err == nil {
		t.Fatal("Decide() = nil, want the channel-level denial to fire")
	}
	var re *PolicyRejectError
	if !errors.As(err, &re) || re.Reason != "memory channel closed" {
		t.Fatalf("Decide() error = %v, want the DeniedChannels reason", err)
	}
}

// TestPolicyFunc_AdaptsAPlainPredicate proves the PolicyFunc adapter really
// delegates: two different closures over the same header type produce two
// different verdicts.
func TestPolicyFunc_AdaptsAPlainPredicate(t *testing.T) {
	alwaysAllow := PolicyFunc(func(relay.Direction, relay.FrameHeader) error { return nil })
	alwaysDeny := PolicyFunc(func(dir relay.Direction, header relay.FrameHeader) error {
		return &PolicyRejectError{Dir: dir, Channel: npamp.ChannelID(header.Channel), Type: npamp.FrameType(header.Type), Reason: "test predicate denies everything"}
	})
	hdr := relay.FrameHeader{Channel: uint16(npamp.ChanControl), Type: uint16(npamp.FramePing)}

	if err := alwaysAllow.Decide(relay.DirAToB, hdr); err != nil {
		t.Fatalf("alwaysAllow.Decide() = %v, want nil", err)
	}
	if err := alwaysDeny.Decide(relay.DirAToB, hdr); err == nil {
		t.Fatal("alwaysDeny.Decide() = nil, want a rejection")
	}
}

// TestPolicyRejectError_ErrorStringNamesTheOffendingHeader is a light
// sanity check that Error() is not empty/generic across different headers
// (so a log line is actually actionable).
func TestPolicyRejectError_ErrorStringNamesTheOffendingHeader(t *testing.T) {
	e1 := &PolicyRejectError{Dir: relay.DirAToB, Channel: npamp.ChanControl, Type: npamp.FrameClientHello, Reason: "r1"}
	e2 := &PolicyRejectError{Dir: relay.DirBToA, Channel: npamp.ChanMemory, Type: npamp.FramePing, Reason: "r2"}
	if e1.Error() == e2.Error() {
		t.Fatalf("two PolicyRejectErrors with different fields produced the same Error() string: %q", e1.Error())
	}
}
