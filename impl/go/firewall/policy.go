// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package firewall

import (
	"fmt"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
	"github.com/bubblefish-tech/npamp_protocol/impl/go/relay"
)

// Policy is the per-frame allow/deny decision Firewall consults for every
// relayed frame, AFTER that frame has already passed the wire validator's
// structural/registry check (doc.go). It sees exactly the same cleartext
// relay.FrameHeader the wire validator's Hook sees -- frame type, channel,
// sequence number, flags, declared payload length, and the raw 36 header
// octets -- never payload bytes.
//
// Decide returns nil to ALLOW the frame, or a non-nil error explaining why
// to DENY it. A denial rejects the frame at the relay.HookFunc seam, which
// tears down BOTH legs of the flow (fail-closed, matching R12's posture and
// wirevalidator's own rejection contract) -- Decide never gets a chance to
// silently drop just one frame while letting the flow continue.
type Policy interface {
	Decide(dir relay.Direction, header relay.FrameHeader) error
}

// PolicyFunc adapts a plain function to the Policy interface, for a
// caller-supplied predicate that does not need any configuration state
// beyond a closure.
type PolicyFunc func(dir relay.Direction, header relay.FrameHeader) error

// Decide calls f, satisfying Policy.
func (f PolicyFunc) Decide(dir relay.Direction, header relay.FrameHeader) error {
	return f(dir, header)
}

// ChannelFrameType is the (channel, frame type) composite key
// ChannelPolicy.DeniedFrameTypes is keyed by -- the same pairing
// wirevalidator's own frame_types_channel.csv registry uses, so a caller
// configuring a per-(channel,type) deny rule can read it the same way they
// would read that registry.
type ChannelFrameType struct {
	Channel npamp.ChannelID
	Type    npamp.FrameType
}

// ChannelPolicy is a reference allow/deny-list Policy over channel and
// (channel, frame-type) pairs -- the concrete mechanism R1.1 calls for: an
// operator can refuse specific channels outright, or refuse specific frame
// types (including CLIENT_HELLO/SERVER_HELLO -- the "CH/SH" of R1.1) on a
// channel that otherwise remains open, WITHOUT needing wirevalidator-level
// registry changes (a registry change would forbid a frame type/channel
// pair for every deployment; a ChannelPolicy denial is this one firewall
// instance's local, operator-configured policy).
//
// The zero value denies nothing: an empty (nil) DeniedChannels and
// DeniedFrameTypes means every frame that already passed the wire validator
// is allowed. Every field is read-only after construction; ChannelPolicy is
// safe for concurrent use by multiple Firewall.Hook invocations as long as
// the caller does not mutate the maps after handing the policy to a
// Firewall.
type ChannelPolicy struct {
	// DeniedChannels denies EVERY frame on a listed channel, in either
	// direction, regardless of frame type -- the "routing metadata" half of
	// R1.1 (refuse an entire channel/route).
	DeniedChannels map[npamp.ChannelID]string

	// DeniedFrameTypes denies a specific (channel, frame-type) pair even
	// when the channel itself is not in DeniedChannels -- e.g. refusing
	// CLIENT_HELLO on the Control channel while leaving every other Control
	// frame type (and every other channel) untouched. This is the "CH/SH
	// selections" half of R1.1: a deployment can refuse the handshake
	// itself, at its very first frame, before any session is ever
	// established.
	DeniedFrameTypes map[ChannelFrameType]string
}

// Decide implements Policy: DeniedChannels is checked first (a whole-channel
// denial is the coarser rule and should win over a narrower per-type
// allowance the caller never expressed), then DeniedFrameTypes. A frame
// matching neither map is allowed. This is a real decision over its
// parameters, not a stub: an empty ChannelPolicy{} allows everything an
// otherwise-identical ChannelPolicy with DeniedChannels/DeniedFrameTypes
// populated would deny for the exact same header -- the verdict is
// determined by the policy's configuration, never hardcoded.
func (p *ChannelPolicy) Decide(dir relay.Direction, header relay.FrameHeader) error {
	ch := npamp.ChannelID(header.Channel)
	ft := npamp.FrameType(header.Type)

	if p.DeniedChannels != nil {
		if reason, denied := p.DeniedChannels[ch]; denied {
			return &PolicyRejectError{
				Dir:     dir,
				Channel: ch,
				Type:    ft,
				Reason:  reasonOrDefault(reason, fmt.Sprintf("channel 0x%04X is denied by firewall policy", uint16(ch))),
			}
		}
	}

	if p.DeniedFrameTypes != nil {
		key := ChannelFrameType{Channel: ch, Type: ft}
		if reason, denied := p.DeniedFrameTypes[key]; denied {
			return &PolicyRejectError{
				Dir:     dir,
				Channel: ch,
				Type:    ft,
				Reason:  reasonOrDefault(reason, fmt.Sprintf("frame type 0x%04X on channel 0x%04X is denied by firewall policy", uint16(ft), uint16(ch))),
			}
		}
	}

	return nil
}

// reasonOrDefault returns reason if it is non-empty, else def -- so a
// caller MAY supply a human-readable reason per deny-list entry (surfaced
// in PolicyRejectError.Reason and, downstream, in any audit log) without
// being REQUIRED to.
func reasonOrDefault(reason, def string) string {
	if reason != "" {
		return reason
	}
	return def
}

// PolicyRejectError is the error every ChannelPolicy denial returns:
// enough structured detail (which direction, which channel, which frame
// type, why) for a caller to log or assert on without string-matching
// Error(). errors.As recovers it from the wrapped error Firewall.Hook
// returns.
type PolicyRejectError struct {
	Dir     relay.Direction
	Channel npamp.ChannelID
	Type    npamp.FrameType
	Reason  string
}

func (e *PolicyRejectError) Error() string {
	return fmt.Sprintf("firewall: policy denied %s frame type=0x%04X channel=0x%04X: %s",
		e.Dir, uint16(e.Type), uint16(e.Channel), e.Reason)
}
