// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package firewall

import (
	"errors"
	"net"

	"github.com/bubblefish-tech/npamp_protocol/impl/go/relay"
	"github.com/bubblefish-tech/npamp_protocol/impl/go/wirevalidator"
)

// ErrNoRegistries is returned by Hook (and Wrap) when Firewall.Registries is
// nil: a Firewall with no loaded wire-validator registries cannot honestly
// claim to inspect anything, so it refuses to build a Hook at all rather
// than silently skipping R3.2's registry check.
var ErrNoRegistries = errors.New("firewall: Registries is required (nil wirevalidator.Registries)")

// Firewall composes impl/go/wirevalidator's structural/registry validation
// (R3.2) with an optional per-deployment Policy (R1.1) into a single
// relay.HookFunc that plugs directly into impl/go/relay.Relay.Hook -- see
// doc.go for the full composition order and capability-boundary rationale.
type Firewall struct {
	// Registries is the loaded wire-validator allowlist set (frame types,
	// channels, TLV tags, error codes) this Firewall's Hook enforces first,
	// on every relayed frame. Required: Hook and Wrap both return
	// ErrNoRegistries when this is nil.
	Registries *wirevalidator.Registries

	// Policy, if non-nil, is consulted for every frame that already passed
	// Registries' checks. A nil Policy denies nothing beyond what
	// Registries itself denies (mirrors relay.Relay's own "nil Hook forwards
	// every well-formed frame" default).
	Policy Policy
}

// Hook builds the composed relay.HookFunc: wirevalidator.Registries.RelayHook()
// first, then Policy.Decide if Policy is non-nil. Either layer's non-nil
// error is returned unwrapped-of-composition (the specific *wirevalidator.RejectError
// or *PolicyRejectError, still recoverable via errors.As by a caller further
// up the stack) so a caller can distinguish "the registry rejected this" from
// "this deployment's policy rejected this" without string-matching.
//
// Hook itself performs no I/O and holds no per-call state: the returned
// relay.HookFunc is safe to install on any number of relay.Relay values, and
// f.Registries/f.Policy must not be mutated concurrently with Relay.Run
// calls using a Hook this method produced (matching wirevalidator.Registries'
// own "safe for concurrent READ-only use" contract).
func (f *Firewall) Hook() (relay.HookFunc, error) {
	if f.Registries == nil {
		return nil, ErrNoRegistries
	}
	regHook := f.Registries.RelayHook()
	policy := f.Policy
	return func(dir relay.Direction, header relay.FrameHeader) error {
		if err := regHook(dir, header); err != nil {
			return err
		}
		if policy != nil {
			if err := policy.Decide(dir, header); err != nil {
				return err
			}
		}
		return nil
	}, nil
}

// Wrap is the convenience constructor for the common case: build a
// *relay.Relay between legs a and b with this Firewall's composed Hook
// already installed, and maxFrameSize forwarded verbatim to
// relay.Relay.MaxFrameSize (zero means npamp.MaxFrameSize, relay.Relay's own
// default -- Wrap does not reinterpret it). Returns ErrNoRegistries under
// the same condition Hook does.
func (f *Firewall) Wrap(a, b net.Conn, maxFrameSize uint32) (*relay.Relay, error) {
	hook, err := f.Hook()
	if err != nil {
		return nil, err
	}
	return &relay.Relay{A: a, B: b, Hook: hook, MaxFrameSize: maxFrameSize}, nil
}
