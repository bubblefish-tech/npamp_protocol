// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Command n-pamp-firewall is the reference agent firewall (task E2.2,
// requirements R1.1/R3.2; see impl/go/firewall for the composition logic
// and design rationale). Like n-pamp-relay (E2.1), it listens on two TCP
// addresses, accepts exactly one connection on each, and forwards
// self-delimiting N-PAMP frames between them in both directions — but,
// unlike n-pamp-relay's unconditional forwarding, it inspects each frame's
// cleartext header (frame type, channel, sequence number, flags) against
// impl/go/wirevalidator's registries AND an operator-configured policy
// before forwarding, and REFUSES the session pre-payload (tears down both
// legs) the moment either layer rejects a frame.
//
// Usage:
//
//	n-pamp-firewall -addr-a 127.0.0.1:47730 -addr-b 127.0.0.1:47731 \
//	    -deny-channel 0x0004 -deny-frame-type 0x0000:0x0100
//
// Agent A connects to -addr-a, agent B connects to -addr-b (in either
// order); once both have connected, the firewall-wrapped relay forwards
// frames between them, running every frame through wirevalidator's registry
// check and then the configured deny-lists, until one side closes, a
// malformed/oversized/truncated/unregistered/denied frame is seen, or the
// process is interrupted. It then exits.
//
// -deny-channel may be repeated; each value is a channel_id (hex or
// decimal, per registries/channels.csv) refused outright on EITHER leg,
// regardless of frame type -- the "routing metadata" refusal R1.1 names.
//
// -deny-frame-type may be repeated; each value is "channel:type" (both hex
// or decimal) refusing that EXACT (channel, frame-type) pair while leaving
// the rest of the channel open -- e.g. "0x0000:0x0100" refuses
// CLIENT_HELLO (frame type 0x0100) on the Control channel (0x0000), the
// "CH/SH selections" refusal R1.1 names, without blocking every other
// Control-channel frame.
//
// This binary carries the reference policy shape (impl/go/firewall.ChannelPolicy)
// only; a deployment wanting a different decision procedure implements
// firewall.Policy itself (or firewall.PolicyFunc for a plain predicate) and
// constructs firewall.Firewall directly rather than using this CLI.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
	"github.com/bubblefish-tech/npamp_protocol/impl/go/firewall"
	"github.com/bubblefish-tech/npamp_protocol/impl/go/wirevalidator"
)

// repeatedFlag collects every occurrence of a flag passed more than once
// (flag.Var's documented pattern for a multi-value flag; the standard
// library's flag package has no built-in repeated-string-flag type).
type repeatedFlag []string

func (r *repeatedFlag) String() string { return strings.Join(*r, ",") }
func (r *repeatedFlag) Set(v string) error {
	*r = append(*r, v)
	return nil
}

func main() {
	addrA := flag.String("addr-a", "127.0.0.1:47730", "listen address for agent A")
	addrB := flag.String("addr-b", "127.0.0.1:47731", "listen address for agent B")
	maxFrameSize := flag.Uint("max-frame-size", npamp.MaxFrameSize, "maximum accepted frame size (header+payload) in octets")
	registryRoot := flag.String("registry-root", "", "N-PAMP repository root containing registries/*.csv (default: resolved from this binary's own source tree via wirevalidator.DefaultRegistryRoot)")
	var denyChannels repeatedFlag
	flag.Var(&denyChannels, "deny-channel", "channel_id (hex or decimal) to refuse outright; may be repeated")
	var denyFrameTypes repeatedFlag
	flag.Var(&denyFrameTypes, "deny-frame-type", "channel:type pair (hex or decimal) to refuse; may be repeated (e.g. 0x0000:0x0100 refuses CLIENT_HELLO on Control)")
	flag.Parse()

	if err := run(*addrA, *addrB, uint32(*maxFrameSize), *registryRoot, denyChannels, denyFrameTypes); err != nil {
		fmt.Fprintf(os.Stderr, "n-pamp-firewall: %v\n", err)
		os.Exit(1)
	}
}

func run(addrA, addrB string, maxFrameSize uint32, registryRoot string, denyChannels, denyFrameTypes []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	reg, err := loadRegistries(registryRoot)
	if err != nil {
		return fmt.Errorf("load wire-validator registries: %w", err)
	}
	policy, err := buildPolicy(denyChannels, denyFrameTypes)
	if err != nil {
		return fmt.Errorf("build policy: %w", err)
	}
	fw := &firewall.Firewall{Registries: reg, Policy: policy}

	connA, err := acceptOne(ctx, addrA, "A")
	if err != nil {
		return err
	}
	defer connA.Close()

	connB, err := acceptOne(ctx, addrB, "B")
	if err != nil {
		return err
	}
	defer connB.Close()

	fmt.Fprintf(os.Stderr, "n-pamp-firewall: agent A (%s) and agent B (%s) connected; forwarding frames (max %d octets/frame, %d denied channel(s), %d denied (channel,type) pair(s))\n",
		connA.RemoteAddr(), connB.RemoteAddr(), maxFrameSize, len(denyChannels), len(denyFrameTypes))

	rl, err := fw.Wrap(connA, connB, maxFrameSize)
	if err != nil {
		return fmt.Errorf("wrap connections: %w", err)
	}
	if err := rl.Run(ctx); err != nil {
		return fmt.Errorf("flow ended: %w", err)
	}
	fmt.Fprintln(os.Stderr, "n-pamp-firewall: flow ended cleanly")
	return nil
}

// loadRegistries loads the wire-validator registries this firewall enforces
// (R3.2): from root if non-empty, else from wirevalidator's own
// source-tree-relative default (the same resolution n-pamp-relay's sibling
// packages and this repository's own tests use).
func loadRegistries(root string) (*wirevalidator.Registries, error) {
	if root != "" {
		return wirevalidator.Load(root)
	}
	return wirevalidator.LoadDefault()
}

// buildPolicy parses -deny-channel and -deny-frame-type into a
// firewall.ChannelPolicy. A caller passing neither flag gets a policy that
// denies nothing beyond what the registries already deny -- this binary's
// honest default, mirroring n-pamp-relay's own "no Hook" default posture
// one layer up (wire-validator-only, no additional local policy).
func buildPolicy(denyChannels, denyFrameTypes []string) (*firewall.ChannelPolicy, error) {
	p := &firewall.ChannelPolicy{
		DeniedChannels:   map[npamp.ChannelID]string{},
		DeniedFrameTypes: map[firewall.ChannelFrameType]string{},
	}
	for _, raw := range denyChannels {
		id, err := parseUint16(raw)
		if err != nil {
			return nil, fmt.Errorf("-deny-channel %q: %w", raw, err)
		}
		p.DeniedChannels[npamp.ChannelID(id)] = "denied by -deny-channel"
	}
	for _, raw := range denyFrameTypes {
		parts := strings.SplitN(raw, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("-deny-frame-type %q: want channel:type (e.g. 0x0000:0x0100)", raw)
		}
		ch, err := parseUint16(parts[0])
		if err != nil {
			return nil, fmt.Errorf("-deny-frame-type %q: channel: %w", raw, err)
		}
		ft, err := parseUint16(parts[1])
		if err != nil {
			return nil, fmt.Errorf("-deny-frame-type %q: type: %w", raw, err)
		}
		p.DeniedFrameTypes[firewall.ChannelFrameType{Channel: npamp.ChannelID(ch), Type: npamp.FrameType(ft)}] = "denied by -deny-frame-type"
	}
	return p, nil
}

// parseUint16 parses a hex ("0x..."/"0X...") or decimal code point, base 0
// (Go auto-detects the 0x prefix), matching how registries/*.csv and this
// repository's own CLI flags mix hex and decimal representations.
func parseUint16(tok string) (uint16, error) {
	v, err := strconv.ParseUint(strings.TrimSpace(tok), 0, 16)
	if err != nil {
		return 0, err
	}
	return uint16(v), nil
}

// acceptOne listens on addr, accepts exactly one connection, and closes the
// listener (this reference firewall forwards a single flow per invocation,
// exactly like n-pamp-relay; a production deployment would loop Accept and
// spawn a Firewall-wrapped Relay per accepted pair, reusing the same
// firewall.Firewall/relay.Relay types unchanged).
func acceptOne(ctx context.Context, addr, label string) (net.Conn, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen (agent %s) on %s: %w", label, addr, err)
	}
	defer ln.Close()
	fmt.Fprintf(os.Stderr, "n-pamp-firewall: waiting for agent %s on %s\n", label, ln.Addr())

	type result struct {
		conn net.Conn
		err  error
	}
	acceptCh := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		acceptCh <- result{conn, err}
	}()

	select {
	case r := <-acceptCh:
		if r.err != nil {
			return nil, fmt.Errorf("accept (agent %s) on %s: %w", label, addr, r.err)
		}
		return r.conn, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("accept (agent %s) on %s: %w", label, addr, ctx.Err())
	}
}
