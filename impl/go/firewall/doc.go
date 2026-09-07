// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package firewall implements a reference N-PAMP agent firewall (task E2.2,
// requirements R1.1/R3.2): a policy layer that composes with a
// non-decrypting impl/go/relay.Relay to inspect the cleartext handshake
// (CLIENT_HELLO/SERVER_HELLO frame types on the Control channel) and
// channel/routing metadata of every relayed frame, and to refuse a session
// PRE-PAYLOAD when policy denies it.
//
// # What the firewall is
//
// A Firewall does not implement its own frame forwarding: it composes with
// an existing impl/go/relay.Relay by building a single relay.HookFunc that
// runs, per frame, in this fixed order:
//
//  1. impl/go/wirevalidator's own RelayHook (R3.2): structural + registry
//     validation -- a reserved frame type, an unregistered channel, an
//     unregistered (channel, frame-type) pair, or an oversized frame is
//     rejected here, before this package's policy is even consulted.
//  2. This package's Policy (R1.1): a caller-configured allow/deny decision
//     over the SAME cleartext relay.FrameHeader fields (frame type,
//     channel, sequence number, flags) -- which frame types (including
//     CLIENT_HELLO/SERVER_HELLO -- npamp.FrameClientHello /
//     npamp.FrameServerHello, the "CH/SH" of R1.1) and which channels a
//     given deployment permits.
//
// Either layer's rejection rejects the frame. Per relay.HookFunc's
// documented contract, a non-nil error from the composed hook tears down
// BOTH legs of the flow (fail-closed) rather than forwarding it or silently
// dropping only that one frame -- so a denied CLIENT_HELLO refuses the
// session before the handshake ever completes, and a denied post-handshake
// channel refuses the flow before any application payload on that channel
// is forwarded to the peer. Both are "refuse a session pre-payload" in the
// sense R1.1 names, at two different points in a session's lifetime.
//
// # Capability boundary (same one wirevalidator.RelayHook already documents)
//
// relay.FrameHeader carries ONLY the cleartext 36-octet header fields --
// never payload bytes, encrypted or otherwise (impl/go/relay/doc.go, "The
// firewall seam"). So this package's Policy can inspect WHICH handshake
// frame types transit (CLIENT_HELLO vs SERVER_HELLO vs an application
// frame) and WHICH channel/sequence/flags a frame carries, but it cannot
// inspect the negotiated cipher suite, KEM group, or any other field
// encoded INSIDE a CLIENT_HELLO/SERVER_HELLO payload -- that would require
// decrypting or at least payload-parsing a frame the relay seam never
// exposes. This is an honest capability boundary, not an oversight: a
// deployment that also wants to gate on negotiated-parameter content needs
// a layer that terminates or payload-parses the handshake (an SDK-level
// endpoint), not a non-decrypting relay-seam firewall.
//
// # Fail-closed defaults
//
// A Firewall with a nil Policy denies nothing beyond what wirevalidator
// already denies (mirroring relay.Relay's own "nil Hook forwards every
// well-formed frame" default) -- but Firewall.Registries is REQUIRED
// (unlike relay's nil-Hook default, a Firewall with no registries loaded
// cannot honestly claim to inspect anything, so Hook returns an error
// rather than silently skipping registry validation). A non-nil Policy
// that itself returns a decision depending only on its OWN zero-value
// configuration (e.g. an empty deny-list) is exercised, not bypassed: an
// empty ChannelPolicy denies nothing, by construction of its allow-by-
// default map-membership check, not by a hardcoded bypass.
package firewall
