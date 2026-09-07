// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package relay implements a frame-delimiting, non-decrypting N-PAMP
// forwarder (task E2.1, requirements R1.1/R1.2/DES-10): a bidirectional
// intermediary that routes an N-PAMP session between two agents without
// terminating the cryptographic session between them.
//
// # What the relay is
//
// A Relay owns exactly two net.Conn legs, A and B, and copies each
// self-delimiting N-PAMP frame (the 36-octet fixed header of frame.go plus
// the payload the header's Payload Length field declares) from one leg to
// the other, in both directions, preserving frame boundaries and order. It
// is FRAME-AWARE: it parses each cleartext header far enough to know where
// the frame ends and to report the header's routing metadata (frame type,
// channel, sequence number, flags, payload length) to an optional
// inspection hook. It is NOT a protocol endpoint: it never derives an AEAD
// key, never opens a FlagENC payload, and never re-encodes a payload it
// forwards — every octet after the header is copied through verbatim.
//
// # Why this preserves end-to-end security
//
// The two agents run the SAME 1.5-RTT mutually-authenticated handshake
// (impl/go/sdk) THROUGH the relay: CLIENT_HELLO / SERVER_HELLO / SERVER_AUTH
// / CLIENT_AUTH all transit the relay as opaque framed records, and the
// resulting master secret — and every traffic key derived from it — is
// known only to the two agents, never to the relay. A relay that instead
// terminated each leg's cryptography and re-encrypted onward (a classic
// TLS-terminating proxy) would defeat the mutual authentication the
// handshake provides; this one deliberately does not, so the two agents
// authenticate EACH OTHER, not the relay.
//
// # The firewall seam (E2.2)
//
// Relay.Hook is the seam a later policy layer (E2.2, a frame-inspecting
// firewall) plugs into: it runs once per relayed frame, after the header is
// parsed and validated but before the frame is forwarded, and sees only the
// cleartext FrameHeader — never the payload bytes, encrypted or otherwise.
// Returning a non-nil error rejects the frame and tears the flow down (see
// Fail-closed below). This package implements only the seam and its default
// pass-through (a nil Hook forwards every well-formed frame); it carries no
// policy of its own.
//
// # Per-flow state ownership (DES-10)
//
// The N-PAMP protocol itself does not require an intermediary to hold any
// per-session state — a conformant relay could in principle be a dumb byte
// pipe. This Relay chooses to hold per-flow ROUTING state (which net.Conn is
// "A" and which is "B", the negotiated max frame size, the optional Hook)
// for the lifetime of one forwarded flow, because a relay that positions
// itself between two agents is legitimately in the business of routing
// decisions. That state is scoped to a single Relay value / a single flow;
// nothing here accumulates cross-flow state or requires the protocol's
// cooperation to exist.
//
// # Fail-closed and bounded (R12)
//
// A malformed frame (bad magic, a header CRC32C mismatch, an unsupported
// wire version, a nonzero reserved octet or reserved flag bit — see
// npamp.Frame.UnmarshalBinary), an oversized declared payload length, or a
// truncated stream all end the SAME way: Relay.Run closes BOTH legs and
// returns, tearing down that flow as a unit. The relay never forwards a
// frame it could not fully validate, never allocates space for a payload
// beyond MaxFrameSize (npamp.MaxFrameSize by default, matching the base
// parser's own cap so the two never diverge), and never blocks forwarding
// indefinitely on a hostile peer that advertises a length it does not
// deliver — a partial header or payload is read with io.ReadFull semantics,
// so a stalled peer surfaces io.ErrUnexpectedEOF rather than hanging the
// goroutine forever.
package relay
