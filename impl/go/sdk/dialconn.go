// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// DialConn runs the client side of an N-PAMP session over a CALLER-SUPPLIED
// net.Conn instead of opening its own TCP socket. It is the connection-injecting
// counterpart to Dial: use it when the transport already exists — an accepted
// socket, a pipe, or a stream tunneled inside another (already-established)
// N-PAMP session (the Phantom Relay inner tunnel is the motivating case).
//
// The security posture is IDENTICAL to Dial. DialConn wraps raw in a TLS 1.3
// client with the same pinned ALPN ("n-pamp/2") and TLS 1.3 floor that Dial
// applies (via withNpampTLS), enforces the ALPN check (requireALPN), and drives
// the SAME 1.5-RTT mutually-authenticated handshake (runClientHandshake) that
// Dial uses, ending in a Conn built by the SAME newConn with the same
// per-direction roles. cfg.ExpectedPeerKey is honored identically: the pin is
// checked inside runClientHandshake BEFORE CLIENT_AUTH is sent, so the client
// never authenticates to an impostor. The resulting Conn has the same ephemeral
// hybrid-KEM (X25519MLKEM768) master, the same AES-256-GCM record layer, and the
// same channel/framing behavior as a Dial session — a DialConn client and a
// Listen server (or a Dial client and an AcceptConn server) interoperate on the
// wire byte-for-byte.
//
// cfg.HandshakeTimeout, when > 0, bounds the whole per-connection handshake — the
// TLS handshake AND the N-PAMP handshake — layered on top of ctx (whichever
// deadline is sooner wins). Because DialConn cannot rely on a dialer's
// context-bounded DialContext to bound TLS setup (the caller supplied the
// socket), arming HandshakeTimeout here closes the same stalled-peer denial of
// service that Config.HandshakeTimeout closes on the server's Accept: a peer that
// never completes the TLS or N-PAMP handshake is dropped after HandshakeTimeout
// rather than pinning this goroutine indefinitely. A zero HandshakeTimeout leaves
// only ctx to bound the handshake.
//
// Connection ownership: on success the returned Conn owns raw — Conn.Close closes
// it. On error DialConn does NOT close raw (it did not open it); the caller
// retains ownership and should Close raw itself. DialConn never opens a socket of
// its own. Config.TLSConfig is required.
func DialConn(ctx context.Context, raw net.Conn, cfg Config) (*Conn, error) {
	if cfg.TLSConfig == nil {
		return nil, fmt.Errorf("npamp/sdk: Config.TLSConfig is required")
	}
	if raw == nil {
		return nil, fmt.Errorf("npamp/sdk: DialConn requires a non-nil net.Conn")
	}
	priv, pub, err := identity(cfg.Identity)
	if err != nil {
		return nil, err
	}
	// Bound the handshake (TLS + N-PAMP) under HandshakeTimeout, layered on ctx —
	// mirroring Listener.Accept. On a caller-supplied socket there is no
	// dialer-DialContext to bound TLS setup, so this is what closes the stalled-peer
	// DoS on the client side.
	hctx := ctx
	if cfg.HandshakeTimeout > 0 {
		var cancel context.CancelFunc
		hctx, cancel = context.WithTimeout(ctx, cfg.HandshakeTimeout)
		defer cancel()
	}
	// Wrap the caller's conn in a TLS client using the SAME config Dial uses:
	// withNpampTLS pins ALPN "n-pamp/2" and a TLS 1.3 floor while preserving the
	// caller's certificates and verification settings. tls.Client is lazy, so force
	// the handshake under hctx here — Dial gets this from tls.Dialer.DialContext.
	tc := tls.Client(raw, withNpampTLS(cfg.TLSConfig))
	if err := tc.HandshakeContext(hctx); err != nil {
		return nil, fmt.Errorf("npamp/sdk: TLS handshake: %w", err)
	}
	if err := requireALPN(tc); err != nil {
		return nil, err
	}
	master, peerID, err := runClientHandshake(hctx, tc, priv, pub, cfg.ExpectedPeerKey)
	if err != nil {
		return nil, err
	}
	return newConn(tc, master, peerID, npamp.DirClientToServer, npamp.DirServerToClient), nil
}

// AcceptConn runs the server side of an N-PAMP session over a CALLER-SUPPLIED
// net.Conn instead of accepting from its own listener. It is the
// connection-injecting counterpart to Listener.Accept, and the server mirror of
// DialConn: use it when the server already holds the raw transport (an accepted
// socket handed in from elsewhere, a pipe, or a tunneled inner stream).
//
// The security posture is IDENTICAL to Listener.Accept. AcceptConn wraps raw in a
// TLS 1.3 server with the same pinned ALPN and TLS 1.3 floor (withNpampTLS),
// forces the TLS handshake under the handshake deadline, enforces the ALPN check
// (requireALPN), and drives the SAME 1.5-RTT mutually-authenticated handshake
// (runServerHandshake) that Accept uses, ending in a Conn built by the SAME
// newConn with the same per-direction roles. cfg.ExpectedPeerKey pins the CLIENT
// identity exactly as on Accept (the pin is checked inside runServerHandshake).
// cfg.HandshakeTimeout, when > 0, bounds the TLS + N-PAMP handshake layered on ctx
// — closing the pre-authentication stalled-handshake DoS identically to Accept.
//
// Connection ownership: on success the returned Conn owns raw — Conn.Close closes
// it. On error AcceptConn does NOT close raw; the caller retains ownership.
// AcceptConn never opens a socket of its own. Config.TLSConfig is required.
func AcceptConn(ctx context.Context, raw net.Conn, cfg Config) (*Conn, error) {
	if cfg.TLSConfig == nil {
		return nil, fmt.Errorf("npamp/sdk: Config.TLSConfig is required")
	}
	if raw == nil {
		return nil, fmt.Errorf("npamp/sdk: AcceptConn requires a non-nil net.Conn")
	}
	priv, pub, err := identity(cfg.Identity)
	if err != nil {
		return nil, err
	}
	// Bound the handshake (TLS + N-PAMP) under HandshakeTimeout, layered on ctx —
	// identical to Listener.Accept.
	hctx := ctx
	if cfg.HandshakeTimeout > 0 {
		var cancel context.CancelFunc
		hctx, cancel = context.WithTimeout(ctx, cfg.HandshakeTimeout)
		defer cancel()
	}
	// Wrap the caller's conn in a TLS server. tls.Listen wraps each accepted conn
	// with tls.Server under the listener's config; here we do the same per-conn wrap
	// explicitly with the SAME withNpampTLS config, then force the handshake under
	// hctx so ALPN is populated before the requireALPN check (as Accept does).
	tc := tls.Server(raw, withNpampTLS(cfg.TLSConfig))
	if err := tc.HandshakeContext(hctx); err != nil {
		return nil, fmt.Errorf("npamp/sdk: TLS handshake: %w", err)
	}
	if err := requireALPN(tc); err != nil {
		return nil, err
	}
	master, peerID, err := runServerHandshake(hctx, tc, priv, pub, cfg.ExpectedPeerKey)
	if err != nil {
		return nil, err
	}
	return newConn(tc, master, peerID, npamp.DirServerToClient, npamp.DirClientToServer), nil
}
