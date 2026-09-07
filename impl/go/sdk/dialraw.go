// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"context"
	"fmt"
	"net"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// DialRaw runs the client side of an N-PAMP session directly over a CALLER-SUPPLIED
// net.Conn, WITHOUT wrapping it in TLS. It is the TLS-free counterpart to DialConn: use
// it when the transport is in-process (a net.Pipe), a conformance / state-learning
// harness, or a stream whose confidentiality is ALREADY provided by an outer layer (a
// tunnel inside an established N-PAMP session, or a caller-managed TLS conn).
//
// Authentication is UNCHANGED from Dial / DialConn: the 1.5-RTT handshake
// (runClientHandshake) proves the peer's Ed25519 identity, binds the transcript with
// CertVerify + Finished, and derives the post-quantum hybrid-KEM master independently of
// any transport encryption. cfg.ExpectedPeerKey is honored identically — the pin is
// checked BEFORE CLIENT_AUTH is sent, so the client never authenticates to an impostor.
//
// What DialRaw does NOT provide, relative to Dial, is transport-layer CONFIDENTIALITY of
// the handshake: the cleartext CLIENT_HELLO / SERVER_HELLO (offered profiles, algorithms,
// KEM share) are exposed to an on-path observer, and none of the transports this document
// specifies (TCP + TLS 1.3, QUIC) — nor the transport-provided anti-amplification address
// validation those transports supply — apply. DialRaw MUST NOT be used over an untrusted
// network without an outer confidentiality layer; over any transport that is not
// in-process, pin cfg.ExpectedPeerKey.
//
// cfg.HandshakeTimeout, when > 0, bounds the N-PAMP handshake layered on ctx. cfg.TLSConfig
// is NOT required and is ignored. Connection ownership matches DialConn: on success the
// returned Conn owns raw (Conn.Close closes it); on error DialRaw does not close raw (it
// did not open it).
func DialRaw(ctx context.Context, raw net.Conn, cfg Config) (*Conn, error) {
	if raw == nil {
		return nil, fmt.Errorf("npamp/sdk: DialRaw requires a non-nil net.Conn")
	}
	id, err := resolveIdentity(cfg)
	if err != nil {
		return nil, err
	}
	hctx := ctx
	if cfg.HandshakeTimeout > 0 {
		var cancel context.CancelFunc
		hctx, cancel = context.WithTimeout(ctx, cfg.HandshakeTimeout)
		defer cancel()
	}
	master, peerID, profile, err := runClientHandshake(hctx, raw, id, cfg.ExpectedPeerKey)
	if err != nil {
		return nil, err
	}
	conn := newConn(raw, master, peerID, npamp.DirClientToServer, npamp.DirServerToClient)
	conn.profile = profile
	return conn, nil
}

// AcceptRaw runs the server side of an N-PAMP session directly over a CALLER-SUPPLIED
// net.Conn, WITHOUT TLS — the server mirror of DialRaw and the TLS-free counterpart to
// AcceptConn. The same security posture and caveats as DialRaw apply: authentication is
// unchanged (runServerHandshake proves the client's Ed25519 identity; cfg.ExpectedPeerKey
// pins it, checked inside the handshake), but the handshake is not transport-encrypted,
// so AcceptRaw is for in-process pipes, conformance harnesses, or transports that already
// provide confidentiality.
//
// cfg.HandshakeTimeout bounds the N-PAMP handshake on ctx. cfg.TLSConfig is not required.
// Connection ownership matches AcceptConn.
func AcceptRaw(ctx context.Context, raw net.Conn, cfg Config) (*Conn, error) {
	if raw == nil {
		return nil, fmt.Errorf("npamp/sdk: AcceptRaw requires a non-nil net.Conn")
	}
	id, err := resolveIdentity(cfg)
	if err != nil {
		return nil, err
	}
	hctx := ctx
	if cfg.HandshakeTimeout > 0 {
		var cancel context.CancelFunc
		hctx, cancel = context.WithTimeout(ctx, cfg.HandshakeTimeout)
		defer cancel()
	}
	master, peerID, profile, err := runServerHandshake(hctx, raw, id, cfg.ExpectedPeerKey)
	if err != nil {
		return nil, err
	}
	conn := newConn(raw, master, peerID, npamp.DirServerToClient, npamp.DirClientToServer)
	conn.profile = profile
	return conn, nil
}
