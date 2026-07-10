// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"net"
	"slices"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// sdkProfile is the single security profile this SDK offers and selects.
var sdkProfile = npamp.ProfileStandard

// Dial establishes an N-PAMP session to addr ("host:port") over TCP + TLS 1.3,
// completes the 1.5-RTT mutually-authenticated handshake, and returns the
// established Conn. The caller MUST Close the returned Conn.
func Dial(ctx context.Context, addr string, cfg Config) (*Conn, error) {
	if cfg.TLSConfig == nil {
		return nil, fmt.Errorf("npamp/sdk: Config.TLSConfig is required")
	}
	priv, pub, err := identity(cfg.Identity)
	if err != nil {
		return nil, err
	}
	d := &tls.Dialer{Config: withNpampTLS(cfg.TLSConfig)}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("npamp/sdk: dial %s: %w", addr, err)
	}
	if err := requireALPN(raw); err != nil {
		_ = raw.Close()
		return nil, err
	}
	master, peerID, err := runClientHandshake(ctx, raw, priv, pub, cfg.ExpectedPeerKey)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return newConn(raw, master, peerID, npamp.DirClientToServer, npamp.DirServerToClient), nil
}

// Listener accepts N-PAMP connections. Create one with Listen and Close it when
// done.
type Listener struct {
	ln  net.Listener
	cfg Config
}

// Listen starts a TCP + TLS 1.3 listener on addr negotiating ALPN "n-pamp/2".
func Listen(addr string, cfg Config) (*Listener, error) {
	if cfg.TLSConfig == nil {
		return nil, fmt.Errorf("npamp/sdk: Config.TLSConfig is required")
	}
	ln, err := tls.Listen("tcp", addr, withNpampTLS(cfg.TLSConfig))
	if err != nil {
		return nil, fmt.Errorf("npamp/sdk: listen %s: %w", addr, err)
	}
	return &Listener{ln: ln, cfg: cfg}, nil
}

// Addr returns the listener's network address (useful with a ":0" port).
func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// Close stops the listener.
func (l *Listener) Close() error { return l.ln.Close() }

// Accept waits for the next connection, completes the TLS and N-PAMP handshakes
// under ctx, and returns the established Conn. The caller MUST Close the
// returned Conn. Accept is safe to call from multiple goroutines.
func (l *Listener) Accept(ctx context.Context) (*Conn, error) {
	raw, err := l.ln.Accept()
	if err != nil {
		return nil, fmt.Errorf("npamp/sdk: accept: %w", err)
	}
	priv, pub, err := identity(l.cfg.Identity)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	// Bound the handshake (TLS + N-PAMP) per connection, starting AFTER the raw
	// accept — so the deadline covers only the handshake work, not the idle wait for
	// a connection (l.ln.Accept does not observe ctx). This closes the pre-auth
	// stalled-handshake DoS: a peer that completes TCP/TLS but never finishes the
	// N-PAMP handshake is dropped after HandshakeTimeout instead of pinning this
	// goroutine and socket. A zero HandshakeTimeout leaves only the caller's ctx.
	hctx := ctx
	if l.cfg.HandshakeTimeout > 0 {
		var cancel context.CancelFunc
		hctx, cancel = context.WithTimeout(ctx, l.cfg.HandshakeTimeout)
		defer cancel()
	}
	// Force the TLS handshake here, in the per-connection path, so ALPN is
	// populated and a slow client cannot stall the accept loop.
	if tc, ok := raw.(*tls.Conn); ok {
		if err := tc.HandshakeContext(hctx); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("npamp/sdk: TLS handshake: %w", err)
		}
	}
	if err := requireALPN(raw); err != nil {
		_ = raw.Close()
		return nil, err
	}
	master, peerID, err := runServerHandshake(hctx, raw, priv, pub, l.cfg.ExpectedPeerKey)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return newConn(raw, master, peerID, npamp.DirServerToClient, npamp.DirClientToServer), nil
}

func newConn(raw net.Conn, master []byte, peerID ed25519.PublicKey, sendDir, recvDir npamp.Direction) *Conn {
	return &Conn{
		raw:     raw,
		profile: sdkProfile,
		master:  master,
		peerID:  append(ed25519.PublicKey(nil), peerID...),
		sendDir: sendDir,
		recvDir: recvDir,
		sendKeys: make(map[npamp.ChannelID]*epochKeys),
		recvKeys: make(map[npamp.ChannelID]*epochKeys),
	}
}

func identity(priv ed25519.PrivateKey) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if priv == nil {
		pub, p, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("npamp/sdk: generate identity: %w", err)
		}
		return p, pub, nil
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("npamp/sdk: Config.Identity is not a valid Ed25519 key")
	}
	return priv, pub, nil
}

func requireALPN(raw net.Conn) error {
	tc, ok := raw.(*tls.Conn)
	if !ok {
		return fmt.Errorf("npamp/sdk: connection is not TLS")
	}
	if got := tc.ConnectionState().NegotiatedProtocol; got != ALPN {
		return fmt.Errorf("npamp/sdk: negotiated ALPN %q, want %q", got, ALPN)
	}
	return nil
}

// runClientHandshake drives the client's side of the 1.5-RTT draft-01 handshake
// (spec/10) over raw, returning the master secret and the peer's authenticated
// identity. The transcript/key-schedule steps mirror the reference flow in
// impl/go's TestHandshakeFlowStandard, which is pinned to the published KATs.
func runClientHandshake(ctx context.Context, raw net.Conn, priv ed25519.PrivateKey, pub ed25519.PublicKey, expectedPeer ed25519.PublicKey) (master []byte, peerID ed25519.PublicKey, err error) {
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
		defer func() { _ = raw.SetDeadline(time.Time{}) }()
	}
	p := sdkProfile

	kem, err := npamp.GenerateKEMClient()
	if err != nil {
		return nil, nil, fmt.Errorf("npamp/sdk: KEM keygen: %w", err)
	}
	ch := &npamp.ClientHello{
		ProfileOffer: []npamp.Profile{p},
		KEMOffer:     []npamp.KEMID{npamp.KEMX25519MLKEM768},
		SigOffer:     []npamp.SigID{npamp.SigEd25519},
		AEADOffer:    []npamp.AEADID{npamp.AEADAES256GCM},
		KEMShare:     kem.KEMShare(),
	}
	t := npamp.NewTranscript(p)
	if err := sendCleartext(raw, npamp.FrameClientHello, ch.Encode()); err != nil {
		return nil, nil, fmt.Errorf("npamp/sdk: send CLIENT_HELLO: %w", err)
	}
	t.AddFrame(npamp.FrameClientHello, ch.TLVs())

	shPayload, err := recvCleartext(raw, npamp.FrameServerHello)
	if err != nil {
		return nil, nil, fmt.Errorf("npamp/sdk: recv SERVER_HELLO: %w", err)
	}
	sh, err := npamp.DecodeServerHello(shPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("npamp/sdk: decode SERVER_HELLO: %w", err)
	}
	if err := requireSelections(sh); err != nil {
		return nil, nil, err
	}
	t.AddFrame(npamp.FrameServerHello, sh.TLVs())

	ss, err := kem.SharedSecrets(sh.KEMCiphertext)
	if err != nil {
		return nil, nil, fmt.Errorf("npamp/sdk: KEM decapsulate: %w", err)
	}
	hs, err := npamp.HandshakeSecret(ss, p)
	if err != nil {
		return nil, nil, err
	}
	cHS, sHS, err := npamp.DeriveHandshakeTrafficSecrets(hs, t.Sum(), p) // TH_kem
	if err != nil {
		return nil, nil, err
	}

	// --- SERVER_AUTH (AEAD-sealed under the server handshake key) ---
	saWire, err := readFrame(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("npamp/sdk: recv SERVER_AUTH: %w", err)
	}
	sAuth, err := openAuthFrame(saWire, npamp.FrameServerAuth, sHS, npamp.DirServerToClient, p)
	if err != nil {
		return nil, nil, fmt.Errorf("npamp/sdk: open SERVER_AUTH: %w", err)
	}
	t.AddFrameType(npamp.FrameServerAuth)
	t.AddTLV(npamp.TLV{Type: npamp.TLVIdentityKey, Value: sAuth.IdentityKey})
	if err := npamp.VerifyCertVerify(sAuth.IdentityKey, npamp.RoleServer, t.Sum(), sAuth.CertVerify); err != nil {
		return nil, nil, fmt.Errorf("npamp/sdk: server CertVerify: %w", err)
	}
	t.AddTLV(npamp.TLV{Type: npamp.TLVCertVerify, Value: sAuth.CertVerify})
	sFinKey, err := npamp.DeriveFinishedKey(sHS, p)
	if err != nil {
		return nil, nil, err
	}
	if err := npamp.VerifyFinished(sFinKey, t.Sum(), sAuth.Finished, p); err != nil {
		return nil, nil, fmt.Errorf("npamp/sdk: server Finished: %w", err)
	}
	t.AddTLV(npamp.TLV{Type: npamp.TLVFinished, Value: sAuth.Finished})
	peerID = append(ed25519.PublicKey(nil), sAuth.IdentityKey...)

	// Pinned-key check BEFORE CLIENT_AUTH: never authenticate to an impostor.
	if expectedPeer != nil && subtle.ConstantTimeCompare(peerID, expectedPeer) != 1 {
		return nil, nil, fmt.Errorf("npamp/sdk: server identity does not match the pinned key")
	}

	// --- CLIENT_AUTH (AEAD-sealed under the client handshake key) ---
	t.AddFrameType(npamp.FrameClientAuth)
	t.AddTLV(npamp.TLV{Type: npamp.TLVIdentityKey, Value: pub})
	cCV, err := npamp.SignCertVerify(priv, npamp.RoleClient, t.Sum()) // TH_cId
	if err != nil {
		return nil, nil, err
	}
	t.AddTLV(npamp.TLV{Type: npamp.TLVCertVerify, Value: cCV})
	thCCV := t.Sum()
	cFinKey, err := npamp.DeriveFinishedKey(cHS, p)
	if err != nil {
		return nil, nil, err
	}
	cFin := npamp.ComputeFinished(cFinKey, thCCV, p)
	auth := &npamp.AuthMessage{IdentityKey: pub, CertVerify: cCV, Finished: cFin}
	caWire, err := sealFrame(cHS, npamp.DirClientToServer, npamp.ChanControl, 0, npamp.FrameClientAuth, auth.Encode(), p)
	if err != nil {
		return nil, nil, err
	}
	if err := writeFrame(raw, caWire); err != nil {
		return nil, nil, fmt.Errorf("npamp/sdk: send CLIENT_AUTH: %w", err)
	}

	master, err = npamp.DeriveMasterSecret(hs, thCCV, p)
	if err != nil {
		return nil, nil, err
	}
	return master, peerID, nil
}

// runServerHandshake drives the server's side of the 1.5-RTT draft-01 handshake
// over raw, returning the master secret and the peer's authenticated identity.
func runServerHandshake(ctx context.Context, raw net.Conn, priv ed25519.PrivateKey, pub ed25519.PublicKey, expectedPeer ed25519.PublicKey) (master []byte, peerID ed25519.PublicKey, err error) {
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
		defer func() { _ = raw.SetDeadline(time.Time{}) }()
	}
	p := sdkProfile
	t := npamp.NewTranscript(p)

	chPayload, err := recvCleartext(raw, npamp.FrameClientHello)
	if err != nil {
		return nil, nil, fmt.Errorf("npamp/sdk: recv CLIENT_HELLO: %w", err)
	}
	ch, err := npamp.DecodeClientHello(chPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("npamp/sdk: decode CLIENT_HELLO: %w", err)
	}
	if err := requireOffers(ch); err != nil {
		return nil, nil, err
	}
	t.AddFrame(npamp.FrameClientHello, ch.TLVs())

	kemCT, ss, err := npamp.Encapsulate(ch.KEMShare)
	if err != nil {
		return nil, nil, fmt.Errorf("npamp/sdk: KEM encapsulate: %w", err)
	}
	sh := &npamp.ServerHello{
		ProfileSelect: npamp.ProfileStandard,
		KEMSelect:     npamp.KEMX25519MLKEM768,
		SigSelect:     npamp.SigEd25519,
		AEADSelect:    npamp.AEADAES256GCM,
		KEMCiphertext: kemCT,
	}
	if err := sendCleartext(raw, npamp.FrameServerHello, sh.Encode()); err != nil {
		return nil, nil, fmt.Errorf("npamp/sdk: send SERVER_HELLO: %w", err)
	}
	t.AddFrame(npamp.FrameServerHello, sh.TLVs())

	hs, err := npamp.HandshakeSecret(ss, p)
	if err != nil {
		return nil, nil, err
	}
	cHS, sHS, err := npamp.DeriveHandshakeTrafficSecrets(hs, t.Sum(), p) // TH_kem
	if err != nil {
		return nil, nil, err
	}

	// --- SERVER_AUTH ---
	t.AddFrameType(npamp.FrameServerAuth)
	t.AddTLV(npamp.TLV{Type: npamp.TLVIdentityKey, Value: pub})
	sCV, err := npamp.SignCertVerify(priv, npamp.RoleServer, t.Sum()) // TH_sId
	if err != nil {
		return nil, nil, err
	}
	t.AddTLV(npamp.TLV{Type: npamp.TLVCertVerify, Value: sCV})
	sFinKey, err := npamp.DeriveFinishedKey(sHS, p)
	if err != nil {
		return nil, nil, err
	}
	sFin := npamp.ComputeFinished(sFinKey, t.Sum(), p) // TH_sCV
	t.AddTLV(npamp.TLV{Type: npamp.TLVFinished, Value: sFin})
	auth := &npamp.AuthMessage{IdentityKey: pub, CertVerify: sCV, Finished: sFin}
	saWire, err := sealFrame(sHS, npamp.DirServerToClient, npamp.ChanControl, 0, npamp.FrameServerAuth, auth.Encode(), p)
	if err != nil {
		return nil, nil, err
	}
	if err := writeFrame(raw, saWire); err != nil {
		return nil, nil, fmt.Errorf("npamp/sdk: send SERVER_AUTH: %w", err)
	}

	// --- CLIENT_AUTH ---
	caWire, err := readFrame(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("npamp/sdk: recv CLIENT_AUTH: %w", err)
	}
	cAuth, err := openAuthFrame(caWire, npamp.FrameClientAuth, cHS, npamp.DirClientToServer, p)
	if err != nil {
		return nil, nil, fmt.Errorf("npamp/sdk: open CLIENT_AUTH: %w", err)
	}
	t.AddFrameType(npamp.FrameClientAuth)
	t.AddTLV(npamp.TLV{Type: npamp.TLVIdentityKey, Value: cAuth.IdentityKey})
	if err := npamp.VerifyCertVerify(cAuth.IdentityKey, npamp.RoleClient, t.Sum(), cAuth.CertVerify); err != nil {
		return nil, nil, fmt.Errorf("npamp/sdk: client CertVerify: %w", err)
	}
	t.AddTLV(npamp.TLV{Type: npamp.TLVCertVerify, Value: cAuth.CertVerify})
	thCCV := t.Sum()
	cFinKey, err := npamp.DeriveFinishedKey(cHS, p)
	if err != nil {
		return nil, nil, err
	}
	if err := npamp.VerifyFinished(cFinKey, thCCV, cAuth.Finished, p); err != nil {
		return nil, nil, fmt.Errorf("npamp/sdk: client Finished: %w", err)
	}
	peerID = append(ed25519.PublicKey(nil), cAuth.IdentityKey...)
	if expectedPeer != nil && subtle.ConstantTimeCompare(peerID, expectedPeer) != 1 {
		return nil, nil, fmt.Errorf("npamp/sdk: client identity does not match the pinned key")
	}

	master, err = npamp.DeriveMasterSecret(hs, thCCV, p)
	if err != nil {
		return nil, nil, err
	}
	return master, peerID, nil
}

// sendCleartext writes a cleartext handshake HELLO frame (Control channel,
// seq 0, no FlagENC) carrying payload.
func sendCleartext(raw net.Conn, ft npamp.FrameType, payload []byte) error {
	f := npamp.Frame{Type: uint16(ft), Channel: uint16(npamp.ChanControl), Seq: 0, Payload: payload}
	wire, err := f.MarshalBinary()
	if err != nil {
		return err
	}
	return writeFrame(raw, wire)
}

// recvCleartext reads one cleartext HELLO frame, checks its type, and returns
// its payload.
func recvCleartext(raw net.Conn, want npamp.FrameType) ([]byte, error) {
	wire, err := readFrame(raw)
	if err != nil {
		return nil, err
	}
	var f npamp.Frame
	if err := f.UnmarshalBinary(wire); err != nil {
		return nil, err
	}
	if f.Type != uint16(want) {
		return nil, fmt.Errorf("npamp/sdk: got frame type 0x%04x, want 0x%04x", f.Type, uint16(want))
	}
	if f.Flags&npamp.FlagENC != 0 {
		return nil, fmt.Errorf("npamp/sdk: handshake hello frame unexpectedly encrypted")
	}
	return f.Payload, nil
}

// openAuthFrame parses, type-checks, and AEAD-opens an AUTH frame into its
// AuthMessage.
func openAuthFrame(wire []byte, want npamp.FrameType, baseSecret []byte, dir npamp.Direction, p npamp.Profile) (*npamp.AuthMessage, error) {
	var f npamp.Frame
	if err := f.UnmarshalBinary(wire); err != nil {
		return nil, err
	}
	if f.Type != uint16(want) {
		return nil, fmt.Errorf("npamp/sdk: got frame type 0x%04x, want 0x%04x", f.Type, uint16(want))
	}
	if f.Flags&npamp.FlagENC == 0 {
		return nil, fmt.Errorf("npamp/sdk: AUTH frame is not AEAD-encrypted")
	}
	pt, err := openFrame(&f, baseSecret, dir, p)
	if err != nil {
		return nil, err
	}
	return npamp.DecodeAuthMessage(pt)
}

func requireSelections(sh *npamp.ServerHello) error {
	switch {
	case sh.ProfileSelect != npamp.ProfileStandard:
		return fmt.Errorf("npamp/sdk: server selected unsupported profile 0x%02x (SDK is Standard-only)", uint8(sh.ProfileSelect))
	case sh.KEMSelect != npamp.KEMX25519MLKEM768:
		return fmt.Errorf("npamp/sdk: server selected unsupported KEM 0x%04x", uint16(sh.KEMSelect))
	case sh.SigSelect != npamp.SigEd25519:
		return fmt.Errorf("npamp/sdk: server selected unsupported signature 0x%04x", uint16(sh.SigSelect))
	case sh.AEADSelect != npamp.AEADAES256GCM:
		return fmt.Errorf("npamp/sdk: server selected unsupported AEAD 0x%04x", uint16(sh.AEADSelect))
	}
	return nil
}

func requireOffers(ch *npamp.ClientHello) error {
	switch {
	case !slices.Contains(ch.ProfileOffer, npamp.ProfileStandard):
		return fmt.Errorf("npamp/sdk: client did not offer the Standard profile")
	case !slices.Contains(ch.KEMOffer, npamp.KEMX25519MLKEM768):
		return fmt.Errorf("npamp/sdk: client did not offer X25519MLKEM768")
	case !slices.Contains(ch.SigOffer, npamp.SigEd25519):
		return fmt.Errorf("npamp/sdk: client did not offer Ed25519")
	case !slices.Contains(ch.AEADOffer, npamp.AEADAES256GCM):
		return fmt.Errorf("npamp/sdk: client did not offer AES-256-GCM")
	}
	return nil
}
