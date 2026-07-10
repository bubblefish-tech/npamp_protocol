// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// ALPN is the application-layer protocol negotiation identifier for the
// npamp:// fallback transport (TCP + TLS 1.3); it corresponds to wire major
// version 2.
const ALPN = "n-pamp/2"

// maxFrameSize caps a single frame (header + payload) accepted off the wire, so
// a peer cannot force an unbounded allocation with a hostile length field.
const maxFrameSize = 16 << 20 // 16 MiB

// errClosed is returned by the key-derivation gateways (sendState/recvState) once
// the connection's master secret has been wiped by Zeroize/Close, so no frame is
// ever sealed or opened under an all-zero key after teardown. Send/Recv surface it
// wrapped.
var errClosed = errors.New("npamp/sdk: connection is closed")

// Config configures Dial and Listen.
//
// TLSConfig is REQUIRED and governs certificate verification; the SDK pins the
// ALPN identifier and a TLS 1.3 floor but never weakens the verification the
// caller configured. For loopback development a self-signed certificate with
// InsecureSkipVerify is acceptable because the N-PAMP handshake authenticates
// the peer's Ed25519 identity independently of the TLS certificate; production
// callers should verify the certificate, pin ExpectedPeerKey, or both.
type Config struct {
	// TLSConfig carries the certificate(s) and verification settings for the
	// TLS 1.3 transport. Required for both Dial and Listen.
	TLSConfig *tls.Config

	// Identity is the local long-term Ed25519 signing key proven to the peer
	// during the handshake. A fresh ephemeral key is generated when nil.
	Identity ed25519.PrivateKey

	// ExpectedPeerKey, when set, pins the peer's Ed25519 identity: the handshake
	// fails on a mismatch. On the client the check runs BEFORE CLIENT_AUTH is
	// sent, so the client never authenticates to an impostor.
	ExpectedPeerKey ed25519.PublicKey

	// HandshakeTimeout bounds the server-side handshake (TLS + N-PAMP) per
	// connection in Listener.Accept. The deadline starts AFTER a raw connection is
	// accepted, so it bounds only the handshake work — never the idle wait for the
	// next connection (the underlying net.Listener.Accept does not observe a
	// context). This closes the pre-authentication stalled-handshake denial of
	// service in which a peer completes TCP/TLS setup but never finishes the N-PAMP
	// handshake, otherwise pinning the accepting goroutine and socket indefinitely.
	// It bounds each individual handshake but does not by itself provide accept-loop
	// concurrency: Accept blocks on the full per-connection handshake, so a server
	// expecting many concurrent or slow handshakes should run several concurrent
	// Accept goroutines (Accept is safe for concurrent use); the timeout then
	// guarantees no such goroutine is held longer than HandshakeTimeout. Zero means
	// no per-connection handshake deadline (only the caller's Accept context
	// applies). It has no effect on Dial, whose handshake is already bounded by its
	// context.
	HandshakeTimeout time.Duration
}

// Conn is an established, mutually-authenticated N-PAMP session. It is
// full-duplex: one goroutine may Send while another calls Recv. Sends are
// serialized with respect to each other, as are receives. Call Close when done.
type Conn struct {
	raw     net.Conn
	profile npamp.Profile
	master  []byte
	peerID  ed25519.PublicKey

	sendDir npamp.Direction
	recvDir npamp.Direction

	wmu      sync.Mutex
	sendKeys map[npamp.ChannelID]*epochKeys
	rmu      sync.Mutex
	recvKeys map[npamp.ChannelID]*epochKeys

	closeOnce sync.Once

	// closed is set true by Zeroize under wmu+rmu and read by sendState/recvState
	// under wmu/rmu, so no traffic key is derived from the master after it is wiped.
	closed bool
}

// epochKeys is the cached AEAD key material for one (channel, direction) at the
// current key-update epoch, plus the per-epoch sequence counter. Caching the
// derived key/iv (rather than re-deriving per frame) lets KeyUpdate zeroize a
// retired epoch's key material, per spec/06 ("on key update, new-epoch secrets
// are derived afresh and the prior epoch's secrets are zeroized").
//
// Scope of the guarantee: this bounds exposure of a retired epoch's *traffic
// key* — after rotation the old key/iv are wiped and the new epoch's key is an
// independent HKDF output. It does NOT provide forward secrecy against
// compromise of the master secret: per the spec's key schedule the master is
// retained for the connection's lifetime, and DeriveTrafficSecret(master, dir,
// epoch, ...) can reproduce any epoch's key from it. Whole-session forward
// secrecy is a property of the transport's ephemeral (re)handshake, not of a
// per-connection KeyUpdate.
type epochKeys struct {
	epoch uint64
	key   [32]byte
	iv    [12]byte
	seq   uint64
}

// derive computes key/iv for the current epoch from the master secret via the
// per-(direction, epoch, suite, channel) traffic schedule.
func (k *epochKeys) derive(master []byte, dir npamp.Direction, channel npamp.ChannelID, p npamp.Profile) error {
	ts, err := npamp.DeriveTrafficSecret(master, dir, k.epoch, npamp.AEADAES256GCM, channel, p)
	if err != nil {
		return err
	}
	key, iv, err := npamp.DeriveKeyIV(ts, p)
	// The traffic secret is an intermediate from which key+iv are re-derivable;
	// wipe it once extracted so it does not linger on the heap after rotation.
	for i := range ts {
		ts[i] = 0
	}
	if err != nil {
		return err
	}
	k.key, k.iv = key, iv
	return nil
}

// zeroize wipes the current epoch's key and IV in place so a retired epoch's key
// does not linger in this struct after rotation (see the epochKeys doc for the
// scope of the forward-secrecy guarantee).
func (k *epochKeys) zeroize() {
	for i := range k.key {
		k.key[i] = 0
	}
	for i := range k.iv {
		k.iv[i] = 0
	}
}

// advance rotates to the next epoch: zeroize the retired key material, bump the
// epoch, reset the sequence counter (a fresh key restarts the nonce space), and
// derive the new epoch's key/iv.
func (k *epochKeys) advance(master []byte, dir npamp.Direction, channel npamp.ChannelID, p npamp.Profile) error {
	k.zeroize()
	k.epoch++
	k.seq = 0
	return k.derive(master, dir, channel, p)
}

// PeerIdentity returns a copy of the peer's authenticated Ed25519 public key
// (proven by the handshake). A caller can record it for trust-on-first-use
// pinning via Config.ExpectedPeerKey on a later connection.
func (c *Conn) PeerIdentity() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), c.peerID...)
}

// Close tears down the underlying transport and zeroizes the connection's key
// material. It is safe to call more than once; the socket teardown and the wipe
// each run exactly once. The socket is closed FIRST so any Send or Recv blocked in
// I/O unblocks and releases its direction lock, letting the wipe acquire both locks
// without racing an in-flight key derivation from the master secret.
func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = c.raw.Close()
		c.Zeroize()
	})
	return err
}

// Zeroize wipes the connection's master secret and every cached per-epoch traffic
// key from memory, under both direction locks so it cannot race an in-flight
// Send/Recv deriving a key from the master. It is idempotent and safe to call more
// than once (Close calls it). It bounds how long the long-lived master secret —
// from which any epoch's traffic key is derivable — lingers in the process heap
// after a session ends; it does NOT substitute for the transport's ephemeral
// (re)handshake as the source of whole-session forward secrecy. After Zeroize the
// connection can no longer Send or Recv, as derivation from the wiped master would
// no longer be correct.
//
// Lock order: wmu before rmu (the canonical order in this type). No other method
// holds both locks at once — Send/KeyUpdate take wmu alone, Recv takes rmu alone,
// and the KEY_UPDATE ACK is dispatched off the receive path — so Zeroize cannot
// deadlock against them.
func (c *Conn) Zeroize() {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.rmu.Lock()
	defer c.rmu.Unlock()
	c.closed = true
	for i := range c.master {
		c.master[i] = 0
	}
	for _, st := range c.sendKeys {
		st.zeroize()
	}
	for _, st := range c.recvKeys {
		st.zeroize()
	}
}

// Send AEAD-seals payload into one frame on channel with the given application
// frame type and writes it. The per-channel sequence advances within the current
// key-update epoch, so no two frames on a (channel, epoch) reuse an AEAD nonce.
func (c *Conn) Send(ctx context.Context, channel npamp.ChannelID, frameType npamp.FrameType, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.sendLocked(ctx, channel, frameType, payload)
}

// sendLocked seals + writes one frame under the channel's current send epoch key.
// The caller MUST hold wmu.
func (c *Conn) sendLocked(ctx context.Context, channel npamp.ChannelID, frameType npamp.FrameType, payload []byte) error {
	st, err := c.sendState(channel)
	if err != nil {
		return fmt.Errorf("npamp/sdk: derive send key: %w", err)
	}
	// Refuse to send once the epoch's 64-bit sequence space is exhausted: the
	// next seq would wrap to 0 and reuse an AEAD nonce. Callers must KeyUpdate
	// (rotating to a fresh key + reset sequence) first. Practically unreachable
	// at 2^64 frames, but a hard guard against catastrophic nonce reuse.
	if st.seq == ^uint64(0) {
		return fmt.Errorf("npamp/sdk: channel %d epoch %d sequence space exhausted; call KeyUpdate before sending more", channel, st.epoch)
	}
	wire, err := sealWith(st, channel, frameType, payload)
	if err != nil {
		return fmt.Errorf("npamp/sdk: seal frame: %w", err)
	}
	if err := c.writeWire(ctx, wire); err != nil {
		return err
	}
	st.seq++
	return nil
}

// sendState returns the send AEAD state for channel, deriving + caching the
// epoch-0 key on first use. Caller holds wmu.
func (c *Conn) sendState(channel npamp.ChannelID) (*epochKeys, error) {
	if c.closed {
		return nil, errClosed
	}
	st := c.sendKeys[channel]
	if st == nil {
		st = &epochKeys{}
		if err := st.derive(c.master, c.sendDir, channel, c.profile); err != nil {
			return nil, err
		}
		c.sendKeys[channel] = st
	}
	return st, nil
}

// Recv reads, authenticates, and opens the next application frame, returning its
// channel, frame type, and plaintext. Record-layer control frames (KEY_UPDATE /
// KEY_UPDATE_ACK) are processed transparently and never returned to the caller.
// It enforces the per-(channel, epoch) receive sequence, rejecting a replayed or
// reordered frame.
func (c *Conn) Recv(ctx context.Context) (npamp.ChannelID, npamp.FrameType, []byte, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for {
		wire, err := c.readWire(ctx)
		if err != nil {
			return 0, 0, nil, err
		}
		var f npamp.Frame
		if err := f.UnmarshalBinary(wire); err != nil {
			return 0, 0, nil, fmt.Errorf("npamp/sdk: parse frame: %w", err)
		}
		if f.Flags&npamp.FlagENC == 0 {
			return 0, 0, nil, fmt.Errorf("npamp/sdk: frame is not AEAD-encrypted")
		}
		ch := npamp.ChannelID(f.Channel)
		st, err := c.recvState(ch)
		if err != nil {
			return 0, 0, nil, fmt.Errorf("npamp/sdk: derive recv key: %w", err)
		}
		if f.Seq != st.seq {
			return 0, 0, nil, fmt.Errorf("npamp/sdk: channel %d out-of-sequence frame: got seq %d, want %d (epoch %d)", ch, f.Seq, st.seq, st.epoch)
		}
		pt, err := openWith(st, &f)
		if err != nil {
			return 0, 0, nil, fmt.Errorf("npamp/sdk: open frame: %w", err)
		}
		st.seq++

		switch npamp.FrameType(f.Type) {
		case npamp.FrameKeyUpdate:
			if err := c.handleKeyUpdate(ch, st, pt); err != nil {
				return 0, 0, nil, err
			}
			continue // transparent control frame; read the next
		case npamp.FrameKeyUpdateAck:
			continue // confirmation of our own KeyUpdate; nothing to do
		default:
			return ch, npamp.FrameType(f.Type), pt, nil
		}
	}
}

// recvState returns the recv AEAD state for channel, deriving + caching the
// epoch-0 key on first use. Caller holds rmu.
func (c *Conn) recvState(channel npamp.ChannelID) (*epochKeys, error) {
	if c.closed {
		return nil, errClosed
	}
	st := c.recvKeys[channel]
	if st == nil {
		st = &epochKeys{}
		if err := st.derive(c.master, c.recvDir, channel, c.profile); err != nil {
			return nil, err
		}
		c.recvKeys[channel] = st
	}
	return st, nil
}

// --- application record layer (cached epoch key) ---

// sealWith seals plaintext under a cached epoch key. The nonce is st.iv XOR
// st.seq; because (key, iv) are fixed within an epoch and seq advances, no nonce
// repeats within an epoch, and a KeyUpdate restarts the space under a fresh key.
func sealWith(st *epochKeys, channel npamp.ChannelID, ft npamp.FrameType, plaintext []byte) ([]byte, error) {
	f := npamp.Frame{Flags: npamp.FlagENC, Type: uint16(ft), Channel: uint16(channel), Seq: st.seq}
	var aad [21]byte
	f.HeaderPrefix(aad[:], uint32(len(plaintext)+16)) // +16: AES-256-GCM tag
	sealed, err := npamp.SealAES256GCM(st.key, st.iv, st.seq, aad[:], plaintext)
	if err != nil {
		return nil, err
	}
	f.Payload = sealed
	return f.MarshalBinary()
}

// openWith opens a parsed FlagENC frame under a cached epoch key.
func openWith(st *epochKeys, f *npamp.Frame) ([]byte, error) {
	var aad [21]byte
	f.HeaderPrefix(aad[:], uint32(len(f.Payload)))
	return npamp.OpenAES256GCM(st.key, st.iv, f.Seq, aad[:], f.Payload)
}

// --- handshake AUTH-frame sealing (epoch-0, one-shot; used by handshake.go) ---

func deriveKeyIV(baseSecret []byte, dir npamp.Direction, channel npamp.ChannelID, p npamp.Profile) (key [32]byte, iv [12]byte, err error) {
	ts, err := npamp.DeriveTrafficSecret(baseSecret, dir, 0, npamp.AEADAES256GCM, channel, p)
	if err != nil {
		return key, iv, err
	}
	return npamp.DeriveKeyIV(ts, p)
}

// sealFrame AEAD-seals plaintext into a marshaled, self-delimiting frame:
// FlagENC, the caller's channel/type/seq, and AAD = the 21-octet header prefix
// (so the ciphertext is bound to the frame header). Used for the epoch-0
// handshake AUTH frames.
func sealFrame(baseSecret []byte, dir npamp.Direction, channel npamp.ChannelID, seq uint64, ft npamp.FrameType, plaintext []byte, p npamp.Profile) ([]byte, error) {
	key, iv, err := deriveKeyIV(baseSecret, dir, channel, p)
	if err != nil {
		return nil, err
	}
	f := npamp.Frame{Flags: npamp.FlagENC, Type: uint16(ft), Channel: uint16(channel), Seq: seq}
	var aad [21]byte
	f.HeaderPrefix(aad[:], uint32(len(plaintext)+16)) // +16: AES-256-GCM tag
	sealed, err := npamp.SealAES256GCM(key, iv, seq, aad[:], plaintext)
	if err != nil {
		return nil, err
	}
	f.Payload = sealed
	return f.MarshalBinary()
}

// openFrame opens an already-parsed FlagENC frame under the per-(direction,
// channel) epoch-0 traffic key and returns the plaintext.
func openFrame(f *npamp.Frame, baseSecret []byte, dir npamp.Direction, p npamp.Profile) ([]byte, error) {
	key, iv, err := deriveKeyIV(baseSecret, dir, npamp.ChannelID(f.Channel), p)
	if err != nil {
		return nil, err
	}
	var aad [21]byte
	f.HeaderPrefix(aad[:], uint32(len(f.Payload)))
	return npamp.OpenAES256GCM(key, iv, f.Seq, aad[:], f.Payload)
}

// --- stream framing + per-call deadlines over the TLS byte stream ---

func (c *Conn) writeWire(ctx context.Context, wire []byte) error {
	if dl, ok := ctx.Deadline(); ok {
		if err := c.raw.SetWriteDeadline(dl); err != nil {
			return fmt.Errorf("npamp/sdk: set write deadline: %w", err)
		}
		defer func() { _ = c.raw.SetWriteDeadline(time.Time{}) }()
	}
	return writeFrame(c.raw, wire)
}

func (c *Conn) readWire(ctx context.Context) ([]byte, error) {
	if dl, ok := ctx.Deadline(); ok {
		if err := c.raw.SetReadDeadline(dl); err != nil {
			return nil, fmt.Errorf("npamp/sdk: set read deadline: %w", err)
		}
		defer func() { _ = c.raw.SetReadDeadline(time.Time{}) }()
	}
	return readFrame(c.raw)
}

// writeFrame writes a marshaled frame verbatim (N-PAMP frames are
// self-delimiting; no length prefix is added).
func writeFrame(w io.Writer, frame []byte) error {
	if len(frame) < npamp.HeaderSize {
		return fmt.Errorf("npamp/sdk: frame too short (%d < %d)", len(frame), npamp.HeaderSize)
	}
	if len(frame) > maxFrameSize {
		return fmt.Errorf("npamp/sdk: frame size %d exceeds max %d", len(frame), maxFrameSize)
	}
	_, err := w.Write(frame)
	return err
}

// readFrame reads exactly one self-delimiting frame: the fixed 36-octet header,
// then the payload whose length the header advertises (octets 17-20). Header
// integrity (CRC32C, version, reserved octets) is validated by
// npamp.Frame.UnmarshalBinary at the call site; readFrame guarantees only the
// frame boundary, the magic, and the size cap. The payload is read incrementally
// so a peer that advertises a large length it does not deliver cannot force a
// large up-front allocation.
func readFrame(r io.Reader) ([]byte, error) {
	header := make([]byte, npamp.HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err // io.EOF / io.ErrUnexpectedEOF pass through
	}
	if !bytes.Equal(header[:4], npamp.Magic[:]) {
		return nil, fmt.Errorf("npamp/sdk: bad frame magic %#x, want NPAM", header[:4])
	}
	payloadLen := binary.BigEndian.Uint32(header[17:21])
	// int64 so a hostile high-bit length cannot wrap negative and slip past the cap.
	total := int64(npamp.HeaderSize) + int64(payloadLen)
	if total > int64(maxFrameSize) {
		return nil, fmt.Errorf("npamp/sdk: frame size %d exceeds max %d", total, maxFrameSize)
	}
	buf := bytes.NewBuffer(make([]byte, 0, npamp.HeaderSize))
	buf.Write(header)
	if _, err := io.CopyN(buf, r, int64(payloadLen)); err != nil {
		return nil, fmt.Errorf("npamp/sdk: read frame payload (%d octets): %w", payloadLen, err)
	}
	return buf.Bytes(), nil
}

// withNpampTLS clones cfg and pins the ALPN identifier and a TLS 1.3 floor,
// preserving every other setting (notably certificates and verification).
func withNpampTLS(cfg *tls.Config) *tls.Config {
	var c *tls.Config
	if cfg != nil {
		c = cfg.Clone()
	} else {
		c = &tls.Config{}
	}
	c.NextProtos = []string{ALPN}
	if c.MinVersion < tls.VersionTLS13 {
		c.MinVersion = tls.VersionTLS13
	}
	return c
}
