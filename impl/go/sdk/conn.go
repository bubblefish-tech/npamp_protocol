// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/binary"
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

	wmu     sync.Mutex
	sendSeq map[npamp.ChannelID]uint64
	rmu     sync.Mutex
	recvSeq map[npamp.ChannelID]uint64

	closeOnce sync.Once
}

// PeerIdentity returns a copy of the peer's authenticated Ed25519 public key
// (proven by the handshake). A caller can record it for trust-on-first-use
// pinning via Config.ExpectedPeerKey on a later connection.
func (c *Conn) PeerIdentity() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), c.peerID...)
}

// Close tears down the underlying transport. It is safe to call more than once.
func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() { err = c.raw.Close() })
	return err
}

// Send AEAD-seals payload into one frame on channel with the given application
// frame type and writes it. The per-channel send sequence advances so no two
// frames on a channel reuse an AEAD nonce.
func (c *Conn) Send(ctx context.Context, channel npamp.ChannelID, frameType npamp.FrameType, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	seq := c.sendSeq[channel]
	wire, err := sealFrame(c.master, c.sendDir, channel, seq, frameType, payload, c.profile)
	if err != nil {
		return fmt.Errorf("npamp/sdk: seal frame: %w", err)
	}
	if err := c.writeWire(ctx, wire); err != nil {
		return err
	}
	c.sendSeq[channel] = seq + 1
	return nil
}

// Recv reads, authenticates, and opens the next frame, returning its channel,
// application frame type, and plaintext. It enforces the per-channel receive
// sequence, rejecting a replayed or reordered frame.
func (c *Conn) Recv(ctx context.Context) (npamp.ChannelID, npamp.FrameType, []byte, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	wire, err := c.readWire(ctx)
	if err != nil {
		return 0, 0, nil, err
	}
	var f npamp.Frame
	if err := f.UnmarshalBinary(wire); err != nil {
		return 0, 0, nil, fmt.Errorf("npamp/sdk: parse frame: %w", err)
	}
	if f.Flags&npamp.FlagENC == 0 {
		return 0, 0, nil, fmt.Errorf("npamp/sdk: application frame is not AEAD-encrypted")
	}
	ch := npamp.ChannelID(f.Channel)
	want := c.recvSeq[ch]
	if f.Seq != want {
		return 0, 0, nil, fmt.Errorf("npamp/sdk: channel %d out-of-sequence frame: got seq %d, want %d", ch, f.Seq, want)
	}
	pt, err := openFrame(&f, c.master, c.recvDir, c.profile)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("npamp/sdk: open frame: %w", err)
	}
	c.recvSeq[ch] = want + 1
	return ch, npamp.FrameType(f.Type), pt, nil
}

// --- record-layer sealing, shared by the handshake AUTH frames and Send/Recv ---

func deriveKeyIV(baseSecret []byte, dir npamp.Direction, channel npamp.ChannelID, p npamp.Profile) (key [32]byte, iv [12]byte, err error) {
	ts, err := npamp.DeriveTrafficSecret(baseSecret, dir, 0, npamp.AEADAES256GCM, channel, p)
	if err != nil {
		return key, iv, err
	}
	return npamp.DeriveKeyIV(ts, p)
}

// sealFrame AEAD-seals plaintext into a marshaled, self-delimiting frame:
// FlagENC, the caller's channel/type/seq, and AAD = the 21-octet header prefix
// (so the ciphertext is bound to the frame header).
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
// channel) traffic key and returns the plaintext.
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
// frame boundary, the magic, and the size cap. The payload is read
// incrementally so a peer that advertises a large length it does not deliver
// cannot force a large up-front allocation.
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
