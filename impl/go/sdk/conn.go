// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// ALPN is the application-layer protocol negotiation identifier for the
// npamp:// fallback transport (TCP + TLS 1.3); it corresponds to wire major
// version 2.
const ALPN = "n-pamp/3"

// maxFrameSize caps a single frame (header + payload) accepted off the wire, so
// a peer cannot force an unbounded allocation with a hostile length field. It is
// npamp.MaxFrameSize so the SDK and the base parser (frame.go) enforce the SAME cap
// (R12; no uncoordinated divergence).
const maxFrameSize = npamp.MaxFrameSize // 16 MiB

// errClosed is returned by the key-derivation gateways (sendState/recvState) once
// the connection's master secret has been wiped by Zeroize/Close, so no frame is
// ever sealed or opened under an all-zero key after teardown. Send/Recv surface it
// wrapped.
var errClosed = errors.New("npamp/sdk: connection is closed")

// ErrPeerClosed is returned by Recv when the peer performed a graceful, authenticated
// CLOSE (draft {#... CLOSE Frame}): the endpoint has replied CLOSE_ACK and reached the
// terminal CLOSED state (its keys are zeroized), so this is a clean end-of-association,
// NOT a fault. Callers (and CloseGraceful) test for it with errors.Is to distinguish an
// orderly teardown from a transport error or a protocol violation. It wraps io.EOF so
// existing loops that stop on io.EOF still terminate.
var ErrPeerClosed = fmt.Errorf("npamp/sdk: peer closed the association: %w", io.EOF)

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
	// during the handshake when the negotiated profile is Standard. A fresh
	// ephemeral key is generated when nil AND the offered/accepted profile set
	// includes Standard (the zero-value, single-profile behavior is unchanged).
	Identity ed25519.PrivateKey

	// MLDSAIdentity is the local long-term ML-DSA-87 (FIPS 204, post-quantum;
	// IANA TLS SignatureScheme 0x0906) signing key proven to the peer when the
	// negotiated profile is High or Sovereign (spec/05_profiles.md §"Profile
	// invariants" — High and Sovereign both require ML-DSA-87; core
	// npamp.SignCertVerifyMLDSA87 / VerifyCertVerifyMLDSA87). Nil by default:
	// an endpoint that never sets it can only ever offer or accept the
	// Standard profile, exactly today's behavior. Construct one with
	// mldsa.GenerateKey(mldsa.MLDSA87()) or
	// mldsa.NewPrivateKey(mldsa.MLDSA87(), seed). Offering or accepting High
	// or Sovereign (via Profiles) with MLDSAIdentity nil is a Config error:
	// Dial, Listen.Accept, DialConn, AcceptConn, DialRaw, and AcceptRaw all
	// return it before any wire I/O.
	//
	// Residual (tracked, not a silent gap): spec/05_profiles.md's Profile
	// invariants table sets the High/Sovereign minimum KEM to
	// SecP384r1MLKEM1024 (kem1024.go), but the core package's exported
	// combiner (npamp.HandshakeSecret) accepts only the X25519MLKEM768
	// SharedSecrets type — there is no exported way to combine a
	// SharedSecrets1024 into a handshake secret today. This SDK therefore
	// negotiates X25519MLKEM768 for every profile (matching every other
	// reference driver in this tree, including cmd/npamp-interop); a High or
	// Sovereign session here diversifies CertVerify (ML-DSA-87) and the KDF
	// hash (SHA-384, automatic via the negotiated Profile) but not the KEM
	// group. Closing this gap requires extending the core package's exported
	// API and is out of this SDK build's scope.
	MLDSAIdentity *mldsa.PrivateKey

	// Profiles is the ordered set of N-PAMP security profiles (spec/05_profiles.md)
	// this endpoint offers (client, via Dial/DialConn/DialRaw) or is willing to
	// select from (server, via Listen/AcceptConn/AcceptRaw). The zero value
	// (nil or empty) is exactly []npamp.Profile{npamp.ProfileStandard} — the
	// BYTE-FOR-BYTE same ClientHello/ServerHello a pre-multi-profile caller
	// produced, so an existing caller's wire behavior is unchanged. On the
	// server, the FIRST entry of Profiles that also appears in the client's
	// ProfileOffer is selected (Profiles is therefore the server's preference
	// order, strongest-first if configured that way); if no entry matches, the
	// handshake is refused. Offering or accepting npamp.ProfileHigh or
	// npamp.ProfileSovereign requires MLDSAIdentity to be set.
	Profiles []npamp.Profile

	// ExpectedPeerKey, when set, pins the peer's identity — the raw public-key
	// encoding for the NEGOTIATED profile's signature scheme (an Ed25519
	// public key at Standard, an ML-DSA-87 public-key encoding at High or
	// Sovereign, per npamp.SignCertVerifyMLDSA87's TLV 0x09 IdentityKey) — and
	// the handshake fails on a mismatch. On the client the check runs BEFORE
	// CLIENT_AUTH is sent, so the client never authenticates to an impostor.
	// The field keeps its Ed25519-typed name and type for backward
	// compatibility; ed25519.PublicKey is itself a []byte and accepts an
	// ML-DSA-87 encoding unchanged.
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
	// masterSend / masterRecv are the two per-direction connection ROOTS of the
	// Hybrid Tree Ratchet (spec/10 section 9). Both are seeded from a copy of the
	// handshake master at generation 0 (so gen-0 keys are byte-identical to the
	// pre-ratchet schedule), and each advances INDEPENDENTLY as its direction
	// ratchets. masterSend is the root for the direction this endpoint sends (==
	// the peer's masterRecv); masterRecv is the root for the direction it receives.
	// genSend / genRecv are the generation indices of the two roots, starting 0.
	// They are atomic so Conn.ReKEM can read the receive generation lock-free when
	// choosing a Tier-2 target — an app Recv-loop holds rmu for the entire blocking
	// Recv, so ReKEM (which holds wmu) must never take rmu. Each is WRITTEN under
	// its direction's lock (wmu for genSend, rmu for genRecv) together with the
	// matching root swap, so a same-direction reader sees a consistent root/gen pair.
	masterSend []byte
	masterRecv []byte
	genSend    atomic.Uint64
	genRecv    atomic.Uint64
	// peerID is the peer's authenticated identity-key encoding for the
	// NEGOTIATED profile: an Ed25519 public key (32 octets) at Standard, or an
	// ML-DSA-87 public-key encoding (2592 octets, mldsa.MLDSA87PublicKeySize)
	// at High or Sovereign. []byte rather than ed25519.PublicKey because the
	// two schemes are different sizes; PeerIdentity() below returns it typed
	// ed25519.PublicKey for backward compatibility (ed25519.PublicKey is
	// itself a []byte, so this is a widening, not a truncation).
	peerID []byte

	sendDir npamp.Direction
	recvDir npamp.Direction

	wmu      sync.Mutex
	sendKeys map[npamp.ChannelID]*epochKeys
	rmu      sync.Mutex
	recvKeys map[npamp.ChannelID]*epochKeys

	// pmu is the leaf lock for this endpoint's PENDING-CONTROL-CORRELATION state: the
	// send-initiated control exchanges awaiting the peer's acknowledgement. Every field it
	// guards is WRITTEN by a send-side method (which holds wmu) and READ/CONSUMED by the
	// receive path (which holds rmu), so it has its own lock to avoid coupling the two
	// direction locks. Canonical order is wmu->pmu and rmu->pmu (pmu never nests either).
	//
	//   - pendingReKEM: the initiator-side state of an in-flight Tier-2 re-KEM (the ephemeral
	//     KEM client + the generation it will heal), set by ReKEM, consumed by the REKEM_ACK
	//     handler.
	//   - pendingKUAck: per-channel set of KEY_UPDATE epochs this endpoint announced and whose
	//     KEY_UPDATE_ACK it has not yet seen. A KEY_UPDATE_ACK matching an entry is SOLICITED
	//     (consumed, SILENT); one with no entry is UNSOLICITED and is the total default
	//     (unexpected_message), mirroring the unsolicited-CLOSE_ACK rejection.
	//   - pendingMRAck: conn-scope (Control-only) set of MASTER_RATCHET generations awaiting a
	//     MASTER_RATCHET_ACK, with the same solicited/unsolicited semantics.
	//
	// Both ACK sets are grown ONLY by this endpoint's own KeyUpdate/RatchetSend calls (a peer
	// cannot inflate them), so no bound is needed; they hold no key material, so no wipe is
	// owed (they are cleared at Zeroize only to free the maps).
	pmu          sync.Mutex
	pendingReKEM *pendingReKEM
	pendingKUAck map[npamp.ChannelID]map[uint64]int
	pendingMRAck map[uint64]struct{}

	// droppedUnauthenticated / droppedOutOfSequence count frames the receive loop DROPPED
	// without tearing the association down — the draft's discard posture: an unauthenticated
	// (cleartext or AEAD-open-failed) or out-of-sequence frame is dropped and counted, and the
	// connection SURVIVES, so an off-path injection cannot end the association (the same
	// resilience DTLS 1.3 RFC 9147 §4.5.2 and QUIC RFC 9001 §6.6.2 give the record/packet layer).
	// Atomic: incremented under rmu by recvLocked, read lock-free by SecurityDrops.
	droppedUnauthenticated atomic.Uint64
	droppedOutOfSequence   atomic.Uint64

	// cmu guards the CLOSING-state pending-close handshake used by CloseGraceful: closing is
	// true while this endpoint has sent a CLOSE (Authenticated Close) and is awaiting the
	// peer's CLOSE_ACK, and closeAckCh is closed by the receive path (signalCloseAck) when
	// that CLOSE_ACK arrives. It has its own lock so the closer's wait touches neither
	// direction lock: CloseGraceful sends the CLOSE under wmu, then waits on closeAckCh,
	// which the Recv loop (rmu) signals.
	cmu        sync.Mutex
	closing    bool
	closeAckCh chan struct{}

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

// PeerIdentity returns a copy of the peer's authenticated identity-key
// encoding (proven by the handshake), typed ed25519.PublicKey for backward
// compatibility. At the Standard profile this IS a genuine Ed25519 public
// key. At High or Sovereign it is instead the raw ML-DSA-87 public-key
// encoding (2592 octets) — NOT a valid Ed25519 key; call Profile() first to
// tell them apart, or use PeerMLDSAIdentity for a typed accessor. A caller
// can record either encoding for trust-on-first-use pinning via
// Config.ExpectedPeerKey on a later connection.
func (c *Conn) PeerIdentity() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), c.peerID...)
}

// PeerMLDSAIdentity returns the peer's authenticated ML-DSA-87 public key
// when this session negotiated the High or Sovereign profile, or nil at
// Standard (use PeerIdentity there instead). The error is non-nil only if the
// recorded peer identity bytes do not decode as an ML-DSA-87 public key,
// which cannot happen for a Conn produced by this package's own handshake
// (VerifyCertVerifyMLDSA87 already validated it) but is checked rather than
// ignored so a hand-built Conn cannot silently return a corrupt key.
func (c *Conn) PeerMLDSAIdentity() (*mldsa.PublicKey, error) {
	if c.profile == npamp.ProfileStandard {
		return nil, nil
	}
	return mldsa.NewPublicKey(mldsa.MLDSA87(), c.peerID)
}

// Profile returns the security profile (spec/05_profiles.md) this session
// negotiated during the handshake.
func (c *Conn) Profile() npamp.Profile {
	return c.profile
}

// SecurityDrops reports the cumulative counts of frames this endpoint DROPPED without tearing
// the association down, per the draft's discard posture: an unauthenticated frame (cleartext, or
// one whose AEAD tag failed) and an out-of-sequence frame are dropped and counted, and the
// connection survives — so an off-path injection cannot end the association. An operator SHOULD
// surface these as security events: a rising unauthenticated count on an otherwise-quiet
// connection indicates injection or tampering attempts. The counts are monotonic and read
// lock-free.
func (c *Conn) SecurityDrops() (unauthenticated, outOfSequence uint64) {
	return c.droppedUnauthenticated.Load(), c.droppedOutOfSequence.Load()
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
	// Wipe BOTH per-direction ratchet roots (Step 8 of the HTR build map): after
	// teardown neither root — from which any generation's traffic key is derivable
	// — lingers in the heap.
	wipeRoot(c.masterSend)
	wipeRoot(c.masterRecv)
	for _, st := range c.sendKeys {
		st.zeroize()
	}
	for _, st := range c.recvKeys {
		st.zeroize()
	}
	// Wipe any in-flight Tier-2 ephemeral KEM material so a pending re-KEM's
	// private keys do not outlive the connection, and drop the pending-ACK sets
	// (no secrets — freed only so a closed Conn holds no dangling maps).
	c.pmu.Lock()
	if c.pendingReKEM != nil {
		c.pendingReKEM.zeroize()
		c.pendingReKEM = nil
	}
	c.pendingKUAck = nil
	c.pendingMRAck = nil
	c.pmu.Unlock()
}

// wipeRoot zeroizes a ratchet root (or any secret byte slice) in place. It is the
// factored-out form of the Zeroize wipe loop, reused between ratchet steps (not
// only at Close) so a retired root is erased the moment its successor is derived —
// mirroring the derive-next -> zeroize-old-in-place -> replace discipline. Best
// effort: Go's GC may have copied the bytes earlier (see the epochKeys.zeroize
// caveat), so the one-wayness guarantee is only as strong as this in-place wipe.
func wipeRoot(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// dropSendKeys zeroizes and forgets every cached send-direction epoch key so that
// after a root advance every channel lazily re-derives off the NEW root at leaf
// epoch 0 (the MLS-epoch "fresh tree per generation"). Caller holds wmu.
func (c *Conn) dropSendKeys() {
	for ch, st := range c.sendKeys {
		st.zeroize()
		delete(c.sendKeys, ch)
	}
}

// dropRecvKeys is dropSendKeys for the receive direction. Caller holds rmu.
func (c *Conn) dropRecvKeys() {
	for ch, st := range c.recvKeys {
		st.zeroize()
		delete(c.recvKeys, ch)
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
		if err := st.derive(c.masterSend, c.sendDir, channel, c.profile); err != nil {
			return nil, err
		}
		c.sendKeys[channel] = st
	}
	return st, nil
}

// recvActionKind names what Recv must do AFTER it releases rmu.
type recvActionKind int

const (
	actDeliver   recvActionKind = iota // return (ch, ft, pt, err) to the caller unchanged
	actEmitError                       // POST-KEY total default: seal+send ERROR(code) on Control, tear down, return err
	actCloseAck                        // peer CLOSE: seal+send CLOSE_ACK, tear down (CLOSED), return ErrPeerClosed
	actPeerError                       // peer ERROR (advisory): tear down, send NO reply, return err (a *npamp.SessionError)
)

// recvAction is what Recv must do after releasing rmu: deliver a frame, or perform a
// control-frame REACTION that seals on the send direction. Those reactions need wmu, and
// running them while rmu is held would invert the canonical wmu->rmu order and deadlock
// against Zeroize — so recvLocked returns the intent and Recv performs it post-rmu.
type recvAction struct {
	kind recvActionKind
	code npamp.SessionErrorCode // for actEmitError
	err  error                  // the error Recv returns for this action
}

// Recv reads, authenticates, and opens the next application frame, returning its
// channel, frame type, and plaintext. Record-layer control frames (KEY_UPDATE /
// KEY_UPDATE_ACK, and the master-ratchet / re-KEM frames) are processed transparently and
// never returned to the caller. It enforces the per-(channel, epoch) receive sequence,
// rejecting a replayed or reordered frame. On the Control channel it enforces the state
// machine's total default: a frame with no legal transition in ESTABLISHED — a
// handshake-flight frame, an unknown type, or a payload-bearing CLOSE — is answered with a
// sealed ERROR carrying `unexpected_message` and the connection is torn down; a well-formed
// CLOSE is answered with CLOSE_ACK and Recv returns ErrPeerClosed; a peer ERROR is surfaced
// as a *npamp.SessionError (advisory — no reply).
func (c *Conn) Recv(ctx context.Context) (npamp.ChannelID, npamp.FrameType, []byte, error) {
	c.rmu.Lock()
	ch, ft, pt, act := c.recvLocked(ctx)
	c.rmu.Unlock()
	// Any control-frame reaction that seals on the send direction runs HERE, after rmu is
	// released, so taking wmu cannot invert the canonical wmu->rmu order and deadlock
	// against Zeroize (which takes wmu then rmu). recvLocked itself never takes wmu.
	switch act.kind {
	case actEmitError:
		c.sendSessionError(act.code) // seal + send the ERROR before teardown (best-effort)
		_ = c.Close()
		return 0, 0, nil, act.err
	case actCloseAck:
		c.sendCloseAck() // seal + send CLOSE_ACK, then reach CLOSED (Close zeroizes)
		_ = c.Close()
		return 0, 0, nil, ErrPeerClosed
	case actPeerError:
		_ = c.Close() // advisory: surface + close, send NO reply (no error loop)
		return 0, 0, nil, act.err
	default: // actDeliver
		return ch, ft, pt, act.err
	}
}

// recvLocked runs the receive loop under rmu (held by Recv) and returns either a frame to
// deliver or a recvAction describing a control-frame reaction Recv must perform after it
// releases rmu. It NEVER takes wmu — every ACK / ERROR / CLOSE_ACK send is deferred to the
// post-rmu switch in Recv — so no goroutine nests wmu inside rmu.
func (c *Conn) recvLocked(ctx context.Context) (npamp.ChannelID, npamp.FrameType, []byte, recvAction) {
	for {
		wire, err := c.readWire(ctx)
		if err != nil {
			return 0, 0, nil, recvAction{kind: actDeliver, err: err}
		}
		var f npamp.Frame
		if err := f.UnmarshalBinary(wire); err != nil {
			return 0, 0, nil, recvAction{kind: actDeliver, err: fmt.Errorf("npamp/sdk: parse frame: %w", err)}
		}
		if f.Flags&npamp.FlagENC == 0 {
			// An unauthenticated (cleartext) frame in a keyed session cannot drive a security
			// decision (draft: MUST NOT act on unauthenticated input). It is DROPPED and counted
			// and the association SURVIVES — the receive loop reads the next frame — so an off-path
			// injection can neither tear the connection down (a fatal ERROR would let it) NOR end it
			// by surfacing an error to the caller. This is the record-layer resilience DTLS 1.3
			// (RFC 9147 §4.5.2, "invalid records SHOULD be silently discarded, thus preserving the
			// association") and QUIC (RFC 9001 §6.6.2) give. Dropped BEFORE recvState: no traffic
			// key is derived from attacker-chosen input.
			c.droppedUnauthenticated.Add(1)
			continue
		}
		ch := npamp.ChannelID(f.Channel)
		st, err := c.recvState(ch)
		if err != nil {
			return 0, 0, nil, recvAction{kind: actDeliver, err: fmt.Errorf("npamp/sdk: derive recv key: %w", err)}
		}
		if f.Seq != st.seq {
			// A replayed (sequence below the expected value) or reordered frame is DROPPED and
			// counted; the association survives and st.seq is unchanged, so the next in-sequence
			// frame still opens. It is dropped BEFORE openWith — no AEAD work on a wrong-sequence
			// frame — and a replayed frame carries a valid old tag, so surfacing an error here would
			// let one replayed capture end the session (the exact replay DoS the discard posture
			// prevents). A sequence AHEAD of the expected value cannot arise from a conformant peer
			// over the in-order transports this document specifies (TCP+TLS, QUIC per-stream) and is
			// treated as the same drop. Replay is modeled OUT of the abstract state machine (a
			// sequence-number property; the replay KAT covers it).
			c.droppedOutOfSequence.Add(1)
			continue
		}
		pt, err := openWith(st, &f)
		if err != nil {
			// AEAD open failed: the frame is FlagENC but its tag does not verify — a forged or
			// corrupted sealed frame, i.e. unauthenticated input. DROP and count; the association
			// survives and st.seq is NOT advanced, so a subsequent legitimate frame at this sequence
			// still opens. Same posture as the cleartext case (RFC 9147 §4.5.2 / RFC 9001 §6.6.2):
			// an off-path attacker who flips a ciphertext octet cannot end the association.
			c.droppedUnauthenticated.Add(1)
			continue
		}
		st.seq++

		switch npamp.FrameType(f.Type) {
		case npamp.FrameKeyUpdate:
			if err := c.handleKeyUpdate(ch, st, pt); err != nil {
				// A malformed or out-of-order KeyUpdateMarker is fatal key_update_out_of_order
				// (draft row 9): seal the ERROR and tear down. Any other failure (e.g. a local
				// key-derivation error) is a plain drop surfaced to the caller.
				if errors.Is(err, errKeyUpdateOutOfOrder) {
					return 0, 0, nil, recvAction{kind: actEmitError, code: npamp.ErrCodeKeyUpdateOutOfOrder, err: err}
				}
				return 0, 0, nil, recvAction{kind: actDeliver, err: err}
			}
			continue // transparent control frame; read the next
		case npamp.FrameKeyUpdateAck:
			// A KEY_UPDATE_ACK is legal only if this endpoint SOLICITED it by sending the
			// matching KEY_UPDATE (correlated per (channel, epoch)). A solicited one is consumed
			// and the receive path stays SILENT; an unsolicited (well-formed) one is the state
			// machine's total default (unexpected_message), mirroring the unsolicited-CLOSE_ACK
			// rejection below. A malformed marker is fatal key_update_out_of_order (draft row 9) —
			// the same code as a malformed KEY_UPDATE marker, since it is the same TLV on either
			// frame.
			epoch, err := parseKeyUpdateMarker(pt)
			if err != nil {
				return 0, 0, nil, recvAction{kind: actEmitError, code: npamp.ErrCodeKeyUpdateOutOfOrder,
					err: fmt.Errorf("npamp/sdk: KEY_UPDATE_ACK on channel %d marker: %w (%v)", ch, errKeyUpdateOutOfOrder, err)}
			}
			if c.consumePendingKeyUpdateAck(ch, epoch) {
				continue // solicited confirmation of our own KeyUpdate; SILENT
			}
			return 0, 0, nil, recvAction{kind: actEmitError, code: npamp.ErrCodeUnexpectedMessage,
				err: fmt.Errorf("npamp/sdk: unsolicited KEY_UPDATE_ACK on channel %d (epoch %d)", ch, epoch)}
		case frameMasterRatchet:
			// Master-ratchet control frames are Control-channel-specific; the same
			// numeric value on another channel belongs to that channel's namespace and
			// is returned to the caller unchanged.
			if ch != npamp.ChanControl {
				return ch, npamp.FrameType(f.Type), pt, recvAction{kind: actDeliver}
			}
			if err := c.handleMasterRatchet(ch, pt); err != nil {
				return 0, 0, nil, recvAction{kind: actDeliver, err: err}
			}
			continue
		case frameMasterRatchetAck:
			if ch != npamp.ChanControl {
				return ch, npamp.FrameType(f.Type), pt, recvAction{kind: actDeliver}
			}
			// Legal only if this endpoint SOLICITED it via RatchetSend (correlated per
			// generation); a solicited one is consumed (SILENT), an unsolicited one is the total
			// default (unexpected_message), like KEY_UPDATE_ACK / CLOSE_ACK. A malformed marker
			// is a plain error (drop), not a fatal ERROR.
			gen, err := parseRatchetGenMarker(pt)
			if err != nil {
				return 0, 0, nil, recvAction{kind: actDeliver, err: fmt.Errorf("npamp/sdk: MASTER_RATCHET_ACK: %w", err)}
			}
			if c.consumePendingRatchetAck(gen) {
				continue // solicited confirmation of our own Tier-1 step; SILENT
			}
			return 0, 0, nil, recvAction{kind: actEmitError, code: npamp.ErrCodeUnexpectedMessage,
				err: fmt.Errorf("npamp/sdk: unsolicited MASTER_RATCHET_ACK (gen %d)", gen)}
		case frameReKEM:
			if ch != npamp.ChanControl {
				return ch, npamp.FrameType(f.Type), pt, recvAction{kind: actDeliver}
			}
			if err := c.handleReKEM(ch, pt); err != nil {
				return 0, 0, nil, recvAction{kind: actDeliver, err: err}
			}
			continue
		case frameReKEMAck:
			if ch != npamp.ChanControl {
				return ch, npamp.FrameType(f.Type), pt, recvAction{kind: actDeliver}
			}
			if err := c.handleReKEMAck(pt); err != nil {
				// An UNSOLICITED REKEM_ACK (no outstanding re-KEM) is the total default
				// (unexpected_message), uniform with unsolicited KEY_UPDATE_ACK / MASTER_RATCHET_ACK
				// / CLOSE_ACK. A SOLICITED-but-invalid ack (wrong generation or a decapsulation
				// failure) is a different class and stays a fail-closed plain drop.
				if errors.Is(err, errUnsolicitedReKEMAck) {
					return 0, 0, nil, recvAction{kind: actEmitError, code: npamp.ErrCodeUnexpectedMessage, err: err}
				}
				return 0, 0, nil, recvAction{kind: actDeliver, err: err}
			}
			continue
		case npamp.FrameClose:
			// Authenticated CLOSE (Control-only): because the receive stream is drained in
			// sequence order, every in-flight frame ahead of the CLOSE has already been
			// processed, so the reaction is CLOSE_ACK then CLOSED. A CLOSE carrying a payload
			// is rejected with unexpected_message (draft: CLOSE/CLOSE_ACK carry no payload).
			// On a non-Control channel 0x0003 belongs to that channel's namespace (delivered).
			if ch != npamp.ChanControl {
				return ch, npamp.FrameType(f.Type), pt, recvAction{kind: actDeliver}
			}
			if len(pt) != 0 {
				return 0, 0, nil, recvAction{kind: actEmitError, code: npamp.ErrCodeUnexpectedMessage,
					err: fmt.Errorf("npamp/sdk: CLOSE carried a %d-octet payload", len(pt))}
			}
			return 0, 0, nil, recvAction{kind: actCloseAck}
		case npamp.FrameCloseAck:
			if ch != npamp.ChanControl {
				return ch, npamp.FrameType(f.Type), pt, recvAction{kind: actDeliver}
			}
			// A CLOSE_ACK is legal only while this endpoint is CLOSING (it sent a CLOSE via
			// CloseGraceful); it then signals the closer and reaches CLOSED. Unsolicited, it
			// is the total default.
			if c.signalCloseAck() {
				return 0, 0, nil, recvAction{kind: actDeliver, err: ErrPeerClosed}
			}
			return 0, 0, nil, recvAction{kind: actEmitError, code: npamp.ErrCodeUnexpectedMessage,
				err: fmt.Errorf("npamp/sdk: unsolicited CLOSE_ACK")}
		case npamp.FrameError:
			// A RECEIVED ERROR is advisory (draft {#error-handling}): the receiver surfaces
			// the peer's reason and closes, and sends NO reply (no error loop). A malformed
			// ERROR body is not acted on as an ERROR — it is surfaced as a plain parse error.
			if ch != npamp.ChanControl {
				return ch, npamp.FrameType(f.Type), pt, recvAction{kind: actDeliver}
			}
			code, ectx, derr := npamp.DecodeErrorBody(pt)
			if derr != nil {
				return 0, 0, nil, recvAction{kind: actDeliver, err: fmt.Errorf("npamp/sdk: malformed ERROR frame from peer: %w", derr)}
			}
			return 0, 0, nil, recvAction{kind: actPeerError, err: &npamp.SessionError{Code: code, Context: ectx}}
		default:
			if ch == npamp.ChanControl {
				// The Control channel is the system channel: no application frame is delivered
				// on it, so a type not handled above — a handshake-flight frame after
				// establishment, or an unknown/unexpected type — is the total default.
				return 0, 0, nil, recvAction{kind: actEmitError, code: npamp.ErrCodeUnexpectedMessage,
					err: fmt.Errorf("npamp/sdk: unexpected frame type 0x%04x on Control in ESTABLISHED", f.Type)}
			}
			return ch, npamp.FrameType(f.Type), pt, recvAction{kind: actDeliver}
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
		if err := st.derive(c.masterRecv, c.recvDir, channel, c.profile); err != nil {
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
