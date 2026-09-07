// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
	sdk "github.com/bubblefish-tech/npamp_protocol/impl/go/sdk"
)

// responderDriverSendDir/responderDriverRecvDir are the cryptographic directions the driver
// uses when it plays the INITIATOR (client) side against a RESPONDER (server) SUT.
const (
	responderDriverSendDir = npamp.DirClientToServer
	responderDriverRecvDir = npamp.DirServerToClient
)

// placeholderSecret stands in for cHS/sHS before the driver has ever completed a real
// CLIENT_HELLO/SERVER_HELLO round-trip with the SUT (unlike initiator-testing, a responder
// SUT sends nothing until it validly receives CLIENT_HELLO, so the driver has no real KEM
// material to derive from yet). It is used only to seal handshake-phase deviant frames
// while the SUT is still at LISTEN, where the SUT's own recvCleartext type-checks BEFORE
// ever inspecting FlagENC/ciphertext — so the observed reaction never depends on this value
// being cryptographically real (see wire.go / initiator.go doc for the same argument on the
// initiator side, where it does not arise because a real CH is always available at reset).
var placeholderSecret = make([]byte, 32)

// acceptResult is what the background sdk.AcceptRaw goroutine reports once the SUT's real
// server-side handshake call returns (success or failure).
type acceptResult struct {
	conn *sdk.Conn
	err  error
}

// responderScenario drives the N-PAMP SDK's RESPONDER (server) role as the SUT via the real
// sdk.AcceptRaw over an in-process net.Pipe (no TCP, no TLS, no listener). The driver plays
// the initiator (client) side by HAND on its own pipe end — never sdk.DialRaw, which would
// run the SDK's OWN client-side handshake instead of the driver's scripted one.
type responderScenario struct {
	conn    net.Conn // driver's pipe end for the CURRENT episode (the scripted-client side)
	sutPipe net.Conn // the SUT's pipe end; retained so teardown can close it to unblock an
	// AcceptRaw still mid-handshake (AcceptRaw does not close raw on error, and sutConn is
	// nil until the handshake resolves, so nothing else would).

	// epCtx/epCancel bound EVERY goroutine spawned for the current episode (the background
	// AcceptRaw, and any CloseGraceful). teardown cancels epCtx FIRST (waking a CloseGraceful
	// parked in its ctx-select), then closes both pipe ends (io.ErrClosedPipe wakes an
	// AcceptRaw blocked in a pipe read/write), then wg.Wait()s. Using epCtx (not a fixed 5 s
	// ioTimeout) as the AcceptRaw context is load-bearing for LearnLib determinism — see the
	// initiator's field doc.
	epCtx    context.Context
	epCancel context.CancelFunc
	wg       sync.WaitGroup

	acceptCh       chan acceptResult
	acceptResolved bool
	acceptErr      error
	sutConn        *sdk.Conn

	established bool
	closing     bool // CloseGraceful already triggered this episode (see stepInitClose)
	closed      bool

	// The driver's own valid CLIENT_HELLO material — real KEM material, so it can complete
	// a genuine handshake and reach ESTABLISHED. Built once per RESET (no network I/O).
	kem *npamp.KEMClient
	ch  *npamp.ClientHello

	// Populated lazily, the FIRST time a real SH_SA round-trip is observed (the driver has
	// no way to derive these before that: it does not know the SUT's real KEMCiphertext).
	hs          []byte
	cHS, sHS    []byte
	caPlaintext []byte // valid CLIENT_AUTH AuthMessage encoding, once cHS/sHS are known

	// pendingMaster is the master secret independently derived from the driver's cached
	// CLIENT_AUTH plaintext (thCCV), ready BEFORE that CLIENT_AUTH is ever actually applied
	// as an input. The responder's (WAIT_CA, CLIENT_AUTH) -> ESTABLISHED transition emits no
	// wire frame (output SILENT), so — unlike the initiator side, which observes the SUT's
	// real CLIENT_AUTH arriving on the wire — this harness has no wire signal to react to;
	// it instead notices ESTABLISHED by polling sdk.AcceptRaw's completion (see
	// maybeEstablish) and promotes pendingMaster to master at that point.
	pendingMaster []byte
	master        []byte // populated once ESTABLISHED

	ctrlOut chanState
	appOut  chanState
}

func newResponderScenario() *responderScenario {
	return &responderScenario{}
}

// teardown ends the current episode leak-free — same ordered discipline as the initiator's:
// cancel epCtx (wake a CloseGraceful parked in its ctx-select), close BOTH raw pipe ends
// (io.ErrClosedPipe wakes an AcceptRaw or driver read blocked in the pipe), then wg.Wait().
// sutPipe.Close() covers AcceptRaw having errored (it does not close raw) or not yet resolved.
func (s *responderScenario) teardown() {
	if s.epCancel != nil {
		s.epCancel()
	}
	if s.sutConn != nil {
		_ = s.sutConn.Close()
	}
	if s.sutPipe != nil {
		_ = s.sutPipe.Close()
	}
	if s.conn != nil {
		_ = s.conn.Close()
	}
	s.wg.Wait()
	s.epCtx, s.epCancel = nil, nil
	s.sutConn = nil
	s.sutPipe = nil
	s.conn = nil
}

func (s *responderScenario) closeScenario() {
	s.teardown()
}

// reset tears down any prior episode and starts a fresh sdk.AcceptRaw() — landing the SUT
// at LISTEN (it has read nothing yet; unlike the initiator, the responder never sends an
// opening flight). It also builds the driver's own valid CLIENT_HELLO material so the
// "CLIENT_HELLO" symbol can legitimately drive the SUT to WAIT_CA whenever applied.
func (s *responderScenario) reset() error {
	s.teardown()

	s.acceptResolved = false
	s.acceptErr = nil
	s.established = false
	s.closing = false
	s.closed = false
	s.hs, s.cHS, s.sHS, s.caPlaintext = nil, nil, nil, nil
	s.pendingMaster = nil
	s.master = nil
	s.ctrlOut = chanState{}
	s.appOut = chanState{}

	// A fresh, single-use in-process pipe per episode: pipeSUT runs the real sdk.AcceptRaw
	// (the SUT's server handshake), pipeDriver is the scripted-client side this driver drives
	// by hand. net.Pipe is unbuffered — every driver write is paired with a concurrent SUT
	// read. epCtx bounds the AcceptRaw goroutine; teardown cancels it and closes the pipe.
	s.epCtx, s.epCancel = context.WithCancel(context.Background())
	pipeSUT, pipeDriver := net.Pipe()
	s.sutPipe = pipeSUT
	s.conn = pipeDriver

	// acceptCh is a LOCAL captured by the goroutine, with s.acceptCh assigned only AFTER the
	// spawn — see initiator.go's reset() for the full rationale: a straggler AcceptRaw from a
	// prior episode must never write into the new episode's channel and make the SUL
	// non-deterministic (teardown's wg.Wait already joined it; this is belt-and-suspenders).
	// The goroutine runs the SUT's real server handshake over pipeSUT under epCtx — NOT a
	// fixed wall-clock, for LearnLib determinism (advisor). AcceptRaw ignores TLSConfig, so
	// only Identity is set.
	acceptCh := make(chan acceptResult, 1)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		conn, err := sdk.AcceptRaw(s.epCtx, pipeSUT, sdk.Config{Identity: sutPriv})
		acceptCh <- acceptResult{conn: conn, err: err}
	}()
	s.acceptCh = acceptCh

	kem, err := npamp.GenerateKEMClient()
	if err != nil {
		return fmt.Errorf("KEM keygen: %w", err)
	}
	s.kem = kem
	s.ch = &npamp.ClientHello{
		ProfileOffer: []npamp.Profile{npamp.ProfileStandard},
		KEMOffer:     []npamp.KEMID{npamp.KEMX25519MLKEM768},
		SigOffer:     []npamp.SigID{npamp.SigEd25519},
		AEADOffer:    []npamp.AEADID{npamp.AEADAES256GCM},
		KEMShare:     kem.KEMShare(),
	}
	return nil
}

// concretize maps ONE abstract input symbol to its Control-channel wire shape. SERVER_HELLO
// / SERVER_HELLO_BADSEL / SERVER_AUTH / SERVER_AUTH_BADAUTH are role-nonsensical for a
// responder SUT (the server only ever SENDS them) — their content is never meaningfully
// parsed (type/role mismatch rejects first), so a fixed placeholder suffices.
func (s *responderScenario) concretize(input string) (ft npamp.FrameType, payload []byte, cleartext, corrupt bool) {
	switch input {
	case "CLIENT_HELLO":
		return npamp.FrameClientHello, s.ch.Encode(), true, false
	case "SERVER_HELLO":
		return npamp.FrameServerHello, dummyServerHelloPayload(), true, false
	case "SERVER_HELLO_BADSEL":
		return npamp.FrameServerHello, dummyServerHelloPayload(), true, false
	case "SERVER_AUTH":
		return npamp.FrameServerAuth, dummyAuthPayload(sutPub), false, false
	case "SERVER_AUTH_BADAUTH":
		return npamp.FrameServerAuth, dummyAuthPayload(sutPub), false, true
	case "CLIENT_AUTH":
		return npamp.FrameClientAuth, s.clientAuthOrDummy(), false, false
	case "CLIENT_AUTH_BADAUTH":
		return npamp.FrameClientAuth, s.clientAuthOrDummy(), false, true
	case "KEY_UPDATE":
		return npamp.FrameKeyUpdate, keyUpdateMarkerBytes(s.ctrlOut.epoch + 1), false, false
	case "KEY_UPDATE_ACK":
		return npamp.FrameKeyUpdateAck, keyUpdateMarkerBytes(s.ctrlOut.epoch), false, false
	case "CLOSE":
		return npamp.FrameClose, nil, false, false
	case "CLOSE_ACK":
		return npamp.FrameCloseAck, nil, false, false
	case "UNKNOWN":
		return unknownFrameType, nil, false, false
	default:
		logf("responder: concretize: unrecognized input symbol %q", input)
		return unknownFrameType, nil, false, false
	}
}

func dummyServerHelloPayload() []byte {
	sh := &npamp.ServerHello{
		ProfileSelect: npamp.ProfileStandard, KEMSelect: npamp.KEMX25519MLKEM768,
		SigSelect: npamp.SigEd25519, AEADSelect: npamp.AEADAES256GCM,
		KEMCiphertext: make([]byte, npamp.KEMCiphertextSize768),
	}
	return sh.Encode()
}

// clientAuthOrDummy returns the driver's cached VALID CLIENT_AUTH plaintext once cHS/sHS
// have been derived from a real SH_SA round-trip (see establishHandshakeSecrets), or a
// structurally well-formed placeholder before that — role-correct content is only load
// bearing for the ONE listed transition (responder, WAIT_CA, CLIENT_AUTH), which can only be
// reached after that round-trip has already happened in this same episode.
func (s *responderScenario) clientAuthOrDummy() []byte {
	if s.caPlaintext != nil {
		return s.caPlaintext
	}
	return dummyAuthPayload(driverPub)
}

func (s *responderScenario) step(input string) string {
	if s.closed {
		return "SILENT"
	}
	if input == "INIT_CLOSE" {
		return s.stepInitClose()
	}
	if s.established {
		return s.stepEstablished(input)
	}
	return s.stepHandshake(input)
}

func (s *responderScenario) stepHandshake(input string) string {
	if input == "APP" {
		return "SILENT"
	}
	ft, payload, cleartext, corrupt := s.concretize(input)
	var wire []byte
	var err error
	if cleartext {
		f := npamp.Frame{Type: uint16(ft), Channel: uint16(npamp.ChanControl), Seq: 0, Payload: payload}
		wire, err = f.MarshalBinary()
	} else {
		base := s.cHS
		if base == nil {
			base = placeholderSecret
		}
		wire, err = sealFrameWire(base, responderDriverSendDir, 0, npamp.ChanControl, 0, ft, payload, profile)
		if err == nil && corrupt {
			wire[npamp.HeaderSize]++
		}
	}
	if err != nil {
		logf("responder: build handshake frame for %s: %v", input, err)
		return "SILENT"
	}
	if err := writeWireFrame(s.conn, wire, ioTimeout); err != nil {
		s.closed = true
		return "SILENT"
	}

	f1, timedOut, torndown := s.waitHandshakeReaction()
	switch {
	case f1 != nil:
		return s.classifyHandshakeFrame(f1)
	case torndown:
		s.closed = true
		return "SILENT_ABORT"
	default:
		_ = timedOut
		s.pollAccept(0)
		return "SILENT"
	}
}

// pollAccept is the SINGLE place that drains s.acceptCh (a channel can only be received from
// meaningfully once its value is consumed, so no other method may also select on it). If
// Accept has not yet resolved, it waits up to `wait` (0 = a non-blocking check only); once
// resolved it is idempotent. On a SUCCESSFUL resolution with pendingMaster already computed,
// it promotes ESTABLISHED — the reaction to the table's one SILENT listed transition,
// (responder, WAIT_CA, CLIENT_AUTH) -> ESTABLISHED, which this harness has no wire signal
// for (see the pendingMaster field doc).
func (s *responderScenario) pollAccept(wait time.Duration) {
	if !s.acceptResolved {
		var res acceptResult
		var got bool
		if wait <= 0 {
			select {
			case res = <-s.acceptCh:
				got = true
			default:
			}
		} else {
			select {
			case res = <-s.acceptCh:
				got = true
			case <-time.After(wait):
			}
		}
		if got {
			s.acceptResolved = true
			s.acceptErr = res.err
			s.sutConn = res.conn
		}
	}
	if s.acceptResolved && !s.established && s.acceptErr == nil && s.pendingMaster != nil {
		s.master = s.pendingMaster
		s.established = true
	}
}

func (s *responderScenario) waitHandshakeReaction() (frame *npamp.Frame, timedOut, torndown bool) {
	f, err := readWireFrame(s.conn, reactionWindow)
	if err == nil {
		return f, false, false
	}
	s.pollAccept(abortGrace)
	if s.acceptResolved && s.acceptErr != nil && !s.established {
		return nil, false, true
	}
	return nil, true, false
}

// classifyHandshakeFrame classifies the driver's reaction to a handshake-phase injection: a
// sealed ERROR, or the SUT's own SH_SA flight (SERVER_HELLO cleartext immediately followed
// by a sealed SERVER_AUTH) — the ONE listed transition (LISTEN, CLIENT_HELLO) -> SH_SA. On
// the first genuine SH_SA it also derives cHS/sHS/a valid CLIENT_AUTH so later CLIENT_AUTH
// concretizations use real content.
func (s *responderScenario) classifyHandshakeFrame(f *npamp.Frame) string {
	switch npamp.FrameType(f.Type) {
	case npamp.FrameError:
		base := s.sHS
		if base == nil {
			base = placeholderSecret
		}
		pt, err := openFrameWire(f, base, responderDriverRecvDir, 0, profile)
		if err != nil {
			logf("responder: open handshake ERROR frame: %v", err)
			s.closed = true
			return "SILENT_ABORT"
		}
		code, _, err := npamp.DecodeErrorBody(pt)
		if err != nil {
			logf("responder: decode handshake ERROR body: %v", err)
			s.closed = true
			return "SILENT_ABORT"
		}
		s.closed = true
		return errCodeOutput(code)
	case npamp.FrameServerHello:
		sh, err := npamp.DecodeServerHello(f.Payload)
		if err != nil {
			logf("responder: decode real SERVER_HELLO: %v", err)
			return "SILENT"
		}
		saFrame, err := readWireFrame(s.conn, reactionWindow+abortGrace)
		if err != nil {
			logf("responder: expected SERVER_AUTH after real SERVER_HELLO: %v", err)
			return "SILENT"
		}
		if npamp.FrameType(saFrame.Type) != npamp.FrameServerAuth {
			logf("responder: expected SERVER_AUTH after real SERVER_HELLO, got type 0x%04x", saFrame.Type)
			return "SILENT"
		}
		if err := s.establishHandshakeSecrets(sh, saFrame); err != nil {
			logf("responder: derive handshake secrets from real SH_SA: %v", err)
		}
		return "SH_SA"
	default:
		logf("responder: unexpected handshake-phase reaction frame type 0x%04x", f.Type)
		return "SILENT"
	}
}

// establishHandshakeSecrets derives cHS/sHS from the SUT's real SERVER_HELLO (its own KEM
// ciphertext) and caches a valid CLIENT_AUTH plaintext so a later "CLIENT_AUTH" input can
// legitimately drive WAIT_CA -> ESTABLISHED (the table's one listed transition there).
func (s *responderScenario) establishHandshakeSecrets(sh *npamp.ServerHello, saFrame *npamp.Frame) error {
	ss, err := s.kem.SharedSecrets(sh.KEMCiphertext)
	if err != nil {
		return fmt.Errorf("decapsulate: %w", err)
	}
	hs, err := npamp.HandshakeSecret(ss, profile)
	if err != nil {
		return fmt.Errorf("handshake secret: %w", err)
	}
	s.hs = hs

	tr := npamp.NewTranscript(profile)
	tr.AddFrame(npamp.FrameClientHello, s.ch.TLVs())
	tr.AddFrame(npamp.FrameServerHello, sh.TLVs())
	cHS, sHS, err := npamp.DeriveHandshakeTrafficSecrets(hs, tr.Sum(), profile)
	if err != nil {
		return fmt.Errorf("derive handshake traffic secrets: %w", err)
	}
	s.cHS, s.sHS = cHS, sHS

	// Open + absorb the SUT's REAL SERVER_AUTH flight (type + its 3 TLVs) BEFORE continuing
	// to CLIENT_AUTH — the transcript is a running hash over EVERY flight in order (spec/10
	// section 3); skipping this flight would make the driver's CertVerify/Finished cover a
	// different transcript point than the one the SUT verifies against.
	saPt, err := openFrameWire(saFrame, sHS, responderDriverRecvDir, 0, profile)
	if err != nil {
		return fmt.Errorf("open real SERVER_AUTH: %w", err)
	}
	sAuth, err := npamp.DecodeAuthMessage(saPt)
	if err != nil {
		return fmt.Errorf("decode real SERVER_AUTH: %w", err)
	}
	tr.AddFrameType(npamp.FrameServerAuth)
	tr.AddTLV(npamp.TLV{Type: npamp.TLVIdentityKey, Value: sAuth.IdentityKey})
	tr.AddTLV(npamp.TLV{Type: npamp.TLVCertVerify, Value: sAuth.CertVerify})
	tr.AddTLV(npamp.TLV{Type: npamp.TLVFinished, Value: sAuth.Finished})

	tr.AddFrameType(npamp.FrameClientAuth)
	tr.AddTLV(npamp.TLV{Type: npamp.TLVIdentityKey, Value: driverPub})
	cCV, err := npamp.SignCertVerify(driverPriv, npamp.RoleClient, tr.Sum())
	if err != nil {
		return fmt.Errorf("sign client CertVerify: %w", err)
	}
	tr.AddTLV(npamp.TLV{Type: npamp.TLVCertVerify, Value: cCV})
	cFinKey, err := npamp.DeriveFinishedKey(cHS, profile)
	if err != nil {
		return fmt.Errorf("derive client Finished key: %w", err)
	}
	cFin := npamp.ComputeFinished(cFinKey, tr.Sum(), profile)
	auth := &npamp.AuthMessage{IdentityKey: driverPub, CertVerify: cCV, Finished: cFin}
	s.caPlaintext = auth.Encode()

	// Independently derive the SAME master the SUT will compute once it validly accepts a
	// CLIENT_AUTH built from this exact plaintext (thCCV is the transcript through
	// IdentityKey+CertVerify, excluding Finished — spec/10 section 5).
	thCCV := tr.Sum()
	master, err := npamp.DeriveMasterSecret(hs, thCCV, profile)
	if err != nil {
		return fmt.Errorf("derive master: %w", err)
	}
	s.pendingMaster = master
	return nil
}

func (s *responderScenario) stepEstablished(input string) string {
	if input == "APP" {
		return s.stepApp()
	}
	ft, payload, cleartext, corrupt := s.concretize(input)
	var wire []byte
	var err error
	if cleartext {
		f := npamp.Frame{Type: uint16(ft), Channel: uint16(npamp.ChanControl), Seq: 0, Payload: payload}
		wire, err = f.MarshalBinary()
	} else {
		epoch, seq := s.ctrlOut.epoch, s.ctrlOut.seq
		wire, err = sealFrameWire(s.master, responderDriverSendDir, epoch, npamp.ChanControl, seq, ft, payload, profile)
		if err == nil {
			if corrupt {
				wire[npamp.HeaderSize]++
			} else {
				s.ctrlOut.seq++
				if input == "KEY_UPDATE" {
					s.ctrlOut.advance()
				}
			}
		}
	}
	if err != nil {
		logf("responder: build established frame for %s: %v", input, err)
		return "SILENT"
	}
	return s.injectAndObserve(wire)
}

func (s *responderScenario) stepApp() string {
	seq := s.appOut.seq
	wire, err := sealFrameWire(s.master, responderDriverSendDir, 0, appChannel, seq, appFrameType, []byte("app"), profile)
	if err != nil {
		logf("responder: build APP frame: %v", err)
		return "SILENT"
	}
	s.appOut.seq++
	return s.injectAndObserve(wire)
}

func (s *responderScenario) injectAndObserve(wire []byte) string {
	recvCh := make(chan recvResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), reactionWindow+abortGrace)
		defer cancel()
		ch, ft, pt, err := s.sutConn.Recv(ctx)
		recvCh <- recvResult{ch, ft, pt, err}
	}()

	if err := writeWireFrame(s.conn, wire, ioTimeout); err != nil {
		s.closed = true
		<-recvCh
		return "SILENT"
	}

	rf, rerr := readWireFrame(s.conn, reactionWindow)
	res := <-recvCh

	if rerr == nil {
		return s.classifyEstablishedFrame(rf)
	}
	switch {
	case res.err == nil:
		return "ACCEPT"
	case errors.Is(res.err, sdk.ErrPeerClosed):
		s.closed = true
		return "SILENT"
	default:
		return "SILENT"
	}
}

func (s *responderScenario) classifyEstablishedFrame(f *npamp.Frame) string {
	switch npamp.FrameType(f.Type) {
	case npamp.FrameError:
		pt, err := openFrameWire(f, s.master, responderDriverRecvDir, 0, profile)
		if err != nil {
			logf("responder: open established ERROR: %v", err)
			s.closed = true
			return "SILENT"
		}
		code, _, err := npamp.DecodeErrorBody(pt)
		if err != nil {
			logf("responder: decode established ERROR body: %v", err)
			s.closed = true
			return "SILENT"
		}
		s.closed = true
		return errCodeOutput(code)
	case npamp.FrameCloseAck:
		s.closed = true
		return "CLOSE_ACK"
	case npamp.FrameKeyUpdateAck:
		return "KEY_UPDATE_ACK"
	default:
		logf("responder: unexpected established reaction frame type 0x%04x", f.Type)
		return "SILENT"
	}
}

func (s *responderScenario) stepInitClose() string {
	if s.sutConn == nil || s.closing {
		// See initiator.go's stepInitClose for why a second CloseGraceful in the same
		// episode is deliberately made a no-op rather than exercised as a race.
		return "SILENT"
	}
	s.closing = true
	// Capture conn+ctx as locals: teardown cancels epCtx (waking this CloseGraceful via the
	// ctx-select) and nils the fields, so the goroutine must not read them after that. It is
	// wg-tracked and joined in teardown.
	conn, ctx := s.sutConn, s.epCtx
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		_ = conn.CloseGraceful(ctx)
	}()
	f, err := readWireFrame(s.conn, reactionWindow+abortGrace)
	if err != nil {
		return "SILENT"
	}
	if npamp.FrameType(f.Type) != npamp.FrameClose {
		logf("responder: expected CLOSE after INIT_CLOSE, got type 0x%04x", f.Type)
	}
	return "SILENT"
}
