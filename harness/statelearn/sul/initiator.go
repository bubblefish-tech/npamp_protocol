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

// initiatorDriverSendDir/initiatorDriverRecvDir are the cryptographic directions the driver
// uses when it plays the RESPONDER (server) side of the connection against an INITIATOR
// (client) SUT: the driver's outbound traffic authenticates as "server->client" and the
// SUT's outbound traffic (which the driver opens) authenticates as "client->server".
const (
	initiatorDriverSendDir = npamp.DirServerToClient
	initiatorDriverRecvDir = npamp.DirClientToServer
)

// dialResult is what the background sdk.DialRaw goroutine reports once the SUT's real
// handshake call returns (success or failure).
type dialResult struct {
	conn *sdk.Conn
	err  error
}

// initiatorScenario drives the N-PAMP SDK's INITIATOR (client) role as the SUT via the real
// sdk.DialRaw over an in-process net.Pipe (no TCP, no TLS, no listener). The driver plays the
// responder (server) side by HAND on its own pipe end — never sdk.AcceptRaw, which would run
// the SDK's OWN server-side handshake instead of the driver's scripted one.
type initiatorScenario struct {
	conn    net.Conn // driver's pipe end for the CURRENT episode (the scripted-server side)
	sutPipe net.Conn // the SUT's pipe end; retained so teardown can close it to unblock a
	// DialRaw still mid-handshake (DialRaw does not close raw on error, and sutConn is nil
	// until the handshake resolves, so nothing else would).

	// epCtx/epCancel bound EVERY goroutine spawned for the current episode (the background
	// DialRaw, and any CloseGraceful). teardown cancels epCtx FIRST (waking a CloseGraceful
	// parked in its ctx-select, close.go), then closes both pipe ends (io.ErrClosedPipe wakes
	// a DialRaw blocked in a pipe read/write), then wg.Wait()s — the two wake mechanisms are
	// orthogonal, so both are required. Using epCtx (not a fixed 5 s ioTimeout) as the
	// DialRaw context is load-bearing: a wall-clock timeout inside an episode would make the
	// SUT's handshake spuriously fail on a long input sequence, breaking LearnLib determinism.
	epCtx    context.Context
	epCancel context.CancelFunc
	wg       sync.WaitGroup

	dialCh       chan dialResult
	dialResolved bool
	dialErr      error
	sutConn      *sdk.Conn

	established bool
	closing     bool // CloseGraceful already triggered this episode (see stepInitClose)
	closed      bool

	// Handshake-phase material, populated fresh each RESET from the SUT's real CLIENT_HELLO.
	ch          *npamp.ClientHello
	chBytes     []byte
	shValid     *npamp.ServerHello
	shBad       *npamp.ServerHello
	hs          []byte // handshake_secret
	cHS, sHS    []byte
	saPlaintext []byte // valid SERVER_AUTH AuthMessage encoding (deterministic: Ed25519+HMAC)

	master []byte // populated once ESTABLISHED

	ctrlOut chanState
	appOut  chanState
}

func newInitiatorScenario() *initiatorScenario {
	return &initiatorScenario{}
}

// teardown ends the current episode leak-free. The two wake mechanisms are orthogonal so
// both are applied, in order: (1) cancel epCtx — wakes a CloseGraceful goroutine parked in
// its ctx-select (close.go:122); (2) close BOTH raw pipe ends — io.ErrClosedPipe wakes any
// goroutine (a mid-handshake DialRaw, the driver's own reads) blocked in a pipe read/write;
// (3) wg.Wait() — join every episode goroutine before the next reset() builds a fresh pipe.
// sutConn.Close() zeroizes keys and is idempotent; sutPipe.Close() covers the case where
// DialRaw errored (it does not close raw) or has not resolved yet (sutConn still nil).
func (s *initiatorScenario) teardown() {
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

func (s *initiatorScenario) closeScenario() {
	s.teardown()
}

// reset tears down any prior episode and drives a fresh sdk.DialRaw() up to (and including)
// reading its real, opening CLIENT_HELLO — landing the SUT at WAIT_SH (modeled_exclusions:
// "the initiator sends CLIENT_HELLO as its opening ACTION... A SUL for the initiator resets
// into WAIT_SH"). It also precomputes every artifact needed to concretize the full input
// alphabet against WHATEVER state the SUT is later found to actually be in.
func (s *initiatorScenario) reset() error {
	s.teardown()

	s.dialResolved = false
	s.dialErr = nil
	s.established = false
	s.closing = false
	s.closed = false
	s.master = nil
	s.ctrlOut = chanState{}
	s.appOut = chanState{}

	// A fresh, single-use in-process pipe per episode: pipeSUT is handed to the real
	// sdk.DialRaw (the SUT's client handshake), pipeDriver is the scripted-server side this
	// driver drives by hand. net.Pipe is synchronous and UNBUFFERED, so every driver write
	// must be paired with a concurrent SUT read (the SDK's recv path, or a driver
	// readWireFrame on the other role). epCtx bounds the DialRaw goroutine; teardown cancels
	// it and closes the pipe to unblock and join it.
	s.epCtx, s.epCancel = context.WithCancel(context.Background())
	pipeSUT, pipeDriver := net.Pipe()
	s.sutPipe = pipeSUT
	s.conn = pipeDriver

	// dialCh is a LOCAL variable captured by the goroutine's closure, and s.dialCh is only
	// assigned to it AFTER the goroutine is spawned. This is deliberate: a straggler
	// goroutine from a PRIOR episode (one whose DialRaw is still unwinding) must never be
	// able to write into the NEW episode's channel by reading s.dialCh at send-time — that
	// field will have already been reassigned. Sending into a captured local eliminates that
	// cross-episode contamination, which otherwise makes the SUL's output non-deterministic
	// for an identical input sequence and crashes LearnLib's TTT algorithm (it assumes
	// SUL.step is a pure function of the reset-to-here input prefix). teardown's wg.Wait
	// already joins the prior goroutine, so this is belt-and-suspenders.
	//
	// The goroutine runs the SUT's real client handshake over pipeSUT under epCtx — NOT a
	// fixed wall-clock timeout: a long episode-length input sequence must not spuriously time
	// the handshake out and make the SUL nondeterministic (advisor). DialRaw ignores
	// TLSConfig, so only Identity is set.
	dialCh := make(chan dialResult, 1)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		conn, err := sdk.DialRaw(s.epCtx, pipeSUT, sdk.Config{Identity: sutPriv})
		dialCh <- dialResult{conn: conn, err: err}
	}()
	s.dialCh = dialCh

	chFrame, err := readWireFrame(s.conn, ioTimeout)
	if err != nil {
		return fmt.Errorf("read CLIENT_HELLO: %w", err)
	}
	if chFrame.Type != uint16(npamp.FrameClientHello) || chFrame.Flags&npamp.FlagENC != 0 {
		return fmt.Errorf("unexpected opening frame type=0x%04x flags=0x%02x", chFrame.Type, chFrame.Flags)
	}
	s.chBytes = chFrame.Payload
	ch, err := npamp.DecodeClientHello(s.chBytes)
	if err != nil {
		return fmt.Errorf("decode CLIENT_HELLO: %w", err)
	}
	s.ch = ch

	kemCT, ss, err := npamp.Encapsulate(ch.KEMShare)
	if err != nil {
		return fmt.Errorf("encapsulate: %w", err)
	}
	s.shValid = &npamp.ServerHello{
		ProfileSelect: npamp.ProfileStandard, KEMSelect: npamp.KEMX25519MLKEM768,
		SigSelect: npamp.SigEd25519, AEADSelect: npamp.AEADAES256GCM, KEMCiphertext: kemCT,
	}
	s.shBad = &npamp.ServerHello{
		ProfileSelect: npamp.ProfileHigh, KEMSelect: npamp.KEMX25519MLKEM768,
		SigSelect: npamp.SigEd25519, AEADSelect: npamp.AEADAES256GCM, KEMCiphertext: kemCT,
	}

	hs, err := npamp.HandshakeSecret(ss, profile)
	if err != nil {
		return fmt.Errorf("handshake secret: %w", err)
	}
	s.hs = hs

	trThroughSH := s.transcriptThroughSH()
	cHS, sHS, err := npamp.DeriveHandshakeTrafficSecrets(hs, trThroughSH.Sum(), profile)
	if err != nil {
		return fmt.Errorf("derive handshake traffic secrets: %w", err)
	}
	s.cHS, s.sHS = cHS, sHS

	_, sCV, sFin := s.transcriptThroughServerAuth()
	auth := &npamp.AuthMessage{IdentityKey: driverPub, CertVerify: sCV, Finished: sFin}
	s.saPlaintext = auth.Encode()

	return nil
}

// transcriptThroughSH rebuilds the transcript through a validly-received SERVER_HELLO —
// deterministically reproducible from s.ch/s.shValid, so it is recomputed on demand instead
// of caching a mutable *npamp.Transcript across calls.
func (s *initiatorScenario) transcriptThroughSH() *npamp.Transcript {
	tr := npamp.NewTranscript(profile)
	tr.AddFrame(npamp.FrameClientHello, s.ch.TLVs())
	tr.AddFrame(npamp.FrameServerHello, s.shValid.TLVs())
	return tr
}

// transcriptThroughServerAuth continues transcriptThroughSH with the driver's own valid
// SERVER_AUTH flight (Ed25519 CertVerify and HMAC Finished are both deterministic, so this
// reproduces byte-identical sCV/sFin on every call).
func (s *initiatorScenario) transcriptThroughServerAuth() (tr *npamp.Transcript, sCV, sFin []byte) {
	tr = s.transcriptThroughSH()
	tr.AddFrameType(npamp.FrameServerAuth)
	tr.AddTLV(npamp.TLV{Type: npamp.TLVIdentityKey, Value: driverPub})
	sCV, err := npamp.SignCertVerify(driverPriv, npamp.RoleServer, tr.Sum())
	if err != nil {
		logf("initiator: sign server CertVerify: %v", err)
		return tr, nil, nil
	}
	tr.AddTLV(npamp.TLV{Type: npamp.TLVCertVerify, Value: sCV})
	sFinKey, err := npamp.DeriveFinishedKey(s.sHS, profile)
	if err != nil {
		logf("initiator: derive server Finished key: %v", err)
		return tr, sCV, nil
	}
	sFin = npamp.ComputeFinished(sFinKey, tr.Sum(), profile)
	tr.AddTLV(npamp.TLV{Type: npamp.TLVFinished, Value: sFin})
	return tr, sCV, sFin
}

// concretize maps ONE abstract input symbol to its Control-channel wire shape: frame type,
// plaintext (or cleartext payload), whether it is cleartext, and whether the AEAD tag should
// be deliberately corrupted after sealing (the _BADAUTH symbols). APP and INIT_CLOSE are
// handled outside this function (a different channel / no frame at all, respectively).
func (s *initiatorScenario) concretize(input string) (ft npamp.FrameType, payload []byte, cleartext, corrupt bool) {
	switch input {
	case "CLIENT_HELLO":
		return npamp.FrameClientHello, s.chBytes, true, false
	case "SERVER_HELLO":
		return npamp.FrameServerHello, s.shValid.Encode(), true, false
	case "SERVER_HELLO_BADSEL":
		return npamp.FrameServerHello, s.shBad.Encode(), true, false
	case "SERVER_AUTH":
		return npamp.FrameServerAuth, s.saPlaintext, false, false
	case "SERVER_AUTH_BADAUTH":
		return npamp.FrameServerAuth, s.saPlaintext, false, true
	case "CLIENT_AUTH":
		// Role-nonsensical for an initiator SUT (the client only ever SENDS CLIENT_AUTH); the
		// content is never meaningfully parsed (type/role mismatch rejects it first).
		return npamp.FrameClientAuth, dummyAuthPayload(sutPub), false, false
	case "CLIENT_AUTH_BADAUTH":
		return npamp.FrameClientAuth, dummyAuthPayload(sutPub), false, true
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
		logf("initiator: concretize: unrecognized input symbol %q", input)
		return unknownFrameType, nil, false, false
	}
}

// step concretizes and injects ONE abstract input symbol against the current episode and
// returns the classified abstract output symbol.
func (s *initiatorScenario) step(input string) string {
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

// stepHandshake handles every input while the SUT is still inside its blocked sdk.DialRaw()
// call (pre-ESTABLISHED): it seals/sends the concretized frame under the handshake-phase
// secret (cHS/sHS, seq fixed at 0 — the handshake AUTH-frame path has no independent
// expected-seq check; see wire.go) and classifies the reaction.
func (s *initiatorScenario) stepHandshake(input string) string {
	if input == "APP" {
		return "SILENT" // no application channel exists before ESTABLISHED
	}
	ft, payload, cleartext, corrupt := s.concretize(input)
	var wire []byte
	var err error
	if cleartext {
		f := npamp.Frame{Type: uint16(ft), Channel: uint16(npamp.ChanControl), Seq: 0, Payload: payload}
		wire, err = f.MarshalBinary()
	} else {
		wire, err = sealFrameWire(s.sHS, initiatorDriverSendDir, 0, npamp.ChanControl, 0, ft, payload, profile)
		if err == nil && corrupt {
			wire[npamp.HeaderSize]++
		}
	}
	if err != nil {
		logf("initiator: build handshake frame for %s: %v", input, err)
		return "SILENT"
	}
	if err := writeWireFrame(s.conn, wire, ioTimeout); err != nil {
		s.closed = true
		return "SILENT"
	}

	frame, timedOut, torndown := s.waitHandshakeReaction()
	switch {
	case frame != nil:
		return s.classifyHandshakeFrame(frame)
	case torndown:
		s.closed = true
		return "SILENT_ABORT"
	default:
		_ = timedOut
		return "SILENT"
	}
}

// waitHandshakeReaction reads for a reaction frame within reactionWindow; if none arrives it
// consults (or, on the first occasion, waits up to abortGrace on) the Dial() completion
// channel to distinguish "still alive, no reaction" (SILENT) from "torn down, no ERROR sent"
// (SILENT_ABORT — the pre-key case).
func (s *initiatorScenario) waitHandshakeReaction() (frame *npamp.Frame, timedOut, torndown bool) {
	f, err := readWireFrame(s.conn, reactionWindow)
	if err == nil {
		return f, false, false
	}
	if s.dialResolved {
		if s.dialErr != nil {
			return nil, false, true
		}
		return nil, true, false
	}
	select {
	case res := <-s.dialCh:
		s.dialResolved = true
		s.dialErr = res.err
		s.sutConn = res.conn
		if res.err != nil {
			return nil, false, true
		}
		return nil, true, false
	case <-time.After(abortGrace):
		return nil, true, false
	}
}

func (s *initiatorScenario) classifyHandshakeFrame(f *npamp.Frame) string {
	switch npamp.FrameType(f.Type) {
	case npamp.FrameError:
		pt, err := openFrameWire(f, s.cHS, initiatorDriverRecvDir, 0, profile)
		if err != nil {
			logf("initiator: open handshake ERROR frame: %v", err)
			s.closed = true
			return "SILENT_ABORT"
		}
		code, _, err := npamp.DecodeErrorBody(pt)
		if err != nil {
			logf("initiator: decode handshake ERROR body: %v", err)
			s.closed = true
			return "SILENT_ABORT"
		}
		s.closed = true
		return errCodeOutput(code)
	case npamp.FrameClientAuth:
		if err := s.establish(f); err != nil {
			logf("initiator: establish from real CLIENT_AUTH: %v", err)
			return "SILENT"
		}
		if !s.dialResolved {
			select {
			case res := <-s.dialCh:
				s.dialResolved = true
				s.dialErr = res.err
				s.sutConn = res.conn
			case <-time.After(ioTimeout):
				logf("initiator: Dial() did not resolve after a real CLIENT_AUTH")
			}
		}
		if s.dialErr != nil || s.sutConn == nil {
			logf("initiator: Dial() reported an error after a real CLIENT_AUTH: %v", s.dialErr)
			s.closed = true
			return "SILENT_ABORT"
		}
		s.established = true
		return "CLIENT_AUTH"
	default:
		logf("initiator: unexpected handshake-phase reaction frame type 0x%04x", f.Type)
		return "SILENT"
	}
}

// establish independently derives the SAME master secret the SUT computed, by continuing
// the driver's own transcript with the REAL CLIENT_AUTH the SUT sent (IdentityKey +
// CertVerify — not re-verified, since a mismatch would simply make every later
// established-phase AEAD operation fail closed, which is its own correctness check).
func (s *initiatorScenario) establish(clientAuthFrame *npamp.Frame) error {
	pt, err := openFrameWire(clientAuthFrame, s.cHS, initiatorDriverRecvDir, 0, profile)
	if err != nil {
		return fmt.Errorf("open real CLIENT_AUTH: %w", err)
	}
	cAuth, err := npamp.DecodeAuthMessage(pt)
	if err != nil {
		return fmt.Errorf("decode real CLIENT_AUTH: %w", err)
	}
	tr, _, _ := s.transcriptThroughServerAuth()
	tr.AddFrameType(npamp.FrameClientAuth)
	tr.AddTLV(npamp.TLV{Type: npamp.TLVIdentityKey, Value: cAuth.IdentityKey})
	tr.AddTLV(npamp.TLV{Type: npamp.TLVCertVerify, Value: cAuth.CertVerify})
	thCCV := tr.Sum()
	master, err := npamp.DeriveMasterSecret(s.hs, thCCV, profile)
	if err != nil {
		return fmt.Errorf("derive master: %w", err)
	}
	s.master = master
	return nil
}

// stepEstablished handles every input once the SUT holds a real *sdk.Conn: it seals under
// the post-handshake master-rooted Control (or, for APP, Memory) channel key at the
// driver's tracked epoch/seq, injects it, and — because the SDK only reacts to received
// traffic when its CALLER actively invokes Conn.Recv — spawns exactly one bounded Recv()
// call per step, mirroring statetrace_test.go's injectAndReadReaction pattern.
func (s *initiatorScenario) stepEstablished(input string) string {
	if input == "APP" {
		return s.stepApp()
	}
	ft, payload, cleartext, corrupt := s.concretize(input)
	var wire []byte
	var err error
	if cleartext {
		// A cleartext handshake-flight-shaped frame is rejected pre-dispatch once
		// ESTABLISHED (recvLocked requires FlagENC before anything else runs), so it never
		// touches ctrlOut bookkeeping.
		f := npamp.Frame{Type: uint16(ft), Channel: uint16(npamp.ChanControl), Seq: 0, Payload: payload}
		wire, err = f.MarshalBinary()
	} else {
		epoch, seq := s.ctrlOut.epoch, s.ctrlOut.seq
		wire, err = sealFrameWire(s.master, initiatorDriverSendDir, epoch, npamp.ChanControl, seq, ft, payload, profile)
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
		logf("initiator: build established frame for %s: %v", input, err)
		return "SILENT"
	}
	return s.injectAndObserve(wire)
}

func (s *initiatorScenario) stepApp() string {
	seq := s.appOut.seq
	wire, err := sealFrameWire(s.master, initiatorDriverSendDir, 0, appChannel, seq, appFrameType, []byte("app"), profile)
	if err != nil {
		logf("initiator: build APP frame: %v", err)
		return "SILENT"
	}
	s.appOut.seq++
	return s.injectAndObserve(wire)
}

type recvResult struct {
	ch  npamp.ChannelID
	ft  npamp.FrameType
	pt  []byte
	err error
}

// injectAndObserve writes wire to the driver's raw connection, spawns exactly one bounded
// sutConn.Recv call (the mechanism by which the SUT's real recvLocked logic actually runs
// for this frame), and classifies the reaction from whichever signal arrives: a raw wire
// frame (ERROR / CLOSE_ACK / KEY_UPDATE_ACK) or the Recv() call's own return (nil error ==
// ACCEPT — an application frame delivered to the caller with no wire-level reaction).
func (s *initiatorScenario) injectAndObserve(wire []byte) string {
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

func (s *initiatorScenario) classifyEstablishedFrame(f *npamp.Frame) string {
	switch npamp.FrameType(f.Type) {
	case npamp.FrameError:
		pt, err := openFrameWire(f, s.master, initiatorDriverRecvDir, 0, profile)
		if err != nil {
			logf("initiator: open established ERROR: %v", err)
			s.closed = true
			return "SILENT"
		}
		code, _, err := npamp.DecodeErrorBody(pt)
		if err != nil {
			logf("initiator: decode established ERROR body: %v", err)
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
		logf("initiator: unexpected established reaction frame type 0x%04x", f.Type)
		return "SILENT"
	}
}

// stepInitClose is the ACTION symbol that triggers the SUT's OWN CloseGraceful (CLOSING is
// entered by SENDING a CLOSE, not by receiving a frame — draft's "both" CLOSING transition
// only models the RECEIVE side). It is not a table row (the table only models
// received-frame reactions), so its own step output is fixed at SILENT by this harness's
// design; the interesting state change is exercised by whatever input is applied NEXT (e.g.
// a subsequent "CLOSE_ACK" completes CloseGraceful; see README for this documented
// extension).
func (s *initiatorScenario) stepInitClose() string {
	if s.sutConn == nil || s.closing {
		// No Conn to close yet, or CloseGraceful has already been triggered this episode:
		// sdk/close.go's sendClose does not itself guard against a second concurrent call
		// (it would seal and send a SECOND CLOSE frame, racing the first CloseGraceful
		// goroutine's own wmu-held send/ack-wait), so this harness makes the ACTION
		// idempotent per episode rather than exercise that race — INIT_CLOSE while already
		// CLOSING is a no-op / self-loop by this harness's design (see README).
		return "SILENT"
	}
	s.closing = true
	// Capture conn+ctx as locals: teardown cancels epCtx (waking this CloseGraceful via
	// close.go's ctx-select) and then nils the fields, so the goroutine must not read them
	// after that. The goroutine is wg-tracked and joined in teardown.
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
		logf("initiator: expected CLOSE after INIT_CLOSE, got type 0x%04x", f.Type)
	}
	return "SILENT"
}
