// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package relay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

func mustMarshalFrame(t *testing.T, f npamp.Frame) []byte {
	t.Helper()
	wire, err := f.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	return wire
}

// ---------------------------------------------------------------------------
// readRawFrame / writeRawFrame: low-level frame-boundary I/O
// ---------------------------------------------------------------------------

// TestReadRawFrame_RoundTrip proves readRawFrame returns the wire bytes of a
// well-formed frame VERBATIM — byte-identical to what MarshalBinary produced
// — which is the "no re-encoding" property the relay's forwarding depends
// on.
func TestReadRawFrame_RoundTrip(t *testing.T) {
	want := mustMarshalFrame(t, npamp.Frame{
		Type:    0x0120,
		Channel: uint16(npamp.ChanMemory),
		Seq:     7,
		Payload: []byte("hello from a KAT-style test frame"),
	})
	got, err := readRawFrame(bytes.NewReader(want), npamp.MaxFrameSize)
	if err != nil {
		t.Fatalf("readRawFrame: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("readRawFrame returned bytes that differ from the input:\n got=%x\nwant=%x", got, want)
	}
}

// TestReadRawFrame_RejectsOversizedLength proves an oversized DECLARED
// payload length is rejected before any payload is read (R12: reject the
// hostile length up front rather than buffering toward it).
func TestReadRawFrame_RejectsOversizedLength(t *testing.T) {
	const smallMax = 64
	header := make([]byte, npamp.HeaderSize)
	copy(header[0:4], npamp.Magic[:])
	header[4] = npamp.ProtocolVersion << 4
	// Declare a payload length that alone exceeds smallMax; no payload bytes
	// follow, so a reader that tried to honor the declared length would
	// block or fail differently than the up-front size-cap rejection this
	// test expects.
	header[17], header[18], header[19], header[20] = 0, 1, 0, 0 // 0x00010000 = 65536
	_, err := readRawFrame(bytes.NewReader(header), smallMax)
	if err == nil {
		t.Fatal("readRawFrame accepted a declared length far exceeding maxFrameSize")
	}
}

// TestReadRawFrame_TruncatedStream proves a stream that ends mid-payload
// surfaces an error (io.ErrUnexpectedEOF via io.CopyN) rather than hanging
// or returning a short frame.
func TestReadRawFrame_TruncatedStream(t *testing.T) {
	full := mustMarshalFrame(t, npamp.Frame{Type: 1, Channel: 1, Seq: 0, Payload: []byte("0123456789")})
	truncated := full[:len(full)-5] // header complete, payload short by 5 octets
	_, err := readRawFrame(bytes.NewReader(truncated), npamp.MaxFrameSize)
	if err == nil {
		t.Fatal("readRawFrame accepted a truncated payload")
	}
	if errors.Is(err, io.EOF) {
		t.Fatalf("truncated payload reported as clean io.EOF, want a distinct truncation error: %v", err)
	}
}

// TestReadRawFrame_CleanEOF proves an EOF at a frame boundary (nothing at
// all buffered) is reported as plain io.EOF, the signal Relay.forward treats
// as a clean peer close rather than a defect.
func TestReadRawFrame_CleanEOF(t *testing.T) {
	_, err := readRawFrame(bytes.NewReader(nil), npamp.MaxFrameSize)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("readRawFrame on an empty stream = %v, want io.EOF", err)
	}
}

// ---------------------------------------------------------------------------
// Relay.Run: full bidirectional forwarding over net.Pipe legs
// ---------------------------------------------------------------------------

// pipePair wires a Relay between two OBSERVABLE endpoints: agentA talks to
// relay.A, agentB talks to relay.B, and the test drives agentA/agentB
// directly (as a plain net.Conn) to inject and observe frames, exactly as
// two real N-PAMP peers would sit on either side of a deployed relay.
type pipePair struct {
	agentA, relayA net.Conn
	relayB, agentB net.Conn
}

func newPipePair() *pipePair {
	agentA, relayA := net.Pipe()
	relayB, agentB := net.Pipe()
	return &pipePair{agentA: agentA, relayA: relayA, relayB: relayB, agentB: agentB}
}

func (p *pipePair) closeAll() {
	_ = p.agentA.Close()
	_ = p.relayA.Close()
	_ = p.relayB.Close()
	_ = p.agentB.Close()
}

// TestRun_ForwardsAToB_ByteIdentical proves a well-formed frame written by
// agentA arrives at agentB byte-identical, with a nil Hook (default
// pass-through).
func TestRun_ForwardsAToB_ByteIdentical(t *testing.T) {
	p := newPipePair()
	defer p.closeAll()
	rl := &Relay{A: p.relayA, B: p.relayB}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- rl.Run(ctx) }()

	want := mustMarshalFrame(t, npamp.Frame{Type: 0x0120, Channel: uint16(npamp.ChanMemory), Seq: 3, Payload: []byte("A to B, byte for byte")})
	writeErr := make(chan error, 1)
	go func() { _, err := p.agentA.Write(want); writeErr <- err }() // net.Pipe is unbuffered: write on its own goroutine

	got := make([]byte, len(want))
	if _, err := io.ReadFull(p.agentB, got); err != nil {
		t.Fatalf("agentB read: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("agentA write: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("forwarded frame differs from what was sent:\n got=%x\nwant=%x", got, want)
	}

	p.closeAll()
	<-runErr
}

// TestRun_ForwardsBToA_ByteIdentical is TestRun_ForwardsAToB_ByteIdentical's
// mirror: the OTHER direction, proving the relay is genuinely bidirectional
// rather than only piping one way.
func TestRun_ForwardsBToA_ByteIdentical(t *testing.T) {
	p := newPipePair()
	defer p.closeAll()
	rl := &Relay{A: p.relayA, B: p.relayB}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- rl.Run(ctx) }()

	want := mustMarshalFrame(t, npamp.Frame{Type: 0x0121, Channel: uint16(npamp.ChanControl), Seq: 9, Payload: []byte("B to A, the other direction")})
	writeErr := make(chan error, 1)
	go func() { _, err := p.agentB.Write(want); writeErr <- err }()

	got := make([]byte, len(want))
	if _, err := io.ReadFull(p.agentA, got); err != nil {
		t.Fatalf("agentA read: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("agentB write: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("forwarded frame differs from what was sent:\n got=%x\nwant=%x", got, want)
	}

	p.closeAll()
	<-runErr
}

// TestRun_HookSeesParsedHeader proves the Hook seam (E2.2's plug point) is
// called with the CORRECT parsed header fields, and NEVER sees the
// payload bytes it wasn't given.
func TestRun_HookSeesParsedHeader(t *testing.T) {
	p := newPipePair()
	defer p.closeAll()

	var mu sync.Mutex
	var gotDir Direction
	var gotHdr FrameHeader
	called := make(chan struct{}, 1)
	rl := &Relay{A: p.relayA, B: p.relayB, Hook: func(dir Direction, h FrameHeader) error {
		mu.Lock()
		gotDir, gotHdr = dir, h
		mu.Unlock()
		called <- struct{}{}
		return nil
	}}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- rl.Run(ctx) }()

	payload := []byte("payload the hook must never receive")
	wire := mustMarshalFrame(t, npamp.Frame{Type: 0x0155, Channel: uint16(npamp.ChanMemory), Seq: 42, Payload: payload})
	writeErr := make(chan error, 1)
	go func() { _, err := p.agentA.Write(wire); writeErr <- err }()

	got := make([]byte, len(wire))
	if _, err := io.ReadFull(p.agentB, got); err != nil {
		t.Fatalf("agentB read: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("agentA write: %v", err)
	}
	select {
	case <-called:
	case <-time.After(5 * time.Second):
		t.Fatal("Hook was never called")
	}

	mu.Lock()
	defer mu.Unlock()
	if gotDir != DirAToB {
		t.Fatalf("Hook direction = %v, want DirAToB", gotDir)
	}
	if gotHdr.Type != 0x0155 || gotHdr.Channel != uint16(npamp.ChanMemory) || gotHdr.Seq != 42 {
		t.Fatalf("Hook header = %+v, want Type=0x0155 Channel=%d Seq=42", gotHdr, uint16(npamp.ChanMemory))
	}
	if gotHdr.PayloadLen != uint32(len(payload)) {
		t.Fatalf("Hook PayloadLen = %d, want %d", gotHdr.PayloadLen, len(payload))
	}

	p.closeAll()
	<-runErr
}

// TestRun_HookRejectionTearsDownFlow proves a Hook that rejects a frame ends
// the WHOLE flow (both legs close) rather than silently dropping just that
// frame — the fail-closed posture R12 requires.
func TestRun_HookRejectionTearsDownFlow(t *testing.T) {
	p := newPipePair()
	defer p.closeAll()

	rejectErr := errors.New("policy: frame rejected by test hook")
	rl := &Relay{A: p.relayA, B: p.relayB, Hook: func(dir Direction, h FrameHeader) error {
		return rejectErr
	}}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- rl.Run(ctx) }()

	wire := mustMarshalFrame(t, npamp.Frame{Type: 1, Channel: 1, Seq: 0, Payload: []byte("should never reach agentB")})
	go func() { _, _ = p.agentA.Write(wire) }()

	select {
	case err := <-runErr:
		if !errors.Is(err, rejectErr) {
			t.Fatalf("Run() = %v, want an error wrapping the Hook's rejection", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the Hook rejected a frame")
	}

	// The flow tore down: agentB's read never got the (would-be forwarded)
	// frame and instead observes the leg closing.
	one := make([]byte, 1)
	if _, err := p.agentB.Read(one); err == nil {
		t.Fatal("agentB received data after a Hook rejection tore the flow down")
	}
}

// TestRun_MalformedFrameTearsDownFlow proves a frame that fails
// npamp.Frame.UnmarshalBinary validation (here: a corrupted CRC32C) is NEVER
// forwarded, and ends the flow — mutation anchor for the RED-EVIDENCE
// record: this is the "malformed frame -> tear down" half of R12.
func TestRun_MalformedFrameTearsDownFlow(t *testing.T) {
	p := newPipePair()
	defer p.closeAll()
	rl := &Relay{A: p.relayA, B: p.relayB}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- rl.Run(ctx) }()

	wire := mustMarshalFrame(t, npamp.Frame{Type: 1, Channel: 1, Seq: 0, Payload: []byte("corrupt me")})
	wire[5] ^= 0xFF // flip a byte inside the CRC32C-covered prefix (octets 0..20): invalidates the CRC
	go func() { _, _ = p.agentA.Write(wire) }()

	select {
	case err := <-runErr:
		if err == nil {
			t.Fatal("Run() = nil, want a malformed-frame error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after a malformed frame")
	}

	one := make([]byte, 1)
	if _, err := p.agentB.Read(one); err == nil {
		t.Fatal("agentB received data derived from a malformed frame")
	}
}

// TestRun_CleanEOFClosesBothLegs proves an agent closing its connection
// before sending anything ends the flow with a NIL error (a clean close,
// not a defect) and still tears down the OTHER leg.
func TestRun_CleanEOFClosesBothLegs(t *testing.T) {
	p := newPipePair()
	defer p.closeAll()
	rl := &Relay{A: p.relayA, B: p.relayB}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- rl.Run(ctx) }()

	_ = p.agentA.Close()

	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run() = %v, want nil on a clean peer close", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after agentA closed")
	}

	one := make([]byte, 1)
	if _, err := p.agentB.Read(one); err == nil {
		t.Fatal("agentB read succeeded after Run should have closed relay.B")
	}
}

// TestRelay_MaxFrameSizeDefault proves a zero-value MaxFrameSize defaults to
// npamp.MaxFrameSize, so a Relay constructed without an explicit bound still
// enforces the base parser's cap rather than accepting anything.
func TestRelay_MaxFrameSizeDefault(t *testing.T) {
	rl := &Relay{}
	if got := rl.maxFrameSize(); got != npamp.MaxFrameSize {
		t.Fatalf("default maxFrameSize() = %d, want npamp.MaxFrameSize (%d)", got, npamp.MaxFrameSize)
	}
	rl2 := &Relay{MaxFrameSize: 1024}
	if got := rl2.maxFrameSize(); got != 1024 {
		t.Fatalf("explicit maxFrameSize() = %d, want 1024", got)
	}
}
