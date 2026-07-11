// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// countingConn wraps a net.Conn but discards + counts Writes (non-blocking), so a test can assert
// whether a code path wrote a frame without a reader draining the other end.
type countingConn struct {
	net.Conn
	writes int32
}

func (c *countingConn) Write(b []byte) (int, error) {
	atomic.AddInt32(&c.writes, 1)
	return len(b), nil
}

func guardTestMaster() []byte {
	m := make([]byte, 32)
	for i := range m {
		m[i] = 0xAB
	}
	return m
}

// TestSendRefusesSequenceExhaustion pins the AEAD nonce-reuse guard: once an epoch's 64-bit send
// sequence is exhausted (seq == 2^64-1) the next send would wrap seq to 0 and reuse a nonce, so
// Send MUST refuse AND MUST NOT write a frame — the caller has to KeyUpdate (fresh key + reset
// sequence) first. White-box: it injects the exhausted seq on the cached epoch key. Mutation-
// surviving: dropping the guard makes Send write a frame (writes==1) and return nil; moving it
// after the write leaves writes==1.
func TestSendRefusesSequenceExhaustion(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	cc := &countingConn{Conn: a}
	c := newConn(cc, guardTestMaster(), nil, npamp.DirClientToServer, npamp.DirServerToClient)

	st, err := c.sendState(npamp.ChanMemory)
	if err != nil {
		t.Fatalf("sendState: %v", err)
	}
	st.seq = ^uint64(0) // exhaust the epoch's sequence space

	err = c.Send(context.Background(), npamp.ChanMemory, npamp.FrameType(0x0120), []byte("x"))
	if err == nil {
		t.Fatal("Send must refuse once the epoch sequence space is exhausted")
	}
	if !strings.Contains(err.Error(), "sequence space exhausted") {
		t.Fatalf("wrong error: %v", err)
	}
	if n := atomic.LoadInt32(&cc.writes); n != 0 {
		t.Fatalf("Send wrote %d frame(s) despite exhaustion — the nonce-reuse guard was bypassed", n)
	}
}

// TestRecvRejectsOutOfSequenceReplayAndPerChannelSeq pins the receive-side replay/reorder guard
// (f.Seq must equal the expected per-(channel,epoch) seq) and per-channel sequence independence. A
// client and server Conn share a master over net.Pipe. A replayed frame (send seq reset to 0 after
// one accepted frame) must be rejected out-of-sequence; a fresh channel starts its own seq at 0 and
// is accepted. Mutation-surviving: dropping the f.Seq!=st.seq check accepts the replay.
func TestRecvRejectsOutOfSequenceReplayAndPerChannelSeq(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	master := guardTestMaster()
	client := newConn(a, master, nil, npamp.DirClientToServer, npamp.DirServerToClient)
	server := newConn(b, master, nil, npamp.DirServerToClient, npamp.DirClientToServer)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ft := npamp.FrameType(0x0120)
	sendErr := make(chan error, 1)

	// Frame 0 on Memory: in-order, accepted.
	go func() { sendErr <- client.Send(ctx, npamp.ChanMemory, ft, []byte("m0")) }()
	if _, _, got, err := server.Recv(ctx); err != nil {
		t.Fatalf("first in-order frame rejected: %v", err)
	} else if string(got) != "m0" {
		t.Fatalf("payload = %q, want m0", got)
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("client.Send #0: %v", err)
	}

	// Per-channel independence: a fresh channel (Knowledge) starts its own seq at 0 and is accepted
	// even though Memory has already advanced past seq 0.
	go func() { sendErr <- client.Send(ctx, npamp.ChanKnowledge, ft, []byte("k0")) }()
	if ch, _, got, err := server.Recv(ctx); err != nil {
		t.Fatalf("fresh-channel frame rejected — seq counters are not per-channel: %v", err)
	} else if ch != npamp.ChanKnowledge || string(got) != "k0" {
		t.Fatalf("got ch %#x payload %q, want Knowledge/k0", uint16(ch), got)
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("client.Send Knowledge: %v", err)
	}

	// Replay on Memory: reset the client's Memory send seq to 0 and resend — the server now expects
	// seq 1, so it must reject the replayed seq-0 frame out-of-sequence.
	client.sendKeys[npamp.ChanMemory].seq = 0
	go func() { sendErr <- client.Send(ctx, npamp.ChanMemory, ft, []byte("replay")) }()
	_, _, _, err := server.Recv(ctx)
	if err == nil {
		t.Fatal("server accepted a replayed (out-of-sequence) frame — the replay guard was bypassed")
	}
	if !strings.Contains(err.Error(), "out-of-sequence") {
		t.Fatalf("wrong error (want out-of-sequence): %v", err)
	}
	<-sendErr // the replayed frame was written + read before rejection; drain the sender
}

// TestReadFrameRejectsHostilePayloadLength pins the unauthenticated-peer byte-path hardening: a
// hostile high-bit PayloadLength must be capped on a wrap-safe int64 path (never wrap negative and
// slip past the size cap) and must not panic. readFrame is the first code an unauthenticated peer's
// bytes reach. White-box: readFrame is fed a header-only frame with a high-bit length. Mutation-
// surviving: reverting total to a 32-bit int would wrap and bypass the cap for these inputs.
func TestReadFrameRejectsHostilePayloadLength(t *testing.T) {
	for _, plen := range []uint32{0x80000000, 0xC0000000, 0xFFFFFFFF} {
		header := make([]byte, npamp.HeaderSize)
		copy(header[:4], npamp.Magic[:])
		binary.BigEndian.PutUint32(header[17:21], plen)
		if _, err := readFrame(bytes.NewReader(header)); err == nil {
			t.Fatalf("plen=%#x: readFrame accepted a hostile frame size", plen)
		} else if !strings.Contains(err.Error(), "exceeds max") {
			t.Fatalf("plen=%#x: wrong error (want size cap 'exceeds max'): %v", plen, err)
		}
	}
}
