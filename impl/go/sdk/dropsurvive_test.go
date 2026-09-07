// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"net"
	"testing"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// TestUnauthenticatedFrame_DropAndSurvive proves the drop-and-count-survive posture (Disc2): an
// unauthenticated or out-of-sequence frame injected into an ESTABLISHED session is DROPPED and
// COUNTED, and the association SURVIVES — a subsequent legitimate sealed frame still delivers.
// Before the fix, Recv surfaced an error on the junk frame and the caller's loop ended, so a
// single injected cleartext / forged / replayed frame killed the association (a trivial off-path
// DoS). The draft mandates the opposite (a forged frame MUST be dropped, the connection survives),
// matching DTLS 1.3 RFC 9147 §4.5.2 and QUIC RFC 9001 §6.6.2.
//
// The "delivers" assertion is the load-bearing SURVIVES proof and the mutation anchor: revert the
// drop-and-continue to a surface-error return and the legit frame never arrives.
func TestUnauthenticatedFrame_DropAndSurvive(t *testing.T) {
	p := npamp.ProfileStandard

	cases := []struct {
		name  string
		junk  func(master []byte) []byte      // one junk frame injected from the client side
		count func(c *Conn) uint64            // the drop counter that must increment
	}{
		{
			name: "cleartext",
			junk: func(master []byte) []byte {
				// A cleartext (FlagENC-clear) frame on Control — a bare header, no AEAD seal.
				f := npamp.Frame{Type: uint16(npamp.FrameKeyUpdate), Channel: uint16(npamp.ChanControl), Seq: 0}
				w, _ := f.MarshalBinary()
				return w
			},
			count: func(c *Conn) uint64 { u, _ := c.SecurityDrops(); return u },
		},
		{
			name: "aead_fail",
			junk: func(master []byte) []byte {
				// A FlagENC frame whose ciphertext is corrupt — the header (incl CRC) is intact so
				// it parses, but the AEAD open fails (a forged / tampered sealed frame).
				w, err := sealFrame(master, npamp.DirClientToServer, npamp.ChanControl, 0, npamp.FrameType(0x00FE), []byte("x"), p)
				if err != nil {
					return nil
				}
				w[npamp.HeaderSize]++ // flip the first ciphertext octet
				return w
			},
			count: func(c *Conn) uint64 { u, _ := c.SecurityDrops(); return u },
		},
		{
			name: "out_of_sequence",
			junk: func(master []byte) []byte {
				// A validly-sealed frame at the WRONG sequence (a replay/reorder): seq 5 where 0 is
				// expected on Control. Dropped BEFORE the AEAD open (no work on attacker input).
				w, err := sealFrame(master, npamp.DirClientToServer, npamp.ChanControl, 5, npamp.FrameType(0x00FE), nil, p)
				if err != nil {
					return nil
				}
				return w
			},
			count: func(c *Conn) uint64 { _, o := c.SecurityDrops(); return o },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			master := guardTestMaster()
			a, b := net.Pipe()
			server := newConn(b, master, nil, npamp.DirServerToClient, npamp.DirClientToServer)
			t.Cleanup(func() { _ = a.Close(); _ = server.Close() })

			ctx, cancel := stDeadlineCtx(t)
			defer cancel()

			type recvOut struct {
				ch  npamp.ChannelID
				pt  []byte
				err error
			}
			out := make(chan recvOut, 1)
			go func() {
				ch, _, pt, err := server.Recv(ctx)
				out <- recvOut{ch, pt, err}
			}()

			junkWire := tc.junk(master)
			if junkWire == nil {
				t.Fatalf("%s: failed to build the junk frame", tc.name)
			}
			// A legitimate application frame on ChanMemory at seq 0 — must deliver after the junk
			// is dropped.
			legitWire, err := sealFrame(master, npamp.DirClientToServer, npamp.ChanMemory, 0, npamp.FrameType(0x0120), []byte("hello"), p)
			if err != nil {
				t.Fatalf("seal legit frame: %v", err)
			}

			// Inject junk then the legit frame from a writer goroutine, so a RED (the server
			// returns early on the junk) fails on the survival assertion below, not on a blocked
			// write to a reader that has gone away.
			go func() {
				stSetDeadline(t, a)
				if e := writeFrame(a, junkWire); e != nil {
					return
				}
				_ = writeFrame(a, legitWire)
			}()

			r := <-out
			// SURVIVES: the legit frame delivered rather than the junk ending the association.
			if r.err != nil {
				t.Fatalf("%s: association did not survive — Recv returned %v (the junk frame killed it?)", tc.name, r.err)
			}
			if r.ch != npamp.ChanMemory || string(r.pt) != "hello" {
				t.Fatalf("%s: delivered ch %d pt %q, want ChanMemory %q", tc.name, r.ch, r.pt, "hello")
			}
			// COUNTED: the matching drop counter incremented (the draft's SHOULD-count).
			if got := tc.count(server); got != 1 {
				t.Fatalf("%s: drop counter = %d, want 1 (the junk frame was not counted)", tc.name, got)
			}
		})
	}
}
