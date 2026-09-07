// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package relay

import (
	"context"
	"net"
	"strconv"
	"testing"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// BenchmarkRelayFrameRate measures the sustained frame-forwarding rate of Relay.Run: how
// many well-formed frames per second one Relay instance can copy from one leg to the
// other, including the real per-frame cost this package's own forward() actually pays —
// readRawFrame's header parse + declared-length bound check, Frame.UnmarshalBinary's
// CRC32C validation and wire-version/reserved-field checks, and writeRawFrame's raw-byte
// write to the destination leg (the relay never derives an AEAD key or opens a payload,
// so this is genuinely the relay's OWN forwarding cost, not an AEAD or handshake cost —
// those are covered by ../aead_bench_test.go and ../sdk/handshake_bench_test.go
// respectively).
//
// Measure with a NON-race build: `cd impl/go && GOWORK=off go test -bench=BenchmarkRelayFrameRate
// -benchmem -run=^$ ./relay/...`. Do not pin a headline ns/op or frames/sec captured under
// `go test -race` -- race instrumentation distorts timings (see the repo-wide convention
// this comment mirrors from aead_bench_test.go / handshake_bench_test.go).
//
// Deliberately uses the classic `for i := 0; i < b.N; i++` form (not the newer
// `for b.Loop()` sugar the other two benchmark files in this repo use) rather than
// `for b.Loop()`: this is a genuine producer/consumer benchmark — a background goroutine
// WRITES exactly b.N frames onto one leg of a real net.Pipe (unbuffered: a Write blocks
// until a matching Read consumes it — the well-known net.Pipe unbuffered-transport
// property) while the benchmark loop itself READS them back out through the relay. The
// producer needs a
// concrete, stable iteration count fixed BEFORE the loop starts so it writes exactly as
// many frames as the consumer will read — b.N (fixed for the whole timed invocation under
// the classic form) gives that; b.Loop()'s per-call adaptive iteration accounting does not
// expose the same pre-loop-stable count contract to a second, independently-iterating
// goroutine.
func BenchmarkRelayFrameRate(b *testing.B) {
	// Representative frame payload sizes: a small control frame, a typical application
	// body, and a large streamed chunk — the same size tiers aead_bench_test.go uses for
	// the AEAD seal/open benchmarks, so the two benchmark suites' size axes line up.
	for _, size := range []int{64, 1024, 16 * 1024} {
		size := size
		b.Run(benchSizeLabel(size), func(b *testing.B) {
			agentAConn, relayAConn := net.Pipe()
			relayBConn, agentBConn := net.Pipe()
			defer func() {
				_ = agentAConn.Close()
				_ = relayAConn.Close()
				_ = relayBConn.Close()
				_ = agentBConn.Close()
			}()

			rl := &Relay{A: relayAConn, B: relayBConn}
			runCtx, runCancel := context.WithCancel(context.Background())
			defer runCancel()
			runDone := make(chan error, 1)
			go func() { runDone <- rl.Run(runCtx) }()

			payload := make([]byte, size)

			writeDone := make(chan error, 1)
			go func() {
				defer close(writeDone)
				for n := 0; n < b.N; n++ {
					f := npamp.Frame{
						Type:    0x0120,
						Channel: uint16(npamp.ChanMemory),
						Seq:     uint64(n),
						Payload: payload,
					}
					wire, err := f.MarshalBinary()
					if err != nil {
						writeDone <- err
						return
					}
					if _, err := agentAConn.Write(wire); err != nil {
						writeDone <- err
						return
					}
				}
			}()

			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := readRawFrame(agentBConn, npamp.MaxFrameSize); err != nil {
					b.Fatalf("readRawFrame (frame %d/%d): %v", i, b.N, err)
				}
			}
			b.StopTimer()

			if err := <-writeDone; err != nil {
				b.Fatalf("frame producer goroutine: %v", err)
			}
			_ = agentAConn.Close()
			_ = agentBConn.Close()
			<-runDone // Run tears down both legs once either direction ends; drain it.
		})
	}
}

// benchSizeLabel renders a payload size as a benchmark sub-name (this package's own copy
// of the top-level npamp package's unexported sizeLabel in aead_bench_test.go — that
// helper is unexported in a different package, so it cannot be imported here).
func benchSizeLabel(size int) string {
	switch {
	case size < 1024:
		return strconv.Itoa(size) + "B"
	case size < 1024*1024:
		return strconv.Itoa(size/1024) + "KiB"
	default:
		return strconv.Itoa(size/(1024*1024)) + "MiB"
	}
}
