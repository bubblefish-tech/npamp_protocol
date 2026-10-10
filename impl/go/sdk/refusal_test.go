// SPDX-License-Identifier: Apache-2.0

package sdk_test

// This package implements the Standard profile only. A Config that offers or
// accepts the High or Sovereign profile is refused with
// npamp.ErrNoSuiteForProfile BEFORE any wire I/O, by every entry point. Each
// test asserts the specific error (errors.Is) AND that nothing reached the
// transport: a plain listener counts accepted connections, and a net.Pipe peer
// counts bytes received.

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
	"github.com/bubblefish-tech/npamp_protocol/impl/go/sdk"
)

var refusedProfiles = []struct {
	name string
	set  []npamp.Profile
}{
	{"High", []npamp.Profile{npamp.ProfileHigh}},
	{"Sovereign", []npamp.Profile{npamp.ProfileSovereign}},
	{"Standard_then_High", []npamp.Profile{npamp.ProfileStandard, npamp.ProfileHigh}},
	{"Sovereign_then_Standard", []npamp.Profile{npamp.ProfileSovereign, npamp.ProfileStandard}},
}

func refusalConfig(profiles []npamp.Profile) sdk.Config {
	return sdk.Config{
		TLSConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // loopback refusal test, no TLS session is ever established
		Profiles:  profiles,
	}
}

// countingListener accepts connections in the background and counts them.
type countingListener struct {
	ln    net.Listener
	count atomic.Int64
}

func newCountingListener(t *testing.T) *countingListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	c := &countingListener{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.count.Add(1)
			go func() { _, _ = io.Copy(io.Discard, conn); _ = conn.Close() }()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return c
}

// accepted returns how many connections reached the listener, after proving the
// accept loop has drained everything queued before it: a sentinel connection is
// sent and the count is read once the sentinel itself has been counted. TCP
// accept order is FIFO, so any earlier connection was counted first.
func (c *countingListener) accepted(t *testing.T) int64 {
	t.Helper()
	before := c.count.Load()
	s, err := net.Dial("tcp", c.ln.Addr().String())
	if err != nil {
		t.Fatalf("sentinel dial: %v", err)
	}
	defer s.Close()
	deadline := time.Now().Add(3 * time.Second)
	for c.count.Load() == before {
		if time.Now().After(deadline) {
			t.Fatal("sentinel connection was never accepted")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return c.count.Load() - 1 // exclude the sentinel
}

func TestDialRefusesHighAndSovereignBeforeAnyConnection(t *testing.T) {
	for _, tc := range refusedProfiles {
		t.Run(tc.name, func(t *testing.T) {
			srv := newCountingListener(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := sdk.Dial(ctx, srv.ln.Addr().String(), refusalConfig(tc.set))
			if conn != nil {
				_ = conn.Close()
				t.Fatal("Dial returned a connection for a refused profile set")
			}
			if !errors.Is(err, npamp.ErrNoSuiteForProfile) {
				t.Fatalf("Dial error = %v, want errors.Is npamp.ErrNoSuiteForProfile", err)
			}
			if n := srv.accepted(t); n != 0 {
				t.Fatalf("%d connection(s) reached the server; the refusal must precede any wire I/O", n)
			}
		})
	}
}

func TestDialWithFallbackRefusesHighAndSovereignBeforeAnyConnection(t *testing.T) {
	for _, tc := range refusedProfiles {
		t.Run(tc.name, func(t *testing.T) {
			srv := newCountingListener(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, _, err := sdk.DialWithFallback(ctx, srv.ln.Addr().String(), sdk.FallbackConfig{Config: refusalConfig(tc.set)})
			if conn != nil {
				_ = conn.Close()
				t.Fatal("DialWithFallback returned a connection for a refused profile set")
			}
			if !errors.Is(err, npamp.ErrNoSuiteForProfile) {
				t.Fatalf("DialWithFallback error = %v, want errors.Is npamp.ErrNoSuiteForProfile", err)
			}
			if n := srv.accepted(t); n != 0 {
				t.Fatalf("%d connection(s) reached the server; the refusal must precede any wire I/O", n)
			}
		})
	}
}

func TestListenRefusesHighAndSovereignBeforeBinding(t *testing.T) {
	for _, tc := range refusedProfiles {
		t.Run(tc.name, func(t *testing.T) {
			l, err := sdk.Listen("127.0.0.1:0", refusalConfig(tc.set))
			if l != nil {
				_ = l.Close()
				t.Fatal("Listen returned a listener for a refused profile set")
			}
			if !errors.Is(err, npamp.ErrNoSuiteForProfile) {
				t.Fatalf("Listen error = %v, want errors.Is npamp.ErrNoSuiteForProfile", err)
			}
		})
	}
}

// pipeBytes drains the peer end of a net.Pipe and reports how many bytes the
// code under test wrote before the pipe was closed.
type pipeBytes struct {
	n    atomic.Int64
	done chan struct{}
}

func drainPipe(peer net.Conn) *pipeBytes {
	p := &pipeBytes{done: make(chan struct{})}
	go func() {
		defer close(p.done)
		buf := make([]byte, 4096)
		for {
			n, err := peer.Read(buf)
			p.n.Add(int64(n))
			if err != nil {
				return
			}
		}
	}()
	return p
}

func TestRawEntryPointsRefuseHighAndSovereignBeforeAnyWrite(t *testing.T) {
	entries := []struct {
		name string
		call func(ctx context.Context, raw net.Conn, cfg sdk.Config) (*sdk.Conn, error)
	}{
		{"DialConn", sdk.DialConn},
		{"AcceptConn", sdk.AcceptConn},
		{"DialRaw", sdk.DialRaw},
		{"AcceptRaw", sdk.AcceptRaw},
	}
	for _, e := range entries {
		for _, tc := range refusedProfiles {
			t.Run(e.name+"/"+tc.name, func(t *testing.T) {
				a, b := net.Pipe()
				defer b.Close()
				seen := drainPipe(b)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				conn, err := e.call(ctx, a, refusalConfig(tc.set))
				_ = a.Close()
				<-seen.done
				if conn != nil {
					_ = conn.Close()
					t.Fatalf("%s returned a connection for a refused profile set", e.name)
				}
				if !errors.Is(err, npamp.ErrNoSuiteForProfile) {
					t.Fatalf("%s error = %v, want errors.Is npamp.ErrNoSuiteForProfile", e.name, err)
				}
				if n := seen.n.Load(); n != 0 {
					t.Fatalf("%s wrote %d byte(s) before refusing; the refusal must precede any wire I/O", e.name, n)
				}
			})
		}
	}
}
