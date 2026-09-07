// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"context"
	"fmt"
	"net"
	"time"
)

// TransportKind names which physical path an association completed over,
// for FallbackTelemetry (R11).
type TransportKind string

const (
	// TransportQUIC never appears as FallbackTelemetry.Winner in this
	// repository (see FallbackConfig's doc comment) — it is defined for a
	// future N-PAMP-over-QUIC transport binding to reuse this file's
	// racing/telemetry contract without a breaking rename.
	TransportQUIC   TransportKind = "quic"
	TransportTCPTLS TransportKind = "tcp-tls"
)

// quicInitialPad is the minimum size (octets) of a QUIC Initial packet once
// padded, per RFC 9000 section 14.1 ("Initial datagrams MUST be padded to at
// least the smallest allowed maximum datagram size of 1200 bytes"). The
// QUIC-path probe below sends a datagram this size so that a network path
// which black-holes traffic above a size threshold — a real, documented QUIC
// deployment failure (PMTU black hole: an on-path device drops oversized
// datagrams and blocks the ICMP "fragmentation needed" message PMTUD relies
// on) — fails the probe exactly as it would fail a real QUIC handshake.
const quicInitialPad = 1200

// FallbackConfig configures DialWithFallback's race between a QUIC-path
// reachability probe and the existing, real TCP+TLS N-PAMP handshake (Dial).
//
// Honest scope limitation. impl/go has no QUIC transport: no QUIC dependency
// (go.mod), no N-PAMP-over-QUIC wire mapping, and no QUIC record layer.
// probeQUICPath therefore does NOT attempt an N-PAMP handshake over QUIC —
// it performs a real UDP round trip shaped like a padded QUIC Initial
// datagram, to prove (or disprove) that the path is reachable at all. A
// successful probe is recorded in telemetry but never yields a live *Conn:
// this file's only source of an authenticated N-PAMP session is the real
// TCP+TLS leg (Dial). Concretely this means DialWithFallback exercises the
// FAILURE side of the race today (QUIC-blocked / ECN-blackholed /
// PMTU-blackholed all fall through to TCP+TLS, per R11's three named
// scenarios); a future QUIC transport binding would only need to replace
// probeQUICPath's success path with a real N-PAMP-over-QUIC Dial, keeping
// this file's racing and FallbackTelemetry contract unchanged.
type FallbackConfig struct {
	Config

	// QUICAddr is the UDP "host:port" the QUIC-path probe targets. Leave
	// empty to skip the QUIC leg entirely — DialWithFallback then behaves
	// exactly like Dial (used by tests that want a TCP+TLS-only baseline).
	QUICAddr string

	// QUICProbeTimeout bounds how long the QUIC-path probe waits for a
	// reply. Defaults to 300ms.
	QUICProbeTimeout time.Duration

	// ConnectionAttemptDelay staggers the start of the TCP+TLS leg behind
	// the QUIC probe, Happy-Eyeballs style (RFC 8305 describes the same
	// stagger for IPv6-vs-IPv4; N-PAMP applies it to QUIC-vs-TCP/TLS), so a
	// healthy QUIC path is given a head start before the fallback socket
	// opens. Zero (the default) starts both legs immediately.
	ConnectionAttemptDelay time.Duration

	// QUICProbeECNMarked, when true, sets an application-level marker octet
	// in the probe datagram standing in for an ECT/CE-marked IP header (a
	// real ECN codepoint requires a raw socket — golang.org/x/net/ipv4
	// SetTOS — which this dependency-free harness intentionally does not
	// take on). It lets a test simulate the documented "ECN-blackholed"
	// failure mode — a middlebox that discards ECN-marked traffic while
	// passing unmarked traffic — by having the simulated network path key
	// its drop decision off this marker instead of a real DSCP/ECN bit.
	QUICProbeECNMarked bool
}

// FallbackTelemetry records which path an association completed over and
// why, so an operator can observe fallback decisions instead of inferring
// them (R11 "telemetry records which transport won").
type FallbackTelemetry struct {
	Winner        TransportKind
	QUICAttempted bool
	QUICErr       error
	QUICRTT       time.Duration
	TCPTLSErr     error
	TCPTLSRTT     time.Duration
	Started       time.Time
	Decided       time.Time
}

// probeQUICPath performs one real UDP round trip to addr using a datagram
// padded to quicInitialPad octets. It returns the observed round-trip time
// on any reply, or an error naming why the path is unusable — unreachable
// (QUIC-blocked: nothing answers), or a timeout after sending the full-size
// probe (ECN-blackholed / PMTU-blackholed: a path that answers a small probe
// but silently drops a QUIC-Initial-sized or ECN-marked one presents
// identically at this layer — an unanswered send).
//
// probeQUICPath does not manipulate IP-header ECN codepoints (that needs a
// raw socket / golang.org/x/net/ipv4, which this harness deliberately avoids
// to stay dependency-free and portable); an ECN-blackhole scenario is
// exercised by having the simulated network path drop datagrams by an
// application-level marker instead of a real DSCP/ECN bit, which reproduces
// the same observable symptom this function can detect: a sent probe that
// never gets a reply.

// quicProbeECNMarker is the application-level stand-in for an ECT/CE IP
// header codepoint (octet 0 of the padded probe datagram). It carries no
// real ECN semantics — see FallbackConfig.QUICProbeECNMarked.
const quicProbeECNMarker = 0x01

func probeQUICPath(ctx context.Context, addr string, timeout time.Duration, ecnMarked bool) (time.Duration, error) {
	if timeout <= 0 {
		timeout = 300 * time.Millisecond
	}
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return 0, fmt.Errorf("npamp/sdk: resolve quic path %s: %w", addr, err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return 0, fmt.Errorf("npamp/sdk: dial quic path %s: %w", addr, err)
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return 0, fmt.Errorf("npamp/sdk: set quic probe deadline: %w", err)
	}

	probe := make([]byte, quicInitialPad)
	copy(probe[1:], []byte("NPAMP-QUIC-PATH-PROBE"))
	if ecnMarked {
		probe[0] = quicProbeECNMarker
	}

	sent := time.Now()
	if _, err := conn.Write(probe); err != nil {
		return 0, fmt.Errorf("npamp/sdk: quic path %s send: %w", addr, err)
	}
	reply := make([]byte, quicInitialPad)
	n, err := conn.Read(reply)
	if err != nil {
		return 0, fmt.Errorf("npamp/sdk: quic path %s unreachable: %w", addr, err)
	}
	if n == 0 {
		return 0, fmt.Errorf("npamp/sdk: quic path %s: empty reply", addr)
	}
	return time.Since(sent), nil
}

// DialWithFallback races a QUIC-path reachability probe against the real
// TCP+TLS N-PAMP handshake (Dial) and returns the resulting association.
// Because this repository's QUIC leg never completes a full N-PAMP session
// (see FallbackConfig's doc comment), the returned *Conn — when err is nil —
// is always the product of the real Dial call: the SAME negotiated ALPN
// ("n-pamp/3", enforced inside Dial), the SAME Profile negotiation, and the
// SAME mutual-authentication guarantees a direct Dial(ctx, addr, cfg.Config)
// would produce. A caller cannot observe, from the Conn alone, that a QUIC
// path was attempted and failed — the fallback is transparent (R11).
//
// DialWithFallback waits for both legs to settle (bounded by
// QUICProbeTimeout) before returning, so FallbackTelemetry is always
// complete; it does not return as soon as the TCP+TLS leg succeeds while a
// slower QUIC probe is still outstanding. This trades a small, bounded
// amount of latency (at most QUICProbeTimeout) for telemetry that always
// explains the QUIC leg's outcome, which the test suite and any operator
// dashboard both depend on.
func DialWithFallback(ctx context.Context, addr string, cfg FallbackConfig) (*Conn, *FallbackTelemetry, error) {
	tel := &FallbackTelemetry{Started: time.Now()}

	if cfg.QUICAddr == "" {
		conn, err := Dial(ctx, addr, cfg.Config)
		tel.TCPTLSErr = err
		tel.Decided = time.Now()
		if err != nil {
			return nil, tel, err
		}
		tel.Winner = TransportTCPTLS
		return conn, tel, nil
	}
	tel.QUICAttempted = true

	type legResult struct {
		kind TransportKind
		conn *Conn
		rtt  time.Duration
		err  error
	}
	resCh := make(chan legResult, 2)

	go func() {
		rtt, err := probeQUICPath(ctx, cfg.QUICAddr, cfg.QUICProbeTimeout, cfg.QUICProbeECNMarked)
		resCh <- legResult{kind: TransportQUIC, rtt: rtt, err: err}
	}()

	go func() {
		if cfg.ConnectionAttemptDelay > 0 {
			t := time.NewTimer(cfg.ConnectionAttemptDelay)
			defer t.Stop()
			select {
			case <-t.C:
			case <-ctx.Done():
				resCh <- legResult{kind: TransportTCPTLS, err: ctx.Err()}
				return
			}
		}
		start := time.Now()
		conn, err := Dial(ctx, addr, cfg.Config)
		resCh <- legResult{kind: TransportTCPTLS, conn: conn, rtt: time.Since(start), err: err}
	}()

	var tcpConn *Conn
	for i := 0; i < 2; i++ {
		r := <-resCh
		switch r.kind {
		case TransportQUIC:
			tel.QUICErr = r.err
			tel.QUICRTT = r.rtt
			// A successful probe is recorded but never wins the race in
			// this repository — see the doc comment above.
		case TransportTCPTLS:
			tel.TCPTLSErr = r.err
			tel.TCPTLSRTT = r.rtt
			tcpConn = r.conn
		}
	}
	tel.Decided = time.Now()

	if tel.TCPTLSErr == nil {
		tel.Winner = TransportTCPTLS
		return tcpConn, tel, nil
	}
	return nil, tel, fmt.Errorf("npamp/sdk: fallback dial %s failed: quic=%v tcp+tls=%v", addr, tel.QUICErr, tel.TCPTLSErr)
}
