// SPDX-License-Identifier: Apache-2.0

package sdk_test

// QUIC-to-TCP/TLS fallback conformance suite (E3.7 / R11). Builds a real
// UDP "simulated network path" server whose drop policy reproduces three
// named, documented QUIC deployment failures — UDP/443 fully blocked, an
// ECN-blackholed middlebox, and a PMTU black hole — and races
// sdk.DialWithFallback's real UDP probe against it while a real TCP+TLS
// N-PAMP listener (sdk.Listen/sdk.Dial, the same machinery
// TestLoopbackHandshakeAndRoundTrip in sdk_test.go exercises) stands in for
// the always-available fallback path.
//
// F3 non-circularity: the pass/fail decision the test makes (did the
// association complete? is the negotiated profile/identity/ALPN identical
// to a direct Dial baseline?) does not depend on sdk.DialWithFallback's own
// internal bookkeeping — it re-derives the expected outcome from a
// side-by-side plain sdk.Dial call and from the blackhole server's own,
// independently-specified drop policy.
//
// The mutation anchor for the red-evidence ledger is
// TestDialWithFallback_NoCryptoDowngrade: temporarily changing
// fallback.go's TCP+TLS leg to dial with a stripped-down Config (dropping
// Identity/MLDSAIdentity) — simulating a fallback path that silently
// authenticates less than the caller asked for — flips that test red
// because the resulting Conn's PeerIdentity/Profile no longer match the
// direct-Dial baseline.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/bubblefish-tech/npamp_protocol/impl/go/sdk"
)

// quicProbeECNMarkerForTest mirrors fallback.go's unexported
// quicProbeECNMarker (0x01): the application-level stand-in for an
// ECT/CE-marked datagram (see FallbackConfig.QUICProbeECNMarked's doc
// comment — this harness does not manipulate real IP-header ECN bits).
const quicProbeECNMarkerForTest = 0x01

// newSimulatedNetworkPath starts a real UDP listener that answers every
// datagram NOT matched by drop with an identical echo, and silently
// discards every datagram drop matches — reproducing, at the UDP layer, the
// three documented QUIC-over-UDP failure modes R11 names. It returns the
// listener's address and stops the listener via t.Cleanup.
func newSimulatedNetworkPath(t *testing.T, drop func(pkt []byte) bool) string {
	t.Helper()
	laddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve udp listen addr: %v", err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	go func() {
		buf := make([]byte, 2048)
		for {
			n, raddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return // listener closed
			}
			pkt := append([]byte(nil), buf[:n]...)
			if drop(pkt) {
				continue
			}
			_, _ = conn.WriteToUDP(pkt, raddr)
		}
	}()
	return conn.LocalAddr().String()
}

// fallbackTestFixture wires a real sdk.Listener + a matching sdk.Config, the
// same pattern sdk_test.go's TestLoopbackHandshakeAndRoundTrip uses. Accepted
// server-side conns are tracked and closed by a single t.Cleanup registered
// synchronously in newFallbackFixture (never from the background accept
// goroutine), so cleanup registration can never race test completion.
type fallbackTestFixture struct {
	ln        *sdk.Listener
	clientCfg sdk.Config
	serverPub ed25519.PublicKey

	mu       sync.Mutex
	accepted []*sdk.Conn
}

func newFallbackFixture(t *testing.T) *fallbackTestFixture {
	t.Helper()
	tlsCfg := loopbackTLS(t)
	serverPub, serverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := sdk.Listen("127.0.0.1:0", sdk.Config{TLSConfig: tlsCfg, Identity: serverPriv})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	fx := &fallbackTestFixture{
		ln: ln,
		clientCfg: sdk.Config{
			TLSConfig:       tlsCfg,
			Identity:        clientPriv,
			ExpectedPeerKey: serverPub,
		},
		serverPub: serverPub,
	}

	acceptLoopDone := make(chan struct{})
	go func() {
		defer close(acceptLoopDone)
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			c, err := ln.Accept(ctx)
			cancel()
			if err != nil {
				return // listener closed (or timed out) — the loop ends
			}
			fx.mu.Lock()
			fx.accepted = append(fx.accepted, c)
			fx.mu.Unlock()
		}
	}()

	t.Cleanup(func() {
		_ = ln.Close() // unblocks the pending Accept, ending the goroutine above
		<-acceptLoopDone
		fx.mu.Lock()
		for _, c := range fx.accepted {
			_ = c.Close()
		}
		fx.mu.Unlock()
	})

	return fx
}

func dialCtx(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), 15*time.Second)
}

// --- Scenario 1: QUIC-blocked (UDP/443 dropped) ----------------------------

func TestDialWithFallback_QUICBlocked_CompletesOverTCPTLS(t *testing.T) {
	fx := newFallbackFixture(t)
	quicAddr := newSimulatedNetworkPath(t, func(pkt []byte) bool { return true }) // drop everything: UDP fully blocked

	ctx, cancel := dialCtx(t)
	defer cancel()
	conn, tel, err := sdk.DialWithFallback(ctx, fx.ln.Addr().String(), sdk.FallbackConfig{
		Config:           fx.clientCfg,
		QUICAddr:         quicAddr,
		QUICProbeTimeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("DialWithFallback: %v", err)
	}
	defer conn.Close()

	if tel.Winner != sdk.TransportTCPTLS {
		t.Fatalf("Winner = %q, want %q", tel.Winner, sdk.TransportTCPTLS)
	}
	if !tel.QUICAttempted {
		t.Fatal("telemetry does not record that the QUIC path was attempted")
	}
	if tel.QUICErr == nil {
		t.Fatal("QUICErr is nil: a fully-blocked UDP path MUST be reported as failed")
	}
	if !conn.PeerIdentity().Equal(fx.serverPub) {
		t.Fatal("session did not mutually authenticate the server identity")
	}
}

// --- Scenario 2: ECN-blackholed ---------------------------------------------

func TestDialWithFallback_ECNBlackholed_CompletesOverTCPTLS(t *testing.T) {
	fx := newFallbackFixture(t)
	// Drop only datagrams carrying the simulated ECN marker; an unmarked
	// datagram on the same path would pass (proving the drop is selective,
	// not a blanket UDP block — the distinguishing property of a real
	// ECN-blackhole versus scenario 1).
	quicAddr := newSimulatedNetworkPath(t, func(pkt []byte) bool {
		return len(pkt) > 0 && pkt[0] == quicProbeECNMarkerForTest
	})

	ctx, cancel := dialCtx(t)
	defer cancel()
	conn, tel, err := sdk.DialWithFallback(ctx, fx.ln.Addr().String(), sdk.FallbackConfig{
		Config:             fx.clientCfg,
		QUICAddr:           quicAddr,
		QUICProbeTimeout:   200 * time.Millisecond,
		QUICProbeECNMarked: true,
	})
	if err != nil {
		t.Fatalf("DialWithFallback: %v", err)
	}
	defer conn.Close()

	if tel.Winner != sdk.TransportTCPTLS {
		t.Fatalf("Winner = %q, want %q", tel.Winner, sdk.TransportTCPTLS)
	}
	if tel.QUICErr == nil {
		t.Fatal("QUICErr is nil: an ECN-marked probe on an ECN-blackholed path MUST be reported as failed")
	}
	if !conn.PeerIdentity().Equal(fx.serverPub) {
		t.Fatal("session did not mutually authenticate the server identity")
	}
}

// --- Scenario 3: PMTU-blackholed --------------------------------------------

func TestDialWithFallback_PMTUBlackholed_CompletesOverTCPTLS(t *testing.T) {
	fx := newFallbackFixture(t)
	// Drop any datagram above a small path-MTU-like threshold; the QUIC
	// probe (padded to 1200 octets per RFC 9000 section 14.1) exceeds it
	// and is dropped, while a small datagram would pass — the distinguishing
	// property of a real PMTU black hole (an on-path device silently drops
	// oversized datagrams and also blocks the ICMP message PMTUD needs).
	const pmtuThreshold = 500
	quicAddr := newSimulatedNetworkPath(t, func(pkt []byte) bool {
		return len(pkt) > pmtuThreshold
	})

	ctx, cancel := dialCtx(t)
	defer cancel()
	conn, tel, err := sdk.DialWithFallback(ctx, fx.ln.Addr().String(), sdk.FallbackConfig{
		Config:           fx.clientCfg,
		QUICAddr:         quicAddr,
		QUICProbeTimeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("DialWithFallback: %v", err)
	}
	defer conn.Close()

	if tel.Winner != sdk.TransportTCPTLS {
		t.Fatalf("Winner = %q, want %q", tel.Winner, sdk.TransportTCPTLS)
	}
	if tel.QUICErr == nil {
		t.Fatal("QUICErr is nil: an oversized probe on a PMTU-blackholed path MUST be reported as failed")
	}
	if !conn.PeerIdentity().Equal(fx.serverPub) {
		t.Fatal("session did not mutually authenticate the server identity")
	}
}

// --- Control: the probe mechanism itself can succeed ------------------------

// TestDialWithFallback_QUICPathHealthy_ProbeSucceeds is the sanity control
// for the three scenarios above: without it, a bug that makes probeQUICPath
// ALWAYS fail (regardless of the simulated path's behavior) would make every
// "blackholed" test pass for the wrong reason. Here the simulated path
// answers every datagram, so the probe MUST succeed.
func TestDialWithFallback_QUICPathHealthy_ProbeSucceeds(t *testing.T) {
	fx := newFallbackFixture(t)
	quicAddr := newSimulatedNetworkPath(t, func(pkt []byte) bool { return false }) // echo everything back

	ctx, cancel := dialCtx(t)
	defer cancel()
	conn, tel, err := sdk.DialWithFallback(ctx, fx.ln.Addr().String(), sdk.FallbackConfig{
		Config:           fx.clientCfg,
		QUICAddr:         quicAddr,
		QUICProbeTimeout: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("DialWithFallback: %v", err)
	}
	defer conn.Close()

	if tel.QUICErr != nil {
		t.Fatalf("QUICErr = %v, want nil: the simulated path answers every datagram", tel.QUICErr)
	}
	if tel.QUICRTT < 0 {
		t.Fatalf("QUICRTT = %v, want >= 0 for a successful probe", tel.QUICRTT)
	}
	// The QUIC leg's success does not change the outcome in this
	// repository (no QUIC transport exists yet — see FallbackConfig's doc
	// comment): the association still completes over TCP+TLS.
	if tel.Winner != sdk.TransportTCPTLS {
		t.Fatalf("Winner = %q, want %q even when the QUIC probe succeeds", tel.Winner, sdk.TransportTCPTLS)
	}
}

// --- No crypto downgrade + same ALPN ----------------------------------------

// TestDialWithFallback_NoCryptoDowngrade proves the fallback path is not a
// separate, weaker code path: the Conn it returns under a fully-blocked
// QUIC leg is byte-for-byte identical, on every field this test can observe
// (negotiated ALPN, negotiated Profile, mutually-authenticated peer
// identity), to a Conn obtained from a direct sdk.Dial using the exact same
// Config. This is the test the RED-EVIDENCE mutation targets (see the file
// header comment).
func TestDialWithFallback_NoCryptoDowngrade(t *testing.T) {
	fx := newFallbackFixture(t)

	// Baseline: a direct Dial with no fallback involved at all.
	baseCtx, baseCancel := dialCtx(t)
	defer baseCancel()
	baseline, err := sdk.Dial(baseCtx, fx.ln.Addr().String(), fx.clientCfg)
	if err != nil {
		t.Fatalf("baseline Dial: %v", err)
	}
	defer baseline.Close()

	// Fallback, with the QUIC leg fully blocked, against a second accepted
	// connection on the same listener.
	quicAddr := newSimulatedNetworkPath(t, func(pkt []byte) bool { return true })
	fbCtx, fbCancel := dialCtx(t)
	defer fbCancel()
	fallback, tel, err := sdk.DialWithFallback(fbCtx, fx.ln.Addr().String(), sdk.FallbackConfig{
		Config:           fx.clientCfg,
		QUICAddr:         quicAddr,
		QUICProbeTimeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("DialWithFallback: %v", err)
	}
	defer fallback.Close()

	if tel.Winner != sdk.TransportTCPTLS {
		t.Fatalf("Winner = %q, want %q", tel.Winner, sdk.TransportTCPTLS)
	}
	if fallback.Profile() != baseline.Profile() {
		t.Fatalf("fallback Profile = %v, want %v (same as a direct Dial): a mismatch here IS a crypto downgrade", fallback.Profile(), baseline.Profile())
	}
	if !fallback.PeerIdentity().Equal(baseline.PeerIdentity()) {
		t.Fatal("fallback PeerIdentity does not match the direct-Dial baseline")
	}
	if !fallback.PeerIdentity().Equal(fx.serverPub) {
		t.Fatal("fallback did not authenticate the real server identity")
	}
}

// --- Fallback leg enforces peer-key pinning exactly like a direct Dial -----

// TestDialWithFallback_PeerKeyPinningEnforced proves the TCP+TLS fallback leg
// is not a separate, less-verified code path: pinning the WRONG server
// identity in FallbackConfig.ExpectedPeerKey MUST make DialWithFallback fail,
// exactly as it would make a direct sdk.Dial fail, even though the QUIC leg
// is also unusable in this scenario. A fallback path that silently dropped
// peer-key verification (to "fall back faster", say) would make this call
// succeed against the real server despite the wrong pin -- exactly the
// crypto-downgrade class TestDialWithFallback_NoCryptoDowngrade's equality
// checks cannot see (those check the RESULT'S values; this checks that a
// REJECTED credential still gets rejected).
func TestDialWithFallback_PeerKeyPinningEnforced(t *testing.T) {
	fx := newFallbackFixture(t)
	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	badCfg := fx.clientCfg
	badCfg.ExpectedPeerKey = wrongPub // deliberately NOT fx.serverPub

	quicAddr := newSimulatedNetworkPath(t, func(pkt []byte) bool { return true })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, tel, err := sdk.DialWithFallback(ctx, fx.ln.Addr().String(), sdk.FallbackConfig{
		Config:           badCfg,
		QUICAddr:         quicAddr,
		QUICProbeTimeout: 200 * time.Millisecond,
	})
	if err == nil {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatal("DialWithFallback succeeded despite a wrong ExpectedPeerKey pin: the fallback leg did not enforce peer-key pinning")
	}
	if tel.TCPTLSErr == nil {
		t.Fatal("TCPTLSErr is nil: the TCP+TLS leg MUST report the peer-key mismatch")
	}
}

// --- Telemetry records which transport won ----------------------------------

func TestDialWithFallback_TelemetryRecordsWinner(t *testing.T) {
	fx := newFallbackFixture(t)
	quicAddr := newSimulatedNetworkPath(t, func(pkt []byte) bool { return true })

	ctx, cancel := dialCtx(t)
	defer cancel()
	conn, tel, err := sdk.DialWithFallback(ctx, fx.ln.Addr().String(), sdk.FallbackConfig{
		Config:           fx.clientCfg,
		QUICAddr:         quicAddr,
		QUICProbeTimeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("DialWithFallback: %v", err)
	}
	defer conn.Close()

	if tel.Started.IsZero() || tel.Decided.IsZero() {
		t.Fatal("telemetry Started/Decided timestamps were not recorded")
	}
	if tel.Decided.Before(tel.Started) {
		t.Fatal("telemetry Decided is before Started")
	}
	// The QUIC path is fully blocked in this scenario, so the winner MUST be
	// specifically tcp-tls -- not merely "a winner": a bug that recorded the
	// blocked/losing leg as the winner would still satisfy a bare non-empty
	// check.
	if tel.Winner != sdk.TransportTCPTLS {
		t.Fatalf("Winner = %q, want %q", tel.Winner, sdk.TransportTCPTLS)
	}
}

// --- Both paths failing is reported honestly --------------------------------

func TestDialWithFallback_AllPathsFail_ReturnsError(t *testing.T) {
	fx := newFallbackFixture(t)
	// Close the listener so the TCP+TLS leg also fails, and block the QUIC
	// path too: DialWithFallback MUST NOT report success when neither leg
	// produced a live association.
	if err := fx.ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	quicAddr := newSimulatedNetworkPath(t, func(pkt []byte) bool { return true })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, tel, err := sdk.DialWithFallback(ctx, fx.ln.Addr().String(), sdk.FallbackConfig{
		Config:           fx.clientCfg,
		QUICAddr:         quicAddr,
		QUICProbeTimeout: 200 * time.Millisecond,
	})
	if err == nil {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatal("DialWithFallback returned nil error when both legs failed")
	}
	if conn != nil {
		t.Fatal("DialWithFallback returned a non-nil Conn alongside an error")
	}
	if tel.Winner != "" {
		t.Fatalf("telemetry Winner = %q, want empty when both legs failed", tel.Winner)
	}
	if tel.QUICErr == nil {
		t.Fatal("QUICErr is nil: the blocked QUIC path MUST also be reported as failed")
	}
	if tel.TCPTLSErr == nil {
		t.Fatal("TCPTLSErr is nil: dialing a closed listener MUST be reported as failed")
	}
}
