// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// drain reads and discards from r until it errors (the peer end of a net.Pipe),
// so a Conn's blocking writeWire completes in these single-Conn unit tests.
func drain(r net.Conn) {
	buf := make([]byte, 4096)
	for {
		if _, err := r.Read(buf); err != nil {
			return
		}
	}
}

// TestRatchetGenZeroByteIdentical proves R4: at generation 0 both per-direction
// roots ARE the handshake master byte-for-byte, and the derived gen-0 traffic key
// is byte-identical to the pre-ratchet schedule (DeriveTrafficSecret off the
// master). This is the parity guarantee that keeps the five delivered handshake
// KATs valid.
func TestRatchetGenZeroByteIdentical(t *testing.T) {
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(0x40 + i)
	}
	masterCopy := append([]byte(nil), master...)

	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	c := newConn(a, master, nil, npamp.DirClientToServer, npamp.DirServerToClient)

	if c.genSend.Load() != 0 || c.genRecv.Load() != 0 {
		t.Fatalf("gen-0 counters: genSend=%d genRecv=%d, want 0/0", c.genSend.Load(), c.genRecv.Load())
	}
	if !bytes.Equal(c.masterSend, masterCopy) {
		t.Fatalf("masterSend not byte-identical to the handshake master\n got  %x\n want %x", c.masterSend, masterCopy)
	}
	if !bytes.Equal(c.masterRecv, masterCopy) {
		t.Fatalf("masterRecv not byte-identical to the handshake master\n got  %x\n want %x", c.masterRecv, masterCopy)
	}

	// The gen-0 send key equals an INDEPENDENT derivation straight off the master
	// via the published traffic schedule — no ratchet generation in the leaf.
	st, err := c.sendState(npamp.ChanMemory)
	if err != nil {
		t.Fatalf("sendState: %v", err)
	}
	ts, err := npamp.DeriveTrafficSecret(masterCopy, npamp.DirClientToServer, 0, npamp.AEADAES256GCM, npamp.ChanMemory, sdkProfile)
	if err != nil {
		t.Fatal(err)
	}
	wantKey, wantIV, err := npamp.DeriveKeyIV(ts, sdkProfile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(st.key[:], wantKey[:]) || !bytes.Equal(st.iv[:], wantIV[:]) {
		t.Fatal("gen-0 traffic key/iv differ from the pre-ratchet DeriveTrafficSecret schedule")
	}
}

// TestRatchetSendTier1AdvancesAndZeroizesRoot proves the Tier-1 SEND step advances
// masterSend one generation via the one-way HKDF step, wipes the retired root in
// place (forward secrecy), and bumps genSend — the SignerRatchet advance-and-wipe
// shape at the connection root.
func TestRatchetSendTier1AdvancesAndZeroizesRoot(t *testing.T) {
	master := make([]byte, 32)
	for i := range master {
		master[i] = 0x5A
	}
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	go drain(b)
	c := newConn(a, master, nil, npamp.DirClientToServer, npamp.DirServerToClient)

	oldRoot := c.masterSend
	oldCopy := append([]byte(nil), oldRoot...)

	if err := c.RatchetSend(context.Background()); err != nil {
		t.Fatalf("RatchetSend: %v", err)
	}

	if c.genSend.Load() != 1 {
		t.Fatalf("genSend = %d after one Tier-1 step, want 1", c.genSend.Load())
	}
	if !allZero(oldRoot) {
		t.Errorf("retired send root not zeroized in place: %x", oldRoot)
	}
	if bytes.Equal(c.masterSend, oldCopy) {
		t.Fatal("masterSend unchanged after Tier-1 step (no forward step taken)")
	}
	want, err := npamp.RatchetMasterTier1(oldCopy, 1, sdkProfile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.masterSend, want) {
		t.Fatalf("masterSend after Tier-1\n got  %x\n want %x", c.masterSend, want)
	}
	// genRecv (the other direction) is untouched by a send-direction step.
	if c.genRecv.Load() != 0 {
		t.Fatalf("genRecv = %d after a send-only Tier-1 step, want 0", c.genRecv.Load())
	}
}

// TestHandleMasterRatchetTier1AdvancesRecvRoot proves the Tier-1 RECEIVE handler
// validates the announced generation, advances masterRecv identically, and wipes
// the retired root. It calls the handler directly with a well-formed marker; the
// informational ACK it spawns is drained.
func TestHandleMasterRatchetTier1AdvancesRecvRoot(t *testing.T) {
	master := make([]byte, 32)
	for i := range master {
		master[i] = 0x33
	}
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	go drain(b)
	c := newConn(a, master, nil, npamp.DirServerToClient, npamp.DirClientToServer)

	oldRoot := c.masterRecv
	oldCopy := append([]byte(nil), oldRoot...)

	// A marker for a generation OTHER than genRecv+1 must be rejected.
	if err := c.handleMasterRatchet(npamp.ChanControl, ratchetGenMarker(5)); err == nil {
		t.Fatal("handleMasterRatchet accepted a non-sequential generation (5, want 1)")
	}
	if c.genRecv.Load() != 0 {
		t.Fatalf("genRecv advanced on a rejected marker: %d", c.genRecv.Load())
	}

	if err := c.handleMasterRatchet(npamp.ChanControl, ratchetGenMarker(1)); err != nil {
		t.Fatalf("handleMasterRatchet: %v", err)
	}
	if c.genRecv.Load() != 1 {
		t.Fatalf("genRecv = %d after Tier-1 receive, want 1", c.genRecv.Load())
	}
	if !allZero(oldRoot) {
		t.Errorf("retired recv root not zeroized in place: %x", oldRoot)
	}
	want, err := npamp.RatchetMasterTier1(oldCopy, 1, sdkProfile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.masterRecv, want) {
		t.Fatalf("masterRecv after Tier-1\n got  %x\n want %x", c.masterRecv, want)
	}
	// Allow the spawned ACK goroutine to write before the pipe closes.
	time.Sleep(20 * time.Millisecond)
}

// ratchetTLS is a self-signed loopback TLS config for the internal loopback tests
// (the N-PAMP handshake, not the certificate, authenticates the peer).
func ratchetTLS(t *testing.T) *tls.Config {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "npamp-ratchet-loopback"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
		InsecureSkipVerify: true, //nolint:gosec // loopback: peer auth is via the N-PAMP handshake
	}
}

// eventually polls cond up to timeout, failing the test if it never holds. Used
// to await an off-path (goroutine) root advance without racing the mutator.
func eventually(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s: %s", timeout, msg)
}

// dialLoopbackPair establishes a real TCP+TLS+N-PAMP loopback session and returns
// the (client, server) Conns.
func dialLoopbackPair(t *testing.T, ctx context.Context) (*Conn, *Conn) {
	t.Helper()
	tlsCfg := ratchetTLS(t)
	_, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, clientPriv, _ := ed25519.GenerateKey(rand.Reader)

	ln, err := Listen("127.0.0.1:0", Config{TLSConfig: tlsCfg, Identity: serverPriv})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	type accepted struct {
		conn *Conn
		err  error
	}
	accCh := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept(ctx)
		accCh <- accepted{c, err}
	}()
	client, err := Dial(ctx, ln.Addr().String(), Config{TLSConfig: tlsCfg, Identity: clientPriv})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	acc := <-accCh
	if acc.err != nil {
		t.Fatalf("accept: %v", acc.err)
	}
	return client, acc.conn
}

// snapshotSend / snapshotRecv read a Conn's per-direction generation + root under
// the matching lock (race-free), copying the root out.
func snapshotSend(c *Conn) (uint64, []byte) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.genSend.Load(), append([]byte(nil), c.masterSend...)
}
func snapshotRecv(c *Conn) (uint64, []byte) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	return c.genRecv.Load(), append([]byte(nil), c.masterRecv...)
}

// TestReKEMTier2HealsBothRootsLoopback is the behavioral D1/D3 proof that the
// Tier-2 re-KEM actually FIRES over a real loopback session and MIXES FRESH KEM
// entropy into the healed root — it is not an inert local bump. It drives a full
// REKEM/REKEM_ACK exchange with the real X25519MLKEM768 KEM and asserts:
//
//   - the healed direction's root CHANGES (initiator masterRecv and responder
//     masterSend both advance to generation 1 — the step is not a no-op);
//   - the two peers converge on the SAME new root for that direction (symmetric
//     heal — a wrong/absent fresh secret would diverge them and break traffic);
//   - the OTHER direction is untouched (per-direction healing);
//   - application traffic keeps flowing across the boundary under the new root.
//
// Because the heal is driven by a fresh ephemeral KEM the attacker/self cannot
// predict, a root that changed AND matches the peer is positive evidence the
// fresh entropy was mixed (D3: designed machinery engaged, not silently skipped).
func TestReKEMTier2HealsBothRootsLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client, server := dialLoopbackPair(t, ctx)
	defer client.Close()
	defer server.Close()

	const ft npamp.FrameType = 0x0120

	gen0GenC, gen0RootC := snapshotRecv(client) // client's RECEIVE dir (the one Tier-2 heals)
	gen0GenS, gen0RootS := snapshotSend(server) // server's SEND dir (== client recv dir)
	if gen0GenC != 0 || gen0GenS != 0 {
		t.Fatalf("precondition gens: clientRecv=%d serverSend=%d, want 0/0", gen0GenC, gen0GenS)
	}
	if !bytes.Equal(gen0RootC, gen0RootS) {
		t.Fatal("precondition: client's recv root and server's send root should be equal at gen 0")
	}
	// The un-healed direction (client send == server recv) — for the untouched check.
	gen0SendGenC, gen0SendRootC := snapshotSend(client)

	// Initiate Tier-2 on the client (heals client's receive direction). Then send
	// an app frame on the SEND direction so the server's Recv, after transparently
	// spawning the responder, returns the app frame and unblocks.
	errc := make(chan error, 1)
	go func() {
		_, _, pt, err := server.Recv(ctx)
		if err == nil && string(pt) != "ping-after-rekem" {
			err = io.ErrUnexpectedEOF
		}
		errc <- err
	}()
	if err := client.ReKEM(ctx); err != nil {
		t.Fatalf("client.ReKEM: %v", err)
	}
	if err := client.Send(ctx, npamp.ChanMemory, ft, []byte("ping-after-rekem")); err != nil {
		t.Fatalf("client.Send after ReKEM: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("server.Recv (REKEM + app): %v", err)
	}

	// The responder advances its send root off the receive path; await it.
	eventually(t, 5*time.Second, func() bool {
		g, _ := snapshotSend(server)
		return g == 1
	}, "server send direction did not heal to generation 1 (Tier-2 responder inert)")

	// Now let the client finalize: server sends an app frame on the healed (its
	// send) direction; the client's Recv processes the REKEM_ACK boundary
	// transparently, advances its receive root, and returns the app frame.
	go func() {
		if err := server.Send(ctx, npamp.ChanMemory, ft, []byte("pong-healed")); err != nil {
			errc <- err
			return
		}
		errc <- nil
	}()
	_, _, pt, err := client.Recv(ctx)
	if err != nil {
		t.Fatalf("client.Recv (REKEM_ACK + app): %v", err)
	}
	if string(pt) != "pong-healed" {
		t.Fatalf("client.Recv got %q, want pong-healed", pt)
	}
	if err := <-errc; err != nil {
		t.Fatalf("server.Send on healed direction: %v", err)
	}

	// --- Assertions: the healed direction changed, symmetrically, with fresh entropy. ---
	healGenC, healRootC := snapshotRecv(client)
	healGenS, healRootS := snapshotSend(server)
	if healGenC != 1 || healGenS != 1 {
		t.Fatalf("post-heal gens: clientRecv=%d serverSend=%d, want 1/1", healGenC, healGenS)
	}
	if bytes.Equal(healRootC, gen0RootC) {
		t.Fatal("client receive root UNCHANGED after Tier-2 — the re-KEM was inert (no fresh entropy mixed)")
	}
	if !bytes.Equal(healRootC, healRootS) {
		t.Fatal("client receive root and server send root DIVERGED after Tier-2 — heal was not symmetric")
	}

	// The other direction (client send == server recv) is untouched by a one-sided heal.
	otherGenC, otherRootC := snapshotSend(client)
	if otherGenC != gen0SendGenC || !bytes.Equal(otherRootC, gen0SendRootC) {
		t.Fatal("Tier-2 heal of the receive direction disturbed the send direction")
	}

	// Traffic still flows across the boundary in the healed direction (behavioral).
	go func() {
		_, _, pt, err := client.Recv(ctx)
		if err == nil && string(pt) != "second-healed" {
			err = io.ErrUnexpectedEOF
		}
		errc <- err
	}()
	if err := server.Send(ctx, npamp.ChanMemory, ft, []byte("second-healed")); err != nil {
		t.Fatalf("server.Send second healed frame: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("client.Recv second healed frame: %v", err)
	}
}
