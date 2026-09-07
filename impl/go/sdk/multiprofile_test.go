// SPDX-License-Identifier: Apache-2.0

package sdk_test

// Multi-profile SDK end-to-end tests (external black-box, package sdk_test —
// mirrors sdk_test.go's TestLoopbackHandshakeAndRoundTrip pattern: a real
// TCP+TLS loopback, real keys, both directions). TestLoopbackHandshakeAndRoundTrip
// itself (unmodified by this change) is the Standard/Ed25519 regression
// evidence: it still passes unchanged, proving the multi-profile SDK build
// left the existing single-profile wire path byte-for-byte intact.

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"testing"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
	"github.com/bubblefish-tech/npamp_protocol/impl/go/sdk"
)

// TestHighProfileSessionEndToEnd runs the full 1.5-RTT handshake at the High
// profile over a real TCP+TLS loopback: both endpoints offer/accept
// [Standard, High], both hold an ML-DSA-87 identity, and the negotiation
// (spec/05_profiles.md) selects High. It verifies the session actually used
// ML-DSA-87 CertVerify (Conn.Profile() and PeerMLDSAIdentity(), not just
// "the handshake didn't error") and exchanges application frames in both
// directions, exactly like the Standard-profile test.
func TestHighProfileSessionEndToEnd(t *testing.T) {
	tlsCfg := loopbackTLS(t)

	serverMLDSA, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		t.Fatalf("server mldsa.GenerateKey: %v", err)
	}
	clientMLDSA, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		t.Fatalf("client mldsa.GenerateKey: %v", err)
	}

	// Strongest-first: Config.Profiles is the SERVER's preference order (the
	// first entry also present in the client's offer is selected), so listing
	// High before Standard here means a client that offers both gets High.
	profiles := []npamp.Profile{npamp.ProfileHigh, npamp.ProfileStandard}

	ln, err := sdk.Listen("127.0.0.1:0", sdk.Config{
		TLSConfig:     tlsCfg,
		MLDSAIdentity: serverMLDSA,
		Profiles:      profiles,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type accepted struct {
		conn *sdk.Conn
		err  error
	}
	accCh := make(chan accepted, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		c, err := ln.Accept(ctx)
		accCh <- accepted{c, err}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := sdk.Dial(ctx, ln.Addr().String(), sdk.Config{
		TLSConfig:     tlsCfg,
		MLDSAIdentity: clientMLDSA,
		Profiles:      profiles,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	acc := <-accCh
	if acc.err != nil {
		t.Fatalf("accept: %v", acc.err)
	}
	server := acc.conn
	defer server.Close()

	// The negotiated profile must be High on BOTH sides — not Standard (a
	// silent downgrade would defeat the whole point of this test).
	if client.Profile() != npamp.ProfileHigh {
		t.Fatalf("client negotiated profile %s, want High", client.Profile())
	}
	if server.Profile() != npamp.ProfileHigh {
		t.Fatalf("server negotiated profile %s, want High", server.Profile())
	}

	// Mutual ML-DSA-87 authentication: each side's PeerMLDSAIdentity() must be
	// the OTHER side's public key. PeerIdentity() (the Ed25519-typed accessor)
	// is deliberately NOT used to check identity here — at High/Sovereign it
	// carries the ML-DSA-87 encoding, not an Ed25519 key.
	clientSawServer, err := client.PeerMLDSAIdentity()
	if err != nil {
		t.Fatalf("client.PeerMLDSAIdentity: %v", err)
	}
	if clientSawServer == nil || !bytes.Equal(clientSawServer.Bytes(), serverMLDSA.PublicKey().Bytes()) {
		t.Fatal("client did not authenticate the server's ML-DSA-87 identity")
	}
	serverSawClient, err := server.PeerMLDSAIdentity()
	if err != nil {
		t.Fatalf("server.PeerMLDSAIdentity: %v", err)
	}
	if serverSawClient == nil || !bytes.Equal(serverSawClient.Bytes(), clientMLDSA.PublicKey().Bytes()) {
		t.Fatal("server did not authenticate the client's ML-DSA-87 identity")
	}

	// A Standard-profile session's PeerIdentity() returns 32 octets (Ed25519);
	// a High-profile session's returns the 2592-octet ML-DSA-87 encoding — a
	// second, independent (size-based) signal that the PQ path actually ran.
	if got := len(client.PeerIdentity()); got != mldsa.MLDSA87PublicKeySize {
		t.Fatalf("client.PeerIdentity() is %d octets, want %d (ML-DSA-87)", got, mldsa.MLDSA87PublicKeySize)
	}

	// Data round-trip, both directions, on the real AEAD record layer (which
	// derives its keys from c.profile — High selects SHA-384 throughout the
	// key schedule, per npamp.hashForProfile).
	const ftReq npamp.FrameType = 0x0120
	msg := []byte("hello from the High-profile client")
	if err := client.Send(ctx, npamp.ChanMemory, ftReq, msg); err != nil {
		t.Fatalf("client send: %v", err)
	}
	ch, ft, got, err := server.Recv(ctx)
	if err != nil {
		t.Fatalf("server recv: %v", err)
	}
	if ch != npamp.ChanMemory || ft != ftReq || !bytes.Equal(got, msg) {
		t.Fatalf("server got ch=%d ft=%#x msg=%q", ch, ft, got)
	}

	const ftResp npamp.FrameType = 0x0121
	reply := []byte("hello back from the High-profile server")
	if err := server.Send(ctx, npamp.ChanMemory, ftResp, reply); err != nil {
		t.Fatalf("server send: %v", err)
	}
	ch2, ft2, got2, err := client.Recv(ctx)
	if err != nil {
		t.Fatalf("client recv: %v", err)
	}
	if ch2 != npamp.ChanMemory || ft2 != ftResp || !bytes.Equal(got2, reply) {
		t.Fatalf("client got ch=%d ft=%#x msg=%q", ch2, ft2, got2)
	}
}

// TestHighProfileOfferWithoutMLDSAIdentityRejected asserts the fail-closed
// Config validation: offering High without an MLDSAIdentity is a Config
// error returned before any wire I/O, never a silent fallback to Standard or
// a panic deep inside the handshake.
func TestHighProfileOfferWithoutMLDSAIdentityRejected(t *testing.T) {
	tlsCfg := loopbackTLS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := sdk.Dial(ctx, "127.0.0.1:1", sdk.Config{
		TLSConfig: tlsCfg,
		Profiles:  []npamp.Profile{npamp.ProfileHigh},
	})
	if err == nil {
		t.Fatal("Dial offering High with no MLDSAIdentity succeeded; want a Config error")
	}
}
