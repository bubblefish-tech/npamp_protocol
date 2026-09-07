// SPDX-License-Identifier: Apache-2.0

package sdk

// Deviant-trace conformance suite (T18.1). The N-PAMP handshake + keyed-session state
// machine has a NORMATIVE total default (draft §State Machine): in any non-terminal
// state, a frame with no listed transition — a skip, a hop to a later/earlier flight, a
// repeat, or an unknown type — is a fatal `unexpected_message`, and the endpoint MUST NOT
// silently ignore it or recover by skipping. The observable reaction is key-state
// conditional: PRE-KEY it aborts WITHOUT an ERROR (no unauthenticated ERROR an off-path
// attacker could forge); POST-KEY it seals and sends an ERROR frame carrying the code
// before teardown (draft {#error-handling}).
//
// F3 NON-CIRCULARITY. Every expected output in this file is looked up from
// harness/statemodel/npamp-state-table.json — the Mealy model derived from the draft
// TEXT, never from this Go implementation. The suite drives the REAL runClientHandshake /
// runServerHandshake and the REAL Conn.Recv against hand-built deviant peers, and asserts
// the observed wire reaction equals the table's prediction. A state-machine bug shared
// between this code and the table cannot hide, because the table does not come from this
// code. TestStateTable_GeneratorConsumesTable makes that consumption explicit and checkable.
//
// The mutation anchor for the red-evidence ledger is a POST-KEY case (the pre-key cases are
// green from birth because the impl already silent-aborts): disabling the ESTABLISHED
// total-default rejection flips TestStateTable_EstablishedTotalDefault/unknown_type red.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// ---------------------------------------------------------------------------
// F3 authority: load and query the draft-derived state table
// ---------------------------------------------------------------------------

type stTransition struct {
	Role   string `json:"role"`
	From   string `json:"from"`
	Input  string `json:"input"`
	To     string `json:"to"`
	Output string `json:"output"`
}

type stTable struct {
	Transitions  []stTransition `json:"transitions"`
	TotalDefault struct {
		OutputPostKey        string          `json:"output_post_key"`
		OutputPreKey         string          `json:"output_pre_key"`
		KeyEstablishedBySt   json.RawMessage `json:"key_established_by_state"`
		keyEstablishedByName map[string]any
	} `json:"total_default"`
}

// loadStateTable reads the committed draft-derived Mealy model. The path is resolved
// from this test file's package directory (impl/go/sdk) up to the repo root, so the test
// is independent of the shell's working directory.
func loadStateTable(t *testing.T) *stTable {
	t.Helper()
	path := filepath.Join("..", "..", "..", "harness", "statemodel", "npamp-state-table.json")
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state table %s: %v", path, err)
	}
	var tbl stTable
	if err := json.Unmarshal(blob, &tbl); err != nil {
		t.Fatalf("parse state table: %v", err)
	}
	if err := json.Unmarshal(tbl.TotalDefault.KeyEstablishedBySt, &tbl.TotalDefault.keyEstablishedByName); err != nil {
		t.Fatalf("parse key_established_by_state: %v", err)
	}
	if len(tbl.Transitions) == 0 || tbl.TotalDefault.OutputPostKey == "" {
		t.Fatalf("state table looks empty: %d transitions, post-key default %q", len(tbl.Transitions), tbl.TotalDefault.OutputPostKey)
	}
	return &tbl
}

// legalOutput returns the listed transition output for (role, state, input), if any.
func (tbl *stTable) legalOutput(role, state, input string) (string, bool) {
	for _, tr := range tbl.Transitions {
		if (tr.Role == role || tr.Role == "both") && tr.From == state && tr.Input == input {
			return tr.Output, true
		}
	}
	return "", false
}

// keyEstablished reports whether a traffic key exists in state (drives pre/post-key).
func (tbl *stTable) keyEstablished(state string) bool {
	v, ok := tbl.TotalDefault.keyEstablishedByName[state]
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
}

// expect is the table's prediction for the reaction to input in (role, state): a listed
// transition's output, else the total default selected by whether a key is established.
// THIS is the F3 oracle — the assertions below compare the impl's observed reaction to it.
func (tbl *stTable) expect(role, state, input string) string {
	if out, ok := tbl.legalOutput(role, state, input); ok {
		return out
	}
	if tbl.keyEstablished(state) {
		return tbl.TotalDefault.OutputPostKey
	}
	return tbl.TotalDefault.OutputPreKey
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

const stTestTimeout = 5 * time.Second

func stKeypair(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return priv, pub
}

func stDeadlineCtx(t *testing.T) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), stTestTimeout)
}

func stSetDeadline(t *testing.T, raw net.Conn) {
	t.Helper()
	if err := raw.SetDeadline(time.Now().Add(stTestTimeout)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
}

// stStandardCH builds a Standard-profile CLIENT_HELLO offering exactly what the SDK
// accepts, plus a real KEM client so the responder can encapsulate.
func stStandardCH(t *testing.T) (*npamp.ClientHello, *npamp.KEMClient) {
	t.Helper()
	kem, err := npamp.GenerateKEMClient()
	if err != nil {
		t.Fatalf("KEM keygen: %v", err)
	}
	return &npamp.ClientHello{
		ProfileOffer: []npamp.Profile{npamp.ProfileStandard},
		KEMOffer:     []npamp.KEMID{npamp.KEMX25519MLKEM768},
		SigOffer:     []npamp.SigID{npamp.SigEd25519},
		AEADOffer:    []npamp.AEADID{npamp.AEADAES256GCM},
		KEMShare:     kem.KEMShare(),
	}, kem
}

// stReadErrorFrame reads one frame from raw, opens it under the peer's handshake send
// key, and returns the decoded ERROR code + the wire seq. It fails the test if the frame
// is not a sealed FrameError on the Control channel — which is exactly the RED assertion
// when the impl does not (yet) emit an ERROR: a timeout/EOF instead of a FrameError.
func stReadErrorFrame(t *testing.T, raw net.Conn, peerSendSecret []byte, peerSendDir npamp.Direction, p npamp.Profile) (npamp.SessionErrorCode, uint64) {
	t.Helper()
	stSetDeadline(t, raw)
	wire, err := readFrame(raw)
	if err != nil {
		t.Fatalf("expected a sealed ERROR frame, got read error (impl emitted nothing?): %v", err)
	}
	var f npamp.Frame
	if err := f.UnmarshalBinary(wire); err != nil {
		t.Fatalf("ERROR frame does not parse: %v", err)
	}
	if npamp.FrameType(f.Type) != npamp.FrameError {
		t.Fatalf("expected FrameError (0x0005), got frame type 0x%04x", f.Type)
	}
	if npamp.ChannelID(f.Channel) != npamp.ChanControl {
		t.Fatalf("ERROR frame on channel 0x%04x, want Control (0x0000)", f.Channel)
	}
	if f.Flags&npamp.FlagENC == 0 {
		t.Fatalf("ERROR frame is not AEAD-sealed (FlagENC clear) — an off-path-forgeable ERROR")
	}
	pt, err := openFrame(&f, peerSendSecret, peerSendDir, p)
	if err != nil {
		t.Fatalf("open ERROR frame under the peer's handshake send key at seq %d: %v", f.Seq, err)
	}
	code, _, err := npamp.DecodeErrorBody(pt)
	if err != nil {
		t.Fatalf("ERROR body does not decode: %v", err)
	}
	return code, f.Seq
}

// stAssertNoFrame asserts that no frame arrives within a short window (the pre-key
// SILENT_ABORT: the endpoint tears down without emitting an ERROR). A read error / EOF /
// timeout is the pass; a readable frame is the failure.
func stAssertNoFrame(t *testing.T, raw net.Conn) {
	t.Helper()
	if err := raw.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if wire, err := readFrame(raw); err == nil {
		var f npamp.Frame
		_ = f.UnmarshalBinary(wire)
		t.Fatalf("SILENT_ABORT expected: no frame, but got frame type 0x%04x (impl emitted a pre-key ERROR?)", f.Type)
	}
}

// stCodeName maps the abstract "ERROR:<name>" output to the wire SessionErrorCode.
func stCodeName(t *testing.T, output string) npamp.SessionErrorCode {
	t.Helper()
	switch output {
	case "ERROR:unexpected_message":
		return npamp.ErrCodeUnexpectedMessage
	case "ERROR:decrypt_failed":
		return npamp.ErrCodeDecryptFailed
	default:
		t.Fatalf("output %q is not an ERROR output", output)
		return 0
	}
}

// assertSealedErrorCode checks a reaction from injectAndReadReaction: the frame f (present iff
// have) MUST be a sealed FrameError on Control opened under the server's send key and carrying
// wantCode, and recvErr MUST be non-nil (the session tore down). Used by the code-level
// refinements below the abstract table alphabet (key_update_out_of_order, unsolicited acks).
func assertSealedErrorCode(t *testing.T, f npamp.Frame, have bool, master []byte, p npamp.Profile, wantCode npamp.SessionErrorCode, recvErr error, what string) {
	t.Helper()
	if !have {
		t.Fatalf("%s: expected a sealed ERROR reaction, got none (impl dropped it silently?)", what)
	}
	if npamp.FrameType(f.Type) != npamp.FrameError {
		t.Fatalf("%s: reaction frame type 0x%04x, want FrameError (0x0005)", what, f.Type)
	}
	if npamp.ChannelID(f.Channel) != npamp.ChanControl || f.Flags&npamp.FlagENC == 0 {
		t.Fatalf("%s: ERROR must be sealed on Control; got channel 0x%04x flags 0x%02x", what, f.Channel, f.Flags)
	}
	pt, err := openFrame(&f, master, npamp.DirServerToClient, p)
	if err != nil {
		t.Fatalf("%s: open ERROR under server send key: %v", what, err)
	}
	code, _, err := npamp.DecodeErrorBody(pt)
	if err != nil {
		t.Fatalf("%s: decode ERROR body: %v", what, err)
	}
	if code != wantCode {
		t.Fatalf("%s: got ERROR code %s, want %s", what, code, wantCode)
	}
	if recvErr == nil {
		t.Fatalf("%s: server.Recv returned nil (no teardown)", what)
	}
}

// ---------------------------------------------------------------------------
// Pre-key deviants — SILENT_ABORT (green from birth: the impl already aborts w/o ERROR)
// ---------------------------------------------------------------------------

func TestStateTable_PreKeyDeviants_SilentAbort(t *testing.T) {
	tbl := loadStateTable(t)

	// (responder, LISTEN, SERVER_HELLO): the server's first received frame is a hop to a
	// server-flight frame. Pre-key → SILENT_ABORT (no ERROR).
	t.Run("listen_hop_serverhello", func(t *testing.T) {
		if got := tbl.expect("responder", "LISTEN", "SERVER_HELLO"); got != "SILENT_ABORT" {
			t.Fatalf("table says LISTEN+SERVER_HELLO -> %q, want SILENT_ABORT", got)
		}
		sPriv, sPub := stKeypair(t)
		a, b := net.Pipe()
		defer func() { _ = a.Close(); _ = b.Close() }()
		ctx, cancel := stDeadlineCtx(t)
		defer cancel()

		srvErr := make(chan error, 1)
		go func() { _, _, _, e := runServerHandshake(ctx, b, stdIdentity(sPriv, sPub), nil); srvErr <- e }()

		// Deviant client sends a cleartext SERVER_HELLO as its opening frame.
		sh := &npamp.ServerHello{ProfileSelect: npamp.ProfileStandard, KEMSelect: npamp.KEMX25519MLKEM768, SigSelect: npamp.SigEd25519, AEADSelect: npamp.AEADAES256GCM, KEMCiphertext: make([]byte, npamp.KEMCiphertextSize768)}
		stSetDeadline(t, a)
		if err := sendCleartext(a, npamp.FrameServerHello, sh.Encode()); err != nil {
			t.Fatalf("send deviant SERVER_HELLO: %v", err)
		}
		stAssertNoFrame(t, a)
		if err := <-srvErr; err == nil {
			t.Fatal("server accepted a hop frame in LISTEN — the total default was bypassed")
		}
	})

	// (initiator, WAIT_SH, CLIENT_HELLO): the client, awaiting SERVER_HELLO, gets a repeat
	// of a client-flight frame. Pre-key → SILENT_ABORT.
	t.Run("wait_sh_repeat_clienthello", func(t *testing.T) {
		if got := tbl.expect("initiator", "WAIT_SH", "CLIENT_HELLO"); got != "SILENT_ABORT" {
			t.Fatalf("table says WAIT_SH+CLIENT_HELLO -> %q, want SILENT_ABORT", got)
		}
		cPriv, cPub := stKeypair(t)
		a, b := net.Pipe()
		defer func() { _ = a.Close(); _ = b.Close() }()
		ctx, cancel := stDeadlineCtx(t)
		defer cancel()

		cliErr := make(chan error, 1)
		go func() { _, _, _, e := runClientHandshake(ctx, a, stdIdentity(cPriv, cPub), nil); cliErr <- e }()

		// Deviant server: read CLIENT_HELLO, then echo a cleartext CLIENT_HELLO back.
		stSetDeadline(t, b)
		chPayload, err := recvCleartext(b, npamp.FrameClientHello)
		if err != nil {
			t.Fatalf("read CLIENT_HELLO: %v", err)
		}
		if err := sendCleartext(b, npamp.FrameClientHello, chPayload); err != nil {
			t.Fatalf("send deviant CLIENT_HELLO: %v", err)
		}
		stAssertNoFrame(t, b)
		if err := <-cliErr; err == nil {
			t.Fatal("client accepted a repeated CLIENT_HELLO in WAIT_SH — the total default was bypassed")
		}
	})

	// (initiator, WAIT_SH, SERVER_HELLO_BADSEL): a SERVER_HELLO selecting something the
	// client never offered. Listed transition → SILENT_ABORT (pre-key; caught by
	// requireSelections before key derivation).
	t.Run("wait_sh_badsel", func(t *testing.T) {
		if got := tbl.expect("initiator", "WAIT_SH", "SERVER_HELLO_BADSEL"); got != "SILENT_ABORT" {
			t.Fatalf("table says WAIT_SH+SERVER_HELLO_BADSEL -> %q, want SILENT_ABORT", got)
		}
		cPriv, cPub := stKeypair(t)
		a, b := net.Pipe()
		defer func() { _ = a.Close(); _ = b.Close() }()
		ctx, cancel := stDeadlineCtx(t)
		defer cancel()

		cliErr := make(chan error, 1)
		go func() { _, _, _, e := runClientHandshake(ctx, a, stdIdentity(cPriv, cPub), nil); cliErr <- e }()

		stSetDeadline(t, b)
		chPayload, err := recvCleartext(b, npamp.FrameClientHello)
		if err != nil {
			t.Fatalf("read CLIENT_HELLO: %v", err)
		}
		ch, err := npamp.DecodeClientHello(chPayload)
		if err != nil {
			t.Fatalf("decode CLIENT_HELLO: %v", err)
		}
		kemCT, _, err := npamp.Encapsulate(ch.KEMShare)
		if err != nil {
			t.Fatalf("encapsulate: %v", err)
		}
		// A profile the client did not offer (Standard-only SDK): High.
		bad := &npamp.ServerHello{ProfileSelect: npamp.ProfileHigh, KEMSelect: npamp.KEMX25519MLKEM768, SigSelect: npamp.SigEd25519, AEADSelect: npamp.AEADAES256GCM, KEMCiphertext: kemCT}
		if err := sendCleartext(b, npamp.FrameServerHello, bad.Encode()); err != nil {
			t.Fatalf("send BADSEL SERVER_HELLO: %v", err)
		}
		stAssertNoFrame(t, b)
		if err := <-cliErr; err == nil {
			t.Fatal("client accepted an unoffered selection — downgrade guard bypassed")
		}
	})
}

// ---------------------------------------------------------------------------
// Post-key handshake deviants — sealed ERROR with the table's code (RED until wired)
// ---------------------------------------------------------------------------

func TestStateTable_PostKeyHandshakeDeviants_Error(t *testing.T) {
	p := npamp.ProfileStandard
	tbl := loadStateTable(t)

	// deviantServerToWaitSA drives the real client to WAIT_SA (valid CH read, valid SH
	// sent, keys derived) and returns the derived handshake secrets + the pipe end, so the
	// caller can inject the deviant SERVER_AUTH-flight frame and read the client's ERROR.
	deviantServerToWaitSA := func(t *testing.T, b net.Conn) (cHS, sHS []byte) {
		t.Helper()
		stSetDeadline(t, b)
		chPayload, err := recvCleartext(b, npamp.FrameClientHello)
		if err != nil {
			t.Fatalf("read CLIENT_HELLO: %v", err)
		}
		ch, err := npamp.DecodeClientHello(chPayload)
		if err != nil {
			t.Fatalf("decode CLIENT_HELLO: %v", err)
		}
		tr := npamp.NewTranscript(p)
		tr.AddFrame(npamp.FrameClientHello, ch.TLVs())
		kemCT, ss, err := npamp.Encapsulate(ch.KEMShare)
		if err != nil {
			t.Fatalf("encapsulate: %v", err)
		}
		sh := &npamp.ServerHello{ProfileSelect: npamp.ProfileStandard, KEMSelect: npamp.KEMX25519MLKEM768, SigSelect: npamp.SigEd25519, AEADSelect: npamp.AEADAES256GCM, KEMCiphertext: kemCT}
		if err := sendCleartext(b, npamp.FrameServerHello, sh.Encode()); err != nil {
			t.Fatalf("send SERVER_HELLO: %v", err)
		}
		tr.AddFrame(npamp.FrameServerHello, sh.TLVs())
		hs, err := npamp.HandshakeSecret(ss, p)
		if err != nil {
			t.Fatalf("handshake secret: %v", err)
		}
		cHS, sHS, err = npamp.DeriveHandshakeTrafficSecrets(hs, tr.Sum(), p)
		if err != nil {
			t.Fatalf("derive handshake traffic secrets: %v", err)
		}
		return cHS, sHS
	}

	// (initiator, WAIT_SA, SERVER_HELLO): wrong-type hop where SERVER_AUTH is expected.
	// Post-key → ERROR:unexpected_message at the client's send seq 0 (no CLIENT_AUTH sent).
	t.Run("wait_sa_wrongtype_unexpected", func(t *testing.T) {
		want := stCodeName(t, tbl.expect("initiator", "WAIT_SA", "SERVER_HELLO"))
		cPriv, cPub := stKeypair(t)
		a, b := net.Pipe()
		defer func() { _ = a.Close(); _ = b.Close() }()
		ctx, cancel := stDeadlineCtx(t)
		defer cancel()

		cliErr := make(chan error, 1)
		go func() { _, _, _, e := runClientHandshake(ctx, a, stdIdentity(cPriv, cPub), nil); cliErr <- e }()

		cHS, _ := deviantServerToWaitSA(t, b)
		// Deviant: repeat SERVER_HELLO where SERVER_AUTH is expected.
		sh := &npamp.ServerHello{ProfileSelect: npamp.ProfileStandard, KEMSelect: npamp.KEMX25519MLKEM768, SigSelect: npamp.SigEd25519, AEADSelect: npamp.AEADAES256GCM, KEMCiphertext: make([]byte, npamp.KEMCiphertextSize768)}
		if err := sendCleartext(b, npamp.FrameServerHello, sh.Encode()); err != nil {
			t.Fatalf("send deviant SERVER_HELLO: %v", err)
		}
		// The client emits its ERROR under the CLIENT handshake key (its send direction).
		code, seq := stReadErrorFrame(t, b, cHS, npamp.DirClientToServer, p)
		if code != want {
			t.Fatalf("WAIT_SA wrong-type: got ERROR code %s, want %s", code, want)
		}
		if seq != 0 {
			t.Fatalf("client WAIT_SA ERROR seq = %d, want 0 (no CLIENT_AUTH sent yet)", seq)
		}
		if err := <-cliErr; err == nil {
			t.Fatal("client handshake returned nil on a deviant SERVER_AUTH flight")
		}
	})

	// (initiator, WAIT_SA, SERVER_AUTH_BADAUTH): a SERVER_AUTH whose AEAD tag fails.
	// Listed transition → ERROR:decrypt_failed at seq 0.
	t.Run("wait_sa_badauth_decrypt_failed", func(t *testing.T) {
		want := stCodeName(t, tbl.expect("initiator", "WAIT_SA", "SERVER_AUTH_BADAUTH"))
		cPriv, cPub := stKeypair(t)
		a, b := net.Pipe()
		defer func() { _ = a.Close(); _ = b.Close() }()
		ctx, cancel := stDeadlineCtx(t)
		defer cancel()

		cliErr := make(chan error, 1)
		go func() { _, _, _, e := runClientHandshake(ctx, a, stdIdentity(cPriv, cPub), nil); cliErr <- e }()

		cHS, sHS := deviantServerToWaitSA(t, b)
		// A validly-framed SERVER_AUTH sealed under sHS, then one ciphertext byte flipped:
		// the frame parses, but the AEAD open fails -> decrypt_failed.
		saWire, err := sealFrame(sHS, npamp.DirServerToClient, npamp.ChanControl, 0, npamp.FrameServerAuth, []byte("not a real auth message"), p)
		if err != nil {
			t.Fatalf("seal SERVER_AUTH: %v", err)
		}
		saWire[npamp.HeaderSize]++ // corrupt the first ciphertext octet (header CRC intact)
		if err := writeFrame(b, saWire); err != nil {
			t.Fatalf("send tampered SERVER_AUTH: %v", err)
		}
		code, seq := stReadErrorFrame(t, b, cHS, npamp.DirClientToServer, p)
		if code != want {
			t.Fatalf("WAIT_SA badauth: got ERROR code %s, want %s", code, want)
		}
		if seq != 0 {
			t.Fatalf("client WAIT_SA ERROR seq = %d, want 0", seq)
		}
		if err := <-cliErr; err == nil {
			t.Fatal("client handshake returned nil on a tampered SERVER_AUTH")
		}
	})

	// deviantClientToWaitCA drives the real server to WAIT_CA (valid CH sent, valid SH read,
	// keys derived, SERVER_AUTH read+discarded) and returns the derived secrets.
	deviantClientToWaitCA := func(t *testing.T, a net.Conn) (cHS, sHS []byte) {
		t.Helper()
		ch, kem := stStandardCH(t)
		tr := npamp.NewTranscript(p)
		stSetDeadline(t, a)
		if err := sendCleartext(a, npamp.FrameClientHello, ch.Encode()); err != nil {
			t.Fatalf("send CLIENT_HELLO: %v", err)
		}
		tr.AddFrame(npamp.FrameClientHello, ch.TLVs())
		shPayload, err := recvCleartext(a, npamp.FrameServerHello)
		if err != nil {
			t.Fatalf("read SERVER_HELLO: %v", err)
		}
		sh, err := npamp.DecodeServerHello(shPayload)
		if err != nil {
			t.Fatalf("decode SERVER_HELLO: %v", err)
		}
		tr.AddFrame(npamp.FrameServerHello, sh.TLVs())
		ss, err := kem.SharedSecrets(sh.KEMCiphertext)
		if err != nil {
			t.Fatalf("decapsulate: %v", err)
		}
		hs, err := npamp.HandshakeSecret(ss, p)
		if err != nil {
			t.Fatalf("handshake secret: %v", err)
		}
		cHS, sHS, err = npamp.DeriveHandshakeTrafficSecrets(hs, tr.Sum(), p)
		if err != nil {
			t.Fatalf("derive handshake traffic secrets: %v", err)
		}
		// Read + discard the server's SERVER_AUTH (seq 0 under sHS); we do not verify it.
		if _, err := readFrame(a); err != nil {
			t.Fatalf("read SERVER_AUTH: %v", err)
		}
		return cHS, sHS
	}

	// (responder, WAIT_CA, CLIENT_HELLO): wrong-type repeat where CLIENT_AUTH is expected.
	// Post-key → ERROR:unexpected_message at the server's send seq 1 (SERVER_AUTH used 0).
	t.Run("wait_ca_wrongtype_unexpected", func(t *testing.T) {
		want := stCodeName(t, tbl.expect("responder", "WAIT_CA", "CLIENT_HELLO"))
		sPriv, sPub := stKeypair(t)
		a, b := net.Pipe()
		defer func() { _ = a.Close(); _ = b.Close() }()
		ctx, cancel := stDeadlineCtx(t)
		defer cancel()

		srvErr := make(chan error, 1)
		go func() { _, _, _, e := runServerHandshake(ctx, b, stdIdentity(sPriv, sPub), nil); srvErr <- e }()

		_, sHS := deviantClientToWaitCA(t, a)
		ch, _ := stStandardCH(t)
		if err := sendCleartext(a, npamp.FrameClientHello, ch.Encode()); err != nil {
			t.Fatalf("send deviant CLIENT_HELLO: %v", err)
		}
		code, seq := stReadErrorFrame(t, a, sHS, npamp.DirServerToClient, p)
		if code != want {
			t.Fatalf("WAIT_CA wrong-type: got ERROR code %s, want %s", code, want)
		}
		if seq != 1 {
			t.Fatalf("server WAIT_CA ERROR seq = %d, want 1 (SERVER_AUTH already used seq 0)", seq)
		}
		if err := <-srvErr; err == nil {
			t.Fatal("server handshake returned nil on a deviant CLIENT_AUTH flight")
		}
	})

	// (responder, WAIT_CA, CLIENT_AUTH_BADAUTH): a CLIENT_AUTH whose AEAD tag fails.
	// Listed transition → ERROR:decrypt_failed at seq 1.
	t.Run("wait_ca_badauth_decrypt_failed", func(t *testing.T) {
		want := stCodeName(t, tbl.expect("responder", "WAIT_CA", "CLIENT_AUTH_BADAUTH"))
		sPriv, sPub := stKeypair(t)
		a, b := net.Pipe()
		defer func() { _ = a.Close(); _ = b.Close() }()
		ctx, cancel := stDeadlineCtx(t)
		defer cancel()

		srvErr := make(chan error, 1)
		go func() { _, _, _, e := runServerHandshake(ctx, b, stdIdentity(sPriv, sPub), nil); srvErr <- e }()

		cHS, sHS := deviantClientToWaitCA(t, a)
		caWire, err := sealFrame(cHS, npamp.DirClientToServer, npamp.ChanControl, 0, npamp.FrameClientAuth, []byte("not a real auth message"), p)
		if err != nil {
			t.Fatalf("seal CLIENT_AUTH: %v", err)
		}
		caWire[npamp.HeaderSize]++ // corrupt first ciphertext octet
		if err := writeFrame(a, caWire); err != nil {
			t.Fatalf("send tampered CLIENT_AUTH: %v", err)
		}
		code, seq := stReadErrorFrame(t, a, sHS, npamp.DirServerToClient, p)
		if code != want {
			t.Fatalf("WAIT_CA badauth: got ERROR code %s, want %s", code, want)
		}
		if seq != 1 {
			t.Fatalf("server WAIT_CA ERROR seq = %d, want 1", seq)
		}
		if err := <-srvErr; err == nil {
			t.Fatal("server handshake returned nil on a tampered CLIENT_AUTH")
		}
	})
}

// ---------------------------------------------------------------------------
// ESTABLISHED total default — the keyed-session skip/hop/repeat family (RED until wired)
// ---------------------------------------------------------------------------

func TestStateTable_EstablishedTotalDefault(t *testing.T) {
	p := npamp.ProfileStandard
	tbl := loadStateTable(t)

	// establishedPair returns a real server Conn on b and the raw client end a sharing a
	// master, so the test can inject a sealed deviant frame from a and read the server's
	// raw reaction. Both derive the SAME epoch-0 Control key (server recvDir ==
	// DirClientToServer == the direction sealFrame(master, DirClientToServer, ...) targets).
	establishedServer := func(t *testing.T) (a net.Conn, server *Conn, master []byte) {
		master = guardTestMaster()
		a, b := net.Pipe()
		server = newConn(b, master, nil, npamp.DirServerToClient, npamp.DirClientToServer)
		t.Cleanup(func() { _ = a.Close(); _ = server.Close() })
		return a, server, master
	}

	// injectAndReadReaction seals a deviant frame (type ft, empty-or-given payload) on
	// Control from the client side, runs server.Recv concurrently, and returns the raw
	// reaction frame read off a plus the Recv error. net.Pipe rendezvous: server.Recv
	// blocks reading the deviant; its synchronous emit blocks writing until we read a.
	injectAndReadReaction := func(t *testing.T, a net.Conn, server *Conn, master []byte, ft npamp.FrameType, payload []byte) (npamp.Frame, bool, error) {
		t.Helper()
		ctx, cancel := stDeadlineCtx(t)
		defer cancel()
		recvErr := make(chan error, 1)
		go func() { _, _, _, e := server.Recv(ctx); recvErr <- e }()

		wire, err := sealFrame(master, npamp.DirClientToServer, npamp.ChanControl, 0, ft, payload, p)
		if err != nil {
			t.Fatalf("seal deviant frame: %v", err)
		}
		stSetDeadline(t, a)
		if err := writeFrame(a, wire); err != nil {
			t.Fatalf("write deviant frame: %v", err)
		}
		// Read the server's raw reaction (an ERROR or CLOSE_ACK), if any.
		var f npamp.Frame
		haveFrame := false
		if err := a.SetReadDeadline(time.Now().Add(stTestTimeout)); err == nil {
			if rw, rerr := readFrame(a); rerr == nil {
				if perr := f.UnmarshalBinary(rw); perr == nil {
					haveFrame = true
				}
			}
		}
		return f, haveFrame, <-recvErr
	}

	// (both, ESTABLISHED, SERVER_AUTH): a handshake frame after establishment — total
	// default → ERROR:unexpected_message. RAW-BYTES observer (opens the ERROR manually,
	// pins type/channel/FlagENC/seq/code) so this test of EMISSION does not depend on the
	// reception path.
	t.Run("handshake_frame_in_session", func(t *testing.T) {
		want := stCodeName(t, tbl.expect("both", "ESTABLISHED", "SERVER_AUTH"))
		a, server, master := establishedServer(t)
		f, have, recvErr := injectAndReadReaction(t, a, server, master, npamp.FrameServerAuth, nil)
		if !have {
			t.Fatal("expected a sealed ERROR reaction to a handshake frame in ESTABLISHED, got none")
		}
		if npamp.FrameType(f.Type) != npamp.FrameError {
			t.Fatalf("reaction frame type 0x%04x, want FrameError (0x0005)", f.Type)
		}
		if npamp.ChannelID(f.Channel) != npamp.ChanControl || f.Flags&npamp.FlagENC == 0 {
			t.Fatalf("ERROR must be sealed on Control; got channel 0x%04x flags 0x%02x", f.Channel, f.Flags)
		}
		if f.Seq != 0 {
			t.Fatalf("server ESTABLISHED ERROR seq = %d, want 0 (first Control send)", f.Seq)
		}
		pt, err := openFrame(&f, master, npamp.DirServerToClient, p)
		if err != nil {
			t.Fatalf("open ERROR under server send key: %v", err)
		}
		code, ctxb, err := npamp.DecodeErrorBody(pt)
		if err != nil {
			t.Fatalf("decode ERROR body: %v", err)
		}
		if code != want {
			t.Fatalf("got ERROR code %s, want %s", code, want)
		}
		if len(ctxb) != 0 {
			t.Fatalf("ERROR context must be zero-length (no info oracle), got %d bytes", len(ctxb))
		}
		if recvErr == nil {
			t.Fatal("server.Recv returned nil for a handshake frame in ESTABLISHED")
		}
	})

	// (both, ESTABLISHED, UNKNOWN): an unassigned reserved Control type (0x00FE — NOT a
	// ratchet type, per the table's modeled_exclusion). Total default → unexpected_message.
	// This is the mutation anchor for the red-evidence ledger.
	t.Run("unknown_type", func(t *testing.T) {
		want := stCodeName(t, tbl.expect("both", "ESTABLISHED", "UNKNOWN"))
		a, server, master := establishedServer(t)
		f, have, recvErr := injectAndReadReaction(t, a, server, master, npamp.FrameType(0x00FE), nil)
		if !have {
			t.Fatal("expected a sealed ERROR reaction to an unknown Control frame, got none")
		}
		if npamp.FrameType(f.Type) != npamp.FrameError {
			t.Fatalf("reaction frame type 0x%04x, want FrameError", f.Type)
		}
		pt, err := openFrame(&f, master, npamp.DirServerToClient, p)
		if err != nil {
			t.Fatalf("open ERROR: %v", err)
		}
		code, _, err := npamp.DecodeErrorBody(pt)
		if err != nil {
			t.Fatalf("decode ERROR body: %v", err)
		}
		if code != want {
			t.Fatalf("got ERROR code %s, want %s", code, want)
		}
		if recvErr == nil {
			t.Fatal("server.Recv returned nil for an unknown Control frame")
		}
	})

	// (both, ESTABLISHED, CLOSE): a well-formed CLOSE — listed transition → CLOSE_ACK, then
	// CLOSED. The reaction is a sealed CLOSE_ACK; Recv returns ErrPeerClosed.
	t.Run("close_yields_close_ack", func(t *testing.T) {
		if got, _ := tbl.legalOutput("both", "ESTABLISHED", "CLOSE"); got != "CLOSE_ACK" {
			t.Fatalf("table says ESTABLISHED+CLOSE -> %q, want CLOSE_ACK", got)
		}
		a, server, master := establishedServer(t)
		f, have, recvErr := injectAndReadReaction(t, a, server, master, npamp.FrameClose, nil)
		if !have {
			t.Fatal("expected a sealed CLOSE_ACK reaction to CLOSE, got none")
		}
		if npamp.FrameType(f.Type) != npamp.FrameCloseAck {
			t.Fatalf("reaction frame type 0x%04x, want FrameCloseAck (0x0004)", f.Type)
		}
		if npamp.ChannelID(f.Channel) != npamp.ChanControl || f.Flags&npamp.FlagENC == 0 {
			t.Fatalf("CLOSE_ACK must be sealed on Control; got channel 0x%04x flags 0x%02x", f.Channel, f.Flags)
		}
		if !errors.Is(recvErr, ErrPeerClosed) {
			t.Fatalf("server.Recv after CLOSE = %v, want ErrPeerClosed", recvErr)
		}
	})

	// Draft-clause refinement (draft {#... CLOSE Frame}): a CLOSE carrying a non-empty
	// payload MUST be rejected with unexpected_message (below the abstract table's alphabet).
	t.Run("close_with_payload_rejected", func(t *testing.T) {
		a, server, master := establishedServer(t)
		f, have, recvErr := injectAndReadReaction(t, a, server, master, npamp.FrameClose, []byte("payload"))
		if !have {
			t.Fatal("expected an ERROR reaction to a CLOSE-with-payload, got none")
		}
		if npamp.FrameType(f.Type) != npamp.FrameError {
			t.Fatalf("reaction to CLOSE-with-payload type 0x%04x, want FrameError", f.Type)
		}
		pt, err := openFrame(&f, master, npamp.DirServerToClient, p)
		if err != nil {
			t.Fatalf("open ERROR: %v", err)
		}
		code, _, err := npamp.DecodeErrorBody(pt)
		if err != nil {
			t.Fatalf("decode ERROR: %v", err)
		}
		if code != npamp.ErrCodeUnexpectedMessage {
			t.Fatalf("CLOSE-with-payload code %s, want unexpected_message", code)
		}
		if recvErr == nil {
			t.Fatal("server.Recv returned nil for a CLOSE-with-payload")
		}
	})

	// Draft-clause refinement (draft {#error-handling}): a RECEIVED ERROR frame is advisory
	// — the receiver surfaces it as *npamp.SessionError and closes, and MUST NOT reply with
	// an ERROR of its own (no error loop). Assert Recv returns SessionError AND no reply.
	t.Run("received_error_is_surfaced_no_reply", func(t *testing.T) {
		a, server, master := establishedServer(t)
		body := npamp.EncodeErrorBody(npamp.ErrCodeFlowControl, nil)
		f, have, recvErr := injectAndReadReaction(t, a, server, master, npamp.FrameError, body)
		if have {
			t.Fatalf("receiver replied to a peer ERROR with frame type 0x%04x — an error loop", f.Type)
		}
		var se *npamp.SessionError
		if !errors.As(recvErr, &se) {
			t.Fatalf("server.Recv after a peer ERROR = %v, want *npamp.SessionError", recvErr)
		}
		if se.Code != npamp.ErrCodeFlowControl {
			t.Fatalf("surfaced code %s, want flow_control_error", se.Code)
		}
	})

	// (both, ESTABLISHED, KEY_UPDATE_ACK): an UNSOLICITED KEY_UPDATE_ACK — this endpoint sent
	// no matching KEY_UPDATE — has NO listed transition, so it is the total default
	// (unexpected_message), exactly like an unsolicited CLOSE_ACK. Before the T18.2 hardening
	// the impl silently swallowed it (`continue`), a table violation; this asserts the
	// strengthened reject. On Control (the helper's channel); a well-formed marker so it reaches
	// the not-pending branch (a malformed marker is a plain error, tested at the unit level).
	t.Run("unsolicited_key_update_ack", func(t *testing.T) {
		want := stCodeName(t, tbl.expect("both", "ESTABLISHED", "KEY_UPDATE_ACK"))
		a, server, master := establishedServer(t)
		f, have, recvErr := injectAndReadReaction(t, a, server, master, npamp.FrameKeyUpdateAck, keyUpdateMarker(5))
		if !have {
			t.Fatal("expected a sealed ERROR reaction to an unsolicited KEY_UPDATE_ACK, got none (impl swallowed it?)")
		}
		if npamp.FrameType(f.Type) != npamp.FrameError {
			t.Fatalf("reaction frame type 0x%04x, want FrameError (0x0005)", f.Type)
		}
		pt, err := openFrame(&f, master, npamp.DirServerToClient, p)
		if err != nil {
			t.Fatalf("open ERROR under server send key: %v", err)
		}
		code, _, err := npamp.DecodeErrorBody(pt)
		if err != nil {
			t.Fatalf("decode ERROR body: %v", err)
		}
		if code != want {
			t.Fatalf("unsolicited KEY_UPDATE_ACK: got ERROR code %s, want %s", code, want)
		}
		if recvErr == nil {
			t.Fatal("server.Recv returned nil for an unsolicited KEY_UPDATE_ACK")
		}
	})

	// An unsolicited KEY_UPDATE_ACK on a NON-Control channel is ALSO rejected: KEY_UPDATE
	// (0x0007) is a per-channel frame type, so the reject is keyed by (channel, epoch) and NOT
	// gated to Control. The endpoint solicited nothing on ChanMemory, so the ACK is the total
	// default — and the ERROR reaction is still sealed on Control (all ERRORs ride Control).
	t.Run("unsolicited_key_update_ack_non_control", func(t *testing.T) {
		want := stCodeName(t, tbl.expect("both", "ESTABLISHED", "KEY_UPDATE_ACK"))
		a, server, master := establishedServer(t)
		ctx, cancel := stDeadlineCtx(t)
		defer cancel()
		recvErr := make(chan error, 1)
		go func() { _, _, _, e := server.Recv(ctx); recvErr <- e }()

		wire, err := sealFrame(master, npamp.DirClientToServer, npamp.ChanMemory, 0, npamp.FrameKeyUpdateAck, keyUpdateMarker(3), p)
		if err != nil {
			t.Fatalf("seal unsolicited KEY_UPDATE_ACK on ChanMemory: %v", err)
		}
		stSetDeadline(t, a)
		if err := writeFrame(a, wire); err != nil {
			t.Fatalf("write frame: %v", err)
		}
		code, _ := stReadErrorFrame(t, a, master, npamp.DirServerToClient, p)
		if code != want {
			t.Fatalf("non-Control unsolicited KEY_UPDATE_ACK: got %s, want %s", code, want)
		}
		if err := <-recvErr; err == nil {
			t.Fatal("server.Recv returned nil for an unsolicited KEY_UPDATE_ACK on ChanMemory")
		}
	})

	// (both, ESTABLISHED, MASTER_RATCHET_ACK): the ratchet ACKs are a modeled_exclusion of the
	// F3 table (the multi-generation ratchet sub-protocol would explode a flat Mealy machine),
	// so this is a CODE-LEVEL CONSISTENCY assertion (like the CLOSE-with-payload refinement),
	// NOT learned coverage: an unsolicited MASTER_RATCHET_ACK must be rejected as
	// unexpected_message exactly like KEY_UPDATE_ACK / CLOSE_ACK. Covered here + by the ratchet
	// differential tests, never by the learner.
	t.Run("unsolicited_master_ratchet_ack", func(t *testing.T) {
		a, server, master := establishedServer(t)
		f, have, recvErr := injectAndReadReaction(t, a, server, master, frameMasterRatchetAck, ratchetGenMarker(1))
		if !have {
			t.Fatal("expected a sealed ERROR reaction to an unsolicited MASTER_RATCHET_ACK, got none")
		}
		if npamp.FrameType(f.Type) != npamp.FrameError {
			t.Fatalf("reaction frame type 0x%04x, want FrameError", f.Type)
		}
		pt, err := openFrame(&f, master, npamp.DirServerToClient, p)
		if err != nil {
			t.Fatalf("open ERROR: %v", err)
		}
		code, _, err := npamp.DecodeErrorBody(pt)
		if err != nil {
			t.Fatalf("decode ERROR body: %v", err)
		}
		if code != npamp.ErrCodeUnexpectedMessage {
			t.Fatalf("unsolicited MASTER_RATCHET_ACK: got %s, want unexpected_message", code)
		}
		if recvErr == nil {
			t.Fatal("server.Recv returned nil for an unsolicited MASTER_RATCHET_ACK")
		}
	})

	// (A1) A KEY_UPDATE whose KeyUpdateMarker announces an epoch != current+1 is fatal
	// key_update_out_of_order (draft error registry row 9 / §1306-1311 "MUST be rejected with
	// key_update_out_of_order ... MUST be torn down"), NOT a silent drop. The server's Control
	// recv epoch is 0, so a marker announcing epoch 5 is out of order.
	t.Run("key_update_wrong_epoch_out_of_order", func(t *testing.T) {
		a, server, master := establishedServer(t)
		f, have, recvErr := injectAndReadReaction(t, a, server, master, npamp.FrameKeyUpdate, keyUpdateMarker(5))
		assertSealedErrorCode(t, f, have, master, p, npamp.ErrCodeKeyUpdateOutOfOrder, recvErr, "wrong-epoch KEY_UPDATE")
	})

	// (A2) A KEY_UPDATE whose marker is malformed (here: absent — an empty payload, which the
	// draft names as malformed) is the same fatal key_update_out_of_order (row 9).
	t.Run("key_update_malformed_marker_out_of_order", func(t *testing.T) {
		a, server, master := establishedServer(t)
		f, have, recvErr := injectAndReadReaction(t, a, server, master, npamp.FrameKeyUpdate, nil)
		assertSealedErrorCode(t, f, have, master, p, npamp.ErrCodeKeyUpdateOutOfOrder, recvErr, "malformed KEY_UPDATE marker")
	})

	// (A3) A malformed KeyUpdateMarker on a KEY_UPDATE_ACK is the SAME fatal
	// key_update_out_of_order — the marker is the same TLV on either frame — replacing part 1's
	// plain-drop, whose "handleKeyUpdate precedent" was itself the A1/A2 defect.
	t.Run("key_update_ack_malformed_marker_out_of_order", func(t *testing.T) {
		a, server, master := establishedServer(t)
		f, have, recvErr := injectAndReadReaction(t, a, server, master, npamp.FrameKeyUpdateAck, nil)
		assertSealedErrorCode(t, f, have, master, p, npamp.ErrCodeKeyUpdateOutOfOrder, recvErr, "malformed KEY_UPDATE_ACK marker")
	})

	// (A4) An unsolicited (no outstanding re-KEM) REKEM_ACK is unexpected_message, uniform with
	// unsolicited KEY_UPDATE_ACK / MASTER_RATCHET_ACK / CLOSE_ACK — replacing the plain-drop
	// that made the draft's uniform unsolicited-ack rule false about the impl. Well-formed body
	// (passes parseReKEMAck) so it reaches the no-pending branch.
	t.Run("unsolicited_rekem_ack", func(t *testing.T) {
		a, server, master := establishedServer(t)
		body := encodeReKEMAck(make([]byte, npamp.KEMCiphertextSize768), 1)
		f, have, recvErr := injectAndReadReaction(t, a, server, master, frameReKEMAck, body)
		assertSealedErrorCode(t, f, have, master, p, npamp.ErrCodeUnexpectedMessage, recvErr, "unsolicited REKEM_ACK")
	})
}

// ---------------------------------------------------------------------------
// F3 consumption is explicit: prove the deviant inputs are NOT legal transitions
// ---------------------------------------------------------------------------

func TestStateTable_GeneratorConsumesTable(t *testing.T) {
	tbl := loadStateTable(t)

	// Each post-key wrong-type/unknown deviant input MUST have NO listed transition in its
	// state (so it genuinely falls to the total default), and the total default MUST be the
	// post-key sealed ERROR. If a future table edit added a transition for one of these, the
	// deviant would no longer be a deviant and this guard flags it.
	totalDefaultCases := []struct{ role, state, input string }{
		{"initiator", "WAIT_SA", "SERVER_HELLO"},
		{"responder", "WAIT_CA", "CLIENT_HELLO"},
		{"both", "ESTABLISHED", "SERVER_AUTH"},
		{"both", "ESTABLISHED", "UNKNOWN"},
		// KEY_UPDATE_ACK is in the alphabet but has NO ESTABLISHED transition: an unsolicited
		// one falls to the total default (the T18.2 hardening asserts the impl matches this).
		{"both", "ESTABLISHED", "KEY_UPDATE_ACK"},
	}
	for _, c := range totalDefaultCases {
		if out, ok := tbl.legalOutput(c.role, c.state, c.input); ok {
			t.Fatalf("%s/%s/%s is a LISTED transition (%s) — not a total-default deviant; table drifted", c.role, c.state, c.input, out)
		}
		if !tbl.keyEstablished(c.state) {
			t.Fatalf("%s is pre-key in the table but used as a post-key ERROR case", c.state)
		}
		if got := tbl.expect(c.role, c.state, c.input); got != "ERROR:unexpected_message" {
			t.Fatalf("table total default for %s/%s = %q, want ERROR:unexpected_message", c.state, c.input, got)
		}
	}

	// Pre-key deviants must resolve to SILENT_ABORT.
	for _, c := range []struct{ role, state, input string }{
		{"responder", "LISTEN", "SERVER_HELLO"},
		{"initiator", "WAIT_SH", "CLIENT_HELLO"},
	} {
		if got := tbl.expect(c.role, c.state, c.input); got != "SILENT_ABORT" {
			t.Fatalf("table for %s/%s/%s = %q, want SILENT_ABORT", c.role, c.state, c.input, got)
		}
	}
}
