// Command npamp-interop is the Go side of the Go<->Rust two-implementation
// interop harness for the N-PAMP 1.5-RTT mutually-authenticated handshake
// (spec/10). It drives the SAME handshake the reference SDK's runClientHandshake
// / runServerHandshake drive (impl/go/sdk/handshake.go), but over a RAW TCP
// stream — the N-PAMP handshake is transport-agnostic (four frames over the
// Control channel), so this omits only the SDK's TLS 1.3 (ALPN "n-pamp/2")
// transport binding. It interoperates frame-for-frame and byte-for-byte with the
// Rust reference examples impl/rust/examples/interop_{client,server}.rs.
//
// Usage:
//
//	npamp-interop -role server -addr 127.0.0.1:47700
//	npamp-interop -role client -addr 127.0.0.1:47700
//
// A server accepts one connection, completes the server handshake, receives one
// AEAD-protected application frame on the Memory channel, and echoes it back. A
// client completes the client handshake, sends one application frame, and verifies
// the server's echo byte-for-byte (exit 0 iff the round-trip matches).
//
// Every primitive used here is an EXPORTED function of the reference impl/go
// package (the same core the sdk package calls); the unexported sdk driver is not
// importable, so the four-frame flow is reproduced with the exported API.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

const (
	appFrameType = 0x0120 // application-defined frame type (matches the Rust example)
	profile      = npamp.ProfileStandard
	maxFrameSize = 16 << 20
)

func main() {
	role := flag.String("role", "", "server | client")
	addr := flag.String("addr", "127.0.0.1:47700", "host:port")
	flag.Parse()

	if err := run(*role, *addr); err != nil {
		fmt.Fprintf(os.Stderr, "npamp-interop(%s): %v\n", *role, err)
		os.Exit(1)
	}
}

func run(role, addr string) error {
	switch role {
	case "server":
		return runServer(addr)
	case "client":
		return runClient(addr)
	default:
		return fmt.Errorf("-role must be 'server' or 'client'")
	}
}

// ---------------------------------------------------------------------------
// server
// ---------------------------------------------------------------------------
func runServer(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	defer ln.Close()
	priv, pub, err := genIdentity()
	if err != nil {
		return err
	}
	fmt.Printf("npamp-interop server: listening on %s\n", ln.Addr())
	fmt.Printf("npamp-interop server: identity ed25519 = %s\n", hex8(pub))

	conn, err := ln.Accept()
	if err != nil {
		return fmt.Errorf("accept: %w", err)
	}
	defer conn.Close()
	fmt.Printf("npamp-interop server: accepted %s\n", conn.RemoteAddr())

	master, peer, err := serverHandshake(conn, priv, pub)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	fmt.Printf("npamp-interop server: handshake OK — authenticated client ed25519 = %s\n", hex8(peer))

	// Receive one application frame from the client (recv dir = C2S), seq 0.
	channel, ftype, pt, err := recvData(conn, master, npamp.DirClientToServer, 0)
	if err != nil {
		return fmt.Errorf("recv data: %w", err)
	}
	fmt.Printf("npamp-interop server: recv channel=0x%04x type=0x%04x payload=%q\n", channel, ftype, pt)

	// Echo it back (send dir = S2C), seq 0.
	if err := sendData(conn, master, npamp.DirServerToClient, channel, appFrameType, 0, pt); err != nil {
		return fmt.Errorf("echo data: %w", err)
	}
	fmt.Println("npamp-interop server: echoed payload back; interop OK")
	return nil
}

// ---------------------------------------------------------------------------
// client
// ---------------------------------------------------------------------------
func runClient(addr string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()
	priv, pub, err := genIdentity()
	if err != nil {
		return err
	}
	fmt.Printf("npamp-interop client: connected to %s\n", addr)
	fmt.Printf("npamp-interop client: identity ed25519 = %s\n", hex8(pub))

	master, peer, err := clientHandshake(conn, priv, pub)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	fmt.Printf("npamp-interop client: handshake OK — authenticated server ed25519 = %s\n", hex8(peer))

	payload := []byte("hello from the go interop client")
	if err := sendData(conn, master, npamp.DirClientToServer, uint16(npamp.ChanMemory), appFrameType, 0, payload); err != nil {
		return fmt.Errorf("send data: %w", err)
	}
	fmt.Printf("npamp-interop client: sent %d octets on the Memory channel\n", len(payload))

	channel, ftype, echo, err := recvData(conn, master, npamp.DirServerToClient, 0)
	if err != nil {
		return fmt.Errorf("recv echo: %w", err)
	}
	fmt.Printf("npamp-interop client: recv echo channel=0x%04x type=0x%04x payload=%q\n", channel, ftype, echo)
	if !bytes.Equal(echo, payload) {
		return fmt.Errorf("echo did not match sent payload")
	}
	fmt.Println("npamp-interop client: PASS — live N-PAMP handshake + data frame round-trip verified")
	return nil
}

// ---------------------------------------------------------------------------
// handshake drivers (mirror impl/go/sdk/handshake.go over raw TCP)
// ---------------------------------------------------------------------------
func clientHandshake(conn net.Conn, priv ed25519.PrivateKey, pub ed25519.PublicKey) (master []byte, peer ed25519.PublicKey, err error) {
	kem, err := npamp.GenerateKEMClient()
	if err != nil {
		return nil, nil, fmt.Errorf("KEM keygen: %w", err)
	}
	ch := &npamp.ClientHello{
		ProfileOffer: []npamp.Profile{profile},
		KEMOffer:     []npamp.KEMID{npamp.KEMX25519MLKEM768},
		SigOffer:     []npamp.SigID{npamp.SigEd25519},
		AEADOffer:    []npamp.AEADID{npamp.AEADAES256GCM},
		KEMShare:     kem.KEMShare(),
	}
	t := npamp.NewTranscript(profile)
	if err := sendCleartext(conn, npamp.FrameClientHello, ch.Encode()); err != nil {
		return nil, nil, err
	}
	t.AddFrame(npamp.FrameClientHello, ch.TLVs())

	shPayload, err := recvCleartext(conn, npamp.FrameServerHello)
	if err != nil {
		return nil, nil, err
	}
	sh, err := npamp.DecodeServerHello(shPayload)
	if err != nil {
		return nil, nil, err
	}
	t.AddFrame(npamp.FrameServerHello, sh.TLVs())

	ss, err := kem.SharedSecrets(sh.KEMCiphertext)
	if err != nil {
		return nil, nil, fmt.Errorf("KEM decapsulate: %w", err)
	}
	hs, err := npamp.HandshakeSecret(ss, profile)
	if err != nil {
		return nil, nil, err
	}
	cHS, sHS, err := npamp.DeriveHandshakeTrafficSecrets(hs, t.Sum(), profile)
	if err != nil {
		return nil, nil, err
	}

	// SERVER_AUTH
	saWire, err := readFrame(conn)
	if err != nil {
		return nil, nil, err
	}
	sAuth, err := openAuth(saWire, npamp.FrameServerAuth, sHS, npamp.DirServerToClient)
	if err != nil {
		return nil, nil, err
	}
	t.AddFrameType(npamp.FrameServerAuth)
	t.AddTLV(npamp.TLV{Type: npamp.TLVIdentityKey, Value: sAuth.IdentityKey})
	if err := npamp.VerifyCertVerify(sAuth.IdentityKey, npamp.RoleServer, t.Sum(), sAuth.CertVerify); err != nil {
		return nil, nil, fmt.Errorf("server CertVerify: %w", err)
	}
	t.AddTLV(npamp.TLV{Type: npamp.TLVCertVerify, Value: sAuth.CertVerify})
	sFinKey, err := npamp.DeriveFinishedKey(sHS, profile)
	if err != nil {
		return nil, nil, err
	}
	if err := npamp.VerifyFinished(sFinKey, t.Sum(), sAuth.Finished, profile); err != nil {
		return nil, nil, fmt.Errorf("server Finished: %w", err)
	}
	t.AddTLV(npamp.TLV{Type: npamp.TLVFinished, Value: sAuth.Finished})
	peer = append(ed25519.PublicKey(nil), sAuth.IdentityKey...)

	// CLIENT_AUTH
	t.AddFrameType(npamp.FrameClientAuth)
	t.AddTLV(npamp.TLV{Type: npamp.TLVIdentityKey, Value: pub})
	cCV, err := npamp.SignCertVerify(priv, npamp.RoleClient, t.Sum())
	if err != nil {
		return nil, nil, err
	}
	t.AddTLV(npamp.TLV{Type: npamp.TLVCertVerify, Value: cCV})
	thCCV := t.Sum()
	cFinKey, err := npamp.DeriveFinishedKey(cHS, profile)
	if err != nil {
		return nil, nil, err
	}
	cFin := npamp.ComputeFinished(cFinKey, thCCV, profile)
	auth := &npamp.AuthMessage{IdentityKey: pub, CertVerify: cCV, Finished: cFin}
	caWire, err := sealFrame(cHS, npamp.DirClientToServer, uint16(npamp.ChanControl), 0, npamp.FrameClientAuth, auth.Encode())
	if err != nil {
		return nil, nil, err
	}
	if err := writeFrame(conn, caWire); err != nil {
		return nil, nil, err
	}

	master, err = npamp.DeriveMasterSecret(hs, thCCV, profile)
	if err != nil {
		return nil, nil, err
	}
	return master, peer, nil
}

func serverHandshake(conn net.Conn, priv ed25519.PrivateKey, pub ed25519.PublicKey) (master []byte, peer ed25519.PublicKey, err error) {
	t := npamp.NewTranscript(profile)

	chPayload, err := recvCleartext(conn, npamp.FrameClientHello)
	if err != nil {
		return nil, nil, err
	}
	ch, err := npamp.DecodeClientHello(chPayload)
	if err != nil {
		return nil, nil, err
	}
	t.AddFrame(npamp.FrameClientHello, ch.TLVs())

	kemCT, ss, err := npamp.Encapsulate(ch.KEMShare)
	if err != nil {
		return nil, nil, fmt.Errorf("KEM encapsulate: %w", err)
	}
	sh := &npamp.ServerHello{
		ProfileSelect: npamp.ProfileStandard,
		KEMSelect:     npamp.KEMX25519MLKEM768,
		SigSelect:     npamp.SigEd25519,
		AEADSelect:    npamp.AEADAES256GCM,
		KEMCiphertext: kemCT,
	}
	if err := sendCleartext(conn, npamp.FrameServerHello, sh.Encode()); err != nil {
		return nil, nil, err
	}
	t.AddFrame(npamp.FrameServerHello, sh.TLVs())

	hs, err := npamp.HandshakeSecret(ss, profile)
	if err != nil {
		return nil, nil, err
	}
	cHS, sHS, err := npamp.DeriveHandshakeTrafficSecrets(hs, t.Sum(), profile)
	if err != nil {
		return nil, nil, err
	}

	// SERVER_AUTH
	t.AddFrameType(npamp.FrameServerAuth)
	t.AddTLV(npamp.TLV{Type: npamp.TLVIdentityKey, Value: pub})
	sCV, err := npamp.SignCertVerify(priv, npamp.RoleServer, t.Sum())
	if err != nil {
		return nil, nil, err
	}
	t.AddTLV(npamp.TLV{Type: npamp.TLVCertVerify, Value: sCV})
	sFinKey, err := npamp.DeriveFinishedKey(sHS, profile)
	if err != nil {
		return nil, nil, err
	}
	sFin := npamp.ComputeFinished(sFinKey, t.Sum(), profile)
	t.AddTLV(npamp.TLV{Type: npamp.TLVFinished, Value: sFin})
	auth := &npamp.AuthMessage{IdentityKey: pub, CertVerify: sCV, Finished: sFin}
	saWire, err := sealFrame(sHS, npamp.DirServerToClient, uint16(npamp.ChanControl), 0, npamp.FrameServerAuth, auth.Encode())
	if err != nil {
		return nil, nil, err
	}
	if err := writeFrame(conn, saWire); err != nil {
		return nil, nil, err
	}

	// CLIENT_AUTH
	caWire, err := readFrame(conn)
	if err != nil {
		return nil, nil, err
	}
	cAuth, err := openAuth(caWire, npamp.FrameClientAuth, cHS, npamp.DirClientToServer)
	if err != nil {
		return nil, nil, err
	}
	t.AddFrameType(npamp.FrameClientAuth)
	t.AddTLV(npamp.TLV{Type: npamp.TLVIdentityKey, Value: cAuth.IdentityKey})
	if err := npamp.VerifyCertVerify(cAuth.IdentityKey, npamp.RoleClient, t.Sum(), cAuth.CertVerify); err != nil {
		return nil, nil, fmt.Errorf("client CertVerify: %w", err)
	}
	t.AddTLV(npamp.TLV{Type: npamp.TLVCertVerify, Value: cAuth.CertVerify})
	thCCV := t.Sum()
	cFinKey, err := npamp.DeriveFinishedKey(cHS, profile)
	if err != nil {
		return nil, nil, err
	}
	if err := npamp.VerifyFinished(cFinKey, thCCV, cAuth.Finished, profile); err != nil {
		return nil, nil, fmt.Errorf("client Finished: %w", err)
	}
	peer = append(ed25519.PublicKey(nil), cAuth.IdentityKey...)

	master, err = npamp.DeriveMasterSecret(hs, thCCV, profile)
	if err != nil {
		return nil, nil, err
	}
	return master, peer, nil
}

// ---------------------------------------------------------------------------
// frame I/O + record layer (exported-primitive replicas of the sdk helpers)
// ---------------------------------------------------------------------------
func sendCleartext(conn net.Conn, ft npamp.FrameType, payload []byte) error {
	f := npamp.Frame{Type: uint16(ft), Channel: uint16(npamp.ChanControl), Seq: 0, Payload: payload}
	wire, err := f.MarshalBinary()
	if err != nil {
		return err
	}
	return writeFrame(conn, wire)
}

func recvCleartext(conn net.Conn, want npamp.FrameType) ([]byte, error) {
	wire, err := readFrame(conn)
	if err != nil {
		return nil, err
	}
	var f npamp.Frame
	if err := f.UnmarshalBinary(wire); err != nil {
		return nil, err
	}
	if f.Type != uint16(want) {
		return nil, fmt.Errorf("got frame type 0x%04x, want 0x%04x", f.Type, uint16(want))
	}
	if f.Flags&npamp.FlagENC != 0 {
		return nil, fmt.Errorf("handshake hello frame unexpectedly encrypted")
	}
	return f.Payload, nil
}

func deriveKeyIV(base []byte, dir npamp.Direction, channel npamp.ChannelID) (key [32]byte, iv [12]byte, err error) {
	ts, err := npamp.DeriveTrafficSecret(base, dir, 0, npamp.AEADAES256GCM, channel, profile)
	if err != nil {
		return key, iv, err
	}
	return npamp.DeriveKeyIV(ts, profile)
}

func sealFrame(base []byte, dir npamp.Direction, channel uint16, seq uint64, ft npamp.FrameType, plaintext []byte) ([]byte, error) {
	key, iv, err := deriveKeyIV(base, dir, npamp.ChannelID(channel))
	if err != nil {
		return nil, err
	}
	f := npamp.Frame{Flags: npamp.FlagENC, Type: uint16(ft), Channel: channel, Seq: seq}
	var aad [21]byte
	f.HeaderPrefix(aad[:], uint32(len(plaintext)+16))
	sealed, err := npamp.SealAES256GCM(key, iv, seq, aad[:], plaintext)
	if err != nil {
		return nil, err
	}
	f.Payload = sealed
	return f.MarshalBinary()
}

func openAuth(wire []byte, want npamp.FrameType, base []byte, dir npamp.Direction) (*npamp.AuthMessage, error) {
	var f npamp.Frame
	if err := f.UnmarshalBinary(wire); err != nil {
		return nil, err
	}
	if f.Type != uint16(want) {
		return nil, fmt.Errorf("got frame type 0x%04x, want 0x%04x", f.Type, uint16(want))
	}
	if f.Flags&npamp.FlagENC == 0 {
		return nil, fmt.Errorf("AUTH frame is not AEAD-encrypted")
	}
	pt, err := openFrame(&f, base, dir)
	if err != nil {
		return nil, err
	}
	return npamp.DecodeAuthMessage(pt)
}

func openFrame(f *npamp.Frame, base []byte, dir npamp.Direction) ([]byte, error) {
	key, iv, err := deriveKeyIV(base, dir, npamp.ChannelID(f.Channel))
	if err != nil {
		return nil, err
	}
	var aad [21]byte
	f.HeaderPrefix(aad[:], uint32(len(f.Payload)))
	return npamp.OpenAES256GCM(key, iv, f.Seq, aad[:], f.Payload)
}

func sendData(conn net.Conn, master []byte, dir npamp.Direction, channel, ft uint16, seq uint64, payload []byte) error {
	wire, err := sealFrame(master, dir, channel, seq, npamp.FrameType(ft), payload)
	if err != nil {
		return err
	}
	return writeFrame(conn, wire)
}

func recvData(conn net.Conn, master []byte, dir npamp.Direction, wantSeq uint64) (channel, ftype uint16, pt []byte, err error) {
	wire, err := readFrame(conn)
	if err != nil {
		return 0, 0, nil, err
	}
	var f npamp.Frame
	if err := f.UnmarshalBinary(wire); err != nil {
		return 0, 0, nil, err
	}
	if f.Flags&npamp.FlagENC == 0 {
		return 0, 0, nil, fmt.Errorf("data frame is not AEAD-encrypted")
	}
	if f.Seq != wantSeq {
		return 0, 0, nil, fmt.Errorf("out-of-sequence data frame: got %d, want %d", f.Seq, wantSeq)
	}
	pt, err = openFrame(&f, master, dir)
	if err != nil {
		return 0, 0, nil, err
	}
	return f.Channel, f.Type, pt, nil
}

// writeFrame / readFrame reproduce the sdk's self-delimiting framing.
func writeFrame(w io.Writer, frame []byte) error {
	_, err := w.Write(frame)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	header := make([]byte, npamp.HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	if !bytes.Equal(header[:4], npamp.Magic[:]) {
		return nil, fmt.Errorf("bad frame magic %#x, want NPAM", header[:4])
	}
	payloadLen := binary.BigEndian.Uint32(header[17:21])
	total := int64(npamp.HeaderSize) + int64(payloadLen)
	if total > int64(maxFrameSize) {
		return nil, fmt.Errorf("frame size %d exceeds max %d", total, maxFrameSize)
	}
	buf := bytes.NewBuffer(make([]byte, 0, npamp.HeaderSize))
	buf.Write(header)
	if _, err := io.CopyN(buf, r, int64(payloadLen)); err != nil {
		return nil, fmt.Errorf("read frame payload (%d octets): %w", payloadLen, err)
	}
	return buf.Bytes(), nil
}

func genIdentity() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate identity: %w", err)
	}
	return priv, pub, nil
}

func hex8(b []byte) string {
	if len(b) > 8 {
		b = b[:8]
	}
	return hex.EncodeToString(b)
}
