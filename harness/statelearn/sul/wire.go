// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package main is the N-PAMP T18.2 LearnLib SUL (System Under Learning) driver. It speaks a
// line-oriented stdio protocol (RESET / <input-symbol> -> <output-symbol>) to a Java LearnLib
// harness, and on the wire it drives the REAL, unmodified N-PAMP Go SDK
// (github.com/bubblefish-tech/npamp_protocol/impl/go/sdk) over an in-process net.Pipe using
// the SDK's own public entry points (sdk.DialRaw / sdk.AcceptRaw, Conn.Recv,
// Conn.CloseGraceful).
//
// F3/A9 note: harness/statelearn may not modify any file outside itself (including
// impl/go/sdk), so it cannot call the sdk package's unexported test-only helpers
// (runClientHandshake/runServerHandshake/sealFrame/readFrame/... — see
// impl/go/sdk/statetrace_test.go, the T18.1 template). Instead the "driver" (scripted
// deviant peer) role in this file reimplements the SAME wire-level framing/sealing math
// using ONLY EXPORTED building blocks from the root npamp package (Frame, SealAES256GCM,
// DeriveTrafficSecret, DeriveKeyIV, HandshakeSecret, DeriveHandshakeTrafficSecrets,
// DeriveMasterSecret, SignCertVerify/VerifyCertVerify, ComputeFinished/VerifyFinished,
// NewTranscript, ...) — the exact same three-to-eight-line wrappers sdk/conn.go's private
// sealFrame/deriveKeyIV/openFrame perform, reproduced here because Go's package boundary
// (not a difference in logic) blocks a direct import. The SUT itself is always the REAL
// sdk.DialRaw / sdk.AcceptRaw / Conn.Recv / Conn.CloseGraceful — never reimplemented.
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// profile is the single security profile this harness drives (the SDK is Standard-only).
const profile = npamp.ProfileStandard

// silentWindow bounds how long the driver waits for a reaction frame before concluding
// "nothing is coming" (SILENT). Both peers are in-process over a synchronous net.Pipe, so a
// genuine reaction is delivered at goroutine-scheduling speed — sub-millisecond, as the
// smoke-test round-trips confirm (establish + react in < 1 ms). This window therefore only
// absorbs scheduling / GC jitter. 100 ms is ~100x the observed reaction latency and well
// above any Go GC pause on this tiny heap, yet small enough that the many SILENT-classifying
// steps of a full active learn stay tractable: the 200 ms value carried over from the removed
// loopback-TCP+TLS transport made even a WP_DEPTH=2 learn exceed a practical wall-clock. A
// too-short window would misclassify a delayed reaction as SILENT and surface as a spurious
// diff mismatch or a TTT nondeterminism crash — so a clean diff plus the recorded mutation
// (which must still flip the diff RED) together validate this value.
const silentWindow = 100 * time.Millisecond

// ioTimeout bounds ordinary (non-silence-probing) reads/writes so a wedged connection
// cannot hang a query indefinitely. The SDK has no protocol timers of its own in play here
// (HandshakeTimeout is left at zero; CloseGraceful's internal 5s ack-wait is the one timer
// this harness cannot shorten, since it lives in sdk/close.go and is not exported).
const ioTimeout = 5 * time.Second

// readWireFrame reads exactly one self-delimiting N-PAMP frame from conn, bounded by
// timeout (0 = no deadline). It mirrors sdk/conn.go's unexported readFrame byte-for-byte,
// reimplemented with only exported npamp building blocks (see package doc).
func readWireFrame(conn net.Conn, timeout time.Duration) (*npamp.Frame, error) {
	if timeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return nil, err
		}
		defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	}
	header := make([]byte, npamp.HeaderSize)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	payloadLen := binary.BigEndian.Uint32(header[17:21])
	total := int64(npamp.HeaderSize) + int64(payloadLen)
	if total > int64(npamp.MaxFrameSize) {
		return nil, fmt.Errorf("sul: frame size %d exceeds max %d", total, npamp.MaxFrameSize)
	}
	buf := make([]byte, npamp.HeaderSize, total)
	copy(buf, header)
	if payloadLen > 0 {
		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return nil, err
		}
		buf = append(buf, payload...)
	}
	var f npamp.Frame
	if err := f.UnmarshalBinary(buf); err != nil {
		return nil, err
	}
	return &f, nil
}

// writeWireFrame writes a marshaled frame verbatim, bounded by timeout (0 = no deadline).
func writeWireFrame(conn net.Conn, wire []byte, timeout time.Duration) error {
	if timeout > 0 {
		if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
		defer func() { _ = conn.SetWriteDeadline(time.Time{}) }()
	}
	_, err := conn.Write(wire)
	return err
}

// sendCleartextFrame writes a cleartext (no FlagENC) frame on the Control channel at seq 0 —
// the wire shape of CLIENT_HELLO / SERVER_HELLO (mirrors sdk/handshake.go's sendCleartext).
func sendCleartextFrame(conn net.Conn, ft npamp.FrameType, payload []byte) error {
	f := npamp.Frame{Type: uint16(ft), Channel: uint16(npamp.ChanControl), Seq: 0, Payload: payload}
	wire, err := f.MarshalBinary()
	if err != nil {
		return err
	}
	return writeWireFrame(conn, wire, ioTimeout)
}

// recvCleartextFrame reads one cleartext frame and checks its type (mirrors
// sdk/handshake.go's recvCleartext).
func recvCleartextFrame(conn net.Conn, want npamp.FrameType, timeout time.Duration) ([]byte, error) {
	f, err := readWireFrame(conn, timeout)
	if err != nil {
		return nil, err
	}
	if f.Type != uint16(want) {
		return nil, fmt.Errorf("sul: got frame type 0x%04x, want 0x%04x", f.Type, uint16(want))
	}
	if f.Flags&npamp.FlagENC != 0 {
		return nil, fmt.Errorf("sul: expected a cleartext frame, got FlagENC set")
	}
	return f.Payload, nil
}

// deriveKeyIV derives the AEAD key/iv for (base secret, direction, epoch, channel) — the
// SAME derivation sdk/conn.go's epochKeys.derive (post-handshake, base=master) and
// sdk/conn.go's unexported deriveKeyIV (handshake AUTH frames, base=cHS/sHS, epoch
// implicitly 0) both perform, unified here into one function since they are the identical
// two-call sequence (DeriveTrafficSecret + DeriveKeyIV) at different epochs.
func deriveKeyIV(base []byte, dir npamp.Direction, epoch uint64, channel npamp.ChannelID, p npamp.Profile) (key [32]byte, iv [12]byte, err error) {
	ts, err := npamp.DeriveTrafficSecret(base, dir, epoch, npamp.AEADAES256GCM, channel, p)
	if err != nil {
		return key, iv, err
	}
	return npamp.DeriveKeyIV(ts, p)
}

// sealFrameWire AEAD-seals plaintext into a marshaled, self-delimiting frame under
// (base,dir,epoch,channel,seq) — mirrors sdk/conn.go's unexported sealFrame / sealWith.
func sealFrameWire(base []byte, dir npamp.Direction, epoch uint64, channel npamp.ChannelID, seq uint64, ft npamp.FrameType, plaintext []byte, p npamp.Profile) ([]byte, error) {
	key, iv, err := deriveKeyIV(base, dir, epoch, channel, p)
	if err != nil {
		return nil, err
	}
	f := npamp.Frame{Flags: npamp.FlagENC, Type: uint16(ft), Channel: uint16(channel), Seq: seq}
	var aad [21]byte
	f.HeaderPrefix(aad[:], uint32(len(plaintext)+16)) // +16: AES-256-GCM tag
	sealed, err := npamp.SealAES256GCM(key, iv, seq, aad[:], plaintext)
	if err != nil {
		return nil, err
	}
	f.Payload = sealed
	return f.MarshalBinary()
}

// openFrameWire opens an already-parsed FlagENC frame under (base,dir,epoch) — mirrors
// sdk/conn.go's unexported openFrame / openWith.
func openFrameWire(f *npamp.Frame, base []byte, dir npamp.Direction, epoch uint64, p npamp.Profile) ([]byte, error) {
	key, iv, err := deriveKeyIV(base, dir, epoch, npamp.ChannelID(f.Channel), p)
	if err != nil {
		return nil, err
	}
	var aad [21]byte
	f.HeaderPrefix(aad[:], uint32(len(f.Payload)))
	return npamp.OpenAES256GCM(key, iv, f.Seq, aad[:], f.Payload)
}

// errCodeOutput maps a decoded SessionErrorCode to the abstract "ERROR:<name>" output
// symbol used throughout the state table.
func errCodeOutput(code npamp.SessionErrorCode) string {
	return "ERROR:" + code.String()
}
