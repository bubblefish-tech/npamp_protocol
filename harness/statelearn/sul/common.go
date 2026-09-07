// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package main

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"os"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// chanState tracks the driver's own bookkeeping of ONE channel's SEND-direction
// epoch/sequence — the counter the driver must match so a properly-sealed injected frame
// is accepted by the SUT's receive-side epochKeys check (sdk/conn.go recvLocked: `f.Seq !=
// st.seq` rejects before any frame-type logic runs). It mirrors sdk/conn.go's unexported
// epochKeys, reimplemented here because that type is unexported and this package may not
// modify impl/go/sdk. Only the driver's OWN outbound direction needs tracking: the SUT's
// outbound seq is read directly off each frame's own Seq field when the driver opens it
// (see wire.go openFrameWire), so no independent "expected" counter is needed for reads.
type chanState struct {
	epoch uint64
	seq   uint64
}

// advance mirrors epochKeys.advance: bump the epoch and reset the sequence counter, as the
// SDK does on a successful KEY_UPDATE.
func (c *chanState) advance() {
	c.epoch++
	c.seq = 0
}

// dummyAuthPayload returns a structurally well-formed but semantically meaningless
// AuthMessage encoding (correct-length CertVerify/Finished so a decoder does not choke
// structurally), used for symbols that are ALWAYS role-nonsensical for the SUT under test
// (e.g. feeding "CLIENT_AUTH" — a frame the client only ever SENDS — to an initiator SUT,
// which can only ever receive it as a total-default reject, never as content the SUT
// actually parses). identity is whichever fixed key is cosmetically plausible as the
// claimed IdentityKey field; its value has no bearing on the observed reaction.
func dummyAuthPayload(identity ed25519.PublicKey) []byte {
	certVerify := make([]byte, 2+ed25519.SignatureSize) // SignatureScheme(2) || sig(64)
	binary.BigEndian.PutUint16(certVerify, uint16(npamp.SigEd25519))
	finished := make([]byte, 32) // SHA-256 HMAC length at Standard profile
	am := &npamp.AuthMessage{IdentityKey: identity, CertVerify: certVerify, Finished: finished}
	return am.Encode()
}

// keyUpdateMarkerBytes encodes the TLV 0x17 KeyUpdateMarker payload for a KEY_UPDATE /
// KEY_UPDATE_ACK frame (mirrors sdk/keyupdate.go's unexported keyUpdateMarker).
func keyUpdateMarkerBytes(epoch uint64) []byte {
	var v [8]byte
	binary.BigEndian.PutUint64(v[:], epoch)
	return npamp.TLV{Type: npamp.TLVKeyUpdateMarker, Value: v[:]}.Encode(nil)
}

// unknownFrameType is the abstract UNKNOWN input's concretization: an unassigned reserved
// Control-channel type (T18.1/T18.2 plan: "0x00FE — NOT a ratchet type, per the table's
// modeled_exclusion"), matching impl/go/sdk/statetrace_test.go's
// TestStateTable_EstablishedTotalDefault/unknown_type mutation anchor.
const unknownFrameType = npamp.FrameType(0x00FE)

// appChannel is the single non-Control channel this harness uses to concretize the
// abstract APP input (an application frame on any open channel — draft:862). Any channel
// other than Control resolves identically in sdk/conn.go's recvLocked default case, so one
// representative channel suffices.
const appChannel = npamp.ChanMemory

// appFrameType is an arbitrary channel-specific frame type for the APP concretization; its
// value is never interpreted specially by the SDK (non-Control frames are delivered
// verbatim regardless of type).
const appFrameType = npamp.ChannelSpecificBase

// logf writes a diagnostic line to stderr (never stdout, which is reserved for the
// RESET/step response protocol the Java harness reads).
func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "sul: "+format+"\n", args...)
}

// waitFrame is the result of racing a raw-wire read against a "the handshake/session
// concluded" signal, used by both scenario implementations to classify a step's reaction.
type waitFrame struct {
	frame   *npamp.Frame
	timeout bool // no frame arrived within the window and the connection is still alive
	closed  bool // the connection is confirmed torn down (EOF / explicit signal), no frame
}

const (
	// reactionWindow is how long a single readWireFrame attempt blocks for the FIRST byte of
	// a reaction before this harness concludes "nothing else is coming yet".
	reactionWindow = silentWindow
	// abortGrace is a short additional wait after a read timeout, giving a just-scheduled
	// goroutine (the blocked handshake call, or a torn-down socket) time to signal before
	// this harness commits to "still alive, no reaction" (SILENT) rather than "torn down"
	// (SILENT_ABORT).
	abortGrace = 60 * time.Millisecond
)
