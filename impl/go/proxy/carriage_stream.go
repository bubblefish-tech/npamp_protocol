// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package proxy

import (
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// NPAMP-CC-STREAM (spec/companion/23_carriage_streaming.md) shared codec,
// composed by both the gRPC leg (carriage_grpc.go/grpc.go) and the WebSocket
// leg (carriage_websocket.go/websocket.go) -- per NPAMP-REG (spec/companion/
// 30_protocol_registry.md §6), `protocol_id 0x04` "WebSocket generic carriage"
// is assigned carriage class STREAM, not MESSAGING; gRPC has no assigned
// `protocol_id` (§7.1 experimental range), and this build uses one locally
// (carriage_grpc.go) under STREAM because gRPC's native streaming model and
// its already-reserved `content_type=application/grpc+proto` (bridge.go) fit
// this class, not NPAMP-CC-MSG's performative/speech-act model. This file
// implements §5 (StreamControl TLV) precisely and the §5.1 event-id
// invariant; grpc.go/websocket.go layer their own class-specific request/
// reply shape and producer policy on top.

// TLVStreamControl is the NPAMP-CC-STREAM §5.3 StreamControl TLV Type. It is
// PROVISIONAL pending an explicit core-specification reservation (§11) --
// this package treats it exactly as the companion spec's own open item
// describes: usable today, without a guarantee of interoperability with an
// independently developed peer that has bound 0x0011 to a different meaning.
const TLVStreamControl npamp.TLVType = 0x0011

// StreamControl `control` selector values (§5.2).
const (
	streamControlData   uint8 = 0x00
	streamControlResume uint8 = 0x01
	streamControlCancel uint8 = 0x02
)

// StreamControl `flags` bits (§5.2).
const (
	streamFlagResumable uint8 = 0x01
	streamFlagCancelAck uint8 = 0x02
)

// streamControlVersion is the only StreamControl format version this
// document defines (§5.2); a peer's TLV carrying any other version MUST be
// rejected.
const streamControlVersion uint8 = 0x01

// BridgeErrNotResumable is NPAMP-CC-STREAM's additional N-PAMP transport-error
// code (§6.4), continuing the NPAMP-BRIDGE §6 numbering (1-5) with 6.
const BridgeErrNotResumable npamp.BridgeErrorCode = 6

// streamControl is the decoded §5.2 StreamControl TLV value.
type streamControl struct {
	Control uint8
	Flags   uint8
	EventID uint64
}

func (s streamControl) Resumable() bool { return s.Flags&streamFlagResumable != 0 }
func (s streamControl) CancelAck() bool { return s.Flags&streamFlagCancelAck != 0 }

// errStreamMalformed reports a §5.2/§9 StreamControl structural failure. Every
// failure here MUST be reported to the peer as BRIDGE_ERROR code
// EnvelopeMalformed (§9), matching carriage_http.go's errCarriageMalformed and
// carriage_jsonrpc.go's errJSONRPCMalformed convention for this package.
type errStreamMalformed struct{ reason string }

func (e *errStreamMalformed) Error() string {
	return fmt.Sprintf("npamp/proxy: StreamControl TLV malformed: %s", e.reason)
}

// encodeStreamControlValue encodes the fixed 11-octet §5.2 value: version(1) +
// control(1) + flags(1) + event_id(8, big-endian).
func encodeStreamControlValue(sc streamControl) []byte {
	v := make([]byte, 11)
	v[0] = streamControlVersion
	v[1] = sc.Control
	v[2] = sc.Flags
	binary.BigEndian.PutUint64(v[3:11], sc.EventID)
	return v
}

// decodeLeadingStreamControl parses a StreamControl TLV from the FRONT of buf
// and returns the decoded control plus the remaining bytes (the real foreign
// event, carried verbatim, NPAMP-BRIDGE §1). This is a bare TLV-header parse
// (Type u16, Length u16, matching the core extension-TLV encoding, tlv.go);
// npamp.DecodeTLVs is not used because it requires the ENTIRE buffer to
// consist of TLVs, whereas here exactly one TLV precedes opaque event bytes
// that MUST NOT themselves be parsed as TLVs (§9: "MUST treat the foreign
// event as opaque").
func decodeLeadingStreamControl(buf []byte) (streamControl, []byte, error) {
	if len(buf) < 4 {
		return streamControl{}, nil, &errStreamMalformed{reason: fmt.Sprintf("payload %d octets, too short for a TLV header", len(buf))}
	}
	typ := npamp.TLVType(binary.BigEndian.Uint16(buf[0:2]))
	ln := int(binary.BigEndian.Uint16(buf[2:4]))
	if typ != TLVStreamControl {
		return streamControl{}, nil, &errStreamMalformed{reason: fmt.Sprintf("first TLV type 0x%04x is not StreamControl (0x0011)", uint16(typ))}
	}
	if len(buf) < 4+ln {
		return streamControl{}, nil, &errStreamMalformed{reason: "StreamControl TLV Length exceeds remaining payload"}
	}
	v := buf[4 : 4+ln]
	if len(v) != 11 {
		return streamControl{}, nil, &errStreamMalformed{reason: fmt.Sprintf("StreamControl TLV Length %d, want 11 (§5.2)", len(v))}
	}
	if v[0] != streamControlVersion {
		return streamControl{}, nil, &errStreamMalformed{reason: fmt.Sprintf("StreamControl version 0x%02x not implemented (this build implements 0x01)", v[0])}
	}
	switch v[1] {
	case streamControlData, streamControlResume, streamControlCancel:
	default:
		return streamControl{}, nil, &errStreamMalformed{reason: fmt.Sprintf("undefined StreamControl control value 0x%02x", v[1])}
	}
	sc := streamControl{Control: v[1], Flags: v[2], EventID: binary.BigEndian.Uint64(v[3:11])}
	return sc, buf[4+ln:], nil
}

// encodeStreamFrame builds a Bridge frame payload for a BRIDGE_STREAM_DATA or
// BRIDGE_STREAM_END frame (§4): the envelope TLV, then the StreamControl TLV
// concatenated with the foreign event as the NPAMP-BRIDGE "foreign" region
// (TLV order is not significant within a payload, §4). It composes the
// already-graded Part-1 npamp.EncodeBridgePayload/npamp.TLV primitives and
// defines no new frame type or header layout of its own.
func encodeStreamFrame(env npamp.BridgeEnvelope, sc streamControl, event []byte) []byte {
	foreign := npamp.TLV{Type: TLVStreamControl, Value: encodeStreamControlValue(sc)}.Encode(nil)
	foreign = append(foreign, event...)
	return npamp.EncodeBridgePayload(env, nil, foreign)
}

// streamChunk is one decoded stream reply frame delivered to a consumer
// waiting on openConsumerStream's channel (stream.go).
type streamChunk struct {
	ft      npamp.FrameType // FrameBridgeStreamData or FrameBridgeStreamEnd
	control streamControl
	event   []byte
	err     error // a decode failure for this specific frame; event/control are zero when set
}

// atomicBool is a cancel flag shared between Run's receive loop (setter, on
// an observed §7.1 upstream cancel) and a producer loop (checker, between
// event emissions) -- a real, if coarse-grained (checked between emissions,
// not preemptive mid-Send), cooperative cancellation signal per §7.2 "MUST
// cease emitting new BRIDGE_STREAM_DATA frames ... as soon as it observes the
// cancel." See grpc.go/websocket.go for the honestly-scoped producer policy
// this drives.
type atomicBool struct{ v atomic.Bool }

func (a *atomicBool) set()      { a.v.Store(true) }
func (a *atomicBool) get() bool { return a.v.Load() }

// streamEventTracker enforces the §5.1 strict-monotonic event_id invariant
// for one stream (scoped to one correlation_id, one instance per consumed
// stream): the first accepted event_id establishes the floor and every
// subsequent one MUST strictly exceed the previous, or the frame is rejected
// (§9: "MUST reject ... a BRIDGE_STREAM_DATA frame whose event_id does not
// strictly exceed the previous data frame's event_id on the same stream").
type streamEventTracker struct {
	mu      sync.Mutex
	started bool
	last    uint64
}

// accept validates and records id, returning an error if id does not strictly
// exceed the previous accepted event_id on this stream.
func (t *streamEventTracker) accept(id uint64) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.started && id <= t.last {
		return &errStreamMalformed{reason: fmt.Sprintf("event_id %d does not strictly exceed the previous event_id %d on this stream (§5.1)", id, t.last)}
	}
	t.started = true
	t.last = id
	return nil
}
