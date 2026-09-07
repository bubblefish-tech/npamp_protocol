// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package proxy

import (
	"bytes"
	"testing"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// TestStreamControl_RoundTrip proves encodeStreamControlValue and
// decodeLeadingStreamControl are inverse operations, including a trailing
// foreign event that must be returned untouched (§9: "MUST treat the foreign
// event as opaque").
func TestStreamControl_RoundTrip(t *testing.T) {
	sc := streamControl{Control: streamControlData, Flags: streamFlagResumable, EventID: 42}
	event := []byte("the foreign event bytes")
	wire := npamp.TLV{Type: TLVStreamControl, Value: encodeStreamControlValue(sc)}.Encode(nil)
	wire = append(wire, event...)

	got, rest, err := decodeLeadingStreamControl(wire)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != sc {
		t.Errorf("decoded streamControl = %+v, want %+v", got, sc)
	}
	if !got.Resumable() {
		t.Error("Resumable() = false, want true (flag bit 0 set)")
	}
	if !bytes.Equal(rest, event) {
		t.Errorf("rest = %q, want the untouched foreign event %q", rest, event)
	}
}

// TestStreamControl_WrongType_Rejected is a MUTATION ANCHOR (RED-EVIDENCE):
// a leading TLV whose Type is not 0x0011 MUST be rejected as "not a
// StreamControl TLV" -- the frame either carries no StreamControl at all
// (this build's fresh-request-vs-resume-request disambiguation, stream.go)
// or is malformed.
func TestStreamControl_WrongType_Rejected(t *testing.T) {
	wire := npamp.TLV{Type: 0x0099, Value: encodeStreamControlValue(streamControl{})}.Encode(nil)
	if _, _, err := decodeLeadingStreamControl(wire); err == nil {
		t.Fatal("decodeLeadingStreamControl accepted a non-StreamControl leading TLV type")
	}
}

// TestStreamControl_WrongVersion_Rejected asserts §5.2: a receiver MUST
// reject a StreamControl TLV whose version it does not implement.
func TestStreamControl_WrongVersion_Rejected(t *testing.T) {
	v := encodeStreamControlValue(streamControl{Control: streamControlData})
	v[0] = 0x02 // an unimplemented version
	wire := npamp.TLV{Type: TLVStreamControl, Value: v}.Encode(nil)
	if _, _, err := decodeLeadingStreamControl(wire); err == nil {
		t.Fatal("decodeLeadingStreamControl accepted StreamControl version 0x02 (only 0x01 is implemented)")
	}
}

// TestStreamControl_UndefinedControl_Rejected asserts §5.2: control values
// 0x03-0xFF are reserved and MUST be rejected.
func TestStreamControl_UndefinedControl_Rejected(t *testing.T) {
	v := encodeStreamControlValue(streamControl{Control: 0x00})
	v[1] = 0x7F // undefined control value
	wire := npamp.TLV{Type: TLVStreamControl, Value: v}.Encode(nil)
	if _, _, err := decodeLeadingStreamControl(wire); err == nil {
		t.Fatal("decodeLeadingStreamControl accepted an undefined control value 0x7F")
	}
}

// TestStreamControl_WrongLength_Rejected asserts §5.2: the StreamControl
// value is fixed at 11 octets; any other Length MUST be rejected.
func TestStreamControl_WrongLength_Rejected(t *testing.T) {
	wire := npamp.TLV{Type: TLVStreamControl, Value: []byte{0x01, 0x00, 0x00}}.Encode(nil) // 3 octets, not 11
	if _, _, err := decodeLeadingStreamControl(wire); err == nil {
		t.Fatal("decodeLeadingStreamControl accepted a 3-octet StreamControl value (want exactly 11, §5.2)")
	}
}

// TestStreamEventTracker_StrictMonotonic_Enforced is the §5.1 event-id
// invariant MUTATION ANCHOR (RED-EVIDENCE): a data frame whose event_id does
// not strictly exceed the previous one MUST be rejected.
func TestStreamEventTracker_StrictMonotonic_Enforced(t *testing.T) {
	var tr streamEventTracker
	if err := tr.accept(1); err != nil {
		t.Fatalf("accept(1): %v", err)
	}
	if err := tr.accept(5); err != nil {
		t.Fatalf("accept(5): %v", err)
	}
	if err := tr.accept(5); err == nil {
		t.Fatal("accept(5) a second time (non-increasing) was accepted -- the strict-monotonic invariant did not fire")
	}
	if err := tr.accept(3); err == nil {
		t.Fatal("accept(3) after accept(5) (a decrease) was accepted -- the strict-monotonic invariant did not fire")
	}
	if err := tr.accept(9); err != nil {
		t.Fatalf("accept(9) after accept(5) (a genuine increase) should be accepted: %v", err)
	}
}

// TestStreamEventTracker_SkippedValuesAllowed asserts §5.1: "A producer MAY
// skip values (the sequence need not be contiguous)".
func TestStreamEventTracker_SkippedValuesAllowed(t *testing.T) {
	var tr streamEventTracker
	if err := tr.accept(1); err != nil {
		t.Fatalf("accept(1): %v", err)
	}
	if err := tr.accept(100); err != nil {
		t.Fatalf("accept(100) after accept(1) (a skip) should be accepted: %v", err)
	}
}

// TestEncodeDecodeStreamFrame_RoundTrip proves encodeStreamFrame builds a
// payload that npamp.DecodeBridgeFrame accepts and whose Foreign region
// decodeLeadingStreamControl correctly re-parses -- the composition this
// leg's grpc.go/websocket.go dispatch relies on.
func TestEncodeDecodeStreamFrame_RoundTrip(t *testing.T) {
	env := npamp.BridgeEnvelope{
		Protocol:      grpcProtocolID,
		Kind:          npamp.BridgeKindStreamData,
		ContentType:   npamp.BridgeContentGRPCProto,
		CorrelationID: []byte("corr-1"),
	}
	sc := streamControl{Control: streamControlData, EventID: 3}
	event := encodeGRPCLengthPrefixedMessage(false, []byte("hello"))
	payload := encodeStreamFrame(env, sc, event)

	frame, err := npamp.DecodeBridgeFrame(npamp.FrameBridgeStreamData, payload)
	if err != nil {
		t.Fatalf("DecodeBridgeFrame: %v", err)
	}
	gotSC, rest, err := decodeLeadingStreamControl(frame.Foreign)
	if err != nil {
		t.Fatalf("decodeLeadingStreamControl: %v", err)
	}
	if gotSC.EventID != 3 {
		t.Errorf("EventID = %d, want 3", gotSC.EventID)
	}
	_, msg, err := decodeGRPCLengthPrefixedMessage(rest)
	if err != nil {
		t.Fatalf("decodeGRPCLengthPrefixedMessage: %v", err)
	}
	if string(msg) != "hello" {
		t.Errorf("msg = %q, want hello", msg)
	}
}
