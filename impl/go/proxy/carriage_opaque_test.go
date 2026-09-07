// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package proxy

import (
	"bytes"
	"testing"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

func opaqueTestEnvelope() npamp.BridgeEnvelope {
	return npamp.BridgeEnvelope{
		Protocol:      0x50, // an arbitrary private-use protocol_id for the test
		Kind:          npamp.BridgeKindRequest,
		CorrelationID: []byte{0x01, 0x02, 0x03, 0x04},
	}
}

// TestOpaquePayload_Case1_EnumeratedMediaType_RoundTrip proves §4.2 case 1:
// a payload whose media type is already BridgeEnvelope-enumerated is carried
// with no OpaqueContentType TLV, and decodes back to the same media type and
// byte-exact payload.
func TestOpaquePayload_Case1_EnumeratedMediaType_RoundTrip(t *testing.T) {
	raw := []byte(`{"hello":"world"}`)
	wire, err := encodeOpaquePayload(opaqueTestEnvelope(), "application/json", raw)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	frame, derr := npamp.DecodeBridgeFrame(npamp.FrameBridgeRequest, wire)
	if derr != nil {
		t.Fatalf("DecodeBridgeFrame: %v", derr)
	}
	if frame.Envelope.ContentType != npamp.BridgeContentJSON {
		t.Errorf("ContentType = 0x%02x, want BridgeContentJSON (0x01) -- case 1 MUST set the enumerated value", byte(frame.Envelope.ContentType))
	}
	mt, got, err := decodeOpaquePayload(frame.Envelope, frame.Foreign)
	if err != nil {
		t.Fatalf("decodeOpaquePayload: %v", err)
	}
	if mt != "application/json" {
		t.Errorf("mediaType = %q, want application/json", mt)
	}
	if !bytes.Equal(got, raw) {
		t.Errorf("raw = %q, want %q (byte-exact case-1 round trip)", got, raw)
	}
}

// TestOpaquePayload_Case2_NonEnumeratedMediaType_RoundTrip proves §4.2 case 2
// and the §4.3/§4.4 open items this leg resolves: a media type NOT one of the
// three enumerated values (application/octet-stream, the raw-TCP default)
// is carried via the OpaqueContentType TLV and the content_type discriminator,
// and decodes back to the same media type and byte-exact payload.
func TestOpaquePayload_Case2_NonEnumeratedMediaType_RoundTrip(t *testing.T) {
	raw := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02} // arbitrary binary, includes a NUL octet mid-payload -- must NOT be treated as an end-of-string marker
	wire, err := encodeOpaquePayload(opaqueTestEnvelope(), "application/octet-stream", raw)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	frame, derr := npamp.DecodeBridgeFrame(npamp.FrameBridgeRequest, wire)
	if derr != nil {
		t.Fatalf("DecodeBridgeFrame: %v", derr)
	}
	if frame.Envelope.ContentType != opaqueContentTypeDiscriminator {
		t.Errorf("ContentType = 0x%02x, want the discriminator 0x%02x", byte(frame.Envelope.ContentType), byte(opaqueContentTypeDiscriminator))
	}
	mt, got, err := decodeOpaquePayload(frame.Envelope, frame.Foreign)
	if err != nil {
		t.Fatalf("decodeOpaquePayload: %v", err)
	}
	if mt != "application/octet-stream" {
		t.Errorf("mediaType = %q, want application/octet-stream", mt)
	}
	if !bytes.Equal(got, raw) {
		t.Errorf("raw = %v, want %v (byte-exact case-2 round trip, including the embedded NUL octet)", got, raw)
	}
}

// TestOpaquePayload_Case2_MediaTypeWithParameters_RoundTrip proves §4.1's
// grammar allows optional parameters (for example "text/plain; charset=utf-8").
func TestOpaquePayload_Case2_MediaTypeWithParameters_RoundTrip(t *testing.T) {
	wire, err := encodeOpaquePayload(opaqueTestEnvelope(), "text/plain; charset=utf-8", []byte("hello"))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	frame, _ := npamp.DecodeBridgeFrame(npamp.FrameBridgeRequest, wire)
	mt, _, err := decodeOpaquePayload(frame.Envelope, frame.Foreign)
	if err != nil {
		t.Fatalf("decodeOpaquePayload: %v", err)
	}
	if mt != "text/plain; charset=utf-8" {
		t.Errorf("mediaType = %q, want text/plain; charset=utf-8", mt)
	}
}

// TestOpaquePayload_EmptyMediaType_Rejected asserts §4.3: "MUST be non-empty."
func TestOpaquePayload_EmptyMediaType_Rejected(t *testing.T) {
	if _, err := encodeOpaquePayload(opaqueTestEnvelope(), "", []byte("x")); err == nil {
		t.Fatal("encodeOpaquePayload accepted an empty media type")
	}
}

// TestOpaquePayload_NULInMediaType_Rejected asserts §4.3: "MUST NOT contain a
// NUL octet."
func TestOpaquePayload_NULInMediaType_Rejected(t *testing.T) {
	if _, err := encodeOpaquePayload(opaqueTestEnvelope(), "application/x\x00evil", []byte("x")); err == nil {
		t.Fatal("encodeOpaquePayload accepted a media type containing a NUL octet")
	}
}

// TestOpaquePayload_SyntacticallyInvalidMediaType_Rejected asserts §4.3: "not
// a syntactically valid media type" is rejected -- a bare token with no '/'.
func TestOpaquePayload_SyntacticallyInvalidMediaType_Rejected(t *testing.T) {
	if _, err := encodeOpaquePayload(opaqueTestEnvelope(), "not-a-media-type", []byte("x")); err == nil {
		t.Fatal("encodeOpaquePayload accepted a media type with no '/'")
	}
	if _, err := encodeOpaquePayload(opaqueTestEnvelope(), "/subtype-with-no-type", []byte("x")); err == nil {
		t.Fatal("encodeOpaquePayload accepted a media type with an empty type")
	}
	if _, err := encodeOpaquePayload(opaqueTestEnvelope(), "type-with-no-subtype/", []byte("x")); err == nil {
		t.Fatal("encodeOpaquePayload accepted a media type with an empty subtype")
	}
}

// TestOpaquePayload_AmbiguousBothDeclared_Rejected is a §4.2 point 3 MUTATION
// ANCHOR (RED-EVIDENCE): a receiver MUST reject a frame that carries both an
// enumerated content_type value other than the discriminator AND an
// OpaqueContentType TLV. This test constructs exactly that malformed wire
// shape by hand (case-1 encoding with content_type left enumerated, then an
// OpaqueContentType TLV spliced onto the front of the foreign payload) --
// something an honest sender never does, but a receiver MUST still detect.
func TestOpaquePayload_AmbiguousBothDeclared_Rejected(t *testing.T) {
	env := opaqueTestEnvelope()
	env.ContentType = npamp.BridgeContentJSON // an enumerated value, NOT the discriminator
	ext := npamp.TLV{Type: opaqueContentTypeTLV, Value: []byte("application/octet-stream")}.Encode(nil)
	foreign := append(ext, []byte(`{"real":"payload"}`)...)
	if _, _, err := decodeOpaquePayload(env, foreign); err == nil {
		t.Fatal("decodeOpaquePayload accepted a frame declaring both an enumerated content_type and an OpaqueContentType TLV (§4.2 point 3 ambiguity check did not fire)")
	}
}

// TestOpaquePayload_DiscriminatorWithoutTLV_Rejected asserts the converse
// half of §4.2 point 3: content_type is the discriminator but no
// OpaqueContentType TLV is present, so there is nothing to read the declared
// media type from.
func TestOpaquePayload_DiscriminatorWithoutTLV_Rejected(t *testing.T) {
	env := opaqueTestEnvelope()
	env.ContentType = opaqueContentTypeDiscriminator
	if _, _, err := decodeOpaquePayload(env, []byte("just some bytes, no TLV header")); err == nil {
		t.Fatal("decodeOpaquePayload accepted the discriminator content_type with no OpaqueContentType TLV present")
	}
}

// TestOpaquePayload_UnrecognizedContentType_Rejected asserts §4.4's last
// paragraph: "a receiver MUST treat an unrecognized content_type value as a
// malformed envelope."
func TestOpaquePayload_UnrecognizedContentType_Rejected(t *testing.T) {
	env := opaqueTestEnvelope()
	env.ContentType = 0x7F // neither 0x01-0x03 nor the 0x04 discriminator
	if _, _, err := decodeOpaquePayload(env, []byte("payload")); err == nil {
		t.Fatal("decodeOpaquePayload accepted an unrecognized content_type value")
	}
}

// TestOpaquePayload_EmptyOpaqueContentTypeTLV_Rejected asserts §4.3: the
// OpaqueContentType TLV's own value "MUST be non-empty."
func TestOpaquePayload_EmptyOpaqueContentTypeTLV_Rejected(t *testing.T) {
	env := opaqueTestEnvelope()
	env.ContentType = opaqueContentTypeDiscriminator
	ext := npamp.TLV{Type: opaqueContentTypeTLV, Value: nil}.Encode(nil)
	if _, _, err := decodeOpaquePayload(env, ext); err == nil {
		t.Fatal("decodeOpaquePayload accepted an empty OpaqueContentType TLV value")
	}
}

// TestOpaquePayload_TruncatedOpaqueContentTypeTLV_Rejected proves a truncated
// TLV (declared length exceeds the remaining buffer) is rejected rather than
// panicking or silently truncating.
func TestOpaquePayload_TruncatedOpaqueContentTypeTLV_Rejected(t *testing.T) {
	// A TLV header declaring length 100 with only 4 octets of value present.
	buf := []byte{0x00, 0x12, 0x00, 0x64, 'a', 'b', 'c', 'd'}
	env := opaqueTestEnvelope()
	env.ContentType = opaqueContentTypeDiscriminator
	if _, _, err := decodeOpaquePayload(env, buf); err == nil {
		t.Fatal("decodeOpaquePayload accepted a truncated OpaqueContentType TLV")
	}
}

// TestOpaqueContentTypeTLV_IsTheAssignedCodePoint pins the D11 registration
// this leg depends on: 0x0012, not any other value (RED-EVIDENCE mutation
// anchor -- changing this constant flips this test and every round-trip test
// above that decodes via the real npamp.DecodeTLVs/DecodeBridgeFrame path).
func TestOpaqueContentTypeTLV_IsTheAssignedCodePoint(t *testing.T) {
	if opaqueContentTypeTLV != 0x0012 {
		t.Fatalf("opaqueContentTypeTLV = 0x%04x, want 0x0012 (decisions/adr/0015)", uint16(opaqueContentTypeTLV))
	}
}

// TestOpaqueContentTypeDiscriminator_IsTheAssignedValue pins the D11
// discriminator value this leg depends on: 0x04, distinct from the three
// assigned content_type values 0x01-0x03.
func TestOpaqueContentTypeDiscriminator_IsTheAssignedValue(t *testing.T) {
	if opaqueContentTypeDiscriminator != 0x04 {
		t.Fatalf("opaqueContentTypeDiscriminator = 0x%02x, want 0x04 (decisions/adr/0015)", byte(opaqueContentTypeDiscriminator))
	}
	for _, assigned := range []npamp.BridgeContentType{npamp.BridgeContentJSON, npamp.BridgeContentCBOR, npamp.BridgeContentGRPCProto} {
		if opaqueContentTypeDiscriminator == assigned {
			t.Fatalf("opaqueContentTypeDiscriminator 0x%02x collides with an already-assigned content_type value", byte(assigned))
		}
	}
}
