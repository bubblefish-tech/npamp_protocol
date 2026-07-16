package npamp

import (
	"encoding/hex"
	"testing"
)

// TestBridgeOracleCrossValidate proves the independent Python oracle
// (test-vectors/gen/bridge_oracle.py) and this Go implementation AGREE, and does so NON-CIRCULARLY:
// every payload hex below is the oracle's ACTUAL output — a fixed-layout BridgeEnvelope/SafetyLabel
// TLV wrapper built by the oracle's from-scratch big-endian constructor from spec/companion/
// 10_bridge_framework.md §3/§4/§5/§7 (NOT dumped from impl/go/bridge*.go). For each accepted vector
// the impl's DecodeBridgeFrame must decode it to the fields the oracle declares AND a canonical
// re-encode (EncodeBridgeFrame) must reproduce the oracle's exact bytes; independently, building the
// frame from those declared fields and calling EncodeBridgePayload must produce the same bytes (the
// bridge.envelope.encode vectors). For each MUST-reject vector the impl must return an error. The
// bridge.correlate vectors assert §5 match-by-identifier. A drift in either the oracle or the impl
// fails here in `go test`, before the full conformance runner.

func mustHexBridge(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// bridgeSafety mirrors the oracle's `safety` object (nil == no SafetyLabel TLV).
type bridgeSafety struct {
	effect BridgeEffect
	scope  string
}

// bridgeAcceptCase fully describes one accepted Bridge payload — the oracle's canonical bytes plus the
// exact fields it declares. It drives BOTH the bridge.envelope.decode and bridge.envelope.encode
// cross-validation so the two directions cannot silently diverge.
type bridgeAcceptCase struct {
	name       string
	ft         FrameType
	payloadHex string
	protocol   BridgeProtocol
	kind       BridgeMessageKind
	content    BridgeContentType
	flags      uint8
	final      bool
	corrHex    string
	method     string
	safety     *bridgeSafety
	foreignHex string
}

// The six accepted vectors (bridge_oracle.py ACCEPT), transcribed from out/bridge.json.
var bridgeAccept = []bridgeAcceptCase{
	{
		name: "request_mcp_tools_call", ft: FrameBridgeRequest,
		payloadHex: "0010001401010100040a0b0c0d0a746f6f6c732f63616c6c00130009020766733a2f746d707b226a736f6e727063223a22322e30222c226964223a312c226d6574686f64223a22746f6f6c732f63616c6c227d",
		protocol:   BridgeProtoMCP, kind: BridgeKindRequest, content: BridgeContentJSON, flags: 0x00, final: false,
		corrHex: "0a0b0c0d", method: "tools/call",
		safety:     &bridgeSafety{effect: BridgeEffectNonIdempotentWrite, scope: "fs:/tmp"},
		foreignHex: "7b226a736f6e727063223a22322e30222c226964223a312c226d6574686f64223a22746f6f6c732f63616c6c227d",
	},
	{
		name: "response_echo_corr", ft: FrameBridgeResponse,
		payloadHex: "0010001401020100040a0b0c0d0a746f6f6c732f63616c6c7b226a736f6e727063223a22322e30222c226964223a312c22726573756c74223a7b226f6b223a747275657d7d",
		protocol:   BridgeProtoMCP, kind: BridgeKindResponse, content: BridgeContentJSON, flags: 0x00, final: false,
		corrHex: "0a0b0c0d", method: "tools/call", safety: nil,
		foreignHex: "7b226a736f6e727063223a22322e30222c226964223a312c22726573756c74223a7b226f6b223a747275657d7d",
	},
	{
		name: "error_foreign_object_verbatim", ft: FrameBridgeError,
		payloadHex: "0010001401040100040a0b0c0d0a746f6f6c732f63616c6c7b226a736f6e727063223a22322e30222c226964223a312c226572726f72223a7b22636f6465223a2d33323630312c226d657373616765223a224d6574686f64206e6f7420666f756e64227d7d",
		protocol:   BridgeProtoMCP, kind: BridgeKindError, content: BridgeContentJSON, flags: 0x00, final: false,
		corrHex: "0a0b0c0d", method: "tools/call", safety: nil,
		foreignHex: "7b226a736f6e727063223a22322e30222c226964223a312c226572726f72223a7b22636f6465223a2d33323630312c226d657373616765223a224d6574686f64206e6f7420666f756e64227d7d",
	},
	{
		name: "notify_corr_len_zero", ft: FrameBridgeNotify,
		payloadHex: "0010001b0203010000156e6f74696669636174696f6e732f6d6573736167657b226a736f6e727063223a22322e30222c226d6574686f64223a226e6f74696669636174696f6e732f6d657373616765227d",
		protocol:   BridgeProtoA2A, kind: BridgeKindNotification, content: BridgeContentJSON, flags: 0x00, final: false,
		corrHex: "", method: "notifications/message", safety: nil,
		foreignHex: "7b226a736f6e727063223a22322e30222c226d6574686f64223a226e6f74696669636174696f6e732f6d657373616765227d",
	},
	{
		name: "stream_data_reserved_flag_ignored", ft: FrameBridgeStreamData,
		payloadHex: "0010001401050102040a0b0c0d0a746f6f6c732f63616c6c6368756e6b2d30",
		protocol:   BridgeProtoMCP, kind: BridgeKindStreamData, content: BridgeContentJSON, flags: 0x02, final: false,
		corrHex: "0a0b0c0d", method: "tools/call", safety: nil,
		foreignHex: "6368756e6b2d30",
	},
	{
		name: "stream_end_final_empty_foreign", ft: FrameBridgeStreamEnd,
		payloadHex: "0010001401060101040a0b0c0d0a746f6f6c732f63616c6c",
		protocol:   BridgeProtoMCP, kind: BridgeKindStreamEnd, content: BridgeContentJSON, flags: 0x01, final: true,
		corrHex: "0a0b0c0d", method: "tools/call", safety: nil,
		foreignHex: "",
	},
}

// buildBridgeFrame reconstructs a BridgeFrame from an accepted case's DECLARED fields (the oracle's
// values), independent of the impl's decoder — the non-circular source for the encode direction.
func buildBridgeFrame(t *testing.T, c bridgeAcceptCase) BridgeFrame {
	t.Helper()
	env := BridgeEnvelope{
		Protocol:      c.protocol,
		Kind:          c.kind,
		ContentType:   c.content,
		Flags:         c.flags,
		CorrelationID: mustHexBridge(t, c.corrHex),
		Method:        []byte(c.method),
	}
	var safety *SafetyLabel
	if c.safety != nil {
		safety = &SafetyLabel{Effect: c.safety.effect, Scope: []byte(c.safety.scope)}
	}
	return BridgeFrame{Envelope: env, Safety: safety, Foreign: mustHexBridge(t, c.foreignHex)}
}

func TestBridgeOracleCrossValidate(t *testing.T) {
	// ---- bridge.envelope.decode: accepted vectors ----
	for _, c := range bridgeAccept {
		t.Run("decode/"+c.name, func(t *testing.T) {
			payload := mustHexBridge(t, c.payloadHex)
			f, err := DecodeBridgeFrame(c.ft, payload)
			if err != nil {
				t.Fatalf("oracle-accepted payload rejected by impl: %v", err)
			}
			if f.Envelope.Protocol != c.protocol {
				t.Errorf("protocol_id = 0x%02X, want 0x%02X", byte(f.Envelope.Protocol), byte(c.protocol))
			}
			if f.Envelope.Kind != c.kind {
				t.Errorf("message_kind = 0x%02X, want 0x%02X", byte(f.Envelope.Kind), byte(c.kind))
			}
			if f.Envelope.ContentType != c.content {
				t.Errorf("content_type = 0x%02X, want 0x%02X", byte(f.Envelope.ContentType), byte(c.content))
			}
			if f.Envelope.Flags != c.flags {
				t.Errorf("flags = 0x%02X, want 0x%02X", f.Envelope.Flags, c.flags)
			}
			if f.Envelope.Final() != c.final {
				t.Errorf("final = %v, want %v", f.Envelope.Final(), c.final)
			}
			if got := hex.EncodeToString(f.Envelope.CorrelationID); got != c.corrHex {
				t.Errorf("corr = %q, want %q", got, c.corrHex)
			}
			if got := string(f.Envelope.Method); got != c.method {
				t.Errorf("method = %q, want %q", got, c.method)
			}
			if c.safety == nil {
				if f.Safety != nil {
					t.Errorf("SafetyLabel present, want absent")
				}
			} else {
				if f.Safety == nil {
					t.Fatalf("SafetyLabel absent, want effect=0x%02X scope=%q", byte(c.safety.effect), c.safety.scope)
				}
				if f.Safety.Effect != c.safety.effect {
					t.Errorf("safety.effect = 0x%02X, want 0x%02X", byte(f.Safety.Effect), byte(c.safety.effect))
				}
				if string(f.Safety.Scope) != c.safety.scope {
					t.Errorf("safety.scope = %q, want %q", string(f.Safety.Scope), c.safety.scope)
				}
			}
			if got := hex.EncodeToString(f.Foreign); got != c.foreignHex {
				t.Errorf("foreign = %q, want %q (octet-for-octet, §1)", got, c.foreignHex)
			}
			// Canonical re-encode MUST reproduce the oracle's exact bytes.
			if got := hex.EncodeToString(EncodeBridgeFrame(f)); got != c.payloadHex {
				t.Errorf("re-encode = %s, want oracle bytes %s", got, c.payloadHex)
			}
		})
	}

	// ---- bridge.envelope.encode: build from the oracle's declared fields, assert canonical bytes ----
	for _, c := range bridgeAccept {
		t.Run("encode/"+c.name, func(t *testing.T) {
			f := buildBridgeFrame(t, c)
			got := hex.EncodeToString(EncodeBridgePayload(f.Envelope, f.Safety, f.Foreign))
			if got != c.payloadHex {
				t.Errorf("encode = %s, want oracle bytes %s", got, c.payloadHex)
			}
		})
	}

	// ---- bridge.envelope.decode: MUST-reject vectors (bridge_oracle.py rejects) ----
	rejects := []struct {
		name       string
		ft         FrameType
		payloadHex string
	}{
		{"envelope_absent", FrameBridgeRequest, "001300030001787b226a736f6e727063223a22322e30222c226964223a312c226d6574686f64223a22746f6f6c732f63616c6c227d"},
		{"envelope_tlv_truncated", FrameBridgeRequest, "001000200101010004"},
		{"envelope_value_truncated", FrameBridgeRequest, "001000080101010008aabbcc"},
		{"message_kind_mismatch", FrameBridgeRequest, "0010001401020100040a0b0c0d0a746f6f6c732f63616c6c7b226a736f6e727063223a22322e30222c226964223a312c226d6574686f64223a22746f6f6c732f63616c6c227d"},
		{"request_empty_corr", FrameBridgeRequest, "0010001001010100000a746f6f6c732f63616c6c7b226a736f6e727063223a22322e30222c226964223a312c226d6574686f64223a22746f6f6c732f63616c6c227d"},
		{"notify_nonempty_corr", FrameBridgeNotify, "0010001f02030100040a0b0c0d156e6f74696669636174696f6e732f6d6573736167657b226a736f6e727063223a22322e30222c226d6574686f64223a226e6f74696669636174696f6e732f6d657373616765227d"},
		{"reply_empty_corr", FrameBridgeResponse, "0010001001020100000a746f6f6c732f63616c6c7b226a736f6e727063223a22322e30222c226964223a312c22726573756c74223a7b226f6b223a747275657d7d"},
		{"envelope_trailing_octets", FrameBridgeRequest, "0010001201010100040a0b0c0d04746f6f6c63616c6c7b226a736f6e727063223a22322e30222c226964223a312c226d6574686f64223a22746f6f6c732f63616c6c227d"},
		{"safetylabel_truncated", FrameBridgeRequest, "0010001401010100040a0b0c0d0a746f6f6c732f63616c6c001300030205667b226a736f6e727063223a22322e30222c226964223a312c226d6574686f64223a22746f6f6c732f63616c6c227d"},
		{"not_a_bridge_frame", FrameType(0x0001), "0010001401010100040a0b0c0d0a746f6f6c732f63616c6c7b226a736f6e727063223a22322e30222c226964223a312c226d6574686f64223a22746f6f6c732f63616c6c227d"},
	}
	for _, r := range rejects {
		t.Run("reject/"+r.name, func(t *testing.T) {
			if _, err := DecodeBridgeFrame(r.ft, mustHexBridge(t, r.payloadHex)); err == nil {
				t.Fatalf("oracle=MUST-reject but impl ACCEPTED payload %s", r.payloadHex)
			}
		})
	}

	// ---- bridge.correlate: §5 match-by-identifier ----
	correlate := []struct {
		name       string
		reqFt      FrameType
		reqPayload string
		repFt      FrameType
		repPayload string
		match      bool
	}{
		{"reply_correlates", FrameBridgeRequest,
			"0010001401010100040a0b0c0d0a746f6f6c732f63616c6c7b226a736f6e727063223a22322e30222c226964223a312c226d6574686f64223a22746f6f6c732f63616c6c227d",
			FrameBridgeResponse,
			"0010001401020100040a0b0c0d0a746f6f6c732f63616c6c7b226a736f6e727063223a22322e30222c226964223a312c22726573756c74223a7b226f6b223a747275657d7d", true},
		{"reply_different_corr", FrameBridgeRequest,
			"0010001401010100040a0b0c0d0a746f6f6c732f63616c6c7b226a736f6e727063223a22322e30222c226964223a312c226d6574686f64223a22746f6f6c732f63616c6c227d",
			FrameBridgeResponse,
			"001000140102010004ffffffff0a746f6f6c732f63616c6c7b226a736f6e727063223a22322e30222c226964223a312c22726573756c74223a7b226f6b223a747275657d7d", false},
		{"stream_reply_correlates", FrameBridgeRequest,
			"0010001401010100040a0b0c0d0a746f6f6c732f63616c6c7b226a736f6e727063223a22322e30222c226964223a312c226d6574686f64223a22746f6f6c732f63616c6c227d",
			FrameBridgeStreamData,
			"0010001401050100040a0b0c0d0a746f6f6c732f63616c6c6368756e6b2d30", true},
	}
	for _, cc := range correlate {
		t.Run("correlate/"+cc.name, func(t *testing.T) {
			reqEnv, err := DecodeBridgeEnvelope(cc.reqFt, mustHexBridge(t, cc.reqPayload))
			if err != nil {
				t.Fatalf("request payload rejected by impl: %v", err)
			}
			repEnv, err := DecodeBridgeEnvelope(cc.repFt, mustHexBridge(t, cc.repPayload))
			if err != nil {
				t.Fatalf("reply payload rejected by impl: %v", err)
			}
			if got := CorrelateBridgeReply(reqEnv, repEnv); got != cc.match {
				t.Errorf("CorrelateBridgeReply = %v, want %v", got, cc.match)
			}
		})
	}
}
