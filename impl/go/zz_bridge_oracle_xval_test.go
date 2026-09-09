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
		payloadHex: "001000150001010100040a0b0c0d0a746f6f6c732f63616c6c00130009020766733a2f746d707b226a736f6e727063223a22322e30222c226964223a312c226d6574686f64223a22746f6f6c732f63616c6c227d",
		protocol:   BridgeProtoMCP, kind: BridgeKindRequest, content: BridgeContentJSON, flags: 0x00, final: false,
		corrHex: "0a0b0c0d", method: "tools/call",
		safety:     &bridgeSafety{effect: BridgeEffectNonIdempotentWrite, scope: "fs:/tmp"},
		foreignHex: "7b226a736f6e727063223a22322e30222c226964223a312c226d6574686f64223a22746f6f6c732f63616c6c227d",
	},
	{
		name: "response_echo_corr", ft: FrameBridgeResponse,
		payloadHex: "001000150001020100040a0b0c0d0a746f6f6c732f63616c6c7b226a736f6e727063223a22322e30222c226964223a312c22726573756c74223a7b226f6b223a747275657d7d",
		protocol:   BridgeProtoMCP, kind: BridgeKindResponse, content: BridgeContentJSON, flags: 0x00, final: false,
		corrHex: "0a0b0c0d", method: "tools/call", safety: nil,
		foreignHex: "7b226a736f6e727063223a22322e30222c226964223a312c22726573756c74223a7b226f6b223a747275657d7d",
	},
	{
		name: "error_foreign_object_verbatim", ft: FrameBridgeError,
		payloadHex: "001000150001040100040a0b0c0d0a746f6f6c732f63616c6c7b226a736f6e727063223a22322e30222c226964223a312c226572726f72223a7b22636f6465223a2d33323630312c226d657373616765223a224d6574686f64206e6f7420666f756e64227d7d",
		protocol:   BridgeProtoMCP, kind: BridgeKindError, content: BridgeContentJSON, flags: 0x00, final: false,
		corrHex: "0a0b0c0d", method: "tools/call", safety: nil,
		foreignHex: "7b226a736f6e727063223a22322e30222c226964223a312c226572726f72223a7b22636f6465223a2d33323630312c226d657373616765223a224d6574686f64206e6f7420666f756e64227d7d",
	},
	{
		name: "notify_corr_len_zero", ft: FrameBridgeNotify,
		payloadHex: "0010001c000203010000156e6f74696669636174696f6e732f6d6573736167657b226a736f6e727063223a22322e30222c226d6574686f64223a226e6f74696669636174696f6e732f6d657373616765227d",
		protocol:   BridgeProtoA2A, kind: BridgeKindNotification, content: BridgeContentJSON, flags: 0x00, final: false,
		corrHex: "", method: "notifications/message", safety: nil,
		foreignHex: "7b226a736f6e727063223a22322e30222c226d6574686f64223a226e6f74696669636174696f6e732f6d657373616765227d",
	},
	{
		name: "stream_data_reserved_flag_ignored", ft: FrameBridgeStreamData,
		payloadHex: "001000150001050102040a0b0c0d0a746f6f6c732f63616c6c6368756e6b2d30",
		protocol:   BridgeProtoMCP, kind: BridgeKindStreamData, content: BridgeContentJSON, flags: 0x02, final: false,
		corrHex: "0a0b0c0d", method: "tools/call", safety: nil,
		foreignHex: "6368756e6b2d30",
	},
	{
		name: "stream_end_final_empty_foreign", ft: FrameBridgeStreamEnd,
		payloadHex: "001000150001060101040a0b0c0d0a746f6f6c732f63616c6c",
		protocol:   BridgeProtoMCP, kind: BridgeKindStreamEnd, content: BridgeContentJSON, flags: 0x01, final: true,
		corrHex: "0a0b0c0d", method: "tools/call", safety: nil,
		foreignHex: "",
	},

	// ---- wave-1 (NPAMP-REG 30_protocol_registry.md §6, 0x06-0x0A): one request+response pair per
	// newly assigned protocol_id, transcribed from the oracle's actual output (out/bridge.json) exactly
	// as the six cases above were. See test-vectors/gen/bridge_oracle.py for the per-case grounding. ----
	{
		name: "request_nlip_stream_session_open", ft: FrameBridgeRequest,
		payloadHex: "0010000b0006010100044e4c3031000013000702052f6e6c69707b22666f726d6174223a2274657874222c22737562666f726d6174223a22656e676c697368222c22636f6e74656e74223a225768617420697320746865207765617468657220696e2050617269733f227d",
		protocol:   BridgeProtoNLIP, kind: BridgeKindRequest, content: BridgeContentJSON, flags: 0x00, final: false,
		corrHex: "4e4c3031", method: "", safety: &bridgeSafety{effect: BridgeEffectNonIdempotentWrite, scope: "/nlip"},
		foreignHex: "7b22666f726d6174223a2274657874222c22737562666f726d6174223a22656e676c697368222c22636f6e74656e74223a225768617420697320746865207765617468657220696e2050617269733f227d",
	},
	{
		name: "response_nlip_stream_reply", ft: FrameBridgeResponse,
		payloadHex: "0010000b0006020100044e4c3031007b22666f726d6174223a2274657874222c22737562666f726d6174223a22656e676c697368222c22636f6e74656e74223a22436c65617220736b6965732c203138432e227d",
		protocol:   BridgeProtoNLIP, kind: BridgeKindResponse, content: BridgeContentJSON, flags: 0x00, final: false,
		corrHex: "4e4c3031", method: "", safety: nil,
		foreignHex: "7b22666f726d6174223a2274657874222c22737562666f726d6174223a22656e676c697368222c22636f6e74656e74223a22436c65617220736b6965732c203138432e227d",
	},
	{
		name: "request_anp_meta_protocol_negotiation", ft: FrameBridgeRequest,
		payloadHex: "00100024000701010004414e3031196d6574612d70726f746f636f6c2d6e65676f74696174696f6e0013000f020d6d6574612d70726f746f636f6c7b2240636f6e74657874223a5b2268747470733a2f2f7777772e77332e6f72672f6e732f6469642f7631225d2c226964223a226469643a7762613a746573742d666978747572653a6167656e74733a706c616e6e6572222c2274797065223a224e65676f74696174696f6e52657175657374222c2270726f706f73616c223a22766e642e746573742d666978747572652e726f7574652d706c616e6e696e672d76312b6a736f6e227d",
		protocol:   BridgeProtoANP, kind: BridgeKindRequest, content: BridgeContentJSON, flags: 0x00, final: false,
		corrHex: "414e3031", method: "meta-protocol-negotiation", safety: &bridgeSafety{effect: BridgeEffectNonIdempotentWrite, scope: "meta-protocol"},
		foreignHex: "7b2240636f6e74657874223a5b2268747470733a2f2f7777772e77332e6f72672f6e732f6469642f7631225d2c226964223a226469643a7762613a746573742d666978747572653a6167656e74733a706c616e6e6572222c2274797065223a224e65676f74696174696f6e52657175657374222c2270726f706f73616c223a22766e642e746573742d666978747572652e726f7574652d706c616e6e696e672d76312b6a736f6e227d",
	},
	{
		name: "response_anp_meta_protocol_negotiation", ft: FrameBridgeResponse,
		payloadHex: "00100024000702010004414e3031196d6574612d70726f746f636f6c2d6e65676f74696174696f6e7b2240636f6e74657874223a5b2268747470733a2f2f7777772e77332e6f72672f6e732f6469642f7631225d2c226964223a226469643a7762613a746573742d666978747572653a6167656e74733a706c616e6e6572222c2274797065223a224e65676f74696174696f6e526573706f6e7365222c226163636570746564223a22766e642e746573742d666978747572652e726f7574652d706c616e6e696e672d76312b6a736f6e227d",
		protocol:   BridgeProtoANP, kind: BridgeKindResponse, content: BridgeContentJSON, flags: 0x00, final: false,
		corrHex: "414e3031", method: "meta-protocol-negotiation", safety: nil,
		foreignHex: "7b2240636f6e74657874223a5b2268747470733a2f2f7777772e77332e6f72672f6e732f6469642f7631225d2c226964223a226469643a7762613a746573742d666978747572653a6167656e74733a706c616e6e6572222c2274797065223a224e65676f74696174696f6e526573706f6e7365222c226163636570746564223a22766e642e746573742d666978747572652e726f7574652d706c616e6e696e672d76312b6a736f6e227d",
	},
	{
		name: "request_agntcy_acp_create_run", ft: FrameBridgeRequest,
		payloadHex: "00100015000801010004414330310a504f5354202f72756e730013000702052f72756e737b226167656e745f6964223a22706c616e6e65722d6167656e74222c22696e707574223a7b226d65737361676573223a5b7b22726f6c65223a2275736572222c22636f6e74656e74223a22706c616e20612074726970227d5d7d7d",
		protocol:   BridgeProtoAGNTCY, kind: BridgeKindRequest, content: BridgeContentJSON, flags: 0x00, final: false,
		corrHex: "41433031", method: "POST /runs", safety: &bridgeSafety{effect: BridgeEffectNonIdempotentWrite, scope: "/runs"},
		foreignHex: "7b226167656e745f6964223a22706c616e6e65722d6167656e74222c22696e707574223a7b226d65737361676573223a5b7b22726f6c65223a2275736572222c22636f6e74656e74223a22706c616e20612074726970227d5d7d7d",
	},
	{
		name: "response_agntcy_acp_create_run", ft: FrameBridgeResponse,
		payloadHex: "00100015000802010004414330310a504f5354202f72756e737b2272756e5f6964223a2272756e5f30303031222c22737461747573223a2273756363657373222c226f7574707574223a7b226d65737361676573223a5b7b22726f6c65223a22617373697374616e74222c22636f6e74656e74223a22706c616e207265616479227d5d7d7d",
		protocol:   BridgeProtoAGNTCY, kind: BridgeKindResponse, content: BridgeContentJSON, flags: 0x00, final: false,
		corrHex: "41433031", method: "POST /runs", safety: nil,
		foreignHex: "7b2272756e5f6964223a2272756e5f30303031222c22737461747573223a2273756363657373222c226f7574707574223a7b226d65737361676573223a5b7b22726f6c65223a22617373697374616e74222c22636f6e74656e74223a22706c616e207265616479227d5d7d7d",
	},
	{
		name: "request_ap2_checkout_mandate", ft: FrameBridgeRequest,
		payloadHex: "0010000b000901040004415030310065794a68624763694f694a46557a49314e694973496e523563434936496e5a6a4b334e6b4c57703364434a392e65794a32593351694f694a745957356b5958526c4c6d4e6f5a574e72623356304c6a45694c434a7063334d694f694a6b615751366447567a6443316d6158683064584a6c4f6d6c7a6333566c63694a392e63326c6e7e",
		protocol:   BridgeProtoAP2, kind: BridgeKindRequest, content: BridgeContentOpaqueTLV, flags: 0x00, final: false,
		corrHex: "41503031", method: "", safety: nil,
		foreignHex: "65794a68624763694f694a46557a49314e694973496e523563434936496e5a6a4b334e6b4c57703364434a392e65794a32593351694f694a745957356b5958526c4c6d4e6f5a574e72623356304c6a45694c434a7063334d694f694a6b615751366447567a6443316d6158683064584a6c4f6d6c7a6333566c63694a392e63326c6e7e",
	},
	{
		name: "response_ap2_payment_mandate", ft: FrameBridgeResponse,
		payloadHex: "0010000b000902040004415030310065794a68624763694f694a46557a49314e694973496e523563434936496e5a6a4b334e6b4c57703364434a392e65794a32593351694f694a745957356b5958526c4c6e42686557316c626e51754d534973496d6c7a63794936496d52705a4470305a584e304c575a7065485231636d553661584e7a64575679496e302e63326c6e7e",
		protocol:   BridgeProtoAP2, kind: BridgeKindResponse, content: BridgeContentOpaqueTLV, flags: 0x00, final: false,
		corrHex: "41503031", method: "", safety: nil,
		foreignHex: "65794a68624763694f694a46557a49314e694973496e523563434936496e5a6a4b334e6b4c57703364434a392e65794a32593351694f694a745957356b5958526c4c6e42686557316c626e51754d534973496d6c7a63794936496d52705a4470305a584e304c575a7065485231636d553661584e7a64575679496e302e63326c6e7e",
	},
	{
		name: "request_x402_initial_resource_get", ft: FrameBridgeRequest,
		payloadHex: "0010001d000a010200045834303212474554202f706169642d656e64706f696e74a301010263474554036e2f706169642d656e64706f696e74",
		protocol:   BridgeProtoX402, kind: BridgeKindRequest, content: BridgeContentCBOR, flags: 0x00, final: false,
		corrHex: "58343032", method: "GET /paid-endpoint", safety: nil,
		foreignHex: "a301010263474554036e2f706169642d656e64706f696e74",
	},
	{
		name: "response_x402_payment_required", ft: FrameBridgeResponse,
		payloadHex: "0010001d000a020200045834303212474554202f706169642d656e64706f696e74a3010206190192088182707061796d656e742d726571756972656459014865794a344e444179566d567963326c76626949364d537769636d567a62335679593255694f694976634746705a43316c626d527762326c7564434973496d466a5932567764484d694f6c7437496e4e6a614756745a534936496d563459574e3049697769626d56306432397961794936496d5670634445314e546f344e44557a496977695957317664573530496a6f694d5441774d4441694c434a6863334e6c64434936496a42344d4441774d4441774d4441774d4441774d4441774d4441774d4441774d4441774d4441774d4441774d4441774d4441774d4441774d434973496e426865565276496a6f694d4867774d4441774d4441774d4441774d4441774d4441774d4441774d4441774d4441774d4441774d4441774d4441774d4441774d444177496977696257463456476c745a57393164464e6c593239755a484d694f6a597766563139",
		protocol:   BridgeProtoX402, kind: BridgeKindResponse, content: BridgeContentCBOR, flags: 0x00, final: false,
		corrHex: "58343032", method: "GET /paid-endpoint", safety: nil,
		foreignHex: "a3010206190192088182707061796d656e742d726571756972656459014865794a344e444179566d567963326c76626949364d537769636d567a62335679593255694f694976634746705a43316c626d527762326c7564434973496d466a5932567764484d694f6c7437496e4e6a614756745a534936496d563459574e3049697769626d56306432397961794936496d5670634445314e546f344e44557a496977695957317664573530496a6f694d5441774d4441694c434a6863334e6c64434936496a42344d4441774d4441774d4441774d4441774d4441774d4441774d4441774d4441774d4441774d4441774d4441774d4441774d4441774d434973496e426865565276496a6f694d4867774d4441774d4441774d4441774d4441774d4441774d4441774d4441774d4441774d4441774d4441774d4441774d4441774d444177496977696257463456476c745a57393164464e6c593239755a484d694f6a597766563139",
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
		{"envelope_value_truncated", FrameBridgeRequest, "00100009000101010008aabbcc"},
		{"message_kind_mismatch", FrameBridgeRequest, "001000150001020100040a0b0c0d0a746f6f6c732f63616c6c7b226a736f6e727063223a22322e30222c226964223a312c226d6574686f64223a22746f6f6c732f63616c6c227d"},
		{"request_empty_corr", FrameBridgeRequest, "001000110001010100000a746f6f6c732f63616c6c7b226a736f6e727063223a22322e30222c226964223a312c226d6574686f64223a22746f6f6c732f63616c6c227d"},
		{"notify_nonempty_corr", FrameBridgeNotify, "001000200002030100040a0b0c0d156e6f74696669636174696f6e732f6d6573736167657b226a736f6e727063223a22322e30222c226d6574686f64223a226e6f74696669636174696f6e732f6d657373616765227d"},
		{"reply_empty_corr", FrameBridgeResponse, "001000110001020100000a746f6f6c732f63616c6c7b226a736f6e727063223a22322e30222c226964223a312c22726573756c74223a7b226f6b223a747275657d7d"},
		{"envelope_trailing_octets", FrameBridgeRequest, "001000130001010100040a0b0c0d04746f6f6c63616c6c7b226a736f6e727063223a22322e30222c226964223a312c226d6574686f64223a22746f6f6c732f63616c6c227d"},
		{"safetylabel_truncated", FrameBridgeRequest, "001000150001010100040a0b0c0d0a746f6f6c732f63616c6c001300030205667b226a736f6e727063223a22322e30222c226964223a312c226d6574686f64223a22746f6f6c732f63616c6c227d"},
		{"not_a_bridge_frame", FrameType(0x0001), "001000150001010100040a0b0c0d0a746f6f6c732f63616c6c7b226a736f6e727063223a22322e30222c226964223a312c226d6574686f64223a22746f6f6c732f63616c6c227d"},
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
			"001000150001010100040a0b0c0d0a746f6f6c732f63616c6c7b226a736f6e727063223a22322e30222c226964223a312c226d6574686f64223a22746f6f6c732f63616c6c227d",
			FrameBridgeResponse,
			"001000150001020100040a0b0c0d0a746f6f6c732f63616c6c7b226a736f6e727063223a22322e30222c226964223a312c22726573756c74223a7b226f6b223a747275657d7d", true},
		{"reply_different_corr", FrameBridgeRequest,
			"001000150001010100040a0b0c0d0a746f6f6c732f63616c6c7b226a736f6e727063223a22322e30222c226964223a312c226d6574686f64223a22746f6f6c732f63616c6c227d",
			FrameBridgeResponse,
			"00100015000102010004ffffffff0a746f6f6c732f63616c6c7b226a736f6e727063223a22322e30222c226964223a312c22726573756c74223a7b226f6b223a747275657d7d", false},
		{"stream_reply_correlates", FrameBridgeRequest,
			"001000150001010100040a0b0c0d0a746f6f6c732f63616c6c7b226a736f6e727063223a22322e30222c226964223a312c226d6574686f64223a22746f6f6c732f63616c6c227d",
			FrameBridgeStreamData,
			"001000150001050100040a0b0c0d0a746f6f6c732f63616c6c6368756e6b2d30", true},
		// wave-1: correlation is per §5 identifier equality, independent of protocol_id -- these prove
		// that generic property holds at two of the newly assigned code points (30/6, oracle tcId 4-5).
		{"wave1_nlip_reply_correlates", FrameBridgeRequest,
			"0010000b0006010100044e4c3031007b22666f726d6174223a2274657874222c22737562666f726d6174223a22656e676c697368222c22636f6e74656e74223a225768617420697320746865207765617468657220696e2050617269733f227d",
			FrameBridgeResponse,
			"0010000b0006020100044e4c3031007b22666f726d6174223a2274657874222c22737562666f726d6174223a22656e676c697368222c22636f6e74656e74223a22436c65617220736b6965732c203138432e227d", true},
		{"wave1_agntcy_reply_different_corr_does_not_correlate", FrameBridgeRequest,
			"00100015000801010004414330310a504f5354202f72756e737b226167656e745f6964223a22706c616e6e65722d6167656e74222c22696e707574223a7b226d65737361676573223a5b7b22726f6c65223a2275736572222c22636f6e74656e74223a22706c616e20612074726970227d5d7d7d",
			FrameBridgeResponse,
			"00100015000802010004ffffffff0a504f5354202f72756e737b2272756e5f6964223a2272756e5f30303031222c22737461747573223a2273756363657373222c226f7574707574223a7b226d65737361676573223a5b7b22726f6c65223a22617373697374616e74222c22636f6e74656e74223a22706c616e207265616479227d5d7d7d", false},
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
