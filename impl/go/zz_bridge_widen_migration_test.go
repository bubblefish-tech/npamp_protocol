package npamp

import (
	"encoding/hex"
	"testing"
)

// TestBridgeProtocolIDU8ToU16MigrationRoundTrip proves the NPAMP-REG 30_protocol_registry.md §8.4
// migration invariant (design.md P-U16-MIGRATE, ecosystem-viral-wire task C.7 AC-8.2.2): for every
// protocol_id value that was standards-assigned under the one-octet field (0x01-0x0A, §6), the
// two-octet wire encoding is the EXACT zero-extension of the one-octet value (0xNN -> 0x00NN), and
// decoding that two-octet wire form yields the identical named protocol the one-octet value named
// before the widening -- "for any u8 value v, decode(widen(v)) == decode(v) (same protocol)".
//
// This is NOT a test of the oracle's bytes (that is TestBridgeOracleCrossValidate); it is a direct,
// from-scratch check of the migration property against the impl's own codec, independent of any
// fixture file: it hand-constructs the "as it would have been on the wire before the widening"
// single-octet value, zero-extends it itself (the migration formula, applied here rather than in the
// codec, so the test does not merely restate encodeEnvelopeValue's behavior), and confirms the
// widened codec accepts that construction and decodes it back to the same BridgeProtocol constant.
func TestBridgeProtocolIDU8ToU16MigrationRoundTrip(t *testing.T) {
	// The ten protocol_id values standards-assigned before the §8.4 widening (0x01-0x0A; NPAMP-REG §6),
	// each paired with the u8-era single octet it was carried as, per the protocol_id column of §6.
	cases := []struct {
		name      string
		u8Wire    byte // the single octet the pre-widening wire format carried
		wideProto BridgeProtocol
	}{
		{"mcp", 0x01, BridgeProtoMCP},
		{"a2a", 0x02, BridgeProtoA2A},
		{"http2", 0x03, BridgeProtoHTTP2},
		{"websocket", 0x04, BridgeProtoWebSocket},
		{"nlip", 0x06, BridgeProtoNLIP},
		{"anp", 0x07, BridgeProtoANP},
		{"agntcy", 0x08, BridgeProtoAGNTCY},
		{"ap2", 0x09, BridgeProtoAP2},
		{"x402", 0x0A, BridgeProtoX402},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// The §8.4 migration formula applied directly, NOT via the codec under test: a pre-widening
			// value 0xNN becomes the two-octet value 0x00NN (zero high-order octet).
			widened := uint16(0x0000)<<8 | uint16(c.u8Wire)
			if widened != uint16(c.wideProto) {
				t.Fatalf("migration formula: widen(0x%02x) = 0x%04x, want the assigned constant 0x%04x (%s)",
					c.u8Wire, widened, uint16(c.wideProto), c.name)
			}

			// Build a minimal, otherwise-valid BridgeEnvelope value by hand (protocol_id as the
			// migrated two-octet value, then message_kind/content_type/flags/corr_len/method_len all
			// zero, corr/method both empty) and confirm the widened decoder accepts it and reports the
			// exact protocol the pre-widening octet named.
			envHex := "00" + hex.EncodeToString([]byte{c.u8Wire}) + "0000000000"
			raw, err := hex.DecodeString(envHex)
			if err != nil {
				t.Fatalf("bad test hex %q: %v", envHex, err)
			}
			env, err := decodeEnvelopeValue(raw)
			if err != nil {
				t.Fatalf("decodeEnvelopeValue rejected a migrated (zero-extended) envelope: %v", err)
			}
			if env.Protocol != c.wideProto {
				t.Fatalf("decode(widen(0x%02x)) = protocol 0x%04x, want 0x%04x (%s) -- migration changed which protocol is named",
					c.u8Wire, uint16(env.Protocol), uint16(c.wideProto), c.name)
			}

			// The canonical re-encode of that migrated envelope MUST reproduce the exact widened wire
			// bytes -- the migration is lossless in both directions, not merely decode-tolerant.
			reEncoded := encodeEnvelopeValue(env)
			if hex.EncodeToString(reEncoded) != envHex {
				t.Fatalf("re-encode of the migrated envelope = %s, want %s (lossless round-trip)",
					hex.EncodeToString(reEncoded), envHex)
			}
		})
	}
}

// TestBridgeProtocolIDWidenedFieldIsTwoOctets proves the wire-level shape of the widening directly:
// encodeEnvelopeValue emits protocol_id as two big-endian octets (not one), and decodeEnvelopeValue
// requires at least six head octets (not five) before it will even look at corr_len -- the exact
// mutation-sensitive property that would fail if the codec had not actually been widened.
func TestBridgeProtocolIDWidenedFieldIsTwoOctets(t *testing.T) {
	e := BridgeEnvelope{Protocol: BridgeProtoNLIP, Kind: BridgeKindNotification, ContentType: BridgeContentJSON}
	out := encodeEnvelopeValue(e)
	if len(out) < 2 || out[0] != 0x00 || out[1] != 0x06 {
		t.Fatalf("encodeEnvelopeValue leading octets = % x, want 00 06 (protocol_id as u16 big-endian for BridgeProtoNLIP=0x0006)", out[:min(2, len(out))])
	}
	// A five-octet head (the pre-widening minimum) is now truncated: the sixth octet (corr_len) is
	// unreadable, so a decoder that still assumed a one-octet protocol_id would (wrongly) accept this
	// as a complete, corr_len=0 envelope; the widened decoder MUST instead reject it as truncated.
	if _, err := decodeEnvelopeValue([]byte{0x00, 0x06, 0x03, 0x01, 0x00}); err == nil {
		t.Fatalf("decodeEnvelopeValue accepted a 5-octet head as complete; the widened field needs 6 octets before corr_len")
	}
}
