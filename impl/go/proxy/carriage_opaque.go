// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package proxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// NPAMP-CC-OPAQUE (spec/companion/25_carriage_opaque.md) -- the sixth and
// final carriage leg of E2.4/R10 (doc.go): raw TCP, or any payload whose
// media type is not one of the three BridgeEnvelope `content_type`-enumerated
// values (application/json, application/cbor, application/grpc+proto).
//
// This leg was genuinely spec-blocked (doc.go's prior "Not yet built" note):
// §10 of the companion spec named two open items "for the core-specification
// maintainer" -- the OpaqueContentType TLV type code point (§4.3) and the
// BridgeEnvelope `content_type` discriminator value (§4.4) -- neither of
// which the core registries had assigned. Registering both (registries/
// tlv_tags.csv, registries/bridge_protocol_ids.csv's sibling content_type
// prose in spec/companion/10_bridge_framework.md, and decisions/adr/0015)
// unblocks this file; see that ADR for the derivation and authority of each
// value. Both assignments are additive reservations within ranges the core
// specification already sets aside for companions (§10's own framing) and
// touch no frozen n-pamp/3 wire byte.

// opaqueContentTypeTLV is the OpaqueContentType TLV Type (§4.3): a companion-
// reserved, variable-length extension TLV carrying the full IANA media-type
// string when the payload's media type is not one of the three BridgeEnvelope
// `content_type`-enumerated values. Assigned 0x0012 -- the fourth of the core
// specification's four companion-reserved TLV Types (0x0010 BridgeEnvelope,
// 0x0012 OpaqueContentType, 0x0013 SafetyLabel; 0x0014 remains reserved but is
// fixed-32-octet/handshake-only and cannot carry a variable-length string).
// 0x0012 became available when T15.2/DECISIONS.md D11 retired the unspecified
// "AnomalyCharge" TLV back to "(reserved) for a companion specification"
// (registries/tlv_tags.csv); this leg is the first companion to consume it.
const opaqueContentTypeTLV npamp.TLVType = 0x0012

// opaqueContentTypeDiscriminator is the BridgeEnvelope `content_type`
// discriminator value (§4.4): a value distinct from the three assigned values
// (0x01 JSON, 0x02 CBOR, 0x03 grpc+proto, bridge.go) whose sole meaning is
// "the media type is carried in the OpaqueContentType TLV." Assigned 0x04,
// the next value in the `content_type` enumeration after the three currently
// assigned ones (spec/companion/10_bridge_framework.md §4; decisions/adr/0015).
const opaqueContentTypeDiscriminator npamp.BridgeContentType = 0x04

// errOpaqueContentType classifies the four §4.2/§4.3 envelope faults this leg
// can detect; every one maps to BRIDGE_ERROR code EnvelopeMalformed (§8.3:
// "This document defines no new error codes").
type errOpaqueContentType struct{ reason string }

func (e *errOpaqueContentType) Error() string {
	return fmt.Sprintf("npamp/proxy: opaque carriage content-type declaration malformed: %s", e.reason)
}

// contentTypeToMediaType maps a BridgeEnvelope §4.2-case-1 enumerated
// content_type to its IANA media type (§4.1's own naming for the three
// values NPAMP-BRIDGE already assigns).
func contentTypeToMediaType(ct npamp.BridgeContentType) (string, bool) {
	switch ct {
	case npamp.BridgeContentJSON:
		return "application/json", true
	case npamp.BridgeContentCBOR:
		return "application/cbor", true
	case npamp.BridgeContentGRPCProto:
		return "application/grpc+proto", true
	default:
		return "", false
	}
}

// mediaTypeToContentType is the inverse of contentTypeToMediaType, used by
// encodeOpaquePayload to choose §4.2 case 1 (an already-enumerated media
// type) over case 2 (the OpaqueContentType TLV) whenever possible -- §4.2
// case 1 is REQUIRED whenever it applies ("the sender MUST set that
// enumerated value ... and MUST NOT attach a separate content-type extension
// TLV").
func mediaTypeToContentType(mediaType string) (npamp.BridgeContentType, bool) {
	switch mediaType {
	case "application/json":
		return npamp.BridgeContentJSON, true
	case "application/cbor":
		return npamp.BridgeContentCBOR, true
	case "application/grpc+proto":
		return npamp.BridgeContentGRPCProto, true
	default:
		return 0, false
	}
}

// validMediaTypeSyntax reports whether s is a syntactically valid media type
// per §4.3 ("type/subtype syntax with optional parameters as defined by the
// media-type grammar", RFC 7231 §3.1.1.1 media-type ABNF). It requires a
// non-empty type and subtype built from RFC 7231 tchar octets, separated by
// exactly one '/', with any ';'-delimited parameter section left otherwise
// unparsed (a full RFC 7231 parameter-quoting grammar is not required for
// this leg's fail-closed structural check: an empty type/subtype or a
// missing '/' is what a genuinely malformed declaration looks like).
func validMediaTypeSyntax(s string) bool {
	if s == "" {
		return false
	}
	head := s
	if i := strings.IndexByte(s, ';'); i >= 0 {
		head = s[:i]
	}
	slash := strings.IndexByte(head, '/')
	if slash <= 0 || slash == len(head)-1 {
		return false // no '/', or an empty type/subtype half
	}
	return isToken(head[:slash]) && isToken(head[slash+1:])
}

// isToken reports whether s is a non-empty RFC 7231 §3.2.6 "token": one or
// more tchar octets (ALPHA / DIGIT / one of "!#$%&'*+-.^_`|~").
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isTchar(s[i]) {
			return false
		}
	}
	return true
}

func isTchar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}

// encodeOpaquePayload builds an NPAMP-CC-OPAQUE Bridge frame payload for env
// (Protocol/Kind/CorrelationID/Method already set by the caller; ContentType
// is overwritten here per mediaType) carrying raw verbatim (§1.3: byte-exact,
// never inspected or transformed). It implements §4.2's REQUIRED case split:
// case 1 (mediaType is one of the three enumerated media types) sets the
// enumerated content_type and attaches no extension TLV; case 2 (any other
// media type, for example the raw-TCP default application/octet-stream)
// attaches the OpaqueContentType TLV per §4.3/§4.4/§5's frame layout
// (BridgeEnvelope, OpaqueContentType, [SafetyLabel], foreign -- this leg
// never attaches a SafetyLabel, matching every other leg in this build,
// doc.go). mediaType MUST be non-empty, NUL-free, and syntactically valid
// (§4.3) when case 2 applies; a case-1 mediaType is validated by construction
// (mediaTypeToContentType only recognizes the three well-formed values).
func encodeOpaquePayload(env npamp.BridgeEnvelope, mediaType string, raw []byte) ([]byte, error) {
	if ct, ok := mediaTypeToContentType(mediaType); ok {
		env.ContentType = ct
		return npamp.EncodeBridgePayload(env, nil, raw), nil
	}
	if mediaType == "" {
		return nil, &errOpaqueContentType{reason: "declared media type is empty (§4.3: MUST be non-empty)"}
	}
	if strings.IndexByte(mediaType, 0) >= 0 {
		return nil, &errOpaqueContentType{reason: "declared media type contains a NUL octet (§4.3)"}
	}
	if !validMediaTypeSyntax(mediaType) {
		return nil, &errOpaqueContentType{reason: fmt.Sprintf("declared media type %q is not a syntactically valid media type (§4.3)", mediaType)}
	}
	env.ContentType = opaqueContentTypeDiscriminator
	envelopeOnly := npamp.EncodeBridgePayload(env, nil, nil)
	ext := npamp.TLV{Type: opaqueContentTypeTLV, Value: []byte(mediaType)}.Encode(nil)
	out := make([]byte, 0, len(envelopeOnly)+len(ext)+len(raw))
	out = append(out, envelopeOnly...)
	out = append(out, ext...)
	out = append(out, raw...)
	return out, nil
}

// peekLeadingTLV reports whether buf begins with a well-formed TLV of type
// want (a 4-octet Type/Length header the core specification's extension-TLV
// encoding defines), mirroring the same header-peek idiom impl/go's own
// ValidateBridgePayload uses to detect an optional SafetyLabel TLV
// immediately following the envelope (bridge_bodies.go) -- applied here one
// TLV further down the frame, since this leg's payload layout places
// OpaqueContentType before any SafetyLabel (§5). Returns present=false with a
// nil error when buf does not begin with type want (too short, or a
// different type) -- that is not itself a fault, since case 1 payloads
// legitimately begin with arbitrary application bytes.
func peekLeadingTLV(buf []byte, want npamp.TLVType) (value []byte, rest []byte, present bool, err error) {
	if len(buf) < 4 {
		return nil, buf, false, nil
	}
	typ := npamp.TLVType(binary.BigEndian.Uint16(buf[0:2]))
	if typ != want {
		return nil, buf, false, nil
	}
	ln := int(binary.BigEndian.Uint16(buf[2:4]))
	if len(buf) < 4+ln {
		return nil, nil, true, &errOpaqueContentType{reason: fmt.Sprintf("OpaqueContentType TLV length %d exceeds remaining payload", ln)}
	}
	return buf[4 : 4+ln], buf[4+ln:], true, nil
}

// decodeOpaquePayload is encodeOpaquePayload's inverse: given the envelope
// and the generic decoder's `Foreign` slice (npamp.DecodeBridgeFrame /
// DecodeBridgeEnvelope, which does not recognize opaqueContentTypeTLV and so
// folds it -- when present -- into the front of Foreign verbatim), it
// recovers the declared media type and the true raw payload, enforcing every
// §4.2/§4.3 MUST-reject rule:
//
//   - both an enumerated non-discriminator content_type AND an
//     OpaqueContentType TLV present -> ambiguous, reject (§4.2 point 3);
//   - the discriminator content_type but no OpaqueContentType TLV -> reject
//     (nothing to read the declared media type from);
//   - a present OpaqueContentType TLV whose value is empty, contains a NUL
//     octet, or is not syntactically valid -> reject (§4.3);
//   - a content_type value that is neither one of the three enumerated
//     values nor the discriminator -> reject (unrecognized, §4.4 last
//     paragraph: "a receiver MUST treat an unrecognized content_type value as
//     a malformed envelope").
func decodeOpaquePayload(env npamp.BridgeEnvelope, foreign []byte) (mediaType string, raw []byte, err error) {
	tlvValue, rest, present, perr := peekLeadingTLV(foreign, opaqueContentTypeTLV)
	if perr != nil {
		return "", nil, perr
	}
	isDiscriminator := env.ContentType == opaqueContentTypeDiscriminator

	switch {
	case present && !isDiscriminator:
		return "", nil, &errOpaqueContentType{reason: "carries both an enumerated content_type value and an OpaqueContentType TLV (§4.2 point 3)"}
	case !present && isDiscriminator:
		return "", nil, &errOpaqueContentType{reason: "content_type is the OpaqueContentType discriminator but no OpaqueContentType TLV is present"}
	case present && isDiscriminator:
		if len(tlvValue) == 0 {
			return "", nil, &errOpaqueContentType{reason: "OpaqueContentType TLV value is empty (§4.3: MUST be non-empty)"}
		}
		if bytes.IndexByte(tlvValue, 0) >= 0 {
			return "", nil, &errOpaqueContentType{reason: "OpaqueContentType TLV value contains a NUL octet (§4.3)"}
		}
		mt := string(tlvValue)
		if !validMediaTypeSyntax(mt) {
			return "", nil, &errOpaqueContentType{reason: fmt.Sprintf("OpaqueContentType TLV value %q is not a syntactically valid media type (§4.3)", mt)}
		}
		return mt, rest, nil
	default: // !present && !isDiscriminator: §4.2 case 1
		mt, ok := contentTypeToMediaType(env.ContentType)
		if !ok {
			return "", nil, &errOpaqueContentType{reason: fmt.Sprintf("content_type 0x%02x is neither an enumerated media type nor the OpaqueContentType discriminator", byte(env.ContentType))}
		}
		return mt, foreign, nil
	}
}
