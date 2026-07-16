package npamp

// NPAMP-CAP companion frame types — spec/companion/84_capability_channel.md §3.
//
// These are channel-specific frame types interpreted only on the Capability channel
// (0x0002); a given value has no NPAMP-CAP meaning on any other channel (draft-01
// §4.6, per-channel frame-type namespace). The set is the nine application-band
// operation frames (0x0100–0x0108) plus the four token-extension frames in the
// companion-extension band (0x0060–0x0063, the range the core reserves for the
// Capability channel's token extensions, §3.3).
//
// Unlike NPAMP-STREAM's persistent Unsigned-int sub_stream_id, and like NPAMP-MEMORY,
// the common-envelope key 1 is corr — a per-exchange byte-string correlation token
// (§4.2, §5): every *_REQ and each of CAP_TOKEN_PRESENT / CAP_TOKEN_CHALLENGE carries
// a non-empty corr, and every reply echoes it. The Capability channel carries no
// foreign protocol: the operation body IS N-PAMP's own deterministic-CBOR encoding
// (§2), so the correlation token, operation semantics, and error object all live
// inside the CBOR body and this companion consumes no extension-TLV code point.
const (
	// Application-band operation frames (0x0100+): per-operation request/result
	// pairs plus a single structured error frame (§3.1).
	FrameCapIssueReq       FrameType = 0x0100
	FrameCapIssueResult    FrameType = 0x0101
	FrameCapDelegateReq    FrameType = 0x0102
	FrameCapDelegateResult FrameType = 0x0103
	FrameCapRevokeReq      FrameType = 0x0104
	FrameCapRevokeResult   FrameType = 0x0105
	FrameCapLookupReq      FrameType = 0x0106
	FrameCapLookupResult   FrameType = 0x0107
	FrameCapError          FrameType = 0x0108

	// Companion-extension band token-extension frames (0x0060–0x0063), the
	// Capability channel's reserved range in the core's Reserved Frame-Type Ranges
	// table (§3.3). OPTIONAL to implement; a responder that does not implement them
	// replies CAP_ERROR unknown_operation.
	FrameCapTokenPresent   FrameType = 0x0060
	FrameCapTokenAccept    FrameType = 0x0061
	FrameCapTokenChallenge FrameType = 0x0062
	FrameCapTokenProof     FrameType = 0x0063
)

// IsCapabilityFrame reports whether ft is an NPAMP-CAP companion frame type — one of
// the application-band operation frames (0x0100–0x0108) or a token-extension frame
// (0x0060–0x0063). It does not consider the channel; a caller has already established
// that the frame arrived on the Capability channel (0x0002), on which these values
// carry their NPAMP-CAP meaning.
func IsCapabilityFrame(ft FrameType) bool {
	switch {
	case ft >= FrameCapTokenPresent && ft <= FrameCapTokenProof:
		return true
	case ft >= FrameCapIssueReq && ft <= FrameCapError:
		return true
	default:
		return false
	}
}

// IsCapabilityRequest reports whether ft is an NPAMP-CAP request frame — one that a
// requester originates and that a responder answers with a matching *_RESULT or with
// FrameCapError (§3, §5). The *_RESULT, CAP_TOKEN_ACCEPT, CAP_TOKEN_PROOF, and
// CAP_ERROR reply frames return false. CAP_TOKEN_PRESENT and CAP_TOKEN_CHALLENGE are
// requests: each carries a corr and elicits a reply (§5.1).
func IsCapabilityRequest(ft FrameType) bool {
	switch ft {
	case FrameCapIssueReq, FrameCapDelegateReq, FrameCapRevokeReq, FrameCapLookupReq,
		FrameCapTokenPresent, FrameCapTokenChallenge:
		return true
	default:
		return false
	}
}
