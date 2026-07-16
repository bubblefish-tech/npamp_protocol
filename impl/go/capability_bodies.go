package npamp

import (
	"errors"
	"fmt"
)

// NPAMP-CAP operation-body validation — spec/companion/84_capability_channel.md §4–§8.
// A Capability frame payload is a deterministic-CBOR map (memory_cbor.go, shared
// codec). This file adds the per-frame field schemas and the structural validation
// the spec requires: the common envelope (§4.2 frame_kind + byte-string corr), the
// required/typed body fields (§6–§8), and the forward-compatibility rule (§4.3:
// ignore unknown non-negative keys, reject unknown negative keys). It reuses the
// generic cborKind / memField / checkFields / matchesKind helpers defined in
// memory_bodies.go.
//
// Value-level constraints (for example that a lookup carries effect=read_only, or the
// effect fail-safe of §5.3, or the delegation-attenuation invariants of §6.2) are the
// responder's to apply against live state; this layer establishes that the body is
// structurally valid deterministic CBOR with the required fields present and correctly
// typed, and enforces the §4 MUST-reject clauses that the graded payload-decode
// surface covers (§10, final paragraph).

// CapEffectClass is the §5.3 side-effect class carried by a state-mutating Capability
// request. It is the native-body analogue of a Bridge SafetyLabel, carried in-body
// because the Capability channel owns its body (§2).
type CapEffectClass uint64

const (
	CapEffectReadOnly           CapEffectClass = 0x00
	CapEffectIdempotentWrite    CapEffectClass = 0x01
	CapEffectNonIdempotentWrite CapEffectClass = 0x02
	CapEffectDestructive        CapEffectClass = 0x03
)

// CapErrorCode is a §8 Capability error code carried in a CAP_ERROR (0x0108).
type CapErrorCode uint64

const (
	CapErrMalformedRequest CapErrorCode = 1
	CapErrUnknownOperation CapErrorCode = 2
	CapErrPolicyDenied     CapErrorCode = 3
	// CapErrApprovalRequired: the operation was escalated for human approval and was
	// NOT executed (§8.1). It is neither a success nor a definitive denial and MUST
	// NOT be conflated with CapErrPolicyDenied or reported as any *_RESULT; it carries
	// approval_id (key 5).
	CapErrApprovalRequired CapErrorCode = 4
	CapErrNotFound         CapErrorCode = 5
	CapErrNotDelegable     CapErrorCode = 6
	CapErrRevoked          CapErrorCode = 7
	CapErrTokenInvalid     CapErrorCode = 8
	CapErrInternalError    CapErrorCode = 9
)

// ErrCapMalformed is returned by ValidateCapabilityPayload for any structural fault a
// responder reports as CAP_ERROR code malformed_request (§8, code 1): invalid
// deterministic CBOR, a missing required field, a wrong CBOR major type, a frame_kind
// that contradicts the frame type, a corr that is not a non-empty 1–64 B byte string,
// an unknown negative key, or a non-integer key.
var ErrCapMalformed = errors.New("npamp/capability: malformed_request")

// capabilitySchemas holds the body-field schema at keys 2+ per Capability frame type
// (the common-envelope keys 0/1 are validated separately). Transcribed from
// spec/companion/84 §6, §7, §8.
var capabilitySchemas = map[FrameType][]memField{
	FrameCapIssueReq: { // §6.1
		{2, kText, true}, {3, kText, true}, {4, kMap, false}, {5, kText, false},
		{6, kText, false}, {7, kUint, false}, {8, kText, false}, {9, kUint, true},
	},
	FrameCapIssueResult: {{2, kMap, true}, {3, kText, true}}, // §6.1 (token + status)
	FrameCapDelegateReq: { // §6.2
		{2, kText, true}, {3, kText, true}, {4, kMap, false}, {5, kText, false},
		{6, kUint, false}, {7, kUint, true},
	},
	FrameCapDelegateResult: {{2, kMap, true}, {3, kText, true}}, // §6.2 (token + status)
	FrameCapRevokeReq: { // §6.3
		{2, kText, true}, {3, kBool, false}, {4, kText, false}, {5, kUint, true},
	},
	FrameCapRevokeResult: {{2, kText, true}, {3, kText, true}, {4, kUint, false}}, // §6.3
	FrameCapLookupReq: { // §6.4
		{2, kText, false}, {3, kText, false}, {4, kText, false}, {5, kBool, false},
		{6, kUint, false}, {7, kBytes, false}, {8, kUint, true},
	},
	FrameCapLookupResult: {{2, kArray, true}, {3, kBool, true}, {4, kBytes, false}}, // §6.4
	FrameCapError: { // §8
		{2, kUint, true}, {3, kText, true}, {4, kUint, false}, {5, kText, false},
	},
	FrameCapTokenPresent: {{2, kMap, true}, {3, kArray, false}, {4, kUint, true}}, // §7.1
	FrameCapTokenAccept:  {{2, kText, true}, {3, kText, true}},                    // §7.1
	FrameCapTokenChallenge: { // §7.2
		{2, kText, true}, {3, kBytes, true}, {4, kUint, true},
	},
	FrameCapTokenProof: {{2, kText, true}, {3, kBytes, true}}, // §7.2
}

// capabilityTokenSchema is the capability_token projection (§6.5), a nested map whose
// keys start at 0. Used to validate tokens carried in issue/delegate/lookup results
// and in a CAP_TOKEN_PRESENT body.
var capabilityTokenSchema = []memField{
	{0, kText, true}, {1, kText, true}, {2, kText, true}, {3, kText, true},
	{4, kMap, false}, {5, kText, false}, {6, kText, false}, {7, kText, false},
	{8, kUint, false}, {9, kUint, false}, {10, kText, false}, {11, kText, false},
	{12, kText, false}, {13, kText, false},
}

// ValidateCapabilityPayload decodes and structurally validates a Capability frame
// payload for frame type ft. It returns the decoded map on success. On any structural
// fault it returns an error wrapping ErrCapMalformed (spec §8 malformed_request): the
// payload is not valid deterministic CBOR, is not a map, has a frame_kind (0) that
// contradicts ft, carries a corr (1) that is not a non-empty 1–64 B byte string, omits
// a required field, carries a field of the wrong CBOR major type, or carries an unknown
// negative / non-integer key. Unknown non-negative keys are accepted and left in the
// returned map (forward compatibility, §4.3).
func ValidateCapabilityPayload(ft FrameType, payload []byte) (*cborMap, error) {
	schema, known := capabilitySchemas[ft]
	if !known {
		return nil, fmt.Errorf("%w: 0x%04X is not a Capability operation frame type", ErrCapMalformed, uint16(ft))
	}
	v, err := cborDecodeTop(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCapMalformed, err)
	}
	m, ok := v.(*cborMap)
	if !ok {
		return nil, fmt.Errorf("%w: payload is not a CBOR map", ErrCapMalformed)
	}

	// Common envelope (§4.2): frame_kind (0) MUST equal ft; corr (1) MUST be a
	// non-empty byte string of 1–64 bytes (present on every Capability frame — every
	// frame is a *_REQ, a CAP_TOKEN_PRESENT/CHALLENGE, or a reply that echoes corr).
	fk, ok := m.get(0)
	if !ok {
		return nil, fmt.Errorf("%w: missing frame_kind (0)", ErrCapMalformed)
	}
	fkv, ok := fk.(uint64)
	if !ok {
		return nil, fmt.Errorf("%w: frame_kind (0) is not an unsigned int", ErrCapMalformed)
	}
	if fkv != uint64(ft) {
		return nil, fmt.Errorf("%w: frame_kind 0x%04X contradicts frame type 0x%04X", ErrCapMalformed, uint16(fkv), uint16(ft))
	}
	corr, ok := m.get(1)
	if !ok {
		return nil, fmt.Errorf("%w: missing corr (1)", ErrCapMalformed)
	}
	cb, ok := corr.([]byte)
	if !ok || len(cb) < 1 || len(cb) > 64 {
		return nil, fmt.Errorf("%w: corr (1) must be a non-empty byte string of 1–64 bytes", ErrCapMalformed)
	}

	if err := checkFields(m, schema, map[uint64]bool{0: true, 1: true}); err != nil {
		// checkFields reports via ErrMemoryMalformed (shared helper); re-wrap under
		// ErrCapMalformed so callers get a consistent Capability error surface (the
		// inner text is preserved for logs).
		return nil, fmt.Errorf("%w: %v", ErrCapMalformed, err)
	}
	return m, nil
}

// ValidateCapabilityToken validates a nested capability_token map (§6.5). Its keys
// start at 0; there is no envelope. Unknown non-negative keys are accepted; an unknown
// negative or non-integer key is rejected (§4.3).
func ValidateCapabilityToken(tok *cborMap) error {
	if tok == nil {
		return fmt.Errorf("%w: nil capability_token", ErrCapMalformed)
	}
	if err := checkFields(tok, capabilityTokenSchema, map[uint64]bool{}); err != nil {
		return fmt.Errorf("%w: %v", ErrCapMalformed, err)
	}
	return nil
}
