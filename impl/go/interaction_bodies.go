package npamp

import (
	"errors"
	"fmt"
)

// NPAMP-INTERACT operation-body validation — spec/companion/89_interaction_channel.md
// §4–§8. An Interaction frame payload is a deterministic-CBOR map (memory_cbor.go, the
// shared codec). This file adds the per-frame field schemas and the structural
// validation the spec requires: the common envelope (§4.2 frame_kind + byte-string
// corr), the required/typed body fields (§6, §8), and the forward-compatibility rule
// (§4.3: ignore unknown non-negative keys, reject unknown negative keys). It reuses the
// generic cborKind / memField / checkFields helpers defined in memory_bodies.go.
//
// This layer establishes that a body is structurally valid deterministic CBOR with the
// required fields present and correctly typed. Value-level and cross-frame constraints
// (for example that a `choice` prompt carries `options`, §6.2, or that a
// PROMPT_RESULT `value` type matches the originating request's `prompt_kind`, §6.2) are
// the responder's to apply against its per-exchange state; they cannot be decided from a
// single frame and are graded by the live-exchange harness, not by this decode surface.

// EventClass is the §6.1 advisory event classification carried on an INTERACT_EVENT.
type EventClass uint64

const (
	EventClassDisplay   EventClass = 0x00
	EventClassNotice    EventClass = 0x01
	EventClassStatus    EventClass = 0x02
	EventClassInput     EventClass = 0x03
	EventClassLifecycle EventClass = 0x04
)

// PromptKind is the §6.2 kind of response solicited by an INTERACT_PROMPT_REQ.
type PromptKind uint64

const (
	PromptKindAcknowledge PromptKind = 0x00
	PromptKindText        PromptKind = 0x01
	PromptKindChoice      PromptKind = 0x02
	PromptKindMultiChoice PromptKind = 0x03
	PromptKindConfirm     PromptKind = 0x04
	PromptKindForm        PromptKind = 0x05
)

// ApprovalDecision is the §6.3 completed human decision on an INTERACT_APPROVAL_RESULT.
type ApprovalDecision uint64

const (
	ApprovalGranted ApprovalDecision = 0x00
	ApprovalDenied  ApprovalDecision = 0x01
)

// InteractionErrorCode is a §8 Interaction error code carried in an INTERACT_ERROR
// (0x0107).
type InteractionErrorCode uint64

const (
	IntErrMalformedRequest  InteractionErrorCode = 1
	IntErrUnknownOperation  InteractionErrorCode = 2
	IntErrUnsupportedPrompt InteractionErrorCode = 3
	IntErrNoHuman           InteractionErrorCode = 4
	IntErrPolicyDenied      InteractionErrorCode = 5
	// IntErrApprovalHeld: an approval request was escalated for a human decision that
	// was NOT obtained (§8.1). It is neither a success nor a definitive denial but a
	// pending human decision, and MUST NOT be conflated with IntErrPolicyDenied or with
	// an INTERACT_APPROVAL_RESULT (granted/denied). Carries approval_id (key 5).
	IntErrApprovalHeld  InteractionErrorCode = 6
	IntErrTimedOut      InteractionErrorCode = 7
	IntErrInternalError InteractionErrorCode = 8
)

// ErrInteractionMalformed is returned by ValidateInteractionPayload for any structural
// fault a responder reports as INTERACT_ERROR code malformed_request (§8, code 1):
// invalid deterministic CBOR, a payload that is not a map, a frame_kind that contradicts
// the frame type, a missing/mistyped corr, a missing required field, a wrong CBOR major
// type, or an unknown negative / non-integer key.
var ErrInteractionMalformed = errors.New("npamp/interaction: malformed_request")

// interactionSchemas holds the body-field schema at keys 2+ per Interaction frame type
// (the common-envelope keys 0/1 are validated separately). Transcribed from
// spec/companion/89 §6 and §8.
//
// INTERACT_PROMPT_RESULT's `value` (key 3) is deliberately absent from its schema: its
// CBOR type is fixed by the originating request's prompt_kind (§6.2), which is not
// available when decoding this frame in isolation, so it is accepted structurally (as an
// OPTIONAL non-negative key, §4.3) and its type is checked by the responder against the
// exchange it answers.
var interactionSchemas = map[FrameType][]memField{
	FrameInteractEvent: { // §6.1
		{2, kUint, true}, {3, kText, false}, {4, kMap, false}, {5, kBool, false},
	},
	FrameInteractEventAck: {}, // §6.1 (envelope only)
	FrameInteractPromptReq: { // §6.2
		{2, kUint, true}, {3, kText, true}, {4, kArray, false}, {5, kMap, false},
		{6, kUint, false},
	},
	FrameInteractPromptResult: {{2, kUint, true}}, // §6.2 (value(3) type varies by prompt_kind)
	FrameInteractApprovalReq: { // §6.3
		{2, kText, true}, {3, kUint, false}, {4, kMap, false}, {5, kUint, false},
	},
	FrameInteractApprovalResult: {{2, kUint, true}, {3, kText, false}}, // §6.3
	FrameInteractCancel:         {{2, kUint, false}},                   // §6.4
	FrameInteractError: { // §8
		{2, kUint, true}, {3, kText, true}, {4, kUint, false}, {5, kText, false},
	},
}

// ValidateInteractionPayload decodes and structurally validates an Interaction frame
// payload for frame type ft. It returns the decoded map on success. On any structural
// fault it returns an error wrapping ErrInteractionMalformed (spec §8 malformed_request):
// the payload is not valid deterministic CBOR, is not a map, has a frame_kind (0) that
// contradicts ft, omits or mistypes corr (1), omits a required field, carries a field of
// the wrong CBOR major type, or carries an unknown negative / non-integer key. Unknown
// non-negative keys are accepted and left in the returned map (forward compatibility,
// §4.3), including in every nested body/schema/context map.
func ValidateInteractionPayload(ft FrameType, payload []byte) (*cborMap, error) {
	schema, known := interactionSchemas[ft]
	if !known {
		return nil, fmt.Errorf("%w: 0x%04X is not an Interaction operation frame type", ErrInteractionMalformed, uint16(ft))
	}
	v, err := cborDecodeTop(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInteractionMalformed, err)
	}
	m, ok := v.(*cborMap)
	if !ok {
		return nil, fmt.Errorf("%w: payload is not a CBOR map", ErrInteractionMalformed)
	}

	// Common envelope (§4.2): frame_kind (0) MUST equal ft; corr (1) MUST be a
	// non-empty byte string of 1–64 bytes (present on every Interaction frame — every
	// *_REQ, every INTERACT_EVENT, and every frame that replies to, acknowledges, or
	// withdraws one, §5.1).
	fk, ok := m.get(0)
	if !ok {
		return nil, fmt.Errorf("%w: missing frame_kind (0)", ErrInteractionMalformed)
	}
	fkv, ok := fk.(uint64)
	if !ok {
		return nil, fmt.Errorf("%w: frame_kind (0) is not an unsigned int", ErrInteractionMalformed)
	}
	if fkv != uint64(ft) {
		return nil, fmt.Errorf("%w: frame_kind 0x%04X contradicts frame type 0x%04X", ErrInteractionMalformed, uint16(fkv), uint16(ft))
	}
	corr, ok := m.get(1)
	if !ok {
		return nil, fmt.Errorf("%w: missing corr (1)", ErrInteractionMalformed)
	}
	cb, ok := corr.([]byte)
	if !ok || len(cb) < 1 || len(cb) > 64 {
		return nil, fmt.Errorf("%w: corr (1) must be a byte string of 1–64 bytes", ErrInteractionMalformed)
	}

	if err := checkFields(m, schema, map[uint64]bool{0: true, 1: true}); err != nil {
		// checkFields reports via ErrMemoryMalformed (shared helper); re-wrap under
		// ErrInteractionMalformed so callers get a consistent Interaction error surface
		// (the inner text is preserved for logs).
		return nil, fmt.Errorf("%w: %v", ErrInteractionMalformed, err)
	}
	return m, nil
}
