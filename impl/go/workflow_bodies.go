package npamp

import (
	"errors"
	"fmt"
)

// NPAMP-WORKFLOW operation-body validation — spec/companion/8a_workflow_channel.md
// §4–§8. A Workflow frame payload is a deterministic-CBOR map (memory_cbor.go, shared
// codec). This file adds the per-frame field schemas and the structural validation the
// spec requires: the common envelope (§4.2 frame_kind + conditional corr), the
// required/typed body fields (§6, §8), and the forward-compatibility rule (§4.3: ignore
// unknown non-negative keys, reject unknown negative keys). It reuses the generic
// cborKind / memField / checkFields helpers defined in memory_bodies.go, and the
// EffectClass constants (§5.3 share the 0x00–0x03 side-effect classes with NPAMP-MEMORY).

// ErrWorkflowMalformed is returned for any structural fault a receiver answers with
// WORKFLOW_ERROR code malformed_request (§8, code 1): invalid deterministic CBOR, a
// payload that is not a map, a missing REQUIRED field, a wrong CBOR major type, a
// frame_kind that contradicts the frame type, a corr that is absent or not a byte
// string on a corr-bearing frame, or an unknown negative / non-integer key.
var ErrWorkflowMalformed = errors.New("npamp/workflow: malformed_request")

// WorkflowState is a §5.4 task lifecycle state carried as the `state` field of the
// frames that report it. States 0x02–0x04 are terminal.
type WorkflowState uint64

const (
	WfStateAccepted  WorkflowState = 0x00
	WfStateRunning   WorkflowState = 0x01
	WfStateSucceeded WorkflowState = 0x02
	WfStateFailed    WorkflowState = 0x03
	WfStateCanceled  WorkflowState = 0x04
)

// WorkflowErrorCode is a §8 Workflow error code carried in a WORKFLOW_ERROR (0x0108).
type WorkflowErrorCode uint64

const (
	WfErrMalformedRequest WorkflowErrorCode = 1
	WfErrUnknownOperation WorkflowErrorCode = 2
	WfErrPolicyDenied     WorkflowErrorCode = 3
	// WfErrApprovalRequired: the task was escalated for human approval and was NOT
	// executed (§8.1). It is neither a success nor a definitive denial, and MUST NOT be
	// conflated with WfErrPolicyDenied or reported as a WORKFLOW_SUBMIT_RESULT. It
	// carries an approval_id (key 5).
	WfErrApprovalRequired WorkflowErrorCode = 4
	WfErrUnknownTask      WorkflowErrorCode = 5
	WfErrInternalError    WorkflowErrorCode = 6
)

// workflowSchemas holds the body-field schema at keys 2+ per Workflow frame type (the
// common-envelope keys 0/1 are validated separately). Transcribed from
// spec/companion/8a §6.1–§6.5 and §8.
var workflowSchemas = map[FrameType][]memField{
	FrameWorkflowSubmitReq: { // §6.1
		{2, kText, true}, {3, kBytes, false}, {4, kMap, false}, {5, kUint, false},
		{6, kText, false}, {7, kText, false}, {8, kText, false}, {9, kText, false},
		{10, kMap, false}, {11, kUint, true},
	},
	FrameWorkflowSubmitResult: {{2, kText, true}, {3, kUint, true}}, // §6.1
	FrameWorkflowStatusReq:    {{2, kText, true}},                   // §6.2
	FrameWorkflowStatusResult: { // §6.2
		{2, kText, true}, {3, kUint, true}, {4, kUint, false}, {5, kText, false},
		{6, kUint, false}, {7, kText, false},
	},
	FrameWorkflowCancelReq:    {{2, kText, true}, {3, kText, false}}, // §6.3
	FrameWorkflowCancelResult: {{2, kText, true}, {3, kUint, true}},  // §6.3
	FrameWorkflowStepEvent: { // §6.4 (no corr; task-scoped)
		{2, kText, true}, {3, kUint, true}, {4, kUint, true}, {5, kUint, false},
		{6, kText, false}, {7, kUint, false}, {8, kBytes, false}, {9, kText, false},
	},
	FrameWorkflowComplete: { // §6.5 (no corr; task-scoped)
		{2, kText, true}, {3, kUint, true}, {4, kUint, true}, {5, kBytes, false},
		{6, kUint, false}, {7, kText, false},
	},
	FrameWorkflowError: { // §8
		{2, kUint, true}, {3, kText, true}, {4, kUint, false}, {5, kText, false},
	},
}

// ValidateWorkflowPayload decodes and structurally validates a Workflow frame payload
// for frame type ft. It returns the decoded map on success. On any structural fault it
// returns an error wrapping ErrWorkflowMalformed (§4–§8): the payload is not valid
// deterministic CBOR, is not a map, has a frame_kind (0) that contradicts ft, omits or
// mistypes the corr (1) a corr-bearing frame MUST carry, omits a required field, carries
// a field of the wrong CBOR major type, or carries an unknown negative / non-integer key.
// Unknown non-negative keys are accepted and left in the returned map (forward
// compatibility, §4.3). WORKFLOW_STEP_EVENT (0x0106) and WORKFLOW_COMPLETE (0x0107) carry
// NO corr (§4.2, §5.2), so the corr envelope check is skipped for them.
func ValidateWorkflowPayload(ft FrameType, payload []byte) (*cborMap, error) {
	schema, known := workflowSchemas[ft]
	if !known {
		return nil, fmt.Errorf("%w: 0x%04X is not a Workflow frame type", ErrWorkflowMalformed, uint16(ft))
	}
	v, err := cborDecodeTop(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWorkflowMalformed, err)
	}
	m, ok := v.(*cborMap)
	if !ok {
		return nil, fmt.Errorf("%w: payload is not a CBOR map", ErrWorkflowMalformed)
	}

	// Common envelope (§4.2): frame_kind (0) MUST equal ft.
	fk, ok := m.get(0)
	if !ok {
		return nil, fmt.Errorf("%w: missing frame_kind (0)", ErrWorkflowMalformed)
	}
	fkv, ok := fk.(uint64)
	if !ok {
		return nil, fmt.Errorf("%w: frame_kind (0) is not an unsigned int", ErrWorkflowMalformed)
	}
	if fkv != uint64(ft) {
		return nil, fmt.Errorf("%w: frame_kind 0x%04X contradicts frame type 0x%04X", ErrWorkflowMalformed, uint16(fkv), uint16(ft))
	}

	// corr (1): present and a non-empty byte string of 1–64 bytes on every *_REQ,
	// *_RESULT, and WORKFLOW_ERROR (§4.2, §5.1). Absent on the unsolicited task-scoped
	// notifications WORKFLOW_STEP_EVENT / WORKFLOW_COMPLETE, for which it is not part of
	// the envelope (a stray non-negative key is then tolerated by the §4.3 forward-compat
	// rule via checkFields).
	envelope := map[uint64]bool{0: true}
	if workflowFrameHasCorr(ft) {
		corr, ok := m.get(1)
		if !ok {
			return nil, fmt.Errorf("%w: missing corr (1)", ErrWorkflowMalformed)
		}
		cb, ok := corr.([]byte)
		if !ok || len(cb) < 1 || len(cb) > 64 {
			return nil, fmt.Errorf("%w: corr (1) must be a byte string of 1–64 bytes", ErrWorkflowMalformed)
		}
		envelope[1] = true
	}

	if err := checkFields(m, schema, envelope); err != nil {
		// checkFields reports via ErrMemoryMalformed (shared helper); re-wrap under
		// ErrWorkflowMalformed so callers get a consistent Workflow error surface (the
		// inner text is preserved for logs).
		return nil, fmt.Errorf("%w: %v", ErrWorkflowMalformed, err)
	}
	return m, nil
}
