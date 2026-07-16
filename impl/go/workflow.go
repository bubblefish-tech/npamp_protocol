package npamp

// NPAMP-WORKFLOW companion frame types — spec/companion/8a_workflow_channel.md §3.
//
// The Workflow channel (0x0011, min-profile Standard, direction Bidirectional)
// carries native multi-agent orchestration and task-delegation operations: a task
// lifecycle (submit/status/cancel), asynchronous step events, a terminal completion
// event, and a single structured error frame. Frame bodies are deterministic-CBOR
// maps (§4.1). Like NPAMP-MEMORY, the common-envelope key 1 is corr — a per-exchange
// byte-string correlation token (1–64 B) — but UNLIKE both MEMORY and STREAM, the two
// unsolicited task-scoped notifications WORKFLOW_STEP_EVENT (0x0106) and
// WORKFLOW_COMPLETE (0x0107) carry NO corr; they are correlated to their task by the
// in-body task_id instead (§4.2, §5.2).
//
// The core specification reserves no companion-extension range for this channel, so
// all nine frame types lie in the per-channel application band (0x0100+); they carry
// their NPAMP-WORKFLOW meaning ONLY on the Workflow channel (draft-02 §4.6, per-channel
// frame-type namespace), so a value here may coincide numerically with a frame type of
// another channel.
const (
	FrameWorkflowSubmitReq    FrameType = 0x0100
	FrameWorkflowSubmitResult FrameType = 0x0101
	FrameWorkflowStatusReq    FrameType = 0x0102
	FrameWorkflowStatusResult FrameType = 0x0103
	FrameWorkflowCancelReq    FrameType = 0x0104
	FrameWorkflowCancelResult FrameType = 0x0105
	FrameWorkflowStepEvent    FrameType = 0x0106
	FrameWorkflowComplete     FrameType = 0x0107
	FrameWorkflowError        FrameType = 0x0108
)

// IsWorkflowFrame reports whether ft is an NPAMP-WORKFLOW frame type (0x0100–0x0108).
// It does not consider the channel; a caller has already established that the frame
// arrived on the Workflow channel (0x0011), on which these values carry their
// NPAMP-WORKFLOW meaning.
func IsWorkflowFrame(ft FrameType) bool {
	return ft >= FrameWorkflowSubmitReq && ft <= FrameWorkflowError
}

// IsWorkflowRequest reports whether ft is an NPAMP-WORKFLOW request frame — one that a
// delegator originates and that an executor answers with a matching *_RESULT or a
// WORKFLOW_ERROR (§3). The reply, event, and error frames return false.
func IsWorkflowRequest(ft FrameType) bool {
	switch ft {
	case FrameWorkflowSubmitReq, FrameWorkflowStatusReq, FrameWorkflowCancelReq:
		return true
	default:
		return false
	}
}

// workflowFrameHasCorr reports whether frame type ft carries the per-exchange corr (1)
// envelope field. Every *_REQ, *_RESULT, and WORKFLOW_ERROR does; the two unsolicited
// task-scoped notifications WORKFLOW_STEP_EVENT (0x0106) and WORKFLOW_COMPLETE (0x0107)
// do NOT — they are correlated to their task by the in-body task_id (§4.2, §5.2).
func workflowFrameHasCorr(ft FrameType) bool {
	return ft != FrameWorkflowStepEvent && ft != FrameWorkflowComplete
}
