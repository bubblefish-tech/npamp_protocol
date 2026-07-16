package npamp

import (
	"errors"
	"fmt"
)

// NPAMP-KNOWLEDGE operation-body validation — spec/companion/8b_knowledge_channel.md
// §4–§9. A Knowledge frame payload is a deterministic-CBOR map (memory_cbor.go, the
// shared codec). This file adds the per-frame field schemas and the structural
// validation the spec requires: the common envelope (§4.2 frame_kind + corr), the
// required/typed body fields (§6/§9), the forward-compatibility rule (§4.3: ignore
// unknown non-negative keys, reject unknown negative keys), and the §6.5 cross-field
// rule that a KNOWLEDGE_UPDATE MUST carry at least one of `results` or `removed`. It
// reuses the generic cborKind / memField / checkFields helpers defined in
// memory_bodies.go.
//
// Scope: this layer establishes that a body is structurally valid deterministic CBOR
// with the required fields present and correctly typed. Value-level and semantic
// clauses (correlation across streams §5, ranking-is-array-order §6.3, the
// subscription state machine and per-subscription credit §8) are the responder's to
// apply and are not decided here. The advisory FLOAT fields `min_score` (§6.1 key 7,
// §6.4 key 6) and per-result `score` (§6.2) lie outside the deterministic-CBOR
// integer/text/bytes/bool/array/map subset this rail's codec decodes; they are not
// listed in the schemas below, so a body that does carry a float is rejected at the
// CBOR-decode step (as a non-subset value), the same limitation NPAMP-STREAM and
// NPAMP-MEMORY carry for their own bodies.

// KnowledgeErrorCode is a §9 Knowledge error code carried in a KNOWLEDGE_ERROR (0x0109).
type KnowledgeErrorCode uint64

const (
	KnowErrMalformedRequest    KnowledgeErrorCode = 1
	KnowErrUnknownOperation    KnowledgeErrorCode = 2
	KnowErrPolicyDenied        KnowledgeErrorCode = 3
	KnowErrFilterUnsupported   KnowledgeErrorCode = 4
	KnowErrUnknownSubscription KnowledgeErrorCode = 5
	KnowErrSubscriptionRefused KnowledgeErrorCode = 6
	KnowErrResourceExhausted   KnowledgeErrorCode = 7
	KnowErrInternalError       KnowledgeErrorCode = 8
)

// ErrKnowledgeMalformed is returned by ValidateKnowledgePayload for any structural
// fault a responder reports as KNOWLEDGE_ERROR code malformed_request (§9, code 1):
// invalid deterministic CBOR, a payload that is not a map, a frame_kind that
// contradicts the frame type, a missing REQUIRED field, a wrong CBOR major type, an
// unknown negative key, a non-integer key, or a KNOWLEDGE_UPDATE carrying neither
// `results` nor `removed` (§6.5).
var ErrKnowledgeMalformed = errors.New("npamp/knowledge: malformed_request")

// knowledgeSchemas holds the body-field schema at keys 2+ per Knowledge frame type
// (the common-envelope keys 0/1 are validated separately). Transcribed from
// spec/companion/8b §6/§9. The advisory float fields min_score (QUERY_REQ key 7,
// SUBSCRIBE_REQ key 6) and knowledge_result score are intentionally absent (see the
// file comment): they are outside the codec's deterministic-CBOR subset.
var knowledgeSchemas = map[FrameType][]memField{
	FrameKnowledgeQueryReq: { // §6.1 — all body fields OPTIONAL (min_score float omitted)
		{2, kText, false}, {3, kText, false}, {4, kText, false}, {5, kText, false},
		{6, kUint, false}, {8, kText, false}, {9, kBytes, false},
	},
	FrameKnowledgeQueryResult: { // §6.2
		{2, kArray, true}, {3, kBool, true}, {4, kBytes, false}, {5, kUint, false},
		{6, kBool, false},
	},
	FrameKnowledgeQueryStreamData: {{2, kArray, true}},                    // §7
	FrameKnowledgeQueryStreamEnd:  {{2, kArray, false}, {3, kBool, true}}, // §7
	FrameKnowledgeSubscribeReq: { // §6.4 — credit(9) REQUIRED (min_score float omitted)
		{2, kText, false}, {3, kText, false}, {4, kText, false}, {5, kText, false},
		{7, kText, false}, {8, kBool, false}, {9, kUint, true},
	},
	FrameKnowledgeSubscribeAck: { // §6.4
		{2, kBytes, true}, {3, kUint, true}, {4, kBool, false},
	},
	FrameKnowledgeUpdate: { // §6.5 — results(4)/removed(5) both OPTIONAL here; the
		// "at least one present" rule is enforced separately (checkUpdateResultsOrRemoved).
		{2, kBytes, true}, {3, kUint, true}, {4, kArray, false}, {5, kArray, false},
	},
	FrameKnowledgeCredit: { // §6.6
		{2, kBytes, true}, {3, kUint, true}, {4, kUint, false},
	},
	FrameKnowledgeUnsubscribe: {{2, kBytes, true}}, // §6.7
	FrameKnowledgeError: { // §9
		{2, kUint, true}, {3, kText, true}, {4, kUint, false}, {5, kBytes, false},
	},
}

// ValidateKnowledgePayload decodes and structurally validates a Knowledge frame
// payload for frame type ft. It returns the decoded map on success. On any structural
// fault it returns an error wrapping ErrKnowledgeMalformed (spec §9 malformed_request):
// the payload is not valid deterministic CBOR, is not a map, has a frame_kind (0) that
// contradicts ft, omits or mistypes corr (1), omits a REQUIRED field, carries a field
// of the wrong CBOR major type, carries an unknown negative / non-integer key, or is a
// KNOWLEDGE_UPDATE carrying neither results (4) nor removed (5) (§6.5). Unknown
// non-negative keys are accepted and left in the returned map (forward compatibility,
// §4.3).
func ValidateKnowledgePayload(ft FrameType, payload []byte) (*cborMap, error) {
	schema, known := knowledgeSchemas[ft]
	if !known {
		return nil, fmt.Errorf("%w: 0x%04X is not a Knowledge operation frame type", ErrKnowledgeMalformed, uint16(ft))
	}
	v, err := cborDecodeTop(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKnowledgeMalformed, err)
	}
	m, ok := v.(*cborMap)
	if !ok {
		return nil, fmt.Errorf("%w: payload is not a CBOR map", ErrKnowledgeMalformed)
	}

	// Common envelope (§4.2): frame_kind (0) MUST equal ft; corr (1) MUST be a
	// non-empty byte string of 1–64 bytes (present on every Knowledge frame — every
	// frame is a *_REQ or echoes the corr of the request/subscription it serves, §5.1).
	fk, ok := m.get(0)
	if !ok {
		return nil, fmt.Errorf("%w: missing frame_kind (0)", ErrKnowledgeMalformed)
	}
	fkv, ok := fk.(uint64)
	if !ok {
		return nil, fmt.Errorf("%w: frame_kind (0) is not an unsigned int", ErrKnowledgeMalformed)
	}
	if fkv != uint64(ft) {
		return nil, fmt.Errorf("%w: frame_kind 0x%04X contradicts frame type 0x%04X", ErrKnowledgeMalformed, uint16(fkv), uint16(ft))
	}
	corr, ok := m.get(1)
	if !ok {
		return nil, fmt.Errorf("%w: missing corr (1)", ErrKnowledgeMalformed)
	}
	cb, ok := corr.([]byte)
	if !ok || len(cb) < 1 || len(cb) > 64 {
		return nil, fmt.Errorf("%w: corr (1) must be a byte string of 1–64 bytes", ErrKnowledgeMalformed)
	}

	if err := checkFields(m, schema, map[uint64]bool{0: true, 1: true}); err != nil {
		// checkFields reports via ErrMemoryMalformed (shared helper); re-wrap under
		// ErrKnowledgeMalformed so callers get a consistent Knowledge error surface
		// (the inner text is preserved for logs).
		return nil, fmt.Errorf("%w: %v", ErrKnowledgeMalformed, err)
	}

	// §6.5 cross-field rule: a KNOWLEDGE_UPDATE MUST carry at least one of results (4)
	// or removed (5); an update carrying neither is malformed. This is beyond the
	// per-field required/typed schema (both fields are individually OPTIONAL) and is
	// enforced here explicitly.
	if ft == FrameKnowledgeUpdate {
		_, hasResults := m.get(4)
		_, hasRemoved := m.get(5)
		if !hasResults && !hasRemoved {
			return nil, fmt.Errorf("%w: KNOWLEDGE_UPDATE carries neither results (4) nor removed (5) (§6.5)", ErrKnowledgeMalformed)
		}
	}
	return m, nil
}
