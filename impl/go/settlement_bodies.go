package npamp

import (
	"errors"
	"fmt"
)

// NPAMP-SETTLEMENT operation-body validation — spec/companion/86_settlement_channel.md
// §4–§8. A Settlement frame payload is a deterministic-CBOR map (memory_cbor.go,
// shared codec). This file adds the per-frame field schemas and the structural
// validation the spec requires: the common envelope (§4.2 frame_kind + corr), the
// required/typed body fields (§6, §8), and the forward-compatibility rule (§4.3:
// ignore unknown non-negative keys, reject unknown negative keys). It reuses the
// generic cborKind / memField / checkFields helpers defined in memory_bodies.go.
//
// Like NPAMP-MEMORY (and unlike NPAMP-STREAM, whose envelope key 1 is an Unsigned
// int sub_stream_id), the Settlement envelope key 1 is corr — a byte string of
// 1–64 bytes carried on every *_REQ and on every frame that replies to one (§4.2,
// §5). Value-level policy (whether a settlement is permitted, denied, or escalated
// for human approval) is the responder's to apply (§1.2, §8); this layer establishes
// that the body is structurally valid deterministic CBOR with the required fields
// present and correctly typed.

// SettleEffectClass is the §5.3 side-effect class carried by a state-mutating
// Settlement request. It is the native-body analogue of a Bridge SafetyLabel,
// carried in-body because the Settlement channel owns its body (§2).
type SettleEffectClass uint64

const (
	SettleEffectReadOnly           SettleEffectClass = 0x00
	SettleEffectIdempotentWrite    SettleEffectClass = 0x01
	SettleEffectNonIdempotentWrite SettleEffectClass = 0x02
	SettleEffectDestructive        SettleEffectClass = 0x03
)

// SettlementErrorCode is a §8 Settlement error code carried in a SETTLE_ERROR
// (0x0104).
type SettlementErrorCode uint64

const (
	SettleErrMalformedRequest SettlementErrorCode = 1
	SettleErrUnknownOperation SettlementErrorCode = 2
	SettleErrPolicyDenied     SettlementErrorCode = 3
	// SettleErrApprovalRequired: the operation was escalated for human approval and
	// was NOT executed (§8.1). It is neither a success nor a definitive denial and
	// MUST NOT be conflated with SettleErrPolicyDenied or reported as any *_RESULT.
	// A SETTLE_ERROR carrying this code carries approval_id (key 5, §8).
	SettleErrApprovalRequired   SettlementErrorCode = 4
	SettleErrNotFound           SettlementErrorCode = 5
	SettleErrAlreadySettled     SettlementErrorCode = 6
	SettleErrCommitmentConflict SettlementErrorCode = 7
	SettleErrInternalError      SettlementErrorCode = 8
)

// ErrSettlementMalformed is returned by ValidateSettlementPayload for any structural
// fault a responder reports as SETTLE_ERROR code malformed_request (§8, code 1):
// invalid deterministic CBOR, a payload that is not a map, a missing required field,
// a wrong CBOR major type, a frame_kind that contradicts the frame type, a corr that
// is not a non-empty 1–64-byte byte string, or an unknown negative / non-integer key
// (§4).
var ErrSettlementMalformed = errors.New("npamp/settlement: malformed_request")

// settlementSchemas holds the body-field schema at keys 2+ per Settlement frame type
// (the common-envelope keys 0/1 are validated separately). Transcribed from
// spec/companion/86 §6 and §8.
var settlementSchemas = map[FrameType][]memField{
	FrameSettleIntentReq: { // §6.1 SETTLE_INTENT_REQ
		{2, kText, true}, {3, kText, false}, {4, kText, false}, {5, kText, false},
		{6, kText, false}, {7, kText, false}, {8, kUint, true},
	},
	FrameSettleIntentResult: { // §6.1 SETTLE_INTENT_RESULT
		{2, kText, true}, {3, kText, true}, {4, kText, false},
	},
	FrameReceiptReq: { // §6.2 RECEIPT_REQ
		{2, kText, true}, {3, kText, false}, {4, kUint, true},
	},
	FrameReceiptResult: { // §6.2 RECEIPT_RESULT (a settlement_receipt map)
		{2, kMap, true},
	},
	FrameSettleError: { // §8 SETTLE_ERROR
		{2, kUint, true}, {3, kText, true}, {4, kUint, false}, {5, kText, false},
	},
	FrameSettleBatchCommitReq: { // §6.3 SETTLE_BATCH_COMMIT_REQ
		{2, kText, true}, {3, kBytes, true}, {4, kText, false}, {5, kUint, false},
		{6, kText, false}, {7, kUint, true},
	},
	FrameSettleBatchCommitResult: { // §6.3 SETTLE_BATCH_COMMIT_RESULT
		{2, kText, true}, {3, kText, true}, {4, kText, false},
	},
}

// settlementReceiptSchema is the settlement_receipt projection (§6.2), a nested map
// whose keys start at 0. Used to validate a receipt carried in a RECEIPT_RESULT.
var settlementReceiptSchema = []memField{
	{0, kText, true}, {1, kText, true}, {2, kText, false}, {3, kText, false},
	{4, kText, false}, {5, kText, true}, {6, kText, false}, {7, kText, false},
	{8, kText, false}, {9, kText, false}, {10, kText, false},
}

// ValidateSettlementPayload decodes and structurally validates a Settlement frame
// payload for frame type ft. It returns the decoded map on success. On any structural
// fault it returns an error wrapping ErrSettlementMalformed (spec §8
// malformed_request): the payload is not valid deterministic CBOR, is not a map, has
// a frame_kind (0) that contradicts ft, omits or mistypes corr (1), omits a required
// field, carries a field of the wrong CBOR major type, or carries an unknown negative
// / non-integer key. Unknown non-negative keys are accepted and left in the returned
// map (forward compatibility, §4.3).
func ValidateSettlementPayload(ft FrameType, payload []byte) (*cborMap, error) {
	schema, known := settlementSchemas[ft]
	if !known {
		return nil, fmt.Errorf("%w: 0x%04X is not a Settlement operation frame type", ErrSettlementMalformed, uint16(ft))
	}
	v, err := cborDecodeTop(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSettlementMalformed, err)
	}
	m, ok := v.(*cborMap)
	if !ok {
		return nil, fmt.Errorf("%w: payload is not a CBOR map", ErrSettlementMalformed)
	}

	// Common envelope (§4.2): frame_kind (0) MUST equal ft; corr (1) MUST be a
	// non-empty byte string of 1–64 bytes (present on every Settlement frame — each
	// is a *_REQ or a reply to one, §5).
	fk, ok := m.get(0)
	if !ok {
		return nil, fmt.Errorf("%w: missing frame_kind (0)", ErrSettlementMalformed)
	}
	fkv, ok := fk.(uint64)
	if !ok {
		return nil, fmt.Errorf("%w: frame_kind (0) is not an unsigned int", ErrSettlementMalformed)
	}
	if fkv != uint64(ft) {
		return nil, fmt.Errorf("%w: frame_kind 0x%04X contradicts frame type 0x%04X", ErrSettlementMalformed, uint16(fkv), uint16(ft))
	}
	corr, ok := m.get(1)
	if !ok {
		return nil, fmt.Errorf("%w: missing corr (1)", ErrSettlementMalformed)
	}
	cb, ok := corr.([]byte)
	if !ok || len(cb) < 1 || len(cb) > 64 {
		return nil, fmt.Errorf("%w: corr (1) must be a byte string of 1–64 bytes", ErrSettlementMalformed)
	}

	if err := checkFields(m, schema, map[uint64]bool{0: true, 1: true}); err != nil {
		// checkFields reports via ErrMemoryMalformed (shared helper); re-wrap under
		// ErrSettlementMalformed so callers get a consistent Settlement error surface
		// (the inner text is preserved for logs).
		return nil, fmt.Errorf("%w: %v", ErrSettlementMalformed, err)
	}
	return m, nil
}

// ValidateSettlementReceipt validates a nested settlement_receipt map (§6.2). Its
// keys start at 0; there is no envelope. Required fields are receipt_ref (0),
// settlement_ref (1), and status (5); every other field is OPTIONAL. Unknown
// non-negative keys are accepted; an unknown negative key is rejected (§4.3).
func ValidateSettlementReceipt(rec *cborMap) error {
	if rec == nil {
		return fmt.Errorf("%w: nil settlement_receipt", ErrSettlementMalformed)
	}
	if err := checkFields(rec, settlementReceiptSchema, map[uint64]bool{}); err != nil {
		return fmt.Errorf("%w: %v", ErrSettlementMalformed, err)
	}
	return nil
}
