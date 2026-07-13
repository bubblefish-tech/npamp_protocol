package npamp

import (
	"errors"
	"fmt"
)

// NPAMP-MEMORY operation-body validation — spec/companion/81_memory_channel.md
// §4–§8. A Memory frame payload is a deterministic-CBOR map (memory_cbor.go). This
// file adds the per-frame field schemas and the structural validation the spec
// requires: the common envelope, required/typed body fields, and the
// forward-compatibility rule (ignore unknown non-negative keys, reject unknown
// negative keys). Value-level constraints (for example that a READ carries
// effect=read_only, or the effect fail-safe of §5.3) are the responder's to apply;
// this layer establishes that the body is structurally valid deterministic CBOR
// with the required fields present and correctly typed.

// EffectClass is the §5.3 side-effect class carried by a state-mutating request.
type EffectClass uint64

const (
	EffectReadOnly           EffectClass = 0x00
	EffectIdempotentWrite    EffectClass = 0x01
	EffectNonIdempotentWrite EffectClass = 0x02
	EffectDestructive        EffectClass = 0x03
)

// MemoryErrorCode is a §8 Memory error code carried in a MEMORY_ERROR (0x010E).
type MemoryErrorCode uint64

const (
	MemErrMalformedRequest MemoryErrorCode = 1
	MemErrUnknownOperation MemoryErrorCode = 2
	MemErrPolicyDenied     MemoryErrorCode = 3
	// MemErrApprovalRequired: the operation was escalated for human approval and
	// was NOT executed (§8.1). It is neither a success nor a definitive denial and
	// MUST NOT be conflated with MemErrPolicyDenied or reported as any *_RESULT.
	MemErrApprovalRequired MemoryErrorCode = 4
	MemErrNotFound         MemoryErrorCode = 5
	MemErrInternalError    MemoryErrorCode = 6
)

// ErrMemoryMalformed is returned by ValidateMemoryPayload for any structural fault
// a responder reports as MEMORY_ERROR code malformed_request (§8, code 1): invalid
// deterministic CBOR, a missing required field, a wrong CBOR major type, an unknown
// negative key, or a non-integer key.
var ErrMemoryMalformed = errors.New("npamp/memory: malformed_request")

// cborKind is the expected CBOR type of a body field.
type cborKind uint8

const (
	kUint cborKind = iota
	kText
	kBytes
	kArray
	kMap
	kBool
)

// memField is one body field: its integer key, expected CBOR kind, and whether the
// spec marks it REQUIRED.
type memField struct {
	key      uint64
	kind     cborKind
	required bool
}

// Body-field schemas at keys 2+ per Memory frame type (the common envelope keys
// 0/1 are validated separately). Transcribed from spec/companion/81 §6–§8.
var memorySchemas = map[FrameType][]memField{
	FrameMemoryCreateReq: { // §6.1
		{2, kText, true}, {3, kText, false}, {4, kText, false}, {5, kText, false},
		{6, kText, false}, {7, kText, false}, {8, kText, false}, {9, kText, false},
		{10, kMap, false}, {11, kUint, true},
	},
	FrameMemoryCreateResult: {{2, kText, true}, {3, kText, true}}, // §6.1
	FrameMemoryReadReq:      {{2, kText, true}, {3, kUint, true}}, // §6.2
	FrameMemoryReadResult:   {{2, kMap, true}},                   // §6.2 (a memory_record)
	FrameMemoryUpdateReq: { // §6.3
		{2, kText, true}, {3, kText, false}, {4, kText, false}, {5, kText, false},
		{6, kText, false}, {7, kText, false}, {8, kText, false}, {9, kMap, false},
		{10, kUint, true},
	},
	FrameMemoryUpdateResult: {{2, kText, true}, {3, kText, true}}, // §6.3
	FrameMemoryDeleteReq:    {{2, kText, true}, {3, kUint, true}}, // §6.3
	FrameMemoryDeleteResult: {{2, kText, true}, {3, kText, true}}, // §6.3
	FrameMemoryRetrieveReq: { // §6.4
		{2, kText, false}, {3, kText, false}, {4, kText, false}, {5, kText, false},
		{6, kText, false}, {7, kUint, false}, {8, kText, false}, {9, kBytes, false},
		{10, kUint, true},
	},
	FrameMemoryRetrieveResult: { // §6.5
		{2, kArray, true}, {3, kBool, true}, {4, kBytes, false}, {5, kUint, false},
		{6, kBool, false},
	},
	FrameMemoryRetrieveStreamData: {{2, kArray, true}},                // §7
	FrameMemoryRetrieveStreamEnd:  {{2, kArray, false}, {3, kBool, true}}, // §7
	FrameMemoryStatusReq:          {},                                // §6.6 (envelope only)
	FrameMemoryStatusResult: { // §6.6
		{2, kText, true}, {3, kText, false}, {4, kUint, false}, {5, kMap, false},
	},
	FrameMemoryError: { // §8
		{2, kUint, true}, {3, kText, true}, {4, kUint, false}, {5, kText, false},
	},
	FrameMemoryEvict:  {{2, kText, true}, {3, kText, false}, {4, kUint, true}}, // §6.7
	FrameMemoryRevive: {{2, kText, true}, {3, kUint, true}},                    // §6.7
}

// memoryRecordSchema is the memory_record projection (§6.5), a nested map whose
// keys start at 0. Used to validate records carried in read/retrieve results.
var memoryRecordSchema = []memField{
	{0, kText, true}, {1, kText, true}, {2, kText, false}, {3, kText, false},
	{4, kText, false}, {5, kText, false}, {6, kText, false}, {7, kText, false},
	{8, kText, false}, {9, kText, false}, {10, kText, false}, {11, kText, false},
	{12, kText, false}, {13, kText, false}, {14, kText, false},
}

func matchesKind(v any, k cborKind) bool {
	switch k {
	case kUint:
		_, ok := v.(uint64)
		return ok
	case kText:
		_, ok := v.(string)
		return ok
	case kBytes:
		_, ok := v.([]byte)
		return ok
	case kArray:
		_, ok := v.([]any)
		return ok
	case kMap:
		_, ok := v.(*cborMap)
		return ok
	case kBool:
		_, ok := v.(bool)
		return ok
	default:
		return false
	}
}

// ValidateMemoryPayload decodes and structurally validates a Memory frame payload
// for frame type ft. It returns the decoded map on success. On any structural
// fault it returns an error wrapping ErrMemoryMalformed (spec §8 malformed_request):
// the payload is not valid deterministic CBOR, is not a map, has a frame_kind that
// contradicts ft, omits a required field, carries a field of the wrong CBOR major
// type, or carries an unknown negative / non-integer key. Unknown non-negative keys
// are accepted and left in the returned map (forward compatibility, §4.3).
func ValidateMemoryPayload(ft FrameType, payload []byte) (*cborMap, error) {
	schema, known := memorySchemas[ft]
	if !known {
		return nil, fmt.Errorf("%w: 0x%04X is not a Memory operation frame type", ErrMemoryMalformed, uint16(ft))
	}
	v, err := cborDecodeTop(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMemoryMalformed, err)
	}
	m, ok := v.(*cborMap)
	if !ok {
		return nil, fmt.Errorf("%w: payload is not a CBOR map", ErrMemoryMalformed)
	}

	// Common envelope (§4.2): frame_kind (0) MUST equal ft; corr (1) MUST be a
	// non-empty byte string of 1–64 bytes (present on every Memory frame — every
	// frame is a *_REQ, an evict/revive, or a reply to one).
	fk, ok := m.get(0)
	if !ok {
		return nil, fmt.Errorf("%w: missing frame_kind (0)", ErrMemoryMalformed)
	}
	fkv, ok := fk.(uint64)
	if !ok {
		return nil, fmt.Errorf("%w: frame_kind (0) is not an unsigned int", ErrMemoryMalformed)
	}
	if fkv != uint64(ft) {
		return nil, fmt.Errorf("%w: frame_kind 0x%04X contradicts frame type 0x%04X", ErrMemoryMalformed, uint16(fkv), uint16(ft))
	}
	corr, ok := m.get(1)
	if !ok {
		return nil, fmt.Errorf("%w: missing corr (1)", ErrMemoryMalformed)
	}
	cb, ok := corr.([]byte)
	if !ok || len(cb) < 1 || len(cb) > 64 {
		return nil, fmt.Errorf("%w: corr (1) must be a byte string of 1–64 bytes", ErrMemoryMalformed)
	}

	if err := checkFields(m, schema, map[uint64]bool{0: true, 1: true}); err != nil {
		return nil, err
	}
	return m, nil
}

// ValidateMemoryRecord validates a nested memory_record map (§6.5). Its keys start
// at 0; there is no envelope. Unknown non-negative keys are accepted.
func ValidateMemoryRecord(rec *cborMap) error {
	if rec == nil {
		return fmt.Errorf("%w: nil memory_record", ErrMemoryMalformed)
	}
	return checkFields(rec, memoryRecordSchema, map[uint64]bool{})
}

// checkFields enforces required/typed schema fields and the §4.3 forward-compat
// key rule on a decoded map. envelope names keys validated by the caller.
func checkFields(m *cborMap, schema []memField, envelope map[uint64]bool) error {
	known := make(map[uint64]bool, len(schema)+len(envelope))
	for k := range envelope {
		known[k] = true
	}
	for _, f := range schema {
		known[f.key] = true
		val, present := m.get(f.key)
		if !present {
			if f.required {
				return fmt.Errorf("%w: missing required field (key %d)", ErrMemoryMalformed, f.key)
			}
			continue
		}
		if !matchesKind(val, f.kind) {
			return fmt.Errorf("%w: field (key %d) has the wrong CBOR type", ErrMemoryMalformed, f.key)
		}
	}
	// Forward compatibility (§4.3): reject an unknown negative or non-integer key;
	// ignore an unknown non-negative integer key.
	for _, k := range m.keys() {
		switch kk := k.(type) {
		case uint64:
			// known or unknown-non-negative: both accepted.
		case int64:
			if kk < 0 {
				return fmt.Errorf("%w: unknown negative key %d (reserved, §4.3)", ErrMemoryMalformed, kk)
			}
		default:
			return fmt.Errorf("%w: non-integer map key", ErrMemoryMalformed)
		}
	}
	return nil
}
