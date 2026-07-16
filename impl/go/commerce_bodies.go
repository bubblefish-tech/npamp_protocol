package npamp

import (
	"errors"
	"fmt"
)

// NPAMP-COMMERCE operation-body validation — spec/companion/88_commerce_channel.md §4–§8. A Commerce
// frame payload is a deterministic-CBOR map (memory_cbor.go, shared codec). This file adds the
// per-frame field schemas and the structural validation the spec requires: the common envelope
// (§4.2 frame_kind + byte-string corr), the required/typed body fields (§6, §8), the §4.3
// monetary-amount well-formedness, the §6.6 leg-party-membership rule, and the forward-compatibility
// rule (§4.4: ignore unknown non-negative keys, reject unknown negative keys). It reuses the generic
// cborKind / memField / checkFields helpers defined in memory_bodies.go.

// CommerceEffectValueTransfer is the §5.3 side-effect class 0x03 (value_transfer) — the most severe
// class, the fail-safe default for a state-affecting request with a missing/unknown effect. The
// less-severe classes reuse the shared EffectClass constants from memory_bodies.go (EffectReadOnly
// 0x00, EffectIdempotentWrite 0x01, EffectNonIdempotentWrite 0x02), whose numeric values §5.3 shares.
const CommerceEffectValueTransfer EffectClass = 0x03

// CommerceErrorCode is a §8 Commerce error code carried in a COMMERCE_ERROR (0x010E).
type CommerceErrorCode uint64

const (
	ComErrMalformedRequest CommerceErrorCode = 1
	ComErrUnknownOperation CommerceErrorCode = 2
	// ComErrPolicyDenied is a definitive refusal: the operation will not proceed (§8.1).
	ComErrPolicyDenied CommerceErrorCode = 3
	// ComErrApprovalRequired: the operation was escalated for human approval and was NOT executed
	// (§8.1). It is neither a success nor a definitive denial and MUST NOT be conflated with
	// ComErrPolicyDenied or reported as any *_RESULT; it carries approval_id (key 5).
	ComErrApprovalRequired CommerceErrorCode = 4
	ComErrNotFound         CommerceErrorCode = 5
	ComErrMandateInvalid   CommerceErrorCode = 6
	ComErrIntentConflict   CommerceErrorCode = 7
	ComErrInternalError    CommerceErrorCode = 8
)

// ErrCommerceMalformed is returned by ValidateCommercePayload for any structural fault a responder
// reports as COMMERCE_ERROR code malformed_request (§8, code 1): invalid deterministic CBOR, a
// payload that is not a map, a frame_kind that contradicts the frame type, a corr that is not a
// 1–64-byte byte string, a missing REQUIRED field, a wrong CBOR major type, an unknown negative /
// non-integer key, a malformed monetary amount (§4.3), or a settlement leg naming a party not in
// `parties` (§6.6).
var ErrCommerceMalformed = errors.New("npamp/commerce: malformed_request")

// commerceSchemas holds the body-field schema at keys 2+ per Commerce frame type (the common-envelope
// keys 0/1 are validated separately). Transcribed from spec/companion/88 §6 and §8.
var commerceSchemas = map[FrameType][]memField{
	FrameCommerceMandateCreateReq: { // §6.1
		{2, kText, true}, {3, kText, true}, {4, kMap, true}, {5, kText, false},
		{6, kText, false}, {7, kText, false}, {8, kMap, false}, {9, kText, false},
		{10, kBytes, false}, {11, kText, false}, {12, kText, false}, {13, kUint, true},
	},
	FrameCommerceMandateCreateResult: {{2, kText, true}, {3, kText, true}},                    // §6.1
	FrameCommerceMandateReadReq:      {{2, kText, true}, {3, kUint, true}},                    // §6.2
	FrameCommerceMandateReadResult:   {{2, kMap, true}},                                       // §6.2 (a mandate_record)
	FrameCommerceMandateRevokeReq:    {{2, kText, true}, {3, kText, false}, {4, kUint, true}}, // §6.3
	FrameCommerceMandateRevokeResult: {{2, kText, true}, {3, kText, true}},                    // §6.3
	FrameCommerceMandateStatusReq:    {{2, kText, true}, {3, kUint, true}},                    // §6.4
	FrameCommerceMandateStatusResult: {{2, kText, true}, {3, kText, true}, {4, kText, false}}, // §6.4
	FrameCommerceIntentProposeReq: { // §6.6
		{2, kArray, true}, {3, kArray, true}, {4, kText, false}, {5, kMap, false},
		{6, kText, false}, {7, kUint, true},
	},
	FrameCommerceIntentProposeResult: {{2, kText, true}, {3, kText, true}}, // §6.6
	FrameCommerceIntentRespondReq: { // §6.7
		{2, kText, true}, {3, kUint, true}, {4, kArray, false}, {5, kText, false}, {6, kUint, true},
	},
	FrameCommerceIntentRespondResult: {{2, kText, true}, {3, kText, true}}, // §6.7
	FrameCommerceIntentStatusReq:     {{2, kText, true}, {3, kUint, true}}, // §6.8
	FrameCommerceIntentStatusResult: { // §6.8
		{2, kText, true}, {3, kText, true}, {4, kArray, false}, {5, kArray, false},
	},
	FrameCommerceError: { // §8
		{2, kUint, true}, {3, kText, true}, {4, kUint, false}, {5, kText, false},
	},
}

// ValidateCommercePayload decodes and structurally validates a Commerce frame payload for frame type
// ft. It returns the decoded map on success. On any structural fault it returns an error wrapping
// ErrCommerceMalformed (spec §8 malformed_request): the payload is not valid deterministic CBOR, is
// not a map, has a frame_kind (0) that contradicts ft, omits or mistypes corr (1), omits a REQUIRED
// field, carries a field of the wrong CBOR major type, carries an unknown negative / non-integer key
// (§4.4), carries a malformed monetary amount (§4.3), or (on a settlement-intent proposal) names a
// leg party not present in `parties` (§6.6). Unknown non-negative keys are accepted and left in the
// returned map (forward compatibility, §4.4).
func ValidateCommercePayload(ft FrameType, payload []byte) (*cborMap, error) {
	schema, known := commerceSchemas[ft]
	if !known {
		return nil, fmt.Errorf("%w: 0x%04X is not a Commerce operation frame type", ErrCommerceMalformed, uint16(ft))
	}
	v, err := cborDecodeTop(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCommerceMalformed, err)
	}
	m, ok := v.(*cborMap)
	if !ok {
		return nil, fmt.Errorf("%w: payload is not a CBOR map", ErrCommerceMalformed)
	}

	// Common envelope (§4.2): frame_kind (0) MUST equal ft; corr (1) MUST be a non-empty byte string
	// of 1–64 bytes (present on every *_REQ and every frame that replies to one).
	fk, ok := m.get(0)
	if !ok {
		return nil, fmt.Errorf("%w: missing frame_kind (0)", ErrCommerceMalformed)
	}
	fkv, ok := fk.(uint64)
	if !ok {
		return nil, fmt.Errorf("%w: frame_kind (0) is not an unsigned int", ErrCommerceMalformed)
	}
	if fkv != uint64(ft) {
		return nil, fmt.Errorf("%w: frame_kind 0x%04X contradicts frame type 0x%04X", ErrCommerceMalformed, uint16(fkv), uint16(ft))
	}
	corr, ok := m.get(1)
	if !ok {
		return nil, fmt.Errorf("%w: missing corr (1)", ErrCommerceMalformed)
	}
	cb, ok := corr.([]byte)
	if !ok || len(cb) < 1 || len(cb) > 64 {
		return nil, fmt.Errorf("%w: corr (1) must be a byte string of 1–64 bytes", ErrCommerceMalformed)
	}

	if err := checkFields(m, schema, map[uint64]bool{0: true, 1: true}); err != nil {
		// checkFields reports via ErrMemoryMalformed (shared helper); re-wrap under ErrCommerceMalformed
		// so callers get a consistent Commerce error surface (the inner text is preserved for logs).
		return nil, fmt.Errorf("%w: %v", ErrCommerceMalformed, err)
	}

	// Nested-structure MUST-reject rules the Commerce spec adds beyond the top-level envelope:
	//   §4.3 — a monetary `amount` MUST carry units/scale/currency of the right types;
	//   §6.6 — every settlement leg's `from`/`to` MUST be a named party, and each leg's amount valid.
	if err := validateCommerceNested(ft, m); err != nil {
		return nil, err
	}
	return m, nil
}

// validateCommerceNested applies the §4.3 amount and §6.6 leg-party MUST-reject rules for the frame
// types that carry those nested structures. checkFields has already established that the relevant
// top-level keys are present and of the right CBOR container type, so the type assertions here hold.
func validateCommerceNested(ft FrameType, m *cborMap) error {
	switch ft {
	case FrameCommerceMandateCreateReq:
		// §6.1: amount (4) is REQUIRED and is a §4.3 monetary amount.
		if av, ok := m.get(4); ok {
			if err := validateCommerceAmount(av); err != nil {
				return err
			}
		}
	case FrameCommerceIntentProposeReq:
		// §6.6: gather the named parties, then require every leg's from/to to be one of them and
		// every leg's amount to be a well-formed §4.3 amount.
		parties, err := commerceParties(m)
		if err != nil {
			return err
		}
		lv, _ := m.get(3) // legs (3) REQUIRED kArray, already type-checked by checkFields
		legs, _ := lv.([]any)
		for _, lg := range legs {
			if err := validateCommerceLeg(lg, parties); err != nil {
				return err
			}
		}
	}
	return nil
}

// commerceParties reads the `parties` array (key 2) of a settlement-intent proposal into a set,
// rejecting a parties element that is not a text string (§6.6: "Array of Text string").
func commerceParties(m *cborMap) (map[string]bool, error) {
	pv, _ := m.get(2) // parties (2) REQUIRED kArray, already type-checked by checkFields
	arr, _ := pv.([]any)
	set := make(map[string]bool, len(arr))
	for _, p := range arr {
		s, ok := p.(string)
		if !ok {
			return nil, fmt.Errorf("%w: a `parties` element is not a text string (§6.6)", ErrCommerceMalformed)
		}
		set[s] = true
	}
	return set, nil
}

// validateCommerceLeg enforces the §6.6 leg shape { from (0): tstr, to (1): tstr, amount (2): amount }
// and the rule that from/to MUST be named parties. It also validates the leg's nested amount (§4.3)
// and applies the §4.4 forward-compat key rule to the leg map.
func validateCommerceLeg(v any, parties map[string]bool) error {
	m, ok := v.(*cborMap)
	if !ok {
		return fmt.Errorf("%w: a settlement leg is not a CBOR map (§6.6)", ErrCommerceMalformed)
	}
	frm, ok := m.get(0)
	if !ok {
		return fmt.Errorf("%w: a leg omits REQUIRED `from` (0) (§6.6)", ErrCommerceMalformed)
	}
	frmS, ok := frm.(string)
	if !ok {
		return fmt.Errorf("%w: a leg `from` (0) is not a text string (§6.6)", ErrCommerceMalformed)
	}
	to, ok := m.get(1)
	if !ok {
		return fmt.Errorf("%w: a leg omits REQUIRED `to` (1) (§6.6)", ErrCommerceMalformed)
	}
	toS, ok := to.(string)
	if !ok {
		return fmt.Errorf("%w: a leg `to` (1) is not a text string (§6.6)", ErrCommerceMalformed)
	}
	amt, ok := m.get(2)
	if !ok {
		return fmt.Errorf("%w: a leg omits REQUIRED `amount` (2) (§6.6)", ErrCommerceMalformed)
	}
	if err := validateCommerceAmount(amt); err != nil {
		return err
	}
	if !parties[frmS] {
		return fmt.Errorf("%w: leg `from` names a party not in `parties` (§6.6)", ErrCommerceMalformed)
	}
	if !parties[toS] {
		return fmt.Errorf("%w: leg `to` names a party not in `parties` (§6.6)", ErrCommerceMalformed)
	}
	return commerceForwardCompatKeys(m)
}

// validateCommerceAmount enforces the §4.3 monetary-amount structure: units (0) a signed integer
// (a uint64 or, when negative, an int64 from the codec), scale (1) an unsigned int, currency (2) a
// text string — all REQUIRED — and applies the §4.4 forward-compat key rule to the nested amount map.
func validateCommerceAmount(v any) error {
	m, ok := v.(*cborMap)
	if !ok {
		return fmt.Errorf("%w: `amount` is not a CBOR map (§4.3)", ErrCommerceMalformed)
	}
	units, ok := m.get(0)
	if !ok {
		return fmt.Errorf("%w: `amount` omits REQUIRED units (0) (§4.3)", ErrCommerceMalformed)
	}
	switch units.(type) {
	case uint64, int64: // a signed integer number of minor units
	default:
		return fmt.Errorf("%w: `amount` units (0) is not an integer (§4.3)", ErrCommerceMalformed)
	}
	scale, ok := m.get(1)
	if !ok {
		return fmt.Errorf("%w: `amount` omits REQUIRED scale (1) (§4.3)", ErrCommerceMalformed)
	}
	if _, ok := scale.(uint64); !ok {
		return fmt.Errorf("%w: `amount` scale (1) is not an unsigned int (§4.3)", ErrCommerceMalformed)
	}
	cur, ok := m.get(2)
	if !ok {
		return fmt.Errorf("%w: `amount` omits REQUIRED currency (2) (§4.3)", ErrCommerceMalformed)
	}
	if _, ok := cur.(string); !ok {
		return fmt.Errorf("%w: `amount` currency (2) is not a text string (§4.3)", ErrCommerceMalformed)
	}
	return commerceForwardCompatKeys(m)
}

// commerceForwardCompatKeys applies the §4.4 rule to a nested map (amount, leg): ignore an unknown
// non-negative integer key, reject an unknown negative or non-integer key.
func commerceForwardCompatKeys(m *cborMap) error {
	for _, k := range m.keys() {
		switch kk := k.(type) {
		case uint64:
			// known or unknown-non-negative: both accepted.
		case int64:
			if kk < 0 {
				return fmt.Errorf("%w: unknown negative key %d in a nested map (reserved, §4.4)", ErrCommerceMalformed, kk)
			}
		default:
			return fmt.Errorf("%w: non-integer key in a nested map", ErrCommerceMalformed)
		}
	}
	return nil
}
