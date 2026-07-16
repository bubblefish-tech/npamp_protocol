package npamp

import (
	"errors"
	"fmt"
)

// NPAMP-IMMUNE operation-body validation — spec/companion/85_immune_channel.md
// §4–§8. An Immune frame payload is a deterministic-CBOR map (memory_cbor.go, the
// shared codec). This file adds the per-frame field schemas and the structural
// validation the spec requires: the common envelope (§4.2 frame_kind + corr), the
// required/typed body fields (§6, §8), the nested gossip-descriptor / gossip-item
// required-key enforcement (§6.4, §6.5), and the forward-compatibility rule (§4.3:
// ignore unknown non-negative keys, reject unknown negative keys). It reuses the
// generic cborKind / memField / checkFields / matchesKind helpers defined in
// memory_bodies.go.
//
// Value-level and cross-frame semantics (the severity fail-safe of §6.1, the
// disposition mapping of §6.3, the freshness/expiry/hop propagation rules of §7,
// and the policy_denied-vs-below_threshold distinction of §8.1) are the responder's
// to apply; this layer establishes that the body is structurally valid
// deterministic CBOR with the required fields present and correctly typed — the
// contract a receiver enforces before dispatch, whose violation is IMMUNE_ERROR
// malformed_request (§4, §8 code 1).

// AnomalyClass is the §6.1 kind-of-irregularity enumeration.
type AnomalyClass uint64

const (
	AnomalyOperational  AnomalyClass = 0x00
	AnomalySecurity     AnomalyClass = 0x01
	AnomalyIntegrity    AnomalyClass = 0x02
	AnomalyAvailability AnomalyClass = 0x03
	AnomalyOther        AnomalyClass = 0x04
)

// Severity is the §6.1 reporter-severity enumeration. Per the §6.1 fail-safe a
// missing or unrecognized severity MUST be treated as SeverityCritical.
type Severity uint64

const (
	SeverityInfo     Severity = 0x00
	SeverityLow      Severity = 0x01
	SeverityMedium   Severity = 0x02
	SeverityHigh     Severity = 0x03
	SeverityCritical Severity = 0x04
)

// Disposition is the §6.3 IMMUNE_REPORT_RESULT disposition enumeration.
type Disposition uint64

const (
	DispositionAcknowledged   Disposition = 0x00
	DispositionAccepted       Disposition = 0x01
	DispositionDuplicate      Disposition = 0x02
	DispositionBelowThreshold Disposition = 0x03
)

// ImmuneErrorCode is a §8 Immune error code carried in an IMMUNE_ERROR (0x0102).
type ImmuneErrorCode uint64

const (
	ImmuneErrMalformedRequest ImmuneErrorCode = 1
	ImmuneErrUnknownOperation ImmuneErrorCode = 2
	ImmuneErrPolicyDenied     ImmuneErrorCode = 3
	ImmuneErrRateLimited      ImmuneErrorCode = 4
	ImmuneErrNotFound         ImmuneErrorCode = 5
	ImmuneErrInternalError    ImmuneErrorCode = 6
)

// ErrImmuneMalformed is returned by ValidateImmunePayload for any structural fault a
// responder reports as IMMUNE_ERROR code malformed_request (§8, code 1): invalid
// deterministic CBOR, a payload that is not a map, a missing required field, a wrong
// CBOR major type, a frame_kind that contradicts the frame type, a corr that is not
// a non-empty 1–64-byte byte string, an unknown negative key, or a nested
// gossip-descriptor/item that omits a required key.
var ErrImmuneMalformed = errors.New("npamp/immune: malformed_request")

// immuneSchemas holds the body-field schema at keys 2+ per Immune frame type (the
// common-envelope keys 0/1 are validated separately). Transcribed from
// spec/companion/85 §6 and §8.
var immuneSchemas = map[FrameType][]memField{
	FrameImmuneReportReq: { // §6.2 IMMUNE_REPORT_REQ
		{2, kText, true}, {3, kUint, true}, {4, kUint, true}, {5, kText, false},
		{6, kText, false}, {7, kText, false}, {8, kBytes, false}, {9, kUint, false},
		{10, kText, false},
	},
	FrameImmuneReportResult: { // §6.2 IMMUNE_REPORT_RESULT
		{2, kUint, true}, {3, kText, false},
	},
	FrameImmuneError: { // §8 IMMUNE_ERROR
		{2, kUint, true}, {3, kText, true}, {4, kUint, false},
	},
	FrameImmuneGossipAdvertise: { // §6.4 IMMUNE_GOSSIP_ADVERTISE
		{2, kArray, true}, {3, kBool, false},
	},
	FrameImmuneGossipAck: { // §6.4 IMMUNE_GOSSIP_ACK
		{2, kArray, false}, {3, kArray, false}, {4, kUint, false},
	},
	FrameImmuneGossipPullReq: { // §6.5 IMMUNE_GOSSIP_PULL_REQ
		{2, kArray, true},
	},
	FrameImmuneGossipPullResult: { // §6.5 IMMUNE_GOSSIP_PULL_RESULT
		{2, kArray, true},
	},
	FrameImmuneGossipRetract: { // §6.6 IMMUNE_GOSSIP_RETRACT
		{2, kBytes, true}, {3, kUint, true}, {4, kUint, false},
	},
}

// gossipDescriptorSchema is the §6.4 gossip_descriptor projection, a nested map whose
// keys start at 0. Carried in the items[] array of an IMMUNE_GOSSIP_ADVERTISE.
var gossipDescriptorSchema = []memField{
	{0, kBytes, true}, {1, kUint, true}, {2, kUint, false}, {3, kUint, false},
	{4, kBytes, false}, {5, kText, false}, {6, kText, false}, {7, kUint, false},
	{8, kBytes, false}, {9, kBytes, false},
}

// gossipItemSchema is the §6.5 gossip_item projection, a nested map whose keys start
// at 0. Carried in the items[] array of an IMMUNE_GOSSIP_PULL_RESULT; unlike a
// descriptor its body(8) is REQUIRED.
var gossipItemSchema = []memField{
	{0, kBytes, true}, {1, kUint, true}, {2, kUint, false}, {3, kUint, false},
	{4, kBytes, false}, {5, kText, false}, {6, kText, false}, {7, kUint, false},
	{8, kBytes, true},
}

// ValidateImmunePayload decodes and structurally validates an Immune frame payload
// for frame type ft. It returns the decoded map on success. On any structural fault
// it returns an error wrapping ErrImmuneMalformed (spec §8 malformed_request): the
// payload is not valid deterministic CBOR, is not a map, has a frame_kind (0) that
// contradicts ft, omits or mistypes corr (1), omits a required field, carries a
// field of the wrong CBOR major type, carries a nested gossip-descriptor/item that
// omits a required key, or carries an unknown negative / non-integer key. Unknown
// non-negative keys are accepted and left in the returned map (forward
// compatibility, §4.3).
func ValidateImmunePayload(ft FrameType, payload []byte) (*cborMap, error) {
	schema, known := immuneSchemas[ft]
	if !known {
		return nil, fmt.Errorf("%w: 0x%04X is not an Immune operation frame type", ErrImmuneMalformed, uint16(ft))
	}
	v, err := cborDecodeTop(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrImmuneMalformed, err)
	}
	m, ok := v.(*cborMap)
	if !ok {
		return nil, fmt.Errorf("%w: payload is not a CBOR map", ErrImmuneMalformed)
	}

	// Common envelope (§4.2): frame_kind (0) MUST equal ft; corr (1) MUST be a
	// non-empty byte string of 1–64 bytes. corr is present on every Immune frame —
	// every frame is a request or a reply that echoes a request's corr (§5).
	fk, ok := m.get(0)
	if !ok {
		return nil, fmt.Errorf("%w: missing frame_kind (0)", ErrImmuneMalformed)
	}
	fkv, ok := fk.(uint64)
	if !ok {
		return nil, fmt.Errorf("%w: frame_kind (0) is not an unsigned int", ErrImmuneMalformed)
	}
	if fkv != uint64(ft) {
		return nil, fmt.Errorf("%w: frame_kind 0x%04X contradicts frame type 0x%04X", ErrImmuneMalformed, uint16(fkv), uint16(ft))
	}
	corr, ok := m.get(1)
	if !ok {
		return nil, fmt.Errorf("%w: missing corr (1)", ErrImmuneMalformed)
	}
	cb, ok := corr.([]byte)
	if !ok || len(cb) < 1 || len(cb) > 64 {
		return nil, fmt.Errorf("%w: corr (1) must be a byte string of 1–64 bytes", ErrImmuneMalformed)
	}

	if err := checkFields(m, schema, map[uint64]bool{0: true, 1: true}); err != nil {
		// checkFields reports via ErrMemoryMalformed (shared helper); re-wrap under
		// ErrImmuneMalformed so callers get a consistent Immune error surface (the
		// inner text is preserved for logs).
		return nil, fmt.Errorf("%w: %v", ErrImmuneMalformed, err)
	}

	// Nested descriptor/item validation (§6.4, §6.5): the items(2) array of an
	// ADVERTISE carries gossip_descriptor maps; that of a PULL_RESULT carries
	// gossip_item maps (whose body(8) is REQUIRED). Each element MUST be a map that
	// satisfies its nested schema, or the frame is malformed.
	switch ft {
	case FrameImmuneGossipAdvertise:
		if err := validateGossipArray(m, gossipDescriptorSchema); err != nil {
			return nil, err
		}
	case FrameImmuneGossipPullResult:
		if err := validateGossipArray(m, gossipItemSchema); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// validateGossipArray validates each element of the items(2) array of a gossip frame
// against nested (each element is a gossip_descriptor or gossip_item map with keys
// starting at 0, no envelope). A non-map element or one that fails the nested schema
// is malformed. An empty array is permitted (§6.4: "possibly empty"; §6.5: "possibly
// empty if none are still held").
func validateGossipArray(m *cborMap, nested []memField) error {
	itemsV, ok := m.get(2)
	if !ok {
		// Unreachable: items(2) is REQUIRED and already checked by the schema.
		return fmt.Errorf("%w: missing items (2)", ErrImmuneMalformed)
	}
	arr, ok := itemsV.([]any)
	if !ok {
		// Unreachable: the schema already validated items(2) as a CBOR array.
		return fmt.Errorf("%w: items (2) is not an array", ErrImmuneMalformed)
	}
	for i, el := range arr {
		em, ok := el.(*cborMap)
		if !ok {
			return fmt.Errorf("%w: items[%d] is not a CBOR map", ErrImmuneMalformed, i)
		}
		if err := checkFields(em, nested, map[uint64]bool{}); err != nil {
			return fmt.Errorf("%w: items[%d]: %v", ErrImmuneMalformed, i, err)
		}
	}
	return nil
}
