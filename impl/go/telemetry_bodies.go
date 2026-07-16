package npamp

import (
	"errors"
	"fmt"
)

// NPAMP-TELEMETRY operation-body validation — spec/companion/87_telemetry_channel.md §4-§8. A Telemetry
// frame payload is a deterministic-CBOR map (memory_cbor.go, shared codec). This file adds the
// per-frame field schemas and the structural validation the spec requires: the common envelope
// (§4.1 frame_kind + conditional corr), the required/typed body fields (§5-§8), the nested
// MetricSample / Event / HealthReport schemas (§5.1-§5.3), the TELEMETRY_REPORT content rule (§5: at
// least one non-empty array among metrics/events/health), and the forward-compatibility rule (§4:
// ignore unknown non-negative integer keys, reject unknown negative or non-integer keys).
//
// It reuses the shared deterministic-CBOR codec (memory_cbor.go) but validates fields with its own
// type predicates rather than the memory_bodies.go cborKind table, because the Telemetry `value`
// field (§5.1) accepts either a CBOR unsigned int or a negative int (Int/Float), which the shared
// kUint/kText enum cannot express.

// ErrTelemetryMalformed is returned for any structural fault a receiver reports as TELEMETRY_ERROR
// code MalformedPayload (§8, code 1) or KindMismatch (§8, code 2): invalid deterministic CBOR, a
// payload that is not a map, a frame_kind that contradicts the frame type, a missing REQUIRED key, a
// wrong CBOR major type, a corr present/absent in violation of §4.1/§5, a TELEMETRY_REPORT with no
// content, or an unknown negative / non-integer key.
var ErrTelemetryMalformed = errors.New("npamp/telemetry: malformed_payload")

// telField is one body field: its integer key, a predicate that reports whether a decoded value has
// the CBOR type the field requires, and whether the spec marks it REQUIRED.
type telField struct {
	key      uint64
	ok       func(any) bool
	required bool
}

func telIsUint(v any) bool  { _, ok := v.(uint64); return ok }
func telIsText(v any) bool  { _, ok := v.(string); return ok }
func telIsBytes(v any) bool { _, ok := v.([]byte); return ok }
func telIsArray(v any) bool { _, ok := v.([]any); return ok }
func telIsMap(v any) bool   { _, ok := v.(*cborMap); return ok }

// telIsNumber accepts a CBOR unsigned int (uint64) or a negative int (int64) — the two numeric shapes
// the shared deterministic codec produces for a MetricSample `value` (§5.1: Int/Float; floats are
// outside the deterministic subset the shared codec admits, so an integer measurement is required).
func telIsNumber(v any) bool {
	switch v.(type) {
	case uint64, int64:
		return true
	default:
		return false
	}
}

// telemetrySchemas holds the body-field schema at keys 2+ for the frame types whose envelope carries a
// REQUIRED corr (every Telemetry frame except TELEMETRY_REPORT, which is validated separately by
// validateTelemetryReport because its corr — and therefore its sub_id — is conditional). Transcribed
// from spec/companion/87 §6.1 (SUBSCRIBE), §6.2 (SUB_ACK), §6.3 (UNSUBSCRIBE), §7 (CREDIT), §8 (ERROR).
var telemetrySchemas = map[FrameType][]telField{
	FrameTelemetrySubscribe: { // §6.1
		{2, telIsArray, false}, {3, telIsArray, false}, {4, telIsArray, false},
		{5, telIsUint, false}, {6, telIsUint, false}, {7, telIsUint, true},
	},
	FrameTelemetrySubAck: { // §6.2
		{2, telIsBytes, true}, {3, telIsUint, true}, {4, telIsArray, false},
	},
	FrameTelemetryUnsubscribe: { // §6.3
		{2, telIsBytes, true},
	},
	FrameTelemetryCredit: { // §7
		{2, telIsBytes, true}, {3, telIsUint, true}, {4, telIsUint, false},
	},
	FrameTelemetryError: { // §8
		{2, telIsUint, true}, {3, telIsText, false}, {4, telIsBytes, false},
	},
}

// Nested item schemas (§5.1-§5.3). Keys start at 0; there is no envelope. These validate elements of
// the metrics / events / health arrays carried in a TELEMETRY_REPORT.
var (
	metricSchema = []telField{ // §5.1
		{0, telIsText, true}, {1, telIsUint, true}, {2, telIsUint, true}, {3, telIsNumber, true},
		{4, telIsText, false}, {5, telIsMap, false}, {6, telIsUint, false},
	}
	eventSchema = []telField{ // §5.2
		{0, telIsText, true}, {1, telIsUint, true}, {2, telIsUint, false},
		{3, telIsMap, false}, {4, telIsText, false}, {5, telIsUint, false},
	}
	healthSchema = []telField{ // §5.3
		{0, telIsText, true}, {1, telIsUint, true}, {2, telIsUint, true},
		{3, telIsText, false}, {4, telIsMap, false},
	}
)

// ValidateTelemetryPayload decodes and structurally validates a Telemetry frame payload for frame type
// ft. It returns the decoded map on success. On any structural fault it returns an error wrapping
// ErrTelemetryMalformed (§4-§8): the payload is not valid deterministic CBOR, is not a map, has a
// frame_kind (0) that contradicts ft, violates the §4.1 corr rule, omits a REQUIRED field, carries a
// field of the wrong CBOR major type, is a TELEMETRY_REPORT with no content (§5), or carries an
// unknown negative / non-integer key. Unknown non-negative integer keys are accepted and left in the
// returned map (forward compatibility, §4).
func ValidateTelemetryPayload(ft FrameType, payload []byte) (*cborMap, error) {
	if !IsTelemetryFrame(ft) {
		return nil, fmt.Errorf("%w: 0x%04X is not a Telemetry operation frame type", ErrTelemetryMalformed, uint16(ft))
	}
	v, err := cborDecodeTop(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTelemetryMalformed, err)
	}
	m, ok := v.(*cborMap)
	if !ok {
		return nil, fmt.Errorf("%w: payload is not a CBOR map", ErrTelemetryMalformed)
	}

	// Common envelope (§4.1): frame_kind (0) MUST equal ft (a contradiction is KindMismatch, §8 code 2).
	fk, ok := m.get(0)
	if !ok {
		return nil, fmt.Errorf("%w: missing frame_kind (0)", ErrTelemetryMalformed)
	}
	fkv, ok := fk.(uint64)
	if !ok {
		return nil, fmt.Errorf("%w: frame_kind (0) is not an unsigned int", ErrTelemetryMalformed)
	}
	if fkv != uint64(ft) {
		return nil, fmt.Errorf("%w: frame_kind 0x%04X contradicts frame type 0x%04X", ErrTelemetryMalformed, uint16(fkv), uint16(ft))
	}

	if ft == FrameTelemetryReport {
		return validateTelemetryReport(m)
	}

	// Every non-REPORT Telemetry frame carries a REQUIRED, non-empty corr (1) byte string of 1-64 B
	// (§4.1); it is echoed verbatim and matches a reply to its subscription.
	if err := checkTelemetryCorr(m, true); err != nil {
		return nil, err
	}
	if err := checkTelemetryFields(m, telemetrySchemas[ft]); err != nil {
		return nil, err
	}
	return m, nil
}

// validateTelemetryReport validates a TELEMETRY_REPORT (0x0100) body (§5). Its corr (1) is CONDITIONAL:
// present if and only if the batch answers a subscription, in which case sub_id (2) MUST also be
// present; a standalone (unsolicited) report MUST omit both. batch_seq (3) is REQUIRED. The report MUST
// carry content: at least one of metrics (4), events (5), or health (6) MUST be present and non-empty,
// and every element of a present array is validated against its nested schema (§5.1-§5.3).
func validateTelemetryReport(m *cborMap) (*cborMap, error) {
	corr, hasCorr := m.get(1)
	_, hasSubID := m.get(2)
	if hasCorr {
		cb, ok := corr.([]byte)
		if !ok || len(cb) < 1 || len(cb) > 64 {
			return nil, fmt.Errorf("%w: corr (1) must be a byte string of 1–64 bytes", ErrTelemetryMalformed)
		}
		if !hasSubID {
			return nil, fmt.Errorf("%w: subscribed report carries corr (1) but omits sub_id (2)", ErrTelemetryMalformed)
		}
		if sub, _ := m.get(2); !telIsBytes(sub) {
			return nil, fmt.Errorf("%w: sub_id (2) must be a byte string", ErrTelemetryMalformed)
		}
	} else if hasSubID {
		return nil, fmt.Errorf("%w: standalone report carries sub_id (2) without corr (1)", ErrTelemetryMalformed)
	}

	// batch_seq (3) REQUIRED unsigned int (§5).
	bs, ok := m.get(3)
	if !ok {
		return nil, fmt.Errorf("%w: missing required batch_seq (3)", ErrTelemetryMalformed)
	}
	if !telIsUint(bs) {
		return nil, fmt.Errorf("%w: batch_seq (3) is not an unsigned int", ErrTelemetryMalformed)
	}

	// Content arrays (§5): metrics (4), events (5), health (6). At least one MUST be present and
	// non-empty; each present array MUST be a CBOR array of well-formed items.
	nonEmpty := 0
	for _, c := range []struct {
		key    uint64
		schema []telField
		what   string
	}{
		{4, metricSchema, "metric"},
		{5, eventSchema, "event"},
		{6, healthSchema, "health"},
	} {
		val, present := m.get(c.key)
		if !present {
			continue
		}
		arr, ok := val.([]any)
		if !ok {
			return nil, fmt.Errorf("%w: %s array (key %d) is not a CBOR array", ErrTelemetryMalformed, c.what, c.key)
		}
		if len(arr) > 0 {
			nonEmpty++
		}
		for _, el := range arr {
			em, ok := el.(*cborMap)
			if !ok {
				return nil, fmt.Errorf("%w: %s array element is not a CBOR map", ErrTelemetryMalformed, c.what)
			}
			if err := checkTelemetryFields(em, c.schema); err != nil {
				return nil, err
			}
		}
	}
	if nonEmpty == 0 {
		return nil, fmt.Errorf("%w: TELEMETRY_REPORT carries no metrics, events, or health (§5)", ErrTelemetryMalformed)
	}

	// Forward-compat key scan over the top-level report map (envelope keys included).
	if err := telemetryForwardCompat(m); err != nil {
		return nil, err
	}
	return m, nil
}

// checkTelemetryCorr enforces the common-envelope corr (1) rule for a frame whose corr is REQUIRED: it
// MUST be present and a byte string of 1-64 bytes (§4.1).
func checkTelemetryCorr(m *cborMap, required bool) error {
	corr, ok := m.get(1)
	if !ok {
		if required {
			return fmt.Errorf("%w: missing corr (1)", ErrTelemetryMalformed)
		}
		return nil
	}
	cb, ok := corr.([]byte)
	if !ok || len(cb) < 1 || len(cb) > 64 {
		return fmt.Errorf("%w: corr (1) must be a byte string of 1–64 bytes", ErrTelemetryMalformed)
	}
	return nil
}

// checkTelemetryFields enforces a schema's REQUIRED/typed fields and then the §4 forward-compatibility
// key rule (accept unknown non-negative integer keys; reject unknown negative or non-integer keys) on
// a decoded map. It does not itself validate the envelope keys 0/1 — the caller does.
func checkTelemetryFields(m *cborMap, schema []telField) error {
	for _, f := range schema {
		val, present := m.get(f.key)
		if !present {
			if f.required {
				return fmt.Errorf("%w: missing required field (key %d)", ErrTelemetryMalformed, f.key)
			}
			continue
		}
		if !f.ok(val) {
			return fmt.Errorf("%w: field (key %d) has the wrong CBOR type", ErrTelemetryMalformed, f.key)
		}
	}
	return telemetryForwardCompat(m)
}

// telemetryForwardCompat enforces §4: an unknown non-negative integer key is accepted (later revisions
// MAY add fields); an unknown NEGATIVE integer key, or a non-integer key, MUST be rejected.
func telemetryForwardCompat(m *cborMap) error {
	for _, k := range m.keys() {
		switch kk := k.(type) {
		case uint64:
			// known or unknown-non-negative: both accepted.
		case int64:
			if kk < 0 {
				return fmt.Errorf("%w: unknown negative key %d (reserved, §4)", ErrTelemetryMalformed, kk)
			}
		default:
			return fmt.Errorf("%w: non-integer map key", ErrTelemetryMalformed)
		}
	}
	return nil
}
