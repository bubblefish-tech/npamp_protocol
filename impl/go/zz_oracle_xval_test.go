package npamp

import (
	"encoding/hex"
	"testing"
)

// TestOracleCrossValidate proves NON-CIRCULARITY: the memory conformance-vector bodies produced by
// the independent Python oracle (test-vectors/gen/memory_oracle.py) are ACCEPTED by this Go impl's
// ValidateMemoryPayload when the oracle marks them valid/acceptable, and REJECTED when the oracle
// marks them MUST-reject. Two independent implementations agreeing is what makes the corpus vectors
// non-circular. (Throwaway dev cross-check; the permanent grading is the corpus + Go adapter.)
func TestOracleCrossValidate(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		accept bool
	}{
		{"valid_create", "a400190100014163026d72656d656d62657220746869730b02", true},
		{"fwd_compat_nonneg", "a500190100014163026d72656d656d62657220746869730b0218636c6675747572652d6669656c64", true},
		{"nonshortest_key", "a1180000", false},
		{"unknown_negative_key", "a5001901000141630261780b022009", false},
		{"missing_required_content", "a3001901000141630b02", false},
		{"wrong_major_type_content", "a40019010001416302090b02", false},
		{"frame_kind_mismatch", "a4001901020141630261780b02", false},
		{"not_a_map", "05", false},
	}
	for _, c := range cases {
		b, err := hex.DecodeString(c.body)
		if err != nil {
			t.Fatalf("%s: bad hex: %v", c.name, err)
		}
		_, verr := ValidateMemoryPayload(FrameMemoryCreateReq, b)
		if c.accept && verr != nil {
			t.Errorf("%s: oracle=accept but impl REJECTED: %v", c.name, verr)
		}
		if !c.accept && verr == nil {
			t.Errorf("%s: oracle=MUST-reject but impl ACCEPTED", c.name)
		}
	}
}
