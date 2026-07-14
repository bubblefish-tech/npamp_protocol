package npamp

import "testing"

func TestIsMemoryFrame(t *testing.T) {
	cases := []struct {
		name string
		ft   FrameType
		want bool
	}{
		// Application-band operation frames (0x0100–0x010E): all true.
		{"create_req", FrameMemoryCreateReq, true},
		{"create_result", FrameMemoryCreateResult, true},
		{"read_req", FrameMemoryReadReq, true},
		{"retrieve_stream_data", FrameMemoryRetrieveStreamData, true},
		{"status_result", FrameMemoryStatusResult, true},
		{"error", FrameMemoryError, true},
		// Companion-extension eviction/revive (0x0035–0x0036): true.
		{"evict", FrameMemoryEvict, true},
		{"revive", FrameMemoryRevive, true},
		// Boundaries and non-Memory frames: false.
		{"system_ping", FramePing, false},                       // 0x0001, reserved system
		{"just_below_evict", FrameType(0x0034), false},          // Stream's reserved range
		{"between_revive_and_app", FrameType(0x0037), false},    // gap above 0x0036
		{"channel_specific_base_minus_1", FrameType(0x00FF), false},
		{"just_above_error", FrameType(0x010F), false},          // first value past 0x010E
		{"far_app", FrameType(0x0200), false},
		{"zero", FrameType(0x0000), false},
	}
	for _, c := range cases {
		if got := IsMemoryFrame(c.ft); got != c.want {
			t.Errorf("IsMemoryFrame(0x%04X) [%s] = %v, want %v", uint16(c.ft), c.name, got, c.want)
		}
	}
}

func TestIsMemoryRequest(t *testing.T) {
	req := []FrameType{
		FrameMemoryCreateReq, FrameMemoryReadReq, FrameMemoryUpdateReq,
		FrameMemoryDeleteReq, FrameMemoryRetrieveReq, FrameMemoryStatusReq,
		FrameMemoryEvict, FrameMemoryRevive,
	}
	for _, ft := range req {
		if !IsMemoryRequest(ft) {
			t.Errorf("IsMemoryRequest(0x%04X) = false, want true", uint16(ft))
		}
	}
	notReq := []FrameType{
		FrameMemoryCreateResult, FrameMemoryReadResult, FrameMemoryUpdateResult,
		FrameMemoryDeleteResult, FrameMemoryRetrieveResult, FrameMemoryRetrieveStreamData,
		FrameMemoryRetrieveStreamEnd, FrameMemoryStatusResult, FrameMemoryError,
		FramePing, FrameType(0x010F),
	}
	for _, ft := range notReq {
		if IsMemoryRequest(ft) {
			t.Errorf("IsMemoryRequest(0x%04X) = true, want false", uint16(ft))
		}
	}
	// Every request frame is a memory frame (cross-check the two predicates).
	for _, ft := range req {
		if !IsMemoryFrame(ft) {
			t.Errorf("request 0x%04X is not classified as a memory frame", uint16(ft))
		}
	}
}
