package npamp

import (
	"bytes"
	"errors"
	"testing"
)

// reEncode decodes e and re-encodes the result; for canonical input the output must
// be byte-identical. This exercises both directions and the deterministic property.
func reEncode(t *testing.T, e []byte) {
	t.Helper()
	v, err := cborDecodeTop(e)
	if err != nil {
		t.Fatalf("decode(% x) failed: %v", e, err)
	}
	e2 := cborEncode(v)
	if !bytes.Equal(e, e2) {
		t.Fatalf("round-trip not canonical: in=% x out=% x", e, e2)
	}
}

func TestCBORRoundTripCanonical(t *testing.T) {
	vals := []any{
		uint64(0), uint64(1), uint64(23), uint64(24), uint64(255), uint64(256),
		uint64(65535), uint64(65536), uint64(1<<32 - 1), uint64(1 << 32),
		int64(-1), int64(-24), int64(-256),
		[]byte{}, []byte{0x00, 0xff, 0x10}, "", "hello", "😀 unicode",
		[]any{}, []any{uint64(1), "x", []byte{0x02}},
		map[uint64]any{0: uint64(0x0100), 1: []byte("corr"), 2: "content", 11: uint64(2)},
		true, false, nil,
		map[uint64]any{0: uint64(1), 5: map[uint64]any{7: "nested", 3: uint64(9)}},
	}
	for _, v := range vals {
		reEncode(t, cborEncode(v))
	}
}

func TestCBOREncodeShortestBoundaries(t *testing.T) {
	cases := []struct {
		v    uint64
		want []byte
	}{
		{0, []byte{0x00}},
		{23, []byte{0x17}},
		{24, []byte{0x18, 0x18}},
		{255, []byte{0x18, 0xff}},
		{256, []byte{0x19, 0x01, 0x00}},
		{65535, []byte{0x19, 0xff, 0xff}},
		{65536, []byte{0x1a, 0x00, 0x01, 0x00, 0x00}},
		{1 << 32, []byte{0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}},
	}
	for _, c := range cases {
		if got := cborEncode(c.v); !bytes.Equal(got, c.want) {
			t.Errorf("cborEncode(%d) = % x, want % x", c.v, got, c.want)
		}
	}
	// Negative-int major-1 shortest form: -1 -> 0x20, -24 -> 0x37, -25 -> 0x38 0x18.
	if got := cborEncode(int64(-1)); !bytes.Equal(got, []byte{0x20}) {
		t.Errorf("cborEncode(-1) = % x, want 20", got)
	}
	if got := cborEncode(int64(-25)); !bytes.Equal(got, []byte{0x38, 0x18}) {
		t.Errorf("cborEncode(-25) = % x, want 38 18", got)
	}
}

func TestCBORMapCanonicalOrder(t *testing.T) {
	// Keys supplied out of order must encode in ascending canonical order 0,1,2,11.
	enc := cborEncode(map[uint64]any{11: uint64(2), 1: []byte("c"), 0: uint64(0x0100), 2: "x"})
	v, err := cborDecodeTop(enc)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	m, ok := v.(*cborMap)
	if !ok {
		t.Fatalf("decoded type = %T, want *cborMap", v)
	}
	gotKeys := m.keys()
	wantOrder := []uint64{0, 1, 2, 11}
	if len(gotKeys) != len(wantOrder) {
		t.Fatalf("key count = %d, want %d", len(gotKeys), len(wantOrder))
	}
	for i, wk := range wantOrder {
		if gotKeys[i].(uint64) != wk {
			t.Errorf("key[%d] = %v, want %d (keys not canonically ordered)", i, gotKeys[i], wk)
		}
	}
	// get() resolves the right values.
	if fk, _ := m.get(0); fk.(uint64) != 0x0100 {
		t.Errorf("get(0) = %v, want 0x0100", fk)
	}
	if corr, _ := m.get(1); !bytes.Equal(corr.([]byte), []byte("c")) {
		t.Errorf("get(1) wrong")
	}
	if _, ok := m.get(9); ok {
		t.Errorf("get(9) present, want absent")
	}
}

func TestCBORDecodeRejectsNonDeterministic(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"non_shortest_uint_24_of_0", []byte{0x18, 0x00}, errCBORNotShortest},
		{"non_shortest_uint_24_of_23", []byte{0x18, 0x17}, errCBORNotShortest},
		{"non_shortest_uint_16_of_255", []byte{0x19, 0x00, 0xff}, errCBORNotShortest},
		{"non_shortest_uint_32_of_65535", []byte{0x1a, 0x00, 0x00, 0xff, 0xff}, errCBORNotShortest},
		{"indefinite_array", []byte{0x9f, 0xff}, errCBORIndefinite},
		{"indefinite_map", []byte{0xbf, 0xff}, errCBORIndefinite},
		{"map_keys_out_of_order", []byte{0xa2, 0x01, 0x00, 0x00, 0x00}, errCBORMapOrder},
		{"map_duplicate_keys", []byte{0xa2, 0x00, 0x00, 0x00, 0x00}, errCBORMapOrder},
		{"trailing_bytes", []byte{0x00, 0x00}, errCBORTrailing},
		{"tag", []byte{0xc0, 0x00}, errCBORUnsupported},
		{"float32", []byte{0xfa, 0x00, 0x00, 0x00, 0x00}, errCBORUnsupported},
		{"reserved_ai_28", []byte{0x1c}, errCBORUnsupported},
		{"truncated_uint8", []byte{0x18}, errCBORTruncated},
		{"truncated_bytestring", []byte{0x42, 0x00}, errCBORTruncated},
		{"empty", []byte{}, errCBORTruncated},
		// Huge array/map counts must be rejected before allocation (no panic / DoS).
		{"huge_array_count_2p63", []byte{0x9b, 0x80, 0, 0, 0, 0, 0, 0, 0}, errCBORTruncated},
		{"huge_array_count_max", []byte{0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, errCBORTruncated},
		{"huge_map_count_2p63", []byte{0xbb, 0x80, 0, 0, 0, 0, 0, 0, 0}, errCBORTruncated},
	}
	for _, c := range cases {
		_, err := cborDecodeTop(c.in)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: decode(% x) err = %v, want %v", c.name, c.in, err, c.want)
		}
	}
}

// A well-formed canonical map with in-order keys must decode cleanly (guards the
// order check against false positives).
func TestCBORDecodeAcceptsCanonicalMap(t *testing.T) {
	in := []byte{0xa2, 0x00, 0x00, 0x01, 0x18, 0x2a} // {0:0, 1:42}
	v, err := cborDecodeTop(in)
	if err != nil {
		t.Fatalf("decode of canonical map failed: %v", err)
	}
	m := v.(*cborMap)
	if fk, _ := m.get(0); fk.(uint64) != 0 {
		t.Errorf("get(0) wrong")
	}
	if val, _ := m.get(1); val.(uint64) != 42 {
		t.Errorf("get(1) = %v, want 42", val)
	}
}
