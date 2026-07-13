package npamp

import (
	"errors"
	"fmt"
	"math"
	"sort"
)

// Minimal deterministic (canonical) CBOR codec for NPAMP-MEMORY operation bodies
// (spec/companion/81_memory_channel.md §4; RFC 8949 §4.2.1 core-deterministic).
//
// It implements exactly the subset the Memory bodies use — unsigned integers,
// negative integers, byte strings, text strings, arrays, maps, and the simple
// values false/true/null — all definite-length, shortest-form, with map keys in
// canonical (bytewise-of-encoded-key) order. It is deliberately NOT a general CBOR
// library: on decode it REJECTS anything outside this subset (indefinite lengths,
// non-shortest integer/length encodings, tags, floats, and out-of-order or
// duplicate map keys), which is precisely what a deterministic-encoding receiver
// MUST reject. Encoding always produces the one canonical form.
//
// Decoded value types: uint64 (major 0), int64 (major 1, negative), []byte
// (major 2), string (major 3), []any (major 4), *cborMap (major 5), and bool / nil
// (major 7 simple false/true/null). Encoding accepts the same Go types.

var (
	errCBORTrailing    = errors.New("npamp/cbor: trailing bytes after top-level item")
	errCBORTruncated   = errors.New("npamp/cbor: truncated input")
	errCBORNotShortest = errors.New("npamp/cbor: integer/length not in shortest form")
	errCBORIndefinite  = errors.New("npamp/cbor: indefinite-length item (non-deterministic)")
	errCBORUnsupported = errors.New("npamp/cbor: unsupported major type or simple value")
	errCBORMapOrder    = errors.New("npamp/cbor: map keys not in canonical ascending order (or duplicate)")
	errCBORBadType     = errors.New("npamp/cbor: unsupported Go type for encoding")
)

// cborMap is a CBOR map preserving canonical key order. Keys are themselves CBOR
// values (here always uint64/int64/string/[]byte); entries are kept sorted by the
// bytewise ordering of each key's canonical encoding, so iteration and re-encoding
// are deterministic.
type cborMap struct {
	entries []cborEntry
}

type cborEntry struct {
	keyEnc []byte // canonical encoding of the key, used for ordering + equality
	key    any
	val    any
}

// get returns the value for an unsigned-integer key (the form every NPAMP-MEMORY
// envelope/body key takes) and whether it was present. Maps here hold a handful of
// keys, so a direct scan over the canonically-ordered entries is used.
func (m *cborMap) get(key uint64) (any, bool) {
	ke := cborEncode(key)
	for _, e := range m.entries {
		if byteEqual(e.keyEnc, ke) {
			return e.val, true
		}
	}
	return nil, false
}

// keys returns every key in canonical order (used for forward-compat checks).
func (m *cborMap) keys() []any {
	out := make([]any, len(m.entries))
	for i, e := range m.entries {
		out[i] = e.key
	}
	return out
}

func byteEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// byteLess reports whether a sorts strictly before b in bytewise (shorter-prefix-
// first, then lexicographic) order — RFC 8949 §4.2.1 canonical map-key ordering.
func byteLess(a, b []byte) bool {
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// ---------- encoding ----------

// cborEncode returns the canonical CBOR encoding of v. Supported v types: uint64,
// int (>=0 encoded as uint), int64 (negative allowed), []byte, string, []any,
// *cborMap, map[uint64]any (encoded with canonically ordered keys), bool, nil.
func cborEncode(v any) []byte {
	switch t := v.(type) {
	case uint64:
		return encodeHead(0, t)
	case int:
		if t < 0 {
			return encodeHead(1, uint64(-1-int64(t)))
		}
		return encodeHead(0, uint64(t))
	case int64:
		if t < 0 {
			return encodeHead(1, uint64(-1-t))
		}
		return encodeHead(0, uint64(t))
	case []byte:
		out := encodeHead(2, uint64(len(t)))
		return append(out, t...)
	case string:
		out := encodeHead(3, uint64(len(t)))
		return append(out, t...)
	case []any:
		out := encodeHead(4, uint64(len(t)))
		for _, e := range t {
			out = append(out, cborEncode(e)...)
		}
		return out
	case *cborMap:
		out := encodeHead(5, uint64(len(t.entries)))
		for _, e := range t.entries { // entries are kept in canonical order
			out = append(out, e.keyEnc...)
			out = append(out, cborEncode(e.val)...)
		}
		return out
	case map[uint64]any:
		return cborEncode(newCBORMapU(t))
	case bool:
		if t {
			return []byte{0xf5} // true
		}
		return []byte{0xf4} // false
	case nil:
		return []byte{0xf6} // null
	default:
		panic(fmt.Errorf("%w: %T", errCBORBadType, v))
	}
}

// newCBORMapU builds a canonical cborMap from an unsigned-int-keyed Go map.
func newCBORMapU(m map[uint64]any) *cborMap {
	cm := &cborMap{entries: make([]cborEntry, 0, len(m))}
	for k, val := range m {
		cm.entries = append(cm.entries, cborEntry{keyEnc: cborEncode(k), key: k, val: val})
	}
	sort.Slice(cm.entries, func(i, j int) bool { return byteLess(cm.entries[i].keyEnc, cm.entries[j].keyEnc) })
	return cm
}

// encodeHead encodes a CBOR type header (major<<5 | argument) in shortest form.
func encodeHead(major byte, arg uint64) []byte {
	mb := major << 5
	switch {
	case arg < 24:
		return []byte{mb | byte(arg)}
	case arg < 1<<8:
		return []byte{mb | 24, byte(arg)}
	case arg < 1<<16:
		return []byte{mb | 25, byte(arg >> 8), byte(arg)}
	case arg < 1<<32:
		return []byte{mb | 26, byte(arg >> 24), byte(arg >> 16), byte(arg >> 8), byte(arg)}
	default:
		return []byte{mb | 27,
			byte(arg >> 56), byte(arg >> 48), byte(arg >> 40), byte(arg >> 32),
			byte(arg >> 24), byte(arg >> 16), byte(arg >> 8), byte(arg)}
	}
}

// ---------- decoding ----------

// cborDecodeTop decodes a single canonical CBOR item and requires that it consumes
// all of b (no trailing bytes) — the shape of a frame payload.
func cborDecodeTop(b []byte) (any, error) {
	v, n, err := cborDecode(b)
	if err != nil {
		return nil, err
	}
	if n != len(b) {
		return nil, errCBORTrailing
	}
	return v, nil
}

// cborDecode decodes one item from b, returning the value and the number of bytes
// consumed. It enforces the deterministic subset strictly.
func cborDecode(b []byte) (any, int, error) {
	if len(b) == 0 {
		return nil, 0, errCBORTruncated
	}
	ib := b[0]
	major := ib >> 5
	ai := ib & 0x1f
	if major == 7 {
		// Simple values and floats. Only false(20)/true(21)/null(22) are in the
		// deterministic subset; floats (25/26/27), other simple values, and the
		// break stop (31) are rejected. The integer-argument shortest-form check
		// does not apply to a float's payload, so major 7 is handled here.
		switch ai {
		case 20:
			return false, 1, nil
		case 21:
			return true, 1, nil
		case 22:
			return nil, 1, nil
		default:
			return nil, 0, errCBORUnsupported
		}
	}
	arg, n, err := decodeArg(ai, b)
	if err != nil {
		return nil, 0, err
	}
	switch major {
	case 0: // unsigned int
		return arg, n, nil
	case 1: // negative int: value = -1 - arg
		if arg > uint64(math.MaxInt64) {
			return nil, 0, errCBORUnsupported // out of int64 range; not used by Memory bodies
		}
		return int64(-1) - int64(arg), n, nil
	case 2, 3: // byte string / text string
		end := n + int(arg)
		if arg > uint64(len(b)) || end > len(b) || end < n {
			return nil, 0, errCBORTruncated
		}
		payload := b[n:end]
		if major == 2 {
			out := make([]byte, len(payload))
			copy(out, payload)
			return out, end, nil
		}
		return string(payload), end, nil
	case 4: // array
		out := make([]any, 0, arg)
		off := n
		for i := uint64(0); i < arg; i++ {
			el, en, err := cborDecode(b[off:])
			if err != nil {
				return nil, 0, err
			}
			out = append(out, el)
			off += en
		}
		return out, off, nil
	case 5: // map
		cm := &cborMap{entries: make([]cborEntry, 0, arg)}
		off := n
		var prevKeyEnc []byte
		for i := uint64(0); i < arg; i++ {
			keyStart := off
			key, kn, err := cborDecode(b[off:])
			if err != nil {
				return nil, 0, err
			}
			keyEnc := b[keyStart : off+kn]
			// Canonical order: each key MUST sort strictly after the previous one.
			if prevKeyEnc != nil && !byteLess(prevKeyEnc, keyEnc) {
				return nil, 0, errCBORMapOrder
			}
			prevKeyEnc = keyEnc
			off += kn
			val, vn, err := cborDecode(b[off:])
			if err != nil {
				return nil, 0, err
			}
			off += vn
			enc := make([]byte, len(keyEnc))
			copy(enc, keyEnc)
			cm.entries = append(cm.entries, cborEntry{keyEnc: enc, key: key, val: val})
		}
		return cm, off, nil
	default: // major 6 (tags); major 7 is handled above: unsupported
		return nil, 0, errCBORUnsupported
	}
}

// decodeArg reads the argument for an additional-information value ai from b[0],
// enforcing shortest-form (RFC 8949 §4.2.1) and rejecting indefinite lengths.
// Returns the argument and the total header length (including the leading byte).
func decodeArg(ai byte, b []byte) (uint64, int, error) {
	switch {
	case ai < 24:
		return uint64(ai), 1, nil
	case ai == 24:
		if len(b) < 2 {
			return 0, 0, errCBORTruncated
		}
		v := uint64(b[1])
		if v < 24 { // could have fit in the initial byte
			return 0, 0, errCBORNotShortest
		}
		return v, 2, nil
	case ai == 25:
		if len(b) < 3 {
			return 0, 0, errCBORTruncated
		}
		v := uint64(b[1])<<8 | uint64(b[2])
		if v < 1<<8 {
			return 0, 0, errCBORNotShortest
		}
		return v, 3, nil
	case ai == 26:
		if len(b) < 5 {
			return 0, 0, errCBORTruncated
		}
		v := uint64(b[1])<<24 | uint64(b[2])<<16 | uint64(b[3])<<8 | uint64(b[4])
		if v < 1<<16 {
			return 0, 0, errCBORNotShortest
		}
		return v, 5, nil
	case ai == 27:
		if len(b) < 9 {
			return 0, 0, errCBORTruncated
		}
		var v uint64
		for i := 1; i <= 8; i++ {
			v = v<<8 | uint64(b[i])
		}
		if v < 1<<32 {
			return 0, 0, errCBORNotShortest
		}
		return v, 9, nil
	case ai == 31:
		return 0, 0, errCBORIndefinite
	default: // 28,29,30 are reserved
		return 0, 0, errCBORUnsupported
	}
}
