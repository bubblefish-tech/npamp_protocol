// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package keyformat

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// A minimal deterministic (core-deterministic, RFC 8949 section 4.2.1) CBOR
// codec for the fixed five-field key-record structure this package defines —
// the same determinism profile impl/go/memory_cbor.go applies to NPAMP-MEMORY
// bodies: definite-length only, shortest-form integers and lengths, and (for
// this package's fixed, ascending small-integer key set) canonically ordered
// map keys. It is deliberately NOT a general CBOR library — it encodes and
// decodes exactly the grammar keyRecord uses (an unsigned-integer-keyed map
// of unsigned integers, one text string, and one array of byte strings) and
// REJECTS everything else on decode: indefinite lengths, non-shortest
// integer/length encodings, wrong major types, unknown map keys, duplicate or
// out-of-order map keys, and trailing bytes after the top-level item.

// CBOR major types (RFC 8949 section 3).
const (
	cborMajorUint  = 0
	cborMajorBytes = 2
	cborMajorText  = 3
	cborMajorArray = 4
	cborMajorMap   = 5
)

var (
	errCBORTruncated     = errors.New("keyformat/cbor: truncated input")
	errCBORTrailing      = errors.New("keyformat/cbor: trailing bytes after top-level item")
	errCBORNotShortest   = errors.New("keyformat/cbor: integer or length is not in shortest form")
	errCBORIndefinite    = errors.New("keyformat/cbor: indefinite-length item (not core-deterministic)")
	errCBORWrongKeyOrder = errors.New("keyformat/cbor: map keys are not canonically ordered, or are duplicated")
)

// encodeUint appends the canonical (RFC 8949 section 4.2.1 shortest-form)
// CBOR encoding of the (major, value) pair.
func encodeUint(major byte, v uint64) []byte {
	switch {
	case v < 24:
		return []byte{major<<5 | byte(v)}
	case v <= 0xff:
		return []byte{major<<5 | 24, byte(v)}
	case v <= 0xffff:
		b := make([]byte, 3)
		b[0] = major<<5 | 25
		binary.BigEndian.PutUint16(b[1:], uint16(v))
		return b
	case v <= 0xffffffff:
		b := make([]byte, 5)
		b[0] = major<<5 | 26
		binary.BigEndian.PutUint32(b[1:], uint32(v))
		return b
	default:
		b := make([]byte, 9)
		b[0] = major<<5 | 27
		binary.BigEndian.PutUint64(b[1:], v)
		return b
	}
}

func encodeBytesItem(b []byte) []byte {
	out := encodeUint(cborMajorBytes, uint64(len(b)))
	return append(out, b...)
}

func encodeTextItem(s string) []byte {
	out := encodeUint(cborMajorText, uint64(len(s)))
	return append(out, s...)
}

// cborReader is a forward-only cursor over a CBOR byte string.
type cborReader struct {
	buf []byte
	pos int
}

// readHead consumes one CBOR item head of the required major type and
// returns its numeric argument (the length, for bytes/text/array/map; the
// value itself, for an unsigned integer), enforcing shortest-form encoding
// and rejecting indefinite length.
func (d *cborReader) readHead(wantMajor byte) (uint64, error) {
	if d.pos >= len(d.buf) {
		return 0, errCBORTruncated
	}
	ib := d.buf[d.pos]
	major := ib >> 5
	ai := ib & 0x1f
	if major != wantMajor {
		return 0, fmt.Errorf("keyformat/cbor: major type %d at offset %d, want %d", major, d.pos, wantMajor)
	}
	d.pos++
	switch {
	case ai < 24:
		return uint64(ai), nil
	case ai == 24:
		if d.pos+1 > len(d.buf) {
			return 0, errCBORTruncated
		}
		v := uint64(d.buf[d.pos])
		d.pos++
		if v < 24 {
			return 0, errCBORNotShortest
		}
		return v, nil
	case ai == 25:
		if d.pos+2 > len(d.buf) {
			return 0, errCBORTruncated
		}
		v := uint64(binary.BigEndian.Uint16(d.buf[d.pos:]))
		d.pos += 2
		if v <= 0xff {
			return 0, errCBORNotShortest
		}
		return v, nil
	case ai == 26:
		if d.pos+4 > len(d.buf) {
			return 0, errCBORTruncated
		}
		v := uint64(binary.BigEndian.Uint32(d.buf[d.pos:]))
		d.pos += 4
		if v <= 0xffff {
			return 0, errCBORNotShortest
		}
		return v, nil
	case ai == 27:
		if d.pos+8 > len(d.buf) {
			return 0, errCBORTruncated
		}
		v := binary.BigEndian.Uint64(d.buf[d.pos:])
		d.pos += 8
		if v <= 0xffffffff {
			return 0, errCBORNotShortest
		}
		return v, nil
	case ai == 31:
		return 0, errCBORIndefinite
	default:
		return 0, fmt.Errorf("keyformat/cbor: unsupported additional-info value %d", ai)
	}
}

func (d *cborReader) readUint() (uint64, error) { return d.readHead(cborMajorUint) }

func (d *cborReader) readBytes() ([]byte, error) {
	n, err := d.readHead(cborMajorBytes)
	if err != nil {
		return nil, err
	}
	if n > uint64(len(d.buf)-d.pos) {
		return nil, errCBORTruncated
	}
	out := make([]byte, n)
	copy(out, d.buf[d.pos:d.pos+int(n)])
	d.pos += int(n)
	return out, nil
}

func (d *cborReader) readText() (string, error) {
	n, err := d.readHead(cborMajorText)
	if err != nil {
		return "", err
	}
	if n > uint64(len(d.buf)-d.pos) {
		return "", errCBORTruncated
	}
	out := string(d.buf[d.pos : d.pos+int(n)])
	d.pos += int(n)
	return out, nil
}

func (d *cborReader) readArrayLen() (uint64, error) { return d.readHead(cborMajorArray) }
func (d *cborReader) readMapLen() (uint64, error)   { return d.readHead(cborMajorMap) }
