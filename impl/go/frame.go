package npamp

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
)

// HeaderSize is the fixed N-PAMP frame header size in octets (draft-00 section 4.2).
const HeaderSize = 36

// MaxFrameSize caps a single frame (header + payload) at 16 MiB so a hostile Payload
// Length field cannot force an unbounded allocation. The Payload Length field is a
// uint32 and can express up to ~4 GiB; a receiver MUST reject any frame whose total
// size exceeds MaxFrameSize. This is the single source of truth for the cap: the base
// parser (ReadFrame) enforces it and the SDK references it, so the two never diverge
// (draft § Numeric Bounds).
const MaxFrameSize = 16 << 20 // 16 MiB

// ProtocolVersion is the WIRE-FORMAT version carried in the high nibble of octet 4:
// it identifies the frame layout, not the crypto generation. It is an invariant of the
// protocol -- a receiver MUST reject any frame whose Ver nibble != 0x2. The crypto
// generation is carried out of band by the negotiated ALPN identifier (currently
// "n-pamp/3"), or by explicit configuration where frames are exchanged without TLS;
// a raw frame is not generation-self-describing (ADR 0014).
const ProtocolVersion uint8 = 0x2

// Magic is the 4-octet frame magic, ASCII "NPAM".
var Magic = [4]byte{0x4E, 0x50, 0x41, 0x4D}

// Frame flags occupy the low nibble of header octet 4. Bits 0 (0x01) and 3 (0x08)
// are reserved in this revision -- the never-specified URG/FRAG flags (T15.2); a
// receiver MUST reject a frame that sets either (reservedFlagMask, fail-closed),
// and a future assignment rides a new ALPN generation. Bits 1 (ENC) and 2 (COMP)
// remain defined.
const (
	FlagENC  uint8 = 0x02 // payload is AEAD-encrypted
	FlagCOMP uint8 = 0x04 // payload is compressed
)

// reservedFlagMask is the set of low-nibble flag bits reserved for a future
// revision (bit 0, formerly URG; bit 3, formerly FRAG). UnmarshalBinary rejects
// any frame that sets one.
const reservedFlagMask uint8 = 0x09

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

var (
	ErrShortHeader     = errors.New("npamp: buffer shorter than 36-octet header")
	ErrBadMagic        = errors.New("npamp: bad magic (want NPAM)")
	ErrBadVersion      = errors.New("npamp: unsupported wire version")
	ErrBadCRC          = errors.New("npamp: header CRC32C mismatch")
	ErrReservedNonzero = errors.New("npamp: reserved octets are non-zero")
	ErrReservedFlag    = errors.New("npamp: a reserved frame-flag bit is set")
	ErrLengthMismatch  = errors.New("npamp: payload length does not match buffer")
	ErrIncompleteFrame = errors.New("npamp: buffer holds a valid header but not the full frame yet")
	ErrFrameTooLarge   = errors.New("npamp: frame size exceeds MaxFrameSize")
)

// Frame holds the parsed fixed-header fields plus the (already AEAD-protected, if
// applicable) payload. Extension TLVs and the AEAD tag are handled by the TLV and
// record layers; Payload is carried verbatim.
type Frame struct {
	Version uint8
	Flags   uint8
	Type    uint16
	Channel uint16
	Seq     uint64
	Payload []byte
}

// HeaderPrefix returns the 21 octets (0..20) that the CRC32C covers and that the
// record layer uses as AEAD associated data. dst must be at least 21 octets; the
// payloadLen is the byte count that will follow the 36-octet header.
func (f *Frame) HeaderPrefix(dst []byte, payloadLen uint32) {
	ver := f.Version
	if ver == 0 {
		ver = ProtocolVersion
	}
	copy(dst[0:4], Magic[:])
	dst[4] = (ver << 4) | (f.Flags & 0x0F)
	binary.BigEndian.PutUint16(dst[5:7], f.Type)
	binary.BigEndian.PutUint16(dst[7:9], f.Channel)
	binary.BigEndian.PutUint64(dst[9:17], f.Seq)
	binary.BigEndian.PutUint32(dst[17:21], payloadLen)
}

func (f *Frame) marshalHeaderInto(dst []byte, payloadLen uint32) {
	f.HeaderPrefix(dst, payloadLen)
	crc := crc32.Checksum(dst[0:21], castagnoli)
	binary.BigEndian.PutUint32(dst[21:25], crc)
	for i := 25; i < HeaderSize; i++ {
		dst[i] = 0
	}
}

// MarshalBinary encodes the frame as header || payload. If Version is zero it is
// set to ProtocolVersion so a zero-value Frame marshals to a valid wire frame.
func (f *Frame) MarshalBinary() ([]byte, error) {
	if f.Version == 0 {
		f.Version = ProtocolVersion
	}
	out := make([]byte, HeaderSize+len(f.Payload))
	f.marshalHeaderInto(out, uint32(len(f.Payload)))
	copy(out[HeaderSize:], f.Payload)
	return out, nil
}

// UnmarshalBinary parses buf into f. Per draft-00 section 4.2 the CRC32C is
// validated BEFORE any other header field is processed; the reserved octets MUST
// be zero; and the version MUST be the supported wire major version.
func (f *Frame) UnmarshalBinary(buf []byte) error {
	if len(buf) < HeaderSize {
		return ErrShortHeader
	}
	got := binary.BigEndian.Uint32(buf[21:25])
	want := crc32.Checksum(buf[0:21], castagnoli)
	if got != want {
		return ErrBadCRC
	}
	if buf[0] != Magic[0] || buf[1] != Magic[1] || buf[2] != Magic[2] || buf[3] != Magic[3] {
		return ErrBadMagic
	}
	ver := buf[4] >> 4
	if ver != ProtocolVersion {
		return ErrBadVersion
	}
	if buf[4]&reservedFlagMask != 0 {
		return ErrReservedFlag
	}
	for i := 25; i < HeaderSize; i++ {
		if buf[i] != 0 {
			return ErrReservedNonzero
		}
	}
	payloadLen := binary.BigEndian.Uint32(buf[17:21])
	if int(payloadLen) != len(buf)-HeaderSize {
		return ErrLengthMismatch
	}
	f.Version = ver
	f.Flags = buf[4] & 0x0F
	f.Type = binary.BigEndian.Uint16(buf[5:7])
	f.Channel = binary.BigEndian.Uint16(buf[7:9])
	f.Seq = binary.BigEndian.Uint64(buf[9:17])
	f.Payload = append([]byte(nil), buf[HeaderSize:]...)
	return nil
}

// ReadFrame parses the frame at the front of buf, which MAY be followed by more
// frames: a stream transport (TCP/TLS) delivers a byte stream with no message
// boundaries, so a reader locates each frame from the fixed 36-octet header and
// the Payload Length field (octets 17..20). The frame occupies exactly
// HeaderSize + PayloadLength octets; ReadFrame returns the parsed frame and the
// octet count consumed, so the caller advances to the next frame at buf[n:].
//
// ErrShortHeader means fewer than 36 octets are buffered; ErrIncompleteFrame means
// the header is complete but the declared payload has not fully arrived. Both are
// "buffer more bytes and retry" conditions, distinct from the hard parse errors
// (ErrBadCRC, ErrBadMagic, ...) that indicate a corrupt stream.
func ReadFrame(buf []byte) (frame *Frame, n int, err error) {
	if len(buf) < HeaderSize {
		return nil, 0, ErrShortHeader
	}
	payloadLen := binary.BigEndian.Uint32(buf[17:21])
	total := uint64(HeaderSize) + uint64(payloadLen)
	if total > MaxFrameSize {
		// Reject a hostile length BEFORE waiting to buffer it, so a huge declared
		// Payload Length cannot pin the reader (draft § Numeric Bounds).
		return nil, 0, ErrFrameTooLarge
	}
	if uint64(len(buf)) < total {
		return nil, 0, ErrIncompleteFrame
	}
	var f Frame
	if err := f.UnmarshalBinary(buf[:total]); err != nil {
		return nil, 0, err
	}
	return &f, int(total), nil
}
