package npamp

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
)

// HeaderSize is the fixed N-PAMP frame header size in octets (draft-00 section 4.2).
const HeaderSize = 36

// ProtocolVersion is the wire major version carried in the high nibble of octet 4.
// The value 0x2 corresponds to ALPN "n-pamp/2".
const ProtocolVersion uint8 = 0x2

// Magic is the 4-octet frame magic, ASCII "NPAM".
var Magic = [4]byte{0x4E, 0x50, 0x41, 0x4D}

// Frame flags occupy the low nibble of header octet 4 (draft-00 section 4.3).
const (
	FlagURG  uint8 = 0x01 // urgent-priority scheduling
	FlagENC  uint8 = 0x02 // payload is AEAD-encrypted
	FlagCOMP uint8 = 0x04 // payload is compressed
	FlagFRAG uint8 = 0x08 // frame is a fragment of a larger logical message
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

var (
	ErrShortHeader     = errors.New("npamp: buffer shorter than 36-octet header")
	ErrBadMagic        = errors.New("npamp: bad magic (want NPAM)")
	ErrBadVersion      = errors.New("npamp: unsupported wire version")
	ErrBadCRC          = errors.New("npamp: header CRC32C mismatch")
	ErrReservedNonzero = errors.New("npamp: reserved octets are non-zero")
	ErrLengthMismatch  = errors.New("npamp: payload length does not match buffer")
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
