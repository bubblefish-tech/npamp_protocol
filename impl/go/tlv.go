package npamp

import (
	"encoding/binary"
	"errors"
)

// TLVType is a 16-bit extension-TLV type (draft-00 section 4.5, registry section 9.4).
type TLVType uint16

const (
	TLVProfileOffer    TLVType = 0x01
	TLVProfileSelect   TLVType = 0x02
	TLVKEMOffer        TLVType = 0x03
	TLVKEMSelect       TLVType = 0x04
	TLVSigOffer        TLVType = 0x05
	TLVSigSelect       TLVType = 0x06
	TLVKEMShare        TLVType = 0x07
	TLVKEMCiphertext   TLVType = 0x08
	TLVIdentityKey     TLVType = 0x09 // handshake binding (spec/10 section 1.1)
	TLVCertVerify      TLVType = 0x0A // handshake binding (spec/10 section 1.1)
	TLVFinished        TLVType = 0x0B // handshake binding (spec/10 section 1.1)
	TLVAEADOffer       TLVType = 0x0C // handshake binding (spec/10 section 1.1)
	TLVAEADSelect      TLVType = 0x0D // handshake binding (spec/10 section 1.1)
	TLVAnomalyCharge   TLVType = 0x12
	TLVPathChallenge   TLVType = 0x15
	TLVPathResponse    TLVType = 0x16
	TLVKeyUpdateMarker TLVType = 0x17
	TLVProtectionMode  TLVType = 0x18
)

var ErrTruncatedTLV = errors.New("npamp: truncated TLV")

// TLV is a single Type-Length-Value extension. Length is implicit (len(Value)).
type TLV struct {
	Type  TLVType
	Value []byte
}

// ForwardIncompatible reports whether the TLV type has its high bit (0x8000) set;
// a receiver that does not understand such a TLV MUST reject the frame (draft-00 section 4.5).
func (t TLVType) ForwardIncompatible() bool { return t&0x8000 != 0 }

// Encode appends the wire encoding (Type u16, Length u16, Value) of t to dst.
func (t TLV) Encode(dst []byte) []byte {
	var hdr [4]byte
	binary.BigEndian.PutUint16(hdr[0:2], uint16(t.Type))
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(t.Value)))
	dst = append(dst, hdr[:]...)
	return append(dst, t.Value...)
}

// DecodeTLVs parses a concatenation of TLVs from buf.
func DecodeTLVs(buf []byte) ([]TLV, error) {
	var out []TLV
	for len(buf) > 0 {
		if len(buf) < 4 {
			return nil, ErrTruncatedTLV
		}
		typ := TLVType(binary.BigEndian.Uint16(buf[0:2]))
		ln := int(binary.BigEndian.Uint16(buf[2:4]))
		if len(buf) < 4+ln {
			return nil, ErrTruncatedTLV
		}
		out = append(out, TLV{Type: typ, Value: append([]byte(nil), buf[4:4+ln]...)})
		buf = buf[4+ln:]
	}
	return out, nil
}
