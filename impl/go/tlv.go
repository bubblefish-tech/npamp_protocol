package npamp

import (
	"encoding/binary"
	"errors"
	"fmt"
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
	TLVKeyUpdateMarker TLVType = 0x17
	TLVProtectionMode  TLVType = 0x18
	// TLVRatchetGeneration carries an 8-octet big-endian master-ratchet generation
	// index in the MASTER_RATCHET / REKEM control frames (spec/10 section 9.3, Hybrid
	// Tree Ratchet), mirroring TLVKeyUpdateMarker's 8-octet layout one level up at
	// the connection root.
	TLVRatchetGeneration TLVType = 0x19
)

var ErrTruncatedTLV = errors.New("npamp: truncated TLV")

// MaxTLVsPerFrame bounds the number of TLVs a single frame payload may carry, so a
// frame cannot force unbounded TLV allocation. The handshake frames carry at most 5
// TLVs; this cap leaves ample room for extension TLVs while remaining finite
// (draft § Numeric Bounds).
const MaxTLVsPerFrame = 64

// ErrTooManyTLVs is returned when a frame payload holds more than MaxTLVsPerFrame TLVs.
var ErrTooManyTLVs = errors.New("npamp: TLV count exceeds MaxTLVsPerFrame")

// TLV is a single Type-Length-Value extension. Length is implicit (len(Value)).
type TLV struct {
	Type  TLVType
	Value []byte
}

// ForwardIncompatible reports whether the TLV type has its high bit (0x8000) set;
// a receiver that does not understand such a TLV MUST reject the frame with
// ErrUnknownCriticalTLV (the must-understand rule; enforced by CheckMustUnderstand).
func (t TLVType) ForwardIncompatible() bool { return t&0x8000 != 0 }

// ErrUnknownCriticalTLV is returned when a decoded frame carries an unknown extension
// TLV whose Type has the high bit (0x8000) set — a forward-incompatible
// "must-understand" extension the receiver cannot process. It maps to the wire error
// code unknown_critical_tlv (registries/error_codes.csv). A high-bit-clear unknown TLV
// is NOT critical and is not rejected by this check.
var ErrUnknownCriticalTLV = errors.New("npamp: unknown critical (must-understand) TLV")

// CheckMustUnderstand enforces the forward-incompatibility rule: for each TLV in tlvs,
// if the type is ForwardIncompatible (high bit 0x8000 set) and recognized reports it is
// not understood, the frame is rejected with ErrUnknownCriticalTLV. It is the
// production enforcement point for the ForwardIncompatible safety valve — the handshake
// TLV validator calls it, and any TLV-payload decoder may call it with the set of TLV
// types it understands.
func CheckMustUnderstand(tlvs []TLV, recognized func(TLVType) bool) error {
	for _, t := range tlvs {
		if t.Type.ForwardIncompatible() && !recognized(t.Type) {
			return fmt.Errorf("%w: TLV type 0x%04x", ErrUnknownCriticalTLV, uint16(t.Type))
		}
	}
	return nil
}

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
		if len(out) > MaxTLVsPerFrame {
			return nil, ErrTooManyTLVs
		}
		buf = buf[4+ln:]
	}
	return out, nil
}
