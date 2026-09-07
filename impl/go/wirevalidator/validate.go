// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package wirevalidator

import (
	"fmt"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// RejectReason names WHY Validate (or one of its narrower siblings)
// rejected something -- a stable, machine-comparable identifier distinct
// from the free-text Detail, so a caller (an audit log, a metrics counter,
// a test assertion) can switch on the reason without string-matching.
type RejectReason string

const (
	// ReasonFrameTypeReserved is frame type 0x0000, which
	// registries/frame_types_reserved.csv marks "(reserved); MUST NOT be
	// used as a frame type" unconditionally.
	ReasonFrameTypeReserved RejectReason = "frame_type_reserved"
	// ReasonChannelNotRegistered is a channel_id absent from
	// registries/channels.csv (0x0000-0x0013): includes the reserved
	// future-core range, the extension range, GREASE, and the forbidden
	// value 0xFFFF -- see the package doc's fail-closed allowlist note.
	ReasonChannelNotRegistered RejectReason = "channel_not_registered"
	// ReasonFrameTypeNotRegisteredForChannel is a channel-specific frame
	// type (above SystemFrameMax) with no matching row in
	// registries/frame_types_channel.csv for that exact (channel, type)
	// pair.
	ReasonFrameTypeNotRegisteredForChannel RejectReason = "frame_type_not_registered_for_channel"
	// ReasonFrameTooLarge is a total frame size (header + payload)
	// exceeding npamp.MaxFrameSize.
	ReasonFrameTooLarge RejectReason = "frame_exceeds_max_frame_size"
	// ReasonTooManyTLVs is a TLV count exceeding npamp.MaxTLVsPerFrame.
	ReasonTooManyTLVs RejectReason = "tlv_count_exceeds_max"
	// ReasonTLVTagNotRegistered is a TLV type absent from the assigned set
	// in registries/tlv_tags.csv.
	ReasonTLVTagNotRegistered RejectReason = "tlv_tag_not_registered"
	// ReasonErrorCodeNotRegistered is a SessionErrorCode absent from the
	// assigned set in registries/error_codes.csv.
	ReasonErrorCodeNotRegistered RejectReason = "error_code_not_registered"
)

// RejectError is the error type every rejection in this package returns: a
// stable Reason plus a human-readable Detail. errors.As(err, &rejectErr)
// recovers it from a wrapped error.
type RejectError struct {
	Reason RejectReason
	Detail string
}

func (e *RejectError) Error() string {
	return fmt.Sprintf("wirevalidator: reject [%s]: %s", e.Reason, e.Detail)
}

// checkFrameType validates a (channel, frameType) pair against the loaded
// channel and frame-type registries. It is the shared core behind Validate
// (which has the full npamp.Frame, including Payload) and the relay Hook
// adapter (which sees only header fields, never the payload) -- both call
// exactly this logic so a frame accepted by one path is accepted by the
// other for the fields they share.
func (reg *Registries) checkFrameType(channel, frameType uint16) error {
	if frameType == 0 {
		return &RejectError{
			Reason: ReasonFrameTypeReserved,
			Detail: "frame type 0x0000 is reserved and MUST NOT be used (registries/frame_types_reserved.csv)",
		}
	}
	if _, ok := reg.channels[channel]; !ok {
		return &RejectError{
			Reason: ReasonChannelNotRegistered,
			Detail: fmt.Sprintf("channel 0x%04X is not a registered channel (registries/channels.csv)", channel),
		}
	}
	if frameType <= SystemFrameMax {
		if _, ok := reg.systemFrames[frameType]; !ok {
			// Defensive: SystemFrameMax and the loaded system-frame set are
			// both derived from the same registry file, so this branch
			// should be unreachable for a valid registry load, but a
			// validator MUST fail closed rather than assume.
			return &RejectError{
				Reason: ReasonFrameTypeNotRegisteredForChannel,
				Detail: fmt.Sprintf("frame type 0x%04X is in the system band but not a registered system frame type", frameType),
			}
		}
		return nil // system frame type: valid on any registered channel
	}
	if _, ok := reg.chanFrames[chanFrameKey{channel: channel, frameType: frameType}]; !ok {
		return &RejectError{
			Reason: ReasonFrameTypeNotRegisteredForChannel,
			Detail: fmt.Sprintf("frame type 0x%04X is not registered for channel 0x%04X (registries/frame_types_channel.csv)", frameType, channel),
		}
	}
	return nil
}

// checkBounds validates a frame's total wire size and (where known) its TLV
// count against the frozen bounds npamp.MaxFrameSize and
// npamp.MaxTLVsPerFrame declare (frame.go, tlv.go) -- the single source of
// truth for both caps, never re-derived here. tlvCount may be -1 to skip
// the TLV-count check (the caller has not decoded TLVs, e.g. the relay Hook
// adapter, which never sees the payload).
func checkBounds(totalSize int, tlvCount int) error {
	if totalSize > npamp.MaxFrameSize {
		return &RejectError{
			Reason: ReasonFrameTooLarge,
			Detail: fmt.Sprintf("frame size %d octets exceeds MaxFrameSize (%d octets)", totalSize, npamp.MaxFrameSize),
		}
	}
	if tlvCount >= 0 && tlvCount > npamp.MaxTLVsPerFrame {
		return &RejectError{
			Reason: ReasonTooManyTLVs,
			Detail: fmt.Sprintf("TLV count %d exceeds MaxTLVsPerFrame (%d)", tlvCount, npamp.MaxTLVsPerFrame),
		}
	}
	return nil
}

// Validate checks an already-parsed npamp.Frame against the registries and
// the frozen bounds: frame type not reserved, channel registered, frame
// type registered for that channel (or a universal system type), and total
// wire size within MaxFrameSize. It does NOT decode the payload -- Validate
// operates purely on header-derived fields plus the payload's LENGTH, so it
// is safe to call on an AEAD-encrypted (ciphertext) frame exactly as on a
// cleartext one. A caller that has decrypted a payload and wants the
// additional TLV-tag or error-code registry checks calls
// ValidateTLVSequence / ValidateErrorCode itself with the decoded content.
//
// Validate returns nil for an accepted frame, or a *RejectError (or an
// error wrapping one) naming why the frame was rejected.
func (reg *Registries) Validate(f *npamp.Frame) error {
	if f == nil {
		return &RejectError{Reason: ReasonFrameTypeReserved, Detail: "nil frame"}
	}
	if err := reg.checkFrameType(f.Channel, f.Type); err != nil {
		return err
	}
	total := npamp.HeaderSize + len(f.Payload)
	return checkBounds(total, -1)
}

// ValidateBytes parses buf as a wire frame via npamp.Frame.UnmarshalBinary
// (reusing the existing structural parser -- CRC32C, magic, version,
// reserved-octet/flag checks; NEVER reimplemented here) and, only if that
// parse succeeds, runs Validate against the registries. A structural
// rejection from UnmarshalBinary (e.g. npamp.ErrBadCRC) is returned
// unwrapped, so a caller can distinguish "malformed wire bytes" from "a
// well-formed frame this validator's registries reject" by checking the
// concrete error/reason.
func ValidateBytes(reg *Registries, buf []byte) error {
	var f npamp.Frame
	if err := f.UnmarshalBinary(buf); err != nil {
		return err
	}
	return reg.Validate(&f)
}

// ValidateTLVTag checks a single TLV type against the assigned tag set in
// registries/tlv_tags.csv. It is the per-tag primitive ValidateTLVSequence
// loops over, and is also useful standalone (e.g. checking one TLV a caller
// has already located inside a larger, already-decrypted payload).
func (reg *Registries) ValidateTLVTag(t npamp.TLVType) error {
	if _, ok := reg.tlvTags[uint16(t)]; !ok {
		return &RejectError{
			Reason: ReasonTLVTagNotRegistered,
			Detail: fmt.Sprintf("TLV tag 0x%04X is not a registered/assigned tag (registries/tlv_tags.csv)", uint16(t)),
		}
	}
	return nil
}

// ValidateTLVSequence checks a decoded TLV sequence (e.g. the return of
// npamp.DecodeTLVs on a CLEARTEXT payload, or on a payload the caller has
// already AEAD-opened) against MaxTLVsPerFrame and, for every TLV in it,
// against the assigned tag registry. It returns the FIRST violation found
// (bound check first, then tag order), so a caller gets one actionable
// reason per call rather than needing to loop itself.
//
// MaxTLVsPerFrame is checked here too, defense-in-depth alongside
// npamp.DecodeTLVs' own enforcement: DecodeTLVs stops and returns
// ErrTooManyTLVs once it has decoded more than MaxTLVsPerFrame entries, so
// in practice a caller only ever hands this function a slice DecodeTLVs
// itself produced (already within bound); this check independently catches
// a slice a caller constructed directly, bypassing DecodeTLVs.
func (reg *Registries) ValidateTLVSequence(tlvs []npamp.TLV) error {
	if err := checkBounds(0, len(tlvs)); err != nil {
		return err
	}
	for _, t := range tlvs {
		if err := reg.ValidateTLVTag(t.Type); err != nil {
			return err
		}
	}
	return nil
}

// ValidateErrorCode checks a decoded ERROR-frame code (from
// npamp.DecodeErrorBody, after the caller has AEAD-opened the ERROR
// frame's payload) against the assigned code set in
// registries/error_codes.csv. Code 0 (reserved) and any code in the
// unassigned 0x000B-0x00FF range are both rejected, matching this
// package's fail-closed allowlist posture (package doc).
func (reg *Registries) ValidateErrorCode(code npamp.SessionErrorCode) error {
	if _, ok := reg.errorCodes[uint8(code)]; !ok {
		return &RejectError{
			Reason: ReasonErrorCodeNotRegistered,
			Detail: fmt.Sprintf("error code %d is not a registered/assigned code (registries/error_codes.csv)", uint8(code)),
		}
	}
	return nil
}
