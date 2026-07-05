package npamp

import (
	"encoding/binary"
	"hash"
)

// Transcript is the handshake transcript of spec/10 section 3: a running byte
// buffer whose hash points are H over all bytes absorbed so far. It
// deliberately diverges from RFC 8446 section 4.4.1 — a frame contributes only
// its 2-octet big-endian frame type followed by each TLV in canonical
// Type(2) || Length(2) || Value form; the remaining 34 octets of the frame
// header (magic, flags, channel, seq, payload length, CRC, reserved) and the
// AEAD tag are NOT absorbed. Granularity is per-TLV so the bundled AUTH frames
// can be hashed up to sub-frame boundaries (TH_sId, TH_sCV, TH_cId, TH_cCV).
type Transcript struct {
	newHash func() hash.Hash
	buf     []byte
}

// NewTranscript returns an empty transcript using the negotiated profile's KDF
// hash (SHA-256 at Standard, SHA-384 at High/Sovereign).
func NewTranscript(p Profile) *Transcript {
	return &Transcript{newHash: hashForProfile(p)}
}

// AddFrameType absorbs a frame's 2-octet big-endian frame type. Nothing else
// from the 36-octet frame header is absorbed (spec/10 section 3).
func (t *Transcript) AddFrameType(ft FrameType) {
	t.buf = binary.BigEndian.AppendUint16(t.buf, uint16(ft))
}

// AddTLV absorbs one TLV in canonical Type(2) || Length(2) || Value form —
// the identical decoded on-wire bytes, so both peers' transcripts are
// byte-identical.
func (t *Transcript) AddTLV(v TLV) {
	t.buf = v.Encode(t.buf)
}

// AddFrame absorbs a whole handshake frame: its frame type, then each TLV in
// order.
func (t *Transcript) AddFrame(ft FrameType, tlvs []TLV) {
	t.AddFrameType(ft)
	for _, v := range tlvs {
		t.AddTLV(v)
	}
}

// Sum returns the transcript-hash point at the current position: H over all
// bytes absorbed so far. The transcript remains usable; later absorptions
// extend it.
func (t *Transcript) Sum() []byte {
	h := t.newHash()
	h.Write(t.buf)
	return h.Sum(nil)
}
