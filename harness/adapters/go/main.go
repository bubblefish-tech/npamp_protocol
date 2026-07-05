// N-PAMP conformance adapter (Go) that wires the OPEN reference implementation
// (github.com/bubblefish-tech/npamp_protocol/impl/go, at impl/go) to the npamp-conform runner.
//
// It is a "testee": it reads length-prefixed JSON requests {op,in} on stdin and
// writes length-prefixed JSON responses {out|error|skipped} on stdout. Unlike the
// template adapter, every operation below dispatches into an EXPORTED function of
// the reference package rather than reimplementing the primitive:
//
//   header.encode  -> npamp.Frame.MarshalBinary           (computes the CRC-covered header)
//   header.decode  -> npamp.Frame.UnmarshalBinary         (the spec MUST-reject rules)
//   crc32c         -> npamp.Frame.MarshalBinary           (CRC32C over header octets 0..20)
//   tlv.decode     -> npamp.DecodeTLVs + TLVType.ForwardIncompatible
//   aead.seal      -> npamp.SealAES256GCM                 (suite 0x0001)
//   aead.open      -> npamp.OpenAES256GCM                 (suite 0x0001, tag-verifying)
//   hkdf.expand    -> crypto/hkdf.Expand                  (the exact HKDF-Expand the
//                                                          reference key schedule calls
//                                                          at keyschedule.go:45)
//   profile.check  -> npamp.Profile + npamp.Profile.MinKEM (section 6 KEM-acceptance)
//
// Windows: stdio is treated as raw binary and stdout is flushed after every
// response so the little-endian length framing is not corrupted by CRLF translation
// or buffering.
package main

import (
	"bufio"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash"
	"io"
	"os"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

type request struct {
	Op string                 `json:"op"`
	In map[string]interface{} `json:"in"`
}
type response struct {
	Out     map[string]interface{} `json:"out,omitempty"`
	Error   string                 `json:"error,omitempty"`
	Skipped string                 `json:"skipped,omitempty"`
}

func s(in map[string]interface{}, k string) string {
	if v, ok := in[k].(string); ok {
		return v
	}
	return ""
}
func i(in map[string]interface{}, k string) int {
	if v, ok := in[k].(float64); ok {
		return int(v)
	}
	return 0
}
func hx(in map[string]interface{}, k string) ([]byte, error) { return hex.DecodeString(s(in, k)) }

// fixedKey copies a 32-octet key into the array type the reference seal/open take.
func fixedKey(b []byte) (k [32]byte, ok bool) {
	if len(b) != 32 {
		return k, false
	}
	copy(k[:], b)
	return k, true
}

func handle(req request) response {
	switch req.Op {
	case "header.encode":
		// Build a reference Frame and let the impl marshal it. MarshalBinary writes
		// the magic, the (ver<<4|flags) octet, the big-endian fields, and the CRC32C
		// over octets 0..20; the conformance vectors carry an empty payload so the
		// 36-octet header is exactly MarshalBinary's output.
		f := &npamp.Frame{
			Version: uint8(i(req.In, "ver")),
			Flags:   uint8(i(req.In, "flags")) & 0x0F,
			Type:    uint16(i(req.In, "frameType")),
			Channel: uint16(i(req.In, "channel")),
			Seq:     uint64(i(req.In, "seq")),
		}
		if pl := i(req.In, "payloadLength"); pl != 0 {
			// The spec frame's payloadLength field must equal the trailing byte count;
			// the corpus encode cases use 0. Reflect a non-zero request honestly by
			// attaching that many payload bytes so the impl encodes a matching length.
			f.Payload = make([]byte, pl)
		}
		frame, err := f.MarshalBinary()
		if err != nil {
			return response{Error: err.Error()}
		}
		return response{Out: map[string]interface{}{"frame": hex.EncodeToString(frame[:npamp.HeaderSize])}}

	case "header.decode":
		b, err := hx(req.In, "frame")
		if err != nil {
			return response{Error: "bad hex"}
		}
		var f npamp.Frame
		if err := f.UnmarshalBinary(b); err != nil {
			// Any reference rejection (short header, CRC mismatch, bad magic, bad
			// version, reserved-nonzero, length mismatch) is an "invalid" verdict.
			return response{Error: err.Error()}
		}
		return response{Out: map[string]interface{}{
			"magic":         "NPAM",
			"ver":           int(f.Version),
			"flags":         int(f.Flags),
			"frameType":     int(f.Type),
			"channel":       int(f.Channel),
			"seq":           int(f.Seq),
			"payloadLength": len(f.Payload),
			"crc32c":        hex.EncodeToString(b[21:25]),
			"reservedZero":  true,
		}}

	case "crc32c":
		// The op's octets are the 21-octet header prefix the CRC32C covers. Parse the
		// prefix back into a reference Frame and re-marshal it: MarshalBinary computes
		// crc32.Checksum(header[0:21], castagnoli) internally, so the CRC in octets
		// 21..24 of the produced frame is the reference impl's CRC over these octets.
		b, err := hx(req.In, "octets")
		if err != nil {
			return response{Error: "bad hex"}
		}
		if len(b) != 21 {
			return response{Error: "crc32c expects the 21-octet header prefix"}
		}
		f := &npamp.Frame{
			Version: b[4] >> 4,
			Flags:   b[4] & 0x0F,
			Type:    binary.BigEndian.Uint16(b[5:7]),
			Channel: binary.BigEndian.Uint16(b[7:9]),
			Seq:     binary.BigEndian.Uint64(b[9:17]),
		}
		payloadLen := binary.BigEndian.Uint32(b[17:21])
		var prefix [21]byte
		f.HeaderPrefix(prefix[:], payloadLen) // reconstruct the exact CRC-covered octets
		frame, err := f.MarshalBinary()
		if err != nil {
			return response{Error: err.Error()}
		}
		// Defensive: confirm the impl re-emitted the same prefix we were given before
		// trusting its CRC; magic/ver normalisation could otherwise diverge.
		for k := 0; k < 21; k++ {
			if frame[k] != b[k] {
				return response{Error: "non-canonical header prefix"}
			}
		}
		return response{Out: map[string]interface{}{"crc32c": hex.EncodeToString(frame[21:25])}}

	case "tlv.decode":
		b, err := hx(req.In, "tlv")
		if err != nil {
			return response{Error: "bad hex"}
		}
		// The high-bit (0x8000) forward-incompatible MUST-reject rule lives on the
		// reference TLVType; check it before/with decode so unknown criticals reject.
		if len(b) >= 2 && npamp.TLVType(binary.BigEndian.Uint16(b[0:2])).ForwardIncompatible() {
			return response{Error: "unknown forward-incompatible TLV (high bit set)"}
		}
		tlvs, err := npamp.DecodeTLVs(b)
		if err != nil {
			return response{Error: err.Error()}
		}
		if len(tlvs) != 1 {
			// The op decodes a single TLV; anything else is a malformed/over-long input.
			return response{Error: "expected exactly one TLV"}
		}
		t := tlvs[0]
		return response{Out: map[string]interface{}{
			"type":   int(t.Type),
			"length": len(t.Value),
			"value":  hex.EncodeToString(t.Value),
		}}

	case "aead.seal":
		if s(req.In, "suite") != "AES-256-GCM" {
			return response{Skipped: "suite not implemented: " + s(req.In, "suite")}
		}
		keyB, _ := hx(req.In, "key")
		nonce, _ := hx(req.In, "nonce")
		aad, _ := hx(req.In, "aad")
		pt, _ := hx(req.In, "pt")
		key, ok := fixedKey(keyB)
		if !ok {
			return response{Error: "key must be 32 octets for AES-256-GCM"}
		}
		// The reference seal derives nonce = iv XOR (0^4 || seq). With seq=0 the
		// derived nonce IS iv, so passing the op's nonce as iv with seq 0 exercises
		// the real SealAES256GCM path on the requested nonce.
		var iv [12]byte
		if len(nonce) != 12 {
			return response{Error: "nonce must be 12 octets"}
		}
		copy(iv[:], nonce)
		sealed, err := npamp.SealAES256GCM(key, iv, 0, aad, pt)
		if err != nil {
			return response{Error: err.Error()}
		}
		return response{Out: map[string]interface{}{"sealed": hex.EncodeToString(sealed)}}

	case "aead.open":
		if s(req.In, "suite") != "AES-256-GCM" {
			return response{Skipped: "suite not implemented: " + s(req.In, "suite")}
		}
		keyB, _ := hx(req.In, "key")
		nonce, _ := hx(req.In, "nonce")
		aad, _ := hx(req.In, "aad")
		sealed, _ := hx(req.In, "sealed")
		key, ok := fixedKey(keyB)
		if !ok {
			return response{Error: "key must be 32 octets for AES-256-GCM"}
		}
		var iv [12]byte
		if len(nonce) != 12 {
			return response{Error: "nonce must be 12 octets"}
		}
		copy(iv[:], nonce)
		pt, err := npamp.OpenAES256GCM(key, iv, 0, aad, sealed)
		if err != nil {
			return response{Error: "authentication failed"}
		}
		return response{Out: map[string]interface{}{"pt": hex.EncodeToString(pt)}}

	case "hkdf.expand":
		// Plain RFC 5869 HKDF-Expand. This is the exact primitive the reference key
		// schedule invokes at keyschedule.go:45 (crypto/hkdf.Expand); HkdfExpandLabel
		// wraps it with the N-PAMP label structure, which these raw vectors do not use.
		prk, _ := hx(req.In, "prk")
		info, _ := hx(req.In, "info")
		length := i(req.In, "length")
		var h func() hash.Hash
		switch s(req.In, "hash") {
		case "sha256":
			h = sha256.New
		case "sha384":
			h = sha512.New384
		default:
			return response{Skipped: "hash not implemented: " + s(req.In, "hash")}
		}
		okm, err := hkdf.Expand(h, prk, string(info), length)
		if err != nil {
			return response{Error: err.Error()}
		}
		return response{Out: map[string]interface{}{"okm": hex.EncodeToString(okm)}}

	case "profile.check":
		// Section 6 KEM-acceptance invariant via the reference Profile.MinKEM. A
		// profile MUST NOT accept a KEM below its minimum code point.
		var p npamp.Profile
		switch s(req.In, "profile") {
		case "Standard":
			p = npamp.ProfileStandard
		case "High":
			p = npamp.ProfileHigh
		case "Sovereign":
			p = npamp.ProfileSovereign
		default:
			return response{Skipped: "unknown profile: " + s(req.In, "profile")}
		}
		var kem npamp.KEMID
		switch s(req.In, "kem") {
		case "X25519MLKEM768":
			kem = npamp.KEMX25519MLKEM768
		case "X25519MLKEM1024":
			kem = npamp.KEMX25519MLKEM1024
		default:
			return response{Skipped: "unknown kem: " + s(req.In, "kem")}
		}
		if kem < p.MinKEM() {
			return response{Error: p.String() + " MUST NOT accept a KEM below its minimum"}
		}
		return response{Out: map[string]interface{}{"accepted": true}}

	default:
		return response{Skipped: "op not implemented: " + req.Op}
	}
}

func main() {
	r := bufio.NewReader(os.Stdin)
	w := bufio.NewWriter(os.Stdout)
	for {
		var lp [4]byte
		if _, err := io.ReadFull(r, lp[:]); err != nil {
			return // EOF: runner closed stdin
		}
		n := binary.LittleEndian.Uint32(lp[:])
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			return
		}
		var req request
		resp := response{}
		if err := json.Unmarshal(buf, &req); err != nil {
			resp = response{Error: "bad request json: " + err.Error()}
		} else {
			resp = handle(req)
		}
		ob, _ := json.Marshal(resp)
		var ol [4]byte
		binary.LittleEndian.PutUint32(ol[:], uint32(len(ob)))
		w.Write(ol[:])
		w.Write(ob)
		if err := w.Flush(); err != nil { // flush after every response (Windows framing)
			return
		}
	}
}
