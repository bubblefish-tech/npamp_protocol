package npamp

import (
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
)

// Handshake frame types on the Control channel (spec/10 section 1.1). The
// handshake is a four-frame 1.5-RTT exchange with mutual authentication;
// there is no separate Finished frame — the Finished MAC is a TLV inside each
// AUTH frame. These occupy the channel-specific space (>= ChannelSpecificBase)
// and are frozen for draft-01.
const (
	FrameClientHello FrameType = 0x0100 // cleartext
	FrameServerHello FrameType = 0x0101 // cleartext
	FrameServerAuth  FrameType = 0x0102 // AEAD-sealed under the s-hs handshake key
	FrameClientAuth  FrameType = 0x0103 // AEAD-sealed under the c-hs handshake key
)

// Role identifies which side of the handshake produced an authentication
// message. The CertVerify context string differs per role, so a server
// CertVerify is unusable as a client one (spec/10 section 6.1).
type Role uint8

const (
	RoleClient Role = 1
	RoleServer Role = 2
)

var (
	ErrHandshakeTLVOrder   = errors.New("npamp: handshake TLVs missing, extra, or out of order")
	ErrHandshakeTLVValue   = errors.New("npamp: handshake TLV value has an invalid size")
	ErrInvalidRole         = errors.New("npamp: role must be RoleClient or RoleServer")
	ErrCertVerifyScheme    = errors.New("npamp: CertVerify signature scheme was not negotiated")
	ErrCertVerifySignature = errors.New("npamp: CertVerify signature verification failed")
	ErrCertVerifyKeySize   = errors.New("npamp: identity key is not an Ed25519 public key")
	ErrFinishedMismatch    = errors.New("npamp: Finished verify_data mismatch")
)

// certVerifyContext returns the role's CertVerify context string
// (spec/10 section 6.1), or "" for an invalid role.
func (r Role) certVerifyContext() string {
	switch r {
	case RoleClient:
		return "N-PAMP/2, client CertificateVerify"
	case RoleServer:
		return "N-PAMP/2, server CertificateVerify"
	default:
		return ""
	}
}

// ClientHello is the first handshake flight (frame type 0x0100, cleartext):
// ProfileOffer, KEMOffer, SigOffer, AEADOffer, KEMShare, in that order
// (spec/10 section 1).
type ClientHello struct {
	ProfileOffer []Profile
	KEMOffer     []KEMID
	SigOffer     []SigID
	AEADOffer    []AEADID
	KEMShare     []byte
}

// ServerHello is the second handshake flight (frame type 0x0101, cleartext):
// ProfileSelect, KEMSelect, SigSelect, AEADSelect, KEMCiphertext, in that
// order (spec/10 section 1).
type ServerHello struct {
	ProfileSelect Profile
	KEMSelect     KEMID
	SigSelect     SigID
	AEADSelect    AEADID
	KEMCiphertext []byte
}

// AuthMessage is the SERVER_AUTH (0x0102) / CLIENT_AUTH (0x0103) plaintext:
// exactly three TLVs in order — IdentityKey, CertVerify, Finished
// (spec/10 sections 1 and 6.4). The frames carrying it are AEAD-sealed under
// the per-direction handshake traffic key.
type AuthMessage struct {
	IdentityKey []byte // Ed25519 public key (32 octets at Standard)
	CertVerify  []byte // SignatureScheme uint16 || signature
	Finished    []byte // HashLen-octet HMAC verify_data
}

// u16ListBytes encodes a list of 16-bit code points big-endian.
func u16ListBytes[T ~uint16](ids []T) []byte {
	out := make([]byte, 0, 2*len(ids))
	for _, id := range ids {
		out = binary.BigEndian.AppendUint16(out, uint16(id))
	}
	return out
}

// parseU16List decodes a big-endian list of 16-bit code points; the value must
// be non-empty and of even length.
func parseU16List[T ~uint16](v []byte, name string) ([]T, error) {
	if len(v) == 0 || len(v)%2 != 0 {
		return nil, fmt.Errorf("%w: %s is %d octets", ErrHandshakeTLVValue, name, len(v))
	}
	out := make([]T, 0, len(v)/2)
	for i := 0; i < len(v); i += 2 {
		out = append(out, T(binary.BigEndian.Uint16(v[i:i+2])))
	}
	return out, nil
}

// requireTLVs checks that tlvs is exactly the expected types in the expected
// order (the handshake fixes both, spec/10 section 1).
func requireTLVs(tlvs []TLV, want []TLVType) error {
	if len(tlvs) != len(want) {
		return fmt.Errorf("%w: got %d TLVs, want %d", ErrHandshakeTLVOrder, len(tlvs), len(want))
	}
	for i, w := range want {
		if tlvs[i].Type != w {
			return fmt.Errorf("%w: position %d is 0x%02x, want 0x%02x", ErrHandshakeTLVOrder, i, uint16(tlvs[i].Type), uint16(w))
		}
	}
	return nil
}

// TLVs returns the flight's TLVs in transcript/wire order.
func (m *ClientHello) TLVs() []TLV {
	profiles := make([]byte, len(m.ProfileOffer))
	for i, p := range m.ProfileOffer {
		profiles[i] = byte(p)
	}
	return []TLV{
		{Type: TLVProfileOffer, Value: profiles},
		{Type: TLVKEMOffer, Value: u16ListBytes(m.KEMOffer)},
		{Type: TLVSigOffer, Value: u16ListBytes(m.SigOffer)},
		{Type: TLVAEADOffer, Value: u16ListBytes(m.AEADOffer)},
		{Type: TLVKEMShare, Value: m.KEMShare},
	}
}

// Encode returns the CLIENT_HELLO frame payload: the TLVs concatenated in
// canonical form.
func (m *ClientHello) Encode() []byte {
	var out []byte
	for _, v := range m.TLVs() {
		out = v.Encode(out)
	}
	return out
}

// DecodeClientHello parses a CLIENT_HELLO frame payload, enforcing the exact
// TLV set and order of spec/10 section 1.
func DecodeClientHello(payload []byte) (*ClientHello, error) {
	tlvs, err := DecodeTLVs(payload)
	if err != nil {
		return nil, err
	}
	if err := requireTLVs(tlvs, []TLVType{TLVProfileOffer, TLVKEMOffer, TLVSigOffer, TLVAEADOffer, TLVKEMShare}); err != nil {
		return nil, err
	}
	if len(tlvs[0].Value) == 0 {
		return nil, fmt.Errorf("%w: ProfileOffer is empty", ErrHandshakeTLVValue)
	}
	profiles := make([]Profile, len(tlvs[0].Value))
	for i, b := range tlvs[0].Value {
		profiles[i] = Profile(b)
	}
	kems, err := parseU16List[KEMID](tlvs[1].Value, "KEMOffer")
	if err != nil {
		return nil, err
	}
	sigs, err := parseU16List[SigID](tlvs[2].Value, "SigOffer")
	if err != nil {
		return nil, err
	}
	aeads, err := parseU16List[AEADID](tlvs[3].Value, "AEADOffer")
	if err != nil {
		return nil, err
	}
	if len(tlvs[4].Value) == 0 {
		return nil, fmt.Errorf("%w: KEMShare is empty", ErrHandshakeTLVValue)
	}
	return &ClientHello{
		ProfileOffer: profiles,
		KEMOffer:     kems,
		SigOffer:     sigs,
		AEADOffer:    aeads,
		KEMShare:     tlvs[4].Value,
	}, nil
}

// TLVs returns the flight's TLVs in transcript/wire order.
func (m *ServerHello) TLVs() []TLV {
	return []TLV{
		{Type: TLVProfileSelect, Value: []byte{byte(m.ProfileSelect)}},
		{Type: TLVKEMSelect, Value: binary.BigEndian.AppendUint16(nil, uint16(m.KEMSelect))},
		{Type: TLVSigSelect, Value: binary.BigEndian.AppendUint16(nil, uint16(m.SigSelect))},
		{Type: TLVAEADSelect, Value: binary.BigEndian.AppendUint16(nil, uint16(m.AEADSelect))},
		{Type: TLVKEMCiphertext, Value: m.KEMCiphertext},
	}
}

// Encode returns the SERVER_HELLO frame payload: the TLVs concatenated in
// canonical form.
func (m *ServerHello) Encode() []byte {
	var out []byte
	for _, v := range m.TLVs() {
		out = v.Encode(out)
	}
	return out
}

// DecodeServerHello parses a SERVER_HELLO frame payload, enforcing the exact
// TLV set and order of spec/10 section 1 and the fixed select-value sizes
// (ProfileSelect 1 octet; KEM/Sig/AEADSelect 2 octets each).
func DecodeServerHello(payload []byte) (*ServerHello, error) {
	tlvs, err := DecodeTLVs(payload)
	if err != nil {
		return nil, err
	}
	if err := requireTLVs(tlvs, []TLVType{TLVProfileSelect, TLVKEMSelect, TLVSigSelect, TLVAEADSelect, TLVKEMCiphertext}); err != nil {
		return nil, err
	}
	if len(tlvs[0].Value) != 1 {
		return nil, fmt.Errorf("%w: ProfileSelect is %d octets, want 1", ErrHandshakeTLVValue, len(tlvs[0].Value))
	}
	for i, name := range []string{"", "KEMSelect", "SigSelect", "AEADSelect"} {
		if i == 0 {
			continue
		}
		if len(tlvs[i].Value) != 2 {
			return nil, fmt.Errorf("%w: %s is %d octets, want 2", ErrHandshakeTLVValue, name, len(tlvs[i].Value))
		}
	}
	if len(tlvs[4].Value) == 0 {
		return nil, fmt.Errorf("%w: KEMCiphertext is empty", ErrHandshakeTLVValue)
	}
	return &ServerHello{
		ProfileSelect: Profile(tlvs[0].Value[0]),
		KEMSelect:     KEMID(binary.BigEndian.Uint16(tlvs[1].Value)),
		SigSelect:     SigID(binary.BigEndian.Uint16(tlvs[2].Value)),
		AEADSelect:    AEADID(binary.BigEndian.Uint16(tlvs[3].Value)),
		KEMCiphertext: tlvs[4].Value,
	}, nil
}

// TLVs returns the AUTH message's TLVs in transcript/wire order.
func (m *AuthMessage) TLVs() []TLV {
	return []TLV{
		{Type: TLVIdentityKey, Value: m.IdentityKey},
		{Type: TLVCertVerify, Value: m.CertVerify},
		{Type: TLVFinished, Value: m.Finished},
	}
}

// Encode returns the AUTH frame plaintext (sealed by the record layer): the
// three TLVs concatenated in canonical form.
func (m *AuthMessage) Encode() []byte {
	var out []byte
	for _, v := range m.TLVs() {
		out = v.Encode(out)
	}
	return out
}

// DecodeAuthMessage parses an opened SERVER_AUTH / CLIENT_AUTH plaintext.
// Exactly three TLVs in order (IdentityKey, CertVerify, Finished) are required
// (spec/10 section 6.4).
func DecodeAuthMessage(payload []byte) (*AuthMessage, error) {
	tlvs, err := DecodeTLVs(payload)
	if err != nil {
		return nil, err
	}
	if err := requireTLVs(tlvs, []TLVType{TLVIdentityKey, TLVCertVerify, TLVFinished}); err != nil {
		return nil, err
	}
	for i, name := range []string{"IdentityKey", "CertVerify", "Finished"} {
		if len(tlvs[i].Value) == 0 {
			return nil, fmt.Errorf("%w: %s is empty", ErrHandshakeTLVValue, name)
		}
	}
	return &AuthMessage{
		IdentityKey: tlvs[0].Value,
		CertVerify:  tlvs[1].Value,
		Finished:    tlvs[2].Value,
	}, nil
}

// CertVerifySigningInput builds the RFC 8446 section 4.4.3-style input the
// CertVerify signature covers (spec/10 section 6.1):
//
//	0x20 x 64 || context || 0x00 || transcript_hash
//
// where transcript_hash is TH_sId (server) / TH_cId (client) — the transcript
// through the signer's own IdentityKey, before its own CertVerify.
func CertVerifySigningInput(role Role, transcriptHash []byte) ([]byte, error) {
	ctx := role.certVerifyContext()
	if ctx == "" {
		return nil, ErrInvalidRole
	}
	out := make([]byte, 0, 64+len(ctx)+1+len(transcriptHash))
	for range 64 {
		out = append(out, 0x20)
	}
	out = append(out, ctx...)
	out = append(out, 0x00)
	return append(out, transcriptHash...), nil
}

// SignCertVerify produces the TLV 0x0A value for the given role:
// SignatureScheme uint16 (Ed25519 = 0x0807) || Ed25519 signature over
// CertVerifySigningInput (spec/10 section 6.1). Standard profile signs with
// Ed25519 only.
func SignCertVerify(priv ed25519.PrivateKey, role Role, transcriptHash []byte) ([]byte, error) {
	input, err := CertVerifySigningInput(role, transcriptHash)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, input)
	out := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(sig)), uint16(SigEd25519))
	return append(out, sig...), nil
}

// VerifyCertVerify checks a TLV 0x0A value against the peer's identity key,
// role, and transcript hash. It rejects a signature scheme other than the
// negotiated Ed25519 (0x0807), and — because the role selects the context
// string — a server CertVerify presented as a client one (spec/10 section
// 6.1).
func VerifyCertVerify(pub []byte, role Role, transcriptHash, certVerifyValue []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return ErrCertVerifyKeySize
	}
	if len(certVerifyValue) != 2+ed25519.SignatureSize {
		return fmt.Errorf("%w: value is %d octets, want %d", ErrCertVerifySignature, len(certVerifyValue), 2+ed25519.SignatureSize)
	}
	if SigID(binary.BigEndian.Uint16(certVerifyValue[:2])) != SigEd25519 {
		return ErrCertVerifyScheme
	}
	input, err := CertVerifySigningInput(role, transcriptHash)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), input, certVerifyValue[2:]) {
		return ErrCertVerifySignature
	}
	return nil
}

// ComputeFinished produces the TLV 0x0B verify_data (spec/10 section 6.2, per
// RFC 8446 section 4.4.4):
//
//	verify_data = HMAC(finished_key, transcript_hash)
//
// with HMAC over the profile's KDF hash. transcript_hash is TH_sCV (server) /
// TH_cCV (client) — the transcript through the sender's own CertVerify,
// excluding its own Finished. finished_key comes from DeriveFinishedKey.
func ComputeFinished(finishedKey, transcriptHash []byte, p Profile) []byte {
	m := hmac.New(hashForProfile(p), finishedKey)
	m.Write(transcriptHash)
	return m.Sum(nil)
}

// VerifyFinished recomputes the Finished MAC and compares it to verifyData in
// constant time, returning ErrFinishedMismatch on any difference (spec/10
// section 6.2 requires constant-time verification and abort on mismatch).
func VerifyFinished(finishedKey, transcriptHash, verifyData []byte, p Profile) error {
	want := ComputeFinished(finishedKey, transcriptHash, p)
	if !hmac.Equal(want, verifyData) {
		return ErrFinishedMismatch
	}
	return nil
}
