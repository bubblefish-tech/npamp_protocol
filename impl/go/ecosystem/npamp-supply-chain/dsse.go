// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package supplychain

import "strconv"

// InTotoPayloadType is the DSSE payloadType this package always uses for a signed
// provenance Statement — the in-toto attestation spec's own recommended value
// (https://github.com/in-toto/attestation/blob/main/spec/v1/envelope.md, fetched this
// session: "payloadType MUST be set to `application/vnd.in-toto.<predicate>+json` or to
// `application/vnd.in-toto+json`").
const InTotoPayloadType = "application/vnd.in-toto+json"

// Signature is one DSSE v1 envelope signature entry
// (https://github.com/secure-systems-lab/dsse/blob/master/envelope.md, fetched this
// session). Sig is REQUIRED and base64-encoded; KeyID is OPTIONAL.
type Signature struct {
	KeyID string `json:"keyid,omitempty"`
	Sig   string `json:"sig"`
}

// Envelope is a DSSE (Dead Simple Signing Envelope) v1 document
// (https://github.com/secure-systems-lab/dsse/blob/master/envelope.md, fetched this
// session): `{"payload": Base64(SERIALIZED_BODY), "payloadType": ..., "signatures":
// [{"keyid": ..., "sig": Base64(SIGNATURE)}]}`. This is the real, standard in-toto/SLSA
// attestation transport format — the same envelope shape cosign and
// slsa-github-generator produce for a SLSA provenance attestation — not a bespoke
// invention (see doc.go's grounding section).
type Envelope struct {
	Payload     string      `json:"payload"`
	PayloadType string      `json:"payloadType"`
	Signatures  []Signature `json:"signatures"`
}

// dssePrefix is the literal ASCII string DSSE v1's PAE algorithm prepends to every
// encoding (https://github.com/secure-systems-lab/dsse/blob/master/protocol.md, fetched
// this session, verbatim: `"DSSEv1"` = the literal ASCII string [0x44, 0x53, 0x53, 0x45,
// 0x76, 0x31]).
const dssePrefix = "DSSEv1"

// PAE computes the DSSE v1 Pre-Authentication Encoding of (payloadType, body) — the exact
// bytes a DSSE signature is computed over
// (https://github.com/secure-systems-lab/dsse/blob/master/protocol.md, fetched this
// session, verbatim):
//
//	PAE(type, body) = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(body) + SP + body
//
// where SP is a single ASCII space (0x20) and LEN is the decimal ASCII byte length with no
// leading zeros (strconv.Itoa never emits a leading zero for a non-negative int, which is
// exactly this requirement). "What gets signed: the signature is computed over
// PAE(UTF8(PAYLOAD_TYPE), SERIALIZED_BODY)" — payloadType here is already a Go string
// (inherently UTF-8), so []byte(payloadType) is that UTF-8 encoding.
func PAE(payloadType string, body []byte) []byte {
	t := []byte(payloadType)
	out := make([]byte, 0, len(dssePrefix)+1+20+1+len(t)+1+20+1+len(body)+4)
	out = append(out, dssePrefix...)
	out = append(out, ' ')
	out = append(out, strconv.Itoa(len(t))...)
	out = append(out, ' ')
	out = append(out, t...)
	out = append(out, ' ')
	out = append(out, strconv.Itoa(len(body))...)
	out = append(out, ' ')
	out = append(out, body...)
	return out
}
