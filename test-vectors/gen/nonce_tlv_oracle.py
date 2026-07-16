#!/usr/bin/env python3
# Independent nonce-derivation + TLV-encoding oracle + conformance-vector generator (TRACK C5).
#
# Emits two op-groups the pre-C5 corpus never graded:
#   nonce.derive -- the per-frame AEAD nonce = iv XOR (0x00000000 || seq_BE64). The pre-existing
#                   aead.seal/aead.open ops pin seq to 0 (nonce == iv), so the seq->nonce fold was
#                   never graded on its own. The Channel ID is deliberately NOT an input and NOT
#                   mixed in (spec/06 forbids a Channel-ID-in-nonce construction).
#   tlv.encode   -- the extension-TLV wire ENCODING: Type(BE16) || Length(BE16) || Value. The
#                   pre-existing tlv.decode grades only the parse/MUST-reject direction; the byte
#                   layout produced by an encoder (the interop contract two peers must match) was
#                   ungraded.
#
# NON-CIRCULARITY (test-vectors/README.md; 55_conformance_requirements.md §5.2):
#   * nonce.derive expected bytes are produced by the from-scratch XOR in `derive_nonce()`, derived
#     from spec/06_cryptographic_suites.md §"Key Schedule and Nonces" (RFC 8446 §5.3 / RFC 9001 form)
#     -- NOT from impl/go/aead.go DeriveNonce.
#   * tlv.encode expected bytes are assembled from scratch in `tlv_encode()` from the field widths
#     in spec/02_frame_format.md §"Extension TLV encoding" (Type/Length 16-bit big-endian) -- NOT
#     from impl/go/tlv.go TLV.Encode.
#   A passing vector proves the Go impl AGREES with an independent constructor; it never grades the
#   impl against its own output. The single MUST-reject (a 13-octet IV) is an inherent wire-format
#   length violation carrying no `expected`.
#
# Run: python3 test-vectors/gen/nonce_tlv_oracle.py  -> writes nonce.derive/tlv.encode groups as JSON.
import json, sys

def derive_nonce(iv, seq):
    seqpad = (0).to_bytes(4, 'big') + seq.to_bytes(8, 'big')
    return bytes(a ^ b for a, b in zip(iv, seqpad))

def tlv_encode(ttype, value):
    return ttype.to_bytes(2, 'big') + len(value).to_bytes(2, 'big') + value

def hx(b): return b.hex()

# ---------- nonce.derive ----------
IV_A = bytes(range(0xa0, 0xac))   # a0a1...ab
IV_0 = bytes(12)                  # all zero: nonce == seqpad, proving seq lands in octets 4..11
IV_F = b'\xff' * 12               # all ones: proves every octet is XORed

def nd(tcid, req, comment, iv, seq, result, expected=None, flags=None):
    # seq is carried as a decimal STRING so a 64-bit counter round-trips losslessly through the
    # shared runner and every language's JSON decoder — a bare JSON number > 2^53 is silently
    # corrupted by any float64-based decoder (e.g. nonce.derive tcId=4 seq=0x0102030405060708).
    o = {"tcId": tcid, "requirement": req, "comment": comment,
         "in": {"iv": hx(iv), "seq": str(seq)}, "result": result}
    if expected is not None: o["expected"] = expected
    if flags is not None: o["flags"] = flags
    return o

nonce_tests = [
    nd(1, "06/nonce/seq-zero-identity", "seq 0 => nonce == iv (XOR identity on the low 8 octets)",
       IV_A, 0, "valid", {"nonce": hx(derive_nonce(IV_A, 0))}),
    nd(2, "06/nonce/low-octet", "seq 1 flips only the last nonce octet",
       IV_A, 1, "valid", {"nonce": hx(derive_nonce(IV_A, 1))}),
    nd(3, "06/nonce/high-seq-into-octets-4-11", "large seq lands entirely in octets 4..11 (zero IV)",
       IV_0, 0x00000000ff00000a, "valid", {"nonce": hx(derive_nonce(IV_0, 0x00000000ff00000a))}),
    nd(4, "06/nonce/full-width-xor", "every low-8 octet is XORed (all-ones IV, 8-octet seq)",
       IV_F, 0x0102030405060708, "valid", {"nonce": hx(derive_nonce(IV_F, 0x0102030405060708))}),
    nd(5, "06/nonce/iv-length-MUST-reject", "IV must be exactly 12 octets; a 13-octet IV is invalid",
       b'\x00' * 13, 0, "invalid", None, ["MustReject", "IvWrongLength"]),
]

# ---------- tlv.encode ----------
def te(tcid, req, comment, ttype, value, result, expected=None, flags=None):
    o = {"tcId": tcid, "requirement": req, "comment": comment,
         "in": {"type": ttype, "value": hx(value)}, "result": result}
    if expected is not None: o["expected"] = expected
    if flags is not None: o["flags"] = flags
    return o

encode_tests = [
    te(1, "02/tlv/encode-path-challenge", "PathChallenge (0x0015), 32-octet value",
       0x0015, b'\x11' * 32, "valid", {"tlv": hx(tlv_encode(0x0015, b'\x11' * 32))}),
    te(2, "02/tlv/encode-zero-length", "ProfileSelect (0x0002) with an empty value -> length 0x0000",
       0x0002, b'', "valid", {"tlv": hx(tlv_encode(0x0002, b''))}),
    te(3, "02/tlv/encode-keyupdate-marker", "KeyUpdateMarker (0x0017), 8-octet BE value",
       0x0017, bytes(range(8)), "valid", {"tlv": hx(tlv_encode(0x0017, bytes(range(8))))}),
    te(4, "02/tlv/encode-ratchet-generation", "RatchetGeneration (0x0019), 8-octet BE generation index",
       0x0019, (5).to_bytes(8, 'big'), "valid", {"tlv": hx(tlv_encode(0x0019, (5).to_bytes(8, 'big')))}),
    te(5, "02/tlv/encode-high-bit-type-is-legal", "encoding a forward-incompatible (high-bit) type is legal; only DECODING an unknown one rejects",
       0x8001, b'\xab\xcd', "valid", {"tlv": hx(tlv_encode(0x8001, b'\xab\xcd'))}),
]

groups = [
    {"op": "nonce.derive", "profile": "any", "tests": nonce_tests},
    {"op": "tlv.encode", "profile": "any", "tests": encode_tests},
]
json.dump(groups, sys.stdout, indent=2)
sys.stdout.write("\n")
