#!/usr/bin/env python3
# Independent whole-frame AEAD oracle + core-wire conformance-vector generator (TRACK C4).
#
# Emits two op-groups the pre-C4 corpus never graded:
#   frame.seal  -- AEAD-seal a payload with the AAD = the 21-octet frame HEADER PREFIX and the
#                  per-frame nonce = DeriveNonce(iv, seq). This is the interop-critical whole-frame
#                  path: the header fields are BOUND into the tag via the AAD, and the sequence
#                  number is BOUND into the nonce. The pre-existing aead.seal op passes an ARBITRARY
#                  aad with seq fixed to 0 (nonce == iv), so it never exercises header-binding or the
#                  seq->nonce derivation -- the silent gap this op closes.
#   frame.open  -- the inverse, with the spec MUST-reject list: tampered header field (AAD mismatch),
#                  mismatched sequence number (nonce mismatch), tampered AEAD tag, tampered ciphertext.
#
# NON-CIRCULARITY (test-vectors/README.md; spec/companion/55_conformance_requirements.md §5.2):
#   * The 21-octet AAD is built by the from-scratch `header_prefix()` below, derived from
#     spec/02_frame_format.md §"Fixed 36-octet header" (magic "NPAM", (Ver<<4)|Flags, Type/Channel
#     BE16, Seq BE64, PayloadLength BE32) -- NOT from impl/go/frame.go HeaderPrefix.
#   * The per-frame nonce is built by the from-scratch `derive_nonce()` below: iv XOR
#     (0x00000000 || seq_BE64), per spec/06_cryptographic_suites.md §"Key Schedule and Nonces"
#     (the TLS-1.3 / RFC 8446 §5.3 form; the Channel ID is deliberately NOT in the nonce) -- NOT from
#     impl/go/aead.go DeriveNonce.
#   * The ciphertext||tag is produced by pyca/cryptography's AES-256-GCM (OpenSSL, RFC 5116 /
#     NIST SP 800-38D), an AEAD implementation INDEPENDENT of Go's crypto/aes + crypto/cipher.
#   A passing frame.seal/frame.open vector therefore proves the Go impl AGREES with an independent
#   AEAD + independent header/nonce constructors; it never grades the impl against its own output.
#   The MUST-reject cases carry no `expected` and are inherently non-circular.
#
# Run: python3 test-vectors/gen/frame_seal_oracle.py  -> writes frame.seal/frame.open groups as JSON.
import json, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------- independent constructors (spec/02 §4.2, spec/06 §"Key Schedule and Nonces") ----------
MAGIC = b'\x4e\x50\x41\x4d'  # "NPAM"

def header_prefix(ver, flags, ftype, channel, seq, payload_len):
    # Octets 0..20: the CRC-covered / AEAD-AAD prefix (spec/02_frame_format.md fixed-header table).
    p = bytearray(21)
    p[0:4] = MAGIC
    p[4] = ((ver & 0x0F) << 4) | (flags & 0x0F)
    p[5:7] = ftype.to_bytes(2, 'big')
    p[7:9] = channel.to_bytes(2, 'big')
    p[9:17] = seq.to_bytes(8, 'big')
    p[17:21] = payload_len.to_bytes(4, 'big')
    return bytes(p)

def derive_nonce(iv, seq):
    # nonce = iv XOR (0x00000000 || seq_BE64); Channel ID is NOT mixed in (spec/06).
    seqpad = (0).to_bytes(4, 'big') + seq.to_bytes(8, 'big')
    return bytes(a ^ b for a, b in zip(iv, seqpad))

def seal(key, iv, ver, flags, ftype, channel, seq, pt):
    aad = header_prefix(ver, flags, ftype, channel, seq, len(pt))
    nonce = derive_nonce(iv, seq)
    return AESGCM(key).encrypt(nonce, pt, aad)

def hx(b): return b.hex()

# ---------- fixed inputs (chosen here; not read from any impl) ----------
KEY = bytes(range(32))                       # 000102...1f
IV  = bytes(range(0xa0, 0xac))               # a0a1...ab (12 octets)
VER, FLAG_ENC = 0x2, 0x02

# Three valid frames spanning seq=0 (nonce==iv), a small seq (low octet into nonce), and a large seq
# whose high octets land in nonce[4..8] -- exercising the full 8-octet seq->nonce fold.
V1 = dict(ver=VER, flags=FLAG_ENC, ftype=0x0100, channel=0x0001, seq=7,
          pt=b'npamp-frame-payload')                       # MEMORY_CREATE_REQ on Memory channel
V2 = dict(ver=VER, flags=FLAG_ENC, ftype=0x0101, channel=0x000c, seq=0x00000000ff00000a,
          pt=b'stream-data-body')                          # STREAM_DATA on Stream channel, high seq
V3 = dict(ver=VER, flags=FLAG_ENC, ftype=0x0001, channel=0x0000, seq=0,
          pt=b'PING')                                      # PING on Control, seq 0 => nonce == iv

def sealed_of(v):
    return seal(KEY, IV, v['ver'], v['flags'], v['ftype'], v['channel'], v['seq'], v['pt'])

S1, S2, S3 = sealed_of(V1), sealed_of(V2), sealed_of(V3)

def seal_in(v):
    return {"suite": "AES-256-GCM", "ver": v['ver'], "flags": v['flags'], "frameType": v['ftype'],
            "channel": v['channel'], "seq": v['seq'], "key": hx(KEY), "iv": hx(IV), "pt": hx(v['pt'])}

def open_in(v, sealed):
    d = seal_in(v); del d['pt']; d['sealed'] = hx(sealed); return d

def tc(tcid, req, comment, in_, result, expected=None, flags=None):
    o = {"tcId": tcid, "requirement": req, "comment": comment, "in": in_, "result": result}
    if expected is not None: o["expected"] = expected
    if flags is not None: o["flags"] = flags
    return o

seal_tests = [
    tc(1, "02/4.2/aead-aad-header-prefix", "seal binds the 21-octet header prefix as AAD (Memory, seq 7)",
       seal_in(V1), "valid", {"sealed": hx(S1)}),
    tc(2, "06/nonce/seq-into-nonce", "seal folds a large 8-octet seq into the nonce (Stream, seq 0xff00000a)",
       seal_in(V2), "valid", {"sealed": hx(S2)}),
    tc(3, "06/nonce/seq-zero-nonce-equals-iv", "seq 0 => nonce == iv (Control PING)",
       seal_in(V3), "valid", {"sealed": hx(S3)}),
]

# MUST-reject open vectors: each presents V1's ciphertext but with one field perturbed so the
# reconstructed AAD or nonce diverges, or the tag/ciphertext is corrupted -> AEAD open MUST fail.
V1_BADCHAN = dict(V1); V1_BADCHAN['channel'] = 0x0002       # AAD (header) mismatch
V1_BADSEQ  = dict(V1); V1_BADSEQ['seq'] = 8                  # nonce mismatch
S1_BADTAG  = bytearray(S1); S1_BADTAG[-1] ^= 0x01           # flipped tag nibble
S1_BADCT   = bytearray(S1); S1_BADCT[0] ^= 0x80             # flipped ciphertext bit

open_tests = [
    tc(1, "02/4.2/aead-open-roundtrip", "open recovers the payload sealed under the header-prefix AAD",
       open_in(V1, S1), "valid", {"pt": hx(V1['pt'])}),
    tc(2, "06/nonce/seq-zero-open", "open a seq-0 frame (nonce == iv)",
       open_in(V3, S3), "valid", {"pt": hx(V3['pt'])}),
    tc(3, "02/4.2/tampered-aad-MUST-reject", "open with a tampered header field (channel 0x0001->0x0002): AAD mismatch",
       open_in(V1_BADCHAN, S1), "invalid", None, ["MustReject", "AeadAadMismatch"]),
    tc(4, "06/nonce/wrong-seq-MUST-reject", "open with the wrong sequence number (7->8): nonce mismatch",
       open_in(V1_BADSEQ, S1), "invalid", None, ["MustReject", "AeadNonceMismatch"]),
    tc(5, "02/4.2/tampered-tag-MUST-reject", "open with a flipped AEAD tag nibble",
       open_in(V1, bytes(S1_BADTAG)), "invalid", None, ["MustReject", "AeadTagMismatch"]),
    tc(6, "02/4.2/tampered-ciphertext-MUST-reject", "open with a flipped ciphertext bit",
       open_in(V1, bytes(S1_BADCT)), "invalid", None, ["MustReject", "AeadCiphertextTamper"]),
]

groups = [
    {"op": "frame.seal", "profile": "any", "tests": seal_tests},
    {"op": "frame.open", "profile": "any", "tests": open_tests},
]
json.dump(groups, sys.stdout, indent=2)
sys.stdout.write("\n")
