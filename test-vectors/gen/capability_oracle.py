#!/usr/bin/env python3
# Independent RFC 8949 canonical-CBOR oracle + NPAMP-CAP conformance-vector generator.
#
# NON-CIRCULARITY (test-vectors/README.md; 55_conformance_requirements.md §5.2): the canonical
# CBOR bytes and expected values in the emitted vectors are produced by THIS from-scratch encoder,
# derived from RFC 8949 §4.2 (core-deterministic encoding) and the key tables in
# spec/companion/84_capability_channel.md §4-§6/§8 -- NOT dumped from impl/go (the implementation
# under test). A passing capability.body.* vector therefore proves the Go impl AGREES with an
# independent oracle; it does not grade the impl against its own output.
#
# The MUST-reject cases carry no `expected` (schema omits it for result:"invalid") and are the
# spec's own MUST-reject list (84 §4.1/§4.2/§4.3) crafted as deliberately non-canonical or
# structurally-invalid CBOR -- inherently non-circular.
#
# Run: python3 test-vectors/gen/capability_oracle.py  -> writes capability testGroups to stdout as JSON.
import json, sys

# ---------- independent canonical CBOR encoder (RFC 8949 §4.2) ----------
def _head(major, arg):
    mb = major << 5
    if arg < 24:      return bytes([mb | arg])
    if arg < 1 << 8:  return bytes([mb | 24, arg])
    if arg < 1 << 16: return bytes([mb | 25]) + arg.to_bytes(2, 'big')
    if arg < 1 << 32: return bytes([mb | 26]) + arg.to_bytes(4, 'big')
    return bytes([mb | 27]) + arg.to_bytes(8, 'big')

def c_uint(n):  return _head(0, n)
def c_nint(n):  return _head(1, -1 - n)          # n < 0
def c_bytes(b): return _head(2, len(b)) + b
def c_text(s):  e = s.encode('utf-8'); return _head(3, len(e)) + e

def c_map(d):
    # d: dict{int_key: value_bytes}. Canonical key order = bytewise ordering of the shortest-form
    # encoding of each key (RFC 8949 §4.2.1): shorter encoding first, then lexicographic.
    items = [(c_uint(k), v) for k, v in d.items()]
    items.sort(key=lambda kv: (len(kv[0]), kv[0]))
    out = _head(5, len(items))
    for k, v in items:
        out += k + v
    return out

def hx(b): return b.hex()

# ---------- NPAMP-CAP frame types + envelope (84 §3.1, §3.3, §4.2) ----------
CAP_ISSUE_REQ       = 0x0100
CAP_ISSUE_RESULT    = 0x0101
CAP_DELEGATE_REQ    = 0x0102
CAP_REVOKE_REQ      = 0x0104
CAP_LOOKUP_REQ      = 0x0106
CAP_ERROR           = 0x0108
CORR = b'\x7a'            # 1-byte correlation token (§4.2: byte string 1-64 B)

# Side-effect classes (§5.3): read_only=0x00, idempotent_write=0x01, non_idempotent_write=0x02,
# destructive=0x03.

# A valid CAP_ISSUE_REQ body: envelope frame_kind(0)+corr(1) + REQUIRED subject(2,text) +
# authority(3,text) + effect(9,uint non_idempotent_write). (§6.1)
def issue_body(extra=None):
    d = {0: c_uint(CAP_ISSUE_REQ), 1: c_bytes(CORR),
         2: c_text('agent-b'), 3: c_text('read:ledger'), 9: c_uint(0x02)}
    if extra:
        d.update(extra)
    return c_map(d)

# A valid CAP_DELEGATE_REQ body: envelope + REQUIRED token_id(2,text) + subject(3,text) +
# effect(7,uint). (§6.2)
def delegate_body():
    return c_map({0: c_uint(CAP_DELEGATE_REQ), 1: c_bytes(CORR),
                  2: c_text('cap-1'), 3: c_text('agent-c'), 7: c_uint(0x02)})

# A valid CAP_REVOKE_REQ body: envelope + REQUIRED token_id(2,text) + effect(5,uint destructive). (§6.3)
def revoke_body():
    return c_map({0: c_uint(CAP_REVOKE_REQ), 1: c_bytes(CORR),
                  2: c_text('cap-1'), 5: c_uint(0x03)})

# A valid CAP_LOOKUP_REQ body: envelope + REQUIRED effect(8,uint read_only). All scoping fields
# are OPTIONAL (§6.4). effect for a lookup MUST be 0x00 read_only.
def lookup_body():
    return c_map({0: c_uint(CAP_LOOKUP_REQ), 1: c_bytes(CORR), 8: c_uint(0x00)})

# A valid CAP_ERROR body: envelope + REQUIRED code(2,uint) + message(3,text). (§8)
def error_body():
    return c_map({0: c_uint(CAP_ERROR), 1: c_bytes(CORR),
                  2: c_uint(4), 3: c_text('approval required')})

VALID_ISSUE    = issue_body()
VALID_DELEGATE = delegate_body()
VALID_REVOKE   = revoke_body()
VALID_LOOKUP   = lookup_body()
VALID_ERROR    = error_body()
# Forward-compat: an unknown NON-NEGATIVE key (99) MUST be accepted (§4.3).
FWD_COMPAT     = issue_body({99: c_text('future-field')})

# ---------- MUST-reject bodies (84 §4.1/§4.2/§4.3) -- crafted invalid, no oracle output ----------
# (a) non-deterministic CBOR: key 0 encoded in non-shortest form (0x18 0x00 instead of 0x00). §4.1
NONSHORTEST_KEY = bytes([0xa1, 0x18, 0x00, 0x00])
# (b) unknown NEGATIVE key (-1 = 0x20) on an otherwise-valid ISSUE. §4.3 -> reject.
#     Build canonically then splice a negative-keyed pair AFTER the last key (-1 sorts after every
#     non-negative key because 0x20 is bytewise-greater than 0x00..0x09) and bump the map count.
UNKNOWN_NEG_KEY = c_map({0: c_uint(CAP_ISSUE_REQ), 1: c_bytes(CORR),
                         2: c_text('agent-b'), 3: c_text('read:ledger'), 9: c_uint(0x02)})
UNKNOWN_NEG_KEY = bytes([0xa6]) + UNKNOWN_NEG_KEY[1:] + c_nint(-1) + c_uint(9)
# (c) missing REQUIRED subject(2) on a CAP_ISSUE_REQ. §4.1/§6.1 -> reject.
MISSING_SUBJECT = c_map({0: c_uint(CAP_ISSUE_REQ), 1: c_bytes(CORR),
                         3: c_text('read:ledger'), 9: c_uint(0x02)})
# (d) wrong CBOR major type for subject (uint where text is required). §4.1 -> reject.
WRONG_TYPE_SUBJECT = c_map({0: c_uint(CAP_ISSUE_REQ), 1: c_bytes(CORR),
                            2: c_uint(9), 3: c_text('read:ledger'), 9: c_uint(0x02)})
# (e) frame_kind contradicts the frame header: body says ISSUE_RESULT but validated as ISSUE_REQ. §4.2
FRAMEKIND_MISMATCH = c_map({0: c_uint(CAP_ISSUE_RESULT), 1: c_bytes(CORR),
                            2: c_text('agent-b'), 3: c_text('read:ledger'), 9: c_uint(0x02)})
# (f) corr(1) is an Unsigned int, not the required byte string (§4.2 envelope type). -> reject.
CORR_WRONG_TYPE = c_map({0: c_uint(CAP_ISSUE_REQ), 1: c_uint(0x7a),
                         2: c_text('agent-b'), 3: c_text('read:ledger'), 9: c_uint(0x02)})
# (g) corr(1) is an empty byte string; §4.2 requires a non-empty 1-64 B corr. -> reject.
CORR_EMPTY = c_map({0: c_uint(CAP_ISSUE_REQ), 1: c_bytes(b''),
                    2: c_text('agent-b'), 3: c_text('read:ledger'), 9: c_uint(0x02)})
# (h) payload is not a map at all (a bare uint). §4.1 -> reject.
NOT_A_MAP = c_uint(5)

def dec(tcid, req, comment, frame_type, body_hex, result, expected=None, flags=None):
    o = {"tcId": tcid, "requirement": req, "comment": comment,
         "in": {"frameType": frame_type, "body": body_hex}, "result": result}
    if expected is not None: o["expected"] = expected
    if flags is not None: o["flags"] = flags
    return o

decode_tests = [
    dec(1, "84/4.1/deterministic-cbor-map", "valid CAP_ISSUE_REQ: envelope + subject + authority + effect",
        CAP_ISSUE_REQ, hx(VALID_ISSUE), "valid", {"frame_kind": CAP_ISSUE_REQ, "corr": hx(CORR)}),
    dec(2, "84/4.1/deterministic-cbor-map", "valid CAP_DELEGATE_REQ: envelope + token_id + subject + effect",
        CAP_DELEGATE_REQ, hx(VALID_DELEGATE), "valid", {"frame_kind": CAP_DELEGATE_REQ, "corr": hx(CORR)}),
    dec(3, "84/4.1/deterministic-cbor-map", "valid CAP_REVOKE_REQ: envelope + token_id + destructive effect",
        CAP_REVOKE_REQ, hx(VALID_REVOKE), "valid", {"frame_kind": CAP_REVOKE_REQ, "corr": hx(CORR)}),
    dec(4, "84/6.4/lookup-scoping-optional", "valid CAP_LOOKUP_REQ: envelope + read_only effect, no scoping filter",
        CAP_LOOKUP_REQ, hx(VALID_LOOKUP), "valid", {"frame_kind": CAP_LOOKUP_REQ, "corr": hx(CORR)}),
    dec(5, "84/8/error-frame", "valid CAP_ERROR: envelope + code + message",
        CAP_ERROR, hx(VALID_ERROR), "valid", {"frame_kind": CAP_ERROR, "corr": hx(CORR)}),
    dec(6, "84/4.3/forward-compat-accept-nonneg", "unknown NON-negative key (99) MUST be accepted",
        CAP_ISSUE_REQ, hx(FWD_COMPAT), "acceptable", {"frame_kind": CAP_ISSUE_REQ, "corr": hx(CORR)},
        ["ForwardCompat"]),
    dec(7, "84/4.1/non-deterministic-cbor-MUST-reject", "key 0 in non-shortest form (0x18 0x00)",
        CAP_ISSUE_REQ, hx(NONSHORTEST_KEY), "invalid", None, ["MustReject", "NonDeterministicCBOR"]),
    dec(8, "84/4.3/unknown-negative-key-MUST-reject", "unknown NEGATIVE integer key (-1)",
        CAP_ISSUE_REQ, hx(UNKNOWN_NEG_KEY), "invalid", None, ["MustReject", "UnknownNegativeKey"]),
    dec(9, "84/4.1/missing-required-key-MUST-reject", "CAP_ISSUE_REQ missing REQUIRED subject(2)",
        CAP_ISSUE_REQ, hx(MISSING_SUBJECT), "invalid", None, ["MustReject", "MissingRequiredKey"]),
    dec(10, "84/4.1/wrong-major-type-MUST-reject", "subject(2) is uint where text is required",
        CAP_ISSUE_REQ, hx(WRONG_TYPE_SUBJECT), "invalid", None, ["MustReject", "WrongMajorType"]),
    dec(11, "84/4.2/frame-kind-mismatch-MUST-reject", "frame_kind says ISSUE_RESULT(0x0101) but frame is ISSUE_REQ(0x0100)",
        CAP_ISSUE_REQ, hx(FRAMEKIND_MISMATCH), "invalid", None, ["MustReject", "FrameKindMismatch"]),
    dec(12, "84/4.2/corr-not-byte-string-MUST-reject", "corr(1) is an Unsigned int, not the required byte string",
        CAP_ISSUE_REQ, hx(CORR_WRONG_TYPE), "invalid", None, ["MustReject", "EnvelopeWrongType"]),
    dec(13, "84/4.2/corr-empty-MUST-reject", "corr(1) is an empty byte string; a non-empty 1-64 B corr is required",
        CAP_ISSUE_REQ, hx(CORR_EMPTY), "invalid", None, ["MustReject", "EnvelopeEmptyCorr"]),
    dec(14, "84/4.1/payload-not-a-map-MUST-reject", "payload is a bare uint, not a CBOR map",
        CAP_ISSUE_REQ, hx(NOT_A_MAP), "invalid", None, ["MustReject", "NotAMap"]),
]

# Only capability.body.decode is emitted: its `in` is flat (frameType + hex body), so adapters that
# do not implement it skip gracefully (Unimplemented) rather than erroring on a nested-typed input.
# It grades the core wire contract for the Capability channel (the §4 MUST-reject clauses + common-
# envelope decode incl. the byte-string corr type + non-empty corr divergence). Canonical ENCODING is
# covered by the reference impl's own round-trip test (zz_capability_oracle_xval_test.go).
groups = [
    {"op": "capability.body.decode", "profile": "Standard", "tests": decode_tests},
]
json.dump(groups, sys.stdout, indent=2)
sys.stdout.write("\n")
