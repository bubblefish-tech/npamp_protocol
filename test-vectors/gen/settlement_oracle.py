#!/usr/bin/env python3
# Independent RFC 8949 canonical-CBOR oracle + NPAMP-SETTLEMENT conformance-vector generator.
#
# NON-CIRCULARITY (test-vectors/README.md; 55_conformance_requirements.md §5.2): the canonical CBOR
# bytes and expected values in the emitted vectors are produced by THIS from-scratch encoder, derived
# from RFC 8949 §4.2 (core-deterministic encoding) and the key tables in
# spec/companion/86_settlement_channel.md §4-§8 -- NOT dumped from impl/go (the implementation under
# test). A passing settlement.body.* vector therefore proves the Go impl AGREES with an independent
# oracle; it does not grade the impl against its own output.
#
# The MUST-reject cases carry no `expected` (schema omits it for result:"invalid") and are the spec's
# own MUST-reject list (86 §4.1/§4.2/§4.3/§5.3) crafted as deliberately non-canonical or
# structurally-invalid CBOR -- inherently non-circular.
#
# Run: python3 test-vectors/gen/settlement_oracle.py  -> writes settlement testGroups to stdout as JSON.
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

# ---------- NPAMP-SETTLEMENT frame types + envelope (86 §3, §4.2) ----------
SETTLE_INTENT_REQ         = 0x0100
SETTLE_INTENT_RESULT      = 0x0101
RECEIPT_REQ               = 0x0102
RECEIPT_RESULT            = 0x0103
SETTLE_ERROR              = 0x0104
SETTLE_BATCH_COMMIT_REQ   = 0x00A0
SETTLE_BATCH_COMMIT_RESULT = 0x00A1

# corr (key 1): a byte string of 1-64 bytes (§4.2), like NPAMP-MEMORY's corr and unlike NPAMP-STREAM's
# Unsigned-int sub_stream_id. Present on every *_REQ and on every frame that replies to one (§5).
CORR = b'\x01\x02\x03\x04'
# Effect classes (§5.3): read_only=0x00, idempotent_write=0x01, non_idempotent_write=0x02.

# ---------- valid operation bodies (86 §6, §8) ----------
# SETTLE_INTENT_REQ (§6.1): envelope + REQUIRED obligation_ref(2,text) + effect(8,uint).
def intent_req_body(extra=None):
    d = {0: c_uint(SETTLE_INTENT_REQ), 1: c_bytes(CORR),
         2: c_text('obligation:invoice-42'), 8: c_uint(0x02)}
    if extra:
        d.update(extra)
    return c_map(d)

# SETTLE_INTENT_RESULT (§6.1): envelope + REQUIRED settlement_ref(2,text) + status(3,text).
def intent_result_body():
    return c_map({0: c_uint(SETTLE_INTENT_RESULT), 1: c_bytes(CORR),
                  2: c_text('settlement:s-001'), 3: c_text('settled')})

# RECEIPT_REQ (§6.2): envelope + REQUIRED settlement_ref(2,text) + effect(4,uint=read_only).
def receipt_req_body():
    return c_map({0: c_uint(RECEIPT_REQ), 1: c_bytes(CORR),
                  2: c_text('settlement:s-001'), 4: c_uint(0x00)})

# RECEIPT_RESULT (§6.2): envelope + REQUIRED receipt(2,map). The nested settlement_receipt carries
# its REQUIRED receipt_ref(0), settlement_ref(1), status(5) (keys start at 0, no envelope).
def receipt_result_body():
    receipt = c_map({0: c_text('receipt:r-001'), 1: c_text('settlement:s-001'), 5: c_text('settled')})
    return c_map({0: c_uint(RECEIPT_RESULT), 1: c_bytes(CORR), 2: receipt})

# SETTLE_ERROR (§8): envelope + REQUIRED code(2,uint) + message(3,text). For approval_required
# (code 4, §8.1) approval_id(5,text) is present -- a governance escalation held for human approval.
def settle_error_body():
    return c_map({0: c_uint(SETTLE_ERROR), 1: c_bytes(CORR),
                  2: c_uint(4), 3: c_text('approval required'), 5: c_text('approval:a-001')})

# SETTLE_BATCH_COMMIT_REQ (§6.3): envelope + REQUIRED batch_ref(2,text) + commitment(3,bytes) +
# effect(7,uint). commitment is opaque octets (the construction is NOT fixed by this document).
def batch_commit_req_body():
    return c_map({0: c_uint(SETTLE_BATCH_COMMIT_REQ), 1: c_bytes(CORR),
                  2: c_text('batch:b-2026-07'), 3: c_bytes(bytes.fromhex('deadbeef')), 7: c_uint(0x02)})

# SETTLE_BATCH_COMMIT_RESULT (§6.3): envelope + REQUIRED batch_ref(2,text) + status(3,text).
def batch_commit_result_body():
    return c_map({0: c_uint(SETTLE_BATCH_COMMIT_RESULT), 1: c_bytes(CORR),
                  2: c_text('batch:b-2026-07'), 3: c_text('committed')})

VALID_INTENT_REQ           = intent_req_body()
VALID_INTENT_RESULT        = intent_result_body()
VALID_RECEIPT_REQ          = receipt_req_body()
VALID_RECEIPT_RESULT       = receipt_result_body()
VALID_SETTLE_ERROR         = settle_error_body()
VALID_BATCH_COMMIT_REQ     = batch_commit_req_body()
VALID_BATCH_COMMIT_RESULT  = batch_commit_result_body()
# Forward-compat: an unknown NON-NEGATIVE key (99) MUST be accepted (§4.3).
FWD_COMPAT = intent_req_body({99: c_text('future-field')})

# ---------- MUST-reject bodies (86 §4.1/§4.2/§4.3/§5.3) -- crafted invalid, no oracle output ----------
# (a) non-deterministic CBOR: key 0 encoded in non-shortest form (0x18 0x00 instead of 0x00). §4.1
NONSHORTEST_KEY = bytes([0xa1, 0x18, 0x00, 0x00])
# (b) unknown NEGATIVE key (-1 = 0x20) on an otherwise-valid SETTLE_INTENT_REQ. §4.3 -> reject.
#     Build the 4-key body canonically then splice a 5th entry (-1 -> 9) AFTER the last key (-1 sorts
#     after non-negative keys because 0x20 is bytewise-greater than 0x00..0x08) and bump 0xa4 -> 0xa5.
UNKNOWN_NEG_KEY = c_map({0: c_uint(SETTLE_INTENT_REQ), 1: c_bytes(CORR), 2: c_text('x'), 8: c_uint(0x02)})
UNKNOWN_NEG_KEY = bytes([0xa5]) + UNKNOWN_NEG_KEY[1:] + c_nint(-1) + c_uint(9)
# (c) missing REQUIRED obligation_ref(2) on a SETTLE_INTENT_REQ. §4.1/§6.1 -> reject.
MISSING_OBLIGATION_REF = c_map({0: c_uint(SETTLE_INTENT_REQ), 1: c_bytes(CORR), 8: c_uint(0x02)})
# (d) wrong CBOR major type for obligation_ref (uint where text is required). §4.1 -> reject.
WRONG_TYPE_OBLIGATION_REF = c_map({0: c_uint(SETTLE_INTENT_REQ), 1: c_bytes(CORR), 2: c_uint(9), 8: c_uint(0x02)})
# (e) missing REQUIRED effect(8) on a state-mutating SETTLE_INTENT_REQ. §5.3/§6.1 -> reject
#     (fail-safe: a mutating request that omits effect is treated as destructive and MAY be refused).
MISSING_EFFECT = c_map({0: c_uint(SETTLE_INTENT_REQ), 1: c_bytes(CORR), 2: c_text('x')})
# (f) frame_kind contradicts the frame header: body says RECEIPT_REQ but validated as SETTLE_INTENT_REQ. §4.2
FRAMEKIND_MISMATCH = c_map({0: c_uint(RECEIPT_REQ), 1: c_bytes(CORR), 2: c_text('x'), 8: c_uint(0x02)})
# (g) corr(1) is an Unsigned int, not the required byte string (§4.2). -> reject.
CORR_NOT_BYTES = c_map({0: c_uint(SETTLE_INTENT_REQ), 1: c_uint(4), 2: c_text('x'), 8: c_uint(0x02)})
# (h) corr(1) is an EMPTY byte string; §4.2 requires a non-empty 1-64-byte corr. -> reject.
CORR_EMPTY = c_map({0: c_uint(SETTLE_INTENT_REQ), 1: c_bytes(b''), 2: c_text('x'), 8: c_uint(0x02)})
# (i) missing REQUIRED commitment(3) on a SETTLE_BATCH_COMMIT_REQ. §6.3 -> reject.
BATCH_MISSING_COMMITMENT = c_map({0: c_uint(SETTLE_BATCH_COMMIT_REQ), 1: c_bytes(CORR),
                                  2: c_text('batch:b-1'), 7: c_uint(0x02)})
# (j) payload is not a map at all (a bare uint). §4.1 -> reject.
NOT_A_MAP = c_uint(5)

def dec(tcid, req, comment, frame_type, body_hex, result, expected=None, flags=None):
    o = {"tcId": tcid, "requirement": req, "comment": comment,
         "in": {"frameType": frame_type, "body": body_hex}, "result": result}
    if expected is not None: o["expected"] = expected
    if flags is not None: o["flags"] = flags
    return o

decode_tests = [
    dec(1, "86/4.1/deterministic-cbor-map", "valid SETTLE_INTENT_REQ: envelope + obligation_ref + effect",
        SETTLE_INTENT_REQ, hx(VALID_INTENT_REQ), "valid", {"frame_kind": SETTLE_INTENT_REQ, "corr": hx(CORR)}),
    dec(2, "86/6.1/settle-intent-result", "valid SETTLE_INTENT_RESULT: envelope + settlement_ref + status",
        SETTLE_INTENT_RESULT, hx(VALID_INTENT_RESULT), "valid", {"frame_kind": SETTLE_INTENT_RESULT, "corr": hx(CORR)}),
    dec(3, "86/6.2/receipt-req", "valid RECEIPT_REQ: envelope + settlement_ref + effect=read_only",
        RECEIPT_REQ, hx(VALID_RECEIPT_REQ), "valid", {"frame_kind": RECEIPT_REQ, "corr": hx(CORR)}),
    dec(4, "86/6.2/receipt-result", "valid RECEIPT_RESULT: envelope + settlement_receipt map",
        RECEIPT_RESULT, hx(VALID_RECEIPT_RESULT), "valid", {"frame_kind": RECEIPT_RESULT, "corr": hx(CORR)}),
    dec(5, "86/8.1/settle-error-approval-required", "valid SETTLE_ERROR: approval_required(4) carrying approval_id",
        SETTLE_ERROR, hx(VALID_SETTLE_ERROR), "valid", {"frame_kind": SETTLE_ERROR, "corr": hx(CORR)}),
    dec(6, "86/6.3/batch-commit-req", "valid SETTLE_BATCH_COMMIT_REQ: envelope + batch_ref + commitment + effect",
        SETTLE_BATCH_COMMIT_REQ, hx(VALID_BATCH_COMMIT_REQ), "valid", {"frame_kind": SETTLE_BATCH_COMMIT_REQ, "corr": hx(CORR)}),
    dec(7, "86/6.3/batch-commit-result", "valid SETTLE_BATCH_COMMIT_RESULT: envelope + batch_ref + status",
        SETTLE_BATCH_COMMIT_RESULT, hx(VALID_BATCH_COMMIT_RESULT), "valid", {"frame_kind": SETTLE_BATCH_COMMIT_RESULT, "corr": hx(CORR)}),
    dec(8, "86/4.3/forward-compat-accept-nonneg", "unknown NON-negative key (99) MUST be accepted",
        SETTLE_INTENT_REQ, hx(FWD_COMPAT), "acceptable", {"frame_kind": SETTLE_INTENT_REQ, "corr": hx(CORR)},
        ["ForwardCompat"]),
    dec(9, "86/4.1/non-deterministic-cbor-MUST-reject", "key 0 in non-shortest form (0x18 0x00)",
        SETTLE_INTENT_REQ, hx(NONSHORTEST_KEY), "invalid", None, ["MustReject", "NonDeterministicCBOR"]),
    dec(10, "86/4.3/unknown-negative-key-MUST-reject", "unknown NEGATIVE integer key (-1)",
        SETTLE_INTENT_REQ, hx(UNKNOWN_NEG_KEY), "invalid", None, ["MustReject", "UnknownNegativeKey"]),
    dec(11, "86/6.1/missing-required-key-MUST-reject", "SETTLE_INTENT_REQ missing REQUIRED obligation_ref(2)",
        SETTLE_INTENT_REQ, hx(MISSING_OBLIGATION_REF), "invalid", None, ["MustReject", "MissingRequiredKey"]),
    dec(12, "86/4.1/wrong-major-type-MUST-reject", "obligation_ref(2) is uint where text is required",
        SETTLE_INTENT_REQ, hx(WRONG_TYPE_OBLIGATION_REF), "invalid", None, ["MustReject", "WrongMajorType"]),
    dec(13, "86/5.3/missing-effect-MUST-reject", "state-mutating SETTLE_INTENT_REQ missing REQUIRED effect(8)",
        SETTLE_INTENT_REQ, hx(MISSING_EFFECT), "invalid", None, ["MustReject", "MissingRequiredKey"]),
    dec(14, "86/4.2/frame-kind-mismatch-MUST-reject", "frame_kind says RECEIPT_REQ(0x0102) but frame is SETTLE_INTENT_REQ(0x0100)",
        SETTLE_INTENT_REQ, hx(FRAMEKIND_MISMATCH), "invalid", None, ["MustReject", "FrameKindMismatch"]),
    dec(15, "86/4.2/corr-not-bytes-MUST-reject", "corr(1) is an Unsigned int, not the required byte string",
        SETTLE_INTENT_REQ, hx(CORR_NOT_BYTES), "invalid", None, ["MustReject", "EnvelopeWrongType"]),
    dec(16, "86/4.2/corr-empty-MUST-reject", "corr(1) is an empty byte string; a non-empty 1-64-byte corr is required",
        SETTLE_INTENT_REQ, hx(CORR_EMPTY), "invalid", None, ["MustReject", "EnvelopeWrongType"]),
    dec(17, "86/6.3/batch-missing-commitment-MUST-reject", "SETTLE_BATCH_COMMIT_REQ missing REQUIRED commitment(3)",
        SETTLE_BATCH_COMMIT_REQ, hx(BATCH_MISSING_COMMITMENT), "invalid", None, ["MustReject", "MissingRequiredKey"]),
    dec(18, "86/4.1/payload-not-a-map-MUST-reject", "payload is a bare uint, not a CBOR map",
        SETTLE_INTENT_REQ, hx(NOT_A_MAP), "invalid", None, ["MustReject", "NotAMap"]),
]

# Only settlement.body.decode is emitted: its `in` is flat (frameType + hex body), so adapters that do
# not implement it skip gracefully (Unimplemented) rather than erroring on a nested-typed input. It
# grades the core wire contract (the §4 MUST-reject clauses + envelope decode incl. the Settlement
# byte-string corr, shared with MEMORY and divergent from STREAM). Canonical ENCODING is covered by
# the reference impl's own round-trip cross-validation test (zz_settlement_oracle_xval_test.go).
groups = [
    {"op": "settlement.body.decode", "profile": "Standard", "tests": decode_tests},
]
json.dump(groups, sys.stdout, indent=2)
sys.stdout.write("\n")
