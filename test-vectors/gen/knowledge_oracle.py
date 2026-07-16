#!/usr/bin/env python3
# Independent RFC 8949 canonical-CBOR oracle + NPAMP-KNOWLEDGE conformance-vector generator.
#
# NON-CIRCULARITY (test-vectors/README.md; 55_conformance_requirements.md §5.2): the canonical CBOR
# bytes and expected values in the emitted vectors are produced by THIS from-scratch encoder, derived
# from RFC 8949 §4.2 (core-deterministic encoding) and the key tables in
# spec/companion/8b_knowledge_channel.md §4-§6/§9 -- NOT dumped from impl/go (the implementation under
# test). A passing knowledge.body.* vector therefore proves the Go impl AGREES with an independent
# oracle; it does not grade the impl against its own output.
#
# The MUST-reject cases carry no `expected` (schema omits it for result:"invalid") and are the spec's
# own MUST-reject list (8b §4.1/§4.2/§4.3/§5.1/§6.5) crafted as deliberately non-canonical or
# structurally-invalid CBOR -- inherently non-circular.
#
# Grading scope: the structural wire contract (the §4 payload + §4.2 envelope MUST-reject clauses, the
# §4.3 forward-compat key rule, and the §6.5 "a KNOWLEDGE_UPDATE MUST carry at least one of `results`
# or `removed`" cross-field rule). The advisory FLOAT fields (`min_score`, `score`; §6.1/§6.2/§6.4)
# lie outside the deterministic-CBOR integer/text/bytes/bool/array/map subset this rail's codec
# validates, so -- as with NPAMP-STREAM/NPAMP-MEMORY -- no valid vector here carries a float. Semantic
# §5/§7/§8/§10 behaviour (correlation across streams, subscription state machine, per-subscription
# credit) is not graded by a body-decode oracle and remains spec-audited pending a live-exchange
# harness.
#
# Run: python3 test-vectors/gen/knowledge_oracle.py  -> writes knowledge testGroups to stdout as JSON.
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

def c_array(items):
    out = _head(4, len(items))
    for it in items:
        out += it
    return out

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

# ---------- NPAMP-KNOWLEDGE frame types + envelope (8b §3.1, §4.2) ----------
KNOWLEDGE_QUERY_REQ         = 0x0100
KNOWLEDGE_QUERY_RESULT      = 0x0101
KNOWLEDGE_QUERY_STREAM_DATA = 0x0102
KNOWLEDGE_QUERY_STREAM_END  = 0x0103
KNOWLEDGE_SUBSCRIBE_REQ     = 0x0104
KNOWLEDGE_SUBSCRIBE_ACK     = 0x0105
KNOWLEDGE_UPDATE            = 0x0106
KNOWLEDGE_CREDIT            = 0x0107
KNOWLEDGE_UNSUBSCRIBE       = 0x0108
KNOWLEDGE_ERROR             = 0x0109

CORR  = b'\x71'          # 1-byte correlation token (§4.2: byte string 1-64 B)
SUBID = b'\x01\x02'      # 2-byte subscription id (§6.4: byte string 1-32 B)

# A knowledge_result projection (§6.2): result_id(0)+content(1) REQUIRED; source(4) provenance.
def knowledge_result():
    return c_map({0: c_text('doc-1'), 1: c_text('the retrieved content'), 4: c_text('corpus-a')})

# ---------- VALID bodies (8b §4.2 envelope + §6/§9 per-frame required keys) ----------
# (v1) KNOWLEDGE_QUERY_REQ envelope-only: every §6.1 body field is OPTIONAL, so envelope alone is valid.
VALID_QUERY_MIN = c_map({0: c_uint(KNOWLEDGE_QUERY_REQ), 1: c_bytes(CORR)})
# (v2) KNOWLEDGE_QUERY_REQ with body scoping fields: query(2,text)+source(3,text)+limit(6,uint).
VALID_QUERY_FULL = c_map({0: c_uint(KNOWLEDGE_QUERY_REQ), 1: c_bytes(CORR),
                          2: c_text('vector databases'), 3: c_text('corpus-a'), 6: c_uint(10)})
# (v3) KNOWLEDGE_QUERY_RESULT: results(2,array of knowledge_result) REQUIRED + has_more(3,bool) REQUIRED.
VALID_RESULT = c_map({0: c_uint(KNOWLEDGE_QUERY_RESULT), 1: c_bytes(CORR),
                      2: c_array([knowledge_result()]), 3: b'\xf4'})  # has_more=false
# (v4) KNOWLEDGE_SUBSCRIBE_REQ: credit(9,uint) REQUIRED (>=1); query(2,text) optional.
VALID_SUBSCRIBE = c_map({0: c_uint(KNOWLEDGE_SUBSCRIBE_REQ), 1: c_bytes(CORR),
                         2: c_text('standing query'), 9: c_uint(4)})
# (v5) KNOWLEDGE_SUBSCRIBE_ACK: sub_id(2,bytes) REQUIRED + credit(3,uint) REQUIRED.
VALID_SUB_ACK = c_map({0: c_uint(KNOWLEDGE_SUBSCRIBE_ACK), 1: c_bytes(CORR),
                       2: c_bytes(SUBID), 3: c_uint(4)})
# (v6) KNOWLEDGE_UPDATE (removed-only): sub_id(2)+update_seq(3) REQUIRED; removed(5) present (§6.5).
VALID_UPDATE_REMOVED = c_map({0: c_uint(KNOWLEDGE_UPDATE), 1: c_bytes(CORR),
                              2: c_bytes(SUBID), 3: c_uint(7), 5: c_array([c_text('doc-9')])})
# (v7) KNOWLEDGE_UPDATE (results-present): sub_id(2)+update_seq(3) REQUIRED; results(4) present (§6.5).
VALID_UPDATE_RESULTS = c_map({0: c_uint(KNOWLEDGE_UPDATE), 1: c_bytes(CORR),
                              2: c_bytes(SUBID), 3: c_uint(8), 4: c_array([knowledge_result()])})
# (v8) KNOWLEDGE_ERROR: code(2,uint) REQUIRED + message(3,text) REQUIRED (§9).
VALID_ERROR = c_map({0: c_uint(KNOWLEDGE_ERROR), 1: c_bytes(CORR),
                     2: c_uint(1), 3: c_text('malformed request')})
# Forward-compat: an unknown NON-NEGATIVE key (99) MUST be accepted (§4.3).
FWD_COMPAT = c_map({0: c_uint(KNOWLEDGE_QUERY_REQ), 1: c_bytes(CORR), 99: c_text('future-field')})

# ---------- MUST-reject bodies (8b §4.1/§4.2/§4.3/§5.1/§6.5) -- crafted invalid, no oracle output ----
# (r1) non-deterministic CBOR: key 0 encoded in non-shortest form (0x18 0x00 instead of 0x00). §4.1
NONSHORTEST_KEY = bytes([0xa1, 0x18, 0x00, 0x00])
# (r2) unknown NEGATIVE key (-1 = 0x20) on an otherwise-valid QUERY_REQ. §4.3 -> reject. Build the
#      canonical 3-entry map then splice a 4th entry (-1 -> 9) after the last key (-1 sorts after the
#      non-negative keys because 0x20 is bytewise-greater than 0x00..0x02) and bump 0xa3 -> 0xa4.
UNKNOWN_NEG_KEY = c_map({0: c_uint(KNOWLEDGE_QUERY_REQ), 1: c_bytes(CORR), 2: c_text('x')})
UNKNOWN_NEG_KEY = bytes([0xa4]) + UNKNOWN_NEG_KEY[1:] + c_nint(-1) + c_uint(9)
# (r3) missing REQUIRED credit(9) on a SUBSCRIBE_REQ. §6.4 -> reject.
MISSING_CREDIT = c_map({0: c_uint(KNOWLEDGE_SUBSCRIBE_REQ), 1: c_bytes(CORR), 2: c_text('q')})
# (r4) wrong CBOR major type for credit(9) (text where an unsigned int is required). §6.4 -> reject.
WRONG_TYPE_CREDIT = c_map({0: c_uint(KNOWLEDGE_SUBSCRIBE_REQ), 1: c_bytes(CORR), 9: c_text('x')})
# (r5) frame_kind contradicts the frame header: body says QUERY_RESULT but validated as QUERY_REQ. §4.2
FRAMEKIND_MISMATCH = c_map({0: c_uint(KNOWLEDGE_QUERY_RESULT), 1: c_bytes(CORR)})
# (r6) corr(1) is an unsigned int, not the required byte string. §4.2 -> reject.
CORR_NOT_BYTES = c_map({0: c_uint(KNOWLEDGE_QUERY_REQ), 1: c_uint(5)})
# (r7) corr(1) is an empty byte string (violates the 1-64 B, non-empty envelope rule). §4.2/§5.1
EMPTY_CORR = c_map({0: c_uint(KNOWLEDGE_QUERY_REQ), 1: c_bytes(b'')})
# (r8) KNOWLEDGE_UPDATE carrying neither results(4) nor removed(5). §6.5 -> reject (malformed).
UPDATE_NEITHER = c_map({0: c_uint(KNOWLEDGE_UPDATE), 1: c_bytes(CORR), 2: c_bytes(SUBID), 3: c_uint(1)})
# (r9) missing REQUIRED corr(1) envelope key on a QUERY_REQ. §4.2 -> reject.
MISSING_CORR = c_map({0: c_uint(KNOWLEDGE_QUERY_REQ)})
# (r10) payload is not a map at all (a bare uint). §4.1 -> reject.
NOT_A_MAP = c_uint(5)

def dec(tcid, req, comment, frame_type, body_hex, result, expected=None, flags=None):
    o = {"tcId": tcid, "requirement": req, "comment": comment,
         "in": {"frameType": frame_type, "body": body_hex}, "result": result}
    if expected is not None: o["expected"] = expected
    if flags is not None: o["flags"] = flags
    return o

decode_tests = [
    dec(1, "8b/4.2/deterministic-cbor-map", "valid KNOWLEDGE_QUERY_REQ: envelope only (all §6.1 body fields optional)",
        KNOWLEDGE_QUERY_REQ, hx(VALID_QUERY_MIN), "valid",
        {"frame_kind": KNOWLEDGE_QUERY_REQ, "corr": hx(CORR)}),
    dec(2, "8b/6.1/query-scoping-fields", "valid KNOWLEDGE_QUERY_REQ: query + source + limit",
        KNOWLEDGE_QUERY_REQ, hx(VALID_QUERY_FULL), "valid",
        {"frame_kind": KNOWLEDGE_QUERY_REQ, "corr": hx(CORR)}),
    dec(3, "8b/6.2/query-result-required-keys", "valid KNOWLEDGE_QUERY_RESULT: results array + has_more",
        KNOWLEDGE_QUERY_RESULT, hx(VALID_RESULT), "valid",
        {"frame_kind": KNOWLEDGE_QUERY_RESULT, "corr": hx(CORR)}),
    dec(4, "8b/6.4/subscribe-req-credit-required", "valid KNOWLEDGE_SUBSCRIBE_REQ: credit present",
        KNOWLEDGE_SUBSCRIBE_REQ, hx(VALID_SUBSCRIBE), "valid",
        {"frame_kind": KNOWLEDGE_SUBSCRIBE_REQ, "corr": hx(CORR)}),
    dec(5, "8b/6.4/subscribe-ack-required-keys", "valid KNOWLEDGE_SUBSCRIBE_ACK: sub_id + credit",
        KNOWLEDGE_SUBSCRIBE_ACK, hx(VALID_SUB_ACK), "valid",
        {"frame_kind": KNOWLEDGE_SUBSCRIBE_ACK, "corr": hx(CORR)}),
    dec(6, "8b/6.5/update-removed-only", "valid KNOWLEDGE_UPDATE: removed present (results absent)",
        KNOWLEDGE_UPDATE, hx(VALID_UPDATE_REMOVED), "valid",
        {"frame_kind": KNOWLEDGE_UPDATE, "corr": hx(CORR)}),
    dec(7, "8b/6.5/update-results-present", "valid KNOWLEDGE_UPDATE: results present (removed absent)",
        KNOWLEDGE_UPDATE, hx(VALID_UPDATE_RESULTS), "valid",
        {"frame_kind": KNOWLEDGE_UPDATE, "corr": hx(CORR)}),
    dec(8, "8b/9/error-required-keys", "valid KNOWLEDGE_ERROR: code + message",
        KNOWLEDGE_ERROR, hx(VALID_ERROR), "valid",
        {"frame_kind": KNOWLEDGE_ERROR, "corr": hx(CORR)}),
    dec(9, "8b/4.3/forward-compat-accept-nonneg", "unknown NON-negative key (99) MUST be accepted",
        KNOWLEDGE_QUERY_REQ, hx(FWD_COMPAT), "acceptable",
        {"frame_kind": KNOWLEDGE_QUERY_REQ, "corr": hx(CORR)}, ["ForwardCompat"]),
    dec(10, "8b/4.1/non-deterministic-cbor-MUST-reject", "key 0 in non-shortest form (0x18 0x00)",
        KNOWLEDGE_QUERY_REQ, hx(NONSHORTEST_KEY), "invalid", None, ["MustReject", "NonDeterministicCBOR"]),
    dec(11, "8b/4.3/unknown-negative-key-MUST-reject", "unknown NEGATIVE integer key (-1)",
        KNOWLEDGE_QUERY_REQ, hx(UNKNOWN_NEG_KEY), "invalid", None, ["MustReject", "UnknownNegativeKey"]),
    dec(12, "8b/6.4/missing-required-key-MUST-reject", "KNOWLEDGE_SUBSCRIBE_REQ missing REQUIRED credit(9)",
        KNOWLEDGE_SUBSCRIBE_REQ, hx(MISSING_CREDIT), "invalid", None, ["MustReject", "MissingRequiredKey"]),
    dec(13, "8b/6.4/wrong-major-type-MUST-reject", "credit(9) is text where an unsigned int is required",
        KNOWLEDGE_SUBSCRIBE_REQ, hx(WRONG_TYPE_CREDIT), "invalid", None, ["MustReject", "WrongMajorType"]),
    dec(14, "8b/4.2/frame-kind-mismatch-MUST-reject", "frame_kind says QUERY_RESULT(0x0101) but frame is QUERY_REQ(0x0100)",
        KNOWLEDGE_QUERY_REQ, hx(FRAMEKIND_MISMATCH), "invalid", None, ["MustReject", "FrameKindMismatch"]),
    dec(15, "8b/4.2/corr-not-bytes-MUST-reject", "corr(1) is an unsigned int, not the required byte string",
        KNOWLEDGE_QUERY_REQ, hx(CORR_NOT_BYTES), "invalid", None, ["MustReject", "EnvelopeWrongType"]),
    dec(16, "8b/4.2/corr-empty-MUST-reject", "corr(1) is an empty byte string (violates 1-64 B non-empty)",
        KNOWLEDGE_QUERY_REQ, hx(EMPTY_CORR), "invalid", None, ["MustReject", "EnvelopeWrongType"]),
    dec(17, "8b/6.5/update-neither-MUST-reject", "KNOWLEDGE_UPDATE carries neither results(4) nor removed(5)",
        KNOWLEDGE_UPDATE, hx(UPDATE_NEITHER), "invalid", None, ["MustReject", "UpdateNeitherResultsNorRemoved"]),
    dec(18, "8b/4.2/missing-corr-MUST-reject", "KNOWLEDGE_QUERY_REQ missing REQUIRED corr(1) envelope key",
        KNOWLEDGE_QUERY_REQ, hx(MISSING_CORR), "invalid", None, ["MustReject", "MissingRequiredKey"]),
    dec(19, "8b/4.1/payload-not-a-map-MUST-reject", "payload is a bare uint, not a CBOR map",
        KNOWLEDGE_QUERY_REQ, hx(NOT_A_MAP), "invalid", None, ["MustReject", "NotAMap"]),
]

# Only knowledge.body.decode is emitted: its `in` is flat (frameType + hex body), so adapters that do
# not implement it skip gracefully (Unimplemented) rather than erroring on a nested-typed input. It
# grades the core wire contract (the §4 MUST-reject clauses + envelope decode incl. the KNOWLEDGE
# corr-is-bytes envelope and the §6.5 UPDATE results-or-removed cross-field rule). Canonical ENCODING
# is covered by the reference impl's own cross-validation test (zz_knowledge_oracle_xval_test.go).
groups = [
    {"op": "knowledge.body.decode", "profile": "Standard", "tests": decode_tests},
]
json.dump(groups, sys.stdout, indent=2)
sys.stdout.write("\n")
