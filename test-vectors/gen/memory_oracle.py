#!/usr/bin/env python3
# Independent RFC 8949 canonical-CBOR oracle + NPAMP-MEMORY conformance-vector generator.
#
# NON-CIRCULARITY (test-vectors/README.md; 55_conformance_requirements.md §5.2): the canonical
# CBOR bytes and expected values in the emitted vectors are produced by THIS from-scratch encoder,
# derived from RFC 8949 §4.2 (core-deterministic encoding) and the key tables in
# spec/companion/81_memory_channel.md §4 -- NOT dumped from impl/go/memory_cbor.go (the
# implementation under test). A passing memory.body.* vector therefore proves the Go impl AGREES
# with an independent oracle; it does not grade the impl against its own output.
#
# The MUST-reject cases carry no `expected` (schema omits it for result:"invalid") and are the
# spec's own MUST-reject list (81 §4.1/§4.2/§4.3/§8) crafted as deliberately non-canonical or
# structurally-invalid CBOR -- inherently non-circular.
#
# Run: python3 test-vectors/gen/memory_oracle.py  -> writes memory testGroups to stdout as JSON.
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

# ---------- NPAMP-MEMORY frame types + envelope (81 §3.1, §4.2) ----------
MEMORY_CREATE_REQ = 0x0100
MEMORY_READ_REQ   = 0x0102
CORR = b'\x63'            # 1-byte correlation id (§4.2: bytes 1-64)

# A valid MEMORY_CREATE_REQ body: envelope frame_kind(0)+corr(1) + REQUIRED content(2,text) + effect(11,uint).
def create_body(extra=None):
    d = {0: c_uint(MEMORY_CREATE_REQ), 1: c_bytes(CORR), 2: c_text('remember this'), 11: c_uint(2)}
    if extra:
        d.update(extra)
    return c_map(d)

VALID_CREATE = create_body()
# Forward-compat: an unknown NON-NEGATIVE key (99) MUST be accepted (§4.3).
FWD_COMPAT   = create_body({99: c_text('future-field')})

# ---------- MUST-reject bodies (81 §4.1/§4.2/§4.3/§8) -- crafted invalid, no oracle output ----------
# (a) non-deterministic CBOR: key 0 encoded in non-shortest form (0x18 0x00 instead of 0x00). §4.1
NONSHORTEST_KEY = bytes([0xa1, 0x18, 0x00, 0x00])
# (b) unknown NEGATIVE key (-1 = 0x20) on an otherwise-valid CREATE. §4.3 -> reject.
#     Build canonically then append a negative-keyed pair AFTER the last key (canonical order: -1 sorts
#     after non-negative keys because its encoding 0x20 is bytewise-greater than 0x00..0x63).
UNKNOWN_NEG_KEY = c_map({0: c_uint(MEMORY_CREATE_REQ), 1: c_bytes(CORR), 2: c_text('x'), 11: c_uint(2)})
# manually splice a 6th entry (-1 -> 9) and bump the map count 0xa4->0xa5 (still canonical order).
UNKNOWN_NEG_KEY = bytes([0xa5]) + UNKNOWN_NEG_KEY[1:] + c_nint(-1) + c_uint(9)
# (c) missing REQUIRED content(2) on a CREATE. §4.1 -> reject.
MISSING_CONTENT = c_map({0: c_uint(MEMORY_CREATE_REQ), 1: c_bytes(CORR), 11: c_uint(2)})
# (d) wrong CBOR major type for content (uint where text is required). §4.1 -> reject.
WRONG_TYPE_CONTENT = c_map({0: c_uint(MEMORY_CREATE_REQ), 1: c_bytes(CORR), 2: c_uint(9), 11: c_uint(2)})
# (e) frame_kind contradicts the frame header: body says READ but validated as CREATE. §4.2 -> reject.
FRAMEKIND_MISMATCH = c_map({0: c_uint(MEMORY_READ_REQ), 1: c_bytes(CORR), 2: c_text('x'), 11: c_uint(2)})
# (f) payload is not a map at all (a bare uint). §4.1 -> reject.
NOT_A_MAP = c_uint(5)

def dec(tcid, req, comment, frame_type, body_hex, result, expected=None, flags=None):
    o = {"tcId": tcid, "requirement": req, "comment": comment,
         "in": {"frameType": frame_type, "body": body_hex}, "result": result}
    if expected is not None: o["expected"] = expected
    if flags is not None: o["flags"] = flags
    return o

decode_tests = [
    dec(1, "81/4.1/deterministic-cbor-map", "valid MEMORY_CREATE_REQ: envelope + content + effect",
        MEMORY_CREATE_REQ, hx(VALID_CREATE), "valid", {"frame_kind": MEMORY_CREATE_REQ, "corr": hx(CORR)}),
    dec(2, "81/4.3/forward-compat-accept-nonneg", "unknown NON-negative key (99) MUST be accepted",
        MEMORY_CREATE_REQ, hx(FWD_COMPAT), "acceptable", {"frame_kind": MEMORY_CREATE_REQ, "corr": hx(CORR)},
        ["ForwardCompat"]),
    dec(3, "81/4.1/non-deterministic-cbor-MUST-reject", "key 0 in non-shortest form (0x18 0x00)",
        MEMORY_CREATE_REQ, hx(NONSHORTEST_KEY), "invalid", None, ["MustReject", "NonDeterministicCBOR"]),
    dec(4, "81/4.3/unknown-negative-key-MUST-reject", "unknown NEGATIVE integer key (-1)",
        MEMORY_CREATE_REQ, hx(UNKNOWN_NEG_KEY), "invalid", None, ["MustReject", "UnknownNegativeKey"]),
    dec(5, "81/4.1/missing-required-key-MUST-reject", "MEMORY_CREATE_REQ missing REQUIRED content(2)",
        MEMORY_CREATE_REQ, hx(MISSING_CONTENT), "invalid", None, ["MustReject", "MissingRequiredKey"]),
    dec(6, "81/4.1/wrong-major-type-MUST-reject", "content(2) is uint where text is required",
        MEMORY_CREATE_REQ, hx(WRONG_TYPE_CONTENT), "invalid", None, ["MustReject", "WrongMajorType"]),
    dec(7, "81/4.2/frame-kind-mismatch-MUST-reject", "frame_kind says READ(0x0102) but frame is CREATE(0x0100)",
        MEMORY_CREATE_REQ, hx(FRAMEKIND_MISMATCH), "invalid", None, ["MustReject", "FrameKindMismatch"]),
    dec(8, "81/4.1/payload-not-a-map-MUST-reject", "payload is a bare uint, not a CBOR map",
        MEMORY_CREATE_REQ, hx(NOT_A_MAP), "invalid", None, ["MustReject", "NotAMap"]),
]

# ---------- memory.body.encode: independent oracle asserts canonical output ----------
# `in.entries` is an ordered list [type, key, value]; the adapter builds the map and encodes it,
# and the runner compares the produced hex to `expected.body` (this oracle's canonical bytes).
def enc(tcid, req, comment, entries, expected_hex):
    return {"tcId": tcid, "requirement": req, "comment": comment,
            "in": {"entries": entries}, "expected": {"body": expected_hex}, "result": "valid"}

encode_tests = [
    enc(1, "81/4.1/canonical-key-order", "keys supplied out of order MUST encode in canonical ascending order",
        [["uint", 11, 2], ["text", 2, "remember this"], ["bytes", 1, "63"], ["uint", 0, MEMORY_CREATE_REQ]],
        hx(VALID_CREATE)),
    enc(2, "81/4.1/shortest-form-uint", "frame_kind 0x0100 MUST use shortest-form uint16 (0x19 0x01 0x00)",
        [["uint", 0, MEMORY_CREATE_REQ], ["bytes", 1, "63"]],
        hx(c_map({0: c_uint(MEMORY_CREATE_REQ), 1: c_bytes(CORR)}))),
]

# Only memory.body.decode is emitted: its `in` is flat (frameType + hex body), so adapters that
# do not implement it skip gracefully (Unimplemented) rather than erroring on a nested-typed input.
# It already grades the core wire contract (the §4 MUST-reject clauses + envelope decode); canonical
# ENCODING is covered by the reference impl's own round-trip test (memory_cbor_test.go). A dedicated
# memory.body.encode op with a minimal-adapter-safe representation can be added later.
groups = [
    {"op": "memory.body.decode", "profile": "Standard", "tests": decode_tests},
]
json.dump(groups, sys.stdout, indent=2)
sys.stdout.write("\n")
