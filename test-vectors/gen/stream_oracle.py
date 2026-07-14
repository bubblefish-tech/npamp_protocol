#!/usr/bin/env python3
# Independent RFC 8949 canonical-CBOR oracle + NPAMP-STREAM conformance-vector generator.
#
# NON-CIRCULARITY (test-vectors/README.md; 55_conformance_requirements.md §5.2): the canonical CBOR
# bytes and expected values in the emitted vectors are produced by THIS from-scratch encoder, derived
# from RFC 8949 §4.2 (core-deterministic encoding) and the key tables in
# spec/companion/80_stream_channel.md §4-§5 -- NOT dumped from impl/go (the implementation under
# test). A passing stream.body.* vector therefore proves the Go impl AGREES with an independent
# oracle; it does not grade the impl against its own output.
#
# The MUST-reject cases carry no `expected` (schema omits it for result:"invalid") and are the spec's
# own MUST-reject list (80 §4.1/§4.2/§4.3/§5) crafted as deliberately non-canonical or
# structurally-invalid CBOR -- inherently non-circular.
#
# Run: python3 test-vectors/gen/stream_oracle.py  -> writes stream testGroups to stdout as JSON.
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

# ---------- NPAMP-STREAM frame types + envelope (80 §3.1, §4.2) ----------
STREAM_OPEN          = 0x0100
STREAM_DATA          = 0x0101
SSID                 = 4          # sub_stream_id: even = handshake initiator (§6.1); Unsigned int (NOT a byte-string corr)

# A valid STREAM_OPEN body: envelope frame_kind(0)+sub_stream_id(1) + REQUIRED init_window(2)+content_type(3).
def open_body(extra=None):
    d = {0: c_uint(STREAM_OPEN), 1: c_uint(SSID), 2: c_uint(65536), 3: c_uint(0x01)}
    if extra:
        d.update(extra)
    return c_map(d)

# A valid STREAM_DATA body: envelope + REQUIRED offset(2)+data(3,bytes).
def data_body():
    return c_map({0: c_uint(STREAM_DATA), 1: c_uint(SSID), 2: c_uint(0), 3: c_bytes(b'hello')})

VALID_OPEN = open_body()
VALID_DATA = data_body()
# Forward-compat: an unknown NON-NEGATIVE key (99) MUST be accepted (§4.3).
FWD_COMPAT = open_body({99: c_text('future-field')})

# ---------- MUST-reject bodies (80 §4.1/§4.2/§4.3/§5) -- crafted invalid, no oracle output ----------
# (a) non-deterministic CBOR: key 0 encoded in non-shortest form (0x18 0x00 instead of 0x00). §4.1
NONSHORTEST_KEY = bytes([0xa1, 0x18, 0x00, 0x00])
# (b) unknown NEGATIVE key (-1 = 0x20) on an otherwise-valid OPEN. §4.3 -> reject. Build canonically
#     then splice a 5th entry (-1 -> 9) after the last key (-1 sorts after non-negative keys) and
#     bump the map count 0xa4 -> 0xa5.
UNKNOWN_NEG_KEY = c_map({0: c_uint(STREAM_OPEN), 1: c_uint(SSID), 2: c_uint(1), 3: c_uint(1)})
UNKNOWN_NEG_KEY = bytes([0xa5]) + UNKNOWN_NEG_KEY[1:] + c_nint(-1) + c_uint(9)
# (c) missing REQUIRED init_window(2) on an OPEN. §5.1 -> reject.
MISSING_INIT_WINDOW = c_map({0: c_uint(STREAM_OPEN), 1: c_uint(SSID), 3: c_uint(1)})
# (d) wrong CBOR major type for content_type (text where uint required). §5.1 -> reject.
WRONG_TYPE_CONTENT_TYPE = c_map({0: c_uint(STREAM_OPEN), 1: c_uint(SSID), 2: c_uint(1), 3: c_text('x')})
# (e) frame_kind contradicts the frame header: body says DATA but validated as OPEN. §4.2 -> reject.
FRAMEKIND_MISMATCH = c_map({0: c_uint(STREAM_DATA), 1: c_uint(SSID), 2: c_uint(1), 3: c_uint(1)})
# (f) sub_stream_id is a byte string, not the required Unsigned int (the STREAM envelope divergence
#     from MEMORY, whose corr IS a byte string). §4.2 -> reject.
SSID_NOT_UINT = c_map({0: c_uint(STREAM_OPEN), 1: c_bytes(b'\x04'), 2: c_uint(1), 3: c_uint(1)})
# (g) payload is not a map at all (a bare uint). §4.1 -> reject.
NOT_A_MAP = c_uint(5)

def dec(tcid, req, comment, frame_type, body_hex, result, expected=None, flags=None):
    o = {"tcId": tcid, "requirement": req, "comment": comment,
         "in": {"frameType": frame_type, "body": body_hex}, "result": result}
    if expected is not None: o["expected"] = expected
    if flags is not None: o["flags"] = flags
    return o

decode_tests = [
    dec(1, "80/5.1/deterministic-cbor-map", "valid STREAM_OPEN: envelope + init_window + content_type",
        STREAM_OPEN, hx(VALID_OPEN), "valid", {"frame_kind": STREAM_OPEN, "sub_stream_id": SSID}),
    dec(2, "80/5.2/deterministic-cbor-map", "valid STREAM_DATA: envelope + offset + data",
        STREAM_DATA, hx(VALID_DATA), "valid", {"frame_kind": STREAM_DATA, "sub_stream_id": SSID}),
    dec(3, "80/4.3/forward-compat-accept-nonneg", "unknown NON-negative key (99) MUST be accepted",
        STREAM_OPEN, hx(FWD_COMPAT), "acceptable", {"frame_kind": STREAM_OPEN, "sub_stream_id": SSID},
        ["ForwardCompat"]),
    dec(4, "80/4.1/non-deterministic-cbor-MUST-reject", "key 0 in non-shortest form (0x18 0x00)",
        STREAM_OPEN, hx(NONSHORTEST_KEY), "invalid", None, ["MustReject", "NonDeterministicCBOR"]),
    dec(5, "80/4.3/unknown-negative-key-MUST-reject", "unknown NEGATIVE integer key (-1)",
        STREAM_OPEN, hx(UNKNOWN_NEG_KEY), "invalid", None, ["MustReject", "UnknownNegativeKey"]),
    dec(6, "80/5.1/missing-required-key-MUST-reject", "STREAM_OPEN missing REQUIRED init_window(2)",
        STREAM_OPEN, hx(MISSING_INIT_WINDOW), "invalid", None, ["MustReject", "MissingRequiredKey"]),
    dec(7, "80/5.1/wrong-major-type-MUST-reject", "content_type(3) is text where an unsigned int is required",
        STREAM_OPEN, hx(WRONG_TYPE_CONTENT_TYPE), "invalid", None, ["MustReject", "WrongMajorType"]),
    dec(8, "80/4.2/frame-kind-mismatch-MUST-reject", "frame_kind says DATA(0x0101) but frame is OPEN(0x0100)",
        STREAM_OPEN, hx(FRAMEKIND_MISMATCH), "invalid", None, ["MustReject", "FrameKindMismatch"]),
    dec(9, "80/4.2/sub-stream-id-not-uint-MUST-reject", "sub_stream_id(1) is a byte string, not an Unsigned int",
        STREAM_OPEN, hx(SSID_NOT_UINT), "invalid", None, ["MustReject", "EnvelopeWrongType"]),
    dec(10, "80/4.1/payload-not-a-map-MUST-reject", "payload is a bare uint, not a CBOR map",
        STREAM_OPEN, hx(NOT_A_MAP), "invalid", None, ["MustReject", "NotAMap"]),
]

# Only stream.body.decode is emitted: its `in` is flat (frameType + hex body), so adapters that do
# not implement it skip gracefully (Unimplemented) rather than erroring on a nested-typed input. It
# grades the core wire contract (the §4 MUST-reject clauses + envelope decode incl. the STREAM
# sub_stream_id-is-uint divergence). Canonical ENCODING is covered by the reference impl's own tests.
groups = [
    {"op": "stream.body.decode", "profile": "Standard", "tests": decode_tests},
]
json.dump(groups, sys.stdout, indent=2)
sys.stdout.write("\n")
