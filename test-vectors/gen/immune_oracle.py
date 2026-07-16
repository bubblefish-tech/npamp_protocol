#!/usr/bin/env python3
# Independent RFC 8949 canonical-CBOR oracle + NPAMP-IMMUNE conformance-vector generator.
#
# NON-CIRCULARITY (test-vectors/README.md; 55_conformance_requirements.md §5.2): the canonical
# CBOR bytes and expected values in the emitted vectors are produced by THIS from-scratch encoder,
# derived from RFC 8949 §4.2 (core-deterministic encoding) and the key tables in
# spec/companion/85_immune_channel.md §4-§8 -- NOT dumped from impl/go (the implementation under
# test). A passing immune.body.* vector therefore proves the Go impl AGREES with an independent
# oracle; it does not grade the impl against its own output.
#
# The MUST-reject cases carry no `expected` (schema omits it for result:"invalid") and are the
# spec's own MUST-reject list (85 §4.1/§4.2/§4.3/§6/§8) crafted as deliberately non-canonical or
# structurally-invalid CBOR -- inherently non-circular.
#
# Run: python3 test-vectors/gen/immune_oracle.py  -> writes immune testGroups to stdout as JSON.
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
def c_bool(x):  return bytes([0xf5]) if x else bytes([0xf4])

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

# ---------- NPAMP-IMMUNE frame types + envelope (85 §3, §4.2) ----------
# Application band (§3.1) and reserved propagation band (§3.3).
IMMUNE_REPORT_REQ       = 0x0100
IMMUNE_REPORT_RESULT    = 0x0101
IMMUNE_ERROR            = 0x0102
IMMUNE_GOSSIP_ADVERTISE = 0x00C0
IMMUNE_GOSSIP_ACK       = 0x00C1
IMMUNE_GOSSIP_PULL_REQ  = 0x00C2
IMMUNE_GOSSIP_PULL_RES  = 0x00C3
IMMUNE_GOSSIP_RETRACT   = 0x00C4

CORR = b'\x63'            # 1-byte correlation token (§4.2: byte string 1-64 B)
ITEM = b'\x9a\x1c'        # 2-byte item_id for a gossip descriptor/item (§6.4)

# ---------- valid bodies (§6, §8), built from the companion's OWN key tables ----------
# IMMUNE_REPORT_REQ (§6.2): envelope frame_kind(0)+corr(1) + REQUIRED report_id(2,text)
# + anomaly_class(3,uint) + severity(4,uint).
def report_req_body(extra=None):
    d = {0: c_uint(IMMUNE_REPORT_REQ), 1: c_bytes(CORR),
         2: c_text('anomaly-42'), 3: c_uint(0x01), 4: c_uint(0x03)}
    if extra:
        d.update(extra)
    return c_map(d)

# IMMUNE_REPORT_RESULT (§6.2): envelope + REQUIRED disposition(2,uint); optional tracking_id(3,text).
def report_result_body():
    return c_map({0: c_uint(IMMUNE_REPORT_RESULT), 1: c_bytes(CORR),
                  2: c_uint(0x01), 3: c_text('trk-7')})

# IMMUNE_ERROR (§8): envelope + REQUIRED code(2,uint) + message(3,text); optional retry_after_s(4,uint).
def immune_error_body():
    return c_map({0: c_uint(IMMUNE_ERROR), 1: c_bytes(CORR),
                  2: c_uint(1), 3: c_text('malformed request')})

# IMMUNE_GOSSIP_ADVERTISE (§6.4, pull-mode): envelope + REQUIRED items(2,array of gossip_descriptor).
# A gossip_descriptor is a nested map with REQUIRED item_id(0,bytes) + version(1,uint); here it also
# carries the optional severity(3,uint).
def advertise_body():
    descriptor = c_map({0: c_bytes(ITEM), 1: c_uint(7), 3: c_uint(0x03)})
    return c_map({0: c_uint(IMMUNE_GOSSIP_ADVERTISE), 1: c_bytes(CORR),
                  2: c_array([descriptor])})

# IMMUNE_GOSSIP_RETRACT (§6.6): envelope + REQUIRED item_id(2,bytes) + version(3,uint);
# optional reason(4,uint).
def retract_body():
    return c_map({0: c_uint(IMMUNE_GOSSIP_RETRACT), 1: c_bytes(CORR),
                  2: c_bytes(ITEM), 3: c_uint(8), 4: c_uint(0x00)})

VALID_REPORT_REQ    = report_req_body()
VALID_REPORT_RESULT = report_result_body()
VALID_IMMUNE_ERROR  = immune_error_body()
VALID_ADVERTISE     = advertise_body()
VALID_RETRACT       = retract_body()
# Forward-compat: an unknown NON-NEGATIVE key (99) MUST be accepted (§4.3).
FWD_COMPAT          = report_req_body({99: c_text('future-field')})

# ---------- MUST-reject bodies (85 §4.1/§4.2/§4.3/§6/§8) -- crafted invalid, no oracle output ----------
# (a) non-deterministic CBOR: key 0 encoded in non-shortest form (0x18 0x00 instead of 0x00). §4.1
NONSHORTEST_KEY = bytes([0xa1, 0x18, 0x00, 0x00])
# (b) unknown NEGATIVE key (-1 = 0x20) on an otherwise-valid REPORT_REQ. §4.3 -> reject. Build
#     canonically then splice a negative-keyed pair AFTER the last key (canonical order: -1 sorts
#     after non-negative keys because 0x20 is bytewise-greater than 0x00..0x04) and bump the map
#     count 0xa5 -> 0xa6.
UNKNOWN_NEG_KEY = c_map({0: c_uint(IMMUNE_REPORT_REQ), 1: c_bytes(CORR),
                         2: c_text('x'), 3: c_uint(1), 4: c_uint(3)})
UNKNOWN_NEG_KEY = bytes([0xa6]) + UNKNOWN_NEG_KEY[1:] + c_nint(-1) + c_uint(9)
# (c) missing REQUIRED report_id(2) on a REPORT_REQ. §6.2 -> reject.
MISSING_REPORT_ID = c_map({0: c_uint(IMMUNE_REPORT_REQ), 1: c_bytes(CORR),
                           3: c_uint(1), 4: c_uint(3)})
# (d) wrong CBOR major type for anomaly_class (text where uint required). §6.2 -> reject.
WRONG_TYPE_ANOMALY_CLASS = c_map({0: c_uint(IMMUNE_REPORT_REQ), 1: c_bytes(CORR),
                                  2: c_text('x'), 3: c_text('bad'), 4: c_uint(3)})
# (e) frame_kind contradicts the frame header: body says REPORT_RESULT but validated as REPORT_REQ.
#     §4.2 -> reject.
FRAMEKIND_MISMATCH = c_map({0: c_uint(IMMUNE_REPORT_RESULT), 1: c_bytes(CORR),
                            2: c_text('x'), 3: c_uint(1), 4: c_uint(3)})
# (f) corr(1) is an unsigned int, not the required byte string. §4.2 -> reject.
CORR_NOT_BYTES = c_map({0: c_uint(IMMUNE_REPORT_REQ), 1: c_uint(0x63),
                        2: c_text('x'), 3: c_uint(1), 4: c_uint(3)})
# (g) corr(1) is an empty byte string (§4.2 requires non-empty, 1-64 B). §4.2 -> reject.
CORR_EMPTY = c_map({0: c_uint(IMMUNE_REPORT_REQ), 1: c_bytes(b''),
                    2: c_text('x'), 3: c_uint(1), 4: c_uint(3)})
# (h) missing REQUIRED corr(1) envelope field. §4.2 -> reject.
MISSING_CORR = c_map({0: c_uint(IMMUNE_REPORT_REQ),
                      2: c_text('x'), 3: c_uint(1), 4: c_uint(3)})
# (i) nested gossip_descriptor missing REQUIRED item_id(0) inside an ADVERTISE items array. §6.4 ->
#     reject. The descriptor carries only version(1); its REQUIRED item_id(0) is absent.
BAD_DESCRIPTOR = c_map({1: c_uint(7)})
ADVERTISE_BAD_DESCRIPTOR = c_map({0: c_uint(IMMUNE_GOSSIP_ADVERTISE), 1: c_bytes(CORR),
                                  2: c_array([BAD_DESCRIPTOR])})
# (j) IMMUNE_GOSSIP_RETRACT missing REQUIRED version(3). §6.6 -> reject.
RETRACT_MISSING_VERSION = c_map({0: c_uint(IMMUNE_GOSSIP_RETRACT), 1: c_bytes(CORR),
                                 2: c_bytes(ITEM), 4: c_uint(0)})
# (k) map keys out of canonical order: key 1 before key 0 (non-deterministic). §4.1 -> reject.
#     Hand-built: map(2) with entry(1 -> corr) then entry(0 -> frame_kind), violating ascending order.
OUT_OF_ORDER = bytes([0xa2]) + c_uint(1) + c_bytes(CORR) + c_uint(0) + c_uint(IMMUNE_REPORT_REQ)
# (l) payload is not a map at all (a bare uint). §4.1 -> reject.
NOT_A_MAP = c_uint(5)

def dec(tcid, req, comment, frame_type, body_hex, result, expected=None, flags=None):
    o = {"tcId": tcid, "requirement": req, "comment": comment,
         "in": {"frameType": frame_type, "body": body_hex}, "result": result}
    if expected is not None: o["expected"] = expected
    if flags is not None: o["flags"] = flags
    return o

decode_tests = [
    dec(1, "85/6.2/deterministic-cbor-map", "valid IMMUNE_REPORT_REQ: envelope + report_id + anomaly_class + severity",
        IMMUNE_REPORT_REQ, hx(VALID_REPORT_REQ), "valid", {"frame_kind": IMMUNE_REPORT_REQ, "corr": hx(CORR)}),
    dec(2, "85/6.2/deterministic-cbor-map", "valid IMMUNE_REPORT_RESULT: envelope + disposition + tracking_id",
        IMMUNE_REPORT_RESULT, hx(VALID_REPORT_RESULT), "valid", {"frame_kind": IMMUNE_REPORT_RESULT, "corr": hx(CORR)}),
    dec(3, "85/8/deterministic-cbor-map", "valid IMMUNE_ERROR: envelope + code + message",
        IMMUNE_ERROR, hx(VALID_IMMUNE_ERROR), "valid", {"frame_kind": IMMUNE_ERROR, "corr": hx(CORR)}),
    dec(4, "85/6.4/deterministic-cbor-map", "valid IMMUNE_GOSSIP_ADVERTISE: envelope + items[gossip_descriptor]",
        IMMUNE_GOSSIP_ADVERTISE, hx(VALID_ADVERTISE), "valid", {"frame_kind": IMMUNE_GOSSIP_ADVERTISE, "corr": hx(CORR)}),
    dec(5, "85/6.6/deterministic-cbor-map", "valid IMMUNE_GOSSIP_RETRACT: envelope + item_id + version + reason",
        IMMUNE_GOSSIP_RETRACT, hx(VALID_RETRACT), "valid", {"frame_kind": IMMUNE_GOSSIP_RETRACT, "corr": hx(CORR)}),
    dec(6, "85/4.3/forward-compat-accept-nonneg", "unknown NON-negative key (99) MUST be accepted",
        IMMUNE_REPORT_REQ, hx(FWD_COMPAT), "acceptable", {"frame_kind": IMMUNE_REPORT_REQ, "corr": hx(CORR)},
        ["ForwardCompat"]),
    dec(7, "85/4.1/non-deterministic-cbor-MUST-reject", "key 0 in non-shortest form (0x18 0x00)",
        IMMUNE_REPORT_REQ, hx(NONSHORTEST_KEY), "invalid", None, ["MustReject", "NonDeterministicCBOR"]),
    dec(8, "85/4.3/unknown-negative-key-MUST-reject", "unknown NEGATIVE integer key (-1)",
        IMMUNE_REPORT_REQ, hx(UNKNOWN_NEG_KEY), "invalid", None, ["MustReject", "UnknownNegativeKey"]),
    dec(9, "85/6.2/missing-required-key-MUST-reject", "IMMUNE_REPORT_REQ missing REQUIRED report_id(2)",
        IMMUNE_REPORT_REQ, hx(MISSING_REPORT_ID), "invalid", None, ["MustReject", "MissingRequiredKey"]),
    dec(10, "85/6.2/wrong-major-type-MUST-reject", "anomaly_class(3) is text where an unsigned int is required",
        IMMUNE_REPORT_REQ, hx(WRONG_TYPE_ANOMALY_CLASS), "invalid", None, ["MustReject", "WrongMajorType"]),
    dec(11, "85/4.2/frame-kind-mismatch-MUST-reject", "frame_kind says REPORT_RESULT(0x0101) but frame is REPORT_REQ(0x0100)",
        IMMUNE_REPORT_REQ, hx(FRAMEKIND_MISMATCH), "invalid", None, ["MustReject", "FrameKindMismatch"]),
    dec(12, "85/4.2/corr-not-bytes-MUST-reject", "corr(1) is an unsigned int, not the required byte string",
        IMMUNE_REPORT_REQ, hx(CORR_NOT_BYTES), "invalid", None, ["MustReject", "EnvelopeWrongType"]),
    dec(13, "85/4.2/corr-empty-MUST-reject", "corr(1) is an empty byte string (§4.2 requires non-empty 1-64 B)",
        IMMUNE_REPORT_REQ, hx(CORR_EMPTY), "invalid", None, ["MustReject", "EnvelopeWrongType"]),
    dec(14, "85/4.2/missing-corr-MUST-reject", "IMMUNE_REPORT_REQ missing REQUIRED corr(1) envelope field",
        IMMUNE_REPORT_REQ, hx(MISSING_CORR), "invalid", None, ["MustReject", "MissingRequiredKey"]),
    dec(15, "85/6.4/nested-descriptor-missing-item-id-MUST-reject", "gossip_descriptor in items[] omits REQUIRED item_id(0)",
        IMMUNE_GOSSIP_ADVERTISE, hx(ADVERTISE_BAD_DESCRIPTOR), "invalid", None, ["MustReject", "MissingRequiredKey"]),
    dec(16, "85/6.6/retract-missing-version-MUST-reject", "IMMUNE_GOSSIP_RETRACT missing REQUIRED version(3)",
        IMMUNE_GOSSIP_RETRACT, hx(RETRACT_MISSING_VERSION), "invalid", None, ["MustReject", "MissingRequiredKey"]),
    dec(17, "85/4.1/map-keys-out-of-order-MUST-reject", "map keys not in canonical ascending order (key 1 before key 0)",
        IMMUNE_REPORT_REQ, hx(OUT_OF_ORDER), "invalid", None, ["MustReject", "NonDeterministicCBOR"]),
    dec(18, "85/4.1/payload-not-a-map-MUST-reject", "payload is a bare uint, not a CBOR map",
        IMMUNE_REPORT_REQ, hx(NOT_A_MAP), "invalid", None, ["MustReject", "NotAMap"]),
]

# Only immune.body.decode is emitted: its `in` is flat (frameType + hex body), so adapters that do
# not implement it skip gracefully (Unimplemented) rather than erroring on a nested-typed input. It
# grades the core wire contract (the §4/§6/§8 MUST-reject clauses + the Immune envelope decode, whose
# corr(1) is a byte-string correlation token, plus nested gossip-descriptor required-key enforcement).
# Canonical ENCODING is covered by the reference impl's own round-trip test.
groups = [
    {"op": "immune.body.decode", "profile": "Standard", "tests": decode_tests},
]
json.dump(groups, sys.stdout, indent=2)
sys.stdout.write("\n")
