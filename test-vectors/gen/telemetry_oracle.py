#!/usr/bin/env python3
# Independent RFC 8949 canonical-CBOR oracle + NPAMP-TELEMETRY conformance-vector generator.
#
# NON-CIRCULARITY (test-vectors/README.md; 55_conformance_requirements.md §5.2): the canonical CBOR
# bytes and expected values in the emitted vectors are produced by THIS from-scratch encoder, derived
# from RFC 8949 §4.2 (core-deterministic encoding) and the key tables in
# spec/companion/87_telemetry_channel.md §4-§8 -- NOT dumped from impl/go (the implementation under
# test). A passing telemetry.body.* vector therefore proves the Go impl AGREES with an independent
# oracle; it does not grade the impl against its own output.
#
# The MUST-reject cases carry no `expected` (schema omits it for result:"invalid") and are the spec's
# own MUST-reject list (87 §4/§4.1/§5/§6.1) crafted as deliberately non-canonical or
# structurally-invalid CBOR -- inherently non-circular.
#
# Run: python3 test-vectors/gen/telemetry_oracle.py  -> writes telemetry testGroups to stdout as JSON.
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

# ---------- NPAMP-TELEMETRY frame types + envelope (87 §3, §4.1) ----------
TELEMETRY_REPORT      = 0x0100
TELEMETRY_SUBSCRIBE   = 0x0101
TELEMETRY_SUB_ACK     = 0x0102
TELEMETRY_UNSUBSCRIBE = 0x0103
TELEMETRY_CREDIT      = 0x0104
TELEMETRY_ERROR       = 0x0105

CORR   = b'\x63'        # correlation token, byte string 1-64 B (§4.1)
SUB_ID = b'\x2a'        # subscription id, byte string 1-32 B (§6.2)

# ---------- nested item encoders (all uint-keyed maps, §5.1/§5.2/§5.3) ----------
# MetricSample (§5.1): name(0,text) ts(1,uint) kind(2,uint) value(3,int/float) [unit(4) labels(5) seq(6)]
def metric(name, ts, kind, value):
    v = c_uint(value) if value >= 0 else c_nint(value)
    return c_map({0: c_text(name), 1: c_uint(ts), 2: c_uint(kind), 3: v})

# Event (§5.2): name(0,text) ts(1,uint) [severity(2) attrs(3) message(4) seq(5)]
def event(name, ts, severity=None):
    d = {0: c_text(name), 1: c_uint(ts)}
    if severity is not None:
        d[2] = c_uint(severity)
    return c_map(d)

# HealthReport (§5.3): domain(0,text) ts(1,uint) status(2,uint) [message(3) detail(4)]
def health(domain, ts, status):
    return c_map({0: c_text(domain), 1: c_uint(ts), 2: c_uint(status)})

# ---------- valid bodies (87 §5-§8) ----------
# Standalone (unsolicited) REPORT: NO corr, NO sub_id; batch_seq(3) + metrics(4). §4.1/§5.
REPORT_STANDALONE = c_map({
    0: c_uint(TELEMETRY_REPORT), 3: c_uint(0),
    4: c_array([metric('cpu.load', 1700000000000, 0, 42)]),
})
# Subscribed REPORT: corr(1) + sub_id(2) + batch_seq(3) + events(5). §5.
REPORT_SUBSCRIBED = c_map({
    0: c_uint(TELEMETRY_REPORT), 1: c_bytes(CORR), 2: c_bytes(SUB_ID), 3: c_uint(7),
    5: c_array([event('gc.pause', 1700000000001, 2)]),
})
# REPORT carrying a health statement (unsolicited). §5.3.
REPORT_HEALTH = c_map({
    0: c_uint(TELEMETRY_REPORT), 3: c_uint(1),
    6: c_array([health('storage', 1700000000002, 1)]),
})
# REPORT mixing all three reporting classes in one batch (§5). Also exercises a negative delta value.
REPORT_MIXED = c_map({
    0: c_uint(TELEMETRY_REPORT), 3: c_uint(2),
    4: c_array([metric('queue.depth', 1700000000003, 2, -3)]),
    5: c_array([event('rekey', 1700000000004)]),
    6: c_array([health('net', 1700000000005, 0)]),
})
# TELEMETRY_SUBSCRIBE: corr(1) + credit(7). §6.1 (credit REQUIRED).
SUBSCRIBE = c_map({0: c_uint(TELEMETRY_SUBSCRIBE), 1: c_bytes(CORR), 7: c_uint(8)})
# TELEMETRY_SUBSCRIBE with selector: classes(2) + names(3) + min_severity(5) + credit(7). §6.1.
SUBSCRIBE_SEL = c_map({
    0: c_uint(TELEMETRY_SUBSCRIBE), 1: c_bytes(CORR),
    2: c_array([c_uint(0), c_uint(1)]), 3: c_array([c_text('cpu.load')]),
    5: c_uint(2), 7: c_uint(4),
})
# TELEMETRY_SUB_ACK: corr(1) + sub_id(2) + credit(3). §6.2.
SUB_ACK = c_map({0: c_uint(TELEMETRY_SUB_ACK), 1: c_bytes(CORR), 2: c_bytes(SUB_ID), 3: c_uint(4)})
# TELEMETRY_UNSUBSCRIBE: corr(1) + sub_id(2). §6.3.
UNSUBSCRIBE = c_map({0: c_uint(TELEMETRY_UNSUBSCRIBE), 1: c_bytes(CORR), 2: c_bytes(SUB_ID)})
# TELEMETRY_CREDIT: corr(1) + sub_id(2) + credit(3). §7.
CREDIT = c_map({0: c_uint(TELEMETRY_CREDIT), 1: c_bytes(CORR), 2: c_bytes(SUB_ID), 3: c_uint(16)})
# TELEMETRY_ERROR: corr(1) + code(2). §8 (sub_id here is key 4, OPTIONAL, omitted).
ERROR = c_map({0: c_uint(TELEMETRY_ERROR), 1: c_bytes(CORR), 2: c_uint(1)})
# Forward-compat: an unknown NON-NEGATIVE key (99) on a SUBSCRIBE MUST be accepted (§4).
FWD_COMPAT = c_map({0: c_uint(TELEMETRY_SUBSCRIBE), 1: c_bytes(CORR), 7: c_uint(8),
                    99: c_text('future-field')})

# ---------- MUST-reject bodies (87 §4/§4.1/§5/§6.1) -- crafted invalid, no oracle output ----------
# (a) non-deterministic CBOR: key 0 encoded in non-shortest form (0x18 0x00 instead of 0x00). §4.
NONSHORTEST_KEY = bytes([0xa1, 0x18, 0x00, 0x00])
# (b) non-canonical map key ORDER: key 1 emitted before key 0. §4 (RFC 8949 §4.2.1) -> reject.
NONCANONICAL_ORDER = bytes([0xa2]) + c_uint(1) + c_bytes(CORR) + c_uint(0) + c_uint(TELEMETRY_SUBSCRIBE)
# (c) unknown NEGATIVE key (-1 = 0x20) on an otherwise-valid SUBSCRIBE. §4 -> reject. Build canonically
#     then splice a 4th entry (-1 -> 9) after key 7 (0x20 sorts after 0x00/0x01/0x07) and bump 0xa3->0xa4.
UNKNOWN_NEG_KEY = c_map({0: c_uint(TELEMETRY_SUBSCRIBE), 1: c_bytes(CORR), 7: c_uint(8)})
UNKNOWN_NEG_KEY = bytes([0xa4]) + UNKNOWN_NEG_KEY[1:] + c_nint(-1) + c_uint(9)
# (d) SUBSCRIBE missing REQUIRED credit(7). §6.1 -> reject.
MISSING_CREDIT = c_map({0: c_uint(TELEMETRY_SUBSCRIBE), 1: c_bytes(CORR)})
# (e) corr(1) is an unsigned int where a byte string is required. §4.1 -> reject.
CORR_WRONG_TYPE = c_map({0: c_uint(TELEMETRY_SUBSCRIBE), 1: c_uint(9), 7: c_uint(8)})
# (f) corr(1) is an empty byte string (violates the 1-64 B length). §4.1 -> reject.
CORR_EMPTY = c_map({0: c_uint(TELEMETRY_SUBSCRIBE), 1: c_bytes(b''), 7: c_uint(8)})
# (g) frame_kind contradicts the frame header: body says SUBSCRIBE but validated as REPORT. §4.1 -> reject.
FRAMEKIND_MISMATCH = c_map({0: c_uint(TELEMETRY_SUBSCRIBE), 3: c_uint(0),
                            4: c_array([metric('x', 1, 0, 1)])})
# (h) REPORT with NO metrics/events/health (empty content). §5 -> reject.
REPORT_EMPTY = c_map({0: c_uint(TELEMETRY_REPORT), 3: c_uint(0)})
# (i) REPORT missing REQUIRED batch_seq(3). §5 -> reject.
REPORT_NO_BATCH_SEQ = c_map({0: c_uint(TELEMETRY_REPORT), 4: c_array([metric('x', 1, 0, 1)])})
# (j) REPORT with corr(1) present but sub_id(2) absent (sub_id present iff corr). §5 -> reject.
REPORT_CORR_NO_SUBID = c_map({0: c_uint(TELEMETRY_REPORT), 1: c_bytes(CORR), 3: c_uint(0),
                              4: c_array([metric('x', 1, 0, 1)])})
# (k) MetricSample missing REQUIRED value(3). §5.1 -> reject.
METRIC_MISSING_VALUE = c_map({0: c_uint(TELEMETRY_REPORT), 3: c_uint(0),
                              4: c_array([c_map({0: c_text('x'), 1: c_uint(1), 2: c_uint(0)})])})
# (l) MetricSample name(0) is a uint where text is required. §5.1 -> reject.
METRIC_WRONG_TYPE = c_map({0: c_uint(TELEMETRY_REPORT), 3: c_uint(0),
                           4: c_array([c_map({0: c_uint(9), 1: c_uint(1), 2: c_uint(0), 3: c_uint(1)})])})
# (m) HealthReport missing REQUIRED status(2). §5.3 -> reject.
HEALTH_MISSING_STATUS = c_map({0: c_uint(TELEMETRY_REPORT), 3: c_uint(0),
                               6: c_array([c_map({0: c_text('storage'), 1: c_uint(1)})])})
# (n) payload is not a map at all (a bare uint). §4 -> reject.
NOT_A_MAP = c_uint(5)

def dec(tcid, req, comment, frame_type, body_hex, result, expected=None, flags=None):
    o = {"tcId": tcid, "requirement": req, "comment": comment,
         "in": {"frameType": frame_type, "body": body_hex}, "result": result}
    if expected is not None: o["expected"] = expected
    if flags is not None: o["flags"] = flags
    return o

def exp(ft, corr=None):
    e = {"frame_kind": ft}
    if corr is not None:
        e["corr"] = corr.hex()
    return e

decode_tests = [
    # ---- VALID ----
    dec(1, "87/5/deterministic-cbor-map", "valid standalone TELEMETRY_REPORT: batch_seq + metrics, no corr",
        TELEMETRY_REPORT, hx(REPORT_STANDALONE), "valid", exp(TELEMETRY_REPORT)),
    dec(2, "87/5/subscribed-report", "valid subscribed TELEMETRY_REPORT: corr + sub_id + batch_seq + events",
        TELEMETRY_REPORT, hx(REPORT_SUBSCRIBED), "valid", exp(TELEMETRY_REPORT, CORR)),
    dec(3, "87/5.3/report-health", "valid TELEMETRY_REPORT carrying a health statement",
        TELEMETRY_REPORT, hx(REPORT_HEALTH), "valid", exp(TELEMETRY_REPORT)),
    dec(4, "87/5/report-mixed", "valid TELEMETRY_REPORT mixing metrics + events + health",
        TELEMETRY_REPORT, hx(REPORT_MIXED), "valid", exp(TELEMETRY_REPORT)),
    dec(5, "87/6.1/subscribe", "valid TELEMETRY_SUBSCRIBE: corr + credit",
        TELEMETRY_SUBSCRIBE, hx(SUBSCRIBE), "valid", exp(TELEMETRY_SUBSCRIBE, CORR)),
    dec(6, "87/6.1/subscribe-selector", "valid TELEMETRY_SUBSCRIBE with classes + names + min_severity selector",
        TELEMETRY_SUBSCRIBE, hx(SUBSCRIBE_SEL), "valid", exp(TELEMETRY_SUBSCRIBE, CORR)),
    dec(7, "87/6.2/sub-ack", "valid TELEMETRY_SUB_ACK: corr + sub_id + credit",
        TELEMETRY_SUB_ACK, hx(SUB_ACK), "valid", exp(TELEMETRY_SUB_ACK, CORR)),
    dec(8, "87/6.3/unsubscribe", "valid TELEMETRY_UNSUBSCRIBE: corr + sub_id",
        TELEMETRY_UNSUBSCRIBE, hx(UNSUBSCRIBE), "valid", exp(TELEMETRY_UNSUBSCRIBE, CORR)),
    dec(9, "87/7/credit", "valid TELEMETRY_CREDIT: corr + sub_id + credit",
        TELEMETRY_CREDIT, hx(CREDIT), "valid", exp(TELEMETRY_CREDIT, CORR)),
    dec(10, "87/8/error", "valid TELEMETRY_ERROR: corr + code",
        TELEMETRY_ERROR, hx(ERROR), "valid", exp(TELEMETRY_ERROR, CORR)),
    dec(11, "87/4/forward-compat-accept-nonneg", "unknown NON-negative key (99) MUST be accepted",
        TELEMETRY_SUBSCRIBE, hx(FWD_COMPAT), "acceptable", exp(TELEMETRY_SUBSCRIBE, CORR), ["ForwardCompat"]),
    # ---- MUST-REJECT ----
    dec(12, "87/4/non-deterministic-cbor-MUST-reject", "key 0 in non-shortest form (0x18 0x00)",
        TELEMETRY_SUBSCRIBE, hx(NONSHORTEST_KEY), "invalid", None, ["MustReject", "NonDeterministicCBOR"]),
    dec(13, "87/4/non-canonical-key-order-MUST-reject", "map keys out of canonical order (key 1 before key 0)",
        TELEMETRY_SUBSCRIBE, hx(NONCANONICAL_ORDER), "invalid", None, ["MustReject", "NonDeterministicCBOR"]),
    dec(14, "87/4/unknown-negative-key-MUST-reject", "unknown NEGATIVE integer key (-1)",
        TELEMETRY_SUBSCRIBE, hx(UNKNOWN_NEG_KEY), "invalid", None, ["MustReject", "UnknownNegativeKey"]),
    dec(15, "87/6.1/missing-required-key-MUST-reject", "TELEMETRY_SUBSCRIBE missing REQUIRED credit(7)",
        TELEMETRY_SUBSCRIBE, hx(MISSING_CREDIT), "invalid", None, ["MustReject", "MissingRequiredKey"]),
    dec(16, "87/4.1/corr-wrong-type-MUST-reject", "corr(1) is an unsigned int where a byte string is required",
        TELEMETRY_SUBSCRIBE, hx(CORR_WRONG_TYPE), "invalid", None, ["MustReject", "WrongMajorType"]),
    dec(17, "87/4.1/corr-empty-MUST-reject", "corr(1) is an empty byte string (violates 1-64 B length)",
        TELEMETRY_SUBSCRIBE, hx(CORR_EMPTY), "invalid", None, ["MustReject", "EnvelopeWrongType"]),
    dec(18, "87/4.1/frame-kind-mismatch-MUST-reject", "frame_kind says SUBSCRIBE(0x0101) but frame is REPORT(0x0100)",
        TELEMETRY_REPORT, hx(FRAMEKIND_MISMATCH), "invalid", None, ["MustReject", "FrameKindMismatch"]),
    dec(19, "87/5/report-empty-content-MUST-reject", "TELEMETRY_REPORT with no metrics, events, or health",
        TELEMETRY_REPORT, hx(REPORT_EMPTY), "invalid", None, ["MustReject", "MalformedPayload"]),
    dec(20, "87/5/report-missing-batch-seq-MUST-reject", "TELEMETRY_REPORT missing REQUIRED batch_seq(3)",
        TELEMETRY_REPORT, hx(REPORT_NO_BATCH_SEQ), "invalid", None, ["MustReject", "MissingRequiredKey"]),
    dec(21, "87/5/report-corr-without-sub-id-MUST-reject", "subscribed TELEMETRY_REPORT has corr(1) but omits sub_id(2)",
        TELEMETRY_REPORT, hx(REPORT_CORR_NO_SUBID), "invalid", None, ["MustReject", "MalformedPayload"]),
    dec(22, "87/5.1/metric-missing-required-MUST-reject", "MetricSample missing REQUIRED value(3)",
        TELEMETRY_REPORT, hx(METRIC_MISSING_VALUE), "invalid", None, ["MustReject", "MissingRequiredKey"]),
    dec(23, "87/5.1/metric-wrong-type-MUST-reject", "MetricSample name(0) is a uint where text is required",
        TELEMETRY_REPORT, hx(METRIC_WRONG_TYPE), "invalid", None, ["MustReject", "WrongMajorType"]),
    dec(24, "87/5.3/health-missing-required-MUST-reject", "HealthReport missing REQUIRED status(2)",
        TELEMETRY_REPORT, hx(HEALTH_MISSING_STATUS), "invalid", None, ["MustReject", "MissingRequiredKey"]),
    dec(25, "87/4/payload-not-a-map-MUST-reject", "payload is a bare uint, not a CBOR map",
        TELEMETRY_SUBSCRIBE, hx(NOT_A_MAP), "invalid", None, ["MustReject", "NotAMap"]),
]

# Only telemetry.body.decode is emitted: its `in` is flat (frameType + hex body), so adapters that do
# not implement it skip gracefully (Unimplemented) rather than erroring on a nested-typed input. It
# grades the core wire contract (the §4/§5 MUST-reject clauses + envelope decode incl. the Telemetry
# conditional-corr divergence: standalone REPORT omits corr, subscribed REPORT carries corr+sub_id).
# Canonical ENCODING is covered by the reference impl's own cross-validation test
# (impl/go/zz_telemetry_oracle_xval_test.go, which re-encodes each valid vector and compares bytes).
groups = [
    {"op": "telemetry.body.decode", "profile": "Standard", "tests": decode_tests},
]
json.dump(groups, sys.stdout, indent=2)
sys.stdout.write("\n")
