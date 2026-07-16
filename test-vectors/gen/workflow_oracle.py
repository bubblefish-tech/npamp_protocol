#!/usr/bin/env python3
# Independent RFC 8949 canonical-CBOR oracle + NPAMP-WORKFLOW conformance-vector generator.
#
# NON-CIRCULARITY (test-vectors/README.md; 55_conformance_requirements.md §5.2): the canonical CBOR
# bytes and expected values in the emitted vectors are produced by THIS from-scratch encoder, derived
# from RFC 8949 §4.2 (core-deterministic encoding) and the key tables in
# spec/companion/8a_workflow_channel.md §4-§6/§8 -- NOT dumped from impl/go (the implementation under
# test). A passing workflow.body.* vector therefore proves the Go impl AGREES with an independent
# oracle; it does not grade the impl against its own output.
#
# The MUST-reject cases carry no `expected` (schema omits it for result:"invalid") and are the spec's
# own MUST-reject list (8a §4.1/§4.2/§4.3/§5.3/§6/§8) crafted as deliberately non-canonical or
# structurally-invalid CBOR -- inherently non-circular.
#
# Run: python3 test-vectors/gen/workflow_oracle.py  -> writes workflow testGroups to stdout as JSON.
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

# ---------- NPAMP-WORKFLOW frame types + envelope (8a §3.1, §4.2) ----------
WORKFLOW_SUBMIT_REQ    = 0x0100
WORKFLOW_SUBMIT_RESULT = 0x0101
WORKFLOW_STATUS_REQ    = 0x0102
WORKFLOW_STEP_EVENT    = 0x0106
WORKFLOW_COMPLETE      = 0x0107
WORKFLOW_ERROR         = 0x0108
CORR = b'\x63'            # 1-byte correlation token (§4.2: bytes 1-64), like NPAMP-MEMORY's corr

# Effect classes (§5.3) and task states (§5.4).
EFFECT_IDEMPOTENT_WRITE = 0x01
STATE_ACCEPTED          = 0x00
STATE_RUNNING           = 0x01
STATE_SUCCEEDED         = 0x02
ERR_APPROVAL_REQUIRED   = 4       # §8 error code

# A valid WORKFLOW_SUBMIT_REQ body: envelope frame_kind(0)+corr(1) + REQUIRED task_type(2,text) +
# REQUIRED effect(11,uint). §6.1.
def submit_req_body(extra=None):
    d = {0: c_uint(WORKFLOW_SUBMIT_REQ), 1: c_bytes(CORR),
         2: c_text('summarize'), 11: c_uint(EFFECT_IDEMPOTENT_WRITE)}
    if extra:
        d.update(extra)
    return c_map(d)

# A valid WORKFLOW_SUBMIT_RESULT body: envelope + REQUIRED task_id(2,text) + state(3,uint). §6.1.
def submit_result_body():
    return c_map({0: c_uint(WORKFLOW_SUBMIT_RESULT), 1: c_bytes(CORR),
                  2: c_text('task-7'), 3: c_uint(STATE_ACCEPTED)})

# A valid WORKFLOW_STEP_EVENT body: envelope frame_kind(0) ONLY (NO corr, §4.2) + REQUIRED
# task_id(2,text) + seq(3,uint) + state(4,uint, non-terminal). §6.4.
def step_event_body():
    return c_map({0: c_uint(WORKFLOW_STEP_EVENT),
                  2: c_text('task-7'), 3: c_uint(0), 4: c_uint(STATE_RUNNING)})

# A valid WORKFLOW_COMPLETE body: envelope frame_kind(0) ONLY (NO corr, §4.2) + REQUIRED
# task_id(2,text) + seq(3,uint) + state(4,uint, terminal). §6.5.
def complete_body():
    return c_map({0: c_uint(WORKFLOW_COMPLETE),
                  2: c_text('task-7'), 3: c_uint(3), 4: c_uint(STATE_SUCCEEDED)})

# A valid WORKFLOW_ERROR body carrying the governance-escalation outcome: envelope + REQUIRED
# code(2,uint)=approval_required + message(3,text) + approval_id(5,text). §8/§8.1.
def error_approval_body():
    return c_map({0: c_uint(WORKFLOW_ERROR), 1: c_bytes(CORR),
                  2: c_uint(ERR_APPROVAL_REQUIRED), 3: c_text('held for human approval'),
                  5: c_text('appr-1')})

VALID_SUBMIT_REQ    = submit_req_body()
VALID_SUBMIT_RESULT = submit_result_body()
VALID_STEP_EVENT    = step_event_body()
VALID_COMPLETE      = complete_body()
VALID_ERROR_APPROVAL = error_approval_body()
# Forward-compat: an unknown NON-NEGATIVE key (99) MUST be accepted (§4.3).
FWD_COMPAT          = submit_req_body({99: c_text('future-field')})

# ---------- MUST-reject bodies (8a §4.1/§4.2/§4.3/§5.3/§6/§8) -- crafted invalid, no oracle output ---
# (a) non-deterministic CBOR: key 0 encoded in non-shortest form (0x18 0x00 instead of 0x00). §4.1
NONSHORTEST_KEY = bytes([0xa1, 0x18, 0x00, 0x00])
# (b) unknown NEGATIVE key (-1 = 0x20) on an otherwise-valid SUBMIT_REQ. §4.3 -> reject. Build
#     canonically (4 entries) then splice a 5th entry (-1 -> 9) after the last key (-1 sorts after the
#     non-negative keys because its encoding 0x20 is bytewise-greater) and bump 0xa4 -> 0xa5.
UNKNOWN_NEG_KEY = c_map({0: c_uint(WORKFLOW_SUBMIT_REQ), 1: c_bytes(CORR),
                         2: c_text('x'), 11: c_uint(EFFECT_IDEMPOTENT_WRITE)})
UNKNOWN_NEG_KEY = bytes([0xa5]) + UNKNOWN_NEG_KEY[1:] + c_nint(-1) + c_uint(9)
# (c) missing REQUIRED task_type(2) on a SUBMIT_REQ. §6.1 -> reject.
MISSING_TASK_TYPE = c_map({0: c_uint(WORKFLOW_SUBMIT_REQ), 1: c_bytes(CORR),
                           11: c_uint(EFFECT_IDEMPOTENT_WRITE)})
# (d) missing REQUIRED effect(11) on a SUBMIT_REQ. §5.3/§6.1 -> reject (effect is REQUIRED; the
#     §5.3 fail-safe treats a missing effect as destructive, and the body is malformed_request).
MISSING_EFFECT = c_map({0: c_uint(WORKFLOW_SUBMIT_REQ), 1: c_bytes(CORR), 2: c_text('x')})
# (e) wrong CBOR major type for effect (text where uint required). §4.1 -> reject.
WRONG_TYPE_EFFECT = c_map({0: c_uint(WORKFLOW_SUBMIT_REQ), 1: c_bytes(CORR),
                           2: c_text('x'), 11: c_text('nope')})
# (f) frame_kind contradicts the frame header: body says STATUS_REQ but validated as SUBMIT_REQ. §4.2
FRAMEKIND_MISMATCH = c_map({0: c_uint(WORKFLOW_STATUS_REQ), 1: c_bytes(CORR),
                            2: c_text('x'), 11: c_uint(EFFECT_IDEMPOTENT_WRITE)})
# (g) corr(1) is an unsigned int, not the required byte string, on a *_REQ. §4.2 -> reject.
CORR_NOT_BYTES = c_map({0: c_uint(WORKFLOW_SUBMIT_REQ), 1: c_uint(0x63),
                        2: c_text('x'), 11: c_uint(EFFECT_IDEMPOTENT_WRITE)})
# (h) corr(1) absent on a *_REQ (SUBMIT_REQ MUST carry a non-empty corr, §5.1). §4.2 -> reject.
MISSING_CORR = c_map({0: c_uint(WORKFLOW_SUBMIT_REQ),
                      2: c_text('x'), 11: c_uint(EFFECT_IDEMPOTENT_WRITE)})
# (i) missing REQUIRED message(3) on a WORKFLOW_ERROR. §8 -> reject.
MISSING_ERROR_MESSAGE = c_map({0: c_uint(WORKFLOW_ERROR), 1: c_bytes(CORR),
                               2: c_uint(ERR_APPROVAL_REQUIRED)})
# (j) payload is not a map at all (a bare uint). §4.1 -> reject.
NOT_A_MAP = c_uint(5)

def dec(tcid, req, comment, frame_type, body_hex, result, expected=None, flags=None):
    o = {"tcId": tcid, "requirement": req, "comment": comment,
         "in": {"frameType": frame_type, "body": body_hex}, "result": result}
    if expected is not None: o["expected"] = expected
    if flags is not None: o["flags"] = flags
    return o

decode_tests = [
    dec(1, "8a/6.1/deterministic-cbor-map", "valid WORKFLOW_SUBMIT_REQ: envelope + task_type + effect",
        WORKFLOW_SUBMIT_REQ, hx(VALID_SUBMIT_REQ), "valid",
        {"frame_kind": WORKFLOW_SUBMIT_REQ, "corr": hx(CORR)}),
    dec(2, "8a/6.1/deterministic-cbor-map", "valid WORKFLOW_SUBMIT_RESULT: envelope + task_id + state",
        WORKFLOW_SUBMIT_RESULT, hx(VALID_SUBMIT_RESULT), "valid",
        {"frame_kind": WORKFLOW_SUBMIT_RESULT, "corr": hx(CORR)}),
    dec(3, "8a/6.4/step-event-no-corr", "valid WORKFLOW_STEP_EVENT: task-scoped, carries NO corr (§4.2)",
        WORKFLOW_STEP_EVENT, hx(VALID_STEP_EVENT), "valid",
        {"frame_kind": WORKFLOW_STEP_EVENT}),
    dec(4, "8a/6.5/complete-no-corr", "valid WORKFLOW_COMPLETE: terminal, task-scoped, NO corr (§4.2)",
        WORKFLOW_COMPLETE, hx(VALID_COMPLETE), "valid",
        {"frame_kind": WORKFLOW_COMPLETE}),
    dec(5, "8a/8.1/approval-required-distinct", "valid WORKFLOW_ERROR approval_required carrying approval_id",
        WORKFLOW_ERROR, hx(VALID_ERROR_APPROVAL), "valid",
        {"frame_kind": WORKFLOW_ERROR, "corr": hx(CORR)}),
    dec(6, "8a/4.3/forward-compat-accept-nonneg", "unknown NON-negative key (99) MUST be accepted",
        WORKFLOW_SUBMIT_REQ, hx(FWD_COMPAT), "acceptable",
        {"frame_kind": WORKFLOW_SUBMIT_REQ, "corr": hx(CORR)}, ["ForwardCompat"]),
    dec(7, "8a/4.1/non-deterministic-cbor-MUST-reject", "key 0 in non-shortest form (0x18 0x00)",
        WORKFLOW_SUBMIT_REQ, hx(NONSHORTEST_KEY), "invalid", None,
        ["MustReject", "NonDeterministicCBOR"]),
    dec(8, "8a/4.3/unknown-negative-key-MUST-reject", "unknown NEGATIVE integer key (-1)",
        WORKFLOW_SUBMIT_REQ, hx(UNKNOWN_NEG_KEY), "invalid", None,
        ["MustReject", "UnknownNegativeKey"]),
    dec(9, "8a/6.1/missing-required-key-MUST-reject", "SUBMIT_REQ missing REQUIRED task_type(2)",
        WORKFLOW_SUBMIT_REQ, hx(MISSING_TASK_TYPE), "invalid", None,
        ["MustReject", "MissingRequiredKey"]),
    dec(10, "8a/5.3/missing-required-effect-MUST-reject", "SUBMIT_REQ missing REQUIRED effect(11)",
        WORKFLOW_SUBMIT_REQ, hx(MISSING_EFFECT), "invalid", None,
        ["MustReject", "MissingRequiredKey"]),
    dec(11, "8a/4.1/wrong-major-type-MUST-reject", "effect(11) is text where an unsigned int is required",
        WORKFLOW_SUBMIT_REQ, hx(WRONG_TYPE_EFFECT), "invalid", None,
        ["MustReject", "WrongMajorType"]),
    dec(12, "8a/4.2/frame-kind-mismatch-MUST-reject", "frame_kind says STATUS_REQ(0x0102) but frame is SUBMIT_REQ(0x0100)",
        WORKFLOW_SUBMIT_REQ, hx(FRAMEKIND_MISMATCH), "invalid", None,
        ["MustReject", "FrameKindMismatch"]),
    dec(13, "8a/4.2/corr-not-bytes-MUST-reject", "corr(1) is an unsigned int, not the required byte string",
        WORKFLOW_SUBMIT_REQ, hx(CORR_NOT_BYTES), "invalid", None,
        ["MustReject", "EnvelopeWrongType"]),
    dec(14, "8a/5.1/missing-corr-MUST-reject", "SUBMIT_REQ omits the REQUIRED corr(1) an *_REQ MUST carry",
        WORKFLOW_SUBMIT_REQ, hx(MISSING_CORR), "invalid", None,
        ["MustReject", "MissingRequiredKey"]),
    dec(15, "8a/8/missing-error-message-MUST-reject", "WORKFLOW_ERROR missing REQUIRED message(3)",
        WORKFLOW_ERROR, hx(MISSING_ERROR_MESSAGE), "invalid", None,
        ["MustReject", "MissingRequiredKey"]),
    dec(16, "8a/4.1/payload-not-a-map-MUST-reject", "payload is a bare uint, not a CBOR map",
        WORKFLOW_SUBMIT_REQ, hx(NOT_A_MAP), "invalid", None,
        ["MustReject", "NotAMap"]),
]

# Only workflow.body.decode is emitted: its `in` is flat (frameType + hex body), so adapters that do
# not implement it skip gracefully (Unimplemented) rather than erroring on a nested-typed input. It
# grades the core wire contract (the §4 MUST-reject clauses + envelope decode, including the WORKFLOW
# divergence that STEP_EVENT/COMPLETE carry NO corr). Canonical ENCODING is covered by the reference
# impl's own round-trip test (zz_workflow_oracle_xval_test.go re-encodes each valid body).
groups = [
    {"op": "workflow.body.decode", "profile": "Standard", "tests": decode_tests},
]
json.dump(groups, sys.stdout, indent=2)
sys.stdout.write("\n")
