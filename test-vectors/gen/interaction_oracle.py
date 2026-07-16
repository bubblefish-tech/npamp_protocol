#!/usr/bin/env python3
# Independent RFC 8949 canonical-CBOR oracle + NPAMP-INTERACT conformance-vector generator.
#
# NON-CIRCULARITY (test-vectors/README.md; 55_conformance_requirements.md §5.2): the canonical CBOR
# bytes and expected values in the emitted vectors are produced by THIS from-scratch encoder, derived
# from RFC 8949 §4.2 (core-deterministic encoding) and the key tables in
# spec/companion/89_interaction_channel.md §3 (frame types), §4.2 (common envelope), and §6/§8 (body
# fields) -- NOT dumped from impl/go (the implementation under test). A passing interaction.body.*
# vector therefore proves the Go impl AGREES with an independent oracle; it does not grade the impl
# against its own output.
#
# The MUST-reject cases carry no `expected` (schema omits it for result:"invalid") and are the spec's
# own MUST-reject list (89 §4.1/§4.2/§4.3) crafted as deliberately non-canonical or structurally-
# invalid CBOR -- inherently non-circular.
#
# Run: python3 test-vectors/gen/interaction_oracle.py  -> writes interaction testGroups to stdout as JSON.
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

# ---------- NPAMP-INTERACT frame types + envelope (89 §3.1, §4.2) ----------
INTERACT_EVENT           = 0x0100
INTERACT_EVENT_ACK       = 0x0101
INTERACT_PROMPT_REQ      = 0x0102
INTERACT_PROMPT_RESULT   = 0x0103
INTERACT_APPROVAL_REQ    = 0x0104
INTERACT_APPROVAL_RESULT = 0x0105
INTERACT_CANCEL          = 0x0106
INTERACT_ERROR           = 0x0107
CORR = b'\x2a'           # non-empty correlation token (§4.2: byte string, 1-64 bytes)

# A valid INTERACT_EVENT body: envelope frame_kind(0)+corr(1) + REQUIRED event_class(2,uint).
def event_body(extra=None):
    d = {0: c_uint(INTERACT_EVENT), 1: c_bytes(CORR), 2: c_uint(0x03)}  # 0x03 = input event (§6.1)
    if extra:
        d.update(extra)
    return c_map(d)

# A valid INTERACT_PROMPT_REQ body: envelope + REQUIRED prompt_kind(2,uint) + prompt(3,text).
# prompt_kind 0x01 = text (§6.2): no `options` required, so this is semantically complete.
def prompt_req_body():
    return c_map({0: c_uint(INTERACT_PROMPT_REQ), 1: c_bytes(CORR),
                  2: c_uint(0x01), 3: c_text('Your name?')})

# A valid INTERACT_APPROVAL_REQ body: envelope + REQUIRED action(2,text) + optional severity(3,uint).
def approval_req_body():
    return c_map({0: c_uint(INTERACT_APPROVAL_REQ), 1: c_bytes(CORR),
                  2: c_text('delete record X'), 3: c_uint(0x02)})  # 0x02 = sensitive (§6.3)

# A valid INTERACT_APPROVAL_RESULT body: envelope + REQUIRED decision(2,uint). 0x00 = granted (§6.3).
def approval_result_body():
    return c_map({0: c_uint(INTERACT_APPROVAL_RESULT), 1: c_bytes(CORR), 2: c_uint(0x00)})

# A valid INTERACT_ERROR body carrying the channel's signature non-success outcome: code(2)=6
# approval_held + REQUIRED message(3,text) + approval_id(5,text) (§8, §8.1).
def error_held_body():
    return c_map({0: c_uint(INTERACT_ERROR), 1: c_bytes(CORR),
                  2: c_uint(6), 3: c_text('approval held for human decision'),
                  5: c_text('a1b2c3d4')})

# A valid INTERACT_EVENT_ACK body: envelope only (§6.1), echoes corr, no keys 2+.
def event_ack_body():
    return c_map({0: c_uint(INTERACT_EVENT_ACK), 1: c_bytes(CORR)})

VALID_EVENT           = event_body()
VALID_PROMPT_REQ      = prompt_req_body()
VALID_APPROVAL_REQ    = approval_req_body()
VALID_APPROVAL_RESULT = approval_result_body()
VALID_ERROR_HELD      = error_held_body()
VALID_EVENT_ACK       = event_ack_body()
# Forward-compat: an unknown NON-NEGATIVE key (99) MUST be accepted (§4.3).
FWD_COMPAT            = event_body({99: c_text('future-field')})

# ---------- MUST-reject bodies (89 §4.1/§4.2/§4.3) -- crafted invalid, no oracle output ----------
# (a) non-deterministic CBOR: key 0 encoded in non-shortest form (0x18 0x00 instead of 0x00). §4.1
NONSHORTEST_KEY = bytes([0xa1, 0x18, 0x00, 0x00])
# (b) unknown NEGATIVE key (-1 = 0x20) on an otherwise-valid EVENT. §4.3 -> reject. Build canonically
#     then splice a 4th entry (-1 -> 9) after the last key (-1 sorts after non-negative keys because
#     its encoding 0x20 is bytewise-greater than 0x00..0x63) and bump the map count 0xa3 -> 0xa4.
UNKNOWN_NEG_KEY = c_map({0: c_uint(INTERACT_EVENT), 1: c_bytes(CORR), 2: c_uint(0x03)})
UNKNOWN_NEG_KEY = bytes([0xa4]) + UNKNOWN_NEG_KEY[1:] + c_nint(-1) + c_uint(9)
# (c) missing REQUIRED event_class(2) on an EVENT. §4.1/§6.1 -> reject.
MISSING_EVENT_CLASS = c_map({0: c_uint(INTERACT_EVENT), 1: c_bytes(CORR)})
# (d) wrong CBOR major type for event_class (text where an unsigned int is required). §4.1 -> reject.
WRONG_TYPE_EVENT_CLASS = c_map({0: c_uint(INTERACT_EVENT), 1: c_bytes(CORR), 2: c_text('x')})
# (e) frame_kind contradicts the frame header: body says PROMPT_REQ but validated as EVENT. §4.2 -> reject.
FRAMEKIND_MISMATCH = c_map({0: c_uint(INTERACT_PROMPT_REQ), 1: c_bytes(CORR), 2: c_uint(0x03)})
# (f) corr(1) is an unsigned int, not the required byte string (§4.2). §4.2 -> reject.
CORR_NOT_BYTES = c_map({0: c_uint(INTERACT_EVENT), 1: c_uint(0x2a), 2: c_uint(0x03)})
# (g) missing REQUIRED corr(1) on an EVENT (present on every frame, §4.2). §4.2 -> reject.
MISSING_CORR = c_map({0: c_uint(INTERACT_EVENT), 2: c_uint(0x03)})
# (h) payload is not a map at all (a bare uint). §4.1 -> reject.
NOT_A_MAP = c_uint(5)

def dec(tcid, req, comment, frame_type, body_hex, result, expected=None, flags=None):
    o = {"tcId": tcid, "requirement": req, "comment": comment,
         "in": {"frameType": frame_type, "body": body_hex}, "result": result}
    if expected is not None: o["expected"] = expected
    if flags is not None: o["flags"] = flags
    return o

decode_tests = [
    dec(1, "89/6.1/deterministic-cbor-map", "valid INTERACT_EVENT: envelope + event_class",
        INTERACT_EVENT, hx(VALID_EVENT), "valid",
        {"frame_kind": INTERACT_EVENT, "corr": hx(CORR)}),
    dec(2, "89/6.2/deterministic-cbor-map", "valid INTERACT_PROMPT_REQ: envelope + prompt_kind + prompt",
        INTERACT_PROMPT_REQ, hx(VALID_PROMPT_REQ), "valid",
        {"frame_kind": INTERACT_PROMPT_REQ, "corr": hx(CORR)}),
    dec(3, "89/6.3/deterministic-cbor-map", "valid INTERACT_APPROVAL_REQ: envelope + action + severity",
        INTERACT_APPROVAL_REQ, hx(VALID_APPROVAL_REQ), "valid",
        {"frame_kind": INTERACT_APPROVAL_REQ, "corr": hx(CORR)}),
    dec(4, "89/6.3/deterministic-cbor-map", "valid INTERACT_APPROVAL_RESULT: envelope + decision(granted)",
        INTERACT_APPROVAL_RESULT, hx(VALID_APPROVAL_RESULT), "valid",
        {"frame_kind": INTERACT_APPROVAL_RESULT, "corr": hx(CORR)}),
    dec(5, "89/8.1/approval-held-distinct-outcome", "valid INTERACT_ERROR approval_held: code 6 + message + approval_id",
        INTERACT_ERROR, hx(VALID_ERROR_HELD), "valid",
        {"frame_kind": INTERACT_ERROR, "corr": hx(CORR)}),
    dec(6, "89/6.1/event-ack-envelope-only", "valid INTERACT_EVENT_ACK: envelope only (echoes corr)",
        INTERACT_EVENT_ACK, hx(VALID_EVENT_ACK), "valid",
        {"frame_kind": INTERACT_EVENT_ACK, "corr": hx(CORR)}),
    dec(7, "89/4.3/forward-compat-accept-nonneg", "unknown NON-negative key (99) MUST be accepted",
        INTERACT_EVENT, hx(FWD_COMPAT), "acceptable",
        {"frame_kind": INTERACT_EVENT, "corr": hx(CORR)}, ["ForwardCompat"]),
    dec(8, "89/4.1/non-deterministic-cbor-MUST-reject", "key 0 in non-shortest form (0x18 0x00)",
        INTERACT_EVENT, hx(NONSHORTEST_KEY), "invalid", None, ["MustReject", "NonDeterministicCBOR"]),
    dec(9, "89/4.3/unknown-negative-key-MUST-reject", "unknown NEGATIVE integer key (-1)",
        INTERACT_EVENT, hx(UNKNOWN_NEG_KEY), "invalid", None, ["MustReject", "UnknownNegativeKey"]),
    dec(10, "89/6.1/missing-required-key-MUST-reject", "INTERACT_EVENT missing REQUIRED event_class(2)",
        INTERACT_EVENT, hx(MISSING_EVENT_CLASS), "invalid", None, ["MustReject", "MissingRequiredKey"]),
    dec(11, "89/4.1/wrong-major-type-MUST-reject", "event_class(2) is text where an unsigned int is required",
        INTERACT_EVENT, hx(WRONG_TYPE_EVENT_CLASS), "invalid", None, ["MustReject", "WrongMajorType"]),
    dec(12, "89/4.2/frame-kind-mismatch-MUST-reject", "frame_kind says PROMPT_REQ(0x0102) but frame is EVENT(0x0100)",
        INTERACT_EVENT, hx(FRAMEKIND_MISMATCH), "invalid", None, ["MustReject", "FrameKindMismatch"]),
    dec(13, "89/4.2/corr-not-bytes-MUST-reject", "corr(1) is an unsigned int, not the required byte string",
        INTERACT_EVENT, hx(CORR_NOT_BYTES), "invalid", None, ["MustReject", "EnvelopeWrongType"]),
    dec(14, "89/4.2/missing-corr-MUST-reject", "INTERACT_EVENT missing REQUIRED corr(1)",
        INTERACT_EVENT, hx(MISSING_CORR), "invalid", None, ["MustReject", "MissingRequiredKey"]),
    dec(15, "89/4.1/payload-not-a-map-MUST-reject", "payload is a bare uint, not a CBOR map",
        INTERACT_EVENT, hx(NOT_A_MAP), "invalid", None, ["MustReject", "NotAMap"]),
]

# Only interaction.body.decode is emitted: its `in` is flat (frameType + hex body), so adapters that
# do not implement it skip gracefully (Unimplemented) rather than erroring on a nested-typed input. It
# grades the core wire contract (the §4 MUST-reject clauses + envelope decode incl. the byte-string
# corr envelope). Canonical ENCODING is covered by the reference impl's own cross-validation test
# (zz_interaction_oracle_xval_test.go), which re-encodes each valid body and compares to these bytes.
groups = [
    {"op": "interaction.body.decode", "profile": "Standard", "tests": decode_tests},
]
json.dump(groups, sys.stdout, indent=2)
sys.stdout.write("\n")
