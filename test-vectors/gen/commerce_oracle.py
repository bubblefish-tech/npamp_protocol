#!/usr/bin/env python3
# Independent RFC 8949 canonical-CBOR oracle + NPAMP-COMMERCE conformance-vector generator.
#
# NON-CIRCULARITY (test-vectors/README.md; 55_conformance_requirements.md §5.2): the canonical CBOR
# bytes and expected values in the emitted vectors are produced by THIS from-scratch encoder, derived
# from RFC 8949 §4.2 (core-deterministic encoding) and the key tables in
# spec/companion/88_commerce_channel.md §4-§8 -- NOT dumped from impl/go (the implementation under
# test). A passing commerce.body.* vector therefore proves the Go impl AGREES with an independent
# oracle; it does not grade the impl against its own output.
#
# The MUST-reject cases carry no `expected` (schema omits it for result:"invalid") and are the spec's
# own MUST-reject list (88 §4.1/§4.2/§4.3/§4.4/§6.6) crafted as deliberately non-canonical or
# structurally-invalid CBOR -- inherently non-circular.
#
# Run: python3 test-vectors/gen/commerce_oracle.py  -> writes commerce testGroups to stdout as JSON.
import json, sys

# ---------- independent canonical CBOR encoder (RFC 8949 §4.2) ----------
# Copied verbatim from stream_oracle.py / memory_oracle.py: one from-scratch encoder shared by every
# channel oracle, so no channel's expected bytes derive from another impl.
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

# ---------- NPAMP-COMMERCE frame types + envelope (88 §3.1, §4.2) ----------
COMMERCE_MANDATE_CREATE_REQ = 0x0100
COMMERCE_MANDATE_READ_REQ   = 0x0102
COMMERCE_INTENT_PROPOSE_REQ = 0x0108
COMMERCE_INTENT_RESPOND_REQ = 0x010A
COMMERCE_ERROR              = 0x010E
CORR = b'\x63'            # 1-byte correlation token (§4.2: byte string 1-64 B), like MEMORY's corr

# The §4.3 monetary-amount structure: units(0) signed int, scale(1) uint, currency(2) text.
def amount(units, scale, currency):
    return c_map({0: c_uint(units), 1: c_uint(scale), 2: c_text(currency)})

VALID_AMOUNT = amount(12345, 2, 'USD')          # 123.45 USD, exact (no float)

# A valid COMMERCE_MANDATE_CREATE_REQ body (§6.1): envelope frame_kind(0)+corr(1) + REQUIRED
# payer(2,text) + payee(3,text) + amount(4,map) + effect(13,uint=0x03 value_transfer).
def create_body(extra=None):
    d = {0: c_uint(COMMERCE_MANDATE_CREATE_REQ), 1: c_bytes(CORR),
         2: c_text('payer:alice'), 3: c_text('payee:bob'), 4: VALID_AMOUNT, 13: c_uint(0x03)}
    if extra:
        d.update(extra)
    return c_map(d)

# A valid COMMERCE_MANDATE_READ_REQ body (§6.2): envelope + REQUIRED mandate_id(2,text) +
# effect(3,uint=0x00 read_only).
def read_body():
    return c_map({0: c_uint(COMMERCE_MANDATE_READ_REQ), 1: c_bytes(CORR),
                  2: c_text('mandate:xyz'), 3: c_uint(0x00)})

# A valid COMMERCE_INTENT_PROPOSE_REQ body (§6.6): envelope + REQUIRED parties(2,array of text) +
# legs(3,array of leg maps {from(0),to(1),amount(2)}) + effect(7,uint=0x02 non_idempotent_write).
def leg(frm, to, amt):
    return c_map({0: c_text(frm), 1: c_text(to), 2: amt})

def propose_body(extra=None):
    parties = c_array([c_text('party:a'), c_text('party:b')])
    legs    = c_array([leg('party:a', 'party:b', VALID_AMOUNT)])
    d = {0: c_uint(COMMERCE_INTENT_PROPOSE_REQ), 1: c_bytes(CORR),
         2: parties, 3: legs, 7: c_uint(0x02)}
    if extra:
        d.update(extra)
    return c_map(d)

# A valid COMMERCE_ERROR body (§8) reporting the load-bearing governance escalation: code(2)=4
# approval_required, message(3), approval_id(5) -- a held-for-approval, NOT-executed outcome (§8.1).
def error_body():
    return c_map({0: c_uint(COMMERCE_ERROR), 1: c_bytes(CORR),
                  2: c_uint(4), 3: c_text('approval required'), 5: c_text('appr:123')})

VALID_CREATE  = create_body()
VALID_READ    = read_body()
VALID_PROPOSE = propose_body()
VALID_ERROR   = error_body()
# Forward-compat: an unknown NON-NEGATIVE key (99) MUST be accepted (§4.4).
FWD_COMPAT    = create_body({99: c_text('future-field')})

# ---------- MUST-reject bodies (88 §4.1/§4.2/§4.3/§4.4/§6.6) -- crafted invalid, no oracle output ----------
# (a) non-deterministic CBOR: key 0 encoded in non-shortest form (0x18 0x00 instead of 0x00). §4.1
NONSHORTEST_KEY = bytes([0xa1, 0x18, 0x00, 0x00])
# (b) unknown NEGATIVE key (-1 = 0x20) on an otherwise-valid CREATE. §4.4 -> reject. Build canonically
#     (6 entries -> 0xa6), then splice a 7th entry (-1 -> 9) after the last key (-1 sorts after all
#     non-negative keys because 0x20 is bytewise-greater than 0x00..0x0d) and bump 0xa6 -> 0xa7.
UNKNOWN_NEG_KEY = c_map({0: c_uint(COMMERCE_MANDATE_CREATE_REQ), 1: c_bytes(CORR),
                         2: c_text('p'), 3: c_text('q'), 4: VALID_AMOUNT, 13: c_uint(0x03)})
UNKNOWN_NEG_KEY = bytes([0xa7]) + UNKNOWN_NEG_KEY[1:] + c_nint(-1) + c_uint(9)
# (c) missing REQUIRED amount(4) on a CREATE. §4.1/§6.1 -> reject.
MISSING_AMOUNT = c_map({0: c_uint(COMMERCE_MANDATE_CREATE_REQ), 1: c_bytes(CORR),
                        2: c_text('payer:alice'), 3: c_text('payee:bob'), 13: c_uint(0x03)})
# (d) wrong CBOR major type for payer(2): uint where text is required. §4.1 -> reject.
WRONG_TYPE_PAYER = c_map({0: c_uint(COMMERCE_MANDATE_CREATE_REQ), 1: c_bytes(CORR),
                          2: c_uint(9), 3: c_text('payee:bob'), 4: VALID_AMOUNT, 13: c_uint(0x03)})
# (e) frame_kind contradicts the frame header: body says READ(0x0102) but validated as CREATE(0x0100).
#     §4.2 -> reject.
FRAMEKIND_MISMATCH = c_map({0: c_uint(COMMERCE_MANDATE_READ_REQ), 1: c_bytes(CORR),
                            2: c_text('payer:alice'), 3: c_text('payee:bob'), 4: VALID_AMOUNT, 13: c_uint(0x03)})
# (f) corr(1) is an Unsigned int, not the required byte string (envelope wrong type). §4.2 -> reject.
CORR_NOT_BYTES = c_map({0: c_uint(COMMERCE_MANDATE_CREATE_REQ), 1: c_uint(0x63),
                        2: c_text('payer:alice'), 3: c_text('payee:bob'), 4: VALID_AMOUNT, 13: c_uint(0x03)})
# (g) payload is not a map at all (a bare uint). §4.1 -> reject.
NOT_A_MAP = c_uint(5)
# (h) malformed `amount`: omits REQUIRED currency(2). §4.3 -> reject.
BAD_AMOUNT_MISSING_CUR = c_map({0: c_uint(COMMERCE_MANDATE_CREATE_REQ), 1: c_bytes(CORR),
                                2: c_text('payer:alice'), 3: c_text('payee:bob'),
                                4: c_map({0: c_uint(12345), 1: c_uint(2)}), 13: c_uint(0x03)})
# (i) malformed `amount`: scale(1) is text where an Unsigned int is required. §4.3 -> reject.
BAD_AMOUNT_WRONG_TYPE = c_map({0: c_uint(COMMERCE_MANDATE_CREATE_REQ), 1: c_bytes(CORR),
                               2: c_text('payer:alice'), 3: c_text('payee:bob'),
                               4: c_map({0: c_uint(12345), 1: c_text('two'), 2: c_text('USD')}), 13: c_uint(0x03)})
# (j) a settlement-intent leg whose `to` party is not a named party. §6.6 -> reject.
LEG_PARTY_NOT_NAMED = c_map({0: c_uint(COMMERCE_INTENT_PROPOSE_REQ), 1: c_bytes(CORR),
                             2: c_array([c_text('party:a'), c_text('party:b')]),
                             3: c_array([leg('party:a', 'party:c', VALID_AMOUNT)]),
                             7: c_uint(0x02)})

def dec(tcid, req, comment, frame_type, body_hex, result, expected=None, flags=None):
    o = {"tcId": tcid, "requirement": req, "comment": comment,
         "in": {"frameType": frame_type, "body": body_hex}, "result": result}
    if expected is not None: o["expected"] = expected
    if flags is not None: o["flags"] = flags
    return o

decode_tests = [
    dec(1, "88/4.1/deterministic-cbor-map", "valid COMMERCE_MANDATE_CREATE_REQ: envelope + payer + payee + amount + effect",
        COMMERCE_MANDATE_CREATE_REQ, hx(VALID_CREATE), "valid",
        {"frame_kind": COMMERCE_MANDATE_CREATE_REQ, "corr": hx(CORR)}),
    dec(2, "88/6.2/deterministic-cbor-map", "valid COMMERCE_MANDATE_READ_REQ: envelope + mandate_id + effect=read_only",
        COMMERCE_MANDATE_READ_REQ, hx(VALID_READ), "valid",
        {"frame_kind": COMMERCE_MANDATE_READ_REQ, "corr": hx(CORR)}),
    dec(3, "88/6.6/deterministic-cbor-map", "valid COMMERCE_INTENT_PROPOSE_REQ: parties + legs (from/to named) + effect",
        COMMERCE_INTENT_PROPOSE_REQ, hx(VALID_PROPOSE), "valid",
        {"frame_kind": COMMERCE_INTENT_PROPOSE_REQ, "corr": hx(CORR)}),
    dec(4, "88/8.1/approval-required-distinct-outcome", "valid COMMERCE_ERROR: code=approval_required carries approval_id (a held, NOT-executed outcome)",
        COMMERCE_ERROR, hx(VALID_ERROR), "valid",
        {"frame_kind": COMMERCE_ERROR, "corr": hx(CORR)}),
    dec(5, "88/4.4/forward-compat-accept-nonneg", "unknown NON-negative key (99) MUST be accepted",
        COMMERCE_MANDATE_CREATE_REQ, hx(FWD_COMPAT), "acceptable",
        {"frame_kind": COMMERCE_MANDATE_CREATE_REQ, "corr": hx(CORR)}, ["ForwardCompat"]),
    dec(6, "88/4.1/non-deterministic-cbor-MUST-reject", "key 0 in non-shortest form (0x18 0x00)",
        COMMERCE_MANDATE_CREATE_REQ, hx(NONSHORTEST_KEY), "invalid", None, ["MustReject", "NonDeterministicCBOR"]),
    dec(7, "88/4.4/unknown-negative-key-MUST-reject", "unknown NEGATIVE integer key (-1)",
        COMMERCE_MANDATE_CREATE_REQ, hx(UNKNOWN_NEG_KEY), "invalid", None, ["MustReject", "UnknownNegativeKey"]),
    dec(8, "88/4.1/missing-required-key-MUST-reject", "COMMERCE_MANDATE_CREATE_REQ missing REQUIRED amount(4)",
        COMMERCE_MANDATE_CREATE_REQ, hx(MISSING_AMOUNT), "invalid", None, ["MustReject", "MissingRequiredKey"]),
    dec(9, "88/4.1/wrong-major-type-MUST-reject", "payer(2) is uint where text is required",
        COMMERCE_MANDATE_CREATE_REQ, hx(WRONG_TYPE_PAYER), "invalid", None, ["MustReject", "WrongMajorType"]),
    dec(10, "88/4.2/frame-kind-mismatch-MUST-reject", "frame_kind says READ(0x0102) but frame is CREATE(0x0100)",
        COMMERCE_MANDATE_CREATE_REQ, hx(FRAMEKIND_MISMATCH), "invalid", None, ["MustReject", "FrameKindMismatch"]),
    dec(11, "88/4.2/corr-not-bytes-MUST-reject", "corr(1) is an unsigned int, not the required byte string",
        COMMERCE_MANDATE_CREATE_REQ, hx(CORR_NOT_BYTES), "invalid", None, ["MustReject", "EnvelopeWrongType"]),
    dec(12, "88/4.1/payload-not-a-map-MUST-reject", "payload is a bare uint, not a CBOR map",
        COMMERCE_MANDATE_CREATE_REQ, hx(NOT_A_MAP), "invalid", None, ["MustReject", "NotAMap"]),
    dec(13, "88/4.3/malformed-amount-MUST-reject", "amount omits REQUIRED currency(2)",
        COMMERCE_MANDATE_CREATE_REQ, hx(BAD_AMOUNT_MISSING_CUR), "invalid", None, ["MustReject", "MalformedAmount"]),
    dec(14, "88/4.3/malformed-amount-wrong-type-MUST-reject", "amount scale(1) is text where an unsigned int is required",
        COMMERCE_MANDATE_CREATE_REQ, hx(BAD_AMOUNT_WRONG_TYPE), "invalid", None, ["MustReject", "MalformedAmount"]),
    dec(15, "88/6.6/leg-party-not-in-parties-MUST-reject", "a leg names a `to` party (party:c) that is not in `parties`",
        COMMERCE_INTENT_PROPOSE_REQ, hx(LEG_PARTY_NOT_NAMED), "invalid", None, ["MustReject", "LegPartyNotNamed"]),
]

# Only commerce.body.decode is emitted: its `in` is flat (frameType + hex body), so adapters that do
# not implement it skip gracefully (Unimplemented) rather than erroring on a nested-typed input. It
# grades the core wire contract (the §4 MUST-reject clauses + envelope decode incl. the byte-string
# corr, the §4.3 monetary-amount well-formedness, and the §6.6 leg-party-membership rule). Canonical
# ENCODING is covered by the reference impl's own cross-validation round-trip (zz_commerce_oracle_xval_test.go).
groups = [
    {"op": "commerce.body.decode", "profile": "Standard", "tests": decode_tests},
]
json.dump(groups, sys.stdout, indent=2)
sys.stdout.write("\n")
