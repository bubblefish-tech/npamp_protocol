#!/usr/bin/env python3
# Independent NPAMP-BRIDGE conformance-vector generator (byte-layout oracle).
#
# NON-CIRCULARITY (test-vectors/README.md; 55_conformance_requirements.md §5.2): the wire bytes and
# expected values in the emitted vectors are produced by THIS from-scratch big-endian TLV/envelope
# constructor, derived DIRECTLY from spec/companion/10_bridge_framework.md §3 (payload layout), §4
# (BridgeEnvelope value layout), §5 (correlation), §6 (errors), and §7 (SafetyLabel value layout),
# together with the core extension-TLV encoding (Type u16 big-endian, Length u16 big-endian, Value;
# tlv.go / core §4.5) -- NOT dumped from impl/go/bridge*.go (the implementation under test). A passing
# bridge.envelope.* / bridge.correlate vector therefore proves the Go impl AGREES with an independent
# oracle; it does not grade the impl against its own output.
#
# Unlike the native operation channels (Memory/Settlement/Stream), a Bridge payload is NOT a
# deterministic-CBOR map: it is a fixed-order TLV envelope carried AROUND a foreign message that is
# preserved octet-for-octet (§1 Transparency). This oracle constructs that layout byte for byte.
#
# The MUST-reject cases carry no `expected` and are the spec's own §4/§5/§7 reject clauses crafted as
# deliberately absent/truncated/contradicting-kind/empty-or-nonempty-corr envelopes -- inherently
# non-circular.
#
# Run: python3 test-vectors/gen/bridge_oracle.py  -> writes bridge testGroups to stdout as JSON.
import json, sys

# ---------- independent big-endian TLV / envelope constructor (spec 10 §3/§4/§7; core §4.5) ----------
def be16(n):            return bytes([(n >> 8) & 0xFF, n & 0xFF])
def tlv(t, v):          return be16(t) + be16(len(v)) + v         # Type u16, Length u16, Value
def hx(b):              return b.hex()

def envelope_value(protocol, kind, content, flags, corr, method):
    # §4: protocol_id u8, message_kind u8, content_type u8, flags u8, corr_len u8, correlation_id,
    #     method_len u8, method. corr/method are each length-prefixed by a single u8 (<= 255 octets).
    assert len(corr) <= 255 and len(method) <= 255
    return (bytes([protocol, kind, content, flags, len(corr)]) + corr
            + bytes([len(method)]) + method)

def safety_value(effect, scope):
    # §7: effect u8, scope_len u8, scope.
    assert len(scope) <= 255
    return bytes([effect, len(scope)]) + scope

def payload(env_val, safety_val, foreign):
    # §3: BridgeEnvelope TLV (0x0010) [+ SafetyLabel TLV (0x0013)] + foreign message (verbatim).
    out = tlv(TLV_ENVELOPE, env_val)
    if safety_val is not None:
        out += tlv(TLV_SAFETY, safety_val)
    return out + foreign

# ---------- code points (spec 10 §2/§4/§7) ----------
TLV_ENVELOPE = 0x0010
TLV_SAFETY   = 0x0013

BRIDGE_REQUEST     = 0x0100
BRIDGE_RESPONSE    = 0x0101
BRIDGE_ERROR       = 0x0102
BRIDGE_NOTIFY      = 0x0103
BRIDGE_STREAM_DATA = 0x0104
BRIDGE_STREAM_END  = 0x0105

KIND_REQUEST=0x01; KIND_RESPONSE=0x02; KIND_NOTIFICATION=0x03
KIND_ERROR=0x04;   KIND_STREAM_DATA=0x05; KIND_STREAM_END=0x06

PROTO_MCP=0x01; PROTO_A2A=0x02
CONTENT_JSON=0x01
EFF_READ_ONLY=0x00; EFF_IDEMPOTENT=0x01; EFF_NONIDEMPOTENT=0x02; EFF_DESTRUCTIVE=0x03
FLAG_FINAL=0x01

# ---------- shared fixtures ----------
CORR = bytes.fromhex('0a0b0c0d')                                   # a non-empty per-exchange correlation id
OTHER_CORR = bytes.fromhex('ffffffff')                            # a different id (correlation must fail)
FOREIGN_REQ = b'{"jsonrpc":"2.0","id":1,"method":"tools/call"}'   # MCP JSON-RPC request, carried verbatim (§1)
FOREIGN_RES = b'{"jsonrpc":"2.0","id":1,"result":{"ok":true}}'    # JSON-RPC success result
FOREIGN_ERR = b'{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}'  # foreign error object, verbatim (§6)
FOREIGN_NTF = b'{"jsonrpc":"2.0","method":"notifications/message"}'  # one-way notification
FOREIGN_CHUNK = b'chunk-0'

# ---------- accepted envelope cases (each yields a decode vector AND an encode vector) ----------
# A "case" fully describes an accepted Bridge payload; the oracle computes its canonical bytes once and
# uses them for both the decode expectation and the encode expectation, so the two ops cannot disagree.
def case(name, req, comment, ft, protocol, kind, content, flags, corr, method, safety, foreign):
    ev = envelope_value(protocol, kind, content, flags, corr, method)
    sv = None if safety is None else safety_value(safety[0], safety[1])
    pl = payload(ev, sv, foreign)
    expected = {
        "protocol_id": protocol, "message_kind": kind, "content_type": content,
        "flags": flags, "final": bool(flags & FLAG_FINAL),
        "corr": hx(corr), "method": method.decode('utf-8'),
        "safety": (None if safety is None else {"effect": safety[0], "scope": safety[1].decode('utf-8')}),
        "foreign": hx(foreign),
    }
    return {"name": name, "req": req, "comment": comment, "ft": ft, "payload": pl, "expected": expected}

ACCEPT = [
    case("request_mcp_tools_call", "10/4/envelope-request",
         "BRIDGE_REQUEST (MCP tools/call): envelope + SafetyLabel(non_idempotent_write) + foreign JSON verbatim",
         BRIDGE_REQUEST, PROTO_MCP, KIND_REQUEST, CONTENT_JSON, 0x00, CORR, b'tools/call',
         (EFF_NONIDEMPOTENT, b'fs:/tmp'), FOREIGN_REQ),
    case("response_echo_corr", "10/5/reply-echoes-corr",
         "BRIDGE_RESPONSE echoes the request correlation_id; no SafetyLabel on a reply",
         BRIDGE_RESPONSE, PROTO_MCP, KIND_RESPONSE, CONTENT_JSON, 0x00, CORR, b'tools/call',
         None, FOREIGN_RES),
    case("error_foreign_object_verbatim", "10/6/preserve-foreign-error",
         "BRIDGE_ERROR carries the foreign protocol's own JSON-RPC error object verbatim (never reduced to text)",
         BRIDGE_ERROR, PROTO_MCP, KIND_ERROR, CONTENT_JSON, 0x00, CORR, b'tools/call',
         None, FOREIGN_ERR),
    case("notify_corr_len_zero", "10/5/notify-corr-len-zero",
         "BRIDGE_NOTIFY (A2A) MUST set corr_len=0; one-way, no reply",
         BRIDGE_NOTIFY, PROTO_A2A, KIND_NOTIFICATION, CONTENT_JSON, 0x00, b'', b'notifications/message',
         None, FOREIGN_NTF),
    case("stream_data_reserved_flag_ignored", "10/4/reserved-flags-ignored",
         "BRIDGE_STREAM_DATA with a reserved flag bit (0x02) set: receiver MUST ignore it; final stays false",
         BRIDGE_STREAM_DATA, PROTO_MCP, KIND_STREAM_DATA, CONTENT_JSON, 0x02, CORR, b'tools/call',
         None, FOREIGN_CHUNK),
    case("stream_end_final_empty_foreign", "10/2/stream-end-final",
         "BRIDGE_STREAM_END sets the final flag (0x01) and carries an empty foreign message",
         BRIDGE_STREAM_END, PROTO_MCP, KIND_STREAM_END, CONTENT_JSON, FLAG_FINAL, CORR, b'tools/call',
         None, b''),
]

def dec(tcid, req, comment, ft, payload_hex, result, expected=None, flags=None):
    o = {"tcId": tcid, "requirement": req, "comment": comment,
         "in": {"frameType": ft, "payload": payload_hex}, "result": result}
    if expected is not None: o["expected"] = expected
    if flags is not None: o["flags"] = flags
    return o

# ---------- bridge.envelope.decode: accepted + MUST-reject ----------
decode_tests = []
tc = 0
for c in ACCEPT:
    tc += 1
    decode_tests.append(dec(tc, c["req"], c["comment"], c["ft"], hx(c["payload"]), "valid", c["expected"]))

# MUST-reject payloads (spec 10 §4/§5/§7) -- crafted invalid, no oracle output.
# (a) envelope absent: the payload's first TLV is a SafetyLabel (0x0013), not the REQUIRED envelope. §4
REJ_ENV_ABSENT = tlv(TLV_SAFETY, safety_value(EFF_READ_ONLY, b'x')) + FOREIGN_REQ
# (b) envelope TLV truncated: header declares length 32 but far fewer octets follow. §4
REJ_ENV_TRUNC_TLV = be16(TLV_ENVELOPE) + be16(32) + b'\x01\x01\x01\x00\x04'
# (c) envelope value truncated: corr_len=8 but only 3 correlation octets present. §4
_ev_bad = bytes([PROTO_MCP, KIND_REQUEST, CONTENT_JSON, 0x00, 0x08]) + b'\xaa\xbb\xcc'
REJ_ENV_VALUE_TRUNC = tlv(TLV_ENVELOPE, _ev_bad)
# (d) message_kind contradicts frame type: frame is BRIDGE_REQUEST but kind says response (0x02). §4
REJ_KIND_MISMATCH = payload(envelope_value(PROTO_MCP, KIND_RESPONSE, CONTENT_JSON, 0x00, CORR, b'tools/call'), None, FOREIGN_REQ)
# (e) BRIDGE_REQUEST with an empty correlation_id (corr_len=0). §5
REJ_REQ_EMPTY_CORR = payload(envelope_value(PROTO_MCP, KIND_REQUEST, CONTENT_JSON, 0x00, b'', b'tools/call'), None, FOREIGN_REQ)
# (f) BRIDGE_NOTIFY with a non-empty correlation_id (corr_len>0). §5/§8
REJ_NOTIFY_NONEMPTY_CORR = payload(envelope_value(PROTO_A2A, KIND_NOTIFICATION, CONTENT_JSON, 0x00, CORR, b'notifications/message'), None, FOREIGN_NTF)
# (g) a reply (BRIDGE_RESPONSE) with an empty correlation_id: cannot echo a non-empty request id. §5
REJ_REPLY_EMPTY_CORR = payload(envelope_value(PROTO_MCP, KIND_RESPONSE, CONTENT_JSON, 0x00, b'', b'tools/call'), None, FOREIGN_RES)
# (h) trailing octets INSIDE the envelope value: method_len=4 but 7 method octets present. §4
_ev_trail = bytes([PROTO_MCP, KIND_REQUEST, CONTENT_JSON, 0x00, len(CORR)]) + CORR + bytes([4]) + b'toolcall'
REJ_ENV_TRAILING = tlv(TLV_ENVELOPE, _ev_trail) + FOREIGN_REQ
# (i) a present SafetyLabel TLV whose value is truncated: scope_len=5 but only 1 scope octet. §7
_env_ok = envelope_value(PROTO_MCP, KIND_REQUEST, CONTENT_JSON, 0x00, CORR, b'tools/call')
_bad_safety_val = bytes([EFF_NONIDEMPOTENT, 0x05]) + b'\x66'
REJ_SAFETY_TRUNC = tlv(TLV_ENVELOPE, _env_ok) + tlv(TLV_SAFETY, _bad_safety_val) + FOREIGN_REQ
# (j) not a Bridge frame type: PING (0x0001) is a reserved all-channel frame, not a Bridge op. §2
REJ_NOT_BRIDGE_FT = payload(envelope_value(PROTO_MCP, KIND_REQUEST, CONTENT_JSON, 0x00, CORR, b'tools/call'), None, FOREIGN_REQ)

rejects = [
    (REJ_ENV_ABSENT,           BRIDGE_REQUEST, "10/4/envelope-absent-MUST-reject",           "payload's first TLV is a SafetyLabel, not the REQUIRED BridgeEnvelope", ["MustReject", "EnvelopeAbsent"]),
    (REJ_ENV_TRUNC_TLV,        BRIDGE_REQUEST, "10/4/envelope-tlv-truncated-MUST-reject",    "BridgeEnvelope TLV length exceeds the remaining payload", ["MustReject", "EnvelopeTruncated"]),
    (REJ_ENV_VALUE_TRUNC,      BRIDGE_REQUEST, "10/4/envelope-value-truncated-MUST-reject",  "corr_len=8 but only 3 correlation octets present", ["MustReject", "EnvelopeTruncated"]),
    (REJ_KIND_MISMATCH,        BRIDGE_REQUEST, "10/4/message-kind-mismatch-MUST-reject",     "message_kind=response(0x02) contradicts frame type BRIDGE_REQUEST(0x0100)", ["MustReject", "MessageKindMismatch"]),
    (REJ_REQ_EMPTY_CORR,       BRIDGE_REQUEST, "10/5/request-empty-corr-MUST-reject",        "BRIDGE_REQUEST carries an empty correlation_id (corr_len=0)", ["MustReject", "CorrelationRule"]),
    (REJ_NOTIFY_NONEMPTY_CORR, BRIDGE_NOTIFY,  "10/5/notify-nonempty-corr-MUST-reject",      "BRIDGE_NOTIFY carries a non-empty correlation_id (corr_len>0)", ["MustReject", "CorrelationRule"]),
    (REJ_REPLY_EMPTY_CORR,     BRIDGE_RESPONSE,"10/5/reply-empty-corr-MUST-reject",          "BRIDGE_RESPONSE carries an empty correlation_id and cannot echo the request", ["MustReject", "CorrelationRule"]),
    (REJ_ENV_TRAILING,         BRIDGE_REQUEST, "10/4/envelope-trailing-octets-MUST-reject",  "method_len=4 but 7 method octets present (trailing octets in the envelope value)", ["MustReject", "EnvelopeTruncated"]),
    (REJ_SAFETY_TRUNC,         BRIDGE_REQUEST, "10/7/safetylabel-truncated-MUST-reject",     "present SafetyLabel TLV value is truncated (scope_len=5, 1 octet)", ["MustReject", "SafetyLabelMalformed"]),
    (REJ_NOT_BRIDGE_FT,        0x0001,         "10/2/not-a-bridge-frame-MUST-reject",        "frame type PING(0x0001) is not a Bridge operation frame", ["MustReject", "NotABridgeFrame"]),
]
for pl, ft, req, comment, fl in rejects:
    tc += 1
    decode_tests.append(dec(tc, req, comment, ft, hx(pl), "invalid", None, fl))

# ---------- bridge.envelope.encode: independent oracle asserts canonical output ----------
# `in.fields` fully describes an envelope (+ optional safety + foreign); the adapter builds the payload
# and the runner compares the produced hex to `expected.payload` (this oracle's canonical bytes).
def enc(tcid, req, comment, fields, expected_hex):
    return {"tcId": tcid, "requirement": req, "comment": comment,
            "in": {"fields": fields}, "expected": {"payload": expected_hex}, "result": "valid"}

encode_tests = []
tc = 0
for c in ACCEPT:
    tc += 1
    e = c["expected"]
    fields = {"frameType": c["ft"], "protocol_id": e["protocol_id"], "message_kind": e["message_kind"],
              "content_type": e["content_type"], "flags": e["flags"], "corr": e["corr"],
              "method": e["method"], "safety": e["safety"], "foreign": e["foreign"]}
    encode_tests.append(enc(tc, c["req"], "canonical encode of: " + c["comment"], fields, hx(c["payload"])))

# ---------- bridge.correlate: §5 match-by-identifier, not by sequence ----------
def cor(tcid, req, comment, req_ft, req_pl, rep_ft, rep_pl, match):
    return {"tcId": tcid, "requirement": req, "comment": comment,
            "in": {"requestFrameType": req_ft, "requestPayload": req_pl,
                   "replyFrameType": rep_ft, "replyPayload": rep_pl},
            "expected": {"match": match}, "result": "valid"}

REQ_PL   = payload(envelope_value(PROTO_MCP, KIND_REQUEST, CONTENT_JSON, 0x00, CORR, b'tools/call'), None, FOREIGN_REQ)
RES_MATCH = payload(envelope_value(PROTO_MCP, KIND_RESPONSE, CONTENT_JSON, 0x00, CORR, b'tools/call'), None, FOREIGN_RES)
RES_NOMATCH = payload(envelope_value(PROTO_MCP, KIND_RESPONSE, CONTENT_JSON, 0x00, OTHER_CORR, b'tools/call'), None, FOREIGN_RES)
STREAM_MATCH = payload(envelope_value(PROTO_MCP, KIND_STREAM_DATA, CONTENT_JSON, 0x00, CORR, b'tools/call'), None, FOREIGN_CHUNK)

correlate_tests = [
    cor(1, "10/5/reply-correlates", "BRIDGE_RESPONSE echoing the request correlation_id correlates",
        BRIDGE_REQUEST, hx(REQ_PL), BRIDGE_RESPONSE, hx(RES_MATCH), True),
    cor(2, "10/5/reply-different-corr-does-not-correlate", "a reply with a different correlation_id does NOT correlate",
        BRIDGE_REQUEST, hx(REQ_PL), BRIDGE_RESPONSE, hx(RES_NOMATCH), False),
    cor(3, "10/5/stream-reply-correlates", "a BRIDGE_STREAM_DATA chunk echoing the correlation_id correlates",
        BRIDGE_REQUEST, hx(REQ_PL), BRIDGE_STREAM_DATA, hx(STREAM_MATCH), True),
]

groups = [
    {"op": "bridge.envelope.decode", "profile": "Standard", "tests": decode_tests},
    {"op": "bridge.envelope.encode", "profile": "Standard", "tests": encode_tests},
    {"op": "bridge.correlate", "profile": "Standard", "tests": correlate_tests},
]
json.dump(groups, sys.stdout, indent=2)
sys.stdout.write("\n")
