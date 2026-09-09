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
# WAVE-1 EXTENSION (NPAMP-REG 30_protocol_registry.md §6, commit 58bd68d): 0x06 NLIP, 0x07 ANP,
# 0x08 AGNTCY, 0x09 AP2, 0x0A x402 are now standards-assigned protocol_id values. The BridgeEnvelope
# codec (impl/go/bridge_bodies.go decodeEnvelopeValue/encodeEnvelopeValue) treats protocol_id as an
# opaque scalar -- "a structural decoder accepts any value" (impl/go/bridge.go) -- so no per-protocol
# impl branch exists or is needed; these cases exercise that same generic envelope machinery at the
# five new code points, each dressed in a foreign-message shape grounded in that protocol's own map
# document (spec/companion/70_map_nlip.md, 63_map_anp.md, 6f_map_agntcy.md, 65_map_ap2.md,
# 71_map_x402.md) and, through them, the protocol's own published specification. See the per-case
# comments below for the exact grounding and the chosen carriage variant.
#
# WIDENING (NPAMP-REG 30_protocol_registry.md §8.4): protocol_id is now u16 big-endian (formerly u8).
# Every value above (0x01-0x0A) migrates losslessly to its two-octet zero-extension (0xNN -> 0x00NN);
# the numeric protocol identifiers, carriage classes, and expected fields below are UNCHANGED by the
# widening -- only the wire encoding of protocol_id gains a leading zero octet (be16() below, in place
# of the prior single protocol byte).
#
# Run: python3 test-vectors/gen/bridge_oracle.py  -> writes bridge testGroups to stdout as JSON.
import base64, json, sys

# ---------- independent big-endian TLV / envelope constructor (spec 10 §3/§4/§7; core §4.5) ----------
def be16(n):            return bytes([(n >> 8) & 0xFF, n & 0xFF])
def tlv(t, v):          return be16(t) + be16(len(v)) + v         # Type u16, Length u16, Value
def hx(b):              return b.hex()

def envelope_value(protocol, kind, content, flags, corr, method):
    # §4: protocol_id u16 (big-endian; NPAMP-REG 30_protocol_registry.md §8.4 widening -- formerly
    #     u8, a pre-widening value 0xNN migrating losslessly to 0x00NN), message_kind u8,
    #     content_type u8, flags u8, corr_len u8, correlation_id, method_len u8, method. corr/method
    #     are each length-prefixed by a single u8 (<= 255 octets).
    assert len(corr) <= 255 and len(method) <= 255
    return (be16(protocol) + bytes([kind, content, flags, len(corr)]) + corr
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

# ---------- independent deterministic-CBOR HTTP-Carriage Object constructor (spec 21 §4.1/§4.2) ----------
# Hand-rolled, from-scratch RFC 8949 canonical-CBOR encoder for exactly the shapes the x402 wave-1
# vector needs (a small uint-keyed map in ascending key order, text strings, byte strings, arrays of
# 2-element [name, value] header entries). NOT reused from any N-PAMP implementation and NOT a general
# CBOR library -- it implements only the definite-length canonical forms RFC 8949 §4.2.1 requires for
# the values used here (arguments < 2^16), which is all this fixture needs.
def cbor_head(major, n):
    if n < 24:      return bytes([(major << 5) | n])
    if n < 256:     return bytes([(major << 5) | 24, n])
    if n < 65536:   return bytes([(major << 5) | 25]) + n.to_bytes(2, 'big')
    raise ValueError("cbor_head: argument too large for this minimal fixture encoder")

def cbor_uint(n):         return cbor_head(0, n)
def cbor_text(s):         b = s.encode('utf-8'); return cbor_head(3, len(b)) + b
def cbor_bstr(b):         return cbor_head(2, len(b)) + b
def cbor_array(items):    return cbor_head(4, len(items)) + b''.join(items)

def http_header_entry(name, value_bytes):
    # §4.4: a header field entry is a 2-element array [name (text, lowercase), value (bstr)].
    return cbor_array([cbor_text(name), cbor_bstr(value_bytes)])

def http_carriage_object(kind, method=None, target=None, status=None, headers=None, body=None):
    # §4.1/§4.2: a deterministic-CBOR map with unsigned-integer keys, emitted in ascending numeric
    # order, OPTIONAL keys omitted (never encoded as null) when absent. Object keys used here:
    # 1 kind (REQUIRED), 2 method / 3 target (request only), 6 status (response only), 8 headers,
    # 9 body -- the full key set §4.2 defines; only the ones a given case needs are passed.
    entries = [(1, cbor_uint(kind))]
    if method is not None: entries.append((2, cbor_text(method)))
    if target is not None: entries.append((3, cbor_text(target)))
    if status is not None: entries.append((6, cbor_uint(status)))
    if headers is not None:
        entries.append((8, cbor_array([http_header_entry(n, v) for n, v in headers])))
    if body is not None: entries.append((9, cbor_bstr(body)))
    entries.sort(key=lambda kv: kv[0])
    out = cbor_head(5, len(entries))
    for k, v in entries:
        out += cbor_uint(k) + v
    return out

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
# Wave-1 standards-assigned protocol_id values (NPAMP-REG 30_protocol_registry.md §6, commit 58bd68d).
PROTO_NLIP=0x06; PROTO_ANP=0x07; PROTO_AGNTCY=0x08; PROTO_AP2=0x09; PROTO_X402=0x0A
CONTENT_JSON=0x01
CONTENT_CBOR=0x02
# content_type 0x04: "the media type is carried in the OpaqueContentType TLV" (spec 10 §4) -- used by
# the AP2 SD-JWT Mandate case below, whose media type the core content_type registry does not yet
# enumerate a dedicated value for (65_map_ap2.md §3, which explicitly notes this rather than inventing
# a value).
CONTENT_OPAQUE_TLV=0x04
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

# ---------- wave-1 fixtures (each grounded in the named protocol's own map document / spec) ----------
CORR_NLIP = b'NL01'; CORR_ANP = b'AN01'; CORR_AGNTCY = b'AC01'; CORR_AP2 = b'AP01'; CORR_X402 = b'X402'

# NLIP (0x06): ECMA-430 message object, REQUIRED fields format/subformat/content (70_map_nlip.md §9,
# "confirmed from NLIP's primary sources"; carried directly as the foreign event of the STREAM/WebSocket
# JSON-fallback binding per §2's content_type=0x01 row -- no HTTP-Carriage Object wrapper on this path).
FOREIGN_NLIP_REQ = b'{"format":"text","subformat":"english","content":"What is the weather in Paris?"}'
FOREIGN_NLIP_RES = b'{"format":"text","subformat":"english","content":"Clear skies, 18C."}'

# ANP (0x07): a did:wba-identified meta-protocol negotiation exchange (63_map_anp.md §1/§7, "meta-
# protocol negotiation" row), carried directly under Class OPAQUE with content_type=0x01 (§2 row 90).
# "https://www.w3.org/ns/did/v1" is the real W3C DID v1 JSON-LD context; the did:wba subject below uses
# a synthetic label, not a resolvable identifier -- this is fixture data illustrating the documented
# JSON-LD shape, not a captured exchange.
FOREIGN_ANP_REQ = (b'{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:wba:test-fixture:agents:planner",'
                    b'"type":"NegotiationRequest","proposal":"vnd.test-fixture.route-planning-v1+json"}')
FOREIGN_ANP_RES = (b'{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:wba:test-fixture:agents:planner",'
                    b'"type":"NegotiationResponse","accepted":"vnd.test-fixture.route-planning-v1+json"}')

# AGNTCY (0x08): an ACP `POST /runs` invocation and its result (6f_map_agntcy.md §7 row "ACP create a
# run"), carried directly under Class OPAQUE with content_type=0x01 for ACP's JSON bodies (§2 row 128).
FOREIGN_AGNTCY_REQ = b'{"agent_id":"planner-agent","input":{"messages":[{"role":"user","content":"plan a trip"}]}}'
FOREIGN_AGNTCY_RES = b'{"run_id":"run_0001","status":"success","output":{"messages":[{"role":"assistant","content":"plan ready"}]}}'

# AP2 (0x09): a Checkout Mandate and a Payment Mandate -- each a signed SD-JWT verifiable credential
# (65_map_ap2.md §2/§4.1), carried octet-for-octet as the Bridge foreign message with content_type
# 0x04 (OpaqueContentType TLV; §3 notes no dedicated SD-JWT value exists). The `vct` values
# `mandate.checkout.1` / `mandate.payment.1` are the confirmed AP2 values (§2); header/payload/
# signature/disclosure below are an illustrative SD-JWT-SHAPED fixture, not a real credential.
FOREIGN_AP2_CHECKOUT_MANDATE = (b'eyJhbGciOiJFUzI1NiIsInR5cCI6InZjK3NkLWp3dCJ9.'
                                 b'eyJ2Y3QiOiJtYW5kYXRlLmNoZWNrb3V0LjEiLCJpc3MiOiJkaWQ6dGVzdC1maXh0dXJlOmlzc3VlciJ9.c2ln~')
FOREIGN_AP2_PAYMENT_MANDATE = (b'eyJhbGciOiJFUzI1NiIsInR5cCI6InZjK3NkLWp3dCJ9.'
                                b'eyJ2Y3QiOiJtYW5kYXRlLnBheW1lbnQuMSIsImlzcyI6ImRpZDp0ZXN0LWZpeHR1cmU6aXNzdWVyIn0.c2ln~')

# x402 (0x0A): the initial resource GET and the `402 Payment Required` challenge (71_map_x402.md §4
# table, §6), the ONE wave-1 protocol whose sole registered carriage is HTTP with content_type=0x02
# (a deterministic-CBOR HTTP-Carriage Object per NPAMP-CC-HTTP §4.1/§4.2, not a JSON-direct fallback --
# unlike NLIP/ANP/AGNTCY, x402's map document defines no Class OPAQUE alternative). The `PaymentRequired`
# JSON fields (x402Version, resource, accepts[].{scheme,network,amount,asset,payTo,maxTimeoutSeconds})
# are the confirmed field set (71_map_x402.md §5 table); the header value is carried as opaque octets
# per HTTP-Carriage §4.4, so it is base64-encoded exactly as x402's own PAYMENT-REQUIRED header does.
# `resource` is the relative target (not a fabricated external endpoint) to keep this fixture honest.
X402_PAYREQ_JSON = (b'{"x402Version":1,"resource":"/paid-endpoint",'
                     b'"accepts":[{"scheme":"exact","network":"eip155:8453","amount":"10000",'
                     b'"asset":"0x0000000000000000000000000000000000000000",'
                     b'"payTo":"0x0000000000000000000000000000000000000000","maxTimeoutSeconds":60}]}')
FOREIGN_X402_REQ = http_carriage_object(kind=1, method="GET", target="/paid-endpoint")
FOREIGN_X402_RES = http_carriage_object(kind=2, status=402,
                                         headers=[("payment-required", base64.b64encode(X402_PAYREQ_JSON))])

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

    # ---- wave-1 (NPAMP-REG §6 0x06-0x0A): one request+response pair per newly assigned protocol_id,
    # each demonstrating that protocol's own registered carriage class and content_type. ----
    case("request_nlip_stream_session_open", "30/6/wave1-nlip-request",
         "BRIDGE_REQUEST (NLIP 0x06, STREAM/WebSocket JSON-fallback binding): envelope + "
         "SafetyLabel(non_idempotent_write, the ECMA-431 POST/stream-open floor, 70_map_nlip.md §7) "
         "+ an ECMA-430 NLIP message object carried verbatim; NLIP has no method namespace (§4.1), so "
         "method_len=0",
         BRIDGE_REQUEST, PROTO_NLIP, KIND_REQUEST, CONTENT_JSON, 0x00, CORR_NLIP, b'',
         (EFF_NONIDEMPOTENT, b'/nlip'), FOREIGN_NLIP_REQ),
    case("response_nlip_stream_reply", "30/6/wave1-nlip-reply",
         "BRIDGE_RESPONSE (NLIP 0x06) echoes the request correlation_id; no SafetyLabel on a reply",
         BRIDGE_RESPONSE, PROTO_NLIP, KIND_RESPONSE, CONTENT_JSON, 0x00, CORR_NLIP, b'',
         None, FOREIGN_NLIP_RES),

    case("request_anp_meta_protocol_negotiation", "30/6/wave1-anp-request",
         "BRIDGE_REQUEST (ANP 0x07, Class OPAQUE JSON-LD): envelope + "
         "SafetyLabel(non_idempotent_write, 63_map_anp.md §7 'meta-protocol negotiation' row) + a "
         "did:wba-identified negotiation request carried verbatim",
         BRIDGE_REQUEST, PROTO_ANP, KIND_REQUEST, CONTENT_JSON, 0x00, CORR_ANP, b'meta-protocol-negotiation',
         (EFF_NONIDEMPOTENT, b'meta-protocol'), FOREIGN_ANP_REQ),
    case("response_anp_meta_protocol_negotiation", "30/6/wave1-anp-reply",
         "BRIDGE_RESPONSE (ANP 0x07) echoes the request correlation_id and method; no SafetyLabel on "
         "a reply",
         BRIDGE_RESPONSE, PROTO_ANP, KIND_RESPONSE, CONTENT_JSON, 0x00, CORR_ANP, b'meta-protocol-negotiation',
         None, FOREIGN_ANP_RES),

    case("request_agntcy_acp_create_run", "30/6/wave1-agntcy-request",
         "BRIDGE_REQUEST (AGNTCY 0x08, ACP over Class OPAQUE): envelope + "
         "SafetyLabel(non_idempotent_write, 6f_map_agntcy.md §7 'ACP create a run' row) + a "
         "`POST /runs` JSON body carried verbatim",
         BRIDGE_REQUEST, PROTO_AGNTCY, KIND_REQUEST, CONTENT_JSON, 0x00, CORR_AGNTCY, b'POST /runs',
         (EFF_NONIDEMPOTENT, b'/runs'), FOREIGN_AGNTCY_REQ),
    case("response_agntcy_acp_create_run", "30/6/wave1-agntcy-reply",
         "BRIDGE_RESPONSE (AGNTCY 0x08) echoes the request correlation_id and method; no SafetyLabel "
         "on a reply",
         BRIDGE_RESPONSE, PROTO_AGNTCY, KIND_RESPONSE, CONTENT_JSON, 0x00, CORR_AGNTCY, b'POST /runs',
         None, FOREIGN_AGNTCY_RES),

    case("request_ap2_checkout_mandate", "30/6/wave1-ap2-request",
         "BRIDGE_REQUEST (AP2 0x09, standalone Mandate carriage): envelope, content_type=0x04 "
         "(OpaqueContentType TLV; no dedicated SD-JWT value exists, 65_map_ap2.md §3) + a Checkout "
         "Mandate SD-JWT carried octet-for-octet; serving a Mandate document is read_only "
         "(65_map_ap2.md §4.1), so no SafetyLabel; AP2 defines no operation-method namespace, so "
         "method_len=0",
         BRIDGE_REQUEST, PROTO_AP2, KIND_REQUEST, CONTENT_OPAQUE_TLV, 0x00, CORR_AP2, b'',
         None, FOREIGN_AP2_CHECKOUT_MANDATE),
    case("response_ap2_payment_mandate", "30/6/wave1-ap2-reply",
         "BRIDGE_RESPONSE (AP2 0x09) echoes the request correlation_id and carries a Payment Mandate "
         "SD-JWT octet-for-octet; read_only, no SafetyLabel",
         BRIDGE_RESPONSE, PROTO_AP2, KIND_RESPONSE, CONTENT_OPAQUE_TLV, 0x00, CORR_AP2, b'',
         None, FOREIGN_AP2_PAYMENT_MANDATE),

    case("request_x402_initial_resource_get", "30/6/wave1-x402-request",
         "BRIDGE_REQUEST (x402 0x0A, native HTTP binding): envelope, content_type=0x02 (deterministic-"
         "CBOR HTTP-Carriage Object per NPAMP-CC-HTTP §4.1/§4.2 -- x402's sole registered carriage) + "
         "a plain GET carrying no payment header; read_only (71_map_x402.md §6), so no SafetyLabel",
         BRIDGE_REQUEST, PROTO_X402, KIND_REQUEST, CONTENT_CBOR, 0x00, CORR_X402, b'GET /paid-endpoint',
         None, FOREIGN_X402_REQ),
    case("response_x402_payment_required", "30/6/wave1-x402-reply",
         "BRIDGE_RESPONSE (x402 0x0A) carries the `402 Payment Required` challenge as a deterministic-"
         "CBOR HTTP-Carriage Object (status=402, a base64-encoded PaymentRequired object in the "
         "lowercase `payment-required` header per HTTP-Carriage §4.4); read_only (71_map_x402.md §6), "
         "so no SafetyLabel",
         BRIDGE_RESPONSE, PROTO_X402, KIND_RESPONSE, CONTENT_CBOR, 0x00, CORR_X402, b'GET /paid-endpoint',
         None, FOREIGN_X402_RES),
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
_ev_bad = be16(PROTO_MCP) + bytes([KIND_REQUEST, CONTENT_JSON, 0x00, 0x08]) + b'\xaa\xbb\xcc'
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
_ev_trail = be16(PROTO_MCP) + bytes([KIND_REQUEST, CONTENT_JSON, 0x00, len(CORR)]) + CORR + bytes([4]) + b'toolcall'
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

# wave-1: correlation is per NPAMP-BRIDGE §5 identifier equality, independent of protocol_id -- these
# prove that generic property holds at two of the newly assigned code points.
NLIP_REQ_PL = payload(envelope_value(PROTO_NLIP, KIND_REQUEST, CONTENT_JSON, 0x00, CORR_NLIP, b''), None, FOREIGN_NLIP_REQ)
NLIP_RES_MATCH = payload(envelope_value(PROTO_NLIP, KIND_RESPONSE, CONTENT_JSON, 0x00, CORR_NLIP, b''), None, FOREIGN_NLIP_RES)
AGNTCY_REQ_PL = payload(envelope_value(PROTO_AGNTCY, KIND_REQUEST, CONTENT_JSON, 0x00, CORR_AGNTCY, b'POST /runs'), None, FOREIGN_AGNTCY_REQ)
AGNTCY_RES_NOMATCH = payload(envelope_value(PROTO_AGNTCY, KIND_RESPONSE, CONTENT_JSON, 0x00, OTHER_CORR, b'POST /runs'), None, FOREIGN_AGNTCY_RES)

correlate_tests += [
    cor(4, "30/6/wave1-nlip-reply-correlates", "a BRIDGE_RESPONSE (NLIP 0x06) echoing the request correlation_id correlates",
        BRIDGE_REQUEST, hx(NLIP_REQ_PL), BRIDGE_RESPONSE, hx(NLIP_RES_MATCH), True),
    cor(5, "30/6/wave1-agntcy-reply-different-corr-does-not-correlate",
        "a BRIDGE_RESPONSE (AGNTCY 0x08) with a different correlation_id does NOT correlate",
        BRIDGE_REQUEST, hx(AGNTCY_REQ_PL), BRIDGE_RESPONSE, hx(AGNTCY_RES_NOMATCH), False),
]

groups = [
    {"op": "bridge.envelope.decode", "profile": "Standard", "tests": decode_tests},
    {"op": "bridge.envelope.encode", "profile": "Standard", "tests": encode_tests},
    {"op": "bridge.correlate", "profile": "Standard", "tests": correlate_tests},
]
json.dump(groups, sys.stdout, indent=2)
sys.stdout.write("\n")
