"""Deterministic-CBOR decode + MUST-reject enforcement for the eight NPAMP native
operation channels (Capability §84, Immune §85, Settlement §86, Telemetry §87,
Commerce §88, Interaction §89, Workflow §8a, Knowledge §8b).

This is the Python mirror of the Go reference decoders (impl/go/{capability,immune,
settlement,telemetry,commerce,interaction,workflow,knowledge}_bodies.go + the shared
deterministic-CBOR codec memory_cbor.go). It carries its own deterministic-CBOR
decoder rather than a general CBOR library because the whole point of the graded
surface is REJECTING everything a deterministic-encoding receiver MUST reject:
indefinite lengths, non-shortest integer/length encodings, tags, floats, and
out-of-order or duplicate map keys (RFC 8949 §4.2.1). A permissive library would
silently accept those.

Decoded value types (mirror of the Go codec):
  major 0 unsigned int  -> int  (>= 0)
  major 1 negative int  -> int  (<  0)   value = -1 - arg
  major 2 byte string   -> bytes
  major 3 text string   -> str
  major 4 array         -> list
  major 5 map           -> CborMap  (preserves canonical key order)
  major 7 false/true/null -> False / True / None

Every validator returns the decoded CborMap on success and raises BodyError (or its
CborError base) on any structural fault. The corpus grades a "valid"/"acceptable"
vector as MUST-decode-OK and an "invalid" vector as MUST-raise.
"""
from __future__ import annotations

_MAX_INT64 = (1 << 63) - 1


class CborError(Exception):
    """A deterministic-CBOR decode fault (non-shortest, indefinite, tag, float,
    out-of-order/duplicate key, truncation, or trailing bytes)."""


class BodyError(CborError):
    """A structural body fault a receiver reports as malformed_request: not a map,
    frame_kind mismatch, missing/mistyped envelope or field, unknown negative /
    non-integer key, or a channel-specific cross-field violation."""


# ---------------------------------------------------------------------------
# CborMap: a CBOR map that preserves the canonical (decode) key order and the raw
# encoded key bytes, so re-encoding and key lookup are deterministic.
# ---------------------------------------------------------------------------
class CborMap:
    __slots__ = ("_entries",)

    def __init__(self):
        self._entries = []  # list[(key, val)]

    def _add(self, key, val):
        self._entries.append((key, val))

    def get(self, key):
        """Return (value, present) for an integer key."""
        for k, v in self._entries:
            # A CBOR unsigned-int key decodes to a non-negative int; bool is never a
            # key here. Compare by value AND exact int type so True/1 cannot collide.
            if type(k) is int and k == key:
                return v, True
        return None, False

    def keys(self):
        return [k for k, _ in self._entries]


# ---------------------------------------------------------------------------
# Deterministic-CBOR decoder (mirror of memory_cbor.go).
# ---------------------------------------------------------------------------
def _byte_less(a: bytes, b: bytes) -> bool:
    """Bytewise canonical ordering (RFC 8949 §4.2.1): shorter encoding sorts first,
    then lexicographic. Strict — equal returns False (used to reject dup/out-of-order)."""
    if len(a) != len(b):
        return len(a) < len(b)
    return a < b


def _decode_arg(ai: int, b: bytes, off: int):
    """Read the argument for additional-information ai at b[off], enforcing
    shortest-form and rejecting indefinite length. Returns (arg, header_len)."""
    if ai < 24:
        return ai, 1
    if ai == 24:
        if off + 2 > len(b):
            raise CborError("truncated input")
        v = b[off + 1]
        if v < 24:  # would have fit in the initial byte
            raise CborError("integer/length not in shortest form")
        return v, 2
    if ai == 25:
        if off + 3 > len(b):
            raise CborError("truncated input")
        v = (b[off + 1] << 8) | b[off + 2]
        if v < (1 << 8):
            raise CborError("integer/length not in shortest form")
        return v, 3
    if ai == 26:
        if off + 5 > len(b):
            raise CborError("truncated input")
        v = int.from_bytes(b[off + 1:off + 5], "big")
        if v < (1 << 16):
            raise CborError("integer/length not in shortest form")
        return v, 5
    if ai == 27:
        if off + 9 > len(b):
            raise CborError("truncated input")
        v = int.from_bytes(b[off + 1:off + 9], "big")
        if v < (1 << 32):
            raise CborError("integer/length not in shortest form")
        return v, 9
    if ai == 31:
        raise CborError("indefinite-length item (non-deterministic)")
    raise CborError("unsupported additional information (reserved)")  # 28,29,30


def _decode(b: bytes, off: int):
    """Decode one item from b at off. Returns (value, next_off). Enforces the
    deterministic subset strictly."""
    if off >= len(b):
        raise CborError("truncated input")
    ib = b[off]
    major = ib >> 5
    ai = ib & 0x1F

    if major == 7:
        # Only the simple values false(20)/true(21)/null(22) are in the deterministic
        # subset; floats (25/26/27), other simple values, and break(31) are rejected.
        if ai == 20:
            return False, off + 1
        if ai == 21:
            return True, off + 1
        if ai == 22:
            return None, off + 1
        raise CborError("unsupported simple value or float (non-deterministic)")

    arg, hlen = _decode_arg(ai, b, off)
    start = off + hlen

    if major == 0:  # unsigned int
        return arg, start
    if major == 1:  # negative int: value = -1 - arg
        if arg > _MAX_INT64:
            raise CborError("negative integer out of range")
        return -1 - arg, start
    if major == 2 or major == 3:  # byte / text string
        end = start + arg
        if end > len(b):
            raise CborError("truncated input")
        payload = b[start:end]
        if major == 2:
            return bytes(payload), end
        return payload.decode("utf-8", "surrogatepass"), end
    if major == 4:  # array
        if arg > len(b) - start:  # each element is >=1 byte; huge-count guard
            raise CborError("truncated input")
        out = []
        cur = start
        for _ in range(arg):
            el, cur = _decode(b, cur)
            out.append(el)
        return out, cur
    if major == 5:  # map
        if arg > len(b) - start:  # each entry is >=2 bytes; huge-count guard
            raise CborError("truncated input")
        m = CborMap()
        cur = start
        prev_key_enc = None
        for _ in range(arg):
            key_start = cur
            key, cur = _decode(b, cur)
            key_enc = b[key_start:cur]
            # Canonical order: each key MUST sort strictly after the previous one.
            # This rejects both out-of-order keys and duplicates.
            if prev_key_enc is not None and not _byte_less(prev_key_enc, key_enc):
                raise CborError("map keys not in canonical ascending order (or duplicate)")
            prev_key_enc = key_enc
            val, cur = _decode(b, cur)
            m._add(key, val)
        return m, cur
    # major 6 (tags): unsupported
    raise CborError("unsupported major type (tag)")


def cbor_decode_top(b: bytes):
    """Decode a single canonical CBOR item requiring it to consume all of b (the
    shape of a frame payload). Trailing bytes are a fault."""
    v, n = _decode(b, 0)
    if n != len(b):
        raise CborError("trailing bytes after top-level item")
    return v


# ---------------------------------------------------------------------------
# Generic field-schema enforcement (mirror of memory_bodies.go checkFields).
# A schema is a list of (key, kind, required); kind is one of the K* predicates.
# ---------------------------------------------------------------------------
def _k_uint(v):
    return type(v) is int and v >= 0


def _k_text(v):
    return type(v) is str


def _k_bytes(v):
    return type(v) is bytes


def _k_array(v):
    return type(v) is list


def _k_map(v):
    return isinstance(v, CborMap)


def _k_bool(v):
    return type(v) is bool


def _k_number(v):
    # A CBOR unsigned int OR a negative int (Telemetry value §5.1, Commerce units §4.3).
    return type(v) is int


K_UINT, K_TEXT, K_BYTES, K_ARRAY, K_MAP, K_BOOL, K_NUMBER = (
    _k_uint, _k_text, _k_bytes, _k_array, _k_map, _k_bool, _k_number,
)


def _forward_compat_keys(m: CborMap):
    """Forward-compatibility key rule (§4.3): an unknown non-negative integer key is
    accepted; an unknown NEGATIVE integer key, or a non-integer key, MUST be rejected."""
    for k in m.keys():
        if type(k) is int:
            if k < 0:
                raise BodyError(f"unknown negative key {k} (reserved)")
        else:
            raise BodyError("non-integer map key")


def _check_fields(m: CborMap, schema, envelope):
    """Enforce required/typed schema fields at keys 2+ and then the forward-compat key
    rule. `envelope` is the set of envelope keys the caller validated (0, and usually 1)."""
    for key, kind, required in schema:
        val, present = m.get(key)
        if not present:
            if required:
                raise BodyError(f"missing required field (key {key})")
            continue
        if not kind(val):
            raise BodyError(f"field (key {key}) has the wrong CBOR type")
    _forward_compat_keys(m)


def _decode_map(payload: bytes) -> CborMap:
    v = cbor_decode_top(payload)
    if not isinstance(v, CborMap):
        raise BodyError("payload is not a CBOR map")
    return v


def _check_frame_kind(m: CborMap, ft: int):
    fk, present = m.get(0)
    if not present:
        raise BodyError("missing frame_kind (0)")
    if not (type(fk) is int and fk >= 0):
        raise BodyError("frame_kind (0) is not an unsigned int")
    if fk != ft:
        raise BodyError(f"frame_kind 0x{fk:04X} contradicts frame type 0x{ft:04X}")


def _check_corr(m: CborMap):
    """Common envelope corr (1): a non-empty byte string of 1-64 bytes (§4.2)."""
    corr, present = m.get(1)
    if not present:
        raise BodyError("missing corr (1)")
    if not (type(corr) is bytes and 1 <= len(corr) <= 64):
        raise BodyError("corr (1) must be a byte string of 1-64 bytes")


# ---------------------------------------------------------------------------
# Frame-type constants (mirror of the Go per-channel frame maps).
# ---------------------------------------------------------------------------
# Capability §84 (capability.go)
CAP_ISSUE_REQ, CAP_ISSUE_RESULT = 0x0100, 0x0101
CAP_DELEGATE_REQ, CAP_DELEGATE_RESULT = 0x0102, 0x0103
CAP_REVOKE_REQ, CAP_REVOKE_RESULT = 0x0104, 0x0105
CAP_LOOKUP_REQ, CAP_LOOKUP_RESULT = 0x0106, 0x0107
CAP_ERROR = 0x0108
CAP_TOKEN_PRESENT, CAP_TOKEN_ACCEPT = 0x0060, 0x0061
CAP_TOKEN_CHALLENGE, CAP_TOKEN_PROOF = 0x0062, 0x0063

CAPABILITY_SCHEMAS = {
    CAP_ISSUE_REQ: [(2, K_TEXT, True), (3, K_TEXT, True), (4, K_MAP, False), (5, K_TEXT, False),
                    (6, K_TEXT, False), (7, K_UINT, False), (8, K_TEXT, False), (9, K_UINT, True)],
    CAP_ISSUE_RESULT: [(2, K_MAP, True), (3, K_TEXT, True)],
    CAP_DELEGATE_REQ: [(2, K_TEXT, True), (3, K_TEXT, True), (4, K_MAP, False), (5, K_TEXT, False),
                       (6, K_UINT, False), (7, K_UINT, True)],
    CAP_DELEGATE_RESULT: [(2, K_MAP, True), (3, K_TEXT, True)],
    CAP_REVOKE_REQ: [(2, K_TEXT, True), (3, K_BOOL, False), (4, K_TEXT, False), (5, K_UINT, True)],
    CAP_REVOKE_RESULT: [(2, K_TEXT, True), (3, K_TEXT, True), (4, K_UINT, False)],
    CAP_LOOKUP_REQ: [(2, K_TEXT, False), (3, K_TEXT, False), (4, K_TEXT, False), (5, K_BOOL, False),
                     (6, K_UINT, False), (7, K_BYTES, False), (8, K_UINT, True)],
    CAP_LOOKUP_RESULT: [(2, K_ARRAY, True), (3, K_BOOL, True), (4, K_BYTES, False)],
    CAP_ERROR: [(2, K_UINT, True), (3, K_TEXT, True), (4, K_UINT, False), (5, K_TEXT, False)],
    CAP_TOKEN_PRESENT: [(2, K_MAP, True), (3, K_ARRAY, False), (4, K_UINT, True)],
    CAP_TOKEN_ACCEPT: [(2, K_TEXT, True), (3, K_TEXT, True)],
    CAP_TOKEN_CHALLENGE: [(2, K_TEXT, True), (3, K_BYTES, True), (4, K_UINT, True)],
    CAP_TOKEN_PROOF: [(2, K_TEXT, True), (3, K_BYTES, True)],
}


def validate_capability(ft: int, payload: bytes) -> CborMap:
    schema = CAPABILITY_SCHEMAS.get(ft)
    if schema is None:
        raise BodyError(f"0x{ft:04X} is not a Capability operation frame type")
    m = _decode_map(payload)
    _check_frame_kind(m, ft)
    _check_corr(m)
    _check_fields(m, schema, {0, 1})
    return m


# Immune §85 (immune.go)
IMMUNE_REPORT_REQ, IMMUNE_REPORT_RESULT, IMMUNE_ERROR = 0x0100, 0x0101, 0x0102
IMMUNE_GOSSIP_ADVERTISE, IMMUNE_GOSSIP_ACK = 0x00C0, 0x00C1
IMMUNE_GOSSIP_PULL_REQ, IMMUNE_GOSSIP_PULL_RESULT, IMMUNE_GOSSIP_RETRACT = 0x00C2, 0x00C3, 0x00C4

IMMUNE_SCHEMAS = {
    IMMUNE_REPORT_REQ: [(2, K_TEXT, True), (3, K_UINT, True), (4, K_UINT, True), (5, K_TEXT, False),
                        (6, K_TEXT, False), (7, K_TEXT, False), (8, K_BYTES, False), (9, K_UINT, False),
                        (10, K_TEXT, False)],
    IMMUNE_REPORT_RESULT: [(2, K_UINT, True), (3, K_TEXT, False)],
    IMMUNE_ERROR: [(2, K_UINT, True), (3, K_TEXT, True), (4, K_UINT, False)],
    IMMUNE_GOSSIP_ADVERTISE: [(2, K_ARRAY, True), (3, K_BOOL, False)],
    IMMUNE_GOSSIP_ACK: [(2, K_ARRAY, False), (3, K_ARRAY, False), (4, K_UINT, False)],
    IMMUNE_GOSSIP_PULL_REQ: [(2, K_ARRAY, True)],
    IMMUNE_GOSSIP_PULL_RESULT: [(2, K_ARRAY, True)],
    IMMUNE_GOSSIP_RETRACT: [(2, K_BYTES, True), (3, K_UINT, True), (4, K_UINT, False)],
}

# gossip_descriptor §6.4 (nested; keys start at 0, no envelope).
_GOSSIP_DESCRIPTOR_SCHEMA = [(0, K_BYTES, True), (1, K_UINT, True), (2, K_UINT, False), (3, K_UINT, False),
                             (4, K_BYTES, False), (5, K_TEXT, False), (6, K_TEXT, False), (7, K_UINT, False),
                             (8, K_BYTES, False), (9, K_BYTES, False)]
# gossip_item §6.5 (nested; body(8) is REQUIRED, unlike a descriptor).
_GOSSIP_ITEM_SCHEMA = [(0, K_BYTES, True), (1, K_UINT, True), (2, K_UINT, False), (3, K_UINT, False),
                       (4, K_BYTES, False), (5, K_TEXT, False), (6, K_TEXT, False), (7, K_UINT, False),
                       (8, K_BYTES, True)]


def _validate_gossip_array(m: CborMap, nested):
    itemsv, present = m.get(2)
    if not present or not isinstance(itemsv, list):
        raise BodyError("missing items (2)")  # unreachable: schema already checked
    for i, el in enumerate(itemsv):
        if not isinstance(el, CborMap):
            raise BodyError(f"items[{i}] is not a CBOR map")
        _check_fields(el, nested, set())


def validate_immune(ft: int, payload: bytes) -> CborMap:
    schema = IMMUNE_SCHEMAS.get(ft)
    if schema is None:
        raise BodyError(f"0x{ft:04X} is not an Immune operation frame type")
    m = _decode_map(payload)
    _check_frame_kind(m, ft)
    _check_corr(m)
    _check_fields(m, schema, {0, 1})
    if ft == IMMUNE_GOSSIP_ADVERTISE:
        _validate_gossip_array(m, _GOSSIP_DESCRIPTOR_SCHEMA)
    elif ft == IMMUNE_GOSSIP_PULL_RESULT:
        _validate_gossip_array(m, _GOSSIP_ITEM_SCHEMA)
    return m


# Settlement §86 (settlement.go)
SETTLE_INTENT_REQ, SETTLE_INTENT_RESULT = 0x0100, 0x0101
RECEIPT_REQ, RECEIPT_RESULT, SETTLE_ERROR = 0x0102, 0x0103, 0x0104
SETTLE_BATCH_COMMIT_REQ, SETTLE_BATCH_COMMIT_RESULT = 0x00A0, 0x00A1

SETTLEMENT_SCHEMAS = {
    SETTLE_INTENT_REQ: [(2, K_TEXT, True), (3, K_TEXT, False), (4, K_TEXT, False), (5, K_TEXT, False),
                        (6, K_TEXT, False), (7, K_TEXT, False), (8, K_UINT, True)],
    SETTLE_INTENT_RESULT: [(2, K_TEXT, True), (3, K_TEXT, True), (4, K_TEXT, False)],
    RECEIPT_REQ: [(2, K_TEXT, True), (3, K_TEXT, False), (4, K_UINT, True)],
    RECEIPT_RESULT: [(2, K_MAP, True)],
    SETTLE_ERROR: [(2, K_UINT, True), (3, K_TEXT, True), (4, K_UINT, False), (5, K_TEXT, False)],
    SETTLE_BATCH_COMMIT_REQ: [(2, K_TEXT, True), (3, K_BYTES, True), (4, K_TEXT, False), (5, K_UINT, False),
                              (6, K_TEXT, False), (7, K_UINT, True)],
    SETTLE_BATCH_COMMIT_RESULT: [(2, K_TEXT, True), (3, K_TEXT, True), (4, K_TEXT, False)],
}


def validate_settlement(ft: int, payload: bytes) -> CborMap:
    schema = SETTLEMENT_SCHEMAS.get(ft)
    if schema is None:
        raise BodyError(f"0x{ft:04X} is not a Settlement operation frame type")
    m = _decode_map(payload)
    _check_frame_kind(m, ft)
    _check_corr(m)
    _check_fields(m, schema, {0, 1})
    return m


# Interaction §89 (interaction.go)
INTERACT_EVENT, INTERACT_EVENT_ACK = 0x0100, 0x0101
INTERACT_PROMPT_REQ, INTERACT_PROMPT_RESULT = 0x0102, 0x0103
INTERACT_APPROVAL_REQ, INTERACT_APPROVAL_RESULT = 0x0104, 0x0105
INTERACT_CANCEL, INTERACT_ERROR = 0x0106, 0x0107

INTERACTION_SCHEMAS = {
    INTERACT_EVENT: [(2, K_UINT, True), (3, K_TEXT, False), (4, K_MAP, False), (5, K_BOOL, False)],
    INTERACT_EVENT_ACK: [],
    INTERACT_PROMPT_REQ: [(2, K_UINT, True), (3, K_TEXT, True), (4, K_ARRAY, False), (5, K_MAP, False),
                          (6, K_UINT, False)],
    INTERACT_PROMPT_RESULT: [(2, K_UINT, True)],  # value(3) type varies by prompt_kind
    INTERACT_APPROVAL_REQ: [(2, K_TEXT, True), (3, K_UINT, False), (4, K_MAP, False), (5, K_UINT, False)],
    INTERACT_APPROVAL_RESULT: [(2, K_UINT, True), (3, K_TEXT, False)],
    INTERACT_CANCEL: [(2, K_UINT, False)],
    INTERACT_ERROR: [(2, K_UINT, True), (3, K_TEXT, True), (4, K_UINT, False), (5, K_TEXT, False)],
}


def validate_interaction(ft: int, payload: bytes) -> CborMap:
    schema = INTERACTION_SCHEMAS.get(ft)
    if schema is None:
        raise BodyError(f"0x{ft:04X} is not an Interaction operation frame type")
    m = _decode_map(payload)
    _check_frame_kind(m, ft)
    _check_corr(m)
    _check_fields(m, schema, {0, 1})
    return m


# Knowledge §8b (knowledge.go)
KNOW_QUERY_REQ, KNOW_QUERY_RESULT = 0x0100, 0x0101
KNOW_QUERY_STREAM_DATA, KNOW_QUERY_STREAM_END = 0x0102, 0x0103
KNOW_SUBSCRIBE_REQ, KNOW_SUBSCRIBE_ACK = 0x0104, 0x0105
KNOW_UPDATE, KNOW_CREDIT, KNOW_UNSUBSCRIBE, KNOW_ERROR = 0x0106, 0x0107, 0x0108, 0x0109

KNOWLEDGE_SCHEMAS = {
    KNOW_QUERY_REQ: [(2, K_TEXT, False), (3, K_TEXT, False), (4, K_TEXT, False), (5, K_TEXT, False),
                     (6, K_UINT, False), (8, K_TEXT, False), (9, K_BYTES, False)],
    KNOW_QUERY_RESULT: [(2, K_ARRAY, True), (3, K_BOOL, True), (4, K_BYTES, False), (5, K_UINT, False),
                        (6, K_BOOL, False)],
    KNOW_QUERY_STREAM_DATA: [(2, K_ARRAY, True)],
    KNOW_QUERY_STREAM_END: [(2, K_ARRAY, False), (3, K_BOOL, True)],
    KNOW_SUBSCRIBE_REQ: [(2, K_TEXT, False), (3, K_TEXT, False), (4, K_TEXT, False), (5, K_TEXT, False),
                         (7, K_TEXT, False), (8, K_BOOL, False), (9, K_UINT, True)],
    KNOW_SUBSCRIBE_ACK: [(2, K_BYTES, True), (3, K_UINT, True), (4, K_BOOL, False)],
    KNOW_UPDATE: [(2, K_BYTES, True), (3, K_UINT, True), (4, K_ARRAY, False), (5, K_ARRAY, False)],
    KNOW_CREDIT: [(2, K_BYTES, True), (3, K_UINT, True), (4, K_UINT, False)],
    KNOW_UNSUBSCRIBE: [(2, K_BYTES, True)],
    KNOW_ERROR: [(2, K_UINT, True), (3, K_TEXT, True), (4, K_UINT, False), (5, K_BYTES, False)],
}


def validate_knowledge(ft: int, payload: bytes) -> CborMap:
    schema = KNOWLEDGE_SCHEMAS.get(ft)
    if schema is None:
        raise BodyError(f"0x{ft:04X} is not a Knowledge operation frame type")
    m = _decode_map(payload)
    _check_frame_kind(m, ft)
    _check_corr(m)
    _check_fields(m, schema, {0, 1})
    # §6.5: a KNOWLEDGE_UPDATE MUST carry at least one of results (4) or removed (5).
    if ft == KNOW_UPDATE:
        _, has_results = m.get(4)
        _, has_removed = m.get(5)
        if not has_results and not has_removed:
            raise BodyError("KNOWLEDGE_UPDATE carries neither results (4) nor removed (5)")
    return m


# Workflow §8a (workflow.go)
WF_SUBMIT_REQ, WF_SUBMIT_RESULT = 0x0100, 0x0101
WF_STATUS_REQ, WF_STATUS_RESULT = 0x0102, 0x0103
WF_CANCEL_REQ, WF_CANCEL_RESULT = 0x0104, 0x0105
WF_STEP_EVENT, WF_COMPLETE, WF_ERROR = 0x0106, 0x0107, 0x0108

WORKFLOW_SCHEMAS = {
    WF_SUBMIT_REQ: [(2, K_TEXT, True), (3, K_BYTES, False), (4, K_MAP, False), (5, K_UINT, False),
                    (6, K_TEXT, False), (7, K_TEXT, False), (8, K_TEXT, False), (9, K_TEXT, False),
                    (10, K_MAP, False), (11, K_UINT, True)],
    WF_SUBMIT_RESULT: [(2, K_TEXT, True), (3, K_UINT, True)],
    WF_STATUS_REQ: [(2, K_TEXT, True)],
    WF_STATUS_RESULT: [(2, K_TEXT, True), (3, K_UINT, True), (4, K_UINT, False), (5, K_TEXT, False),
                       (6, K_UINT, False), (7, K_TEXT, False)],
    WF_CANCEL_REQ: [(2, K_TEXT, True), (3, K_TEXT, False)],
    WF_CANCEL_RESULT: [(2, K_TEXT, True), (3, K_UINT, True)],
    WF_STEP_EVENT: [(2, K_TEXT, True), (3, K_UINT, True), (4, K_UINT, True), (5, K_UINT, False),
                    (6, K_TEXT, False), (7, K_UINT, False), (8, K_BYTES, False), (9, K_TEXT, False)],
    WF_COMPLETE: [(2, K_TEXT, True), (3, K_UINT, True), (4, K_UINT, True), (5, K_BYTES, False),
                  (6, K_UINT, False), (7, K_TEXT, False)],
    WF_ERROR: [(2, K_UINT, True), (3, K_TEXT, True), (4, K_UINT, False), (5, K_TEXT, False)],
}


def _workflow_has_corr(ft: int) -> bool:
    # WORKFLOW_STEP_EVENT / WORKFLOW_COMPLETE are unsolicited, task-scoped, and carry NO corr (§4.2).
    return ft != WF_STEP_EVENT and ft != WF_COMPLETE


def validate_workflow(ft: int, payload: bytes) -> CborMap:
    schema = WORKFLOW_SCHEMAS.get(ft)
    if schema is None:
        raise BodyError(f"0x{ft:04X} is not a Workflow frame type")
    m = _decode_map(payload)
    _check_frame_kind(m, ft)
    envelope = {0}
    if _workflow_has_corr(ft):
        _check_corr(m)
        envelope.add(1)
    _check_fields(m, schema, envelope)
    return m


# Commerce §88 (commerce.go)
COM_MANDATE_CREATE_REQ, COM_MANDATE_CREATE_RESULT = 0x0100, 0x0101
COM_MANDATE_READ_REQ, COM_MANDATE_READ_RESULT = 0x0102, 0x0103
COM_MANDATE_REVOKE_REQ, COM_MANDATE_REVOKE_RESULT = 0x0104, 0x0105
COM_MANDATE_STATUS_REQ, COM_MANDATE_STATUS_RESULT = 0x0106, 0x0107
COM_INTENT_PROPOSE_REQ, COM_INTENT_PROPOSE_RESULT = 0x0108, 0x0109
COM_INTENT_RESPOND_REQ, COM_INTENT_RESPOND_RESULT = 0x010A, 0x010B
COM_INTENT_STATUS_REQ, COM_INTENT_STATUS_RESULT = 0x010C, 0x010D
COM_ERROR = 0x010E

COMMERCE_SCHEMAS = {
    COM_MANDATE_CREATE_REQ: [(2, K_TEXT, True), (3, K_TEXT, True), (4, K_MAP, True), (5, K_TEXT, False),
                             (6, K_TEXT, False), (7, K_TEXT, False), (8, K_MAP, False), (9, K_TEXT, False),
                             (10, K_BYTES, False), (11, K_TEXT, False), (12, K_TEXT, False), (13, K_UINT, True)],
    COM_MANDATE_CREATE_RESULT: [(2, K_TEXT, True), (3, K_TEXT, True)],
    COM_MANDATE_READ_REQ: [(2, K_TEXT, True), (3, K_UINT, True)],
    COM_MANDATE_READ_RESULT: [(2, K_MAP, True)],
    COM_MANDATE_REVOKE_REQ: [(2, K_TEXT, True), (3, K_TEXT, False), (4, K_UINT, True)],
    COM_MANDATE_REVOKE_RESULT: [(2, K_TEXT, True), (3, K_TEXT, True)],
    COM_MANDATE_STATUS_REQ: [(2, K_TEXT, True), (3, K_UINT, True)],
    COM_MANDATE_STATUS_RESULT: [(2, K_TEXT, True), (3, K_TEXT, True), (4, K_TEXT, False)],
    COM_INTENT_PROPOSE_REQ: [(2, K_ARRAY, True), (3, K_ARRAY, True), (4, K_TEXT, False), (5, K_MAP, False),
                             (6, K_TEXT, False), (7, K_UINT, True)],
    COM_INTENT_PROPOSE_RESULT: [(2, K_TEXT, True), (3, K_TEXT, True)],
    COM_INTENT_RESPOND_REQ: [(2, K_TEXT, True), (3, K_UINT, True), (4, K_ARRAY, False), (5, K_TEXT, False),
                             (6, K_UINT, True)],
    COM_INTENT_RESPOND_RESULT: [(2, K_TEXT, True), (3, K_TEXT, True)],
    COM_INTENT_STATUS_REQ: [(2, K_TEXT, True), (3, K_UINT, True)],
    COM_INTENT_STATUS_RESULT: [(2, K_TEXT, True), (3, K_TEXT, True), (4, K_ARRAY, False), (5, K_ARRAY, False)],
    COM_ERROR: [(2, K_UINT, True), (3, K_TEXT, True), (4, K_UINT, False), (5, K_TEXT, False)],
}


def _validate_commerce_amount(v):
    """§4.3 monetary amount: units(0) signed int, scale(1) uint, currency(2) text — all REQUIRED."""
    if not isinstance(v, CborMap):
        raise BodyError("`amount` is not a CBOR map (§4.3)")
    units, ok = v.get(0)
    if not ok:
        raise BodyError("`amount` omits REQUIRED units (0) (§4.3)")
    if type(units) is not int:
        raise BodyError("`amount` units (0) is not an integer (§4.3)")
    scale, ok = v.get(1)
    if not ok:
        raise BodyError("`amount` omits REQUIRED scale (1) (§4.3)")
    if not _k_uint(scale):
        raise BodyError("`amount` scale (1) is not an unsigned int (§4.3)")
    cur, ok = v.get(2)
    if not ok:
        raise BodyError("`amount` omits REQUIRED currency (2) (§4.3)")
    if not _k_text(cur):
        raise BodyError("`amount` currency (2) is not a text string (§4.3)")
    _forward_compat_keys(v)


def _commerce_parties(m: CborMap):
    pv, _ = m.get(2)  # parties(2) REQUIRED array, already type-checked
    parties = set()
    for p in pv:
        if type(p) is not str:
            raise BodyError("a `parties` element is not a text string (§6.6)")
        parties.add(p)
    return parties


def _validate_commerce_leg(v, parties):
    if not isinstance(v, CborMap):
        raise BodyError("a settlement leg is not a CBOR map (§6.6)")
    frm, ok = v.get(0)
    if not ok:
        raise BodyError("a leg omits REQUIRED `from` (0) (§6.6)")
    if type(frm) is not str:
        raise BodyError("a leg `from` (0) is not a text string (§6.6)")
    to, ok = v.get(1)
    if not ok:
        raise BodyError("a leg omits REQUIRED `to` (1) (§6.6)")
    if type(to) is not str:
        raise BodyError("a leg `to` (1) is not a text string (§6.6)")
    amt, ok = v.get(2)
    if not ok:
        raise BodyError("a leg omits REQUIRED `amount` (2) (§6.6)")
    _validate_commerce_amount(amt)
    if frm not in parties:
        raise BodyError("leg `from` names a party not in `parties` (§6.6)")
    if to not in parties:
        raise BodyError("leg `to` names a party not in `parties` (§6.6)")
    _forward_compat_keys(v)


def validate_commerce(ft: int, payload: bytes) -> CborMap:
    schema = COMMERCE_SCHEMAS.get(ft)
    if schema is None:
        raise BodyError(f"0x{ft:04X} is not a Commerce operation frame type")
    m = _decode_map(payload)
    _check_frame_kind(m, ft)
    _check_corr(m)
    _check_fields(m, schema, {0, 1})
    if ft == COM_MANDATE_CREATE_REQ:
        av, ok = m.get(4)  # amount(4) REQUIRED, already type-checked as a map
        if ok:
            _validate_commerce_amount(av)
    elif ft == COM_INTENT_PROPOSE_REQ:
        parties = _commerce_parties(m)
        lv, _ = m.get(3)  # legs(3) REQUIRED array, already type-checked
        for lg in lv:
            _validate_commerce_leg(lg, parties)
    return m


# Telemetry §87 (telemetry.go) — its own field predicates because value §5.1 accepts
# a signed number, and its corr is conditional on TELEMETRY_REPORT.
TELEMETRY_REPORT, TELEMETRY_SUBSCRIBE, TELEMETRY_SUB_ACK = 0x0100, 0x0101, 0x0102
TELEMETRY_UNSUBSCRIBE, TELEMETRY_CREDIT, TELEMETRY_ERROR = 0x0103, 0x0104, 0x0105

TELEMETRY_SCHEMAS = {
    TELEMETRY_SUBSCRIBE: [(2, K_ARRAY, False), (3, K_ARRAY, False), (4, K_ARRAY, False),
                          (5, K_UINT, False), (6, K_UINT, False), (7, K_UINT, True)],
    TELEMETRY_SUB_ACK: [(2, K_BYTES, True), (3, K_UINT, True), (4, K_ARRAY, False)],
    TELEMETRY_UNSUBSCRIBE: [(2, K_BYTES, True)],
    TELEMETRY_CREDIT: [(2, K_BYTES, True), (3, K_UINT, True), (4, K_UINT, False)],
    TELEMETRY_ERROR: [(2, K_UINT, True), (3, K_TEXT, False), (4, K_BYTES, False)],
}

# Nested item schemas (§5.1-§5.3). value(3) is a signed number.
_METRIC_SCHEMA = [(0, K_TEXT, True), (1, K_UINT, True), (2, K_UINT, True), (3, K_NUMBER, True),
                  (4, K_TEXT, False), (5, K_MAP, False), (6, K_UINT, False)]
_EVENT_SCHEMA = [(0, K_TEXT, True), (1, K_UINT, True), (2, K_UINT, False),
                 (3, K_MAP, False), (4, K_TEXT, False), (5, K_UINT, False)]
_HEALTH_SCHEMA = [(0, K_TEXT, True), (1, K_UINT, True), (2, K_UINT, True),
                  (3, K_TEXT, False), (4, K_MAP, False)]


def _is_telemetry_frame(ft: int) -> bool:
    return TELEMETRY_REPORT <= ft <= TELEMETRY_ERROR


def _validate_telemetry_report(m: CborMap) -> CborMap:
    """TELEMETRY_REPORT §5: corr(1) is conditional (present iff answering a subscription,
    in which case sub_id(2) MUST also be present); batch_seq(3) REQUIRED; at least one of
    metrics(4)/events(5)/health(6) MUST be present and non-empty."""
    corr, has_corr = m.get(1)
    _, has_sub_id = m.get(2)
    if has_corr:
        if not (type(corr) is bytes and 1 <= len(corr) <= 64):
            raise BodyError("corr (1) must be a byte string of 1-64 bytes")
        if not has_sub_id:
            raise BodyError("subscribed report carries corr (1) but omits sub_id (2)")
        sub, _ = m.get(2)
        if not _k_bytes(sub):
            raise BodyError("sub_id (2) must be a byte string")
    elif has_sub_id:
        raise BodyError("standalone report carries sub_id (2) without corr (1)")

    bs, ok = m.get(3)
    if not ok:
        raise BodyError("missing required batch_seq (3)")
    if not _k_uint(bs):
        raise BodyError("batch_seq (3) is not an unsigned int")

    non_empty = 0
    for key, schema in ((4, _METRIC_SCHEMA), (5, _EVENT_SCHEMA), (6, _HEALTH_SCHEMA)):
        val, present = m.get(key)
        if not present:
            continue
        if not isinstance(val, list):
            raise BodyError(f"content array (key {key}) is not a CBOR array")
        if len(val) > 0:
            non_empty += 1
        for el in val:
            if not isinstance(el, CborMap):
                raise BodyError("content array element is not a CBOR map")
            _check_telemetry_fields(el, schema)
    if non_empty == 0:
        raise BodyError("TELEMETRY_REPORT carries no metrics, events, or health (§5)")
    _forward_compat_keys(m)
    return m


def _check_telemetry_fields(m: CborMap, schema):
    for key, kind, required in schema:
        val, present = m.get(key)
        if not present:
            if required:
                raise BodyError(f"missing required field (key {key})")
            continue
        if not kind(val):
            raise BodyError(f"field (key {key}) has the wrong CBOR type")
    _forward_compat_keys(m)


def validate_telemetry(ft: int, payload: bytes) -> CborMap:
    if not _is_telemetry_frame(ft):
        raise BodyError(f"0x{ft:04X} is not a Telemetry operation frame type")
    m = _decode_map(payload)
    _check_frame_kind(m, ft)
    if ft == TELEMETRY_REPORT:
        return _validate_telemetry_report(m)
    _check_corr(m)  # every non-REPORT frame carries a REQUIRED corr
    _check_telemetry_fields(m, TELEMETRY_SCHEMAS[ft])
    return m


# ---------------------------------------------------------------------------
# Corpus op-group -> validator dispatch.
# ---------------------------------------------------------------------------
VALIDATORS = {
    "capability.body.decode": validate_capability,
    "immune.body.decode": validate_immune,
    "settlement.body.decode": validate_settlement,
    "telemetry.body.decode": validate_telemetry,
    "commerce.body.decode": validate_commerce,
    "interaction.body.decode": validate_interaction,
    "workflow.body.decode": validate_workflow,
    "knowledge.body.decode": validate_knowledge,
}
