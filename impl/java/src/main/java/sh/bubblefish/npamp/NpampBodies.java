// Open reference implementation of the N-PAMP native-channel body validators
// (draft-bubblefish-npamp-01). OPEN protocol layer only. No proprietary methods.
//
// A native operation-channel frame payload is a deterministic-CBOR map
// (NpampCbor, the shared codec). This file adds, per channel, the common envelope
// check (§4.2 frame_kind + correlation key), the per-frame-type body field schemas
// (required/typed), the forward-compatibility rule (accept an unknown non-negative
// integer key, reject an unknown negative or non-integer key), and the nested-
// structure MUST-reject rules each channel adds. It is a straight port of the Go
// reference validators impl/go/{memory,stream,capability,immune,settlement,
// telemetry,commerce,interaction,workflow,knowledge}_bodies.go and their
// TypeScript counterpart impl/typescript/src/npamp_bodies.ts -- matching their
// behavior, keyed to the same spec sections.
//
// Each validate<Channel>Payload(ft, payload) returns the decoded CborMap on
// success and THROWS on any structural fault (invalid deterministic CBOR, a
// non-map payload, a frame_kind that contradicts ft, a missing/mistyped envelope
// or body field, a nested-structure violation, or an unknown negative/non-integer
// key). Throwing-on-reject is the whole contract the corpus MUST-reject vectors
// grade.
package sh.bubblefish.npamp;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

/** Deterministic-CBOR body validators for the ten N-PAMP native operation channels. */
public final class NpampBodies {

    private NpampBodies() {
    }

    /** A structural fault in a native-channel body (a MUST-reject). */
    public static final class BodyException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public BodyException(String message) {
            super(message);
        }
    }

    // ---------- shared field-schema machinery (port of memory_bodies.go) ----------

    /** The expected CBOR type of a body field. */
    enum Kind {
        UINT,
        TEXT,
        BYTES,
        ARRAY,
        MAP,
        BOOL,
        NUMBER // uint OR negative int (telemetry MetricSample value, §5.1; commerce units, §4.3)
    }

    /** A single required/typed field of a body schema. */
    static final class Field {
        final long key;
        final Kind kind;
        final boolean required;

        Field(long key, Kind kind, boolean required) {
            this.key = key;
            this.kind = kind;
            this.required = required;
        }
    }

    private static Field f(long key, Kind kind, boolean required) {
        return new Field(key, kind, required);
    }

    private static boolean isUint(Object v) {
        return v instanceof BigInteger && ((BigInteger) v).signum() >= 0;
    }

    private static boolean matchesKind(Object v, Kind k) {
        switch (k) {
            case UINT:
                return v instanceof BigInteger && ((BigInteger) v).signum() >= 0;
            case TEXT:
                return v instanceof String;
            case BYTES:
                return v instanceof byte[];
            case ARRAY:
                return v instanceof List;
            case MAP:
                return v instanceof NpampCbor.CborMap;
            case BOOL:
                return v instanceof Boolean;
            case NUMBER:
                return v instanceof BigInteger;
            default:
                return false;
        }
    }

    // forwardCompatKeys enforces the §4.3/§4.4 rule on a decoded map: an unknown
    // non-negative integer key is accepted; an unknown NEGATIVE integer key, or a
    // non-integer key, MUST be rejected. Since the deterministic codec decodes every
    // integer to a BigInteger (non-negative for major 0, negative for major 1), a
    // negative BigInteger key is a reserved-key violation and any non-BigInteger key
    // (text, bytes, ...) is a non-integer key.
    private static void forwardCompatKeys(NpampCbor.CborMap m, String prefix) {
        for (Object k : m.keys()) {
            if (k instanceof BigInteger) {
                if (((BigInteger) k).signum() < 0) {
                    throw bad(prefix, "unknown negative key " + k + " (reserved)");
                }
            } else {
                throw bad(prefix, "non-integer map key");
            }
        }
    }

    // checkFields enforces a schema's required/typed fields and then the
    // forward-compatibility key rule on a decoded map.
    private static void checkFields(NpampCbor.CborMap m, Field[] schema, String prefix) {
        for (Field fld : schema) {
            if (!m.has(fld.key)) {
                if (fld.required) {
                    throw bad(prefix, "missing required field (key " + fld.key + ")");
                }
                continue;
            }
            Object val = m.get(fld.key);
            if (!matchesKind(val, fld.kind)) {
                throw bad(prefix, "field (key " + fld.key + ") has the wrong CBOR type");
            }
        }
        forwardCompatKeys(m, prefix);
    }

    // decodeMap decodes payload as deterministic CBOR and requires the top-level
    // item to be a map. It surfaces both the codec's MUST-reject faults (non-
    // deterministic encoding) and the "payload is not a map" fault as the channel's
    // malformed error.
    private static NpampCbor.CborMap decodeMap(byte[] payload, String prefix) {
        Object v;
        try {
            v = NpampCbor.decodeTop(payload);
        } catch (NpampCbor.CborException e) {
            throw bad(prefix, e.getMessage());
        }
        if (!(v instanceof NpampCbor.CborMap)) {
            throw bad(prefix, "payload is not a CBOR map");
        }
        return (NpampCbor.CborMap) v;
    }

    // checkFrameKind enforces the common-envelope frame_kind (0) == ft rule (§4.2).
    private static void checkFrameKind(NpampCbor.CborMap m, int ft, String prefix) {
        if (!m.has(0)) {
            throw bad(prefix, "missing frame_kind (0)");
        }
        Object fk = m.get(0);
        if (!isUint(fk)) {
            throw bad(prefix, "frame_kind (0) is not an unsigned int");
        }
        if (!fk.equals(BigInteger.valueOf(ft))) {
            throw bad(prefix, "frame_kind " + fk + " contradicts frame type " + ft);
        }
    }

    // checkCorr enforces the common-envelope corr (1) rule shared by the corr-
    // bearing channels (§4.2): a non-empty byte string of 1-64 bytes.
    private static void checkCorr(NpampCbor.CborMap m, String prefix) {
        if (!m.has(1)) {
            throw bad(prefix, "missing corr (1)");
        }
        Object corr = m.get(1);
        if (!(corr instanceof byte[]) || ((byte[]) corr).length < 1 || ((byte[]) corr).length > 64) {
            throw bad(prefix, "corr (1) must be a byte string of 1-64 bytes");
        }
    }

    private static BodyException bad(String prefix, String msg) {
        return new BodyException(prefix + ": " + msg);
    }

    // ---------- NPAMP-MEMORY (spec/companion/81 §4-§8) ----------

    static final int FRAME_MEMORY_CREATE_REQ = 0x0100;
    static final int FRAME_MEMORY_CREATE_RESULT = 0x0101;
    static final int FRAME_MEMORY_READ_REQ = 0x0102;
    static final int FRAME_MEMORY_READ_RESULT = 0x0103;
    static final int FRAME_MEMORY_UPDATE_REQ = 0x0104;
    static final int FRAME_MEMORY_UPDATE_RESULT = 0x0105;
    static final int FRAME_MEMORY_DELETE_REQ = 0x0106;
    static final int FRAME_MEMORY_DELETE_RESULT = 0x0107;
    static final int FRAME_MEMORY_RETRIEVE_REQ = 0x0108;
    static final int FRAME_MEMORY_RETRIEVE_RESULT = 0x0109;
    static final int FRAME_MEMORY_RETRIEVE_STREAM_DATA = 0x010a;
    static final int FRAME_MEMORY_RETRIEVE_STREAM_END = 0x010b;
    static final int FRAME_MEMORY_STATUS_REQ = 0x010c;
    static final int FRAME_MEMORY_STATUS_RESULT = 0x010d;
    static final int FRAME_MEMORY_ERROR = 0x010e;
    static final int FRAME_MEMORY_EVICT = 0x0035;
    static final int FRAME_MEMORY_REVIVE = 0x0036;

    private static final Map<Integer, Field[]> MEMORY_SCHEMAS = Map.ofEntries(
            Map.entry(FRAME_MEMORY_CREATE_REQ, new Field[] {
                    f(2, Kind.TEXT, true), f(3, Kind.TEXT, false), f(4, Kind.TEXT, false), f(5, Kind.TEXT, false),
                    f(6, Kind.TEXT, false), f(7, Kind.TEXT, false), f(8, Kind.TEXT, false), f(9, Kind.TEXT, false),
                    f(10, Kind.MAP, false), f(11, Kind.UINT, true) }),
            Map.entry(FRAME_MEMORY_CREATE_RESULT, new Field[] { f(2, Kind.TEXT, true), f(3, Kind.TEXT, true) }),
            Map.entry(FRAME_MEMORY_READ_REQ, new Field[] { f(2, Kind.TEXT, true), f(3, Kind.UINT, true) }),
            Map.entry(FRAME_MEMORY_READ_RESULT, new Field[] { f(2, Kind.MAP, true) }),
            Map.entry(FRAME_MEMORY_UPDATE_REQ, new Field[] {
                    f(2, Kind.TEXT, true), f(3, Kind.TEXT, false), f(4, Kind.TEXT, false), f(5, Kind.TEXT, false),
                    f(6, Kind.TEXT, false), f(7, Kind.TEXT, false), f(8, Kind.TEXT, false), f(9, Kind.MAP, false),
                    f(10, Kind.UINT, true) }),
            Map.entry(FRAME_MEMORY_UPDATE_RESULT, new Field[] { f(2, Kind.TEXT, true), f(3, Kind.TEXT, true) }),
            Map.entry(FRAME_MEMORY_DELETE_REQ, new Field[] { f(2, Kind.TEXT, true), f(3, Kind.UINT, true) }),
            Map.entry(FRAME_MEMORY_DELETE_RESULT, new Field[] { f(2, Kind.TEXT, true), f(3, Kind.TEXT, true) }),
            Map.entry(FRAME_MEMORY_RETRIEVE_REQ, new Field[] {
                    f(2, Kind.TEXT, false), f(3, Kind.TEXT, false), f(4, Kind.TEXT, false), f(5, Kind.TEXT, false),
                    f(6, Kind.TEXT, false), f(7, Kind.UINT, false), f(8, Kind.TEXT, false), f(9, Kind.BYTES, false),
                    f(10, Kind.UINT, true) }),
            Map.entry(FRAME_MEMORY_RETRIEVE_RESULT, new Field[] {
                    f(2, Kind.ARRAY, true), f(3, Kind.BOOL, true), f(4, Kind.BYTES, false), f(5, Kind.UINT, false),
                    f(6, Kind.BOOL, false) }),
            Map.entry(FRAME_MEMORY_RETRIEVE_STREAM_DATA, new Field[] { f(2, Kind.ARRAY, true) }),
            Map.entry(FRAME_MEMORY_RETRIEVE_STREAM_END, new Field[] { f(2, Kind.ARRAY, false), f(3, Kind.BOOL, true) }),
            Map.entry(FRAME_MEMORY_STATUS_REQ, new Field[] {}),
            Map.entry(FRAME_MEMORY_STATUS_RESULT, new Field[] {
                    f(2, Kind.TEXT, true), f(3, Kind.TEXT, false), f(4, Kind.UINT, false), f(5, Kind.MAP, false) }),
            Map.entry(FRAME_MEMORY_ERROR, new Field[] {
                    f(2, Kind.UINT, true), f(3, Kind.TEXT, true), f(4, Kind.UINT, false), f(5, Kind.TEXT, false) }),
            Map.entry(FRAME_MEMORY_EVICT, new Field[] { f(2, Kind.TEXT, true), f(3, Kind.TEXT, false), f(4, Kind.UINT, true) }),
            Map.entry(FRAME_MEMORY_REVIVE, new Field[] { f(2, Kind.TEXT, true), f(3, Kind.UINT, true) }));

    public static NpampCbor.CborMap validateMemoryPayload(int ft, byte[] payload) {
        String p = "npamp/memory: malformed_request";
        Field[] schema = MEMORY_SCHEMAS.get(ft);
        if (schema == null) {
            throw bad(p, ft + " is not a Memory operation frame type");
        }
        NpampCbor.CborMap m = decodeMap(payload, p);
        checkFrameKind(m, ft, p);
        checkCorr(m, p);
        checkFields(m, schema, p);
        return m;
    }

    // ---------- NPAMP-STREAM (spec/companion/80 §4-§5) ----------

    static final int FRAME_STREAM_OPEN = 0x0100;
    static final int FRAME_STREAM_DATA = 0x0101;
    static final int FRAME_STREAM_CLOSE = 0x0102;
    static final int FRAME_STREAM_RESET = 0x0103;
    static final int FRAME_STREAM_WINDOW_UPDATE = 0x0104;

    private static final Map<Integer, Field[]> STREAM_SCHEMAS = Map.of(
            FRAME_STREAM_OPEN, new Field[] {
                    f(2, Kind.UINT, true), f(3, Kind.UINT, true), f(4, Kind.TEXT, false), f(5, Kind.UINT, false) },
            FRAME_STREAM_DATA, new Field[] { f(2, Kind.UINT, true), f(3, Kind.BYTES, true), f(4, Kind.UINT, false) },
            FRAME_STREAM_CLOSE, new Field[] { f(2, Kind.UINT, true) },
            FRAME_STREAM_RESET, new Field[] { f(2, Kind.UINT, true), f(3, Kind.UINT, true) },
            FRAME_STREAM_WINDOW_UPDATE, new Field[] { f(2, Kind.UINT, true) });

    public static NpampCbor.CborMap validateStreamPayload(int ft, byte[] payload) {
        String p = "npamp/stream: malformed";
        Field[] schema = STREAM_SCHEMAS.get(ft);
        if (schema == null) {
            throw bad(p, ft + " is not a Stream frame type");
        }
        NpampCbor.CborMap m = decodeMap(payload, p);
        checkFrameKind(m, ft, p);
        // Envelope key 1 is sub_stream_id -- an Unsigned int, unlike the byte-string corr.
        if (!m.has(1)) {
            throw bad(p, "missing sub_stream_id (1)");
        }
        if (!isUint(m.get(1))) {
            throw bad(p, "sub_stream_id (1) is not an unsigned int");
        }
        checkFields(m, schema, p);
        return m;
    }

    // ---------- NPAMP-CAP (spec/companion/84 §4-§8) ----------

    static final int FRAME_CAP_ISSUE_REQ = 0x0100;
    static final int FRAME_CAP_ISSUE_RESULT = 0x0101;
    static final int FRAME_CAP_DELEGATE_REQ = 0x0102;
    static final int FRAME_CAP_DELEGATE_RESULT = 0x0103;
    static final int FRAME_CAP_REVOKE_REQ = 0x0104;
    static final int FRAME_CAP_REVOKE_RESULT = 0x0105;
    static final int FRAME_CAP_LOOKUP_REQ = 0x0106;
    static final int FRAME_CAP_LOOKUP_RESULT = 0x0107;
    static final int FRAME_CAP_ERROR = 0x0108;
    static final int FRAME_CAP_TOKEN_PRESENT = 0x0060;
    static final int FRAME_CAP_TOKEN_ACCEPT = 0x0061;
    static final int FRAME_CAP_TOKEN_CHALLENGE = 0x0062;
    static final int FRAME_CAP_TOKEN_PROOF = 0x0063;

    private static final Map<Integer, Field[]> CAPABILITY_SCHEMAS = Map.ofEntries(
            Map.entry(FRAME_CAP_ISSUE_REQ, new Field[] {
                    f(2, Kind.TEXT, true), f(3, Kind.TEXT, true), f(4, Kind.MAP, false), f(5, Kind.TEXT, false),
                    f(6, Kind.TEXT, false), f(7, Kind.UINT, false), f(8, Kind.TEXT, false), f(9, Kind.UINT, true) }),
            Map.entry(FRAME_CAP_ISSUE_RESULT, new Field[] { f(2, Kind.MAP, true), f(3, Kind.TEXT, true) }),
            Map.entry(FRAME_CAP_DELEGATE_REQ, new Field[] {
                    f(2, Kind.TEXT, true), f(3, Kind.TEXT, true), f(4, Kind.MAP, false), f(5, Kind.TEXT, false),
                    f(6, Kind.UINT, false), f(7, Kind.UINT, true) }),
            Map.entry(FRAME_CAP_DELEGATE_RESULT, new Field[] { f(2, Kind.MAP, true), f(3, Kind.TEXT, true) }),
            Map.entry(FRAME_CAP_REVOKE_REQ, new Field[] {
                    f(2, Kind.TEXT, true), f(3, Kind.BOOL, false), f(4, Kind.TEXT, false), f(5, Kind.UINT, true) }),
            Map.entry(FRAME_CAP_REVOKE_RESULT, new Field[] { f(2, Kind.TEXT, true), f(3, Kind.TEXT, true), f(4, Kind.UINT, false) }),
            Map.entry(FRAME_CAP_LOOKUP_REQ, new Field[] {
                    f(2, Kind.TEXT, false), f(3, Kind.TEXT, false), f(4, Kind.TEXT, false), f(5, Kind.BOOL, false),
                    f(6, Kind.UINT, false), f(7, Kind.BYTES, false), f(8, Kind.UINT, true) }),
            Map.entry(FRAME_CAP_LOOKUP_RESULT, new Field[] { f(2, Kind.ARRAY, true), f(3, Kind.BOOL, true), f(4, Kind.BYTES, false) }),
            Map.entry(FRAME_CAP_ERROR, new Field[] {
                    f(2, Kind.UINT, true), f(3, Kind.TEXT, true), f(4, Kind.UINT, false), f(5, Kind.TEXT, false) }),
            Map.entry(FRAME_CAP_TOKEN_PRESENT, new Field[] { f(2, Kind.MAP, true), f(3, Kind.ARRAY, false), f(4, Kind.UINT, true) }),
            Map.entry(FRAME_CAP_TOKEN_ACCEPT, new Field[] { f(2, Kind.TEXT, true), f(3, Kind.TEXT, true) }),
            Map.entry(FRAME_CAP_TOKEN_CHALLENGE, new Field[] { f(2, Kind.TEXT, true), f(3, Kind.BYTES, true), f(4, Kind.UINT, true) }),
            Map.entry(FRAME_CAP_TOKEN_PROOF, new Field[] { f(2, Kind.TEXT, true), f(3, Kind.BYTES, true) }));

    public static NpampCbor.CborMap validateCapabilityPayload(int ft, byte[] payload) {
        String p = "npamp/capability: malformed_request";
        Field[] schema = CAPABILITY_SCHEMAS.get(ft);
        if (schema == null) {
            throw bad(p, ft + " is not a Capability operation frame type");
        }
        NpampCbor.CborMap m = decodeMap(payload, p);
        checkFrameKind(m, ft, p);
        checkCorr(m, p);
        checkFields(m, schema, p);
        return m;
    }

    // ---------- NPAMP-IMMUNE (spec/companion/85 §4-§8) ----------

    static final int FRAME_IMMUNE_REPORT_REQ = 0x0100;
    static final int FRAME_IMMUNE_REPORT_RESULT = 0x0101;
    static final int FRAME_IMMUNE_ERROR = 0x0102;
    static final int FRAME_IMMUNE_GOSSIP_ADVERTISE = 0x00c0;
    static final int FRAME_IMMUNE_GOSSIP_ACK = 0x00c1;
    static final int FRAME_IMMUNE_GOSSIP_PULL_REQ = 0x00c2;
    static final int FRAME_IMMUNE_GOSSIP_PULL_RESULT = 0x00c3;
    static final int FRAME_IMMUNE_GOSSIP_RETRACT = 0x00c4;

    private static final Map<Integer, Field[]> IMMUNE_SCHEMAS = Map.ofEntries(
            Map.entry(FRAME_IMMUNE_REPORT_REQ, new Field[] {
                    f(2, Kind.TEXT, true), f(3, Kind.UINT, true), f(4, Kind.UINT, true), f(5, Kind.TEXT, false),
                    f(6, Kind.TEXT, false), f(7, Kind.TEXT, false), f(8, Kind.BYTES, false), f(9, Kind.UINT, false),
                    f(10, Kind.TEXT, false) }),
            Map.entry(FRAME_IMMUNE_REPORT_RESULT, new Field[] { f(2, Kind.UINT, true), f(3, Kind.TEXT, false) }),
            Map.entry(FRAME_IMMUNE_ERROR, new Field[] { f(2, Kind.UINT, true), f(3, Kind.TEXT, true), f(4, Kind.UINT, false) }),
            Map.entry(FRAME_IMMUNE_GOSSIP_ADVERTISE, new Field[] { f(2, Kind.ARRAY, true), f(3, Kind.BOOL, false) }),
            Map.entry(FRAME_IMMUNE_GOSSIP_ACK, new Field[] { f(2, Kind.ARRAY, false), f(3, Kind.ARRAY, false), f(4, Kind.UINT, false) }),
            Map.entry(FRAME_IMMUNE_GOSSIP_PULL_REQ, new Field[] { f(2, Kind.ARRAY, true) }),
            Map.entry(FRAME_IMMUNE_GOSSIP_PULL_RESULT, new Field[] { f(2, Kind.ARRAY, true) }),
            Map.entry(FRAME_IMMUNE_GOSSIP_RETRACT, new Field[] { f(2, Kind.BYTES, true), f(3, Kind.UINT, true), f(4, Kind.UINT, false) }));

    // gossip_descriptor (§6.4) -- nested map, keys start at 0, no envelope.
    private static final Field[] GOSSIP_DESCRIPTOR_SCHEMA = new Field[] {
            f(0, Kind.BYTES, true), f(1, Kind.UINT, true), f(2, Kind.UINT, false), f(3, Kind.UINT, false),
            f(4, Kind.BYTES, false), f(5, Kind.TEXT, false), f(6, Kind.TEXT, false), f(7, Kind.UINT, false),
            f(8, Kind.BYTES, false), f(9, Kind.BYTES, false) };

    // gossip_item (§6.5) -- like a descriptor but body(8) is REQUIRED.
    private static final Field[] GOSSIP_ITEM_SCHEMA = new Field[] {
            f(0, Kind.BYTES, true), f(1, Kind.UINT, true), f(2, Kind.UINT, false), f(3, Kind.UINT, false),
            f(4, Kind.BYTES, false), f(5, Kind.TEXT, false), f(6, Kind.TEXT, false), f(7, Kind.UINT, false),
            f(8, Kind.BYTES, true) };

    private static void validateGossipArray(NpampCbor.CborMap m, Field[] nested, String p) {
        Object itemsV = m.get(2);
        if (!(itemsV instanceof List)) {
            throw bad(p, "items (2) is not an array");
        }
        List<?> items = (List<?>) itemsV;
        for (int i = 0; i < items.size(); i++) {
            Object el = items.get(i);
            if (!(el instanceof NpampCbor.CborMap)) {
                throw bad(p, "items[" + i + "] is not a CBOR map");
            }
            checkFields((NpampCbor.CborMap) el, nested, p);
        }
    }

    public static NpampCbor.CborMap validateImmunePayload(int ft, byte[] payload) {
        String p = "npamp/immune: malformed_request";
        Field[] schema = IMMUNE_SCHEMAS.get(ft);
        if (schema == null) {
            throw bad(p, ft + " is not an Immune operation frame type");
        }
        NpampCbor.CborMap m = decodeMap(payload, p);
        checkFrameKind(m, ft, p);
        checkCorr(m, p);
        checkFields(m, schema, p);
        if (ft == FRAME_IMMUNE_GOSSIP_ADVERTISE) {
            validateGossipArray(m, GOSSIP_DESCRIPTOR_SCHEMA, p);
        } else if (ft == FRAME_IMMUNE_GOSSIP_PULL_RESULT) {
            validateGossipArray(m, GOSSIP_ITEM_SCHEMA, p);
        }
        return m;
    }

    // ---------- NPAMP-SETTLEMENT (spec/companion/86 §4-§8) ----------

    static final int FRAME_SETTLE_INTENT_REQ = 0x0100;
    static final int FRAME_SETTLE_INTENT_RESULT = 0x0101;
    static final int FRAME_RECEIPT_REQ = 0x0102;
    static final int FRAME_RECEIPT_RESULT = 0x0103;
    static final int FRAME_SETTLE_ERROR = 0x0104;
    static final int FRAME_SETTLE_BATCH_COMMIT_REQ = 0x00a0;
    static final int FRAME_SETTLE_BATCH_COMMIT_RESULT = 0x00a1;

    private static final Map<Integer, Field[]> SETTLEMENT_SCHEMAS = Map.ofEntries(
            Map.entry(FRAME_SETTLE_INTENT_REQ, new Field[] {
                    f(2, Kind.TEXT, true), f(3, Kind.TEXT, false), f(4, Kind.TEXT, false), f(5, Kind.TEXT, false),
                    f(6, Kind.TEXT, false), f(7, Kind.TEXT, false), f(8, Kind.UINT, true) }),
            Map.entry(FRAME_SETTLE_INTENT_RESULT, new Field[] { f(2, Kind.TEXT, true), f(3, Kind.TEXT, true), f(4, Kind.TEXT, false) }),
            Map.entry(FRAME_RECEIPT_REQ, new Field[] { f(2, Kind.TEXT, true), f(3, Kind.TEXT, false), f(4, Kind.UINT, true) }),
            Map.entry(FRAME_RECEIPT_RESULT, new Field[] { f(2, Kind.MAP, true) }),
            Map.entry(FRAME_SETTLE_ERROR, new Field[] {
                    f(2, Kind.UINT, true), f(3, Kind.TEXT, true), f(4, Kind.UINT, false), f(5, Kind.TEXT, false) }),
            Map.entry(FRAME_SETTLE_BATCH_COMMIT_REQ, new Field[] {
                    f(2, Kind.TEXT, true), f(3, Kind.BYTES, true), f(4, Kind.TEXT, false), f(5, Kind.UINT, false),
                    f(6, Kind.TEXT, false), f(7, Kind.UINT, true) }),
            Map.entry(FRAME_SETTLE_BATCH_COMMIT_RESULT, new Field[] { f(2, Kind.TEXT, true), f(3, Kind.TEXT, true), f(4, Kind.TEXT, false) }));

    public static NpampCbor.CborMap validateSettlementPayload(int ft, byte[] payload) {
        String p = "npamp/settlement: malformed_request";
        Field[] schema = SETTLEMENT_SCHEMAS.get(ft);
        if (schema == null) {
            throw bad(p, ft + " is not a Settlement operation frame type");
        }
        NpampCbor.CborMap m = decodeMap(payload, p);
        checkFrameKind(m, ft, p);
        checkCorr(m, p);
        checkFields(m, schema, p);
        return m;
    }

    // ---------- NPAMP-TELEMETRY (spec/companion/87 §4-§8) ----------

    static final int FRAME_TELEMETRY_REPORT = 0x0100;
    static final int FRAME_TELEMETRY_SUBSCRIBE = 0x0101;
    static final int FRAME_TELEMETRY_SUB_ACK = 0x0102;
    static final int FRAME_TELEMETRY_UNSUBSCRIBE = 0x0103;
    static final int FRAME_TELEMETRY_CREDIT = 0x0104;
    static final int FRAME_TELEMETRY_ERROR = 0x0105;

    private static final Map<Integer, Field[]> TELEMETRY_SCHEMAS = Map.of(
            FRAME_TELEMETRY_SUBSCRIBE, new Field[] {
                    f(2, Kind.ARRAY, false), f(3, Kind.ARRAY, false), f(4, Kind.ARRAY, false),
                    f(5, Kind.UINT, false), f(6, Kind.UINT, false), f(7, Kind.UINT, true) },
            FRAME_TELEMETRY_SUB_ACK, new Field[] { f(2, Kind.BYTES, true), f(3, Kind.UINT, true), f(4, Kind.ARRAY, false) },
            FRAME_TELEMETRY_UNSUBSCRIBE, new Field[] { f(2, Kind.BYTES, true) },
            FRAME_TELEMETRY_CREDIT, new Field[] { f(2, Kind.BYTES, true), f(3, Kind.UINT, true), f(4, Kind.UINT, false) },
            FRAME_TELEMETRY_ERROR, new Field[] { f(2, Kind.UINT, true), f(3, Kind.TEXT, false), f(4, Kind.BYTES, false) });

    // Nested item schemas (§5.1-§5.3); keys start at 0, no envelope.
    private static final Field[] METRIC_SCHEMA = new Field[] {
            f(0, Kind.TEXT, true), f(1, Kind.UINT, true), f(2, Kind.UINT, true), f(3, Kind.NUMBER, true),
            f(4, Kind.TEXT, false), f(5, Kind.MAP, false), f(6, Kind.UINT, false) };
    private static final Field[] EVENT_SCHEMA = new Field[] {
            f(0, Kind.TEXT, true), f(1, Kind.UINT, true), f(2, Kind.UINT, false),
            f(3, Kind.MAP, false), f(4, Kind.TEXT, false), f(5, Kind.UINT, false) };
    private static final Field[] HEALTH_SCHEMA = new Field[] {
            f(0, Kind.TEXT, true), f(1, Kind.UINT, true), f(2, Kind.UINT, true),
            f(3, Kind.TEXT, false), f(4, Kind.MAP, false) };

    private static boolean isTelemetryFrame(int ft) {
        return ft >= FRAME_TELEMETRY_REPORT && ft <= FRAME_TELEMETRY_ERROR;
    }

    public static NpampCbor.CborMap validateTelemetryPayload(int ft, byte[] payload) {
        String p = "npamp/telemetry: malformed_payload";
        if (!isTelemetryFrame(ft)) {
            throw bad(p, ft + " is not a Telemetry operation frame type");
        }
        NpampCbor.CborMap m = decodeMap(payload, p);
        checkFrameKind(m, ft, p);

        if (ft == FRAME_TELEMETRY_REPORT) {
            return validateTelemetryReport(m, p);
        }

        // Every non-REPORT Telemetry frame carries a REQUIRED, non-empty corr (1) (§4.1).
        checkCorr(m, p);
        checkFields(m, TELEMETRY_SCHEMAS.get(ft), p);
        return m;
    }

    // validateTelemetryReport enforces the §5 TELEMETRY_REPORT rules: corr (1) is
    // CONDITIONAL (present iff the batch answers a subscription, in which case
    // sub_id (2) MUST also be present; a standalone report MUST omit both);
    // batch_seq (3) is REQUIRED; and the report MUST carry content (at least one of
    // metrics(4)/events(5)/health(6) present and non-empty), each element validated.
    private static NpampCbor.CborMap validateTelemetryReport(NpampCbor.CborMap m, String p) {
        boolean hasCorr = m.has(1);
        boolean hasSubID = m.has(2);
        if (hasCorr) {
            Object corr = m.get(1);
            if (!(corr instanceof byte[]) || ((byte[]) corr).length < 1 || ((byte[]) corr).length > 64) {
                throw bad(p, "corr (1) must be a byte string of 1-64 bytes");
            }
            if (!hasSubID) {
                throw bad(p, "subscribed report carries corr (1) but omits sub_id (2)");
            }
            if (!(m.get(2) instanceof byte[])) {
                throw bad(p, "sub_id (2) must be a byte string");
            }
        } else if (hasSubID) {
            throw bad(p, "standalone report carries sub_id (2) without corr (1)");
        }

        if (!m.has(3)) {
            throw bad(p, "missing required batch_seq (3)");
        }
        if (!isUint(m.get(3))) {
            throw bad(p, "batch_seq (3) is not an unsigned int");
        }

        int nonEmpty = 0;
        long[] contentKeys = { 4, 5, 6 };
        Field[][] contentSchemas = { METRIC_SCHEMA, EVENT_SCHEMA, HEALTH_SCHEMA };
        String[] contentNames = { "metric", "event", "health" };
        for (int c = 0; c < contentKeys.length; c++) {
            if (!m.has(contentKeys[c])) {
                continue;
            }
            Object val = m.get(contentKeys[c]);
            if (!(val instanceof List)) {
                throw bad(p, contentNames[c] + " array (key " + contentKeys[c] + ") is not a CBOR array");
            }
            List<?> arr = (List<?>) val;
            if (!arr.isEmpty()) {
                nonEmpty++;
            }
            for (Object el : arr) {
                if (!(el instanceof NpampCbor.CborMap)) {
                    throw bad(p, contentNames[c] + " array element is not a CBOR map");
                }
                checkFields((NpampCbor.CborMap) el, contentSchemas[c], p);
            }
        }
        if (nonEmpty == 0) {
            throw bad(p, "TELEMETRY_REPORT carries no metrics, events, or health");
        }

        forwardCompatKeys(m, p);
        return m;
    }

    // ---------- NPAMP-COMMERCE (spec/companion/88 §4-§8) ----------

    static final int FRAME_COMMERCE_MANDATE_CREATE_REQ = 0x0100;
    static final int FRAME_COMMERCE_MANDATE_CREATE_RESULT = 0x0101;
    static final int FRAME_COMMERCE_MANDATE_READ_REQ = 0x0102;
    static final int FRAME_COMMERCE_MANDATE_READ_RESULT = 0x0103;
    static final int FRAME_COMMERCE_MANDATE_REVOKE_REQ = 0x0104;
    static final int FRAME_COMMERCE_MANDATE_REVOKE_RESULT = 0x0105;
    static final int FRAME_COMMERCE_MANDATE_STATUS_REQ = 0x0106;
    static final int FRAME_COMMERCE_MANDATE_STATUS_RESULT = 0x0107;
    static final int FRAME_COMMERCE_INTENT_PROPOSE_REQ = 0x0108;
    static final int FRAME_COMMERCE_INTENT_PROPOSE_RESULT = 0x0109;
    static final int FRAME_COMMERCE_INTENT_RESPOND_REQ = 0x010a;
    static final int FRAME_COMMERCE_INTENT_RESPOND_RESULT = 0x010b;
    static final int FRAME_COMMERCE_INTENT_STATUS_REQ = 0x010c;
    static final int FRAME_COMMERCE_INTENT_STATUS_RESULT = 0x010d;
    static final int FRAME_COMMERCE_ERROR = 0x010e;

    private static final Map<Integer, Field[]> COMMERCE_SCHEMAS = Map.ofEntries(
            Map.entry(FRAME_COMMERCE_MANDATE_CREATE_REQ, new Field[] {
                    f(2, Kind.TEXT, true), f(3, Kind.TEXT, true), f(4, Kind.MAP, true), f(5, Kind.TEXT, false),
                    f(6, Kind.TEXT, false), f(7, Kind.TEXT, false), f(8, Kind.MAP, false), f(9, Kind.TEXT, false),
                    f(10, Kind.BYTES, false), f(11, Kind.TEXT, false), f(12, Kind.TEXT, false), f(13, Kind.UINT, true) }),
            Map.entry(FRAME_COMMERCE_MANDATE_CREATE_RESULT, new Field[] { f(2, Kind.TEXT, true), f(3, Kind.TEXT, true) }),
            Map.entry(FRAME_COMMERCE_MANDATE_READ_REQ, new Field[] { f(2, Kind.TEXT, true), f(3, Kind.UINT, true) }),
            Map.entry(FRAME_COMMERCE_MANDATE_READ_RESULT, new Field[] { f(2, Kind.MAP, true) }),
            Map.entry(FRAME_COMMERCE_MANDATE_REVOKE_REQ, new Field[] { f(2, Kind.TEXT, true), f(3, Kind.TEXT, false), f(4, Kind.UINT, true) }),
            Map.entry(FRAME_COMMERCE_MANDATE_REVOKE_RESULT, new Field[] { f(2, Kind.TEXT, true), f(3, Kind.TEXT, true) }),
            Map.entry(FRAME_COMMERCE_MANDATE_STATUS_REQ, new Field[] { f(2, Kind.TEXT, true), f(3, Kind.UINT, true) }),
            Map.entry(FRAME_COMMERCE_MANDATE_STATUS_RESULT, new Field[] { f(2, Kind.TEXT, true), f(3, Kind.TEXT, true), f(4, Kind.TEXT, false) }),
            Map.entry(FRAME_COMMERCE_INTENT_PROPOSE_REQ, new Field[] {
                    f(2, Kind.ARRAY, true), f(3, Kind.ARRAY, true), f(4, Kind.TEXT, false), f(5, Kind.MAP, false),
                    f(6, Kind.TEXT, false), f(7, Kind.UINT, true) }),
            Map.entry(FRAME_COMMERCE_INTENT_PROPOSE_RESULT, new Field[] { f(2, Kind.TEXT, true), f(3, Kind.TEXT, true) }),
            Map.entry(FRAME_COMMERCE_INTENT_RESPOND_REQ, new Field[] {
                    f(2, Kind.TEXT, true), f(3, Kind.UINT, true), f(4, Kind.ARRAY, false), f(5, Kind.TEXT, false), f(6, Kind.UINT, true) }),
            Map.entry(FRAME_COMMERCE_INTENT_RESPOND_RESULT, new Field[] { f(2, Kind.TEXT, true), f(3, Kind.TEXT, true) }),
            Map.entry(FRAME_COMMERCE_INTENT_STATUS_REQ, new Field[] { f(2, Kind.TEXT, true), f(3, Kind.UINT, true) }),
            Map.entry(FRAME_COMMERCE_INTENT_STATUS_RESULT, new Field[] {
                    f(2, Kind.TEXT, true), f(3, Kind.TEXT, true), f(4, Kind.ARRAY, false), f(5, Kind.ARRAY, false) }),
            Map.entry(FRAME_COMMERCE_ERROR, new Field[] {
                    f(2, Kind.UINT, true), f(3, Kind.TEXT, true), f(4, Kind.UINT, false), f(5, Kind.TEXT, false) }));

    // validateCommerceAmount enforces the §4.3 monetary-amount structure: units (0)
    // a signed integer, scale (1) an unsigned int, currency (2) a text string -- all
    // REQUIRED -- plus the §4.4 forward-compat key rule.
    private static void validateCommerceAmount(Object v, String p) {
        if (!(v instanceof NpampCbor.CborMap)) {
            throw bad(p, "`amount` is not a CBOR map (§4.3)");
        }
        NpampCbor.CborMap am = (NpampCbor.CborMap) v;
        if (!am.has(0)) {
            throw bad(p, "`amount` omits REQUIRED units (0) (§4.3)");
        }
        if (!(am.get(0) instanceof BigInteger)) {
            throw bad(p, "`amount` units (0) is not an integer (§4.3)");
        }
        if (!am.has(1)) {
            throw bad(p, "`amount` omits REQUIRED scale (1) (§4.3)");
        }
        if (!isUint(am.get(1))) {
            throw bad(p, "`amount` scale (1) is not an unsigned int (§4.3)");
        }
        if (!am.has(2)) {
            throw bad(p, "`amount` omits REQUIRED currency (2) (§4.3)");
        }
        if (!(am.get(2) instanceof String)) {
            throw bad(p, "`amount` currency (2) is not a text string (§4.3)");
        }
        forwardCompatKeys(am, p);
    }

    private static void validateCommerceLeg(Object v, java.util.Set<String> parties, String p) {
        if (!(v instanceof NpampCbor.CborMap)) {
            throw bad(p, "a settlement leg is not a CBOR map (§6.6)");
        }
        NpampCbor.CborMap leg = (NpampCbor.CborMap) v;
        if (!leg.has(0)) {
            throw bad(p, "a leg omits REQUIRED `from` (0) (§6.6)");
        }
        Object frm = leg.get(0);
        if (!(frm instanceof String)) {
            throw bad(p, "a leg `from` (0) is not a text string (§6.6)");
        }
        if (!leg.has(1)) {
            throw bad(p, "a leg omits REQUIRED `to` (1) (§6.6)");
        }
        Object to = leg.get(1);
        if (!(to instanceof String)) {
            throw bad(p, "a leg `to` (1) is not a text string (§6.6)");
        }
        if (!leg.has(2)) {
            throw bad(p, "a leg omits REQUIRED `amount` (2) (§6.6)");
        }
        validateCommerceAmount(leg.get(2), p);
        if (!parties.contains(frm)) {
            throw bad(p, "leg `from` names a party not in `parties` (§6.6)");
        }
        if (!parties.contains(to)) {
            throw bad(p, "leg `to` names a party not in `parties` (§6.6)");
        }
        forwardCompatKeys(leg, p);
    }

    private static void validateCommerceNested(int ft, NpampCbor.CborMap m, String p) {
        if (ft == FRAME_COMMERCE_MANDATE_CREATE_REQ) {
            Object av = m.get(4);
            if (av != null) {
                validateCommerceAmount(av, p);
            }
        } else if (ft == FRAME_COMMERCE_INTENT_PROPOSE_REQ) {
            Object pv = m.get(2);
            java.util.Set<String> parties = new java.util.HashSet<>();
            if (pv instanceof List) {
                for (Object party : (List<?>) pv) {
                    if (!(party instanceof String)) {
                        throw bad(p, "a `parties` element is not a text string (§6.6)");
                    }
                    parties.add((String) party);
                }
            }
            Object lv = m.get(3);
            if (lv instanceof List) {
                for (Object lg : (List<?>) lv) {
                    validateCommerceLeg(lg, parties, p);
                }
            }
        }
    }

    public static NpampCbor.CborMap validateCommercePayload(int ft, byte[] payload) {
        String p = "npamp/commerce: malformed_request";
        Field[] schema = COMMERCE_SCHEMAS.get(ft);
        if (schema == null) {
            throw bad(p, ft + " is not a Commerce operation frame type");
        }
        NpampCbor.CborMap m = decodeMap(payload, p);
        checkFrameKind(m, ft, p);
        checkCorr(m, p);
        checkFields(m, schema, p);
        validateCommerceNested(ft, m, p);
        return m;
    }

    // ---------- NPAMP-INTERACT (spec/companion/89 §4-§8) ----------

    static final int FRAME_INTERACT_EVENT = 0x0100;
    static final int FRAME_INTERACT_EVENT_ACK = 0x0101;
    static final int FRAME_INTERACT_PROMPT_REQ = 0x0102;
    static final int FRAME_INTERACT_PROMPT_RESULT = 0x0103;
    static final int FRAME_INTERACT_APPROVAL_REQ = 0x0104;
    static final int FRAME_INTERACT_APPROVAL_RESULT = 0x0105;
    static final int FRAME_INTERACT_CANCEL = 0x0106;
    static final int FRAME_INTERACT_ERROR = 0x0107;

    private static final Map<Integer, Field[]> INTERACTION_SCHEMAS = Map.ofEntries(
            Map.entry(FRAME_INTERACT_EVENT, new Field[] {
                    f(2, Kind.UINT, true), f(3, Kind.TEXT, false), f(4, Kind.MAP, false), f(5, Kind.BOOL, false) }),
            Map.entry(FRAME_INTERACT_EVENT_ACK, new Field[] {}),
            Map.entry(FRAME_INTERACT_PROMPT_REQ, new Field[] {
                    f(2, Kind.UINT, true), f(3, Kind.TEXT, true), f(4, Kind.ARRAY, false), f(5, Kind.MAP, false), f(6, Kind.UINT, false) }),
            Map.entry(FRAME_INTERACT_PROMPT_RESULT, new Field[] { f(2, Kind.UINT, true) }),
            Map.entry(FRAME_INTERACT_APPROVAL_REQ, new Field[] {
                    f(2, Kind.TEXT, true), f(3, Kind.UINT, false), f(4, Kind.MAP, false), f(5, Kind.UINT, false) }),
            Map.entry(FRAME_INTERACT_APPROVAL_RESULT, new Field[] { f(2, Kind.UINT, true), f(3, Kind.TEXT, false) }),
            Map.entry(FRAME_INTERACT_CANCEL, new Field[] { f(2, Kind.UINT, false) }),
            Map.entry(FRAME_INTERACT_ERROR, new Field[] {
                    f(2, Kind.UINT, true), f(3, Kind.TEXT, true), f(4, Kind.UINT, false), f(5, Kind.TEXT, false) }));

    public static NpampCbor.CborMap validateInteractionPayload(int ft, byte[] payload) {
        String p = "npamp/interaction: malformed_request";
        Field[] schema = INTERACTION_SCHEMAS.get(ft);
        if (schema == null) {
            throw bad(p, ft + " is not an Interaction operation frame type");
        }
        NpampCbor.CborMap m = decodeMap(payload, p);
        checkFrameKind(m, ft, p);
        checkCorr(m, p);
        checkFields(m, schema, p);
        return m;
    }

    // ---------- NPAMP-WORKFLOW (spec/companion/8a §4-§8) ----------

    static final int FRAME_WORKFLOW_SUBMIT_REQ = 0x0100;
    static final int FRAME_WORKFLOW_SUBMIT_RESULT = 0x0101;
    static final int FRAME_WORKFLOW_STATUS_REQ = 0x0102;
    static final int FRAME_WORKFLOW_STATUS_RESULT = 0x0103;
    static final int FRAME_WORKFLOW_CANCEL_REQ = 0x0104;
    static final int FRAME_WORKFLOW_CANCEL_RESULT = 0x0105;
    static final int FRAME_WORKFLOW_STEP_EVENT = 0x0106;
    static final int FRAME_WORKFLOW_COMPLETE = 0x0107;
    static final int FRAME_WORKFLOW_ERROR = 0x0108;

    private static final Map<Integer, Field[]> WORKFLOW_SCHEMAS = Map.ofEntries(
            Map.entry(FRAME_WORKFLOW_SUBMIT_REQ, new Field[] {
                    f(2, Kind.TEXT, true), f(3, Kind.BYTES, false), f(4, Kind.MAP, false), f(5, Kind.UINT, false),
                    f(6, Kind.TEXT, false), f(7, Kind.TEXT, false), f(8, Kind.TEXT, false), f(9, Kind.TEXT, false),
                    f(10, Kind.MAP, false), f(11, Kind.UINT, true) }),
            Map.entry(FRAME_WORKFLOW_SUBMIT_RESULT, new Field[] { f(2, Kind.TEXT, true), f(3, Kind.UINT, true) }),
            Map.entry(FRAME_WORKFLOW_STATUS_REQ, new Field[] { f(2, Kind.TEXT, true) }),
            Map.entry(FRAME_WORKFLOW_STATUS_RESULT, new Field[] {
                    f(2, Kind.TEXT, true), f(3, Kind.UINT, true), f(4, Kind.UINT, false), f(5, Kind.TEXT, false),
                    f(6, Kind.UINT, false), f(7, Kind.TEXT, false) }),
            Map.entry(FRAME_WORKFLOW_CANCEL_REQ, new Field[] { f(2, Kind.TEXT, true), f(3, Kind.TEXT, false) }),
            Map.entry(FRAME_WORKFLOW_CANCEL_RESULT, new Field[] { f(2, Kind.TEXT, true), f(3, Kind.UINT, true) }),
            Map.entry(FRAME_WORKFLOW_STEP_EVENT, new Field[] {
                    f(2, Kind.TEXT, true), f(3, Kind.UINT, true), f(4, Kind.UINT, true), f(5, Kind.UINT, false),
                    f(6, Kind.TEXT, false), f(7, Kind.UINT, false), f(8, Kind.BYTES, false), f(9, Kind.TEXT, false) }),
            Map.entry(FRAME_WORKFLOW_COMPLETE, new Field[] {
                    f(2, Kind.TEXT, true), f(3, Kind.UINT, true), f(4, Kind.UINT, true), f(5, Kind.BYTES, false),
                    f(6, Kind.UINT, false), f(7, Kind.TEXT, false) }),
            Map.entry(FRAME_WORKFLOW_ERROR, new Field[] {
                    f(2, Kind.UINT, true), f(3, Kind.TEXT, true), f(4, Kind.UINT, false), f(5, Kind.TEXT, false) }));

    private static boolean workflowFrameHasCorr(int ft) {
        return ft != FRAME_WORKFLOW_STEP_EVENT && ft != FRAME_WORKFLOW_COMPLETE;
    }

    public static NpampCbor.CborMap validateWorkflowPayload(int ft, byte[] payload) {
        String p = "npamp/workflow: malformed_request";
        Field[] schema = WORKFLOW_SCHEMAS.get(ft);
        if (schema == null) {
            throw bad(p, ft + " is not a Workflow frame type");
        }
        NpampCbor.CborMap m = decodeMap(payload, p);
        checkFrameKind(m, ft, p);
        // corr (1) is REQUIRED on every corr-bearing frame; the task-scoped
        // WORKFLOW_STEP_EVENT / WORKFLOW_COMPLETE carry no corr (§4.2, §5.2).
        if (workflowFrameHasCorr(ft)) {
            checkCorr(m, p);
        }
        checkFields(m, schema, p);
        return m;
    }

    // ---------- NPAMP-KNOWLEDGE (spec/companion/8b §4-§9) ----------

    static final int FRAME_KNOWLEDGE_QUERY_REQ = 0x0100;
    static final int FRAME_KNOWLEDGE_QUERY_RESULT = 0x0101;
    static final int FRAME_KNOWLEDGE_QUERY_STREAM_DATA = 0x0102;
    static final int FRAME_KNOWLEDGE_QUERY_STREAM_END = 0x0103;
    static final int FRAME_KNOWLEDGE_SUBSCRIBE_REQ = 0x0104;
    static final int FRAME_KNOWLEDGE_SUBSCRIBE_ACK = 0x0105;
    static final int FRAME_KNOWLEDGE_UPDATE = 0x0106;
    static final int FRAME_KNOWLEDGE_CREDIT = 0x0107;
    static final int FRAME_KNOWLEDGE_UNSUBSCRIBE = 0x0108;
    static final int FRAME_KNOWLEDGE_ERROR = 0x0109;

    private static final Map<Integer, Field[]> KNOWLEDGE_SCHEMAS = Map.ofEntries(
            Map.entry(FRAME_KNOWLEDGE_QUERY_REQ, new Field[] {
                    f(2, Kind.TEXT, false), f(3, Kind.TEXT, false), f(4, Kind.TEXT, false), f(5, Kind.TEXT, false),
                    f(6, Kind.UINT, false), f(8, Kind.TEXT, false), f(9, Kind.BYTES, false) }),
            Map.entry(FRAME_KNOWLEDGE_QUERY_RESULT, new Field[] {
                    f(2, Kind.ARRAY, true), f(3, Kind.BOOL, true), f(4, Kind.BYTES, false), f(5, Kind.UINT, false), f(6, Kind.BOOL, false) }),
            Map.entry(FRAME_KNOWLEDGE_QUERY_STREAM_DATA, new Field[] { f(2, Kind.ARRAY, true) }),
            Map.entry(FRAME_KNOWLEDGE_QUERY_STREAM_END, new Field[] { f(2, Kind.ARRAY, false), f(3, Kind.BOOL, true) }),
            Map.entry(FRAME_KNOWLEDGE_SUBSCRIBE_REQ, new Field[] {
                    f(2, Kind.TEXT, false), f(3, Kind.TEXT, false), f(4, Kind.TEXT, false), f(5, Kind.TEXT, false),
                    f(7, Kind.TEXT, false), f(8, Kind.BOOL, false), f(9, Kind.UINT, true) }),
            Map.entry(FRAME_KNOWLEDGE_SUBSCRIBE_ACK, new Field[] { f(2, Kind.BYTES, true), f(3, Kind.UINT, true), f(4, Kind.BOOL, false) }),
            Map.entry(FRAME_KNOWLEDGE_UPDATE, new Field[] { f(2, Kind.BYTES, true), f(3, Kind.UINT, true), f(4, Kind.ARRAY, false), f(5, Kind.ARRAY, false) }),
            Map.entry(FRAME_KNOWLEDGE_CREDIT, new Field[] { f(2, Kind.BYTES, true), f(3, Kind.UINT, true), f(4, Kind.UINT, false) }),
            Map.entry(FRAME_KNOWLEDGE_UNSUBSCRIBE, new Field[] { f(2, Kind.BYTES, true) }),
            Map.entry(FRAME_KNOWLEDGE_ERROR, new Field[] { f(2, Kind.UINT, true), f(3, Kind.TEXT, true), f(4, Kind.UINT, false), f(5, Kind.BYTES, false) }));

    public static NpampCbor.CborMap validateKnowledgePayload(int ft, byte[] payload) {
        String p = "npamp/knowledge: malformed_request";
        Field[] schema = KNOWLEDGE_SCHEMAS.get(ft);
        if (schema == null) {
            throw bad(p, ft + " is not a Knowledge operation frame type");
        }
        NpampCbor.CborMap m = decodeMap(payload, p);
        checkFrameKind(m, ft, p);
        checkCorr(m, p);
        checkFields(m, schema, p);
        // §6.5: a KNOWLEDGE_UPDATE MUST carry at least one of results (4) or removed (5).
        if (ft == FRAME_KNOWLEDGE_UPDATE) {
            if (!m.has(4) && !m.has(5)) {
                throw bad(p, "KNOWLEDGE_UPDATE carries neither results (4) nor removed (5) (§6.5)");
            }
        }
        return m;
    }
}
