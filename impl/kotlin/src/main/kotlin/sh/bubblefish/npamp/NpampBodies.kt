// Open reference implementation of the N-PAMP native-channel body validators
// (draft-bubblefish-npamp-01). OPEN protocol layer only. No proprietary methods.
//
// A native operation-channel frame payload is a deterministic-CBOR map (NpampCbor,
// the shared codec). This file adds, per channel, the common envelope check (§4.2
// frame_kind + correlation key), the per-frame-type body field schemas
// (required/typed), the forward-compatibility rule (accept an unknown non-negative
// integer key, reject an unknown negative or non-integer key), and the nested-
// structure MUST-reject rules each channel adds. It is a straight port of the Go
// reference validators impl/go/{memory,stream,capability,immune,settlement,
// telemetry,commerce,interaction,workflow,knowledge}_bodies.go and their TypeScript
// counterpart impl/typescript/src/npamp_bodies.ts.
//
// Each validate<Channel>Payload(ft, payload) returns the decoded CborMap on success
// and THROWS on any structural fault. Throwing-on-reject is the whole contract the
// corpus MUST-reject vectors grade.
package sh.bubblefish.npamp

import java.math.BigInteger

/** A structural fault in a native-channel body (a MUST-reject). */
class BodyException(message: String) : RuntimeException(message)

/** Deterministic-CBOR body validators for the ten N-PAMP native operation channels. */
object NpampBodies {

    /** The expected CBOR type of a body field. */
    private enum class Kind { UINT, TEXT, BYTES, ARRAY, MAP, BOOL, NUMBER }

    /** A single required/typed field of a body schema. */
    private class Field(val key: Long, val kind: Kind, val required: Boolean)

    private fun f(key: Long, kind: Kind, required: Boolean) = Field(key, kind, required)

    private fun isUint(v: Any?): Boolean = v is BigInteger && v.signum() >= 0

    private fun matchesKind(v: Any?, k: Kind): Boolean = when (k) {
        Kind.UINT -> v is BigInteger && v.signum() >= 0
        Kind.TEXT -> v is String
        Kind.BYTES -> v is ByteArray
        Kind.ARRAY -> v is List<*>
        Kind.MAP -> v is NpampCbor.CborMap
        Kind.BOOL -> v is Boolean
        Kind.NUMBER -> v is BigInteger
    }

    // forwardCompatKeys enforces the §4.3/§4.4 rule: an unknown non-negative integer
    // key is accepted; an unknown NEGATIVE integer key, or a non-integer key, MUST be
    // rejected. Integers decode to BigInteger (non-negative for major 0, negative for
    // major 1); a negative BigInteger key is reserved, a non-BigInteger key non-integer.
    private fun forwardCompatKeys(m: NpampCbor.CborMap, prefix: String) {
        for (k in m.keys()) {
            if (k is BigInteger) {
                if (k.signum() < 0) throw bad(prefix, "unknown negative key $k (reserved)")
            } else {
                throw bad(prefix, "non-integer map key")
            }
        }
    }

    private fun checkFields(m: NpampCbor.CborMap, schema: Array<Field>, prefix: String) {
        for (fld in schema) {
            if (!m.has(fld.key)) {
                if (fld.required) throw bad(prefix, "missing required field (key ${fld.key})")
                continue
            }
            if (!matchesKind(m.get(fld.key), fld.kind)) {
                throw bad(prefix, "field (key ${fld.key}) has the wrong CBOR type")
            }
        }
        forwardCompatKeys(m, prefix)
    }

    private fun decodeMap(payload: ByteArray, prefix: String): NpampCbor.CborMap {
        val v = try {
            NpampCbor.decodeTop(payload)
        } catch (e: CborException) {
            throw bad(prefix, e.message ?: "cbor error")
        }
        if (v !is NpampCbor.CborMap) throw bad(prefix, "payload is not a CBOR map")
        return v
    }

    private fun checkFrameKind(m: NpampCbor.CborMap, ft: Int, prefix: String) {
        if (!m.has(0)) throw bad(prefix, "missing frame_kind (0)")
        val fk = m.get(0)
        if (!isUint(fk)) throw bad(prefix, "frame_kind (0) is not an unsigned int")
        if (fk != BigInteger.valueOf(ft.toLong())) {
            throw bad(prefix, "frame_kind $fk contradicts frame type $ft")
        }
    }

    private fun checkCorr(m: NpampCbor.CborMap, prefix: String) {
        if (!m.has(1)) throw bad(prefix, "missing corr (1)")
        val corr = m.get(1)
        if (corr !is ByteArray || corr.size < 1 || corr.size > 64) {
            throw bad(prefix, "corr (1) must be a byte string of 1-64 bytes")
        }
    }

    private fun bad(prefix: String, msg: String) = BodyException("$prefix: $msg")

    // ---------- NPAMP-MEMORY (spec/companion/81 §4-§8) ----------

    private const val FRAME_MEMORY_CREATE_REQ = 0x0100
    private const val FRAME_MEMORY_CREATE_RESULT = 0x0101
    private const val FRAME_MEMORY_READ_REQ = 0x0102
    private const val FRAME_MEMORY_READ_RESULT = 0x0103
    private const val FRAME_MEMORY_UPDATE_REQ = 0x0104
    private const val FRAME_MEMORY_UPDATE_RESULT = 0x0105
    private const val FRAME_MEMORY_DELETE_REQ = 0x0106
    private const val FRAME_MEMORY_DELETE_RESULT = 0x0107
    private const val FRAME_MEMORY_RETRIEVE_REQ = 0x0108
    private const val FRAME_MEMORY_RETRIEVE_RESULT = 0x0109
    private const val FRAME_MEMORY_RETRIEVE_STREAM_DATA = 0x010a
    private const val FRAME_MEMORY_RETRIEVE_STREAM_END = 0x010b
    private const val FRAME_MEMORY_STATUS_REQ = 0x010c
    private const val FRAME_MEMORY_STATUS_RESULT = 0x010d
    private const val FRAME_MEMORY_ERROR = 0x010e
    private const val FRAME_MEMORY_EVICT = 0x0035
    private const val FRAME_MEMORY_REVIVE = 0x0036

    private val MEMORY_SCHEMAS: Map<Int, Array<Field>> = mapOf(
        FRAME_MEMORY_CREATE_REQ to arrayOf(
            f(2, Kind.TEXT, true), f(3, Kind.TEXT, false), f(4, Kind.TEXT, false), f(5, Kind.TEXT, false),
            f(6, Kind.TEXT, false), f(7, Kind.TEXT, false), f(8, Kind.TEXT, false), f(9, Kind.TEXT, false),
            f(10, Kind.MAP, false), f(11, Kind.UINT, true)
        ),
        FRAME_MEMORY_CREATE_RESULT to arrayOf(f(2, Kind.TEXT, true), f(3, Kind.TEXT, true)),
        FRAME_MEMORY_READ_REQ to arrayOf(f(2, Kind.TEXT, true), f(3, Kind.UINT, true)),
        FRAME_MEMORY_READ_RESULT to arrayOf(f(2, Kind.MAP, true)),
        FRAME_MEMORY_UPDATE_REQ to arrayOf(
            f(2, Kind.TEXT, true), f(3, Kind.TEXT, false), f(4, Kind.TEXT, false), f(5, Kind.TEXT, false),
            f(6, Kind.TEXT, false), f(7, Kind.TEXT, false), f(8, Kind.TEXT, false), f(9, Kind.MAP, false),
            f(10, Kind.UINT, true)
        ),
        FRAME_MEMORY_UPDATE_RESULT to arrayOf(f(2, Kind.TEXT, true), f(3, Kind.TEXT, true)),
        FRAME_MEMORY_DELETE_REQ to arrayOf(f(2, Kind.TEXT, true), f(3, Kind.UINT, true)),
        FRAME_MEMORY_DELETE_RESULT to arrayOf(f(2, Kind.TEXT, true), f(3, Kind.TEXT, true)),
        FRAME_MEMORY_RETRIEVE_REQ to arrayOf(
            f(2, Kind.TEXT, false), f(3, Kind.TEXT, false), f(4, Kind.TEXT, false), f(5, Kind.TEXT, false),
            f(6, Kind.TEXT, false), f(7, Kind.UINT, false), f(8, Kind.TEXT, false), f(9, Kind.BYTES, false),
            f(10, Kind.UINT, true)
        ),
        FRAME_MEMORY_RETRIEVE_RESULT to arrayOf(
            f(2, Kind.ARRAY, true), f(3, Kind.BOOL, true), f(4, Kind.BYTES, false), f(5, Kind.UINT, false),
            f(6, Kind.BOOL, false)
        ),
        FRAME_MEMORY_RETRIEVE_STREAM_DATA to arrayOf(f(2, Kind.ARRAY, true)),
        FRAME_MEMORY_RETRIEVE_STREAM_END to arrayOf(f(2, Kind.ARRAY, false), f(3, Kind.BOOL, true)),
        FRAME_MEMORY_STATUS_REQ to arrayOf(),
        FRAME_MEMORY_STATUS_RESULT to arrayOf(
            f(2, Kind.TEXT, true), f(3, Kind.TEXT, false), f(4, Kind.UINT, false), f(5, Kind.MAP, false)
        ),
        FRAME_MEMORY_ERROR to arrayOf(
            f(2, Kind.UINT, true), f(3, Kind.TEXT, true), f(4, Kind.UINT, false), f(5, Kind.TEXT, false)
        ),
        FRAME_MEMORY_EVICT to arrayOf(f(2, Kind.TEXT, true), f(3, Kind.TEXT, false), f(4, Kind.UINT, true)),
        FRAME_MEMORY_REVIVE to arrayOf(f(2, Kind.TEXT, true), f(3, Kind.UINT, true))
    )

    fun validateMemoryPayload(ft: Int, payload: ByteArray): NpampCbor.CborMap {
        val p = "npamp/memory: malformed_request"
        val schema = MEMORY_SCHEMAS[ft] ?: throw bad(p, "$ft is not a Memory operation frame type")
        val m = decodeMap(payload, p)
        checkFrameKind(m, ft, p)
        checkCorr(m, p)
        checkFields(m, schema, p)
        return m
    }

    // ---------- NPAMP-STREAM (spec/companion/80 §4-§5) ----------

    private const val FRAME_STREAM_OPEN = 0x0100
    private const val FRAME_STREAM_DATA = 0x0101
    private const val FRAME_STREAM_CLOSE = 0x0102
    private const val FRAME_STREAM_RESET = 0x0103
    private const val FRAME_STREAM_WINDOW_UPDATE = 0x0104

    private val STREAM_SCHEMAS: Map<Int, Array<Field>> = mapOf(
        FRAME_STREAM_OPEN to arrayOf(f(2, Kind.UINT, true), f(3, Kind.UINT, true), f(4, Kind.TEXT, false), f(5, Kind.UINT, false)),
        FRAME_STREAM_DATA to arrayOf(f(2, Kind.UINT, true), f(3, Kind.BYTES, true), f(4, Kind.UINT, false)),
        FRAME_STREAM_CLOSE to arrayOf(f(2, Kind.UINT, true)),
        FRAME_STREAM_RESET to arrayOf(f(2, Kind.UINT, true), f(3, Kind.UINT, true)),
        FRAME_STREAM_WINDOW_UPDATE to arrayOf(f(2, Kind.UINT, true))
    )

    fun validateStreamPayload(ft: Int, payload: ByteArray): NpampCbor.CborMap {
        val p = "npamp/stream: malformed"
        val schema = STREAM_SCHEMAS[ft] ?: throw bad(p, "$ft is not a Stream frame type")
        val m = decodeMap(payload, p)
        checkFrameKind(m, ft, p)
        // Envelope key 1 is sub_stream_id -- an Unsigned int, unlike the byte-string corr.
        if (!m.has(1)) throw bad(p, "missing sub_stream_id (1)")
        if (!isUint(m.get(1))) throw bad(p, "sub_stream_id (1) is not an unsigned int")
        checkFields(m, schema, p)
        return m
    }

    // ---------- NPAMP-CAP (spec/companion/84 §4-§8) ----------

    private const val FRAME_CAP_ISSUE_REQ = 0x0100
    private const val FRAME_CAP_ISSUE_RESULT = 0x0101
    private const val FRAME_CAP_DELEGATE_REQ = 0x0102
    private const val FRAME_CAP_DELEGATE_RESULT = 0x0103
    private const val FRAME_CAP_REVOKE_REQ = 0x0104
    private const val FRAME_CAP_REVOKE_RESULT = 0x0105
    private const val FRAME_CAP_LOOKUP_REQ = 0x0106
    private const val FRAME_CAP_LOOKUP_RESULT = 0x0107
    private const val FRAME_CAP_ERROR = 0x0108
    private const val FRAME_CAP_TOKEN_PRESENT = 0x0060
    private const val FRAME_CAP_TOKEN_ACCEPT = 0x0061
    private const val FRAME_CAP_TOKEN_CHALLENGE = 0x0062
    private const val FRAME_CAP_TOKEN_PROOF = 0x0063

    private val CAPABILITY_SCHEMAS: Map<Int, Array<Field>> = mapOf(
        FRAME_CAP_ISSUE_REQ to arrayOf(
            f(2, Kind.TEXT, true), f(3, Kind.TEXT, true), f(4, Kind.MAP, false), f(5, Kind.TEXT, false),
            f(6, Kind.TEXT, false), f(7, Kind.UINT, false), f(8, Kind.TEXT, false), f(9, Kind.UINT, true)
        ),
        FRAME_CAP_ISSUE_RESULT to arrayOf(f(2, Kind.MAP, true), f(3, Kind.TEXT, true)),
        FRAME_CAP_DELEGATE_REQ to arrayOf(
            f(2, Kind.TEXT, true), f(3, Kind.TEXT, true), f(4, Kind.MAP, false), f(5, Kind.TEXT, false),
            f(6, Kind.UINT, false), f(7, Kind.UINT, true)
        ),
        FRAME_CAP_DELEGATE_RESULT to arrayOf(f(2, Kind.MAP, true), f(3, Kind.TEXT, true)),
        FRAME_CAP_REVOKE_REQ to arrayOf(f(2, Kind.TEXT, true), f(3, Kind.BOOL, false), f(4, Kind.TEXT, false), f(5, Kind.UINT, true)),
        FRAME_CAP_REVOKE_RESULT to arrayOf(f(2, Kind.TEXT, true), f(3, Kind.TEXT, true), f(4, Kind.UINT, false)),
        FRAME_CAP_LOOKUP_REQ to arrayOf(
            f(2, Kind.TEXT, false), f(3, Kind.TEXT, false), f(4, Kind.TEXT, false), f(5, Kind.BOOL, false),
            f(6, Kind.UINT, false), f(7, Kind.BYTES, false), f(8, Kind.UINT, true)
        ),
        FRAME_CAP_LOOKUP_RESULT to arrayOf(f(2, Kind.ARRAY, true), f(3, Kind.BOOL, true), f(4, Kind.BYTES, false)),
        FRAME_CAP_ERROR to arrayOf(f(2, Kind.UINT, true), f(3, Kind.TEXT, true), f(4, Kind.UINT, false), f(5, Kind.TEXT, false)),
        FRAME_CAP_TOKEN_PRESENT to arrayOf(f(2, Kind.MAP, true), f(3, Kind.ARRAY, false), f(4, Kind.UINT, true)),
        FRAME_CAP_TOKEN_ACCEPT to arrayOf(f(2, Kind.TEXT, true), f(3, Kind.TEXT, true)),
        FRAME_CAP_TOKEN_CHALLENGE to arrayOf(f(2, Kind.TEXT, true), f(3, Kind.BYTES, true), f(4, Kind.UINT, true)),
        FRAME_CAP_TOKEN_PROOF to arrayOf(f(2, Kind.TEXT, true), f(3, Kind.BYTES, true))
    )

    fun validateCapabilityPayload(ft: Int, payload: ByteArray): NpampCbor.CborMap {
        val p = "npamp/capability: malformed_request"
        val schema = CAPABILITY_SCHEMAS[ft] ?: throw bad(p, "$ft is not a Capability operation frame type")
        val m = decodeMap(payload, p)
        checkFrameKind(m, ft, p)
        checkCorr(m, p)
        checkFields(m, schema, p)
        return m
    }

    // ---------- NPAMP-IMMUNE (spec/companion/85 §4-§8) ----------

    private const val FRAME_IMMUNE_REPORT_REQ = 0x0100
    private const val FRAME_IMMUNE_REPORT_RESULT = 0x0101
    private const val FRAME_IMMUNE_ERROR = 0x0102
    private const val FRAME_IMMUNE_GOSSIP_ADVERTISE = 0x00c0
    private const val FRAME_IMMUNE_GOSSIP_ACK = 0x00c1
    private const val FRAME_IMMUNE_GOSSIP_PULL_REQ = 0x00c2
    private const val FRAME_IMMUNE_GOSSIP_PULL_RESULT = 0x00c3
    private const val FRAME_IMMUNE_GOSSIP_RETRACT = 0x00c4

    private val IMMUNE_SCHEMAS: Map<Int, Array<Field>> = mapOf(
        FRAME_IMMUNE_REPORT_REQ to arrayOf(
            f(2, Kind.TEXT, true), f(3, Kind.UINT, true), f(4, Kind.UINT, true), f(5, Kind.TEXT, false),
            f(6, Kind.TEXT, false), f(7, Kind.TEXT, false), f(8, Kind.BYTES, false), f(9, Kind.UINT, false),
            f(10, Kind.TEXT, false)
        ),
        FRAME_IMMUNE_REPORT_RESULT to arrayOf(f(2, Kind.UINT, true), f(3, Kind.TEXT, false)),
        FRAME_IMMUNE_ERROR to arrayOf(f(2, Kind.UINT, true), f(3, Kind.TEXT, true), f(4, Kind.UINT, false)),
        FRAME_IMMUNE_GOSSIP_ADVERTISE to arrayOf(f(2, Kind.ARRAY, true), f(3, Kind.BOOL, false)),
        FRAME_IMMUNE_GOSSIP_ACK to arrayOf(f(2, Kind.ARRAY, false), f(3, Kind.ARRAY, false), f(4, Kind.UINT, false)),
        FRAME_IMMUNE_GOSSIP_PULL_REQ to arrayOf(f(2, Kind.ARRAY, true)),
        FRAME_IMMUNE_GOSSIP_PULL_RESULT to arrayOf(f(2, Kind.ARRAY, true)),
        FRAME_IMMUNE_GOSSIP_RETRACT to arrayOf(f(2, Kind.BYTES, true), f(3, Kind.UINT, true), f(4, Kind.UINT, false))
    )

    private val GOSSIP_DESCRIPTOR_SCHEMA = arrayOf(
        f(0, Kind.BYTES, true), f(1, Kind.UINT, true), f(2, Kind.UINT, false), f(3, Kind.UINT, false),
        f(4, Kind.BYTES, false), f(5, Kind.TEXT, false), f(6, Kind.TEXT, false), f(7, Kind.UINT, false),
        f(8, Kind.BYTES, false), f(9, Kind.BYTES, false)
    )
    private val GOSSIP_ITEM_SCHEMA = arrayOf(
        f(0, Kind.BYTES, true), f(1, Kind.UINT, true), f(2, Kind.UINT, false), f(3, Kind.UINT, false),
        f(4, Kind.BYTES, false), f(5, Kind.TEXT, false), f(6, Kind.TEXT, false), f(7, Kind.UINT, false),
        f(8, Kind.BYTES, true)
    )

    private fun validateGossipArray(m: NpampCbor.CborMap, nested: Array<Field>, p: String) {
        val itemsV = m.get(2)
        if (itemsV !is List<*>) throw bad(p, "items (2) is not an array")
        for ((i, el) in itemsV.withIndex()) {
            if (el !is NpampCbor.CborMap) throw bad(p, "items[$i] is not a CBOR map")
            checkFields(el, nested, p)
        }
    }

    fun validateImmunePayload(ft: Int, payload: ByteArray): NpampCbor.CborMap {
        val p = "npamp/immune: malformed_request"
        val schema = IMMUNE_SCHEMAS[ft] ?: throw bad(p, "$ft is not an Immune operation frame type")
        val m = decodeMap(payload, p)
        checkFrameKind(m, ft, p)
        checkCorr(m, p)
        checkFields(m, schema, p)
        when (ft) {
            FRAME_IMMUNE_GOSSIP_ADVERTISE -> validateGossipArray(m, GOSSIP_DESCRIPTOR_SCHEMA, p)
            FRAME_IMMUNE_GOSSIP_PULL_RESULT -> validateGossipArray(m, GOSSIP_ITEM_SCHEMA, p)
        }
        return m
    }

    // ---------- NPAMP-SETTLEMENT (spec/companion/86 §4-§8) ----------

    private const val FRAME_SETTLE_INTENT_REQ = 0x0100
    private const val FRAME_SETTLE_INTENT_RESULT = 0x0101
    private const val FRAME_RECEIPT_REQ = 0x0102
    private const val FRAME_RECEIPT_RESULT = 0x0103
    private const val FRAME_SETTLE_ERROR = 0x0104
    private const val FRAME_SETTLE_BATCH_COMMIT_REQ = 0x00a0
    private const val FRAME_SETTLE_BATCH_COMMIT_RESULT = 0x00a1

    private val SETTLEMENT_SCHEMAS: Map<Int, Array<Field>> = mapOf(
        FRAME_SETTLE_INTENT_REQ to arrayOf(
            f(2, Kind.TEXT, true), f(3, Kind.TEXT, false), f(4, Kind.TEXT, false), f(5, Kind.TEXT, false),
            f(6, Kind.TEXT, false), f(7, Kind.TEXT, false), f(8, Kind.UINT, true)
        ),
        FRAME_SETTLE_INTENT_RESULT to arrayOf(f(2, Kind.TEXT, true), f(3, Kind.TEXT, true), f(4, Kind.TEXT, false)),
        FRAME_RECEIPT_REQ to arrayOf(f(2, Kind.TEXT, true), f(3, Kind.TEXT, false), f(4, Kind.UINT, true)),
        FRAME_RECEIPT_RESULT to arrayOf(f(2, Kind.MAP, true)),
        FRAME_SETTLE_ERROR to arrayOf(f(2, Kind.UINT, true), f(3, Kind.TEXT, true), f(4, Kind.UINT, false), f(5, Kind.TEXT, false)),
        FRAME_SETTLE_BATCH_COMMIT_REQ to arrayOf(
            f(2, Kind.TEXT, true), f(3, Kind.BYTES, true), f(4, Kind.TEXT, false), f(5, Kind.UINT, false),
            f(6, Kind.TEXT, false), f(7, Kind.UINT, true)
        ),
        FRAME_SETTLE_BATCH_COMMIT_RESULT to arrayOf(f(2, Kind.TEXT, true), f(3, Kind.TEXT, true), f(4, Kind.TEXT, false))
    )

    fun validateSettlementPayload(ft: Int, payload: ByteArray): NpampCbor.CborMap {
        val p = "npamp/settlement: malformed_request"
        val schema = SETTLEMENT_SCHEMAS[ft] ?: throw bad(p, "$ft is not a Settlement operation frame type")
        val m = decodeMap(payload, p)
        checkFrameKind(m, ft, p)
        checkCorr(m, p)
        checkFields(m, schema, p)
        return m
    }

    // ---------- NPAMP-TELEMETRY (spec/companion/87 §4-§8) ----------

    private const val FRAME_TELEMETRY_REPORT = 0x0100
    private const val FRAME_TELEMETRY_SUBSCRIBE = 0x0101
    private const val FRAME_TELEMETRY_SUB_ACK = 0x0102
    private const val FRAME_TELEMETRY_UNSUBSCRIBE = 0x0103
    private const val FRAME_TELEMETRY_CREDIT = 0x0104
    private const val FRAME_TELEMETRY_ERROR = 0x0105

    private val TELEMETRY_SCHEMAS: Map<Int, Array<Field>> = mapOf(
        FRAME_TELEMETRY_SUBSCRIBE to arrayOf(
            f(2, Kind.ARRAY, false), f(3, Kind.ARRAY, false), f(4, Kind.ARRAY, false),
            f(5, Kind.UINT, false), f(6, Kind.UINT, false), f(7, Kind.UINT, true)
        ),
        FRAME_TELEMETRY_SUB_ACK to arrayOf(f(2, Kind.BYTES, true), f(3, Kind.UINT, true), f(4, Kind.ARRAY, false)),
        FRAME_TELEMETRY_UNSUBSCRIBE to arrayOf(f(2, Kind.BYTES, true)),
        FRAME_TELEMETRY_CREDIT to arrayOf(f(2, Kind.BYTES, true), f(3, Kind.UINT, true), f(4, Kind.UINT, false)),
        FRAME_TELEMETRY_ERROR to arrayOf(f(2, Kind.UINT, true), f(3, Kind.TEXT, false), f(4, Kind.BYTES, false))
    )

    private val METRIC_SCHEMA = arrayOf(
        f(0, Kind.TEXT, true), f(1, Kind.UINT, true), f(2, Kind.UINT, true), f(3, Kind.NUMBER, true),
        f(4, Kind.TEXT, false), f(5, Kind.MAP, false), f(6, Kind.UINT, false)
    )
    private val EVENT_SCHEMA = arrayOf(
        f(0, Kind.TEXT, true), f(1, Kind.UINT, true), f(2, Kind.UINT, false),
        f(3, Kind.MAP, false), f(4, Kind.TEXT, false), f(5, Kind.UINT, false)
    )
    private val HEALTH_SCHEMA = arrayOf(
        f(0, Kind.TEXT, true), f(1, Kind.UINT, true), f(2, Kind.UINT, true),
        f(3, Kind.TEXT, false), f(4, Kind.MAP, false)
    )

    private fun isTelemetryFrame(ft: Int) = ft in FRAME_TELEMETRY_REPORT..FRAME_TELEMETRY_ERROR

    fun validateTelemetryPayload(ft: Int, payload: ByteArray): NpampCbor.CborMap {
        val p = "npamp/telemetry: malformed_payload"
        if (!isTelemetryFrame(ft)) throw bad(p, "$ft is not a Telemetry operation frame type")
        val m = decodeMap(payload, p)
        checkFrameKind(m, ft, p)
        if (ft == FRAME_TELEMETRY_REPORT) return validateTelemetryReport(m, p)
        // Every non-REPORT Telemetry frame carries a REQUIRED, non-empty corr (1) (§4.1).
        checkCorr(m, p)
        checkFields(m, TELEMETRY_SCHEMAS.getValue(ft), p)
        return m
    }

    // validateTelemetryReport: corr (1) is CONDITIONAL (present iff the batch answers
    // a subscription, in which case sub_id (2) MUST also be present; a standalone
    // report MUST omit both); batch_seq (3) is REQUIRED; the report MUST carry content
    // (at least one of metrics(4)/events(5)/health(6) present and non-empty).
    private fun validateTelemetryReport(m: NpampCbor.CborMap, p: String): NpampCbor.CborMap {
        val hasCorr = m.has(1)
        val hasSubID = m.has(2)
        if (hasCorr) {
            val corr = m.get(1)
            if (corr !is ByteArray || corr.size < 1 || corr.size > 64) {
                throw bad(p, "corr (1) must be a byte string of 1-64 bytes")
            }
            if (!hasSubID) throw bad(p, "subscribed report carries corr (1) but omits sub_id (2)")
            if (m.get(2) !is ByteArray) throw bad(p, "sub_id (2) must be a byte string")
        } else if (hasSubID) {
            throw bad(p, "standalone report carries sub_id (2) without corr (1)")
        }

        if (!m.has(3)) throw bad(p, "missing required batch_seq (3)")
        if (!isUint(m.get(3))) throw bad(p, "batch_seq (3) is not an unsigned int")

        var nonEmpty = 0
        val content = listOf(
            Triple(4L, METRIC_SCHEMA, "metric"),
            Triple(5L, EVENT_SCHEMA, "event"),
            Triple(6L, HEALTH_SCHEMA, "health")
        )
        for ((key, schema, what) in content) {
            if (!m.has(key)) continue
            val v = m.get(key)
            if (v !is List<*>) throw bad(p, "$what array (key $key) is not a CBOR array")
            if (v.isNotEmpty()) nonEmpty++
            for (el in v) {
                if (el !is NpampCbor.CborMap) throw bad(p, "$what array element is not a CBOR map")
                checkFields(el, schema, p)
            }
        }
        if (nonEmpty == 0) throw bad(p, "TELEMETRY_REPORT carries no metrics, events, or health")

        forwardCompatKeys(m, p)
        return m
    }

    // ---------- NPAMP-COMMERCE (spec/companion/88 §4-§8) ----------

    private const val FRAME_COMMERCE_MANDATE_CREATE_REQ = 0x0100
    private const val FRAME_COMMERCE_MANDATE_CREATE_RESULT = 0x0101
    private const val FRAME_COMMERCE_MANDATE_READ_REQ = 0x0102
    private const val FRAME_COMMERCE_MANDATE_READ_RESULT = 0x0103
    private const val FRAME_COMMERCE_MANDATE_REVOKE_REQ = 0x0104
    private const val FRAME_COMMERCE_MANDATE_REVOKE_RESULT = 0x0105
    private const val FRAME_COMMERCE_MANDATE_STATUS_REQ = 0x0106
    private const val FRAME_COMMERCE_MANDATE_STATUS_RESULT = 0x0107
    private const val FRAME_COMMERCE_INTENT_PROPOSE_REQ = 0x0108
    private const val FRAME_COMMERCE_INTENT_PROPOSE_RESULT = 0x0109
    private const val FRAME_COMMERCE_INTENT_RESPOND_REQ = 0x010a
    private const val FRAME_COMMERCE_INTENT_RESPOND_RESULT = 0x010b
    private const val FRAME_COMMERCE_INTENT_STATUS_REQ = 0x010c
    private const val FRAME_COMMERCE_INTENT_STATUS_RESULT = 0x010d
    private const val FRAME_COMMERCE_ERROR = 0x010e

    private val COMMERCE_SCHEMAS: Map<Int, Array<Field>> = mapOf(
        FRAME_COMMERCE_MANDATE_CREATE_REQ to arrayOf(
            f(2, Kind.TEXT, true), f(3, Kind.TEXT, true), f(4, Kind.MAP, true), f(5, Kind.TEXT, false),
            f(6, Kind.TEXT, false), f(7, Kind.TEXT, false), f(8, Kind.MAP, false), f(9, Kind.TEXT, false),
            f(10, Kind.BYTES, false), f(11, Kind.TEXT, false), f(12, Kind.TEXT, false), f(13, Kind.UINT, true)
        ),
        FRAME_COMMERCE_MANDATE_CREATE_RESULT to arrayOf(f(2, Kind.TEXT, true), f(3, Kind.TEXT, true)),
        FRAME_COMMERCE_MANDATE_READ_REQ to arrayOf(f(2, Kind.TEXT, true), f(3, Kind.UINT, true)),
        FRAME_COMMERCE_MANDATE_READ_RESULT to arrayOf(f(2, Kind.MAP, true)),
        FRAME_COMMERCE_MANDATE_REVOKE_REQ to arrayOf(f(2, Kind.TEXT, true), f(3, Kind.TEXT, false), f(4, Kind.UINT, true)),
        FRAME_COMMERCE_MANDATE_REVOKE_RESULT to arrayOf(f(2, Kind.TEXT, true), f(3, Kind.TEXT, true)),
        FRAME_COMMERCE_MANDATE_STATUS_REQ to arrayOf(f(2, Kind.TEXT, true), f(3, Kind.UINT, true)),
        FRAME_COMMERCE_MANDATE_STATUS_RESULT to arrayOf(f(2, Kind.TEXT, true), f(3, Kind.TEXT, true), f(4, Kind.TEXT, false)),
        FRAME_COMMERCE_INTENT_PROPOSE_REQ to arrayOf(
            f(2, Kind.ARRAY, true), f(3, Kind.ARRAY, true), f(4, Kind.TEXT, false), f(5, Kind.MAP, false),
            f(6, Kind.TEXT, false), f(7, Kind.UINT, true)
        ),
        FRAME_COMMERCE_INTENT_PROPOSE_RESULT to arrayOf(f(2, Kind.TEXT, true), f(3, Kind.TEXT, true)),
        FRAME_COMMERCE_INTENT_RESPOND_REQ to arrayOf(
            f(2, Kind.TEXT, true), f(3, Kind.UINT, true), f(4, Kind.ARRAY, false), f(5, Kind.TEXT, false), f(6, Kind.UINT, true)
        ),
        FRAME_COMMERCE_INTENT_RESPOND_RESULT to arrayOf(f(2, Kind.TEXT, true), f(3, Kind.TEXT, true)),
        FRAME_COMMERCE_INTENT_STATUS_REQ to arrayOf(f(2, Kind.TEXT, true), f(3, Kind.UINT, true)),
        FRAME_COMMERCE_INTENT_STATUS_RESULT to arrayOf(
            f(2, Kind.TEXT, true), f(3, Kind.TEXT, true), f(4, Kind.ARRAY, false), f(5, Kind.ARRAY, false)
        ),
        FRAME_COMMERCE_ERROR to arrayOf(f(2, Kind.UINT, true), f(3, Kind.TEXT, true), f(4, Kind.UINT, false), f(5, Kind.TEXT, false))
    )

    private fun validateCommerceAmount(v: Any?, p: String) {
        if (v !is NpampCbor.CborMap) throw bad(p, "`amount` is not a CBOR map (§4.3)")
        if (!v.has(0)) throw bad(p, "`amount` omits REQUIRED units (0) (§4.3)")
        if (v.get(0) !is BigInteger) throw bad(p, "`amount` units (0) is not an integer (§4.3)")
        if (!v.has(1)) throw bad(p, "`amount` omits REQUIRED scale (1) (§4.3)")
        if (!isUint(v.get(1))) throw bad(p, "`amount` scale (1) is not an unsigned int (§4.3)")
        if (!v.has(2)) throw bad(p, "`amount` omits REQUIRED currency (2) (§4.3)")
        if (v.get(2) !is String) throw bad(p, "`amount` currency (2) is not a text string (§4.3)")
        forwardCompatKeys(v, p)
    }

    private fun validateCommerceLeg(v: Any?, parties: Set<String>, p: String) {
        if (v !is NpampCbor.CborMap) throw bad(p, "a settlement leg is not a CBOR map (§6.6)")
        if (!v.has(0)) throw bad(p, "a leg omits REQUIRED `from` (0) (§6.6)")
        val frm = v.get(0)
        if (frm !is String) throw bad(p, "a leg `from` (0) is not a text string (§6.6)")
        if (!v.has(1)) throw bad(p, "a leg omits REQUIRED `to` (1) (§6.6)")
        val to = v.get(1)
        if (to !is String) throw bad(p, "a leg `to` (1) is not a text string (§6.6)")
        if (!v.has(2)) throw bad(p, "a leg omits REQUIRED `amount` (2) (§6.6)")
        validateCommerceAmount(v.get(2), p)
        if (!parties.contains(frm)) throw bad(p, "leg `from` names a party not in `parties` (§6.6)")
        if (!parties.contains(to)) throw bad(p, "leg `to` names a party not in `parties` (§6.6)")
        forwardCompatKeys(v, p)
    }

    private fun validateCommerceNested(ft: Int, m: NpampCbor.CborMap, p: String) {
        if (ft == FRAME_COMMERCE_MANDATE_CREATE_REQ) {
            val av = m.get(4)
            if (av != null) validateCommerceAmount(av, p)
        } else if (ft == FRAME_COMMERCE_INTENT_PROPOSE_REQ) {
            val pv = m.get(2)
            val parties = HashSet<String>()
            if (pv is List<*>) {
                for (party in pv) {
                    if (party !is String) throw bad(p, "a `parties` element is not a text string (§6.6)")
                    parties.add(party)
                }
            }
            val lv = m.get(3)
            if (lv is List<*>) {
                for (lg in lv) validateCommerceLeg(lg, parties, p)
            }
        }
    }

    fun validateCommercePayload(ft: Int, payload: ByteArray): NpampCbor.CborMap {
        val p = "npamp/commerce: malformed_request"
        val schema = COMMERCE_SCHEMAS[ft] ?: throw bad(p, "$ft is not a Commerce operation frame type")
        val m = decodeMap(payload, p)
        checkFrameKind(m, ft, p)
        checkCorr(m, p)
        checkFields(m, schema, p)
        validateCommerceNested(ft, m, p)
        return m
    }

    // ---------- NPAMP-INTERACT (spec/companion/89 §4-§8) ----------

    private const val FRAME_INTERACT_EVENT = 0x0100
    private const val FRAME_INTERACT_EVENT_ACK = 0x0101
    private const val FRAME_INTERACT_PROMPT_REQ = 0x0102
    private const val FRAME_INTERACT_PROMPT_RESULT = 0x0103
    private const val FRAME_INTERACT_APPROVAL_REQ = 0x0104
    private const val FRAME_INTERACT_APPROVAL_RESULT = 0x0105
    private const val FRAME_INTERACT_CANCEL = 0x0106
    private const val FRAME_INTERACT_ERROR = 0x0107

    private val INTERACTION_SCHEMAS: Map<Int, Array<Field>> = mapOf(
        FRAME_INTERACT_EVENT to arrayOf(f(2, Kind.UINT, true), f(3, Kind.TEXT, false), f(4, Kind.MAP, false), f(5, Kind.BOOL, false)),
        FRAME_INTERACT_EVENT_ACK to arrayOf(),
        FRAME_INTERACT_PROMPT_REQ to arrayOf(
            f(2, Kind.UINT, true), f(3, Kind.TEXT, true), f(4, Kind.ARRAY, false), f(5, Kind.MAP, false), f(6, Kind.UINT, false)
        ),
        FRAME_INTERACT_PROMPT_RESULT to arrayOf(f(2, Kind.UINT, true)),
        FRAME_INTERACT_APPROVAL_REQ to arrayOf(f(2, Kind.TEXT, true), f(3, Kind.UINT, false), f(4, Kind.MAP, false), f(5, Kind.UINT, false)),
        FRAME_INTERACT_APPROVAL_RESULT to arrayOf(f(2, Kind.UINT, true), f(3, Kind.TEXT, false)),
        FRAME_INTERACT_CANCEL to arrayOf(f(2, Kind.UINT, false)),
        FRAME_INTERACT_ERROR to arrayOf(f(2, Kind.UINT, true), f(3, Kind.TEXT, true), f(4, Kind.UINT, false), f(5, Kind.TEXT, false))
    )

    fun validateInteractionPayload(ft: Int, payload: ByteArray): NpampCbor.CborMap {
        val p = "npamp/interaction: malformed_request"
        val schema = INTERACTION_SCHEMAS[ft] ?: throw bad(p, "$ft is not an Interaction operation frame type")
        val m = decodeMap(payload, p)
        checkFrameKind(m, ft, p)
        checkCorr(m, p)
        checkFields(m, schema, p)
        return m
    }

    // ---------- NPAMP-WORKFLOW (spec/companion/8a §4-§8) ----------

    private const val FRAME_WORKFLOW_SUBMIT_REQ = 0x0100
    private const val FRAME_WORKFLOW_SUBMIT_RESULT = 0x0101
    private const val FRAME_WORKFLOW_STATUS_REQ = 0x0102
    private const val FRAME_WORKFLOW_STATUS_RESULT = 0x0103
    private const val FRAME_WORKFLOW_CANCEL_REQ = 0x0104
    private const val FRAME_WORKFLOW_CANCEL_RESULT = 0x0105
    private const val FRAME_WORKFLOW_STEP_EVENT = 0x0106
    private const val FRAME_WORKFLOW_COMPLETE = 0x0107
    private const val FRAME_WORKFLOW_ERROR = 0x0108

    private val WORKFLOW_SCHEMAS: Map<Int, Array<Field>> = mapOf(
        FRAME_WORKFLOW_SUBMIT_REQ to arrayOf(
            f(2, Kind.TEXT, true), f(3, Kind.BYTES, false), f(4, Kind.MAP, false), f(5, Kind.UINT, false),
            f(6, Kind.TEXT, false), f(7, Kind.TEXT, false), f(8, Kind.TEXT, false), f(9, Kind.TEXT, false),
            f(10, Kind.MAP, false), f(11, Kind.UINT, true)
        ),
        FRAME_WORKFLOW_SUBMIT_RESULT to arrayOf(f(2, Kind.TEXT, true), f(3, Kind.UINT, true)),
        FRAME_WORKFLOW_STATUS_REQ to arrayOf(f(2, Kind.TEXT, true)),
        FRAME_WORKFLOW_STATUS_RESULT to arrayOf(
            f(2, Kind.TEXT, true), f(3, Kind.UINT, true), f(4, Kind.UINT, false), f(5, Kind.TEXT, false),
            f(6, Kind.UINT, false), f(7, Kind.TEXT, false)
        ),
        FRAME_WORKFLOW_CANCEL_REQ to arrayOf(f(2, Kind.TEXT, true), f(3, Kind.TEXT, false)),
        FRAME_WORKFLOW_CANCEL_RESULT to arrayOf(f(2, Kind.TEXT, true), f(3, Kind.UINT, true)),
        FRAME_WORKFLOW_STEP_EVENT to arrayOf(
            f(2, Kind.TEXT, true), f(3, Kind.UINT, true), f(4, Kind.UINT, true), f(5, Kind.UINT, false),
            f(6, Kind.TEXT, false), f(7, Kind.UINT, false), f(8, Kind.BYTES, false), f(9, Kind.TEXT, false)
        ),
        FRAME_WORKFLOW_COMPLETE to arrayOf(
            f(2, Kind.TEXT, true), f(3, Kind.UINT, true), f(4, Kind.UINT, true), f(5, Kind.BYTES, false),
            f(6, Kind.UINT, false), f(7, Kind.TEXT, false)
        ),
        FRAME_WORKFLOW_ERROR to arrayOf(f(2, Kind.UINT, true), f(3, Kind.TEXT, true), f(4, Kind.UINT, false), f(5, Kind.TEXT, false))
    )

    private fun workflowFrameHasCorr(ft: Int) = ft != FRAME_WORKFLOW_STEP_EVENT && ft != FRAME_WORKFLOW_COMPLETE

    fun validateWorkflowPayload(ft: Int, payload: ByteArray): NpampCbor.CborMap {
        val p = "npamp/workflow: malformed_request"
        val schema = WORKFLOW_SCHEMAS[ft] ?: throw bad(p, "$ft is not a Workflow frame type")
        val m = decodeMap(payload, p)
        checkFrameKind(m, ft, p)
        // corr (1) is REQUIRED on every corr-bearing frame; the task-scoped
        // WORKFLOW_STEP_EVENT / WORKFLOW_COMPLETE carry no corr (§4.2, §5.2).
        if (workflowFrameHasCorr(ft)) checkCorr(m, p)
        checkFields(m, schema, p)
        return m
    }

    // ---------- NPAMP-KNOWLEDGE (spec/companion/8b §4-§9) ----------

    private const val FRAME_KNOWLEDGE_QUERY_REQ = 0x0100
    private const val FRAME_KNOWLEDGE_QUERY_RESULT = 0x0101
    private const val FRAME_KNOWLEDGE_QUERY_STREAM_DATA = 0x0102
    private const val FRAME_KNOWLEDGE_QUERY_STREAM_END = 0x0103
    private const val FRAME_KNOWLEDGE_SUBSCRIBE_REQ = 0x0104
    private const val FRAME_KNOWLEDGE_SUBSCRIBE_ACK = 0x0105
    private const val FRAME_KNOWLEDGE_UPDATE = 0x0106
    private const val FRAME_KNOWLEDGE_CREDIT = 0x0107
    private const val FRAME_KNOWLEDGE_UNSUBSCRIBE = 0x0108
    private const val FRAME_KNOWLEDGE_ERROR = 0x0109

    private val KNOWLEDGE_SCHEMAS: Map<Int, Array<Field>> = mapOf(
        FRAME_KNOWLEDGE_QUERY_REQ to arrayOf(
            f(2, Kind.TEXT, false), f(3, Kind.TEXT, false), f(4, Kind.TEXT, false), f(5, Kind.TEXT, false),
            f(6, Kind.UINT, false), f(8, Kind.TEXT, false), f(9, Kind.BYTES, false)
        ),
        FRAME_KNOWLEDGE_QUERY_RESULT to arrayOf(
            f(2, Kind.ARRAY, true), f(3, Kind.BOOL, true), f(4, Kind.BYTES, false), f(5, Kind.UINT, false), f(6, Kind.BOOL, false)
        ),
        FRAME_KNOWLEDGE_QUERY_STREAM_DATA to arrayOf(f(2, Kind.ARRAY, true)),
        FRAME_KNOWLEDGE_QUERY_STREAM_END to arrayOf(f(2, Kind.ARRAY, false), f(3, Kind.BOOL, true)),
        FRAME_KNOWLEDGE_SUBSCRIBE_REQ to arrayOf(
            f(2, Kind.TEXT, false), f(3, Kind.TEXT, false), f(4, Kind.TEXT, false), f(5, Kind.TEXT, false),
            f(7, Kind.TEXT, false), f(8, Kind.BOOL, false), f(9, Kind.UINT, true)
        ),
        FRAME_KNOWLEDGE_SUBSCRIBE_ACK to arrayOf(f(2, Kind.BYTES, true), f(3, Kind.UINT, true), f(4, Kind.BOOL, false)),
        FRAME_KNOWLEDGE_UPDATE to arrayOf(f(2, Kind.BYTES, true), f(3, Kind.UINT, true), f(4, Kind.ARRAY, false), f(5, Kind.ARRAY, false)),
        FRAME_KNOWLEDGE_CREDIT to arrayOf(f(2, Kind.BYTES, true), f(3, Kind.UINT, true), f(4, Kind.UINT, false)),
        FRAME_KNOWLEDGE_UNSUBSCRIBE to arrayOf(f(2, Kind.BYTES, true)),
        FRAME_KNOWLEDGE_ERROR to arrayOf(f(2, Kind.UINT, true), f(3, Kind.TEXT, true), f(4, Kind.UINT, false), f(5, Kind.BYTES, false))
    )

    fun validateKnowledgePayload(ft: Int, payload: ByteArray): NpampCbor.CborMap {
        val p = "npamp/knowledge: malformed_request"
        val schema = KNOWLEDGE_SCHEMAS[ft] ?: throw bad(p, "$ft is not a Knowledge operation frame type")
        val m = decodeMap(payload, p)
        checkFrameKind(m, ft, p)
        checkCorr(m, p)
        checkFields(m, schema, p)
        // §6.5: a KNOWLEDGE_UPDATE MUST carry at least one of results (4) or removed (5).
        if (ft == FRAME_KNOWLEDGE_UPDATE && !m.has(4) && !m.has(5)) {
            throw bad(p, "KNOWLEDGE_UPDATE carries neither results (4) nor removed (5) (§6.5)")
        }
        return m
    }
}
