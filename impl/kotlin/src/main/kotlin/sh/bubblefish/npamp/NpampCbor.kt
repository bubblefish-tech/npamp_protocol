// Open reference implementation of the N-PAMP native-channel body codec
// (draft-bubblefish-npamp-01). OPEN protocol layer only: the deterministic
// (canonical) CBOR subset that every native operation channel (NPAMP-MEMORY,
// -STREAM, -CAP, -IMMUNE, -SETTLEMENT, -TELEMETRY, -COMMERCE, -INTERACT,
// -WORKFLOW, -KNOWLEDGE) encodes its bodies in. No proprietary methods.
//
// A straight port of the Go reference codec impl/go/memory_cbor.go
// (spec/companion/81_memory_channel.md §4; RFC 8949 §4.2.1 core-deterministic) and
// its TypeScript counterpart impl/typescript/src/npamp_cbor.ts. It implements
// exactly the subset the native bodies use -- unsigned integers, negative integers,
// byte strings, text strings, arrays, maps, and the simple values false/true/null
// -- all definite-length, shortest-form, with map keys in canonical order. It is
// deliberately NOT a general CBOR library: on decode it REJECTS anything outside
// this subset (indefinite lengths, non-shortest integer/length encodings, tags,
// floats, other simple values, and out-of-order or duplicate map keys), which is
// precisely what a deterministic-encoding receiver MUST reject.
//
// Decoded value types (mirroring the Go uint64/int64/[]byte/string/[]any/*cborMap/
// bool/nil): integers decode to java.math.BigInteger (major 0 -> a non-negative
// BigInteger; major 1 -> a negative BigInteger), byte strings to ByteArray, text
// strings to String, arrays to List<Any?>, maps to CborMap, and the three simple
// values to Boolean / null.
package sh.bubblefish.npamp

import java.math.BigInteger

/** A structural fault in the deterministic-CBOR encoding (a MUST-reject). */
class CborException(message: String) : RuntimeException(message)

/** Deterministic (canonical) CBOR decoder for the N-PAMP native operation bodies. */
object NpampCbor {

    /** One decoded map entry: canonical key encoding (for ordering), the key, the value. */
    internal class Entry(val keyEnc: ByteArray, val key: Any?, val value: Any?)

    /**
     * A CBOR map preserving canonical key order. Keys are themselves CBOR values
     * (here always BigInteger/String/ByteArray); entries are kept in the order they
     * were decoded, which the decoder has already verified is canonical ascending.
     */
    class CborMap internal constructor(private val entries: List<Entry>) {

        /**
         * Returns the value for an unsigned-integer key, or null if absent. A present
         * CBOR null value is also returned as null; callers that must distinguish an
         * absent key from a present null value call [has] first.
         */
        fun get(key: Long): Any? {
            val k = BigInteger.valueOf(key)
            for (e in entries) {
                if (e.key is BigInteger && e.key == k) return e.value
            }
            return null
        }

        /** Reports whether an unsigned-integer key is present. */
        fun has(key: Long): Boolean {
            val k = BigInteger.valueOf(key)
            for (e in entries) {
                if (e.key is BigInteger && e.key == k) return true
            }
            return false
        }

        /** Returns every key in canonical order (used for forward-compat checks). */
        fun keys(): List<Any?> = entries.map { it.key }
    }

    // byteLess reports whether a sorts strictly before b in bytewise (shorter-prefix-
    // first, then lexicographic) order -- RFC 8949 §4.2.1 canonical map-key ordering.
    private fun byteLess(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return a.size < b.size
        for (i in a.indices) {
            val ai = a[i].toInt() and 0xff
            val bi = b[i].toInt() and 0xff
            if (ai != bi) return ai < bi
        }
        return false
    }

    /**
     * Decodes a single canonical CBOR item and requires that it consumes all of [b]
     * (no trailing bytes) -- the shape of a frame payload.
     */
    fun decodeTop(b: ByteArray): Any? {
        val d = Dec(b)
        val v = d.item()
        if (d.pos != b.size) throw CborException("npamp/cbor: trailing bytes after top-level item")
        return v
    }

    // toUnsigned converts a 64-bit argument (raw bits) into a non-negative BigInteger,
    // treating it as unsigned -- so a uint in [2^63, 2^64) is not mistaken for negative.
    private fun toUnsigned(v: Long): BigInteger =
        if (v >= 0) BigInteger.valueOf(v) else BigInteger.valueOf(v and Long.MAX_VALUE).setBit(63)

    /** Stateful single-pass decoder over a byte buffer. */
    private class Dec(val b: ByteArray) {
        var pos = 0

        fun item(): Any? {
            if (pos >= b.size) throw CborException("npamp/cbor: truncated input")
            val ib = b[pos].toInt() and 0xff
            val major = ib ushr 5
            val ai = ib and 0x1f

            if (major == 7) {
                // Only false(20)/true(21)/null(22) are in the deterministic subset;
                // floats (25/26/27), other simple values, and the break stop (31) reject.
                return when (ai) {
                    20 -> { pos += 1; false }
                    21 -> { pos += 1; true }
                    22 -> { pos += 1; null }
                    else -> throw CborException("npamp/cbor: unsupported major type or simple value")
                }
            }

            val argBits = decodeArg(ai) // advances pos past the header
            val n = pos // absolute offset just past the header

            return when (major) {
                0 -> toUnsigned(argBits) // unsigned int
                1 -> BigInteger.valueOf(-1).subtract(toUnsigned(argBits)) // negative int: -1 - arg
                2, 3 -> {
                    // byte string / text string
                    val remaining = b.size - n
                    if (java.lang.Long.compareUnsigned(argBits, remaining.toLong()) > 0) {
                        throw CborException("npamp/cbor: truncated input")
                    }
                    val len = argBits.toInt()
                    val payload = b.copyOfRange(n, n + len)
                    pos = n + len
                    if (major == 2) payload else String(payload, Charsets.UTF_8)
                }
                4 -> {
                    // array. Each element is >= 1 byte, so a declared count larger than the
                    // remaining input cannot be satisfied (huge-count DoS guard).
                    val remaining = b.size - n
                    if (java.lang.Long.compareUnsigned(argBits, remaining.toLong()) > 0) {
                        throw CborException("npamp/cbor: truncated input")
                    }
                    val count = argBits.toInt()
                    val out = ArrayList<Any?>(count)
                    repeat(count) { out.add(item()) }
                    out
                }
                5 -> {
                    // map. Each entry is >= 2 bytes, so a declared count larger than the
                    // remaining input cannot be satisfied.
                    val remaining = b.size - n
                    if (java.lang.Long.compareUnsigned(argBits, remaining.toLong()) > 0) {
                        throw CborException("npamp/cbor: truncated input")
                    }
                    val count = argBits.toInt()
                    val entries = ArrayList<Entry>(count)
                    var prevKeyEnc: ByteArray? = null
                    repeat(count) {
                        val keyStart = pos
                        val key = item()
                        val keyEnc = b.copyOfRange(keyStart, pos)
                        // Canonical order: each key MUST sort strictly after the previous one.
                        val prev = prevKeyEnc
                        if (prev != null && !byteLess(prev, keyEnc)) {
                            throw CborException(
                                "npamp/cbor: map keys not in canonical ascending order (or duplicate)"
                            )
                        }
                        prevKeyEnc = keyEnc
                        val value = item()
                        entries.add(Entry(keyEnc, key, value))
                    }
                    CborMap(entries)
                }
                else -> throw CborException("npamp/cbor: unsupported major type or simple value") // major 6: tags
            }
        }

        // decodeArg reads the argument for an additional-information value ai, enforcing
        // shortest-form (RFC 8949 §4.2.1) and rejecting indefinite lengths. Advances pos
        // past the whole header and returns the argument bits.
        private fun decodeArg(ai: Int): Long {
            if (ai < 24) {
                pos += 1
                return ai.toLong()
            }
            when (ai) {
                24 -> {
                    if (pos + 2 > b.size) throw CborException("npamp/cbor: truncated input")
                    val v = (b[pos + 1].toLong() and 0xff)
                    if (v < 24) throw CborException("npamp/cbor: integer/length not in shortest form")
                    pos += 2
                    return v
                }
                25 -> {
                    if (pos + 3 > b.size) throw CborException("npamp/cbor: truncated input")
                    val v = ((b[pos + 1].toLong() and 0xff) shl 8) or (b[pos + 2].toLong() and 0xff)
                    if (v < (1L shl 8)) throw CborException("npamp/cbor: integer/length not in shortest form")
                    pos += 3
                    return v
                }
                26 -> {
                    if (pos + 5 > b.size) throw CborException("npamp/cbor: truncated input")
                    var v = 0L
                    for (i in 1..4) v = (v shl 8) or (b[pos + i].toLong() and 0xff)
                    if (v < (1L shl 16)) throw CborException("npamp/cbor: integer/length not in shortest form")
                    pos += 5
                    return v
                }
                27 -> {
                    if (pos + 9 > b.size) throw CborException("npamp/cbor: truncated input")
                    var v = 0L
                    for (i in 1..8) v = (v shl 8) or (b[pos + i].toLong() and 0xff)
                    // shortest-form: an 8-byte argument must be >= 2^32 (unsigned compare).
                    if (java.lang.Long.compareUnsigned(v, 1L shl 32) < 0) {
                        throw CborException("npamp/cbor: integer/length not in shortest form")
                    }
                    pos += 9
                    return v
                }
                31 -> throw CborException("npamp/cbor: indefinite-length item (non-deterministic)")
                else -> throw CborException("npamp/cbor: unsupported major type or simple value") // 28,29,30 reserved
            }
        }
    }
}
