// N-PAMP conformance adapter (Kotlin). A "testee": it reads length-prefixed JSON
// requests {op,in} on stdin and writes length-prefixed JSON responses
// {out|error|skipped} on stdout, performing each op by CALLING the OPEN reference
// implementation in sh.bubblefish.npamp.Npamp (impl/kotlin). It is NOT a
// reimplementation: every primitive routes into the reference object's functions.
//
// Mapping of the contract op to the reference function it calls:
//   header.encode -> Npamp.Frame(...).marshal()
//   header.decode -> Npamp.Frame.unmarshal(...)
//   crc32c        -> Npamp.crc32c(...)
//   aead.seal     -> Npamp.sealAes256Gcm(key, iv=nonce, seq=0, aad, pt)
//   aead.open     -> Npamp.openAes256Gcm(key, iv=nonce, seq=0, aad, sealed)
//   hkdf.expand   -> Npamp.hkdfExpand(...)  (reference's private RFC-5869 Expand,
//                    reached via reflection so the REAL reference code runs)
//   tlv.decode    -> skipped: the reference exposes no TLV-decode function
//   profile.check -> skipped: the reference has no profile-acceptance logic
//
// aead nonce note: Npamp.sealAes256Gcm derives its GCM nonce as
//   deriveNonce(iv, seq) = iv XOR (seq as 12-byte BE in [4:12]).
// Passing the contract's raw `nonce` as `iv` with seq=0 yields deriveNonce(nonce, 0)
// == nonce, so the real reference AEAD runs with exactly the contract nonce.
//
// Windows note: uses the raw System.in / System.out byte streams (no Reader/Writer,
// no CRLF translation) and flushes after every response, or the byte framing corrupts.

package sh.bubblefish.npamp.adapter

import sh.bubblefish.npamp.Npamp
import java.io.DataInputStream
import java.io.EOFException

// ---- minimal hex ----------------------------------------------------------

private fun hexToBytes(s: String): ByteArray {
    val clean = s.trim()
    val out = ByteArray(clean.length / 2)
    var i = 0
    while (i < out.size) {
        out[i] = ((Character.digit(clean[2 * i], 16) shl 4) or
            Character.digit(clean[2 * i + 1], 16)).toByte()
        i++
    }
    return out
}

private fun bytesToHex(b: ByteArray): String {
    val sb = StringBuilder(b.size * 2)
    for (x in b) {
        sb.append("0123456789abcdef"[(x.toInt() ushr 4) and 0xF])
        sb.append("0123456789abcdef"[x.toInt() and 0xF])
    }
    return sb.toString()
}

// ---- minimal JSON ---------------------------------------------------------
// The contract's request/response shapes are a flat object whose values are
// strings, integers, or a nested "in" object of the same. A tiny recursive
// parser covers exactly that; it is not a general-purpose JSON library.

private class JsonParser(private val s: String) {
    private var p = 0

    fun parse(): Any? {
        skipWs()
        val v = parseValue()
        skipWs()
        return v
    }

    private fun skipWs() {
        while (p < s.length && s[p].isWhitespace()) p++
    }

    private fun parseValue(): Any? {
        skipWs()
        return when (s[p]) {
            '{' -> parseObject()
            '[' -> parseArray()
            '"' -> parseString()
            't' -> { expect("true"); true }
            'f' -> { expect("false"); false }
            'n' -> { expect("null"); null }
            else -> parseNumber()
        }
    }

    private fun expect(w: String) {
        require(s.regionMatches(p, w, 0, w.length)) { "expected $w at $p" }
        p += w.length
    }

    private fun parseObject(): LinkedHashMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        p++ // {
        skipWs()
        if (s[p] == '}') { p++; return m }
        while (true) {
            skipWs()
            val k = parseString()
            skipWs()
            require(s[p] == ':') { "expected : at $p" }
            p++
            val v = parseValue()
            m[k] = v
            skipWs()
            when (s[p]) {
                ',' -> { p++; continue }
                '}' -> { p++; break }
                else -> throw IllegalArgumentException("expected , or } at $p")
            }
        }
        return m
    }

    private fun parseArray(): ArrayList<Any?> {
        val a = ArrayList<Any?>()
        p++ // [
        skipWs()
        if (s[p] == ']') { p++; return a }
        while (true) {
            a.add(parseValue())
            skipWs()
            when (s[p]) {
                ',' -> { p++; continue }
                ']' -> { p++; break }
                else -> throw IllegalArgumentException("expected , or ] at $p")
            }
        }
        return a
    }

    private fun parseString(): String {
        require(s[p] == '"') { "expected string at $p" }
        p++
        val sb = StringBuilder()
        while (s[p] != '"') {
            val c = s[p]
            if (c == '\\') {
                p++
                when (s[p]) {
                    '"' -> sb.append('"')
                    '\\' -> sb.append('\\')
                    '/' -> sb.append('/')
                    'b' -> sb.append('\b')
                    'f' -> sb.append('\u000C')
                    'n' -> sb.append('\n')
                    'r' -> sb.append('\r')
                    't' -> sb.append('\t')
                    'u' -> {
                        val hex = s.substring(p + 1, p + 5)
                        sb.append(hex.toInt(16).toChar())
                        p += 4
                    }
                    else -> throw IllegalArgumentException("bad escape at $p")
                }
                p++
            } else {
                sb.append(c)
                p++
            }
        }
        p++ // closing quote
        return sb.toString()
    }

    private fun parseNumber(): Any {
        val start = p
        while (p < s.length && (s[p].isDigit() || s[p] == '-' || s[p] == '+' ||
                s[p] == '.' || s[p] == 'e' || s[p] == 'E')) p++
        val tok = s.substring(start, p)
        return if (tok.any { it == '.' || it == 'e' || it == 'E' }) tok.toDouble()
        else tok.toLong()
    }
}

private fun jsonEscape(s: String): String {
    val sb = StringBuilder(s.length + 2)
    for (c in s) {
        when (c) {
            '"' -> sb.append("\\\"")
            '\\' -> sb.append("\\\\")
            '\n' -> sb.append("\\n")
            '\r' -> sb.append("\\r")
            '\t' -> sb.append("\\t")
            else -> if (c < ' ') sb.append("\\u%04x".format(c.code)) else sb.append(c)
        }
    }
    return sb.toString()
}

private fun jsonValue(v: Any?): String = when (v) {
    null -> "null"
    is Boolean -> v.toString()
    is Int -> v.toString()
    is Long -> v.toString()
    is String -> "\"" + jsonEscape(v) + "\""
    is Map<*, *> -> jsonObject(v)
    else -> "\"" + jsonEscape(v.toString()) + "\""
}

private fun jsonObject(m: Map<*, *>): String {
    val sb = StringBuilder("{")
    var first = true
    for ((k, v) in m) {
        if (!first) sb.append(",")
        first = false
        sb.append("\"").append(jsonEscape(k.toString())).append("\":").append(jsonValue(v))
    }
    sb.append("}")
    return sb.toString()
}

// ---- field accessors ------------------------------------------------------

@Suppress("UNCHECKED_CAST")
private fun inputOf(req: Map<String, Any?>): Map<String, Any?> =
    (req["in"] as? Map<String, Any?>) ?: emptyMap()

private fun str(m: Map<String, Any?>, k: String): String = when (val v = m[k]) {
    is String -> v
    null -> ""
    else -> v.toString()
}

private fun int(m: Map<String, Any?>, k: String): Int = when (val v = m[k]) {
    is Long -> v.toInt()
    is Int -> v
    is Double -> v.toInt()
    is String -> v.toInt()
    else -> 0
}

private fun hx(m: Map<String, Any?>, k: String): ByteArray = hexToBytes(str(m, k))

// ---- reflection handle for the reference's private HKDF-Expand -------------
// Npamp is a Kotlin `object` (singleton); hkdfExpand is a private member. We
// reach the REAL reference function (not a copy) via reflection so the wired
// implementation is genuinely impl/kotlin's RFC-5869 Expand.

private val hkdfExpandMethod by lazy {
    val m = Npamp.javaClass.getDeclaredMethod(
        "hkdfExpand",
        String::class.java,
        ByteArray::class.java,
        ByteArray::class.java,
        Int::class.javaPrimitiveType,
    )
    m.isAccessible = true
    m
}

private fun callReferenceHkdfExpand(macAlg: String, prk: ByteArray, info: ByteArray, length: Int): ByteArray =
    hkdfExpandMethod.invoke(Npamp, macAlg, prk, info, length) as ByteArray

// ---- op dispatch ----------------------------------------------------------

private fun handle(req: Map<String, Any?>): Map<String, Any?> {
    val op = str(req, "op")
    val ins = inputOf(req)
    return when (op) {
        "header.encode" -> {
            // Build a Frame and let the reference marshal it. version=2 so the
            // reference writes (2<<4)|flags into octet 4 and the golden CRC.
            val f = Npamp.Frame(
                ftype = int(ins, "frameType"),
                channel = int(ins, "channel"),
                seq = int(ins, "seq").toLong(),
                flags = int(ins, "flags"),
                version = int(ins, "ver"),
                payload = ByteArray(int(ins, "payloadLength")),
            )
            mapOf("out" to mapOf("frame" to Npamp.toHex(f.marshal())))
        }

        "header.decode" -> {
            val frame = try {
                hx(ins, "frame")
            } catch (e: Exception) {
                return mapOf("error" to "bad hex")
            }
            try {
                val f = Npamp.Frame.unmarshal(frame)
                mapOf(
                    "out" to mapOf(
                        "magic" to "NPAM",
                        "ver" to f.version,
                        "flags" to f.flags,
                        "frameType" to f.ftype,
                        "channel" to f.channel,
                        "seq" to f.seq,
                        "payloadLength" to frame.size - Npamp.HEADER_SIZE,
                        "crc32c" to bytesToHex(frame.copyOfRange(21, 25)),
                        "reservedZero" to true,
                    ),
                )
            } catch (e: Npamp.FrameException) {
                mapOf("error" to (e.message ?: "frame rejected"))
            } catch (e: Exception) {
                mapOf("error" to (e.message ?: "frame rejected"))
            }
        }

        "crc32c" -> {
            val octets = try {
                hx(ins, "octets")
            } catch (e: Exception) {
                return mapOf("error" to "bad hex")
            }
            val crc = Npamp.crc32c(octets) // unsigned 32-bit in a Long
            val be = ByteArray(4)
            be[0] = ((crc ushr 24) and 0xFF).toByte()
            be[1] = ((crc ushr 16) and 0xFF).toByte()
            be[2] = ((crc ushr 8) and 0xFF).toByte()
            be[3] = (crc and 0xFF).toByte()
            mapOf("out" to mapOf("crc32c" to bytesToHex(be)))
        }

        "tlv.decode" ->
            // The OPEN reference (Npamp.kt) exposes no TLV-decode function, so this
            // op is honestly Unimplemented rather than reimplemented in the adapter.
            mapOf("skipped" to "tlv.decode not exposed by reference impl")

        "aead.seal" -> {
            if (str(ins, "suite") != "AES-256-GCM") {
                return mapOf("skipped" to "suite not implemented: " + str(ins, "suite"))
            }
            try {
                val key = hx(ins, "key")
                val nonce = hx(ins, "nonce")
                val aad = hx(ins, "aad")
                val pt = hx(ins, "pt")
                // iv=nonce, seq=0 => reference deriveNonce(nonce,0) == nonce
                val sealed = Npamp.sealAes256Gcm(key, nonce, 0L, aad, pt)
                mapOf("out" to mapOf("sealed" to bytesToHex(sealed)))
            } catch (e: Exception) {
                mapOf("error" to (e.message ?: "seal failed"))
            }
        }

        "aead.open" -> {
            if (str(ins, "suite") != "AES-256-GCM") {
                return mapOf("skipped" to "suite not implemented: " + str(ins, "suite"))
            }
            try {
                val key = hx(ins, "key")
                val nonce = hx(ins, "nonce")
                val aad = hx(ins, "aad")
                val sealed = hx(ins, "sealed")
                val pt = Npamp.openAes256Gcm(key, nonce, 0L, aad, sealed)
                mapOf("out" to mapOf("pt" to bytesToHex(pt)))
            } catch (e: Exception) {
                // tag mismatch / bad key -> rejection
                mapOf("error" to "authentication failed")
            }
        }

        "hkdf.expand" -> {
            val macAlg = when (str(ins, "hash")) {
                "sha256" -> "HmacSHA256"
                "sha384" -> "HmacSHA384"
                else -> return mapOf("skipped" to "hash not implemented: " + str(ins, "hash"))
            }
            try {
                val prk = hx(ins, "prk")
                val info = hx(ins, "info")
                val length = int(ins, "length")
                val okm = callReferenceHkdfExpand(macAlg, prk, info, length)
                mapOf("out" to mapOf("okm" to bytesToHex(okm)))
            } catch (e: Exception) {
                mapOf("error" to (e.message ?: "hkdf-expand failed"))
            }
        }

        "profile.check" ->
            // The OPEN reference has no profile KEM-acceptance logic; honestly
            // Unimplemented rather than reimplemented here.
            mapOf("skipped" to "profile.check not exposed by reference impl")

        else -> mapOf("skipped" to "op not implemented: $op")
    }
}

// ---- length-prefixed framing loop -----------------------------------------

private fun readLE32(din: DataInputStream): Int {
    val b0 = din.read()
    if (b0 < 0) throw EOFException()
    val b1 = din.read()
    val b2 = din.read()
    val b3 = din.read()
    if (b1 < 0 || b2 < 0 || b3 < 0) throw EOFException()
    return (b0 and 0xFF) or ((b1 and 0xFF) shl 8) or ((b2 and 0xFF) shl 16) or ((b3 and 0xFF) shl 24)
}

fun main() {
    val din = DataInputStream(System.`in`.buffered())
    val out = System.out
    while (true) {
        val n = try {
            readLE32(din)
        } catch (e: EOFException) {
            return // runner closed stdin
        }
        val body = ByteArray(n)
        try {
            din.readFully(body)
        } catch (e: EOFException) {
            return
        }
        val respMap: Map<String, Any?> = try {
            @Suppress("UNCHECKED_CAST")
            val req = JsonParser(String(body, Charsets.UTF_8)).parse() as Map<String, Any?>
            handle(req)
        } catch (e: Exception) {
            mapOf("error" to ("adapter exception: " + (e.message ?: e.toString())))
        }
        val ob = jsonObject(respMap).toByteArray(Charsets.UTF_8)
        val len = ob.size
        out.write(len and 0xFF)
        out.write((len ushr 8) and 0xFF)
        out.write((len ushr 16) and 0xFF)
        out.write((len ushr 24) and 0xFF)
        out.write(ob)
        out.flush()
    }
}
