// Shared, dependency-free support for the draft-00 handshake KATs: a minimal
// recursive-descent JSON parser, hex helpers, and a SHA-256-pinned vector loader.
// JDK ships no JSON parser, so the parser below is self-contained (no new dependency).
package sh.bubblefish.npamp

import java.math.BigInteger
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.security.MessageDigest

object KatSupport {

    // -- Hex ---------------------------------------------------------------

    /** Decodes a lowercase/uppercase hex string into bytes; "" -> empty array. */
    fun fromHex(s: String): ByteArray {
        val n = s.length
        require(n and 1 == 0) { "odd-length hex: $s" }
        val out = ByteArray(n / 2)
        var i = 0
        while (i < n) {
            val hi = Character.digit(s[i], 16)
            val lo = Character.digit(s[i + 1], 16)
            require(hi >= 0 && lo >= 0) { "bad hex: $s" }
            out[i / 2] = ((hi shl 4) or lo).toByte()
            i += 2
        }
        return out
    }

    /** Lowercase hex encoding. */
    fun toHex(data: ByteArray): String {
        val sb = StringBuilder(data.size * 2)
        for (b in data) {
            sb.append(Character.forDigit((b.toInt() ushr 4) and 0xF, 16))
            sb.append(Character.forDigit(b.toInt() and 0xF, 16))
        }
        return sb.toString()
    }

    /** Strips a leading "0x"/"0X" prefix. */
    fun trimHexPrefix(s: String): String =
        if (s.length >= 2 && (s.substring(0, 2) == "0x" || s.substring(0, 2) == "0X")) s.substring(2) else s

    /** Parses a (possibly 0x-prefixed) hex integer into an Int. */
    fun parseHexInt(s: String): Int = BigInteger(trimHexPrefix(s), 16).toInt()

    // -- Vector resolution + SHA-256 pin -----------------------------------

    /**
     * Resolves the test-vectors/v1 directory. Order: args[0] if given, then an
     * upward walk from the CWD for a `test-vectors/v1` directory, then the canonical
     * relative path `../../../test-vectors/v1` (relative to impl/<lang>/test).
     */
    fun vectorsDir(args: Array<String>): Path {
        if (args.isNotEmpty()) {
            return Paths.get(args[0])
        }
        var dir: Path? = Paths.get(System.getProperty("user.dir")).toAbsolutePath()
        while (dir != null) {
            val cand = dir.resolve("test-vectors").resolve("v1")
            if (Files.isDirectory(cand)) {
                return cand
            }
            dir = dir.parent
        }
        return Paths.get("..", "..", "..", "test-vectors", "v1")
    }

    /**
     * Reads the named vector file's raw bytes, fails loud unless its SHA-256 equals
     * [pinHex] (catches a swapped vector), then returns it parsed as JSON.
     */
    fun loadPinned(args: Array<String>, fileName: String, pinHex: String): Map<String, Any?> {
        val path = vectorsDir(args).resolve(fileName)
        val raw = Files.readAllBytes(path)
        val got = toHex(MessageDigest.getInstance("SHA-256").digest(raw))
        check(got == pinHex) { "$fileName SHA-256 mismatch (swapped vector?):\n  got  $got\n  want $pinHex" }
        val parsed = Json.parse(String(raw, Charsets.UTF_8))
        @Suppress("UNCHECKED_CAST")
        return parsed as Map<String, Any?>
    }

    // -- Typed accessors over the parsed tree ------------------------------

    @Suppress("UNCHECKED_CAST")
    fun obj(node: Any?, key: String): Map<String, Any?> =
        (node as Map<String, Any?>)[key] as Map<String, Any?>

    @Suppress("UNCHECKED_CAST")
    fun arr(node: Any?, key: String): List<Any?> =
        (node as Map<String, Any?>)[key] as List<Any?>

    @Suppress("UNCHECKED_CAST")
    fun str(node: Any?, key: String): String =
        (node as Map<String, Any?>)[key] as String
}

/** Minimal recursive-descent JSON parser. Returns Map / List / String / Long / Double / Boolean / null. */
object Json {
    fun parse(text: String): Any? {
        val p = Parser(text)
        p.skipWs()
        val v = p.value()
        p.skipWs()
        return v
    }

    private class Parser(val s: String) {
        var i = 0

        fun skipWs() {
            while (i < s.length && s[i].isWhitespace()) i++
        }

        fun value(): Any? {
            skipWs()
            return when (s[i]) {
                '{' -> obj()
                '[' -> arr()
                '"' -> str()
                't' -> { expect("true"); true }
                'f' -> { expect("false"); false }
                'n' -> { expect("null"); null }
                else -> number()
            }
        }

        fun expect(w: String) {
            require(s.startsWith(w, i)) { "expected '$w' at offset $i" }
            i += w.length
        }

        fun obj(): LinkedHashMap<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            i++ // consume '{'
            skipWs()
            if (s[i] == '}') { i++; return m }
            while (true) {
                skipWs()
                val key = str()
                skipWs()
                require(s[i] == ':') { "expected ':' at offset $i" }
                i++
                m[key] = value()
                skipWs()
                when (s[i]) {
                    ',' -> { i++; continue }
                    '}' -> { i++; break }
                    else -> throw IllegalArgumentException("expected ',' or '}' at offset $i")
                }
            }
            return m
        }

        fun arr(): ArrayList<Any?> {
            val a = ArrayList<Any?>()
            i++ // consume '['
            skipWs()
            if (s[i] == ']') { i++; return a }
            while (true) {
                a.add(value())
                skipWs()
                when (s[i]) {
                    ',' -> { i++; continue }
                    ']' -> { i++; break }
                    else -> throw IllegalArgumentException("expected ',' or ']' at offset $i")
                }
            }
            return a
        }

        fun str(): String {
            require(s[i] == '"') { "expected '\"' at offset $i" }
            i++
            val sb = StringBuilder()
            while (s[i] != '"') {
                val c = s[i]
                if (c == '\\') {
                    i++
                    when (s[i]) {
                        '"' -> sb.append('"')
                        '\\' -> sb.append('\\')
                        '/' -> sb.append('/')
                        'b' -> sb.append('\b')
                        'f' -> sb.append('')
                        'n' -> sb.append('\n')
                        'r' -> sb.append('\r')
                        't' -> sb.append('\t')
                        'u' -> {
                            val hex = s.substring(i + 1, i + 5)
                            sb.append(hex.toInt(16).toChar())
                            i += 4
                        }
                        else -> throw IllegalArgumentException("bad escape at offset $i")
                    }
                    i++
                } else {
                    sb.append(c)
                    i++
                }
            }
            i++ // consume closing '"'
            return sb.toString()
        }

        fun number(): Any {
            val start = i
            while (i < s.length && (s[i].isDigit() || s[i] == '+' || s[i] == '-' ||
                    s[i] == '.' || s[i] == 'e' || s[i] == 'E')) {
                i++
            }
            val num = s.substring(start, i)
            return if (num.contains('.') || num.contains('e') || num.contains('E')) num.toDouble() else num.toLong()
        }
    }
}
