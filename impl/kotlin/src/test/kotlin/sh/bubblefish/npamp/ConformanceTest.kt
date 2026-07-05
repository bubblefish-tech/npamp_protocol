// Conformance test for the N-PAMP Kotlin reference (draft-bubblefish-npamp-00).
// Dependency-free; mirrors the Java/Rust/Go suites: 4 golden vectors + 5 property
// tests. Exits 0 on success, 1 if any assertion fails.
package sh.bubblefish.npamp

import java.nio.charset.StandardCharsets
import kotlin.system.exitProcess

object ConformanceTest {

    private var failures = 0

    private fun check(name: String, ok: Boolean) {
        if (ok) {
            println("ok   - $name")
        } else {
            println("FAIL - $name")
            failures++
        }
    }

    private fun ramp(start: Int, count: Int): ByteArray {
        val b = ByteArray(count)
        for (i in 0 until count) {
            b[i] = (start + i).toByte()
        }
        return b
    }

    // --- cross-language vector reproduction (values from the Go reference) ---

    private fun vecHeader() {
        val f = Npamp.Frame(Npamp.FRAME_PING, Npamp.CHAN_CONTROL)
        check(
            "vec_header",
            Npamp.toHex(f.marshal()) ==
                "4e50414d20000100000000000000000000000000000d880c250000000000000000000000",
        )
    }

    private fun vecNonce() {
        val iv = ramp(0x01, 12)
        check(
            "vec_nonce",
            Npamp.toHex(Npamp.deriveNonce(iv, 0x0102030405060708L)) == "010203040404040c0c0c0c04",
        )
    }

    private fun vecAead() {
        val key = ramp(0x00, 32)
        val iv = ramp(0x10, 12)
        val aad = Npamp.Frame(Npamp.FRAME_PING, Npamp.CHAN_CONTROL).headerPrefix(11)
        val sealed = Npamp.sealAes256Gcm(key, iv, 7L, aad, "hello world".toByteArray(StandardCharsets.US_ASCII))
        check(
            "vec_aead",
            Npamp.toHex(sealed) == "3fe8b79f95b5697926b3395429c2c2466999c652f9346aeebb30bf",
        )
    }

    private fun vecTrafficKey() {
        val master = ByteArray(48)
        java.util.Arrays.fill(master, 0x2A.toByte())
        val ts = Npamp.deriveTrafficSecret(master, 0, 0L, Npamp.AEAD_AES256_GCM, Npamp.CHAN_CONTROL, false)
        val tk = Npamp.deriveKeyIv(ts, false)[0]
        check(
            "vec_traffic_key",
            Npamp.toHex(tk) == "79372e2fb7f92d63e3a68099ff72514f310ebf6773deb0fa7ef45d013c652dcc",
        )
    }

    // --- property tests (mirror the Go/Rust suites) ---

    private fun roundtrip() {
        val f = Npamp.Frame(
            0x0100, Npamp.CHAN_MEMORY, 42L, Npamp.FLAG_ENC, 0,
            "payload".toByteArray(StandardCharsets.US_ASCII),
        )
        val g = Npamp.Frame.unmarshal(f.marshal())
        check(
            "roundtrip",
            g.flags == Npamp.FLAG_ENC && g.ftype == 0x0100 && g.channel == Npamp.CHAN_MEMORY &&
                g.seq == 42L && String(g.payload, StandardCharsets.US_ASCII) == "payload",
        )
    }

    private fun crcValidatedFirst() {
        val buf = Npamp.Frame(Npamp.FRAME_PING, Npamp.CHAN_CONTROL).marshal()
        buf[5] = (buf[5].toInt() xor 0xFF).toByte() // corrupt the frame-type byte; CRC must reject first
        var rejected = false
        try {
            Npamp.Frame.unmarshal(buf)
        } catch (e: Npamp.FrameException) {
            rejected = e.message == "bad crc"
        }
        check("crc_validated_first", rejected)
    }

    private fun reservedMustBeZero() {
        val buf = Npamp.Frame(Npamp.FRAME_PING, Npamp.CHAN_CONTROL).marshal()
        buf[30] = 1 // a reserved octet
        var rejected = false
        try {
            Npamp.Frame.unmarshal(buf)
        } catch (e: Npamp.FrameException) {
            rejected = e.message == "bad crc" || e.message == "reserved nonzero"
        }
        check("reserved_must_be_zero", rejected)
    }

    private fun aeadTamperFails() {
        val key = ByteArray(32)
        val iv = ramp(0x10, 12)
        val aad = Npamp.Frame(Npamp.FRAME_PING, Npamp.CHAN_CONTROL).headerPrefix(5)
        val sealed = Npamp.sealAes256Gcm(key, iv, 7L, aad, "hello".toByteArray(StandardCharsets.US_ASCII))
        val openOk = String(Npamp.openAes256Gcm(key, iv, 7L, aad, sealed), StandardCharsets.US_ASCII) == "hello"
        aad[5] = (aad[5].toInt() xor 1).toByte()
        var tamperRejected = false
        try {
            Npamp.openAes256Gcm(key, iv, 7L, aad, sealed)
        } catch (e: RuntimeException) {
            tamperRejected = true
        }
        check("aead_tamper_fails", openOk && tamperRejected)
    }

    private fun hkdfPrefixProtocolSpecific() {
        check(
            "hkdf_prefix_protocol_specific",
            Npamp.LABEL_PREFIX == "n-pamp " && Npamp.LABEL_PREFIX != "tls13 ",
        )
    }

    @JvmStatic
    fun main(args: Array<String>) {
        vecHeader()
        vecNonce()
        vecAead()
        vecTrafficKey()
        roundtrip()
        crcValidatedFirst()
        reservedMustBeZero()
        aeadTamperFails()
        hkdfPrefixProtocolSpecific()
        println(if (failures == 0) "ALL PASS (9/9)" else "FAILURES: $failures")
        exitProcess(if (failures == 0) 0 else 1)
    }
}
