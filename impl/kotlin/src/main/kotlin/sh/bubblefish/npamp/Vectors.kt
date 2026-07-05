// Test-vector generator for the N-PAMP wire format (draft-bubblefish-npamp-00).
// Prints the four canonical OPEN-layer vectors as JSON on stdout.
package sh.bubblefish.npamp

import java.io.PrintStream
import java.nio.charset.StandardCharsets

/** Emits the canonical draft-00 OPEN-layer test vectors as a fixed JSON document. */
object Vectors {

    /** Returns bytes [start, start+1, ..., start+count-1] truncated to 8 bits. */
    private fun ramp(start: Int, count: Int): ByteArray {
        val b = ByteArray(count)
        for (i in 0 until count) {
            b[i] = (start + i).toByte()
        }
        return b
    }

    /** Returns a buffer of [count] octets all equal to [value]. */
    private fun fill(value: Int, count: Int): ByteArray {
        val b = ByteArray(count)
        java.util.Arrays.fill(b, value.toByte())
        return b
    }

    fun render(): String {
        // 1) header = Frame{PING, Control, seq=0, no payload}.marshal()
        val f1 = Npamp.Frame(Npamp.FRAME_PING, Npamp.CHAN_CONTROL)
        val header = Npamp.toHex(f1.marshal())

        // 2) nonce = deriveNonce(iv=[01..0C], seq=0x0102030405060708)
        val iv2 = ramp(0x01, 12) // 01 02 ... 0C
        val nonce = Npamp.toHex(Npamp.deriveNonce(iv2, 0x0102030405060708L))

        // 3) aead = sealAes256Gcm(key=[00..1F], iv=[10..1B], seq=7,
        //          aad=Frame{PING,Control}.headerPrefix(11), plaintext="hello world")
        val key3 = ramp(0x00, 32) // 00 01 ... 1F
        val iv3 = ramp(0x10, 12)  // 10 11 ... 1B
        val aad3 = Npamp.Frame(Npamp.FRAME_PING, Npamp.CHAN_CONTROL).headerPrefix(11)
        val pt3 = "hello world".toByteArray(StandardCharsets.US_ASCII)
        val aead = Npamp.toHex(Npamp.sealAes256Gcm(key3, iv3, 7L, aad3, pt3))

        // 4) traffic = deriveKeyIv(deriveTrafficSecret(master=48*0x2A, dir=0, epoch=0,
        //          suite=AES-256-GCM, channel=Control, standard=false), standard=false)[key]
        val master = fill(0x2A, 48)
        val secret = Npamp.deriveTrafficSecret(
            master, 0, 0L,
            Npamp.AEAD_AES256_GCM, Npamp.CHAN_CONTROL, false,
        )
        val trafficKey = Npamp.deriveKeyIv(secret, false)[0]
        val traffic = Npamp.toHex(trafficKey)

        val sb = StringBuilder()
        sb.append("{\n")
        sb.append("  \"spec\": \"draft-bubblefish-npamp-00\",\n")
        sb.append("  \"header_ping_control_seq0\": \"").append(header).append("\",\n")
        sb.append("  \"nonce_iv1to12_seq0102\": \"").append(nonce).append("\",\n")
        sb.append("  \"aes256gcm_seal_helloworld\": \"").append(aead).append("\",\n")
        sb.append("  \"traffic_key_sha384\": \"").append(traffic).append("\"\n")
        sb.append("}\n")
        return sb.toString()
    }

    @JvmStatic
    fun main(args: Array<String>) {
        // Force LF line endings regardless of platform default.
        val out = PrintStream(System.out, true, StandardCharsets.UTF_8)
        out.print(render())
    }
}
