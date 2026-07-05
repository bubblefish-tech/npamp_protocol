// Runnable example: the draft-00 secure record layer, end to end.
//
// Composes the OPEN-protocol primitives this port provides — the HKDF key schedule, the
// AES-256-GCM record layer, and the 36-octet frame codec — into one send -> receive round-trip
// over an in-memory "wire". Mirrors the Go reference's Example_secureRecordLayer
// (impl/go/example_test.go).
//
// The master secret is a fixed demo value; in a live session it is the handshake output (binding
// spec/10 section 5). Standard profile only (SHA-256, AES-256-GCM). Compile and run from
// impl/kotlin:
//
//   kotlinc src/main/kotlin/sh/bubblefish/npamp/Npamp.kt examples/SecureRecordLayer.kt \
//       -include-runtime -d secure-record-layer.jar
//   java -jar secure-record-layer.jar

import sh.bubblefish.npamp.Npamp

/** Direction octet (draft-00 7.5): client-to-server = 0. */
const val DIR_CLIENT_TO_SERVER = 0

fun main() {
    // 1. Key schedule: derive a per-(direction, channel, suite) traffic key + IV from the master
    //    secret. In a live session the master secret is the handshake output; here it is fixed.
    val master = ByteArray(32) { 0x2B.toByte() }
    val ts = Npamp.deriveTrafficSecret(master, DIR_CLIENT_TO_SERVER, 0L, Npamp.AEAD_AES256_GCM, Npamp.CHAN_MEMORY, true)
    val keyIv = Npamp.deriveKeyIv(ts, true)
    val key = keyIv[0]
    val iv = keyIv[1]

    // 2. Sender: seal an application payload into an AEAD-protected frame on the Memory channel.
    //    The AEAD associated data is the 21-octet header prefix, so the ciphertext is bound to
    //    the frame's type/channel/seq/length — a tampered header makes the open fail.
    val appType = 0x0120 // application frame type (app-defined; this port is wire-only)
    val plaintext = "hello over n-pamp".toByteArray(Charsets.UTF_8)
    val seq = 0L
    val out = Npamp.Frame(ftype = appType, channel = Npamp.CHAN_MEMORY, seq = seq, flags = Npamp.FLAG_ENC)
    val aad = out.headerPrefix((plaintext.size + 16).toLong()) // +16 = AES-256-GCM authentication tag
    out.payload = Npamp.sealAes256Gcm(key, iv, seq, aad, plaintext)
    val wire = out.marshal()

    // 3. ... the `wire` bytes travel over any transport (the consumer supplies TCP/TLS) ...

    // 4. Receiver: parse the frame (validates CRC32C/magic/version) and open the payload under
    //    the same key/seq and the reconstructed header-prefix AAD.
    val inc = Npamp.Frame.unmarshal(wire)
    val raad = inc.headerPrefix(inc.payload.size.toLong())
    val opened = Npamp.openAes256Gcm(key, iv, inc.seq, raad, inc.payload)

    println("channel=${inc.channel} seq=${inc.seq} encrypted=${(inc.flags and Npamp.FLAG_ENC) != 0}")
    println("recovered: ${String(opened, Charsets.UTF_8)}")
    check(opened.contentEquals(plaintext)) { "roundtrip mismatch" }
}
