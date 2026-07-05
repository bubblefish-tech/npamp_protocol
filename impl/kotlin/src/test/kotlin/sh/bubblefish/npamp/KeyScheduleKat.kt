// Standards-derived, NON-CIRCULAR known-answer test for the draft-00 key schedule
// (binding spec/10 §5; draft-00 §7.4 HKDF-Expand-Label + §7.5 traffic keys). Kotlin mirror
// of the Go/TS/Python reference tests against the SAME pinned vector
// (test-vectors/v1/key-schedule-kat.json), which stores ONLY external RFC anchors and fixed
// inputs — never N-PAMP output bytes (those would be circular).
//
// Three legs: ANCHOR (raw HKDF-Extract/Expand reproduce RFC 5869 TC1 prk/okm), ORACLE (an
// independent in-test HKDF-Expand-Label that rebuilds the HkdfLabel bytes itself, with the
// prefix as a parameter, validated against RFC 8448 using the "tls13 " prefix), IMPL (the new
// Npamp handshake-secret ladder + finished_key + the existing traffic key/iv, each compared to
// the proven ORACLE applied with the "n-pamp " prefix). The oracle never calls the impl's
// HKDF-Expand-Label, so the two must independently agree.
package sh.bubblefish.npamp

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.system.exitProcess

object KeyScheduleKat {

    private const val PIN = "e108f5cfdf99a378d7b677792448c8046abf3c630fc23fd8ea2ccb3927f2691c"

    // AES-256-GCM = 0x0001 per registries/aead.csv (= the impl's AEAD_AES256_GCM =
    // npamp.AEADAES256GCM in the Go reference); 0x0002 is ChaCha20-Poly1305. The §7.5 traffic
    // context binds this AEAD code point.
    private const val SUITE_AES256_GCM: Int = Npamp.AEAD_AES256_GCM

    // Traffic directions (binding §5.4): ServerToClient = 1.
    private const val DIR_SERVER_TO_CLIENT: Int = 1

    private var failures = 0

    private fun leg(name: String, fn: () -> Unit) {
        try {
            fn()
            println("PASS $name")
        } catch (e: Throwable) {
            println("FAIL $name: ${e.message}")
            failures++
        }
    }

    // -- Independent in-test oracle (re-derives the spec; never calls the impl) -------------

    /** Standard HMAC-SHA-256, the only MAC this Standard-profile vector needs. */
    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        // SecretKeySpec rejects an empty key; every salt/secret used here is non-empty.
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    /** HKDF-Extract (RFC 5869 §2.2), independent of Npamp.hkdfExtract. */
    private fun extractOracle(salt: ByteArray, ikm: ByteArray): ByteArray = hmacSha256(salt, ikm)

    /** Raw HKDF-Expand (RFC 5869 §2.3), independent of the impl. */
    private fun expandOracle(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        val out = ByteArrayOutputStream()
        var t = ByteArray(0)
        var i = 1
        while (out.size() < length) {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update(t)
            mac.update(info)
            mac.update(i.toByte())
            t = mac.doFinal()
            out.write(t, 0, t.size)
            i++
        }
        return out.toByteArray().copyOf(length)
    }

    /**
     * Independent HKDF-Expand-Label (RFC 8446 §7.1) with the prefix as a PARAMETER: it rebuilds
     * HkdfLabel = uint16(length) || uint8(len(prefix+label)) || prefix+label || uint8(len(context))
     * || context straight from the spec, then calls the in-test raw expand. It does NOT call
     * Npamp.hkdfExpandLabel — so when the impl is judged against it, agreement is independent.
     */
    private fun expandLabelOracle(secret: ByteArray, prefix: String, label: String, context: ByteArray, length: Int): ByteArray {
        val full = (prefix + label).toByteArray(StandardCharsets.US_ASCII)
        val info = ByteArrayOutputStream()
        info.write((length ushr 8) and 0xFF)
        info.write(length and 0xFF)
        info.write(full.size and 0xFF)
        info.write(full, 0, full.size)
        info.write(context.size and 0xFF)
        info.write(context, 0, context.size)
        return expandOracle(secret, info.toByteArray(), length)
    }

    /** Traffic-secret context (binding §5.4): dir(1) || epoch(8 BE) || suite(2 BE) || channel(2 BE). */
    private fun trafficContext(dir: Int, epoch: Long, suite: Int, channel: Int): ByteArray {
        val out = ByteArray(1 + 8 + 2 + 2)
        out[0] = (dir and 0xFF).toByte()
        for (j in 0 until 8) {
            out[1 + j] = ((epoch ushr (56 - 8 * j)) and 0xFF).toByte()
        }
        out[9] = ((suite ushr 8) and 0xFF).toByte()
        out[10] = (suite and 0xFF).toByte()
        out[11] = ((channel ushr 8) and 0xFF).toByte()
        out[12] = (channel and 0xFF).toByte()
        return out
    }

    private val EMPTY = ByteArray(0)

    @JvmStatic
    fun main(args: Array<String>) {
        val k = KatSupport.loadPinned(args, "key-schedule-kat.json", PIN)

        // (B) ANCHOR — raw HKDF-Extract/Expand reproduce RFC 5869 TC1.
        leg("key_schedule_kat_rfc5869_anchor") {
            val tc = KatSupport.obj(k, "rfc5869_tc1")
            val salt = KatSupport.fromHex(tc["salt"] as String)
            val ikm = KatSupport.fromHex(tc["ikm"] as String)
            val info = KatSupport.fromHex(tc["info"] as String)
            val length = (tc["L"] as Long).toInt()
            val prkHex = tc["prk"] as String
            val okmHex = tc["okm"] as String

            // impl HKDF-Extract is RFC-5869-anchored.
            val implPrk = KatSupport.toHex(Npamp.hkdfExtract(salt, ikm, true))
            check(implPrk == prkHex) { "Npamp.hkdfExtract != RFC 5869 prk\n  got  $implPrk\n  want $prkHex" }
            // in-test oracle extract is RFC-5869-anchored.
            val oraclePrk = KatSupport.toHex(extractOracle(salt, ikm))
            check(oraclePrk == prkHex) { "extractOracle != RFC 5869 prk\n  got  $oraclePrk\n  want $prkHex" }
            // in-test oracle raw expand is RFC-5869-anchored.
            val oracleOkm = KatSupport.toHex(expandOracle(KatSupport.fromHex(prkHex), info, length))
            check(oracleOkm == okmHex) { "expandOracle != RFC 5869 okm\n  got  $oracleOkm\n  want $okmHex" }
        }

        // (C) ORACLE — the independent Expand-Label reproduces RFC 8448 with the "tls13 " prefix.
        leg("key_schedule_kat_rfc8448_oracle") {
            val r = KatSupport.obj(k, "rfc8448_expand_label")
            val secret = KatSupport.fromHex(r["client_handshake_traffic_secret"] as String)
            val gotKey = KatSupport.toHex(expandLabelOracle(secret, "tls13 ", "key", EMPTY, 16))
            check(gotKey == r["write_key"]) { "oracle expandLabel(key) != RFC 8448\n  got  $gotKey\n  want ${r["write_key"]}" }
            val gotIv = KatSupport.toHex(expandLabelOracle(secret, "tls13 ", "iv", EMPTY, 12))
            check(gotIv == r["write_iv"]) { "oracle expandLabel(iv) != RFC 8448\n  got  $gotIv\n  want ${r["write_iv"]}" }
            val gotFin = KatSupport.toHex(expandLabelOracle(secret, "tls13 ", "finished", EMPTY, 32))
            check(gotFin == r["finished_key"]) { "oracle expandLabel(finished) != RFC 8448\n  got  $gotFin\n  want ${r["finished_key"]}" }
        }

        // (D) IMPL — the new ladder + finished_key + existing traffic key/iv match the proven oracle.
        leg("key_schedule_kat_impl") {
            check(Npamp.LABEL_PREFIX == "n-pamp ") { "Npamp.LABEL_PREFIX drifted from the spec's \"n-pamp \" prefix" }
            val nn = KatSupport.obj(k, "npamp_inputs")
            val mlkem = KatSupport.fromHex(nn["ikm_mlkem_ss"] as String)
            val x25519 = KatSupport.fromHex(nn["ikm_x25519_ss"] as String)
            val thKem = KatSupport.fromHex(nn["th_kem"] as String)
            val thCcv = KatSupport.fromHex(nn["th_ccv"] as String)
            val zeros32 = ByteArray(32)

            // handshake_secret = HKDF-Extract(32 zero octets, ML-KEM_SS || X25519_SS).
            val hs = Npamp.deriveHandshakeSecret(mlkem, x25519, true)
            val ikm = ByteArray(mlkem.size + x25519.size)
            System.arraycopy(mlkem, 0, ikm, 0, mlkem.size)
            System.arraycopy(x25519, 0, ikm, mlkem.size, x25519.size)
            val hsWant = KatSupport.toHex(extractOracle(zeros32, ikm))
            val hsGot = KatSupport.toHex(hs)
            check(hsGot == hsWant) { "handshake_secret != oracle\n  got  $hsGot\n  want $hsWant" }

            // c_hs / s_hs / master.
            val cHs = Npamp.deriveClientHandshakeSecret(hs, thKem, true)
            val cHsWant = KatSupport.toHex(expandLabelOracle(hs, "n-pamp ", "c hs", thKem, 32))
            check(KatSupport.toHex(cHs) == cHsWant) { "c_hs != oracle\n  got  ${KatSupport.toHex(cHs)}\n  want $cHsWant" }

            val sHs = Npamp.deriveServerHandshakeSecret(hs, thKem, true)
            val sHsWant = KatSupport.toHex(expandLabelOracle(hs, "n-pamp ", "s hs", thKem, 32))
            check(KatSupport.toHex(sHs) == sHsWant) { "s_hs != oracle\n  got  ${KatSupport.toHex(sHs)}\n  want $sHsWant" }

            val master = Npamp.deriveMasterSecret(hs, thCcv, true)
            val masterWant = KatSupport.toHex(expandLabelOracle(hs, "n-pamp ", "master", thCcv, 32))
            check(KatSupport.toHex(master) == masterWant) { "master != oracle\n  got  ${KatSupport.toHex(master)}\n  want $masterWant" }

            // finished_key: client derives from c_hs, server from s_hs.
            val fkClient = Npamp.deriveFinishedKey(cHs, true)
            val fkClientWant = KatSupport.toHex(expandLabelOracle(cHs, "n-pamp ", "finished", EMPTY, 32))
            check(KatSupport.toHex(fkClient) == fkClientWant) { "finished_key(c_hs) != oracle\n  got  ${KatSupport.toHex(fkClient)}\n  want $fkClientWant" }

            val fkServer = Npamp.deriveFinishedKey(sHs, true)
            val fkServerWant = KatSupport.toHex(expandLabelOracle(sHs, "n-pamp ", "finished", EMPTY, 32))
            check(KatSupport.toHex(fkServer) == fkServerWant) { "finished_key(s_hs) != oracle\n  got  ${KatSupport.toHex(fkServer)}\n  want $fkServerWant" }

            // s2c handshake AEAD via the existing derive_traffic_secret / derive_key_iv from s_hs:
            // dir=ServerToClient(1), epoch=0, suite=AES-256-GCM(0x0001), channel=Control(0x0000).
            val traffic = Npamp.deriveTrafficSecret(sHs, DIR_SERVER_TO_CLIENT, 0L, SUITE_AES256_GCM, Npamp.CHAN_CONTROL, true)
            val keyIv = Npamp.deriveKeyIv(traffic, true)
            val key = keyIv[0]
            val iv = keyIv[1]

            val ctx = trafficContext(DIR_SERVER_TO_CLIENT, 0L, SUITE_AES256_GCM, Npamp.CHAN_CONTROL)
            val oracleTraffic = expandLabelOracle(sHs, "n-pamp ", "traffic", ctx, 32)
            val keyWant = KatSupport.toHex(expandLabelOracle(oracleTraffic, "n-pamp ", "key", EMPTY, 32))
            val ivWant = KatSupport.toHex(expandLabelOracle(oracleTraffic, "n-pamp ", "iv", EMPTY, 12))
            check(KatSupport.toHex(key) == keyWant) { "s2c handshake key != oracle\n  got  ${KatSupport.toHex(key)}\n  want $keyWant" }
            check(KatSupport.toHex(iv) == ivWant) { "s2c handshake iv != oracle\n  got  ${KatSupport.toHex(iv)}\n  want $ivWant" }
        }

        println(if (failures == 0) "ALL PASS (3/3)" else "FAILURES: $failures")
        exitProcess(if (failures == 0) 0 else 1)
    }
}
