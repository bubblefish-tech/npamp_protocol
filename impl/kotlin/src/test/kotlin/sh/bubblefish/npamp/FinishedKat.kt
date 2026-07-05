// Standards-derived, NON-CIRCULAR known-answer test for the draft-00 Finished
// verify_data (binding spec/10 §6.2; RFC 8446 §4.4.4): verify_data =
// HMAC(finished_key, transcript_hash) under the profile hash (SHA-256 at Standard).
// Kotlin mirror of the Go/TS/Python reference tests against the SAME pinned vector
// (test-vectors/v1/finished-kat.json).
//
// Three legs: ANCHOR (HMAC-SHA-256 reproduces RFC 4231 TC1/TC2), ORACLE (independent
// javax.crypto.Mac, no computeFinished), IMPL (computeFinished + verifyFinished accept/reject).
package sh.bubblefish.npamp

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.system.exitProcess

object FinishedKat {

    private const val PIN = "25c21b0bd3b3b6b77862f4a819f81ff5e4ff42e4b1d70af81feeedc5aad73c7f"

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

    /** Standard HMAC-SHA-256, independent of computeFinished. */
    private fun hmacOracle(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    @JvmStatic
    fun main(args: Array<String>) {
        val k = KatSupport.loadPinned(args, "finished-kat.json", PIN)
        val nn = KatSupport.obj(k, "npamp_inputs")
        val e = KatSupport.obj(k, "expected")

        leg("finished_kat_rfc4231_anchor") {
            val rfc = KatSupport.obj(k, "rfc4231_hmac_sha256")
            for (tcName in listOf("tc1", "tc2")) {
                val tc = KatSupport.obj(rfc, tcName)
                val got = KatSupport.toHex(hmacOracle(KatSupport.fromHex(tc["key"] as String), KatSupport.fromHex(tc["data"] as String)))
                val want = tc["hmac_sha256"] as String
                check(got == want) { "HMAC-SHA-256 $tcName != RFC 4231\n  got  $got\n  want $want" }
            }
        }

        leg("finished_kat_oracle") {
            val gotS = KatSupport.toHex(hmacOracle(KatSupport.fromHex(nn["finished_key_server"] as String), KatSupport.fromHex(nn["th_scv"] as String)))
            check(gotS == e["verify_data_server"]) { "oracle server verify_data mismatch" }
            val gotC = KatSupport.toHex(hmacOracle(KatSupport.fromHex(nn["finished_key_client"] as String), KatSupport.fromHex(nn["th_ccv"] as String)))
            check(gotC == e["verify_data_client"]) { "oracle client verify_data mismatch" }
        }

        leg("finished_kat_impl") {
            data class Case(val name: String, val fk: String, val th: String, val want: String)
            val cases = listOf(
                Case("server", nn["finished_key_server"] as String, nn["th_scv"] as String, e["verify_data_server"] as String),
                Case("client", nn["finished_key_client"] as String, nn["th_ccv"] as String, e["verify_data_client"] as String),
            )
            for (c in cases) {
                val fk = KatSupport.fromHex(c.fk)
                val th = KatSupport.fromHex(c.th)
                val want = KatSupport.fromHex(c.want)
                val got = KatSupport.toHex(Handshake.computeFinished(fk, th, true))
                check(got == c.want) { "[${c.name}] computeFinished mismatch\n  got  $got\n  want ${c.want}" }
                check(Handshake.verifyFinished(fk, th, want, true)) { "[${c.name}] verifyFinished rejected the correct verify_data" }
                val bad = want.copyOf()
                bad[0] = (bad[0].toInt() xor 0x01).toByte()
                check(!Handshake.verifyFinished(fk, th, bad, true)) { "[${c.name}] verifyFinished accepted a tampered verify_data" }
            }
        }

        println(if (failures == 0) "ALL PASS (3/3)" else "FAILURES: $failures")
        exitProcess(if (failures == 0) 0 else 1)
    }
}
