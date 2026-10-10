// Behaviour check, not a conformance vector: the open Kotlin module implements the Standard
// profile only, so every key-schedule, transcript and Finished primitive refuses a non-Standard
// profile with Npamp.NoSuiteForProfile and still succeeds at Standard. No external authority
// (RFC or FIPS) defines this module's scope.
//
//   kotlinc src/main/kotlin src/test/kotlin -d out
//   java -cp "out:$KOTLIN_HOME/lib/kotlin-stdlib.jar" sh.bubblefish.npamp.RefusalKat
package sh.bubblefish.npamp

import kotlin.system.exitProcess

object RefusalKat {

    private var failures = 0

    private fun check(name: String, ok: Boolean) {
        if (ok) {
            println("PASS $name")
        } else {
            println("FAIL $name")
            failures++
        }
    }

    private fun refused(name: String, call: () -> Unit) {
        var threw = false
        try {
            call()
        } catch (e: Npamp.NoSuiteForProfile) {
            threw = true
        } catch (e: RuntimeException) {
            println("     wrong exception for $name: $e")
        }
        check("non-standard refused: $name", threw)
    }

    @JvmStatic
    fun main(args: Array<String>) {
        val secret = ByteArray(32) { 0x11 }
        val th = ByteArray(32) { 0x22 }

        check("standard control: hkdfExtract", Npamp.hkdfExtract(ByteArray(32), secret, true).size == 32)
        check(
            "standard control: deriveTrafficSecret",
            Npamp.deriveTrafficSecret(secret, 0, 0L, Npamp.AEAD_AES256_GCM, Npamp.CHAN_CONTROL, true).size == 32,
        )
        val ki = Npamp.deriveKeyIv(secret, true)
        check("standard control: deriveKeyIv", ki[0].size == 32 && ki[1].size == 12)
        check("standard control: deriveHandshakeSecret", Npamp.deriveHandshakeSecret(secret, secret, true).size == 32)
        check("standard control: deriveFinishedKey", Npamp.deriveFinishedKey(secret, true).size == 32)
        check("standard control: transcript hash", Handshake.Transcript().hash(true).size == 32)
        val mac = Handshake.computeFinished(secret, th, true)
        check("standard control: finished verifies", Handshake.verifyFinished(secret, th, mac, true))

        refused("hkdfExtract") { Npamp.hkdfExtract(ByteArray(48), secret, false) }
        refused("hkdfExpandLabel") { Npamp.hkdfExpandLabel(secret, "key", ByteArray(0), 32, false) }
        refused("deriveTrafficSecret") {
            Npamp.deriveTrafficSecret(secret, 0, 0L, Npamp.AEAD_AES256_GCM, Npamp.CHAN_CONTROL, false)
        }
        refused("deriveKeyIv") { Npamp.deriveKeyIv(secret, false) }
        refused("deriveHandshakeSecret") { Npamp.deriveHandshakeSecret(secret, secret, false) }
        refused("deriveClientHandshakeSecret") { Npamp.deriveClientHandshakeSecret(secret, th, false) }
        refused("deriveServerHandshakeSecret") { Npamp.deriveServerHandshakeSecret(secret, th, false) }
        refused("deriveMasterSecret") { Npamp.deriveMasterSecret(secret, th, false) }
        refused("deriveFinishedKey") { Npamp.deriveFinishedKey(secret, false) }
        refused("Transcript.hash") { Handshake.Transcript().hash(false) }
        refused("computeFinished") { Handshake.computeFinished(secret, th, false) }
        refused("verifyFinished") { Handshake.verifyFinished(secret, th, th, false) }

        println(if (failures == 0) "ALL PASS" else "FAILURES: $failures")
        exitProcess(if (failures == 0) 0 else 1)
    }
}
