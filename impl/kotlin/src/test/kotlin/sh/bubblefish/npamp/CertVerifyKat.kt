// Standards-derived, NON-CIRCULAR known-answer test for the draft-00 CertVerify
// (binding spec/10 §6.1; RFC 8446 §4.4.3 structure; Ed25519 per RFC 8032). The value
// is u16(0x0807) || Ed25519(priv, signing_input), signing_input = 64*0x20 || context ||
// 0x00 || TH. Kotlin mirror of the Go/TS/Python reference tests against the SAME pinned
// vector (test-vectors/v1/certverify-kat.json).
//
// Three legs: ANCHOR (the src Ed25519 helpers reproduce RFC 8032 TEST1/TEST2 signature +
// public-key decode), ORACLE (rebuild signing_input by hand + sign with an independently
// constructed JDK key, no src signing functions), IMPL (certVerifySigningInput +
// signCertVerify reproduce the vector; verifyCertVerify accepts the correct value but
// rejects a role/context mismatch, a wrong transcript, a wrong scheme, and a truncated sig).
package sh.bubblefish.npamp

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.EdECPrivateKeySpec
import java.security.spec.NamedParameterSpec
import kotlin.system.exitProcess

object CertVerifyKat {

    private const val PIN = "19afd438c3036fd7d51481e5e6e91cc73010d76cb94aa2082c7752c8ba714d3f"

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

    /** Builds an Ed25519 private key from its seed, inline and independent of Handshake. */
    private fun oraclePriv(seed: ByteArray): PrivateKey =
        KeyFactory.getInstance("Ed25519").generatePrivate(EdECPrivateKeySpec(NamedParameterSpec.ED25519, seed))

    /** Raw Ed25519 sign over [msg], independent of signCertVerify. */
    private fun oracleSign(priv: PrivateKey, msg: ByteArray): ByteArray {
        val s = Signature.getInstance("Ed25519")
        s.initSign(priv)
        s.update(msg)
        return s.sign()
    }

    /** The §6.1 signing input, built by hand and independent of certVerifySigningInput. */
    private fun oracleSigningInput(ctx: String, th: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        for (i in 0 until 64) {
            out.write(0x20)
        }
        val c = ctx.toByteArray(StandardCharsets.US_ASCII)
        out.write(c, 0, c.size)
        out.write(0x00)
        out.write(th, 0, th.size)
        return out.toByteArray()
    }

    @JvmStatic
    fun main(args: Array<String>) {
        val k = KatSupport.loadPinned(args, "certverify-kat.json", PIN)
        val nn = KatSupport.obj(k, "npamp_inputs")
        val e = KatSupport.obj(k, "expected")
        val c = KatSupport.obj(k, "contexts")

        leg("certverify_kat_rfc8032_anchor") {
            val rfc = KatSupport.obj(k, "rfc8032_ed25519")
            for (label in listOf("test1", "test2")) {
                val v = KatSupport.obj(rfc, label)
                val seed = KatSupport.fromHex(v["seed"] as String)
                val msg = KatSupport.fromHex(v["message"] as String)
                // src signer reproduces the RFC 8032 signature.
                val priv = Handshake.ed25519PrivateKeyFromSeed(seed)
                val gotSig = KatSupport.toHex(oracleSign(priv, msg))
                check(gotSig == v["signature"]) { "$label signature != RFC 8032\n  got  $gotSig\n  want ${v["signature"]}" }
                // src public-key decoder reproduces a key that verifies the RFC 8032 signature.
                val pub = Handshake.ed25519PublicKeyFromRaw(KatSupport.fromHex(v["public_key"] as String))
                val verifier = Signature.getInstance("Ed25519")
                verifier.initVerify(pub)
                verifier.update(msg)
                check(verifier.verify(KatSupport.fromHex(v["signature"] as String))) {
                    "$label: ed25519PublicKeyFromRaw produced a key that rejected the RFC 8032 signature"
                }
            }
        }

        leg("certverify_kat_oracle") {
            data class Case(val name: String, val ctx: String, val seed: String, val th: String, val wantSI: String, val wantSig: String)
            val cases = listOf(
                Case("server", c["server"] as String, nn["server_seed"] as String, nn["th_sid"] as String, e["signing_input_server"] as String, e["signature_server"] as String),
                Case("client", c["client"] as String, nn["client_seed"] as String, nn["th_cid"] as String, e["signing_input_client"] as String, e["signature_client"] as String),
            )
            for (cs in cases) {
                val si = oracleSigningInput(cs.ctx, KatSupport.fromHex(cs.th))
                check(KatSupport.toHex(si) == cs.wantSI) { "[${cs.name}] oracle signing_input != vector" }
                val gotSig = KatSupport.toHex(oracleSign(oraclePriv(KatSupport.fromHex(cs.seed)), si))
                check(gotSig == cs.wantSig) { "[${cs.name}] oracle signature != vector\n  got  $gotSig\n  want ${cs.wantSig}" }
            }
        }

        leg("certverify_kat_impl") {
            check(Handshake.CONTEXT_SERVER_CERTVERIFY == c["server"]) { "server context constant drifted from spec §6.1" }
            check(Handshake.CONTEXT_CLIENT_CERTVERIFY == c["client"]) { "client context constant drifted from spec §6.1" }
            data class Case(val name: String, val isServer: Boolean, val seed: String, val pub: String, val th: String, val wantSI: String, val wantVal: String)
            val cases = listOf(
                Case("server", true, nn["server_seed"] as String, nn["server_pub"] as String, nn["th_sid"] as String, e["signing_input_server"] as String, e["certverify_value_server"] as String),
                Case("client", false, nn["client_seed"] as String, nn["client_pub"] as String, nn["th_cid"] as String, e["signing_input_client"] as String, e["certverify_value_client"] as String),
            )
            for (cs in cases) {
                val priv = Handshake.ed25519PrivateKeyFromSeed(KatSupport.fromHex(cs.seed))
                val pub = Handshake.ed25519PublicKeyFromRaw(KatSupport.fromHex(cs.pub))
                val th = KatSupport.fromHex(cs.th)

                val gotSI = KatSupport.toHex(Handshake.certVerifySigningInput(cs.isServer, th))
                check(gotSI == cs.wantSI) { "[${cs.name}] certVerifySigningInput != vector\n  got  $gotSI\n  want ${cs.wantSI}" }

                val value = Handshake.signCertVerify(priv, cs.isServer, th)
                val gotVal = KatSupport.toHex(value)
                check(gotVal == cs.wantVal) { "[${cs.name}] signCertVerify value != vector\n  got  $gotVal\n  want ${cs.wantVal}" }

                check(Handshake.verifyCertVerify(pub, cs.isServer, th, value)) { "[${cs.name}] verifyCertVerify rejected the correct value" }
                // Domain separation: the opposite role must FAIL (different context string).
                check(!Handshake.verifyCertVerify(pub, !cs.isServer, th, value)) { "[${cs.name}] accepted a role/context mismatch" }
                // Transcript binding: a different transcript hash must FAIL.
                val wrong = th.copyOf()
                wrong[0] = (wrong[0].toInt() xor 0x01).toByte()
                check(!Handshake.verifyCertVerify(pub, cs.isServer, wrong, value)) { "[${cs.name}] accepted a wrong transcript hash" }
                // Scheme guard: a non-Ed25519 scheme code point must FAIL.
                val badScheme = value.copyOf()
                badScheme[0] = ((Npamp.SIG_MLDSA87 ushr 8) and 0xFF).toByte()
                badScheme[1] = (Npamp.SIG_MLDSA87 and 0xFF).toByte()
                check(!Handshake.verifyCertVerify(pub, cs.isServer, th, badScheme)) { "[${cs.name}] accepted a non-Ed25519 scheme" }
                // Length guard: an Ed25519 signature is exactly 64 octets; a truncated value must FAIL.
                check(!Handshake.verifyCertVerify(pub, cs.isServer, th, value.copyOf(value.size - 1))) { "[${cs.name}] accepted a truncated signature" }
            }
        }

        println(if (failures == 0) "ALL PASS (3/3)" else "FAILURES: $failures")
        exitProcess(if (failures == 0) 0 else 1)
    }
}
