// Handshake binding layer for the N-PAMP wire format (draft-bubblefish-npamp-00).
// OPEN protocol layer only: the transcript construction (spec/10 §3), the Finished
// MAC (spec/10 §6.2), and the CertVerify signature (spec/10 §6.1). No proprietary
// methods, parameters, or weights.
//
// Pure-Kotlin sibling of Npamp.kt. Uses the same JDK crypto providers: MessageDigest
// "SHA-256"/"SHA-384", Mac "HmacSHA256"/"HmacSHA384", Signature "Ed25519", and
// KeyFactory "Ed25519" with EdECPrivateKeySpec / EdECPublicKeySpec.
package sh.bubblefish.npamp

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.EdECPoint
import java.security.spec.EdECPrivateKeySpec
import java.security.spec.EdECPublicKeySpec
import java.security.spec.NamedParameterSpec
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * N-PAMP draft-00 handshake binding (spec/10): transcript, Finished, CertVerify.
 * Big-endian throughout. All cryptography uses the JDK providers.
 */
object Handshake {

    // -- Constants ---------------------------------------------------------

    // Handshake frame types (spec §1), carried on the control channel.
    const val FRAME_CLIENT_HELLO: Int = 0x0100
    const val FRAME_SERVER_HELLO: Int = 0x0101
    const val FRAME_SERVER_AUTH: Int = 0x0102
    const val FRAME_CLIENT_AUTH: Int = 0x0103

    // CertVerify context strings (spec §6.1).
    const val CONTEXT_SERVER_CERTVERIFY: String = "N-PAMP draft-00, server CertificateVerify"
    const val CONTEXT_CLIENT_CERTVERIFY: String = "N-PAMP draft-00, client CertificateVerify"

    // -- Transcript --------------------------------------------------------

    /**
     * Accumulates the draft-00 handshake transcript (binding spec/10 §3) and hashes
     * it at a cut point. Per-TLV granularity: [addFrameType] appends the 2-octet
     * frame type ONLY (not the rest of the 36-octet header — the §3/§7.1 divergence
     * from RFC 8446 §4.4.1); [addTlv] appends Type(2 BE) || Length(2 BE) || Value.
     * A point = the profile hash (SHA-256 at Standard, SHA-384 at High/Sovereign)
     * over all bytes absorbed so far.
     */
    class Transcript {
        private val buf = ByteArrayOutputStream()

        /** Absorbs a frame type as exactly two big-endian octets. */
        fun addFrameType(ft: Int) {
            buf.write((ft ushr 8) and 0xFF)
            buf.write(ft and 0xFF)
        }

        /** Absorbs one TLV: Type(2 BE) || Length(2 BE) || Value. */
        fun addTlv(type: Int, value: ByteArray) {
            buf.write((type ushr 8) and 0xFF)
            buf.write(type and 0xFF)
            buf.write((value.size ushr 8) and 0xFF)
            buf.write(value.size and 0xFF)
            buf.write(value, 0, value.size)
        }

        /** Hashes all absorbed bytes: SHA-256 at Standard, SHA-384 otherwise. */
        fun hash(standard: Boolean): ByteArray {
            val md = MessageDigest.getInstance(if (standard) "SHA-256" else "SHA-384")
            return md.digest(buf.toByteArray())
        }
    }

    // -- Finished (spec §6.2; RFC 8446 §4.4.4) -----------------------------

    /**
     * Finished verify_data = HMAC(finished_key, transcript_hash) under the profile
     * hash (HmacSHA256 at Standard, HmacSHA384 at High/Sovereign).
     */
    fun computeFinished(finishedKey: ByteArray, transcriptHash: ByteArray, standard: Boolean): ByteArray {
        val alg = if (standard) "HmacSHA256" else "HmacSHA384"
        val mac = Mac.getInstance(alg)
        mac.init(SecretKeySpec(finishedKey, alg))
        return mac.doFinal(transcriptHash)
    }

    /**
     * Recomputes the Finished MAC and constant-time-compares it to the received
     * verify_data. MessageDigest.isEqual is the JDK's constant-time comparison.
     */
    fun verifyFinished(finishedKey: ByteArray, transcriptHash: ByteArray, verifyData: ByteArray, standard: Boolean): Boolean {
        return MessageDigest.isEqual(computeFinished(finishedKey, transcriptHash, standard), verifyData)
    }

    // -- CertVerify (spec §6.1; RFC 8446 §4.4.3; Ed25519 RFC 8032) ---------

    /** Builds an Ed25519 private key from its raw 32-octet seed (RFC 8032). */
    fun ed25519PrivateKeyFromSeed(seed: ByteArray): PrivateKey {
        val spec = EdECPrivateKeySpec(NamedParameterSpec.ED25519, seed)
        return KeyFactory.getInstance("Ed25519").generatePrivate(spec)
    }

    /**
     * Builds an Ed25519 public key from its raw 32-octet encoding (RFC 8032 §5.1.2):
     * little-endian y with the MSB of the final octet carrying the x sign.
     */
    fun ed25519PublicKeyFromRaw(raw: ByteArray): PublicKey {
        require(raw.size == 32) { "ed25519 public key must be 32 octets" }
        // Reverse little-endian -> big-endian; the top bit of the (now leading) octet is the x sign.
        val be = ByteArray(32)
        for (i in 0 until 32) {
            be[i] = raw[31 - i]
        }
        val xOdd = (be[0].toInt() and 0x80) != 0
        be[0] = (be[0].toInt() and 0x7F).toByte()
        val y = BigInteger(1, be)
        val point = EdECPoint(xOdd, y)
        val spec = EdECPublicKeySpec(NamedParameterSpec.ED25519, point)
        return KeyFactory.getInstance("Ed25519").generatePublic(spec)
    }

    /**
     * The §6.1 signing input: 64 octets of 0x20, the role context string, a 0x00
     * separator, then the transcript hash — TLS-1.3-style domain separation
     * (RFC 8446 §4.4.3).
     */
    fun certVerifySigningInput(isServer: Boolean, transcriptHash: ByteArray): ByteArray {
        val ctx = (if (isServer) CONTEXT_SERVER_CERTVERIFY else CONTEXT_CLIENT_CERTVERIFY)
            .toByteArray(StandardCharsets.US_ASCII)
        val out = ByteArrayOutputStream()
        for (i in 0 until 64) {
            out.write(0x20)
        }
        out.write(ctx, 0, ctx.size)
        out.write(0x00)
        out.write(transcriptHash, 0, transcriptHash.size)
        return out.toByteArray()
    }

    /** The CertVerify TLV value: u16(0x0807, Ed25519) || Ed25519(priv, signing_input). */
    fun signCertVerify(privateKey: PrivateKey, isServer: Boolean, transcriptHash: ByteArray): ByteArray {
        val signer = Signature.getInstance("Ed25519")
        signer.initSign(privateKey)
        signer.update(certVerifySigningInput(isServer, transcriptHash))
        val signature = signer.sign()
        val out = ByteArray(2 + signature.size)
        out[0] = ((Npamp.SIG_ED25519 ushr 8) and 0xFF).toByte()
        out[1] = (Npamp.SIG_ED25519 and 0xFF).toByte()
        System.arraycopy(signature, 0, out, 2, signature.size)
        return out
    }

    /**
     * Checks a CertVerify TLV value against the signer's public key, role, and
     * transcript hash. Rejects a non-Ed25519 scheme, a wrong-length signature, a
     * role/context mismatch, or a wrong transcript.
     */
    fun verifyCertVerify(publicKey: PublicKey, isServer: Boolean, transcriptHash: ByteArray, value: ByteArray): Boolean {
        if (value.size < 2) {
            return false
        }
        val scheme = ((value[0].toInt() and 0xFF) shl 8) or (value[1].toInt() and 0xFF)
        if (scheme != Npamp.SIG_ED25519) {
            return false
        }
        val sig = value.copyOfRange(2, value.size)
        if (sig.size != 64) { // Ed25519 signatures are exactly 64 octets (RFC 8032 §5.1.6)
            return false
        }
        return try {
            val verifier = Signature.getInstance("Ed25519")
            verifier.initVerify(publicKey)
            verifier.update(certVerifySigningInput(isServer, transcriptHash))
            verifier.verify(sig)
        } catch (e: Exception) {
            false
        }
    }
}
