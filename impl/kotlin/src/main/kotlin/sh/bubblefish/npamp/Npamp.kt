// Open reference implementation of the N-PAMP wire format (draft-bubblefish-npamp-00).
// OPEN protocol layer only: framing, registries, AEAD record layer, key schedule.
// No proprietary methods, parameters, or weights.
//
// Pure-Kotlin port of the Java reference (sh.bubblefish.npamp.Npamp). Uses the same
// JDK crypto providers: java.util.zip.CRC32C, AES/GCM/NoPadding, HmacSHA256/HmacSHA384.
package sh.bubblefish.npamp

import java.nio.charset.StandardCharsets
import java.util.zip.CRC32C
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * N-PAMP OPEN-layer reference: frame framing, CRC32C integrity, per-frame AEAD
 * nonce derivation, AES-256-GCM record layer, and the HKDF-Expand-Label key
 * schedule. Big-endian throughout. All cryptography uses the JDK providers.
 */
object Npamp {

    // -- Constants ---------------------------------------------------------

    const val HEADER_SIZE: Int = 36
    const val PROTOCOL_VERSION: Int = 0x2

    @JvmField
    val MAGIC: ByteArray = byteArrayOf('N'.code.toByte(), 'P'.code.toByte(), 'A'.code.toByte(), 'M'.code.toByte()) // "NPAM" = 0x4E50414D

    const val ALPN: String = "n-pamp/2"
    const val LABEL_PREFIX: String = "n-pamp " // protocol-specific; NOT "tls13 "

    const val FLAG_URG: Int = 0x01
    const val FLAG_ENC: Int = 0x02
    const val FLAG_COMP: Int = 0x04
    const val FLAG_FRAG: Int = 0x08

    const val CHAN_CONTROL: Int = 0x0000
    const val CHAN_MEMORY: Int = 0x0001
    const val CHAN_IMMUNE: Int = 0x0005
    const val CHAN_AUDIT: Int = 0x000B
    const val CHAN_BRIDGE: Int = 0x000D
    const val CHAN_SPATIAL: Int = 0x0013

    const val FRAME_PING: Int = 0x0001
    const val FRAME_PONG: Int = 0x0002
    const val FRAME_CLOSE: Int = 0x0003
    const val FRAME_FLOW_UPDATE: Int = 0x000A
    const val CHANNEL_SPECIFIC_BASE: Int = 0x0100

    const val TLV_PROFILE_OFFER: Int = 0x01
    const val TLV_KEM_CIPHERTEXT: Int = 0x08
    const val TLV_ANOMALY_CHARGE: Int = 0x12

    const val KEM_X25519_MLKEM768: Int = 0x11ec
    const val KEM_X25519_MLKEM1024: Int = 0x11ed
    const val AEAD_AES256_GCM: Int = 0x0001
    const val AEAD_CHACHA20_POLY1305: Int = 0x0002
    const val SIG_ED25519: Int = 0x0807
    const val SIG_MLDSA87: Int = 0x0905

    // -- Errors ------------------------------------------------------------

    /** Raised when a wire frame fails structural or integrity validation. */
    class FrameException(message: String) : RuntimeException(message)

    // -- CRC32C ------------------------------------------------------------

    /**
     * CRC32C (Castagnoli, reflected): poly 0x82F63B78, init 0xFFFFFFFF, final
     * xor 0xFFFFFFFF. Delegates to java.util.zip.CRC32C, which produces exactly
     * this value. Returned as an unsigned 32-bit value held in a Long.
     */
    fun crc32c(data: ByteArray): Long {
        val c = CRC32C()
        c.update(data, 0, data.size)
        return c.value
    }

    // -- Big-endian helpers ------------------------------------------------

    private fun putU16BE(buf: ByteArray, off: Int, v: Int) {
        buf[off] = ((v ushr 8) and 0xFF).toByte()
        buf[off + 1] = (v and 0xFF).toByte()
    }

    private fun putU32BE(buf: ByteArray, off: Int, v: Long) {
        buf[off] = ((v ushr 24) and 0xFF).toByte()
        buf[off + 1] = ((v ushr 16) and 0xFF).toByte()
        buf[off + 2] = ((v ushr 8) and 0xFF).toByte()
        buf[off + 3] = (v and 0xFF).toByte()
    }

    private fun putU64BE(buf: ByteArray, off: Int, v: Long) {
        for (i in 0 until 8) {
            buf[off + i] = ((v ushr (56 - 8 * i)) and 0xFF).toByte()
        }
    }

    private fun getU16BE(buf: ByteArray, off: Int): Int {
        return ((buf[off].toInt() and 0xFF) shl 8) or (buf[off + 1].toInt() and 0xFF)
    }

    private fun getU32BE(buf: ByteArray, off: Int): Long {
        return ((buf[off].toLong() and 0xFF) shl 24) or
            ((buf[off + 1].toLong() and 0xFF) shl 16) or
            ((buf[off + 2].toLong() and 0xFF) shl 8) or
            (buf[off + 3].toLong() and 0xFF)
    }

    private fun getU64BE(buf: ByteArray, off: Int): Long {
        var v = 0L
        for (i in 0 until 8) {
            v = (v shl 8) or (buf[off + i].toLong() and 0xFF)
        }
        return v
    }

    // -- Frame -------------------------------------------------------------

    /**
     * A single N-PAMP wire frame: a 36-octet header followed by an opaque
     * payload. [seq] and epoch carry unsigned 64-bit values in a Kotlin Long;
     * only the bit pattern is wire-significant.
     */
    class Frame(
        @JvmField var ftype: Int = 0,
        @JvmField var channel: Int = 0,
        @JvmField var seq: Long = 0L,
        @JvmField var flags: Int = 0,
        @JvmField var version: Int = 0,
        payload: ByteArray = ByteArray(0),
    ) {
        @JvmField
        var payload: ByteArray = payload

        /** Convenience for {PING, Control}-style frames with no payload. */
        constructor(ftype: Int, channel: Int) : this(ftype, channel, 0L, 0, 0, ByteArray(0))

        /**
         * Builds octets [0:21]: MAGIC, (version<<4)|flags, frameType, channel,
         * seq, payloadLen. When [version] is 0 the protocol default (0x2) is
         * substituted. This 21-octet prefix is exactly the AEAD associated data.
         */
        fun headerPrefix(payloadLen: Long): ByteArray {
            val ver = if (version != 0) version else PROTOCOL_VERSION
            val out = ByteArray(21)
            System.arraycopy(MAGIC, 0, out, 0, 4)
            out[4] = (((ver shl 4) or (flags and 0x0F)) and 0xFF).toByte()
            putU16BE(out, 5, ftype)
            putU16BE(out, 7, channel)
            putU64BE(out, 9, seq)
            putU32BE(out, 17, payloadLen)
            return out
        }

        /** Serialises the frame: prefix || CRC32C(prefix) || 11 zero octets || payload. */
        fun marshal(): ByteArray {
            val prefix = headerPrefix(payload.size.toLong())
            val out = ByteArray(HEADER_SIZE + payload.size)
            System.arraycopy(prefix, 0, out, 0, 21)
            putU32BE(out, 21, crc32c(prefix))
            // octets 25..36 reserved, already zero
            System.arraycopy(payload, 0, out, HEADER_SIZE, payload.size)
            return out
        }

        companion object {
            /**
             * Parses a wire frame. Validation order: CRC32C first, then magic,
             * then version, then reserved-all-zero, then payload-length agreement.
             */
            @JvmStatic
            fun unmarshal(buf: ByteArray): Frame {
                if (buf.size < HEADER_SIZE) {
                    throw FrameException("short header")
                }
                val got = getU32BE(buf, 21)
                if (got != crc32c(buf.copyOfRange(0, 21))) {
                    throw FrameException("bad crc")
                }
                for (i in 0 until 4) {
                    if (buf[i] != MAGIC[i]) {
                        throw FrameException("bad magic")
                    }
                }
                val ver = (buf[4].toInt() and 0xFF) ushr 4
                if (ver != PROTOCOL_VERSION) {
                    throw FrameException("bad version")
                }
                for (i in 25 until HEADER_SIZE) {
                    if (buf[i].toInt() != 0) {
                        throw FrameException("reserved nonzero")
                    }
                }
                val plen = getU32BE(buf, 17)
                if (plen != (buf.size - HEADER_SIZE).toLong()) {
                    throw FrameException("length mismatch")
                }
                val f = Frame()
                f.version = ver
                f.flags = buf[4].toInt() and 0x0F
                f.ftype = getU16BE(buf, 5)
                f.channel = getU16BE(buf, 7)
                f.seq = getU64BE(buf, 9)
                f.payload = buf.copyOfRange(HEADER_SIZE, buf.size)
                return f
            }
        }
    }

    // -- AEAD record layer -------------------------------------------------

    /**
     * Per-frame AEAD nonce (draft-00 7.5): a 12-octet buffer holding the seq as
     * a big-endian u64 in bytes [4:12], XORed with the 12-octet IV. The channel
     * ID is NOT part of the nonce.
     */
    fun deriveNonce(iv: ByteArray, seq: Long): ByteArray {
        val n = ByteArray(12)
        putU64BE(n, 4, seq)
        for (i in 0 until 12) {
            n[i] = (n[i].toInt() xor iv[i].toInt()).toByte()
        }
        return n
    }

    /**
     * AES-256-GCM seal. Returns ciphertext||tag (16-octet tag). The associated
     * data is the 21-octet header prefix.
     */
    fun sealAes256Gcm(key: ByteArray, iv: ByteArray, seq: Long, aad: ByteArray, pt: ByteArray): ByteArray {
        try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            val spec = GCMParameterSpec(128, deriveNonce(iv, seq))
            c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), spec)
            c.updateAAD(aad)
            return c.doFinal(pt)
        } catch (e: Exception) {
            throw RuntimeException("aes-256-gcm seal failed", e)
        }
    }

    /**
     * AES-256-GCM open. Accepts ciphertext||tag and verifies the tag against
     * the supplied associated data; throws on authentication failure.
     */
    fun openAes256Gcm(key: ByteArray, iv: ByteArray, seq: Long, aad: ByteArray, sealed: ByteArray): ByteArray {
        try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            val spec = GCMParameterSpec(128, deriveNonce(iv, seq))
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), spec)
            c.updateAAD(aad)
            return c.doFinal(sealed)
        } catch (e: Exception) {
            throw RuntimeException("aes-256-gcm open failed", e)
        }
    }

    // -- Key schedule (HKDF-Expand-Label) ----------------------------------

    /**
     * HKDF-Expand (RFC 5869, section 2.3), expand step only: the supplied secret
     * IS the PRK, so HKDF-Extract is not run. The hash is selected by the caller
     * (HmacSHA256 or HmacSHA384).
     */
    private fun hkdfExpand(macAlg: String, prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        try {
            val mac = Mac.getInstance(macAlg)
            val hashLen = mac.macLength
            val n = (length + hashLen - 1) / hashLen
            val out = ByteArray(n * hashLen)
            var t = ByteArray(0)
            var pos = 0
            for (i in 1..n) {
                mac.init(SecretKeySpec(prk, macAlg))
                mac.update(t)
                mac.update(info)
                mac.update(i.toByte())
                t = mac.doFinal()
                System.arraycopy(t, 0, out, pos, hashLen)
                pos += hashLen
            }
            return out.copyOfRange(0, length)
        } catch (e: Exception) {
            throw RuntimeException("hkdf-expand failed", e)
        }
    }

    /**
     * HKDF-Expand-Label (draft-00 7.4). full = LABEL_PREFIX + label.
     * info = u16(length) || u8(len(full)) || full || u8(len(context)) || context.
     * [standard] selects SHA-256 (true) or SHA-384 (false).
     */
    fun hkdfExpandLabel(secret: ByteArray, label: String, context: ByteArray, length: Int, standard: Boolean): ByteArray {
        val full = (LABEL_PREFIX + label).toByteArray(StandardCharsets.US_ASCII)
        val info = ByteArray(2 + 1 + full.size + 1 + context.size)
        var p = 0
        info[p++] = ((length ushr 8) and 0xFF).toByte()
        info[p++] = (length and 0xFF).toByte()
        info[p++] = full.size.toByte()
        System.arraycopy(full, 0, info, p, full.size)
        p += full.size
        info[p++] = context.size.toByte()
        System.arraycopy(context, 0, info, p, context.size)
        return hkdfExpand(if (standard) "HmacSHA256" else "HmacSHA384", secret, info, length)
    }

    /**
     * Derives a directional traffic secret.
     * context = dir(1) || epoch(8 BE) || suite(2 BE) || channel(2 BE);
     * output length 32 (SHA-256) or 48 (SHA-384); label "traffic".
     */
    fun deriveTrafficSecret(master: ByteArray, dir: Int, epoch: Long, suite: Int, channel: Int, standard: Boolean): ByteArray {
        val ctx = ByteArray(1 + 8 + 2 + 2)
        ctx[0] = (dir and 0xFF).toByte()
        putU64BE(ctx, 1, epoch)
        putU16BE(ctx, 9, suite)
        putU16BE(ctx, 11, channel)
        val hlen = if (standard) 32 else 48
        return hkdfExpandLabel(master, "traffic", ctx, hlen, standard)
    }

    /** Derives the {key(32), iv(12)} pair from a traffic secret. */
    fun deriveKeyIv(secret: ByteArray, standard: Boolean): Array<ByteArray> {
        val key = hkdfExpandLabel(secret, "key", ByteArray(0), 32, standard)
        val iv = hkdfExpandLabel(secret, "iv", ByteArray(0), 12, standard)
        return arrayOf(key, iv)
    }

    // -- Handshake-secret ladder (binding spec/10 §5) ----------------------

    /**
     * HKDF-Extract (RFC 5869, section 2.2): extract(salt, IKM) = HMAC-Hash(salt, IKM).
     * The hash is selected by [standard]: HmacSHA256 (true) or HmacSHA384 (false), wired
     * exactly like the Expand side. RFC 5869 specifies that an empty salt is treated as
     * HashLen zero octets; the binding always passes an explicit HashLen-octet zero salt.
     */
    fun hkdfExtract(salt: ByteArray, ikm: ByteArray, standard: Boolean): ByteArray {
        try {
            val alg = if (standard) "HmacSHA256" else "HmacSHA384"
            val mac = Mac.getInstance(alg)
            val key = if (salt.isEmpty()) ByteArray(mac.macLength) else salt
            mac.init(SecretKeySpec(key, alg))
            return mac.doFinal(ikm)
        } catch (e: Exception) {
            throw RuntimeException("hkdf-extract failed", e)
        }
    }

    /**
     * Derives the binding handshake_secret (binding spec/10 §5; ML-KEM-first per ADR-0005).
     * The two inputs are the raw shared secrets from each KEM share; the combined IKM places
     * the ML-KEM shared secret FIRST, then the X25519 shared secret. handshake_secret =
     * HKDF-Extract(salt = HashLen zero octets, IKM). At the Standard profile HashLen is 32,
     * so the salt is 32 zero octets.
     */
    fun deriveHandshakeSecret(mlkemSharedSecret: ByteArray, x25519SharedSecret: ByteArray, standard: Boolean): ByteArray {
        val ikm = ByteArray(mlkemSharedSecret.size + x25519SharedSecret.size)
        System.arraycopy(mlkemSharedSecret, 0, ikm, 0, mlkemSharedSecret.size)
        System.arraycopy(x25519SharedSecret, 0, ikm, mlkemSharedSecret.size, x25519SharedSecret.size)
        val hashLen = if (standard) 32 else 48
        return hkdfExtract(ByteArray(hashLen), ikm, standard)
    }

    /** Derives c_hs = HKDF-Expand-Label(handshake_secret, "c hs", th_kem, HashLen) (binding §5). */
    fun deriveClientHandshakeSecret(handshakeSecret: ByteArray, thKem: ByteArray, standard: Boolean): ByteArray {
        return hkdfExpandLabel(handshakeSecret, "c hs", thKem, if (standard) 32 else 48, standard)
    }

    /** Derives s_hs = HKDF-Expand-Label(handshake_secret, "s hs", th_kem, HashLen) (binding §5). */
    fun deriveServerHandshakeSecret(handshakeSecret: ByteArray, thKem: ByteArray, standard: Boolean): ByteArray {
        return hkdfExpandLabel(handshakeSecret, "s hs", thKem, if (standard) 32 else 48, standard)
    }

    /** Derives master = HKDF-Expand-Label(handshake_secret, "master", th_ccv, HashLen) (binding §5). */
    fun deriveMasterSecret(handshakeSecret: ByteArray, thCcv: ByteArray, standard: Boolean): ByteArray {
        return hkdfExpandLabel(handshakeSecret, "master", thCcv, if (standard) 32 else 48, standard)
    }

    /**
     * Derives a Finished key (binding §6.2 / §5.4): finished_key(secret) =
     * HKDF-Expand-Label(secret, "finished", "" /* empty context */, HashLen). The client
     * Finished key derives from c_hs; the server Finished key derives from s_hs.
     */
    fun deriveFinishedKey(secret: ByteArray, standard: Boolean): ByteArray {
        return hkdfExpandLabel(secret, "finished", ByteArray(0), if (standard) 32 else 48, standard)
    }

    // -- Hex utility -------------------------------------------------------

    /** Lowercase hex encoding, used by the vector generator and tests. */
    fun toHex(data: ByteArray): String {
        val sb = StringBuilder(data.size * 2)
        for (b in data) {
            sb.append(Character.forDigit((b.toInt() ushr 4) and 0xF, 16))
            sb.append(Character.forDigit(b.toInt() and 0xF, 16))
        }
        return sb.toString()
    }
}
