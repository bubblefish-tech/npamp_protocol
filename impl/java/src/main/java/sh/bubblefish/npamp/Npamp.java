// Open reference implementation of the N-PAMP wire format (draft-bubblefish-npamp-00).
// OPEN protocol layer only: framing, registries, AEAD record layer, key schedule.
// No proprietary methods, parameters, or weights.
package sh.bubblefish.npamp;

import java.util.Arrays;
import java.util.zip.CRC32C;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * N-PAMP OPEN-layer reference: frame framing, CRC32C integrity, per-frame AEAD
 * nonce derivation, AES-256-GCM record layer, and the HKDF-Expand-Label key
 * schedule. Big-endian throughout. All cryptography uses the JDK providers.
 */
public final class Npamp {

    private Npamp() {
    }

    // -- Constants ---------------------------------------------------------

    public static final int HEADER_SIZE = 36;
    public static final int PROTOCOL_VERSION = 0x2;
    public static final byte[] MAGIC = {'N', 'P', 'A', 'M'}; // ASCII "NPAM" = 0x4E50414D
    public static final String ALPN = "n-pamp/2";
    public static final String LABEL_PREFIX = "n-pamp "; // protocol-specific; NOT "tls13 "

    public static final int FLAG_URG = 0x01, FLAG_ENC = 0x02, FLAG_COMP = 0x04, FLAG_FRAG = 0x08;

    public static final int CHAN_CONTROL = 0x0000, CHAN_MEMORY = 0x0001, CHAN_IMMUNE = 0x0005,
            CHAN_AUDIT = 0x000B, CHAN_BRIDGE = 0x000D, CHAN_SPATIAL = 0x0013;
    public static final int FRAME_PING = 0x0001, FRAME_PONG = 0x0002, FRAME_CLOSE = 0x0003,
            FRAME_FLOW_UPDATE = 0x000A, CHANNEL_SPECIFIC_BASE = 0x0100;
    public static final int TLV_PROFILE_OFFER = 0x01, TLV_KEM_CIPHERTEXT = 0x08, TLV_ANOMALY_CHARGE = 0x12;
    public static final int KEM_X25519_MLKEM768 = 0x11ec, KEM_X25519_MLKEM1024 = 0x11ed;
    public static final int AEAD_AES256_GCM = 0x0001, AEAD_CHACHA20_POLY1305 = 0x0002;
    public static final int SIG_ED25519 = 0x0807, SIG_MLDSA87 = 0x0905;

    // -- Errors ------------------------------------------------------------

    /** Raised when a wire frame fails structural or integrity validation. */
    public static final class FrameException extends RuntimeException {
        public FrameException(String message) {
            super(message);
        }
    }

    // -- CRC32C ------------------------------------------------------------

    /**
     * CRC32C (Castagnoli, reflected): poly 0x82F63B78, init 0xFFFFFFFF, final
     * xor 0xFFFFFFFF. Delegates to java.util.zip.CRC32C, which produces exactly
     * this value. Returned as an unsigned 32-bit value held in a long.
     */
    public static long crc32c(byte[] data) {
        CRC32C c = new CRC32C();
        c.update(data, 0, data.length);
        return c.getValue();
    }

    // -- Big-endian helpers ------------------------------------------------

    private static void putU16BE(byte[] buf, int off, int v) {
        buf[off] = (byte) ((v >>> 8) & 0xFF);
        buf[off + 1] = (byte) (v & 0xFF);
    }

    private static void putU32BE(byte[] buf, int off, long v) {
        buf[off] = (byte) ((v >>> 24) & 0xFF);
        buf[off + 1] = (byte) ((v >>> 16) & 0xFF);
        buf[off + 2] = (byte) ((v >>> 8) & 0xFF);
        buf[off + 3] = (byte) (v & 0xFF);
    }

    private static void putU64BE(byte[] buf, int off, long v) {
        for (int i = 0; i < 8; i++) {
            buf[off + i] = (byte) ((v >>> (56 - 8 * i)) & 0xFF);
        }
    }

    private static int getU16BE(byte[] buf, int off) {
        return ((buf[off] & 0xFF) << 8) | (buf[off + 1] & 0xFF);
    }

    private static long getU32BE(byte[] buf, int off) {
        return ((long) (buf[off] & 0xFF) << 24) | ((buf[off + 1] & 0xFF) << 16)
                | ((buf[off + 2] & 0xFF) << 8) | (buf[off + 3] & 0xFF);
    }

    private static long getU64BE(byte[] buf, int off) {
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v = (v << 8) | (buf[off + i] & 0xFF);
        }
        return v;
    }

    // -- Frame -------------------------------------------------------------

    /**
     * A single N-PAMP wire frame: a 36-octet header followed by an opaque
     * payload. {@code seq} and {@code epoch} carry unsigned 64-bit values in a
     * Java long; only the bit pattern is wire-significant.
     */
    public static final class Frame {
        public int version;
        public int flags;
        public int ftype;
        public int channel;
        public long seq;
        public byte[] payload;

        public Frame() {
            this(0, 0, 0L, 0, 0, new byte[0]);
        }

        public Frame(int ftype, int channel) {
            this(ftype, channel, 0L, 0, 0, new byte[0]);
        }

        public Frame(int ftype, int channel, long seq, int flags, int version, byte[] payload) {
            this.ftype = ftype;
            this.channel = channel;
            this.seq = seq;
            this.flags = flags;
            this.version = version;
            this.payload = payload != null ? payload : new byte[0];
        }

        /**
         * Builds octets [0:21]: MAGIC, (version&lt;&lt;4)|flags, frameType,
         * channel, seq, payloadLen. When {@code version} is 0 the protocol
         * default (0x2) is substituted. This 21-octet prefix is exactly the
         * AEAD associated data.
         */
        public byte[] headerPrefix(long payloadLen) {
            int ver = version != 0 ? version : PROTOCOL_VERSION;
            byte[] out = new byte[21];
            System.arraycopy(MAGIC, 0, out, 0, 4);
            out[4] = (byte) ((ver << 4) | (flags & 0x0F));
            putU16BE(out, 5, ftype);
            putU16BE(out, 7, channel);
            putU64BE(out, 9, seq);
            putU32BE(out, 17, payloadLen);
            return out;
        }

        /** Serialises the frame: prefix || CRC32C(prefix) || 11 zero octets || payload. */
        public byte[] marshal() {
            byte[] prefix = headerPrefix(payload.length);
            byte[] out = new byte[HEADER_SIZE + payload.length];
            System.arraycopy(prefix, 0, out, 0, 21);
            putU32BE(out, 21, crc32c(prefix));
            // octets 25..36 reserved, already zero
            System.arraycopy(payload, 0, out, HEADER_SIZE, payload.length);
            return out;
        }

        /**
         * Parses a wire frame. Validation order: CRC32C first, then magic, then
         * version, then reserved-all-zero, then payload-length agreement.
         */
        public static Frame unmarshal(byte[] buf) {
            if (buf.length < HEADER_SIZE) {
                throw new FrameException("short header");
            }
            long got = getU32BE(buf, 21);
            if (got != crc32c(Arrays.copyOfRange(buf, 0, 21))) {
                throw new FrameException("bad crc");
            }
            for (int i = 0; i < 4; i++) {
                if (buf[i] != MAGIC[i]) {
                    throw new FrameException("bad magic");
                }
            }
            int ver = (buf[4] & 0xFF) >>> 4;
            if (ver != PROTOCOL_VERSION) {
                throw new FrameException("bad version");
            }
            for (int i = 25; i < HEADER_SIZE; i++) {
                if (buf[i] != 0) {
                    throw new FrameException("reserved nonzero");
                }
            }
            long plen = getU32BE(buf, 17);
            if (plen != buf.length - HEADER_SIZE) {
                throw new FrameException("length mismatch");
            }
            Frame f = new Frame();
            f.version = ver;
            f.flags = buf[4] & 0x0F;
            f.ftype = getU16BE(buf, 5);
            f.channel = getU16BE(buf, 7);
            f.seq = getU64BE(buf, 9);
            f.payload = Arrays.copyOfRange(buf, HEADER_SIZE, buf.length);
            return f;
        }
    }

    // -- AEAD record layer -------------------------------------------------

    /**
     * Per-frame AEAD nonce (draft-00 7.5): a 12-octet buffer holding the seq as
     * a big-endian u64 in bytes [4:12], XORed with the 12-octet IV. The channel
     * ID is NOT part of the nonce.
     */
    public static byte[] deriveNonce(byte[] iv, long seq) {
        byte[] n = new byte[12];
        putU64BE(n, 4, seq);
        for (int i = 0; i < 12; i++) {
            n[i] ^= iv[i];
        }
        return n;
    }

    /**
     * AES-256-GCM seal. Returns ciphertext||tag (16-octet tag). The associated
     * data is the 21-octet header prefix.
     */
    public static byte[] sealAes256Gcm(byte[] key, byte[] iv, long seq, byte[] aad, byte[] pt) {
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(128, deriveNonce(iv, seq));
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
            c.updateAAD(aad);
            return c.doFinal(pt);
        } catch (Exception e) {
            throw new RuntimeException("aes-256-gcm seal failed", e);
        }
    }

    /**
     * AES-256-GCM open. Accepts ciphertext||tag and verifies the tag against
     * the supplied associated data; throws on authentication failure.
     */
    public static byte[] openAes256Gcm(byte[] key, byte[] iv, long seq, byte[] aad, byte[] sealed) {
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(128, deriveNonce(iv, seq));
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
            c.updateAAD(aad);
            return c.doFinal(sealed);
        } catch (Exception e) {
            throw new RuntimeException("aes-256-gcm open failed", e);
        }
    }

    // -- Key schedule (HKDF-Extract / HKDF-Expand / HKDF-Expand-Label) ------

    /**
     * HKDF-Extract (RFC 5869, section 2.2): PRK = HMAC-Hash(salt, IKM). {@code standard}
     * selects SHA-256 (true, HmacSHA256) or SHA-384 (false, HmacSHA384). Per RFC 5869 a
     * null/empty salt is replaced with HashLen zero octets. Exposed for the handshake-secret
     * ladder and for independent KAT against RFC 5869 HKDF-Extract vectors.
     */
    public static byte[] hkdfExtract(byte[] salt, byte[] ikm, boolean standard) {
        try {
            String macAlg = standard ? "HmacSHA256" : "HmacSHA384";
            Mac mac = Mac.getInstance(macAlg);
            byte[] key = (salt == null || salt.length == 0) ? new byte[mac.getMacLength()] : salt;
            mac.init(new SecretKeySpec(key, macAlg));
            return mac.doFinal(ikm);
        } catch (Exception e) {
            throw new RuntimeException("hkdf-extract failed", e);
        }
    }

    /**
     * HKDF-Expand (RFC 5869, section 2.3), expand step only: the supplied secret
     * IS the PRK, so HKDF-Extract is not run. The hash is selected by the caller
     * (HmacSHA256 or HmacSHA384).
     */
    private static byte[] hkdfExpand(String macAlg, byte[] prk, byte[] info, int length) {
        try {
            Mac mac = Mac.getInstance(macAlg);
            int hashLen = mac.getMacLength();
            int n = (length + hashLen - 1) / hashLen;
            byte[] out = new byte[n * hashLen];
            byte[] t = new byte[0];
            int pos = 0;
            for (int i = 1; i <= n; i++) {
                mac.init(new SecretKeySpec(prk, macAlg));
                mac.update(t);
                mac.update(info);
                mac.update((byte) i);
                t = mac.doFinal();
                System.arraycopy(t, 0, out, pos, hashLen);
                pos += hashLen;
            }
            return Arrays.copyOfRange(out, 0, length);
        } catch (Exception e) {
            throw new RuntimeException("hkdf-expand failed", e);
        }
    }

    /**
     * HKDF-Expand (RFC 5869, section 2.3), expand step only: the supplied secret
     * IS the PRK, so HKDF-Extract is not run. {@code standard} selects SHA-256
     * (true, HmacSHA256) or SHA-384 (false, HmacSHA384). Exposed for independent
     * KAT against RFC 5869 / Wycheproof HKDF-Expand vectors.
     */
    public static byte[] hkdfExpand(byte[] prk, byte[] info, int length, boolean standard) {
        return hkdfExpand(standard ? "HmacSHA256" : "HmacSHA384", prk, info, length);
    }

    /**
     * HKDF-Expand-Label (draft-00 7.4). full = LABEL_PREFIX + label.
     * info = u16(length) || u8(len(full)) || full || u8(len(context)) || context.
     * {@code standard} selects SHA-256 (true) or SHA-384 (false).
     */
    public static byte[] hkdfExpandLabel(byte[] secret, String label, byte[] context, int length, boolean standard) {
        byte[] full = (LABEL_PREFIX + label).getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] info = new byte[2 + 1 + full.length + 1 + context.length];
        int p = 0;
        info[p++] = (byte) ((length >>> 8) & 0xFF);
        info[p++] = (byte) (length & 0xFF);
        info[p++] = (byte) full.length;
        System.arraycopy(full, 0, info, p, full.length);
        p += full.length;
        info[p++] = (byte) context.length;
        System.arraycopy(context, 0, info, p, context.length);
        return hkdfExpand(secret, info, length, standard);
    }

    /**
     * Derives a directional traffic secret.
     * context = dir(1) || epoch(8 BE) || suite(2 BE) || channel(2 BE);
     * output length 32 (SHA-256) or 48 (SHA-384); label "traffic".
     */
    public static byte[] deriveTrafficSecret(byte[] master, int dir, long epoch, int suite, int channel, boolean standard) {
        byte[] ctx = new byte[1 + 8 + 2 + 2];
        ctx[0] = (byte) dir;
        putU64BE(ctx, 1, epoch);
        putU16BE(ctx, 9, suite);
        putU16BE(ctx, 11, channel);
        int hlen = standard ? 32 : 48;
        return hkdfExpandLabel(master, "traffic", ctx, hlen, standard);
    }

    /** Derives the {key(32), iv(12)} pair from a traffic secret. */
    public static byte[][] deriveKeyIv(byte[] secret, boolean standard) {
        byte[] key = hkdfExpandLabel(secret, "key", new byte[0], 32, standard);
        byte[] iv = hkdfExpandLabel(secret, "iv", new byte[0], 12, standard);
        return new byte[][]{key, iv};
    }

    // -- Hex utility -------------------------------------------------------

    /** Lowercase hex encoding, used by the vector generator and tests. */
    public static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(Character.forDigit((b >>> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
