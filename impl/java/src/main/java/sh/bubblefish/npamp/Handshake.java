// Open reference implementation of the N-PAMP wire format (draft-bubblefish-npamp-00).
// Handshake binding layer (binding spec/10): transcript construction, Finished MAC,
// CertVerify signature. No proprietary methods, parameters, or weights.
package sh.bubblefish.npamp;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * N-PAMP draft-00 handshake binding layer (binding spec/10): the transcript hash
 * (section 3), the Finished MAC (section 6.2; RFC 8446 section 4.4.4), and the
 * CertVerify signature (section 6.1; RFC 8446 section 4.4.3 structure; Ed25519 per
 * RFC 8032). Big-endian throughout. All cryptography uses the JDK providers.
 */
public final class Handshake {

    private Handshake() {
    }

    // -- Constants ---------------------------------------------------------

    /** Handshake frame types (binding spec/10 section 1), carried on the control channel. */
    public static final int FRAME_CLIENT_HELLO = 0x0100, FRAME_SERVER_HELLO = 0x0101,
            FRAME_SERVER_AUTH = 0x0102, FRAME_CLIENT_AUTH = 0x0103;

    /** CertVerify role context strings (binding spec/10 section 6.1). */
    public static final String CONTEXT_SERVER_CERTVERIFY = "N-PAMP draft-00, server CertificateVerify";
    public static final String CONTEXT_CLIENT_CERTVERIFY = "N-PAMP draft-00, client CertificateVerify";

    // -- Big-endian helpers ------------------------------------------------

    private static byte[] u16be(int v) {
        return new byte[]{(byte) ((v >>> 8) & 0xFF), (byte) (v & 0xFF)};
    }

    private static int getU16BE(byte[] buf, int off) {
        return ((buf[off] & 0xFF) << 8) | (buf[off + 1] & 0xFF);
    }

    // -- Transcript (binding spec/10 section 3) ----------------------------

    /**
     * Accumulates the draft-00 handshake transcript (binding spec/10 section 3) and
     * hashes it at a cut point. Absorption granularity is per-TLV: {@link #addFrameType}
     * appends the 2-octet frame type ONLY (NOT the rest of the 36-octet frame header —
     * the spec section 3 / 7.1 divergence from RFC 8446 section 4.4.1); {@link #addTLV}
     * appends Type(2 BE) || Length(2 BE) || Value. A transcript point = the hash over all
     * bytes absorbed so far (SHA-256 at Standard, SHA-384 at High/Sovereign).
     */
    public static final class Transcript {
        private final ByteArrayOutputStream buf = new ByteArrayOutputStream();

        /** Appends the frame type as exactly 2 octets big-endian. */
        public void addFrameType(int ft) {
            buf.writeBytes(u16be(ft & 0xFFFF));
        }

        /** Appends one TLV: Type(2 BE) || Length(2 BE) || Value. */
        public void addTLV(int type, byte[] value) {
            buf.writeBytes(u16be(type & 0xFFFF));
            buf.writeBytes(u16be(value.length));
            buf.writeBytes(value);
        }

        /** Hashes every octet absorbed so far (SHA-256 when {@code standard}, else SHA-384). */
        public byte[] hash(boolean standard) {
            try {
                MessageDigest md = MessageDigest.getInstance(standard ? "SHA-256" : "SHA-384");
                return md.digest(buf.toByteArray());
            } catch (Exception e) {
                throw new RuntimeException("transcript hash failed", e);
            }
        }
    }

    // -- Finished (binding spec/10 section 6.2; RFC 8446 section 4.4.4) -----

    /**
     * Finished verify_data = HMAC(finished_key, transcript_hash) under the profile hash
     * (HmacSHA256 at Standard, HmacSHA384 at High/Sovereign).
     */
    public static byte[] computeFinished(byte[] finishedKey, byte[] transcriptHash, boolean standard) {
        try {
            String alg = standard ? "HmacSHA256" : "HmacSHA384";
            Mac mac = Mac.getInstance(alg);
            mac.init(new SecretKeySpec(finishedKey, alg));
            return mac.doFinal(transcriptHash);
        } catch (Exception e) {
            throw new RuntimeException("finished MAC failed", e);
        }
    }

    /**
     * Recomputes the Finished MAC and constant-time-compares it to the received
     * verify_data. {@link MessageDigest#isEqual} is time-independent and returns false on
     * a length mismatch.
     */
    public static boolean verifyFinished(byte[] finishedKey, byte[] transcriptHash, byte[] verifyData, boolean standard) {
        return MessageDigest.isEqual(computeFinished(finishedKey, transcriptHash, standard), verifyData);
    }

    // -- Ed25519 key decoding (RFC 8032) -----------------------------------

    /** Builds an Ed25519 private key from its raw 32-octet seed (RFC 8032). */
    public static PrivateKey ed25519PrivateKeyFromSeed(byte[] seed) {
        try {
            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            return kf.generatePrivate(new EdECPrivateKeySpec(NamedParameterSpec.ED25519, seed));
        } catch (Exception e) {
            throw new RuntimeException("ed25519 private key from seed failed", e);
        }
    }

    /**
     * Builds an Ed25519 public key from its raw 32-octet encoding (RFC 8032 section 5.1.2):
     * the y-coordinate as a little-endian integer with the high bit of the last octet
     * carrying the sign (LSB) of x. Reverse to big-endian, extract and clear that sign bit,
     * then construct the EdECPoint.
     */
    public static PublicKey ed25519PublicKeyFromRaw(byte[] raw) {
        try {
            if (raw.length != 32) {
                throw new IllegalArgumentException("ed25519 public key must be 32 octets, got " + raw.length);
            }
            byte[] le = raw.clone();
            boolean xOdd = (le[le.length - 1] & 0x80) != 0;
            le[le.length - 1] &= 0x7F; // clear the x-sign bit to recover y
            byte[] be = new byte[le.length];
            for (int i = 0; i < le.length; i++) {
                be[i] = le[le.length - 1 - i];
            }
            BigInteger y = new BigInteger(1, be);
            EdECPoint point = new EdECPoint(xOdd, y);
            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            return kf.generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED25519, point));
        } catch (Exception e) {
            throw new RuntimeException("ed25519 public key from raw failed", e);
        }
    }

    // -- CertVerify (binding spec/10 section 6.1; RFC 8446 section 4.4.3) ---

    /**
     * The section 6.1 signing input: 64 octets of 0x20, the role context string, a 0x00
     * separator, then the transcript hash — TLS-1.3-style domain separation
     * (RFC 8446 section 4.4.3).
     */
    public static byte[] certVerifySigningInput(boolean isServer, byte[] transcriptHash) {
        byte[] ctx = (isServer ? CONTEXT_SERVER_CERTVERIFY : CONTEXT_CLIENT_CERTVERIFY)
                .getBytes(StandardCharsets.US_ASCII);
        byte[] out = new byte[64 + ctx.length + 1 + transcriptHash.length];
        int p = 0;
        for (int i = 0; i < 64; i++) {
            out[p++] = 0x20;
        }
        System.arraycopy(ctx, 0, out, p, ctx.length);
        p += ctx.length;
        out[p++] = 0x00;
        System.arraycopy(transcriptHash, 0, out, p, transcriptHash.length);
        return out;
    }

    /**
     * The CertVerify TLV value: u16(0x0807, Ed25519) || Ed25519(priv, signing_input).
     */
    public static byte[] signCertVerify(PrivateKey privateKey, boolean isServer, byte[] transcriptHash) {
        try {
            Signature s = Signature.getInstance("Ed25519");
            s.initSign(privateKey);
            s.update(certVerifySigningInput(isServer, transcriptHash));
            byte[] sig = s.sign();
            byte[] scheme = u16be(Npamp.SIG_ED25519);
            byte[] out = new byte[scheme.length + sig.length];
            System.arraycopy(scheme, 0, out, 0, scheme.length);
            System.arraycopy(sig, 0, out, scheme.length, sig.length);
            return out;
        } catch (Exception e) {
            throw new RuntimeException("certverify sign failed", e);
        }
    }

    /**
     * Checks a CertVerify TLV value against the signer's public key, role, and transcript
     * hash. Rejects a non-Ed25519 scheme, a wrong-length (non-64-octet) signature, a
     * role/context mismatch, or a wrong transcript.
     */
    public static boolean verifyCertVerify(PublicKey publicKey, boolean isServer, byte[] transcriptHash, byte[] value) {
        if (value.length < 2 || getU16BE(value, 0) != Npamp.SIG_ED25519) {
            return false;
        }
        byte[] sig = new byte[value.length - 2];
        System.arraycopy(value, 2, sig, 0, sig.length);
        if (sig.length != 64) { // Ed25519 signatures are exactly 64 octets (RFC 8032 section 5.1.6)
            return false;
        }
        try {
            Signature s = Signature.getInstance("Ed25519");
            s.initVerify(publicKey);
            s.update(certVerifySigningInput(isServer, transcriptHash));
            return s.verify(sig);
        } catch (Exception e) {
            return false;
        }
    }

    // -- Key schedule ladder (binding spec/10 section 5) -------------------

    /**
     * Derives the draft-00 handshake_secret (binding spec/10 section 5; ADR-0005):
     * HKDF-Extract(salt = HashLen zero octets, IKM = ML-KEM_SS || X25519_SS). The two KEM
     * shared secrets are concatenated ML-KEM-FIRST (ADR-0005). {@code standard} selects the
     * SHA-256 profile (true, 32-octet zero salt) or SHA-384 (false, 48-octet zero salt).
     */
    public static byte[] deriveHandshakeSecret(byte[] mlkemSharedSecret, byte[] x25519SharedSecret, boolean standard) {
        int hashLen = standard ? 32 : 48;
        byte[] ikm = new byte[mlkemSharedSecret.length + x25519SharedSecret.length];
        System.arraycopy(mlkemSharedSecret, 0, ikm, 0, mlkemSharedSecret.length);
        System.arraycopy(x25519SharedSecret, 0, ikm, mlkemSharedSecret.length, x25519SharedSecret.length);
        return Npamp.hkdfExtract(new byte[hashLen], ikm, standard);
    }

    /**
     * Derives the client handshake traffic secret c_hs (binding spec/10 section 5):
     * HKDF-Expand-Label(handshake_secret, "c hs", TH_KEM, HashLen).
     */
    public static byte[] deriveClientHandshakeSecret(byte[] handshakeSecret, byte[] thKem, boolean standard) {
        return Npamp.hkdfExpandLabel(handshakeSecret, "c hs", thKem, standard ? 32 : 48, standard);
    }

    /**
     * Derives the server handshake traffic secret s_hs (binding spec/10 section 5):
     * HKDF-Expand-Label(handshake_secret, "s hs", TH_KEM, HashLen).
     */
    public static byte[] deriveServerHandshakeSecret(byte[] handshakeSecret, byte[] thKem, boolean standard) {
        return Npamp.hkdfExpandLabel(handshakeSecret, "s hs", thKem, standard ? 32 : 48, standard);
    }

    /**
     * Derives the master secret (binding spec/10 section 5):
     * HKDF-Expand-Label(handshake_secret, "master", TH_CCV, HashLen).
     */
    public static byte[] deriveMasterSecret(byte[] handshakeSecret, byte[] thCcv, boolean standard) {
        return Npamp.hkdfExpandLabel(handshakeSecret, "master", thCcv, standard ? 32 : 48, standard);
    }

    /**
     * Derives a Finished key (binding spec/10 section 6.2 / section 5.4):
     * HKDF-Expand-Label(secret, "finished", empty-context, HashLen). The client Finished key
     * derives from c_hs; the server Finished key derives from s_hs.
     */
    public static byte[] deriveFinishedKey(byte[] secret, boolean standard) {
        return Npamp.hkdfExpandLabel(secret, "finished", new byte[0], standard ? 32 : 48, standard);
    }
}
