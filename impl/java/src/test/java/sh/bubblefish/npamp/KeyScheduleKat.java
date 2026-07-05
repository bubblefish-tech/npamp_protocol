// Standards-derived, NON-CIRCULAR known-answer test for the draft-00 key schedule
// (binding spec/10 section 5; draft-00 section 7.4 HKDF-Expand-Label + section 7.5 traffic
// keys). Java mirror of the Go/TS/Python reference tests against the SAME pinned vector
// (test-vectors/v1/key-schedule-kat.json).
//
// Three legs:
//   ANCHOR - prove raw HKDF-Extract/Expand (both the impl primitives and the in-test
//            oracle primitives) against RFC 5869 Appendix A.1 TC1.
//   ORACLE - prove an INDEPENDENT in-test HKDF-Expand-Label (it reconstructs the HkdfLabel
//            bytes itself, with the prefix as a PARAMETER, and never calls the impl's
//            hkdfExpandLabel) against RFC 8448 section 3 with the "tls13 " prefix.
//   IMPL   - run the new impl functions (deriveHandshakeSecret, deriveClient/ServerHandshakeSecret,
//            deriveMasterSecret, deriveFinishedKey, plus the existing deriveTrafficSecret/
//            deriveKeyIv) and compare every result to the proven ORACLE applied with the
//            "n-pamp " prefix. The golden N-PAMP outputs are NOT hardcoded; they are computed
//            by the proven oracle, so the two must agree independently.
//
// Run via (from impl/java):
//   javac -d <out> src/main/java/sh/bubblefish/npamp/Npamp.java \
//                  src/main/java/sh/bubblefish/npamp/Handshake.java \
//                  src/test/java/sh/bubblefish/npamp/Kat.java \
//                  src/test/java/sh/bubblefish/npamp/KeyScheduleKat.java
//   java -cp <out> sh.bubblefish.npamp.KeyScheduleKat
package sh.bubblefish.npamp;

import static sh.bubblefish.npamp.Kat.at;
import static sh.bubblefish.npamp.Kat.fromHex;
import static sh.bubblefish.npamp.Kat.sat;
import static sh.bubblefish.npamp.Kat.toHex;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class KeyScheduleKat {

    private KeyScheduleKat() {
    }

    static final String KEY_SCHEDULE_KAT_SHA256 =
            "e108f5cfdf99a378d7b677792448c8046abf3c630fc23fd8ea2ccb3927f2691c";

    // AES-256-GCM = 0x0001 per registries/aead.csv (= the impl's AEAD_AES256_GCM =
    // npamp.AEADAES256GCM in the Go reference); 0x0002 is ChaCha20-Poly1305. The
    // §7.5 traffic context binds this AEAD code point.
    static final int SUITE_AES256_GCM = Npamp.AEAD_AES256_GCM;
    static final int DIR_SERVER_TO_CLIENT = 0x01;

    private static int failures = 0;

    private static void check(String name, boolean ok, String detail) {
        if (ok) {
            System.out.println("ok   - " + name);
        } else {
            System.out.println("FAIL - " + name + (detail.isEmpty() ? "" : ": " + detail));
            failures++;
        }
    }

    // -- Independent in-test oracle (no impl key-schedule calls) -----------

    /** SHA-256 HMAC, built directly on javax.crypto; the SHA-256-profile MAC. */
    private static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("oracle hmac failed", e);
        }
    }

    /** Independent HKDF-Extract (RFC 5869 section 2.2): PRK = HMAC-Hash(salt, IKM). */
    private static byte[] extractOracle(byte[] salt, byte[] ikm) {
        return hmac(salt, ikm);
    }

    /** Independent HKDF-Expand (RFC 5869 section 2.3) over SHA-256. */
    private static byte[] expandOracle(byte[] prk, byte[] info, int length) {
        final int hashLen = 32; // SHA-256
        int n = (length + hashLen - 1) / hashLen;
        byte[] out = new byte[n * hashLen];
        byte[] t = new byte[0];
        int pos = 0;
        for (int i = 1; i <= n; i++) {
            byte[] in = new byte[t.length + info.length + 1];
            System.arraycopy(t, 0, in, 0, t.length);
            System.arraycopy(info, 0, in, t.length, info.length);
            in[in.length - 1] = (byte) i;
            t = hmac(prk, in);
            System.arraycopy(t, 0, out, pos, hashLen);
            pos += hashLen;
        }
        return Arrays.copyOfRange(out, 0, length);
    }

    /**
     * Independent HKDF-Expand-Label (RFC 8446 section 7.1) with the label prefix as a
     * PARAMETER. Reconstructs HkdfLabel = uint16(length) || uint8(len(prefix+label)) ||
     * (prefix+label) || uint8(len(context)) || context straight from the spec, then runs
     * the independent HKDF-Expand. Never calls the impl's hkdfExpandLabel.
     */
    private static byte[] expandLabelOracle(byte[] secret, String prefix, String label, byte[] context, int length) {
        byte[] full = (prefix + label).getBytes(StandardCharsets.US_ASCII);
        byte[] info = new byte[2 + 1 + full.length + 1 + context.length];
        int p = 0;
        info[p++] = (byte) ((length >>> 8) & 0xFF);
        info[p++] = (byte) (length & 0xFF);
        info[p++] = (byte) full.length;
        System.arraycopy(full, 0, info, p, full.length);
        p += full.length;
        info[p++] = (byte) context.length;
        System.arraycopy(context, 0, info, p, context.length);
        return expandOracle(secret, info, length);
    }

    // -- ANCHOR ------------------------------------------------------------

    /** ANCHOR: raw HKDF-Extract/Expand reproduce RFC 5869 TC1 (impl primitives AND oracle). */
    private static void anchor(Object root) {
        byte[] ikm = fromHex(sat(root, "rfc5869_tc1", "ikm"));
        byte[] salt = fromHex(sat(root, "rfc5869_tc1", "salt"));
        byte[] info = fromHex(sat(root, "rfc5869_tc1", "info"));
        int len = ((Double) at(root, "rfc5869_tc1", "L")).intValue();
        String wantPrk = sat(root, "rfc5869_tc1", "prk");
        String wantOkm = sat(root, "rfc5869_tc1", "okm");

        String implPrk = toHex(Npamp.hkdfExtract(salt, ikm, true));
        check("anchor: RFC 5869 TC1 HKDF-Extract (impl)", implPrk.equals(wantPrk),
                "got " + implPrk + " want " + wantPrk);
        String implOkm = toHex(Npamp.hkdfExpand(fromHex(wantPrk), info, len, true));
        check("anchor: RFC 5869 TC1 HKDF-Expand (impl)", implOkm.equals(wantOkm),
                "got " + implOkm + " want " + wantOkm);

        String oraPrk = toHex(extractOracle(salt, ikm));
        check("anchor: RFC 5869 TC1 HKDF-Extract (oracle)", oraPrk.equals(wantPrk),
                "got " + oraPrk + " want " + wantPrk);
        String oraOkm = toHex(expandOracle(fromHex(wantPrk), info, len));
        check("anchor: RFC 5869 TC1 HKDF-Expand (oracle)", oraOkm.equals(wantOkm),
                "got " + oraOkm + " want " + wantOkm);
    }

    // -- ORACLE ------------------------------------------------------------

    /** ORACLE: the in-test HKDF-Expand-Label reproduces RFC 8448 with the "tls13 " prefix. */
    private static void oracle(Object root) {
        byte[] secret = fromHex(sat(root, "rfc8448_expand_label", "client_handshake_traffic_secret"));
        byte[] empty = new byte[0];

        String gotKey = toHex(expandLabelOracle(secret, "tls13 ", "key", empty, 16));
        check("oracle: RFC 8448 write_key (tls13 )", gotKey.equals(sat(root, "rfc8448_expand_label", "write_key")),
                "got " + gotKey);
        String gotIv = toHex(expandLabelOracle(secret, "tls13 ", "iv", empty, 12));
        check("oracle: RFC 8448 write_iv (tls13 )", gotIv.equals(sat(root, "rfc8448_expand_label", "write_iv")),
                "got " + gotIv);
        String gotFin = toHex(expandLabelOracle(secret, "tls13 ", "finished", empty, 32));
        check("oracle: RFC 8448 finished_key (tls13 )", gotFin.equals(sat(root, "rfc8448_expand_label", "finished_key")),
                "got " + gotFin);
    }

    // -- IMPL --------------------------------------------------------------

    /** Builds the traffic-secret context: dir(1) || epoch(8 BE) || suite(2 BE) || channel(2 BE). */
    private static byte[] trafficContext(int dir, long epoch, int suite, int channel) {
        byte[] ctx = new byte[1 + 8 + 2 + 2];
        ctx[0] = (byte) dir;
        for (int i = 0; i < 8; i++) {
            ctx[1 + i] = (byte) ((epoch >>> (56 - 8 * i)) & 0xFF);
        }
        ctx[9] = (byte) ((suite >>> 8) & 0xFF);
        ctx[10] = (byte) (suite & 0xFF);
        ctx[11] = (byte) ((channel >>> 8) & 0xFF);
        ctx[12] = (byte) (channel & 0xFF);
        return ctx;
    }

    /** IMPL: the new key-schedule functions agree with the proven oracle under the "n-pamp " prefix. */
    private static void impl(Object root) {
        // Inputs: two KEM shared secrets (IKM) and two transcript-hash inputs.
        byte[] mlkemSs = fromHex(sat(root, "npamp_inputs", "ikm_mlkem_ss"));
        byte[] x25519Ss = fromHex(sat(root, "npamp_inputs", "ikm_x25519_ss"));
        byte[] thKem = fromHex(sat(root, "npamp_inputs", "th_kem"));
        byte[] thCcv = fromHex(sat(root, "npamp_inputs", "th_ccv"));
        final byte[] empty = new byte[0];
        final byte[] zeros32 = new byte[32];
        final String pfx = Npamp.LABEL_PREFIX; // "n-pamp "

        // handshake_secret = HKDF-Extract(32 zero octets, ML-KEM_SS || X25519_SS).
        byte[] ikm = new byte[mlkemSs.length + x25519Ss.length];
        System.arraycopy(mlkemSs, 0, ikm, 0, mlkemSs.length);
        System.arraycopy(x25519Ss, 0, ikm, mlkemSs.length, x25519Ss.length);
        byte[] hsImpl = Handshake.deriveHandshakeSecret(mlkemSs, x25519Ss, true);
        byte[] hsOracle = extractOracle(zeros32, ikm);
        check("impl: handshake_secret", Arrays.equals(hsImpl, hsOracle),
                "impl " + toHex(hsImpl) + " oracle " + toHex(hsOracle));

        // c_hs / s_hs from TH_KEM; master from TH_CCV.
        byte[] cHsImpl = Handshake.deriveClientHandshakeSecret(hsImpl, thKem, true);
        byte[] cHsOracle = expandLabelOracle(hsOracle, pfx, "c hs", thKem, 32);
        check("impl: c_hs", Arrays.equals(cHsImpl, cHsOracle),
                "impl " + toHex(cHsImpl) + " oracle " + toHex(cHsOracle));

        byte[] sHsImpl = Handshake.deriveServerHandshakeSecret(hsImpl, thKem, true);
        byte[] sHsOracle = expandLabelOracle(hsOracle, pfx, "s hs", thKem, 32);
        check("impl: s_hs", Arrays.equals(sHsImpl, sHsOracle),
                "impl " + toHex(sHsImpl) + " oracle " + toHex(sHsOracle));

        byte[] masterImpl = Handshake.deriveMasterSecret(hsImpl, thCcv, true);
        byte[] masterOracle = expandLabelOracle(hsOracle, pfx, "master", thCcv, 32);
        check("impl: master", Arrays.equals(masterImpl, masterOracle),
                "impl " + toHex(masterImpl) + " oracle " + toHex(masterOracle));

        // finished_key: client from c_hs, server from s_hs.
        byte[] finCImpl = Handshake.deriveFinishedKey(cHsImpl, true);
        byte[] finCOracle = expandLabelOracle(cHsOracle, pfx, "finished", empty, 32);
        check("impl: finished_key(c_hs)", Arrays.equals(finCImpl, finCOracle),
                "impl " + toHex(finCImpl) + " oracle " + toHex(finCOracle));

        byte[] finSImpl = Handshake.deriveFinishedKey(sHsImpl, true);
        byte[] finSOracle = expandLabelOracle(sHsOracle, pfx, "finished", empty, 32);
        check("impl: finished_key(s_hs)", Arrays.equals(finSImpl, finSOracle),
                "impl " + toHex(finSImpl) + " oracle " + toHex(finSOracle));

        // s2c handshake AEAD via the existing deriveTrafficSecret/deriveKeyIv, from s_hs:
        // dir=ServerToClient, epoch=0, suite=AES-256-GCM=0x0001, channel=Control=0x0000.
        byte[] trafficImpl = Npamp.deriveTrafficSecret(sHsImpl, DIR_SERVER_TO_CLIENT, 0L,
                SUITE_AES256_GCM, Npamp.CHAN_CONTROL, true);
        byte[][] keyIvImpl = Npamp.deriveKeyIv(trafficImpl, true);

        byte[] ctx = trafficContext(DIR_SERVER_TO_CLIENT, 0L, SUITE_AES256_GCM, Npamp.CHAN_CONTROL);
        byte[] trafficOracle = expandLabelOracle(sHsOracle, pfx, "traffic", ctx, 32);
        byte[] keyOracle = expandLabelOracle(trafficOracle, pfx, "key", empty, 32);
        byte[] ivOracle = expandLabelOracle(trafficOracle, pfx, "iv", empty, 12);

        check("impl: s2c handshake key", Arrays.equals(keyIvImpl[0], keyOracle),
                "impl " + toHex(keyIvImpl[0]) + " oracle " + toHex(keyOracle));
        check("impl: s2c handshake iv", Arrays.equals(keyIvImpl[1], ivOracle),
                "impl " + toHex(keyIvImpl[1]) + " oracle " + toHex(ivOracle));
    }

    public static void main(String[] args) throws Exception {
        Object root = Kat.loadPinned(args, "key-schedule-kat.json", KEY_SCHEDULE_KAT_SHA256);
        anchor(root);
        oracle(root);
        impl(root);
        System.out.println(failures == 0
                ? "ALL PASS (key-schedule KAT: anchor+oracle+impl)"
                : ("FAILURES: " + failures));
        System.exit(failures == 0 ? 0 : 1);
    }
}
