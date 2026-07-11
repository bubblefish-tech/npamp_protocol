// Standards-derived, NON-CIRCULAR known-answer test for the draft-00 CertVerify
// (binding spec/10 section 6.1; RFC 8446 section 4.4.3 structure; Ed25519 per RFC 8032).
// The value is u16(0x0807) || Ed25519(priv, signing_input), signing_input =
// 64*0x20 || context || 0x00 || TH. Java mirror of the Go/TS/Python reference tests
// against the SAME pinned vector (test-vectors/v1/certverify-kat.json).
//
// Three legs: ANCHOR (the src Ed25519 helpers reproduce RFC 8032 TEST1/TEST2 keys +
// signatures), ORACLE (rebuild signing_input by hand + sign with an independently
// constructed key, no src signing functions), IMPL (certVerifySigningInput +
// signCertVerify reproduce the vector; verifyCertVerify accepts the correct value but
// rejects a role/context mismatch, a wrong transcript, a wrong scheme, and a truncated
// signature). Run via:
//   javac -d <out> src/main/java/sh/bubblefish/npamp/*.java src/test/java/sh/bubblefish/npamp/*.java
//   java  -cp <out> sh.bubblefish.npamp.CertVerifyKat
package sh.bubblefish.npamp;

import static sh.bubblefish.npamp.Kat.fromHex;
import static sh.bubblefish.npamp.Kat.sat;
import static sh.bubblefish.npamp.Kat.toHex;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public final class CertVerifyKat {

    private CertVerifyKat() {
    }

    static final String CERTVERIFY_KAT_SHA256 = "19afd438c3036fd7d51481e5e6e91cc73010d76cb94aa2082c7752c8ba714d3f";

    private static int failures = 0;

    private static void check(String name, boolean ok, String detail) {
        if (ok) {
            System.out.println("ok   - " + name);
        } else {
            System.out.println("FAIL - " + name + (detail.isEmpty() ? "" : ": " + detail));
            failures++;
        }
    }

    /** Oracle signing input, built by hand independently of certVerifySigningInput. */
    private static byte[] oracleSigningInput(String ctx, byte[] th) {
        byte[] c = ctx.getBytes(StandardCharsets.US_ASCII);
        byte[] out = new byte[64 + c.length + 1 + th.length];
        int p = 0;
        for (int i = 0; i < 64; i++) {
            out[p++] = 0x20;
        }
        System.arraycopy(c, 0, out, p, c.length);
        p += c.length;
        out[p++] = 0x00;
        System.arraycopy(th, 0, out, p, th.length);
        return out;
    }

    private static byte[] oracleSign(PrivateKey priv, byte[] msg) {
        try {
            Signature s = Signature.getInstance("Ed25519");
            s.initSign(priv);
            s.update(msg);
            return s.sign();
        } catch (Exception e) {
            throw new RuntimeException("oracle ed25519 sign failed", e);
        }
    }

    /** ANCHOR: the src Ed25519 helpers reproduce RFC 8032 TEST1/TEST2 pubkeys + signatures. */
    private static void anchor(Object root) {
        for (String tc : new String[]{"test1", "test2"}) {
            byte[] seed = fromHex(sat(root, "rfc8032_ed25519", tc, "seed"));
            byte[] msg = fromHex(sat(root, "rfc8032_ed25519", tc, "message"));
            String wantPub = sat(root, "rfc8032_ed25519", tc, "public_key");
            String wantSig = sat(root, "rfc8032_ed25519", tc, "signature");

            PrivateKey priv = Handshake.ed25519PrivateKeyFromSeed(seed);
            byte[] sig = oracleSign(priv, msg);
            check("anchor: RFC 8032 " + tc + " signature", toHex(sig).equals(wantSig),
                    "got " + toHex(sig) + " want " + wantSig);

            // ed25519PublicKeyFromRaw decodes the published raw pubkey and verifies the
            // published signature, proving the raw-point decoder round-trips (RFC 8032).
            PublicKey pub = Handshake.ed25519PublicKeyFromRaw(fromHex(wantPub));
            boolean verified;
            try {
                Signature v = Signature.getInstance("Ed25519");
                v.initVerify(pub);
                v.update(msg);
                verified = v.verify(fromHex(wantSig));
            } catch (Exception e) {
                verified = false;
            }
            check("anchor: RFC 8032 " + tc + " pubkey-from-raw verifies", verified, "");
        }
    }

    /** ORACLE: rebuild signing_input by hand + sign with an independent key (guards the vector). */
    private static void oracle(Object root) {
        String[][] cases = {
                {"server", "server", "server_seed", "th_sid", "signing_input_server", "signature_server"},
                {"client", "client", "client_seed", "th_cid", "signing_input_client", "signature_client"},
        };
        for (String[] c : cases) {
            String ctx = sat(root, "contexts", c[1]);
            byte[] seed = fromHex(sat(root, "npamp_inputs", c[2]));
            byte[] th = fromHex(sat(root, "npamp_inputs", c[3]));
            byte[] si = oracleSigningInput(ctx, th);
            check("oracle: " + c[0] + " signing_input", toHex(si).equals(sat(root, "expected", c[4])),
                    "got " + toHex(si));
            byte[] sig = oracleSign(Handshake.ed25519PrivateKeyFromSeed(seed), si);
            check("oracle: " + c[0] + " signature", toHex(sig).equals(sat(root, "expected", c[5])),
                    "got " + toHex(sig));
        }
    }

    /** IMPL: certVerifySigningInput + signCertVerify reproduce the vector; verifyCertVerify guards. */
    private static void impl(Object root) {
        if (!Handshake.CONTEXT_SERVER_CERTVERIFY.equals(sat(root, "contexts", "server"))
                || !Handshake.CONTEXT_CLIENT_CERTVERIFY.equals(sat(root, "contexts", "client"))) {
            check("impl: context constants match spec section 6.1", false,
                    "server=" + Handshake.CONTEXT_SERVER_CERTVERIFY + " client=" + Handshake.CONTEXT_CLIENT_CERTVERIFY);
            return;
        }
        Object[][] cases = {
                {"server", Boolean.TRUE, "server_seed", "server_pub", "th_sid", "signing_input_server", "certverify_value_server"},
                {"client", Boolean.FALSE, "client_seed", "client_pub", "th_cid", "signing_input_client", "certverify_value_client"},
        };
        for (Object[] c : cases) {
            String name = (String) c[0];
            boolean isServer = (Boolean) c[1];
            PrivateKey priv = Handshake.ed25519PrivateKeyFromSeed(fromHex(sat(root, "npamp_inputs", (String) c[2])));
            PublicKey pub = Handshake.ed25519PublicKeyFromRaw(fromHex(sat(root, "npamp_inputs", (String) c[3])));
            byte[] th = fromHex(sat(root, "npamp_inputs", (String) c[4]));

            String gotSI = toHex(Handshake.certVerifySigningInput(isServer, th));
            check("impl: " + name + " certVerifySigningInput", gotSI.equals(sat(root, "expected", (String) c[5])),
                    "got " + gotSI);

            byte[] val = Handshake.signCertVerify(priv, isServer, th);
            check("impl: " + name + " signCertVerify value", toHex(val).equals(sat(root, "expected", (String) c[6])),
                    "got " + toHex(val));

            check("impl: " + name + " verifyCertVerify accepts",
                    Handshake.verifyCertVerify(pub, isServer, th, val), "");

            // Domain separation: the opposite role must FAIL (different context string).
            check("impl: " + name + " rejects role/context mismatch",
                    !Handshake.verifyCertVerify(pub, !isServer, th, val), "");

            // Transcript binding: a different transcript hash must FAIL.
            byte[] wrongTh = th.clone();
            wrongTh[0] ^= 0x01;
            check("impl: " + name + " rejects wrong transcript",
                    !Handshake.verifyCertVerify(pub, isServer, wrongTh, val), "");

            // Scheme guard: a non-Ed25519 scheme code point must FAIL.
            byte[] badScheme = val.clone();
            badScheme[0] = (byte) ((Npamp.SIG_MLDSA87 >>> 8) & 0xFF);
            badScheme[1] = (byte) (Npamp.SIG_MLDSA87 & 0xFF);
            check("impl: " + name + " rejects non-Ed25519 scheme",
                    !Handshake.verifyCertVerify(pub, isServer, th, badScheme), "");

            // Length guard: an Ed25519 signature is exactly 64 octets; a truncated value must FAIL.
            byte[] truncated = new byte[val.length - 1];
            System.arraycopy(val, 0, truncated, 0, truncated.length);
            check("impl: " + name + " rejects truncated signature",
                    !Handshake.verifyCertVerify(pub, isServer, th, truncated), "");
        }
    }

    public static void main(String[] args) throws Exception {
        Object root = Kat.loadPinned(args, "certverify-kat.json", CERTVERIFY_KAT_SHA256);
        anchor(root);
        oracle(root);
        impl(root);
        System.out.println(failures == 0 ? "ALL PASS (certverify KAT: anchor+oracle+impl)" : ("FAILURES: " + failures));
        System.exit(failures == 0 ? 0 : 1);
    }
}
