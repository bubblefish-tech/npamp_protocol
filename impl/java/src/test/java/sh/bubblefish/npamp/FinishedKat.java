// Standards-derived, NON-CIRCULAR known-answer test for the draft-00 Finished verify_data
// (binding spec/10 section 6.2; RFC 8446 section 4.4.4): verify_data =
// HMAC(finished_key, transcript_hash) under the profile hash (SHA-256 at Standard). Java
// mirror of the Go/TS/Python reference tests against the SAME pinned vector
// (test-vectors/v1/finished-kat.json).
//
// Three legs: ANCHOR (HMAC-SHA-256 reproduces RFC 4231 TC1/TC2), ORACLE (independent
// javax.crypto.Mac, no computeFinished), IMPL (computeFinished + verifyFinished
// accept/reject). Run via:
//   javac -d <out> src/main/java/sh/bubblefish/npamp/*.java src/test/java/sh/bubblefish/npamp/*.java
//   java  -cp <out> sh.bubblefish.npamp.FinishedKat
package sh.bubblefish.npamp;

import static sh.bubblefish.npamp.Kat.fromHex;
import static sh.bubblefish.npamp.Kat.sat;
import static sh.bubblefish.npamp.Kat.toHex;

import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class FinishedKat {

    private FinishedKat() {
    }

    static final String FINISHED_KAT_SHA256 = "25c21b0bd3b3b6b77862f4a819f81ff5e4ff42e4b1d70af81feeedc5aad73c7f";

    private static int failures = 0;

    private static void check(String name, boolean ok, String detail) {
        if (ok) {
            System.out.println("ok   - " + name);
        } else {
            System.out.println("FAIL - " + name + (detail.isEmpty() ? "" : ": " + detail));
            failures++;
        }
    }

    /** Standard HMAC-SHA-256, independent of computeFinished. */
    private static byte[] hmacOracle(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("hmac oracle failed", e);
        }
    }

    /** ANCHOR: HMAC-SHA-256 reproduces the published RFC 4231 TC1/TC2 MACs. */
    private static void anchor(Object root) {
        for (String tc : new String[]{"tc1", "tc2"}) {
            byte[] key = fromHex(sat(root, "rfc4231_hmac_sha256", tc, "key"));
            byte[] data = fromHex(sat(root, "rfc4231_hmac_sha256", tc, "data"));
            String want = sat(root, "rfc4231_hmac_sha256", tc, "hmac_sha256");
            String got = toHex(hmacOracle(key, data));
            check("anchor: RFC 4231 " + tc, got.equals(want), "got " + got + " want " + want);
        }
    }

    /** ORACLE: reproduce verify_data with an independent HMAC (guards the vector). */
    private static void oracle(Object root) {
        String gs = toHex(hmacOracle(
                fromHex(sat(root, "npamp_inputs", "finished_key_server")),
                fromHex(sat(root, "npamp_inputs", "th_scv"))));
        check("oracle: server verify_data", gs.equals(sat(root, "expected", "verify_data_server")),
                "got " + gs);
        String gc = toHex(hmacOracle(
                fromHex(sat(root, "npamp_inputs", "finished_key_client")),
                fromHex(sat(root, "npamp_inputs", "th_ccv"))));
        check("oracle: client verify_data", gc.equals(sat(root, "expected", "verify_data_client")),
                "got " + gc);
    }

    /** IMPL: computeFinished reproduces verify_data; verifyFinished accepts + rejects a tamper. */
    private static void impl(Object root) {
        String[][] cases = {
                {"server", "finished_key_server", "th_scv", "verify_data_server"},
                {"client", "finished_key_client", "th_ccv", "verify_data_client"},
        };
        for (String[] c : cases) {
            byte[] fk = fromHex(sat(root, "npamp_inputs", c[1]));
            byte[] th = fromHex(sat(root, "npamp_inputs", c[2]));
            byte[] want = fromHex(sat(root, "expected", c[3]));

            byte[] got = Handshake.computeFinished(fk, th, true);
            check("impl: " + c[0] + " computeFinished", Arrays.equals(got, want),
                    "got " + toHex(got) + " want " + toHex(want));

            check("impl: " + c[0] + " verifyFinished accepts",
                    Handshake.verifyFinished(fk, th, want, true), "");

            byte[] bad = want.clone();
            bad[0] ^= 0x01;
            check("impl: " + c[0] + " verifyFinished rejects tamper",
                    !Handshake.verifyFinished(fk, th, bad, true), "");
        }
    }

    public static void main(String[] args) throws Exception {
        Object root = Kat.loadPinned(args, "finished-kat.json", FINISHED_KAT_SHA256);
        anchor(root);
        oracle(root);
        impl(root);
        System.out.println(failures == 0 ? "ALL PASS (finished KAT: anchor+oracle+impl)" : ("FAILURES: " + failures));
        System.exit(failures == 0 ? 0 : 1);
    }
}
