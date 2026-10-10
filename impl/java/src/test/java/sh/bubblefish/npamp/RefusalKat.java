// Behaviour check, not a conformance vector: the open Java module implements the Standard profile
// only, so every key-schedule, transcript and Finished primitive refuses a non-Standard profile
// with Npamp.NoSuiteForProfile and still succeeds at Standard. No external authority (RFC or FIPS)
// defines this module's scope. Run via:
//   javac -d <out> src/main/java/sh/bubblefish/npamp/*.java src/test/java/sh/bubblefish/npamp/*.java
//   java  -cp <out> sh.bubblefish.npamp.RefusalKat
package sh.bubblefish.npamp;

public final class RefusalKat {

    private RefusalKat() {
    }

    private static int failures = 0;

    private interface Call {
        void run();
    }

    private static void check(String name, boolean ok) {
        if (ok) {
            System.out.println("ok   - " + name);
        } else {
            System.out.println("FAIL - " + name);
            failures++;
        }
    }

    private static void refused(String name, Call c) {
        boolean threw = false;
        try {
            c.run();
        } catch (Npamp.NoSuiteForProfile e) {
            threw = true;
        } catch (RuntimeException e) {
            System.out.println("     wrong exception for " + name + ": " + e);
        }
        check("non-standard refused: " + name, threw);
    }

    public static void main(String[] args) {
        byte[] secret = new byte[32];
        java.util.Arrays.fill(secret, (byte) 0x11);
        byte[] th = new byte[32];
        java.util.Arrays.fill(th, (byte) 0x22);

        check("standard control: hkdfExtract", Npamp.hkdfExtract(new byte[32], secret, true).length == 32);
        check("standard control: hkdfExpand", Npamp.hkdfExpand(secret, new byte[] {1}, 32, true).length == 32);
        check("standard control: deriveTrafficSecret",
                Npamp.deriveTrafficSecret(secret, 0, 0L, Npamp.AEAD_AES256_GCM, Npamp.CHAN_CONTROL, true).length == 32);
        byte[][] ki = Npamp.deriveKeyIv(secret, true);
        check("standard control: deriveKeyIv", ki[0].length == 32 && ki[1].length == 12);
        check("standard control: deriveHandshakeSecret", Handshake.deriveHandshakeSecret(secret, secret, true).length == 32);
        check("standard control: deriveFinishedKey", Handshake.deriveFinishedKey(secret, true).length == 32);
        check("standard control: transcript hash", new Handshake.Transcript().hash(true).length == 32);
        byte[] mac = Handshake.computeFinished(secret, th, true);
        check("standard control: finished verifies", Handshake.verifyFinished(secret, th, mac, true));

        refused("hkdfExtract", () -> Npamp.hkdfExtract(new byte[48], secret, false));
        refused("hkdfExpand", () -> Npamp.hkdfExpand(secret, new byte[] {1}, 48, false));
        refused("hkdfExpandLabel", () -> Npamp.hkdfExpandLabel(secret, "key", new byte[0], 32, false));
        refused("deriveTrafficSecret",
                () -> Npamp.deriveTrafficSecret(secret, 0, 0L, Npamp.AEAD_AES256_GCM, Npamp.CHAN_CONTROL, false));
        refused("deriveKeyIv", () -> Npamp.deriveKeyIv(secret, false));
        refused("deriveHandshakeSecret", () -> Handshake.deriveHandshakeSecret(secret, secret, false));
        refused("deriveClientHandshakeSecret", () -> Handshake.deriveClientHandshakeSecret(secret, th, false));
        refused("deriveServerHandshakeSecret", () -> Handshake.deriveServerHandshakeSecret(secret, th, false));
        refused("deriveMasterSecret", () -> Handshake.deriveMasterSecret(secret, th, false));
        refused("deriveFinishedKey", () -> Handshake.deriveFinishedKey(secret, false));
        refused("Transcript.hash", () -> new Handshake.Transcript().hash(false));
        refused("computeFinished", () -> Handshake.computeFinished(secret, th, false));
        refused("verifyFinished", () -> Handshake.verifyFinished(secret, th, th, false));

        System.out.println(failures == 0 ? "ALL PASS" : "FAILURES: " + failures);
        System.exit(failures == 0 ? 0 : 1);
    }
}
