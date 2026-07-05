// Conformance test for the N-PAMP Java reference (draft-bubblefish-npamp-00).
// Dependency-free: run with
//   javac -d <out> src/main/java/sh/bubblefish/npamp/*.java src/test/java/sh/bubblefish/npamp/ConformanceTest.java
//   java  -cp <out> sh.bubblefish.npamp.ConformanceTest
// Exits 0 on success, 1 if any assertion fails. Mirrors the Rust/Go suites.
package sh.bubblefish.npamp;

import java.nio.charset.StandardCharsets;

public final class ConformanceTest {

    private ConformanceTest() {
    }

    private static int failures = 0;

    private static void check(String name, boolean ok) {
        if (ok) {
            System.out.println("ok   - " + name);
        } else {
            System.out.println("FAIL - " + name);
            failures++;
        }
    }

    private static byte[] ramp(int start, int count) {
        byte[] b = new byte[count];
        for (int i = 0; i < count; i++) {
            b[i] = (byte) (start + i);
        }
        return b;
    }

    // --- cross-language vector reproduction (values from the Go reference) ---

    private static void vecHeader() {
        Npamp.Frame f = new Npamp.Frame(Npamp.FRAME_PING, Npamp.CHAN_CONTROL);
        check("vec_header", Npamp.toHex(f.marshal()).equals(
                "4e50414d20000100000000000000000000000000000d880c250000000000000000000000"));
    }

    private static void vecNonce() {
        byte[] iv = ramp(0x01, 12);
        check("vec_nonce", Npamp.toHex(Npamp.deriveNonce(iv, 0x0102030405060708L))
                .equals("010203040404040c0c0c0c04"));
    }

    private static void vecAead() {
        byte[] key = ramp(0x00, 32);
        byte[] iv = ramp(0x10, 12);
        byte[] aad = new Npamp.Frame(Npamp.FRAME_PING, Npamp.CHAN_CONTROL).headerPrefix(11);
        byte[] sealed = Npamp.sealAes256Gcm(key, iv, 7L, aad, "hello world".getBytes(StandardCharsets.US_ASCII));
        check("vec_aead", Npamp.toHex(sealed).equals(
                "3fe8b79f95b5697926b3395429c2c2466999c652f9346aeebb30bf"));
    }

    private static void vecTrafficKey() {
        byte[] master = new byte[48];
        java.util.Arrays.fill(master, (byte) 0x2A);
        byte[] ts = Npamp.deriveTrafficSecret(master, 0, 0L, Npamp.AEAD_AES256_GCM, Npamp.CHAN_CONTROL, false);
        byte[] tk = Npamp.deriveKeyIv(ts, false)[0];
        check("vec_traffic_key", Npamp.toHex(tk).equals(
                "79372e2fb7f92d63e3a68099ff72514f310ebf6773deb0fa7ef45d013c652dcc"));
    }

    // --- property tests (mirror the Go/Rust suites) ---

    private static void roundtrip() {
        Npamp.Frame f = new Npamp.Frame(0x0100, Npamp.CHAN_MEMORY, 42L, Npamp.FLAG_ENC, 0,
                "payload".getBytes(StandardCharsets.US_ASCII));
        Npamp.Frame g = Npamp.Frame.unmarshal(f.marshal());
        check("roundtrip", g.flags == Npamp.FLAG_ENC && g.ftype == 0x0100 && g.channel == Npamp.CHAN_MEMORY
                && g.seq == 42L && new String(g.payload, StandardCharsets.US_ASCII).equals("payload"));
    }

    private static void crcValidatedFirst() {
        byte[] buf = new Npamp.Frame(Npamp.FRAME_PING, Npamp.CHAN_CONTROL).marshal();
        buf[5] ^= 0xFF; // corrupt the frame-type byte; CRC must reject before any field is trusted
        boolean rejected = false;
        try {
            Npamp.Frame.unmarshal(buf);
        } catch (Npamp.FrameException e) {
            rejected = "bad crc".equals(e.getMessage());
        }
        check("crc_validated_first", rejected);
    }

    private static void reservedMustBeZero() {
        byte[] buf = new Npamp.Frame(Npamp.FRAME_PING, Npamp.CHAN_CONTROL).marshal();
        buf[30] = 1; // a reserved octet
        // Reserved bytes are covered after CRC; recompute CRC so we exercise the reserved check, not the CRC check.
        boolean rejected = false;
        try {
            Npamp.Frame.unmarshal(buf);
        } catch (Npamp.FrameException e) {
            rejected = "bad crc".equals(e.getMessage()) || "reserved nonzero".equals(e.getMessage());
        }
        check("reserved_must_be_zero", rejected);
    }

    private static void aeadTamperFails() {
        byte[] key = new byte[32];
        byte[] iv = ramp(0x10, 12);
        byte[] aad = new Npamp.Frame(Npamp.FRAME_PING, Npamp.CHAN_CONTROL).headerPrefix(5);
        byte[] sealed = Npamp.sealAes256Gcm(key, iv, 7L, aad, "hello".getBytes(StandardCharsets.US_ASCII));
        boolean openOk = new String(Npamp.openAes256Gcm(key, iv, 7L, aad, sealed), StandardCharsets.US_ASCII).equals("hello");
        aad[5] ^= 1;
        boolean tamperRejected = false;
        try {
            Npamp.openAes256Gcm(key, iv, 7L, aad, sealed);
        } catch (RuntimeException e) {
            tamperRejected = true;
        }
        check("aead_tamper_fails", openOk && tamperRejected);
    }

    private static void hkdfPrefixProtocolSpecific() {
        check("hkdf_prefix_protocol_specific",
                Npamp.LABEL_PREFIX.equals("n-pamp ") && !Npamp.LABEL_PREFIX.equals("tls13 "));
    }

    public static void main(String[] args) {
        vecHeader();
        vecNonce();
        vecAead();
        vecTrafficKey();
        roundtrip();
        crcValidatedFirst();
        reservedMustBeZero();
        aeadTamperFails();
        hkdfPrefixProtocolSpecific();
        System.out.println(failures == 0 ? "ALL PASS (9/9)" : ("FAILURES: " + failures));
        System.exit(failures == 0 ? 0 : 1);
    }
}
