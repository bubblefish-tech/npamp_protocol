// Independent crypto KAT: drive N-PAMP's AES-256-GCM seal/open through Google
// Project Wycheproof vectors (C2SP/wycheproof), via the dependency-free flat
// corpus _shared/wycheproof/aesgcm_kat.tsv (keySize=256, ivSize=96, tagSize=128).
//
// These vectors are authored by an independent authority and encode KNOWN ATTACKS
// (truncated tags, modified ciphertext) that our self-generated golden vectors never
// include -- so a shared bug between our impls cannot pass them.
//
// Trick: sealAes256Gcm(key, iv, seq, ...) derives nonce = iv XOR (0^4||seq); with
// seq=0 the nonce IS the given IV, so each vector exercises the REAL seal/open path.
//
// Exit 0 iff every vector behaves exactly as Wycheproof labels it. Java port of the
// Python reference runner kat_aesgcm_wycheproof.py (passes 66/66).
//
// Build (from impl/java):
//   javac -d <out> src/main/java/sh/bubblefish/npamp/Npamp.java \
//                  src/test/java/sh/bubblefish/npamp/KatAesGcmWycheproof.java
//   java -cp <out> sh.bubblefish.npamp.KatAesGcmWycheproof <TSV>
package sh.bubblefish.npamp;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class KatAesGcmWycheproof {

    private KatAesGcmWycheproof() {
    }

    /** Decodes a lowercase/uppercase hex string into bytes; "" -> empty array. */
    private static byte[] fromHex(String s) {
        int n = s.length();
        if ((n & 1) != 0) {
            throw new IllegalArgumentException("odd-length hex: " + s);
        }
        byte[] out = new byte[n / 2];
        for (int i = 0; i < n; i += 2) {
            int hi = Character.digit(s.charAt(i), 16);
            int lo = Character.digit(s.charAt(i + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("bad hex: " + s);
            }
            out[i / 2] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    public static void main(String[] args) throws IOException {
        Path tsv = (args.length > 0)
                ? Paths.get(args[0])
                : Paths.get("..", "..", "_shared", "wycheproof", "aesgcm_kat.tsv");

        int total = 0;
        int passed = 0;
        List<String> fails = new ArrayList<>();

        List<String> lines = Files.readAllLines(tsv, StandardCharsets.UTF_8);
        for (String line : lines) {
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            // -1 limit preserves trailing empty fields (aad/msg/ct/tag may be EMPTY).
            String[] f = line.split("\t", -1);
            if (f.length != 8) {
                throw new IllegalStateException("expected 8 columns, got " + f.length + ": " + line);
            }
            String tc = f[0];
            String result = f[1];
            byte[] key = fromHex(f[2]);
            byte[] iv = fromHex(f[3]);
            byte[] aad = fromHex(f[4]);
            byte[] msg = fromHex(f[5]);
            byte[] ct = fromHex(f[6]);
            byte[] tag = fromHex(f[7]);

            byte[] sealed = new byte[ct.length + tag.length];
            System.arraycopy(ct, 0, sealed, 0, ct.length);
            System.arraycopy(tag, 0, sealed, ct.length, tag.length);

            boolean ok = true;
            String reason = "";

            switch (result) {
                case "valid": {
                    byte[] gotSealed;
                    try {
                        gotSealed = Npamp.sealAes256Gcm(key, iv, 0L, aad, msg);
                    } catch (RuntimeException e) {
                        gotSealed = null;
                    }
                    if (gotSealed == null || !Arrays.equals(gotSealed, sealed)) {
                        ok = false;
                        reason = "encrypt mismatch";
                    } else {
                        byte[] gotPt;
                        try {
                            gotPt = Npamp.openAes256Gcm(key, iv, 0L, aad, sealed);
                        } catch (RuntimeException e) {
                            gotPt = null;
                        }
                        if (gotPt == null || !Arrays.equals(gotPt, msg)) {
                            ok = false;
                            reason = "decrypt mismatch";
                        }
                    }
                    break;
                }
                case "invalid": {
                    try {
                        Npamp.openAes256Gcm(key, iv, 0L, aad, sealed);
                        ok = false;
                        reason = "accepted an invalid vector";
                    } catch (RuntimeException e) {
                        // correct: rejected
                    }
                    break;
                }
                default: { // "acceptable"
                    try {
                        byte[] gotPt = Npamp.openAes256Gcm(key, iv, 0L, aad, sealed);
                        if (!Arrays.equals(gotPt, msg)) {
                            ok = false;
                            reason = "acceptable but wrong plaintext";
                        }
                    } catch (RuntimeException e) {
                        // rejection is also allowed for acceptable
                    }
                    break;
                }
            }

            total++;
            if (ok) {
                passed++;
            } else {
                fails.add("  FAIL tcId=" + tc + " result=" + result + ": " + reason);
            }
        }

        System.out.println("AES-256-GCM Wycheproof KAT (java): " + passed + "/" + total + " passed");
        for (int i = 0; i < fails.size() && i < 15; i++) {
            System.out.println(fails.get(i));
        }
        System.exit((fails.isEmpty() && total > 0) ? 0 : 1);
    }
}
