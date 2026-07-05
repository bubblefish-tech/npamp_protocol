// Independent crypto KAT: drive N-PAMP's HKDF-Expand through Google/C2SP
// Wycheproof HKDF-SHA-256/384 vectors, via the dependency-free flat corpus
// _shared/wycheproof/hkdf_kat.tsv. This validates the HKDF-Expand primitive
// (used by the HKDF-Expand-Label key schedule) against an authority that never
// saw our code -- so a shared bug between our impls cannot pass it.
//
// Each data line: tcId, hash ("sha256"|"sha384"), prk (hex), info (hex),
// size (int), okm (hex). PASS iff toHex(hkdfExpand(prk, info, size,
// standard=hash=="sha256")) == okm.
//
// Exit 0 iff every vector reproduces its OKM and total>0. Java port of the
// Python reference runner kat_hkdf_wycheproof.py (passes 163/163).
//
// Build (from impl/java):
//   javac -d <out> src/main/java/sh/bubblefish/npamp/Npamp.java \
//                  src/test/java/sh/bubblefish/npamp/KatHkdf.java
//   java -cp <out> sh.bubblefish.npamp.KatHkdf <TSV>
package sh.bubblefish.npamp;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public final class KatHkdf {

    private KatHkdf() {
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
                : Paths.get("..", "..", "_shared", "wycheproof", "hkdf_kat.tsv");

        int total = 0;
        int passed = 0;
        List<String> fails = new ArrayList<>();

        List<String> lines = Files.readAllLines(tsv, StandardCharsets.UTF_8);
        for (String line : lines) {
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            // -1 limit preserves trailing empty fields (info may be EMPTY).
            String[] f = line.split("\t", -1);
            if (f.length != 6) {
                throw new IllegalStateException("expected 6 columns, got " + f.length + ": " + line);
            }
            String tc = f[0];
            String hash = f[1];
            byte[] prk = fromHex(f[2]);
            byte[] info = fromHex(f[3]);
            int size = Integer.parseInt(f[4]);
            String okm = f[5];

            boolean standard = hash.equals("sha256");
            String got;
            String reason = "";
            try {
                got = Npamp.toHex(Npamp.hkdfExpand(prk, info, size, standard));
            } catch (RuntimeException e) {
                got = null;
                reason = "exception: " + e.getMessage();
            }

            total++;
            if (got != null && got.equals(okm)) {
                passed++;
            } else {
                fails.add("  FAIL tcId=" + tc + " " + hash
                        + (reason.isEmpty() ? "" : " " + reason));
            }
        }

        System.out.println("HKDF-Expand Wycheproof KAT (java): " + passed + "/" + total + " passed");
        for (int i = 0; i < fails.size() && i < 15; i++) {
            System.out.println(fails.get(i));
        }
        System.exit((fails.isEmpty() && total > 0) ? 0 : 1);
    }
}
