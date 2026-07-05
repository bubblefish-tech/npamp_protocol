// Standards-derived, NON-CIRCULAR known-answer test for the draft-00 transcript
// construction (binding spec/10 section 3). Java mirror of the Go/TS/Python reference
// tests against the SAME pinned, FIPS-180-4-anchored vector
// (test-vectors/v1/transcript-kat.json).
//
// Three legs: ANCHOR (SHA-256("abc") == FIPS 180-4), ORACLE (in-test manual byte
// constructor, no Transcript), IMPL (the real Handshake.Transcript). Run via:
//   javac -d <out> src/main/java/sh/bubblefish/npamp/*.java src/test/java/sh/bubblefish/npamp/*.java
//   java  -cp <out> sh.bubblefish.npamp.TranscriptKat
//
// Absorption is driven straight from the vector's frame/TLV order; the cut points are an
// index-based (frame index, TLV index) -> transcript-hash-name map, which IS the spec
// section 3 structure. The TLV NAMES are never referenced — only positions — so the test
// is value-agnostic and never spells out any TLV's role.
package sh.bubblefish.npamp;

import static sh.bubblefish.npamp.Kat.arr;
import static sh.bubblefish.npamp.Kat.at;
import static sh.bubblefish.npamp.Kat.fromHex;
import static sh.bubblefish.npamp.Kat.sat;
import static sh.bubblefish.npamp.Kat.toHex;
import static sh.bubblefish.npamp.Kat.trimHexPrefix;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class TranscriptKat {

    private TranscriptKat() {
    }

    static final String TRANSCRIPT_KAT_SHA256 = "fab6d852497b6ff56405595e9a014d0c45cabc5cde80a60a17444b337d556ee5";

    // (frame index, TLV index within that frame) -> transcript-hash point name.
    static final Map<String, String> CUT_POINTS = new LinkedHashMap<>();
    static final String[] POINT_ORDER = {"th_kem", "th_sid", "th_scv", "th_cid", "th_ccv"};

    static {
        CUT_POINTS.put("1,4", "th_kem");
        CUT_POINTS.put("2,0", "th_sid");
        CUT_POINTS.put("2,1", "th_scv");
        CUT_POINTS.put("3,0", "th_cid");
        CUT_POINTS.put("3,1", "th_ccv");
    }

    private static int failures = 0;

    private static void check(String name, boolean ok, String detail) {
        if (ok) {
            System.out.println("ok   - " + name);
        } else {
            System.out.println("FAIL - " + name + (detail.isEmpty() ? "" : ": " + detail));
            failures++;
        }
    }

    // -- Functional sinks for the shared absorption driver -----------------

    interface FrameTypeSink {
        void add(int ft);
    }

    interface TlvSink {
        void add(int type, byte[] value);
    }

    interface Snapshot {
        byte[] take();
    }

    /** Walks the vector frames/TLVs in order; snapshots at each spec section 3 cut point. */
    static Map<String, byte[]> drive(Object root, FrameTypeSink ft, TlvSink tlv, Snapshot snap) {
        Map<String, byte[]> points = new LinkedHashMap<>();
        List<Object> frames = arr(at(root, "frames"));
        for (int fi = 0; fi < frames.size(); fi++) {
            Object f = frames.get(fi);
            ft.add(Integer.parseInt(trimHexPrefix(sat(f, "frame_type")), 16));
            List<Object> tlvs = arr(at(f, "tlvs"));
            for (int ti = 0; ti < tlvs.size(); ti++) {
                Object tl = tlvs.get(ti);
                int type = Integer.parseInt(trimHexPrefix(sat(tl, "type")), 16);
                byte[] value = fromHex(sat(tl, "value"));
                tlv.add(type, value);
                String pname = CUT_POINTS.get(fi + "," + ti);
                if (pname != null) {
                    points.put(pname, snap.take());
                }
            }
        }
        return points;
    }

    private static void checkPoints(String leg, Object root, Map<String, byte[]> points) {
        if (points.size() != POINT_ORDER.length) {
            check(leg, false, "expected " + POINT_ORDER.length + " cut points, got " + points.keySet());
            return;
        }
        boolean ok = true;
        StringBuilder detail = new StringBuilder();
        for (String name : POINT_ORDER) {
            String got = toHex(points.get(name));
            String want = sat(root, "expected_transcript_points", name);
            if (!got.equals(want)) {
                ok = false;
                detail.append(name).append(" got ").append(got).append(" want ").append(want).append("; ");
            }
        }
        check(leg, ok, detail.toString());
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new RuntimeException("sha-256 failed", e);
        }
    }

    /** ANCHOR: the test's SHA-256 reproduces the FIPS 180-4 SHA-256("abc") known answer. */
    private static void anchor(Object root) {
        final String fips = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        String in = sat(root, "fips180_4_sha256_abc", "input_ascii");
        String got = toHex(sha256(in.getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
        String vecDigest = sat(root, "fips180_4_sha256_abc", "digest");
        check("anchor: SHA-256(\"abc\") == FIPS 180-4", got.equals(fips) && vecDigest.equals(fips),
                "got " + got + " vecDigest " + vecDigest);
    }

    /** ORACLE: reproduce every TH_* with an in-test manual constructor (no Transcript). */
    private static void oracle(Object root) {
        final ByteArrayOutputStream buf = new ByteArrayOutputStream();
        FrameTypeSink ft = (v) -> {
            buf.write((v >>> 8) & 0xFF);
            buf.write(v & 0xFF);
        };
        TlvSink tlv = (type, value) -> {
            buf.write((type >>> 8) & 0xFF);
            buf.write(type & 0xFF);
            buf.write((value.length >>> 8) & 0xFF);
            buf.write(value.length & 0xFF);
            buf.writeBytes(value);
        };
        Snapshot snap = () -> sha256(buf.toByteArray());
        checkPoints("oracle", root, drive(root, ft, tlv, snap));
    }

    /** IMPL: reproduce every TH_* with the real Handshake.Transcript. */
    private static void impl(Object root) {
        if (Handshake.FRAME_CLIENT_HELLO != 0x0100 || Handshake.FRAME_SERVER_HELLO != 0x0101
                || Handshake.FRAME_SERVER_AUTH != 0x0102 || Handshake.FRAME_CLIENT_AUTH != 0x0103) {
            check("impl: frame-type constants match spec section 1", false,
                    "CH=" + Handshake.FRAME_CLIENT_HELLO + " SH=" + Handshake.FRAME_SERVER_HELLO
                            + " SA=" + Handshake.FRAME_SERVER_AUTH + " CA=" + Handshake.FRAME_CLIENT_AUTH);
            return;
        }
        Handshake.Transcript tr = new Handshake.Transcript();
        FrameTypeSink ft = tr::addFrameType;
        TlvSink tlv = tr::addTLV;
        Snapshot snap = () -> tr.hash(true);
        checkPoints("impl", root, drive(root, ft, tlv, snap));
    }

    public static void main(String[] args) throws Exception {
        Object root = Kat.loadPinned(args, "transcript-kat.json", TRANSCRIPT_KAT_SHA256);
        anchor(root);
        oracle(root);
        impl(root);
        System.out.println(failures == 0 ? "ALL PASS (transcript KAT: anchor+oracle+impl)" : ("FAILURES: " + failures));
        System.exit(failures == 0 ? 0 : 1);
    }
}
