// Spec-derived (non-circular) conformance check for the N-PAMP deterministic-CBOR
// decoder's resource-exhaustion nesting-depth guard (NpampCbor.java, mirroring the Go
// reference impl/go/memory_cbor.go cborMaxNestingDepth = 8).
//
// Vectors are derived directly from RFC 8949 array encoding + the depth-8 rule, NOT
// from this (or any) implementation:
//   - MUST REJECT: 81 81 81 81 81 81 81 81 00 (eight 0x81 array-of-one headers
//     wrapping a 0x00 scalar -> the scalar sits at depth 9; the outermost array is
//     depth 1).
//   - MUST ACCEPT: 81 81 81 81 81 81 81 00 (seven 0x81 headers + the scalar -> the
//     scalar sits at depth 8).
//
// main()-driven (not JUnit; surefire skips this module's tests -- see pom.xml).
// Exit 0 iff both vectors are dispositioned correctly.
package sh.bubblefish.npamp;

public final class CborDepthKat {

    private CborDepthKat() {
    }

    public static void main(String[] args) {
        int failures = 0;

        byte[] reject = {
            (byte) 0x81, (byte) 0x81, (byte) 0x81, (byte) 0x81,
            (byte) 0x81, (byte) 0x81, (byte) 0x81, (byte) 0x81, 0x00,
        };
        try {
            NpampCbor.decodeTop(reject);
            System.out.println("FAIL depth-9 vector: expected depth-exceeded, decode succeeded");
            failures++;
        } catch (NpampCbor.CborException e) {
            if (e.getMessage() != null && e.getMessage().contains("nesting depth exceeds limit")) {
                System.out.println("ok   - depth-9 vector rejected with depth-exceeded error");
            } else {
                System.out.println("FAIL depth-9 vector: wrong error: " + e.getMessage());
                failures++;
            }
        }

        byte[] accept = {
            (byte) 0x81, (byte) 0x81, (byte) 0x81, (byte) 0x81,
            (byte) 0x81, (byte) 0x81, (byte) 0x81, 0x00,
        };
        try {
            NpampCbor.decodeTop(accept);
            System.out.println("ok   - depth-8 vector decodes cleanly");
        } catch (NpampCbor.CborException e) {
            System.out.println("FAIL depth-8 vector: expected success, got: " + e.getMessage());
            failures++;
        }

        int passed = failures == 0 ? 2 : 2 - failures;
        System.out.println("CBOR nesting-depth guard KAT (java): " + passed + "/2 passed");
        if (failures != 0) {
            System.exit(1);
        }
    }
}
