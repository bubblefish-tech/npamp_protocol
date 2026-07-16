// Open reference implementation of the N-PAMP native-channel body codec
// (draft-bubblefish-npamp-01). OPEN protocol layer only: the deterministic
// (canonical) CBOR subset that every native operation channel (NPAMP-MEMORY,
// -STREAM, -CAP, -IMMUNE, -SETTLEMENT, -TELEMETRY, -COMMERCE, -INTERACT,
// -WORKFLOW, -KNOWLEDGE) encodes its bodies in. No proprietary methods.
//
// This is a straight port of the Go reference codec impl/go/memory_cbor.go
// (spec/companion/81_memory_channel.md §4; RFC 8949 §4.2.1 core-deterministic)
// and its TypeScript counterpart impl/typescript/src/npamp_cbor.ts. It implements
// exactly the subset the native bodies use -- unsigned integers, negative
// integers, byte strings, text strings, arrays, maps, and the simple values
// false/true/null -- all definite-length, shortest-form, with map keys in
// canonical (bytewise-of-encoded-key) order. It is deliberately NOT a general
// CBOR library: on decode it REJECTS anything outside this subset (indefinite
// lengths, non-shortest integer/length encodings, tags, floats, other simple
// values, and out-of-order or duplicate map keys), which is precisely what a
// deterministic-encoding receiver MUST reject.
//
// Decoded value types (mirroring the Go uint64/int64/[]byte/string/[]any/
// *cborMap/bool/nil): integers decode to java.math.BigInteger (major 0 -> a
// non-negative BigInteger; major 1 -> a negative BigInteger), byte strings to
// byte[], text strings to String, arrays to List<Object>, maps to CborMap, and
// the three simple values to Boolean / null.
package sh.bubblefish.npamp;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** Deterministic (canonical) CBOR decoder for the N-PAMP native operation bodies. */
public final class NpampCbor {

    private NpampCbor() {
    }

    /** A structural fault in the deterministic-CBOR encoding (a MUST-reject). */
    public static final class CborException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public CborException(String message) {
            super(message);
        }
    }

    // byteLess reports whether a sorts strictly before b in bytewise (shorter-
    // prefix-first, then lexicographic) order -- RFC 8949 §4.2.1 canonical map-key
    // ordering. Bytes are compared as unsigned octets.
    static boolean byteLess(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return a.length < b.length;
        }
        for (int i = 0; i < a.length; i++) {
            int ai = a[i] & 0xff;
            int bi = b[i] & 0xff;
            if (ai != bi) {
                return ai < bi;
            }
        }
        return false;
    }

    /** One decoded map entry: the canonical key encoding (for ordering), the key, the value. */
    static final class Entry {
        final byte[] keyEnc;
        final Object key;
        final Object val;

        Entry(byte[] keyEnc, Object key, Object val) {
            this.keyEnc = keyEnc;
            this.key = key;
            this.val = val;
        }
    }

    /**
     * A CBOR map preserving canonical key order. Keys are themselves CBOR values
     * (here always BigInteger/String/byte[]); entries are kept in the order they
     * were decoded, which the decoder has already verified is canonical ascending.
     */
    public static final class CborMap {
        final List<Entry> entries;

        CborMap(List<Entry> entries) {
            this.entries = entries;
        }

        /**
         * Returns the value for an unsigned-integer key (the form every native
         * envelope/body key takes), or null if the key is absent. A present CBOR
         * null value is also returned as null, so callers that must distinguish an
         * absent key from a present null value use {@link #has(long)} first.
         */
        public Object get(long key) {
            BigInteger k = BigInteger.valueOf(key);
            for (Entry e : entries) {
                if (e.key instanceof BigInteger && e.key.equals(k)) {
                    return e.val;
                }
            }
            return null;
        }

        /** Reports whether an unsigned-integer key is present. */
        public boolean has(long key) {
            BigInteger k = BigInteger.valueOf(key);
            for (Entry e : entries) {
                if (e.key instanceof BigInteger && e.key.equals(k)) {
                    return true;
                }
            }
            return false;
        }

        /** Returns every key in canonical order (used for forward-compat checks). */
        public List<Object> keys() {
            List<Object> out = new ArrayList<>(entries.size());
            for (Entry e : entries) {
                out.add(e.key);
            }
            return out;
        }
    }

    /**
     * Decodes a single canonical CBOR item and requires that it consumes all of
     * {@code b} (no trailing bytes) -- the shape of a frame payload.
     */
    public static Object decodeTop(byte[] b) {
        Dec d = new Dec(b);
        Object v = d.item();
        if (d.pos != b.length) {
            throw new CborException("npamp/cbor: trailing bytes after top-level item");
        }
        return v;
    }

    // toUnsigned converts a 64-bit argument (read as raw bits) into a non-negative
    // BigInteger, treating it as unsigned -- so a uint in the [2^63, 2^64) range is
    // not mistaken for a negative value.
    private static BigInteger toUnsigned(long v) {
        if (v >= 0) {
            return BigInteger.valueOf(v);
        }
        return BigInteger.valueOf(v & Long.MAX_VALUE).setBit(63);
    }

    /** Stateful single-pass decoder over a byte buffer. */
    private static final class Dec {
        final byte[] b;
        int pos;

        Dec(byte[] b) {
            this.b = b;
        }

        Object item() {
            if (pos >= b.length) {
                throw new CborException("npamp/cbor: truncated input");
            }
            int ib = b[pos] & 0xff;
            int major = ib >> 5;
            int ai = ib & 0x1f;

            if (major == 7) {
                // Simple values and floats. Only false(20)/true(21)/null(22) are in the
                // deterministic subset; floats (25/26/27), other simple values, and the
                // break stop (31) are rejected.
                switch (ai) {
                    case 20:
                        pos += 1;
                        return Boolean.FALSE;
                    case 21:
                        pos += 1;
                        return Boolean.TRUE;
                    case 22:
                        pos += 1;
                        return null;
                    default:
                        throw new CborException("npamp/cbor: unsupported major type or simple value");
                }
            }

            long argBits = decodeArg(ai); // advances pos past the header
            int n = pos; // absolute offset just past the header

            switch (major) {
                case 0: // unsigned int
                    return toUnsigned(argBits);
                case 1: // negative int: value = -1 - arg
                    return BigInteger.valueOf(-1).subtract(toUnsigned(argBits));
                case 2:
                case 3: {
                    // byte string / text string
                    int remaining = b.length - n;
                    if (Long.compareUnsigned(argBits, remaining) > 0) {
                        throw new CborException("npamp/cbor: truncated input");
                    }
                    int len = (int) argBits;
                    int end = n + len;
                    byte[] payload = new byte[len];
                    System.arraycopy(b, n, payload, 0, len);
                    pos = end;
                    if (major == 2) {
                        return payload;
                    }
                    return new String(payload, StandardCharsets.UTF_8);
                }
                case 4: {
                    // array. Each element is at least one byte, so a declared count larger
                    // than the remaining input cannot be satisfied -- reject before
                    // iterating on the attacker-controlled count (huge-count DoS guard).
                    int remaining = b.length - n;
                    if (Long.compareUnsigned(argBits, remaining) > 0) {
                        throw new CborException("npamp/cbor: truncated input");
                    }
                    int count = (int) argBits;
                    List<Object> out = new ArrayList<>(count);
                    for (int i = 0; i < count; i++) {
                        out.add(item());
                    }
                    return out;
                }
                case 5: {
                    // map. Each entry is a key plus a value -- at least two bytes -- so a
                    // declared count larger than the remaining input cannot be satisfied.
                    int remaining = b.length - n;
                    if (Long.compareUnsigned(argBits, remaining) > 0) {
                        throw new CborException("npamp/cbor: truncated input");
                    }
                    int count = (int) argBits;
                    List<Entry> entries = new ArrayList<>(count);
                    byte[] prevKeyEnc = null;
                    for (int i = 0; i < count; i++) {
                        int keyStart = pos;
                        Object key = item();
                        int keyEnd = pos;
                        byte[] keyEnc = new byte[keyEnd - keyStart];
                        System.arraycopy(b, keyStart, keyEnc, 0, keyEnd - keyStart);
                        // Canonical order: each key MUST sort strictly after the previous one.
                        if (prevKeyEnc != null && !byteLess(prevKeyEnc, keyEnc)) {
                            throw new CborException(
                                    "npamp/cbor: map keys not in canonical ascending order (or duplicate)");
                        }
                        prevKeyEnc = keyEnc;
                        Object val = item();
                        entries.add(new Entry(keyEnc, key, val));
                    }
                    return new CborMap(entries);
                }
                default: // major 6 (tags): unsupported
                    throw new CborException("npamp/cbor: unsupported major type or simple value");
            }
        }

        // decodeArg reads the argument for an additional-information value ai from
        // b[pos], enforcing shortest-form (RFC 8949 §4.2.1) and rejecting indefinite
        // lengths. Advances pos past the whole header and returns the argument bits.
        private long decodeArg(int ai) {
            if (ai < 24) {
                pos += 1;
                return ai;
            }
            switch (ai) {
                case 24: {
                    if (pos + 2 > b.length) {
                        throw new CborException("npamp/cbor: truncated input");
                    }
                    long v = b[pos + 1] & 0xffL;
                    if (v < 24) {
                        throw new CborException("npamp/cbor: integer/length not in shortest form");
                    }
                    pos += 2;
                    return v;
                }
                case 25: {
                    if (pos + 3 > b.length) {
                        throw new CborException("npamp/cbor: truncated input");
                    }
                    long v = ((b[pos + 1] & 0xffL) << 8) | (b[pos + 2] & 0xffL);
                    if (v < (1L << 8)) {
                        throw new CborException("npamp/cbor: integer/length not in shortest form");
                    }
                    pos += 3;
                    return v;
                }
                case 26: {
                    if (pos + 5 > b.length) {
                        throw new CborException("npamp/cbor: truncated input");
                    }
                    long v = 0;
                    for (int i = 1; i <= 4; i++) {
                        v = (v << 8) | (b[pos + i] & 0xffL);
                    }
                    if (v < (1L << 16)) {
                        throw new CborException("npamp/cbor: integer/length not in shortest form");
                    }
                    pos += 5;
                    return v;
                }
                case 27: {
                    if (pos + 9 > b.length) {
                        throw new CborException("npamp/cbor: truncated input");
                    }
                    long v = 0;
                    for (int i = 1; i <= 8; i++) {
                        v = (v << 8) | (b[pos + i] & 0xffL);
                    }
                    // shortest-form: an 8-byte argument must be >= 2^32 (unsigned compare).
                    if (Long.compareUnsigned(v, 1L << 32) < 0) {
                        throw new CborException("npamp/cbor: integer/length not in shortest form");
                    }
                    pos += 9;
                    return v;
                }
                case 31:
                    throw new CborException("npamp/cbor: indefinite-length item (non-deterministic)");
                default: // 28,29,30 are reserved
                    throw new CborException("npamp/cbor: unsupported major type or simple value");
            }
        }
    }
}
