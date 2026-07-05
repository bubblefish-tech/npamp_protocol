// N-PAMP (draft-bubblefish-npamp-00) conformance adapter (Java). A "testee": it reads
// length-prefixed JSON requests {op,in} on stdin and writes length-prefixed JSON
// responses {out|error|skipped} on stdout, delegating each operation to the OPEN Java
// reference implementation in sh.bubblefish.npamp.Npamp. The adapter owns no protocol
// logic of its own beyond TLV parsing (the reference exposes no TLV decoder) and the
// length-prefixed JSON framing.
//
// Windows note: stdin/stdout are used as raw binary streams (System.in / System.out are
// byte streams in the JVM; no CRLF translation is applied to them) and the output is
// flushed after every response, so the 4-byte little-endian length framing is preserved.
//
// Build (from adapters/java/):
//   javac -d out ..\..\..\impl\java\src\main\java\sh\bubblefish\npamp\Npamp.java Adapter.java
// Run:
//   java -cp out sh.bubblefish.npamp.Adapter
package sh.bubblefish.npamp;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Conformance testee for the N-PAMP OPEN Java reference. Each protocol operation is
 * dispatched to a real {@link Npamp} primitive; the only logic local to this adapter is
 * the wire framing, a minimal JSON reader/writer, and TLV decoding (which the reference
 * does not provide).
 */
public final class Adapter {

    private Adapter() {
    }

    // -- hex helpers -------------------------------------------------------

    private static byte[] hexToBytes(String s) {
        if (s == null) {
            return new byte[0];
        }
        int n = s.length();
        if ((n & 1) != 0) {
            throw new IllegalArgumentException("odd-length hex");
        }
        byte[] out = new byte[n / 2];
        for (int i = 0; i < n; i += 2) {
            int hi = Character.digit(s.charAt(i), 16);
            int lo = Character.digit(s.charAt(i + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("bad hex digit");
            }
            out[i / 2] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    private static String bytesToHex(byte[] b) {
        // Reuse the reference's lowercase-hex encoder so the wire encoding is the impl's.
        return Npamp.toHex(b);
    }

    private static String u32Hex(long v) {
        byte[] b = new byte[4];
        b[0] = (byte) ((v >>> 24) & 0xFF);
        b[1] = (byte) ((v >>> 16) & 0xFF);
        b[2] = (byte) ((v >>> 8) & 0xFF);
        b[3] = (byte) (v & 0xFF);
        return bytesToHex(b);
    }

    // -- per-operation handlers (each delegates to Npamp) ------------------

    @SuppressWarnings("unchecked")
    private static Map<String, Object> handle(Map<String, Object> req) {
        String op = asString(req.get("op"));
        Map<String, Object> in = req.get("in") instanceof Map
                ? (Map<String, Object>) req.get("in") : new LinkedHashMap<>();

        switch (op) {
            case "header.encode": {
                // Assemble the 36-octet frame using the reference's headerPrefix() and
                // crc32c(); octets 25..35 stay zero (reserved). payloadLength is taken
                // from the request, independent of any actual payload bytes.
                Npamp.Frame f = new Npamp.Frame();
                f.version = (int) asLong(in.get("ver"));
                f.flags = (int) asLong(in.get("flags"));
                f.ftype = (int) asLong(in.get("frameType"));
                f.channel = (int) asLong(in.get("channel"));
                f.seq = asLong(in.get("seq"));
                long payloadLength = asLong(in.get("payloadLength"));
                byte[] prefix = f.headerPrefix(payloadLength); // real reference path
                byte[] frame = new byte[Npamp.HEADER_SIZE];
                System.arraycopy(prefix, 0, frame, 0, 21);
                byte[] crc = hexToBytes(u32Hex(Npamp.crc32c(prefix))); // real reference crc32c
                System.arraycopy(crc, 0, frame, 21, 4);
                return out("frame", bytesToHex(frame));
            }

            case "header.decode": {
                byte[] frame = hexToBytes(asString(in.get("frame")));
                try {
                    Npamp.Frame f = Npamp.Frame.unmarshal(frame); // real parse + MUST-reject rules
                    // unmarshal guarantees: crc valid, magic == NPAM, reserved all zero.
                    byte[] crc = hexToBytes(u32Hex(Npamp.crc32c(java.util.Arrays.copyOfRange(frame, 0, 21))));
                    Map<String, Object> o = new LinkedHashMap<>();
                    o.put("magic", "NPAM");
                    o.put("ver", f.version);
                    o.put("flags", f.flags);
                    o.put("frameType", f.ftype);
                    o.put("channel", f.channel);
                    o.put("seq", f.seq);
                    o.put("payloadLength", (long) (frame.length - Npamp.HEADER_SIZE));
                    o.put("crc32c", bytesToHex(crc));
                    o.put("reservedZero", Boolean.TRUE);
                    return wrap("out", o);
                } catch (Npamp.FrameException e) {
                    return error(e.getMessage());
                } catch (RuntimeException e) {
                    return error("malformed header");
                }
            }

            case "crc32c": {
                byte[] octets = hexToBytes(asString(in.get("octets")));
                return out("crc32c", u32Hex(Npamp.crc32c(octets))); // real reference crc32c
            }

            case "tlv.decode": {
                // The OPEN Java reference exposes no TLV decoder; this is the one place the
                // adapter parses the wire itself (mirrors the Go/Python reference adapters).
                byte[] b = hexToBytes(asString(in.get("tlv")));
                if (b.length < 4) {
                    return error("truncated tlv");
                }
                int type = ((b[0] & 0xFF) << 8) | (b[1] & 0xFF);
                int length = ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);
                if ((type & 0x8000) != 0) {
                    return error("unknown forward-incompatible TLV (high bit set)");
                }
                if (length != b.length - 4) {
                    return error("tlv length mismatch");
                }
                Map<String, Object> o = new LinkedHashMap<>();
                o.put("type", (long) type);
                o.put("length", (long) length);
                o.put("value", bytesToHex(java.util.Arrays.copyOfRange(b, 4, b.length)));
                return wrap("out", o);
            }

            case "aead.seal": {
                if (!"AES-256-GCM".equals(asString(in.get("suite")))) {
                    return skipped("suite not implemented: " + asString(in.get("suite")));
                }
                byte[] key = hexToBytes(asString(in.get("key")));
                byte[] nonce = hexToBytes(asString(in.get("nonce")));
                byte[] aad = hexToBytes(asString(in.get("aad")));
                byte[] pt = hexToBytes(asString(in.get("pt")));
                try {
                    // deriveNonce(iv, 0) == iv, so passing the contract nonce as the iv with
                    // seq 0 makes the reference seal use exactly the supplied nonce.
                    byte[] sealed = Npamp.sealAes256Gcm(key, nonce, 0L, aad, pt);
                    return out("sealed", bytesToHex(sealed));
                } catch (RuntimeException e) {
                    return error(rootMessage(e));
                }
            }

            case "aead.open": {
                if (!"AES-256-GCM".equals(asString(in.get("suite")))) {
                    return skipped("suite not implemented: " + asString(in.get("suite")));
                }
                byte[] key = hexToBytes(asString(in.get("key")));
                byte[] nonce = hexToBytes(asString(in.get("nonce")));
                byte[] aad = hexToBytes(asString(in.get("aad")));
                byte[] sealed = hexToBytes(asString(in.get("sealed")));
                try {
                    byte[] pt = Npamp.openAes256Gcm(key, nonce, 0L, aad, sealed);
                    return out("pt", bytesToHex(pt));
                } catch (RuntimeException e) {
                    // Tag mismatch / auth failure MUST be rejected.
                    return error("authentication failed");
                }
            }

            case "hkdf.expand": {
                String hash = asString(in.get("hash"));
                boolean standard;
                if ("sha256".equals(hash)) {
                    standard = true;
                } else if ("sha384".equals(hash)) {
                    standard = false;
                } else {
                    return skipped("hash not implemented: " + hash);
                }
                byte[] prk = hexToBytes(asString(in.get("prk")));
                byte[] info = hexToBytes(asString(in.get("info")));
                int length = (int) asLong(in.get("length"));
                try {
                    byte[] okm = Npamp.hkdfExpand(prk, info, length, standard); // real HKDF-Expand
                    return out("okm", bytesToHex(okm));
                } catch (RuntimeException e) {
                    return error(rootMessage(e));
                }
            }

            case "profile.check":
                // The OPEN Java reference implements no profile/KEM-acceptance registry,
                // so this operation is genuinely unimplemented here.
                return skipped("profile.check not implemented in the Java OPEN reference");

            default:
                return skipped("op not implemented: " + op);
        }
    }

    private static String rootMessage(Throwable e) {
        Throwable t = e;
        while (t.getCause() != null) {
            t = t.getCause();
        }
        String m = t.getMessage();
        return m != null ? m : t.getClass().getSimpleName();
    }

    // -- response builders -------------------------------------------------

    private static Map<String, Object> out(String key, Object value) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put(key, value);
        return wrap("out", o);
    }

    private static Map<String, Object> wrap(String key, Object value) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put(key, value);
        return r;
    }

    private static Map<String, Object> error(String reason) {
        return wrap("error", reason != null ? reason : "rejected");
    }

    private static Map<String, Object> skipped(String why) {
        return wrap("skipped", why);
    }

    // -- coercion helpers --------------------------------------------------

    private static String asString(Object o) {
        return o == null ? null : (o instanceof String ? (String) o : String.valueOf(o));
    }

    private static long asLong(Object o) {
        if (o == null) {
            return 0L;
        }
        if (o instanceof Long) {
            return (Long) o;
        }
        if (o instanceof Number) {
            return ((Number) o).longValue();
        }
        return Long.parseLong(String.valueOf(o).trim());
    }

    // ======================================================================
    //  Minimal JSON parser/serializer (no external dependencies).
    //  Parses objects, arrays, strings, numbers (as Long), booleans, null.
    //  Numbers are kept as Long because every numeric field in the contract
    //  is an integer; this preserves full u64 seq values without float loss.
    // ======================================================================

    private static final class JsonParser {
        private final String s;
        private int i;

        JsonParser(String s) {
            this.s = s;
        }

        Object parse() {
            skipWs();
            Object v = parseValue();
            skipWs();
            return v;
        }

        private Object parseValue() {
            skipWs();
            char c = s.charAt(i);
            switch (c) {
                case '{':
                    return parseObject();
                case '[':
                    return parseArray();
                case '"':
                    return parseString();
                case 't':
                    expect("true");
                    return Boolean.TRUE;
                case 'f':
                    expect("false");
                    return Boolean.FALSE;
                case 'n':
                    expect("null");
                    return null;
                default:
                    return parseNumber();
            }
        }

        private Map<String, Object> parseObject() {
            Map<String, Object> m = new LinkedHashMap<>();
            i++; // {
            skipWs();
            if (s.charAt(i) == '}') {
                i++;
                return m;
            }
            while (true) {
                skipWs();
                String key = parseString();
                skipWs();
                if (s.charAt(i) != ':') {
                    throw new IllegalArgumentException("expected ':'");
                }
                i++;
                Object val = parseValue();
                m.put(key, val);
                skipWs();
                char c = s.charAt(i++);
                if (c == ',') {
                    continue;
                }
                if (c == '}') {
                    break;
                }
                throw new IllegalArgumentException("expected ',' or '}'");
            }
            return m;
        }

        private List<Object> parseArray() {
            List<Object> a = new ArrayList<>();
            i++; // [
            skipWs();
            if (s.charAt(i) == ']') {
                i++;
                return a;
            }
            while (true) {
                a.add(parseValue());
                skipWs();
                char c = s.charAt(i++);
                if (c == ',') {
                    continue;
                }
                if (c == ']') {
                    break;
                }
                throw new IllegalArgumentException("expected ',' or ']'");
            }
            return a;
        }

        private String parseString() {
            if (s.charAt(i) != '"') {
                throw new IllegalArgumentException("expected string");
            }
            i++;
            StringBuilder sb = new StringBuilder();
            while (true) {
                char c = s.charAt(i++);
                if (c == '"') {
                    break;
                }
                if (c == '\\') {
                    char e = s.charAt(i++);
                    switch (e) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'u':
                            int cp = Integer.parseInt(s.substring(i, i + 4), 16);
                            i += 4;
                            sb.append((char) cp);
                            break;
                        default:
                            throw new IllegalArgumentException("bad escape");
                    }
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        private Object parseNumber() {
            int start = i;
            while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) {
                i++;
            }
            String num = s.substring(start, i);
            if (num.indexOf('.') < 0 && num.indexOf('e') < 0 && num.indexOf('E') < 0) {
                try {
                    return Long.parseLong(num);
                } catch (NumberFormatException nfe) {
                    return new java.math.BigInteger(num);
                }
            }
            return (long) Double.parseDouble(num);
        }

        private void expect(String lit) {
            if (!s.regionMatches(i, lit, 0, lit.length())) {
                throw new IllegalArgumentException("expected " + lit);
            }
            i += lit.length();
        }

        private void skipWs() {
            while (i < s.length()) {
                char c = s.charAt(i);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    i++;
                } else {
                    break;
                }
            }
        }
    }

    private static void writeJson(StringBuilder sb, Object v) {
        if (v == null) {
            sb.append("null");
        } else if (v instanceof String) {
            writeString(sb, (String) v);
        } else if (v instanceof Boolean) {
            sb.append(((Boolean) v) ? "true" : "false");
        } else if (v instanceof Number) {
            sb.append(v.toString());
        } else if (v instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                writeString(sb, String.valueOf(e.getKey()));
                sb.append(':');
                writeJson(sb, e.getValue());
            }
            sb.append('}');
        } else if (v instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object e : (List<?>) v) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                writeJson(sb, e);
            }
            sb.append(']');
        } else {
            writeString(sb, String.valueOf(v));
        }
    }

    private static void writeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int k = 0; k < s.length(); k++) {
            char c = s.charAt(k);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
    }

    // -- length-prefixed framing loop --------------------------------------

    private static int readFully(DataInputStream in, byte[] buf) throws IOException {
        int off = 0;
        while (off < buf.length) {
            int r = in.read(buf, off, buf.length - off);
            if (r < 0) {
                return off; // EOF
            }
            off += r;
        }
        return off;
    }

    public static void main(String[] args) throws IOException {
        // Raw binary streams: System.in/System.out are byte streams; no CRLF translation.
        DataInputStream in = new DataInputStream(System.in);
        OutputStream rawOut = System.out;

        byte[] lp = new byte[4];
        while (true) {
            int got = readFully(in, lp);
            if (got < 4) {
                return; // stdin closed
            }
            long n = (lp[0] & 0xFFL)
                    | ((lp[1] & 0xFFL) << 8)
                    | ((lp[2] & 0xFFL) << 16)
                    | ((lp[3] & 0xFFL) << 24);
            byte[] body = new byte[(int) n];
            if (readFully(in, body) < body.length) {
                return; // truncated
            }

            Map<String, Object> resp;
            try {
                Object parsed = new JsonParser(new String(body, StandardCharsets.UTF_8)).parse();
                @SuppressWarnings("unchecked")
                Map<String, Object> req = (Map<String, Object>) parsed;
                resp = handle(req);
            } catch (Exception e) {
                resp = error("adapter exception: " + rootMessage(e));
            }

            StringBuilder sb = new StringBuilder();
            writeJson(sb, resp);
            byte[] ob = sb.toString().getBytes(StandardCharsets.UTF_8);
            byte[] ol = new byte[4];
            int len = ob.length;
            ol[0] = (byte) (len & 0xFF);
            ol[1] = (byte) ((len >>> 8) & 0xFF);
            ol[2] = (byte) ((len >>> 16) & 0xFF);
            ol[3] = (byte) ((len >>> 24) & 0xFF);
            rawOut.write(ol);
            rawOut.write(ob);
            rawOut.flush(); // flush after every response so the byte framing is preserved
        }
    }
}
