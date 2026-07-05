// Shared, dependency-free support for the draft-00 handshake KAT runners: a minimal
// recursive-descent JSON parser, hex codecs, a SHA-256 pin check, and vector-path
// resolution. Stdlib only (no JSON library) to keep the impl in the no-new-dep tier.
package sh.bubblefish.npamp;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Test support: JSON parsing, hex, SHA-256 pinning, and vector location. */
final class Kat {

    private Kat() {
    }

    // -- Hex ---------------------------------------------------------------

    static byte[] fromHex(String s) {
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

    /** Lowercase hex, delegating to the reference encoder for cross-test consistency. */
    static String toHex(byte[] b) {
        return Npamp.toHex(b);
    }

    /** Strips a leading "0x"/"0X" if present. */
    static String trimHexPrefix(String s) {
        return (s.length() >= 2 && (s.charAt(0) == '0') && (s.charAt(1) == 'x' || s.charAt(1) == 'X'))
                ? s.substring(2) : s;
    }

    // -- File load + SHA-256 pin ------------------------------------------

    static String sha256Hex(byte[] data) {
        try {
            return Npamp.toHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (Exception e) {
            throw new RuntimeException("sha-256 failed", e);
        }
    }

    /**
     * Walks up from the current working directory to locate {@code test-vectors/v1}; an
     * explicit {@code args[0]} overrides. Robust to the harness's exact run directory.
     */
    static Path vectorDir(String[] args) {
        if (args.length > 0 && !args[0].isEmpty()) {
            return Paths.get(args[0]);
        }
        Path cur = Paths.get("").toAbsolutePath();
        for (Path p = cur; p != null; p = p.getParent()) {
            Path cand = p.resolve("test-vectors").resolve("v1");
            if (Files.isDirectory(cand)) {
                return cand;
            }
        }
        return Paths.get("..", "..", "test-vectors", "v1");
    }

    /**
     * Reads {@code <vectorDir>/<file>}, verifies its SHA-256 equals {@code wantSha256}
     * (fail loud on a swapped vector), and returns the parsed JSON root.
     */
    static Object loadPinned(String[] args, String file, String wantSha256) throws IOException {
        Path path = vectorDir(args).resolve(file);
        byte[] raw = Files.readAllBytes(path);
        String got = sha256Hex(raw);
        if (!got.equals(wantSha256)) {
            throw new IllegalStateException(file + " SHA-256 mismatch (swapped vector?):\n  got  "
                    + got + "\n  want " + wantSha256 + "\n  path " + path.toAbsolutePath());
        }
        return parse(new String(raw, StandardCharsets.UTF_8));
    }

    // -- Typed navigation --------------------------------------------------

    @SuppressWarnings("unchecked")
    static Map<String, Object> obj(Object o) {
        return (Map<String, Object>) o;
    }

    @SuppressWarnings("unchecked")
    static List<Object> arr(Object o) {
        return (List<Object>) o;
    }

    static String str(Object o) {
        return (String) o;
    }

    /** Navigates nested objects by key path, returning the leaf value. */
    static Object at(Object root, String... keys) {
        Object cur = root;
        for (String k : keys) {
            cur = obj(cur).get(k);
            if (cur == null) {
                throw new IllegalStateException("missing JSON key: " + k);
            }
        }
        return cur;
    }

    /** Navigates by key path and returns the leaf as a string. */
    static String sat(Object root, String... keys) {
        return str(at(root, keys));
    }

    // -- Minimal JSON parser ----------------------------------------------
    //
    // Recursive descent over RFC 8259 JSON. Objects -> LinkedHashMap (insertion order
    // preserved), arrays -> ArrayList, strings -> String (full escape handling),
    // numbers -> Double, plus true/false/null. Sufficient for the KAT vectors.

    static Object parse(String s) {
        P p = new P(s);
        p.ws();
        Object v = p.value();
        p.ws();
        if (p.i != p.n) {
            throw new IllegalStateException("trailing JSON at offset " + p.i);
        }
        return v;
    }

    private static final class P {
        final String s;
        final int n;
        int i;

        P(String s) {
            this.s = s;
            this.n = s.length();
        }

        void ws() {
            while (i < n) {
                char c = s.charAt(i);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    i++;
                } else {
                    break;
                }
            }
        }

        Object value() {
            char c = peek();
            switch (c) {
                case '{':
                    return object();
                case '[':
                    return array();
                case '"':
                    return string();
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
                    return number();
            }
        }

        Map<String, Object> object() {
            Map<String, Object> m = new LinkedHashMap<>();
            i++; // consume '{'
            ws();
            if (peek() == '}') {
                i++;
                return m;
            }
            while (true) {
                ws();
                String key = string();
                ws();
                if (s.charAt(i) != ':') {
                    throw new IllegalStateException("expected ':' at offset " + i);
                }
                i++;
                ws();
                m.put(key, value());
                ws();
                char c = s.charAt(i++);
                if (c == ',') {
                    continue;
                }
                if (c == '}') {
                    return m;
                }
                throw new IllegalStateException("expected ',' or '}' at offset " + (i - 1));
            }
        }

        List<Object> array() {
            List<Object> a = new ArrayList<>();
            i++; // consume '['
            ws();
            if (peek() == ']') {
                i++;
                return a;
            }
            while (true) {
                ws();
                a.add(value());
                ws();
                char c = s.charAt(i++);
                if (c == ',') {
                    continue;
                }
                if (c == ']') {
                    return a;
                }
                throw new IllegalStateException("expected ',' or ']' at offset " + (i - 1));
            }
        }

        String string() {
            if (s.charAt(i) != '"') {
                throw new IllegalStateException("expected string at offset " + i);
            }
            i++; // consume opening quote
            StringBuilder sb = new StringBuilder();
            while (true) {
                char c = s.charAt(i++);
                if (c == '"') {
                    return sb.toString();
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
                            sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                            i += 4;
                            break;
                        default:
                            throw new IllegalStateException("bad escape \\" + e + " at offset " + (i - 1));
                    }
                } else {
                    sb.append(c);
                }
            }
        }

        Double number() {
            int start = i;
            while (i < n) {
                char c = s.charAt(i);
                if ((c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E') {
                    i++;
                } else {
                    break;
                }
            }
            if (i == start) {
                throw new IllegalStateException("unexpected character '" + peek() + "' at offset " + i);
            }
            return Double.parseDouble(s.substring(start, i));
        }

        void expect(String lit) {
            if (!s.startsWith(lit, i)) {
                throw new IllegalStateException("expected '" + lit + "' at offset " + i);
            }
            i += lit.length();
        }

        char peek() {
            if (i >= n) {
                throw new IllegalStateException("unexpected end of JSON");
            }
            return s.charAt(i);
        }
    }
}
