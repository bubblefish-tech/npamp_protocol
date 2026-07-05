// Test-vector generator for the N-PAMP wire format (draft-bubblefish-npamp-00).
// Prints the four canonical OPEN-layer vectors as JSON on stdout.
package sh.bubblefish.npamp;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

/** Emits the canonical draft-00 OPEN-layer test vectors as a fixed JSON document. */
public final class Vectors {

    private Vectors() {
    }

    /** Returns bytes [start, start+1, ..., start+count-1] truncated to 8 bits. */
    private static byte[] ramp(int start, int count) {
        byte[] b = new byte[count];
        for (int i = 0; i < count; i++) {
            b[i] = (byte) (start + i);
        }
        return b;
    }

    /** Returns a buffer of {@code count} octets all equal to {@code value}. */
    private static byte[] fill(int value, int count) {
        byte[] b = new byte[count];
        java.util.Arrays.fill(b, (byte) value);
        return b;
    }

    public static String render() {
        // 1) header = Frame{PING, Control, seq=0, no payload}.marshal()
        Npamp.Frame f1 = new Npamp.Frame(Npamp.FRAME_PING, Npamp.CHAN_CONTROL);
        String header = Npamp.toHex(f1.marshal());

        // 2) nonce = deriveNonce(iv=[01..0C], seq=0x0102030405060708)
        byte[] iv2 = ramp(0x01, 12); // 01 02 ... 0C
        String nonce = Npamp.toHex(Npamp.deriveNonce(iv2, 0x0102030405060708L));

        // 3) aead = sealAes256Gcm(key=[00..1F], iv=[10..1B], seq=7,
        //          aad=Frame{PING,Control}.headerPrefix(11), plaintext="hello world")
        byte[] key3 = ramp(0x00, 32); // 00 01 ... 1F
        byte[] iv3 = ramp(0x10, 12);  // 10 11 ... 1B
        byte[] aad3 = new Npamp.Frame(Npamp.FRAME_PING, Npamp.CHAN_CONTROL).headerPrefix(11);
        byte[] pt3 = "hello world".getBytes(StandardCharsets.US_ASCII);
        String aead = Npamp.toHex(Npamp.sealAes256Gcm(key3, iv3, 7L, aad3, pt3));

        // 4) traffic = deriveKeyIv(deriveTrafficSecret(master=48*0x2A, dir=0, epoch=0,
        //          suite=AES-256-GCM, channel=Control, standard=false), standard=false)[key]
        byte[] master = fill(0x2A, 48);
        byte[] secret = Npamp.deriveTrafficSecret(master, 0, 0L,
                Npamp.AEAD_AES256_GCM, Npamp.CHAN_CONTROL, false);
        byte[] trafficKey = Npamp.deriveKeyIv(secret, false)[0];
        String traffic = Npamp.toHex(trafficKey);

        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"spec\": \"draft-bubblefish-npamp-00\",\n");
        sb.append("  \"header_ping_control_seq0\": \"").append(header).append("\",\n");
        sb.append("  \"nonce_iv1to12_seq0102\": \"").append(nonce).append("\",\n");
        sb.append("  \"aes256gcm_seal_helloworld\": \"").append(aead).append("\",\n");
        sb.append("  \"traffic_key_sha384\": \"").append(traffic).append("\"\n");
        sb.append("}\n");
        return sb.toString();
    }

    public static void main(String[] args) {
        // Force LF line endings regardless of platform default.
        PrintStream out = new PrintStream(System.out, true, StandardCharsets.UTF_8);
        out.print(render());
    }
}
