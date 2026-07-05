// Runnable example: the draft-00 secure record layer, end to end.
//
// Composes the OPEN-protocol primitives this port provides — the HKDF key schedule, the
// AES-256-GCM record layer, and the 36-octet frame codec — into one send -> receive round-trip
// over an in-memory "wire". Mirrors the Go reference's Example_secureRecordLayer
// (impl/go/example_test.go).
//
// The master secret is a fixed demo value; in a live session it is the handshake output (binding
// spec/10 section 5). Standard profile only (SHA-256, AES-256-GCM). Dependency-free; compile and
// run from impl/java:
//
//   javac -d out src/main/java/sh/bubblefish/npamp/Npamp.java examples/SecureRecordLayer.java
//   java  -cp out SecureRecordLayer

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import sh.bubblefish.npamp.Npamp;
import sh.bubblefish.npamp.Npamp.Frame;

public final class SecureRecordLayer {

    /** Direction octet (draft-00 7.5): client-to-server = 0. */
    private static final int DIR_CLIENT_TO_SERVER = 0;

    private SecureRecordLayer() {
    }

    public static void main(String[] args) {
        // 1. Key schedule: derive a per-(direction, channel, suite) traffic key + IV from the
        //    master secret. In a live session the master secret is the handshake output; here it
        //    is fixed so the example is deterministic.
        byte[] master = new byte[32];
        Arrays.fill(master, (byte) 0x2B);
        byte[] ts = Npamp.deriveTrafficSecret(master, DIR_CLIENT_TO_SERVER, 0L, Npamp.AEAD_AES256_GCM, Npamp.CHAN_MEMORY, true);
        byte[][] keyIv = Npamp.deriveKeyIv(ts, true);
        byte[] key = keyIv[0];
        byte[] iv = keyIv[1];

        // 2. Sender: seal an application payload into an AEAD-protected frame on the Memory
        //    channel. The AEAD associated data is the 21-octet header prefix, so the ciphertext
        //    is bound to the frame's type/channel/seq/length — a tampered header makes the open
        //    fail.
        int appType = 0x0120; // application frame type (app-defined; this port is wire-only)
        byte[] plaintext = "hello over n-pamp".getBytes(StandardCharsets.UTF_8);
        long seq = 0L;
        Frame out = new Frame(appType, Npamp.CHAN_MEMORY, seq, Npamp.FLAG_ENC, 0, new byte[0]);
        byte[] aad = out.headerPrefix(plaintext.length + 16L); // +16 = AES-256-GCM authentication tag
        out.payload = Npamp.sealAes256Gcm(key, iv, seq, aad, plaintext);
        byte[] wire = out.marshal();

        // 3. ... the `wire` bytes travel over any transport (the consumer supplies TCP/TLS) ...

        // 4. Receiver: parse the frame (validates CRC32C/magic/version) and open the payload
        //    under the same key/seq and the reconstructed header-prefix AAD.
        Frame in = Frame.unmarshal(wire);
        byte[] raad = in.headerPrefix(in.payload.length);
        byte[] opened = Npamp.openAes256Gcm(key, iv, in.seq, raad, in.payload);

        System.out.println("channel=" + in.channel + " seq=" + in.seq
                + " encrypted=" + ((in.flags & Npamp.FLAG_ENC) != 0));
        System.out.println("recovered: " + new String(opened, StandardCharsets.UTF_8));
        if (!Arrays.equals(opened, plaintext)) {
            System.err.println("roundtrip mismatch");
            System.exit(1);
        }
    }
}
