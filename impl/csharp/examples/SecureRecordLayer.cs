// Runnable example: the draft-00 secure record layer, end to end.
//
// Composes the OPEN-protocol primitives this port provides — the HKDF key schedule, the
// AES-256-GCM record layer, and the 36-octet frame codec — into one send -> receive round-trip
// over an in-memory "wire". Mirrors the Go reference's Example_secureRecordLayer
// (impl/go/example_test.go).
//
// The master secret is a fixed demo value; in a live session it is the handshake output (binding
// spec/10 section 5). Standard profile only (SHA-256, AES-256-GCM). BCL-only (no BouncyCastle).
// Build + run from impl/csharp with:
//
//   pwsh examples/build-example.ps1
//
// (a temp-dir build, SDK `dotnet build` or Roslyn `csc` fallback — the same two paths as
// build-local.ps1 and test/build-handshake-kat.ps1).

using System;
using System.Text;

namespace Sh.Bubblefish.Npamp.Examples
{
    public static class SecureRecordLayer
    {
        /// <summary>Direction octet (draft-00 7.5): client-to-server = 0.</summary>
        private const int DirClientToServer = 0;

        public static int Main()
        {
            // 1. Key schedule: derive a per-(direction, channel, suite) traffic key + IV from the
            //    master secret. In a live session the master secret is the handshake output; here
            //    it is fixed so the example is deterministic.
            byte[] master = new byte[32];
            Array.Fill(master, (byte)0x2B);
            byte[] ts = Npamp.DeriveTrafficSecret(master, DirClientToServer, 0UL, Npamp.AeadAes256Gcm, Npamp.ChanMemory, true);
            (byte[] key, byte[] iv) = Npamp.DeriveKeyIv(ts, true);

            // 2. Sender: seal an application payload into an AEAD-protected frame on the Memory
            //    channel. The AEAD associated data is the 21-octet header prefix, so the
            //    ciphertext is bound to the frame's type/channel/seq/length — a tampered header
            //    makes the open fail.
            const int appType = 0x0120; // application frame type (app-defined; this port is wire-only)
            byte[] plaintext = Encoding.UTF8.GetBytes("hello over n-pamp");
            ulong seq = 0;
            var frameOut = new Npamp.Frame(appType, Npamp.ChanMemory, seq, Npamp.FlagEnc);
            byte[] aad = frameOut.HeaderPrefix(plaintext.Length + 16); // +16 = AES-256-GCM authentication tag
            frameOut.Payload = Npamp.SealAes256Gcm(key, iv, seq, aad, plaintext);
            byte[] wire = frameOut.Marshal();

            // 3. ... the `wire` bytes travel over any transport (the consumer supplies TCP/TLS) ...

            // 4. Receiver: parse the frame (validates CRC32C/magic/version) and open the payload
            //    under the same key/seq and the reconstructed header-prefix AAD.
            Npamp.Frame frameIn = Npamp.Frame.Unmarshal(wire);
            byte[] raad = frameIn.HeaderPrefix(frameIn.Payload.Length);
            byte[] opened = Npamp.OpenAes256Gcm(key, iv, frameIn.Seq, raad, frameIn.Payload);

            Console.WriteLine("channel=" + frameIn.Channel + " seq=" + frameIn.Seq
                + " encrypted=" + (((frameIn.Flags & Npamp.FlagEnc) != 0) ? "true" : "false"));
            Console.WriteLine("recovered: " + Encoding.UTF8.GetString(opened));
            if (!((ReadOnlySpan<byte>)opened).SequenceEqual(plaintext))
            {
                Console.Error.WriteLine("roundtrip mismatch");
                return 1;
            }
            return 0;
        }
    }
}
