// Test-vector generator for the N-PAMP wire format (draft-bubblefish-npamp-00).
// Prints the four canonical OPEN-layer vectors as JSON on stdout (UTF-8, LF).
// Every reference implementation must reproduce these bytes exactly.
using System;
using System.IO;
using System.Text;

namespace Sh.Bubblefish.Npamp;

/// <summary>Emits the canonical draft-00 OPEN-layer test vectors as a fixed JSON document.</summary>
public static class Vectors
{
    /// <summary>Returns bytes [start, start+1, ..., start+count-1] truncated to 8 bits.</summary>
    private static byte[] Ramp(int start, int count)
    {
        byte[] b = new byte[count];
        for (int i = 0; i < count; i++)
        {
            b[i] = (byte)(start + i);
        }
        return b;
    }

    public static string Render()
    {
        // 1) header = Frame{PING, Control, seq=0, no payload}.Marshal()
        var f1 = new Npamp.Frame(Npamp.FramePing, Npamp.ChanControl);
        string header = Npamp.ToHex(f1.Marshal());

        // 2) nonce = DeriveNonce(iv=[01..0C], seq=0x0102030405060708)
        string nonce = Npamp.ToHex(Npamp.DeriveNonce(Ramp(0x01, 12), 0x0102030405060708UL));

        // 3) aead = SealAes256Gcm(key=[00..1F], iv=[10..1B], seq=7,
        //          aad=Frame{PING,Control}.HeaderPrefix(11), plaintext="hello world")
        byte[] key3 = Ramp(0x00, 32);
        byte[] iv3 = Ramp(0x10, 12);
        byte[] aad3 = new Npamp.Frame(Npamp.FramePing, Npamp.ChanControl).HeaderPrefix(11);
        byte[] pt3 = Encoding.ASCII.GetBytes("hello world");
        string aead = Npamp.ToHex(Npamp.SealAes256Gcm(key3, iv3, 7UL, aad3, pt3));

        // 4) traffic = DeriveKeyIv(DeriveTrafficSecret(master=48*0x2A, dir=0, epoch=0,
        //          suite=AES-256-GCM, channel=Control, standard=false), standard=false).Key
        byte[] master = new byte[48];
        Array.Fill(master, (byte)0x2A);
        byte[] secret = Npamp.DeriveTrafficSecret(master, 0, 0UL, Npamp.AeadAes256Gcm, Npamp.ChanControl, false);
        string traffic = Npamp.ToHex(Npamp.DeriveKeyIv(secret, false).Key);

        var sb = new StringBuilder();
        sb.Append("{\n");
        sb.Append("  \"spec\": \"draft-bubblefish-npamp-00\",\n");
        sb.Append("  \"header_ping_control_seq0\": \"").Append(header).Append("\",\n");
        sb.Append("  \"nonce_iv1to12_seq0102\": \"").Append(nonce).Append("\",\n");
        sb.Append("  \"aes256gcm_seal_helloworld\": \"").Append(aead).Append("\",\n");
        sb.Append("  \"traffic_key_sha384\": \"").Append(traffic).Append("\"\n");
        sb.Append("}\n");
        return sb.ToString();
    }

    public static void Main()
    {
        // Write raw UTF-8 bytes with LF endings, bypassing any console newline translation.
        byte[] bytes = Encoding.UTF8.GetBytes(Render());
        using Stream stdout = Console.OpenStandardOutput();
        stdout.Write(bytes, 0, bytes.Length);
        stdout.Flush();
    }
}
