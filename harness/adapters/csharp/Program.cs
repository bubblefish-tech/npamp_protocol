// N-PAMP conformance adapter (C#). A "testee": it reads length-prefixed JSON
// requests {op,in} on stdin and writes length-prefixed JSON responses
// {out|error|skipped} on stdout. Every operation dispatches onto the REAL
// reference implementation in impl/csharp/Npamp.cs (compiled into this
// assembly via Adapter.csproj) — this adapter performs no cryptography of its
// own; it only translates the wire contract into calls on Npamp.* members.
//
// Windows note: stdio is taken as raw binary streams (Console.OpenStandard*),
// never the text Console, so no CRLF translation corrupts the byte framing, and
// stdout is flushed after every response.
#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using System.Text.Json;

namespace Sh.Bubblefish.Npamp.Conformance;

internal static class Adapter
{
    // -- hex / field helpers ----------------------------------------------

    private static byte[] FromHex(string? s) =>
        string.IsNullOrEmpty(s) ? Array.Empty<byte>() : Convert.FromHexString(s);

    private static string ToHex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    private static string Str(JsonElement obj, string key) =>
        obj.ValueKind == JsonValueKind.Object && obj.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String
            ? (v.GetString() ?? "")
            : "";

    private static long Num(JsonElement obj, string key) =>
        obj.ValueKind == JsonValueKind.Object && obj.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.Number
            ? v.GetInt64()
            : 0;

    private static byte[] Hx(JsonElement obj, string key) => FromHex(Str(obj, key));

    // The reference HkdfExpand (raw RFC 5869 §2.3 Expand) is private; bind it once
    // by reflection so this adapter invokes the genuine reference routine rather
    // than reimplementing it. Signature: byte[] HkdfExpand(bool standard, byte[] prk, byte[] info, int length).
    private static readonly MethodInfo HkdfExpandRef =
        typeof(Npamp).GetMethod("HkdfExpand", BindingFlags.NonPublic | BindingFlags.Static)
        ?? throw new MissingMethodException("Npamp.HkdfExpand (private) not found in reference implementation");

    private static byte[] HkdfExpand(bool standard, byte[] prk, byte[] info, int length) =>
        (byte[])HkdfExpandRef.Invoke(null, new object[] { standard, prk, info, (int)length })!;

    // -- response builders -------------------------------------------------

    private static Dictionary<string, object> Out(Dictionary<string, object> fields) =>
        new() { ["out"] = fields };

    private static Dictionary<string, object> Error(string reason) =>
        new() { ["error"] = reason };

    private static Dictionary<string, object> Skipped(string why) =>
        new() { ["skipped"] = why };

    // -- dispatch ----------------------------------------------------------

    private static Dictionary<string, object> Handle(string op, JsonElement input)
    {
        switch (op)
        {
            case "header.encode":
            {
                // octets[0:21] via the reference Frame.HeaderPrefix, then the
                // reference Crc32c, then 11 reserved zero octets.
                var f = new Npamp.Frame(
                    ftype: (int)Num(input, "frameType"),
                    channel: (int)Num(input, "channel"),
                    seq: (ulong)Num(input, "seq"),
                    flags: (int)Num(input, "flags"),
                    version: (int)Num(input, "ver"));
                long payloadLength = Num(input, "payloadLength");
                byte[] prefix = f.HeaderPrefix(payloadLength);
                byte[] frame = new byte[Npamp.HeaderSize];
                Array.Copy(prefix, 0, frame, 0, 21);
                uint crc = Npamp.Crc32c(prefix);
                frame[21] = (byte)((crc >> 24) & 0xFF);
                frame[22] = (byte)((crc >> 16) & 0xFF);
                frame[23] = (byte)((crc >> 8) & 0xFF);
                frame[24] = (byte)(crc & 0xFF);
                // octets 25..35 reserved, already zero
                return Out(new() { ["frame"] = ToHex(frame) });
            }

            case "header.decode":
            {
                byte[] b = Hx(input, "frame");
                Npamp.Frame f;
                try
                {
                    f = Npamp.Frame.Unmarshal(b);
                }
                catch (FrameException e)
                {
                    return Error(e.Message);
                }
                // Unmarshal already verified magic, crc and reserved-zero. The
                // crc field is octets 21..24; reconstruct its hex for the report.
                string crcHex = ToHex(new[] { b[21], b[22], b[23], b[24] });
                return Out(new()
                {
                    ["magic"] = "NPAM",
                    ["ver"] = f.Version,
                    ["flags"] = f.Flags,
                    ["frameType"] = f.Ftype,
                    ["channel"] = f.Channel,
                    ["seq"] = f.Seq,
                    ["payloadLength"] = (long)f.Payload.Length,
                    ["crc32c"] = crcHex,
                    ["reservedZero"] = true,
                });
            }

            case "crc32c":
            {
                byte[] octets = Hx(input, "octets");
                uint crc = Npamp.Crc32c(octets); // reference CRC32C
                byte[] be = { (byte)(crc >> 24), (byte)(crc >> 16), (byte)(crc >> 8), (byte)crc };
                return Out(new() { ["crc32c"] = ToHex(be) });
            }

            case "tlv.decode":
            {
                // The reference impl exposes TLV type constants but no decoder;
                // parse the TLV here per draft-00 R2 (type u16, length u16, value).
                byte[] b = Hx(input, "tlv");
                if (b.Length < 4)
                {
                    return Error("truncated tlv");
                }
                int typ = (b[0] << 8) | b[1];
                int length = (b[2] << 8) | b[3];
                if ((typ & 0x8000) != 0)
                {
                    return Error("unknown forward-incompatible TLV (high bit set)");
                }
                if (length != b.Length - 4)
                {
                    return Error("tlv length mismatch");
                }
                byte[] value = new byte[length];
                Array.Copy(b, 4, value, 0, length);
                return Out(new() { ["type"] = typ, ["length"] = length, ["value"] = ToHex(value) });
            }

            case "aead.seal":
            {
                if (Str(input, "suite") != "AES-256-GCM")
                {
                    return Skipped("suite not implemented: " + Str(input, "suite"));
                }
                byte[] key = Hx(input, "key");
                byte[] nonce = Hx(input, "nonce");
                byte[] aad = Hx(input, "aad");
                byte[] pt = Hx(input, "pt");
                try
                {
                    // Reference seal derives nonce as DeriveNonce(iv, seq) = iv ^ (seq@[4:12]).
                    // Passing iv=nonce, seq=0 yields exactly the supplied nonce, so this
                    // invokes the genuine Npamp.SealAes256Gcm path with the wire nonce.
                    byte[] sealedBytes = Npamp.SealAes256Gcm(key, nonce, 0UL, aad, pt);
                    return Out(new() { ["sealed"] = ToHex(sealedBytes) });
                }
                catch (Exception e)
                {
                    return Error(e.Message);
                }
            }

            case "aead.open":
            {
                if (Str(input, "suite") != "AES-256-GCM")
                {
                    return Skipped("suite not implemented: " + Str(input, "suite"));
                }
                byte[] key = Hx(input, "key");
                byte[] nonce = Hx(input, "nonce");
                byte[] aad = Hx(input, "aad");
                byte[] sealedBytes = Hx(input, "sealed");
                try
                {
                    byte[] pt = Npamp.OpenAes256Gcm(key, nonce, 0UL, aad, sealedBytes);
                    return Out(new() { ["pt"] = ToHex(pt) });
                }
                catch (System.Security.Cryptography.CryptographicException)
                {
                    return Error("authentication failed");
                }
                catch (Exception e)
                {
                    return Error(e.Message);
                }
            }

            case "hkdf.expand":
            {
                string hash = Str(input, "hash");
                bool standard;
                if (hash == "sha256")
                {
                    standard = true;
                }
                else if (hash == "sha384")
                {
                    standard = false;
                }
                else
                {
                    return Skipped("hash not implemented: " + hash);
                }
                byte[] prk = Hx(input, "prk");
                byte[] info = Hx(input, "info");
                int length = (int)Num(input, "length");
                byte[] okm = HkdfExpand(standard, prk, info, length); // reference HkdfExpand via reflection
                return Out(new() { ["okm"] = ToHex(okm) });
            }

            case "profile.check":
                // The C# reference implementation has no profile KEM-acceptance
                // logic; report Unimplemented rather than reimplementing it here.
                return Skipped("profile.check not implemented in csharp reference");

            default:
                return Skipped("op not implemented: " + op);
        }
    }

    // -- length-prefixed read/write loop -----------------------------------

    private static bool ReadFull(Stream s, byte[] buf, int count)
    {
        int off = 0;
        while (off < count)
        {
            int n = s.Read(buf, off, count - off);
            if (n <= 0)
            {
                return false; // EOF
            }
            off += n;
        }
        return true;
    }

    private static readonly JsonSerializerOptions JsonOpts = new() { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    public static int Main()
    {
        using Stream stdin = Console.OpenStandardInput();
        using Stream stdout = Console.OpenStandardOutput();
        byte[] lp = new byte[4];

        while (true)
        {
            if (!ReadFull(stdin, lp, 4))
            {
                return 0; // stdin closed
            }
            uint n = (uint)(lp[0] | (lp[1] << 8) | (lp[2] << 16) | (lp[3] << 24)); // little-endian
            byte[] body = new byte[n];
            if (!ReadFull(stdin, body, (int)n))
            {
                return 0;
            }

            Dictionary<string, object> resp;
            try
            {
                using JsonDocument doc = JsonDocument.Parse(body);
                JsonElement root = doc.RootElement;
                string op = root.TryGetProperty("op", out var opEl) && opEl.ValueKind == JsonValueKind.String
                    ? (opEl.GetString() ?? "")
                    : "";
                JsonElement input = root.TryGetProperty("in", out var inEl) ? inEl : default;
                resp = Handle(op, input);
            }
            catch (Exception e)
            {
                resp = Error("adapter exception: " + e.Message);
            }

            byte[] ob = JsonSerializer.SerializeToUtf8Bytes(resp, JsonOpts);
            byte[] ol =
            {
                (byte)(ob.Length & 0xFF),
                (byte)((ob.Length >> 8) & 0xFF),
                (byte)((ob.Length >> 16) & 0xFF),
                (byte)((ob.Length >> 24) & 0xFF),
            };
            stdout.Write(ol, 0, 4);
            stdout.Write(ob, 0, ob.Length);
            stdout.Flush();
        }
    }
}
