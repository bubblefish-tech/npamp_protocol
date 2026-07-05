// Standards-derived, NON-CIRCULAR known-answer test for the draft-00 transcript construction
// (binding spec/10 section 3). C# mirror of the Go/Java/TS/Python reference tests against the SAME
// pinned, FIPS-180-4-anchored vector (test-vectors/v1/transcript-kat.json).
//
// Three legs: ANCHOR (SHA-256("abc") == FIPS 180-4), ORACLE (in-test manual per-TLV byte
// constructor, no Transcript), IMPL (the real Handshake.Transcript). Absorption is driven straight
// from the vector's frame/TLV order; the cut points are an index-based (frame index, TLV index) ->
// transcript-hash-name map, which IS the spec section 3 structure. TLV NAMES are never referenced —
// only positions — so the test is value-agnostic and never spells out any TLV's role.
//
// Self-contained: builds with Npamp.cs + Handshake.cs + this file only. JSON via System.Text.Json.
#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Sh.Bubblefish.Npamp;

public static class TranscriptKat
{
    private const string TranscriptKatSha256 = "fab6d852497b6ff56405595e9a014d0c45cabc5cde80a60a17444b337d556ee5";

    // (frame index, TLV index within that frame) -> transcript-hash point name.
    private static readonly Dictionary<string, string> CutPoints = new()
    {
        { "1,4", "th_kem" },
        { "2,0", "th_sid" },
        { "2,1", "th_scv" },
        { "3,0", "th_cid" },
        { "3,1", "th_ccv" },
    };

    private static readonly string[] PointOrder = { "th_kem", "th_sid", "th_scv", "th_cid", "th_ccv" };

    private static int _failures;

    private static void Check(string name, bool ok, string detail)
    {
        if (ok)
        {
            Console.WriteLine("ok   - " + name);
        }
        else
        {
            Console.WriteLine("FAIL - " + name + (detail.Length == 0 ? "" : ": " + detail));
            _failures++;
        }
    }

    // -- Small KAT helpers (self-contained) --------------------------------

    private static byte[] FromHex(string s) => s.Length == 0 ? Array.Empty<byte>() : Convert.FromHexString(s);

    private static string TrimHexPrefix(string s) =>
        (s.Length >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) ? s.Substring(2) : s;

    private static byte[] Sha256(byte[] data) => SHA256.HashData(data);

    private static string VectorDir(string[] args)
    {
        if (args.Length > 0 && args[0].Length != 0)
        {
            return args[0];
        }
        for (DirectoryInfo? d = new(Directory.GetCurrentDirectory()); d != null; d = d.Parent)
        {
            string cand = Path.Combine(d.FullName, "test-vectors", "v1");
            if (Directory.Exists(cand))
            {
                return cand;
            }
        }
        return Path.Combine("..", "..", "test-vectors", "v1");
    }

    private static JsonDocument LoadPinned(string[] args, string file, string wantSha256)
    {
        string path = Path.Combine(VectorDir(args), file);
        byte[] raw = File.ReadAllBytes(path);
        string got = Npamp.ToHex(SHA256.HashData(raw));
        if (got != wantSha256)
        {
            throw new InvalidOperationException(file + " SHA-256 mismatch (swapped vector?):\n  got  "
                + got + "\n  want " + wantSha256 + "\n  path " + Path.GetFullPath(path));
        }
        return JsonDocument.Parse(raw);
    }

    private static JsonElement At(JsonElement e, params string[] keys)
    {
        foreach (string k in keys)
        {
            e = e.GetProperty(k);
        }
        return e;
    }

    private static string Sat(JsonElement e, params string[] keys) => At(e, keys).GetString()!;

    // -- Shared absorption driver ------------------------------------------

    /// <summary>Walks the vector frames/TLVs in order; snapshots at each spec section 3 cut point.</summary>
    private static Dictionary<string, byte[]> Drive(JsonElement root, Action<int> ft, Action<int, byte[]> tlv, Func<byte[]> snap)
    {
        var points = new Dictionary<string, byte[]>();
        JsonElement frames = root.GetProperty("frames");
        int fi = 0;
        foreach (JsonElement f in frames.EnumerateArray())
        {
            ft(Convert.ToInt32(TrimHexPrefix(f.GetProperty("frame_type").GetString()!), 16));
            int ti = 0;
            foreach (JsonElement tl in f.GetProperty("tlvs").EnumerateArray())
            {
                int type = Convert.ToInt32(TrimHexPrefix(tl.GetProperty("type").GetString()!), 16);
                byte[] value = FromHex(tl.GetProperty("value").GetString()!);
                tlv(type, value);
                if (CutPoints.TryGetValue(fi + "," + ti, out string? pname))
                {
                    points[pname] = snap();
                }
                ti++;
            }
            fi++;
        }
        return points;
    }

    private static void CheckPoints(string leg, JsonElement root, Dictionary<string, byte[]> points)
    {
        if (points.Count != PointOrder.Length)
        {
            Check(leg, false, "expected " + PointOrder.Length + " cut points, got " + points.Count);
            return;
        }
        bool ok = true;
        var detail = new StringBuilder();
        foreach (string name in PointOrder)
        {
            string got = Npamp.ToHex(points[name]);
            string want = Sat(root, "expected_transcript_points", name);
            if (got != want)
            {
                ok = false;
                detail.Append(name).Append(" got ").Append(got).Append(" want ").Append(want).Append("; ");
            }
        }
        Check(leg, ok, detail.ToString());
    }

    // -- Legs --------------------------------------------------------------

    /// <summary>ANCHOR: the test's SHA-256 reproduces the FIPS 180-4 SHA-256("abc") known answer.</summary>
    private static void Anchor(JsonElement root)
    {
        const string fips = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        string input = Sat(root, "fips180_4_sha256_abc", "input_ascii");
        string got = Npamp.ToHex(Sha256(Encoding.ASCII.GetBytes(input)));
        string vecDigest = Sat(root, "fips180_4_sha256_abc", "digest");
        Check("anchor: SHA-256(\"abc\") == FIPS 180-4", got == fips && vecDigest == fips,
            "got " + got + " vecDigest " + vecDigest);
    }

    /// <summary>ORACLE: reproduce every TH_* with an in-test manual constructor (no Transcript).</summary>
    private static void Oracle(JsonElement root)
    {
        var buf = new List<byte>();
        Action<int> ft = v =>
        {
            buf.Add((byte)((v >> 8) & 0xFF));
            buf.Add((byte)(v & 0xFF));
        };
        Action<int, byte[]> tlv = (type, value) =>
        {
            buf.Add((byte)((type >> 8) & 0xFF));
            buf.Add((byte)(type & 0xFF));
            buf.Add((byte)((value.Length >> 8) & 0xFF));
            buf.Add((byte)(value.Length & 0xFF));
            buf.AddRange(value);
        };
        Func<byte[]> snap = () => Sha256(buf.ToArray());
        CheckPoints("oracle", root, Drive(root, ft, tlv, snap));
    }

    /// <summary>IMPL: reproduce every TH_* with the real Handshake.Transcript.</summary>
    private static void Impl(JsonElement root)
    {
        // Read into locals so the const comparison is a runtime drift-check (not folded away):
        // if a frame-type constant is ever edited off the spec section 1 code points, this fires.
        int ch = Handshake.FrameClientHello, sh = Handshake.FrameServerHello,
            sa = Handshake.FrameServerAuth, ca = Handshake.FrameClientAuth;
        if (ch != 0x0100 || sh != 0x0101 || sa != 0x0102 || ca != 0x0103)
        {
            Check("impl: frame-type constants match spec section 1", false,
                "CH=" + ch + " SH=" + sh + " SA=" + sa + " CA=" + ca);
            return;
        }
        var tr = new Handshake.Transcript();
        Action<int> ft = tr.AddFrameType;
        Action<int, byte[]> tlv = tr.AddTLV;
        Func<byte[]> snap = () => tr.Hash(true);
        CheckPoints("impl", root, Drive(root, ft, tlv, snap));
    }

    public static int Main(string[] args)
    {
        using JsonDocument doc = LoadPinned(args, "transcript-kat.json", TranscriptKatSha256);
        JsonElement root = doc.RootElement;
        Anchor(root);
        Oracle(root);
        Impl(root);
        Console.WriteLine(_failures == 0
            ? "ALL PASS (transcript KAT: anchor+oracle+impl)"
            : "FAILURES: " + _failures);
        return _failures == 0 ? 0 : 1;
    }
}
