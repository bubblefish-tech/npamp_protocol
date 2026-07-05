// Standards-derived, NON-CIRCULAR known-answer test for the draft-00 Finished verify_data
// (binding spec/10 section 6.2; RFC 8446 section 4.4.4): verify_data = HMAC(finished_key,
// transcript_hash) under the profile hash (SHA-256 at Standard). C# mirror of the Go/Java/TS/Python
// reference tests against the SAME pinned vector (test-vectors/v1/finished-kat.json).
//
// Three legs: ANCHOR (HMAC-SHA-256 reproduces RFC 4231 TC1/TC2), ORACLE (independent
// HMACSHA256 instance, no ComputeFinished), IMPL (ComputeFinished + VerifyFinished accept/reject).
//
// Self-contained: builds with Npamp.cs + Handshake.cs + this file only. JSON via System.Text.Json.
#nullable enable
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

namespace Sh.Bubblefish.Npamp;

public static class FinishedKat
{
    private const string FinishedKatSha256 = "25c21b0bd3b3b6b77862f4a819f81ff5e4ff42e4b1d70af81feeedc5aad73c7f";

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

    private static bool BytesEqual(byte[] a, byte[] b)
    {
        if (a.Length != b.Length)
        {
            return false;
        }
        for (int i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }
        return true;
    }

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

    /// <summary>Standard HMAC-SHA-256 via an independent HMACSHA256 instance (not ComputeFinished).</summary>
    private static byte[] HmacOracle(byte[] key, byte[] data)
    {
        using var mac = new HMACSHA256(key);
        return mac.ComputeHash(data);
    }

    // -- Legs --------------------------------------------------------------

    /// <summary>ANCHOR: HMAC-SHA-256 reproduces the published RFC 4231 TC1/TC2 MACs.</summary>
    private static void Anchor(JsonElement root)
    {
        foreach (string tc in new[] { "tc1", "tc2" })
        {
            byte[] key = FromHex(Sat(root, "rfc4231_hmac_sha256", tc, "key"));
            byte[] data = FromHex(Sat(root, "rfc4231_hmac_sha256", tc, "data"));
            string want = Sat(root, "rfc4231_hmac_sha256", tc, "hmac_sha256");
            string got = Npamp.ToHex(HmacOracle(key, data));
            Check("anchor: RFC 4231 " + tc, got == want, "got " + got + " want " + want);
        }
    }

    /// <summary>ORACLE: reproduce verify_data with an independent HMAC (guards the vector).</summary>
    private static void Oracle(JsonElement root)
    {
        string gs = Npamp.ToHex(HmacOracle(
            FromHex(Sat(root, "npamp_inputs", "finished_key_server")),
            FromHex(Sat(root, "npamp_inputs", "th_scv"))));
        Check("oracle: server verify_data", gs == Sat(root, "expected", "verify_data_server"), "got " + gs);

        string gc = Npamp.ToHex(HmacOracle(
            FromHex(Sat(root, "npamp_inputs", "finished_key_client")),
            FromHex(Sat(root, "npamp_inputs", "th_ccv"))));
        Check("oracle: client verify_data", gc == Sat(root, "expected", "verify_data_client"), "got " + gc);
    }

    /// <summary>IMPL: ComputeFinished reproduces verify_data; VerifyFinished accepts + rejects a tamper.</summary>
    private static void Impl(JsonElement root)
    {
        string[][] cases =
        {
            new[] { "server", "finished_key_server", "th_scv", "verify_data_server" },
            new[] { "client", "finished_key_client", "th_ccv", "verify_data_client" },
        };
        foreach (string[] c in cases)
        {
            byte[] fk = FromHex(Sat(root, "npamp_inputs", c[1]));
            byte[] th = FromHex(Sat(root, "npamp_inputs", c[2]));
            byte[] want = FromHex(Sat(root, "expected", c[3]));

            byte[] got = Handshake.ComputeFinished(fk, th, true);
            Check("impl: " + c[0] + " ComputeFinished", BytesEqual(got, want),
                "got " + Npamp.ToHex(got) + " want " + Npamp.ToHex(want));

            Check("impl: " + c[0] + " VerifyFinished accepts",
                Handshake.VerifyFinished(fk, th, want, true), "");

            byte[] bad = (byte[])want.Clone();
            bad[0] ^= 0x01;
            Check("impl: " + c[0] + " VerifyFinished rejects tamper",
                !Handshake.VerifyFinished(fk, th, bad, true), "");
        }
    }

    public static int Main(string[] args)
    {
        using JsonDocument doc = LoadPinned(args, "finished-kat.json", FinishedKatSha256);
        JsonElement root = doc.RootElement;
        Anchor(root);
        Oracle(root);
        Impl(root);
        Console.WriteLine(_failures == 0
            ? "ALL PASS (finished KAT: anchor+oracle+impl)"
            : "FAILURES: " + _failures);
        return _failures == 0 ? 0 : 1;
    }
}
