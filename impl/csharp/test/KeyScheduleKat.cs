// Standards-derived, NON-CIRCULAR known-answer test for the draft-00 key schedule
// (binding spec/10 section 5; draft-00 section 7.4 HKDF-Expand-Label + section 7.5 traffic keys).
// C# mirror of the Go/Java/TS/Python reference tests against the SAME pinned vector
// (test-vectors/v1/key-schedule-kat.json).
//
// Three legs:
//   ANCHOR  raw HKDF-Extract/Expand reproduce the RFC 5869 TC1 prk and okm.
//   ORACLE  an independent in-test HKDF-Expand-Label that rebuilds the HkdfLabel bytes itself with
//           the label prefix as a PARAMETER, proven against RFC 8448's "tls13 " key/iv/finished. The
//           oracle NEVER calls Npamp.HkdfExpandLabel; it re-derives the label bytes from the spec, so
//           the two must independently agree.
//   IMPL    the new HkdfExtract + HandshakeSecret ladder + DeriveFinishedKey, plus the existing
//           DeriveTrafficSecret/DeriveKeyIv, each compared to the proven oracle applied with "n-pamp ".
//
// Non-circularity: this test stores NO golden N-PAMP outputs; it derives them via the RFC-anchored
// oracle, then judges the impl against that oracle. The vector file holds only RFC anchors + inputs.
//
// Self-contained: builds with Npamp.cs + Handshake.cs + this file only. JSON via System.Text.Json.
#nullable enable
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Sh.Bubblefish.Npamp;

public static class KeyScheduleKat
{
    private const string KeyScheduleKatSha256 = "e108f5cfdf99a378d7b677792448c8046abf3c630fc23fd8ea2ccb3927f2691c";

    // The s2c handshake AEAD derivation pins these context fields. The suite is bound via the impl's own
    // Npamp.AeadAes256Gcm: AES-256-GCM = 0x0001 per registries/aead.csv (= the impl's AEAD_AES256_GCM =
    // npamp.AEADAES256GCM in the Go reference); 0x0002 is ChaCha20-Poly1305. The draft-00 section 7.5
    // traffic context binds this AEAD code point. DirServerToClient is the directional byte; epoch 0 + the
    // Control channel complete the handshake-phase context dir(1) || epoch(8 BE) || suite(2 BE) || channel(2 BE).
    private const int DirServerToClient = 1;

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

    // -- Independent oracle primitives (RFC 5869 / RFC 8446 7.1; no Npamp key schedule) -----

    /// <summary>HKDF-Extract (RFC 5869 2.2): HMAC-SHA-256(salt, ikm). Independent of Npamp.HkdfExtract.</summary>
    private static byte[] ExtractOracle(byte[] salt, byte[] ikm)
    {
        using var mac = new HMACSHA256(salt);
        return mac.ComputeHash(ikm);
    }

    /// <summary>HKDF-Expand (RFC 5869 2.3): T(i) = HMAC(prk, T(i-1) || info || i). Independent of Npamp.HkdfExpand.</summary>
    private static byte[] ExpandOracle(byte[] prk, byte[] info, int length)
    {
        const int hashLen = 32; // SHA-256
        using var mac = new HMACSHA256(prk);
        int n = (length + hashLen - 1) / hashLen;
        byte[] outBuf = new byte[n * hashLen];
        byte[] t = Array.Empty<byte>();
        int pos = 0;
        for (int i = 1; i <= n; i++)
        {
            byte[] input = new byte[t.Length + info.Length + 1];
            Array.Copy(t, 0, input, 0, t.Length);
            Array.Copy(info, 0, input, t.Length, info.Length);
            input[input.Length - 1] = (byte)i;
            t = mac.ComputeHash(input);
            Array.Copy(t, 0, outBuf, pos, hashLen);
            pos += hashLen;
        }
        byte[] result = new byte[length];
        Array.Copy(outBuf, 0, result, 0, length);
        return result;
    }

    /// <summary>
    /// HKDF-Expand-Label (RFC 8446 7.1) rebuilt from the spec with the label prefix as a PARAMETER:
    /// HkdfLabel = u16(L) || u8(len(prefix+label)) || (prefix+label) || u8(len(ctx)) || ctx. The prefix
    /// swap ("n-pamp " vs TLS "tls13 ") is the only N-PAMP-original element. Never calls Npamp.HkdfExpandLabel.
    /// </summary>
    private static byte[] ExpandLabelOracle(byte[] secret, string prefix, string label, byte[] context, int length)
    {
        byte[] full = Encoding.ASCII.GetBytes(prefix + label);
        byte[] info = new byte[2 + 1 + full.Length + 1 + context.Length];
        int p = 0;
        info[p++] = (byte)((length >> 8) & 0xFF);
        info[p++] = (byte)(length & 0xFF);
        info[p++] = (byte)full.Length;
        Array.Copy(full, 0, info, p, full.Length);
        p += full.Length;
        info[p++] = (byte)context.Length;
        Array.Copy(context, 0, info, p, context.Length);
        return ExpandOracle(secret, info, length);
    }

    // -- Legs --------------------------------------------------------------

    /// <summary>ANCHOR: raw HKDF-Extract/Expand reproduce the published RFC 5869 TC1 prk and okm.</summary>
    private static void Anchor(JsonElement root)
    {
        byte[] ikm = FromHex(Sat(root, "rfc5869_tc1", "ikm"));
        byte[] salt = FromHex(Sat(root, "rfc5869_tc1", "salt"));
        byte[] info = FromHex(Sat(root, "rfc5869_tc1", "info"));
        int len = At(root, "rfc5869_tc1", "L").GetInt32();
        string wantPrk = Sat(root, "rfc5869_tc1", "prk");
        string wantOkm = Sat(root, "rfc5869_tc1", "okm");

        byte[] prk = ExtractOracle(salt, ikm);
        string gotPrk = Npamp.ToHex(prk);
        Check("anchor: RFC 5869 TC1 extract", gotPrk == wantPrk, "got " + gotPrk + " want " + wantPrk);

        string gotOkm = Npamp.ToHex(ExpandOracle(prk, info, len));
        Check("anchor: RFC 5869 TC1 expand", gotOkm == wantOkm, "got " + gotOkm + " want " + wantOkm);
    }

    /// <summary>ORACLE: the in-test HKDF-Expand-Label reproduces RFC 8448 key/iv/finished (tls13 prefix).</summary>
    private static void Oracle(JsonElement root)
    {
        byte[] secret = FromHex(Sat(root, "rfc8448_expand_label", "client_handshake_traffic_secret"));

        string gotKey = Npamp.ToHex(ExpandLabelOracle(secret, "tls13 ", "key", Array.Empty<byte>(), 16));
        Check("oracle: RFC 8448 write_key (tls13 )",
            gotKey == Sat(root, "rfc8448_expand_label", "write_key"), "got " + gotKey);

        string gotIv = Npamp.ToHex(ExpandLabelOracle(secret, "tls13 ", "iv", Array.Empty<byte>(), 12));
        Check("oracle: RFC 8448 write_iv (tls13 )",
            gotIv == Sat(root, "rfc8448_expand_label", "write_iv"), "got " + gotIv);

        string gotFin = Npamp.ToHex(ExpandLabelOracle(secret, "tls13 ", "finished", Array.Empty<byte>(), 32));
        Check("oracle: RFC 8448 finished_key (tls13 )",
            gotFin == Sat(root, "rfc8448_expand_label", "finished_key"), "got " + gotFin);
    }

    /// <summary>IMPL: the new key-schedule functions reproduce the proven oracle applied with "n-pamp ".</summary>
    private static void Impl(JsonElement root)
    {
        // Drift-check: if the label prefix constant is ever edited off the spec section 7.4 value,
        // this fires before any derivation is judged.
        if (Npamp.LabelPrefix != "n-pamp ")
        {
            Check("impl: label prefix matches spec section 7.4", false, "prefix=" + Npamp.LabelPrefix);
            return;
        }

        byte[] mlkem = FromHex(Sat(root, "npamp_inputs", "ikm_mlkem_ss"));
        byte[] x25519 = FromHex(Sat(root, "npamp_inputs", "ikm_x25519_ss"));
        byte[] thKem = FromHex(Sat(root, "npamp_inputs", "th_kem"));
        byte[] thCcv = FromHex(Sat(root, "npamp_inputs", "th_ccv"));

        // handshake_secret: HKDF-Extract over ML-KEM || X25519 with the 32-zero default salt.
        byte[] zeros32 = new byte[32];
        byte[] ikm = new byte[mlkem.Length + x25519.Length];
        Array.Copy(mlkem, 0, ikm, 0, mlkem.Length);
        Array.Copy(x25519, 0, ikm, mlkem.Length, x25519.Length);
        byte[] hsOracle = ExtractOracle(zeros32, ikm);

        byte[] hs = Npamp.HandshakeSecret(mlkem, x25519, true);
        Check("impl: handshake_secret", BytesEqual(hs, hsOracle),
            "got " + Npamp.ToHex(hs) + " want " + Npamp.ToHex(hsOracle));

        // The raw HKDF-Extract entrypoint reproduces the same root independently of HandshakeSecret.
        Check("impl: HkdfExtract(zeros32, ML-KEM||X25519)",
            BytesEqual(Npamp.HkdfExtract(zeros32, ikm, true), hsOracle), "");

        // c_hs / s_hs (bound to th_kem) and master (bound to th_ccv).
        byte[] cHsOracle = ExpandLabelOracle(hs, "n-pamp ", "c hs", thKem, 32);
        byte[] cHs = Npamp.DeriveClientHandshakeSecret(hs, thKem, true);
        Check("impl: c_hs", BytesEqual(cHs, cHsOracle),
            "got " + Npamp.ToHex(cHs) + " want " + Npamp.ToHex(cHsOracle));

        byte[] sHsOracle = ExpandLabelOracle(hs, "n-pamp ", "s hs", thKem, 32);
        byte[] sHs = Npamp.DeriveServerHandshakeSecret(hs, thKem, true);
        Check("impl: s_hs", BytesEqual(sHs, sHsOracle),
            "got " + Npamp.ToHex(sHs) + " want " + Npamp.ToHex(sHsOracle));

        byte[] masterOracle = ExpandLabelOracle(hs, "n-pamp ", "master", thCcv, 32);
        byte[] master = Npamp.DeriveMasterSecret(hs, thCcv, true);
        Check("impl: master", BytesEqual(master, masterOracle),
            "got " + Npamp.ToHex(master) + " want " + Npamp.ToHex(masterOracle));

        // finished_key for both directions: client from c_hs, server from s_hs.
        byte[] fkClientOracle = ExpandLabelOracle(cHs, "n-pamp ", "finished", Array.Empty<byte>(), 32);
        byte[] fkClient = Npamp.DeriveFinishedKey(cHs, true);
        Check("impl: finished_key(c_hs)", BytesEqual(fkClient, fkClientOracle),
            "got " + Npamp.ToHex(fkClient) + " want " + Npamp.ToHex(fkClientOracle));

        byte[] fkServerOracle = ExpandLabelOracle(sHs, "n-pamp ", "finished", Array.Empty<byte>(), 32);
        byte[] fkServer = Npamp.DeriveFinishedKey(sHs, true);
        Check("impl: finished_key(s_hs)", BytesEqual(fkServer, fkServerOracle),
            "got " + Npamp.ToHex(fkServer) + " want " + Npamp.ToHex(fkServerOracle));

        // s2c handshake AEAD: traffic secret from s_hs, then {key, iv}. The oracle rebuilds the SAME
        // context dir(1) || epoch(8 BE) || suite(2 BE) || channel(2 BE) independently.
        byte[] ctx = new byte[1 + 8 + 2 + 2];
        ctx[0] = (byte)DirServerToClient; // epoch 0 -> bytes 1..8 stay zero
        ctx[9] = (byte)((Npamp.AeadAes256Gcm >> 8) & 0xFF);
        ctx[10] = (byte)(Npamp.AeadAes256Gcm & 0xFF);
        ctx[11] = (byte)((Npamp.ChanControl >> 8) & 0xFF);
        ctx[12] = (byte)(Npamp.ChanControl & 0xFF);
        byte[] tsOracle = ExpandLabelOracle(sHs, "n-pamp ", "traffic", ctx, 32);
        byte[] keyOracle = ExpandLabelOracle(tsOracle, "n-pamp ", "key", Array.Empty<byte>(), 32);
        byte[] ivOracle = ExpandLabelOracle(tsOracle, "n-pamp ", "iv", Array.Empty<byte>(), 12);

        byte[] ts = Npamp.DeriveTrafficSecret(sHs, DirServerToClient, 0UL, Npamp.AeadAes256Gcm, Npamp.ChanControl, true);
        (byte[] key, byte[] iv) = Npamp.DeriveKeyIv(ts, true);
        Check("impl: s2c handshake key", BytesEqual(key, keyOracle),
            "got " + Npamp.ToHex(key) + " want " + Npamp.ToHex(keyOracle));
        Check("impl: s2c handshake iv", BytesEqual(iv, ivOracle),
            "got " + Npamp.ToHex(iv) + " want " + Npamp.ToHex(ivOracle));
    }

    public static int Main(string[] args)
    {
        using JsonDocument doc = LoadPinned(args, "key-schedule-kat.json", KeyScheduleKatSha256);
        JsonElement root = doc.RootElement;
        Anchor(root);
        Oracle(root);
        Impl(root);
        Console.WriteLine(_failures == 0
            ? "ALL PASS (key-schedule KAT: anchor+oracle+impl)"
            : "FAILURES: " + _failures);
        return _failures == 0 ? 0 : 1;
    }
}
