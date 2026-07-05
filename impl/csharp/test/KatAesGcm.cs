// Independent crypto KAT: drive N-PAMP's AES-256-GCM seal/open through Google
// Project Wycheproof vectors (C2SP/wycheproof), via the dependency-free flat
// corpus _shared/wycheproof/aesgcm_kat.tsv (keySize=256, ivSize=96, tagSize=128).
//
// These vectors are authored by an independent authority and encode KNOWN
// ATTACKS (truncated tags, modified ciphertext) that our self-generated golden
// vectors never include — so a shared bug between our impls cannot pass them.
//
// Trick: SealAes256Gcm(key, iv, seq, ...) derives nonce = iv XOR (0^4||seq);
// with seq=0 the nonce IS the given IV, so each vector exercises the REAL
// seal/open path.
//
// Exit 0 iff every vector behaves exactly as Wycheproof labels it. Direct port
// of the reference runner test/kat_aesgcm_wycheproof.py (passes 66/66).
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Sh.Bubblefish.Npamp;

public static class KatAesGcm
{
    private static byte[] Hex(string s) => s.Length == 0 ? Array.Empty<byte>() : Convert.FromHexString(s);

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

    public static int Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.Error.WriteLine("usage: KatAesGcm <aesgcm_kat.tsv>");
            return 1;
        }
        string tsvPath = args[0];

        int total = 0, passed = 0;
        var fails = new List<(string Tc, string Result, string Reason)>();

        foreach (string rawLine in File.ReadAllLines(tsvPath))
        {
            string line = rawLine;
            if (line.Length == 0 || line.StartsWith("#"))
            {
                continue;
            }
            // tcId, result, key, iv, aad, msg, ct, tag — tab-separated; aad/msg/ct/tag may be empty.
            string[] f = line.Split('\t');
            if (f.Length < 8)
            {
                continue;
            }
            string tc = f[0];
            string result = f[1];
            byte[] key = Hex(f[2]);
            byte[] iv = Hex(f[3]);
            byte[] aad = Hex(f[4]);
            byte[] msg = Hex(f[5]);
            byte[] ct = Hex(f[6]);
            byte[] tag = Hex(f[7]);
            byte[] sealedBytes = ct.Concat(tag).ToArray();

            bool ok = true;
            string reason = "";

            if (result == "valid")
            {
                if (!BytesEqual(Npamp.SealAes256Gcm(key, iv, 0UL, aad, msg), sealedBytes))
                {
                    ok = false;
                    reason = "encrypt mismatch";
                }
                else
                {
                    bool decryptMatch;
                    try
                    {
                        decryptMatch = BytesEqual(Npamp.OpenAes256Gcm(key, iv, 0UL, aad, sealedBytes), msg);
                    }
                    catch (Exception)
                    {
                        decryptMatch = false;
                    }
                    if (!decryptMatch)
                    {
                        ok = false;
                        reason = "decrypt mismatch";
                    }
                }
            }
            else if (result == "invalid")
            {
                try
                {
                    Npamp.OpenAes256Gcm(key, iv, 0UL, aad, sealedBytes);
                    ok = false;
                    reason = "accepted an invalid vector";
                }
                catch (Exception)
                {
                    // correct: rejected
                }
            }
            else // "acceptable"
            {
                try
                {
                    if (!BytesEqual(Npamp.OpenAes256Gcm(key, iv, 0UL, aad, sealedBytes), msg))
                    {
                        ok = false;
                        reason = "acceptable but wrong plaintext";
                    }
                }
                catch (Exception)
                {
                    // rejection is also allowed for acceptable vectors
                }
            }

            total++;
            if (ok)
            {
                passed++;
            }
            else
            {
                fails.Add((tc, result, reason));
            }
        }

        Console.WriteLine($"AES-256-GCM Wycheproof KAT (csharp): {passed}/{total} passed");
        foreach (var fail in fails.Take(15))
        {
            Console.WriteLine($"  FAIL tcId={fail.Tc} result={fail.Result}: {fail.Reason}");
        }
        return (fails.Count == 0 && total > 0) ? 0 : 1;
    }
}
