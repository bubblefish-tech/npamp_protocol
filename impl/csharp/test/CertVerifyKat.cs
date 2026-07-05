// Standards-derived, NON-CIRCULAR known-answer test for the draft-00 CertVerify
// (binding spec/10 section 6.1; RFC 8446 section 4.4.3 structure; Ed25519 per RFC 8032). The value
// is u16(0x0807) || Ed25519(priv, signing_input), signing_input = 64*0x20 || context || 0x00 || TH.
// C# mirror of the Go/Java/TS/Python reference tests against the SAME pinned vector
// (test-vectors/v1/certverify-kat.json).
//
// Three legs: ANCHOR (the src Ed25519 helpers reproduce RFC 8032 TEST1/TEST2 pubkeys + signatures),
// ORACLE (rebuild signing_input by hand + sign with an independently constructed key, no src signing
// functions), IMPL (CertVerifySigningInput + SignCertVerify reproduce the vector; VerifyCertVerify
// accepts the correct value but rejects role/context mismatch, wrong transcript, wrong scheme, and a
// truncated signature). Ed25519 (RFC 8032) is deterministic, so any conforming signer reproduces it.
//
// Self-contained: builds with Npamp.cs + Handshake.cs + this file only. JSON via System.Text.Json.
// Ed25519 via BouncyCastle.Cryptography (Org.BouncyCastle.Crypto.Signers.Ed25519Signer).
#nullable enable
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Sh.Bubblefish.Npamp;

public static class CertVerifyKat
{
    private const string CertVerifyKatSha256 = "f56ec6ba250ba8f8c6c84214a16f580a3e476e9b2cfd05720c3352de299fe555";

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

    // -- Independent oracle primitives (no src signing functions) -----------

    /// <summary>Oracle signing input, built by hand independently of CertVerifySigningInput.</summary>
    private static byte[] OracleSigningInput(string ctx, byte[] th)
    {
        byte[] c = Encoding.ASCII.GetBytes(ctx);
        byte[] outBuf = new byte[64 + c.Length + 1 + th.Length];
        int p = 0;
        for (int i = 0; i < 64; i++)
        {
            outBuf[p++] = 0x20;
        }
        Array.Copy(c, 0, outBuf, p, c.Length);
        p += c.Length;
        outBuf[p++] = 0x00;
        Array.Copy(th, 0, outBuf, p, th.Length);
        return outBuf;
    }

    /// <summary>Independent Ed25519 sign over an arbitrary message from a raw 32-octet seed.</summary>
    private static byte[] OracleSign(byte[] seed, byte[] msg)
    {
        var signer = new Ed25519Signer();
        signer.Init(true, new Ed25519PrivateKeyParameters(seed, 0));
        signer.BlockUpdate(msg, 0, msg.Length);
        return signer.GenerateSignature();
    }

    /// <summary>Independent Ed25519 verify of a signature over a message from a raw 32-octet pubkey.</summary>
    private static bool OracleVerify(byte[] rawPub, byte[] msg, byte[] sig)
    {
        var verifier = new Ed25519Signer();
        verifier.Init(false, new Ed25519PublicKeyParameters(rawPub, 0));
        verifier.BlockUpdate(msg, 0, msg.Length);
        return verifier.VerifySignature(sig);
    }

    // -- Legs --------------------------------------------------------------

    /// <summary>ANCHOR: the src Ed25519 helpers reproduce RFC 8032 TEST1/TEST2 pubkeys + signatures.</summary>
    private static void Anchor(JsonElement root)
    {
        foreach (string tc in new[] { "test1", "test2" })
        {
            byte[] seed = FromHex(Sat(root, "rfc8032_ed25519", tc, "seed"));
            byte[] msg = FromHex(Sat(root, "rfc8032_ed25519", tc, "message"));
            string wantPub = Sat(root, "rfc8032_ed25519", tc, "public_key");
            string wantSig = Sat(root, "rfc8032_ed25519", tc, "signature");

            // Derived public key from the seed equals the published RFC 8032 public key.
            string gotPub = Npamp.ToHex(Handshake.Ed25519PrivateKeyFromSeed(seed).GeneratePublicKey().GetEncoded());
            Check("anchor: RFC 8032 " + tc + " derived pubkey", gotPub == wantPub,
                "got " + gotPub + " want " + wantPub);

            // Deterministic signature equals the published RFC 8032 signature.
            string gotSig = Npamp.ToHex(OracleSign(seed, msg));
            Check("anchor: RFC 8032 " + tc + " signature", gotSig == wantSig,
                "got " + gotSig + " want " + wantSig);

            // The raw-pubkey decoder round-trips: decode the published pubkey, verify the published sig.
            Check("anchor: RFC 8032 " + tc + " pubkey-from-raw verifies",
                OracleVerify(FromHex(wantPub), msg, FromHex(wantSig)), "");
        }
    }

    /// <summary>ORACLE: rebuild signing_input by hand + sign with an independent key (guards the vector).</summary>
    private static void Oracle(JsonElement root)
    {
        string[][] cases =
        {
            new[] { "server", "server", "server_seed", "th_sid", "signing_input_server", "signature_server" },
            new[] { "client", "client", "client_seed", "th_cid", "signing_input_client", "signature_client" },
        };
        foreach (string[] c in cases)
        {
            string ctx = Sat(root, "contexts", c[1]);
            byte[] seed = FromHex(Sat(root, "npamp_inputs", c[2]));
            byte[] th = FromHex(Sat(root, "npamp_inputs", c[3]));
            byte[] si = OracleSigningInput(ctx, th);
            string gotSi = Npamp.ToHex(si);
            Check("oracle: " + c[0] + " signing_input", gotSi == Sat(root, "expected", c[4]), "got " + gotSi);
            string gotSig = Npamp.ToHex(OracleSign(seed, si));
            Check("oracle: " + c[0] + " signature", gotSig == Sat(root, "expected", c[5]), "got " + gotSig);
        }
    }

    /// <summary>IMPL: CertVerifySigningInput + SignCertVerify reproduce the vector; VerifyCertVerify guards.</summary>
    private static void Impl(JsonElement root)
    {
        if (Handshake.ContextServerCertVerify != Sat(root, "contexts", "server")
            || Handshake.ContextClientCertVerify != Sat(root, "contexts", "client"))
        {
            Check("impl: context constants match spec section 6.1", false,
                "server=" + Handshake.ContextServerCertVerify + " client=" + Handshake.ContextClientCertVerify);
            return;
        }

        (string name, bool isServer, string seedKey, string pubKey, string thKey, string siKey, string valKey)[] cases =
        {
            ("server", true, "server_seed", "server_pub", "th_sid", "signing_input_server", "certverify_value_server"),
            ("client", false, "client_seed", "client_pub", "th_cid", "signing_input_client", "certverify_value_client"),
        };
        foreach (var c in cases)
        {
            Ed25519PrivateKeyParameters priv = Handshake.Ed25519PrivateKeyFromSeed(FromHex(Sat(root, "npamp_inputs", c.seedKey)));
            Ed25519PublicKeyParameters pub = Handshake.Ed25519PublicKeyFromRaw(FromHex(Sat(root, "npamp_inputs", c.pubKey)));
            byte[] th = FromHex(Sat(root, "npamp_inputs", c.thKey));

            string gotSi = Npamp.ToHex(Handshake.CertVerifySigningInput(c.isServer, th));
            Check("impl: " + c.name + " CertVerifySigningInput", gotSi == Sat(root, "expected", c.siKey), "got " + gotSi);

            byte[] val = Handshake.SignCertVerify(priv, c.isServer, th);
            Check("impl: " + c.name + " SignCertVerify value", Npamp.ToHex(val) == Sat(root, "expected", c.valKey),
                "got " + Npamp.ToHex(val));

            Check("impl: " + c.name + " VerifyCertVerify accepts",
                Handshake.VerifyCertVerify(pub, c.isServer, th, val), "");

            // Domain separation: the opposite role must FAIL (different context string).
            Check("impl: " + c.name + " rejects role/context mismatch",
                !Handshake.VerifyCertVerify(pub, !c.isServer, th, val), "");

            // Transcript binding: a different transcript hash must FAIL.
            byte[] wrongTh = (byte[])th.Clone();
            wrongTh[0] ^= 0x01;
            Check("impl: " + c.name + " rejects wrong transcript",
                !Handshake.VerifyCertVerify(pub, c.isServer, wrongTh, val), "");

            // Scheme guard: a non-Ed25519 scheme code point must FAIL.
            byte[] badScheme = (byte[])val.Clone();
            badScheme[0] = (byte)((Npamp.SigMldsa87 >> 8) & 0xFF);
            badScheme[1] = (byte)(Npamp.SigMldsa87 & 0xFF);
            Check("impl: " + c.name + " rejects non-Ed25519 scheme",
                !Handshake.VerifyCertVerify(pub, c.isServer, th, badScheme), "");

            // Length guard: an Ed25519 signature is exactly 64 octets; a truncated value must FAIL.
            byte[] truncated = new byte[val.Length - 1];
            Array.Copy(val, 0, truncated, 0, truncated.Length);
            Check("impl: " + c.name + " rejects truncated signature",
                !Handshake.VerifyCertVerify(pub, c.isServer, th, truncated), "");
        }
    }

    public static int Main(string[] args)
    {
        using JsonDocument doc = LoadPinned(args, "certverify-kat.json", CertVerifyKatSha256);
        JsonElement root = doc.RootElement;
        Anchor(root);
        Oracle(root);
        Impl(root);
        Console.WriteLine(_failures == 0
            ? "ALL PASS (certverify KAT: anchor+oracle+impl)"
            : "FAILURES: " + _failures);
        return _failures == 0 ? 0 : 1;
    }
}
