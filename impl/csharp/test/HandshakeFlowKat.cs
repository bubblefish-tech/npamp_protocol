// Byte-pinned handshake-flow known-answer test (issue #60, class golden-interop). Unlike the
// standards-anchored primitive KATs (transcript/finished/certverify/key-schedule), this vector pins the
// Go reference's SERIALIZED handshake frames so every language impl reproduces them byte-for-byte. The
// CLIENT_HELLO whole-frame assertion is the one that catches the draft-00-vs-draft-01 ProfileOffer wire
// drift (a fixed 4-octet ProfileOffer vs the draft-01 one-octet form: TLV 0x0001, len 1, value 0x01).
//
// C# mirror of impl/go/handshakeflow_kat_test.go against the SAME frozen vector
// (test-vectors/v1/handshake-flow-kat.json). This rebuilds every EXPECTED artifact through THIS impl's
// real code path from the pinned INPUTS:
//   * kem_share      = ML-KEM-768 encapsulation key (from the d||z seed) || X25519 public (from the
//                      client private) -- both via BouncyCastle, ML-KEM-first per ADR-0005.
//   * decapsulation  = MLKemDecapsulator over the pinned mlkem_ciphertext under the seed-derived key
//                      MUST recover mlkem_shared_secret (self-validating input; encaps is
//                      non-deterministic so the ciphertext is captured-once and pinned). X25519 ECDH
//                      MUST recover x25519_shared_secret.
//   * frames         = CLIENT_HELLO / SERVER_HELLO / SERVER_AUTH / CLIENT_AUTH rebuilt through the real
//                      Npamp.Frame.Marshal() (36-octet header, CRC32C) + the real Npamp AEAD seal, then
//                      asserted for WHOLE-FRAME byte-equality (not lengths/substrings).
//   * transcript     = th_kem/sid/scv/cid/ccv through the real Handshake.Transcript.
//   * key ladder     = handshake_secret / c_hs / s_hs / master / traffic secrets+keys+ivs through the
//                      real Npamp.HandshakeSecret + Derive* functions.
//   * finished       = finished keys + MACs through Npamp.DeriveFinishedKey + Handshake.ComputeFinished.
//   * certverify     = signatures through Handshake.SignCertVerify (Ed25519 is deterministic, RFC 8032).
//   * mutation guard = a one-octet flip in a CertVerify signature AND in the client Finished MAC MUST
//                      REJECT via Handshake.VerifyCertVerify / Handshake.VerifyFinished.
//
// The TLV payload byte layout (ProfileOffer/KEMOffer/... for CH/SH, IdentityKey/CertVerify/Finished for
// AUTH) is rebuilt inline in this test from the vector's pinned artifacts -- the open C# impl exposes the
// framing, AEAD, transcript, key schedule, and CertVerify/Finished primitives, but not a ClientHello/
// ServerHello/AuthMessage message encoder, so the message-level TLV assembly lives here (as the sibling
// KATs assemble their oracle bytes inline). Every cryptographic transform runs through the real impl.
//
// ML-KEM-768 + X25519 come from BouncyCastle.Cryptography 2.6.2 (same binary the Ed25519 KATs use):
//   MLKemParameters.ml_kem_768, MLKemPrivateKeyParameters.FromSeed(params, seed64), MLKemDecapsulator,
//   X25519PrivateKeyParameters, X25519Agreement. SHA-256/HMAC/AES-GCM come from the .NET BCL via Npamp.cs.
#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;

namespace Sh.Bubblefish.Npamp;

public static class HandshakeFlowKat
{
    private const string HandshakeFlowKatSha256 = "cf1d3c1fba550f3742e4de16d0f86d3beeafeb56efff90f85ff16165063c0fc9";

    // Frame types (binding spec/10 section 1), carried on the Control channel, seq 0.
    private const int FrameClientHello = Handshake.FrameClientHello; // 0x0100
    private const int FrameServerHello = Handshake.FrameServerHello; // 0x0101
    private const int FrameServerAuth = Handshake.FrameServerAuth;   // 0x0102
    private const int FrameClientAuth = Handshake.FrameClientAuth;   // 0x0103

    // Directional bytes (draft-00 section 7.5 traffic context).
    private const int DirClientToServer = 0;
    private const int DirServerToClient = 1;

    // ML-KEM-768 / X25519MLKEM768 wire sizes (spec/10 section 4; FIPS 203; RFC 7748).
    private const int MlkemEkSize = 1184;         // ML-KEM-768 encapsulation key
    private const int MlkemCtSize = 1088;         // ML-KEM-768 ciphertext
    private const int X25519PubSize = 32;         // X25519 public key
    private const int KemShareSize = MlkemEkSize + X25519PubSize;  // 1216, TLV 0x0007 value
    private const int KemCiphertextSize = MlkemCtSize + X25519PubSize; // 1120, TLV 0x0008 value

    // CLIENT_HELLO / SERVER_HELLO TLV types (binding spec/10 section 1).
    private const int TlvProfileOffer = 0x0001, TlvKemOffer = 0x0003, TlvSigOffer = 0x0005,
        TlvAeadOffer = 0x000c, TlvKemShare = 0x0007;
    private const int TlvProfileSelect = 0x0002, TlvKemSelect = 0x0004, TlvSigSelect = 0x0006,
        TlvAeadSelect = 0x000d, TlvKemCiphertext = 0x0008;
    // AUTH TLV types.
    private const int TlvIdentityKey = 0x0009, TlvCertVerify = 0x000a, TlvFinished = 0x000b;

    // Wire code points (registries): Standard profile, X25519MLKEM768, Ed25519, AES-256-GCM.
    private const int ProfileStandard = 0x01;

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

    // -- Small KAT helpers (self-contained, mirror the sibling KATs) --------

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

    // -- Inline TLV / frame assembly (message-level encoding lives in the test) ----

    /// <summary>Appends one TLV: Type(2 BE) || Length(2 BE) || Value. Mirrors Handshake.Transcript.AddTLV.</summary>
    private static void AppendTlv(List<byte> buf, int type, byte[] value)
    {
        buf.Add((byte)((type >> 8) & 0xFF));
        buf.Add((byte)(type & 0xFF));
        buf.Add((byte)((value.Length >> 8) & 0xFF));
        buf.Add((byte)(value.Length & 0xFF));
        buf.AddRange(value);
    }

    private static byte[] U16(int v) => new[] { (byte)((v >> 8) & 0xFF), (byte)(v & 0xFF) };

    /// <summary>Builds a cleartext handshake frame (Control channel, seq 0) through the real Npamp.Frame.Marshal().</summary>
    private static byte[] MarshalFrame(int ftype, byte[] payload)
    {
        var f = new Npamp.Frame(ftype, Npamp.ChanControl, 0UL, 0, 0, payload);
        return f.Marshal();
    }

    /// <summary>
    /// Seals an AUTH plaintext into a wire frame through the real key schedule + AEAD record path:
    /// traffic secret from the base handshake secret, {key, iv}, AAD = the 21-octet header prefix over
    /// the encrypted-frame length (plaintext + 16-octet tag), FLAG_ENC set, seq 0.
    /// </summary>
    private static byte[] SealAuthFrame(int ftype, byte[] baseSecret, int dir, byte[] plaintext)
    {
        byte[] ts = Npamp.DeriveTrafficSecret(baseSecret, dir, 0UL, Npamp.AeadAes256Gcm, Npamp.ChanControl, true);
        (byte[] key, byte[] iv) = Npamp.DeriveKeyIv(ts, true);
        var f = new Npamp.Frame(ftype, Npamp.ChanControl, 0UL, Npamp.FlagEnc);
        byte[] aad = f.HeaderPrefix(plaintext.Length + 16);
        byte[] sealed_ = Npamp.SealAes256Gcm(key, iv, 0UL, aad, plaintext);
        f.Payload = sealed_;
        return f.Marshal();
    }

    private static void AssertHex(string name, byte[] got, string wantHex)
    {
        string g = Npamp.ToHex(got);
        Check(name, g == wantHex, "got " + g + " want " + wantHex);
    }

    private static void AssertTrafficKeyIv(string name, byte[] parent, int dir, string tsHex, string keyHex, string ivHex)
    {
        byte[] ts = Npamp.DeriveTrafficSecret(parent, dir, 0UL, Npamp.AeadAes256Gcm, Npamp.ChanControl, true);
        AssertHex(name + "_traffic_secret", ts, tsHex);
        (byte[] key, byte[] iv) = Npamp.DeriveKeyIv(ts, true);
        AssertHex(name + "_key", key, keyHex);
        AssertHex(name + "_iv", iv, ivHex);
    }

    // -- The flow ----------------------------------------------------------

    public static int Main(string[] args)
    {
        using JsonDocument doc = LoadPinned(args, "handshake-flow-kat.json", HandshakeFlowKatSha256);
        JsonElement root = doc.RootElement;
        JsonElement inp = root.GetProperty("inputs");
        JsonElement exp = root.GetProperty("expected");

        // Drift-check: the frame-type constants must match spec section 1 (mirrors TranscriptKat).
        if (FrameClientHello != 0x0100 || FrameServerHello != 0x0101
            || FrameServerAuth != 0x0102 || FrameClientAuth != 0x0103)
        {
            Check("frame-type constants match spec section 1", false,
                "CH=" + FrameClientHello + " SH=" + FrameServerHello);
            Console.WriteLine("FAILURES: " + _failures);
            return 1;
        }

        byte[] clientX25519Priv = FromHex(Sat(inp, "client_x25519_private"));
        byte[] serverX25519Priv = FromHex(Sat(inp, "server_x25519_private"));
        byte[] mlkemSeed = FromHex(Sat(inp, "mlkem768_seed_dz"));
        byte[] mlkemCiphertext = FromHex(Sat(inp, "mlkem_ciphertext"));
        byte[] clientEdSeed = FromHex(Sat(inp, "client_identity_ed25519_seed"));
        byte[] serverEdSeed = FromHex(Sat(inp, "server_identity_ed25519_seed"));
        byte[] wantMlkemSs = FromHex(Sat(inp, "mlkem_shared_secret"));
        byte[] wantX25519Ss = FromHex(Sat(inp, "x25519_shared_secret"));

        // Ed25519 identity keys (RFC 8032) from the fixed seeds, via the impl's helper.
        Ed25519PrivateKeyParameters clientPriv = Handshake.Ed25519PrivateKeyFromSeed(clientEdSeed);
        Ed25519PrivateKeyParameters serverPriv = Handshake.Ed25519PrivateKeyFromSeed(serverEdSeed);
        byte[] clientPub = clientPriv.GeneratePublicKey().GetEncoded();
        byte[] serverPub = serverPriv.GeneratePublicKey().GetEncoded();

        // --- KEM: rebuild kem_share and self-validate the decapsulation. ---
        // ML-KEM-768 decapsulation key from the d||z seed (FromSeed takes the 64-octet seed; d=seed[0:32],
        // z=seed[32:64]) and its encapsulation key. X25519 private from the fixed RFC 7748 scalar.
        MLKemPrivateKeyParameters mlkemPriv =
            MLKemPrivateKeyParameters.FromSeed(MLKemParameters.ml_kem_768, mlkemSeed);
        byte[] mlkemEk = mlkemPriv.GetPublicKeyEncoded();
        var x25519Priv = new X25519PrivateKeyParameters(clientX25519Priv, 0);
        byte[] clientX25519Pub = x25519Priv.GeneratePublicKey().GetEncoded();

        // kem_share = ML-KEM ek (1184) || X25519 public (32), ML-KEM-first (spec/10 section 4).
        byte[] kemShare = new byte[KemShareSize];
        Array.Copy(mlkemEk, 0, kemShare, 0, MlkemEkSize);
        Array.Copy(clientX25519Pub, 0, kemShare, MlkemEkSize, X25519PubSize);
        AssertHex("kem_share", kemShare, Sat(exp, "kem", "kem_share"));

        // The pinned kem_ciphertext = ML-KEM ciphertext (1088) || server X25519 public (32); its front
        // must equal the pinned mlkem_ciphertext input.
        byte[] wantKemCt = FromHex(Sat(exp, "kem", "kem_ciphertext"));
        byte[] kemCtFront = new byte[MlkemCtSize];
        Array.Copy(wantKemCt, 0, kemCtFront, 0, MlkemCtSize);
        Check("kem_ciphertext front == pinned mlkem_ciphertext input",
            BytesEqual(kemCtFront, mlkemCiphertext) && wantKemCt.Length == KemCiphertextSize, "");

        // Decapsulate the pinned ML-KEM ciphertext under the seed-derived key -> MUST recover mlkem_shared_secret.
        var decap = new MLKemDecapsulator(MLKemParameters.ml_kem_768);
        decap.Init(mlkemPriv);
        byte[] mlkemSs = new byte[decap.SecretLength];
        decap.Decapsulate(mlkemCiphertext, 0, mlkemCiphertext.Length, mlkemSs, 0, mlkemSs.Length);
        Check("decapsulate pinned ciphertext -> mlkem_shared_secret (self-validating input)",
            BytesEqual(mlkemSs, wantMlkemSs), "got " + Npamp.ToHex(mlkemSs));

        // X25519 ECDH: client private * server public (kem_ciphertext[1088:1120]) -> x25519_shared_secret.
        byte[] serverX25519Pub = new byte[X25519PubSize];
        Array.Copy(wantKemCt, MlkemCtSize, serverX25519Pub, 0, X25519PubSize);
        var x25519Agree = new X25519Agreement();
        x25519Agree.Init(x25519Priv);
        byte[] x25519Ss = new byte[x25519Agree.AgreementSize];
        x25519Agree.CalculateAgreement(new X25519PublicKeyParameters(serverX25519Pub, 0), x25519Ss, 0);
        Check("x25519 ECDH -> x25519_shared_secret", BytesEqual(x25519Ss, wantX25519Ss),
            "got " + Npamp.ToHex(x25519Ss));

        // Guard: the pinned server X25519 private must be a valid scalar (mirrors the Go dead-wiring guard).
        Check("pinned server X25519 private is valid",
            new X25519PrivateKeyParameters(serverX25519Priv, 0).GetEncoded().Length == 32, "");

        // --- CLIENT_HELLO: rebuild the payload TLVs + whole frame, assert byte-equality. ---
        // ProfileOffer is the DRAFT-01 one-octet form (TLV 0x0001 len 1 value 0x01) -- the wire-drift guard.
        var chPayload = new List<byte>();
        AppendTlv(chPayload, TlvProfileOffer, new[] { (byte)ProfileStandard });
        AppendTlv(chPayload, TlvKemOffer, U16(Npamp.KemX25519Mlkem768));
        AppendTlv(chPayload, TlvSigOffer, U16(Npamp.SigEd25519));
        AppendTlv(chPayload, TlvAeadOffer, U16(Npamp.AeadAes256Gcm));
        AppendTlv(chPayload, TlvKemShare, kemShare);
        byte[] chFrame = MarshalFrame(FrameClientHello, chPayload.ToArray());
        AssertHex("client_hello frame (ProfileOffer wire-drift guard)", chFrame, Sat(exp, "frames", "client_hello"));

        // --- SERVER_HELLO: rebuild payload TLVs + whole frame (KEMCiphertext is the pinned value). ---
        var shPayload = new List<byte>();
        AppendTlv(shPayload, TlvProfileSelect, new[] { (byte)ProfileStandard });
        AppendTlv(shPayload, TlvKemSelect, U16(Npamp.KemX25519Mlkem768));
        AppendTlv(shPayload, TlvSigSelect, U16(Npamp.SigEd25519));
        AppendTlv(shPayload, TlvAeadSelect, U16(Npamp.AeadAes256Gcm));
        AppendTlv(shPayload, TlvKemCiphertext, wantKemCt);
        byte[] shFrame = MarshalFrame(FrameServerHello, shPayload.ToArray());
        AssertHex("server_hello frame", shFrame, Sat(exp, "frames", "server_hello"));

        // --- Transcript + key ladder through the real impl. ---
        var tr = new Handshake.Transcript();
        tr.AddFrameType(FrameClientHello);
        tr.AddTLV(TlvProfileOffer, new[] { (byte)ProfileStandard });
        tr.AddTLV(TlvKemOffer, U16(Npamp.KemX25519Mlkem768));
        tr.AddTLV(TlvSigOffer, U16(Npamp.SigEd25519));
        tr.AddTLV(TlvAeadOffer, U16(Npamp.AeadAes256Gcm));
        tr.AddTLV(TlvKemShare, kemShare);
        tr.AddFrameType(FrameServerHello);
        tr.AddTLV(TlvProfileSelect, new[] { (byte)ProfileStandard });
        tr.AddTLV(TlvKemSelect, U16(Npamp.KemX25519Mlkem768));
        tr.AddTLV(TlvSigSelect, U16(Npamp.SigEd25519));
        tr.AddTLV(TlvAeadSelect, U16(Npamp.AeadAes256Gcm));
        tr.AddTLV(TlvKemCiphertext, wantKemCt);
        byte[] thKem = tr.Hash(true);
        AssertHex("th_kem", thKem, Sat(exp, "transcript", "th_kem"));

        // handshake_secret + c_hs/s_hs (bound to th_kem).
        byte[] hs = Npamp.HandshakeSecret(mlkemSs, x25519Ss, true);
        AssertHex("handshake_secret", hs, Sat(exp, "secrets", "handshake_secret"));
        byte[] cHs = Npamp.DeriveClientHandshakeSecret(hs, thKem, true);
        byte[] sHs = Npamp.DeriveServerHandshakeSecret(hs, thKem, true);
        AssertHex("c_hs_secret", cHs, Sat(exp, "secrets", "c_hs_secret"));
        AssertHex("s_hs_secret", sHs, Sat(exp, "secrets", "s_hs_secret"));

        // --- SERVER_AUTH. ---
        tr.AddFrameType(FrameServerAuth);
        tr.AddTLV(TlvIdentityKey, serverPub);
        byte[] thSid = tr.Hash(true);
        AssertHex("th_sid", thSid, Sat(exp, "transcript", "th_sid"));
        byte[] sCv = Handshake.SignCertVerify(serverPriv, true, thSid);
        AssertHex("cert_verify.server", sCv, Sat(exp, "cert_verify", "server"));
        Check("server CertVerify verifies",
            Handshake.VerifyCertVerify(serverPriv.GeneratePublicKey(), true, thSid, sCv), "");
        tr.AddTLV(TlvCertVerify, sCv);
        byte[] thScv = tr.Hash(true);
        AssertHex("th_scv", thScv, Sat(exp, "transcript", "th_scv"));
        byte[] sFinKey = Npamp.DeriveFinishedKey(sHs, true);
        AssertHex("finished_keys.server", sFinKey, Sat(exp, "finished_keys", "server"));
        byte[] sFin = Handshake.ComputeFinished(sFinKey, thScv, true);
        AssertHex("finished.server", sFin, Sat(exp, "finished", "server"));
        tr.AddTLV(TlvFinished, sFin);

        // SERVER_AUTH plaintext = IdentityKey || CertVerify || Finished TLVs; then seal into the frame.
        var saPlain = new List<byte>();
        AppendTlv(saPlain, TlvIdentityKey, serverPub);
        AppendTlv(saPlain, TlvCertVerify, sCv);
        AppendTlv(saPlain, TlvFinished, sFin);
        byte[] serverAuthPlain = saPlain.ToArray();
        AssertHex("auth_plaintext.server", serverAuthPlain, Sat(exp, "auth_plaintext", "server_auth"));
        byte[] serverAuthFrame = SealAuthFrame(FrameServerAuth, sHs, DirServerToClient, serverAuthPlain);
        AssertHex("server_auth frame", serverAuthFrame, Sat(exp, "frames", "server_auth"));

        // --- CLIENT_AUTH. ---
        tr.AddFrameType(FrameClientAuth);
        tr.AddTLV(TlvIdentityKey, clientPub);
        byte[] thCid = tr.Hash(true);
        AssertHex("th_cid", thCid, Sat(exp, "transcript", "th_cid"));
        byte[] cCv = Handshake.SignCertVerify(clientPriv, false, thCid);
        AssertHex("cert_verify.client", cCv, Sat(exp, "cert_verify", "client"));
        Check("client CertVerify verifies",
            Handshake.VerifyCertVerify(clientPriv.GeneratePublicKey(), false, thCid, cCv), "");
        tr.AddTLV(TlvCertVerify, cCv);
        byte[] thCcv = tr.Hash(true);
        AssertHex("th_ccv", thCcv, Sat(exp, "transcript", "th_ccv"));
        byte[] cFinKey = Npamp.DeriveFinishedKey(cHs, true);
        AssertHex("finished_keys.client", cFinKey, Sat(exp, "finished_keys", "client"));
        byte[] cFin = Handshake.ComputeFinished(cFinKey, thCcv, true);
        AssertHex("finished.client", cFin, Sat(exp, "finished", "client"));

        var caPlain = new List<byte>();
        AppendTlv(caPlain, TlvIdentityKey, clientPub);
        AppendTlv(caPlain, TlvCertVerify, cCv);
        AppendTlv(caPlain, TlvFinished, cFin);
        byte[] clientAuthPlain = caPlain.ToArray();
        AssertHex("auth_plaintext.client", clientAuthPlain, Sat(exp, "auth_plaintext", "client_auth"));
        byte[] clientAuthFrame = SealAuthFrame(FrameClientAuth, cHs, DirClientToServer, clientAuthPlain);
        AssertHex("client_auth frame", clientAuthFrame, Sat(exp, "frames", "client_auth"));

        // --- Master + application-phase traffic keys. ---
        byte[] master = Npamp.DeriveMasterSecret(hs, thCcv, true);
        AssertHex("master_secret", master, Sat(exp, "secrets", "master_secret"));

        AssertTrafficKeyIv("c_hs", cHs, DirClientToServer,
            Sat(exp, "secrets", "c_hs_traffic_secret"), Sat(exp, "secrets", "c_hs_key"), Sat(exp, "secrets", "c_hs_iv"));
        AssertTrafficKeyIv("s_hs", sHs, DirServerToClient,
            Sat(exp, "secrets", "s_hs_traffic_secret"), Sat(exp, "secrets", "s_hs_key"), Sat(exp, "secrets", "s_hs_iv"));
        AssertTrafficKeyIv("app_c2s", master, DirClientToServer,
            Sat(exp, "secrets", "app_c2s_traffic_secret"), Sat(exp, "secrets", "app_c2s_key"), Sat(exp, "secrets", "app_c2s_iv"));
        AssertTrafficKeyIv("app_s2c", master, DirServerToClient,
            Sat(exp, "secrets", "app_s2c_traffic_secret"), Sat(exp, "secrets", "app_s2c_key"), Sat(exp, "secrets", "app_s2c_iv"));

        // --- Mutation guard 1: a one-octet flip in the server CertVerify signature must REJECT. ---
        byte[] badCv = (byte[])sCv.Clone();
        badCv[badCv.Length - 1] ^= 0x01;
        Check("mutation guard: flipped server CertVerify signature REJECTS",
            !Handshake.VerifyCertVerify(serverPriv.GeneratePublicKey(), true, thSid, badCv), "");

        // --- Mutation guard 2: a one-octet flip in the client Finished MAC must REJECT. ---
        byte[] badFin = (byte[])cFin.Clone();
        badFin[0] ^= 0x01;
        Check("mutation guard: flipped client Finished MAC REJECTS",
            !Handshake.VerifyFinished(cFinKey, thCcv, badFin, true), "");

        // Sanity: the untouched signature and MAC still verify.
        Check("unmutated server CertVerify still verifies",
            Handshake.VerifyCertVerify(serverPriv.GeneratePublicKey(), true, thSid, sCv), "");
        Check("unmutated client Finished still verifies",
            Handshake.VerifyFinished(cFinKey, thCcv, cFin, true), "");

        Console.WriteLine(_failures == 0
            ? "ALL PASS (handshake-flow KAT: kem+frames+transcript+ladder+finished+certverify+mutation)"
            : "FAILURES: " + _failures);
        return _failures == 0 ? 0 : 1;
    }
}
