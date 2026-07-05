// Open reference implementation of the N-PAMP wire format (draft-bubblefish-npamp-00).
// Handshake binding layer (binding spec/10): transcript construction, Finished MAC,
// CertVerify signature. No proprietary methods, parameters, or weights. Big-endian throughout.
//
// SHA-256 + HMAC come from System.Security.Cryptography (the .NET BCL). Ed25519 is NOT in
// the BCL, so it comes from BouncyCastle.Cryptography (Org.BouncyCastle.Crypto.Signers.
// Ed25519Signer, pure Ed25519 per RFC 8032). Kept in its OWN file so the BCL-only AES-GCM
// KAT build (Npamp.cs alone) never references BouncyCastle.
#nullable enable
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Sh.Bubblefish.Npamp;

/// <summary>
/// N-PAMP draft-00 handshake binding layer (binding spec/10): the transcript hash
/// (section 3), the Finished MAC (section 6.2; RFC 8446 section 4.4.4), and the
/// CertVerify signature (section 6.1; RFC 8446 section 4.4.3 structure; Ed25519 per
/// RFC 8032). Big-endian throughout.
/// </summary>
public static class Handshake
{
    // -- Constants ---------------------------------------------------------

    /// <summary>Handshake frame types (binding spec/10 section 1), carried on the control channel.</summary>
    public const int FrameClientHello = 0x0100, FrameServerHello = 0x0101,
        FrameServerAuth = 0x0102, FrameClientAuth = 0x0103;

    /// <summary>CertVerify role context strings (binding spec/10 section 6.1).</summary>
    public const string ContextServerCertVerify = "N-PAMP draft-00, server CertificateVerify";
    public const string ContextClientCertVerify = "N-PAMP draft-00, client CertificateVerify";

    // -- Big-endian helpers ------------------------------------------------

    private static int GetU16Be(byte[] buf, int off) => ((buf[off] & 0xFF) << 8) | (buf[off + 1] & 0xFF);

    // -- Transcript (binding spec/10 section 3) ----------------------------

    /// <summary>
    /// Accumulates the draft-00 handshake transcript (binding spec/10 section 3) and
    /// hashes it at a cut point. Absorption granularity is per-TLV: <see cref="AddFrameType"/>
    /// appends the 2-octet frame type ONLY (NOT the rest of the 36-octet frame header — the
    /// spec section 3 / 7.1 divergence from RFC 8446 section 4.4.1); <see cref="AddTLV"/>
    /// appends Type(2 BE) || Length(2 BE) || Value. A transcript point = the hash over all
    /// bytes absorbed so far (SHA-256 at Standard, SHA-384 at High/Sovereign).
    /// </summary>
    public sealed class Transcript
    {
        private readonly List<byte> _buf = new();

        /// <summary>Appends the frame type as exactly 2 octets big-endian.</summary>
        public void AddFrameType(int ft)
        {
            _buf.Add((byte)((ft >> 8) & 0xFF));
            _buf.Add((byte)(ft & 0xFF));
        }

        /// <summary>Appends one TLV: Type(2 BE) || Length(2 BE) || Value.</summary>
        public void AddTLV(int type, byte[] value)
        {
            _buf.Add((byte)((type >> 8) & 0xFF));
            _buf.Add((byte)(type & 0xFF));
            _buf.Add((byte)((value.Length >> 8) & 0xFF));
            _buf.Add((byte)(value.Length & 0xFF));
            _buf.AddRange(value);
        }

        /// <summary>Hashes every octet absorbed so far (SHA-256 when <paramref name="standard"/>, else SHA-384).</summary>
        public byte[] Hash(bool standard)
        {
            byte[] data = _buf.ToArray();
            return standard ? SHA256.HashData(data) : SHA384.HashData(data);
        }
    }

    // -- Finished (binding spec/10 section 6.2; RFC 8446 section 4.4.4) -----

    /// <summary>
    /// Finished verify_data = HMAC(finished_key, transcript_hash) under the profile hash
    /// (HMAC-SHA-256 at Standard, HMAC-SHA-384 at High/Sovereign).
    /// </summary>
    public static byte[] ComputeFinished(byte[] finishedKey, byte[] transcriptHash, bool standard)
    {
        return standard
            ? HMACSHA256.HashData(finishedKey, transcriptHash)
            : HMACSHA384.HashData(finishedKey, transcriptHash);
    }

    /// <summary>
    /// Recomputes the Finished MAC and constant-time-compares it to the received verify_data.
    /// <see cref="CryptographicOperations.FixedTimeEquals"/> is time-independent and returns
    /// false on a length mismatch.
    /// </summary>
    public static bool VerifyFinished(byte[] finishedKey, byte[] transcriptHash, byte[] verifyData, bool standard)
    {
        return CryptographicOperations.FixedTimeEquals(
            ComputeFinished(finishedKey, transcriptHash, standard), verifyData);
    }

    // -- Ed25519 key decoding (RFC 8032) -----------------------------------

    /// <summary>Builds an Ed25519 private key from its raw 32-octet seed (RFC 8032).</summary>
    public static Ed25519PrivateKeyParameters Ed25519PrivateKeyFromSeed(byte[] seed)
    {
        return new Ed25519PrivateKeyParameters(seed, 0);
    }

    /// <summary>Builds an Ed25519 public key from its raw 32-octet encoding (RFC 8032 section 5.1.2).</summary>
    public static Ed25519PublicKeyParameters Ed25519PublicKeyFromRaw(byte[] raw)
    {
        if (raw.Length != 32)
        {
            throw new ArgumentException("ed25519 public key must be 32 octets, got " + raw.Length);
        }
        return new Ed25519PublicKeyParameters(raw, 0);
    }

    // -- CertVerify (binding spec/10 section 6.1; RFC 8446 section 4.4.3) ---

    /// <summary>
    /// The section 6.1 signing input: 64 octets of 0x20, the role context string, a 0x00
    /// separator, then the transcript hash — TLS-1.3-style domain separation
    /// (RFC 8446 section 4.4.3).
    /// </summary>
    public static byte[] CertVerifySigningInput(bool isServer, byte[] transcriptHash)
    {
        byte[] ctx = Encoding.ASCII.GetBytes(isServer ? ContextServerCertVerify : ContextClientCertVerify);
        byte[] outBuf = new byte[64 + ctx.Length + 1 + transcriptHash.Length];
        int p = 0;
        for (int i = 0; i < 64; i++)
        {
            outBuf[p++] = 0x20;
        }
        Array.Copy(ctx, 0, outBuf, p, ctx.Length);
        p += ctx.Length;
        outBuf[p++] = 0x00;
        Array.Copy(transcriptHash, 0, outBuf, p, transcriptHash.Length);
        return outBuf;
    }

    /// <summary>The CertVerify TLV value: u16(0x0807, Ed25519) || Ed25519(priv, signing_input).</summary>
    public static byte[] SignCertVerify(Ed25519PrivateKeyParameters privateKey, bool isServer, byte[] transcriptHash)
    {
        var signer = new Ed25519Signer();
        signer.Init(true, privateKey);
        byte[] msg = CertVerifySigningInput(isServer, transcriptHash);
        signer.BlockUpdate(msg, 0, msg.Length);
        byte[] sig = signer.GenerateSignature();
        byte[] outBuf = new byte[2 + sig.Length];
        outBuf[0] = (byte)((Npamp.SigEd25519 >> 8) & 0xFF);
        outBuf[1] = (byte)(Npamp.SigEd25519 & 0xFF);
        Array.Copy(sig, 0, outBuf, 2, sig.Length);
        return outBuf;
    }

    /// <summary>
    /// Checks a CertVerify TLV value against the signer's public key, role, and transcript
    /// hash. Rejects a non-Ed25519 scheme, a wrong-length (non-64-octet) signature, a
    /// role/context mismatch, or a wrong transcript.
    /// </summary>
    public static bool VerifyCertVerify(Ed25519PublicKeyParameters publicKey, bool isServer, byte[] transcriptHash, byte[] value)
    {
        if (value.Length < 2 || GetU16Be(value, 0) != Npamp.SigEd25519)
        {
            return false;
        }
        byte[] sig = new byte[value.Length - 2];
        Array.Copy(value, 2, sig, 0, sig.Length);
        if (sig.Length != 64) // Ed25519 signatures are exactly 64 octets (RFC 8032 section 5.1.6)
        {
            return false;
        }
        try
        {
            var verifier = new Ed25519Signer();
            verifier.Init(false, publicKey);
            byte[] msg = CertVerifySigningInput(isServer, transcriptHash);
            verifier.BlockUpdate(msg, 0, msg.Length);
            return verifier.VerifySignature(sig);
        }
        catch (Exception)
        {
            return false;
        }
    }
}
