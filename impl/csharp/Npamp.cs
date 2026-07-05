// Open reference implementation of the N-PAMP wire format (draft-bubblefish-npamp-00).
// OPEN protocol layer only: framing, registries, AEAD record layer, key schedule.
// No proprietary methods, parameters, or weights. Big-endian throughout.
#nullable enable
using System;
using System.Security.Cryptography;
using System.Text;

namespace Sh.Bubblefish.Npamp;

/// <summary>Raised when a wire frame fails structural or integrity validation.</summary>
public sealed class FrameException : Exception
{
    public FrameException(string message) : base(message) { }
}

/// <summary>
/// N-PAMP OPEN-layer reference: frame framing, CRC32C integrity, per-frame AEAD
/// nonce derivation, AES-256-GCM record layer, and the HKDF-Expand-Label key
/// schedule. All cryptography uses the .NET base class library providers.
/// </summary>
public static class Npamp
{
    // -- Constants ---------------------------------------------------------

    public const int HeaderSize = 36;
    public const int ProtocolVersion = 0x2;
    public static readonly byte[] Magic = { (byte)'N', (byte)'P', (byte)'A', (byte)'M' }; // 0x4E50414D
    public const string Alpn = "n-pamp/2";
    public const string LabelPrefix = "n-pamp "; // protocol-specific; NOT "tls13 "

    public const int FlagUrg = 0x01, FlagEnc = 0x02, FlagComp = 0x04, FlagFrag = 0x08;

    public const int ChanControl = 0x0000, ChanMemory = 0x0001, ChanImmune = 0x0005,
        ChanAudit = 0x000B, ChanBridge = 0x000D, ChanSpatial = 0x0013;
    public const int FramePing = 0x0001, FramePong = 0x0002, FrameClose = 0x0003,
        FrameFlowUpdate = 0x000A, ChannelSpecificBase = 0x0100;
    public const int TlvProfileOffer = 0x01, TlvKemCiphertext = 0x08, TlvAnomalyCharge = 0x12;
    public const int KemX25519Mlkem768 = 0x11ec, KemX25519Mlkem1024 = 0x11ed;
    public const int AeadAes256Gcm = 0x0001, AeadChacha20Poly1305 = 0x0002;
    public const int SigEd25519 = 0x0807, SigMldsa87 = 0x0905;

    // -- CRC32C (Castagnoli, reflected) ------------------------------------

    // poly 0x82F63B78, init 0xFFFFFFFF, final xor 0xFFFFFFFF. Same value as
    // java.util.zip.CRC32C and Go hash/crc32 Castagnoli; computed directly
    // because the .NET shared runtime ships no CRC32C primitive.
    public static uint Crc32c(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFFFFFFu;
        foreach (byte b in data)
        {
            crc ^= b;
            for (int k = 0; k < 8; k++)
            {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0x82F63B78u : crc >> 1;
            }
        }
        return crc ^ 0xFFFFFFFFu;
    }

    // -- Big-endian helpers ------------------------------------------------

    private static void PutU16Be(byte[] buf, int off, int v)
    {
        buf[off] = (byte)((v >> 8) & 0xFF);
        buf[off + 1] = (byte)(v & 0xFF);
    }

    private static void PutU32Be(byte[] buf, int off, uint v)
    {
        buf[off] = (byte)((v >> 24) & 0xFF);
        buf[off + 1] = (byte)((v >> 16) & 0xFF);
        buf[off + 2] = (byte)((v >> 8) & 0xFF);
        buf[off + 3] = (byte)(v & 0xFF);
    }

    private static void PutU64Be(byte[] buf, int off, ulong v)
    {
        for (int i = 0; i < 8; i++)
        {
            buf[off + i] = (byte)((v >> (56 - 8 * i)) & 0xFF);
        }
    }

    private static int GetU16Be(byte[] buf, int off) => ((buf[off] & 0xFF) << 8) | (buf[off + 1] & 0xFF);

    private static uint GetU32Be(byte[] buf, int off) =>
        ((uint)buf[off] << 24) | ((uint)buf[off + 1] << 16) | ((uint)buf[off + 2] << 8) | buf[off + 3];

    private static ulong GetU64Be(byte[] buf, int off)
    {
        ulong v = 0;
        for (int i = 0; i < 8; i++)
        {
            v = (v << 8) | buf[off + i];
        }
        return v;
    }

    // -- Frame -------------------------------------------------------------

    /// <summary>
    /// A single N-PAMP wire frame: a 36-octet header followed by an opaque
    /// payload. <c>Seq</c> carries an unsigned 64-bit value.
    /// </summary>
    public sealed class Frame
    {
        public int Version;
        public int Flags;
        public int Ftype;
        public int Channel;
        public ulong Seq;
        public byte[] Payload;

        public Frame() : this(0, 0) { }

        public Frame(int ftype, int channel, ulong seq = 0, int flags = 0, int version = 0, byte[]? payload = null)
        {
            Ftype = ftype;
            Channel = channel;
            Seq = seq;
            Flags = flags;
            Version = version;
            Payload = payload ?? Array.Empty<byte>();
        }

        /// <summary>
        /// Builds octets [0:21]: MAGIC, (version&lt;&lt;4)|flags, frameType, channel,
        /// seq, payloadLen. When Version is 0 the protocol default (0x2) is
        /// substituted. This 21-octet prefix is exactly the AEAD associated data.
        /// </summary>
        public byte[] HeaderPrefix(long payloadLen)
        {
            int ver = Version != 0 ? Version : ProtocolVersion;
            byte[] o = new byte[21];
            Array.Copy(Magic, 0, o, 0, 4);
            o[4] = (byte)((ver << 4) | (Flags & 0x0F));
            PutU16Be(o, 5, Ftype);
            PutU16Be(o, 7, Channel);
            PutU64Be(o, 9, Seq);
            PutU32Be(o, 17, (uint)payloadLen);
            return o;
        }

        /// <summary>Serialises: prefix || CRC32C(prefix) || 11 zero octets || payload.</summary>
        public byte[] Marshal()
        {
            byte[] prefix = HeaderPrefix(Payload.Length);
            byte[] o = new byte[HeaderSize + Payload.Length];
            Array.Copy(prefix, 0, o, 0, 21);
            PutU32Be(o, 21, Crc32c(prefix));
            // octets 25..36 reserved, already zero
            Array.Copy(Payload, 0, o, HeaderSize, Payload.Length);
            return o;
        }

        /// <summary>
        /// Parses a wire frame. Validation order: CRC32C first, then magic, then
        /// version, then reserved-all-zero, then payload-length agreement.
        /// </summary>
        public static Frame Unmarshal(byte[] buf)
        {
            if (buf.Length < HeaderSize)
            {
                throw new FrameException("short header");
            }
            uint got = GetU32Be(buf, 21);
            if (got != Crc32c(buf.AsSpan(0, 21)))
            {
                throw new FrameException("bad crc");
            }
            for (int i = 0; i < 4; i++)
            {
                if (buf[i] != Magic[i])
                {
                    throw new FrameException("bad magic");
                }
            }
            int ver = (buf[4] & 0xFF) >> 4;
            if (ver != ProtocolVersion)
            {
                throw new FrameException("bad version");
            }
            for (int i = 25; i < HeaderSize; i++)
            {
                if (buf[i] != 0)
                {
                    throw new FrameException("reserved nonzero");
                }
            }
            uint plen = GetU32Be(buf, 17);
            if (plen != buf.Length - HeaderSize)
            {
                throw new FrameException("length mismatch");
            }
            byte[] payload = new byte[buf.Length - HeaderSize];
            Array.Copy(buf, HeaderSize, payload, 0, payload.Length);
            return new Frame
            {
                Version = ver,
                Flags = buf[4] & 0x0F,
                Ftype = GetU16Be(buf, 5),
                Channel = GetU16Be(buf, 7),
                Seq = GetU64Be(buf, 9),
                Payload = payload,
            };
        }
    }

    // -- AEAD record layer -------------------------------------------------

    /// <summary>
    /// Per-frame AEAD nonce (draft-00 7.5): a 12-octet buffer holding the seq as
    /// a big-endian u64 in bytes [4:12], XORed with the 12-octet IV. The channel
    /// ID is NOT part of the nonce.
    /// </summary>
    public static byte[] DeriveNonce(byte[] iv, ulong seq)
    {
        byte[] n = new byte[12];
        PutU64Be(n, 4, seq);
        for (int i = 0; i < 12; i++)
        {
            n[i] ^= iv[i];
        }
        return n;
    }

    /// <summary>AES-256-GCM seal. Returns ciphertext||tag (16-octet tag). AAD is the 21-octet header prefix.</summary>
    public static byte[] SealAes256Gcm(byte[] key, byte[] iv, ulong seq, byte[] aad, byte[] pt)
    {
        byte[] nonce = DeriveNonce(iv, seq);
        byte[] ct = new byte[pt.Length];
        byte[] tag = new byte[16];
        using var gcm = new AesGcm(key, 16);
        gcm.Encrypt(nonce, pt, ct, tag, aad);
        byte[] o = new byte[ct.Length + 16];
        Array.Copy(ct, 0, o, 0, ct.Length);
        Array.Copy(tag, 0, o, ct.Length, 16);
        return o;
    }

    /// <summary>AES-256-GCM open. Accepts ciphertext||tag; throws on authentication failure.</summary>
    public static byte[] OpenAes256Gcm(byte[] key, byte[] iv, ulong seq, byte[] aad, byte[] sealedBytes)
    {
        byte[] nonce = DeriveNonce(iv, seq);
        int ctLen = sealedBytes.Length - 16;
        byte[] ct = new byte[ctLen];
        byte[] tag = new byte[16];
        Array.Copy(sealedBytes, 0, ct, 0, ctLen);
        Array.Copy(sealedBytes, ctLen, tag, 0, 16);
        byte[] pt = new byte[ctLen];
        using var gcm = new AesGcm(key, 16);
        gcm.Decrypt(nonce, ct, tag, pt, aad); // throws CryptographicException on tag mismatch
        return pt;
    }

    // -- Key schedule (HKDF-Extract / Expand / Expand-Label) ----------------

    // HKDF-Extract (RFC 5869 2.2): extract(salt, ikm) = HMAC-Hash(salt, ikm). The
    // salt is the HMAC key, the IKM is the message. SHA-256 when standard, else SHA-384.
    public static byte[] HkdfExtract(byte[] salt, byte[] ikm, bool standard)
    {
        using HMAC mac = standard ? new HMACSHA256(salt) : new HMACSHA384(salt);
        return mac.ComputeHash(ikm);
    }

    // HKDF-Expand (RFC 5869 2.3), expand step only: the supplied secret IS the
    // PRK, so HKDF-Extract is not run. SHA-256 when standard, else SHA-384.
    private static byte[] HkdfExpand(bool standard, byte[] prk, byte[] info, int length)
    {
        using HMAC mac = standard ? new HMACSHA256(prk) : new HMACSHA384(prk);
        int hashLen = mac.HashSize / 8;
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
    /// HKDF-Expand-Label (draft-00 7.4). full = LabelPrefix + label.
    /// info = u16(length) || u8(len(full)) || full || u8(len(context)) || context.
    /// </summary>
    public static byte[] HkdfExpandLabel(byte[] secret, string label, byte[] context, int length, bool standard)
    {
        byte[] full = Encoding.ASCII.GetBytes(LabelPrefix + label);
        byte[] info = new byte[2 + 1 + full.Length + 1 + context.Length];
        int p = 0;
        info[p++] = (byte)((length >> 8) & 0xFF);
        info[p++] = (byte)(length & 0xFF);
        info[p++] = (byte)full.Length;
        Array.Copy(full, 0, info, p, full.Length);
        p += full.Length;
        info[p++] = (byte)context.Length;
        Array.Copy(context, 0, info, p, context.Length);
        return HkdfExpand(standard, secret, info, length);
    }

    /// <summary>
    /// Derives a directional traffic secret.
    /// context = dir(1) || epoch(8 BE) || suite(2 BE) || channel(2 BE);
    /// output length 32 (SHA-256) or 48 (SHA-384); label "traffic".
    /// </summary>
    public static byte[] DeriveTrafficSecret(byte[] master, int dir, ulong epoch, int suite, int channel, bool standard)
    {
        byte[] ctx = new byte[1 + 8 + 2 + 2];
        ctx[0] = (byte)dir;
        PutU64Be(ctx, 1, epoch);
        PutU16Be(ctx, 9, suite);
        PutU16Be(ctx, 11, channel);
        int hlen = standard ? 32 : 48;
        return HkdfExpandLabel(master, "traffic", ctx, hlen, standard);
    }

    /// <summary>Derives the {key(32), iv(12)} pair from a traffic secret.</summary>
    public static (byte[] Key, byte[] Iv) DeriveKeyIv(byte[] secret, bool standard)
    {
        byte[] key = HkdfExpandLabel(secret, "key", Array.Empty<byte>(), 32, standard);
        byte[] iv = HkdfExpandLabel(secret, "iv", Array.Empty<byte>(), 12, standard);
        return (key, iv);
    }

    // -- Handshake-secret ladder (binding spec/10 5; ML-KEM-first per ADR-0005) ----

    /// <summary>
    /// Derives the handshake_secret root. The IKM is the ML-KEM shared secret concatenated
    /// FIRST with the X25519 shared secret (ML-KEM-first, ADR-0005); the salt is the binding
    /// default of HashLen zero octets. handshake_secret = HKDF-Extract(salt, IKM).
    /// </summary>
    public static byte[] HandshakeSecret(byte[] mlkemSharedSecret, byte[] x25519SharedSecret, bool standard)
    {
        int hashLen = standard ? 32 : 48;
        byte[] salt = new byte[hashLen]; // default salt: HashLen zero octets
        byte[] ikm = new byte[mlkemSharedSecret.Length + x25519SharedSecret.Length];
        Array.Copy(mlkemSharedSecret, 0, ikm, 0, mlkemSharedSecret.Length);
        Array.Copy(x25519SharedSecret, 0, ikm, mlkemSharedSecret.Length, x25519SharedSecret.Length);
        return HkdfExtract(salt, ikm, standard);
    }

    /// <summary>Client handshake traffic secret c_hs = HKDF-Expand-Label(handshake_secret, "c hs", th_kem, HashLen).</summary>
    public static byte[] DeriveClientHandshakeSecret(byte[] handshakeSecret, byte[] thKem, bool standard) =>
        HkdfExpandLabel(handshakeSecret, "c hs", thKem, standard ? 32 : 48, standard);

    /// <summary>Server handshake traffic secret s_hs = HKDF-Expand-Label(handshake_secret, "s hs", th_kem, HashLen).</summary>
    public static byte[] DeriveServerHandshakeSecret(byte[] handshakeSecret, byte[] thKem, bool standard) =>
        HkdfExpandLabel(handshakeSecret, "s hs", thKem, standard ? 32 : 48, standard);

    /// <summary>Master secret = HKDF-Expand-Label(handshake_secret, "master", th_ccv, HashLen).</summary>
    public static byte[] DeriveMasterSecret(byte[] handshakeSecret, byte[] thCcv, bool standard) =>
        HkdfExpandLabel(handshakeSecret, "master", thCcv, standard ? 32 : 48, standard);

    /// <summary>
    /// Finished key (binding spec/10 6.2 / 5.4) = HKDF-Expand-Label(secret, "finished", "", HashLen).
    /// The client Finished key derives from c_hs; the server Finished key derives from s_hs.
    /// </summary>
    public static byte[] DeriveFinishedKey(byte[] secret, bool standard) =>
        HkdfExpandLabel(secret, "finished", Array.Empty<byte>(), standard ? 32 : 48, standard);

    // -- Hex utility -------------------------------------------------------

    /// <summary>Lowercase hex encoding, used by the vector generator and tests.</summary>
    public static string ToHex(byte[] data) => Convert.ToHexString(data).ToLowerInvariant();
}
