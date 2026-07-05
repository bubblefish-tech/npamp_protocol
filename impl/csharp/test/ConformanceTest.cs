// Conformance test for the N-PAMP C# reference (draft-bubblefish-npamp-00).
// Exits 0 on success, 1 if any assertion fails. Mirrors the Go/Rust/Java suites.
using System;
using System.Text;

namespace Sh.Bubblefish.Npamp;

public static class ConformanceTest
{
    private static int _failures;

    private static void Check(string name, bool ok)
    {
        if (ok)
        {
            Console.WriteLine("ok   - " + name);
        }
        else
        {
            Console.WriteLine("FAIL - " + name);
            _failures++;
        }
    }

    private static byte[] Ramp(int start, int count)
    {
        byte[] b = new byte[count];
        for (int i = 0; i < count; i++)
        {
            b[i] = (byte)(start + i);
        }
        return b;
    }

    // --- cross-language vector reproduction (values from the Go reference) ---

    private static void VecHeader()
    {
        var f = new Npamp.Frame(Npamp.FramePing, Npamp.ChanControl);
        Check("vec_header", Npamp.ToHex(f.Marshal()) ==
            "4e50414d20000100000000000000000000000000000d880c250000000000000000000000");
    }

    private static void VecNonce()
    {
        Check("vec_nonce", Npamp.ToHex(Npamp.DeriveNonce(Ramp(0x01, 12), 0x0102030405060708UL)) ==
            "010203040404040c0c0c0c04");
    }

    private static void VecAead()
    {
        byte[] aad = new Npamp.Frame(Npamp.FramePing, Npamp.ChanControl).HeaderPrefix(11);
        byte[] sealedBytes = Npamp.SealAes256Gcm(Ramp(0x00, 32), Ramp(0x10, 12), 7UL, aad,
            Encoding.ASCII.GetBytes("hello world"));
        Check("vec_aead", Npamp.ToHex(sealedBytes) ==
            "3fe8b79f95b5697926b3395429c2c2466999c652f9346aeebb30bf");
    }

    private static void VecTrafficKey()
    {
        byte[] master = new byte[48];
        Array.Fill(master, (byte)0x2A);
        byte[] ts = Npamp.DeriveTrafficSecret(master, 0, 0UL, Npamp.AeadAes256Gcm, Npamp.ChanControl, false);
        Check("vec_traffic_key", Npamp.ToHex(Npamp.DeriveKeyIv(ts, false).Key) ==
            "79372e2fb7f92d63e3a68099ff72514f310ebf6773deb0fa7ef45d013c652dcc");
    }

    // --- property tests (mirror the Go/Rust/Java suites) ---

    private static void Roundtrip()
    {
        var f = new Npamp.Frame(0x0100, Npamp.ChanMemory, 42UL, Npamp.FlagEnc, 0,
            Encoding.ASCII.GetBytes("payload"));
        var g = Npamp.Frame.Unmarshal(f.Marshal());
        Check("roundtrip", g.Flags == Npamp.FlagEnc && g.Ftype == 0x0100 && g.Channel == Npamp.ChanMemory
            && g.Seq == 42UL && Encoding.ASCII.GetString(g.Payload) == "payload");
    }

    private static void CrcValidatedFirst()
    {
        byte[] buf = new Npamp.Frame(Npamp.FramePing, Npamp.ChanControl).Marshal();
        buf[5] ^= 0xFF; // corrupt frame-type byte; CRC must reject before any field is trusted
        bool rejected = false;
        try { Npamp.Frame.Unmarshal(buf); }
        catch (FrameException e) { rejected = e.Message == "bad crc"; }
        Check("crc_validated_first", rejected);
    }

    private static void ReservedMustBeZero()
    {
        byte[] buf = new Npamp.Frame(Npamp.FramePing, Npamp.ChanControl).Marshal();
        buf[30] = 1; // a reserved octet
        bool rejected = false;
        try { Npamp.Frame.Unmarshal(buf); }
        catch (FrameException e) { rejected = e.Message == "bad crc" || e.Message == "reserved nonzero"; }
        Check("reserved_must_be_zero", rejected);
    }

    private static void AeadTamperFails()
    {
        byte[] key = new byte[32];
        byte[] iv = Ramp(0x10, 12);
        byte[] aad = new Npamp.Frame(Npamp.FramePing, Npamp.ChanControl).HeaderPrefix(5);
        byte[] sealedBytes = Npamp.SealAes256Gcm(key, iv, 7UL, aad, Encoding.ASCII.GetBytes("hello"));
        bool openOk = Encoding.ASCII.GetString(Npamp.OpenAes256Gcm(key, iv, 7UL, aad, sealedBytes)) == "hello";
        aad[5] ^= 1;
        bool tamperRejected = false;
        try { Npamp.OpenAes256Gcm(key, iv, 7UL, aad, sealedBytes); }
        catch (Exception) { tamperRejected = true; }
        Check("aead_tamper_fails", openOk && tamperRejected);
    }

    private static void HkdfPrefixProtocolSpecific()
    {
        Check("hkdf_prefix_protocol_specific", Npamp.LabelPrefix == "n-pamp " && Npamp.LabelPrefix != "tls13 ");
    }

    public static int Main()
    {
        VecHeader();
        VecNonce();
        VecAead();
        VecTrafficKey();
        Roundtrip();
        CrcValidatedFirst();
        ReservedMustBeZero();
        AeadTamperFails();
        HkdfPrefixProtocolSpecific();
        Console.WriteLine(_failures == 0 ? "ALL PASS (9/9)" : ("FAILURES: " + _failures));
        return _failures == 0 ? 0 : 1;
    }
}
