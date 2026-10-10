// Behaviour check, not a conformance vector: the open C# module implements the Standard profile
// only, so every key-schedule, transcript and Finished primitive refuses a non-Standard profile
// with Npamp.NoSuiteForProfileException and still succeeds at Standard. No external authority
// (RFC or FIPS) defines this module's scope.
//
// Self-contained: builds with Npamp.cs + Handshake.cs + this file only.
#nullable enable
using System;

namespace Sh.Bubblefish.Npamp;

public static class RefusalKat
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

    private static void Refused(string name, Action call)
    {
        bool threw = false;
        try
        {
            call();
        }
        catch (Npamp.NoSuiteForProfileException)
        {
            threw = true;
        }
        catch (Exception e)
        {
            Console.WriteLine("     wrong exception for " + name + ": " + e.GetType().Name);
        }
        Check("non-standard refused: " + name, threw);
    }

    public static int Main(string[] args)
    {
        byte[] secret = new byte[32];
        Array.Fill(secret, (byte)0x11);
        byte[] th = new byte[32];
        Array.Fill(th, (byte)0x22);

        Check("standard control: HkdfExtract", Npamp.HkdfExtract(new byte[32], secret, true).Length == 32);
        Check("standard control: DeriveTrafficSecret",
            Npamp.DeriveTrafficSecret(secret, 0, 0UL, Npamp.AeadAes256Gcm, Npamp.ChanControl, true).Length == 32);
        var ki = Npamp.DeriveKeyIv(secret, true);
        Check("standard control: DeriveKeyIv", ki.Key.Length == 32 && ki.Iv.Length == 12);
        Check("standard control: HandshakeSecret", Npamp.HandshakeSecret(secret, secret, true).Length == 32);
        Check("standard control: DeriveFinishedKey", Npamp.DeriveFinishedKey(secret, true).Length == 32);
        Check("standard control: transcript hash", new Handshake.Transcript().Hash(true).Length == 32);
        byte[] mac = Handshake.ComputeFinished(secret, th, true);
        Check("standard control: finished verifies", Handshake.VerifyFinished(secret, th, mac, true));

        Refused("HkdfExtract", () => Npamp.HkdfExtract(new byte[48], secret, false));
        Refused("HkdfExpandLabel", () => Npamp.HkdfExpandLabel(secret, "key", Array.Empty<byte>(), 32, false));
        Refused("DeriveTrafficSecret",
            () => Npamp.DeriveTrafficSecret(secret, 0, 0UL, Npamp.AeadAes256Gcm, Npamp.ChanControl, false));
        Refused("DeriveKeyIv", () => Npamp.DeriveKeyIv(secret, false));
        Refused("HandshakeSecret", () => Npamp.HandshakeSecret(secret, secret, false));
        Refused("DeriveClientHandshakeSecret", () => Npamp.DeriveClientHandshakeSecret(secret, th, false));
        Refused("DeriveServerHandshakeSecret", () => Npamp.DeriveServerHandshakeSecret(secret, th, false));
        Refused("DeriveMasterSecret", () => Npamp.DeriveMasterSecret(secret, th, false));
        Refused("DeriveFinishedKey", () => Npamp.DeriveFinishedKey(secret, false));
        Refused("Transcript.Hash", () => new Handshake.Transcript().Hash(false));
        Refused("ComputeFinished", () => Handshake.ComputeFinished(secret, th, false));
        Refused("VerifyFinished", () => Handshake.VerifyFinished(secret, th, th, false));

        return _failures == 0 ? 0 : 1;
    }
}
