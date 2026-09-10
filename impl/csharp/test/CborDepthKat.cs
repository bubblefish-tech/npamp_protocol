// Spec-derived (non-circular) conformance check for the N-PAMP deterministic-CBOR
// decoder's resource-exhaustion nesting-depth guard (NpampCbor.cs, mirroring the Go
// reference impl/go/memory_cbor.go cborMaxNestingDepth = 8).
//
// Vectors are derived directly from RFC 8949 array encoding + the depth-8 rule, NOT
// from this (or any) implementation:
//   - MUST REJECT: 81 81 81 81 81 81 81 81 00 (eight 0x81 array-of-one headers
//     wrapping a 0x00 scalar -> the scalar sits at depth 9; the outermost array is
//     depth 1).
//   - MUST ACCEPT: 81 81 81 81 81 81 81 00 (seven 0x81 headers + the scalar -> the
//     scalar sits at depth 8).
//
// Exit 0 iff both vectors are dispositioned correctly.
using System;

namespace Sh.Bubblefish.Npamp;

public static class CborDepthKat
{
    public static int Main(string[] args)
    {
        int failures = 0;

        byte[] reject = { 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x00 };
        try
        {
            NpampCbor.DecodeTop(reject);
            Console.WriteLine("FAIL depth-9 vector: expected DepthExceeded, decode succeeded");
            failures++;
        }
        catch (CborException e)
        {
            if (e.Message.Contains("nesting depth exceeds limit"))
            {
                Console.WriteLine("ok   - depth-9 vector rejected with depth-exceeded error");
            }
            else
            {
                Console.WriteLine($"FAIL depth-9 vector: wrong error: {e.Message}");
                failures++;
            }
        }

        byte[] accept = { 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x00 };
        try
        {
            NpampCbor.DecodeTop(accept);
            Console.WriteLine("ok   - depth-8 vector decodes cleanly");
        }
        catch (CborException e)
        {
            Console.WriteLine($"FAIL depth-8 vector: expected success, got: {e.Message}");
            failures++;
        }

        Console.WriteLine($"CBOR nesting-depth guard KAT (csharp): {(failures == 0 ? 2 : 2 - failures)}/2 passed");
        return failures == 0 ? 0 : 1;
    }
}
