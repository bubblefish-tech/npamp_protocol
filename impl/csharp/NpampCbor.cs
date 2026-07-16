// Open reference implementation of the N-PAMP native-channel body codec
// (draft-bubblefish-npamp-01). OPEN protocol layer only: the deterministic
// (canonical) CBOR subset that every native operation channel (NPAMP-MEMORY,
// -STREAM, -CAP, -IMMUNE, -SETTLEMENT, -TELEMETRY, -COMMERCE, -INTERACT,
// -WORKFLOW, -KNOWLEDGE) encodes its bodies in. No proprietary methods.
//
// A straight port of the Go reference codec impl/go/memory_cbor.go
// (spec/companion/81_memory_channel.md §4; RFC 8949 §4.2.1 core-deterministic) and
// its TypeScript counterpart impl/typescript/src/npamp_cbor.ts. It implements
// exactly the subset the native bodies use -- unsigned integers, negative integers,
// byte strings, text strings, arrays, maps, and the simple values false/true/null
// -- all definite-length, shortest-form, with map keys in canonical order. It is
// deliberately NOT a general CBOR library: on decode it REJECTS anything outside
// this subset (indefinite lengths, non-shortest integer/length encodings, tags,
// floats, other simple values, and out-of-order or duplicate map keys), which is
// precisely what a deterministic-encoding receiver MUST reject.
//
// Decoded value types (mirroring the Go uint64/int64/[]byte/string/[]any/*cborMap/
// bool/nil): integers decode to System.Numerics.BigInteger (major 0 -> a
// non-negative BigInteger; major 1 -> a negative BigInteger), byte strings to
// byte[], text strings to string, arrays to List<object?>, maps to CborMap, and the
// three simple values to bool / null.
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace Sh.Bubblefish.Npamp;

/// <summary>A structural fault in the deterministic-CBOR encoding (a MUST-reject).</summary>
public sealed class CborException : Exception
{
    public CborException(string message) : base(message) { }
}

/// <summary>A CBOR map preserving canonical key order.</summary>
public sealed class CborMap
{
    internal readonly struct Entry
    {
        public readonly byte[] KeyEnc;
        public readonly object? Key;
        public readonly object? Val;

        public Entry(byte[] keyEnc, object? key, object? val)
        {
            KeyEnc = keyEnc;
            Key = key;
            Val = val;
        }
    }

    private readonly List<Entry> _entries;

    internal CborMap(List<Entry> entries) => _entries = entries;

    /// <summary>
    /// Returns the value for an unsigned-integer key, or null if absent. A present
    /// CBOR null value is also returned as null; callers that must distinguish an
    /// absent key from a present null value call <see cref="Has"/> first.
    /// </summary>
    public object? Get(long key)
    {
        var k = new BigInteger(key);
        foreach (var e in _entries)
        {
            if (e.Key is BigInteger bi && bi == k)
            {
                return e.Val;
            }
        }
        return null;
    }

    /// <summary>Reports whether an unsigned-integer key is present.</summary>
    public bool Has(long key)
    {
        var k = new BigInteger(key);
        foreach (var e in _entries)
        {
            if (e.Key is BigInteger bi && bi == k)
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>Returns every key in canonical order (used for forward-compat checks).</summary>
    public IEnumerable<object?> Keys()
    {
        foreach (var e in _entries)
        {
            yield return e.Key;
        }
    }
}

/// <summary>Deterministic (canonical) CBOR decoder for the N-PAMP native operation bodies.</summary>
public static class NpampCbor
{
    // byteLess reports whether a sorts strictly before b in bytewise (shorter-prefix-
    // first, then lexicographic) order -- RFC 8949 §4.2.1 canonical map-key ordering.
    private static bool ByteLess(byte[] a, byte[] b)
    {
        if (a.Length != b.Length)
        {
            return a.Length < b.Length;
        }
        for (int i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i])
            {
                return a[i] < b[i];
            }
        }
        return false;
    }

    /// <summary>
    /// Decodes a single canonical CBOR item and requires that it consumes all of
    /// <paramref name="b"/> (no trailing bytes) -- the shape of a frame payload.
    /// </summary>
    public static object? DecodeTop(byte[] b)
    {
        int pos = 0;
        object? v = Decode(b, ref pos);
        if (pos != b.Length)
        {
            throw new CborException("npamp/cbor: trailing bytes after top-level item");
        }
        return v;
    }

    private static object? Decode(byte[] b, ref int pos)
    {
        if (pos >= b.Length)
        {
            throw new CborException("npamp/cbor: truncated input");
        }
        int ib = b[pos];
        int major = ib >> 5;
        int ai = ib & 0x1f;

        if (major == 7)
        {
            // Only false(20)/true(21)/null(22) are in the deterministic subset; floats
            // (25/26/27), other simple values, and the break stop (31) reject.
            switch (ai)
            {
                case 20:
                    pos += 1;
                    return false;
                case 21:
                    pos += 1;
                    return true;
                case 22:
                    pos += 1;
                    return null;
                default:
                    throw new CborException("npamp/cbor: unsupported major type or simple value");
            }
        }

        ulong arg = DecodeArg(ai, b, ref pos); // advances pos past the header
        int n = pos; // absolute offset just past the header

        switch (major)
        {
            case 0: // unsigned int
                return new BigInteger(arg);
            case 1: // negative int: value = -1 - arg
                return BigInteger.MinusOne - new BigInteger(arg);
            case 2:
            case 3:
            {
                // byte string / text string
                ulong remaining = (ulong)(b.Length - n);
                if (arg > remaining)
                {
                    throw new CborException("npamp/cbor: truncated input");
                }
                int len = (int)arg;
                byte[] payload = new byte[len];
                Array.Copy(b, n, payload, 0, len);
                pos = n + len;
                if (major == 2)
                {
                    return payload;
                }
                return Encoding.UTF8.GetString(payload);
            }
            case 4:
            {
                // array. Each element is >= 1 byte, so a declared count larger than the
                // remaining input cannot be satisfied (huge-count DoS guard).
                ulong remaining = (ulong)(b.Length - n);
                if (arg > remaining)
                {
                    throw new CborException("npamp/cbor: truncated input");
                }
                int count = (int)arg;
                var outList = new List<object?>(count);
                for (int i = 0; i < count; i++)
                {
                    outList.Add(Decode(b, ref pos));
                }
                return outList;
            }
            case 5:
            {
                // map. Each entry is >= 2 bytes, so a declared count larger than the
                // remaining input cannot be satisfied.
                ulong remaining = (ulong)(b.Length - n);
                if (arg > remaining)
                {
                    throw new CborException("npamp/cbor: truncated input");
                }
                int count = (int)arg;
                var entries = new List<CborMap.Entry>(count);
                byte[]? prevKeyEnc = null;
                for (int i = 0; i < count; i++)
                {
                    int keyStart = pos;
                    object? key = Decode(b, ref pos);
                    byte[] keyEnc = new byte[pos - keyStart];
                    Array.Copy(b, keyStart, keyEnc, 0, pos - keyStart);
                    // Canonical order: each key MUST sort strictly after the previous one.
                    if (prevKeyEnc != null && !ByteLess(prevKeyEnc, keyEnc))
                    {
                        throw new CborException(
                            "npamp/cbor: map keys not in canonical ascending order (or duplicate)");
                    }
                    prevKeyEnc = keyEnc;
                    object? val = Decode(b, ref pos);
                    entries.Add(new CborMap.Entry(keyEnc, key, val));
                }
                return new CborMap(entries);
            }
            default: // major 6 (tags): unsupported
                throw new CborException("npamp/cbor: unsupported major type or simple value");
        }
    }

    // DecodeArg reads the argument for an additional-information value ai, enforcing
    // shortest-form (RFC 8949 §4.2.1) and rejecting indefinite lengths. Advances pos
    // past the whole header and returns the argument.
    private static ulong DecodeArg(int ai, byte[] b, ref int pos)
    {
        if (ai < 24)
        {
            pos += 1;
            return (ulong)ai;
        }
        switch (ai)
        {
            case 24:
            {
                if (pos + 2 > b.Length)
                {
                    throw new CborException("npamp/cbor: truncated input");
                }
                ulong v = b[pos + 1];
                if (v < 24)
                {
                    throw new CborException("npamp/cbor: integer/length not in shortest form");
                }
                pos += 2;
                return v;
            }
            case 25:
            {
                if (pos + 3 > b.Length)
                {
                    throw new CborException("npamp/cbor: truncated input");
                }
                ulong v = ((ulong)b[pos + 1] << 8) | b[pos + 2];
                if (v < (1UL << 8))
                {
                    throw new CborException("npamp/cbor: integer/length not in shortest form");
                }
                pos += 3;
                return v;
            }
            case 26:
            {
                if (pos + 5 > b.Length)
                {
                    throw new CborException("npamp/cbor: truncated input");
                }
                ulong v = 0;
                for (int i = 1; i <= 4; i++)
                {
                    v = (v << 8) | b[pos + i];
                }
                if (v < (1UL << 16))
                {
                    throw new CborException("npamp/cbor: integer/length not in shortest form");
                }
                pos += 5;
                return v;
            }
            case 27:
            {
                if (pos + 9 > b.Length)
                {
                    throw new CborException("npamp/cbor: truncated input");
                }
                ulong v = 0;
                for (int i = 1; i <= 8; i++)
                {
                    v = (v << 8) | b[pos + i];
                }
                if (v < (1UL << 32))
                {
                    throw new CborException("npamp/cbor: integer/length not in shortest form");
                }
                pos += 9;
                return v;
            }
            case 31:
                throw new CborException("npamp/cbor: indefinite-length item (non-deterministic)");
            default: // 28,29,30 are reserved
                throw new CborException("npamp/cbor: unsupported major type or simple value");
        }
    }
}
