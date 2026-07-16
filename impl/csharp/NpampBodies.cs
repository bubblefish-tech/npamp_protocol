// Open reference implementation of the N-PAMP native-channel body validators
// (draft-bubblefish-npamp-01). OPEN protocol layer only. No proprietary methods.
//
// A native operation-channel frame payload is a deterministic-CBOR map (NpampCbor,
// the shared codec). This file adds, per channel, the common envelope check (§4.2
// frame_kind + correlation key), the per-frame-type body field schemas
// (required/typed), the forward-compatibility rule (accept an unknown non-negative
// integer key, reject an unknown negative or non-integer key), and the nested-
// structure MUST-reject rules each channel adds. It is a straight port of the Go
// reference validators impl/go/{memory,stream,capability,immune,settlement,
// telemetry,commerce,interaction,workflow,knowledge}_bodies.go and their TypeScript
// counterpart impl/typescript/src/npamp_bodies.ts.
//
// Each Validate<Channel>Payload(ft, payload) returns the decoded CborMap on success
// and THROWS on any structural fault. Throwing-on-reject is the whole contract the
// corpus MUST-reject vectors grade.
using System.Collections.Generic;
using System.Numerics;

namespace Sh.Bubblefish.Npamp;

/// <summary>A structural fault in a native-channel body (a MUST-reject).</summary>
public sealed class BodyException : System.Exception
{
    public BodyException(string message) : base(message) { }
}

/// <summary>Deterministic-CBOR body validators for the ten N-PAMP native operation channels.</summary>
public static class NpampBodies
{
    private enum Kind { Uint, Text, Bytes, Array, Map, Bool, Number }

    private readonly struct Field
    {
        public readonly long Key;
        public readonly Kind Kind;
        public readonly bool Required;

        public Field(long key, Kind kind, bool required)
        {
            Key = key;
            Kind = kind;
            Required = required;
        }
    }

    private static Field F(long key, Kind kind, bool required) => new Field(key, kind, required);

    private static bool IsUint(object? v) => v is BigInteger bi && bi.Sign >= 0;

    private static bool MatchesKind(object? v, Kind k) => k switch
    {
        Kind.Uint => v is BigInteger bi && bi.Sign >= 0,
        Kind.Text => v is string,
        Kind.Bytes => v is byte[],
        Kind.Array => v is List<object?>,
        Kind.Map => v is CborMap,
        Kind.Bool => v is bool,
        Kind.Number => v is BigInteger,
        _ => false,
    };

    // ForwardCompatKeys enforces the §4.3/§4.4 rule: an unknown non-negative integer
    // key is accepted; an unknown NEGATIVE integer key, or a non-integer key, MUST be
    // rejected. Integers decode to BigInteger (non-negative for major 0, negative for
    // major 1); a negative BigInteger key is reserved, a non-BigInteger key non-integer.
    private static void ForwardCompatKeys(CborMap m, string prefix)
    {
        foreach (object? k in m.Keys())
        {
            if (k is BigInteger bi)
            {
                if (bi.Sign < 0)
                {
                    throw Bad(prefix, $"unknown negative key {bi} (reserved)");
                }
            }
            else
            {
                throw Bad(prefix, "non-integer map key");
            }
        }
    }

    private static void CheckFields(CborMap m, Field[] schema, string prefix)
    {
        foreach (Field fld in schema)
        {
            if (!m.Has(fld.Key))
            {
                if (fld.Required)
                {
                    throw Bad(prefix, $"missing required field (key {fld.Key})");
                }
                continue;
            }
            if (!MatchesKind(m.Get(fld.Key), fld.Kind))
            {
                throw Bad(prefix, $"field (key {fld.Key}) has the wrong CBOR type");
            }
        }
        ForwardCompatKeys(m, prefix);
    }

    private static CborMap DecodeMap(byte[] payload, string prefix)
    {
        object? v;
        try
        {
            v = NpampCbor.DecodeTop(payload);
        }
        catch (CborException e)
        {
            throw Bad(prefix, e.Message);
        }
        if (v is not CborMap m)
        {
            throw Bad(prefix, "payload is not a CBOR map");
        }
        return m;
    }

    private static void CheckFrameKind(CborMap m, int ft, string prefix)
    {
        if (!m.Has(0))
        {
            throw Bad(prefix, "missing frame_kind (0)");
        }
        object? fk = m.Get(0);
        if (!IsUint(fk))
        {
            throw Bad(prefix, "frame_kind (0) is not an unsigned int");
        }
        if ((BigInteger)fk! != new BigInteger(ft))
        {
            throw Bad(prefix, $"frame_kind {fk} contradicts frame type {ft}");
        }
    }

    private static void CheckCorr(CborMap m, string prefix)
    {
        if (!m.Has(1))
        {
            throw Bad(prefix, "missing corr (1)");
        }
        object? corr = m.Get(1);
        if (corr is not byte[] b || b.Length < 1 || b.Length > 64)
        {
            throw Bad(prefix, "corr (1) must be a byte string of 1-64 bytes");
        }
    }

    private static BodyException Bad(string prefix, string msg) => new BodyException($"{prefix}: {msg}");

    // ---------- NPAMP-MEMORY (spec/companion/81 §4-§8) ----------

    private const int FrameMemoryCreateReq = 0x0100;
    private const int FrameMemoryCreateResult = 0x0101;
    private const int FrameMemoryReadReq = 0x0102;
    private const int FrameMemoryReadResult = 0x0103;
    private const int FrameMemoryUpdateReq = 0x0104;
    private const int FrameMemoryUpdateResult = 0x0105;
    private const int FrameMemoryDeleteReq = 0x0106;
    private const int FrameMemoryDeleteResult = 0x0107;
    private const int FrameMemoryRetrieveReq = 0x0108;
    private const int FrameMemoryRetrieveResult = 0x0109;
    private const int FrameMemoryRetrieveStreamData = 0x010a;
    private const int FrameMemoryRetrieveStreamEnd = 0x010b;
    private const int FrameMemoryStatusReq = 0x010c;
    private const int FrameMemoryStatusResult = 0x010d;
    private const int FrameMemoryError = 0x010e;
    private const int FrameMemoryEvict = 0x0035;
    private const int FrameMemoryRevive = 0x0036;

    private static readonly Dictionary<int, Field[]> MemorySchemas = new()
    {
        [FrameMemoryCreateReq] = new[] {
            F(2, Kind.Text, true), F(3, Kind.Text, false), F(4, Kind.Text, false), F(5, Kind.Text, false),
            F(6, Kind.Text, false), F(7, Kind.Text, false), F(8, Kind.Text, false), F(9, Kind.Text, false),
            F(10, Kind.Map, false), F(11, Kind.Uint, true) },
        [FrameMemoryCreateResult] = new[] { F(2, Kind.Text, true), F(3, Kind.Text, true) },
        [FrameMemoryReadReq] = new[] { F(2, Kind.Text, true), F(3, Kind.Uint, true) },
        [FrameMemoryReadResult] = new[] { F(2, Kind.Map, true) },
        [FrameMemoryUpdateReq] = new[] {
            F(2, Kind.Text, true), F(3, Kind.Text, false), F(4, Kind.Text, false), F(5, Kind.Text, false),
            F(6, Kind.Text, false), F(7, Kind.Text, false), F(8, Kind.Text, false), F(9, Kind.Map, false),
            F(10, Kind.Uint, true) },
        [FrameMemoryUpdateResult] = new[] { F(2, Kind.Text, true), F(3, Kind.Text, true) },
        [FrameMemoryDeleteReq] = new[] { F(2, Kind.Text, true), F(3, Kind.Uint, true) },
        [FrameMemoryDeleteResult] = new[] { F(2, Kind.Text, true), F(3, Kind.Text, true) },
        [FrameMemoryRetrieveReq] = new[] {
            F(2, Kind.Text, false), F(3, Kind.Text, false), F(4, Kind.Text, false), F(5, Kind.Text, false),
            F(6, Kind.Text, false), F(7, Kind.Uint, false), F(8, Kind.Text, false), F(9, Kind.Bytes, false),
            F(10, Kind.Uint, true) },
        [FrameMemoryRetrieveResult] = new[] {
            F(2, Kind.Array, true), F(3, Kind.Bool, true), F(4, Kind.Bytes, false), F(5, Kind.Uint, false),
            F(6, Kind.Bool, false) },
        [FrameMemoryRetrieveStreamData] = new[] { F(2, Kind.Array, true) },
        [FrameMemoryRetrieveStreamEnd] = new[] { F(2, Kind.Array, false), F(3, Kind.Bool, true) },
        [FrameMemoryStatusReq] = System.Array.Empty<Field>(),
        [FrameMemoryStatusResult] = new[] {
            F(2, Kind.Text, true), F(3, Kind.Text, false), F(4, Kind.Uint, false), F(5, Kind.Map, false) },
        [FrameMemoryError] = new[] {
            F(2, Kind.Uint, true), F(3, Kind.Text, true), F(4, Kind.Uint, false), F(5, Kind.Text, false) },
        [FrameMemoryEvict] = new[] { F(2, Kind.Text, true), F(3, Kind.Text, false), F(4, Kind.Uint, true) },
        [FrameMemoryRevive] = new[] { F(2, Kind.Text, true), F(3, Kind.Uint, true) },
    };

    public static CborMap ValidateMemoryPayload(int ft, byte[] payload)
    {
        const string p = "npamp/memory: malformed_request";
        if (!MemorySchemas.TryGetValue(ft, out Field[]? schema))
        {
            throw Bad(p, $"{ft} is not a Memory operation frame type");
        }
        CborMap m = DecodeMap(payload, p);
        CheckFrameKind(m, ft, p);
        CheckCorr(m, p);
        CheckFields(m, schema, p);
        return m;
    }

    // ---------- NPAMP-STREAM (spec/companion/80 §4-§5) ----------

    private const int FrameStreamOpen = 0x0100;
    private const int FrameStreamData = 0x0101;
    private const int FrameStreamClose = 0x0102;
    private const int FrameStreamReset = 0x0103;
    private const int FrameStreamWindowUpdate = 0x0104;

    private static readonly Dictionary<int, Field[]> StreamSchemas = new()
    {
        [FrameStreamOpen] = new[] { F(2, Kind.Uint, true), F(3, Kind.Uint, true), F(4, Kind.Text, false), F(5, Kind.Uint, false) },
        [FrameStreamData] = new[] { F(2, Kind.Uint, true), F(3, Kind.Bytes, true), F(4, Kind.Uint, false) },
        [FrameStreamClose] = new[] { F(2, Kind.Uint, true) },
        [FrameStreamReset] = new[] { F(2, Kind.Uint, true), F(3, Kind.Uint, true) },
        [FrameStreamWindowUpdate] = new[] { F(2, Kind.Uint, true) },
    };

    public static CborMap ValidateStreamPayload(int ft, byte[] payload)
    {
        const string p = "npamp/stream: malformed";
        if (!StreamSchemas.TryGetValue(ft, out Field[]? schema))
        {
            throw Bad(p, $"{ft} is not a Stream frame type");
        }
        CborMap m = DecodeMap(payload, p);
        CheckFrameKind(m, ft, p);
        // Envelope key 1 is sub_stream_id -- an Unsigned int, unlike the byte-string corr.
        if (!m.Has(1))
        {
            throw Bad(p, "missing sub_stream_id (1)");
        }
        if (!IsUint(m.Get(1)))
        {
            throw Bad(p, "sub_stream_id (1) is not an unsigned int");
        }
        CheckFields(m, schema, p);
        return m;
    }

    // ---------- NPAMP-CAP (spec/companion/84 §4-§8) ----------

    private const int FrameCapIssueReq = 0x0100;
    private const int FrameCapIssueResult = 0x0101;
    private const int FrameCapDelegateReq = 0x0102;
    private const int FrameCapDelegateResult = 0x0103;
    private const int FrameCapRevokeReq = 0x0104;
    private const int FrameCapRevokeResult = 0x0105;
    private const int FrameCapLookupReq = 0x0106;
    private const int FrameCapLookupResult = 0x0107;
    private const int FrameCapError = 0x0108;
    private const int FrameCapTokenPresent = 0x0060;
    private const int FrameCapTokenAccept = 0x0061;
    private const int FrameCapTokenChallenge = 0x0062;
    private const int FrameCapTokenProof = 0x0063;

    private static readonly Dictionary<int, Field[]> CapabilitySchemas = new()
    {
        [FrameCapIssueReq] = new[] {
            F(2, Kind.Text, true), F(3, Kind.Text, true), F(4, Kind.Map, false), F(5, Kind.Text, false),
            F(6, Kind.Text, false), F(7, Kind.Uint, false), F(8, Kind.Text, false), F(9, Kind.Uint, true) },
        [FrameCapIssueResult] = new[] { F(2, Kind.Map, true), F(3, Kind.Text, true) },
        [FrameCapDelegateReq] = new[] {
            F(2, Kind.Text, true), F(3, Kind.Text, true), F(4, Kind.Map, false), F(5, Kind.Text, false),
            F(6, Kind.Uint, false), F(7, Kind.Uint, true) },
        [FrameCapDelegateResult] = new[] { F(2, Kind.Map, true), F(3, Kind.Text, true) },
        [FrameCapRevokeReq] = new[] { F(2, Kind.Text, true), F(3, Kind.Bool, false), F(4, Kind.Text, false), F(5, Kind.Uint, true) },
        [FrameCapRevokeResult] = new[] { F(2, Kind.Text, true), F(3, Kind.Text, true), F(4, Kind.Uint, false) },
        [FrameCapLookupReq] = new[] {
            F(2, Kind.Text, false), F(3, Kind.Text, false), F(4, Kind.Text, false), F(5, Kind.Bool, false),
            F(6, Kind.Uint, false), F(7, Kind.Bytes, false), F(8, Kind.Uint, true) },
        [FrameCapLookupResult] = new[] { F(2, Kind.Array, true), F(3, Kind.Bool, true), F(4, Kind.Bytes, false) },
        [FrameCapError] = new[] { F(2, Kind.Uint, true), F(3, Kind.Text, true), F(4, Kind.Uint, false), F(5, Kind.Text, false) },
        [FrameCapTokenPresent] = new[] { F(2, Kind.Map, true), F(3, Kind.Array, false), F(4, Kind.Uint, true) },
        [FrameCapTokenAccept] = new[] { F(2, Kind.Text, true), F(3, Kind.Text, true) },
        [FrameCapTokenChallenge] = new[] { F(2, Kind.Text, true), F(3, Kind.Bytes, true), F(4, Kind.Uint, true) },
        [FrameCapTokenProof] = new[] { F(2, Kind.Text, true), F(3, Kind.Bytes, true) },
    };

    public static CborMap ValidateCapabilityPayload(int ft, byte[] payload)
    {
        const string p = "npamp/capability: malformed_request";
        if (!CapabilitySchemas.TryGetValue(ft, out Field[]? schema))
        {
            throw Bad(p, $"{ft} is not a Capability operation frame type");
        }
        CborMap m = DecodeMap(payload, p);
        CheckFrameKind(m, ft, p);
        CheckCorr(m, p);
        CheckFields(m, schema, p);
        return m;
    }

    // ---------- NPAMP-IMMUNE (spec/companion/85 §4-§8) ----------

    private const int FrameImmuneReportReq = 0x0100;
    private const int FrameImmuneReportResult = 0x0101;
    private const int FrameImmuneError = 0x0102;
    private const int FrameImmuneGossipAdvertise = 0x00c0;
    private const int FrameImmuneGossipAck = 0x00c1;
    private const int FrameImmuneGossipPullReq = 0x00c2;
    private const int FrameImmuneGossipPullResult = 0x00c3;
    private const int FrameImmuneGossipRetract = 0x00c4;

    private static readonly Dictionary<int, Field[]> ImmuneSchemas = new()
    {
        [FrameImmuneReportReq] = new[] {
            F(2, Kind.Text, true), F(3, Kind.Uint, true), F(4, Kind.Uint, true), F(5, Kind.Text, false),
            F(6, Kind.Text, false), F(7, Kind.Text, false), F(8, Kind.Bytes, false), F(9, Kind.Uint, false),
            F(10, Kind.Text, false) },
        [FrameImmuneReportResult] = new[] { F(2, Kind.Uint, true), F(3, Kind.Text, false) },
        [FrameImmuneError] = new[] { F(2, Kind.Uint, true), F(3, Kind.Text, true), F(4, Kind.Uint, false) },
        [FrameImmuneGossipAdvertise] = new[] { F(2, Kind.Array, true), F(3, Kind.Bool, false) },
        [FrameImmuneGossipAck] = new[] { F(2, Kind.Array, false), F(3, Kind.Array, false), F(4, Kind.Uint, false) },
        [FrameImmuneGossipPullReq] = new[] { F(2, Kind.Array, true) },
        [FrameImmuneGossipPullResult] = new[] { F(2, Kind.Array, true) },
        [FrameImmuneGossipRetract] = new[] { F(2, Kind.Bytes, true), F(3, Kind.Uint, true), F(4, Kind.Uint, false) },
    };

    private static readonly Field[] GossipDescriptorSchema = {
        F(0, Kind.Bytes, true), F(1, Kind.Uint, true), F(2, Kind.Uint, false), F(3, Kind.Uint, false),
        F(4, Kind.Bytes, false), F(5, Kind.Text, false), F(6, Kind.Text, false), F(7, Kind.Uint, false),
        F(8, Kind.Bytes, false), F(9, Kind.Bytes, false) };
    private static readonly Field[] GossipItemSchema = {
        F(0, Kind.Bytes, true), F(1, Kind.Uint, true), F(2, Kind.Uint, false), F(3, Kind.Uint, false),
        F(4, Kind.Bytes, false), F(5, Kind.Text, false), F(6, Kind.Text, false), F(7, Kind.Uint, false),
        F(8, Kind.Bytes, true) };

    private static void ValidateGossipArray(CborMap m, Field[] nested, string p)
    {
        if (m.Get(2) is not List<object?> items)
        {
            throw Bad(p, "items (2) is not an array");
        }
        for (int i = 0; i < items.Count; i++)
        {
            if (items[i] is not CborMap el)
            {
                throw Bad(p, $"items[{i}] is not a CBOR map");
            }
            CheckFields(el, nested, p);
        }
    }

    public static CborMap ValidateImmunePayload(int ft, byte[] payload)
    {
        const string p = "npamp/immune: malformed_request";
        if (!ImmuneSchemas.TryGetValue(ft, out Field[]? schema))
        {
            throw Bad(p, $"{ft} is not an Immune operation frame type");
        }
        CborMap m = DecodeMap(payload, p);
        CheckFrameKind(m, ft, p);
        CheckCorr(m, p);
        CheckFields(m, schema, p);
        if (ft == FrameImmuneGossipAdvertise)
        {
            ValidateGossipArray(m, GossipDescriptorSchema, p);
        }
        else if (ft == FrameImmuneGossipPullResult)
        {
            ValidateGossipArray(m, GossipItemSchema, p);
        }
        return m;
    }

    // ---------- NPAMP-SETTLEMENT (spec/companion/86 §4-§8) ----------

    private const int FrameSettleIntentReq = 0x0100;
    private const int FrameSettleIntentResult = 0x0101;
    private const int FrameReceiptReq = 0x0102;
    private const int FrameReceiptResult = 0x0103;
    private const int FrameSettleError = 0x0104;
    private const int FrameSettleBatchCommitReq = 0x00a0;
    private const int FrameSettleBatchCommitResult = 0x00a1;

    private static readonly Dictionary<int, Field[]> SettlementSchemas = new()
    {
        [FrameSettleIntentReq] = new[] {
            F(2, Kind.Text, true), F(3, Kind.Text, false), F(4, Kind.Text, false), F(5, Kind.Text, false),
            F(6, Kind.Text, false), F(7, Kind.Text, false), F(8, Kind.Uint, true) },
        [FrameSettleIntentResult] = new[] { F(2, Kind.Text, true), F(3, Kind.Text, true), F(4, Kind.Text, false) },
        [FrameReceiptReq] = new[] { F(2, Kind.Text, true), F(3, Kind.Text, false), F(4, Kind.Uint, true) },
        [FrameReceiptResult] = new[] { F(2, Kind.Map, true) },
        [FrameSettleError] = new[] { F(2, Kind.Uint, true), F(3, Kind.Text, true), F(4, Kind.Uint, false), F(5, Kind.Text, false) },
        [FrameSettleBatchCommitReq] = new[] {
            F(2, Kind.Text, true), F(3, Kind.Bytes, true), F(4, Kind.Text, false), F(5, Kind.Uint, false),
            F(6, Kind.Text, false), F(7, Kind.Uint, true) },
        [FrameSettleBatchCommitResult] = new[] { F(2, Kind.Text, true), F(3, Kind.Text, true), F(4, Kind.Text, false) },
    };

    public static CborMap ValidateSettlementPayload(int ft, byte[] payload)
    {
        const string p = "npamp/settlement: malformed_request";
        if (!SettlementSchemas.TryGetValue(ft, out Field[]? schema))
        {
            throw Bad(p, $"{ft} is not a Settlement operation frame type");
        }
        CborMap m = DecodeMap(payload, p);
        CheckFrameKind(m, ft, p);
        CheckCorr(m, p);
        CheckFields(m, schema, p);
        return m;
    }

    // ---------- NPAMP-TELEMETRY (spec/companion/87 §4-§8) ----------

    private const int FrameTelemetryReport = 0x0100;
    private const int FrameTelemetrySubscribe = 0x0101;
    private const int FrameTelemetrySubAck = 0x0102;
    private const int FrameTelemetryUnsubscribe = 0x0103;
    private const int FrameTelemetryCredit = 0x0104;
    private const int FrameTelemetryError = 0x0105;

    private static readonly Dictionary<int, Field[]> TelemetrySchemas = new()
    {
        [FrameTelemetrySubscribe] = new[] {
            F(2, Kind.Array, false), F(3, Kind.Array, false), F(4, Kind.Array, false),
            F(5, Kind.Uint, false), F(6, Kind.Uint, false), F(7, Kind.Uint, true) },
        [FrameTelemetrySubAck] = new[] { F(2, Kind.Bytes, true), F(3, Kind.Uint, true), F(4, Kind.Array, false) },
        [FrameTelemetryUnsubscribe] = new[] { F(2, Kind.Bytes, true) },
        [FrameTelemetryCredit] = new[] { F(2, Kind.Bytes, true), F(3, Kind.Uint, true), F(4, Kind.Uint, false) },
        [FrameTelemetryError] = new[] { F(2, Kind.Uint, true), F(3, Kind.Text, false), F(4, Kind.Bytes, false) },
    };

    private static readonly Field[] MetricSchema = {
        F(0, Kind.Text, true), F(1, Kind.Uint, true), F(2, Kind.Uint, true), F(3, Kind.Number, true),
        F(4, Kind.Text, false), F(5, Kind.Map, false), F(6, Kind.Uint, false) };
    private static readonly Field[] EventSchema = {
        F(0, Kind.Text, true), F(1, Kind.Uint, true), F(2, Kind.Uint, false),
        F(3, Kind.Map, false), F(4, Kind.Text, false), F(5, Kind.Uint, false) };
    private static readonly Field[] HealthSchema = {
        F(0, Kind.Text, true), F(1, Kind.Uint, true), F(2, Kind.Uint, true),
        F(3, Kind.Text, false), F(4, Kind.Map, false) };

    private static bool IsTelemetryFrame(int ft) => ft >= FrameTelemetryReport && ft <= FrameTelemetryError;

    public static CborMap ValidateTelemetryPayload(int ft, byte[] payload)
    {
        const string p = "npamp/telemetry: malformed_payload";
        if (!IsTelemetryFrame(ft))
        {
            throw Bad(p, $"{ft} is not a Telemetry operation frame type");
        }
        CborMap m = DecodeMap(payload, p);
        CheckFrameKind(m, ft, p);
        if (ft == FrameTelemetryReport)
        {
            return ValidateTelemetryReport(m, p);
        }
        // Every non-REPORT Telemetry frame carries a REQUIRED, non-empty corr (1) (§4.1).
        CheckCorr(m, p);
        CheckFields(m, TelemetrySchemas[ft], p);
        return m;
    }

    // ValidateTelemetryReport: corr (1) is CONDITIONAL (present iff the batch answers
    // a subscription, in which case sub_id (2) MUST also be present; a standalone
    // report MUST omit both); batch_seq (3) is REQUIRED; the report MUST carry content
    // (at least one of metrics(4)/events(5)/health(6) present and non-empty).
    private static CborMap ValidateTelemetryReport(CborMap m, string p)
    {
        bool hasCorr = m.Has(1);
        bool hasSubID = m.Has(2);
        if (hasCorr)
        {
            if (m.Get(1) is not byte[] corr || corr.Length < 1 || corr.Length > 64)
            {
                throw Bad(p, "corr (1) must be a byte string of 1-64 bytes");
            }
            if (!hasSubID)
            {
                throw Bad(p, "subscribed report carries corr (1) but omits sub_id (2)");
            }
            if (m.Get(2) is not byte[])
            {
                throw Bad(p, "sub_id (2) must be a byte string");
            }
        }
        else if (hasSubID)
        {
            throw Bad(p, "standalone report carries sub_id (2) without corr (1)");
        }

        if (!m.Has(3))
        {
            throw Bad(p, "missing required batch_seq (3)");
        }
        if (!IsUint(m.Get(3)))
        {
            throw Bad(p, "batch_seq (3) is not an unsigned int");
        }

        int nonEmpty = 0;
        (long key, Field[] schema, string what)[] content = {
            (4, MetricSchema, "metric"),
            (5, EventSchema, "event"),
            (6, HealthSchema, "health"),
        };
        foreach (var c in content)
        {
            if (!m.Has(c.key))
            {
                continue;
            }
            if (m.Get(c.key) is not List<object?> arr)
            {
                throw Bad(p, $"{c.what} array (key {c.key}) is not a CBOR array");
            }
            if (arr.Count > 0)
            {
                nonEmpty++;
            }
            foreach (object? el in arr)
            {
                if (el is not CborMap em)
                {
                    throw Bad(p, $"{c.what} array element is not a CBOR map");
                }
                CheckFields(em, c.schema, p);
            }
        }
        if (nonEmpty == 0)
        {
            throw Bad(p, "TELEMETRY_REPORT carries no metrics, events, or health");
        }

        ForwardCompatKeys(m, p);
        return m;
    }

    // ---------- NPAMP-COMMERCE (spec/companion/88 §4-§8) ----------

    private const int FrameCommerceMandateCreateReq = 0x0100;
    private const int FrameCommerceMandateCreateResult = 0x0101;
    private const int FrameCommerceMandateReadReq = 0x0102;
    private const int FrameCommerceMandateReadResult = 0x0103;
    private const int FrameCommerceMandateRevokeReq = 0x0104;
    private const int FrameCommerceMandateRevokeResult = 0x0105;
    private const int FrameCommerceMandateStatusReq = 0x0106;
    private const int FrameCommerceMandateStatusResult = 0x0107;
    private const int FrameCommerceIntentProposeReq = 0x0108;
    private const int FrameCommerceIntentProposeResult = 0x0109;
    private const int FrameCommerceIntentRespondReq = 0x010a;
    private const int FrameCommerceIntentRespondResult = 0x010b;
    private const int FrameCommerceIntentStatusReq = 0x010c;
    private const int FrameCommerceIntentStatusResult = 0x010d;
    private const int FrameCommerceError = 0x010e;

    private static readonly Dictionary<int, Field[]> CommerceSchemas = new()
    {
        [FrameCommerceMandateCreateReq] = new[] {
            F(2, Kind.Text, true), F(3, Kind.Text, true), F(4, Kind.Map, true), F(5, Kind.Text, false),
            F(6, Kind.Text, false), F(7, Kind.Text, false), F(8, Kind.Map, false), F(9, Kind.Text, false),
            F(10, Kind.Bytes, false), F(11, Kind.Text, false), F(12, Kind.Text, false), F(13, Kind.Uint, true) },
        [FrameCommerceMandateCreateResult] = new[] { F(2, Kind.Text, true), F(3, Kind.Text, true) },
        [FrameCommerceMandateReadReq] = new[] { F(2, Kind.Text, true), F(3, Kind.Uint, true) },
        [FrameCommerceMandateReadResult] = new[] { F(2, Kind.Map, true) },
        [FrameCommerceMandateRevokeReq] = new[] { F(2, Kind.Text, true), F(3, Kind.Text, false), F(4, Kind.Uint, true) },
        [FrameCommerceMandateRevokeResult] = new[] { F(2, Kind.Text, true), F(3, Kind.Text, true) },
        [FrameCommerceMandateStatusReq] = new[] { F(2, Kind.Text, true), F(3, Kind.Uint, true) },
        [FrameCommerceMandateStatusResult] = new[] { F(2, Kind.Text, true), F(3, Kind.Text, true), F(4, Kind.Text, false) },
        [FrameCommerceIntentProposeReq] = new[] {
            F(2, Kind.Array, true), F(3, Kind.Array, true), F(4, Kind.Text, false), F(5, Kind.Map, false),
            F(6, Kind.Text, false), F(7, Kind.Uint, true) },
        [FrameCommerceIntentProposeResult] = new[] { F(2, Kind.Text, true), F(3, Kind.Text, true) },
        [FrameCommerceIntentRespondReq] = new[] {
            F(2, Kind.Text, true), F(3, Kind.Uint, true), F(4, Kind.Array, false), F(5, Kind.Text, false), F(6, Kind.Uint, true) },
        [FrameCommerceIntentRespondResult] = new[] { F(2, Kind.Text, true), F(3, Kind.Text, true) },
        [FrameCommerceIntentStatusReq] = new[] { F(2, Kind.Text, true), F(3, Kind.Uint, true) },
        [FrameCommerceIntentStatusResult] = new[] {
            F(2, Kind.Text, true), F(3, Kind.Text, true), F(4, Kind.Array, false), F(5, Kind.Array, false) },
        [FrameCommerceError] = new[] { F(2, Kind.Uint, true), F(3, Kind.Text, true), F(4, Kind.Uint, false), F(5, Kind.Text, false) },
    };

    private static void ValidateCommerceAmount(object? v, string p)
    {
        if (v is not CborMap am)
        {
            throw Bad(p, "`amount` is not a CBOR map (§4.3)");
        }
        if (!am.Has(0))
        {
            throw Bad(p, "`amount` omits REQUIRED units (0) (§4.3)");
        }
        if (am.Get(0) is not BigInteger)
        {
            throw Bad(p, "`amount` units (0) is not an integer (§4.3)");
        }
        if (!am.Has(1))
        {
            throw Bad(p, "`amount` omits REQUIRED scale (1) (§4.3)");
        }
        if (!IsUint(am.Get(1)))
        {
            throw Bad(p, "`amount` scale (1) is not an unsigned int (§4.3)");
        }
        if (!am.Has(2))
        {
            throw Bad(p, "`amount` omits REQUIRED currency (2) (§4.3)");
        }
        if (am.Get(2) is not string)
        {
            throw Bad(p, "`amount` currency (2) is not a text string (§4.3)");
        }
        ForwardCompatKeys(am, p);
    }

    private static void ValidateCommerceLeg(object? v, HashSet<string> parties, string p)
    {
        if (v is not CborMap leg)
        {
            throw Bad(p, "a settlement leg is not a CBOR map (§6.6)");
        }
        if (!leg.Has(0))
        {
            throw Bad(p, "a leg omits REQUIRED `from` (0) (§6.6)");
        }
        if (leg.Get(0) is not string frm)
        {
            throw Bad(p, "a leg `from` (0) is not a text string (§6.6)");
        }
        if (!leg.Has(1))
        {
            throw Bad(p, "a leg omits REQUIRED `to` (1) (§6.6)");
        }
        if (leg.Get(1) is not string to)
        {
            throw Bad(p, "a leg `to` (1) is not a text string (§6.6)");
        }
        if (!leg.Has(2))
        {
            throw Bad(p, "a leg omits REQUIRED `amount` (2) (§6.6)");
        }
        ValidateCommerceAmount(leg.Get(2), p);
        if (!parties.Contains(frm))
        {
            throw Bad(p, "leg `from` names a party not in `parties` (§6.6)");
        }
        if (!parties.Contains(to))
        {
            throw Bad(p, "leg `to` names a party not in `parties` (§6.6)");
        }
        ForwardCompatKeys(leg, p);
    }

    private static void ValidateCommerceNested(int ft, CborMap m, string p)
    {
        if (ft == FrameCommerceMandateCreateReq)
        {
            object? av = m.Get(4);
            if (av != null)
            {
                ValidateCommerceAmount(av, p);
            }
        }
        else if (ft == FrameCommerceIntentProposeReq)
        {
            var parties = new HashSet<string>();
            if (m.Get(2) is List<object?> pv)
            {
                foreach (object? party in pv)
                {
                    if (party is not string ps)
                    {
                        throw Bad(p, "a `parties` element is not a text string (§6.6)");
                    }
                    parties.Add(ps);
                }
            }
            if (m.Get(3) is List<object?> lv)
            {
                foreach (object? lg in lv)
                {
                    ValidateCommerceLeg(lg, parties, p);
                }
            }
        }
    }

    public static CborMap ValidateCommercePayload(int ft, byte[] payload)
    {
        const string p = "npamp/commerce: malformed_request";
        if (!CommerceSchemas.TryGetValue(ft, out Field[]? schema))
        {
            throw Bad(p, $"{ft} is not a Commerce operation frame type");
        }
        CborMap m = DecodeMap(payload, p);
        CheckFrameKind(m, ft, p);
        CheckCorr(m, p);
        CheckFields(m, schema, p);
        ValidateCommerceNested(ft, m, p);
        return m;
    }

    // ---------- NPAMP-INTERACT (spec/companion/89 §4-§8) ----------

    private const int FrameInteractEvent = 0x0100;
    private const int FrameInteractEventAck = 0x0101;
    private const int FrameInteractPromptReq = 0x0102;
    private const int FrameInteractPromptResult = 0x0103;
    private const int FrameInteractApprovalReq = 0x0104;
    private const int FrameInteractApprovalResult = 0x0105;
    private const int FrameInteractCancel = 0x0106;
    private const int FrameInteractError = 0x0107;

    private static readonly Dictionary<int, Field[]> InteractionSchemas = new()
    {
        [FrameInteractEvent] = new[] { F(2, Kind.Uint, true), F(3, Kind.Text, false), F(4, Kind.Map, false), F(5, Kind.Bool, false) },
        [FrameInteractEventAck] = System.Array.Empty<Field>(),
        [FrameInteractPromptReq] = new[] {
            F(2, Kind.Uint, true), F(3, Kind.Text, true), F(4, Kind.Array, false), F(5, Kind.Map, false), F(6, Kind.Uint, false) },
        [FrameInteractPromptResult] = new[] { F(2, Kind.Uint, true) },
        [FrameInteractApprovalReq] = new[] { F(2, Kind.Text, true), F(3, Kind.Uint, false), F(4, Kind.Map, false), F(5, Kind.Uint, false) },
        [FrameInteractApprovalResult] = new[] { F(2, Kind.Uint, true), F(3, Kind.Text, false) },
        [FrameInteractCancel] = new[] { F(2, Kind.Uint, false) },
        [FrameInteractError] = new[] { F(2, Kind.Uint, true), F(3, Kind.Text, true), F(4, Kind.Uint, false), F(5, Kind.Text, false) },
    };

    public static CborMap ValidateInteractionPayload(int ft, byte[] payload)
    {
        const string p = "npamp/interaction: malformed_request";
        if (!InteractionSchemas.TryGetValue(ft, out Field[]? schema))
        {
            throw Bad(p, $"{ft} is not an Interaction operation frame type");
        }
        CborMap m = DecodeMap(payload, p);
        CheckFrameKind(m, ft, p);
        CheckCorr(m, p);
        CheckFields(m, schema, p);
        return m;
    }

    // ---------- NPAMP-WORKFLOW (spec/companion/8a §4-§8) ----------

    private const int FrameWorkflowSubmitReq = 0x0100;
    private const int FrameWorkflowSubmitResult = 0x0101;
    private const int FrameWorkflowStatusReq = 0x0102;
    private const int FrameWorkflowStatusResult = 0x0103;
    private const int FrameWorkflowCancelReq = 0x0104;
    private const int FrameWorkflowCancelResult = 0x0105;
    private const int FrameWorkflowStepEvent = 0x0106;
    private const int FrameWorkflowComplete = 0x0107;
    private const int FrameWorkflowError = 0x0108;

    private static readonly Dictionary<int, Field[]> WorkflowSchemas = new()
    {
        [FrameWorkflowSubmitReq] = new[] {
            F(2, Kind.Text, true), F(3, Kind.Bytes, false), F(4, Kind.Map, false), F(5, Kind.Uint, false),
            F(6, Kind.Text, false), F(7, Kind.Text, false), F(8, Kind.Text, false), F(9, Kind.Text, false),
            F(10, Kind.Map, false), F(11, Kind.Uint, true) },
        [FrameWorkflowSubmitResult] = new[] { F(2, Kind.Text, true), F(3, Kind.Uint, true) },
        [FrameWorkflowStatusReq] = new[] { F(2, Kind.Text, true) },
        [FrameWorkflowStatusResult] = new[] {
            F(2, Kind.Text, true), F(3, Kind.Uint, true), F(4, Kind.Uint, false), F(5, Kind.Text, false),
            F(6, Kind.Uint, false), F(7, Kind.Text, false) },
        [FrameWorkflowCancelReq] = new[] { F(2, Kind.Text, true), F(3, Kind.Text, false) },
        [FrameWorkflowCancelResult] = new[] { F(2, Kind.Text, true), F(3, Kind.Uint, true) },
        [FrameWorkflowStepEvent] = new[] {
            F(2, Kind.Text, true), F(3, Kind.Uint, true), F(4, Kind.Uint, true), F(5, Kind.Uint, false),
            F(6, Kind.Text, false), F(7, Kind.Uint, false), F(8, Kind.Bytes, false), F(9, Kind.Text, false) },
        [FrameWorkflowComplete] = new[] {
            F(2, Kind.Text, true), F(3, Kind.Uint, true), F(4, Kind.Uint, true), F(5, Kind.Bytes, false),
            F(6, Kind.Uint, false), F(7, Kind.Text, false) },
        [FrameWorkflowError] = new[] { F(2, Kind.Uint, true), F(3, Kind.Text, true), F(4, Kind.Uint, false), F(5, Kind.Text, false) },
    };

    private static bool WorkflowFrameHasCorr(int ft) => ft != FrameWorkflowStepEvent && ft != FrameWorkflowComplete;

    public static CborMap ValidateWorkflowPayload(int ft, byte[] payload)
    {
        const string p = "npamp/workflow: malformed_request";
        if (!WorkflowSchemas.TryGetValue(ft, out Field[]? schema))
        {
            throw Bad(p, $"{ft} is not a Workflow frame type");
        }
        CborMap m = DecodeMap(payload, p);
        CheckFrameKind(m, ft, p);
        // corr (1) is REQUIRED on every corr-bearing frame; the task-scoped
        // WORKFLOW_STEP_EVENT / WORKFLOW_COMPLETE carry no corr (§4.2, §5.2).
        if (WorkflowFrameHasCorr(ft))
        {
            CheckCorr(m, p);
        }
        CheckFields(m, schema, p);
        return m;
    }

    // ---------- NPAMP-KNOWLEDGE (spec/companion/8b §4-§9) ----------

    private const int FrameKnowledgeQueryReq = 0x0100;
    private const int FrameKnowledgeQueryResult = 0x0101;
    private const int FrameKnowledgeQueryStreamData = 0x0102;
    private const int FrameKnowledgeQueryStreamEnd = 0x0103;
    private const int FrameKnowledgeSubscribeReq = 0x0104;
    private const int FrameKnowledgeSubscribeAck = 0x0105;
    private const int FrameKnowledgeUpdate = 0x0106;
    private const int FrameKnowledgeCredit = 0x0107;
    private const int FrameKnowledgeUnsubscribe = 0x0108;
    private const int FrameKnowledgeError = 0x0109;

    private static readonly Dictionary<int, Field[]> KnowledgeSchemas = new()
    {
        [FrameKnowledgeQueryReq] = new[] {
            F(2, Kind.Text, false), F(3, Kind.Text, false), F(4, Kind.Text, false), F(5, Kind.Text, false),
            F(6, Kind.Uint, false), F(8, Kind.Text, false), F(9, Kind.Bytes, false) },
        [FrameKnowledgeQueryResult] = new[] {
            F(2, Kind.Array, true), F(3, Kind.Bool, true), F(4, Kind.Bytes, false), F(5, Kind.Uint, false), F(6, Kind.Bool, false) },
        [FrameKnowledgeQueryStreamData] = new[] { F(2, Kind.Array, true) },
        [FrameKnowledgeQueryStreamEnd] = new[] { F(2, Kind.Array, false), F(3, Kind.Bool, true) },
        [FrameKnowledgeSubscribeReq] = new[] {
            F(2, Kind.Text, false), F(3, Kind.Text, false), F(4, Kind.Text, false), F(5, Kind.Text, false),
            F(7, Kind.Text, false), F(8, Kind.Bool, false), F(9, Kind.Uint, true) },
        [FrameKnowledgeSubscribeAck] = new[] { F(2, Kind.Bytes, true), F(3, Kind.Uint, true), F(4, Kind.Bool, false) },
        [FrameKnowledgeUpdate] = new[] { F(2, Kind.Bytes, true), F(3, Kind.Uint, true), F(4, Kind.Array, false), F(5, Kind.Array, false) },
        [FrameKnowledgeCredit] = new[] { F(2, Kind.Bytes, true), F(3, Kind.Uint, true), F(4, Kind.Uint, false) },
        [FrameKnowledgeUnsubscribe] = new[] { F(2, Kind.Bytes, true) },
        [FrameKnowledgeError] = new[] { F(2, Kind.Uint, true), F(3, Kind.Text, true), F(4, Kind.Uint, false), F(5, Kind.Bytes, false) },
    };

    public static CborMap ValidateKnowledgePayload(int ft, byte[] payload)
    {
        const string p = "npamp/knowledge: malformed_request";
        if (!KnowledgeSchemas.TryGetValue(ft, out Field[]? schema))
        {
            throw Bad(p, $"{ft} is not a Knowledge operation frame type");
        }
        CborMap m = DecodeMap(payload, p);
        CheckFrameKind(m, ft, p);
        CheckCorr(m, p);
        CheckFields(m, schema, p);
        // §6.5: a KNOWLEDGE_UPDATE MUST carry at least one of results (4) or removed (5).
        if (ft == FrameKnowledgeUpdate && !m.Has(4) && !m.Has(5))
        {
            throw Bad(p, "KNOWLEDGE_UPDATE carries neither results (4) nor removed (5) (§6.5)");
        }
        return m;
    }
}
