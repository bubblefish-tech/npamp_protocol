// Corpus-grading conformance test for the N-PAMP native-channel deterministic-CBOR
// body decoders (draft-bubblefish-npamp-01). It grades the C# validators in
// NpampBodies.cs against the SHARED conformance corpus
// (test-vectors/v1/conformance-corpus.json) -- the same independent grader the Go
// reference is graded against. For each op-group it decodes every vector:
//   - a "valid"/"acceptable" vector MUST decode without error, and its decoded
//     frame_kind (and corr, where the vector pins one) MUST match `expected`;
//   - an "invalid" (MUST-reject) vector MUST throw a decode error (BodyException or
//     CborException). Any OTHER thrown type on an invalid vector is itself a failure.
// The corpus is not modified and no vector is special-cased.
//
// Self-contained: builds with NpampCbor.cs + NpampBodies.cs + this file only. JSON
// via System.Text.Json. Exits 0 iff every vector in every graded op-group graded as
// the corpus demands.
using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Text.Json;

namespace Sh.Bubblefish.Npamp;

public static class BodyCorpusTest
{
    private delegate CborMap Validator(int ft, byte[] body);

    // The ten native-channel validators keyed by the corpus `op` string. The eight
    // that are the deliverable of this task are coverage-guarded (TargetChannels);
    // memory/stream are graded too as codec cross-checks.
    private static readonly (string Op, Validator Validate)[] Validators =
    {
        ("memory.body.decode", NpampBodies.ValidateMemoryPayload),
        ("stream.body.decode", NpampBodies.ValidateStreamPayload),
        ("capability.body.decode", NpampBodies.ValidateCapabilityPayload),
        ("immune.body.decode", NpampBodies.ValidateImmunePayload),
        ("settlement.body.decode", NpampBodies.ValidateSettlementPayload),
        ("telemetry.body.decode", NpampBodies.ValidateTelemetryPayload),
        ("commerce.body.decode", NpampBodies.ValidateCommercePayload),
        ("interaction.body.decode", NpampBodies.ValidateInteractionPayload),
        ("workflow.body.decode", NpampBodies.ValidateWorkflowPayload),
        ("knowledge.body.decode", NpampBodies.ValidateKnowledgePayload),
    };

    private static readonly string[] TargetChannels =
    {
        "capability.body.decode", "immune.body.decode", "settlement.body.decode",
        "telemetry.body.decode", "commerce.body.decode", "interaction.body.decode",
        "workflow.body.decode", "knowledge.body.decode",
    };

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

    // Grades one vector; returns null on pass or a human-readable failure reason.
    private static string? GradeVector(string op, Validator validate, JsonElement v)
    {
        JsonElement input = v.GetProperty("in");
        int ft = input.GetProperty("frameType").GetInt32();
        string hex = input.GetProperty("body").GetString()!;
        byte[] body = hex.Length == 0 ? Array.Empty<byte>() : Convert.FromHexString(hex);
        string result = v.GetProperty("result").GetString()!;
        string label = $"{op} tcId={v.GetProperty("tcId").GetInt32()}";

        if (result == "invalid")
        {
            // MUST-reject: the decoder MUST throw a decode error.
            try
            {
                validate(ft, body);
                return $"MUST-reject vector decoded OK (no error thrown): {label}";
            }
            catch (BodyException)
            {
                return null;
            }
            catch (CborException)
            {
                return null;
            }
            catch (Exception e)
            {
                return $"MUST-reject vector threw the WRONG type ({e.GetType().Name}) " +
                    $"-- reject-by-crash is not honest rejection: {label}";
            }
        }

        CborMap m;
        try
        {
            m = validate(ft, body);
        }
        catch (Exception e)
        {
            return $"valid vector threw: {label} -> {e.Message}";
        }

        if (v.TryGetProperty("expected", out JsonElement exp))
        {
            if (exp.TryGetProperty("frame_kind", out JsonElement fkExp))
            {
                object? fk = m.Get(0);
                int got = fk is BigInteger bi ? (int)bi : -1;
                if (got != fkExp.GetInt32())
                {
                    return $"frame_kind mismatch: {label}";
                }
            }
            if (exp.TryGetProperty("corr", out JsonElement corrExp))
            {
                if (m.Get(1) is not byte[] corr)
                {
                    return $"corr not a byte string: {label}";
                }
                if (Convert.ToHexString(corr).ToLowerInvariant() != corrExp.GetString())
                {
                    return $"corr mismatch: {label}";
                }
            }
        }
        return null;
    }

    public static int Main(string[] args)
    {
        string corpusPath = Path.Combine(VectorDir(args), "conformance-corpus.json");
        byte[] raw = File.ReadAllBytes(corpusPath);
        using JsonDocument doc = JsonDocument.Parse(raw);
        JsonElement root = doc.RootElement;

        var groups = new Dictionary<string, JsonElement>();
        foreach (JsonElement g in root.GetProperty("testGroups").EnumerateArray())
        {
            groups[g.GetProperty("op").GetString()!] = g;
        }

        foreach (var (op, validate) in Validators)
        {
            if (!groups.TryGetValue(op, out JsonElement g))
            {
                Check(op, false);
                Console.WriteLine($"       op-group {op} not found in corpus");
                continue;
            }
            int valid = 0;
            int reject = 0;
            string? firstFail = null;
            foreach (JsonElement vec in g.GetProperty("tests").EnumerateArray())
            {
                string? reason = GradeVector(op, validate, vec);
                if (reason != null && firstFail == null)
                {
                    firstFail = reason;
                }
                if (vec.GetProperty("result").GetString() == "invalid")
                {
                    reject++;
                }
                else
                {
                    valid++;
                }
            }
            Check($"{op} [valid/acceptable={valid} reject={reject} total={valid + reject}]", firstFail == null);
            if (firstFail != null)
            {
                Console.WriteLine($"       {firstFail}");
            }
        }

        // Coverage guard: every one of the eight target channels MUST carry at least
        // one valid AND at least one reject vector.
        bool coverageOk = true;
        foreach (string op in TargetChannels)
        {
            if (!groups.TryGetValue(op, out JsonElement g))
            {
                coverageOk = false;
                break;
            }
            int valid = 0;
            int reject = 0;
            foreach (JsonElement vec in g.GetProperty("tests").EnumerateArray())
            {
                if (vec.GetProperty("result").GetString() == "invalid")
                {
                    reject++;
                }
                else
                {
                    valid++;
                }
            }
            if (valid == 0 || reject == 0)
            {
                coverageOk = false;
                break;
            }
        }
        Check("target-channel coverage (8 channels, each with valid + reject vectors)", coverageOk);

        if (_failures > 0)
        {
            Console.WriteLine($"{_failures} check(s) FAILED");
            return 1;
        }
        Console.WriteLine("all body-corpus checks passed");
        return 0;
    }
}
