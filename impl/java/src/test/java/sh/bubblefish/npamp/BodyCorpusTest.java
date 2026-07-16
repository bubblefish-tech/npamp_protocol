// Corpus-grading conformance test for the N-PAMP native-channel deterministic-CBOR
// body decoders (draft-bubblefish-npamp-01). It grades the Java validators in
// NpampBodies.java against the SHARED conformance corpus
// (test-vectors/v1/conformance-corpus.json) -- the same independent grader the Go
// reference is graded against. For each op-group it decodes every vector:
//   - a "valid"/"acceptable" vector MUST decode without error, and its decoded
//     frame_kind (and corr, where the vector pins one) MUST match `expected`;
//   - an "invalid" (MUST-reject) vector MUST throw a decode error (BodyException or
//     CborException). Any OTHER thrown type on an invalid vector is itself a
//     failure -- a decoder that reject-by-crash is not honestly rejecting.
// The corpus is not modified and no vector is special-cased: the validators are the
// only thing under test.
//
// Dependency-free (stdlib + the in-repo Kat JSON parser); run with:
//   javac -d <out> src/main/java/sh/bubblefish/npamp/*.java \
//         src/test/java/sh/bubblefish/npamp/Kat.java \
//         src/test/java/sh/bubblefish/npamp/BodyCorpusTest.java
//   java -cp <out> sh.bubblefish.npamp.BodyCorpusTest
// Exits 0 iff every vector in every graded op-group graded as the corpus demands.
package sh.bubblefish.npamp;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class BodyCorpusTest {

    private BodyCorpusTest() {
    }

    /** A native-channel body validator: decode + MUST-reject, throwing on any fault. */
    private interface Validator {
        NpampCbor.CborMap validate(int ft, byte[] body);
    }

    // The ten native-channel validators keyed by the corpus `op` string. The eight
    // that are the deliverable of this task are graded strictly (see TARGET_CHANNELS);
    // memory/stream are graded too as codec cross-checks.
    private static final Map<String, Validator> VALIDATORS = new LinkedHashMap<>();
    static {
        VALIDATORS.put("memory.body.decode", NpampBodies::validateMemoryPayload);
        VALIDATORS.put("stream.body.decode", NpampBodies::validateStreamPayload);
        VALIDATORS.put("capability.body.decode", NpampBodies::validateCapabilityPayload);
        VALIDATORS.put("immune.body.decode", NpampBodies::validateImmunePayload);
        VALIDATORS.put("settlement.body.decode", NpampBodies::validateSettlementPayload);
        VALIDATORS.put("telemetry.body.decode", NpampBodies::validateTelemetryPayload);
        VALIDATORS.put("commerce.body.decode", NpampBodies::validateCommercePayload);
        VALIDATORS.put("interaction.body.decode", NpampBodies::validateInteractionPayload);
        VALIDATORS.put("workflow.body.decode", NpampBodies::validateWorkflowPayload);
        VALIDATORS.put("knowledge.body.decode", NpampBodies::validateKnowledgePayload);
    }

    // The eight channels that are the deliverable of this task (coverage-guarded).
    private static final String[] TARGET_CHANNELS = {
            "capability.body.decode", "immune.body.decode", "settlement.body.decode",
            "telemetry.body.decode", "commerce.body.decode", "interaction.body.decode",
            "workflow.body.decode", "knowledge.body.decode",
    };

    private static int failures;

    private static void check(String name, boolean ok) {
        if (ok) {
            System.out.println("ok   - " + name);
        } else {
            System.out.println("FAIL - " + name);
            failures++;
        }
    }

    private static int asInt(Object v) {
        return (int) Math.round((Double) v);
    }

    /** Grades one vector; returns null on pass or a human-readable failure reason. */
    private static String gradeVector(String op, Validator validate, Map<String, Object> v) {
        Map<String, Object> in = Kat.obj(v.get("in"));
        int ft = asInt(in.get("frameType"));
        byte[] body = Kat.fromHex(Kat.str(in.get("body")));
        String result = Kat.str(v.get("result"));
        String label = op + " tcId=" + asInt(v.get("tcId"));

        if ("invalid".equals(result)) {
            // MUST-reject: the decoder MUST throw a decode error. A decoder that
            // ignores its input would decode OK here -- this is the real gate.
            try {
                validate.validate(ft, body);
                return "MUST-reject vector decoded OK (no error thrown): " + label;
            } catch (NpampBodies.BodyException | NpampCbor.CborException e) {
                return null; // honest reject
            } catch (RuntimeException e) {
                return "MUST-reject vector threw the WRONG type (" + e.getClass().getSimpleName()
                        + ") -- reject-by-crash is not honest rejection: " + label;
            }
        }

        // valid / acceptable: MUST decode without error.
        NpampCbor.CborMap m;
        try {
            m = validate.validate(ft, body);
        } catch (RuntimeException e) {
            return "valid vector threw: " + label + " -> " + e.getMessage();
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> exp = v.get("expected") == null
                ? new LinkedHashMap<>()
                : (Map<String, Object>) v.get("expected");
        if (exp.get("frame_kind") != null) {
            Object fk = m.get(0);
            int got = (fk instanceof java.math.BigInteger) ? ((java.math.BigInteger) fk).intValueExact() : -1;
            if (got != asInt(exp.get("frame_kind"))) {
                return "frame_kind mismatch: " + label;
            }
        }
        if (exp.get("corr") != null) {
            Object corr = m.get(1);
            if (!(corr instanceof byte[])) {
                return "corr not a byte string: " + label;
            }
            if (!Kat.toHex((byte[]) corr).equals(Kat.str(exp.get("corr")))) {
                return "corr mismatch: " + label;
            }
        }
        return null;
    }

    public static void main(String[] args) throws Exception {
        Path corpusPath = Kat.vectorDir(args).resolve("conformance-corpus.json");
        byte[] raw = Files.readAllBytes(corpusPath);
        Object root = Kat.parse(new String(raw, StandardCharsets.UTF_8));
        List<Object> testGroups = Kat.arr(Kat.at(root, "testGroups"));

        Map<String, Map<String, Object>> groups = new LinkedHashMap<>();
        for (Object g : testGroups) {
            Map<String, Object> gm = Kat.obj(g);
            groups.put(Kat.str(gm.get("op")), gm);
        }

        // Grade each op-group: every vector in the group must pass.
        for (Map.Entry<String, Validator> e : VALIDATORS.entrySet()) {
            String op = e.getKey();
            Map<String, Object> g = groups.get(op);
            if (g == null) {
                check(op, false);
                System.out.println("       op-group " + op + " not found in corpus");
                continue;
            }
            List<Object> tests = Kat.arr(g.get("tests"));
            int valid = 0;
            int reject = 0;
            String firstFail = null;
            for (Object t : tests) {
                Map<String, Object> vec = Kat.obj(t);
                String reason = gradeVector(op, e.getValue(), vec);
                if (reason != null && firstFail == null) {
                    firstFail = reason;
                }
                if ("invalid".equals(Kat.str(vec.get("result")))) {
                    reject++;
                } else {
                    valid++;
                }
            }
            check(op + " [valid/acceptable=" + valid + " reject=" + reject + " total=" + tests.size() + "]",
                    firstFail == null);
            if (firstFail != null) {
                System.out.println("       " + firstFail);
            }
        }

        // Coverage guard: every one of the eight target channels MUST be present and
        // carry at least one valid AND at least one reject vector, so a green run
        // cannot come from an empty or one-sided group.
        boolean coverageOk = true;
        for (String op : TARGET_CHANNELS) {
            Map<String, Object> g = groups.get(op);
            if (g == null) {
                coverageOk = false;
                break;
            }
            int valid = 0;
            int reject = 0;
            for (Object t : Kat.arr(g.get("tests"))) {
                if ("invalid".equals(Kat.str(Kat.obj(t).get("result")))) {
                    reject++;
                } else {
                    valid++;
                }
            }
            if (valid == 0 || reject == 0) {
                coverageOk = false;
                break;
            }
        }
        check("target-channel coverage (8 channels, each with valid + reject vectors)", coverageOk);

        if (failures > 0) {
            System.out.println(failures + " check(s) FAILED");
            System.exit(1);
        }
        System.out.println("all body-corpus checks passed");
    }
}
