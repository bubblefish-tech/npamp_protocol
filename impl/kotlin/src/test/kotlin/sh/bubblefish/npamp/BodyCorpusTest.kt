// Corpus-grading conformance test for the N-PAMP native-channel deterministic-CBOR
// body decoders (draft-bubblefish-npamp-01). It grades the Kotlin validators in
// NpampBodies.kt against the SHARED conformance corpus
// (test-vectors/v1/conformance-corpus.json) -- the same independent grader the Go
// reference is graded against. For each op-group it decodes every vector:
//   - a "valid"/"acceptable" vector MUST decode without error, and its decoded
//     frame_kind (and corr, where the vector pins one) MUST match `expected`;
//   - an "invalid" (MUST-reject) vector MUST throw a decode error (BodyException or
//     CborException). Any OTHER thrown type on an invalid vector is itself a failure.
// The corpus is not modified and no vector is special-cased.
//
// Reuses the in-repo dependency-free JSON parser (KatSupport.Json). Run via the JVM
// with the Npamp/NpampCbor/NpampBodies main sources + KatSupport + this file on the
// classpath, invoking sh.bubblefish.npamp.BodyCorpusTest.main. Exits 0 iff every
// vector in every graded op-group graded as the corpus demands.
package sh.bubblefish.npamp

import java.math.BigInteger
import java.nio.file.Files

object BodyCorpusTest {

    private fun interface Validator {
        fun validate(ft: Int, body: ByteArray): NpampCbor.CborMap
    }

    // The ten native-channel validators keyed by the corpus `op` string. The eight
    // that are the deliverable of this task are coverage-guarded (TARGET_CHANNELS);
    // memory/stream are graded too as codec cross-checks.
    private val VALIDATORS: Map<String, Validator> = linkedMapOf(
        "memory.body.decode" to Validator(NpampBodies::validateMemoryPayload),
        "stream.body.decode" to Validator(NpampBodies::validateStreamPayload),
        "capability.body.decode" to Validator(NpampBodies::validateCapabilityPayload),
        "immune.body.decode" to Validator(NpampBodies::validateImmunePayload),
        "settlement.body.decode" to Validator(NpampBodies::validateSettlementPayload),
        "telemetry.body.decode" to Validator(NpampBodies::validateTelemetryPayload),
        "commerce.body.decode" to Validator(NpampBodies::validateCommercePayload),
        "interaction.body.decode" to Validator(NpampBodies::validateInteractionPayload),
        "workflow.body.decode" to Validator(NpampBodies::validateWorkflowPayload),
        "knowledge.body.decode" to Validator(NpampBodies::validateKnowledgePayload)
    )

    private val TARGET_CHANNELS = listOf(
        "capability.body.decode", "immune.body.decode", "settlement.body.decode",
        "telemetry.body.decode", "commerce.body.decode", "interaction.body.decode",
        "workflow.body.decode", "knowledge.body.decode"
    )

    private var failures = 0

    private fun check(name: String, ok: Boolean) {
        if (ok) println("ok   - $name") else { println("FAIL - $name"); failures++ }
    }

    private fun asInt(v: Any?): Int = when (v) {
        is Long -> v.toInt()
        is Double -> Math.round(v).toInt()
        is Int -> v
        else -> throw IllegalStateException("not a number: $v")
    }

    @Suppress("UNCHECKED_CAST")
    private fun gradeVector(op: String, validate: Validator, v: Map<String, Any?>): String? {
        val input = v["in"] as Map<String, Any?>
        val ft = asInt(input["frameType"])
        val body = KatSupport.fromHex(input["body"] as String)
        val result = v["result"] as String
        val label = "$op tcId=${asInt(v["tcId"])}"

        if (result == "invalid") {
            return try {
                validate.validate(ft, body)
                "MUST-reject vector decoded OK (no error thrown): $label"
            } catch (e: BodyException) {
                null
            } catch (e: CborException) {
                null
            } catch (e: RuntimeException) {
                "MUST-reject vector threw the WRONG type (${e.javaClass.simpleName}) " +
                    "-- reject-by-crash is not honest rejection: $label"
            }
        }

        val m = try {
            validate.validate(ft, body)
        } catch (e: RuntimeException) {
            return "valid vector threw: $label -> ${e.message}"
        }

        val exp = (v["expected"] as? Map<String, Any?>) ?: emptyMap()
        if (exp["frame_kind"] != null) {
            val fk = m.get(0)
            val got = if (fk is BigInteger) fk.toInt() else -1
            if (got != asInt(exp["frame_kind"])) return "frame_kind mismatch: $label"
        }
        if (exp["corr"] != null) {
            val corr = m.get(1)
            if (corr !is ByteArray) return "corr not a byte string: $label"
            if (KatSupport.toHex(corr) != exp["corr"] as String) return "corr mismatch: $label"
        }
        return null
    }

    @Suppress("UNCHECKED_CAST")
    @JvmStatic
    fun main(args: Array<String>) {
        val corpusPath = KatSupport.vectorsDir(args).resolve("conformance-corpus.json")
        val root = Json.parse(String(Files.readAllBytes(corpusPath), Charsets.UTF_8)) as Map<String, Any?>
        val testGroups = root["testGroups"] as List<Any?>

        val groups = LinkedHashMap<String, Map<String, Any?>>()
        for (g in testGroups) {
            val gm = g as Map<String, Any?>
            groups[gm["op"] as String] = gm
        }

        for ((op, validate) in VALIDATORS) {
            val g = groups[op]
            if (g == null) {
                check(op, false)
                println("       op-group $op not found in corpus")
                continue
            }
            val tests = g["tests"] as List<Any?>
            var valid = 0
            var reject = 0
            var firstFail: String? = null
            for (t in tests) {
                val vec = t as Map<String, Any?>
                val reason = gradeVector(op, validate, vec)
                if (reason != null && firstFail == null) firstFail = reason
                if (vec["result"] == "invalid") reject++ else valid++
            }
            check("$op [valid/acceptable=$valid reject=$reject total=${tests.size}]", firstFail == null)
            if (firstFail != null) println("       $firstFail")
        }

        var coverageOk = true
        for (op in TARGET_CHANNELS) {
            val g = groups[op]
            if (g == null) { coverageOk = false; break }
            val tests = g["tests"] as List<Any?>
            val valid = tests.count { (it as Map<String, Any?>)["result"] != "invalid" }
            val reject = tests.count { (it as Map<String, Any?>)["result"] == "invalid" }
            if (valid == 0 || reject == 0) { coverageOk = false; break }
        }
        check("target-channel coverage (8 channels, each with valid + reject vectors)", coverageOk)

        if (failures > 0) {
            println("$failures check(s) FAILED")
            kotlin.system.exitProcess(1)
        }
        println("all body-corpus checks passed")
    }
}
