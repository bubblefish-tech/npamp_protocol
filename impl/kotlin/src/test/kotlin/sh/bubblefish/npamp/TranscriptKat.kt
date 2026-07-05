// Standards-derived, NON-CIRCULAR known-answer test for the draft-00 transcript
// construction (binding spec/10 §3). Kotlin mirror of the Go/TS/Python reference
// tests against the SAME pinned, FIPS-180-4-anchored vector (test-vectors/v1/transcript-kat.json).
//
// Three legs: ANCHOR (SHA-256("abc") == FIPS 180-4), ORACLE (in-test manual per-TLV
// byte-constructor, no Transcript), IMPL (the real Handshake.Transcript). Absorption
// is driven straight from the vector's frame/TLV order; the cut points are encoded as
// a (frame index, TLV index) map -> transcript-hash name, which IS the spec §3 structure.
package sh.bubblefish.npamp

import java.security.MessageDigest
import kotlin.system.exitProcess

object TranscriptKat {

    private const val PIN = "fab6d852497b6ff56405595e9a014d0c45cabc5cde80a60a17444b337d556ee5"

    // (frame index, TLV index within that frame) -> transcript-hash point name.
    private val CUT_POINTS: Map<Pair<Int, Int>, String> = mapOf(
        Pair(1, 4) to "th_kem",
        Pair(2, 0) to "th_sid",
        Pair(2, 1) to "th_scv",
        Pair(3, 0) to "th_cid",
        Pair(3, 1) to "th_ccv",
    )
    private val POINT_ORDER = listOf("th_kem", "th_sid", "th_scv", "th_cid", "th_ccv")

    private var failures = 0

    private fun leg(name: String, fn: () -> Unit) {
        try {
            fn()
            println("PASS $name")
        } catch (e: Throwable) {
            println("FAIL $name: ${e.message}")
            failures++
        }
    }

    /** Walk the vector frames/TLVs in order; snapshot at each spec §3 cut point. */
    private fun drive(
        frames: List<Any?>,
        addFrameType: (Int) -> Unit,
        addTlv: (Int, ByteArray) -> Unit,
        snap: () -> String,
    ): Map<String, String> {
        val points = LinkedHashMap<String, String>()
        for ((fi, f) in frames.withIndex()) {
            addFrameType(KatSupport.parseHexInt(KatSupport.str(f, "frame_type")))
            for ((ti, tl) in KatSupport.arr(f, "tlvs").withIndex()) {
                addTlv(KatSupport.parseHexInt(KatSupport.str(tl, "type")), KatSupport.fromHex(KatSupport.str(tl, "value")))
                CUT_POINTS[Pair(fi, ti)]?.let { points[it] = snap() }
            }
        }
        return points
    }

    private fun checkPoints(leg: String, k: Map<String, Any?>, points: Map<String, String>) {
        val exp = KatSupport.obj(k, "expected_transcript_points")
        check(points.keys.toSet() == POINT_ORDER.toSet()) { "[$leg] missing/extra cut points: ${points.keys.sorted()}" }
        for (name in POINT_ORDER) {
            val got = points[name]
            val want = exp[name] as String
            check(got == want) { "[$leg] $name mismatch\n  got  $got\n  want $want" }
        }
    }

    @JvmStatic
    fun main(args: Array<String>) {
        val k = KatSupport.loadPinned(args, "transcript-kat.json", PIN)

        leg("transcript_kat_fips180_anchor") {
            val fips = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            val fipsNode = KatSupport.obj(k, "fips180_4_sha256_abc")
            val input = fipsNode["input_ascii"] as String
            val got = KatSupport.toHex(MessageDigest.getInstance("SHA-256").digest(input.toByteArray(Charsets.US_ASCII)))
            check(got == fips) { "SHA-256(\"$input\") != FIPS 180-4\n  got  $got\n  want $fips" }
            check(fipsNode["digest"] == fips) { "vector anchor digest != FIPS 180-4" }
        }

        leg("transcript_kat_oracle") {
            val frames = KatSupport.arr(k, "frames")
            val buf = java.io.ByteArrayOutputStream()
            val points = drive(
                frames,
                { ft -> buf.write((ft ushr 8) and 0xFF); buf.write(ft and 0xFF) },
                { t, v ->
                    buf.write((t ushr 8) and 0xFF); buf.write(t and 0xFF)
                    buf.write((v.size ushr 8) and 0xFF); buf.write(v.size and 0xFF)
                    buf.write(v, 0, v.size)
                },
                { KatSupport.toHex(MessageDigest.getInstance("SHA-256").digest(buf.toByteArray())) },
            )
            checkPoints("oracle", k, points)
        }

        leg("transcript_kat_impl") {
            check(
                Handshake.FRAME_CLIENT_HELLO == 0x0100 && Handshake.FRAME_SERVER_HELLO == 0x0101 &&
                    Handshake.FRAME_SERVER_AUTH == 0x0102 && Handshake.FRAME_CLIENT_AUTH == 0x0103,
            ) { "frame-type constants drifted from spec §1 code points" }
            val frames = KatSupport.arr(k, "frames")
            val tr = Handshake.Transcript()
            val points = drive(
                frames,
                { ft -> tr.addFrameType(ft) },
                { t, v -> tr.addTlv(t, v) },
                { KatSupport.toHex(tr.hash(true)) },
            )
            checkPoints("impl", k, points)
        }

        println(if (failures == 0) "ALL PASS (3/3)" else "FAILURES: $failures")
        exitProcess(if (failures == 0) 0 else 1)
    }
}
