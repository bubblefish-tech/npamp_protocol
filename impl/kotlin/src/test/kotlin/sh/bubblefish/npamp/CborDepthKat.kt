// Spec-derived (non-circular) conformance check for the N-PAMP deterministic-CBOR
// decoder's resource-exhaustion nesting-depth guard (NpampCbor.kt, mirroring the Go
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
package sh.bubblefish.npamp

import kotlin.system.exitProcess

object CborDepthKat {

    @JvmStatic
    fun main(args: Array<String>) {
        var failures = 0

        val reject = byteArrayOf(
            0x81.toByte(), 0x81.toByte(), 0x81.toByte(), 0x81.toByte(),
            0x81.toByte(), 0x81.toByte(), 0x81.toByte(), 0x81.toByte(), 0x00,
        )
        try {
            NpampCbor.decodeTop(reject)
            println("FAIL depth-9 vector: expected depth-exceeded, decode succeeded")
            failures++
        } catch (e: CborException) {
            if (e.message?.contains("nesting depth exceeds limit") == true) {
                println("ok   - depth-9 vector rejected with depth-exceeded error")
            } else {
                println("FAIL depth-9 vector: wrong error: ${e.message}")
                failures++
            }
        }

        val accept = byteArrayOf(
            0x81.toByte(), 0x81.toByte(), 0x81.toByte(), 0x81.toByte(),
            0x81.toByte(), 0x81.toByte(), 0x81.toByte(), 0x00,
        )
        try {
            NpampCbor.decodeTop(accept)
            println("ok   - depth-8 vector decodes cleanly")
        } catch (e: CborException) {
            println("FAIL depth-8 vector: expected success, got: ${e.message}")
            failures++
        }

        val passed = if (failures == 0) 2 else 2 - failures
        println("CBOR nesting-depth guard KAT (kotlin): $passed/2 passed")
        if (failures != 0) {
            exitProcess(1)
        }
    }
}
