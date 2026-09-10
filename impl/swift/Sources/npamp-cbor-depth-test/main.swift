// CBOR nesting-depth resource guard test for the Swift N-PAMP body decoder.
//
// Mirrors the Go reference guard (impl/go/memory_cbor.go, cborMaxNestingDepth = 8)
// against the spec-derived, non-circular conformance vectors:
//   - REJECT: eight 0x81 (array-of-one) headers followed by 0x00 (scalar at
//     depth 9) -> CBORDepthExceededError.
//   - ACCEPT: seven 0x81 headers followed by 0x00 (scalar at depth 8) -> decodes.
//
// Run:  swift run npamp-cbor-depth-test
import Foundation
import Npamp

var failures = 0
func check(_ name: String, _ ok: Bool) {
    if ok { print("ok   - \(name)") } else { print("FAIL - \(name)"); failures += 1 }
}

// Eight 0x81 (array, 1 element) headers + a 0x00 scalar: the scalar sits at
// depth 9 (outermost array = depth 1, ..., 8th nested array = depth 8, its
// element = depth 9). MUST be rejected with the depth-exceeded error.
let rejectBytes: [UInt8] = [0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x00]
var rejectedRight = false
do {
    _ = try NpampCbor.decodeTop(rejectBytes)
} catch is CBORDepthExceededError {
    rejectedRight = true
} catch {
    rejectedRight = false
}
check("depth_9_scalar_rejected_with_depth_exceeded", rejectedRight)

// Seven 0x81 headers + a 0x00 scalar: the scalar sits at depth 8 (outermost
// array = depth 1, ..., 7th nested array = depth 7, its element = depth 8).
// MUST be accepted (decodes without error).
let acceptBytes: [UInt8] = [0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x00]
var acceptedOk = false
do {
    var v = try NpampCbor.decodeTop(acceptBytes)
    var depth = 0
    while case let .array(arr) = v, arr.count == 1 {
        v = arr[0]
        depth += 1
    }
    if case .uint(0) = v {
        acceptedOk = (depth == 7)
    }
} catch {
    acceptedOk = false
}
check("depth_8_scalar_accepted", acceptedOk)

print(failures == 0 ? "ALL PASS (2/2)" : "FAILURES: \(failures)")
exit(failures == 0 ? 0 : 1)
