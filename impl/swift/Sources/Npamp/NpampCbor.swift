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
// Decoded value model (a Swift enum mirroring the Go uint64/int64/[]byte/string/
// []any/*cborMap/bool/nil): a major-0 integer is `.uint`, a major-1 negative integer
// is `.nint` (holding the RFC argument `arg`, i.e. the value -1 - arg), byte strings
// are `.bytes`, text strings `.text`, arrays `.array`, maps `.map`, and the three
// simple values `.bool` / `.null`.
import Foundation

/// A structural fault in the deterministic-CBOR encoding (a MUST-reject).
public struct CBORError: Error {
    public let message: String
    public init(_ message: String) { self.message = message }
}

/// One decoded N-PAMP CBOR value.
public indirect enum CBOR {
    case uint(UInt64)
    case nint(UInt64) // negative int: value == -1 - arg
    case bytes([UInt8])
    case text(String)
    case array([CBOR])
    case map(CBORMap)
    case bool(Bool)
    case null
}

/// A CBOR map preserving canonical key order. Entries are kept in the order they
/// were decoded, which the decoder has already verified is canonical ascending.
public struct CBORMap {
    struct Entry {
        let keyEnc: [UInt8]
        let key: CBOR
        let value: CBOR
    }

    let entries: [Entry]

    /// Returns the value for an unsigned-integer key, or nil if absent.
    public func get(_ key: UInt64) -> CBOR? {
        for e in entries {
            if case let .uint(k) = e.key, k == key { return e.value }
        }
        return nil
    }

    /// Reports whether an unsigned-integer key is present.
    public func has(_ key: UInt64) -> Bool {
        for e in entries {
            if case let .uint(k) = e.key, k == key { return true }
        }
        return false
    }

    /// Returns every key in canonical order (used for forward-compat checks).
    public func keys() -> [CBOR] { entries.map { $0.key } }
}

/// Deterministic (canonical) CBOR decoder for the N-PAMP native operation bodies.
public enum NpampCbor {

    /// Decodes a single canonical CBOR item and requires that it consumes all of
    /// `b` (no trailing bytes) -- the shape of a frame payload.
    public static func decodeTop(_ b: [UInt8]) throws -> CBOR {
        var pos = 0
        let v = try decode(b, &pos)
        if pos != b.count {
            throw CBORError("npamp/cbor: trailing bytes after top-level item")
        }
        return v
    }

    // byteLess reports whether a sorts strictly before b in bytewise (shorter-prefix-
    // first, then lexicographic) order -- RFC 8949 §4.2.1 canonical map-key ordering.
    static func byteLess(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        if a.count != b.count { return a.count < b.count }
        for i in 0..<a.count where a[i] != b[i] { return a[i] < b[i] }
        return false
    }

    private static func decode(_ b: [UInt8], _ pos: inout Int) throws -> CBOR {
        if pos >= b.count { throw CBORError("npamp/cbor: truncated input") }
        let ib = Int(b[pos])
        let major = ib >> 5
        let ai = ib & 0x1f

        if major == 7 {
            // Only false(20)/true(21)/null(22) are in the deterministic subset; floats
            // (25/26/27), other simple values, and the break stop (31) reject.
            switch ai {
            case 20: pos += 1; return .bool(false)
            case 21: pos += 1; return .bool(true)
            case 22: pos += 1; return .null
            default: throw CBORError("npamp/cbor: unsupported major type or simple value")
            }
        }

        let arg = try decodeArg(ai, b, &pos) // advances pos past the header
        let n = pos // absolute offset just past the header

        switch major {
        case 0: // unsigned int
            return .uint(arg)
        case 1: // negative int: value = -1 - arg
            return .nint(arg)
        case 2, 3:
            // byte string / text string
            let remaining = UInt64(b.count - n)
            if arg > remaining { throw CBORError("npamp/cbor: truncated input") }
            let len = Int(arg)
            let payload = Array(b[n..<(n + len)])
            pos = n + len
            if major == 2 { return .bytes(payload) }
            guard let s = String(bytes: payload, encoding: .utf8) else {
                throw CBORError("npamp/cbor: text string is not valid UTF-8")
            }
            return .text(s)
        case 4:
            // array. Each element is >= 1 byte, so a declared count larger than the
            // remaining input cannot be satisfied (huge-count DoS guard).
            let remaining = UInt64(b.count - n)
            if arg > remaining { throw CBORError("npamp/cbor: truncated input") }
            let count = Int(arg)
            var out: [CBOR] = []
            out.reserveCapacity(count)
            for _ in 0..<count { out.append(try decode(b, &pos)) }
            return .array(out)
        case 5:
            // map. Each entry is >= 2 bytes, so a declared count larger than the
            // remaining input cannot be satisfied.
            let remaining = UInt64(b.count - n)
            if arg > remaining { throw CBORError("npamp/cbor: truncated input") }
            let count = Int(arg)
            var entries: [CBORMap.Entry] = []
            entries.reserveCapacity(count)
            var prevKeyEnc: [UInt8]? = nil
            for _ in 0..<count {
                let keyStart = pos
                let key = try decode(b, &pos)
                let keyEnc = Array(b[keyStart..<pos])
                // Canonical order: each key MUST sort strictly after the previous one.
                if let prev = prevKeyEnc, !byteLess(prev, keyEnc) {
                    throw CBORError("npamp/cbor: map keys not in canonical ascending order (or duplicate)")
                }
                prevKeyEnc = keyEnc
                let value = try decode(b, &pos)
                entries.append(CBORMap.Entry(keyEnc: keyEnc, key: key, value: value))
            }
            return .map(CBORMap(entries: entries))
        default: // major 6 (tags): unsupported
            throw CBORError("npamp/cbor: unsupported major type or simple value")
        }
    }

    // decodeArg reads the argument for an additional-information value ai, enforcing
    // shortest-form (RFC 8949 §4.2.1) and rejecting indefinite lengths. Advances pos
    // past the whole header and returns the argument.
    private static func decodeArg(_ ai: Int, _ b: [UInt8], _ pos: inout Int) throws -> UInt64 {
        if ai < 24 {
            pos += 1
            return UInt64(ai)
        }
        switch ai {
        case 24:
            if pos + 2 > b.count { throw CBORError("npamp/cbor: truncated input") }
            let v = UInt64(b[pos + 1])
            if v < 24 { throw CBORError("npamp/cbor: integer/length not in shortest form") }
            pos += 2
            return v
        case 25:
            if pos + 3 > b.count { throw CBORError("npamp/cbor: truncated input") }
            let v = (UInt64(b[pos + 1]) << 8) | UInt64(b[pos + 2])
            if v < (1 << 8) { throw CBORError("npamp/cbor: integer/length not in shortest form") }
            pos += 3
            return v
        case 26:
            if pos + 5 > b.count { throw CBORError("npamp/cbor: truncated input") }
            var v: UInt64 = 0
            for i in 1...4 { v = (v << 8) | UInt64(b[pos + i]) }
            if v < (1 << 16) { throw CBORError("npamp/cbor: integer/length not in shortest form") }
            pos += 5
            return v
        case 27:
            if pos + 9 > b.count { throw CBORError("npamp/cbor: truncated input") }
            var v: UInt64 = 0
            for i in 1...8 { v = (v << 8) | UInt64(b[pos + i]) }
            if v < (1 << 32) { throw CBORError("npamp/cbor: integer/length not in shortest form") }
            pos += 9
            return v
        case 31:
            throw CBORError("npamp/cbor: indefinite-length item (non-deterministic)")
        default: // 28,29,30 are reserved
            throw CBORError("npamp/cbor: unsupported major type or simple value")
        }
    }
}
