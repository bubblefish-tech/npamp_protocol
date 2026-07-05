// N-PAMP conformance adapter (Swift "testee").
//
// Speaks the length-prefixed JSON contract on stdin/stdout:
//   4-byte little-endian length N  ->  N bytes of JSON   (repeat until stdin closes)
//   Request : {"op": "<operation>", "in": { ... }}
//   Response: {"out": {...}} | {"error": "..."} | {"skipped": "..."}
//
// Every primitive is performed by the OPEN Swift reference implementation
// (the `Npamp` module). This file contains NO reimplementation of CRC32C,
// the frame layout, or AES-256-GCM — it only marshals the contract into
// calls on the reference's public API:
//   - Npamp.crc32c(_:)                 -> crc32c op, and header.encode CRC
//   - Npamp.Frame.headerPrefix(_:)     -> header.encode 21-octet prefix
//   - Npamp.Frame.unmarshal(_:)        -> header.decode validation + fields
//   - Npamp.sealAes256Gcm(...)         -> aead.seal
//   - Npamp.openAes256Gcm(...)         -> aead.open
//
// Operations the reference exposes no public primitive for are reported
// honestly as {"skipped": ...} (Unimplemented, not Fail):
//   - tlv.decode   : the reference module implements no TLV codec.
//   - hkdf.expand  : the reference's raw HKDF-Expand is module-internal; only
//                    the label-structured HKDF-Expand-Label is public, which
//                    cannot reproduce an arbitrary `info`. Skipped rather than
//                    reimplemented or routed through a different library.
//   - profile.check: the reference module implements no profile KEM policy.
//
// Windows/WSL note: stdio is treated as raw bytes (FileHandle, not text), and
// every response is written and the buffer drained before reading the next
// request, so the little-endian byte framing is never corrupted.

import Foundation
import Npamp

// MARK: - Raw byte stdio

let stdinHandle = FileHandle.standardInput
let stdoutHandle = FileHandle.standardOutput

/// Read exactly `n` bytes from stdin, or nil on clean EOF (runner closed stdin).
func readExact(_ n: Int) -> [UInt8]? {
    if n == 0 { return [] }
    var buf = [UInt8]()
    buf.reserveCapacity(n)
    while buf.count < n {
        let chunk = stdinHandle.readData(ofLength: n - buf.count)
        if chunk.isEmpty { return nil } // EOF before the full frame
        buf.append(contentsOf: chunk)
    }
    return buf
}

/// Write a length-prefixed JSON response (4-byte LE length || JSON bytes) and flush.
func writeFramed(_ json: [UInt8]) {
    let n = UInt32(json.count)
    var out = [UInt8]()
    out.reserveCapacity(4 + json.count)
    out.append(UInt8(n & 0xFF))
    out.append(UInt8((n >> 8) & 0xFF))
    out.append(UInt8((n >> 16) & 0xFF))
    out.append(UInt8((n >> 24) & 0xFF))
    out.append(contentsOf: json)
    stdoutHandle.write(Data(out))
    // FileHandle.write is unbuffered at this layer; no userspace buffer to flush,
    // but synchronize to guarantee the bytes reach the pipe before the next read.
    try? stdoutHandle.synchronize()
}

// MARK: - JSON helpers

func encodeResponse(_ obj: [String: Any]) -> [UInt8] {
    // sortedKeys keeps output deterministic; the runner parses by key, not order.
    if let data = try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys]) {
        return [UInt8](data)
    }
    // Fallback: a hand-built error object can always be encoded.
    let fallback = "{\"error\":\"adapter json encode failure\"}"
    return [UInt8](fallback.utf8)
}

func str(_ d: [String: Any], _ k: String) -> String { (d[k] as? String) ?? "" }
func intVal(_ d: [String: Any], _ k: String) -> Int {
    if let n = d[k] as? Int { return n }
    if let n = d[k] as? NSNumber { return n.intValue }
    if let n = d[k] as? Double { return Int(n) }
    return 0
}
func u64Val(_ d: [String: Any], _ k: String) -> UInt64 {
    if let n = d[k] as? NSNumber { return n.uint64Value }
    if let n = d[k] as? Int { return UInt64(n) }
    if let n = d[k] as? Double { return UInt64(n) }
    return 0
}
func hexBytes(_ d: [String: Any], _ k: String) -> [UInt8] {
    Npamp.fromHex(str(d, k)) // reference hex decoder
}

/// 32-bit value to a big-endian lowercase hex string (4 octets).
func u32BeHex(_ v: UInt32) -> String {
    let b: [UInt8] = [
        UInt8((v >> 24) & 0xFF), UInt8((v >> 16) & 0xFF),
        UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF),
    ]
    return Npamp.toHex(b) // reference hex encoder
}

// MARK: - Operation dispatch

func handle(_ req: [String: Any]) -> [String: Any] {
    let op = req["op"] as? String ?? ""
    let input = req["in"] as? [String: Any] ?? [:]

    switch op {

    case "header.encode":
        // Reference 21-octet header prefix, then CRC32C(prefix) || 11 zero octets.
        let ver = intVal(input, "ver")
        let frame = Npamp.Frame(
            ftype: intVal(input, "frameType"),
            channel: intVal(input, "channel"),
            seq: u64Val(input, "seq"),
            flags: intVal(input, "flags"),
            version: ver
        )
        let payloadLength = intVal(input, "payloadLength")
        let prefix = frame.headerPrefix(payloadLength)           // reference
        var header = prefix
        let crc = Npamp.crc32c(prefix)                           // reference
        header.append(UInt8((crc >> 24) & 0xFF))
        header.append(UInt8((crc >> 16) & 0xFF))
        header.append(UInt8((crc >> 8) & 0xFF))
        header.append(UInt8(crc & 0xFF))
        header.append(contentsOf: [UInt8](repeating: 0, count: 11)) // reserved
        return ["out": ["frame": Npamp.toHex(header)]]

    case "header.decode":
        let buf = hexBytes(input, "frame")
        do {
            let f = try Npamp.Frame.unmarshal(buf)              // reference (CRC, magic, reserved, length)
            // crc32c output field = the 4 CRC octets as they appear in the frame.
            let crcHex = buf.count >= 25 ? Npamp.toHex(Array(buf[21..<25])) : ""
            return ["out": [
                "magic": "NPAM",
                "ver": f.version,
                "flags": f.flags,
                "frameType": f.ftype,
                "channel": f.channel,
                "seq": f.seq,
                "payloadLength": buf.count - Npamp.headerSize,
                "crc32c": crcHex,
                "reservedZero": true,
            ]]
        } catch let e as Npamp.FrameError {
            return ["error": e.message]
        } catch {
            return ["error": "decode failed"]
        }

    case "crc32c":
        let octets = hexBytes(input, "octets")
        return ["out": ["crc32c": u32BeHex(Npamp.crc32c(octets))]] // reference

    case "aead.seal":
        if str(input, "suite") != "AES-256-GCM" {
            return ["skipped": "suite not implemented: \(str(input, "suite"))"]
        }
        // seq=0 makes the reference deriveNonce(iv, 0) == iv, so passing the
        // contract `nonce` as the iv yields exactly that nonce. Same path the
        // reference's own Wycheproof KAT driver uses.
        let key = hexBytes(input, "key")
        let nonce = hexBytes(input, "nonce")
        let aad = hexBytes(input, "aad")
        let pt = hexBytes(input, "pt")
        do {
            let sealed = try Npamp.sealAes256Gcm(key, nonce, 0, aad, pt) // reference
            return ["out": ["sealed": Npamp.toHex(sealed)]]
        } catch {
            return ["error": "\(error)"]
        }

    case "aead.open":
        if str(input, "suite") != "AES-256-GCM" {
            return ["skipped": "suite not implemented: \(str(input, "suite"))"]
        }
        let key = hexBytes(input, "key")
        let nonce = hexBytes(input, "nonce")
        let aad = hexBytes(input, "aad")
        let sealed = hexBytes(input, "sealed")
        do {
            let pt = try Npamp.openAes256Gcm(key, nonce, 0, aad, sealed) // reference
            return ["out": ["pt": Npamp.toHex(pt)]]
        } catch {
            return ["error": "authentication failed"]
        }

    case "tlv.decode":
        // The OPEN Swift reference module implements no TLV codec; do not fake it.
        return ["skipped": "no TLV primitive in the Swift reference implementation"]

    case "hkdf.expand":
        // RFC 5869 HKDF-Expand over the raw (unlabelled) `info`. This dispatches into
        // the reference module's own HKDF-Expand — the exact primitive its key schedule
        // builds HKDF-Expand-Label on — exposed publicly as Npamp.hkdfExpand(hash:...).
        // No HKDF is reimplemented here. SHA-256/SHA-384 are the reference's supported
        // hashes; any other hash is reported honestly as unimplemented.
        let hash = str(input, "hash")
        guard hash == "sha256" || hash == "sha384" else {
            return ["skipped": "hash not implemented: \(hash)"]
        }
        let prk = hexBytes(input, "prk")
        let info = hexBytes(input, "info")
        let length = intVal(input, "length")
        let okm = Npamp.hkdfExpand(hash: hash, prk: prk, info: info, length: length) // reference
        return ["out": ["okm": Npamp.toHex(okm)]]

    case "profile.check":
        // The reference module implements no profile KEM-acceptance policy.
        return ["skipped": "no profile policy in the Swift reference implementation"]

    default:
        return ["skipped": "op not implemented: \(op)"]
    }
}

// MARK: - Length-prefixed read/respond loop

while true {
    guard let lenBytes = readExact(4) else { break } // clean EOF
    let n = Int(lenBytes[0]) | (Int(lenBytes[1]) << 8) | (Int(lenBytes[2]) << 16) | (Int(lenBytes[3]) << 24)
    guard let body = readExact(n) else { break }
    var response: [String: Any]
    if let obj = try? JSONSerialization.jsonObject(with: Data(body)) as? [String: Any] {
        response = handle(obj)
    } else {
        response = ["error": "bad request json"]
    }
    writeFramed(encodeResponse(response))
}
