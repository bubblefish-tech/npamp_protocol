// N-PAMP conformance adapter (Swift) — a "testee" for npamp-conform. Reads length-prefixed
// JSON requests {op,in} on stdin and writes length-prefixed JSON responses {out|error|skipped}
// on stdout, delegating every primitive to the Npamp reference library. Binary stdio; one
// JSON message per 4-byte little-endian length prefix.
import Foundation
import Npamp

func readExact(_ n: Int) -> Data? {
    if n == 0 { return Data() }
    var buf = Data()
    let h = FileHandle.standardInput
    while buf.count < n {
        // `try?` flattens read(upToCount:)'s `Data?` to a single optional (SE-0230),
        // so one binding both catches a throw and a nil/EOF read.
        guard let c = try? h.read(upToCount: n - buf.count), !c.isEmpty else { return nil }
        buf.append(c)
    }
    return buf
}

func writeFramed(_ obj: [String: Any]) {
    let body = (try? JSONSerialization.data(withJSONObject: obj, options: [])) ?? Data("{}".utf8)
    let n = body.count
    var out = Data([UInt8(n & 0xFF), UInt8((n >> 8) & 0xFF), UInt8((n >> 16) & 0xFF), UInt8((n >> 24) & 0xFF)])
    out.append(body)
    FileHandle.standardOutput.write(out)
}

func handle(_ req: [String: Any]) -> [String: Any] {
    let op = req["op"] as? String ?? ""
    let inp = req["in"] as? [String: Any] ?? [:]
    func s(_ k: String) -> String { inp[k] as? String ?? "" }
    func i(_ k: String) -> Int {
        if let v = inp[k] as? Int { return v }
        if let v = inp[k] as? Double { return Int(v) }
        if let v = inp[k] as? NSNumber { return v.intValue }
        return 0
    }
    func hx(_ k: String) -> [UInt8] { Npamp.fromHex(s(k)) }

    switch op {
    case "header.encode":
        let f = Npamp.Frame(ftype: i("frameType"), channel: i("channel"), seq: UInt64(i("seq")),
                            flags: i("flags"), version: i("ver"))
        return ["out": ["frame": Npamp.toHex(f.marshal())]]

    case "header.decode":
        let b = hx("frame")
        do {
            let f = try Npamp.Frame.unmarshal(b)
            let crc = Npamp.toHex(Array(b[21..<25]))
            return ["out": ["magic": "NPAM", "ver": f.version, "flags": f.flags,
                            "frameType": f.ftype, "channel": f.channel, "seq": Int(f.seq),
                            "payloadLength": f.payload.count, "crc32c": crc, "reservedZero": true]]
        } catch let e as Npamp.FrameError {
            return ["error": e.message]
        } catch {
            return ["error": "\(error)"]
        }

    case "crc32c":
        return ["out": ["crc32c": String(format: "%08x", Npamp.crc32c(hx("octets")))]]

    case "tlv.decode":
        let b = hx("tlv")
        if b.count < 4 { return ["error": "truncated tlv"] }
        let typ = Int(b[0]) << 8 | Int(b[1])
        let length = Int(b[2]) << 8 | Int(b[3])
        if typ & 0x8000 != 0 { return ["error": "unknown forward-incompatible TLV (high bit set)"] }
        if length != b.count - 4 { return ["error": "tlv length mismatch"] }
        return ["out": ["type": typ, "length": length, "value": Npamp.toHex(Array(b[4...]))]]

    case "aead.seal":
        if s("suite") != "AES-256-GCM" { return ["skipped": "suite not implemented: \(s("suite"))"] }
        do {
            let sealed = try Npamp.sealAes256Gcm(hx("key"), hx("nonce"), 0, hx("aad"), hx("pt"))
            return ["out": ["sealed": Npamp.toHex(sealed)]]
        } catch { return ["error": "\(error)"] }

    case "aead.open":
        if s("suite") != "AES-256-GCM" { return ["skipped": "suite not implemented: \(s("suite"))"] }
        do {
            let pt = try Npamp.openAes256Gcm(hx("key"), hx("nonce"), 0, hx("aad"), hx("sealed"))
            return ["out": ["pt": Npamp.toHex(pt)]]
        } catch { return ["error": "authentication failed"] }

    case "hkdf.expand":
        let okm = Npamp.hkdfExpand(hash: s("hash"), prk: hx("prk"), info: hx("info"), length: i("length"))
        return ["out": ["okm": Npamp.toHex(okm)]]

    default:
        return ["skipped": "op not implemented: \(op)"]
    }
}

while true {
    guard let lenData = readExact(4), lenData.count == 4 else { break }
    let len = Int(UInt32(lenData[0]) | UInt32(lenData[1]) << 8 | UInt32(lenData[2]) << 16 | UInt32(lenData[3]) << 24)
    guard let body = readExact(len) else { break }
    if let req = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any] {
        writeFramed(handle(req))
    } else {
        writeFramed(["error": "bad request json"])
    }
}
