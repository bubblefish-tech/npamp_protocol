// Standards-derived, NON-CIRCULAR known-answer tests for the draft-00 handshake
// binding layer (spec/10): the transcript hash (§3), the X25519MLKEM768 KEM-wire
// layout (§4, ADR-0005/0007), the key schedule (§5, ADR-0008), the Finished MAC
// (§6.2; RFC 8446 §4.4.4), and the CertVerify signature (§6.1; RFC 8446 §4.4.3
// structure; Ed25519 per RFC 8032). Swift mirror of the Go/TS/Python/Java/Kotlin/
// Ruby/PHP/Rust/C# reference tests against the SAME pinned vectors
// (test-vectors/v1/*-kat.json — all five, SHA-256-pinned, fail loud on a swap).
//
// Each KAT has three legs:
//   ANCHOR — reproduce the published standard from the vector JSON (FIPS 180-4
//            SHA-256("abc"); RFC 5869 TC1; RFC 8448 §3; RFC 4231 TC1/TC2;
//            RFC 8032 TEST1/TEST2; RFC 7748 §6.1), so the underlying primitive
//            is trusted before any N-PAMP output is.
//   ORACLE — reconstruct the expected outputs WITHOUT the functions under test
//            (hand-built bytes + direct swift-crypto calls), guarding the vector.
//   IMPL   — drive the real Npamp/Handshake functions; assert vector match plus
//            accept/reject behavior.
//
// KEM-wire KAT coverage in THIS port: the X25519 RFC 7748 anchor, the ML-KEM-first
// wire assembly/split order (KEMShare/KEMCiphertext), and the HKDF-Extract IKM
// order are executed. The two ML-KEM-768 legs are explicitly SKIPPED (printed and
// counted, never silently green): swift-crypto 3.15.1's `Crypto` product exposes
// no ML-KEM API (verified against the pinned checkout at tag 3.15.1 — BoringSSL
// carries mlkem internally but no Swift-level API is exported), so the NIST
// d||z -> ek keygen leg and the expanded-dk decapsulation leg are not executable
// with this port's dependency set (the decaps leg is the same deferral the Go
// reference documents in ADR-0007).
//
// Foundation ships JSONSerialization on Linux and Apple platforms, so no JSON
// dependency is added (the JDK/cargo ports hand-rolled parsers because their
// stdlibs lack one; Swift's does not).
import Foundation
import Crypto
import Npamp

// ---------------------------------------------------------------------------
// Pins (SHA-256 of each vector file; identical to the sibling ports' pins)
// ---------------------------------------------------------------------------

let transcriptKatPin = "fab6d852497b6ff56405595e9a014d0c45cabc5cde80a60a17444b337d556ee5"
let keyScheduleKatPin = "e108f5cfdf99a378d7b677792448c8046abf3c630fc23fd8ea2ccb3927f2691c"
let finishedKatPin = "25c21b0bd3b3b6b77862f4a819f81ff5e4ff42e4b1d70af81feeedc5aad73c7f"
let certVerifyKatPin = "f56ec6ba250ba8f8c6c84214a16f580a3e476e9b2cfd05720c3352de299fe555"
let kemWireKatPin = "3edd3e0c1e96fa8a3b45b0e998a2b12082a7b4e66cd5acf3883f2de8ff12c222"

/// Every executable leg below, in order. The summary hard-checks this count so
/// "ALL PASS" is positive evidence that every leg RAN (exit-0 alone cannot tell
/// "all KATs passed" from "zero KATs ran").
let expectedExecutableLegs = 15

// ---------------------------------------------------------------------------
// Leg runner + failure accounting
// ---------------------------------------------------------------------------

struct KatError: Error, CustomStringConvertible {
    let description: String
    init(_ d: String) { description = d }
}

func check(_ cond: Bool, _ msg: @autoclosure () -> String) throws {
    if !cond { throw KatError(msg()) }
}

var passes = 0
var failures = 0
var skips = [String]()

func leg(_ name: String, _ fn: () throws -> Void) {
    do {
        try fn()
        passes += 1
        print("PASS \(name)")
    } catch {
        failures += 1
        print("FAIL \(name): \(error)")
    }
}

func skipLeg(_ name: String, _ reason: String) {
    skips.append(name)
    print("SKIP \(name): \(reason)")
}

// ---------------------------------------------------------------------------
// Hex + JSON access helpers
// ---------------------------------------------------------------------------

func trimHexPrefix(_ s: String) -> String {
    (s.hasPrefix("0x") || s.hasPrefix("0X")) ? String(s.dropFirst(2)) : s
}

func fromHex(_ s: String) throws -> [UInt8] {
    let t = trimHexPrefix(s)
    try check(t.count % 2 == 0, "odd-length hex: \(s)")
    var out = [UInt8]()
    out.reserveCapacity(t.count / 2)
    var idx = t.startIndex
    while idx < t.endIndex {
        let next = t.index(idx, offsetBy: 2)
        guard let b = UInt8(t[idx..<next], radix: 16) else { throw KatError("bad hex: \(s)") }
        out.append(b)
        idx = next
    }
    return out
}

func toHex(_ data: [UInt8]) -> String { Npamp.toHex(data) }

func parseHexInt(_ s: String) throws -> Int {
    guard let v = Int(trimHexPrefix(s), radix: 16) else { throw KatError("bad hex int: \(s)") }
    return v
}

func obj(_ node: Any?, _ key: String) throws -> [String: Any] {
    guard let m = node as? [String: Any], let v = m[key] as? [String: Any] else {
        throw KatError("missing/non-object JSON key: \(key)")
    }
    return v
}

func arr(_ node: Any?, _ key: String) throws -> [Any] {
    guard let m = node as? [String: Any], let v = m[key] as? [Any] else {
        throw KatError("missing/non-array JSON key: \(key)")
    }
    return v
}

func str(_ node: Any?, _ key: String) throws -> String {
    guard let m = node as? [String: Any], let v = m[key] as? String else {
        throw KatError("missing/non-string JSON key: \(key)")
    }
    return v
}

func hexBytes(_ node: Any?, _ key: String) throws -> [UInt8] {
    try fromHex(str(node, key))
}

func int(_ node: Any?, _ key: String) throws -> Int {
    guard let m = node as? [String: Any], let raw = m[key] else {
        throw KatError("missing JSON key: \(key)")
    }
    if let v = raw as? Int { return v }
    if let v = raw as? NSNumber { return v.intValue }
    if let v = raw as? Double { return Int(v) }
    throw KatError("non-numeric JSON key: \(key)")
}

// ---------------------------------------------------------------------------
// Vector resolution + SHA-256 pin
// ---------------------------------------------------------------------------

/// Resolves the test-vectors/v1 directory. Order: argv[1] if given, then an
/// upward walk from the CWD for a `test-vectors/v1` directory, then the
/// canonical relative path `../../../test-vectors/v1` (relative to impl/swift).
func vectorsDir(_ args: [String]) -> URL {
    if args.count >= 2 {
        return URL(fileURLWithPath: args[1], isDirectory: true)
    }
    var dir = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    while true {
        let cand = dir.appendingPathComponent("test-vectors").appendingPathComponent("v1")
        var isDir: ObjCBool = false
        if FileManager.default.fileExists(atPath: cand.path, isDirectory: &isDir), isDir.boolValue {
            return cand
        }
        let parent = dir.deletingLastPathComponent()
        if parent.path == dir.path { break }
        dir = parent
    }
    return URL(fileURLWithPath: "../../../test-vectors/v1", isDirectory: true)
}

/// Reads the named vector file's raw bytes, fails loud unless its SHA-256 equals
/// `pin` (catches a swapped vector), then returns it parsed as a JSON object.
func loadPinned(_ args: [String], _ name: String, _ pin: String) throws -> [String: Any] {
    let url = vectorsDir(args).appendingPathComponent(name)
    let raw: Data
    do {
        raw = try Data(contentsOf: url)
    } catch {
        throw KatError("cannot read \(url.path): \(error)")
    }
    let got = toHex(Array(SHA256.hash(data: raw)))
    try check(got == pin, "\(name) SHA-256 mismatch (swapped vector?):\n  got  \(got)\n  want \(pin)")
    guard let parsed = try JSONSerialization.jsonObject(with: raw) as? [String: Any] else {
        throw KatError("\(name): root is not a JSON object")
    }
    return parsed
}

let args = CommandLine.arguments

// ---------------------------------------------------------------------------
// Transcript KAT (spec/10 §3) — pin fab6d852…, anchor FIPS 180-4
// ---------------------------------------------------------------------------

/// (frame index, TLV index within that frame) -> transcript-hash point name.
/// This IS the spec/10 §3 cut-point structure; driving by position keeps the
/// test value-agnostic.
let transcriptCutPoints: [String: String] = [
    "1.4": "th_kem", "2.0": "th_sid", "2.1": "th_scv", "3.0": "th_cid", "3.1": "th_ccv",
]
let transcriptPointOrder = ["th_kem", "th_sid", "th_scv", "th_cid", "th_ccv"]

/// Walks the vector frames/TLVs in order; snapshots at each spec/10 §3 cut point.
func driveTranscript(_ frames: [Any],
                     addFrameType: (Int) -> Void,
                     addTlv: (Int, [UInt8]) -> Void,
                     snap: () -> String) throws -> [String: String] {
    var points = [String: String]()
    for (fi, f) in frames.enumerated() {
        addFrameType(try parseHexInt(try str(f, "frame_type")))
        for (ti, tl) in (try arr(f, "tlvs")).enumerated() {
            addTlv(try parseHexInt(try str(tl, "type")), try hexBytes(tl, "value"))
            if let name = transcriptCutPoints["\(fi).\(ti)"] {
                points[name] = snap()
            }
        }
    }
    return points
}

func checkTranscriptPoints(_ legName: String, _ k: [String: Any], _ points: [String: String]) throws {
    let exp = try obj(k, "expected_transcript_points")
    try check(Set(points.keys) == Set(transcriptPointOrder),
              "[\(legName)] missing/extra cut points: \(points.keys.sorted())")
    for name in transcriptPointOrder {
        let want = try str(exp, name)
        try check(points[name] == want,
                  "[\(legName)] \(name) mismatch\n  got  \(points[name] ?? "nil")\n  want \(want)")
    }
}

do {
    let k = try loadPinned(args, "transcript-kat.json", transcriptKatPin)

    // (A) ANCHOR — SHA-256("abc") reproduces FIPS 180-4.
    leg("transcript_kat_fips180_anchor") {
        let fips = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        let fipsNode = try obj(k, "fips180_4_sha256_abc")
        let input = try str(fipsNode, "input_ascii")
        let got = toHex(Array(SHA256.hash(data: Array(input.utf8))))
        try check(got == fips, "SHA-256(\"\(input)\") != FIPS 180-4\n  got  \(got)\n  want \(fips)")
        try check(try str(fipsNode, "digest") == fips, "vector anchor digest != FIPS 180-4")
    }

    // (B) ORACLE — independent per-TLV byte constructor, no Transcript.
    leg("transcript_kat_oracle") {
        let frames = try arr(k, "frames")
        var buf = [UInt8]()
        let points = try driveTranscript(
            frames,
            addFrameType: { ft in
                buf.append(UInt8((ft >> 8) & 0xFF)); buf.append(UInt8(ft & 0xFF))
            },
            addTlv: { t, v in
                buf.append(UInt8((t >> 8) & 0xFF)); buf.append(UInt8(t & 0xFF))
                buf.append(UInt8((v.count >> 8) & 0xFF)); buf.append(UInt8(v.count & 0xFF))
                buf.append(contentsOf: v)
            },
            snap: { toHex(Array(SHA256.hash(data: buf))) }
        )
        try checkTranscriptPoints("oracle", k, points)
    }

    // (C) IMPL — the real Handshake.Transcript; frame-type constants pinned too.
    leg("transcript_kat_impl") {
        try check(Handshake.frameClientHello == 0x0100 && Handshake.frameServerHello == 0x0101
                    && Handshake.frameServerAuth == 0x0102 && Handshake.frameClientAuth == 0x0103,
                  "frame-type constants drifted from spec/10 §1 code points")
        let frames = try arr(k, "frames")
        let tr = Handshake.Transcript()
        let points = try driveTranscript(
            frames,
            addFrameType: { tr.addFrameType($0) },
            addTlv: { tr.addTlv($0, $1) },
            snap: { toHex(tr.hash(true)) }
        )
        try checkTranscriptPoints("impl", k, points)
    }
} catch {
    failures += 1
    print("FAIL transcript_kat (vector load): \(error)")
}

// ---------------------------------------------------------------------------
// Key-schedule KAT (spec/10 §5) — pin e108f5…, anchors RFC 5869 TC1 + RFC 8448
// ---------------------------------------------------------------------------

/// Standard HMAC-SHA-256, independent of the impl's key-schedule functions.
func hmacSha256Oracle(_ key: [UInt8], _ data: [UInt8]) -> [UInt8] {
    Array(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key)))
}

/// HKDF-Extract (RFC 5869 §2.2), independent of Npamp.hkdfExtract.
func extractOracle(_ salt: [UInt8], _ ikm: [UInt8]) -> [UInt8] {
    hmacSha256Oracle(salt, ikm)
}

/// Raw HKDF-Expand (RFC 5869 §2.3): T(0)="", T(i)=HMAC(PRK, T(i-1)||info||i).
/// Manual counter loop — never calls Npamp.hkdfExpand.
func expandOracle(_ prk: [UInt8], _ info: [UInt8], _ length: Int) -> [UInt8] {
    var okm = [UInt8]()
    var t = [UInt8]()
    var counter: UInt8 = 1
    while okm.count < length {
        t = hmacSha256Oracle(prk, t + info + [counter])
        okm.append(contentsOf: t)
        counter += 1
    }
    return Array(okm[0..<length])
}

/// Independent HKDF-Expand-Label (RFC 8446 §7.1) with the prefix as a PARAMETER:
/// it rebuilds HkdfLabel = uint16(length) || uint8(len(prefix+label)) ||
/// prefix+label || uint8(len(context)) || context straight from the spec, then
/// calls the in-test raw expand. It does NOT call Npamp.hkdfExpandLabel — so when
/// the impl is judged against it, agreement is independent.
func expandLabelOracle(_ secret: [UInt8], _ prefix: String, _ label: String,
                       _ context: [UInt8], _ length: Int) -> [UInt8] {
    let full = Array((prefix + label).utf8)
    var info = [UInt8]()
    info.append(UInt8((length >> 8) & 0xFF))
    info.append(UInt8(length & 0xFF))
    info.append(UInt8(full.count))
    info.append(contentsOf: full)
    info.append(UInt8(context.count))
    info.append(contentsOf: context)
    return expandOracle(secret, info, length)
}

/// Traffic-secret context (spec/10 §5): dir(1) || epoch(8 BE) || suite(2 BE) || channel(2 BE).
func trafficContext(_ dir: Int, _ epoch: UInt64, _ suite: Int, _ channel: Int) -> [UInt8] {
    var out = [UInt8]()
    out.append(UInt8(dir & 0xFF))
    for j in 0..<8 { out.append(UInt8((epoch >> UInt64(56 - 8 * j)) & 0xFF)) }
    out.append(UInt8((suite >> 8) & 0xFF)); out.append(UInt8(suite & 0xFF))
    out.append(UInt8((channel >> 8) & 0xFF)); out.append(UInt8(channel & 0xFF))
    return out
}

do {
    let k = try loadPinned(args, "key-schedule-kat.json", keyScheduleKatPin)
    // Traffic direction ServerToClient = 1 (spec/10 §5); AES-256-GCM = 0x0001
    // per registries/aead.csv (0x0002 is ChaCha20-Poly1305).
    let dirServerToClient = 1
    let suiteAes256Gcm = Npamp.aeadAes256Gcm

    // (A) ANCHOR — impl hkdfExtract/hkdfExpand AND the in-test oracle reproduce RFC 5869 TC1.
    leg("key_schedule_kat_rfc5869_anchor") {
        let tc = try obj(k, "rfc5869_tc1")
        let salt = try hexBytes(tc, "salt")
        let ikm = try hexBytes(tc, "ikm")
        let info = try hexBytes(tc, "info")
        let length = try int(tc, "L")
        let prkHex = try str(tc, "prk")
        let okmHex = try str(tc, "okm")

        let implPrk = toHex(Npamp.hkdfExtract(salt, ikm, true))
        try check(implPrk == prkHex, "Npamp.hkdfExtract != RFC 5869 prk\n  got  \(implPrk)\n  want \(prkHex)")
        let implOkm = toHex(Npamp.hkdfExpand(hash: "sha256", prk: try fromHex(prkHex), info: info, length: length))
        try check(implOkm == okmHex, "Npamp.hkdfExpand != RFC 5869 okm\n  got  \(implOkm)\n  want \(okmHex)")
        let oraclePrk = toHex(extractOracle(salt, ikm))
        try check(oraclePrk == prkHex, "extractOracle != RFC 5869 prk\n  got  \(oraclePrk)\n  want \(prkHex)")
        let oracleOkm = toHex(expandOracle(try fromHex(prkHex), info, length))
        try check(oracleOkm == okmHex, "expandOracle != RFC 5869 okm\n  got  \(oracleOkm)\n  want \(okmHex)")
    }

    // (B) ORACLE — the independent Expand-Label reproduces RFC 8448 with "tls13 ".
    leg("key_schedule_kat_rfc8448_oracle") {
        let r = try obj(k, "rfc8448_expand_label")
        let secret = try hexBytes(r, "client_handshake_traffic_secret")
        let gotKey = toHex(expandLabelOracle(secret, "tls13 ", "key", [], 16))
        try check(gotKey == (try str(r, "write_key")), "oracle expandLabel(key) != RFC 8448\n  got  \(gotKey)")
        let gotIv = toHex(expandLabelOracle(secret, "tls13 ", "iv", [], 12))
        try check(gotIv == (try str(r, "write_iv")), "oracle expandLabel(iv) != RFC 8448\n  got  \(gotIv)")
        let gotFin = toHex(expandLabelOracle(secret, "tls13 ", "finished", [], 32))
        try check(gotFin == (try str(r, "finished_key")), "oracle expandLabel(finished) != RFC 8448\n  got  \(gotFin)")
    }

    // (C) IMPL — ladder + finished_key + s2c traffic key/iv match the proven oracle
    // applied with the "n-pamp " prefix. Golden N-PAMP bytes are COMPUTED by the
    // oracle, never hardcoded.
    leg("key_schedule_kat_impl") {
        try check(Npamp.labelPrefix == "n-pamp ", "Npamp.labelPrefix drifted from the spec's \"n-pamp \" prefix")
        let nn = try obj(k, "npamp_inputs")
        let mlkem = try hexBytes(nn, "ikm_mlkem_ss")
        let x25519 = try hexBytes(nn, "ikm_x25519_ss")
        let thKem = try hexBytes(nn, "th_kem")
        let thCcv = try hexBytes(nn, "th_ccv")
        let zeros32 = [UInt8](repeating: 0, count: 32)

        // handshake_secret = HKDF-Extract(32 zero octets, ML-KEM_SS || X25519_SS).
        let hs = Npamp.deriveHandshakeSecret(mlkem, x25519, true)
        let hsWant = toHex(extractOracle(zeros32, mlkem + x25519))
        try check(toHex(hs) == hsWant, "handshake_secret != oracle\n  got  \(toHex(hs))\n  want \(hsWant)")

        // c_hs / s_hs / master.
        let cHs = Npamp.deriveClientHandshakeSecret(hs, thKem, true)
        let cHsWant = toHex(expandLabelOracle(hs, "n-pamp ", "c hs", thKem, 32))
        try check(toHex(cHs) == cHsWant, "c_hs != oracle\n  got  \(toHex(cHs))\n  want \(cHsWant)")

        let sHs = Npamp.deriveServerHandshakeSecret(hs, thKem, true)
        let sHsWant = toHex(expandLabelOracle(hs, "n-pamp ", "s hs", thKem, 32))
        try check(toHex(sHs) == sHsWant, "s_hs != oracle\n  got  \(toHex(sHs))\n  want \(sHsWant)")

        let master = Npamp.deriveMasterSecret(hs, thCcv, true)
        let masterWant = toHex(expandLabelOracle(hs, "n-pamp ", "master", thCcv, 32))
        try check(toHex(master) == masterWant, "master != oracle\n  got  \(toHex(master))\n  want \(masterWant)")

        // finished_key: client derives from c_hs, server from s_hs.
        let fkClient = Npamp.deriveFinishedKey(cHs, true)
        let fkClientWant = toHex(expandLabelOracle(cHs, "n-pamp ", "finished", [], 32))
        try check(toHex(fkClient) == fkClientWant, "finished_key(c_hs) != oracle")
        let fkServer = Npamp.deriveFinishedKey(sHs, true)
        let fkServerWant = toHex(expandLabelOracle(sHs, "n-pamp ", "finished", [], 32))
        try check(toHex(fkServer) == fkServerWant, "finished_key(s_hs) != oracle")

        // s2c handshake AEAD via the existing deriveTrafficSecret/deriveKeyIv off
        // s_hs: dir=ServerToClient(1), epoch=0, suite=AES-256-GCM(0x0001),
        // channel=Control(0x0000).
        let traffic = Npamp.deriveTrafficSecret(sHs, dirServerToClient, 0, suiteAes256Gcm,
                                                Npamp.chanControl, true)
        let keyIv = Npamp.deriveKeyIv(traffic, true)
        let ctx = trafficContext(dirServerToClient, 0, suiteAes256Gcm, Npamp.chanControl)
        let oracleTraffic = expandLabelOracle(sHs, "n-pamp ", "traffic", ctx, 32)
        let keyWant = toHex(expandLabelOracle(oracleTraffic, "n-pamp ", "key", [], 32))
        let ivWant = toHex(expandLabelOracle(oracleTraffic, "n-pamp ", "iv", [], 12))
        try check(toHex(keyIv.key) == keyWant, "s2c handshake key != oracle\n  got  \(toHex(keyIv.key))\n  want \(keyWant)")
        try check(toHex(keyIv.iv) == ivWant, "s2c handshake iv != oracle\n  got  \(toHex(keyIv.iv))\n  want \(ivWant)")
    }
} catch {
    failures += 1
    print("FAIL key_schedule_kat (vector load): \(error)")
}

// ---------------------------------------------------------------------------
// Finished KAT (spec/10 §6.2) — pin 25c21b…, anchor RFC 4231 TC1/TC2
// ---------------------------------------------------------------------------

do {
    let k = try loadPinned(args, "finished-kat.json", finishedKatPin)
    let nn = try obj(k, "npamp_inputs")
    let e = try obj(k, "expected")

    // (A) ANCHOR — HMAC-SHA-256 reproduces the published RFC 4231 TC1/TC2 MACs.
    leg("finished_kat_rfc4231_anchor") {
        let rfc = try obj(k, "rfc4231_hmac_sha256")
        for tcName in ["tc1", "tc2"] {
            let tc = try obj(rfc, tcName)
            let got = toHex(hmacSha256Oracle(try hexBytes(tc, "key"), try hexBytes(tc, "data")))
            let want = try str(tc, "hmac_sha256")
            try check(got == want, "HMAC-SHA-256 \(tcName) != RFC 4231\n  got  \(got)\n  want \(want)")
        }
    }

    // (B) ORACLE — reproduce verify_data with the independent HMAC (guards the vector).
    leg("finished_kat_oracle") {
        let gotS = toHex(hmacSha256Oracle(try hexBytes(nn, "finished_key_server"), try hexBytes(nn, "th_scv")))
        try check(gotS == (try str(e, "verify_data_server")), "oracle server verify_data mismatch")
        let gotC = toHex(hmacSha256Oracle(try hexBytes(nn, "finished_key_client"), try hexBytes(nn, "th_ccv")))
        try check(gotC == (try str(e, "verify_data_client")), "oracle client verify_data mismatch")
    }

    // (C) IMPL — computeFinished reproduces verify_data; verifyFinished accepts +
    // rejects a tamper.
    leg("finished_kat_impl") {
        let cases: [(name: String, fkKey: String, thKey: String, vdKey: String)] = [
            ("server", "finished_key_server", "th_scv", "verify_data_server"),
            ("client", "finished_key_client", "th_ccv", "verify_data_client"),
        ]
        for c in cases {
            let fk = try hexBytes(nn, c.fkKey)
            let th = try hexBytes(nn, c.thKey)
            let wantHex = try str(e, c.vdKey)
            let want = try fromHex(wantHex)
            let got = toHex(Handshake.computeFinished(fk, th, true))
            try check(got == wantHex, "[\(c.name)] computeFinished mismatch\n  got  \(got)\n  want \(wantHex)")
            try check(Handshake.verifyFinished(fk, th, want, true),
                      "[\(c.name)] verifyFinished rejected the correct verify_data")
            var bad = want
            bad[0] ^= 0x01
            try check(!Handshake.verifyFinished(fk, th, bad, true),
                      "[\(c.name)] verifyFinished accepted a tampered verify_data")
        }
    }
} catch {
    failures += 1
    print("FAIL finished_kat (vector load): \(error)")
}

// ---------------------------------------------------------------------------
// CertVerify KAT (spec/10 §6.1) — pin f56ec6…, anchor RFC 8032 TEST1/TEST2
// ---------------------------------------------------------------------------

/// The §6.1 signing input, built by hand and independent of certVerifySigningInput.
func oracleSigningInput(_ ctx: String, _ th: [UInt8]) -> [UInt8] {
    var out = [UInt8](repeating: 0x20, count: 64)
    out.append(contentsOf: Array(ctx.utf8))
    out.append(0x00)
    out.append(contentsOf: th)
    return out
}

/// Raw Ed25519 sign over msg with an independently constructed key (never the
/// Handshake helpers). Requires the deterministic (BoringSSL/Linux) backend —
/// checked by the anchor leg before any signature-equality assertion is trusted.
func oracleSign(_ seed: [UInt8], _ msg: [UInt8]) throws -> [UInt8] {
    let priv = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
    return Array(try priv.signature(for: msg))
}

do {
    let k = try loadPinned(args, "certverify-kat.json", certVerifyKatPin)
    let nn = try obj(k, "npamp_inputs")
    let e = try obj(k, "expected")
    let c = try obj(k, "contexts")

    // (A) ANCHOR — the src Ed25519 helpers reproduce RFC 8032 TEST1/TEST2
    // (pubkey from seed, deterministic signature, raw-pubkey decode + verify).
    leg("certverify_kat_rfc8032_anchor") {
        let rfc = try obj(k, "rfc8032_ed25519")
        for label in ["test1", "test2"] {
            let v = try obj(rfc, label)
            let seed = try hexBytes(v, "seed")
            let msg = try hexBytes(v, "message")
            let wantPub = try str(v, "public_key")
            let wantSig = try str(v, "signature")

            let priv = try Handshake.ed25519PrivateKey(fromSeed: seed)
            try check(toHex(Array(priv.publicKey.rawRepresentation)) == wantPub,
                      "\(label) pubkey-from-seed != RFC 8032")

            // Ed25519-determinism guard: RFC 8032 signing is deterministic and the
            // Linux/BoringSSL backend implements it so; Apple CryptoKit randomizes
            // Ed25519 signatures, which would make every signature-equality leg
            // meaningless — fail loud rather than assert against noise.
            let s1 = Array(try priv.signature(for: msg))
            let s2 = Array(try priv.signature(for: msg))
            try check(s1 == s2, "Ed25519 backend produced randomized signatures (Apple CryptoKit "
                        + "behavior); the deterministic-equality legs of this KAT require the "
                        + "RFC 8032-deterministic BoringSSL backend (swift-crypto on Linux)")

            try check(toHex(s1) == wantSig, "\(label) signature != RFC 8032\n  got  \(toHex(s1))\n  want \(wantSig)")

            let pub = try Handshake.ed25519PublicKey(fromRaw: try fromHex(wantPub))
            try check(pub.isValidSignature(try fromHex(wantSig), for: msg),
                      "\(label): ed25519PublicKey(fromRaw:) produced a key that rejected the RFC 8032 signature")
        }
    }

    // (B) ORACLE — rebuild signing_input by hand + sign with an independent key.
    leg("certverify_kat_oracle") {
        let cases: [(name: String, ctxKey: String, seedKey: String, thKey: String, siKey: String, sigKey: String)] = [
            ("server", "server", "server_seed", "th_sid", "signing_input_server", "signature_server"),
            ("client", "client", "client_seed", "th_cid", "signing_input_client", "signature_client"),
        ]
        for cs in cases {
            let ctx = try str(c, cs.ctxKey)
            let th = try hexBytes(nn, cs.thKey)
            let si = oracleSigningInput(ctx, th)
            try check(toHex(si) == (try str(e, cs.siKey)), "[\(cs.name)] oracle signing_input != vector")
            let gotSig = toHex(try oracleSign(try hexBytes(nn, cs.seedKey), si))
            let wantSig = try str(e, cs.sigKey)
            try check(gotSig == wantSig, "[\(cs.name)] oracle signature != vector\n  got  \(gotSig)\n  want \(wantSig)")
        }
    }

    // (C) IMPL — certVerifySigningInput + signCertVerify reproduce the vector;
    // verifyCertVerify accepts the correct value but rejects a role/context
    // mismatch, a wrong transcript, a non-Ed25519 scheme, and a truncated sig.
    leg("certverify_kat_impl") {
        try check(Handshake.contextServerCertVerify == (try str(c, "server")),
                  "server context constant drifted from spec/10 §6.1")
        try check(Handshake.contextClientCertVerify == (try str(c, "client")),
                  "client context constant drifted from spec/10 §6.1")
        let cases: [(name: String, isServer: Bool, seedKey: String, pubKey: String, thKey: String, siKey: String, valKey: String)] = [
            ("server", true, "server_seed", "server_pub", "th_sid", "signing_input_server", "certverify_value_server"),
            ("client", false, "client_seed", "client_pub", "th_cid", "signing_input_client", "certverify_value_client"),
        ]
        for cs in cases {
            let priv = try Handshake.ed25519PrivateKey(fromSeed: try hexBytes(nn, cs.seedKey))
            let pub = try Handshake.ed25519PublicKey(fromRaw: try hexBytes(nn, cs.pubKey))
            let th = try hexBytes(nn, cs.thKey)

            let gotSI = toHex(Handshake.certVerifySigningInput(isServer: cs.isServer, transcriptHash: th))
            let wantSI = try str(e, cs.siKey)
            try check(gotSI == wantSI, "[\(cs.name)] certVerifySigningInput != vector\n  got  \(gotSI)\n  want \(wantSI)")

            let value = try Handshake.signCertVerify(priv, isServer: cs.isServer, transcriptHash: th)
            let wantVal = try str(e, cs.valKey)
            try check(toHex(value) == wantVal, "[\(cs.name)] signCertVerify value != vector\n  got  \(toHex(value))\n  want \(wantVal)")

            try check(Handshake.verifyCertVerify(pub, isServer: cs.isServer, transcriptHash: th, value: value),
                      "[\(cs.name)] verifyCertVerify rejected the correct value")
            // Domain separation: the opposite role must FAIL (different context string).
            try check(!Handshake.verifyCertVerify(pub, isServer: !cs.isServer, transcriptHash: th, value: value),
                      "[\(cs.name)] accepted a role/context mismatch")
            // Transcript binding: a different transcript hash must FAIL.
            var wrong = th
            wrong[0] ^= 0x01
            try check(!Handshake.verifyCertVerify(pub, isServer: cs.isServer, transcriptHash: wrong, value: value),
                      "[\(cs.name)] accepted a wrong transcript hash")
            // Scheme guard: a non-Ed25519 scheme code point must FAIL.
            var badScheme = value
            badScheme[0] = UInt8((Npamp.sigMlDsa87 >> 8) & 0xFF)
            badScheme[1] = UInt8(Npamp.sigMlDsa87 & 0xFF)
            try check(!Handshake.verifyCertVerify(pub, isServer: cs.isServer, transcriptHash: th, value: badScheme),
                      "[\(cs.name)] accepted a non-Ed25519 scheme")
            // Length guard: an Ed25519 signature is exactly 64 octets.
            try check(!Handshake.verifyCertVerify(pub, isServer: cs.isServer, transcriptHash: th,
                                                  value: Array(value[0..<(value.count - 1)])),
                      "[\(cs.name)] accepted a truncated signature")
        }
    }
} catch {
    failures += 1
    print("FAIL certverify_kat (vector load): \(error)")
}

// ---------------------------------------------------------------------------
// KEM-wire KAT (spec/10 §4; ADR-0005/0007) — pin 3edd3e…, anchors NIST ACVP
// (FIPS 203) + RFC 7748 §6.1. Executable legs: the X25519 anchor, the
// ML-KEM-first wire assembly/split order, and the HKDF-Extract IKM order.
// ML-KEM legs are explicit SKIPs (see header comment).
// ---------------------------------------------------------------------------

func x25519SharedSecret(_ privRaw: [UInt8], _ pubRaw: [UInt8]) throws -> [UInt8] {
    let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privRaw)
    let pub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: pubRaw)
    return try priv.sharedSecretFromKeyAgreement(with: pub).withUnsafeBytes { Array($0) }
}

do {
    let k = try loadPinned(args, "kem-wire-kat.json", kemWireKatPin)
    let x = try obj(k, "x25519_rfc7748_6_1")
    let keygen = try obj(k, "mlkem768_keygen")
    let decaps = try obj(k, "mlkem768_decaps_reference")
    let wire = try obj(k, "wire_layout")

    // (A) ANCHOR — swift-crypto's X25519 reproduces RFC 7748 §6.1: both public
    // keys from the raw private scalars (clamping internal) and the shared
    // secret from both directions.
    leg("kemwire_kat_x25519_rfc7748_anchor") {
        let alicePriv = try hexBytes(x, "alice_private")
        let alicePub = try hexBytes(x, "alice_public")
        let bobPriv = try hexBytes(x, "bob_private")
        let bobPub = try hexBytes(x, "bob_public")
        let shared = try str(x, "shared_secret")

        let gotAlicePub = Array(try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: alicePriv).publicKey.rawRepresentation)
        try check(gotAlicePub == alicePub, "alice public != RFC 7748\n  got  \(toHex(gotAlicePub))")
        let gotBobPub = Array(try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: bobPriv).publicKey.rawRepresentation)
        try check(gotBobPub == bobPub, "bob public != RFC 7748\n  got  \(toHex(gotBobPub))")

        let ab = toHex(try x25519SharedSecret(alicePriv, bobPub))
        try check(ab == shared, "ECDH(alice, bob_pub) != RFC 7748 shared secret\n  got  \(ab)\n  want \(shared)")
        let ba = toHex(try x25519SharedSecret(bobPriv, alicePub))
        try check(ba == shared, "ECDH(bob, alice_pub) != RFC 7748 shared secret\n  got  \(ba)\n  want \(shared)")
    }

    // (B) IMPL (wire order) — KEMShare/KEMCiphertext assembly and split are
    // ML-KEM-first (spec/10 §4). The KEMCiphertext split's X25519 half is
    // RFC-anchored: ECDH(alice_private, split.x25519) must reproduce RFC 7748's
    // shared secret — an X25519-first split cannot.
    leg("kemwire_kat_wire_order_impl") {
        try check(Npamp.kemX25519MlKem768 == (try parseHexInt(try str(k, "kem_codepoint"))),
                  "KEM code point drifted from the vector's kem_codepoint")
        let ek = try hexBytes(keygen, "ek")
        let alicePriv = try hexBytes(x, "alice_private")
        let alicePub = try hexBytes(x, "alice_public")
        let bobPub = try hexBytes(x, "bob_public")
        let ct = try hexBytes(decaps, "ciphertext_c")
        let shared = try str(x, "shared_secret")

        // KEMShare: ek(1184) || x25519 public(32) = 1216, ML-KEM-first.
        let share = try Handshake.kemShareBytes(mlkemEncapsulationKey: ek, x25519PublicKey: alicePub)
        try check(share.count == (try int(wire, "kem_share_len")),
                  "KEMShare length != wire_layout.kem_share_len")
        try check(Array(share[0..<ek.count]) == ek && Array(share[ek.count...]) == alicePub,
                  "KEMShare is not ML-KEM-first (ek || x25519_public)")
        let splitShare = try Handshake.splitKemShare(share)
        try check(splitShare.mlkemEncapsulationKey == ek && splitShare.x25519PublicKey == alicePub,
                  "splitKemShare did not round-trip ML-KEM-first")

        // KEMCiphertext: ct(1088) || server x25519 public(32) = 1120, ML-KEM-first.
        let ctWire = try Handshake.kemCiphertextBytes(mlkemCiphertext: ct, x25519PublicKey: bobPub)
        try check(ctWire.count == (try int(wire, "kem_ciphertext_len")),
                  "KEMCiphertext length != wire_layout.kem_ciphertext_len")
        let splitCt = try Handshake.splitKemCiphertext(ctWire)
        try check(splitCt.mlkemCiphertext == ct, "splitKemCiphertext ML-KEM half != ciphertext_c")
        // RFC anchor through the impl's split: the recovered server X25519 public
        // must yield RFC 7748's shared secret against alice's private scalar.
        let recovered = toHex(try x25519SharedSecret(alicePriv, splitCt.x25519PublicKey))
        try check(recovered == shared,
                  "ECDH(alice, split.x25519) != RFC 7748 shared secret (wire order broken)\n  got  \(recovered)\n  want \(shared)")
    }

    // (C) IMPL (IKM order) — handshake_secret = HKDF-Extract(zeros, ML-KEM_SS ||
    // X25519_SS) per wire_layout.combined_secret, and DIFFERS from the
    // X25519-first IKM (the original defect ADR-0005 fixed).
    leg("kemwire_kat_ikm_order_impl") {
        let mlkemSS = try hexBytes(decaps, "shared_secret_K")
        let x25519SS = try hexBytes(x, "shared_secret")
        try check(mlkemSS.count + x25519SS.count == (try int(wire, "combined_secret_len")),
                  "combined secret length != wire_layout.combined_secret_len")
        let zeros32 = [UInt8](repeating: 0, count: 32)
        let hs = toHex(Npamp.deriveHandshakeSecret(mlkemSS, x25519SS, true))
        let want = toHex(extractOracle(zeros32, mlkemSS + x25519SS))
        try check(hs == want, "handshake_secret != HKDF-Extract(zeros, ML-KEM_SS || X25519_SS)\n  got  \(hs)\n  want \(want)")
        let reversed = toHex(extractOracle(zeros32, x25519SS + mlkemSS))
        try check(hs != reversed, "handshake_secret matches the X25519-first IKM — ML-KEM-first order violated (ADR-0005)")
    }

    // Explicit, tracked SKIPs — never silently green (ADR-0007 documents the
    // same decaps deferral for the Go reference).
    skipLeg("kemwire_kat_mlkem768_keygen_anchor",
            "swift-crypto 3.15.1's Crypto product exposes no ML-KEM API (verified against the "
                + "pinned checkout), so the NIST ACVP d||z -> ek keygen leg is not executable "
                + "with this port's dependency set")
    skipLeg("kemwire_kat_mlkem768_decaps_anchor",
            "decapsulating the NIST ciphertext c to the NIST K requires importing the record's "
                + "EXPANDED 2400-octet dk and an ML-KEM API, neither available in this port's "
                + "dependency set (same deferral as the Go reference, ADR-0007)")
} catch {
    failures += 1
    print("FAIL kemwire_kat (vector load): \(error)")
}

// ---------------------------------------------------------------------------
// Summary — 'ALL PASS' is the positive gate token and is printed ONLY when every
// expected executable leg ran and passed (zero-KAT protection).
// ---------------------------------------------------------------------------

if failures == 0 && passes != expectedExecutableLegs {
    failures += 1
    print("FAIL leg_count: expected \(expectedExecutableLegs) executable legs, ran \(passes)")
}

if failures == 0 {
    print("ALL PASS (\(passes)/\(expectedExecutableLegs) legs; \(skips.count) skipped-with-reason: \(skips.joined(separator: ", ")))")
    exit(0)
} else {
    print("FAILURES: \(failures) (passed \(passes)/\(expectedExecutableLegs); skipped \(skips.count))")
    exit(1)
}
