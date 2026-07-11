// Byte-pinned handshake-FLOW known-answer test (issue #60, class golden-interop).
//
// Unlike the standards-anchored primitive KATs (transcript / key-schedule / finished /
// certverify, in npamp-handshake-kat), this vector pins the Go reference's SERIALIZED
// handshake frames so every language impl reproduces them byte-for-byte. It is the Swift
// mirror of impl/go/handshakeflow_kat_test.go and impl/python/tests/test_handshake_flow_kat.py
// against the SAME frozen corpus (test-vectors/v1/handshake-flow-kat.json). The CLIENT_HELLO
// whole-frame assertion is the one that catches draft-00-vs-draft-01 wire drift (a fixed
// 4-octet ProfileOffer vs the draft-01 one-octet form) as a FAILING TEST rather than a
// live-handshake break.
//
// Every EXPECTED artifact is rebuilt through THIS impl's REAL code path from the pinned INPUTS:
//   - frames: TLV payloads (Type(2)||Length(2)||Value, the exact encoding Handshake.Transcript
//     .addTlv emits — guarded below) wrapped by the real Npamp.Frame.marshal(); AUTH frames
//     sealed by the real key schedule (Npamp.deriveTrafficSecret / Npamp.deriveKeyIv) +
//     Npamp.sealAes256Gcm with the 21-octet Npamp.Frame.headerPrefix as AAD.
//   - transcript: the real Handshake.Transcript at each spec/10 §3 cut point.
//   - key ladder: Npamp.deriveHandshakeSecret / deriveClientHandshakeSecret /
//     deriveServerHandshakeSecret / deriveMasterSecret / deriveTrafficSecret / deriveKeyIv.
//   - CertVerify / Finished: Handshake.signCertVerify / verifyCertVerify / computeFinished /
//     verifyFinished.
//   - mutation guard: a one-octet flip of the server CertVerify signature AND of the client
//     Finished MAC must REJECT; the untouched values must still verify.
//
// ML-KEM NOTE (honest scope): swift-crypto 3.15.1's Crypto product exposes NO ML-KEM API
// (verified against the pinned checkout; same deferral the Go reference records in ADR-0007 and
// the Python module records in its docstring). So this verifier does NOT decapsulate the pinned
// ML-KEM ciphertext — that leg is a TRACKED SKIP, never silently green. It DOES perform every KEM
// check Swift CAN do through a real code path: the pinned kem_ciphertext front == mlkem_ciphertext;
// the X25519 shared secret re-runs through swift-crypto (client X25519 private + the server public
// spliced from the pinned kem_ciphertext tail) and recovers x25519_shared_secret; and the ML-KEM-
// first concatenation mlkem_shared_secret || x25519_shared_secret == combined_secret (the IKM the
// key schedule consumes). mlkem_shared_secret is consumed as a pinned self-validating input.
import Foundation
import Crypto
import Npamp

// ---------------------------------------------------------------------------
// TLV type + constant code points (spec/10 §1.1; registry 9.4). The handshake-
// specific TLV types are pinned here as the wire code points the transcript and
// frames must carry (they are the same values impl/go/tlv.go defines).
// ---------------------------------------------------------------------------

let tlvProfileOffer = 0x0001
let tlvKemOffer = 0x0003
let tlvSigOffer = 0x0005
let tlvAeadOffer = 0x000C
let tlvKemShare = 0x0007
let tlvProfileSelect = 0x0002
let tlvKemSelect = 0x0004
let tlvSigSelect = 0x0006
let tlvAeadSelect = 0x000D
let tlvKemCiphertext = 0x0008
let tlvIdentityKey = 0x0009
let tlvCertVerify = 0x000A
let tlvFinished = 0x000B

// draft-00 §6: the ProfileOffer/ProfileSelect value is ONE octet.
let profileStandard = 0x01

let dirC2S = 0
let dirS2C = 1

// ML-KEM-768 ciphertext size (FIPS 203) — the front of the pinned kem_ciphertext; the
// 32-octet tail is the server X25519 public key (spec/10 §4, ML-KEM-first wire layout).
let mlkem768CiphertextSize = 1088

// SHA-256 pin of the flow vector — fails loud on a swapped vector (mirrors the sibling KATs).
let handshakeFlowKatPin = "cf1d3c1fba550f3742e4de16d0f86d3beeafeb56efff90f85ff16165063c0fc9"

// ---------------------------------------------------------------------------
// Leg runner + failure accounting (identical convention to npamp-handshake-kat)
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

/// Every executable leg below, in order. The summary hard-checks this count so "ALL PASS" is
/// positive evidence that every leg RAN (exit-0 alone cannot tell "all passed" from "zero ran").
let expectedExecutableLegs = 3

// ---------------------------------------------------------------------------
// Hex + JSON helpers (same shapes as npamp-handshake-kat/main.swift)
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

func obj(_ node: Any?, _ key: String) throws -> [String: Any] {
    guard let m = node as? [String: Any], let v = m[key] as? [String: Any] else {
        throw KatError("missing/non-object JSON key: \(key)")
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

// ---------------------------------------------------------------------------
// Vector resolution + SHA-256 pin (identical to the sibling KAT runner)
// ---------------------------------------------------------------------------

/// Resolves the test-vectors/v1 directory. Order: argv[1] if given, then an upward walk from the
/// CWD for a `test-vectors/v1` directory, then the canonical relative path `../../../test-vectors/v1`.
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

/// Reads the flow vector's raw bytes, fails loud unless its SHA-256 equals `handshakeFlowKatPin`
/// (catches a swapped vector), then returns it parsed as a JSON object.
func loadFlowVector(_ args: [String]) throws -> [String: Any] {
    let url = vectorsDir(args).appendingPathComponent("handshake-flow-kat.json")
    let raw: Data
    do {
        raw = try Data(contentsOf: url)
    } catch {
        throw KatError("cannot read \(url.path): \(error)")
    }
    let got = toHex(Array(SHA256.hash(data: raw)))
    try check(got == handshakeFlowKatPin,
              "handshake-flow-kat.json SHA-256 mismatch (swapped vector?):\n  got  \(got)\n  want \(handshakeFlowKatPin)")
    guard let parsed = try JSONSerialization.jsonObject(with: raw) as? [String: Any] else {
        throw KatError("handshake-flow-kat.json: root is not a JSON object")
    }
    return parsed
}

// ---------------------------------------------------------------------------
// TLV / frame / seal builders driven through the impl's real code path
// ---------------------------------------------------------------------------

/// One TLV in canonical Type(2 BE) || Length(2 BE) || Value form — the identical byte layout
/// Handshake.Transcript.addTlv appends (asserted in the tlv-matches-transcript leg below).
func tlv(_ type: Int, _ value: [UInt8]) -> [UInt8] {
    var out = [UInt8]()
    out.append(UInt8((type >> 8) & 0xFF))
    out.append(UInt8(type & 0xFF))
    out.append(UInt8((value.count >> 8) & 0xFF))
    out.append(UInt8(value.count & 0xFF))
    out.append(contentsOf: value)
    return out
}

/// A big-endian list of 16-bit code points (the KEM/Sig/AEAD offer value encoding).
func u16list(_ ids: [Int]) -> [UInt8] {
    var out = [UInt8]()
    for id in ids {
        out.append(UInt8((id >> 8) & 0xFF))
        out.append(UInt8(id & 0xFF))
    }
    return out
}

/// A cleartext handshake frame (Control channel, seq 0) through the impl's real Frame.marshal().
func cleartextFrame(_ ftype: Int, _ payload: [UInt8]) -> [UInt8] {
    Npamp.Frame(ftype: ftype, channel: Npamp.chanControl, seq: 0, payload: payload).marshal()
}

/// Seal an AUTH plaintext into a wire frame through the impl's REAL key-schedule + record path:
/// traffic_secret -> key/iv from base_secret (dir, epoch 0, AES-256-GCM, Control), then
/// Npamp.sealAes256Gcm over the plaintext with the 21-octet header prefix as AAD (payload_len =
/// len(plaintext)+16 for the GCM tag), matching impl/go sealAuthKAT and impl/python _seal_auth_frame.
func sealAuthFrame(_ ftype: Int, _ baseSecret: [UInt8], _ direction: Int, _ plaintext: [UInt8]) throws -> [UInt8] {
    let ts = Npamp.deriveTrafficSecret(baseSecret, direction, 0, Npamp.aeadAes256Gcm, Npamp.chanControl, true)
    let keyIv = Npamp.deriveKeyIv(ts, true)
    var f = Npamp.Frame(ftype: ftype, channel: Npamp.chanControl, seq: 0, flags: Npamp.flagEnc)
    let aad = f.headerPrefix(plaintext.count + 16)
    let sealed = try Npamp.sealAes256Gcm(keyIv.key, keyIv.iv, 0, aad, plaintext)
    f.payload = sealed
    return f.marshal()
}

/// Raw X25519 shared secret through swift-crypto (independent of the Npamp helpers).
func x25519SharedSecret(_ privRaw: [UInt8], _ pubRaw: [UInt8]) throws -> [UInt8] {
    let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privRaw)
    let pub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: pubRaw)
    return try priv.sharedSecretFromKeyAgreement(with: pub).withUnsafeBytes { Array($0) }
}

// ---------------------------------------------------------------------------
// The verifier
// ---------------------------------------------------------------------------

let args = CommandLine.arguments

do {
    let k = try loadFlowVector(args)
    let inp = try obj(k, "inputs")
    let exp = try obj(k, "expected")

    // (0) GUARD — the in-test `tlv` encoder produces exactly the bytes Handshake.Transcript.addTlv
    // absorbs, so the frame payloads below are built with the impl's own canonical TLV layout, not
    // a private one. (Transcript exposes no buffer accessor, so compare against the hash of the
    // impl's absorbed bytes vs. the hash of the in-test bytes.)
    leg("handshake_flow_kat_tlv_matches_transcript") {
        let tr = Handshake.Transcript()
        tr.addTlv(tlvProfileOffer, [0x01])
        tr.addTlv(tlvKemShare, [0xaa, 0xbb, 0xcc])
        let manual = tlv(tlvProfileOffer, [0x01]) + tlv(tlvKemShare, [0xaa, 0xbb, 0xcc])
        let implHash = toHex(tr.hash(true))
        let manualHash = toHex(Array(SHA256.hash(data: manual)))
        try check(implHash == manualHash, "in-test TLV encoder diverged from Handshake.Transcript.addTlv")
    }

    // (1) KEM leg checks Swift CAN do (ML-KEM decaps itself is a tracked SKIP below): the pinned
    // kem_ciphertext front == mlkem_ciphertext; the X25519 shared secret re-runs through
    // swift-crypto from client_x25519_private + the server public spliced from the ciphertext tail
    // and recovers x25519_shared_secret; and mlkem_ss || x25519_ss (ML-KEM-first) == combined_secret
    // (the key schedule IKM). mlkem_shared_secret is a pinned self-validating input.
    leg("handshake_flow_kat_kem_and_x25519") {
        let kemInfo = try obj(exp, "kem")
        let kemCt = try hexBytes(kemInfo, "kem_ciphertext")
        let mlkemCt = try hexBytes(inp, "mlkem_ciphertext")
        let mlkemSS = try hexBytes(inp, "mlkem_shared_secret")
        let xSS = try hexBytes(inp, "x25519_shared_secret")
        let combined = try hexBytes(inp, "combined_secret")

        try check(kemCt.count == mlkem768CiphertextSize + 32, "pinned kem_ciphertext is not 1120 octets")
        try check(Array(kemCt[0..<mlkem768CiphertextSize]) == mlkemCt,
                  "kem_ciphertext front != pinned mlkem_ciphertext")
        let serverXPub = Array(kemCt[mlkem768CiphertextSize...])

        // Real X25519 through swift-crypto: recover x25519_shared_secret from the pinned client
        // private and the server public spliced from the ciphertext tail.
        let clientPriv = try hexBytes(inp, "client_x25519_private")
        let gotXSS = try x25519SharedSecret(clientPriv, serverXPub)
        try check(gotXSS == xSS, "recomputed X25519 shared secret != pinned x25519_shared_secret")

        // ML-KEM-first IKM: mlkem_ss || x25519_ss == combined_secret.
        try check(mlkemSS + xSS == combined, "mlkem_ss || x25519_ss != combined_secret (IKM drift)")

        // Sanity: the pinned server X25519 private also yields the same X25519 secret.
        let serverPriv = try hexBytes(inp, "server_x25519_private")
        let clientXPub = Array(try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: clientPriv)
            .publicKey.rawRepresentation)
        let gotXSS2 = try x25519SharedSecret(serverPriv, clientXPub)
        try check(gotXSS2 == xSS, "server-side X25519 exchange != pinned x25519_shared_secret")
    }

    // (2) The whole flow: rebuild every handshake artifact through the impl's real code path and
    // assert WHOLE-frame / byte-exact equality with the frozen vector.
    leg("handshake_flow_kat_frames_and_ladder") {
        let frames = try obj(exp, "frames")
        let kemInfo = try obj(exp, "kem")
        let transcript = try obj(exp, "transcript")
        let secrets = try obj(exp, "secrets")
        let finishedKeys = try obj(exp, "finished_keys")
        let finished = try obj(exp, "finished")
        let certVerify = try obj(exp, "cert_verify")
        let authPlaintext = try obj(exp, "auth_plaintext")

        let kemShare = try hexBytes(kemInfo, "kem_share")
        let kemCt = try hexBytes(kemInfo, "kem_ciphertext")
        let mlkemSS = try hexBytes(inp, "mlkem_shared_secret")
        let xSS = try hexBytes(inp, "x25519_shared_secret")

        // Frame-type constants must match the spec/10 §1 code points.
        try check(Handshake.frameClientHello == 0x0100 && Handshake.frameServerHello == 0x0101
                    && Handshake.frameServerAuth == 0x0102 && Handshake.frameClientAuth == 0x0103,
                  "frame-type constants drifted from spec/10 §1 code points")

        let clientEdSeed = try hexBytes(inp, "client_identity_ed25519_seed")
        let serverEdSeed = try hexBytes(inp, "server_identity_ed25519_seed")
        let clientPrivKey = try Handshake.ed25519PrivateKey(fromSeed: clientEdSeed)
        let serverPrivKey = try Handshake.ed25519PrivateKey(fromSeed: serverEdSeed)
        let clientPub = Array(clientPrivKey.publicKey.rawRepresentation)
        let serverPub = Array(serverPrivKey.publicKey.rawRepresentation)
        let clientPubKey = try Handshake.ed25519PublicKey(fromRaw: clientPub)
        let serverPubKey = try Handshake.ed25519PublicKey(fromRaw: serverPub)

        // --- CLIENT_HELLO: TLVs (ProfileOffer ONE octet = draft-01 form) framed by the real record path. ---
        let chPayload = tlv(tlvProfileOffer, [UInt8(profileStandard)])
            + tlv(tlvKemOffer, u16list([Npamp.kemX25519MlKem768]))
            + tlv(tlvSigOffer, u16list([Npamp.sigEd25519]))
            + tlv(tlvAeadOffer, u16list([Npamp.aeadAes256Gcm]))
            + tlv(tlvKemShare, kemShare)
        let chFrame = cleartextFrame(Handshake.frameClientHello, chPayload)
        try check(chFrame == (try hexBytes(frames, "client_hello")),
                  "CLIENT_HELLO frame != expected (the ProfileOffer draft-00-vs-draft-01 wire-drift guard)")

        // --- SERVER_HELLO: ProfileSelect ONE octet; KEM/Sig/AEAD Select two octets; KEMCiphertext pinned. ---
        let shPayload = tlv(tlvProfileSelect, [UInt8(profileStandard)])
            + tlv(tlvKemSelect, u16list([Npamp.kemX25519MlKem768]))
            + tlv(tlvSigSelect, u16list([Npamp.sigEd25519]))
            + tlv(tlvAeadSelect, u16list([Npamp.aeadAes256Gcm]))
            + tlv(tlvKemCiphertext, kemCt)
        let shFrame = cleartextFrame(Handshake.frameServerHello, shPayload)
        try check(shFrame == (try hexBytes(frames, "server_hello")), "SERVER_HELLO frame != expected")

        // --- Transcript + key ladder through the real impl. ---
        let tr = Handshake.Transcript()
        tr.addFrameType(Handshake.frameClientHello)
        tr.addTlv(tlvProfileOffer, [UInt8(profileStandard)])
        tr.addTlv(tlvKemOffer, u16list([Npamp.kemX25519MlKem768]))
        tr.addTlv(tlvSigOffer, u16list([Npamp.sigEd25519]))
        tr.addTlv(tlvAeadOffer, u16list([Npamp.aeadAes256Gcm]))
        tr.addTlv(tlvKemShare, kemShare)
        tr.addFrameType(Handshake.frameServerHello)
        tr.addTlv(tlvProfileSelect, [UInt8(profileStandard)])
        tr.addTlv(tlvKemSelect, u16list([Npamp.kemX25519MlKem768]))
        tr.addTlv(tlvSigSelect, u16list([Npamp.sigEd25519]))
        tr.addTlv(tlvAeadSelect, u16list([Npamp.aeadAes256Gcm]))
        tr.addTlv(tlvKemCiphertext, kemCt)
        let thKem = tr.hash(true)
        try check(toHex(thKem) == (try str(transcript, "th_kem")), "th_kem != expected")

        // handshake_secret / c_hs / s_hs through the real ladder (ML-KEM-first IKM).
        let hs = Npamp.deriveHandshakeSecret(mlkemSS, xSS, true)
        try check(toHex(hs) == (try str(secrets, "handshake_secret")), "handshake_secret != expected")
        let cHs = Npamp.deriveClientHandshakeSecret(hs, thKem, true)
        try check(toHex(cHs) == (try str(secrets, "c_hs_secret")), "c_hs_secret != expected")
        let sHs = Npamp.deriveServerHandshakeSecret(hs, thKem, true)
        try check(toHex(sHs) == (try str(secrets, "s_hs_secret")), "s_hs_secret != expected")

        // --- SERVER_AUTH. ---
        tr.addFrameType(Handshake.frameServerAuth)
        tr.addTlv(tlvIdentityKey, serverPub)
        let thSid = tr.hash(true)
        try check(toHex(thSid) == (try str(transcript, "th_sid")), "th_sid != expected")
        let sCv = try Handshake.signCertVerify(serverPrivKey, isServer: true, transcriptHash: thSid)
        try check(toHex(sCv) == (try str(certVerify, "server")), "server cert_verify != expected")
        try check(Handshake.verifyCertVerify(serverPubKey, isServer: true, transcriptHash: thSid, value: sCv),
                  "server CertVerify rejected")
        tr.addTlv(tlvCertVerify, sCv)
        let thScv = tr.hash(true)
        try check(toHex(thScv) == (try str(transcript, "th_scv")), "th_scv != expected")
        let sFinKey = Npamp.deriveFinishedKey(sHs, true)
        try check(toHex(sFinKey) == (try str(finishedKeys, "server")), "server finished_key != expected")
        let sFin = Handshake.computeFinished(sFinKey, thScv, true)
        try check(toHex(sFin) == (try str(finished, "server")), "server finished != expected")
        tr.addTlv(tlvFinished, sFin)
        let serverAuthPlain = tlv(tlvIdentityKey, serverPub) + tlv(tlvCertVerify, sCv) + tlv(tlvFinished, sFin)
        try check(serverAuthPlain == (try hexBytes(authPlaintext, "server_auth")),
                  "SERVER_AUTH plaintext != expected")
        let serverAuthFrame = try sealAuthFrame(Handshake.frameServerAuth, sHs, dirS2C, serverAuthPlain)
        try check(serverAuthFrame == (try hexBytes(frames, "server_auth")), "SERVER_AUTH frame != expected")

        // --- CLIENT_AUTH. ---
        tr.addFrameType(Handshake.frameClientAuth)
        tr.addTlv(tlvIdentityKey, clientPub)
        let thCid = tr.hash(true)
        try check(toHex(thCid) == (try str(transcript, "th_cid")), "th_cid != expected")
        let cCv = try Handshake.signCertVerify(clientPrivKey, isServer: false, transcriptHash: thCid)
        try check(toHex(cCv) == (try str(certVerify, "client")), "client cert_verify != expected")
        try check(Handshake.verifyCertVerify(clientPubKey, isServer: false, transcriptHash: thCid, value: cCv),
                  "client CertVerify rejected")
        tr.addTlv(tlvCertVerify, cCv)
        let thCcv = tr.hash(true)
        try check(toHex(thCcv) == (try str(transcript, "th_ccv")), "th_ccv != expected")
        let cFinKey = Npamp.deriveFinishedKey(cHs, true)
        try check(toHex(cFinKey) == (try str(finishedKeys, "client")), "client finished_key != expected")
        let cFin = Handshake.computeFinished(cFinKey, thCcv, true)
        try check(toHex(cFin) == (try str(finished, "client")), "client finished != expected")
        let clientAuthPlain = tlv(tlvIdentityKey, clientPub) + tlv(tlvCertVerify, cCv) + tlv(tlvFinished, cFin)
        try check(clientAuthPlain == (try hexBytes(authPlaintext, "client_auth")),
                  "CLIENT_AUTH plaintext != expected")
        let clientAuthFrame = try sealAuthFrame(Handshake.frameClientAuth, cHs, dirC2S, clientAuthPlain)
        try check(clientAuthFrame == (try hexBytes(frames, "client_auth")), "CLIENT_AUTH frame != expected")

        // --- master_secret binds th_ccv (real ladder). ---
        let master = Npamp.deriveMasterSecret(hs, thCcv, true)
        try check(toHex(master) == (try str(secrets, "master_secret")), "master_secret != expected")

        // --- Traffic secret/key/iv for both handshake directions and both application directions. ---
        func assertTraffic(_ name: String, _ parent: [UInt8], _ direction: Int,
                           _ tsHex: String, _ keyHex: String, _ ivHex: String) throws {
            let ts = Npamp.deriveTrafficSecret(parent, direction, 0, Npamp.aeadAes256Gcm, Npamp.chanControl, true)
            try check(toHex(ts) == tsHex, "\(name)_traffic_secret != expected")
            let keyIv = Npamp.deriveKeyIv(ts, true)
            try check(toHex(keyIv.key) == keyHex, "\(name)_key != expected")
            try check(toHex(keyIv.iv) == ivHex, "\(name)_iv != expected")
        }
        try assertTraffic("c_hs", cHs, dirC2S,
                          try str(secrets, "c_hs_traffic_secret"), try str(secrets, "c_hs_key"), try str(secrets, "c_hs_iv"))
        try assertTraffic("s_hs", sHs, dirS2C,
                          try str(secrets, "s_hs_traffic_secret"), try str(secrets, "s_hs_key"), try str(secrets, "s_hs_iv"))
        try assertTraffic("app_c2s", master, dirC2S,
                          try str(secrets, "app_c2s_traffic_secret"), try str(secrets, "app_c2s_key"), try str(secrets, "app_c2s_iv"))
        try assertTraffic("app_s2c", master, dirS2C,
                          try str(secrets, "app_s2c_traffic_secret"), try str(secrets, "app_s2c_key"), try str(secrets, "app_s2c_iv"))

        // --- Mutation guard 1: a one-octet flip of the server CertVerify signature must REJECT. ---
        var badCv = sCv
        badCv[badCv.count - 1] ^= 0x01  // flip the last signature octet
        try check(!Handshake.verifyCertVerify(serverPubKey, isServer: true, transcriptHash: thSid, value: badCv),
                  "mutation guard: a one-octet-flipped server CertVerify signature VERIFIED")

        // --- Mutation guard 2: a one-octet flip of the client Finished MAC must REJECT. ---
        var badFin = cFin
        badFin[0] ^= 0x01
        try check(!Handshake.verifyFinished(cFinKey, thCcv, badFin, true),
                  "mutation guard: a one-octet-flipped client Finished MAC VERIFIED")

        // --- Sanity: the untouched signature and MAC still verify. ---
        try check(Handshake.verifyCertVerify(serverPubKey, isServer: true, transcriptHash: thSid, value: sCv),
                  "unmutated server CertVerify rejected")
        try check(Handshake.verifyFinished(cFinKey, thCcv, cFin, true),
                  "unmutated client Finished rejected")
    }
} catch {
    failures += 1
    print("FAIL handshake_flow_kat (vector load): \(error)")
}

// Tracked SKIP — never silently green: swift-crypto 3.15.1's Crypto product exposes no ML-KEM API,
// so the pinned ML-KEM ciphertext cannot be decapsulated in Swift (same deferral as Go/ADR-0007 and
// the Python module). The X25519 half of the pinned ciphertext IS decapsulated (leg above); only the
// ML-KEM half is deferred. mlkem_shared_secret is a pinned self-validating input.
skipLeg("handshake_flow_kat_mlkem_decapsulation",
        "swift-crypto 3.15.1's Crypto product exposes no ML-KEM API (verified against the pinned "
            + "checkout), so the pinned ML-KEM ciphertext cannot be decapsulated to mlkem_shared_secret; "
            + "consumed as a pinned self-validating input (same deferral as Go ADR-0007 and the Python module)")

// ---------------------------------------------------------------------------
// Summary — 'ALL PASS' is the positive gate token, printed ONLY when every expected executable leg
// ran and passed (zero-KAT protection).
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
