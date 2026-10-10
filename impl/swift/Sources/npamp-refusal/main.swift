// Behaviour check, not a conformance vector: the open Swift module implements the Standard
// profile only, so every key-schedule, transcript and Finished primitive refuses a non-Standard
// profile with Npamp.NoSuiteForProfile and still succeeds at Standard. No external authority
// (RFC or FIPS) defines this module's scope. Exits 0 on success, 1 if any check fails.
import Foundation
import Npamp

var failures = 0
func check(_ name: String, _ ok: Bool) {
    if ok { print("ok   - \(name)") } else { print("FAIL - \(name)"); failures += 1 }
}

func refused(_ name: String, _ body: () throws -> Void) {
    var threw = false
    do { try body() } catch is Npamp.NoSuiteForProfile { threw = true } catch {
        print("     wrong error for \(name): \(error)")
    }
    check("non-standard refused: \(name)", threw)
}

let secret = [UInt8](repeating: 0x11, count: 32)
let th = [UInt8](repeating: 0x22, count: 32)
let zero32 = [UInt8](repeating: 0, count: 32)
let zero48 = [UInt8](repeating: 0, count: 48)

do {
    check("standard control: hkdfExtract", try Npamp.hkdfExtract(zero32, secret, true).count == 32)
    check("standard control: deriveTrafficSecret",
          try Npamp.deriveTrafficSecret(secret, 0, 0, Npamp.aeadAes256Gcm, Npamp.chanControl, true).count == 32)
    let ki = try Npamp.deriveKeyIv(secret, true)
    check("standard control: deriveKeyIv", ki.key.count == 32 && ki.iv.count == 12)
    check("standard control: deriveHandshakeSecret", try Npamp.deriveHandshakeSecret(secret, secret, true).count == 32)
    check("standard control: deriveFinishedKey", try Npamp.deriveFinishedKey(secret, true).count == 32)
    check("standard control: hkdfExpand sha256",
          try Npamp.hkdfExpand(hash: "sha256", prk: secret, info: [1], length: 32).count == 32)
    check("standard control: transcript hash", try Handshake.Transcript().hash(true).count == 32)
    let mac = try Handshake.computeFinished(secret, th, true)
    check("standard control: finished verifies", try Handshake.verifyFinished(secret, th, mac, true))
} catch {
    print("FAIL - standard control threw: \(error)")
    failures += 1
}

refused("hkdfExtract") { _ = try Npamp.hkdfExtract(zero48, secret, false) }
refused("hkdfExpand sha512") { _ = try Npamp.hkdfExpand(hash: "sha512", prk: secret, info: [1], length: 48) }
refused("hkdfExpandLabel") { _ = try Npamp.hkdfExpandLabel(secret, "key", [], 32, false) }
refused("deriveTrafficSecret") {
    _ = try Npamp.deriveTrafficSecret(secret, 0, 0, Npamp.aeadAes256Gcm, Npamp.chanControl, false)
}
refused("deriveKeyIv") { _ = try Npamp.deriveKeyIv(secret, false) }
refused("deriveHandshakeSecret") { _ = try Npamp.deriveHandshakeSecret(secret, secret, false) }
refused("deriveClientHandshakeSecret") { _ = try Npamp.deriveClientHandshakeSecret(secret, th, false) }
refused("deriveServerHandshakeSecret") { _ = try Npamp.deriveServerHandshakeSecret(secret, th, false) }
refused("deriveMasterSecret") { _ = try Npamp.deriveMasterSecret(secret, th, false) }
refused("deriveFinishedKey") { _ = try Npamp.deriveFinishedKey(secret, false) }
refused("Transcript.hash") { _ = try Handshake.Transcript().hash(false) }
refused("computeFinished") { _ = try Handshake.computeFinished(secret, th, false) }
refused("verifyFinished") { _ = try Handshake.verifyFinished(secret, th, th, false) }

if failures == 0 { print("ALL PASS") } else { print("FAILURES: \(failures)") }
exit(failures == 0 ? 0 : 1)
