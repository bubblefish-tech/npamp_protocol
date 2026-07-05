// Runnable example: the draft-00 secure record layer, end to end.
//
// Composes the OPEN-protocol primitives this port provides — the HKDF key schedule, the
// AES-256-GCM record layer, and the 36-octet frame codec — into one send -> receive round-trip
// over an in-memory "wire". Mirrors the Go reference's Example_secureRecordLayer
// (impl/go/example_test.go).
//
// The master secret is a fixed demo value; in a live session it is the handshake output (binding
// spec/10 section 5). Standard profile only (SHA-256, AES-256-GCM). Build + run from impl/swift:
//
//   bash run.sh example
//
// (run.sh builds the package with the SwiftPM scratch dir kept out of the source tree)
import Foundation
import Npamp

/// Direction octet (draft-00 7.5): client-to-server = 0.
let dirClientToServer = 0

do {
    // 1. Key schedule: derive a per-(direction, channel, suite) traffic key + IV from the master
    //    secret. In a live session the master secret is the handshake output; here it is fixed.
    let master = [UInt8](repeating: 0x2B, count: 32)
    let ts = Npamp.deriveTrafficSecret(master, dirClientToServer, 0, Npamp.aeadAes256Gcm, Npamp.chanMemory, true)
    let (key, iv) = Npamp.deriveKeyIv(ts, true)

    // 2. Sender: seal an application payload into an AEAD-protected frame on the Memory channel.
    //    The AEAD associated data is the 21-octet header prefix, so the ciphertext is bound to
    //    the frame's type/channel/seq/length — a tampered header makes the open fail.
    let appType = 0x0120 // application frame type (app-defined; this port is wire-only)
    let plaintext = Array("hello over n-pamp".utf8)
    let seq: UInt64 = 0
    var out = Npamp.Frame(ftype: appType, channel: Npamp.chanMemory, seq: seq, flags: Npamp.flagEnc)
    let aad = out.headerPrefix(plaintext.count + 16) // +16 = AES-256-GCM authentication tag
    out.payload = try Npamp.sealAes256Gcm(key, iv, seq, aad, plaintext)
    let wire = out.marshal()

    // 3. ... the `wire` bytes travel over any transport (the consumer supplies TCP/TLS) ...

    // 4. Receiver: parse the frame (validates CRC32C/magic/version) and open the payload under
    //    the same key/seq and the reconstructed header-prefix AAD.
    let inc = try Npamp.Frame.unmarshal(wire)
    let raad = inc.headerPrefix(inc.payload.count)
    let opened = try Npamp.openAes256Gcm(key, iv, inc.seq, raad, inc.payload)

    print("channel=\(inc.channel) seq=\(inc.seq) encrypted=\((inc.flags & Npamp.flagEnc) != 0)")
    print("recovered: \(String(decoding: opened, as: UTF8.self))")
    exit(opened == plaintext ? 0 : 1)
} catch {
    FileHandle.standardError.write(Data("example failed: \(error)\n".utf8))
    exit(1)
}
