// Conformance test for the N-PAMP Swift reference. Mirrors the Go/Rust/Java/etc. suites.
// Exits 0 on success, 1 if any check fails.
import Foundation
import Npamp

var failures = 0
func check(_ name: String, _ ok: Bool) {
    if ok { print("ok   - \(name)") } else { print("FAIL - \(name)"); failures += 1 }
}
func ramp(_ start: Int, _ count: Int) -> [UInt8] { (0..<count).map { UInt8((start + $0) & 0xFF) } }

check("vec_header", Npamp.toHex(Npamp.Frame(ftype: Npamp.framePing, channel: Npamp.chanControl).marshal())
    == "4e50414d20000100000000000000000000000000000d880c250000000000000000000000")
check("vec_nonce", Npamp.toHex(Npamp.deriveNonce(ramp(0x01, 12), 0x0102_0304_0506_0708)) == "010203040404040c0c0c0c04")
let aad = Npamp.Frame(ftype: Npamp.framePing, channel: Npamp.chanControl).headerPrefix(11)
check("vec_aead", Npamp.toHex(try! Npamp.sealAes256Gcm(ramp(0x00, 32), ramp(0x10, 12), 7, aad, Array("hello world".utf8)))
    == "3fe8b79f95b5697926b3395429c2c2466999c652f9346aeebb30bf")
let secret = Npamp.deriveTrafficSecret([UInt8](repeating: 0x2A, count: 48), 0, 0,
                                       Npamp.aeadAes256Gcm, Npamp.chanControl, false)
check("vec_traffic_key", Npamp.toHex(Npamp.deriveKeyIv(secret, false).key)
    == "79372e2fb7f92d63e3a68099ff72514f310ebf6773deb0fa7ef45d013c652dcc")

// roundtrip
let f = Npamp.Frame(ftype: 0x0100, channel: Npamp.chanMemory, seq: 42, flags: Npamp.flagEnc, payload: Array("payload".utf8))
let g = try! Npamp.Frame.unmarshal(f.marshal())
check("roundtrip", g.flags == Npamp.flagEnc && g.ftype == 0x0100 && g.channel == Npamp.chanMemory
    && g.seq == 42 && g.payload == Array("payload".utf8))

// crc_validated_first
var buf = Npamp.Frame(ftype: Npamp.framePing, channel: Npamp.chanControl).marshal()
buf[5] ^= 0xFF
var crcRejected = false
do { _ = try Npamp.Frame.unmarshal(buf) } catch let e as Npamp.FrameError { crcRejected = (e.message == "bad crc") } catch {}
check("crc_validated_first", crcRejected)

// reserved_must_be_zero
var buf2 = Npamp.Frame(ftype: Npamp.framePing, channel: Npamp.chanControl).marshal()
buf2[30] = 1
var resRejected = false
do { _ = try Npamp.Frame.unmarshal(buf2) } catch let e as Npamp.FrameError { resRejected = (e.message == "bad crc" || e.message == "reserved nonzero") } catch {}
check("reserved_must_be_zero", resRejected)

// aead_tamper_fails
let key = [UInt8](repeating: 0, count: 32)
let iv = ramp(0x10, 12)
var aad2 = Npamp.Frame(ftype: Npamp.framePing, channel: Npamp.chanControl).headerPrefix(5)
let sealed = try! Npamp.sealAes256Gcm(key, iv, 7, aad2, Array("hello".utf8))
var openOk = false
if let opened = try? Npamp.openAes256Gcm(key, iv, 7, aad2, sealed) { openOk = (opened == Array("hello".utf8)) }
aad2[5] ^= 1
var tamperRejected = false
do { _ = try Npamp.openAes256Gcm(key, iv, 7, aad2, sealed) } catch { tamperRejected = true }
check("aead_tamper_fails", openOk && tamperRejected)

check("hkdf_prefix_protocol_specific", Npamp.labelPrefix == "n-pamp " && Npamp.labelPrefix != "tls13 ")

print(failures == 0 ? "ALL PASS (9/9)" : "FAILURES: \(failures)")
exit(failures == 0 ? 0 : 1)
