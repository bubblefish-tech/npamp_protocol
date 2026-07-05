// Emits the canonical draft-00 OPEN-layer test vectors as JSON on stdout (UTF-8, LF).
import Foundation
import Npamp

func ramp(_ start: Int, _ count: Int) -> [UInt8] { (0..<count).map { UInt8((start + $0) & 0xFF) } }

let header = Npamp.toHex(Npamp.Frame(ftype: Npamp.framePing, channel: Npamp.chanControl).marshal())
let nonce = Npamp.toHex(Npamp.deriveNonce(ramp(0x01, 12), 0x0102_0304_0506_0708))
let aad = Npamp.Frame(ftype: Npamp.framePing, channel: Npamp.chanControl).headerPrefix(11)
let aead = Npamp.toHex(try! Npamp.sealAes256Gcm(ramp(0x00, 32), ramp(0x10, 12), 7, aad, Array("hello world".utf8)))
let secret = Npamp.deriveTrafficSecret([UInt8](repeating: 0x2A, count: 48), 0, 0,
                                       Npamp.aeadAes256Gcm, Npamp.chanControl, false)
let traffic = Npamp.toHex(Npamp.deriveKeyIv(secret, false).key)

var s = "{\n"
s += "  \"spec\": \"draft-bubblefish-npamp-00\",\n"
s += "  \"header_ping_control_seq0\": \"\(header)\",\n"
s += "  \"nonce_iv1to12_seq0102\": \"\(nonce)\",\n"
s += "  \"aes256gcm_seal_helloworld\": \"\(aead)\",\n"
s += "  \"traffic_key_sha384\": \"\(traffic)\"\n"
s += "}\n"
FileHandle.standardOutput.write(Data(s.utf8))
