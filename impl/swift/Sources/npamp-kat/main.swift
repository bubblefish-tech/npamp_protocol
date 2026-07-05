// Independent crypto KAT: drive N-PAMP's AES-256-GCM seal/open through Google/C2SP
// Project Wycheproof vectors (flat corpus _shared/wycheproof/aesgcm_kat.tsv passed as argv[1]).
// seq=0 so the derived nonce equals the given IV — exercises the real seal/open path.
import Foundation
import Npamp

let args = CommandLine.arguments
guard args.count >= 2 else {
    FileHandle.standardError.write(Data("usage: npamp-kat <tsv>\n".utf8)); exit(2)
}
guard let content = try? String(contentsOfFile: args[1], encoding: .utf8) else {
    FileHandle.standardError.write(Data("cannot read \(args[1])\n".utf8)); exit(2)
}

var total = 0, passed = 0
var fails: [String] = []
// Split on any newline (Character.isNewline matches the CRLF grapheme too — Swift treats
// "\r\n" as a single Character, so split(separator: "\n") would NOT split a CRLF file).
for raw in content.split(whereSeparator: { $0.isNewline }) {
    let line = String(raw)
    if line.isEmpty || line.hasPrefix("#") { continue }
    let cols = line.components(separatedBy: "\t")
    if cols.count < 8 { continue }
    let tc = cols[0], result = cols[1]
    let key = Npamp.fromHex(cols[2]), iv = Npamp.fromHex(cols[3]), aad = Npamp.fromHex(cols[4])
    let msg = Npamp.fromHex(cols[5])
    let sealed = Npamp.fromHex(cols[6]) + Npamp.fromHex(cols[7])
    var ok = true, reason = ""
    if result == "valid" {
        if (try? Npamp.sealAes256Gcm(key, iv, 0, aad, msg)) != sealed { ok = false; reason = "encrypt mismatch" }
        else if (try? Npamp.openAes256Gcm(key, iv, 0, aad, sealed)) != msg { ok = false; reason = "decrypt mismatch" }
    } else if result == "invalid" {
        if (try? Npamp.openAes256Gcm(key, iv, 0, aad, sealed)) != nil { ok = false; reason = "accepted invalid" }
    } else { // acceptable
        if let p = try? Npamp.openAes256Gcm(key, iv, 0, aad, sealed), p != msg { ok = false; reason = "acceptable wrong" }
    }
    total += 1
    if ok { passed += 1 } else { fails.append("tcId=\(tc) result=\(result): \(reason)") }
}

print("AES-256-GCM Wycheproof KAT (swift): \(passed)/\(total) passed")
for f in fails.prefix(15) { print("  FAIL \(f)") }
exit(fails.isEmpty && total > 0 ? 0 : 1)
