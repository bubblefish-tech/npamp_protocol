// Open reference implementation of the N-PAMP wire format (draft-bubblefish-npamp-00).
// OPEN protocol layer only: framing, registries, AEAD record layer, key schedule.
// No proprietary methods, parameters, or weights. Big-endian throughout.
// Crypto via swift-crypto (AES-256-GCM, HKDF) — portable across Linux and Apple.
import Foundation
import Crypto

public enum Npamp {

    // -- Constants ---------------------------------------------------------

    public static let headerSize = 36
    public static let protocolVersion: Int = 0x2
    public static let magic: [UInt8] = [0x4E, 0x50, 0x41, 0x4D] // "NPAM"
    public static let alpn = "n-pamp/3"
    public static let labelPrefix = "n-pamp " // protocol-specific; NOT "tls13 "

    public static let flagUrg = 0x01, flagEnc = 0x02, flagComp = 0x04, flagFrag = 0x08
    public static let chanControl = 0x0000, chanMemory = 0x0001, chanImmune = 0x0005,
                      chanAudit = 0x000B, chanBridge = 0x000D, chanSpatial = 0x0013
    public static let framePing = 0x0001, framePong = 0x0002, frameClose = 0x0003,
                      frameFlowUpdate = 0x000A, channelSpecificBase = 0x0100
    public static let aeadAes256Gcm = 0x0001, aeadChacha20Poly1305 = 0x0002
    public static let kemX25519MlKem768 = 0x11EC, kemX25519MlKem1024 = 0x11ED
    public static let sigEd25519 = 0x0807, sigMlDsa87 = 0x0906

    public struct FrameError: Error, Equatable {
        public let message: String
        public init(_ m: String) { message = m }
    }

    /// The Standard profile hash length (SHA-256).
    public static let hashLen = 32

    /// Thrown when a profile other than Standard is requested. This module implements the
    /// Standard profile only; High and Sovereign are refused, before any I/O, with this error.
    public struct NoSuiteForProfile: Error, Equatable, CustomStringConvertible {
        public var description: String {
            "no cipher suite for this profile: only the Standard profile is implemented"
        }
        public init() {}
    }

    /// Throws `NoSuiteForProfile` unless `standard` is true.
    static func requireStandard(_ standard: Bool) throws {
        if !standard { throw NoSuiteForProfile() }
    }

    // -- CRC32C (Castagnoli, reflected) ------------------------------------

    public static func crc32c(_ data: [UInt8]) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for b in data {
            crc ^= UInt32(b)
            for _ in 0..<8 {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0x82F6_3B78 : crc >> 1
            }
        }
        return crc ^ 0xFFFF_FFFF
    }

    // -- Big-endian helpers ------------------------------------------------

    static func u16be(_ v: Int) -> [UInt8] { [UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)] }
    static func u32be(_ v: UInt32) -> [UInt8] {
        [UInt8((v >> 24) & 0xFF), UInt8((v >> 16) & 0xFF), UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)]
    }
    static func u64be(_ v: UInt64) -> [UInt8] { (0..<8).map { UInt8((v >> (56 - 8 * $0)) & 0xFF) } }

    // -- Frame -------------------------------------------------------------

    public struct Frame {
        public var version: Int = 0
        public var flags: Int = 0
        public var ftype: Int = 0
        public var channel: Int = 0
        public var seq: UInt64 = 0
        public var payload: [UInt8] = []

        public init(ftype: Int = 0, channel: Int = 0, seq: UInt64 = 0,
                    flags: Int = 0, version: Int = 0, payload: [UInt8] = []) {
            self.ftype = ftype; self.channel = channel; self.seq = seq
            self.flags = flags; self.version = version; self.payload = payload
        }

        /// 21-octet prefix = MAGIC | (version<<4)|flags | u16 ftype | u16 channel | u64 seq | u32 payloadLen.
        /// version 0 substitutes the protocol default (0x2). This prefix is exactly the AEAD AAD.
        public func headerPrefix(_ payloadLen: Int) -> [UInt8] {
            let ver = version != 0 ? version : Npamp.protocolVersion
            var o = [UInt8]()
            o.append(contentsOf: Npamp.magic)
            o.append(UInt8(((ver << 4) | (flags & 0x0F)) & 0xFF))
            o.append(contentsOf: Npamp.u16be(ftype))
            o.append(contentsOf: Npamp.u16be(channel))
            o.append(contentsOf: Npamp.u64be(seq))
            o.append(contentsOf: Npamp.u32be(UInt32(payloadLen)))
            return o
        }

        /// prefix || CRC32C(prefix) || 11 zero octets || payload.
        public func marshal() -> [UInt8] {
            let prefix = headerPrefix(payload.count)
            var o = prefix
            o.append(contentsOf: Npamp.u32be(Npamp.crc32c(prefix)))
            o.append(contentsOf: [UInt8](repeating: 0, count: 11))
            o.append(contentsOf: payload)
            return o
        }

        /// Validation order: CRC32C, magic, version, reserved-zero, payload-length.
        public static func unmarshal(_ buf: [UInt8]) throws -> Frame {
            if buf.count < Npamp.headerSize { throw FrameError("short header") }
            let got = (UInt32(buf[21]) << 24) | (UInt32(buf[22]) << 16) | (UInt32(buf[23]) << 8) | UInt32(buf[24])
            if got != Npamp.crc32c(Array(buf[0..<21])) { throw FrameError("bad crc") }
            for i in 0..<4 where buf[i] != Npamp.magic[i] { throw FrameError("bad magic") }
            let ver = Int(buf[4] >> 4)
            if ver != Npamp.protocolVersion { throw FrameError("bad version") }
            for i in 25..<Npamp.headerSize where buf[i] != 0 { throw FrameError("reserved nonzero") }
            let plen = Int((UInt32(buf[17]) << 24) | (UInt32(buf[18]) << 16) | (UInt32(buf[19]) << 8) | UInt32(buf[20]))
            if plen != buf.count - Npamp.headerSize { throw FrameError("length mismatch") }
            var f = Frame()
            f.version = ver
            f.flags = Int(buf[4] & 0x0F)
            f.ftype = Int(buf[5]) << 8 | Int(buf[6])
            f.channel = Int(buf[7]) << 8 | Int(buf[8])
            var s: UInt64 = 0
            for i in 9..<17 { s = (s << 8) | UInt64(buf[i]) }
            f.seq = s
            f.payload = Array(buf[Npamp.headerSize...])
            return f
        }
    }

    // -- AEAD record layer -------------------------------------------------

    /// 12-octet nonce: seq as u64 BE in bytes[4..12], XOR the 12-octet IV. No channel.
    public static func deriveNonce(_ iv: [UInt8], _ seq: UInt64) -> [UInt8] {
        var n = [UInt8](repeating: 0, count: 12)
        let s = u64be(seq)
        for i in 0..<8 { n[4 + i] = s[i] }
        for i in 0..<12 { n[i] ^= iv[i] }
        return n
    }

    /// AES-256-GCM seal. Returns ciphertext||tag (16-octet tag); AAD is the 21-octet header prefix.
    public static func sealAes256Gcm(_ key: [UInt8], _ iv: [UInt8], _ seq: UInt64,
                                     _ aad: [UInt8], _ pt: [UInt8]) throws -> [UInt8] {
        let nonce = try AES.GCM.Nonce(data: deriveNonce(iv, seq))
        let box = try AES.GCM.seal(pt, using: SymmetricKey(data: key), nonce: nonce, authenticating: aad)
        return [UInt8](box.ciphertext) + [UInt8](box.tag)
    }

    /// AES-256-GCM open. Accepts ciphertext||tag; throws on authentication failure.
    public static func openAes256Gcm(_ key: [UInt8], _ iv: [UInt8], _ seq: UInt64,
                                     _ aad: [UInt8], _ sealed: [UInt8]) throws -> [UInt8] {
        if sealed.count < 16 { throw FrameError("short sealed") }
        let ct = Array(sealed[0..<(sealed.count - 16)])
        let tag = Array(sealed[(sealed.count - 16)...])
        let nonce = try AES.GCM.Nonce(data: deriveNonce(iv, seq))
        let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ct, tag: tag)
        return [UInt8](try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: aad))
    }

    // -- Key schedule (HKDF-Expand-Label) ----------------------------------

    /// RFC 5869 §2.3 HKDF-Expand over an arbitrary `info`. The supplied secret IS the PRK.
    /// `hash` names the underlying HMAC hash; only "sha256" is implemented, any other name throws
    /// `NoSuiteForProfile`. This is the exact primitive `hkdfExpandLabel`/the key schedule build on,
    /// exposed for KAT/conformance drivers that supply a raw (unlabelled) `info`. Returns the first
    /// `length` OKM octets.
    public static func hkdfExpand(hash: String, prk: [UInt8], info: [UInt8], length: Int) throws -> [UInt8] {
        try hkdfExpand(hash == "sha256", prk, info, length)
    }

    // HKDF-Expand only (RFC 5869 2.3); the supplied secret IS the PRK. SHA-256; throws
    // NoSuiteForProfile unless standard.
    static func hkdfExpand(_ standard: Bool, _ prk: [UInt8], _ info: [UInt8], _ length: Int) throws -> [UInt8] {
        try requireStandard(standard)
        let key = SymmetricKey(data: prk)
        return HKDF<SHA256>.expand(pseudoRandomKey: key, info: info, outputByteCount: length)
            .withUnsafeBytes { Array($0) }
    }

    /// HKDF-Extract (RFC 5869 §2.2): PRK = HMAC-SHA-256(salt, IKM). Throws `NoSuiteForProfile`
    /// unless `standard`. RFC 5869 treats an empty salt as HashLen zero
    /// octets (normalized here); the binding always passes an explicit
    /// HashLen-octet zero salt (spec/10 §5).
    public static func hkdfExtract(_ salt: [UInt8], _ ikm: [UInt8], _ standard: Bool) throws -> [UInt8] {
        try requireStandard(standard)
        let s = salt.isEmpty ? [UInt8](repeating: 0, count: hashLen) : salt
        return Array(HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: ikm), salt: s))
    }

    /// HKDF-Expand-Label: full = labelPrefix + label;
    /// info = u16(length) || u8(len(full)) || full || u8(len(context)) || context.
    public static func hkdfExpandLabel(_ secret: [UInt8], _ label: String, _ context: [UInt8],
                                       _ length: Int, _ standard: Bool) throws -> [UInt8] {
        try requireStandard(standard)
        let full = Array((labelPrefix + label).utf8)
        var info = [UInt8]()
        info.append(UInt8((length >> 8) & 0xFF))
        info.append(UInt8(length & 0xFF))
        info.append(UInt8(full.count))
        info.append(contentsOf: full)
        info.append(UInt8(context.count))
        info.append(contentsOf: context)
        return try hkdfExpand(standard, secret, info, length)
    }

    /// context = dir(1) || epoch(8 BE) || suite(2 BE) || channel(2 BE); label "traffic"; len 32 (SHA-256).
    public static func deriveTrafficSecret(_ master: [UInt8], _ dir: Int, _ epoch: UInt64,
                                           _ suite: Int, _ channel: Int, _ standard: Bool) throws -> [UInt8] {
        try requireStandard(standard)
        var ctx = [UInt8]()
        ctx.append(UInt8(dir))
        ctx.append(contentsOf: u64be(epoch))
        ctx.append(contentsOf: u16be(suite))
        ctx.append(contentsOf: u16be(channel))
        return try hkdfExpandLabel(master, "traffic", ctx, hashLen, standard)
    }

    /// {key(32), iv(12)} from a traffic secret.
    public static func deriveKeyIv(_ secret: [UInt8], _ standard: Bool) throws -> (key: [UInt8], iv: [UInt8]) {
        (try hkdfExpandLabel(secret, "key", [], 32, standard), try hkdfExpandLabel(secret, "iv", [], 12, standard))
    }

    // -- Handshake-secret ladder (binding spec/10 §5) ------------------------

    /// Derives the binding handshake_secret (spec/10 §5; ML-KEM-first). The two inputs are the raw shared secrets from each KEM
    /// component; the combined IKM places the ML-KEM shared secret FIRST, then
    /// the X25519 shared secret. handshake_secret = HKDF-Extract(salt = HashLen
    /// zero octets, IKM). At the Standard profile HashLen is 32.
    public static func deriveHandshakeSecret(_ mlkemSharedSecret: [UInt8],
                                             _ x25519SharedSecret: [UInt8],
                                             _ standard: Bool) throws -> [UInt8] {
        try requireStandard(standard)
        let salt = [UInt8](repeating: 0, count: hashLen)
        return try hkdfExtract(salt, mlkemSharedSecret + x25519SharedSecret, standard)
    }

    /// c_hs = HKDF-Expand-Label(handshake_secret, "c hs", TH_kem, HashLen) (spec/10 §5).
    public static func deriveClientHandshakeSecret(_ handshakeSecret: [UInt8], _ thKem: [UInt8],
                                                   _ standard: Bool) throws -> [UInt8] {
        try hkdfExpandLabel(handshakeSecret, "c hs", thKem, hashLen, standard)
    }

    /// s_hs = HKDF-Expand-Label(handshake_secret, "s hs", TH_kem, HashLen) (spec/10 §5).
    public static func deriveServerHandshakeSecret(_ handshakeSecret: [UInt8], _ thKem: [UInt8],
                                                   _ standard: Bool) throws -> [UInt8] {
        try hkdfExpandLabel(handshakeSecret, "s hs", thKem, hashLen, standard)
    }

    /// master = HKDF-Expand-Label(handshake_secret, "master", TH_cCV, HashLen) (spec/10 §5).
    public static func deriveMasterSecret(_ handshakeSecret: [UInt8], _ thCcv: [UInt8],
                                          _ standard: Bool) throws -> [UInt8] {
        try hkdfExpandLabel(handshakeSecret, "master", thCcv, hashLen, standard)
    }

    /// Derives a Finished key (spec/10 §6.2): finished_key(secret) =
    /// HKDF-Expand-Label(secret, "finished", "", HashLen). The client Finished
    /// key derives from c_hs; the server Finished key derives from s_hs.
    public static func deriveFinishedKey(_ secret: [UInt8], _ standard: Bool) throws -> [UInt8] {
        try hkdfExpandLabel(secret, "finished", [], hashLen, standard)
    }

    // -- Hex utility -------------------------------------------------------

    public static func toHex(_ data: [UInt8]) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    public static func fromHex(_ s: String) -> [UInt8] {
        var out = [UInt8]()
        var idx = s.startIndex
        while idx < s.endIndex {
            let next = s.index(idx, offsetBy: 2)
            out.append(UInt8(s[idx..<next], radix: 16)!)
            idx = next
        }
        return out
    }
}
