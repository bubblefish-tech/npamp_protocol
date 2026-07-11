// Handshake binding layer for the N-PAMP wire format (draft-bubblefish-npamp-00).
// OPEN protocol layer only: the transcript construction (spec/10 §3), the
// X25519MLKEM768 KEM wire layout (spec/10 §4; ML-KEM-first per ADR-0005), the
// Finished MAC (spec/10 §6.2), and the CertVerify signature (spec/10 §6.1).
// No proprietary methods, parameters, or weights.
//
// Pure-Swift sibling of Npamp.swift. Crypto via swift-crypto: SHA-256/SHA-384
// digests, HMAC, and Curve25519.Signing (Ed25519). On Linux swift-crypto backs
// Ed25519 with BoringSSL's ED25519_sign, which is RFC 8032-deterministic; Apple
// CryptoKit randomizes Ed25519 signatures, which the deterministic-equality KAT
// legs detect and fail loud on (npamp-handshake-kat).
import Foundation
import Crypto

/// N-PAMP draft-00 handshake binding (spec/10): transcript, KEM wire layout,
/// Finished, CertVerify. Big-endian throughout.
public enum Handshake {

    // -- Constants ---------------------------------------------------------

    // Handshake frame types (spec/10 §1), carried on the control channel.
    public static let frameClientHello = 0x0100
    public static let frameServerHello = 0x0101
    public static let frameServerAuth = 0x0102
    public static let frameClientAuth = 0x0103

    // CertVerify context strings (spec/10 §6.1).
    public static let contextServerCertVerify = "N-PAMP/2, server CertificateVerify"
    public static let contextClientCertVerify = "N-PAMP/2, client CertificateVerify"

    // X25519MLKEM768 component sizes (spec/10 §4; FIPS 203 / RFC 7748).
    public static let mlkem768EncapsulationKeySize = 1184
    public static let mlkem768CiphertextSize = 1088
    public static let x25519PublicKeySize = 32
    public static let kemShareSize = 1216 // ek(1184) || x25519 public(32)
    public static let kemCiphertextSize = 1120 // ct(1088) || x25519 public(32)

    public struct HandshakeError: Error, Equatable, CustomStringConvertible {
        public let description: String
        public init(_ m: String) { description = m }
    }

    // -- Transcript (spec/10 §3) -------------------------------------------

    /// Accumulates the draft-00 handshake transcript (spec/10 §3) and hashes it
    /// at a cut point. Per-TLV granularity: `addFrameType` appends the 2-octet
    /// frame type ONLY (not the rest of the 36-octet header — the §3/§7.1
    /// divergence from RFC 8446 §4.4.1); `addTlv` appends
    /// Type(2 BE) || Length(2 BE) || Value. A point = the profile hash (SHA-256
    /// at Standard, SHA-384 at High/Sovereign) over all bytes absorbed so far.
    public final class Transcript {
        private var buf = [UInt8]()

        public init() {}

        /// Absorbs a frame type as exactly two big-endian octets.
        public func addFrameType(_ ft: Int) {
            buf.append(UInt8((ft >> 8) & 0xFF))
            buf.append(UInt8(ft & 0xFF))
        }

        /// Absorbs one TLV: Type(2 BE) || Length(2 BE) || Value.
        public func addTlv(_ type: Int, _ value: [UInt8]) {
            buf.append(UInt8((type >> 8) & 0xFF))
            buf.append(UInt8(type & 0xFF))
            buf.append(UInt8((value.count >> 8) & 0xFF))
            buf.append(UInt8(value.count & 0xFF))
            buf.append(contentsOf: value)
        }

        /// Hashes all absorbed bytes: SHA-256 at Standard, SHA-384 otherwise.
        public func hash(_ standard: Bool) -> [UInt8] {
            standard ? Array(SHA256.hash(data: buf)) : Array(SHA384.hash(data: buf))
        }
    }

    // -- Finished (spec/10 §6.2; RFC 8446 §4.4.4) ----------------------------

    /// Finished verify_data = HMAC(finished_key, transcript_hash) under the
    /// profile hash (HMAC-SHA-256 at Standard, HMAC-SHA-384 at High/Sovereign).
    public static func computeFinished(_ finishedKey: [UInt8], _ transcriptHash: [UInt8],
                                       _ standard: Bool) -> [UInt8] {
        let key = SymmetricKey(data: finishedKey)
        if standard {
            return Array(HMAC<SHA256>.authenticationCode(for: transcriptHash, using: key))
        }
        return Array(HMAC<SHA384>.authenticationCode(for: transcriptHash, using: key))
    }

    /// Recomputes the Finished MAC and constant-time-compares it to the received
    /// verify_data (HMAC.isValidAuthenticationCode is swift-crypto's constant-time
    /// MAC comparison).
    public static func verifyFinished(_ finishedKey: [UInt8], _ transcriptHash: [UInt8],
                                      _ verifyData: [UInt8], _ standard: Bool) -> Bool {
        let key = SymmetricKey(data: finishedKey)
        if standard {
            return HMAC<SHA256>.isValidAuthenticationCode(verifyData, authenticating: transcriptHash, using: key)
        }
        return HMAC<SHA384>.isValidAuthenticationCode(verifyData, authenticating: transcriptHash, using: key)
    }

    // -- CertVerify (spec/10 §6.1; RFC 8446 §4.4.3; Ed25519 RFC 8032) --------

    /// Builds an Ed25519 private key from its raw 32-octet seed (RFC 8032;
    /// swift-crypto's rawRepresentation IS the seed).
    public static func ed25519PrivateKey(fromSeed seed: [UInt8]) throws -> Curve25519.Signing.PrivateKey {
        try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
    }

    /// Builds an Ed25519 public key from its raw 32-octet encoding (RFC 8032 §5.1.2).
    public static func ed25519PublicKey(fromRaw raw: [UInt8]) throws -> Curve25519.Signing.PublicKey {
        try Curve25519.Signing.PublicKey(rawRepresentation: raw)
    }

    /// The §6.1 signing input: 64 octets of 0x20, the role context string, a 0x00
    /// separator, then the transcript hash — TLS-1.3-style domain separation
    /// (RFC 8446 §4.4.3).
    public static func certVerifySigningInput(isServer: Bool, transcriptHash: [UInt8]) -> [UInt8] {
        let ctx = Array((isServer ? contextServerCertVerify : contextClientCertVerify).utf8)
        var out = [UInt8](repeating: 0x20, count: 64)
        out.append(contentsOf: ctx)
        out.append(0x00)
        out.append(contentsOf: transcriptHash)
        return out
    }

    /// The CertVerify TLV value: u16(0x0807, Ed25519) || Ed25519(priv, signing_input).
    public static func signCertVerify(_ privateKey: Curve25519.Signing.PrivateKey,
                                      isServer: Bool, transcriptHash: [UInt8]) throws -> [UInt8] {
        let sig = try privateKey.signature(for: certVerifySigningInput(isServer: isServer,
                                                                       transcriptHash: transcriptHash))
        var out = [UInt8]()
        out.append(UInt8((Npamp.sigEd25519 >> 8) & 0xFF))
        out.append(UInt8(Npamp.sigEd25519 & 0xFF))
        out.append(contentsOf: sig)
        return out
    }

    /// Checks a CertVerify TLV value against the signer's public key, role, and
    /// transcript hash. Rejects a non-Ed25519 scheme, a wrong-length signature, a
    /// role/context mismatch, or a wrong transcript.
    public static func verifyCertVerify(_ publicKey: Curve25519.Signing.PublicKey,
                                        isServer: Bool, transcriptHash: [UInt8],
                                        value: [UInt8]) -> Bool {
        if value.count < 2 { return false }
        let scheme = Int(value[0]) << 8 | Int(value[1])
        if scheme != Npamp.sigEd25519 { return false }
        let sig = Array(value[2...])
        if sig.count != 64 { return false } // Ed25519 signatures are exactly 64 octets (RFC 8032 §5.1.6)
        return publicKey.isValidSignature(sig, for: certVerifySigningInput(isServer: isServer,
                                                                           transcriptHash: transcriptHash))
    }

    // -- KEM wire layout (spec/10 §4; ML-KEM-first per ADR-0005) -------------
    //
    // The suite name lists X25519 first; the BYTES are ML-KEM-first, in the wire
    // fields and in the HKDF-Extract IKM (Npamp.deriveHandshakeSecret). These
    // helpers only assemble/split wire bytes — ML-KEM-768 Encaps/Decaps itself is
    // NOT implemented here (swift-crypto's Crypto product exposes no ML-KEM API).

    /// KEMShare (TLV 0x07): ML-KEM-768 encapsulation key (1184) || X25519 public (32)
    /// = 1216 octets, ML-KEM-first.
    public static func kemShareBytes(mlkemEncapsulationKey: [UInt8],
                                     x25519PublicKey: [UInt8]) throws -> [UInt8] {
        guard mlkemEncapsulationKey.count == mlkem768EncapsulationKeySize else {
            throw HandshakeError("ML-KEM-768 encapsulation key must be \(mlkem768EncapsulationKeySize) octets, got \(mlkemEncapsulationKey.count)")
        }
        guard x25519PublicKey.count == x25519PublicKeySize else {
            throw HandshakeError("X25519 public key must be \(x25519PublicKeySize) octets, got \(x25519PublicKey.count)")
        }
        return mlkemEncapsulationKey + x25519PublicKey
    }

    /// Splits a KEMShare TLV value into (ML-KEM-768 ek, X25519 public), ML-KEM-first.
    public static func splitKemShare(_ share: [UInt8]) throws
        -> (mlkemEncapsulationKey: [UInt8], x25519PublicKey: [UInt8]) {
        guard share.count == kemShareSize else {
            throw HandshakeError("KEMShare must be \(kemShareSize) octets, got \(share.count)")
        }
        return (Array(share[0..<mlkem768EncapsulationKeySize]),
                Array(share[mlkem768EncapsulationKeySize...]))
    }

    /// KEMCiphertext (TLV 0x08): ML-KEM-768 ciphertext (1088) || server X25519
    /// public (32) = 1120 octets, ML-KEM-first.
    public static func kemCiphertextBytes(mlkemCiphertext: [UInt8],
                                          x25519PublicKey: [UInt8]) throws -> [UInt8] {
        guard mlkemCiphertext.count == mlkem768CiphertextSize else {
            throw HandshakeError("ML-KEM-768 ciphertext must be \(mlkem768CiphertextSize) octets, got \(mlkemCiphertext.count)")
        }
        guard x25519PublicKey.count == x25519PublicKeySize else {
            throw HandshakeError("X25519 public key must be \(x25519PublicKeySize) octets, got \(x25519PublicKey.count)")
        }
        return mlkemCiphertext + x25519PublicKey
    }

    /// Splits a KEMCiphertext TLV value into (ML-KEM-768 ciphertext, server X25519
    /// public), ML-KEM-first.
    public static func splitKemCiphertext(_ ct: [UInt8]) throws
        -> (mlkemCiphertext: [UInt8], x25519PublicKey: [UInt8]) {
        guard ct.count == kemCiphertextSize else {
            throw HandshakeError("KEMCiphertext must be \(kemCiphertextSize) octets, got \(ct.count)")
        }
        return (Array(ct[0..<mlkem768CiphertextSize]),
                Array(ct[mlkem768CiphertextSize...]))
    }
}
