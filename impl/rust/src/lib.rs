//! Open reference implementation of the N-PAMP wire format (draft-bubblefish-npamp-00).
//!
//! OPEN protocol layer only: the 36-octet frame header, registries, the AEAD record
//! layer, and the HKDF-Expand-Label key schedule. No proprietary scoring/detection/
//! generation methods, no tuned parameters, no model weights.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::{Sha256, Sha384};

pub const HEADER_SIZE: usize = 36;
pub const PROTOCOL_VERSION: u8 = 0x2;
pub const MAGIC: [u8; 4] = [0x4E, 0x50, 0x41, 0x4D];
pub const ALPN: &str = "n-pamp/2";
/// Protocol-specific HKDF-Expand-Label prefix (draft-00 7.4). Provides domain
/// separation from TLS 1.3 ("tls13 ") and QUIC; "tls13 " is non-conformant.
pub const LABEL_PREFIX: &str = "n-pamp ";

pub const FLAG_URG: u8 = 0x01;
pub const FLAG_ENC: u8 = 0x02;
pub const FLAG_COMP: u8 = 0x04;
pub const FLAG_FRAG: u8 = 0x08;

// Core channel registry (draft-00 5.1).
pub const CHAN_CONTROL: u16 = 0x0000;
pub const CHAN_MEMORY: u16 = 0x0001;
pub const CHAN_IMMUNE: u16 = 0x0005;
pub const CHAN_AUDIT: u16 = 0x000B;
pub const CHAN_BRIDGE: u16 = 0x000D;
pub const CHAN_SPATIAL: u16 = 0x0013;

// Reserved system frame types (draft-00 4.6).
pub const FRAME_PING: u16 = 0x0001;
pub const FRAME_PONG: u16 = 0x0002;
pub const FRAME_CLOSE: u16 = 0x0003;
pub const FRAME_FLOW_UPDATE: u16 = 0x000A;
pub const CHANNEL_SPECIFIC_BASE: u16 = 0x0100;

// TLV types (draft-00 9.4).
pub const TLV_PROFILE_OFFER: u16 = 0x01;
pub const TLV_KEM_CIPHERTEXT: u16 = 0x08;
pub const TLV_ANOMALY_CHARGE: u16 = 0x12;

// Crypto-suite code points (draft-00 7).
pub const KEM_X25519_MLKEM768: u16 = 0x11ec;
pub const KEM_X25519_MLKEM1024: u16 = 0x11ed;
pub const AEAD_AES256_GCM: u16 = 0x0001;
pub const AEAD_CHACHA20_POLY1305: u16 = 0x0002;
pub const SIG_ED25519: u16 = 0x0807;
pub const SIG_MLDSA87: u16 = 0x0905;

/// CRC32C (Castagnoli, reflected) — identical to Go hash/crc32 Castagnoli.
pub fn crc32c(data: &[u8]) -> u32 {
    const POLY: u32 = 0x82F6_3B78;
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ POLY } else { crc >> 1 };
        }
    }
    !crc
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Frame {
    pub version: u8,
    pub flags: u8,
    pub ftype: u16,
    pub channel: u16,
    pub seq: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    ShortHeader,
    BadMagic,
    BadVersion,
    BadCrc,
    ReservedNonzero,
    LengthMismatch,
}

impl Frame {
    /// Writes the 21-octet header prefix (octets 0..20) that the CRC covers and that
    /// the record layer uses as AEAD associated data. dst must be at least 21 octets.
    pub fn header_prefix(&self, dst: &mut [u8], payload_len: u32) {
        let ver = if self.version == 0 { PROTOCOL_VERSION } else { self.version };
        dst[0..4].copy_from_slice(&MAGIC);
        dst[4] = (ver << 4) | (self.flags & 0x0F);
        dst[5..7].copy_from_slice(&self.ftype.to_be_bytes());
        dst[7..9].copy_from_slice(&self.channel.to_be_bytes());
        dst[9..17].copy_from_slice(&self.seq.to_be_bytes());
        dst[17..21].copy_from_slice(&payload_len.to_be_bytes());
    }

    pub fn marshal(&self) -> Vec<u8> {
        let plen = self.payload.len() as u32;
        let mut out = vec![0u8; HEADER_SIZE + self.payload.len()];
        self.header_prefix(&mut out, plen);
        let crc = crc32c(&out[0..21]);
        out[21..25].copy_from_slice(&crc.to_be_bytes());
        // octets 25..36 are reserved and already zero.
        out[HEADER_SIZE..].copy_from_slice(&self.payload);
        out
    }

    /// Parses buf. Per draft-00 4.2 the CRC32C is validated BEFORE any other header
    /// field; reserved octets MUST be zero; version MUST be the supported wire version.
    pub fn unmarshal(buf: &[u8]) -> Result<Frame, FrameError> {
        if buf.len() < HEADER_SIZE {
            return Err(FrameError::ShortHeader);
        }
        let got = u32::from_be_bytes([buf[21], buf[22], buf[23], buf[24]]);
        if got != crc32c(&buf[0..21]) {
            return Err(FrameError::BadCrc);
        }
        if buf[0..4] != MAGIC {
            return Err(FrameError::BadMagic);
        }
        let ver = buf[4] >> 4;
        if ver != PROTOCOL_VERSION {
            return Err(FrameError::BadVersion);
        }
        for i in 25..HEADER_SIZE {
            if buf[i] != 0 {
                return Err(FrameError::ReservedNonzero);
            }
        }
        let plen = u32::from_be_bytes([buf[17], buf[18], buf[19], buf[20]]) as usize;
        if plen != buf.len() - HEADER_SIZE {
            return Err(FrameError::LengthMismatch);
        }
        Ok(Frame {
            version: ver,
            flags: buf[4] & 0x0F,
            ftype: u16::from_be_bytes([buf[5], buf[6]]),
            channel: u16::from_be_bytes([buf[7], buf[8]]),
            seq: u64::from_be_bytes(buf[9..17].try_into().unwrap()),
            payload: buf[HEADER_SIZE..].to_vec(),
        })
    }
}

/// Per-frame AEAD nonce (draft-00 7.5): IV XOR left-zero-padded sequence number.
/// The 8-octet big-endian sequence occupies the low 8 octets; the Channel ID is
/// NOT part of the nonce.
pub fn derive_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..12].copy_from_slice(&seq.to_be_bytes());
    for i in 0..12 {
        n[i] ^= iv[i];
    }
    n
}

/// AES-256-GCM seal (suite 0x0001) with the draft-00 nonce and aad. Output = enc||tag.
pub fn seal_aes256gcm(key: &[u8; 32], iv: &[u8; 12], seq: u64, aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("key");
    let nonce = derive_nonce(iv, seq);
    cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: pt, aad })
        .expect("seal")
}

pub fn open_aes256gcm(key: &[u8; 32], iv: &[u8; 12], seq: u64, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, ()> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("key");
    let nonce = derive_nonce(iv, seq);
    cipher
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: sealed, aad })
        .map_err(|_| ())
}

/// HKDF-Expand-Label with the N-PAMP prefix (draft-00 7.4). `standard` selects
/// SHA-256 (Standard profile) vs SHA-384 (High/Sovereign).
pub fn hkdf_expand_label(secret: &[u8], label: &str, context: &[u8], length: usize, standard: bool) -> Vec<u8> {
    let full = format!("{}{}", LABEL_PREFIX, label);
    let mut info = Vec::with_capacity(2 + 1 + full.len() + 1 + context.len());
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand(secret, &info, length, standard)
}

/// HKDF-Expand only (RFC 5869 §2.3): expand the PRK with `info` to `length` octets.
/// SHA-256 when `standard`, else SHA-384. Exposed for independent known-answer testing
/// against RFC 5869 / Wycheproof (the label structure above wraps this primitive).
pub fn hkdf_expand(prk: &[u8], info: &[u8], length: usize, standard: bool) -> Vec<u8> {
    let mut okm = vec![0u8; length];
    if standard {
        Hkdf::<Sha256>::from_prk(prk).expect("prk").expand(info, &mut okm).expect("expand");
    } else {
        Hkdf::<Sha384>::from_prk(prk).expect("prk").expand(info, &mut okm).expect("expand");
    }
    okm
}

/// Binds the (direction, epoch, AEAD suite, channel) tuple into the key schedule
/// (draft-00 7.5).
pub fn derive_traffic_secret(master: &[u8], dir: u8, epoch: u64, suite: u16, channel: u16, standard: bool) -> Vec<u8> {
    let mut ctx = Vec::with_capacity(1 + 8 + 2 + 2);
    ctx.push(dir);
    ctx.extend_from_slice(&epoch.to_be_bytes());
    ctx.extend_from_slice(&suite.to_be_bytes());
    ctx.extend_from_slice(&channel.to_be_bytes());
    let hlen = if standard { 32 } else { 48 };
    hkdf_expand_label(master, "traffic", &ctx, hlen, standard)
}

pub fn derive_key_iv(secret: &[u8], standard: bool) -> ([u8; 32], [u8; 12]) {
    let k = hkdf_expand_label(secret, "key", &[], 32, standard);
    let v = hkdf_expand_label(secret, "iv", &[], 12, standard);
    let mut key = [0u8; 32];
    key.copy_from_slice(&k);
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&v);
    (key, iv)
}

/// HKDF-Extract (RFC 5869 §2.2): PRK = HMAC-Hash(salt, IKM). SHA-256 at the Standard
/// profile, SHA-384 at High/Sovereign — wired through `standard` like the rest of the key
/// schedule. This is the salted HMAC the handshake-secret ladder extracts the two KEM
/// shared secrets through; the leaf HKDF-Expand-Label (above) wraps the matching Expand.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8], standard: bool) -> Vec<u8> {
    if standard {
        Hkdf::<Sha256>::extract(Some(salt), ikm).0.to_vec()
    } else {
        Hkdf::<Sha384>::extract(Some(salt), ikm).0.to_vec()
    }
}

/// handshake_secret = HKDF-Extract(salt = HashLen zero octets, IKM = ML-KEM_SS || X25519_SS)
/// (binding spec/10 §5). The ML-KEM shared secret is concatenated FIRST and the X25519 shared
/// secret SECOND (ML-KEM-first, ADR-0005). `mlkem_ss` / `x25519_ss` are the two KEM shared
/// secrets; the default salt is HashLen zero octets per RFC 5869 §2.2.
pub fn derive_handshake_secret(mlkem_ss: &[u8], x25519_ss: &[u8], standard: bool) -> Vec<u8> {
    let mut ikm = Vec::with_capacity(mlkem_ss.len() + x25519_ss.len());
    ikm.extend_from_slice(mlkem_ss);
    ikm.extend_from_slice(x25519_ss);
    let hlen = if standard { 32 } else { 48 };
    let salt = vec![0u8; hlen];
    hkdf_extract(&salt, &ikm, standard)
}

/// c_hs = HKDF-Expand-Label(handshake_secret, "c hs", th_kem, HashLen) (binding spec/10 §5):
/// the client handshake-traffic secret. `th_kem` is the transcript hash through the KEM exchange.
pub fn derive_client_handshake_secret(handshake_secret: &[u8], th_kem: &[u8], standard: bool) -> Vec<u8> {
    let hlen = if standard { 32 } else { 48 };
    hkdf_expand_label(handshake_secret, "c hs", th_kem, hlen, standard)
}

/// s_hs = HKDF-Expand-Label(handshake_secret, "s hs", th_kem, HashLen) (binding spec/10 §5):
/// the server handshake-traffic secret. `th_kem` is the transcript hash through the KEM exchange.
pub fn derive_server_handshake_secret(handshake_secret: &[u8], th_kem: &[u8], standard: bool) -> Vec<u8> {
    let hlen = if standard { 32 } else { 48 };
    hkdf_expand_label(handshake_secret, "s hs", th_kem, hlen, standard)
}

/// master = HKDF-Expand-Label(handshake_secret, "master", th_ccv, HashLen) (binding spec/10 §5):
/// the master secret bound to the client-authenticated transcript. `th_ccv` is the transcript
/// hash through the client CertVerify.
pub fn derive_master_secret(handshake_secret: &[u8], th_ccv: &[u8], standard: bool) -> Vec<u8> {
    let hlen = if standard { 32 } else { 48 };
    hkdf_expand_label(handshake_secret, "master", th_ccv, hlen, standard)
}

/// finished_key(secret) = HKDF-Expand-Label(secret, "finished", "", HashLen) (binding spec/10
/// §6.2 / §5.4). The client Finished key derives from c_hs, the server Finished key from s_hs;
/// the result keys the HMAC in handshake::compute_finished.
pub fn finished_key(secret: &[u8], standard: bool) -> Vec<u8> {
    let hlen = if standard { 32 } else { 48 };
    hkdf_expand_label(secret, "finished", &[], hlen, standard)
}

/// N-PAMP draft-00 handshake binding layer (binding spec/10): the transcript hash
/// (section 3), the Finished MAC (section 6.2; RFC 8446 section 4.4.4), and the
/// CertVerify signature (section 6.1; RFC 8446 section 4.4.3 structure; Ed25519 per
/// RFC 8032). Big-endian throughout. SHA-256/HMAC-SHA-256 at the Standard profile,
/// SHA-384/HMAC-SHA-384 at High/Sovereign.
pub mod handshake {
    use crate::SIG_ED25519;
    use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, VerifyingKey};
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256, Sha384};

    /// Handshake frame types (binding spec/10 section 1), carried on the control channel.
    pub const FRAME_CLIENT_HELLO: u16 = 0x0100;
    pub const FRAME_SERVER_HELLO: u16 = 0x0101;
    pub const FRAME_SERVER_AUTH: u16 = 0x0102;
    pub const FRAME_CLIENT_AUTH: u16 = 0x0103;

    /// CertVerify role context strings (binding spec/10 section 6.1).
    pub const CONTEXT_SERVER_CERTVERIFY: &str = "N-PAMP/2, server CertificateVerify";
    pub const CONTEXT_CLIENT_CERTVERIFY: &str = "N-PAMP/2, client CertificateVerify";

    /// Accumulates the draft-00 handshake transcript (binding spec/10 section 3) and hashes
    /// it at a cut point. Absorption granularity is per-TLV: [`Transcript::add_frame_type`]
    /// appends the 2-octet frame type ONLY (NOT the rest of the 36-octet frame header — the
    /// spec section 3 / 7.1 divergence from RFC 8446 section 4.4.1); [`Transcript::add_tlv`]
    /// appends Type(2 BE) || Length(2 BE) || Value. A transcript point = the hash over all
    /// bytes absorbed so far (SHA-256 at Standard, SHA-384 at High/Sovereign).
    #[derive(Debug, Clone, Default)]
    pub struct Transcript {
        buf: Vec<u8>,
    }

    impl Transcript {
        pub fn new() -> Self {
            Self { buf: Vec::new() }
        }

        /// Appends the frame type as exactly 2 octets big-endian.
        pub fn add_frame_type(&mut self, ft: u16) {
            self.buf.extend_from_slice(&ft.to_be_bytes());
        }

        /// Appends one TLV: Type(2 BE) || Length(2 BE) || Value.
        pub fn add_tlv(&mut self, typ: u16, value: &[u8]) {
            self.buf.extend_from_slice(&typ.to_be_bytes());
            self.buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
            self.buf.extend_from_slice(value);
        }

        /// Hashes every octet absorbed so far (SHA-256 when `standard`, else SHA-384).
        pub fn hash(&self, standard: bool) -> Vec<u8> {
            if standard {
                Sha256::digest(&self.buf).to_vec()
            } else {
                Sha384::digest(&self.buf).to_vec()
            }
        }
    }

    /// Finished verify_data = HMAC(finished_key, transcript_hash) under the profile hash
    /// (HMAC-SHA-256 at Standard, HMAC-SHA-384 at High/Sovereign). HMAC accepts a key of
    /// any length, so `new_from_slice` never fails here.
    pub fn compute_finished(finished_key: &[u8], transcript_hash: &[u8], standard: bool) -> Vec<u8> {
        if standard {
            let mut mac = Hmac::<Sha256>::new_from_slice(finished_key).expect("HMAC accepts any key length");
            mac.update(transcript_hash);
            mac.finalize().into_bytes().to_vec()
        } else {
            let mut mac = Hmac::<Sha384>::new_from_slice(finished_key).expect("HMAC accepts any key length");
            mac.update(transcript_hash);
            mac.finalize().into_bytes().to_vec()
        }
    }

    /// Recomputes the Finished MAC and constant-time-compares it to the received verify_data
    /// via [`hmac::Mac::verify_slice`] (which uses `subtle::ConstantTimeEq` and rejects a
    /// length mismatch).
    pub fn verify_finished(finished_key: &[u8], transcript_hash: &[u8], verify_data: &[u8], standard: bool) -> bool {
        if standard {
            let mut mac = Hmac::<Sha256>::new_from_slice(finished_key).expect("HMAC accepts any key length");
            mac.update(transcript_hash);
            mac.verify_slice(verify_data).is_ok()
        } else {
            let mut mac = Hmac::<Sha384>::new_from_slice(finished_key).expect("HMAC accepts any key length");
            mac.update(transcript_hash);
            mac.verify_slice(verify_data).is_ok()
        }
    }

    /// Builds an Ed25519 signing key from its raw 32-octet seed (RFC 8032).
    pub fn ed25519_signing_key_from_seed(seed: &[u8; 32]) -> SigningKey {
        SigningKey::from_bytes(seed)
    }

    /// Builds an Ed25519 verifying key from its raw 32-octet encoding (RFC 8032 section 5.1.2).
    /// Returns an error if the bytes are not a valid compressed Edwards point.
    pub fn ed25519_verifying_key_from_raw(raw: &[u8; 32]) -> Result<VerifyingKey, SignatureError> {
        VerifyingKey::from_bytes(raw)
    }

    /// The section 6.1 signing input: 64 octets of 0x20, the role context string, a 0x00
    /// separator, then the transcript hash — TLS-1.3-style domain separation
    /// (RFC 8446 section 4.4.3).
    pub fn cert_verify_signing_input(is_server: bool, transcript_hash: &[u8]) -> Vec<u8> {
        let ctx = if is_server { CONTEXT_SERVER_CERTVERIFY } else { CONTEXT_CLIENT_CERTVERIFY };
        let ctx = ctx.as_bytes();
        let mut out = Vec::with_capacity(64 + ctx.len() + 1 + transcript_hash.len());
        out.extend_from_slice(&[0x20u8; 64]);
        out.extend_from_slice(ctx);
        out.push(0x00);
        out.extend_from_slice(transcript_hash);
        out
    }

    /// The CertVerify TLV value: u16(0x0807, Ed25519) || Ed25519(priv, signing_input).
    pub fn sign_cert_verify(signing_key: &SigningKey, is_server: bool, transcript_hash: &[u8]) -> Vec<u8> {
        let sig = signing_key.sign(&cert_verify_signing_input(is_server, transcript_hash));
        let mut out = Vec::with_capacity(2 + Signature::BYTE_SIZE);
        out.extend_from_slice(&SIG_ED25519.to_be_bytes());
        out.extend_from_slice(&sig.to_bytes());
        out
    }

    /// Checks a CertVerify TLV value against the signer's public key, role, and transcript
    /// hash. Rejects a non-Ed25519 scheme, a wrong-length (non-64-octet) signature, a
    /// role/context mismatch, or a wrong transcript. Uses `verify_strict` (RFC 8032 strict
    /// canonical verification).
    pub fn verify_cert_verify(verifying_key: &VerifyingKey, is_server: bool, transcript_hash: &[u8], value: &[u8]) -> bool {
        if value.len() < 2 || u16::from_be_bytes([value[0], value[1]]) != SIG_ED25519 {
            return false;
        }
        let sig_bytes = &value[2..];
        if sig_bytes.len() != Signature::BYTE_SIZE {
            // Ed25519 signatures are exactly 64 octets (RFC 8032 section 5.1.6).
            return false;
        }
        let mut arr = [0u8; Signature::BYTE_SIZE];
        arr.copy_from_slice(sig_bytes);
        let sig = Signature::from_bytes(&arr);
        verifying_key
            .verify_strict(&cert_verify_signing_input(is_server, transcript_hash), &sig)
            .is_ok()
    }
}
