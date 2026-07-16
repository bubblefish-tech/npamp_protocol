//! Live N-PAMP 1.5-RTT handshake driver for the Go<->Rust interop examples.
//!
//! This module composes the OPEN wire-format library's primitives (frame codec,
//! HKDF key schedule, AES-256-GCM record layer, transcript, CertVerify, Finished)
//! with the X25519MLKEM768 hybrid KEM (ml-kem + x25519-dalek, dev-dependencies)
//! into a stateful, socket-driving client and server handshake. It mirrors the Go
//! reference SDK's runClientHandshake / runServerHandshake (impl/go/sdk/handshake.go)
//! frame-for-frame and byte-for-byte, over a raw TCP stream.
//!
//! Transport note: the Go SDK wraps these N-PAMP frames in TLS 1.3 (ALPN
//! "n-pamp/2") as its `npamp://` fallback transport binding. The N-PAMP handshake
//! itself (spec/10) is transport-agnostic — four frames over the Control channel —
//! so this interop runs the identical handshake + record layer directly over TCP.
//! The Go interop harness (impl/go/cmd/npamp-interop) speaks the same raw-TCP
//! binding, so the two implementations complete a real mutually-authenticated
//! handshake and exchange application frames without the TLS wrapper.
//!
//! It lives under examples/support/ (a subdirectory) so Cargo does not treat it as
//! its own example target; interop_client.rs and interop_server.rs include it via
//! `#[path]`.

#![allow(dead_code)]

use ed25519_dalek::{SigningKey, VerifyingKey};
use kem::Decapsulate;
use ml_kem::array::Array;
use ml_kem::{Ciphertext, EncapsulateDeterministic, EncodedSizeUser, KemCore, MlKem768};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

use npamp::handshake::{
    self, ed25519_signing_key_from_seed, ed25519_verifying_key_from_raw, Transcript,
    FRAME_CLIENT_AUTH, FRAME_CLIENT_HELLO, FRAME_SERVER_AUTH, FRAME_SERVER_HELLO,
};

// ---------------------------------------------------------------------------
// Handshake TLV code points (spec/10 §1.1). The OPEN library exposes only a
// subset as public constants, so the full handshake set is named here.
// ---------------------------------------------------------------------------
const TLV_PROFILE_OFFER: u16 = 0x01;
const TLV_PROFILE_SELECT: u16 = 0x02;
const TLV_KEM_OFFER: u16 = 0x03;
const TLV_KEM_SELECT: u16 = 0x04;
const TLV_SIG_OFFER: u16 = 0x05;
const TLV_SIG_SELECT: u16 = 0x06;
const TLV_KEM_SHARE: u16 = 0x07;
const TLV_KEM_CIPHERTEXT: u16 = 0x08;
const TLV_IDENTITY_KEY: u16 = 0x09;
const TLV_CERT_VERIFY: u16 = 0x0A;
const TLV_FINISHED: u16 = 0x0B;
const TLV_AEAD_OFFER: u16 = 0x0C;
const TLV_AEAD_SELECT: u16 = 0x0D;

const PROFILE_STANDARD: u8 = 0x01;
const STANDARD: bool = true; // SHA-256 profile throughout

// Direction octets (spec/10 §7.5): client-to-server = 0, server-to-client = 1.
const DIR_C2S: u8 = 0;
const DIR_S2C: u8 = 1;

const MLKEM768_EK_LEN: usize = 1184;
const MLKEM768_CT_LEN: usize = 1088;
const X25519_PUB_LEN: usize = 32;
const KEM_SHARE_LEN: usize = MLKEM768_EK_LEN + X25519_PUB_LEN; // 1216
const KEM_CIPHERTEXT_LEN: usize = MLKEM768_CT_LEN + X25519_PUB_LEN; // 1120
const GCM_TAG_LEN: usize = 16;
const MAX_FRAME_SIZE: usize = 16 << 20; // mirrors the Go SDK cap

type Ek768 = <MlKem768 as KemCore>::EncapsulationKey;

// ---------------------------------------------------------------------------
// OS entropy -> deterministic keygen seeds (no rand_core / no C provider).
// ---------------------------------------------------------------------------
fn os_random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("OS CSPRNG");
    b
}

/// Generates a fresh Ed25519 long-term identity signing key from OS entropy.
pub fn generate_identity() -> SigningKey {
    ed25519_signing_key_from_seed(&os_random::<32>())
}

// ---------------------------------------------------------------------------
// TLV codec (Type u16 BE || Length u16 BE || Value), identical to the Go
// npamp.TLV.Encode / DecodeTLVs.
// ---------------------------------------------------------------------------
fn tlv(out: &mut Vec<u8>, typ: u16, value: &[u8]) {
    out.extend_from_slice(&typ.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}

/// Parses a concatenation of TLVs into (type, value) pairs. Rejects a truncated
/// TLV (mirrors npamp.DecodeTLVs / ErrTruncatedTLV).
fn decode_tlvs(mut buf: &[u8]) -> io::Result<Vec<(u16, Vec<u8>)>> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        if buf.len() < 4 {
            return Err(proto("truncated TLV"));
        }
        let typ = u16::from_be_bytes([buf[0], buf[1]]);
        let ln = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if buf.len() < 4 + ln {
            return Err(proto("truncated TLV value"));
        }
        out.push((typ, buf[4..4 + ln].to_vec()));
        buf = &buf[4 + ln..];
    }
    Ok(out)
}

/// Enforces the exact TLV set + order the handshake fixes (spec/10 §1), returning
/// just the values (mirrors npamp.requireTLVs).
fn require_tlvs(tlvs: &[(u16, Vec<u8>)], want: &[u16]) -> io::Result<Vec<Vec<u8>>> {
    if tlvs.len() != want.len() {
        return Err(proto("handshake TLV count mismatch"));
    }
    let mut vals = Vec::with_capacity(want.len());
    for (i, &w) in want.iter().enumerate() {
        if tlvs[i].0 != w {
            return Err(proto("handshake TLV out of order"));
        }
        vals.push(tlvs[i].1.clone());
    }
    Ok(vals)
}

fn proto(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("npamp-live: {msg}"))
}

// ---------------------------------------------------------------------------
// Self-delimiting frame stream I/O (identical framing to the Go SDK readFrame /
// writeFrame: fixed 36-octet header, payload length in octets 17..21, no extra
// length prefix).
// ---------------------------------------------------------------------------
fn read_frame(s: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut header = [0u8; npamp::HEADER_SIZE];
    s.read_exact(&mut header)?;
    if header[0..4] != npamp::MAGIC {
        return Err(proto("bad frame magic"));
    }
    let plen = u32::from_be_bytes([header[17], header[18], header[19], header[20]]) as usize;
    let total = npamp::HEADER_SIZE + plen;
    if total > MAX_FRAME_SIZE {
        return Err(proto("frame exceeds max size"));
    }
    let mut buf = vec![0u8; total];
    buf[..npamp::HEADER_SIZE].copy_from_slice(&header);
    s.read_exact(&mut buf[npamp::HEADER_SIZE..])?;
    Ok(buf)
}

fn write_frame(s: &mut TcpStream, frame: &[u8]) -> io::Result<()> {
    s.write_all(frame)?;
    s.flush()
}

/// Marshals a cleartext handshake frame (Control channel, seq 0) through the OPEN
/// library's real Frame::marshal.
fn cleartext_frame(ftype: u16, payload: Vec<u8>) -> Vec<u8> {
    npamp::Frame {
        ftype,
        channel: npamp::CHAN_CONTROL,
        seq: 0,
        payload,
        ..Default::default()
    }
    .marshal()
}

// ---------------------------------------------------------------------------
// AEAD sealing of the AUTH frames + application frames (epoch 0), identical to
// the Go SDK's sealFrame / openFrame / sealWith / openWith.
// ---------------------------------------------------------------------------

/// Derives the epoch-0 (key, iv) for a (base secret, direction, channel).
fn key_iv(base: &[u8], dir: u8, channel: u16) -> ([u8; 32], [u8; 12]) {
    let ts = npamp::derive_traffic_secret(base, dir, 0, npamp::AEAD_AES256_GCM, channel, STANDARD);
    npamp::derive_key_iv(&ts, STANDARD)
}

/// Seals `plaintext` into a marshaled FlagENC frame on `channel` at `seq`.
fn seal_frame(base: &[u8], dir: u8, channel: u16, seq: u64, ftype: u16, plaintext: &[u8]) -> Vec<u8> {
    let (key, iv) = key_iv(base, dir, channel);
    let mut aad = [0u8; 21];
    npamp::Frame {
        flags: npamp::FLAG_ENC,
        ftype,
        channel,
        seq,
        ..Default::default()
    }
    .header_prefix(&mut aad, (plaintext.len() + GCM_TAG_LEN) as u32);
    let sealed = npamp::seal_aes256gcm(&key, &iv, seq, &aad, plaintext);
    npamp::Frame {
        flags: npamp::FLAG_ENC,
        ftype,
        channel,
        seq,
        payload: sealed,
        ..Default::default()
    }
    .marshal()
}

/// Opens a parsed FlagENC frame under the (base secret, direction) epoch-0 key.
fn open_frame(f: &npamp::Frame, base: &[u8], dir: u8) -> io::Result<Vec<u8>> {
    let (key, iv) = key_iv(base, dir, f.channel);
    let mut aad = [0u8; 21];
    f.header_prefix(&mut aad, f.payload.len() as u32);
    npamp::open_aes256gcm(&key, &iv, f.seq, &aad, &f.payload).map_err(|_| proto("AEAD open failed"))
}

// ---------------------------------------------------------------------------
// X25519MLKEM768 hybrid KEM (ML-KEM-first, ADR-0005). Client generates the key
// pairs and decapsulates; server encapsulates.
// ---------------------------------------------------------------------------
struct KemClient {
    mlkem_dk: <MlKem768 as KemCore>::DecapsulationKey,
    mlkem_ek_bytes: Vec<u8>,
    x25519_sk: XStaticSecret,
    x25519_pub: [u8; 32],
}

impl KemClient {
    fn generate() -> Self {
        let dz = os_random::<64>();
        let d = Array::try_from(&dz[..32]).unwrap();
        let z = Array::try_from(&dz[32..]).unwrap();
        let (dk, ek) = MlKem768::generate_deterministic(&d, &z);
        let x25519_sk = XStaticSecret::from(os_random::<32>());
        let x25519_pub = XPublicKey::from(&x25519_sk).to_bytes();
        KemClient {
            mlkem_ek_bytes: ek.as_bytes().as_slice().to_vec(),
            mlkem_dk: dk,
            x25519_sk,
            x25519_pub,
        }
    }

    /// TLV 0x07 value: ML-KEM-768 ek (1184) || X25519 public (32), ML-KEM-first.
    fn kem_share(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(KEM_SHARE_LEN);
        out.extend_from_slice(&self.mlkem_ek_bytes);
        out.extend_from_slice(&self.x25519_pub);
        out
    }

    /// Decapsulates the server's KEMCiphertext into (ML-KEM_SS, X25519_SS).
    fn shared_secrets(&self, kem_ct: &[u8]) -> io::Result<(Vec<u8>, Vec<u8>)> {
        if kem_ct.len() != KEM_CIPHERTEXT_LEN {
            return Err(proto("KEMCiphertext is not 1120 octets"));
        }
        let ct: Ciphertext<MlKem768> =
            Array::try_from(&kem_ct[..MLKEM768_CT_LEN]).map_err(|_| proto("ML-KEM ciphertext"))?;
        let mlkem_ss = self.mlkem_dk.decapsulate(&ct).map_err(|_| proto("ML-KEM decapsulate"))?;
        let mut server_pub = [0u8; 32];
        server_pub.copy_from_slice(&kem_ct[MLKEM768_CT_LEN..]);
        let x_ss = self.x25519_sk.diffie_hellman(&XPublicKey::from(server_pub)).to_bytes();
        if x_ss.iter().all(|&b| b == 0) {
            return Err(proto("X25519 produced an all-zero (low-order) shared secret"));
        }
        Ok((mlkem_ss.as_slice().to_vec(), x_ss.to_vec()))
    }
}

/// Server side: parse the client KEMShare, encapsulate, and return the TLV 0x08
/// KEMCiphertext value plus (ML-KEM_SS, X25519_SS).
fn encapsulate(kem_share: &[u8]) -> io::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    if kem_share.len() != KEM_SHARE_LEN {
        return Err(proto("KEMShare is not 1216 octets"));
    }
    let ek_arr =
        Array::try_from(&kem_share[..MLKEM768_EK_LEN]).map_err(|_| proto("ML-KEM ek bytes"))?;
    let ek = Ek768::from_bytes(&ek_arr);
    let mut client_pub = [0u8; 32];
    client_pub.copy_from_slice(&kem_share[MLKEM768_EK_LEN..]);

    let m = Array::try_from(&os_random::<32>()[..]).unwrap();
    let (ct, mlkem_ss) = ek.encapsulate_deterministic(&m).map_err(|_| proto("ML-KEM encapsulate"))?;

    let server_sk = XStaticSecret::from(os_random::<32>());
    let server_pub = XPublicKey::from(&server_sk).to_bytes();
    let x_ss = server_sk.diffie_hellman(&XPublicKey::from(client_pub)).to_bytes();
    if x_ss.iter().all(|&b| b == 0) {
        return Err(proto("X25519 produced an all-zero (low-order) shared secret"));
    }

    let mut kem_ct = Vec::with_capacity(KEM_CIPHERTEXT_LEN);
    kem_ct.extend_from_slice(ct.as_slice());
    kem_ct.extend_from_slice(&server_pub);
    Ok((kem_ct, mlkem_ss.as_slice().to_vec(), x_ss.to_vec()))
}

/// The authenticated result of a completed handshake.
pub struct Session {
    pub master: Vec<u8>,
    pub peer_identity: [u8; 32],
}

// ---------------------------------------------------------------------------
// The 1.5-RTT client handshake (mirrors runClientHandshake).
// ---------------------------------------------------------------------------
pub fn run_client_handshake(
    s: &mut TcpStream,
    identity: &SigningKey,
    expected_peer: Option<[u8; 32]>,
) -> io::Result<Session> {
    let client_pub = identity.verifying_key().to_bytes();
    let kem = KemClient::generate();
    let kem_share = kem.kem_share();

    // --- CLIENT_HELLO (cleartext) ---
    let mut ch = Vec::new();
    tlv(&mut ch, TLV_PROFILE_OFFER, &[PROFILE_STANDARD]);
    tlv(&mut ch, TLV_KEM_OFFER, &npamp::KEM_X25519_MLKEM768.to_be_bytes());
    tlv(&mut ch, TLV_SIG_OFFER, &npamp::SIG_ED25519.to_be_bytes());
    tlv(&mut ch, TLV_AEAD_OFFER, &npamp::AEAD_AES256_GCM.to_be_bytes());
    tlv(&mut ch, TLV_KEM_SHARE, &kem_share);
    write_frame(s, &cleartext_frame(FRAME_CLIENT_HELLO, ch))?;

    let mut t = Transcript::new();
    t.add_frame_type(FRAME_CLIENT_HELLO);
    t.add_tlv(TLV_PROFILE_OFFER, &[PROFILE_STANDARD]);
    t.add_tlv(TLV_KEM_OFFER, &npamp::KEM_X25519_MLKEM768.to_be_bytes());
    t.add_tlv(TLV_SIG_OFFER, &npamp::SIG_ED25519.to_be_bytes());
    t.add_tlv(TLV_AEAD_OFFER, &npamp::AEAD_AES256_GCM.to_be_bytes());
    t.add_tlv(TLV_KEM_SHARE, &kem_share);

    // --- SERVER_HELLO (cleartext) ---
    let sh_wire = read_frame(s)?;
    let sh = npamp::Frame::unmarshal(&sh_wire).map_err(|_| proto("SERVER_HELLO parse"))?;
    if sh.ftype != FRAME_SERVER_HELLO {
        return Err(proto("expected SERVER_HELLO"));
    }
    let sh_vals = require_tlvs(
        &decode_tlvs(&sh.payload)?,
        &[
            TLV_PROFILE_SELECT,
            TLV_KEM_SELECT,
            TLV_SIG_SELECT,
            TLV_AEAD_SELECT,
            TLV_KEM_CIPHERTEXT,
        ],
    )?;
    require_standard_select(&sh_vals)?;
    let kem_ct = &sh_vals[4];
    t.add_frame_type(FRAME_SERVER_HELLO);
    t.add_tlv(TLV_PROFILE_SELECT, &sh_vals[0]);
    t.add_tlv(TLV_KEM_SELECT, &sh_vals[1]);
    t.add_tlv(TLV_SIG_SELECT, &sh_vals[2]);
    t.add_tlv(TLV_AEAD_SELECT, &sh_vals[3]);
    t.add_tlv(TLV_KEM_CIPHERTEXT, kem_ct);

    // --- key schedule ---
    let (mlkem_ss, x_ss) = kem.shared_secrets(kem_ct)?;
    let hs = npamp::derive_handshake_secret(&mlkem_ss, &x_ss, STANDARD);
    let th_kem = t.hash(STANDARD);
    let c_hs = npamp::derive_client_handshake_secret(&hs, &th_kem, STANDARD);
    let s_hs = npamp::derive_server_handshake_secret(&hs, &th_kem, STANDARD);

    // --- SERVER_AUTH (sealed under s_hs, s2c) ---
    let sa_wire = read_frame(s)?;
    let sa = parse_enc_frame(&sa_wire, FRAME_SERVER_AUTH)?;
    let sa_pt = open_frame(&sa, &s_hs, DIR_S2C)?;
    let (sid, scv, sfin) = decode_auth(&sa_pt)?;
    t.add_frame_type(FRAME_SERVER_AUTH);
    t.add_tlv(TLV_IDENTITY_KEY, &sid);
    let server_vk = vk_from(&sid)?;
    if !handshake::verify_cert_verify(&server_vk, true, &t.hash(STANDARD), &scv) {
        return Err(proto("server CertVerify rejected"));
    }
    t.add_tlv(TLV_CERT_VERIFY, &scv);
    let s_fin_key = npamp::finished_key(&s_hs, STANDARD);
    if !handshake::verify_finished(&s_fin_key, &t.hash(STANDARD), &sfin, STANDARD) {
        return Err(proto("server Finished rejected"));
    }
    t.add_tlv(TLV_FINISHED, &sfin);
    let peer_identity = to32(&sid)?;
    if let Some(exp) = expected_peer {
        if !ct_eq(&peer_identity, &exp) {
            return Err(proto("server identity does not match the pinned key"));
        }
    }

    // --- CLIENT_AUTH (sealed under c_hs, c2s) ---
    t.add_frame_type(FRAME_CLIENT_AUTH);
    t.add_tlv(TLV_IDENTITY_KEY, &client_pub);
    let c_cv = handshake::sign_cert_verify(identity, false, &t.hash(STANDARD));
    t.add_tlv(TLV_CERT_VERIFY, &c_cv);
    let th_ccv = t.hash(STANDARD);
    let c_fin_key = npamp::finished_key(&c_hs, STANDARD);
    let c_fin = handshake::compute_finished(&c_fin_key, &th_ccv, STANDARD);
    let ca_pt = encode_auth(&client_pub, &c_cv, &c_fin);
    let ca_wire = seal_frame(
        &c_hs,
        DIR_C2S,
        npamp::CHAN_CONTROL,
        0,
        FRAME_CLIENT_AUTH,
        &ca_pt,
    );
    write_frame(s, &ca_wire)?;

    let master = npamp::derive_master_secret(&hs, &th_ccv, STANDARD);
    Ok(Session { master, peer_identity })
}

// ---------------------------------------------------------------------------
// The 1.5-RTT server handshake (mirrors runServerHandshake).
// ---------------------------------------------------------------------------
pub fn run_server_handshake(
    s: &mut TcpStream,
    identity: &SigningKey,
    expected_peer: Option<[u8; 32]>,
) -> io::Result<Session> {
    let server_pub = identity.verifying_key().to_bytes();
    let mut t = Transcript::new();

    // --- CLIENT_HELLO ---
    let ch_wire = read_frame(s)?;
    let ch = npamp::Frame::unmarshal(&ch_wire).map_err(|_| proto("CLIENT_HELLO parse"))?;
    if ch.ftype != FRAME_CLIENT_HELLO {
        return Err(proto("expected CLIENT_HELLO"));
    }
    let ch_vals = require_tlvs(
        &decode_tlvs(&ch.payload)?,
        &[
            TLV_PROFILE_OFFER,
            TLV_KEM_OFFER,
            TLV_SIG_OFFER,
            TLV_AEAD_OFFER,
            TLV_KEM_SHARE,
        ],
    )?;
    require_standard_offer(&ch_vals)?;
    let kem_share = &ch_vals[4];
    t.add_frame_type(FRAME_CLIENT_HELLO);
    t.add_tlv(TLV_PROFILE_OFFER, &ch_vals[0]);
    t.add_tlv(TLV_KEM_OFFER, &ch_vals[1]);
    t.add_tlv(TLV_SIG_OFFER, &ch_vals[2]);
    t.add_tlv(TLV_AEAD_OFFER, &ch_vals[3]);
    t.add_tlv(TLV_KEM_SHARE, kem_share);

    // --- SERVER_HELLO ---
    let (kem_ct, mlkem_ss, x_ss) = encapsulate(kem_share)?;
    let mut sh = Vec::new();
    tlv(&mut sh, TLV_PROFILE_SELECT, &[PROFILE_STANDARD]);
    tlv(&mut sh, TLV_KEM_SELECT, &npamp::KEM_X25519_MLKEM768.to_be_bytes());
    tlv(&mut sh, TLV_SIG_SELECT, &npamp::SIG_ED25519.to_be_bytes());
    tlv(&mut sh, TLV_AEAD_SELECT, &npamp::AEAD_AES256_GCM.to_be_bytes());
    tlv(&mut sh, TLV_KEM_CIPHERTEXT, &kem_ct);
    write_frame(s, &cleartext_frame(FRAME_SERVER_HELLO, sh))?;
    t.add_frame_type(FRAME_SERVER_HELLO);
    t.add_tlv(TLV_PROFILE_SELECT, &[PROFILE_STANDARD]);
    t.add_tlv(TLV_KEM_SELECT, &npamp::KEM_X25519_MLKEM768.to_be_bytes());
    t.add_tlv(TLV_SIG_SELECT, &npamp::SIG_ED25519.to_be_bytes());
    t.add_tlv(TLV_AEAD_SELECT, &npamp::AEAD_AES256_GCM.to_be_bytes());
    t.add_tlv(TLV_KEM_CIPHERTEXT, &kem_ct);

    // --- key schedule ---
    let hs = npamp::derive_handshake_secret(&mlkem_ss, &x_ss, STANDARD);
    let th_kem = t.hash(STANDARD);
    let c_hs = npamp::derive_client_handshake_secret(&hs, &th_kem, STANDARD);
    let s_hs = npamp::derive_server_handshake_secret(&hs, &th_kem, STANDARD);

    // --- SERVER_AUTH (sealed under s_hs, s2c) ---
    t.add_frame_type(FRAME_SERVER_AUTH);
    t.add_tlv(TLV_IDENTITY_KEY, &server_pub);
    let s_cv = handshake::sign_cert_verify(identity, true, &t.hash(STANDARD));
    t.add_tlv(TLV_CERT_VERIFY, &s_cv);
    let s_fin_key = npamp::finished_key(&s_hs, STANDARD);
    let s_fin = handshake::compute_finished(&s_fin_key, &t.hash(STANDARD), STANDARD);
    t.add_tlv(TLV_FINISHED, &s_fin);
    let sa_pt = encode_auth(&server_pub, &s_cv, &s_fin);
    let sa_wire = seal_frame(
        &s_hs,
        DIR_S2C,
        npamp::CHAN_CONTROL,
        0,
        FRAME_SERVER_AUTH,
        &sa_pt,
    );
    write_frame(s, &sa_wire)?;

    // --- CLIENT_AUTH (sealed under c_hs, c2s) ---
    let ca_wire = read_frame(s)?;
    let ca = parse_enc_frame(&ca_wire, FRAME_CLIENT_AUTH)?;
    let ca_pt = open_frame(&ca, &c_hs, DIR_C2S)?;
    let (cid, ccv, cfin) = decode_auth(&ca_pt)?;
    t.add_frame_type(FRAME_CLIENT_AUTH);
    t.add_tlv(TLV_IDENTITY_KEY, &cid);
    let client_vk = vk_from(&cid)?;
    if !handshake::verify_cert_verify(&client_vk, false, &t.hash(STANDARD), &ccv) {
        return Err(proto("client CertVerify rejected"));
    }
    t.add_tlv(TLV_CERT_VERIFY, &ccv);
    let th_ccv = t.hash(STANDARD);
    let c_fin_key = npamp::finished_key(&c_hs, STANDARD);
    if !handshake::verify_finished(&c_fin_key, &th_ccv, &cfin, STANDARD) {
        return Err(proto("client Finished rejected"));
    }
    let peer_identity = to32(&cid)?;
    if let Some(exp) = expected_peer {
        if !ct_eq(&peer_identity, &exp) {
            return Err(proto("client identity does not match the pinned key"));
        }
    }

    let master = npamp::derive_master_secret(&hs, &th_ccv, STANDARD);
    Ok(Session { master, peer_identity })
}

// ---------------------------------------------------------------------------
// Application record layer over the established session (epoch 0).
// ---------------------------------------------------------------------------
/// Seals `payload` on `channel` at `seq` under the send-direction master key and
/// writes it.
pub fn send_data(
    s: &mut TcpStream,
    master: &[u8],
    send_dir: u8,
    channel: u16,
    ftype: u16,
    seq: u64,
    payload: &[u8],
) -> io::Result<()> {
    write_frame(s, &seal_frame(master, send_dir, channel, seq, ftype, payload))
}

/// Reads one application frame, checks the per-(channel) sequence, and opens it
/// under the receive-direction master key. Returns (channel, frame type, plaintext).
pub fn recv_data(
    s: &mut TcpStream,
    master: &[u8],
    recv_dir: u8,
    want_seq: u64,
) -> io::Result<(u16, u16, Vec<u8>)> {
    let wire = read_frame(s)?;
    let f = npamp::Frame::unmarshal(&wire).map_err(|_| proto("data frame parse"))?;
    if f.flags & npamp::FLAG_ENC == 0 {
        return Err(proto("data frame is not AEAD-encrypted"));
    }
    if f.seq != want_seq {
        return Err(proto("out-of-sequence data frame"));
    }
    let pt = open_frame(&f, master, recv_dir)?;
    Ok((f.channel, f.ftype, pt))
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------
fn parse_enc_frame(wire: &[u8], want: u16) -> io::Result<npamp::Frame> {
    let f = npamp::Frame::unmarshal(wire).map_err(|_| proto("AUTH frame parse"))?;
    if f.ftype != want {
        return Err(proto("unexpected AUTH frame type"));
    }
    if f.flags & npamp::FLAG_ENC == 0 {
        return Err(proto("AUTH frame is not AEAD-encrypted"));
    }
    Ok(f)
}

fn encode_auth(identity: &[u8], cert_verify: &[u8], finished: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    tlv(&mut out, TLV_IDENTITY_KEY, identity);
    tlv(&mut out, TLV_CERT_VERIFY, cert_verify);
    tlv(&mut out, TLV_FINISHED, finished);
    out
}

fn decode_auth(pt: &[u8]) -> io::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let vals = require_tlvs(
        &decode_tlvs(pt)?,
        &[TLV_IDENTITY_KEY, TLV_CERT_VERIFY, TLV_FINISHED],
    )?;
    Ok((vals[0].clone(), vals[1].clone(), vals[2].clone()))
}

fn vk_from(raw: &[u8]) -> io::Result<VerifyingKey> {
    ed25519_verifying_key_from_raw(&to32(raw)?).map_err(|_| proto("invalid Ed25519 identity key"))
}

fn to32(b: &[u8]) -> io::Result<[u8; 32]> {
    if b.len() != 32 {
        return Err(proto("identity key is not 32 octets"));
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(b);
    Ok(a)
}

/// Constant-time equality for the pinned-identity check.
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn require_standard_offer(vals: &[Vec<u8>]) -> io::Result<()> {
    if !vals[0].contains(&PROFILE_STANDARD) {
        return Err(proto("client did not offer the Standard profile"));
    }
    if !list_contains_u16(&vals[1], npamp::KEM_X25519_MLKEM768) {
        return Err(proto("client did not offer X25519MLKEM768"));
    }
    if !list_contains_u16(&vals[2], npamp::SIG_ED25519) {
        return Err(proto("client did not offer Ed25519"));
    }
    if !list_contains_u16(&vals[3], npamp::AEAD_AES256_GCM) {
        return Err(proto("client did not offer AES-256-GCM"));
    }
    Ok(())
}

fn require_standard_select(vals: &[Vec<u8>]) -> io::Result<()> {
    if vals[0] != [PROFILE_STANDARD] {
        return Err(proto("server selected an unsupported profile"));
    }
    if vals[1] != npamp::KEM_X25519_MLKEM768.to_be_bytes() {
        return Err(proto("server selected an unsupported KEM"));
    }
    if vals[2] != npamp::SIG_ED25519.to_be_bytes() {
        return Err(proto("server selected an unsupported signature"));
    }
    if vals[3] != npamp::AEAD_AES256_GCM.to_be_bytes() {
        return Err(proto("server selected an unsupported AEAD"));
    }
    Ok(())
}

fn list_contains_u16(v: &[u8], want: u16) -> bool {
    if v.len() % 2 != 0 {
        return false;
    }
    v.chunks_exact(2).any(|c| u16::from_be_bytes([c[0], c[1]]) == want)
}
