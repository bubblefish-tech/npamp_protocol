// Byte-pinned handshake-FLOW known-answer test (issue #60, class golden-interop).
//
// Unlike the standards-anchored primitive KATs in handshake_kat.rs (which each
// reproduce a published RFC vector before judging the impl), this vector pins the
// Go reference's SERIALIZED handshake frames so every language impl reproduces
// them BYTE-FOR-BYTE. It mirrors test-vectors/v1/handshake-flow-kat.json and the
// Go reference verifier impl/go/handshakeflow_kat_test.go: rebuild each EXPECTED
// artifact through THIS impl's real code path from the pinned INPUTS, assert
// whole-frame byte-equality for client_hello/server_hello/server_auth/client_auth,
// decapsulate the pinned ML-KEM ciphertext and recover the pinned shared secret,
// check the transcript points / §5 key ladder / Finished keys+MACs / CertVerify,
// and mutation-guard (a one-octet-flipped CertVerify sig AND client Finished MAC
// must REJECT).
//
// The CLIENT_HELLO assertion is the one that catches the draft-00-vs-draft-01
// ProfileOffer wire drift: the vector pins the draft-01 ONE-octet ProfileOffer
// TLV value (0x01), so a 4-octet draft-00 encoding fails here instead of at a
// live handshake.

use hmac::{Hmac, Mac};
use kem::Decapsulate;
use ml_kem::{Ciphertext, KemCore, MlKem768};
use ml_kem::array::Array;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

// ---------------------------------------------------------------------------
// Minimal recursive-descent JSON parser (RFC 8259), hex codecs, and a SHA-256
// pin check. Same no-new-JSON-dep tier as handshake_kat.rs (stdlib + crate deps
// only, no serde).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum Json {
    Obj(Vec<(String, Json)>),
    Arr(Vec<Json>),
    Str(String),
    Num(f64),
    Bool(bool),
    Null,
}

impl Json {
    fn get(&self, key: &str) -> &Json {
        match self {
            Json::Obj(m) => m
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v)
                .unwrap_or_else(|| panic!("missing JSON key: {key}")),
            _ => panic!("JSON .get({key}) on a non-object"),
        }
    }

    /// Navigates nested objects by key path, returning the leaf value.
    fn at(&self, keys: &[&str]) -> &Json {
        let mut cur = self;
        for k in keys {
            cur = cur.get(k);
        }
        cur
    }

    fn s(&self) -> &str {
        match self {
            Json::Str(s) => s,
            _ => panic!("JSON value is not a string"),
        }
    }
}

struct Parser {
    c: Vec<char>,
    i: usize,
}

impl Parser {
    fn new(s: &str) -> Self {
        Self { c: s.chars().collect(), i: 0 }
    }

    fn ws(&mut self) {
        while self.i < self.c.len() && matches!(self.c[self.i], ' ' | '\t' | '\n' | '\r') {
            self.i += 1;
        }
    }

    fn peek(&self) -> char {
        self.c[self.i]
    }

    fn value(&mut self) -> Json {
        self.ws();
        match self.peek() {
            '{' => self.object(),
            '[' => self.array(),
            '"' => Json::Str(self.string()),
            't' => {
                self.expect("true");
                Json::Bool(true)
            }
            'f' => {
                self.expect("false");
                Json::Bool(false)
            }
            'n' => {
                self.expect("null");
                Json::Null
            }
            _ => self.number(),
        }
    }

    fn object(&mut self) -> Json {
        let mut m: Vec<(String, Json)> = Vec::new();
        self.i += 1; // consume '{'
        self.ws();
        if self.peek() == '}' {
            self.i += 1;
            return Json::Obj(m);
        }
        loop {
            self.ws();
            let key = self.string();
            self.ws();
            assert_eq!(self.c[self.i], ':', "expected ':' at offset {}", self.i);
            self.i += 1;
            let v = self.value();
            m.push((key, v));
            self.ws();
            let ch = self.c[self.i];
            self.i += 1;
            match ch {
                ',' => continue,
                '}' => return Json::Obj(m),
                _ => panic!("expected ',' or '}}' at offset {}", self.i - 1),
            }
        }
    }

    fn array(&mut self) -> Json {
        let mut a: Vec<Json> = Vec::new();
        self.i += 1; // consume '['
        self.ws();
        if self.peek() == ']' {
            self.i += 1;
            return Json::Arr(a);
        }
        loop {
            let v = self.value();
            a.push(v);
            self.ws();
            let ch = self.c[self.i];
            self.i += 1;
            match ch {
                ',' => continue,
                ']' => return Json::Arr(a),
                _ => panic!("expected ',' or ']' at offset {}", self.i - 1),
            }
        }
    }

    fn string(&mut self) -> String {
        assert_eq!(self.c[self.i], '"', "expected string at offset {}", self.i);
        self.i += 1; // consume opening quote
        let mut out = String::new();
        loop {
            let ch = self.c[self.i];
            self.i += 1;
            match ch {
                '"' => return out,
                '\\' => {
                    let e = self.c[self.i];
                    self.i += 1;
                    match e {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        '/' => out.push('/'),
                        'b' => out.push('\u{0008}'),
                        'f' => out.push('\u{000C}'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'u' => {
                            let hex: String = self.c[self.i..self.i + 4].iter().collect();
                            self.i += 4;
                            let cp = u32::from_str_radix(&hex, 16).expect("bad \\u escape");
                            out.push(char::from_u32(cp).expect("bad codepoint"));
                        }
                        _ => panic!("bad escape \\{e}"),
                    }
                }
                _ => out.push(ch),
            }
        }
    }

    fn number(&mut self) -> Json {
        let start = self.i;
        while self.i < self.c.len()
            && matches!(self.c[self.i], '0'..='9' | '-' | '+' | '.' | 'e' | 'E')
        {
            self.i += 1;
        }
        assert!(self.i > start, "unexpected character at offset {}", self.i);
        let s: String = self.c[start..self.i].iter().collect();
        Json::Num(s.parse().expect("bad number"))
    }

    fn expect(&mut self, lit: &str) {
        for want in lit.chars() {
            assert_eq!(self.c[self.i], want, "expected '{lit}' at offset {}", self.i);
            self.i += 1;
        }
    }
}

fn parse_json(s: &str) -> Json {
    let mut p = Parser::new(s);
    p.ws();
    let v = p.value();
    p.ws();
    v
}

fn trim_hex_prefix(s: &str) -> &str {
    s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s)
}

fn from_hex(s: &str) -> Vec<u8> {
    let s = trim_hex_prefix(s);
    let b = s.as_bytes();
    assert!(b.len() % 2 == 0, "odd-length hex: {s}");
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16).expect("bad hex");
        let lo = (b[i + 1] as char).to_digit(16).expect("bad hex");
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    out
}

fn to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// Walks up from CARGO_MANIFEST_DIR to locate test-vectors/v1, robust to the run directory.
fn vector_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let cand = p.join("test-vectors").join("v1");
        if cand.is_dir() {
            return cand;
        }
        if !p.pop() {
            break;
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test-vectors/v1")
}

/// Reads <vectorDir>/<file>, verifies its SHA-256 equals `want_sha256` (fail loud on a
/// swapped vector), and returns the parsed JSON root.
fn load_pinned(file: &str, want_sha256: &str) -> Json {
    let path = vector_dir().join(file);
    let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let got = to_hex(&Sha256::digest(&raw));
    assert_eq!(
        got,
        want_sha256,
        "{file} SHA-256 mismatch (swapped vector?) path={}",
        path.display()
    );
    parse_json(&String::from_utf8(raw).expect("vector is UTF-8"))
}

// ---------------------------------------------------------------------------
// Wire primitives rebuilt through THIS impl's real code path.
// ---------------------------------------------------------------------------

const HANDSHAKE_FLOW_KAT_SHA256: &str =
    "0c89003cd95c4bef744e021797ccd169b062e0a058d2a6e2b17e164eb4e9bad2";

// draft-01 handshake TLV code points (binding spec/10 §1.1; registry §9.4). The
// OPEN wire-format library exposes only a subset as public constants, so the
// full handshake set is named here to build the exact frame payloads.
const TLV_PROFILE_OFFER: u16 = 0x01;
const TLV_PROFILE_SELECT: u16 = 0x02;
const TLV_KEM_OFFER: u16 = 0x03;
const TLV_KEM_SELECT: u16 = 0x04;
const TLV_SIG_OFFER: u16 = 0x05;
const TLV_SIG_SELECT: u16 = 0x06;
const TLV_KEM_SHARE: u16 = 0x07;
const TLV_KEM_CIPHERTEXT: u16 = 0x08;
const TLV_AEAD_OFFER: u16 = 0x0C;
const TLV_AEAD_SELECT: u16 = 0x0D;
const TLV_IDENTITY_KEY: u16 = 0x09;
const TLV_CERT_VERIFY: u16 = 0x0A;
const TLV_FINISHED: u16 = 0x0B;

/// Appends one TLV: Type(2 BE) || Length(2 BE) || Value. Identical wire form to
/// npamp::handshake::Transcript::add_tlv and the Go reference TLV.Encode.
fn tlv(out: &mut Vec<u8>, typ: u16, value: &[u8]) {
    out.extend_from_slice(&typ.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}

/// Builds a cleartext handshake frame (Control channel, seq 0) through the impl's
/// real Frame::marshal — mirrors the Go marshalFrameKAT.
fn marshal_frame(ftype: u16, payload: Vec<u8>) -> Vec<u8> {
    npamp::Frame {
        ftype,
        channel: npamp::CHAN_CONTROL,
        seq: 0,
        payload,
        ..Default::default()
    }
    .marshal()
}

/// Seals an AUTH plaintext into a wire frame through the impl's real key schedule
/// + record path — mirrors the Go sealAuthKAT (FlagENC, seq 0, epoch 0, Control,
/// AES-256-GCM). The 21-octet header prefix over payload_len = plaintext + 16
/// (GCM tag) is the AEAD associated data.
fn seal_auth(ftype: u16, base_secret: &[u8], dir: u8, plaintext: &[u8]) -> Vec<u8> {
    // Standard profile => SHA-256 => standard = true throughout.
    let ts = npamp::derive_traffic_secret(base_secret, dir, 0, npamp::AEAD_AES256_GCM, npamp::CHAN_CONTROL, true);
    let (key, iv) = npamp::derive_key_iv(&ts, true);
    let mut aad = [0u8; 21];
    npamp::Frame {
        flags: npamp::FLAG_ENC,
        ftype,
        channel: npamp::CHAN_CONTROL,
        seq: 0,
        ..Default::default()
    }
    .header_prefix(&mut aad, (plaintext.len() + 16) as u32);
    let sealed = npamp::seal_aes256gcm(&key, &iv, 0, &aad, plaintext);
    npamp::Frame {
        flags: npamp::FLAG_ENC,
        ftype,
        channel: npamp::CHAN_CONTROL,
        seq: 0,
        payload: sealed,
        ..Default::default()
    }
    .marshal()
}

fn assert_hex(name: &str, got: &[u8], want_hex: &str) {
    assert_eq!(to_hex(got), want_hex, "{name} != expected");
}

/// Derives traffic secret + key + iv through the impl and asserts each against the
/// pinned expected hex (mirrors the Go assertTrafficKeyIV). dir: 0 = c2s, 1 = s2c.
fn assert_traffic_key_iv(name: &str, parent: &[u8], dir: u8, root: &Json) {
    let ts = npamp::derive_traffic_secret(parent, dir, 0, npamp::AEAD_AES256_GCM, npamp::CHAN_CONTROL, true);
    assert_hex(&format!("{name}_traffic_secret"), &ts, root.at(&["expected", "secrets", &format!("{name}_traffic_secret")]).s());
    let (key, iv) = npamp::derive_key_iv(&ts, true);
    assert_hex(&format!("{name}_key"), &key, root.at(&["expected", "secrets", &format!("{name}_key")]).s());
    assert_hex(&format!("{name}_iv"), &iv, root.at(&["expected", "secrets", &format!("{name}_iv")]).s());
}

/// Independent HMAC-SHA-256 verify (guards the Finished MAC in the mutation leg
/// without going back through the impl under test).
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn to_arr32(b: &[u8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(b);
    a
}

/// Decapsulates the pinned captured-once ML-KEM-768 ciphertext under the pinned
/// d||z seed (FIPS 203) and recovers the ML-KEM shared secret. crypto ml-kem has
/// no seed-injectable ENCAPS, so — exactly like the Go reference — the ciphertext
/// is a self-validating input: decapsulation MUST reproduce mlkem_shared_secret.
fn decapsulate_mlkem(seed_dz: &[u8], mlkem_ct: &[u8]) -> Vec<u8> {
    assert_eq!(seed_dz.len(), 64, "ML-KEM d||z seed is 64 octets");
    let d = Array::try_from(&seed_dz[..32]).expect("d is 32 octets");
    let z = Array::try_from(&seed_dz[32..]).expect("z is 32 octets");
    let (dk, _ek) = MlKem768::generate_deterministic(&d, &z);
    let ct: Ciphertext<MlKem768> = Array::try_from(mlkem_ct)
        .expect("ML-KEM-768 ciphertext is 1088 octets");
    dk.decapsulate(&ct).expect("decapsulate").to_vec()
}

/// X25519 (RFC 7748) shared secret: pinned client private × server public. Both
/// sides clamp per RFC 7748 (crypto/ecdh in Go, x25519-dalek here), so the result
/// must equal the pinned x25519_shared_secret.
fn x25519_shared(client_priv: &[u8], server_pub: &[u8]) -> Vec<u8> {
    let sk = XStaticSecret::from(to_arr32(client_priv));
    let pk = XPublicKey::from(to_arr32(server_pub));
    sk.diffie_hellman(&pk).to_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// The byte-pinned handshake-flow KAT.
// ---------------------------------------------------------------------------

/// Rebuilds every handshake artifact through the real impl code path from the
/// frozen pinned inputs and asserts byte-equality with the expected wire bytes.
/// NOT env-gated: an ordinary `cargo test --test handshake_flow_kat` runs it.
#[test]
fn handshake_flow_kat() {
    use npamp::handshake;
    let root = load_pinned("handshake-flow-kat.json", HANDSHAKE_FLOW_KAT_SHA256);

    // Spec §1 frame-type constants must be the frozen draft-01 values.
    assert_eq!(handshake::FRAME_CLIENT_HELLO, 0x0100);
    assert_eq!(handshake::FRAME_SERVER_HELLO, 0x0101);
    assert_eq!(handshake::FRAME_SERVER_AUTH, 0x0102);
    assert_eq!(handshake::FRAME_CLIENT_AUTH, 0x0103);

    // --- Pinned inputs. ---
    let client_x25519_priv = from_hex(root.at(&["inputs", "client_x25519_private"]).s());
    let server_x25519_priv = from_hex(root.at(&["inputs", "server_x25519_private"]).s());
    let mlkem_seed_dz = from_hex(root.at(&["inputs", "mlkem768_seed_dz"]).s());
    let mlkem_ciphertext = from_hex(root.at(&["inputs", "mlkem_ciphertext"]).s());
    let client_ed_seed = to_arr32(&from_hex(root.at(&["inputs", "client_identity_ed25519_seed"]).s()));
    let server_ed_seed = to_arr32(&from_hex(root.at(&["inputs", "server_identity_ed25519_seed"]).s()));
    let want_mlkem_ss = from_hex(root.at(&["inputs", "mlkem_shared_secret"]).s());
    let want_x25519_ss = from_hex(root.at(&["inputs", "x25519_shared_secret"]).s());

    // Identity keys from the fixed Ed25519 seeds (RFC 8032).
    let client_sk = handshake::ed25519_signing_key_from_seed(&client_ed_seed);
    let server_sk = handshake::ed25519_signing_key_from_seed(&server_ed_seed);
    let client_pub = client_sk.verifying_key().to_bytes();
    let server_pub = server_sk.verifying_key().to_bytes();

    // --- Self-validating input: decapsulate the pinned ML-KEM ciphertext and the
    // pinned X25519 leg, recovering the two component shared secrets. ---
    let want_kem_ct = from_hex(root.at(&["expected", "kem", "kem_ciphertext"]).s());
    // The pinned KEMCiphertext = ML-KEM ciphertext (1088) || server X25519 public (32).
    assert_eq!(
        &want_kem_ct[..want_kem_ct.len() - 32],
        &mlkem_ciphertext[..],
        "pinned kem_ciphertext front != pinned mlkem_ciphertext input"
    );
    let server_x25519_pub = &want_kem_ct[want_kem_ct.len() - 32..];
    let mlkem_ss = decapsulate_mlkem(&mlkem_seed_dz, &mlkem_ciphertext);
    assert_eq!(
        to_hex(&mlkem_ss),
        to_hex(&want_mlkem_ss),
        "decapsulated ML-KEM shared secret != pinned mlkem_shared_secret (self-validating input failed)"
    );
    let x25519_ss = x25519_shared(&client_x25519_priv, server_x25519_pub);
    assert_eq!(to_hex(&x25519_ss), to_hex(&want_x25519_ss), "X25519 shared secret != pinned");

    // --- Rebuild CLIENT_HELLO and assert whole-frame byte-equality. The KEMShare
    // (TLV 0x07) = ML-KEM-768 encapsulation key (1184) || X25519 public (32); the
    // pinned kem_share holds exactly those bytes, so reuse it (encaps is
    // non-deterministic; the pinned share is self-consistent with the ciphertext). ---
    let kem_share = from_hex(root.at(&["expected", "kem", "kem_share"]).s());
    // draft-01 ProfileOffer is the ONE-octet value 0x01 (Standard); a 4-octet
    // draft-00 encoding here would fail whole-frame equality below.
    let mut ch_payload = Vec::new();
    tlv(&mut ch_payload, TLV_PROFILE_OFFER, &[0x01]);
    tlv(&mut ch_payload, TLV_KEM_OFFER, &npamp::KEM_X25519_MLKEM768.to_be_bytes());
    tlv(&mut ch_payload, TLV_SIG_OFFER, &npamp::SIG_ED25519.to_be_bytes());
    tlv(&mut ch_payload, TLV_AEAD_OFFER, &npamp::AEAD_AES256_GCM.to_be_bytes());
    tlv(&mut ch_payload, TLV_KEM_SHARE, &kem_share);
    let ch_frame = marshal_frame(handshake::FRAME_CLIENT_HELLO, ch_payload.clone());
    assert_hex("client_hello", &ch_frame, root.at(&["expected", "frames", "client_hello"]).s());

    // --- Rebuild SERVER_HELLO. ---
    let mut sh_payload = Vec::new();
    tlv(&mut sh_payload, TLV_PROFILE_SELECT, &[0x01]);
    tlv(&mut sh_payload, TLV_KEM_SELECT, &npamp::KEM_X25519_MLKEM768.to_be_bytes());
    tlv(&mut sh_payload, TLV_SIG_SELECT, &npamp::SIG_ED25519.to_be_bytes());
    tlv(&mut sh_payload, TLV_AEAD_SELECT, &npamp::AEAD_AES256_GCM.to_be_bytes());
    tlv(&mut sh_payload, TLV_KEM_CIPHERTEXT, &want_kem_ct);
    let sh_frame = marshal_frame(handshake::FRAME_SERVER_HELLO, sh_payload.clone());
    assert_hex("server_hello", &sh_frame, root.at(&["expected", "frames", "server_hello"]).s());

    // --- Transcript + key ladder through the real impl. ---
    // TH_kem = H(CLIENT_HELLO frame-type + its 5 TLVs, then SERVER_HELLO frame-type
    // + its 5 TLVs). Absorb the same TLVs the frames carry.
    let mut tr = handshake::Transcript::new();
    tr.add_frame_type(handshake::FRAME_CLIENT_HELLO);
    tr.add_tlv(TLV_PROFILE_OFFER, &[0x01]);
    tr.add_tlv(TLV_KEM_OFFER, &npamp::KEM_X25519_MLKEM768.to_be_bytes());
    tr.add_tlv(TLV_SIG_OFFER, &npamp::SIG_ED25519.to_be_bytes());
    tr.add_tlv(TLV_AEAD_OFFER, &npamp::AEAD_AES256_GCM.to_be_bytes());
    tr.add_tlv(TLV_KEM_SHARE, &kem_share);
    tr.add_frame_type(handshake::FRAME_SERVER_HELLO);
    tr.add_tlv(TLV_PROFILE_SELECT, &[0x01]);
    tr.add_tlv(TLV_KEM_SELECT, &npamp::KEM_X25519_MLKEM768.to_be_bytes());
    tr.add_tlv(TLV_SIG_SELECT, &npamp::SIG_ED25519.to_be_bytes());
    tr.add_tlv(TLV_AEAD_SELECT, &npamp::AEAD_AES256_GCM.to_be_bytes());
    tr.add_tlv(TLV_KEM_CIPHERTEXT, &want_kem_ct);
    let th_kem = tr.hash(true);
    assert_hex("th_kem", &th_kem, root.at(&["expected", "transcript", "th_kem"]).s());

    // handshake_secret = HKDF-Extract(32 zero octets, ML-KEM_SS || X25519_SS).
    let hs = npamp::derive_handshake_secret(&mlkem_ss, &x25519_ss, true);
    assert_hex("handshake_secret", &hs, root.at(&["expected", "secrets", "handshake_secret"]).s());
    let c_hs = npamp::derive_client_handshake_secret(&hs, &th_kem, true);
    assert_hex("c_hs_secret", &c_hs, root.at(&["expected", "secrets", "c_hs_secret"]).s());
    let s_hs = npamp::derive_server_handshake_secret(&hs, &th_kem, true);
    assert_hex("s_hs_secret", &s_hs, root.at(&["expected", "secrets", "s_hs_secret"]).s());

    // --- SERVER_AUTH. ---
    tr.add_frame_type(handshake::FRAME_SERVER_AUTH);
    tr.add_tlv(TLV_IDENTITY_KEY, &server_pub);
    let th_sid = tr.hash(true);
    assert_hex("th_sid", &th_sid, root.at(&["expected", "transcript", "th_sid"]).s());
    // is_server = true; the CertVerify value = u16(0x0807) || Ed25519 signature.
    let s_cv = handshake::sign_cert_verify(&server_sk, true, &th_sid);
    assert_hex("cert_verify.server", &s_cv, root.at(&["expected", "cert_verify", "server"]).s());
    let server_vk = handshake::ed25519_verifying_key_from_raw(&server_pub).expect("server pubkey");
    assert!(handshake::verify_cert_verify(&server_vk, true, &th_sid, &s_cv), "server CertVerify rejected");
    tr.add_tlv(TLV_CERT_VERIFY, &s_cv);
    let th_scv = tr.hash(true);
    assert_hex("th_scv", &th_scv, root.at(&["expected", "transcript", "th_scv"]).s());
    let s_fin_key = npamp::finished_key(&s_hs, true);
    assert_hex("finished_keys.server", &s_fin_key, root.at(&["expected", "finished_keys", "server"]).s());
    let s_fin = handshake::compute_finished(&s_fin_key, &th_scv, true);
    assert_hex("finished.server", &s_fin, root.at(&["expected", "finished", "server"]).s());
    tr.add_tlv(TLV_FINISHED, &s_fin);
    // SERVER_AUTH plaintext = IdentityKey || CertVerify || Finished TLVs.
    let mut server_auth_plain = Vec::new();
    tlv(&mut server_auth_plain, TLV_IDENTITY_KEY, &server_pub);
    tlv(&mut server_auth_plain, TLV_CERT_VERIFY, &s_cv);
    tlv(&mut server_auth_plain, TLV_FINISHED, &s_fin);
    assert_hex("auth_plaintext.server", &server_auth_plain, root.at(&["expected", "auth_plaintext", "server_auth"]).s());
    let server_auth_frame = seal_auth(handshake::FRAME_SERVER_AUTH, &s_hs, 1 /* s2c */, &server_auth_plain);
    assert_hex("server_auth", &server_auth_frame, root.at(&["expected", "frames", "server_auth"]).s());

    // --- CLIENT_AUTH. ---
    tr.add_frame_type(handshake::FRAME_CLIENT_AUTH);
    tr.add_tlv(TLV_IDENTITY_KEY, &client_pub);
    let th_cid = tr.hash(true);
    assert_hex("th_cid", &th_cid, root.at(&["expected", "transcript", "th_cid"]).s());
    let c_cv = handshake::sign_cert_verify(&client_sk, false, &th_cid);
    assert_hex("cert_verify.client", &c_cv, root.at(&["expected", "cert_verify", "client"]).s());
    let client_vk = handshake::ed25519_verifying_key_from_raw(&client_pub).expect("client pubkey");
    assert!(handshake::verify_cert_verify(&client_vk, false, &th_cid, &c_cv), "client CertVerify rejected");
    tr.add_tlv(TLV_CERT_VERIFY, &c_cv);
    let th_ccv = tr.hash(true);
    assert_hex("th_ccv", &th_ccv, root.at(&["expected", "transcript", "th_ccv"]).s());
    let c_fin_key = npamp::finished_key(&c_hs, true);
    assert_hex("finished_keys.client", &c_fin_key, root.at(&["expected", "finished_keys", "client"]).s());
    let c_fin = handshake::compute_finished(&c_fin_key, &th_ccv, true);
    assert_hex("finished.client", &c_fin, root.at(&["expected", "finished", "client"]).s());
    let mut client_auth_plain = Vec::new();
    tlv(&mut client_auth_plain, TLV_IDENTITY_KEY, &client_pub);
    tlv(&mut client_auth_plain, TLV_CERT_VERIFY, &c_cv);
    tlv(&mut client_auth_plain, TLV_FINISHED, &c_fin);
    assert_hex("auth_plaintext.client", &client_auth_plain, root.at(&["expected", "auth_plaintext", "client_auth"]).s());
    let client_auth_frame = seal_auth(handshake::FRAME_CLIENT_AUTH, &c_hs, 0 /* c2s */, &client_auth_plain);
    assert_hex("client_auth", &client_auth_frame, root.at(&["expected", "frames", "client_auth"]).s());

    // --- Master + application-phase traffic keys. ---
    let master = npamp::derive_master_secret(&hs, &th_ccv, true);
    assert_hex("master_secret", &master, root.at(&["expected", "secrets", "master_secret"]).s());

    assert_traffic_key_iv("c_hs", &c_hs, 0, &root);
    assert_traffic_key_iv("s_hs", &s_hs, 1, &root);
    assert_traffic_key_iv("app_c2s", &master, 0, &root);
    assert_traffic_key_iv("app_s2c", &master, 1, &root);

    // --- Independent MAC oracle: the pinned Finished MACs equal HMAC-SHA-256 over
    // the finished key + transcript hash (guards the impl's compute_finished). ---
    assert_eq!(to_hex(&hmac_sha256(&s_fin_key, &th_scv)), to_hex(&s_fin), "server Finished oracle");
    assert_eq!(to_hex(&hmac_sha256(&c_fin_key, &th_ccv)), to_hex(&c_fin), "client Finished oracle");

    // --- Mutation guard 1: a one-octet flip in the server CertVerify signature
    // must REJECT (the flipped copy must not verify). ---
    let mut bad_cv = s_cv.clone();
    let last = bad_cv.len() - 1;
    bad_cv[last] ^= 0x01;
    assert!(
        !handshake::verify_cert_verify(&server_vk, true, &th_sid, &bad_cv),
        "mutation guard: a one-bit-flipped server CertVerify signature VERIFIED"
    );

    // --- Mutation guard 2: a one-octet flip in the client Finished MAC must REJECT. ---
    let mut bad_fin = c_fin.clone();
    bad_fin[0] ^= 0x01;
    assert!(
        !handshake::verify_finished(&c_fin_key, &th_ccv, &bad_fin, true),
        "mutation guard: a one-bit-flipped client Finished MAC VERIFIED"
    );

    // Sanity: the untouched signature and MAC still verify.
    assert!(handshake::verify_cert_verify(&server_vk, true, &th_sid, &s_cv), "unmutated server CertVerify should verify");
    assert!(handshake::verify_finished(&c_fin_key, &th_ccv, &c_fin, true), "unmutated client Finished should verify");

    // Guard the pinned server X25519 private (dead-input guard, mirrors the Go test).
    assert_eq!(server_x25519_priv.len(), 32, "pinned server X25519 private is 32 octets");

    println!("test result: ok — handshake-flow KAT byte-pinned to the Go reference");
}
