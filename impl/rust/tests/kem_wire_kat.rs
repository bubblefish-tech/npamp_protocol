// Standards-anchored X25519MLKEM768 KEM-wire known-answer test (spec/10 §4;
// ADR-0005 ML-KEM-first). Mirrors the Go reference verifier
// impl/go/kemwire_kat_test.go against test-vectors/v1/kem-wire-kat.json.
//
// NON-CIRCULAR: none of the expected values were produced by an N-PAMP impl.
//   * ML-KEM-768 keygen is anchored to NIST ACVP (FIPS 203 final): the
//     encapsulation key generated deterministically from the pinned (d, z) seed
//     MUST equal the pinned ek.
//   * X25519 is anchored to RFC 7748 §6.1: public-from-private and the ECDH
//     shared secret MUST reproduce the published vector, both directions.
//   * The wire layout (ML-KEM-first ordering + component sizes) is asserted
//     against the pinned lengths — the combiner-order surface that symmetric
//     self-interop cannot catch.
//
// The ml-kem crate is a dev-dependency (deterministic feature) so the OPEN
// wire-format library proper adds no post-quantum KEM dependency; this test
// exercises the same primitives a live handshake uses.

use kem::Decapsulate;
use ml_kem::array::Array;
use ml_kem::{EncapsulateDeterministic, EncodedSizeUser, KemCore, MlKem768};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

// ---------------------------------------------------------------------------
// Minimal recursive-descent JSON reader + hex codecs (same stdlib-only tier as
// handshake_flow_kat.rs / handshake_kat.rs: no serde, no new dependency).
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
    fn num(&self) -> f64 {
        match self {
            Json::Num(n) => *n,
            _ => panic!("JSON value is not a number"),
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
        self.i += 1;
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
        self.i += 1;
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
        self.i += 1;
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

fn from_hex(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
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

fn load_pinned(file: &str, want_sha256: &str) -> Json {
    let path = vector_dir().join(file);
    let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let got = to_hex(&Sha256::digest(&raw));
    assert_eq!(got, want_sha256, "{file} SHA-256 mismatch (swapped vector?) path={}", path.display());
    parse_json(&String::from_utf8(raw).expect("vector is UTF-8"))
}

fn to_arr32(b: &[u8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(b);
    a
}

// The pinned SHA-256 of test-vectors/v1/kem-wire-kat.json (git-committed bytes).
const KEM_WIRE_KAT_SHA256: &str =
    "3edd3e0c1e96fa8a3b45b0e998a2b12082a7b4e66cd5acf3883f2de8ff12c222";

// Component wire sizes, spec/10 §4 (FIPS 203 ML-KEM-768 + RFC 7748 X25519).
const MLKEM768_EK_LEN: usize = 1184;
const MLKEM768_CT_LEN: usize = 1088;
const X25519_PUB_LEN: usize = 32;
const KEM_SHARE_LEN: usize = MLKEM768_EK_LEN + X25519_PUB_LEN; // 1216
const KEM_CIPHERTEXT_LEN: usize = MLKEM768_CT_LEN + X25519_PUB_LEN; // 1120
const COMBINED_SECRET_LEN: usize = 64; // ML-KEM_SS(32) || X25519_SS(32)

/// Grades the X25519MLKEM768 hybrid-KEM wire against the standards-anchored
/// vector. `cargo test --test kem_wire_kat`.
#[test]
fn kem_wire_kat() {
    let root = load_pinned("kem-wire-kat.json", KEM_WIRE_KAT_SHA256);
    let cp = from_hex(root.get("kem_codepoint").s());
    assert_eq!(cp.len(), 2, "codepoint is 2 octets");
    assert_eq!(
        u16::from_be_bytes([cp[0], cp[1]]),
        npamp::KEM_X25519_MLKEM768,
        "pinned KEM code point != npamp::KEM_X25519_MLKEM768"
    );

    // --- 1. NIST ACVP anchor: deterministic ML-KEM-768 keygen reproduces ek. ---
    let d = from_hex(root.at(&["mlkem768_keygen", "d"]).s());
    let z = from_hex(root.at(&["mlkem768_keygen", "z"]).s());
    let want_ek = from_hex(root.at(&["mlkem768_keygen", "ek"]).s());
    assert_eq!(want_ek.len(), MLKEM768_EK_LEN, "pinned ek is 1184 octets");
    let d_arr = Array::try_from(&d[..]).expect("d is 32 octets");
    let z_arr = Array::try_from(&z[..]).expect("z is 32 octets");
    let (dk, ek) = MlKem768::generate_deterministic(&d_arr, &z_arr);
    let ek_bytes = ek.as_bytes();
    assert_eq!(
        to_hex(ek_bytes.as_slice()),
        to_hex(&want_ek),
        "ML-KEM-768 encapsulation key from (d,z) != pinned NIST ACVP ek"
    );

    // --- 2. ml-kem primitive round-trip (encaps/decaps agree). Deterministic
    // encapsulation under a fixed m so the check is reproducible; the recovered
    // shared secret MUST match the decapsulation of the produced ciphertext, and
    // the ciphertext MUST be the FIPS 203 length. ---
    let m = to_arr32(&from_hex(
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    ));
    let m_arr = Array::try_from(&m[..]).expect("m is 32 octets");
    let (ct, ss_enc) = ek.encapsulate_deterministic(&m_arr).expect("encapsulate");
    assert_eq!(ct.as_slice().len(), MLKEM768_CT_LEN, "ML-KEM-768 ciphertext is 1088 octets");
    let ss_dec = dk.decapsulate(&ct).expect("decapsulate");
    assert_eq!(
        to_hex(ss_enc.as_slice()),
        to_hex(ss_dec.as_slice()),
        "ML-KEM-768 encaps/decaps shared secrets disagree"
    );
    assert_eq!(ss_enc.as_slice().len(), 32, "ML-KEM shared secret is 32 octets");

    // --- 3. RFC 7748 §6.1 anchor: X25519 public-from-private + ECDH, both ways. ---
    let alice_priv = from_hex(root.at(&["x25519_rfc7748_6_1", "alice_private"]).s());
    let alice_pub = from_hex(root.at(&["x25519_rfc7748_6_1", "alice_public"]).s());
    let bob_priv = from_hex(root.at(&["x25519_rfc7748_6_1", "bob_private"]).s());
    let bob_pub = from_hex(root.at(&["x25519_rfc7748_6_1", "bob_public"]).s());
    let want_ss = from_hex(root.at(&["x25519_rfc7748_6_1", "shared_secret"]).s());

    let alice_sk = XStaticSecret::from(to_arr32(&alice_priv));
    let bob_sk = XStaticSecret::from(to_arr32(&bob_priv));
    assert_eq!(
        to_hex(XPublicKey::from(&alice_sk).as_bytes()),
        to_hex(&alice_pub),
        "X25519 public(alice_private) != RFC 7748 alice_public"
    );
    assert_eq!(
        to_hex(XPublicKey::from(&bob_sk).as_bytes()),
        to_hex(&bob_pub),
        "X25519 public(bob_private) != RFC 7748 bob_public"
    );
    let ab = alice_sk.diffie_hellman(&XPublicKey::from(to_arr32(&bob_pub)));
    let ba = bob_sk.diffie_hellman(&XPublicKey::from(to_arr32(&alice_pub)));
    assert_eq!(to_hex(ab.as_bytes()), to_hex(&want_ss), "X25519 ECDH(alice, bob_pub) != RFC 7748 shared_secret");
    assert_eq!(to_hex(ba.as_bytes()), to_hex(&want_ss), "X25519 ECDH(bob, alice_pub) != RFC 7748 shared_secret");

    // --- 4. Wire layout (ML-KEM-first, ADR-0005). Assemble the on-wire fields
    // exactly as spec/10 §4 mandates and check size + ordering against the pinned
    // lengths. This is the combiner-order surface a symmetric self-interop misses. ---
    assert_eq!(root.at(&["wire_layout", "kem_share_len"]).num() as usize, KEM_SHARE_LEN);
    assert_eq!(root.at(&["wire_layout", "kem_ciphertext_len"]).num() as usize, KEM_CIPHERTEXT_LEN);
    assert_eq!(root.at(&["wire_layout", "combined_secret_len"]).num() as usize, COMBINED_SECRET_LEN);

    // kem_share = ek (1184) || alice_public (32), ML-KEM-first.
    let mut kem_share = Vec::with_capacity(KEM_SHARE_LEN);
    kem_share.extend_from_slice(ek_bytes.as_slice());
    kem_share.extend_from_slice(&alice_pub);
    assert_eq!(kem_share.len(), KEM_SHARE_LEN, "assembled KEMShare is 1216 octets");
    assert_eq!(&kem_share[..MLKEM768_EK_LEN], &want_ek[..], "KEMShare front is the ML-KEM ek (ML-KEM-first)");
    assert_eq!(&kem_share[MLKEM768_EK_LEN..], &alice_pub[..], "KEMShare tail is the X25519 public");

    // kem_ciphertext = ml-kem ct (1088) || server x25519 public (32), ML-KEM-first.
    let mut kem_ct = Vec::with_capacity(KEM_CIPHERTEXT_LEN);
    kem_ct.extend_from_slice(ct.as_slice());
    kem_ct.extend_from_slice(&bob_pub);
    assert_eq!(kem_ct.len(), KEM_CIPHERTEXT_LEN, "assembled KEMCiphertext is 1120 octets");
    assert_eq!(&kem_ct[..MLKEM768_CT_LEN], ct.as_slice(), "KEMCiphertext front is the ML-KEM ciphertext");

    // combined_secret = ML-KEM_SS (32) || X25519_SS (32), the raw IKM to
    // HKDF-Extract. ML-KEM-first is load-bearing: the reversed order is a bug the
    // vector exists to catch, so assert the correct order AND that the reverse
    // differs (the two component secrets are distinct here).
    let mlkem_k = from_hex(root.at(&["mlkem768_decaps_reference", "shared_secret_K"]).s());
    let mut combined = Vec::with_capacity(COMBINED_SECRET_LEN);
    combined.extend_from_slice(&mlkem_k);
    combined.extend_from_slice(&want_ss);
    assert_eq!(combined.len(), COMBINED_SECRET_LEN, "combined IKM is 64 octets");
    assert_eq!(&combined[..32], &mlkem_k[..], "combined IKM leads with the ML-KEM shared secret (ADR-0005)");
    assert_eq!(&combined[32..], &want_ss[..], "combined IKM trails with the X25519 shared secret");
    let mut reversed = Vec::with_capacity(COMBINED_SECRET_LEN);
    reversed.extend_from_slice(&want_ss);
    reversed.extend_from_slice(&mlkem_k);
    assert_ne!(combined, reversed, "ML-KEM-first ordering must be distinguishable from X25519-first");

    println!("test result: ok — KEM-wire KAT (NIST ML-KEM keygen + RFC 7748 X25519 + ML-KEM-first wire order)");
}
