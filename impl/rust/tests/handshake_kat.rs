// Standards-derived, NON-CIRCULAR known-answer tests for the draft-00 handshake binding
// layer (binding spec/10): the transcript hash (section 3), the Finished MAC (section 6.2;
// RFC 8446 section 4.4.4), and the CertVerify signature (section 6.1; RFC 8446 section 4.4.3
// structure; Ed25519 per RFC 8032). Rust mirror of the Go/TS/Python/Java/Kotlin/Ruby/PHP
// reference tests against the SAME pinned vectors (test-vectors/v1/*.json).
//
// Each KAT has three legs:
//   ANCHOR — reproduce the published standard from the vector JSON (SHA-256("abc") vs
//            FIPS 180-4; HMAC-SHA-256 vs RFC 4231 TC1/TC2; Ed25519 vs RFC 8032 TEST1/TEST2),
//            so the underlying primitive is trusted before any N-PAMP output is.
//   ORACLE — reconstruct the expected outputs WITHOUT the functions under test (hand-built
//            bytes + direct sha2/hmac/ed25519-dalek calls), guarding the vector.
//   IMPL   — drive the real npamp::handshake functions; assert vector match + accept/reject.
//
// The vector files are SHA-256-pinned (fail loud on a swapped vector). The transcript leg is
// driven from the vector frames/TLVs IN ORDER with an index-based cut-point map — it never
// references any TLV by name, so it is value-agnostic.

use ed25519_dalek::{Signature, Signer, SigningKey};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Minimal recursive-descent JSON parser (RFC 8259), hex codecs, and a SHA-256
// pin check. Stdlib + the crate's own deps only — no serde (kept in the
// no-new-JSON-dep tier, like the Java reference's Kat.java).
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

    fn arr(&self) -> &[Json] {
        match self {
            Json::Arr(a) => a,
            _ => panic!("JSON value is not an array"),
        }
    }

    fn n(&self) -> f64 {
        match self {
            Json::Num(x) => *x,
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
// Transcript KAT (binding spec/10 section 3)
// ---------------------------------------------------------------------------

const TRANSCRIPT_KAT_SHA256: &str =
    "fab6d852497b6ff56405595e9a014d0c45cabc5cde80a60a17444b337d556ee5";
const FIPS_SHA256_ABC: &str =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

const POINT_ORDER: [&str; 5] = ["th_kem", "th_sid", "th_scv", "th_cid", "th_ccv"];

/// (frame index, TLV index within that frame) -> transcript-hash point name. This IS the
/// spec section 3 cut-point structure; driving by position keeps the test value-agnostic.
fn transcript_cut_point(fi: usize, ti: usize) -> Option<&'static str> {
    match (fi, ti) {
        (1, 4) => Some("th_kem"),
        (2, 0) => Some("th_sid"),
        (2, 1) => Some("th_scv"),
        (3, 0) => Some("th_cid"),
        (3, 1) => Some("th_ccv"),
        _ => None,
    }
}

/// A sink fed the spec section 3 absorption stream (frame types + TLVs) with snapshots at
/// the cut points. Two impls: an independent byte-constructor (oracle) and the real
/// Transcript (impl). A single trait avoids three closures co-borrowing one buffer.
trait TranscriptSink {
    fn frame_type(&mut self, ft: u16);
    fn tlv(&mut self, typ: u16, value: &[u8]);
    fn snap(&mut self) -> Vec<u8>;
}

struct OracleSink {
    buf: Vec<u8>,
}

impl TranscriptSink for OracleSink {
    fn frame_type(&mut self, ft: u16) {
        self.buf.extend_from_slice(&ft.to_be_bytes());
    }
    fn tlv(&mut self, typ: u16, value: &[u8]) {
        self.buf.extend_from_slice(&typ.to_be_bytes());
        self.buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
        self.buf.extend_from_slice(value);
    }
    fn snap(&mut self) -> Vec<u8> {
        Sha256::digest(&self.buf).to_vec()
    }
}

struct ImplSink {
    tr: npamp::handshake::Transcript,
}

impl TranscriptSink for ImplSink {
    fn frame_type(&mut self, ft: u16) {
        self.tr.add_frame_type(ft);
    }
    fn tlv(&mut self, typ: u16, value: &[u8]) {
        self.tr.add_tlv(typ, value);
    }
    fn snap(&mut self) -> Vec<u8> {
        self.tr.hash(true)
    }
}

/// Walks the vector frames/TLVs in order; snapshots at each spec section 3 cut point.
fn drive_transcript<S: TranscriptSink>(root: &Json, sink: &mut S) -> Vec<(&'static str, Vec<u8>)> {
    let mut points: Vec<(&'static str, Vec<u8>)> = Vec::new();
    for (fi, f) in root.get("frames").arr().iter().enumerate() {
        let ft = u16::from_str_radix(trim_hex_prefix(f.get("frame_type").s()), 16).expect("frame_type");
        sink.frame_type(ft);
        for (ti, t) in f.get("tlvs").arr().iter().enumerate() {
            let typ = u16::from_str_radix(trim_hex_prefix(t.get("type").s()), 16).expect("tlv type");
            let value = from_hex(t.get("value").s());
            sink.tlv(typ, &value);
            if let Some(name) = transcript_cut_point(fi, ti) {
                points.push((name, sink.snap()));
            }
        }
    }
    points
}

fn check_transcript_points(root: &Json, points: &[(&'static str, Vec<u8>)]) {
    assert_eq!(points.len(), POINT_ORDER.len(), "wrong number of cut points");
    for (name, got) in points {
        let want = root.get("expected_transcript_points").get(name).s();
        assert_eq!(to_hex(got), want, "transcript point {name} mismatch");
    }
}

/// ANCHOR: the test's SHA-256 reproduces the FIPS 180-4 SHA-256("abc") known answer.
#[test]
fn transcript_anchor_fips180() {
    let root = load_pinned("transcript-kat.json", TRANSCRIPT_KAT_SHA256);
    let input = root.at(&["fips180_4_sha256_abc", "input_ascii"]).s();
    let got = to_hex(&Sha256::digest(input.as_bytes()));
    assert_eq!(got, FIPS_SHA256_ABC, "SHA-256({input:?}) != FIPS 180-4");
    assert_eq!(
        root.at(&["fips180_4_sha256_abc", "digest"]).s(),
        FIPS_SHA256_ABC,
        "vector anchor digest != FIPS 180-4"
    );
}

/// ORACLE: reproduce every TH_* with an independent per-TLV byte constructor (no Transcript).
#[test]
fn transcript_oracle_construction() {
    let root = load_pinned("transcript-kat.json", TRANSCRIPT_KAT_SHA256);
    let mut sink = OracleSink { buf: Vec::new() };
    let points = drive_transcript(&root, &mut sink);
    check_transcript_points(&root, &points);
}

/// IMPL: reproduce every TH_* with the real Transcript type; assert the spec section 1
/// frame-type constants too.
#[test]
fn transcript_impl() {
    use npamp::handshake;
    assert_eq!(handshake::FRAME_CLIENT_HELLO, 0x0100);
    assert_eq!(handshake::FRAME_SERVER_HELLO, 0x0101);
    assert_eq!(handshake::FRAME_SERVER_AUTH, 0x0102);
    assert_eq!(handshake::FRAME_CLIENT_AUTH, 0x0103);
    let root = load_pinned("transcript-kat.json", TRANSCRIPT_KAT_SHA256);
    let mut sink = ImplSink { tr: handshake::Transcript::new() };
    let points = drive_transcript(&root, &mut sink);
    check_transcript_points(&root, &points);
}

// ---------------------------------------------------------------------------
// Finished KAT (binding spec/10 section 6.2; RFC 8446 section 4.4.4)
// ---------------------------------------------------------------------------

const FINISHED_KAT_SHA256: &str =
    "25c21b0bd3b3b6b77862f4a819f81ff5e4ff42e4b1d70af81feeedc5aad73c7f";

/// HMAC-SHA-256 independent of compute_finished (guards the vector / anchors the primitive).
fn hmac_sha256_oracle(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// ANCHOR: HMAC-SHA-256 reproduces the published RFC 4231 TC1/TC2 MACs.
#[test]
fn finished_anchor_rfc4231() {
    let root = load_pinned("finished-kat.json", FINISHED_KAT_SHA256);
    for tc in ["tc1", "tc2"] {
        let key = from_hex(root.at(&["rfc4231_hmac_sha256", tc, "key"]).s());
        let data = from_hex(root.at(&["rfc4231_hmac_sha256", tc, "data"]).s());
        let want = root.at(&["rfc4231_hmac_sha256", tc, "hmac_sha256"]).s();
        assert_eq!(to_hex(&hmac_sha256_oracle(&key, &data)), want, "RFC 4231 {tc}");
    }
}

/// ORACLE: reproduce verify_data with an independent HMAC (guards the vector).
#[test]
fn finished_oracle() {
    let root = load_pinned("finished-kat.json", FINISHED_KAT_SHA256);
    let gs = to_hex(&hmac_sha256_oracle(
        &from_hex(root.at(&["npamp_inputs", "finished_key_server"]).s()),
        &from_hex(root.at(&["npamp_inputs", "th_scv"]).s()),
    ));
    assert_eq!(gs, root.at(&["expected", "verify_data_server"]).s(), "oracle server verify_data");
    let gc = to_hex(&hmac_sha256_oracle(
        &from_hex(root.at(&["npamp_inputs", "finished_key_client"]).s()),
        &from_hex(root.at(&["npamp_inputs", "th_ccv"]).s()),
    ));
    assert_eq!(gc, root.at(&["expected", "verify_data_client"]).s(), "oracle client verify_data");
}

/// IMPL: compute_finished reproduces verify_data; verify_finished accepts + rejects a tamper.
#[test]
fn finished_impl() {
    use npamp::handshake;
    let root = load_pinned("finished-kat.json", FINISHED_KAT_SHA256);
    let cases = [
        ("server", "finished_key_server", "th_scv", "verify_data_server"),
        ("client", "finished_key_client", "th_ccv", "verify_data_client"),
    ];
    for (name, fk_key, th_key, vd_key) in cases {
        let fk = from_hex(root.at(&["npamp_inputs", fk_key]).s());
        let th = from_hex(root.at(&["npamp_inputs", th_key]).s());
        let want = from_hex(root.at(&["expected", vd_key]).s());

        let got = handshake::compute_finished(&fk, &th, true);
        assert_eq!(to_hex(&got), to_hex(&want), "{name} compute_finished");

        assert!(handshake::verify_finished(&fk, &th, &want, true), "{name} verify_finished accepts");

        let mut bad = want.clone();
        bad[0] ^= 0x01;
        assert!(!handshake::verify_finished(&fk, &th, &bad, true), "{name} verify_finished rejects tamper");
    }
}

// ---------------------------------------------------------------------------
// CertVerify KAT (binding spec/10 section 6.1; RFC 8446 section 4.4.3; Ed25519 RFC 8032)
// ---------------------------------------------------------------------------

const CERTVERIFY_KAT_SHA256: &str =
    "f56ec6ba250ba8f8c6c84214a16f580a3e476e9b2cfd05720c3352de299fe555";

/// Oracle signing input, built by hand independently of cert_verify_signing_input.
fn oracle_signing_input(ctx: &str, th: &[u8]) -> Vec<u8> {
    let c = ctx.as_bytes();
    let mut out = Vec::with_capacity(64 + c.len() + 1 + th.len());
    out.extend_from_slice(&[0x20u8; 64]);
    out.extend_from_slice(c);
    out.push(0x00);
    out.extend_from_slice(th);
    out
}

/// Oracle Ed25519 sign, independent of sign_cert_verify (uses the dalek key directly).
fn oracle_sign(seed: &[u8; 32], msg: &[u8]) -> Vec<u8> {
    SigningKey::from_bytes(seed).sign(msg).to_bytes().to_vec()
}

fn to_arr32(b: &[u8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(b);
    a
}

/// ANCHOR: the src Ed25519 helpers reproduce RFC 8032 TEST1/TEST2 pubkeys + signatures.
#[test]
fn certverify_anchor_rfc8032() {
    use npamp::handshake;
    let root = load_pinned("certverify-kat.json", CERTVERIFY_KAT_SHA256);
    for tc in ["test1", "test2"] {
        let seed = to_arr32(&from_hex(root.at(&["rfc8032_ed25519", tc, "seed"]).s()));
        let msg = from_hex(root.at(&["rfc8032_ed25519", tc, "message"]).s());
        let want_pub = root.at(&["rfc8032_ed25519", tc, "public_key"]).s();
        let want_sig = root.at(&["rfc8032_ed25519", tc, "signature"]).s();

        // src seed-decoder -> deterministic signature must equal the RFC 8032 vector.
        let sk = handshake::ed25519_signing_key_from_seed(&seed);
        assert_eq!(to_hex(&sk.sign(&msg).to_bytes()), want_sig, "RFC 8032 {tc} signature");
        assert_eq!(to_hex(sk.verifying_key().as_bytes()), want_pub, "RFC 8032 {tc} pubkey");

        // src raw-pubkey decoder verifies the published signature (round-trips RFC 8032).
        let vk = handshake::ed25519_verifying_key_from_raw(&to_arr32(&from_hex(want_pub)))
            .expect("decode raw pubkey");
        let sig = Signature::from_bytes(&{
            let mut s = [0u8; 64];
            s.copy_from_slice(&from_hex(want_sig));
            s
        });
        assert!(vk.verify_strict(&msg, &sig).is_ok(), "RFC 8032 {tc} pubkey-from-raw verifies");
    }
}

/// ORACLE: rebuild signing_input by hand + sign with an independent key (guards the vector).
#[test]
fn certverify_oracle() {
    let root = load_pinned("certverify-kat.json", CERTVERIFY_KAT_SHA256);
    let cases = [
        ("server", "server", "server_seed", "th_sid", "signing_input_server", "signature_server"),
        ("client", "client", "client_seed", "th_cid", "signing_input_client", "signature_client"),
    ];
    for (name, ctx_key, seed_key, th_key, si_key, sig_key) in cases {
        let ctx = root.at(&["contexts", ctx_key]).s();
        let th = from_hex(root.at(&["npamp_inputs", th_key]).s());
        let si = oracle_signing_input(ctx, &th);
        assert_eq!(to_hex(&si), root.at(&["expected", si_key]).s(), "{name} signing_input");

        let seed = to_arr32(&from_hex(root.at(&["npamp_inputs", seed_key]).s()));
        let sig = oracle_sign(&seed, &si);
        assert_eq!(to_hex(&sig), root.at(&["expected", sig_key]).s(), "{name} signature");
    }
}

/// IMPL: cert_verify_signing_input + sign_cert_verify reproduce the vector; verify_cert_verify
/// accepts the correct value but rejects role/context mismatch, wrong transcript, a non-Ed25519
/// scheme, and a truncated signature.
#[test]
fn certverify_impl() {
    use npamp::handshake;
    let root = load_pinned("certverify-kat.json", CERTVERIFY_KAT_SHA256);
    assert_eq!(handshake::CONTEXT_SERVER_CERTVERIFY, root.at(&["contexts", "server"]).s());
    assert_eq!(handshake::CONTEXT_CLIENT_CERTVERIFY, root.at(&["contexts", "client"]).s());

    let cases = [
        ("server", true, "server_seed", "server_pub", "th_sid", "signing_input_server", "certverify_value_server"),
        ("client", false, "client_seed", "client_pub", "th_cid", "signing_input_client", "certverify_value_client"),
    ];
    for (name, is_server, seed_key, pub_key, th_key, si_key, val_key) in cases {
        let seed = to_arr32(&from_hex(root.at(&["npamp_inputs", seed_key]).s()));
        let pubb = to_arr32(&from_hex(root.at(&["npamp_inputs", pub_key]).s()));
        let th = from_hex(root.at(&["npamp_inputs", th_key]).s());
        let sk = handshake::ed25519_signing_key_from_seed(&seed);
        let vk = handshake::ed25519_verifying_key_from_raw(&pubb).expect("decode raw pubkey");

        let got_si = to_hex(&handshake::cert_verify_signing_input(is_server, &th));
        assert_eq!(got_si, root.at(&["expected", si_key]).s(), "{name} cert_verify_signing_input");

        let val = handshake::sign_cert_verify(&sk, is_server, &th);
        assert_eq!(to_hex(&val), root.at(&["expected", val_key]).s(), "{name} sign_cert_verify value");

        assert!(handshake::verify_cert_verify(&vk, is_server, &th, &val), "{name} verify accepts");

        // Domain separation: the opposite role must FAIL (different context string).
        assert!(!handshake::verify_cert_verify(&vk, !is_server, &th, &val), "{name} rejects role/context mismatch");

        // Transcript binding: a different transcript hash must FAIL.
        let mut wrong_th = th.clone();
        wrong_th[0] ^= 0x01;
        assert!(!handshake::verify_cert_verify(&vk, is_server, &wrong_th, &val), "{name} rejects wrong transcript");

        // Scheme guard: a non-Ed25519 scheme code point must FAIL.
        let mut bad_scheme = val.clone();
        bad_scheme[0] = (npamp::SIG_MLDSA87 >> 8) as u8;
        bad_scheme[1] = (npamp::SIG_MLDSA87 & 0xFF) as u8;
        assert!(!handshake::verify_cert_verify(&vk, is_server, &th, &bad_scheme), "{name} rejects non-Ed25519 scheme");

        // Length guard: an Ed25519 signature is exactly 64 octets; a truncated value must FAIL.
        let truncated = &val[..val.len() - 1];
        assert!(!handshake::verify_cert_verify(&vk, is_server, &th, truncated), "{name} rejects truncated signature");
    }
}

// ---------------------------------------------------------------------------
// Key-schedule KAT (binding spec/10 §5 + draft-00 §7.4 HKDF-Expand-Label / §7.5 traffic keys)
//
// Three legs, NON-CIRCULAR:
//   ANCHOR — src hkdf_extract/hkdf_expand AND the in-test HKDF oracle both reproduce the
//            published RFC 5869 TC1 PRK/OKM (the underlying primitive is trusted first).
//   ORACLE — an INDEPENDENT in-test HKDF-Expand-Label (it re-derives the HkdfLabel bytes
//            itself, with the prefix as a PARAMETER, and never calls npamp::hkdf_expand_label)
//            reproduces the RFC 8448 §3 write_key/write_iv/finished_key with the "tls13 "
//            prefix — proving the mechanism before it judges anything.
//   IMPL   — the src key schedule (handshake_secret ladder + finished_key + s2c traffic
//            key/iv) equals, byte-for-byte, that PROVEN oracle applied with the "n-pamp "
//            prefix. The golden N-PAMP bytes are COMPUTED by the oracle, never hardcoded.
// ---------------------------------------------------------------------------

const KEY_SCHEDULE_KAT_SHA256: &str =
    "e108f5cfdf99a378d7b677792448c8046abf3c630fc23fd8ea2ccb3927f2691c";

/// Independent HMAC-SHA-256 (RFC 2104), distinct from the src key schedule.
fn ks_hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Independent HKDF-Extract (RFC 5869 §2.2): PRK = HMAC-Hash(salt, IKM).
fn oracle_extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    ks_hmac_sha256(salt, ikm)
}

/// Independent HKDF-Expand (RFC 5869 §2.3): T(0)="", T(i)=HMAC(PRK, T(i-1)||info||i).
fn oracle_expand(prk: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let mut okm: Vec<u8> = Vec::with_capacity(length);
    let mut t: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while okm.len() < length {
        let mut input = Vec::with_capacity(t.len() + info.len() + 1);
        input.extend_from_slice(&t);
        input.extend_from_slice(info);
        input.push(counter);
        t = ks_hmac_sha256(prk, &input);
        okm.extend_from_slice(&t);
        counter = counter.checked_add(1).expect("HKDF-Expand counter overflow (L too large)");
    }
    okm.truncate(length);
    okm
}

/// Independent HKDF-Expand-Label (RFC 8446 §7.1) with the label PREFIX as a parameter, so the
/// SAME code proves the "tls13 " mechanism against RFC 8448 and then judges the "n-pamp "
/// impl. HkdfLabel = uint16(length) || uint8(len(prefix+label)) || prefix+label ||
/// uint8(len(context)) || context. This rebuilds those bytes WITHOUT npamp::hkdf_expand_label.
fn oracle_expand_label(secret: &[u8], prefix: &str, label: &str, context: &[u8], length: usize) -> Vec<u8> {
    let full = format!("{prefix}{label}");
    let mut info = Vec::with_capacity(2 + 1 + full.len() + 1 + context.len());
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    oracle_expand(secret, &info, length)
}

/// ANCHOR: src hkdf_extract/hkdf_expand and the in-test oracle both reproduce RFC 5869 TC1.
#[test]
fn key_schedule_anchor_rfc5869() {
    let root = load_pinned("key-schedule-kat.json", KEY_SCHEDULE_KAT_SHA256);
    let salt = from_hex(root.at(&["rfc5869_tc1", "salt"]).s());
    let ikm = from_hex(root.at(&["rfc5869_tc1", "ikm"]).s());
    let info = from_hex(root.at(&["rfc5869_tc1", "info"]).s());
    let l = root.at(&["rfc5869_tc1", "L"]).n() as usize;
    let prk_want = root.at(&["rfc5869_tc1", "prk"]).s();
    let okm_want = root.at(&["rfc5869_tc1", "okm"]).s();

    // The src primitives that leg D drives must match the RFC.
    let prk = npamp::hkdf_extract(&salt, &ikm, true);
    assert_eq!(to_hex(&prk), prk_want, "src hkdf_extract vs RFC 5869 TC1 PRK");
    assert_eq!(to_hex(&npamp::hkdf_expand(&prk, &info, l, true)), okm_want, "src hkdf_expand vs RFC 5869 TC1 OKM");

    // The in-test oracle that JUDGES leg D must match the RFC independently of the src.
    assert_eq!(to_hex(&oracle_extract(&salt, &ikm)), prk_want, "oracle extract vs RFC 5869 TC1 PRK");
    assert_eq!(to_hex(&oracle_expand(&prk, &info, l)), okm_want, "oracle expand vs RFC 5869 TC1 OKM");
}

/// ORACLE: the in-test HKDF-Expand-Label (prefix as a parameter) reproduces RFC 8448 §3's
/// write_key/write_iv/finished_key from the handshake traffic secret with the "tls13 " prefix.
/// This trusts the oracle BEFORE it judges the impl; it never calls npamp::hkdf_expand_label.
#[test]
fn key_schedule_oracle_rfc8448() {
    let root = load_pinned("key-schedule-kat.json", KEY_SCHEDULE_KAT_SHA256);
    let secret = from_hex(root.at(&["rfc8448_expand_label", "client_handshake_traffic_secret"]).s());
    assert_eq!(
        to_hex(&oracle_expand_label(&secret, "tls13 ", "key", &[], 16)),
        root.at(&["rfc8448_expand_label", "write_key"]).s(),
        "oracle expand_label(key) vs RFC 8448"
    );
    assert_eq!(
        to_hex(&oracle_expand_label(&secret, "tls13 ", "iv", &[], 12)),
        root.at(&["rfc8448_expand_label", "write_iv"]).s(),
        "oracle expand_label(iv) vs RFC 8448"
    );
    assert_eq!(
        to_hex(&oracle_expand_label(&secret, "tls13 ", "finished", &[], 32)),
        root.at(&["rfc8448_expand_label", "finished_key"]).s(),
        "oracle expand_label(finished) vs RFC 8448"
    );
}

/// IMPL: the src key schedule equals the RFC-8448-proven oracle applied with the "n-pamp "
/// prefix, for every secret in the handshake-secret ladder, both Finished keys, and the s2c
/// handshake AEAD key/iv. Golden N-PAMP outputs are computed by the oracle, never hardcoded.
#[test]
fn key_schedule_impl() {
    let root = load_pinned("key-schedule-kat.json", KEY_SCHEDULE_KAT_SHA256);
    // mlkem and x25519 are the two KEM shared secrets; th_kem/th_ccv are transcript hashes.
    let mlkem = from_hex(root.at(&["npamp_inputs", "ikm_mlkem_ss"]).s());
    let x25519 = from_hex(root.at(&["npamp_inputs", "ikm_x25519_ss"]).s());
    let th_kem = from_hex(root.at(&["npamp_inputs", "th_kem"]).s());
    let th_ccv = from_hex(root.at(&["npamp_inputs", "th_ccv"]).s());

    // The prefix the src bakes into HKDF-Expand-Label is the "n-pamp " prefix the vector pins.
    assert_eq!(npamp::LABEL_PREFIX, root.at(&["npamp_inputs", "label_prefix"]).s(), "src label prefix");

    // handshake_secret = HKDF-Extract(32 zero octets, ML-KEM_SS || X25519_SS), ML-KEM first.
    let zeros32 = [0u8; 32];
    let mut ikm = Vec::with_capacity(mlkem.len() + x25519.len());
    ikm.extend_from_slice(&mlkem);
    ikm.extend_from_slice(&x25519);
    let hs = npamp::derive_handshake_secret(&mlkem, &x25519, true);
    assert_eq!(to_hex(&hs), to_hex(&oracle_extract(&zeros32, &ikm)), "handshake_secret");

    // c_hs / s_hs / master.
    let c_hs = npamp::derive_client_handshake_secret(&hs, &th_kem, true);
    assert_eq!(to_hex(&c_hs), to_hex(&oracle_expand_label(&hs, "n-pamp ", "c hs", &th_kem, 32)), "c_hs");
    let s_hs = npamp::derive_server_handshake_secret(&hs, &th_kem, true);
    assert_eq!(to_hex(&s_hs), to_hex(&oracle_expand_label(&hs, "n-pamp ", "s hs", &th_kem, 32)), "s_hs");
    let master = npamp::derive_master_secret(&hs, &th_ccv, true);
    assert_eq!(to_hex(&master), to_hex(&oracle_expand_label(&hs, "n-pamp ", "master", &th_ccv, 32)), "master");

    // finished_key per direction: client from c_hs, server from s_hs.
    assert_eq!(
        to_hex(&npamp::finished_key(&c_hs, true)),
        to_hex(&oracle_expand_label(&c_hs, "n-pamp ", "finished", &[], 32)),
        "finished_key(c_hs)"
    );
    assert_eq!(
        to_hex(&npamp::finished_key(&s_hs, true)),
        to_hex(&oracle_expand_label(&s_hs, "n-pamp ", "finished", &[], 32)),
        "finished_key(s_hs)"
    );

    // s2c handshake AEAD via the existing traffic-key derivation off s_hs:
    // dir=ServerToClient(1), epoch=0, suite=AES-256-GCM=0x0001 per registries/aead.csv (= the
    // impl's AEAD_AES256_GCM = npamp.AEADAES256GCM in the Go reference); 0x0002 is
    // ChaCha20-Poly1305. channel=Control(0x0000). The 7.5 traffic context binds this AEAD code
    // point: ctx = dir(1) || epoch(8 BE) || suite(2 BE) || channel(2 BE).
    let dir_s2c: u8 = 1;
    let epoch: u64 = 0;
    let suite: u16 = npamp::AEAD_AES256_GCM;
    let channel: u16 = 0x0000;
    let ts_impl = npamp::derive_traffic_secret(&s_hs, dir_s2c, epoch, suite, channel, true);
    let (key, iv) = npamp::derive_key_iv(&ts_impl, true);

    let mut ctx = Vec::with_capacity(1 + 8 + 2 + 2);
    ctx.push(dir_s2c);
    ctx.extend_from_slice(&epoch.to_be_bytes());
    ctx.extend_from_slice(&suite.to_be_bytes());
    ctx.extend_from_slice(&channel.to_be_bytes());
    let ts_oracle = oracle_expand_label(&s_hs, "n-pamp ", "traffic", &ctx, 32);
    let key_oracle = oracle_expand_label(&ts_oracle, "n-pamp ", "key", &[], 32);
    let iv_oracle = oracle_expand_label(&ts_oracle, "n-pamp ", "iv", &[], 12);
    assert_eq!(to_hex(&key), to_hex(&key_oracle), "s2c handshake key");
    assert_eq!(to_hex(&iv), to_hex(&iv_oracle), "s2c handshake iv");
}
