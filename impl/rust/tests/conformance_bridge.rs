//! Corpus-graded conformance for the NPAMP-BRIDGE frame codec (companion spec 10:
//! `spec/companion/10_bridge_framework.md`).
//!
//! This test grades `npamp::bridge` against the SHARED conformance corpus — the same
//! `test-vectors/v1/conformance-corpus.json` the Go reference and the other SDKs grade
//! against. The corpus is the independent authority (an F3 non-circular oracle,
//! `test-vectors/gen/bridge_oracle.py`); it is embedded verbatim at compile time and is
//! neither weakened nor special-cased here.
//!
//! Grades three op-groups:
//!   * `bridge.envelope.decode` — a `valid` vector MUST decode with the expected
//!     protocol_id/message_kind/content_type/flags/final/corr/method/safety/foreign
//!     fields; an `invalid` (MUST-reject) vector MUST produce a decode error.
//!   * `bridge.envelope.encode` — building a BridgeEnvelope + optional SafetyLabel +
//!     foreign message from the vector's declared fields and encoding it MUST produce
//!     the exact expected payload bytes.
//!   * `bridge.correlate` — decoding a request/reply payload pair and checking
//!     correlation MUST match the expected boolean.
//!
//! A decoder that ignored its input would pass the valid vectors but fail every reject
//! vector, so the reject half is the real gate (the same discipline as
//! `conformance_bodies.rs`).

use npamp::bridge::{self, BridgeEnvelope, SafetyLabel};

// Embedded at compile time from the repo's shared corpus (repo-relative path: this
// test lives at impl/rust/tests/, the corpus at test-vectors/v1/ from the repo root).
const CORPUS: &str = include_str!("../../../test-vectors/v1/conformance-corpus.json");

// ------------------------------------------------------------------------------------
// Minimal, dependency-free JSON parser (the crate adds no serde/json dependency),
// duplicated per-test-file per this crate's existing convention (see
// conformance_bodies.rs). Supports the subset the corpus uses: objects, arrays,
// strings (with \uXXXX + the standard escapes), integer/float numbers, and
// true/false/null.
// ------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
#[allow(dead_code)] // Bool is parsed for completeness though this grader never reads it.
enum J {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl J {
    fn get(&self, key: &str) -> Option<&J> {
        match self {
            J::Obj(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    fn as_str(&self) -> Option<&str> {
        match self {
            J::Str(s) => Some(s),
            _ => None,
        }
    }
    fn as_u64(&self) -> Option<u64> {
        match self {
            J::Num(n) => Some(*n as u64),
            _ => None,
        }
    }
    fn as_bool(&self) -> Option<bool> {
        match self {
            J::Bool(b) => Some(*b),
            _ => None,
        }
    }
    fn as_arr(&self) -> Option<&[J]> {
        match self {
            J::Arr(a) => Some(a),
            _ => None,
        }
    }
    fn is_null(&self) -> bool {
        matches!(self, J::Null)
    }
}

struct P<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> P<'a> {
    fn new(s: &'a str) -> Self {
        P { b: s.as_bytes(), i: 0 }
    }
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn value(&mut self) -> Result<J, String> {
        self.ws();
        if self.i >= self.b.len() {
            return Err("unexpected end of input".into());
        }
        match self.b[self.i] {
            b'{' => self.object(),
            b'[' => self.array(),
            b'"' => Ok(J::Str(self.string()?)),
            b't' => self.literal("true", J::Bool(true)),
            b'f' => self.literal("false", J::Bool(false)),
            b'n' => self.literal("null", J::Null),
            _ => self.number(),
        }
    }
    fn literal(&mut self, lit: &str, v: J) -> Result<J, String> {
        if self.b[self.i..].starts_with(lit.as_bytes()) {
            self.i += lit.len();
            Ok(v)
        } else {
            Err(format!("expected literal {lit} at byte {}", self.i))
        }
    }
    fn object(&mut self) -> Result<J, String> {
        self.i += 1; // {
        let mut pairs = Vec::new();
        self.ws();
        if self.i < self.b.len() && self.b[self.i] == b'}' {
            self.i += 1;
            return Ok(J::Obj(pairs));
        }
        loop {
            self.ws();
            let key = self.string()?;
            self.ws();
            if self.i >= self.b.len() || self.b[self.i] != b':' {
                return Err(format!("expected ':' at byte {}", self.i));
            }
            self.i += 1;
            let val = self.value()?;
            pairs.push((key, val));
            self.ws();
            match self.b.get(self.i) {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b'}') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(format!("expected ',' or '}}' at byte {}", self.i)),
            }
        }
        Ok(J::Obj(pairs))
    }
    fn array(&mut self) -> Result<J, String> {
        self.i += 1; // [
        let mut items = Vec::new();
        self.ws();
        if self.i < self.b.len() && self.b[self.i] == b']' {
            self.i += 1;
            return Ok(J::Arr(items));
        }
        loop {
            let val = self.value()?;
            items.push(val);
            self.ws();
            match self.b.get(self.i) {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b']') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(format!("expected ',' or ']' at byte {}", self.i)),
            }
        }
        Ok(J::Arr(items))
    }
    fn string(&mut self) -> Result<String, String> {
        if self.b[self.i] != b'"' {
            return Err(format!("expected '\"' at byte {}", self.i));
        }
        self.i += 1;
        let mut out: Vec<u8> = Vec::new();
        while self.i < self.b.len() {
            let c = self.b[self.i];
            match c {
                b'"' => {
                    self.i += 1;
                    return String::from_utf8(out).map_err(|e| e.to_string());
                }
                b'\\' => {
                    self.i += 1;
                    let e = *self.b.get(self.i).ok_or("truncated escape")?;
                    self.i += 1;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let cp = self.hex4()?;
                            let ch = char::from_u32(cp).ok_or("invalid \\u code point")?;
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return Err(format!("bad escape \\{}", e as char)),
                    }
                }
                _ => {
                    out.push(c);
                    self.i += 1;
                }
            }
        }
        Err("unterminated string".into())
    }
    fn hex4(&mut self) -> Result<u32, String> {
        if self.i + 4 > self.b.len() {
            return Err("truncated \\u escape".into());
        }
        let mut v = 0u32;
        for _ in 0..4 {
            let d = (self.b[self.i] as char).to_digit(16).ok_or("bad hex digit in \\u")?;
            v = v * 16 + d;
            self.i += 1;
        }
        Ok(v)
    }
    fn number(&mut self) -> Result<J, String> {
        let start = self.i;
        while self.i < self.b.len() && matches!(self.b[self.i], b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E') {
            self.i += 1;
        }
        let s = std::str::from_utf8(&self.b[start..self.i]).map_err(|e| e.to_string())?;
        s.parse::<f64>().map(J::Num).map_err(|e| e.to_string())
    }
}

fn parse_corpus() -> J {
    let mut p = P::new(CORPUS);
    p.value().expect("corpus JSON must parse")
}

fn hex_decode(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "hex string must have even length: {s:?}");
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16).expect("hex digit") as u8;
        let lo = (bytes[i + 1] as char).to_digit(16).expect("hex digit") as u8;
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn find_group<'a>(root: &'a J, op: &str) -> &'a J {
    let groups = root.get("testGroups").and_then(J::as_arr).expect("testGroups array");
    groups
        .iter()
        .find(|g| g.get("op").and_then(J::as_str) == Some(op))
        .unwrap_or_else(|| panic!("op-group {op} not found in corpus"))
}

// ------------------------------------------------------------------------------------
// bridge.envelope.decode
// ------------------------------------------------------------------------------------

fn grade_decode(root: &J) -> (usize, usize, Vec<String>) {
    let group = find_group(root, "bridge.envelope.decode");
    let tests = group.get("tests").and_then(J::as_arr).expect("tests array");

    let mut valid_pass = 0usize;
    let mut reject_pass = 0usize;
    let mut failures = Vec::new();

    for t in tests {
        let tc = t.get("tcId").and_then(J::as_u64).unwrap_or(0);
        let result = t.get("result").and_then(J::as_str).expect("result");
        let comment = t.get("comment").and_then(J::as_str).unwrap_or("");
        let inp = t.get("in").expect("in");
        let ft = inp.get("frameType").and_then(J::as_u64).expect("frameType") as u16;
        let payload = hex_decode(inp.get("payload").and_then(J::as_str).expect("payload"));

        let decoded = bridge::decode_bridge_frame(ft, &payload);
        let must_reject = result == "invalid";

        if must_reject {
            match decoded {
                Err(_) => reject_pass += 1,
                Ok(_) => failures.push(format!(
                    "tc{tc}: MUST-reject vector ({comment}) decoded OK (decoder ignored a fault)"
                )),
            }
            continue;
        }

        match decoded {
            Err(e) => failures.push(format!("tc{tc}: {result} vector ({comment}) failed to decode: {e}")),
            Ok(f) => {
                let mut ok = true;
                let mut mismatch = |field: &str, expected: String, got: String| {
                    if expected != got {
                        ok = false;
                        format!("tc{tc}: {field} mismatch: expected {expected}, got {got}")
                    } else {
                        String::new()
                    }
                };
                if let Some(exp) = t.get("expected") {
                    if let Some(v) = exp.get("protocol_id").and_then(J::as_u64) {
                        let m = mismatch("protocol_id", v.to_string(), (f.envelope.protocol as u64).to_string());
                        if !m.is_empty() {
                            failures.push(m);
                        }
                    }
                    if let Some(v) = exp.get("message_kind").and_then(J::as_u64) {
                        let m = mismatch("message_kind", v.to_string(), (f.envelope.kind as u64).to_string());
                        if !m.is_empty() {
                            failures.push(m);
                        }
                    }
                    if let Some(v) = exp.get("content_type").and_then(J::as_u64) {
                        let m = mismatch(
                            "content_type",
                            v.to_string(),
                            (f.envelope.content_type as u64).to_string(),
                        );
                        if !m.is_empty() {
                            failures.push(m);
                        }
                    }
                    if let Some(v) = exp.get("flags").and_then(J::as_u64) {
                        let m = mismatch("flags", v.to_string(), (f.envelope.flags as u64).to_string());
                        if !m.is_empty() {
                            failures.push(m);
                        }
                    }
                    if let Some(v) = exp.get("final").and_then(J::as_bool) {
                        let m = mismatch("final", v.to_string(), f.envelope.final_flag().to_string());
                        if !m.is_empty() {
                            failures.push(m);
                        }
                    }
                    if let Some(v) = exp.get("corr").and_then(J::as_str) {
                        let m = mismatch("corr", v.to_string(), hex_encode(&f.envelope.correlation_id));
                        if !m.is_empty() {
                            failures.push(m);
                        }
                    }
                    if let Some(v) = exp.get("method").and_then(J::as_str) {
                        let got = String::from_utf8_lossy(&f.envelope.method).into_owned();
                        let m = mismatch("method", v.to_string(), got);
                        if !m.is_empty() {
                            failures.push(m);
                        }
                    }
                    if let Some(v) = exp.get("foreign").and_then(J::as_str) {
                        let m = mismatch("foreign", v.to_string(), hex_encode(&f.foreign));
                        if !m.is_empty() {
                            failures.push(m);
                        }
                    }
                    match exp.get("safety") {
                        Some(sv) if sv.is_null() => {
                            if f.safety.is_some() {
                                ok = false;
                                failures.push(format!("tc{tc}: expected safety=null, decoder returned Some"));
                            }
                        }
                        Some(sv) => match &f.safety {
                            None => {
                                ok = false;
                                failures.push(format!("tc{tc}: expected a SafetyLabel, decoder returned None"));
                            }
                            Some(s) => {
                                if let Some(ev) = sv.get("effect").and_then(J::as_u64) {
                                    if ev != s.effect as u64 {
                                        ok = false;
                                        failures.push(format!(
                                            "tc{tc}: safety.effect mismatch: expected {ev}, got {}",
                                            s.effect
                                        ));
                                    }
                                }
                                if let Some(scv) = sv.get("scope").and_then(J::as_str) {
                                    let got = String::from_utf8_lossy(&s.scope).into_owned();
                                    if scv != got {
                                        ok = false;
                                        failures.push(format!(
                                            "tc{tc}: safety.scope mismatch: expected {scv}, got {got}"
                                        ));
                                    }
                                }
                            }
                        },
                        None => {}
                    }
                }
                if ok {
                    valid_pass += 1;
                }
            }
        }
    }
    (valid_pass, reject_pass, failures)
}

// ------------------------------------------------------------------------------------
// bridge.envelope.encode
// ------------------------------------------------------------------------------------

fn grade_encode(root: &J) -> (usize, Vec<String>) {
    let group = find_group(root, "bridge.envelope.encode");
    let tests = group.get("tests").and_then(J::as_arr).expect("tests array");

    let mut pass = 0usize;
    let mut failures = Vec::new();

    for t in tests {
        let tc = t.get("tcId").and_then(J::as_u64).unwrap_or(0);
        let comment = t.get("comment").and_then(J::as_str).unwrap_or("");
        let inp = t.get("in").expect("in");
        let fields = inp.get("fields").expect("fields");

        let corr = hex_decode(fields.get("corr").and_then(J::as_str).unwrap_or(""));
        let foreign = hex_decode(fields.get("foreign").and_then(J::as_str).unwrap_or(""));
        let method = fields.get("method").and_then(J::as_str).unwrap_or("").as_bytes().to_vec();
        let env = BridgeEnvelope {
            protocol: fields.get("protocol_id").and_then(J::as_u64).unwrap_or(0) as u16,
            kind: fields.get("message_kind").and_then(J::as_u64).unwrap_or(0) as u8,
            content_type: fields.get("content_type").and_then(J::as_u64).unwrap_or(0) as u8,
            flags: fields.get("flags").and_then(J::as_u64).unwrap_or(0) as u8,
            correlation_id: corr,
            method,
        };
        let safety = match fields.get("safety") {
            Some(sv) if !sv.is_null() => Some(SafetyLabel {
                effect: sv.get("effect").and_then(J::as_u64).unwrap_or(0) as u8,
                scope: sv.get("scope").and_then(J::as_str).unwrap_or("").as_bytes().to_vec(),
            }),
            _ => None,
        };

        let got = bridge::encode_bridge_payload(&env, safety.as_ref(), &foreign);
        let want = hex_decode(
            t.get("expected")
                .and_then(|e| e.get("payload"))
                .and_then(J::as_str)
                .expect("expected.payload"),
        );
        if got == want {
            pass += 1;
        } else {
            failures.push(format!(
                "tc{tc}: encode mismatch ({comment}): expected {}, got {}",
                hex_encode(&want),
                hex_encode(&got)
            ));
        }
    }
    (pass, failures)
}

// ------------------------------------------------------------------------------------
// bridge.correlate
// ------------------------------------------------------------------------------------

fn grade_correlate(root: &J) -> (usize, Vec<String>) {
    let group = find_group(root, "bridge.correlate");
    let tests = group.get("tests").and_then(J::as_arr).expect("tests array");

    let mut pass = 0usize;
    let mut failures = Vec::new();

    for t in tests {
        let tc = t.get("tcId").and_then(J::as_u64).unwrap_or(0);
        let comment = t.get("comment").and_then(J::as_str).unwrap_or("");
        let inp = t.get("in").expect("in");
        let req_ft = inp.get("requestFrameType").and_then(J::as_u64).expect("requestFrameType") as u16;
        let req_payload = hex_decode(inp.get("requestPayload").and_then(J::as_str).expect("requestPayload"));
        let rep_ft = inp.get("replyFrameType").and_then(J::as_u64).expect("replyFrameType") as u16;
        let rep_payload = hex_decode(inp.get("replyPayload").and_then(J::as_str).expect("replyPayload"));

        let req_env = bridge::decode_bridge_envelope(req_ft, &req_payload)
            .unwrap_or_else(|e| panic!("tc{tc}: request must decode: {e}"));
        let rep_env = bridge::decode_bridge_envelope(rep_ft, &rep_payload)
            .unwrap_or_else(|e| panic!("tc{tc}: reply must decode: {e}"));
        let got = bridge::correlate_bridge_reply(&req_env, &rep_env);
        let want = t
            .get("expected")
            .and_then(|e| e.get("match"))
            .and_then(J::as_bool)
            .expect("expected.match");
        if got == want {
            pass += 1;
        } else {
            failures.push(format!("tc{tc}: correlate mismatch ({comment}): expected {want}, got {got}"));
        }
    }
    (pass, failures)
}

/// Grades all three Bridge op-groups against the shared corpus. Fails (with a
/// per-vector diagnosis) if any valid vector does not decode/encode/correlate as
/// expected, or any MUST-reject vector decodes without error.
#[test]
fn grade_bridge_envelope_codec() {
    let root = parse_corpus();

    println!("\n=== NPAMP-BRIDGE envelope codec conformance (shared corpus) ===");

    let (valid_pass, reject_pass, decode_failures) = grade_decode(&root);
    println!(
        "  bridge.envelope.decode   valid: {valid_pass:>2}   MUST-reject: {reject_pass:>2}   failures: {}",
        decode_failures.len()
    );
    for f in &decode_failures {
        println!("        - {f}");
    }

    let (encode_pass, encode_failures) = grade_encode(&root);
    println!("  bridge.envelope.encode   valid: {encode_pass:>2}   failures: {}", encode_failures.len());
    for f in &encode_failures {
        println!("        - {f}");
    }

    let (correlate_pass, correlate_failures) = grade_correlate(&root);
    println!("  bridge.correlate         valid: {correlate_pass:>2}   failures: {}", correlate_failures.len());
    for f in &correlate_failures {
        println!("        - {f}");
    }

    let mut all_failures = decode_failures;
    all_failures.extend(encode_failures);
    all_failures.extend(correlate_failures);

    assert!(
        all_failures.is_empty(),
        "{} conformance failure(s):\n{}",
        all_failures.len(),
        all_failures.join("\n")
    );
    // Sanity floor: guards against an accidentally-inert grader (a decoder that
    // ignored its input would pass the valid vectors but never reject).
    assert!(reject_pass >= 10, "expected many MUST-reject vectors, saw {reject_pass}");
    assert!(valid_pass >= 15, "expected many valid decode vectors, saw {valid_pass}");
    assert!(encode_pass >= 15, "expected many valid encode vectors, saw {encode_pass}");
    assert!(correlate_pass >= 4, "expected several correlate vectors, saw {correlate_pass}");
}
