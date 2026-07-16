//! Corpus-graded conformance for the eight native-channel deterministic-CBOR body
//! decoders (companion specs 84–8b): Capability, Immune, Settlement, Telemetry, Commerce,
//! Interaction, Workflow, Knowledge.
//!
//! This test grades `npamp::bodies` against the SHARED conformance corpus — the same
//! `test-vectors/v1/conformance-corpus.json` the Go reference and the other SDKs grade
//! against. The corpus is the independent authority (RFC 8949 §4.2.1 deterministic CBOR +
//! the companion §4 MUST-reject clauses); it is embedded verbatim at compile time and is
//! neither weakened nor special-cased here.
//!
//! For every op-group and every test vector:
//!   * a `valid` / `acceptable` vector MUST decode OK — and, where the vector pins an
//!     expected `frame_kind` / `corr`, the decoded values MUST match;
//!   * an `invalid` (MUST-reject) vector MUST produce a decode error.
//! A decoder that ignored its input would pass the valid vectors but fail every reject
//! vector, so the reject half is the real gate.

use npamp::bodies::validate_by_op;

// Embedded at compile time from the repo's shared corpus (repo-relative path: this test
// lives at impl/rust/tests/, the corpus at test-vectors/v1/ from the repo root).
const CORPUS: &str = include_str!("../../../test-vectors/v1/conformance-corpus.json");

const OPS: [&str; 8] = [
    "capability.body.decode",
    "immune.body.decode",
    "settlement.body.decode",
    "telemetry.body.decode",
    "commerce.body.decode",
    "interaction.body.decode",
    "workflow.body.decode",
    "knowledge.body.decode",
];

// ------------------------------------------------------------------------------------
// Minimal, dependency-free JSON parser (the crate adds no serde/json dependency).
// Supports the subset the corpus uses: objects, arrays, strings (with \uXXXX + the
// standard escapes), integer/float numbers, and true/false/null.
// ------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
#[allow(dead_code)] // Null / Bool are parsed for completeness though the corpus grader never reads them.
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
    fn as_arr(&self) -> Option<&[J]> {
        match self {
            J::Arr(a) => Some(a),
            _ => None,
        }
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
                            // Only the BMP appears in the corpus; encode the code point as
                            // UTF-8 (surrogate pairs are not used by the corpus text).
                            let ch = char::from_u32(cp).ok_or("invalid \\u code point")?;
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return Err(format!("bad escape \\{}", e as char)),
                    }
                }
                _ => {
                    // Copy raw byte (multibyte UTF-8 passes through unchanged).
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
            let d = (self.b[self.i] as char)
                .to_digit(16)
                .ok_or("bad hex digit in \\u")?;
            v = v * 16 + d;
            self.i += 1;
        }
        Ok(v)
    }
    fn number(&mut self) -> Result<J, String> {
        let start = self.i;
        while self.i < self.b.len()
            && matches!(self.b[self.i], b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
        {
            self.i += 1;
        }
        let s = std::str::from_utf8(&self.b[start..self.i]).map_err(|e| e.to_string())?;
        s.parse::<f64>().map(J::Num).map_err(|e| e.to_string())
    }
}

fn parse_corpus() -> J {
    let mut p = P::new(CORPUS);
    let v = p.value().expect("corpus JSON must parse");
    v
}

/// Decodes an even-length lowercase/uppercase hex string to bytes.
fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex string must have even length: {s:?}");
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

/// Per-op grading outcome.
struct OpResult {
    valid_pass: usize,
    reject_pass: usize,
    failures: Vec<String>,
}

fn grade_op(root: &J, op: &str) -> OpResult {
    let groups = root
        .get("testGroups")
        .and_then(J::as_arr)
        .expect("testGroups array");
    let group = groups
        .iter()
        .find(|g| g.get("op").and_then(J::as_str) == Some(op))
        .unwrap_or_else(|| panic!("op-group {op} not found in corpus"));
    let tests = group.get("tests").and_then(J::as_arr).expect("tests array");

    let mut r = OpResult {
        valid_pass: 0,
        reject_pass: 0,
        failures: Vec::new(),
    };

    for t in tests {
        let tc = t.get("tcId").and_then(J::as_u64).unwrap_or(0);
        let result = t.get("result").and_then(J::as_str).expect("result");
        let inp = t.get("in").expect("in");
        let ft = inp.get("frameType").and_then(J::as_u64).expect("frameType");
        let body_hex = inp.get("body").and_then(J::as_str).expect("body");
        let body = hex_decode(body_hex);

        let decoded = validate_by_op(op, ft, &body);
        let must_reject = result == "invalid";

        if must_reject {
            match decoded {
                Err(_) => r.reject_pass += 1,
                Ok(_) => r.failures.push(format!(
                    "tc{tc}: MUST-reject vector ({}) decoded OK (decoder ignored a fault)",
                    t.get("comment").and_then(J::as_str).unwrap_or("")
                )),
            }
            continue;
        }

        // result is "valid" or "acceptable": MUST decode OK.
        match decoded {
            Err(e) => r.failures.push(format!(
                "tc{tc}: {result} vector ({}) failed to decode: {e}",
                t.get("comment").and_then(J::as_str).unwrap_or("")
            )),
            Ok(m) => {
                let mut ok = true;
                if let Some(exp) = t.get("expected") {
                    if let Some(fk) = exp.get("frame_kind").and_then(J::as_u64) {
                        match m.get_u64(0) {
                            Some(got) if got == fk => {}
                            got => {
                                ok = false;
                                r.failures.push(format!(
                                    "tc{tc}: frame_kind mismatch: expected {fk}, decoded {got:?}"
                                ));
                            }
                        }
                    }
                    if let Some(corr) = exp.get("corr").and_then(J::as_str) {
                        match m.get_bytes(1) {
                            Some(got) if hex_encode(got) == corr => {}
                            got => {
                                ok = false;
                                r.failures.push(format!(
                                    "tc{tc}: corr mismatch: expected {corr}, decoded {:?}",
                                    got.map(hex_encode)
                                ));
                            }
                        }
                    }
                }
                if ok {
                    r.valid_pass += 1;
                }
            }
        }
    }
    r
}

/// Grades all eight native-channel op-groups against the shared corpus. Fails (with a
/// per-vector diagnosis) if any valid vector does not decode, any expected value does not
/// match, or any MUST-reject vector decodes without error.
#[test]
fn grade_native_channel_bodies() {
    let root = parse_corpus();
    let mut total_valid = 0usize;
    let mut total_reject = 0usize;
    let mut all_failures: Vec<String> = Vec::new();

    println!("\n=== native-channel body decode conformance (shared corpus) ===");
    for op in OPS {
        let r = grade_op(&root, op);
        total_valid += r.valid_pass;
        total_reject += r.reject_pass;
        let status = if r.failures.is_empty() { "PASS" } else { "FAIL" };
        println!(
            "  {status}  {op:<28}  valid+acceptable: {:>2}   MUST-reject: {:>2}   failures: {}",
            r.valid_pass,
            r.reject_pass,
            r.failures.len()
        );
        for f in &r.failures {
            println!("        - {f}");
        }
        all_failures.extend(r.failures);
    }
    println!(
        "  TOTAL  valid+acceptable decoded OK: {total_valid}   MUST-reject rejected: {total_reject}"
    );

    assert!(
        all_failures.is_empty(),
        "{} conformance failure(s):\n{}",
        all_failures.len(),
        all_failures.join("\n")
    );
    // Sanity floor: the corpus carries many reject vectors per op; a decoder that never
    // errored would trip these. (Guards against an accidentally-inert grader.)
    assert!(total_reject >= 40, "expected many MUST-reject vectors, saw {total_reject}");
    assert!(total_valid >= 30, "expected many valid vectors, saw {total_valid}");
}
