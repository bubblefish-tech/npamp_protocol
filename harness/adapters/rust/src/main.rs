//! N-PAMP (draft-bubblefish-npamp-00) conformance adapter — Rust "testee".
//!
//! Reads length-prefixed JSON requests {op,in} on stdin and writes length-prefixed
//! JSON responses {out|error|skipped} on stdout, performing the real N-PAMP primitive
//! for each op by calling the OPEN reference implementation crate `npamp` (path
//! dependency `../../../impl/rust`). This file owns NO protocol logic: every op routes
//! into a function exported by `npamp` (crc32c, Frame::unmarshal, header_prefix,
//! seal_aes256gcm, open_aes256gcm, hkdf_expand). Operations the reference impl does not
//! provide a function for (tlv.decode, profile.check) return {"skipped":...} and are
//! reported Unimplemented, never reimplemented here.
//!
//! Windows note: stdin/stdout are used as raw binary byte streams (no text-mode CRLF
//! translation exists on the `std::io::Stdin`/`Stdout` byte handles) and the adapter
//! FLUSHES after every response, so the 4-byte little-endian length framing never
//! corrupts. To exercise the runner's mutation check, `--break` corrupts the crc32c op.

use std::io::{self, Read, Write};

use npamp::{self, Frame};

// ---------------------------------------------------------------------------
// Minimal, dependency-free JSON for the flat request/response objects of the
// conformance contract. Requests are {"op": <str>, "in": { <str>: <str|int> }}.
// Responses are one flat object: {"out": {...}} | {"error": <str>} | {"skipped": <str>}.
// ---------------------------------------------------------------------------

/// A decoded JSON scalar value as it appears in the `in` object: every field the
/// contract uses is either a hex/identifier string or a non-negative integer.
#[derive(Debug, Clone)]
enum Val {
    Str(String),
    Int(i64),
}

/// A parsed request.
struct Request {
    op: String,
    input: Vec<(String, Val)>,
}

impl Request {
    fn get_str(&self, key: &str) -> Option<&str> {
        self.input.iter().find(|(k, _)| k == key).and_then(|(_, v)| match v {
            Val::Str(s) => Some(s.as_str()),
            Val::Int(_) => None,
        })
    }
    fn get_int(&self, key: &str) -> Option<i64> {
        self.input.iter().find(|(k, _)| k == key).and_then(|(_, v)| match v {
            Val::Int(n) => Some(*n),
            Val::Str(_) => None,
        })
    }
}

/// A scanning cursor over UTF-8 bytes.
struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn new(b: &'a [u8]) -> Self {
        Parser { b, i: 0 }
    }
    fn skip_ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn expect(&mut self, c: u8) -> Result<(), String> {
        self.skip_ws();
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(format!("expected '{}' at byte {}", c as char, self.i))
        }
    }
    /// Parse a JSON string (with standard escape handling).
    fn parse_string(&mut self) -> Result<String, String> {
        self.skip_ws();
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let c = self.peek().ok_or("unterminated string")?;
            self.i += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    let e = self.peek().ok_or("unterminated escape")?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b't' => out.push('\t'),
                        b'r' => out.push('\r'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'u' => {
                            let hex: String = (0..4)
                                .map(|_| {
                                    let h = self.peek().unwrap_or(b'0');
                                    self.i += 1;
                                    h as char
                                })
                                .collect();
                            let cp = u32::from_str_radix(&hex, 16)
                                .map_err(|_| "bad \\u escape".to_string())?;
                            out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                        }
                        _ => return Err("invalid escape".into()),
                    }
                }
                _ => {
                    // Re-decode the byte as part of a UTF-8 scalar. Hex/identifier
                    // values are ASCII, so the common path is a single byte.
                    if c < 0x80 {
                        out.push(c as char);
                    } else {
                        // Collect a full UTF-8 sequence starting at c.
                        let start = self.i - 1;
                        let len = utf8_len(c);
                        let end = (start + len).min(self.b.len());
                        out.push_str(std::str::from_utf8(&self.b[start..end]).unwrap_or("\u{FFFD}"));
                        self.i = end;
                    }
                }
            }
        }
    }
    /// Parse a JSON number (integers only, which is all the contract uses).
    fn parse_number(&mut self) -> Result<i64, String> {
        self.skip_ws();
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                self.i += 1;
            } else {
                break;
            }
        }
        let s = std::str::from_utf8(&self.b[start..self.i]).map_err(|_| "bad number".to_string())?;
        s.parse::<i64>().map_err(|_| format!("invalid integer {:?}", s))
    }
    /// Parse a scalar value (string or integer) — the only kinds in the `in` object.
    fn parse_value(&mut self) -> Result<Val, String> {
        self.skip_ws();
        match self.peek() {
            Some(b'"') => Ok(Val::Str(self.parse_string()?)),
            Some(c) if c == b'-' || c.is_ascii_digit() => Ok(Val::Int(self.parse_number()?)),
            Some(b't') => {
                self.consume_literal("true")?;
                Ok(Val::Int(1))
            }
            Some(b'f') => {
                self.consume_literal("false")?;
                Ok(Val::Int(0))
            }
            Some(b'n') => {
                self.consume_literal("null")?;
                Ok(Val::Str(String::new()))
            }
            other => Err(format!("unexpected value byte {:?}", other)),
        }
    }
    fn consume_literal(&mut self, lit: &str) -> Result<(), String> {
        for &want in lit.as_bytes() {
            if self.peek() == Some(want) {
                self.i += 1;
            } else {
                return Err(format!("expected literal {:?}", lit));
            }
        }
        Ok(())
    }
    /// Parse a flat object of scalar values: { "k": v, ... }.
    fn parse_flat_object(&mut self) -> Result<Vec<(String, Val)>, String> {
        let mut fields = Vec::new();
        self.expect(b'{')?;
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(fields);
        }
        loop {
            let key = self.parse_string()?;
            self.expect(b':')?;
            let val = self.parse_value()?;
            fields.push((key, val));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b'}') => {
                    self.i += 1;
                    break;
                }
                other => return Err(format!("expected ',' or '}}' got {:?}", other)),
            }
        }
        Ok(fields)
    }
    /// Parse a top-level request object {"op": "...", "in": {...}}.
    fn parse_request(&mut self) -> Result<Request, String> {
        let mut op = String::new();
        let mut input: Vec<(String, Val)> = Vec::new();
        self.expect(b'{')?;
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Request { op, input });
        }
        loop {
            let key = self.parse_string()?;
            self.expect(b':')?;
            self.skip_ws();
            if key == "in" {
                // The "in" value is itself an object.
                if self.peek() == Some(b'{') {
                    input = self.parse_flat_object()?;
                } else {
                    // tolerate null/empty
                    let _ = self.parse_value()?;
                }
            } else if key == "op" {
                op = self.parse_string()?;
            } else {
                // Skip any unexpected scalar field.
                let _ = self.parse_value()?;
            }
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                    self.skip_ws();
                }
                Some(b'}') => {
                    self.i += 1;
                    break;
                }
                other => return Err(format!("expected ',' or '}}' got {:?}", other)),
            }
        }
        Ok(Request { op, input })
    }
}

fn utf8_len(first: u8) -> usize {
    if first >= 0xF0 {
        4
    } else if first >= 0xE0 {
        3
    } else if first >= 0xC0 {
        2
    } else {
        1
    }
}

/// A response field value for serialization.
enum OutVal {
    Str(String),
    Int(i64),
    Bool(bool),
}

/// Escape a string for JSON output.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn serialize_out(fields: &[(&str, OutVal)]) -> String {
    let mut parts = Vec::with_capacity(fields.len());
    for (k, v) in fields {
        let vs = match v {
            OutVal::Str(s) => format!("\"{}\"", json_escape(s)),
            OutVal::Int(n) => n.to_string(),
            OutVal::Bool(b) => b.to_string(),
        };
        parts.push(format!("\"{}\":{}", json_escape(k), vs));
    }
    format!("{{\"out\":{{{}}}}}", parts.join(","))
}

fn serialize_error(reason: &str) -> String {
    format!("{{\"error\":\"{}\"}}", json_escape(reason))
}

fn serialize_skipped(reason: &str) -> String {
    format!("{{\"skipped\":\"{}\"}}", json_escape(reason))
}

// ---------------------------------------------------------------------------
// Hex helpers.
// ---------------------------------------------------------------------------

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return Err(format!("odd-length hex (len {})", b.len()));
    }
    let nib = |c: u8| -> Result<u8, String> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(format!("invalid hex char {:?}", c as char)),
        }
    };
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks_exact(2) {
        out.push((nib(pair[0])? << 4) | nib(pair[1])?);
    }
    Ok(out)
}

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

// ---------------------------------------------------------------------------
// Operation dispatch. Each arm routes into the `npamp` reference crate; the
// adapter performs no protocol computation of its own.
// ---------------------------------------------------------------------------

fn handle(req: &Request, break_mode: bool) -> String {
    match req.op.as_str() {
        // --- header.encode: build the 36-octet header via npamp's own header_prefix
        //     (octets 0..21) and npamp::crc32c (octets 21..25); reserved octets 25..36
        //     stay zero. Mirrors Frame::marshal but honors an explicit payloadLength. ---
        "header.encode" => {
            let ver = req.get_int("ver").unwrap_or(0) as u8;
            let flags = req.get_int("flags").unwrap_or(0) as u8;
            let ftype = req.get_int("frameType").unwrap_or(0) as u16;
            let channel = req.get_int("channel").unwrap_or(0) as u16;
            let seq = req.get_int("seq").unwrap_or(0) as u64;
            let payload_length = req.get_int("payloadLength").unwrap_or(0) as u32;

            let frame = Frame { version: ver, flags, ftype, channel, seq, payload: Vec::new() };
            let mut hdr = [0u8; npamp::HEADER_SIZE];
            // header_prefix writes octets 0..21 (magic, ver/flags, ftype, channel, seq, payloadLength).
            frame.header_prefix(&mut hdr, payload_length);
            // crc32c over octets 0..21, big-endian into 21..25 (npamp::crc32c is the real CRC).
            let crc = npamp::crc32c(&hdr[0..21]);
            hdr[21..25].copy_from_slice(&crc.to_be_bytes());
            // octets 25..36 remain zero (reserved).
            serialize_out(&[("frame", OutVal::Str(hex_encode(&hdr)))])
        }

        // --- header.decode: route through npamp::Frame::unmarshal, which performs the
        //     real MUST-reject rules (CRC validated first, reserved-zero, version,
        //     length). On Err -> {"error"}. Derive the report fields the contract wants. ---
        "header.decode" => {
            let frame_hex = match req.get_str("frame") {
                Some(h) => h,
                None => return serialize_error("missing frame"),
            };
            let buf = match hex_decode(frame_hex) {
                Ok(b) => b,
                Err(e) => return serialize_error(&e),
            };
            match Frame::unmarshal(&buf) {
                Ok(f) => {
                    // unmarshal succeeded => buf is a full valid 36+ octet frame.
                    let crc_hex = hex_encode(&buf[21..25]);
                    serialize_out(&[
                        ("magic", OutVal::Str("NPAM".to_string())),
                        ("ver", OutVal::Int(f.version as i64)),
                        ("flags", OutVal::Int(f.flags as i64)),
                        ("frameType", OutVal::Int(f.ftype as i64)),
                        ("channel", OutVal::Int(f.channel as i64)),
                        ("seq", OutVal::Int(f.seq as i64)),
                        ("payloadLength", OutVal::Int(f.payload.len() as i64)),
                        ("crc32c", OutVal::Str(crc_hex)),
                        ("reservedZero", OutVal::Bool(true)),
                    ])
                }
                Err(e) => serialize_error(&format!("{:?}", e)),
            }
        }

        // --- crc32c: npamp::crc32c (Castagnoli) over the given octets, big-endian. ---
        "crc32c" => {
            let octets = match req.get_str("octets") {
                Some(h) => h,
                None => return serialize_error("missing octets"),
            };
            let b = match hex_decode(octets) {
                Ok(b) => b,
                Err(e) => return serialize_error(&e),
            };
            let crc = if break_mode {
                [0xde, 0xad, 0xbe, 0xef] // deliberate corruption for the runner's mutation check
            } else {
                npamp::crc32c(&b).to_be_bytes()
            };
            serialize_out(&[("crc32c", OutVal::Str(hex_encode(&crc)))])
        }

        // --- tlv.decode: the OPEN reference impl (impl/rust) exposes no TLV decode
        //     function — only TLV *type* constants. Per the adapter contract, report
        //     this op Unimplemented rather than reimplementing it here. ---
        "tlv.decode" => serialize_skipped("tlv.decode not provided by impl/rust"),

        // --- aead.seal: npamp::seal_aes256gcm. The reference API derives the nonce as
        //     iv XOR (0^4||seq); passing the raw nonce as `iv` with seq=0 makes the
        //     derived nonce equal the given nonce, exercising the REAL seal path (this
        //     is the documented technique used by npamp's own Wycheproof KAT). ---
        "aead.seal" => {
            if req.get_str("suite") != Some("AES-256-GCM") {
                return serialize_skipped(&format!(
                    "suite not implemented: {}",
                    req.get_str("suite").unwrap_or("")
                ));
            }
            let key = match decode_key(req) {
                Ok(k) => k,
                Err(e) => return serialize_error(&e),
            };
            let nonce = match decode_nonce(req) {
                Ok(n) => n,
                Err(e) => return serialize_error(&e),
            };
            let aad = match hex_field(req, "aad") {
                Ok(v) => v,
                Err(e) => return serialize_error(&e),
            };
            let pt = match hex_field(req, "pt") {
                Ok(v) => v,
                Err(e) => return serialize_error(&e),
            };
            let sealed = npamp::seal_aes256gcm(&key, &nonce, 0, &aad, &pt);
            serialize_out(&[("sealed", OutVal::Str(hex_encode(&sealed)))])
        }

        // --- aead.open: npamp::open_aes256gcm (same raw-nonce technique). A tag
        //     mismatch returns Err -> {"error"} (the MUST-reject path). ---
        "aead.open" => {
            if req.get_str("suite") != Some("AES-256-GCM") {
                return serialize_skipped(&format!(
                    "suite not implemented: {}",
                    req.get_str("suite").unwrap_or("")
                ));
            }
            let key = match decode_key(req) {
                Ok(k) => k,
                Err(e) => return serialize_error(&e),
            };
            let nonce = match decode_nonce(req) {
                Ok(n) => n,
                Err(e) => return serialize_error(&e),
            };
            let aad = match hex_field(req, "aad") {
                Ok(v) => v,
                Err(e) => return serialize_error(&e),
            };
            let sealed = match hex_field(req, "sealed") {
                Ok(v) => v,
                Err(e) => return serialize_error(&e),
            };
            match npamp::open_aes256gcm(&key, &nonce, 0, &aad, &sealed) {
                Ok(pt) => serialize_out(&[("pt", OutVal::Str(hex_encode(&pt)))]),
                Err(()) => serialize_error("authentication failed"),
            }
        }

        // --- hkdf.expand: npamp::hkdf_expand (RFC 5869 §2.3). standard=true selects
        //     SHA-256, false selects SHA-384, matching the reference key schedule. ---
        "hkdf.expand" => {
            let standard = match req.get_str("hash") {
                Some("sha256") => true,
                Some("sha384") => false,
                other => {
                    return serialize_skipped(&format!("hash not implemented: {}", other.unwrap_or("")))
                }
            };
            let prk = match hex_field(req, "prk") {
                Ok(v) => v,
                Err(e) => return serialize_error(&e),
            };
            let info = match hex_field(req, "info") {
                Ok(v) => v,
                Err(e) => return serialize_error(&e),
            };
            let length = req.get_int("length").unwrap_or(0);
            if length < 0 {
                return serialize_error("negative length");
            }
            let okm = npamp::hkdf_expand(&prk, &info, length as usize, standard);
            serialize_out(&[("okm", OutVal::Str(hex_encode(&okm)))])
        }

        // --- profile.check: the OPEN reference impl (impl/rust) exposes no profile
        //     KEM-acceptance function — only KEM/profile constants. Report Unimplemented
        //     rather than reimplementing the acceptance policy here. ---
        "profile.check" => serialize_skipped("profile.check not provided by impl/rust"),

        other => serialize_skipped(&format!("op not implemented: {}", other)),
    }
}

fn hex_field(req: &Request, key: &str) -> Result<Vec<u8>, String> {
    // Absent optional byte fields decode to empty, matching the Go/Python templates.
    match req.get_str(key) {
        Some(s) => hex_decode(s),
        None => Ok(Vec::new()),
    }
}

fn decode_key(req: &Request) -> Result<[u8; 32], String> {
    let b = hex_field(req, "key")?;
    <[u8; 32]>::try_from(b.as_slice()).map_err(|_| format!("key must be 32 bytes, got {}", b.len()))
}

fn decode_nonce(req: &Request) -> Result<[u8; 12], String> {
    let b = hex_field(req, "nonce")?;
    <[u8; 12]>::try_from(b.as_slice()).map_err(|_| format!("nonce must be 12 bytes, got {}", b.len()))
}

// ---------------------------------------------------------------------------
// Length-prefixed framing loop (4-byte little-endian length + JSON), binary
// stdio, flush after every response.
// ---------------------------------------------------------------------------

fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => {
                if filled == 0 {
                    return Ok(false); // clean EOF at a frame boundary
                }
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated frame"));
            }
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

fn main() {
    let break_mode = std::env::args().skip(1).any(|a| a == "--break");

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut r = stdin.lock();
    let mut w = stdout.lock();

    loop {
        let mut lp = [0u8; 4];
        match read_exact_or_eof(&mut r, &mut lp) {
            Ok(true) => {}
            Ok(false) => break, // runner closed stdin
            Err(_) => break,
        }
        let n = u32::from_le_bytes(lp) as usize;
        let mut body = vec![0u8; n];
        if let Err(_) = read_exact_or_eof(&mut r, &mut body).and_then(|ok| {
            if ok {
                Ok(())
            } else {
                Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof in body"))
            }
        }) {
            break;
        }

        let resp = match Parser::new(&body).parse_request() {
            Ok(req) => handle(&req, break_mode),
            Err(e) => serialize_error(&format!("bad request json: {}", e)),
        };

        let ob = resp.into_bytes();
        let ol = (ob.len() as u32).to_le_bytes();
        if w.write_all(&ol).is_err() || w.write_all(&ob).is_err() || w.flush().is_err() {
            break;
        }
    }
}
