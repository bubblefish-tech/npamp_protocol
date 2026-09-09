//! N-PAMP (draft-bubblefish-npamp-00) conformance adapter — Rust "testee".
//!
//! Reads length-prefixed JSON requests {op,in} on stdin and writes length-prefixed
//! JSON responses {out|error|skipped} on stdout, performing the real N-PAMP primitive
//! for each op by calling the OPEN reference implementation crate `npamp` (path
//! dependency `../../../impl/rust`). This file owns NO protocol logic: every op routes
//! into a function exported by `npamp` (crc32c, Frame::unmarshal, header_prefix,
//! seal_aes256gcm, open_aes256gcm, hkdf_expand; the channel body decoders
//! bodies::validate_memory / validate_stream / validate_by_op; and the Bridge
//! (channel 0x000D) frame codec bridge::decode_bridge_frame / decode_bridge_envelope /
//! encode_bridge_payload / correlate_bridge_reply). Operations the reference impl does
//! not provide a function for (tlv.decode, profile.check) return {"skipped":...} and
//! are reported Unimplemented, never reimplemented here.
//!
//! Windows note: stdin/stdout are used as raw binary byte streams (no text-mode CRLF
//! translation exists on the `std::io::Stdin`/`Stdout` byte handles) and the adapter
//! FLUSHES after every response, so the 4-byte little-endian length framing never
//! corrupts. To exercise the runner's mutation check, `--break` corrupts the crc32c op.

use std::io::{self, Read, Write};

use npamp::{self, Frame};

// ---------------------------------------------------------------------------
// Minimal, dependency-free JSON for the request/response objects of the conformance
// contract. Requests are {"op": <str>, "in": { <str>: <str|int|bool|null|obj|arr> }}.
// Responses are one flat-or-nested object: {"out": {...}} | {"error": <str>} |
// {"skipped": <str>}. Most ops use only flat scalar fields; bridge.envelope.encode's
// `in.fields` (and its nested `in.fields.safety`) is the one nested-object input the
// contract carries, so Val recurses (Obj/Arr) rather than staying flat.
// ---------------------------------------------------------------------------

/// A decoded JSON value as it appears in the `in` object (or nested within it).
#[derive(Debug, Clone)]
#[allow(dead_code)] // Bool/Arr are parsed for completeness; no current op field reads them.
enum Val {
    Str(String),
    Int(i64),
    Bool(bool),
    Null,
    Obj(Vec<(String, Val)>),
    Arr(Vec<Val>),
}

/// A parsed request.
struct Request {
    op: String,
    input: Vec<(String, Val)>,
}

impl Request {
    fn get_str(&self, key: &str) -> Option<&str> {
        field_str(&self.input, key)
    }
    fn get_int(&self, key: &str) -> Option<i64> {
        field_int(&self.input, key)
    }
    /// Returns the nested object at `key` (e.g. `in.fields`), if present and an
    /// object.
    fn get_obj(&self, key: &str) -> Option<&Vec<(String, Val)>> {
        field_obj(&self.input, key)
    }
}

/// Looks up a string-valued field in a flat-or-nested object slice (`in` or a nested
/// object such as `in.fields`).
fn field_str<'a>(fields: &'a [(String, Val)], key: &str) -> Option<&'a str> {
    fields.iter().find(|(k, _)| k == key).and_then(|(_, v)| match v {
        Val::Str(s) => Some(s.as_str()),
        _ => None,
    })
}

/// Looks up an integer-valued field in a flat-or-nested object slice.
fn field_int(fields: &[(String, Val)], key: &str) -> Option<i64> {
    fields.iter().find(|(k, _)| k == key).and_then(|(_, v)| match v {
        Val::Int(n) => Some(*n),
        _ => None,
    })
}

/// Looks up a nested-object-valued field in a flat-or-nested object slice. Returns
/// `None` both when the key is absent and when its value is JSON `null` (the
/// corpus's explicit `"safety": null` on a reply without a SafetyLabel), matching Go's
/// `fields["safety"].(map[string]interface{})` type-assertion semantics.
fn field_obj<'a>(fields: &'a [(String, Val)], key: &str) -> Option<&'a Vec<(String, Val)>> {
    fields.iter().find(|(k, _)| k == key).and_then(|(_, v)| match v {
        Val::Obj(o) => Some(o),
        _ => None,
    })
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
    /// Parse a value from the `in` object, or from a nested object/array within it
    /// (e.g. bridge.envelope.encode's `in.fields` and its nested `in.fields.safety`).
    /// Recurses fully: an object becomes `Val::Obj`, an array `Val::Arr`, so a caller
    /// can walk into any depth the corpus's request payloads use.
    fn parse_value(&mut self) -> Result<Val, String> {
        self.skip_ws();
        match self.peek() {
            Some(b'"') => Ok(Val::Str(self.parse_string()?)),
            Some(c) if c == b'-' || c.is_ascii_digit() => Ok(Val::Int(self.parse_number()?)),
            Some(b'{') => Ok(Val::Obj(self.parse_flat_object()?)),
            Some(b'[') => {
                self.i += 1;
                let mut items = Vec::new();
                self.skip_ws();
                if self.peek() == Some(b']') {
                    self.i += 1;
                    return Ok(Val::Arr(items));
                }
                loop {
                    items.push(self.parse_value()?);
                    self.skip_ws();
                    match self.peek() {
                        Some(b',') => {
                            self.i += 1;
                        }
                        Some(b']') => {
                            self.i += 1;
                            break;
                        }
                        other => return Err(format!("expected ',' or ']' got {:?}", other)),
                    }
                }
                Ok(Val::Arr(items))
            }
            Some(b't') => {
                self.consume_literal("true")?;
                Ok(Val::Bool(true))
            }
            Some(b'f') => {
                self.consume_literal("false")?;
                Ok(Val::Bool(false))
            }
            Some(b'n') => {
                self.consume_literal("null")?;
                Ok(Val::Null)
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

/// A response field value for serialization. `Obj` is used by bridge.envelope.decode's
/// `safety` field, which the contract requires as either a nested object or an
/// explicit JSON `null` (never an omitted key — see `serialize_val`'s `Null` arm).
enum OutVal {
    Str(String),
    Int(i64),
    Bool(bool),
    Null,
    Obj(Vec<(&'static str, OutVal)>),
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
    format!("{{\"out\":{}}}", serialize_obj(fields))
}

fn serialize_obj(fields: &[(&str, OutVal)]) -> String {
    let mut parts = Vec::with_capacity(fields.len());
    for (k, v) in fields {
        parts.push(format!("\"{}\":{}", json_escape(k), serialize_val(v)));
    }
    format!("{{{}}}", parts.join(","))
}

fn serialize_val(v: &OutVal) -> String {
    match v {
        OutVal::Str(s) => format!("\"{}\"", json_escape(s)),
        OutVal::Int(n) => n.to_string(),
        OutVal::Bool(b) => b.to_string(),
        OutVal::Null => "null".to_string(),
        OutVal::Obj(o) => serialize_obj(o),
    }
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

/// Decodes plain UTF-8 bytes (e.g. a Bridge envelope's `method` or a SafetyLabel's
/// `scope`, which the corpus carries as raw text, not hex) for JSON output. Uses
/// `from_utf8_lossy` rather than `unwrap` so a malformed-but-decoded field (never
/// produced by the corpus's own vectors) still serializes instead of panicking.
fn bytes_to_utf8(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
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

        // --- <chan>.body.decode: validate a channel body for the given frame type via the
        //     npamp reference crate's structural validators (impl/rust/src/bodies.rs). A
        //     reference rejection (non-deterministic CBOR, missing REQUIRED key, wrong CBOR
        //     major type, frame_kind/header mismatch, unknown negative key) is an {"error"}
        //     (the "invalid" verdict); a valid body returns its envelope frame_kind (0) and
        //     corr (1) — or, for Stream, sub_stream_id (1), an unsigned int rather than a
        //     byte string. The eight native channels share one validator dispatch
        //     (validate_by_op); Memory and Stream each carry a distinct envelope. ---
        "memory.body.decode" => body_decode_corr(req, |ft, body| npamp::bodies::validate_memory(ft, body)),
        "stream.body.decode" => body_decode_stream(req),
        "capability.body.decode"
        | "immune.body.decode"
        | "settlement.body.decode"
        | "telemetry.body.decode"
        | "commerce.body.decode"
        | "interaction.body.decode"
        | "workflow.body.decode"
        | "knowledge.body.decode" => {
            let op = req.op.as_str();
            body_decode_corr(req, |ft, body| npamp::bodies::validate_by_op(op, ft, body))
        }

        // --- bridge.envelope.decode: decode a Bridge payload (BridgeEnvelope TLV +
        //     optional SafetyLabel + verbatim foreign octets) via npamp::bridge and
        //     project its declared fields; a reference rejection is an {"error"} (the
        //     "invalid" verdict). `safety` is ALWAYS emitted — a nested object when
        //     present, else an explicit JSON null (never an omitted key) — mirroring
        //     the Go adapter's "emit null so the absent case matches" contract. ---
        "bridge.envelope.decode" => {
            let payload = match req.get_str("payload") {
                Some(h) => match hex_decode(h) {
                    Ok(b) => b,
                    Err(e) => return serialize_error(&e),
                },
                None => return serialize_error("missing payload"),
            };
            let ft = req.get_int("frameType").unwrap_or(0) as u16;
            match npamp::bridge::decode_bridge_frame(ft, &payload) {
                Ok(f) => {
                    let mut fields: Vec<(&str, OutVal)> = vec![
                        ("protocol_id", OutVal::Int(f.envelope.protocol as i64)),
                        ("message_kind", OutVal::Int(f.envelope.kind as i64)),
                        ("content_type", OutVal::Int(f.envelope.content_type as i64)),
                        ("flags", OutVal::Int(f.envelope.flags as i64)),
                        ("final", OutVal::Bool(f.envelope.final_flag())),
                        ("corr", OutVal::Str(hex_encode(&f.envelope.correlation_id))),
                        ("method", OutVal::Str(bytes_to_utf8(&f.envelope.method))),
                        ("foreign", OutVal::Str(hex_encode(&f.foreign))),
                    ];
                    fields.push((
                        "safety",
                        match &f.safety {
                            Some(s) => OutVal::Obj(vec![
                                ("effect", OutVal::Int(s.effect as i64)),
                                ("scope", OutVal::Str(bytes_to_utf8(&s.scope))),
                            ]),
                            None => OutVal::Null,
                        },
                    ));
                    serialize_out(&fields)
                }
                Err(e) => serialize_error(&e.0),
            }
        }

        // --- bridge.envelope.encode: build a Bridge payload from the oracle's declared
        //     `fields` (a nested object; `corr`/`foreign` are hex, `method`/
        //     `safety.scope` are plain UTF-8 text) via npamp::bridge; the canonical
        //     bytes MUST match the vector's expected payload. ---
        "bridge.envelope.encode" => {
            let fields = match req.get_obj("fields") {
                Some(f) => f,
                None => return serialize_error("missing fields"),
            };
            let corr = match field_str(fields, "corr").map(hex_decode) {
                Some(Ok(b)) => b,
                Some(Err(e)) => return serialize_error(&format!("bad corr hex: {}", e)),
                None => Vec::new(),
            };
            let foreign = match field_str(fields, "foreign").map(hex_decode) {
                Some(Ok(b)) => b,
                Some(Err(e)) => return serialize_error(&format!("bad foreign hex: {}", e)),
                None => Vec::new(),
            };
            let method = field_str(fields, "method").unwrap_or("").as_bytes().to_vec();
            let env = npamp::bridge::BridgeEnvelope {
                protocol: field_int(fields, "protocol_id").unwrap_or(0) as u16,
                kind: field_int(fields, "message_kind").unwrap_or(0) as u8,
                content_type: field_int(fields, "content_type").unwrap_or(0) as u8,
                flags: field_int(fields, "flags").unwrap_or(0) as u8,
                correlation_id: corr,
                method,
            };
            let safety = field_obj(fields, "safety").map(|sf| npamp::bridge::SafetyLabel {
                effect: field_int(sf, "effect").unwrap_or(0) as u8,
                scope: field_str(sf, "scope").unwrap_or("").as_bytes().to_vec(),
            });
            let payload = npamp::bridge::encode_bridge_payload(&env, safety.as_ref(), &foreign);
            serialize_out(&[("payload", OutVal::Str(hex_encode(&payload)))])
        }

        // --- bridge.correlate: §5 match-by-identifier -- a reply correlates iff its
        //     correlation_id byte-equals the request's (both non-empty). Decode both
        //     envelopes via npamp::bridge and return the boolean. ---
        "bridge.correlate" => {
            let req_payload = match req.get_str("requestPayload") {
                Some(h) => match hex_decode(h) {
                    Ok(b) => b,
                    Err(e) => return serialize_error(&format!("bad request hex: {}", e)),
                },
                None => return serialize_error("missing requestPayload"),
            };
            let rep_payload = match req.get_str("replyPayload") {
                Some(h) => match hex_decode(h) {
                    Ok(b) => b,
                    Err(e) => return serialize_error(&format!("bad reply hex: {}", e)),
                },
                None => return serialize_error("missing replyPayload"),
            };
            let req_ft = req.get_int("requestFrameType").unwrap_or(0) as u16;
            let rep_ft = req.get_int("replyFrameType").unwrap_or(0) as u16;
            let req_env = match npamp::bridge::decode_bridge_envelope(req_ft, &req_payload) {
                Ok(e) => e,
                Err(e) => return serialize_error(&e.0),
            };
            let rep_env = match npamp::bridge::decode_bridge_envelope(rep_ft, &rep_payload) {
                Ok(e) => e,
                Err(e) => return serialize_error(&e.0),
            };
            serialize_out(&[(
                "match",
                OutVal::Bool(npamp::bridge::correlate_bridge_reply(&req_env, &rep_env)),
            )])
        }

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
// Channel body.decode helpers. Each routes a <chan>.body.decode op into the
// npamp reference crate's structural validators and projects the graded fields
// the conformance contract expects; the adapter makes no accept/reject decision
// of its own — every verdict is the reference crate's.
// ---------------------------------------------------------------------------

/// Grade a Memory / native-channel body.decode op: on a valid body report frame_kind (0)
/// and corr (1, hex); on a reference rejection report {"error"} (the "invalid" verdict).
fn body_decode_corr<F>(req: &Request, validate: F) -> String
where
    F: Fn(u64, &[u8]) -> Result<npamp::bodies::CborMap, npamp::bodies::Malformed>,
{
    let body = match req.get_str("body") {
        Some(h) => match hex_decode(h) {
            Ok(b) => b,
            Err(e) => return serialize_error(&e),
        },
        None => return serialize_error("missing body"),
    };
    let ft = req.get_int("frameType").unwrap_or(0) as u64;
    match validate(ft, &body) {
        Ok(m) => {
            let fk = m.get_u64(0).unwrap_or(0);
            let corr = m.get_bytes(1).unwrap_or(&[]);
            serialize_out(&[
                ("frame_kind", OutVal::Int(fk as i64)),
                ("corr", OutVal::Str(hex_encode(corr))),
            ])
        }
        Err(e) => serialize_error(&e.0),
    }
}

/// Grade a Stream body.decode op: on a valid body report frame_kind (0) and sub_stream_id
/// (1, an unsigned int); on a reference rejection report {"error"} (the "invalid" verdict).
fn body_decode_stream(req: &Request) -> String {
    let body = match req.get_str("body") {
        Some(h) => match hex_decode(h) {
            Ok(b) => b,
            Err(e) => return serialize_error(&e),
        },
        None => return serialize_error("missing body"),
    };
    let ft = req.get_int("frameType").unwrap_or(0) as u64;
    match npamp::bodies::validate_stream(ft, &body) {
        Ok(m) => {
            let fk = m.get_u64(0).unwrap_or(0);
            let ssid = m.get_u64(1).unwrap_or(0);
            serialize_out(&[
                ("frame_kind", OutVal::Int(fk as i64)),
                ("sub_stream_id", OutVal::Int(ssid as i64)),
            ])
        }
        Err(e) => serialize_error(&e.0),
    }
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
