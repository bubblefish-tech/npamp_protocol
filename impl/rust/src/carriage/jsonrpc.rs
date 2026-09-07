// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! NPAMP-CC-JSONRPC (spec/companion/20_carriage_jsonrpc.md) carriage codec —
//! carries a JSON-RPC 2.0 object octet-for-octet as the Bridge frame's foreign
//! message (§2, §3): it never re-serializes, reorders, or rewrites the carried
//! object. This module adds no `serde`/JSON dependency to the crate (matching
//! the crate's existing "no serde, no external JSON dependency" posture — see
//! `tests/conformance_bodies.rs`'s own hand-rolled JSON parser for the
//! precedent) — both the encoder and decoder below are hand-written against the
//! JSON grammar (RFC 8259) and Go's `encoding/json` default marshal behavior
//! (map-key sort order, string escaping), the two properties that must match
//! byte-for-byte for this carriage class's wrap-then-unwrap round trip. Both
//! rules were empirically re-confirmed this session against a live Go program
//! (`json.Marshal` of `map[string]any` and of strings containing `<`, `>`,
//! `&`, control characters, and non-ASCII UTF-8) rather than trusted from
//! memory.

use crate::carriage::CarriageError;

// ---------------------------------------------------------------------------
// Encode-side JSON value model
// ---------------------------------------------------------------------------

/// A JSON value to encode. `Number` carries an already-formatted JSON number
/// literal (e.g. `"42"`, `"-7"`, `"3.14"`) emitted verbatim — the caller
/// supplies valid JSON number syntax directly, which avoids reimplementing
/// Go's `encoding/json` float-formatting rules for a type this carriage
/// class's own encode entry points never need to produce (only `String`/`Null`
/// ids and `Object`/`Array`/`String`/`Bool`/`Number` params).
#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<JsonValue>),
    /// Encoded with keys sorted byte-lexicographically before emission,
    /// exactly mirroring Go's `encoding/json` behavior when marshaling a
    /// `map[string]any` (Go's own map iteration is unordered; `encoding/json`
    /// always sorts map keys before emitting them — empirically re-confirmed
    /// this session against a live Go program).
    Object(Vec<(String, JsonValue)>),
}

/// Encodes `v` as compact JSON, matching Go's `encoding/json.Marshal` default
/// behavior for the types above: no whitespace, object keys sorted
/// byte-lexicographically, and strings escaped per Go's default (HTML-safe)
/// rule set.
pub fn encode(v: &JsonValue) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(v, &mut out);
    out
}

fn encode_into(v: &JsonValue, out: &mut Vec<u8>) {
    match v {
        JsonValue::Null => out.extend_from_slice(b"null"),
        JsonValue::Bool(true) => out.extend_from_slice(b"true"),
        JsonValue::Bool(false) => out.extend_from_slice(b"false"),
        JsonValue::Number(s) => out.extend_from_slice(s.as_bytes()),
        JsonValue::String(s) => encode_string(s, out),
        JsonValue::Array(items) => {
            out.push(b'[');
            for (i, it) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                encode_into(it, out);
            }
            out.push(b']');
        }
        JsonValue::Object(entries) => {
            // Go's encoding/json sorts map keys byte-lexicographically before
            // emitting them (empirically confirmed this session: a Go map
            // {"z":1,"a":2,"id":nil,"M":3} marshals as
            // {"M":3,"a":2,"id":null,"z":1} -- plain byte-wise ASCII order,
            // not case-insensitive). Rust's default `String: Ord` is also
            // byte-wise UTF-8 comparison, so `.cmp()` matches directly.
            let mut sorted: Vec<&(String, JsonValue)> = entries.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            out.push(b'{');
            for (i, (k, val)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                encode_string(k, out);
                out.push(b':');
                encode_into(val, out);
            }
            out.push(b'}');
        }
    }
}

/// Encodes `s` as a JSON string literal, matching Go's `encoding/json` default
/// (HTML-safe) escaping exactly: `"`/`\` escaped, control characters 0x00-0x1F
/// escaped (`\b \t \n \f \r` shorthand where defined, `\u00XX` otherwise),
/// `<`/`>`/`&` escaped as `<`/`>`/`&`, U+2028/U+2029 escaped as
/// `\u2028`/`\u2029`, and every other codepoint (including non-ASCII UTF-8 and
/// U+007F DEL) emitted verbatim. Empirically verified this session against a
/// live Go program covering every one of these classes.
fn encode_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '<' => out.extend_from_slice(b"\\u003c"),
            '>' => out.extend_from_slice(b"\\u003e"),
            '&' => out.extend_from_slice(b"\\u0026"),
            '\u{2028}' => out.extend_from_slice(b"\\u2028"),
            '\u{2029}' => out.extend_from_slice(b"\\u2029"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\u{0C}' => out.extend_from_slice(b"\\f"),
            '\r' => out.extend_from_slice(b"\\r"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

// ---------------------------------------------------------------------------
// Decode-side: a raw-span JSON object parser (RFC 8259), mirroring Go's
// `json.Unmarshal(raw, &map[string]json.RawMessage{})` — every top-level
// member's value is captured as its exact byte span, not decoded further,
// except where a member (`jsonrpc`, `method`) must itself be a JSON string.
// ---------------------------------------------------------------------------

struct RawParser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> RawParser<'a> {
    fn new(b: &'a [u8]) -> Self {
        RawParser { b, i: 0 }
    }

    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    /// Parses a JSON string starting at the current position (expects `"`),
    /// returning the decoded string and advancing past the closing quote.
    fn parse_string(&mut self) -> Result<String, CarriageError> {
        if self.peek() != Some(b'"') {
            return Err(CarriageError(format!(
                "expected '\"' at byte {} of JSON input",
                self.i
            )));
        }
        self.i += 1;
        let mut out = String::new();
        loop {
            let c = *self
                .b
                .get(self.i)
                .ok_or_else(|| CarriageError("unterminated JSON string".into()))?;
            match c {
                b'"' => {
                    self.i += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.i += 1;
                    let e = *self
                        .b
                        .get(self.i)
                        .ok_or_else(|| CarriageError("truncated JSON string escape".into()))?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let cp = self.parse_hex4()?;
                            if (0xD800..=0xDBFF).contains(&cp) {
                                // High surrogate: expect a following \uDCxx low
                                // surrogate to combine into one scalar value.
                                if self.b.get(self.i) == Some(&b'\\')
                                    && self.b.get(self.i + 1) == Some(&b'u')
                                {
                                    self.i += 2;
                                    let lo = self.parse_hex4()?;
                                    if (0xDC00..=0xDFFF).contains(&lo) {
                                        let c32 =
                                            0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                        out.push(char::from_u32(c32).unwrap_or('\u{FFFD}'));
                                    } else {
                                        out.push('\u{FFFD}');
                                    }
                                } else {
                                    out.push('\u{FFFD}');
                                }
                            } else if (0xDC00..=0xDFFF).contains(&cp) {
                                out.push('\u{FFFD}'); // lone low surrogate
                            } else {
                                out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                            }
                        }
                        other => {
                            return Err(CarriageError(format!(
                                "invalid JSON string escape '\\{}'",
                                other as char
                            )))
                        }
                    }
                }
                0x00..=0x1F => {
                    return Err(CarriageError(
                        "unescaped control character in JSON string literal".into(),
                    ))
                }
                _ => {
                    let width = utf8_char_width(c);
                    let end = self.i + width;
                    if end > self.b.len() {
                        return Err(CarriageError("truncated UTF-8 sequence in JSON string".into()));
                    }
                    let s = std::str::from_utf8(&self.b[self.i..end])
                        .map_err(|_| CarriageError("invalid UTF-8 in JSON string".into()))?;
                    out.push_str(s);
                    self.i = end;
                }
            }
        }
    }

    fn parse_hex4(&mut self) -> Result<u32, CarriageError> {
        let bytes = self
            .b
            .get(self.i..self.i + 4)
            .ok_or_else(|| CarriageError("truncated \\u escape in JSON string".into()))?;
        let s = std::str::from_utf8(bytes)
            .map_err(|_| CarriageError("invalid \\u escape in JSON string".into()))?;
        let v = u32::from_str_radix(s, 16)
            .map_err(|_| CarriageError("invalid hex digits in \\u escape".into()))?;
        self.i += 4;
        Ok(v)
    }

    /// Skips one JSON value at the current position, returning its raw byte
    /// span `[start, end)` (leading whitespace excluded).
    fn skip_value(&mut self) -> Result<(usize, usize), CarriageError> {
        self.ws();
        let start = self.i;
        match self.peek() {
            Some(b'"') => {
                self.parse_string()?;
            }
            Some(b'{') => self.skip_object()?,
            Some(b'[') => self.skip_array()?,
            Some(b't') => self.expect_literal("true")?,
            Some(b'f') => self.expect_literal("false")?,
            Some(b'n') => self.expect_literal("null")?,
            Some(b'-') | Some(b'0'..=b'9') => self.skip_number()?,
            Some(other) => {
                return Err(CarriageError(format!(
                    "unexpected byte 0x{other:02x} at byte {} of JSON input",
                    self.i
                )))
            }
            None => return Err(CarriageError("unexpected end of JSON input".into())),
        }
        Ok((start, self.i))
    }

    fn expect_literal(&mut self, lit: &str) -> Result<(), CarriageError> {
        if self.b[self.i..].starts_with(lit.as_bytes()) {
            self.i += lit.len();
            Ok(())
        } else {
            Err(CarriageError(format!(
                "expected literal {lit} at byte {}",
                self.i
            )))
        }
    }

    fn skip_number(&mut self) -> Result<(), CarriageError> {
        let is_digit = |b: Option<u8>| b.map(|c| c.is_ascii_digit()) == Some(true);
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        if !is_digit(self.peek()) {
            return Err(CarriageError(format!(
                "invalid JSON number at byte {}",
                self.i
            )));
        }
        while is_digit(self.peek()) {
            self.i += 1;
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if !is_digit(self.peek()) {
                return Err(CarriageError("invalid JSON number fraction".into()));
            }
            while is_digit(self.peek()) {
                self.i += 1;
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.i += 1;
            }
            if !is_digit(self.peek()) {
                return Err(CarriageError("invalid JSON number exponent".into()));
            }
            while is_digit(self.peek()) {
                self.i += 1;
            }
        }
        Ok(())
    }

    fn skip_object(&mut self) -> Result<(), CarriageError> {
        self.i += 1; // '{'
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(());
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(CarriageError("expected a string object key".into()));
            }
            self.parse_string()?;
            self.ws();
            if self.peek() != Some(b':') {
                return Err(CarriageError("expected ':' after object key".into()));
            }
            self.i += 1;
            self.skip_value()?;
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(CarriageError("expected ',' or '}' in JSON object".into())),
            }
        }
        Ok(())
    }

    fn skip_array(&mut self) -> Result<(), CarriageError> {
        self.i += 1; // '['
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(());
        }
        loop {
            self.skip_value()?;
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(CarriageError("expected ',' or ']' in JSON array".into())),
            }
        }
        Ok(())
    }
}

/// Returns the UTF-8 sequence length implied by a leading byte.
fn utf8_char_width(b: u8) -> usize {
    if b & 0x80 == 0 {
        1
    } else if b & 0xE0 == 0xC0 {
        2
    } else if b & 0xF0 == 0xE0 {
        3
    } else if b & 0xF8 == 0xF0 {
        4
    } else {
        1 // invalid leading byte; parse_string's from_utf8 check will reject it
    }
}

/// Parses `raw` as a top-level JSON object, returning each member's key and
/// the exact raw byte span of its value (last-key-wins on duplicates,
/// matching Go's `json.Unmarshal` into a `map[string]json.RawMessage`).
/// Requires the ENTIRE input (apart from surrounding whitespace) to be
/// consumed, matching Go's `json.Unmarshal` strictness.
fn parse_top_object(raw: &[u8]) -> Result<Vec<(String, Vec<u8>)>, CarriageError> {
    let mut p = RawParser::new(raw);
    p.ws();
    if p.peek() != Some(b'{') {
        return Err(CarriageError("not a JSON object".into()));
    }
    p.i += 1;
    let mut fields: Vec<(String, Vec<u8>)> = Vec::new();
    p.ws();
    if p.peek() == Some(b'}') {
        p.i += 1;
    } else {
        loop {
            p.ws();
            if p.peek() != Some(b'"') {
                return Err(CarriageError("expected a string object key".into()));
            }
            let key = p.parse_string()?;
            p.ws();
            if p.peek() != Some(b':') {
                return Err(CarriageError("expected ':' after object key".into()));
            }
            p.i += 1;
            let (vs, ve) = p.skip_value()?;
            let raw_val = raw[vs..ve].to_vec();
            if let Some(existing) = fields.iter_mut().find(|(k, _)| *k == key) {
                existing.1 = raw_val;
            } else {
                fields.push((key, raw_val));
            }
            p.ws();
            match p.peek() {
                Some(b',') => p.i += 1,
                Some(b'}') => {
                    p.i += 1;
                    break;
                }
                _ => return Err(CarriageError("expected ',' or '}' in JSON object".into())),
            }
        }
    }
    p.ws();
    if p.i != raw.len() {
        return Err(CarriageError(format!(
            "not a JSON object: trailing bytes after top-level value ({} of {} consumed)",
            p.i,
            raw.len()
        )));
    }
    Ok(fields)
}

/// Parses `raw` as a JSON value expected to be exactly a JSON string,
/// requiring the whole span to be consumed.
fn parse_json_string_value(raw: &[u8]) -> Result<String, CarriageError> {
    let mut p = RawParser::new(raw);
    p.ws();
    if p.peek() != Some(b'"') {
        return Err(CarriageError("expected a JSON string".into()));
    }
    let s = p.parse_string()?;
    p.ws();
    if p.i != raw.len() {
        return Err(CarriageError("trailing bytes after JSON string value".into()));
    }
    Ok(s)
}

// ---------------------------------------------------------------------------
// Decode-side parsed object
// ---------------------------------------------------------------------------

/// The minimal set of fields this carriage class needs from a parsed JSON-RPC
/// 2.0 object (§4/§5/§6/§7).
#[derive(Debug, Clone)]
pub struct JsonRpcParsed {
    pub raw: Vec<u8>,
    /// `Some(method)` iff the object carries a `method` member (present on
    /// Request/Notification); `None` distinguishes "absent" from "present and
    /// empty string".
    pub method: Option<String>,
    /// The exact raw JSON token of the `id` member (quotes included for a
    /// string id), or `None` when the member is absent.
    pub id_raw: Option<Vec<u8>>,
    pub has_result: bool,
    pub has_error: bool,
}

/// Parses `raw` as a JSON-RPC 2.0 Object (§3: "MUST contain a jsonrpc member
/// equal to the string 2.0") and classifies which members are present. Never
/// discards `raw`; `JsonRpcParsed::raw` is always the exact input.
pub fn parse_jsonrpc_object(raw: &[u8]) -> Result<JsonRpcParsed, CarriageError> {
    let fields = parse_top_object(raw)?;
    let get = |k: &str| fields.iter().find(|(fk, _)| fk == k).map(|(_, v)| v.clone());

    let ver_raw = get("jsonrpc")
        .ok_or_else(|| CarriageError("missing REQUIRED jsonrpc member".into()))?;
    let ver = parse_json_string_value(&ver_raw)
        .map_err(|_| CarriageError("jsonrpc member is not the string \"2.0\"".into()))?;
    if ver != "2.0" {
        return Err(CarriageError(
            "jsonrpc member is not the string \"2.0\"".into(),
        ));
    }

    let id_raw = get("id");

    let mut method = None;
    if let Some(method_raw) = get("method") {
        method = Some(
            parse_json_string_value(&method_raw)
                .map_err(|_| CarriageError("method member is not a string".into()))?,
        );
    }

    let has_result = fields.iter().any(|(k, _)| k == "result");
    let has_error = fields.iter().any(|(k, _)| k == "error");

    Ok(JsonRpcParsed {
        raw: raw.to_vec(),
        method,
        id_raw,
        has_result,
        has_error,
    })
}

/// Derives the §8.2 correlation_id from a Request's `id` member: the UTF-8
/// octets of that id's exact JSON token (quotes included for a string id),
/// EXCEPT for a Null id (§8.4), where a fresh random 16-octet id is required
/// because the literal token `null` does not guarantee uniqueness across
/// concurrent Null-id Requests.
pub fn jsonrpc_correlation_id(id: Option<&[u8]>) -> Result<Vec<u8>, CarriageError> {
    let id = match id {
        Some(b) => b,
        None => {
            return Err(CarriageError(
                "id token is 0 octets (0 or >255 cannot form a correlation_id)".into(),
            ))
        }
    };
    if id.trim_ascii() == b"null" {
        #[cfg(feature = "session")]
        {
            let mut buf = vec![0u8; 16];
            getrandom::getrandom(&mut buf).expect("OS CSPRNG");
            return Ok(buf);
        }
        #[cfg(not(feature = "session"))]
        {
            return Err(CarriageError(
                "a Null id requires a fresh random correlation_id, which needs OS randomness \
                 (the `session` feature) -- unavailable in a --no-default-features build"
                    .into(),
            ));
        }
    }
    if id.is_empty() || id.len() > 255 {
        return Err(CarriageError(format!(
            "id token is {} octets (0 or >255 cannot form a correlation_id)",
            id.len()
        )));
    }
    Ok(id.to_vec())
}

/// Builds a JSON-RPC 2.0 Request object carrying an id (§4) as the exact
/// octets this crate (the originating peer) produces, and returns the derived
/// correlation_id (§8.2) alongside it. `params`, when `None`, is omitted from
/// the object (JSON-RPC 2.0 permits an absent params member).
pub fn encode_jsonrpc_request(
    method: &str,
    params: Option<JsonValue>,
    id: JsonValue,
) -> Result<(Vec<u8>, Vec<u8>), CarriageError> {
    let mut entries = vec![
        ("jsonrpc".to_string(), JsonValue::String("2.0".to_string())),
        ("method".to_string(), JsonValue::String(method.to_string())),
        ("id".to_string(), id),
    ];
    if let Some(p) = params {
        entries.push(("params".to_string(), p));
    }
    let wire = encode(&JsonValue::Object(entries));
    // Re-parse this crate's own encoded output (mirroring the Go reference's
    // exact flow: encode -> parseJSONRPCObject(wire) -> jsonrpcCorrelationID)
    // rather than deriving the correlation_id straight from the `id` value, so
    // the derivation is provably over the SAME bytes that go on the wire.
    let parsed = parse_jsonrpc_object(&wire)?;
    let corr_id = jsonrpc_correlation_id(parsed.id_raw.as_deref())?;
    Ok((wire, corr_id))
}

/// Builds a JSON-RPC 2.0 Notification object — a Request with no id member
/// (§7).
pub fn encode_jsonrpc_notification(method: &str, params: Option<JsonValue>) -> Vec<u8> {
    let mut entries = vec![
        ("jsonrpc".to_string(), JsonValue::String("2.0".to_string())),
        ("method".to_string(), JsonValue::String(method.to_string())),
    ];
    if let Some(p) = params {
        entries.push(("params".to_string(), p));
    }
    encode(&JsonValue::Object(entries))
}

/// Parses an inbound BRIDGE_REQUEST or BRIDGE_NOTIFY foreign message and
/// applies the §4/§7 structural checks: a Request MUST carry an id member
/// (§4); a Notification MUST NOT (§7).
pub fn decode_jsonrpc_request_or_notification(
    foreign: &[u8],
    want_notify: bool,
) -> Result<JsonRpcParsed, CarriageError> {
    let p = parse_jsonrpc_object(foreign)?;
    if p.method.is_none() {
        return Err(CarriageError(
            "Request/Notification missing REQUIRED method member".into(),
        ));
    }
    let has_id = p.id_raw.is_some();
    if want_notify && has_id {
        return Err(CarriageError(
            "carried an id member under BRIDGE_NOTIFY (§7: a Notification MUST NOT have an id)"
                .into(),
        ));
    }
    if !want_notify && !has_id {
        return Err(CarriageError(
            "Request has no id member (§4: use BRIDGE_NOTIFY for a Notification)".into(),
        ));
    }
    Ok(p)
}

/// Parses an inbound BRIDGE_RESPONSE foreign message and applies the §5
/// structural check: exactly a result member, no error member.
pub fn decode_jsonrpc_success_response(foreign: &[u8]) -> Result<JsonRpcParsed, CarriageError> {
    let p = parse_jsonrpc_object(foreign)?;
    if p.has_error {
        return Err(CarriageError(
            "a Response carrying an error member MUST be carried as BRIDGE_ERROR, not \
             BRIDGE_RESPONSE (§5/§6)"
                .into(),
        ));
    }
    if !p.has_result {
        return Err(CarriageError(
            "success Response missing REQUIRED result member".into(),
        ));
    }
    Ok(p)
}

/// Parses an inbound BRIDGE_ERROR foreign message carrying a foreign JSON-RPC
/// error Response (§6) — NOT an N-PAMP transport error (a distinct wire shape
/// the caller disambiguates via the envelope content_type before reaching this
/// function).
pub fn decode_jsonrpc_error_response(foreign: &[u8]) -> Result<JsonRpcParsed, CarriageError> {
    let p = parse_jsonrpc_object(foreign)?;
    if !p.has_error {
        return Err(CarriageError(
            "BRIDGE_ERROR foreign JSON-RPC object missing REQUIRED error member".into(),
        ));
    }
    Ok(p)
}

/// The §4/§7 agreement check: the BridgeEnvelope `method` field MUST equal the
/// carried object's method member byte-for-byte.
pub fn jsonrpc_method_agrees(envelope_method: &[u8], obj: &JsonRpcParsed) -> bool {
    obj.method.as_deref().map(|m| m.as_bytes()) == Some(envelope_method)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_object_sorts_keys_and_omits_absent_params() {
        let wire = encode(&JsonValue::Object(vec![
            ("z".into(), JsonValue::Number("1".into())),
            ("a".into(), JsonValue::Number("2".into())),
            ("id".into(), JsonValue::Null),
            ("M".into(), JsonValue::Number("3".into())),
        ]));
        // Empirically confirmed against a live Go program this session:
        // map[string]any{"z":1,"a":2,"id":nil,"M":3} marshals to exactly this.
        assert_eq!(wire, br#"{"M":3,"a":2,"id":null,"z":1}"#);
    }

    #[test]
    fn encode_string_matches_go_html_safe_escaping() {
        // Each case here was run against a live Go `encoding/json.Marshal`
        // this session; the expected bytes are copied from that output.
        assert_eq!(encode(&JsonValue::String("hello".into())), br#""hello""#);
        assert_eq!(encode(&JsonValue::String("a\"b".into())), br#""a\"b""#);
        assert_eq!(encode(&JsonValue::String("a\\b".into())), br#""a\\b""#);
        assert_eq!(
            encode(&JsonValue::String("a<b>c&d".into())),
            br#""a\u003cb\u003ec\u0026d""#
        );
        assert_eq!(
            encode(&JsonValue::String("a\nb\tc\rd".into())),
            br#""a\nb\tc\rd""#
        );
        assert_eq!(
            encode(&JsonValue::String("a\u{0}b\u{1}c\u{1f}d".into())),
            br#""a\u0000b\u0001c\u001fd""#
        );
        assert_eq!(encode(&JsonValue::String("a/b".into())), br#""a/b""#);
        assert_eq!(
            encode(&JsonValue::String("a\u{8}b\u{c}c".into())),
            br#""a\bb\fc""#
        );
        // DEL (0x7F) passes through unescaped, matching Go's observed output.
        assert_eq!(
            encode(&JsonValue::String("del\u{7f}".into())),
            "\"del\u{7f}\"".as_bytes()
        );
        assert_eq!(
            encode(&JsonValue::String("sep\u{2028}para\u{2029}end".into())),
            br#""sep\u2028para\u2029end""#
        );
        // Non-ASCII UTF-8 passes through verbatim.
        assert_eq!(
            encode(&JsonValue::String("h\u{e9}llo".into())),
            "\"h\u{e9}llo\"".as_bytes()
        );
    }

    #[test]
    fn parse_top_object_last_key_wins_on_duplicates() {
        let fields = parse_top_object(br#"{"a":1,"a":2}"#).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].0, "a");
        assert_eq!(fields[0].1, b"2");
    }

    #[test]
    fn parse_top_object_rejects_trailing_bytes() {
        let err = parse_top_object(br#"{"a":1} garbage"#).unwrap_err();
        assert!(err.0.contains("trailing bytes"), "{err}");
    }

    #[test]
    fn parse_string_decodes_surrogate_pair() {
        // U+1F600 GRINNING FACE, encoded as a JSON surrogate-pair escape (high
        // surrogate D83D, low surrogate DE00), written with the same
        // double-backslash byte-string form the production `encode_string`
        // match arms use, so no literal non-ASCII glyph appears in this file.
        let out = parse_json_string_value(b"\"\\uD83D\\uDE00\"").unwrap();
        assert_eq!(out, "\u{1F600}");
    }

    // These two tests exercise the Null-id branch of `jsonrpc_correlation_id`,
    // which needs OS randomness (the `session` feature -- see that function's
    // doc comment) and therefore returns `Err` instead of a random id in a
    // `--no-default-features` build. Gated to match, so the wire-only build's
    // test suite stays fully green rather than failing on a feature it never
    // opted into.
    #[cfg(feature = "session")]
    #[test]
    fn roundtrip_request_with_null_id_and_nested_params() {
        let (wire, _corr) = encode_jsonrpc_request(
            "tools/call",
            Some(JsonValue::Object(vec![(
                "name".into(),
                JsonValue::String("search".into()),
            )])),
            JsonValue::Null,
        )
        .unwrap();
        let parsed = decode_jsonrpc_request_or_notification(&wire, false).unwrap();
        assert_eq!(parsed.method.as_deref(), Some("tools/call"));
        assert_eq!(parsed.id_raw.as_deref(), Some(&b"null"[..]));
    }

    #[cfg(feature = "session")]
    #[test]
    fn null_id_gets_a_fresh_random_16_octet_correlation_id() {
        let corr = jsonrpc_correlation_id(Some(b"null")).unwrap();
        assert_eq!(corr.len(), 16);
        let corr2 = jsonrpc_correlation_id(Some(b"null")).unwrap();
        assert_ne!(corr, corr2, "two Null-id correlation ids must not collide");
    }

    /// The `--no-default-features` counterpart to the two tests above: the
    /// Null-id path must fail CLOSED (a named error) rather than silently
    /// return a non-random / fake id when OS randomness is unavailable.
    #[cfg(not(feature = "session"))]
    #[test]
    fn null_id_fails_closed_without_the_session_feature() {
        let err = jsonrpc_correlation_id(Some(b"null")).unwrap_err();
        assert!(err.0.contains("session"), "{err}");
    }

    #[test]
    fn notification_round_trip_rejects_as_request_and_vice_versa() {
        let wire = encode_jsonrpc_notification("ping", None);
        assert!(decode_jsonrpc_request_or_notification(&wire, false).is_err());
        let parsed = decode_jsonrpc_request_or_notification(&wire, true).unwrap();
        assert_eq!(parsed.method.as_deref(), Some("ping"));

        let (req_wire, _) =
            encode_jsonrpc_request("ping", None, JsonValue::String("1".into())).unwrap();
        assert!(decode_jsonrpc_request_or_notification(&req_wire, true).is_err());
    }

    #[test]
    fn success_and_error_response_decode() {
        let ok = decode_jsonrpc_success_response(br#"{"jsonrpc":"2.0","id":"1","result":42}"#)
            .unwrap();
        assert!(ok.has_result);

        let err_resp = decode_jsonrpc_error_response(
            br#"{"jsonrpc":"2.0","id":"1","error":{"code":-1,"message":"x"}}"#,
        )
        .unwrap();
        assert!(err_resp.has_error);

        // A Response carrying BOTH result and error must be rejected as
        // success (§5/§6 agreement check).
        let mixed = decode_jsonrpc_success_response(
            br#"{"jsonrpc":"2.0","id":"1","result":1,"error":{"code":-1,"message":"x"}}"#,
        );
        assert!(mixed.is_err());
    }

    #[test]
    fn missing_jsonrpc_member_is_malformed() {
        let err = parse_jsonrpc_object(br#"{"id":"1","method":"ping"}"#).unwrap_err();
        assert!(err.0.contains("missing REQUIRED jsonrpc"), "{err}");
    }

    #[test]
    fn wrong_jsonrpc_version_is_malformed() {
        let err =
            parse_jsonrpc_object(br#"{"jsonrpc":"1.0","id":"1","method":"ping"}"#).unwrap_err();
        assert!(err.0.contains("jsonrpc member is not"), "{err}");
    }

    #[test]
    fn method_agreement_check() {
        let parsed =
            decode_jsonrpc_request_or_notification(br#"{"jsonrpc":"2.0","id":"1","method":"x"}"#, false)
                .unwrap();
        assert!(jsonrpc_method_agrees(b"x", &parsed));
        assert!(!jsonrpc_method_agrees(b"y", &parsed));
    }
}
