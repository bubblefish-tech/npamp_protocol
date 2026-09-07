// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! NPAMP-CC-HTTP (spec/companion/21_carriage_http.md) carriage codec — the
//! public-LLM/HTTP carriage class. An HTTP-Carriage Object is a deterministic
//! (canonical) CBOR map (§4.1), encoded/decoded with the shared
//! `crate::bodies` canonical-CBOR primitives.
//!
//! Only the two non-streaming kinds (request kind=1, response kind=2) are
//! implemented, matching the Go reference's own documented scope
//! (`impl/go/proxy/carriage_http.go`: "streaming kinds 3/4 -- NOT YET BUILT").
//! Only the §4.2 object keys the Go reference carries (1,2,3,6,8,9) are
//! represented — authority (4), scheme (5), reason (7), trailers (10), and
//! passthrough (11) are likewise not yet built and never emitted or expected.
//!
//! See the `crate::carriage` module docs for the header-list scope note: this
//! crate has no `http.Header`-equivalent type, so [`HeaderKv`] is an
//! already-ordered list the caller supplies directly (encoding lower-cases
//! each name per §4.4 but does not re-sort by name the way the Go reference's
//! `http.Header` adapter does).

use crate::bodies::{self, CborValue};
use crate::carriage::CarriageError;

/// The NPAMP-CC-HTTP §4.2 key-1 `kind` discriminant.
pub const KIND_REQUEST: u64 = 1;
pub const KIND_RESPONSE: u64 = 2;
// KIND_STREAM_DATA = 3, KIND_STREAM_END = 4 -- NOT YET BUILT, matching the Go
// reference.

/// One §4.4 field entry: [name (text), value (bstr)]. Order is significant and
/// MUST be preserved (§4.4: "carriage class MUST preserve that order and MUST
/// NOT combine, split, or reorder fields").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderKv {
    pub name: String,
    pub value: Vec<u8>,
}

/// The decoded form of NPAMP-CC-HTTP §4's HTTP-Carriage Object.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HttpCarriageObject {
    pub kind: u64,
    pub method: Option<String>,
    pub target: Option<String>,
    pub status: Option<u32>,
    pub headers: Vec<HeaderKv>,
    pub body: Vec<u8>,
}

/// Reports whether `name` (already lower-cased) is one of the HTTP/2
/// pseudo-headers §4.4 forbids inside the headers/trailers array (their
/// information is carried in the typed object keys instead).
fn is_pseudo_header(name: &str) -> bool {
    matches!(name, ":method" | ":scheme" | ":authority" | ":path" | ":status")
}

/// Lower-cases the ASCII letters of `s`, leaving all other bytes (including
/// non-ASCII UTF-8) untouched — §4.4: "a sender MUST lowercase ASCII field
/// names before carriage."
fn to_lower_ascii(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_uppercase() { c.to_ascii_lowercase() } else { c })
        .collect()
}

/// Converts a header list into the §4.4 CBOR shape: an array of 2-element
/// `[name (text), value (bstr)]` arrays, in the given order, with each name
/// lower-cased.
fn headers_to_cbor(headers: &[HeaderKv]) -> CborValue {
    let arr = headers
        .iter()
        .map(|kv| {
            CborValue::Array(vec![
                CborValue::Text(to_lower_ascii(&kv.name)),
                CborValue::Bytes(kv.value.clone()),
            ])
        })
        .collect();
    CborValue::Array(arr)
}

/// Builds the §4 HTTP-Carriage Object for a request (kind=1) as a
/// deterministic-CBOR map (§4.1) via the shared canonical-CBOR primitive.
pub fn encode_http_carriage_request(
    method: &str,
    target: &str,
    headers: &[HeaderKv],
    body: &[u8],
) -> Vec<u8> {
    let mut entries: Vec<(u64, CborValue)> = vec![
        (1, CborValue::Uint(KIND_REQUEST)),
        (2, CborValue::Text(method.to_string())),
        (3, CborValue::Text(target.to_string())),
    ];
    if !headers.is_empty() {
        entries.push((8, headers_to_cbor(headers)));
    }
    if !body.is_empty() {
        entries.push((9, CborValue::Bytes(body.to_vec())));
    }
    bodies::encode(&bodies::map_from_u64_keys(entries))
}

/// Builds the §4 HTTP-Carriage Object for a response (kind=2).
pub fn encode_http_carriage_response(status: u32, headers: &[HeaderKv], body: &[u8]) -> Vec<u8> {
    let mut entries: Vec<(u64, CborValue)> = vec![
        (1, CborValue::Uint(KIND_RESPONSE)),
        (6, CborValue::Uint(status as u64)),
    ];
    if !headers.is_empty() {
        entries.push((8, headers_to_cbor(headers)));
    }
    if !body.is_empty() {
        entries.push((9, CborValue::Bytes(body.to_vec())));
    }
    bodies::encode(&bodies::map_from_u64_keys(entries))
}

fn decode_header_list(raw: &CborValue) -> Result<Vec<HeaderKv>, CarriageError> {
    let arr = match raw {
        CborValue::Array(a) => a,
        _ => return Err(CarriageError("key 8 (headers) is not an array".into())),
    };
    let mut out = Vec::with_capacity(arr.len());
    for entry in arr {
        let pair = match entry {
            CborValue::Array(a) if a.len() == 2 => a,
            _ => {
                return Err(CarriageError(
                    "a headers entry is not a 2-element [name, value] array".into(),
                ))
            }
        };
        let name = match &pair[0] {
            CborValue::Text(s) => s.clone(),
            _ => return Err(CarriageError("a headers entry's name is not a text string".into())),
        };
        let value = match &pair[1] {
            CborValue::Bytes(b) => b.clone(),
            _ => {
                return Err(CarriageError(
                    "a headers entry's value is not a byte string".into(),
                ))
            }
        };
        out.push(HeaderKv { name, value });
    }
    Ok(out)
}

/// Parses `foreign` (the Bridge frame's Foreign payload) as a §4 HTTP-Carriage
/// Object and applies the §4.7 agreement checks this module owns (they are
/// HTTP-carriage-specific, not part of a generic Bridge decoder). `want_kind`
/// is the kind the caller's frame type/message_kind implies (§2.2); a mismatch
/// is agreement-check failure 1.
pub fn decode_http_carriage_object(
    foreign: &[u8],
    want_kind: u64,
) -> Result<HttpCarriageObject, CarriageError> {
    let v = bodies::decode_top(foreign)
        .map_err(|e| CarriageError(format!("not valid deterministic CBOR: {e}")))?;
    let m = match v {
        CborValue::Map(m) => m,
        _ => return Err(CarriageError("top-level item is not a map".into())),
    };

    let kind = match m.get(1) {
        None => return Err(CarriageError("missing REQUIRED key 1 (kind)".into())),
        Some(CborValue::Uint(u)) => *u,
        Some(_) => return Err(CarriageError("key 1 (kind) is not an unsigned integer".into())),
    };
    // §4.7 check 1: kind MUST correspond to the frame type/message_kind the
    // caller already determined.
    if kind != want_kind {
        return Err(CarriageError(format!(
            "object kind {kind} disagrees with frame type (want {want_kind})"
        )));
    }

    let mut obj = HttpCarriageObject {
        kind,
        ..Default::default()
    };

    match kind {
        KIND_REQUEST => {
            let method = match m.get(2) {
                Some(CborValue::Text(s)) if !s.is_empty() => s.clone(),
                _ => return Err(CarriageError("request missing REQUIRED key 2 (method)".into())),
            };
            let target = match m.get(3) {
                Some(CborValue::Text(s)) if !s.is_empty() => s.clone(),
                _ => return Err(CarriageError("request missing REQUIRED key 3 (target)".into())),
            };
            if m.get(6).is_some() {
                return Err(CarriageError("request MUST NOT carry key 6 (status)".into()));
            }
            obj.method = Some(method);
            obj.target = Some(target);
        }
        KIND_RESPONSE => {
            let status = match m.get(6) {
                None => return Err(CarriageError("response missing REQUIRED key 6 (status)".into())),
                Some(CborValue::Uint(u)) if (100..=599).contains(u) => *u as u32,
                _ => {
                    return Err(CarriageError(
                        "key 6 (status) is not a valid HTTP status code".into(),
                    ))
                }
            };
            if m.get(2).is_some() {
                return Err(CarriageError("response MUST NOT carry key 2 (method)".into()));
            }
            if m.get(3).is_some() {
                return Err(CarriageError("response MUST NOT carry key 3 (target)".into()));
            }
            obj.status = Some(status);
        }
        _ => {
            return Err(CarriageError(format!(
                "unsupported object kind {kind} (streaming kinds 3/4 not yet built)"
            )))
        }
    }

    if let Some(hdrs_raw) = m.get(8) {
        let hdrs = decode_header_list(hdrs_raw)?;
        for kv in &hdrs {
            if is_pseudo_header(&kv.name) {
                // §4.4: a receiver that finds a pseudo-header in
                // headers/trailers MUST reject the frame (agreement-check
                // family, §4.7 item 4).
                return Err(CarriageError(format!(
                    "pseudo-header {:?} present in headers array",
                    kv.name
                )));
            }
        }
        obj.headers = hdrs;
    }
    if let Some(body_raw) = m.get(9) {
        match body_raw {
            CborValue::Bytes(b) => obj.body = b.clone(),
            _ => return Err(CarriageError("key 9 (body) is not a byte string".into())),
        }
    }

    Ok(obj)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_lower_ascii_only_touches_ascii_letters() {
        assert_eq!(to_lower_ascii("Content-Type"), "content-type");
        assert_eq!(to_lower_ascii("X-Ä"), "x-Ä");
    }

    #[test]
    fn is_pseudo_header_matches_http2_pseudo_headers_only() {
        assert!(is_pseudo_header(":method"));
        assert!(is_pseudo_header(":status"));
        assert!(!is_pseudo_header("content-type"));
        assert!(!is_pseudo_header(":unknown"));
    }

    #[test]
    fn request_round_trip_with_headers_and_body() {
        let headers = vec![
            HeaderKv { name: "Content-Type".into(), value: b"application/json".to_vec() },
            HeaderKv { name: "accept".into(), value: b"*/*".to_vec() },
        ];
        let body = b"{\"q\":1}".to_vec();
        let wire = encode_http_carriage_request("POST", "/v1/chat", &headers, &body);
        let obj = decode_http_carriage_object(&wire, KIND_REQUEST).unwrap();
        assert_eq!(obj.method.as_deref(), Some("POST"));
        assert_eq!(obj.target.as_deref(), Some("/v1/chat"));
        assert_eq!(obj.body, body);
        assert_eq!(
            obj.headers,
            vec![
                HeaderKv { name: "content-type".into(), value: b"application/json".to_vec() },
                HeaderKv { name: "accept".into(), value: b"*/*".to_vec() },
            ]
        );
    }

    #[test]
    fn response_round_trip() {
        let wire = encode_http_carriage_response(200, &[], b"ok");
        let obj = decode_http_carriage_object(&wire, KIND_RESPONSE).unwrap();
        assert_eq!(obj.status, Some(200));
        assert_eq!(obj.body, b"ok");
        assert!(obj.method.is_none());
        assert!(obj.target.is_none());
    }

    #[test]
    fn decode_rejects_kind_mismatch() {
        let wire = encode_http_carriage_request("GET", "/", &[], &[]);
        let err = decode_http_carriage_object(&wire, KIND_RESPONSE).unwrap_err();
        assert!(err.0.contains("disagrees with frame type"), "{err}");
    }

    #[test]
    fn decode_rejects_pseudo_header() {
        let headers = vec![HeaderKv { name: ":path".into(), value: b"/x".to_vec() }];
        let wire = encode_http_carriage_request("GET", "/", &headers, &[]);
        let err = decode_http_carriage_object(&wire, KIND_REQUEST).unwrap_err();
        assert!(err.0.contains("pseudo-header"), "{err}");
    }

    #[test]
    fn decode_rejects_invalid_status_code() {
        let bad = bodies::encode(&bodies::map_from_u64_keys(vec![
            (1, CborValue::Uint(KIND_RESPONSE)),
            (6, CborValue::Uint(999)),
        ]));
        let err = decode_http_carriage_object(&bad, KIND_RESPONSE).unwrap_err();
        assert!(err.0.contains("not a valid HTTP status code"), "{err}");
    }

    #[test]
    fn decode_rejects_response_carrying_method() {
        let bad = bodies::encode(&bodies::map_from_u64_keys(vec![
            (1, CborValue::Uint(KIND_RESPONSE)),
            (2, CborValue::Text("GET".into())),
            (6, CborValue::Uint(200)),
        ]));
        let err = decode_http_carriage_object(&bad, KIND_RESPONSE).unwrap_err();
        assert!(err.0.contains("MUST NOT carry key 2"), "{err}");
    }

    #[test]
    fn decode_rejects_missing_kind() {
        let bad = bodies::encode(&bodies::map_from_u64_keys(vec![(2, CborValue::Text("GET".into()))]));
        let err = decode_http_carriage_object(&bad, KIND_REQUEST).unwrap_err();
        assert!(err.0.contains("missing REQUIRED key 1"), "{err}");
    }

    #[test]
    fn decode_rejects_non_map_top_level() {
        let bad = bodies::encode(&CborValue::Text("not a map".into()));
        let err = decode_http_carriage_object(&bad, KIND_REQUEST).unwrap_err();
        assert!(err.0.contains("not a map"), "{err}");
    }
}
