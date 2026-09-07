// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! R14.5/E2.22 — Rust port of the Go reference's shared carriage-object corpus
//! (`impl/go/proxy/carriage_shared_corpus_test.go`): the SAME independently
//! hand-built oracle bytes are reproduced HERE, independent of the encode/decode
//! functions under test (F3 — no oracle value is derived by calling the function
//! under test). Grades `npamp::carriage::{jsonrpc, http, stream}` for
//! wrap-then-unwrap octet-exact carriage round trips: MCP/A2A (JSON-RPC),
//! public-LLM (HTTP), SSE/streaming (STREAM). Every oracle constant/function
//! below is built with primitives INDEPENDENT of the carriage module (Go's
//! `encoding/json` sort-order property for the JSON-RPC case; the already-graded
//! `npamp::bodies::encode` canonical-CBOR primitive for the HTTP case, over a
//! hand-built map literal that bypasses `http::encode_http_carriage_request`'s
//! own object construction; raw `to_be_bytes()` arithmetic for the STREAM case),
//! matching the Go test file's own non-circularity discipline exactly.
//!
//! Scope note (see `npamp::carriage` module docs for the full statement): this
//! grades the CARRIAGE-OBJECT layer only (the exact octets a carriage class
//! produces for its foreign payload). The NPAMP-BRIDGE frame/envelope layer
//! those objects are eventually carried inside does not exist in this crate and
//! is not exercised here, matching the Go reference's own corpus scope.

use npamp::bodies::CborValue;
use npamp::carriage::{http, jsonrpc, stream};

// ---------------------------------------------------------------------------
// Case 1 — MCP/A2A, NPAMP-CC-JSONRPC (spec/companion/20_carriage_jsonrpc.md)
// ---------------------------------------------------------------------------

/// Independently hand-written expected wire bytes for
/// `encode_jsonrpc_request("ping", None, id="1")`: Go's `encoding/json.Marshal`
/// of a `map[string]any` sorts object keys byte-lexicographically (a documented
/// stdlib property, empirically re-confirmed this session against a live Go
/// program rather than trusted from memory) — "id" < "jsonrpc" < "method" — so
/// the expected byte sequence is fully determined independent of running the
/// function under test.
const JSONRPC_ORACLE_REQUEST: &[u8] = br#"{"id":"1","jsonrpc":"2.0","method":"ping"}"#;

#[test]
fn shared_corpus_jsonrpc_wrap_then_unwrap_byte_identical() {
    let (wire, corr_id) =
        jsonrpc::encode_jsonrpc_request("ping", None, jsonrpc::JsonValue::String("1".to_string()))
            .expect("encode");
    assert_eq!(
        wire, JSONRPC_ORACLE_REQUEST,
        "wrap mismatch:\n got  {}\n want {} (independent oracle)",
        String::from_utf8_lossy(&wire),
        String::from_utf8_lossy(JSONRPC_ORACLE_REQUEST)
    );
    assert_eq!(corr_id, br#""1""#, "correlation_id mismatch");

    // Unwrap the ORACLE bytes (not the encoder's own output) through the real
    // decode path — proves decode agrees with an independently-authored wire
    // value, not merely with whatever this module's own encoder happens to
    // produce.
    let obj = jsonrpc::decode_jsonrpc_request_or_notification(JSONRPC_ORACLE_REQUEST, false)
        .expect("unwrap of independent oracle bytes");
    assert_eq!(obj.method.as_deref(), Some("ping"));
    let got_corr_id =
        jsonrpc::jsonrpc_correlation_id(obj.id_raw.as_deref()).expect("jsonrpc_correlation_id");
    assert_eq!(got_corr_id, br#""1""#);
}

// ---------------------------------------------------------------------------
// Case 2 — public-LLM/HTTP, NPAMP-CC-HTTP (spec/companion/21_carriage_http.md)
// ---------------------------------------------------------------------------

#[test]
fn shared_corpus_http_wrap_then_unwrap_byte_identical() {
    // Independent oracle: a hand-built CBOR map literal, bypassing
    // encode_http_carriage_request's own object-construction entirely (only the
    // already-graded, shared npamp::bodies::encode primitive is reused — the
    // same technique the Go test file's own oracle uses over
    // npamp.EncodeCanonicalCBOR).
    let oracle_map = npamp::bodies::map_from_u64_keys(vec![
        (1, CborValue::Uint(http::KIND_REQUEST)),
        (2, CborValue::Text("GET".to_string())),
        (3, CborValue::Text("/v1/ping".to_string())),
    ]);
    let oracle = npamp::bodies::encode(&oracle_map);

    let wire = http::encode_http_carriage_request("GET", "/v1/ping", &[], &[]);
    assert_eq!(
        wire, oracle,
        "wrap mismatch:\n got  {wire:02x?}\n want {oracle:02x?} (independent oracle)"
    );

    let obj = http::decode_http_carriage_object(&oracle, http::KIND_REQUEST)
        .expect("unwrap of independent oracle bytes");
    assert_eq!(obj.method.as_deref(), Some("GET"));
    assert_eq!(obj.target.as_deref(), Some("/v1/ping"));
    assert!(
        obj.headers.is_empty() && obj.body.is_empty(),
        "unwrapped object carries unexpected headers/body: {obj:?}"
    );
}

// ---------------------------------------------------------------------------
// Case 3 — SSE/streaming, NPAMP-CC-STREAM (spec/companion/23_carriage_streaming.md)
// ---------------------------------------------------------------------------

/// Independently constructs the exact §5.2/§5.3 bytes a StreamControl TLV +
/// trailing opaque event must produce: a 4-octet TLV header (Type 0x0011 BE,
/// Length 11 BE) followed by the 11-octet fixed value (version, control, flags,
/// event_id BE u64), followed by the raw event bytes verbatim. Built with
/// `to_be_bytes()` directly — it does not call `encode_stream_control_value` or
/// `encode_tlv`.
fn build_oracle_stream_control_tlv(control: u8, flags: u8, event_id: u64, event: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 11 + event.len());
    out.extend_from_slice(&0x0011u16.to_be_bytes()); // TLVStreamControl
    out.extend_from_slice(&11u16.to_be_bytes()); // fixed value length, §5.2
    let mut val = [0u8; 11];
    val[0] = 0x01; // streamControlVersion
    val[1] = control;
    val[2] = flags;
    val[3..11].copy_from_slice(&event_id.to_be_bytes());
    out.extend_from_slice(&val);
    out.extend_from_slice(event);
    out
}

#[test]
fn shared_corpus_stream_wrap_then_unwrap_byte_identical() {
    let sc = stream::StreamControl {
        control: stream::STREAM_CONTROL_DATA,
        flags: stream::STREAM_FLAG_RESUMABLE,
        event_id: 42,
    };
    let event = b"event-payload";

    let oracle = build_oracle_stream_control_tlv(
        stream::STREAM_CONTROL_DATA,
        stream::STREAM_FLAG_RESUMABLE,
        42,
        event,
    );

    let wire_value = stream::encode_stream_control_value(sc);
    let mut wire = stream::encode_tlv(stream::TLV_STREAM_CONTROL, &wire_value);
    wire.extend_from_slice(event);
    assert_eq!(
        wire, oracle,
        "wrap mismatch:\n got  {wire:02x?}\n want {oracle:02x?} (independent oracle)"
    );

    let (got_sc, remaining) =
        stream::decode_leading_stream_control(&oracle).expect("unwrap of independent oracle bytes");
    assert_eq!(got_sc.control, stream::STREAM_CONTROL_DATA);
    assert_eq!(got_sc.flags, stream::STREAM_FLAG_RESUMABLE);
    assert_eq!(got_sc.event_id, 42);
    assert!(
        got_sc.resumable(),
        "unwrapped control must report resumable() true (flags carried the resumable bit)"
    );
    assert_eq!(
        remaining, event,
        "unwrapped remaining (the opaque event) must be carried verbatim, never re-parsed"
    );
}
