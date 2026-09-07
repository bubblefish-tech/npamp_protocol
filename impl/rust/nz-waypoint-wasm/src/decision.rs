// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! The pure per-request decision this filter makes: carriage
//! classification ([`nz_waypoint_core::classify`]) + N-AALP
//! effect-class/audience authorization
//! ([`nz_waypoint_core::authorize`]/[`nz_waypoint_core::extract::extract_triple`]),
//! decoupled from the proxy-wasm ABI so it is unit-testable on the host
//! target without a live Envoy/wasm runtime (A9). Composes
//! `nz-waypoint-core`'s EXISTING functions — does not reimplement any of
//! them; the only NEW logic in this module is (a) the two-layer denial
//! shape ([`FilterDenied`]: which layer refused) and (b) the
//! `content-type` -> [`nz_waypoint_core::TransportHint`] carriage-hint
//! heuristic ([`transport_hint_from_content_type`]).

use std::collections::HashMap;

use nz_waypoint_core::extract::{extract_triple, TripleExtractError};
use nz_waypoint_core::{authorize, classify, AuthzHook, CarriageClass, TransportHint, WaypointDenied};

/// Why this filter refused a request — named per the specific layer that
/// refused it, mirroring `nz-agent-extauthz`'s `service.rs`'s own
/// two-layer error shape (extraction vs. authorization).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterDenied {
    /// The `(signer_id, audience, effect)` triple could not even be
    /// extracted from the request's headers.
    Extraction(TripleExtractError),
    /// The extracted triple was denied by
    /// [`nz_waypoint_core::authorize`].
    Authorization(WaypointDenied),
}

impl std::fmt::Display for FilterDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FilterDenied::Extraction(e) => write!(f, "nz-waypoint-wasm: {e}"),
            FilterDenied::Authorization(e) => write!(f, "nz-waypoint-wasm: {e}"),
        }
    }
}

impl std::error::Error for FilterDenied {}

/// Maps a request's `content-type` header to the R10 [`TransportHint`] this
/// carriage-negotiation heuristic assumes: a JSON-RPC-shaped body
/// (`application/json-rpc`, or the `application/vnd.npamp.jsonrpc+json`
/// media type) is [`TransportHint::StreamableHttpJsonRpc`] (MCP/A2A over
/// HTTP); everything else defaults to plain [`TransportHint::Http11`].
/// Total (never panics, never constructs an "unrecognized" case) — an
/// absent or unrecognized content-type is simply `Http11`, the
/// least-specific carriage, matching [`classify`]'s own closed-match
/// philosophy one layer up (every `TransportHint` maps to exactly one
/// `CarriageClass`, and every input to this function maps to exactly one
/// `TransportHint`).
pub fn transport_hint_from_content_type(content_type: Option<&str>) -> TransportHint {
    match content_type {
        Some(ct) if ct.eq_ignore_ascii_case("application/json-rpc") || ct.eq_ignore_ascii_case("application/vnd.npamp.jsonrpc+json") => TransportHint::StreamableHttpJsonRpc,
        _ => TransportHint::Http11,
    }
}

/// The one decision this filter makes per request: extract the
/// `(signer_id, audience, effect)` triple from `headers`
/// ([`extract_triple`]), authorize it against `hook`
/// ([`authorize`]), and — only on success — classify the request's
/// carriage class from `content_type` ([`classify`]). Denial short-circuits
/// at whichever layer refused first; carriage classification never runs for
/// a request that will be denied anyway (classifying a rejected request's
/// carriage class would be dead work, not a security issue, but there is
/// no reason to do it).
pub fn evaluate_request<H: AuthzHook>(hook: &H, headers: &HashMap<String, String>, content_type: Option<&str>) -> Result<CarriageClass, FilterDenied> {
    let (signer_id, audience, effect) = extract_triple(headers).map_err(FilterDenied::Extraction)?;
    authorize(hook, &signer_id, &audience, effect).map_err(FilterDenied::Authorization)?;
    Ok(classify(transport_hint_from_content_type(content_type)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nz_waypoint_core::extract::{TripleExtractError, AUDIENCE_HEADER, EFFECT_HEADER, SIGNER_HEADER};
    use nz_waypoint_core::{CarriageClass, EffectClass, TableAuthzHook, TransportHint};
    use std::collections::HashMap;

    fn headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn content_type_json_rpc_maps_to_streamable_http_json_rpc() {
        assert_eq!(transport_hint_from_content_type(Some("application/json-rpc")), TransportHint::StreamableHttpJsonRpc);
        assert_eq!(transport_hint_from_content_type(Some("APPLICATION/JSON-RPC")), TransportHint::StreamableHttpJsonRpc);
        assert_eq!(transport_hint_from_content_type(Some("application/vnd.npamp.jsonrpc+json")), TransportHint::StreamableHttpJsonRpc);
    }

    /// An absent or unrecognized content-type defaults to plain HTTP/1.1 —
    /// total, never panics, never an "unrecognized" variant to construct
    /// (matches `classify`'s own closed-match philosophy one layer up).
    /// Mutated away by M-decision-1 in RED-EVIDENCE.md.
    #[test]
    fn missing_or_unrecognized_content_type_defaults_to_http11() {
        assert_eq!(transport_hint_from_content_type(None), TransportHint::Http11);
        assert_eq!(transport_hint_from_content_type(Some("text/plain")), TransportHint::Http11);
    }

    #[test]
    fn a_well_formed_authorized_request_resolves_its_carriage_class() {
        let hook = TableAuthzHook::new("gateway-a", &[("signer-1", EffectClass::NonIdempotentWrite)]);
        let h = headers(&[(SIGNER_HEADER, "signer-1"), (AUDIENCE_HEADER, "gateway-a"), (EFFECT_HEADER, "1")]);
        let carriage = evaluate_request(&hook, &h, Some("application/json-rpc")).expect("authorized request must resolve a carriage class");
        assert_eq!(carriage, CarriageClass::JsonRpc);
    }

    #[test]
    fn a_missing_header_denies_at_the_extraction_layer() {
        let hook = TableAuthzHook::new("gateway-a", &[("signer-1", EffectClass::NonIdempotentWrite)]);
        let h = headers(&[(AUDIENCE_HEADER, "gateway-a"), (EFFECT_HEADER, "1")]);
        let err = evaluate_request(&hook, &h, None).expect_err("missing signer header must deny");
        assert_eq!(err, FilterDenied::Extraction(TripleExtractError::MissingHeader(SIGNER_HEADER)));
    }

    #[test]
    fn an_effect_above_grant_denies_at_the_authorization_layer() {
        let hook = TableAuthzHook::new("gateway-a", &[("signer-1", EffectClass::ReadOnly)]);
        let h = headers(&[(SIGNER_HEADER, "signer-1"), (AUDIENCE_HEADER, "gateway-a"), (EFFECT_HEADER, "3")]);
        let err = evaluate_request(&hook, &h, None).expect_err("above-grant effect must deny");
        assert!(matches!(err, FilterDenied::Authorization(_)));
    }
}
