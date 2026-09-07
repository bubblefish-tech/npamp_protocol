// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! Extracts the N-PAMP authorization triple `(signer_id, audience,
//! object_effect)` from an inbound request's HTTP-shaped header map.
//! Relocated 2026-09-05 from `nz-agent-extauthz/src/extract.rs` (its
//! original R14-Unit-A ext_authz-gRPC home) so this SAME fail-closed
//! extraction rule is shared by every hosting shape that reads this header
//! triple off a request — the ext_authz gRPC service
//! (`nz-agent-extauthz`, which now re-exports this module) AND the Envoy
//! proxy-wasm filter (`nz-waypoint-wasm`) — instead of each inventing its
//! own, independently-driftable parsing convention for the same three
//! headers.
//!
//! # The documented mapping (R14-Unit-A design decision, carried over
//! unchanged)
//!
//! | Header | Meaning | Wire form |
//! |---|---|---|
//! | `npamp-signer-id` | The signer identity to check ([`authorize`](crate::authorize)'s `signer_id`) | opaque UTF-8 string |
//! | `npamp-audience` | The consuming authority the object claims (`audience`) | opaque UTF-8 string |
//! | `npamp-effect` | The object's declared effect class, wire-encoded | ASCII decimal `u8` (`"0"`-`"255"`), decoded via [`crate::EffectClass::from_wire`] |
//!
//! This is the same shape N-AALP's own protected-header carries on the
//! wire (an octet decoded via the identical fail-closed `from_wire` rule)
//! — chosen specifically because it is testable with plain HTTP headers and
//! does not trust any OTHER transport metadata (source IP, TLS SNI,
//! `x-forwarded-*`, etc.) as identity, per the fail-closed-authorization
//! discipline this crate documents.
//!
//! **This is a documented ASSUMPTION about how the gateway/proxy is
//! configured to populate these three headers** (a real deployment must be
//! configured to set them from an already-authenticated upstream identity —
//! e.g. from a verified N-AALP-signed envelope or an mTLS/JWT claim the
//! gateway itself terminates — never take them unauthenticated from the
//! ORIGINAL caller, or this becomes a trivial spoof). This module's OWN job
//! is narrower and total: given whatever the host put in these three
//! headers, extraction is FAIL-CLOSED — a missing header or an effect value
//! that does not even parse as a `u8` is a hard extraction failure, never a
//! default/guess.

use std::collections::HashMap;

use crate::EffectClass;

pub const SIGNER_HEADER: &str = "npamp-signer-id";
pub const AUDIENCE_HEADER: &str = "npamp-audience";
pub const EFFECT_HEADER: &str = "npamp-effect";

/// An agent JWT's `sub` claim, forwarded by the gateway/proxy (once its OWN
/// JWT-authentication filter has verified the token) as this header. This is
/// FOREIGN-IDENTITY LINKAGE ONLY — a cross-protocol correlation value a
/// caller might log or audit — and MUST NEVER be treated as, or substituted
/// for, [`SIGNER_HEADER`] in an authorization decision. [`extract_triple`]
/// does not read this header at all; its presence here is documentation of
/// the name a real deployment would use.
pub const JWT_SUB_HEADER: &str = "x-jwt-sub";

/// Why triple extraction failed. Every variant means "deny" — there is no
/// variant that means "proceed with a guessed value" (fail-closed by
/// construction: the only way to get a triple out of [`extract_triple`] is
/// the `Ok` path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TripleExtractError {
    /// One of the three required headers was absent from the request.
    MissingHeader(&'static str),
    /// The `npamp-effect` header was present but did not parse as a `u8`
    /// (e.g. empty, non-numeric, or out of `0..=255` range). This is
    /// deliberately NOT routed through [`EffectClass::from_wire`] — that
    /// function only ever sees a value AFTER it is known to be a valid
    /// octet; a header that is not even a valid octet is a malformed
    /// request, not an "unrecognized effect value" (which
    /// `EffectClass::from_wire` already handles by mapping to
    /// [`EffectClass::Destructive`]).
    MalformedEffect(String),
}

impl std::fmt::Display for TripleExtractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TripleExtractError::MissingHeader(name) => {
                write!(f, "nz-waypoint-core/extract: missing required header {name:?}")
            }
            TripleExtractError::MalformedEffect(raw) => {
                write!(f, "nz-waypoint-core/extract: header {EFFECT_HEADER:?} is not a valid u8 octet: {raw:?}")
            }
        }
    }
}

impl std::error::Error for TripleExtractError {}

/// Extracts `(signer_id, audience, object_effect)` from a header map,
/// fail-closed: any of the three headers missing, or the effect header not
/// parsing as `u8`, is an `Err` — never a default/guessed triple. An
/// out-of-range-but-parseable effect octet (e.g. `"4"`..`"255"`) is NOT an
/// extraction error; it decodes via [`EffectClass::from_wire`], which maps
/// every unrecognized value to [`EffectClass::Destructive`] (fail-closed at
/// the AUTHORIZATION layer, not the extraction layer — the two fail-closed
/// rules compose rather than duplicate).
pub fn extract_triple(headers: &HashMap<String, String>) -> Result<(String, String, EffectClass), TripleExtractError> {
    let signer_id = headers.get(SIGNER_HEADER).ok_or(TripleExtractError::MissingHeader(SIGNER_HEADER))?.clone();
    let audience = headers.get(AUDIENCE_HEADER).ok_or(TripleExtractError::MissingHeader(AUDIENCE_HEADER))?.clone();
    let effect_raw = headers.get(EFFECT_HEADER).ok_or(TripleExtractError::MissingHeader(EFFECT_HEADER))?;
    let effect_octet: u8 = effect_raw.trim().parse().map_err(|_| TripleExtractError::MalformedEffect(effect_raw.clone()))?;
    let object_effect = EffectClass::from_wire(effect_octet);
    Ok((signer_id, audience, object_effect))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn extracts_a_well_formed_triple() {
        let h = headers(&[(SIGNER_HEADER, "signer-1"), (AUDIENCE_HEADER, "gateway-a"), (EFFECT_HEADER, "1")]);
        let (signer, audience, effect) = extract_triple(&h).expect("well-formed triple must extract");
        assert_eq!(signer, "signer-1");
        assert_eq!(audience, "gateway-a");
        assert_eq!(effect, EffectClass::IdempotentWrite);
    }

    /// Mutated away by M-waypoint-core-2 in RED-EVIDENCE.md.
    #[test]
    fn missing_signer_header_is_denied_not_defaulted() {
        let h = headers(&[(AUDIENCE_HEADER, "gateway-a"), (EFFECT_HEADER, "0")]);
        let err = extract_triple(&h).expect_err("missing signer header must fail extraction");
        assert_eq!(err, TripleExtractError::MissingHeader(SIGNER_HEADER));
    }

    #[test]
    fn missing_audience_header_is_denied_not_defaulted() {
        let h = headers(&[(SIGNER_HEADER, "signer-1"), (EFFECT_HEADER, "0")]);
        let err = extract_triple(&h).expect_err("missing audience header must fail extraction");
        assert_eq!(err, TripleExtractError::MissingHeader(AUDIENCE_HEADER));
    }

    #[test]
    fn missing_effect_header_is_denied_not_defaulted() {
        let h = headers(&[(SIGNER_HEADER, "signer-1"), (AUDIENCE_HEADER, "gateway-a")]);
        let err = extract_triple(&h).expect_err("missing effect header must fail extraction");
        assert_eq!(err, TripleExtractError::MissingHeader(EFFECT_HEADER));
    }

    #[test]
    fn non_numeric_effect_header_is_malformed_not_defaulted() {
        let h = headers(&[(SIGNER_HEADER, "signer-1"), (AUDIENCE_HEADER, "gateway-a"), (EFFECT_HEADER, "not-a-number")]);
        let err = extract_triple(&h).expect_err("non-numeric effect header must fail extraction");
        assert_eq!(err, TripleExtractError::MalformedEffect("not-a-number".to_string()));
    }

    #[test]
    fn empty_effect_header_is_malformed_not_defaulted() {
        let h = headers(&[(SIGNER_HEADER, "signer-1"), (AUDIENCE_HEADER, "gateway-a"), (EFFECT_HEADER, "")]);
        let err = extract_triple(&h).expect_err("empty effect header must fail extraction");
        assert_eq!(err, TripleExtractError::MalformedEffect(String::new()));
    }

    #[test]
    fn out_of_range_but_parseable_effect_decodes_to_destructive() {
        // 4..=255 is not extraction-malformed (it IS a valid u8) — it is an
        // AUTHORIZATION-layer "unrecognized effect", which EffectClass::
        // from_wire maps to Destructive per N-AALP's fail-closed rule.
        let h = headers(&[(SIGNER_HEADER, "signer-1"), (AUDIENCE_HEADER, "gateway-a"), (EFFECT_HEADER, "250")]);
        let (_, _, effect) = extract_triple(&h).expect("in-range u8 must extract even if semantically unrecognized");
        assert_eq!(effect, EffectClass::Destructive);
    }

    #[test]
    fn value_256_is_malformed_because_it_does_not_fit_a_u8() {
        let h = headers(&[(SIGNER_HEADER, "signer-1"), (AUDIENCE_HEADER, "gateway-a"), (EFFECT_HEADER, "256")]);
        let err = extract_triple(&h).expect_err("256 does not fit u8, must fail extraction");
        assert_eq!(err, TripleExtractError::MalformedEffect("256".to_string()));
    }
}
