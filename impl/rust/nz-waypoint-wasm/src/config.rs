// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! Plugin-configuration parsing: turns the raw JSON bytes Envoy hands
//! `RootContext::on_configure` into a `(consuming_authority, grants)` pair
//! this filter's shared `nz_waypoint_core::TableAuthzHook` is built from.
//! Pure — no proxy-wasm ABI calls — so it is unit-testable on the host
//! target without a live wasm runtime (A9).

use nz_waypoint_core::EffectClass;

/// Parses the plugin configuration JSON, e.g.
/// `{"consuming_authority": "gateway-a", "grants": {"signer-1": 2}}`.
/// Malformed/absent JSON, a missing `consuming_authority`, or a
/// non-object `grants` field is NOT a panic and NOT a crash — it fails
/// CLOSED to an EMPTY configuration (`consuming_authority == ""`, no
/// grants), which [`nz_waypoint_core::authorize`] then denies EVERY object
/// against (`WrongAudience`, since no real object claims `audience == ""`).
/// A grant value that does not fit `u8` is SKIPPED — that one signer gets
/// no grant at all (denied above `ReadOnly` by `authorize`'s own
/// unrecognized-signer default), never rounded/truncated into a different,
/// unintended grant.
pub fn parse_config(bytes: &[u8]) -> (String, Vec<(String, EffectClass)>) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return (String::new(), Vec::new());
    };
    let consuming_authority = v.get("consuming_authority").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let mut grants = Vec::new();
    if let Some(obj) = v.get("grants").and_then(|x| x.as_object()) {
        for (signer_id, val) in obj {
            if let Some(n) = val.as_u64() {
                if n <= u8::MAX as u64 {
                    grants.push((signer_id.clone(), EffectClass::from_wire(n as u8)));
                }
            }
        }
    }
    (consuming_authority, grants)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nz_waypoint_core::EffectClass;

    #[test]
    fn parses_a_well_formed_config() {
        let json = br#"{"consuming_authority":"gateway-a","grants":{"signer-1":2}}"#;
        let (authority, grants) = parse_config(json);
        assert_eq!(authority, "gateway-a");
        assert_eq!(grants, vec![("signer-1".to_string(), EffectClass::NonIdempotentWrite)]);
    }

    #[test]
    fn malformed_json_fails_closed_to_an_empty_configuration() {
        let (authority, grants) = parse_config(b"not json at all");
        assert_eq!(authority, "");
        assert!(grants.is_empty());
    }

    #[test]
    fn empty_bytes_fails_closed_to_an_empty_configuration() {
        let (authority, grants) = parse_config(b"");
        assert_eq!(authority, "");
        assert!(grants.is_empty());
    }

    #[test]
    fn missing_consuming_authority_defaults_to_empty_string_not_a_panic() {
        let json = br#"{"grants":{"signer-1":0}}"#;
        let (authority, _grants) = parse_config(json);
        assert_eq!(authority, "");
    }

    /// A grant value that does not fit a `u8` (the wire encoding
    /// `EffectClass::from_wire` decodes) is SKIPPED — that signer gets no
    /// grant at all (denied above ReadOnly by `authorize`'s own
    /// unrecognized-signer default), never rounded/truncated into a
    /// different, unintended grant. Mutated away by M-config-1 in
    /// RED-EVIDENCE.md.
    #[test]
    fn an_out_of_range_grant_value_is_skipped_not_truncated() {
        let json = br#"{"consuming_authority":"gateway-a","grants":{"signer-1":9999,"signer-2":1}}"#;
        let (_authority, grants) = parse_config(json);
        assert_eq!(grants, vec![("signer-2".to_string(), EffectClass::IdempotentWrite)]);
    }

    #[test]
    fn a_grant_value_above_three_still_decodes_via_from_wire_fail_closed_rule() {
        // 250 does not truncate to a variant integer -- it is a valid u8
        // that from_wire maps to Destructive, exactly like every other
        // unrecognized-but-in-range effect octet in this codebase.
        let json = br#"{"consuming_authority":"gateway-a","grants":{"signer-1":250}}"#;
        let (_authority, grants) = parse_config(json);
        assert_eq!(grants, vec![("signer-1".to_string(), EffectClass::Destructive)]);
    }
}
