// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! The minimal, hand-typed subset of the Gateway-API v1 `HTTPRoute` schema
//! this crate's [`crate::plan`] module consumes. NOT the full HTTPRoute
//! schema (no `matches`, `filters`, `timeouts`, `hostnames`, ...) -- only
//! `parentRefs` and `rules[].backendRefs`, the two fields the authorization
//! mapping needs.
//!
//! Field shapes verified against the primary source, fetched 2026-09-05:
//! <https://gateway-api.sigs.k8s.io/docs/mesh/mesh-overview/> (a GAMMA
//! mesh-attached `HTTPRoute`'s `spec.parentRefs[]` entry: `name`, optional
//! `namespace`, `kind: Service`, `group`) and
//! <https://gateway-api.sigs.k8s.io/api-types/httproute/> (`spec.rules[].
//! backendRefs[]`: `name`, optional `namespace`, `kind`, `group`, `port`,
//! `weight`). This module parses these as plain `serde::Deserialize`
//! structs (typed fields, not raw text -- A11) from the JSON body of a
//! `kube::core::DynamicObject` fetched from a real Kubernetes API.

use serde::Deserialize;

/// `HTTPRoute.spec`, restricted to the two fields [`crate::plan`] reads.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HttpRouteSpec {
    #[serde(rename = "parentRefs", default)]
    pub parent_refs: Vec<ParentRef>,
    #[serde(default)]
    pub rules: Vec<HttpRouteRule>,
}

/// One `spec.parentRefs[]` entry -- the mesh workload (a core `v1/Service`,
/// per the GAMMA convention) this route governs.
///
/// Kubernetes API defaulting fills in an OMITTED `kind`/`group` at
/// admission/write time as `kind: Gateway`, `group: gateway.networking.k8s.io`
/// (the ParentReference "referent" default, paired -- NOT independently
/// defaulted to a core-group Service). A `HttpRouteSpec` parsed directly
/// from a real API-server response therefore has BOTH fields populated
/// whenever a real GAMMA mesh route is meant, matching the two fetched
/// examples above (each shows `kind: Service` alongside an explicit
/// `group` value, never `kind: Service` with `group` omitted). This crate
/// requires both fields EXPLICITLY present as the Service/core-group pair
/// (see `plan::is_mesh_service_parent_ref`) rather than assuming any
/// defaulting behavior on a directly-constructed value (e.g. a unit-test
/// fixture, or a value handed in some other way than a live API-server
/// round-trip) -- fail-closed: an ambiguous parentRef is treated as "not a
/// mesh route", never guessed into one.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ParentRef {
    pub name: String,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
}

/// One `spec.rules[]` entry, restricted to `backendRefs` (the only field
/// [`crate::plan`] reads -- `matches`/`filters`/`timeouts` are intentionally
/// not modeled here).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HttpRouteRule {
    #[serde(rename = "backendRefs", default)]
    pub backend_refs: Vec<BackendRef>,
}

/// One `spec.rules[].backendRefs[]` entry -- a Service this route forwards
/// traffic to. Per the Gateway-API BackendRef "referent" default (the
/// overwhelmingly common case: the vast majority of backend references
/// target a core Service), an OMITTED `kind`/`group` here defaults to
/// `kind: Service`, `group: ""` (core) -- the OPPOSITE default pairing from
/// [`ParentRef`], because `ParentRef`'s and `BackendRef`'s "referent"
/// defaults are independently specified fields of the Gateway-API schema,
/// not the same type.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BackendRef {
    pub name: String,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact JSON shape a real `HTTPRoute` mesh example takes,
    /// transcribed from the fetched primary source's YAML (field-for-field,
    /// including the cross-namespace "Consumer Route" variant's `namespace`
    /// on the parentRef) -- a non-circular fixture: these values come from
    /// the cited external document, not from this crate's own code.
    const MESH_ROUTE_JSON: &str = r#"{
        "parentRefs": [
            { "name": "smiley", "namespace": "faces", "kind": "Service", "group": "" }
        ],
        "rules": [
            { "backendRefs": [ { "name": "smiley-v2" } ] }
        ]
    }"#;

    #[test]
    fn parses_the_fetched_gamma_mesh_httproute_example() {
        let spec: HttpRouteSpec = serde_json::from_str(MESH_ROUTE_JSON).expect("valid HTTPRoute spec JSON must parse");
        assert_eq!(spec.parent_refs.len(), 1);
        assert_eq!(spec.parent_refs[0].name, "smiley");
        assert_eq!(spec.parent_refs[0].namespace.as_deref(), Some("faces"));
        assert_eq!(spec.parent_refs[0].kind.as_deref(), Some("Service"));
        assert_eq!(spec.parent_refs[0].group.as_deref(), Some(""));
        assert_eq!(spec.rules.len(), 1);
        assert_eq!(spec.rules[0].backend_refs.len(), 1);
        assert_eq!(spec.rules[0].backend_refs[0].name, "smiley-v2");
        assert_eq!(spec.rules[0].backend_refs[0].namespace, None);
        assert_eq!(spec.rules[0].backend_refs[0].kind, None);
    }

    /// A `parentRefs`/`rules`-free spec (a `HTTPRoute` this crate has
    /// nothing to say about, or a not-yet-fully-specified object) parses to
    /// empty vectors rather than failing -- `#[serde(default)]` on both
    /// fields, never a required-field error on a legitimately-partial spec.
    #[test]
    fn missing_parent_refs_and_rules_default_to_empty() {
        let spec: HttpRouteSpec = serde_json::from_str("{}").expect("an empty object must still parse");
        assert!(spec.parent_refs.is_empty());
        assert!(spec.rules.is_empty());
    }

    /// A Gateway-attached (non-mesh) route's parentRef omits `kind`/`group`
    /// entirely (the real, common ingress case) -- this MUST still parse
    /// (as `None`/`None`), classification into "not mesh" happens in
    /// `plan`, never here.
    #[test]
    fn gateway_attached_parent_ref_with_no_kind_or_group_parses() {
        let json = r#"{ "parentRefs": [ { "name": "my-gateway" } ] }"#;
        let spec: HttpRouteSpec = serde_json::from_str(json).expect("must parse");
        assert_eq!(spec.parent_refs[0].kind, None);
        assert_eq!(spec.parent_refs[0].group, None);
    }
}
