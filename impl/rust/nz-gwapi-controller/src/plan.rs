// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! The PURE reconcile-mapping core (no I/O, no kube-rs dependency): given a
//! parsed [`crate::types::HttpRouteSpec`] (plus, for peer/grant derivation,
//! a Service's annotations), computes the exact seam calls a real cluster
//! state implies -- [`WaypointConfigOp::Allow`] (`AuthzTable::allow`),
//! [`WaypointConfigOp::RegisterPeer`] (`PeerDirectory::register`), and
//! [`WaypointConfigOp::GrantMaxEffect`] (the `AuthzHook` max-grant ceiling).
//! This is what the UNIT tier grades: every function here takes a concrete
//! value and returns a concrete, deterministic result -- no network, no
//! clock, no randomness.
//!
//! # The authorization-mapping policy decision (documented, not claimed as
//! Gateway-API semantics)
//!
//! Per this crate's docs (and the fetched primary source they cite),
//! standard Gateway-API HTTPRoute carries NO source/authorization semantics
//! at all -- it is a pure routing/traffic-splitting object. This module's
//! mapping is a DELIBERATE POLICY DECISION this controller makes to fill
//! that gap, stated plainly: for a GAMMA mesh-attached `HTTPRoute` whose
//! `parentRefs` name Service `D` (the destination workload the route
//! governs) and whose `rules[].backendRefs` name Service `S` (a routing
//! target), this controller treats the routing edge `S -> D` as an
//! authorization edge and emits `AuthzTable::allow(S, D)` -- "if the mesh
//! admin has configured a route that forwards to a live pair, the waypoint
//! fronting `D` must permit that pair to actually traverse it, or the
//! configured route is unreachable in practice." This is NOT a claim that
//! Gateway-API itself defines this as an authorization primitive.
//!
//! # Fail-closed classification (advisor-corrected 2026-09-05)
//!
//! - A `parentRef` is treated as a GAMMA mesh Service binding ONLY when
//!   `kind` is EXPLICITLY `"Service"` AND `group` is EXPLICITLY `""` or
//!   `"core"` (case-insensitive) -- BOTH fields present. A real API-server
//!   round-trip of a genuine GAMMA route always carries both (the
//!   Gateway/`gateway.networking.k8s.io` pair is what an OMITTED `kind`
//!   defaults to, per the Gateway-API `ParentReference` "referent"
//!   default -- the opposite of Service/core). An ambiguous parentRef
//!   (`kind: Service` with `group` omitted, or vice versa) is treated as
//!   NOT mesh -- skipped, never guessed into an authorization decision.
//! - A `backendRef`'s `kind`/`group` default to `Service`/`""` when
//!   OMITTED (the Gateway-API `BackendRef` "referent" default -- the
//!   overwhelmingly common case, and the OPPOSITE default pairing from
//!   `ParentRef` above, because the two types specify independent
//!   defaults).
//! - A cross-namespace `backendRef` (this crate implements no
//!   `ReferenceGrant` validation) fails the WHOLE route closed -- refusing
//!   to synthesize an unchecked cross-namespace authorization edge is safer
//!   than silently trusting one Gateway-API leaves to a separate mechanism.
//! - An unrecognized `max-effect-class` annotation value is a NAMED ERROR,
//!   never a default grant. This is the OPPOSITE fail-closed rule from
//!   [`nz_waypoint_core::EffectClass::from_wire`]'s own "unrecognized ->
//!   Destructive" default: that rule exists for a DECLARED EFFECT (where
//!   the most dangerous interpretation is the safest -- most likely
//!   denied). Applied to a GRANT CEILING instead, defaulting unrecognized
//!   input to Destructive would grant a typo'd annotation UNLIMITED
//!   authority -- fail OPEN, not closed. So [`parse_effect_class_annotation`]
//!   never calls `from_wire` with an out-of-range/untrusted value: it
//!   FIRST strictly validates the input against the four exact tokens
//!   `EffectClass`'s own `Display` impl emits (or the four exact digit
//!   strings), and only THEN calls `from_wire` with the corresponding
//!   already-validated in-range code -- reusing the decode without ever
//!   exercising its catch-all arm on untrusted input.

use std::collections::BTreeMap;

use nz_agent::agent::PeerDirectory;
use nz_agent::authz::AuthzTable;
use nz_agent::identity::SpiffeId;
use nz_waypoint_core::EffectClass;

use crate::types::HttpRouteSpec;

/// One resolved instruction against a waypoint's seams -- the output of
/// this module's planning functions, and the exact shape a caller applies
/// to a live `AuthzTable`/`PeerDirectory`/grant list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WaypointConfigOp {
    /// `AuthzTable::allow(source, destination)` -- the L4 seam the CLI's
    /// `--allow SOURCE->DEST` flag also populates.
    Allow { source: SpiffeId, destination: SpiffeId },
    /// `PeerDirectory::register(pubkey, id)` -- the L4 seam the CLI's
    /// `--register-peer PUBKEY_HEX=SPIFFE_ID` flag also populates.
    RegisterPeer { pubkey: [u8; 32], id: SpiffeId },
    /// The L7 `AuthzHook` max-effect grant ceiling for `signer_id` when
    /// reaching a waypoint whose own consuming authority is
    /// `consuming_authority` (mirrors `TableAuthzHook::new`'s
    /// `(signer_id, EffectClass)` grant-table entries).
    GrantMaxEffect { signer_id: SpiffeId, consuming_authority: SpiffeId, max_grant: EffectClass },
}

/// Why a `HTTPRoute`, or a Service annotation on an object it references,
/// could not be planned -- named per the specific rule violated (D3: no
/// bare "invalid").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileError {
    /// The route's `parentRefs` list is empty -- malformed (the
    /// Gateway-API schema requires at least one), not "nothing to do".
    NoParentRef,
    /// A `backendRef` named a namespace different from the route's own,
    /// which this crate cannot authorize without `ReferenceGrant`
    /// validation it does not implement.
    CrossNamespaceBackendRequiresReferenceGrant { route_namespace: String, backend_namespace: String, backend_name: String },
    /// A `parentRef`/`backendRef` `name` (or `namespace`) was not a valid
    /// SPIFFE ID path segment once composed into
    /// `spiffe://<trust-domain>/ns/<namespace>/sa/<name>` (formatted, since
    /// `nz_agent::identity::SpiffeIdError` does not implement
    /// `PartialEq`/`Eq`, D3: never a bare "invalid").
    BadSpiffeId(String),
    /// A `npamp.bubblefish.io/max-effect-class` annotation value was not
    /// one of the four exact tokens/digits [`parse_effect_class_annotation`]
    /// accepts.
    BadEffectClassAnnotation(String),
    /// A `npamp.bubblefish.io/svid-pubkey-hex` annotation value was not
    /// exactly 64 valid hex characters.
    BadPubkeyHexAnnotation(String),
}

impl std::fmt::Display for ReconcileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReconcileError::NoParentRef => write!(f, "nz-gwapi-controller: HTTPRoute has no parentRefs"),
            ReconcileError::CrossNamespaceBackendRequiresReferenceGrant { route_namespace, backend_namespace, backend_name } => write!(
                f,
                "nz-gwapi-controller: backendRef {backend_name:?} in namespace {backend_namespace:?} referenced from a route in namespace {route_namespace:?} needs ReferenceGrant validation this crate does not implement; refusing to authorize"
            ),
            ReconcileError::BadSpiffeId(msg) => write!(f, "nz-gwapi-controller: {msg}"),
            ReconcileError::BadEffectClassAnnotation(v) => write!(f, "nz-gwapi-controller: bad max-effect-class annotation {v:?}"),
            ReconcileError::BadPubkeyHexAnnotation(v) => write!(f, "nz-gwapi-controller: bad svid-pubkey-hex annotation {v:?}"),
        }
    }
}

impl std::error::Error for ReconcileError {}

fn spiffe_id_for_service(trust_domain: &str, namespace: &str, name: &str) -> Result<SpiffeId, ReconcileError> {
    SpiffeId::parse(&format!("spiffe://{trust_domain}/ns/{namespace}/sa/{name}"))
        .map_err(|e| ReconcileError::BadSpiffeId(format!("cannot derive a SPIFFE id for Service {namespace}/{name}: {e}")))
}

/// Is this `parentRef` a GAMMA mesh Service binding? See this module's docs
/// for the fail-closed "both fields explicitly present" rule.
fn is_mesh_service_parent_ref(kind: Option<&str>, group: Option<&str>) -> bool {
    let is_service_kind = kind == Some("Service");
    let is_core_group = matches!(group, Some(g) if g.is_empty() || g.eq_ignore_ascii_case("core"));
    is_service_kind && is_core_group
}

/// Is this `backendRef` a (possibly-defaulted) core Service reference? See
/// this module's docs for the "omitted defaults to Service/core" rule
/// (the OPPOSITE default pairing from `is_mesh_service_parent_ref`).
fn is_service_backend_ref(kind: Option<&str>, group: Option<&str>) -> bool {
    let is_service_kind = matches!(kind, None | Some("Service"));
    let is_core_group = matches!(group, None) || matches!(group, Some(g) if g.is_empty() || g.eq_ignore_ascii_case("core"));
    is_service_kind && is_core_group
}

/// Plans the [`WaypointConfigOp::Allow`] ops a single `HTTPRoute` implies.
/// `route_namespace` is the `HTTPRoute` object's OWN namespace (used to
/// default an omitted `parentRef`/`backendRef` namespace, per the
/// Gateway-API convention that a reference with no explicit namespace
/// targets the referencing object's own namespace).
pub fn plan_route_reconcile(trust_domain: &str, route_namespace: &str, spec: &HttpRouteSpec) -> Result<Vec<WaypointConfigOp>, ReconcileError> {
    if spec.parent_refs.is_empty() {
        return Err(ReconcileError::NoParentRef);
    }

    let mut ops = Vec::new();
    for parent in &spec.parent_refs {
        if !is_mesh_service_parent_ref(parent.kind.as_deref(), parent.group.as_deref()) {
            continue; // not a GAMMA mesh binding (e.g. Gateway-attached ingress) -- nothing to authorize
        }
        let dest_namespace = parent.namespace.as_deref().unwrap_or(route_namespace);
        let destination = spiffe_id_for_service(trust_domain, dest_namespace, &parent.name)?;

        for rule in &spec.rules {
            for backend in &rule.backend_refs {
                if !is_service_backend_ref(backend.kind.as_deref(), backend.group.as_deref()) {
                    continue; // not a Service backend (e.g. a Kind we don't recognize) -- nothing to authorize for it
                }
                let backend_namespace = backend.namespace.as_deref().unwrap_or(route_namespace);
                if backend_namespace != route_namespace {
                    return Err(ReconcileError::CrossNamespaceBackendRequiresReferenceGrant {
                        route_namespace: route_namespace.to_string(),
                        backend_namespace: backend_namespace.to_string(),
                        backend_name: backend.name.clone(),
                    });
                }
                let source = spiffe_id_for_service(trust_domain, backend_namespace, &backend.name)?;
                ops.push(WaypointConfigOp::Allow { source, destination: destination.clone() });
            }
        }
    }
    Ok(ops)
}

/// Strictly parses a `npamp.bubblefish.io/max-effect-class` annotation
/// value into an [`EffectClass`] grant ceiling. See this module's docs for
/// why this must NEVER default an unrecognized value to `Destructive`
/// (the grant-ceiling dual of `EffectClass::from_wire`'s declared-effect
/// fail-closed rule).
pub fn parse_effect_class_annotation(s: &str) -> Result<EffectClass, ReconcileError> {
    let code: u8 = match s {
        "read_only" | "0" => 0,
        "idempotent_write" | "1" => 1,
        "non_idempotent_write" | "2" => 2,
        "destructive" | "3" => 3,
        _ => return Err(ReconcileError::BadEffectClassAnnotation(s.to_string())),
    };
    // `code` is always exactly 0..=3 here -- `from_wire`'s catch-all
    // ("unrecognized -> Destructive") is therefore never reached on
    // untrusted input; this call only ever exercises its four exact-match
    // arms, reusing the decode without inheriting its fail-open-for-grants
    // hazard.
    Ok(EffectClass::from_wire(code))
}

/// Strictly parses a `npamp.bubblefish.io/svid-pubkey-hex` annotation value
/// into the 32-octet Ed25519 public key `PeerDirectory::register` expects.
/// Fail-closed on anything but exactly 64 valid hex characters (mirrors
/// `nz-agent`'s own `parse_pubkey_hex` in `src/bin/nz_agent.rs`, which is
/// private to that binary -- this crate cannot reach it and does not
/// duplicate its BEHAVIOR from memory: it is re-derived here and
/// independently tested against the same fail-closed shape).
pub fn parse_pubkey_hex_annotation(s: &str) -> Result<[u8; 32], ReconcileError> {
    if s.len() != 64 {
        return Err(ReconcileError::BadPubkeyHexAnnotation(s.to_string()));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let byte_str = &s[i * 2..i * 2 + 2];
        out[i] = u8::from_str_radix(byte_str, 16).map_err(|_| ReconcileError::BadPubkeyHexAnnotation(s.to_string()))?;
    }
    Ok(out)
}

/// One `HTTPRoute` object as [`plan_full_desired_state`] consumes it: its
/// own namespace plus its parsed spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteInput {
    pub namespace: String,
    pub spec: HttpRouteSpec,
}

/// A Service's identity (namespace + name), keying the annotation map
/// [`plan_full_desired_state`] takes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ServiceKey {
    pub namespace: String,
    pub name: String,
}

/// The full, freshly-recomputed seam state a batch of `HTTPRoute` objects
/// (plus their referenced Services' annotations) implies -- see the crate
/// docs for why this is rebuilt whole and swapped, never mutated
/// incrementally.
pub struct DesiredState {
    pub authz: AuthzTable,
    pub peers: PeerDirectory,
    pub grants: Vec<WaypointConfigOp>,
}

/// Recomputes the FULL desired seam state from every currently-known
/// `HTTPRoute` (`routes`) and the annotations of every Service any of them
/// references (`service_annotations`, keyed by [`ServiceKey`]). Returns the
/// desired state alongside a list of `(route index, error)` pairs for any
/// route that could not be planned -- one broken route never suppresses
/// another, valid route's ops (see this module's tests).
pub fn plan_full_desired_state(trust_domain: &str, routes: &[RouteInput], service_annotations: &BTreeMap<ServiceKey, BTreeMap<String, String>>) -> (DesiredState, Vec<(usize, ReconcileError)>) {
    let mut authz = AuthzTable::new();
    let mut peers = PeerDirectory::new();
    let mut grants = Vec::new();
    let mut errors = Vec::new();

    // Every distinct Service this batch mentions (as either a parentRef or
    // a backendRef) -- peer-pubkey registration is identity-flat (it does
    // not depend on which route referenced the Service, or in which
    // direction), so it runs once per distinct Service here.
    let mut services: BTreeMap<ServiceKey, ()> = BTreeMap::new();

    for (idx, route) in routes.iter().enumerate() {
        match plan_route_reconcile(trust_domain, &route.namespace, &route.spec) {
            Ok(ops) => {
                for op in &ops {
                    let WaypointConfigOp::Allow { source, destination } = op else { continue };
                    authz.allow(source.clone(), destination.clone());

                    // Unlike peer-pubkey registration, a max-effect GRANT is
                    // scoped to a specific (signer, consuming-authority)
                    // PAIR -- `AuthzHook::max_grant_for_signer` is always
                    // consulted for one particular waypoint's own
                    // `consuming_authority` (nz-waypoint-core's `authorize`
                    // takes both together). So the grant annotation is read
                    // off the SOURCE Service, at the exact (source,
                    // destination) pair this Allow op already resolved --
                    // never batched flat like peer registration, and never
                    // defaulted to a self-referential placeholder.
                    if let Some(source_key) = service_key_of(source, trust_domain) {
                        if let Some(annotations) = service_annotations.get(&source_key) {
                            if let Some(grant_token) = annotations.get("npamp.bubblefish.io/max-effect-class") {
                                if let Ok(max_grant) = parse_effect_class_annotation(grant_token) {
                                    grants.push(WaypointConfigOp::GrantMaxEffect { signer_id: source.clone(), consuming_authority: destination.clone(), max_grant });
                                }
                            }
                        }
                    }
                }
                for parent in &route.spec.parent_refs {
                    if is_mesh_service_parent_ref(parent.kind.as_deref(), parent.group.as_deref()) {
                        let ns = parent.namespace.clone().unwrap_or_else(|| route.namespace.clone());
                        services.insert(ServiceKey { namespace: ns, name: parent.name.clone() }, ());
                    }
                }
                for rule in &route.spec.rules {
                    for backend in &rule.backend_refs {
                        if is_service_backend_ref(backend.kind.as_deref(), backend.group.as_deref()) {
                            let ns = backend.namespace.clone().unwrap_or_else(|| route.namespace.clone());
                            services.insert(ServiceKey { namespace: ns, name: backend.name.clone() }, ());
                        }
                    }
                }
            }
            Err(e) => errors.push((idx, e)),
        }
    }

    for key in services.keys() {
        let Some(annotations) = service_annotations.get(key) else { continue };
        let Ok(id) = spiffe_id_for_service(trust_domain, &key.namespace, &key.name) else { continue };
        if let Some(pk_hex) = annotations.get("npamp.bubblefish.io/svid-pubkey-hex") {
            if let Ok(pubkey) = parse_pubkey_hex_annotation(pk_hex) {
                peers.register(pubkey, id.clone());
            }
        }
    }

    (DesiredState { authz, peers, grants }, errors)
}

/// Recovers the [`ServiceKey`] a resolved `SpiffeId` was derived from, by
/// re-parsing its own `spiffe://<trust-domain>/ns/<namespace>/sa/<name>`
/// shape -- the inverse of [`spiffe_id_for_service`]. Returns `None` for an
/// id this crate did not itself construct in that shape (never guessed at;
/// a mismatch here just means "no annotation lookup possible for this
/// identity", not an error -- annotation-derived grants are an optional
/// enrichment, not a required one).
fn service_key_of(id: &SpiffeId, trust_domain: &str) -> Option<ServiceKey> {
    if id.trust_domain() != trust_domain {
        return None;
    }
    let path = id.path(); // "/ns/<namespace>/sa/<name>"
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    match segments.as_slice() {
        ["ns", namespace, "sa", name] => Some(ServiceKey { namespace: namespace.to_string(), name: name.to_string() }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use nz_agent::authz::Decision;
    use nz_agent::identity::SpiffeId;
    use nz_waypoint_core::EffectClass;

    use super::{parse_effect_class_annotation, parse_pubkey_hex_annotation, plan_full_desired_state, plan_route_reconcile, ReconcileError, RouteInput, ServiceKey, WaypointConfigOp};
    use crate::types::{BackendRef, HttpRouteRule, HttpRouteSpec, ParentRef};

    fn sid(s: &str) -> SpiffeId {
        SpiffeId::parse(s).expect("valid SPIFFE id")
    }

    fn mesh_parent(name: &str, namespace: Option<&str>) -> ParentRef {
        ParentRef { name: name.to_string(), namespace: namespace.map(str::to_string), kind: Some("Service".to_string()), group: Some(String::new()) }
    }

    fn backend(name: &str, namespace: Option<&str>) -> BackendRef {
        BackendRef { name: name.to_string(), namespace: namespace.map(str::to_string), kind: None, group: None }
    }

    #[test]
    fn mesh_route_produces_one_allow_from_each_backend_to_the_parent() {
        let spec = HttpRouteSpec { parent_refs: vec![mesh_parent("dest", None)], rules: vec![HttpRouteRule { backend_refs: vec![backend("src-a", None), backend("src-b", None)] }] };
        let ops = plan_route_reconcile("cluster.local", "prod", &spec).expect("a well-formed mesh route must plan cleanly");
        assert_eq!(
            ops,
            vec![
                WaypointConfigOp::Allow { source: sid("spiffe://cluster.local/ns/prod/sa/src-a"), destination: sid("spiffe://cluster.local/ns/prod/sa/dest") },
                WaypointConfigOp::Allow { source: sid("spiffe://cluster.local/ns/prod/sa/src-b"), destination: sid("spiffe://cluster.local/ns/prod/sa/dest") },
            ]
        );
    }

    /// A route with NO parentRefs at all is a fail-closed error, not "no
    /// ops" -- an empty parentRefs list on a real HTTPRoute is malformed
    /// (the field is required by the Gateway-API schema itself), and this
    /// crate must not silently treat malformed input as "nothing to do".
    #[test]
    fn no_parent_refs_is_an_error_not_silently_empty() {
        let spec = HttpRouteSpec { parent_refs: vec![], rules: vec![] };
        let err = plan_route_reconcile("cluster.local", "prod", &spec).expect_err("an HTTPRoute with no parentRefs must be rejected");
        assert_eq!(err, ReconcileError::NoParentRef);
    }

    /// A Gateway-attached (non-mesh) route -- kind/group omitted, the real
    /// ingress default -- produces ZERO ops, not an error: this controller
    /// has nothing to say about ingress routing, and must not misclassify
    /// it into a mesh authorization decision.
    #[test]
    fn gateway_attached_route_produces_no_ops() {
        let spec = HttpRouteSpec { parent_refs: vec![ParentRef { name: "my-gateway".to_string(), namespace: None, kind: None, group: None }], rules: vec![HttpRouteRule { backend_refs: vec![backend("svc", None)] }] };
        let ops = plan_route_reconcile("cluster.local", "prod", &spec).expect("a non-mesh route is not an error");
        assert!(ops.is_empty(), "a Gateway-attached route must produce no waypoint authorization ops");
    }

    /// `kind: Service` with `group` OMITTED is ambiguous per this crate's
    /// documented policy (see types.rs's ParentRef docs) -- fail closed to
    /// "not mesh", never guessed.
    #[test]
    fn parent_ref_service_kind_with_missing_group_is_not_treated_as_mesh() {
        let spec = HttpRouteSpec { parent_refs: vec![ParentRef { name: "dest".to_string(), namespace: None, kind: Some("Service".to_string()), group: None }], rules: vec![] };
        let ops = plan_route_reconcile("cluster.local", "prod", &spec).expect("ambiguous parentRef must not error");
        assert!(ops.is_empty());
    }

    /// A cross-namespace backendRef (no ReferenceGrant validation is
    /// implemented by this crate) fails the WHOLE route closed rather than
    /// silently authorizing an unchecked cross-namespace pair.
    #[test]
    fn cross_namespace_backend_ref_fails_closed() {
        let spec = HttpRouteSpec { parent_refs: vec![mesh_parent("dest", None)], rules: vec![HttpRouteRule { backend_refs: vec![backend("src", Some("other-ns"))] }] };
        let err = plan_route_reconcile("cluster.local", "prod", &spec).expect_err("a cross-namespace backendRef must be rejected");
        assert!(matches!(err, ReconcileError::CrossNamespaceBackendRequiresReferenceGrant { .. }));
    }

    /// An explicit parentRef namespace (the "Consumer Route" cross-namespace
    /// shape the fetched primary source itself documents) is honored, not
    /// defaulted to the route's own namespace.
    #[test]
    fn explicit_parent_ref_namespace_is_honored() {
        let spec = HttpRouteSpec { parent_refs: vec![mesh_parent("smiley", Some("faces"))], rules: vec![HttpRouteRule { backend_refs: vec![backend("smiley-v2", None)] }] };
        let ops = plan_route_reconcile("cluster.local", "fast-clients", &spec).expect("cross-namespace parentRef must plan cleanly");
        assert_eq!(ops, vec![WaypointConfigOp::Allow { source: sid("spiffe://cluster.local/ns/fast-clients/sa/smiley-v2"), destination: sid("spiffe://cluster.local/ns/faces/sa/smiley") }]);
    }

    // ---- annotation parsing: the grant-ceiling dual (advisor-flagged) -----

    /// Every EffectClass value round-trips through its OWN Display token --
    /// the annotation format IS that token, verified against all four
    /// variants (not just one).
    #[test]
    fn effect_class_annotation_round_trips_every_display_token() {
        for (token, want) in [
            ("read_only", EffectClass::ReadOnly),
            ("idempotent_write", EffectClass::IdempotentWrite),
            ("non_idempotent_write", EffectClass::NonIdempotentWrite),
            ("destructive", EffectClass::Destructive),
        ] {
            assert_eq!(parse_effect_class_annotation(token), Ok(want), "token {token:?} must parse to {want}");
        }
    }

    /// A malformed grant annotation is a NAMED ERROR, never a default grant
    /// -- unlike `EffectClass::from_wire`'s fail-closed-to-Destructive rule
    /// for a DECLARED EFFECT (where unknown = most dangerous = most likely
    /// denied), a GRANT CEILING's unknown value must NOT default to
    /// Destructive (that would be the maximum authority, i.e. fail OPEN for
    /// a ceiling). This is the mutation-tested property: flip this to a
    /// default-to-Destructive and this test goes red.
    #[test]
    fn malformed_effect_class_annotation_is_rejected_not_defaulted() {
        for bad in ["", "4", "READ_ONLY", "read-only", "ReadOnly", "nonsense"] {
            let err = parse_effect_class_annotation(bad).expect_err("a malformed grant annotation must be rejected");
            assert_eq!(err, ReconcileError::BadEffectClassAnnotation(bad.to_string()));
        }
    }

    /// The digit-string form (what an operator might type directly) is also
    /// accepted, strictly -- "0".."3" only, never a wider numeric range.
    #[test]
    fn effect_class_annotation_accepts_the_four_digit_strings_only() {
        assert_eq!(parse_effect_class_annotation("0"), Ok(EffectClass::ReadOnly));
        assert_eq!(parse_effect_class_annotation("3"), Ok(EffectClass::Destructive));
        assert!(parse_effect_class_annotation("4").is_err());
        assert!(parse_effect_class_annotation("04").is_err());
    }

    // ---- pubkey annotation parsing ----------------------------------------

    #[test]
    fn pubkey_hex_annotation_parses_64_lowercase_hex_chars() {
        let hex = "a".repeat(64);
        let pk = parse_pubkey_hex_annotation(&hex).expect("64 valid hex chars must parse");
        assert_eq!(pk, [0xaa; 32]);
    }

    #[test]
    fn pubkey_hex_annotation_rejects_wrong_length_or_bad_hex() {
        assert!(parse_pubkey_hex_annotation("ab").is_err(), "too short must be rejected");
        assert!(parse_pubkey_hex_annotation(&"g".repeat(64)).is_err(), "non-hex chars must be rejected");
    }

    // ---- full-desired-state rebuild-and-swap (advisor-flagged deletion drift) --

    #[test]
    fn full_desired_state_denies_a_pair_whose_route_was_removed() {
        let route = RouteInput { namespace: "prod".to_string(), spec: HttpRouteSpec { parent_refs: vec![mesh_parent("dest", None)], rules: vec![HttpRouteRule { backend_refs: vec![backend("src", None)] }] } };
        let (state_with_route, errs) = plan_full_desired_state("cluster.local", &[route], &Default::default());
        assert!(errs.is_empty());
        let (d, _) = state_with_route.authz.check(&sid("spiffe://cluster.local/ns/prod/sa/src"), &sid("spiffe://cluster.local/ns/prod/sa/dest"));
        assert_eq!(d, Decision::Allow, "the pair must be allowed while the route exists");

        // The route is gone from the SECOND call's input entirely (simulating a
        // deletion) -- rebuild-and-swap means the new state has NO memory of it.
        let (state_after_deletion, errs2) = plan_full_desired_state("cluster.local", &[], &Default::default());
        assert!(errs2.is_empty());
        let (d2, _) = state_after_deletion.authz.check(&sid("spiffe://cluster.local/ns/prod/sa/src"), &sid("spiffe://cluster.local/ns/prod/sa/dest"));
        assert_eq!(d2, Decision::Deny, "a deleted route's allow-pair must not survive into the rebuilt state");
    }

    /// One broken route's error does not suppress a DIFFERENT, valid
    /// route's ops from the same batch -- a cluster-wide fail-closed
    /// collapse on one malformed object would be its own availability bug.
    #[test]
    fn one_broken_route_does_not_block_other_routes_in_the_same_batch() {
        let broken = RouteInput { namespace: "prod".to_string(), spec: HttpRouteSpec { parent_refs: vec![], rules: vec![] } };
        let ok = RouteInput { namespace: "prod".to_string(), spec: HttpRouteSpec { parent_refs: vec![mesh_parent("dest", None)], rules: vec![HttpRouteRule { backend_refs: vec![backend("src", None)] }] } };
        let (state, errs) = plan_full_desired_state("cluster.local", &[broken, ok], &Default::default());
        assert_eq!(errs.len(), 1);
        let (d, _) = state.authz.check(&sid("spiffe://cluster.local/ns/prod/sa/src"), &sid("spiffe://cluster.local/ns/prod/sa/dest"));
        assert_eq!(d, Decision::Allow, "the valid route's pair must still be allowed despite the other route's error");
    }

    // ---- full-pipeline peer/grant derivation from Service annotations -----

    /// A distinct Service mentioned by a route (as source OR destination)
    /// with a well-formed `svid-pubkey-hex` annotation is registered as a
    /// peer in the rebuilt `PeerDirectory`.
    #[test]
    fn full_desired_state_registers_peer_pubkey_from_service_annotation() {
        let route = RouteInput { namespace: "prod".to_string(), spec: HttpRouteSpec { parent_refs: vec![mesh_parent("dest", None)], rules: vec![HttpRouteRule { backend_refs: vec![backend("src", None)] }] } };
        let mut annotations = std::collections::BTreeMap::new();
        let mut src_ann = std::collections::BTreeMap::new();
        src_ann.insert("npamp.bubblefish.io/svid-pubkey-hex".to_string(), "bb".repeat(32));
        annotations.insert(ServiceKey { namespace: "prod".to_string(), name: "src".to_string() }, src_ann);

        let (state, errs) = plan_full_desired_state("cluster.local", &[route], &annotations);
        assert!(errs.is_empty());
        let resolved = state.peers.resolve(&[0xbb; 32]).expect("the registered pubkey must resolve");
        assert_eq!(resolved, sid("spiffe://cluster.local/ns/prod/sa/src"));
    }

    /// A malformed pubkey annotation is silently NOT registered (the
    /// annotation is optional enrichment; a malformed value must not panic
    /// or register a garbage/truncated key) -- `resolve` on any key finds
    /// nothing for this Service.
    #[test]
    fn full_desired_state_ignores_a_malformed_pubkey_annotation() {
        let route = RouteInput { namespace: "prod".to_string(), spec: HttpRouteSpec { parent_refs: vec![mesh_parent("dest", None)], rules: vec![HttpRouteRule { backend_refs: vec![backend("src", None)] }] } };
        let mut annotations = std::collections::BTreeMap::new();
        let mut src_ann = std::collections::BTreeMap::new();
        src_ann.insert("npamp.bubblefish.io/svid-pubkey-hex".to_string(), "not-hex".to_string());
        annotations.insert(ServiceKey { namespace: "prod".to_string(), name: "src".to_string() }, src_ann);

        let (state, _) = plan_full_desired_state("cluster.local", &[route], &annotations);
        assert_eq!(state.peers.resolve(&[0u8; 32]), None);
    }

    /// The max-effect grant annotation on the SOURCE Service becomes a
    /// `GrantMaxEffect { signer_id: source, consuming_authority: destination,
    /// .. }` op scoped to the exact pair the route resolved -- never a
    /// self-referential (signer == consuming_authority) placeholder.
    #[test]
    fn full_desired_state_derives_max_effect_grant_scoped_to_the_resolved_pair() {
        let route = RouteInput { namespace: "prod".to_string(), spec: HttpRouteSpec { parent_refs: vec![mesh_parent("dest", None)], rules: vec![HttpRouteRule { backend_refs: vec![backend("src", None)] }] } };
        let mut annotations = std::collections::BTreeMap::new();
        let mut src_ann = std::collections::BTreeMap::new();
        src_ann.insert("npamp.bubblefish.io/max-effect-class".to_string(), "idempotent_write".to_string());
        annotations.insert(ServiceKey { namespace: "prod".to_string(), name: "src".to_string() }, src_ann);

        let (state, errs) = plan_full_desired_state("cluster.local", &[route], &annotations);
        assert!(errs.is_empty());
        assert_eq!(
            state.grants,
            vec![WaypointConfigOp::GrantMaxEffect {
                signer_id: sid("spiffe://cluster.local/ns/prod/sa/src"),
                consuming_authority: sid("spiffe://cluster.local/ns/prod/sa/dest"),
                max_grant: EffectClass::IdempotentWrite,
            }]
        );
    }

    /// A malformed grant annotation on a Service produces NO grant op for
    /// that pair -- never a defaulted one (this is the full-pipeline
    /// counterpart of `malformed_effect_class_annotation_is_rejected_not_defaulted`:
    /// the batch-level path must not silently manufacture a grant either).
    #[test]
    fn full_desired_state_emits_no_grant_for_a_malformed_annotation() {
        let route = RouteInput { namespace: "prod".to_string(), spec: HttpRouteSpec { parent_refs: vec![mesh_parent("dest", None)], rules: vec![HttpRouteRule { backend_refs: vec![backend("src", None)] }] } };
        let mut annotations = std::collections::BTreeMap::new();
        let mut src_ann = std::collections::BTreeMap::new();
        src_ann.insert("npamp.bubblefish.io/max-effect-class".to_string(), "nonsense".to_string());
        annotations.insert(ServiceKey { namespace: "prod".to_string(), name: "src".to_string() }, src_ann);

        let (state, _) = plan_full_desired_state("cluster.local", &[route], &annotations);
        assert!(state.grants.is_empty(), "a malformed grant annotation must never produce a grant op");
    }
}
