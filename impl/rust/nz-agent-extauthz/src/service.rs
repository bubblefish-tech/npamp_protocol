// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! The `Authorization` gRPC service implementation: maps a `CheckRequest`
//! to the N-PAMP triple ([`crate::extract::extract_triple`]), then calls
//! [`nz_agent::waypoint::authorize`] for the ONE decision this service
//! makes. This module contains no authorization logic — only wire
//! plumbing (parse the request, call the core, shape the response).

use nz_agent::waypoint::{authorize, AuthzHook, WaypointDenied};
use tonic::{Request, Response, Status};

use crate::extract::{extract_triple, TripleExtractError};
use crate::pb::authorization_server::Authorization;
use crate::pb::{CheckRequest, CheckResponse, DeniedHttpResponse, HttpStatus, StatusCode};

/// The ext_authz `Authorization` gRPC service, generic over any
/// [`AuthzHook`] implementation (see this crate's module docs for why the
/// hook is a seam, not a stub). `H` must be `Send + Sync + 'static`
/// because tonic dispatches `check` across its async server task pool.
pub struct ExtAuthzService<H: AuthzHook + Send + Sync + 'static> {
    hook: H,
}

impl<H: AuthzHook + Send + Sync + 'static> ExtAuthzService<H> {
    pub fn new(hook: H) -> Self {
        ExtAuthzService { hook }
    }
}

/// google.rpc.Code (verified this session against `google/rpc/code.proto`,
/// see `proto/ext_authz.proto`'s `RpcStatus` message comment): OK = 0,
/// PERMISSION_DENIED = 7. These are the only two values this service ever
/// emits — the primary allow/deny signal ext_authz clients read.
const RPC_CODE_OK: i32 = 0;
const RPC_CODE_PERMISSION_DENIED: i32 = 7;

fn allow_response() -> CheckResponse {
    CheckResponse {
        status: Some(crate::pb::RpcStatus { code: RPC_CODE_OK, message: String::new() }),
        http_response: None,
    }
}

fn deny_response(reason: String) -> CheckResponse {
    CheckResponse {
        status: Some(crate::pb::RpcStatus { code: RPC_CODE_PERMISSION_DENIED, message: reason.clone() }),
        http_response: Some(crate::pb::check_response::HttpResponse::DeniedResponse(DeniedHttpResponse {
            status: Some(HttpStatus { code: StatusCode::Forbidden as i32 }),
            body: reason,
        })),
    }
}

#[tonic::async_trait]
impl<H: AuthzHook + Send + Sync + 'static> Authorization for ExtAuthzService<H> {
    /// The one RPC this service implements. Fail-closed at every branch:
    /// a missing/malformed triple denies (never allows); an unrecognized
    /// signer or an unrecognized effect value denies via
    /// `nz_agent::waypoint::authorize`'s own fail-closed rules (this
    /// function never overrides or second-guesses that decision — it only
    /// shapes the gRPC response around it).
    async fn check(&self, request: Request<CheckRequest>) -> Result<Response<CheckResponse>, Status> {
        let req = request.into_inner();

        // Fail-closed: any missing level of the (attributes -> request ->
        // http) chain is treated identically to "no headers at all", which
        // extract_triple then denies with MissingHeader — no special-cased
        // "malformed CheckRequest" allow path exists.
        let headers = req
            .attributes
            .and_then(|a| a.request)
            .and_then(|r| r.http)
            .map(|h| h.headers)
            .unwrap_or_default();

        let (signer_id, audience, object_effect) = match extract_triple(&headers) {
            Ok(triple) => triple,
            Err(TripleExtractError::MissingHeader(name)) => {
                return Ok(Response::new(deny_response(format!("npamp-extauthz: missing required header {name:?}"))));
            }
            Err(TripleExtractError::MalformedEffect(raw)) => {
                return Ok(Response::new(deny_response(format!("npamp-extauthz: malformed effect header value {raw:?}"))));
            }
        };

        match authorize(&self.hook, &signer_id, &audience, object_effect) {
            Ok(()) => Ok(Response::new(allow_response())),
            Err(WaypointDenied::WrongAudience { object_audience, expected }) => Ok(Response::new(deny_response(format!(
                "npamp-extauthz: WrongAudience (object names {object_audience:?}, this waypoint is {expected:?})"
            )))),
            Err(WaypointDenied::EffectExceedsGrant { object_effect, max_grant }) => Ok(Response::new(deny_response(format!(
                "npamp-extauthz: effect {object_effect} exceeds max grant {max_grant} for signer {signer_id:?}"
            )))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nz_agent::waypoint::{EffectClass, TableAuthzHook};
    use std::collections::HashMap;

    fn check_request(pairs: &[(&str, &str)]) -> Request<CheckRequest> {
        let headers: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        Request::new(CheckRequest {
            attributes: Some(crate::pb::AttributeContext {
                request: Some(crate::pb::Request {
                    http: Some(crate::pb::HttpRequest { method: "POST".to_string(), headers, path: "/tools/call".to_string(), host: "gateway-a".to_string() }),
                }),
            }),
        })
    }

    fn rpc_code(resp: &CheckResponse) -> i32 {
        resp.status.as_ref().expect("status must be set").code
    }

    #[tokio::test]
    async fn allows_a_request_within_grant() {
        let hook = TableAuthzHook::new("gateway-a", &[("signer-1", EffectClass::NonIdempotentWrite)]);
        let svc = ExtAuthzService::new(hook);
        let req = check_request(&[("npamp-signer-id", "signer-1"), ("npamp-audience", "gateway-a"), ("npamp-effect", "1")]);
        let resp = svc.check(req).await.expect("check must not error transport-side").into_inner();
        assert_eq!(rpc_code(&resp), RPC_CODE_OK);
        assert!(resp.http_response.is_none(), "an allow must not carry a denied_response");
    }

    #[tokio::test]
    async fn denies_wrong_audience() {
        let hook = TableAuthzHook::new("gateway-a", &[("signer-1", EffectClass::Destructive)]);
        let svc = ExtAuthzService::new(hook);
        let req = check_request(&[("npamp-signer-id", "signer-1"), ("npamp-audience", "gateway-b"), ("npamp-effect", "0")]);
        let resp = svc.check(req).await.expect("check must not error transport-side").into_inner();
        assert_eq!(rpc_code(&resp), RPC_CODE_PERMISSION_DENIED);
        let denied = match resp.http_response {
            Some(crate::pb::check_response::HttpResponse::DeniedResponse(d)) => d,
            _ => panic!("deny must carry a DeniedHttpResponse"),
        };
        assert_eq!(denied.status, Some(HttpStatus { code: StatusCode::Forbidden as i32 }));
        assert!(denied.body.contains("WrongAudience"), "deny body must name the specific rule: {}", denied.body);
    }

    #[tokio::test]
    async fn denies_effect_exceeding_grant() {
        let hook = TableAuthzHook::new("gateway-a", &[("signer-1", EffectClass::ReadOnly)]);
        let svc = ExtAuthzService::new(hook);
        let req = check_request(&[("npamp-signer-id", "signer-1"), ("npamp-audience", "gateway-a"), ("npamp-effect", "3")]);
        let resp = svc.check(req).await.expect("check must not error transport-side").into_inner();
        assert_eq!(rpc_code(&resp), RPC_CODE_PERMISSION_DENIED);
        let denied = match resp.http_response {
            Some(crate::pb::check_response::HttpResponse::DeniedResponse(d)) => d,
            _ => panic!("deny must carry a DeniedHttpResponse"),
        };
        assert!(denied.body.contains("EffectExceedsGrant") || denied.body.contains("exceeds max grant"), "deny body must name the specific rule: {}", denied.body);
    }

    /// The load-bearing fail-closed property this crate adds on top of
    /// `waypoint::authorize`: a request missing the N-PAMP triple entirely
    /// (no npamp-* headers at all — e.g. a gateway that is not configured
    /// to forward them, or a caller that bypassed the gateway's header
    /// injection) MUST deny, never allow. `waypoint::authorize` is never
    /// even reached on this path.
    #[tokio::test]
    async fn denies_a_request_with_no_npamp_headers_at_all() {
        let hook = TableAuthzHook::new("gateway-a", &[("signer-1", EffectClass::Destructive)]);
        let svc = ExtAuthzService::new(hook);
        let req = check_request(&[]);
        let resp = svc.check(req).await.expect("check must not error transport-side").into_inner();
        assert_eq!(rpc_code(&resp), RPC_CODE_PERMISSION_DENIED, "a request with none of the three required headers must be denied");
        assert!(resp.http_response.is_some());
    }

    /// Same fail-closed property, at the "attributes/request/http chain is
    /// entirely absent" level (a malformed/degenerate CheckRequest) rather
    /// than "headers map is empty" — a distinct code path through `check`
    /// (the `and_then` chain in `check`, not `extract_triple`'s own
    /// missing-header check) that must ALSO deny.
    #[tokio::test]
    async fn denies_a_check_request_with_no_attributes_at_all() {
        let hook = TableAuthzHook::new("gateway-a", &[("signer-1", EffectClass::Destructive)]);
        let svc = ExtAuthzService::new(hook);
        let req = Request::new(CheckRequest { attributes: None });
        let resp = svc.check(req).await.expect("check must not error transport-side").into_inner();
        assert_eq!(rpc_code(&resp), RPC_CODE_PERMISSION_DENIED, "a CheckRequest with no attributes at all must be denied");
    }

    #[tokio::test]
    async fn denies_malformed_effect_header() {
        let hook = TableAuthzHook::new("gateway-a", &[("signer-1", EffectClass::Destructive)]);
        let svc = ExtAuthzService::new(hook);
        let req = check_request(&[("npamp-signer-id", "signer-1"), ("npamp-audience", "gateway-a"), ("npamp-effect", "not-a-number")]);
        let resp = svc.check(req).await.expect("check must not error transport-side").into_inner();
        assert_eq!(rpc_code(&resp), RPC_CODE_PERMISSION_DENIED, "a malformed effect header must be denied");
    }

    /// An effect value outside 0..=3 but still a valid u8 decodes to
    /// Destructive (EffectClass::from_wire's fail-closed rule) and is
    /// denied unless the signer holds a Destructive grant.
    // ---- R14 authorization-composition conformance (E2.21), 3 named cases ----

    /// Case (a): a request reaching this service necessarily means the
    /// GATEWAY's own upstream RBAC filter already permitted it to arrive
    /// here (Envoy invokes `ext_authz` only for requests its RBAC filter
    /// already let through the filter chain) — but that upstream permission
    /// carries NO authority over this service's own, independent N-AALP
    /// effect-class decision. A carriage object whose declared effect
    /// exceeds the signer's grant is denied (`EffectNotAuthorized`) even
    /// when a header explicitly (and, in a real deployment, untrustworthily)
    /// claims the gateway already decided "allow" — this service's decision
    /// depends on exactly the three documented `npamp-*` headers and nothing
    /// else forwarded alongside them. Mutated as M-svc-3 in RED-EVIDENCE.md.
    #[tokio::test]
    async fn conformance_gateway_rbac_permit_does_not_override_effect_exceeds_grant_denial() {
        let hook = TableAuthzHook::new("gateway-a", &[("signer-1", EffectClass::ReadOnly)]);
        let svc = ExtAuthzService::new(hook);
        let req = check_request(&[
            ("npamp-signer-id", "signer-1"),
            ("npamp-audience", "gateway-a"),
            ("npamp-effect", "3"), // Destructive: exceeds signer-1's ReadOnly grant
            ("x-rbac-decision", "allow"), // the gateway's own (irrelevant) upstream RBAC verdict
        ]);
        let resp = svc.check(req).await.expect("check must not error transport-side").into_inner();
        assert_eq!(
            rpc_code(&resp),
            RPC_CODE_PERMISSION_DENIED,
            "a gateway-RBAC-permitted call whose carriage object exceeds the N-AALP grant must still be denied (EffectNotAuthorized)"
        );
    }

    /// Case (b): an unrecognized effect-class value is treated as
    /// `Destructive`, never a lower/default class — already proven at the
    /// core (`nz_agent::waypoint`'s `M-waypoint-1` in that crate's own
    /// RED-EVIDENCE.md). `unrecognized_effect_value_is_denied_unless_signer_holds_destructive`
    /// below is this composition's named conformance test for case (b): it
    /// proves the WIRE ADAPTER correctly surfaces that core decision
    /// end-to-end (a gRPC deny), not merely that the core function computes
    /// it. Mutated at the adapter layer as M-svc-4 in RED-EVIDENCE.md (a
    /// fresh mutation in `extract.rs`, distinct from `M-waypoint-1`'s
    /// core-layer mutation in `waypoint.rs`).
    #[tokio::test]
    async fn unrecognized_effect_value_is_denied_unless_signer_holds_destructive() {
        let hook = TableAuthzHook::new("gateway-a", &[("signer-1", EffectClass::NonIdempotentWrite)]);
        let svc = ExtAuthzService::new(hook);
        let req = check_request(&[("npamp-signer-id", "signer-1"), ("npamp-audience", "gateway-a"), ("npamp-effect", "250")]);
        let resp = svc.check(req).await.expect("check must not error transport-side").into_inner();
        assert_eq!(rpc_code(&resp), RPC_CODE_PERMISSION_DENIED, "an unrecognized effect value (250) must decode to Destructive and be denied for a sub-Destructive grant");
    }

    /// Case (c): an agent JWT's `sub` claim, forwarded as
    /// `extract::JWT_SUB_HEADER` once the gateway's own JWT filter has
    /// verified the token, is FOREIGN-IDENTITY LINKAGE ONLY — it MUST NEVER
    /// substitute for, or elevate, the N-AALP authorization identity
    /// `npamp-signer-id` carries. A request naming a low-privilege
    /// `npamp-signer-id` but a high-privilege `sub` claim is decided on the
    /// low-privilege signer alone. Mutated as M-svc-5 in RED-EVIDENCE.md.
    #[tokio::test]
    async fn conformance_jwt_sub_is_foreign_identity_linkage_not_an_authz_identity() {
        let hook = TableAuthzHook::new("gateway-a", &[("low-priv-signer", EffectClass::ReadOnly), ("admin", EffectClass::Destructive)]);
        let svc = ExtAuthzService::new(hook);
        let req = check_request(&[
            ("npamp-signer-id", "low-priv-signer"),
            ("npamp-audience", "gateway-a"),
            ("npamp-effect", "3"), // Destructive
            (crate::extract::JWT_SUB_HEADER, "admin"), // a verified JWT's sub — NOT the authz identity
        ]);
        let resp = svc.check(req).await.expect("check must not error transport-side").into_inner();
        assert_eq!(
            rpc_code(&resp),
            RPC_CODE_PERMISSION_DENIED,
            "the JWT sub claim ('admin', a Destructive grant) must never substitute for npamp-signer-id ('low-priv-signer', a ReadOnly grant)"
        );
    }
}
