// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! `nz-agent-extauthz` — N-PAMP R14-Unit-A: an external-authorization
//! (ext_authz) gRPC service that lets an agent gateway (agentgateway / any
//! Envoy-`ext_authz`-v3-compatible proxy) delegate per-request
//! authorization to `nz-agent`'s already-built, mutation-tested,
//! fail-closed [`nz_agent::waypoint::authorize`] core.
//!
//! # What this crate builds vs. what it composes
//!
//! This crate builds ONLY the ext_authz wire adapter: [`pb`] (the
//! grounded, minimal `envoy.service.auth.v3`-subset gRPC service, codegen'd
//! from `proto/ext_authz.proto` — see that file's header comment for
//! sourcing), [`extract`] (the documented N-PAMP-triple-from-HTTP-headers
//! mapping), and [`service`] (the `Authorization` gRPC service impl that
//! wires the two together). **It does not reimplement the authorization
//! decision.** Every allow/deny this service returns is the direct result
//! of calling `nz_agent::waypoint::authorize` — a decision already built
//! and mutation-tested in `../nz-agent/src/waypoint.rs` (`RED-EVIDENCE.md`
//! in that crate). A bug fix to the authorization RULE (e.g. what counts as
//! "exceeds grant") is made exactly once, in `waypoint.rs`; this crate
//! cannot drift from it because it has no authorization logic of its own to
//! drift.
//!
//! # Tracked gap: the real `AuthzHook`
//!
//! [`service::ExtAuthzService`] is generic over any
//! `nz_agent::waypoint::AuthzHook` implementation. This build ships and
//! tests against `nz_agent::waypoint::TableAuthzHook` (an in-memory test
//! double, already built in `nz-agent`) — matching that crate's own
//! documented posture ("this build ships a fail-closed default and a
//! table-based test double, not a cross-repo client to the (Go) N-AALP
//! policy engine", `waypoint.rs` module docs). A real deployment supplies
//! its own `AuthzHook` (backed by N-AALP's policy engine, a config file, a
//! database, ...) — the seam is this trait, not a stub inside this crate.

pub mod extract;
pub mod service;

/// Generated gRPC code for `npamp.extauthz.v1` (from `proto/ext_authz.proto`
/// via `build.rs` — protox + tonic-prost-build, no `protoc` binary needed;
/// see `build.rs`'s header comment).
pub mod pb {
    tonic::include_proto!("npamp.extauthz.v1");
}

pub use service::ExtAuthzService;
