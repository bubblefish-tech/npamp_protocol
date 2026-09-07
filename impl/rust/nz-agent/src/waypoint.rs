// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! The optional per-namespace L7 waypoint (E2.7, R12 AC3): carriage
//! translation (the R10 transport set) + N-AALP effect-class/audience
//! authorization, for the ~20% of services that need L7 (the 80/20 rule).
//! Most workloads stay L4-only via [`crate::authz`] alone.
//!
//! # This module is now a thin re-export (relocated 2026-09-05)
//!
//! Every type and function this module used to define directly now lives in
//! the standalone [`nz_waypoint_core`] crate (`../nz-waypoint-core`) and is
//! `pub use`d back here unchanged — the public path `nz_agent::waypoint::*`
//! every existing caller uses (`nz-agent-extauthz`, `src/bin/
//! print_waypoint_grant_fixture.rs`, `gnapexport.go`'s cross-language JSON
//! contract) is byte-identical to before this move; only the code's HOME
//! changed, not its shape or behavior.
//!
//! **Why:** E2.7/R12 AC3 names TWO hosting shapes for this waypoint — "an
//! Envoy proxy-wasm N-PAMP filter and/or an agentgateway backend". This
//! crate (`nz-agent`) cannot cross-compile to `wasm32-unknown-unknown` (its
//! `spire_client`/`telemetry` modules pull in `tonic`/`tokio`
//! `rt-multi-thread`/`hyper-util`, none of which a wasm32 proxy-wasm module
//! can use), so the proxy-wasm hosting shape (`../nz-waypoint-wasm`) is a
//! SEPARATE crate. Extracting the pure authorization/carriage-dispatch logic
//! into `nz-waypoint-core` — which depends on nothing but
//! `serde`/`serde_json` — lets BOTH hosting shapes compose the exact SAME
//! decision instead of maintaining two independently-drifting copies of a
//! security-relevant authorization rule (the same anti-duplication
//! discipline the original `resolved_max_grant` helper's own doc comment
//! already argued for one layer down). See `nz-waypoint-core/src/lib.rs`'s
//! module docs for the full grounding text (N-AALP effect-class lattice,
//! audience field, etc. — carried over unchanged) and
//! `nz-waypoint-core/RED-EVIDENCE.md` for the fresh mutation-witness of the
//! fail-closed property this move staled.
//!
//! This module (`nz-agent::waypoint`) remains the composable core the
//! NATIVE hosting shape calls into, matching the design doc's "this is
//! where N-PAMP becomes the PQC transport under agentgateway" framing (R14
//! shares this same composable core, it does not reimplement it).

pub use nz_waypoint_core::{
    authorize, classify, AuthzHook, CarriageClass, EffectClass, ResolvedWaypointGrant, TableAuthzHook, TransportHint, WaypointDenied,
    resolve_grant_for_export,
};
