// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! P2.5 Option B1 fixture generator: constructs a resolved
//! [`nz_agent::waypoint::ResolvedWaypointGrant`] via
//! [`nz_agent::waypoint::resolve_grant_for_export`] (the SAME function a real nz-agent
//! deployment would call, over the SAME [`nz_agent::waypoint::AuthzHook`] seam), serializes
//! it with [`nz_agent::waypoint::ResolvedWaypointGrant::to_json`], and prints EXACTLY that
//! JSON to stdout — nothing else.
//!
//! This is the mechanism that produces the REAL, Rust-run cross-language fixture at
//! `testdata/waypoint_grant.json` (this crate) — copied byte-for-byte to
//! `impl/go/ecosystem/npamp-gnap/testdata/waypoint_grant.json` — rather than a JSON string
//! hand-typed once on each side of the language boundary. Run it with:
//!
//! ```text
//! cargo run --quiet --bin print-waypoint-grant-fixture > testdata/waypoint_grant.json
//! ```
//!
//! The grant values here are the SAME ones `gnapexport_test.go`'s
//! `TestExportWaypointEvidenceWithinCeilingSucceeds` already exercises on the Go side
//! (`signer_id: "agent-b"`, `consuming_authority: "gateway-a"`,
//! `max_grant: NonIdempotentWrite`) — so the fixture doubles as the exact input the Go
//! round-trip test decodes and re-checks against a REQUESTED effect within, and one above,
//! that ceiling.

use nz_agent::waypoint::{resolve_grant_for_export, EffectClass, TableAuthzHook};

fn main() {
    let hook = TableAuthzHook::new("gateway-a", &[("agent-b", EffectClass::NonIdempotentWrite)]);
    let grant = resolve_grant_for_export(&hook, "agent-b");
    let json = grant.to_json().expect("ResolvedWaypointGrant of a plain string triple must always serialize");
    println!("{json}");
}
