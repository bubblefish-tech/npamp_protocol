// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! The pure, target-agnostic core of the N-PAMP R12/E2.7 optional L7
//! waypoint: carriage translation (the R10 transport set) + N-AALP
//! effect-class/audience authorization. Extracted 2026-09-05 from
//! `nz-agent/src/waypoint.rs` so that BOTH hosting shapes R12 AC3 names —
//! an **Envoy proxy-wasm N-PAMP filter** (`nz-waypoint-wasm`, this crate
//! compiled to `wasm32-unknown-unknown`) and the native `nz-agent` L7
//! waypoint (`nz-agent::waypoint`, which now `pub use`s this crate rather
//! than reimplementing it) — compose the exact SAME authorization decision.
//! No hosting shape reimplements or forks this logic.
//!
//! # Why this crate has no I/O, no async runtime, no OS dependency
//!
//! `nz-agent` itself cannot cross-compile to `wasm32-unknown-unknown`: its
//! `spire_client`/`telemetry` modules pull in `tonic`/`tokio`
//! (`rt-multi-thread` needs OS threads) and `hyper-util` (needs sockets),
//! none of which a `wasm32-unknown-unknown` proxy-wasm module can use. This
//! crate depends on nothing but `serde`/`serde_json` (pure Rust, no
//! OS/libc dependency) precisely so it CAN be the shared dependency of both
//! `nz-agent` (native) and `nz-waypoint-wasm` (`wasm32-unknown-unknown`).
//!
//! # N-AALP effect-class/audience grounding (from the authoritative N-AALP
//! draft, not from memory — carried over unchanged from the original
//! `nz-agent/src/waypoint.rs` module docs)
//!
//! [`EffectClass`] mirrors the four-value lattice `draft-bubblefish-naalp-01`
//! defines (`ietf/draft-bubblefish-naalp-01.md`):
//! `read_only(0) < idempotent_write(1) < non_idempotent_write(2) <
//! destructive(3)`, with **"An unrecognized effect value MUST be treated as
//! destructive and MUST NOT fail open"** — [`EffectClass::from_wire`]
//! implements exactly that rule. `audience` mirrors N-AALP's field 13: "names
//! the one endpoint or channel-scope identity an object is bound to... An
//! object whose audience is not the checking authority... is rejected
//! WrongAudience." This crate does NOT depend on the N-AALP repository (a
//! separate protocol, a separate Go codebase); [`EffectClass`] and
//! [`AuthzHook`] are this crate's own local, composable representation of
//! that authorization shape — the seam a real cross-protocol N-AALP policy
//! client would implement (tracked gap).

use std::fmt;

use serde::Serialize;

/// Header-based extraction of the `(signer_id, audience, object_effect)`
/// triple [`authorize`] decides over — shared by every hosting shape that
/// reads this triple off a request's headers (`nz-agent-extauthz`'s
/// ext_authz gRPC service and `nz-waypoint-wasm`'s Envoy proxy-wasm filter).
pub mod extract;

/// N-AALP's effect-class lattice (grounded from `draft-bubblefish-naalp-01`
/// — see crate docs). Ordered top-to-bottom by authority required:
/// `Destructive` is the top of the lattice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EffectClass {
    ReadOnly = 0,
    IdempotentWrite = 1,
    NonIdempotentWrite = 2,
    Destructive = 3,
}

impl EffectClass {
    /// Decodes a wire effect-class octet per N-AALP's own fail-closed rule:
    /// an unrecognized value is `Destructive`, never a silent default to the
    /// LEAST-privileged class (which would fail OPEN — the exact mistake the
    /// draft calls out). This is the one place this crate's local
    /// representation MUST match the cited normative text exactly.
    pub fn from_wire(v: u8) -> EffectClass {
        match v {
            0 => EffectClass::ReadOnly,
            1 => EffectClass::IdempotentWrite,
            2 => EffectClass::NonIdempotentWrite,
            _ => EffectClass::Destructive, // includes 3 AND every unrecognized value
        }
    }
}

impl fmt::Display for EffectClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            EffectClass::ReadOnly => "read_only",
            EffectClass::IdempotentWrite => "idempotent_write",
            EffectClass::NonIdempotentWrite => "non_idempotent_write",
            EffectClass::Destructive => "destructive",
        };
        write!(f, "{s}")
    }
}

/// Serializes as the SAME lowercase snake_case token [`fmt::Display`] emits (`"read_only"`,
/// `"destructive"`, ...) — not the underlying discriminant integer. This is the P2.5
/// Option B1 wire representation: it matches
/// `impl/go/ecosystem/npamp-gnap/gnapexport.go`'s `EffectClass.String()` output exactly, so
/// the SAME token set both languages already use for the OUTPUT `WaypointAssertionPayload`
/// (`effect`/`max_grant` fields) is reused for the INPUT transport, rather than inventing a
/// second (e.g. integer) encoding only Go's `EffectClassFromWire` would need a new decode
/// path for. A manual `impl` (not `#[derive(Serialize)]`) so this is provably the one
/// `Display` string, not a second, independently-maintained copy of it.
impl Serialize for EffectClass {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

/// Why the waypoint refused an object — named per the specific rule
/// violated, mirroring N-AALP's own named rejections (`WrongAudience`,
/// and the max-grant-exceeded case this crate's local authz adds).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WaypointDenied {
    /// The object's `audience` does not name this waypoint's own consuming
    /// authority (N-AALP `WrongAudience`, field 13).
    WrongAudience { object_audience: String, expected: String },
    /// The object's effect class exceeds the signer id's max-effect grant
    /// (R14 AC3's "a carriage object's declared effect SHALL NOT exceed the
    /// gateway signer id's max-effect grant"; this crate applies the same
    /// rule at the R12 waypoint).
    EffectExceedsGrant { object_effect: EffectClass, max_grant: EffectClass },
}

impl fmt::Display for WaypointDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WaypointDenied::WrongAudience { object_audience, expected } => {
                write!(f, "nz-waypoint-core: WrongAudience (object names {object_audience:?}, this waypoint is {expected:?})")
            }
            WaypointDenied::EffectExceedsGrant { object_effect, max_grant } => {
                write!(f, "nz-waypoint-core: effect {object_effect} exceeds max grant {max_grant}")
            }
        }
    }
}

impl std::error::Error for WaypointDenied {}

/// The seam a real N-AALP policy client implements. This build ships
/// [`TableAuthzHook`] (a deterministic in-memory test double) and the
/// fail-closed [`authorize`] function every hook implementation is checked
/// against — no hook implementation, however it fetches `max_grant`, can
/// bypass the effect-exceeds-grant or wrong-audience checks, because those
/// are enforced by [`authorize`] itself, not by the hook.
pub trait AuthzHook {
    /// Returns the max-effect grant for `signer_id`, or `None` if the signer
    /// is not recognized at all (treated identically to a grant of
    /// [`EffectClass::ReadOnly`]-or-below by [`authorize`]'s caller — i.e. an
    /// unrecognized signer authorizes nothing above read-only, never
    /// everything).
    fn max_grant_for_signer(&self, signer_id: &str) -> Option<EffectClass>;
    /// This waypoint's own consuming-authority identity, checked against an
    /// object's `audience` field.
    fn consuming_authority(&self) -> &str;
}

/// The one authorization decision this module makes, composed from
/// [`AuthzHook`]: reject `WrongAudience` if `audience` does not match
/// `hook.consuming_authority()`, and reject if `object_effect` exceeds
/// `signer_id`'s max grant (an unrecognized signer is denied everything
/// above [`EffectClass::ReadOnly`], matching N-AALP's fail-closed posture —
/// never derived from transport metadata, per the cited draft text).
pub fn authorize<H: AuthzHook>(hook: &H, signer_id: &str, audience: &str, object_effect: EffectClass) -> Result<(), WaypointDenied> {
    if audience != hook.consuming_authority() {
        return Err(WaypointDenied::WrongAudience { object_audience: audience.to_string(), expected: hook.consuming_authority().to_string() });
    }
    let max_grant = resolved_max_grant(hook, signer_id);
    if object_effect > max_grant {
        return Err(WaypointDenied::EffectExceedsGrant { object_effect, max_grant });
    }
    Ok(())
}

/// The ONE place `signer_id`'s effective ceiling is computed from
/// [`AuthzHook::max_grant_for_signer`] — an unrecognized signer defaults to
/// [`EffectClass::ReadOnly`] (never to everything). Shared by [`authorize`] and
/// [`resolve_grant_for_export`] so the two can never drift apart on what "unrecognized
/// signer" means: before this function existed, that default lived twice (once in
/// `authorize`, and it would have been re-typed a second time in
/// `resolve_grant_for_export` below) — exactly the kind of duplicated security-relevant
/// default this crate's own N-AALP fail-closed grounding warns against re-deriving from
/// memory in two places.
fn resolved_max_grant<H: AuthzHook>(hook: &H, signer_id: &str) -> EffectClass {
    hook.max_grant_for_signer(signer_id).unwrap_or(EffectClass::ReadOnly)
}

// ---------------------------------------------------------------------------
// P2.5 Option B1: the shared-JSON cross-language transport (maintainer-approved
// 2026-09-02) — see impl/go/ecosystem/npamp-gnap/gnapexport.go's file header for the two
// options this closes the gap between. This crate serializes the resolved
// (signer_id, consuming_authority, max_grant) triple as JSON over an existing
// process/IPC/admin-API boundary; the Go side independently RE-CHECKS it
// (ExportWaypointEvidence never trusts a caller's own pass/fail verdict) rather than
// trusting this JSON as an authority-carrying assertion by itself.
// ---------------------------------------------------------------------------

/// The wire-serializable counterpart of an [`AuthzHook`]-resolved grant: exactly the three
/// fields `impl/go/ecosystem/npamp-gnap/gnapexport.go`'s `WaypointGrant` (the DOCUMENTED
/// Go-side input shape) already declares it needs, field-named to match
/// `WaypointAssertionPayload`'s existing JSON convention
/// (`signer_id`/`audience`/`effect`/`max_grant`) rather than inventing a new one:
/// `signer_id` and `max_grant` reuse those exact names, and `consuming_authority` reuses
/// the exact Rust-side name `AuthzHook::consuming_authority` and
/// `WaypointDenied::WrongAudience`'s own field already use (Go's `WaypointGrant` field of
/// the same role is itself named `ConsumingAuthority`, not `Audience` — `Audience` on the
/// Go side names something ELSE: the per-export REQUESTED audience `ExportWaypointEvidence`
/// checks the grant against, not the grant's own field. Reusing `Audience` here would
/// therefore be a false-cognate, not a match.).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedWaypointGrant {
    pub signer_id: String,
    pub consuming_authority: String,
    pub max_grant: EffectClass,
}

impl ResolvedWaypointGrant {
    /// The Option B1 wire encoding: `serde_json`'s default (compact) object serialization
    /// of this struct's three fields, in declaration order. Not pretty-printed — the Go
    /// side decodes with `encoding/json`, which does not care about whitespace, and a
    /// compact encoding is what the fixture generator (`nz-agent`'s `src/bin/
    /// print_waypoint_grant_fixture.rs`) actually emits.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }
}

/// Resolves `signer_id`'s grant against `hook` into the wire-serializable
/// [`ResolvedWaypointGrant`] Option B1 sends to Go — using the SAME unrecognized-signer
/// default ([`resolved_max_grant`]) [`authorize`] itself uses, so a grant this function
/// exports always matches what a LOCAL call to `authorize` for the same `(signer_id,
/// hook.consuming_authority())` pair would actually allow.
pub fn resolve_grant_for_export<H: AuthzHook>(hook: &H, signer_id: &str) -> ResolvedWaypointGrant {
    ResolvedWaypointGrant {
        signer_id: signer_id.to_string(),
        consuming_authority: hook.consuming_authority().to_string(),
        max_grant: resolved_max_grant(hook, signer_id),
    }
}

/// A deterministic in-memory [`AuthzHook`] test double: a fixed
/// `signer_id -> EffectClass` grant table plus a fixed consuming-authority
/// string. NOT for production (a real deployment's grants come from N-AALP's
/// own policy engine, cross-repo — the tracked gap this module's docs name).
pub struct TableAuthzHook {
    grants: std::collections::HashMap<String, EffectClass>,
    consuming_authority: String,
}

impl TableAuthzHook {
    pub fn new(consuming_authority: &str, grants: &[(&str, EffectClass)]) -> TableAuthzHook {
        TableAuthzHook {
            grants: grants.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
            consuming_authority: consuming_authority.to_string(),
        }
    }
}

impl AuthzHook for TableAuthzHook {
    fn max_grant_for_signer(&self, signer_id: &str) -> Option<EffectClass> {
        self.grants.get(signer_id).copied()
    }
    fn consuming_authority(&self) -> &str {
        &self.consuming_authority
    }
}

// ---------------------------------------------------------------------------
// Carriage-class translation dispatch (R10's transport set, R12 AC3).
// ---------------------------------------------------------------------------

/// The five N-PAMP carriage classes the waypoint dispatches into (companion
/// specs 20-25, exact names `NPAMP-CC-*` — verified against
/// `spec/companion/{20_carriage_jsonrpc,21_carriage_http,22_carriage_messaging,
/// 23_carriage_streaming,25_carriage_opaque}.md`; this module adds no new
/// carriage class and defines no new wire bytes for any of them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarriageClass {
    /// `NPAMP-CC-HTTP` — HTTP-Semantics Carriage Class.
    Http,
    /// `NPAMP-CC-JSONRPC` — JSON-RPC 2.0 Carriage Class (MCP/A2A, both the
    /// Streamable-HTTP and stdio-local bindings: both carry the same
    /// JSON-RPC 2.0 message shape, so both dispatch to this one class).
    JsonRpc,
    /// `NPAMP-CC-MSG` — Messaging/Performative Carriage Class.
    Msg,
    /// `NPAMP-CC-STREAM` — Streaming Carriage Class.
    Stream,
    /// `NPAMP-CC-OPAQUE` — Opaque Carriage Class.
    Opaque,
}

impl fmt::Display for CarriageClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            CarriageClass::Http => "NPAMP-CC-HTTP",
            CarriageClass::JsonRpc => "NPAMP-CC-JSONRPC",
            CarriageClass::Msg => "NPAMP-CC-MSG",
            CarriageClass::Stream => "NPAMP-CC-STREAM",
            CarriageClass::Opaque => "NPAMP-CC-OPAQUE",
        };
        write!(f, "{s}")
    }
}

/// What a workload's traffic identifies itself as, before carriage
/// classification — the R10/R12 "full agent-transport set" (requirements.md
/// R10 AC1): HTTP/1.1+2, Streamable-HTTP+JSON-RPC (MCP/A2A), gRPC,
/// WebSocket, stdio (local MCP), raw TCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportHint {
    Http11,
    Http2,
    StreamableHttpJsonRpc,
    Grpc,
    WebSocket,
    StdioJsonRpc,
    RawTcp,
}

/// Dispatches a [`TransportHint`] to the [`CarriageClass`] that carries it.
/// Fail-closed by construction: this is a `match` over the closed
/// `TransportHint` enum, so every hint has exactly one class — there is no
/// "unrecognized transport" case to default anywhere (an unrecognized
/// transport simply cannot construct a `TransportHint` in the first place).
pub fn classify(hint: TransportHint) -> CarriageClass {
    match hint {
        TransportHint::Http11 | TransportHint::Http2 => CarriageClass::Http,
        TransportHint::StreamableHttpJsonRpc | TransportHint::StdioJsonRpc => CarriageClass::JsonRpc,
        TransportHint::Grpc => CarriageClass::Stream,
        TransportHint::WebSocket => CarriageClass::Msg,
        TransportHint::RawTcp => CarriageClass::Opaque,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effect_class_lattice_orders_destructive_at_top() {
        assert!(EffectClass::ReadOnly < EffectClass::IdempotentWrite);
        assert!(EffectClass::IdempotentWrite < EffectClass::NonIdempotentWrite);
        assert!(EffectClass::NonIdempotentWrite < EffectClass::Destructive);
    }

    /// The exact N-AALP rule this crate must not drift from: an unrecognized
    /// effect value fails CLOSED to Destructive, never open to ReadOnly.
    /// Mutated away by M-waypoint-core-1 in RED-EVIDENCE.md.
    #[test]
    fn unrecognized_effect_value_is_destructive_not_default() {
        for v in [4u8, 5, 200, 255] {
            assert_eq!(EffectClass::from_wire(v), EffectClass::Destructive, "value {v} must map to Destructive");
        }
        assert_eq!(EffectClass::from_wire(3), EffectClass::Destructive);
        assert_eq!(EffectClass::from_wire(0), EffectClass::ReadOnly);
    }

    #[test]
    fn wrong_audience_is_denied_before_effect_is_even_checked() {
        let hook = TableAuthzHook::new("gateway-a", &[("signer-1", EffectClass::Destructive)]);
        let err = authorize(&hook, "signer-1", "gateway-b", EffectClass::ReadOnly).expect_err("wrong audience must deny");
        assert!(matches!(err, WaypointDenied::WrongAudience { .. }));
    }

    #[test]
    fn effect_within_grant_is_allowed() {
        let hook = TableAuthzHook::new("gateway-a", &[("signer-1", EffectClass::NonIdempotentWrite)]);
        authorize(&hook, "signer-1", "gateway-a", EffectClass::IdempotentWrite).expect("within grant must be allowed");
    }

    /// R14 AC3 applied at the R12 waypoint: a declared effect above the
    /// signer's max grant is denied, never silently capped/allowed.
    #[test]
    fn effect_above_grant_is_denied() {
        let hook = TableAuthzHook::new("gateway-a", &[("signer-1", EffectClass::ReadOnly)]);
        let err = authorize(&hook, "signer-1", "gateway-a", EffectClass::Destructive).expect_err("above-grant must deny");
        assert_eq!(err, WaypointDenied::EffectExceedsGrant { object_effect: EffectClass::Destructive, max_grant: EffectClass::ReadOnly });
    }

    #[test]
    fn unrecognized_signer_grants_nothing_above_read_only() {
        let hook = TableAuthzHook::new("gateway-a", &[]);
        authorize(&hook, "unknown-signer", "gateway-a", EffectClass::ReadOnly).expect("read_only from an unknown signer is allowed (grant defaults to ReadOnly)");
        let err = authorize(&hook, "unknown-signer", "gateway-a", EffectClass::IdempotentWrite).expect_err("above-read-only must deny for an unrecognized signer");
        assert!(matches!(err, WaypointDenied::EffectExceedsGrant { .. }));
    }

    #[test]
    fn classify_maps_every_r10_transport_to_its_carriage_class() {
        assert_eq!(classify(TransportHint::Http11), CarriageClass::Http);
        assert_eq!(classify(TransportHint::Http2), CarriageClass::Http);
        assert_eq!(classify(TransportHint::StreamableHttpJsonRpc), CarriageClass::JsonRpc);
        assert_eq!(classify(TransportHint::StdioJsonRpc), CarriageClass::JsonRpc);
        assert_eq!(classify(TransportHint::Grpc), CarriageClass::Stream);
        assert_eq!(classify(TransportHint::WebSocket), CarriageClass::Msg);
        assert_eq!(classify(TransportHint::RawTcp), CarriageClass::Opaque);
    }

    #[test]
    fn carriage_class_display_matches_the_companion_spec_names() {
        assert_eq!(CarriageClass::Http.to_string(), "NPAMP-CC-HTTP");
        assert_eq!(CarriageClass::JsonRpc.to_string(), "NPAMP-CC-JSONRPC");
        assert_eq!(CarriageClass::Msg.to_string(), "NPAMP-CC-MSG");
        assert_eq!(CarriageClass::Stream.to_string(), "NPAMP-CC-STREAM");
        assert_eq!(CarriageClass::Opaque.to_string(), "NPAMP-CC-OPAQUE");
    }

    // ---- P2.5 Option B1: the shared-JSON wire contract -----------------------------------

    /// Pins the EXACT Option B1 wire shape both languages must agree on: field names and
    /// the `max_grant` string token. If a future refactor renames a field, or switches
    /// `max_grant` back to an integer discriminant, this test catches it — a name/shape
    /// drift here would silently break `gnapexport.go`'s `DecodeWaypointGrant`, which
    /// expects exactly this JSON.
    #[test]
    fn resolved_waypoint_grant_json_matches_the_pinned_wire_shape() {
        let grant = ResolvedWaypointGrant {
            signer_id: "agent-b".to_string(),
            consuming_authority: "gateway-a".to_string(),
            max_grant: EffectClass::NonIdempotentWrite,
        };
        let json = grant.to_json().expect("serialization must not fail for a plain string triple");
        assert_eq!(
            json,
            r#"{"signer_id":"agent-b","consuming_authority":"gateway-a","max_grant":"non_idempotent_write"}"#
        );
    }

    /// `max_grant` serializes as the Display token for EVERY EffectClass value, not just
    /// one — the fixture generator and `resolve_grant_for_export` may hand any of the four
    /// values to `to_json`, and a per-variant regression here is cheaper than one caught
    /// cross-language.
    #[test]
    fn resolved_waypoint_grant_max_grant_uses_the_display_token_for_every_effect_class() {
        let cases = [
            (EffectClass::ReadOnly, "read_only"),
            (EffectClass::IdempotentWrite, "idempotent_write"),
            (EffectClass::NonIdempotentWrite, "non_idempotent_write"),
            (EffectClass::Destructive, "destructive"),
        ];
        for (effect, want) in cases {
            let grant = ResolvedWaypointGrant { signer_id: "s".to_string(), consuming_authority: "c".to_string(), max_grant: effect };
            let json = grant.to_json().expect("serialization must not fail");
            let want_json = format!(r#"{{"signer_id":"s","consuming_authority":"c","max_grant":"{want}"}}"#);
            assert_eq!(json, want_json, "EffectClass::{effect:?} must serialize max_grant as {want:?}");
        }
    }

    /// `resolve_grant_for_export` must resolve the SAME ceiling `authorize` itself would
    /// enforce for the identical `(signer_id, hook.consuming_authority())` pair — the
    /// property that makes the exported grant trustworthy input to Go's independent
    /// re-check, not merely a plausible-looking JSON blob.
    #[test]
    fn resolve_grant_for_export_matches_what_authorize_would_actually_allow() {
        let hook = TableAuthzHook::new("gateway-a", &[("signer-1", EffectClass::NonIdempotentWrite)]);
        let exported = resolve_grant_for_export(&hook, "signer-1");
        assert_eq!(exported.signer_id, "signer-1");
        assert_eq!(exported.consuming_authority, "gateway-a");
        assert_eq!(exported.max_grant, EffectClass::NonIdempotentWrite);

        // authorize() allows exactly up to exported.max_grant, and denies one step above it.
        authorize(&hook, "signer-1", "gateway-a", exported.max_grant).expect("authorize must allow exactly the exported ceiling");
        let err = authorize(&hook, "signer-1", "gateway-a", EffectClass::Destructive).expect_err("authorize must deny above the exported ceiling");
        assert!(matches!(err, WaypointDenied::EffectExceedsGrant { .. }));
    }

    /// An unrecognized signer resolves to `ReadOnly`, matching `authorize`'s own
    /// unrecognized-signer default (`resolved_max_grant`) — never a wider, undisclosed
    /// ceiling exported to a process outside this crate's trust boundary.
    #[test]
    fn resolve_grant_for_export_unrecognized_signer_defaults_to_read_only() {
        let hook = TableAuthzHook::new("gateway-a", &[]);
        let exported = resolve_grant_for_export(&hook, "never-seen");
        assert_eq!(exported.max_grant, EffectClass::ReadOnly);
    }
}
