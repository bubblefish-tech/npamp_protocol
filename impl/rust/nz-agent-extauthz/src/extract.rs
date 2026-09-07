// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! Extracts the N-PAMP authorization triple `(signer_id, audience,
//! object_effect)` from an ext_authz `CheckRequest`'s HTTP request headers.
//!
//! # This module is now a thin re-export (relocated 2026-09-05)
//!
//! `extract_triple`/`TripleExtractError`/the three header-name consts now
//! live in [`nz_waypoint_core::extract`] and are `pub use`d back here
//! unchanged — the public path `nz_agent_extauthz::extract::*` this crate's
//! own `service.rs` uses is byte-identical to before this move. **Why:**
//! `nz-waypoint-wasm`'s Envoy proxy-wasm filter (E2.7's other named hosting
//! shape) reads the exact same three headers off a request, so both hosting
//! shapes now share ONE fail-closed extraction rule instead of maintaining
//! two independently-driftable copies of it. See
//! `nz-waypoint-core/src/extract.rs`'s module docs for the full grounding
//! text (the documented header mapping, the R14-Unit-A design decision,
//! and the "never trust unauthenticated transport metadata" caveat, all
//! carried over unchanged).

pub use nz_waypoint_core::extract::{extract_triple, TripleExtractError, AUDIENCE_HEADER, EFFECT_HEADER, JWT_SUB_HEADER, SIGNER_HEADER};
