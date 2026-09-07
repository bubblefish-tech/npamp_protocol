// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! The Envoy proxy-wasm N-PAMP filter -- E2.7/R12 AC3's other named L7
//! waypoint hosting shape (the sibling to `nz-agent::waypoint`, the native
//! hosting shape). Composes `nz-waypoint-core`'s EXISTING
//! `classify()`/`authorize()`/`extract_triple()` via the official
//! `proxy-wasm-rust-sdk` (crates.io `proxy-wasm` 0.2.5) -- does not
//! reimplement any of that logic; see `../nz-agent/src/waypoint.rs` and
//! `../nz-waypoint-core`'s own docs for the shared core both hosting
//! shapes compose.

// On the HOST target (`cargo build`/`cargo test`, no target-triple flag),
// `mod filter` below does not exist (wasm32-only), so `config`/`decision`'s
// pub items have no in-crate caller and would otherwise warn dead_code —
// they ARE used, by `mod filter`, on the wasm32-unknown-unknown target this
// crate actually ships for. Silence the host-only false positive rather
// than un-pub the items (which would break the wasm32 build) or add a fake
// host-side caller (which would be scaffolding).
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

mod config;
mod decision;

// ---------------------------------------------------------------------
// The proxy-wasm ABI glue below is compiled ONLY for wasm32-unknown-unknown
// (`cargo build --target wasm32-unknown-unknown`). `proxy-wasm`'s
// `hostcalls` module declares `extern "C"` functions (`proxy_log`,
// `proxy_get_header_map_value`, ...) that the WASM HOST (Envoy) supplies as
// wasm imports at runtime — on the native host target (what `cargo test`
// builds by default) nothing provides those symbols, so a test binary that
// links this code fails at LINK time (`unresolved external symbol
// proxy_log`, confirmed this session — not a hypothetical). Gating this
// block to wasm32 is the standard way a proxy-wasm crate keeps its ABI
// glue separate from its host-testable pure logic (`config.rs`/
// `decision.rs`, which have no `#[cfg]` gate and run under plain
// `cargo test`) — see this crate's RED-EVIDENCE.md for the confirmed link
// error and why this shape is not a workaround but the correct one.
// ---------------------------------------------------------------------
#[cfg(target_arch = "wasm32")]
mod filter {

use std::collections::HashMap;
use std::rc::Rc;

use nz_waypoint_core::extract::{AUDIENCE_HEADER, EFFECT_HEADER, SIGNER_HEADER};
use nz_waypoint_core::TableAuthzHook;
use proxy_wasm::traits::{Context, HttpContext, RootContext};
use proxy_wasm::types::{Action, ContextType, LogLevel};

use crate::config::parse_config;
use crate::decision::evaluate_request;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(WaypointRoot::default()) });
}}

/// The proxy-wasm `RootContext`: owns the ONE [`TableAuthzHook`] every
/// `HttpContext` this VM spawns shares via [`Rc`] (a proxy-wasm VM instance
/// is single-threaded per the ABI's own execution model, so a plain
/// reference count is correct here — no `Mutex`/`Arc` needed). This is the
/// ONLY new state this crate introduces; the DECISION the hook feeds is
/// entirely [`nz_waypoint_core::authorize`]'s (composed, never
/// reimplemented).
struct WaypointRoot {
    hook: Rc<TableAuthzHook>,
}

impl Default for WaypointRoot {
    /// Before `on_configure` ever runs (or if it never receives a plugin
    /// configuration at all), this waypoint has consuming_authority `""`
    /// and zero grants — fail-closed: `authorize` denies every real object
    /// with `WrongAudience` against an empty consuming authority, rather
    /// than defaulting to an ALLOWING configuration.
    fn default() -> Self {
        WaypointRoot { hook: Rc::new(TableAuthzHook::new("", &[])) }
    }
}

impl Context for WaypointRoot {}

impl RootContext for WaypointRoot {
    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        let bytes = self.get_plugin_configuration().unwrap_or_default();
        let (consuming_authority, grants) = parse_config(&bytes);
        let grants_ref: Vec<(&str, _)> = grants.iter().map(|(k, v)| (k.as_str(), *v)).collect();
        self.hook = Rc::new(TableAuthzHook::new(&consuming_authority, &grants_ref));
        true
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(WaypointFilter { hook: Rc::clone(&self.hook) }))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

/// The proxy-wasm `HttpContext`: a thin ABI adapter around
/// [`crate::decision::evaluate_request`] — reads the three N-PAMP authorization
/// headers plus `content-type` off the live request via the SDK's own
/// `get_http_request_header` hostcall, hands them to the pure decision
/// function, and translates the `Result` into either `Action::Continue`
/// (request proceeds, tagged with its resolved carriage class) or an
/// immediate `403` response via `send_http_response` (`Action::Pause`).
/// This struct and its trait impl are the ONE part of this crate that
/// cannot be unit-tested without a live Envoy/wasm host — see this crate's
/// `RED-EVIDENCE.md` for that named residual and its concrete workaround.
struct WaypointFilter {
    hook: Rc<TableAuthzHook>,
}

impl Context for WaypointFilter {}

impl HttpContext for WaypointFilter {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        let mut headers = HashMap::new();
        for name in [SIGNER_HEADER, AUDIENCE_HEADER, EFFECT_HEADER] {
            if let Some(v) = self.get_http_request_header(name) {
                headers.insert(name.to_string(), v);
            }
        }
        let content_type = self.get_http_request_header("content-type");

        match evaluate_request(self.hook.as_ref(), &headers, content_type.as_deref()) {
            Ok(carriage) => {
                self.add_http_request_header("x-npamp-carriage-class", &carriage.to_string());
                Action::Continue
            }
            Err(denied) => {
                let body = denied.to_string();
                self.send_http_response(403, vec![("content-type", "text/plain")], Some(body.as_bytes()));
                Action::Pause
            }
        }
    }
}

} // mod filter
