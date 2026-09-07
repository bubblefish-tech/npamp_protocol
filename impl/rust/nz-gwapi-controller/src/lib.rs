// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! `nz-gwapi-controller` -- the E2.7c Gateway-API/GAMMA control-plane
//! wiring named as an unbuilt gap by `nz-agent/src/lib.rs`'s own R12 AC4
//! module docs: *"no Kubernetes controller reads Gateway API
//! HTTPRoute/Backend/GAMMA-Mesh CRDs and configures nz-agent/AuthzTable/
//! PeerDirectory from them. The AuthzTable/PeerDirectory population seams
//! this build DOES ship (allow/register, and the CLI's
//! --allow/--register-peer) are exactly what such a controller would call
//! -- a control-plane binding onto those seams is unbuilt, not merely
//! untested."* This crate is that binding.
//!
//! # What this crate reads (verified against the primary source, not from
//! memory -- E8)
//!
//! `HTTPRoute` (`gateway.networking.k8s.io/v1`) is the ONLY Gateway-API CRD
//! this crate watches. Per <https://gateway-api.sigs.k8s.io/docs/mesh/mesh-overview/>
//! (fetched 2026-09-05), a GAMMA mesh-attached `HTTPRoute` names a
//! `spec.parentRefs[]` entry with `kind: Service` (the mesh workload this
//! route governs), and `spec.rules[].backendRefs[]` name the Service(s)
//! traffic is routed to. The SAME fetch confirms: *"[the spec] does not
//! explicitly address how source/client identity or authorization is
//! expressed... these aspects appear to be intentionally left to separate
//! implementations."* This crate's [`plan`] module documents, explicitly,
//! the POLICY DECISION it makes to fill that gap -- it does not claim that
//! decision is normative Gateway-API text.
//!
//! Per R12 AC4 ("Gateway-API/GAMMA-Mesh-profile native, no bespoke CRDs"),
//! this crate defines NO new CRD kind. The one extension it needs --
//! publishing a workload's SVID public key and its N-AALP max-effect grant
//! for the [`AuthzHook`](nz_waypoint_core::AuthzHook) seam -- is carried as
//! two ANNOTATIONS on the standard core `v1/Service` object each `HTTPRoute`
//! already references (`npamp.bubblefish.io/svid-pubkey-hex` and
//! `npamp.bubblefish.io/max-effect-class`), never a new CRD.
//!
//! # Module map
//!
//! | Module | Job |
//! |---|---|
//! | [`types`] | The minimal, hand-typed subset of the `HTTPRoute` v1 schema this crate parses (parentRefs/rules/backendRefs only -- not the full spec: no filters, matches, or timeouts) |
//! | [`plan`] | The PURE, unit-tested reconcile-mapping core: `HTTPRoute` + Service-annotation inputs -> the exact seam calls (`AuthzTable::allow`, `PeerDirectory::register`, an L7 max-effect grant) a real cluster state implies. No I/O, no kube-rs dependency -- this is what the UNIT tier grades. |
//! | [`controller`] | The REAL kube-rs wiring: a `kube::Client` + `kube::runtime::watcher` list+watch loop over `HTTPRoute` (as a [`kube::core::DynamicObject`]) and `Service` that recomputes [`plan::DesiredState`] on every change and atomically swaps it into a shared `Arc<Mutex<..>>` -- rebuild-and-swap, not incremental mutation, so a deleted `HTTPRoute` removes its allow-pairs on the very next reconcile rather than leaking them forever. |
//!
//! # Why rebuild-and-swap, not incremental `.allow()`/`.revoke()` calls
//!
//! `AuthzTable`/`PeerDirectory` are fail-closed BY CONSTRUCTION: a fresh
//! table denies everything (see `nz-agent/src/authz.rs`'s own module docs).
//! An incremental reconciler that only ever calls `.allow()` on a new/changed
//! `HTTPRoute` and never revokes a DELETED one would drift towards
//! fail-OPEN over the cluster's lifetime -- exactly the security regression
//! this codebase's fail-closed discipline exists to prevent. Recomputing the
//! FULL desired state from ALL currently-known `HTTPRoute` objects on every
//! event, then swapping the whole table/directory/grant-list at once, makes
//! "an `HTTPRoute` was deleted" and "an `HTTPRoute` was never created"
//! indistinguishable to the seams -- which is the correct, fail-closed
//! answer.
//!
//! # What this build does NOT do (named non-scope, not a silent gap)
//!
//! This crate constructs and OWNS a live `AuthzTable`/`PeerDirectory`/grant
//! list IN ITS OWN PROCESS, kept in sync with cluster state. It does not
//! open a cross-process IPC channel to push that state into a SEPARATELY
//! running `nz-agent` data-plane process -- `nz-agent`'s CLI (`src/bin/
//! nz_agent.rs`) currently only self-populates its own in-process tables
//! once, from flags, at startup; there is no existing live-reload RPC/API on
//! that process for this crate to call into. Building that cross-process
//! channel is a separate, larger change to `nz-agent` itself, not invented
//! here as a stub. What this crate delivers is real: the exact translation
//! from real Gateway-API cluster state to the exact seam calls, running a
//! real reconcile loop against a real Kubernetes API, with the resulting
//! `AuthzTable`/`PeerDirectory`/grant state live and queryable in this
//! process (see [`controller::SharedState`]).

pub mod controller;
pub mod plan;
pub mod types;
