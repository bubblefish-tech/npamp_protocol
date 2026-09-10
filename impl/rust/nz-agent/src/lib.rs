// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! `nz-agent` — the N-PAMP per-node / ambient post-quantum data-plane agent
//! (Part-2 R12, tasks E2.5-E2.8; design: AMBIENT-DEPLOYMENT-DESIGN.md).
//!
//! # What this crate is
//!
//! A per-node, ztunnel-analogue L4 data-plane agent: one `nz-agent` process per
//! Kubernetes node terminates/originates N-PAMP hybrid-PQC sessions on behalf of
//! every workload on that node, in place of the workload running its own N-PAMP
//! stack (or, at the on-ramp rung R10, its own sidecar). It composes the existing
//! `npamp` crate's [`npamp::session::Session`] — the crate's own KAT-pinned,
//! red-evidenced handshake + AEAD record layer — for every cryptographic
//! operation. **This crate contains no handshake code, no KEM code, and no AEAD
//! code of its own**; it owns only the node-local plumbing the design doc scopes
//! to R12: traffic capture, node-to-node tunnel multiplexing, per-workload
//! (per-SVID) identity binding and session-key isolation, node-local L4
//! authorization, and an optional L7 waypoint's carriage-translation /
//! authorization dispatch.
//!
//! # Module map (mirrors the four E2.5-E2.8 tasks)
//!
//! | Module | Task | Design-doc component |
//! |---|---|---|
//! | [`tunnel`] | E2.5 | "Node-to-node tunnel" — the HBONE-analogue CONNECT mux |
//! | [`capture`] | E2.5 | "Captures workload traffic via eBPF redirect (iptables fallback)" |
//! | [`identity`] | E2.6 | "Identity via SPIFFE/SPIRE" (the [`DelegatedIdentitySource`](identity::DelegatedIdentitySource) trait + the static test double) |
//! | [`audit_seal`] | decision-B residual (b), pending ratification | Dedicated ML-DSA-87 PQ audit-seal key, cryptographically separate from `identity`'s Ed25519 session-identity key |
//! | [`spire_client`] | E2.6 | The real SPIRE Workload API (DelegatedIdentity) gRPC-over-UDS client implementing that trait |
//! | [`authz`] | E2.6 | "L4 authorization (which workload may reach which) enforced here, at the node" |
//! | [`waypoint`] | E2.7 | Component 2 — the optional per-namespace L7 (re-exports `nz-waypoint-core`, shared with the `nz-waypoint-wasm` Envoy proxy-wasm hosting shape) |
//! | [`gateway_backend`] | E2.19/E2.20 (R14) | The `appProtocol: npamp` backend connection-type prototype + its fail-closed downgrade property + the R12/R14 waypoint authorization composition (E2.7 reconciliation) |
//! | [`agent`] | E2.5/E2.6 | `NodeAgent` — composes the above + `npamp::session::Session` into the per-workload dial/accept path |
//! | [`datapath`] | R13-A/R13-B-cont | eBPF datapath selector ladder + fast-path/redirect authorization gates (Linux) |
//! | [`telemetry`] | E2.13 (R13.5, exporter half) | OTel + Prometheus export of `datapath::DropEvent` via the `TelemetrySink` trait |
//! | [`wfp`] (Windows only) | R13-C | Windows Filtering Platform datapath rung — the Windows analog of `datapath`'s ladder |
//! | [`wfp_wire`] | E2.14 (userspace floor) | The kernel-callout &lt;-&gt; userspace wire codec for the (not yet built, signed-driver-gated) WFP redirect-layer callout driver; pure `std`, not Windows-gated |
//!
//! # The one property every other property depends on
//!
//! **Session keys are per-workload (per-SVID), never node-global** (R12 AC2; the
//! design doc's blast-radius mitigation #1). This crate does not derive one
//! shared master secret for the node and multiplex payload confidentiality
//! underneath it — every workload gets its OWN [`npamp::session::Session`],
//! established by its OWN independent N-PAMP handshake, carried over its OWN
//! logical stream of the node-to-node tunnel (see [`tunnel::MuxStream`]). A
//! compromise of the node agent's tunnel-transport layer does not, by itself,
//! recover any workload's traffic key — see `THREAT-MODEL.md` for the full
//! blast-radius analysis (E2.8).
//!
//! # What composes with what (no frozen-wire touch)
//!
//! Nothing in this crate edits, re-derives, or reimplements any byte the
//! `npamp` crate already defines. The node-to-node tunnel's mux framing (stream
//! ID, frame kind, length) is NOT part of the N-PAMP wire — it is this crate's
//! own transport-layer plumbing, the same way HTTP/2 framing is not part of the
//! TLS record layer it carries. Every byte that crosses an `nz-agent`-to-
//! `nz-agent` PQC session boundary is produced and consumed exclusively by
//! `npamp::session::Session::send`/`recv`.
//!
//! # Tracked gaps (this build; see the crate's build report)
//!
//! - ~~Live SPIRE Workload API / DelegatedIdentity fetch~~ — **CLOSED, E2.6**.
//!   [`spire_client::SpireWorkloadApiSource`] is a real gRPC-over-UDS client
//!   implementing [`identity::DelegatedIdentitySource`], wired into
//!   `bin/nz_agent.rs` via `--spire-socket` and tested end to end against an
//!   in-process mock DelegatedIdentity server over a real Unix-domain socket
//!   (`src/spire_client.rs`'s tests). What remains genuinely unbuildable in
//!   this environment is standing up a LIVE SPIRE Server+Agent to dial —
//!   that is an infra/deployment gap, not an implementation one.
//! - **eBPF capture** — [`capture`] defines `CaptureSource` and ships the
//!   iptables/TPROXY rule-construction path (testable without root); it does
//!   not execute rules against a live kernel (needs `CAP_BPF`/root, R13's job
//!   per the design doc's own rung split).
//! - **Envoy proxy-wasm / agentgateway hosting** — [`waypoint`] ships the
//!   carriage-translation dispatch table and the fail-closed `AuthzHook` seam;
//!   it does not compile to a proxy-wasm module or host inside a live
//!   agentgateway process (a separate toolchain/build target, R12 AC3's "and/or"
//!   — this crate builds the composable core both hosts would call into).
//! - **`appProtocol: npamp` upstream wiring (E2.19/E2.20, R14)** — [`gateway_backend`]
//!   builds and mutation-tests the SYNC core of the backend connection type
//!   (dial + fail-closed downgrade refusal, see that module's docs for the
//!   exact upstream `agentgateway/agentgateway` seam this was grounded
//!   against). It does not add a `Transport::Npamp` variant to agentgateway's
//!   own `client::mod.rs` match, add an async `client/npamp_tunnel.rs`
//!   module to that (separate, external) repository, or open the PR — see
//!   an internal design note for that
//!   concrete, citation-grounded writeup, and mesh-underlay validation
//!   (E2.18, actually running agentgateway pods in-mesh with a packet trace)
//!   is held pending a live cluster, per this build's own task table.
//! - **Live N-AALP effect-class/audience authorization** — `waypoint::AuthzHook`
//!   is the seam a real N-AALP policy client would implement; this build ships
//!   a fail-closed default and a table-based test double, not a cross-repo
//!   client to the (Go) N-AALP policy engine.
//! - **WFP kernel callout driver (`WFP-KERNEL-CALLOUT-GAP`, R13-C/E2.14,
//!   Windows only)** — [`wfp`] builds the user-mode WFP filter/condition
//!   object model (the ALE authorize-layer PERMIT filters), the
//!   `WfpEngineInstaller` submission seam, a real (grounded, genuinely
//!   invoked) `FwpmEngineOpen0`/`FwpmEngineClose0` reachability probe, a
//!   callout/filter conflict-scan seam (`WfpConflictScanner`, real
//!   `FwpmFilterCreateEnumHandle0`/`FwpmFilterEnum0`/`FwpmCalloutCreateEnumHandle0`/
//!   `FwpmCalloutEnum0` FFI declared but not invoked against a live engine
//!   in this build — same tracked-gap reasoning as the filter submission
//!   seam), and a Windows-side degrade-to-userspace strategy selector
//!   (`WfpStrategy`/`WfpHandle`, mirroring [`datapath::DatapathHandle`]'s
//!   reselection concept). [`wfp_wire`] builds the pure byte codec a future
//!   signed callout driver's redirect-layer events would cross the
//!   userspace boundary in. What remains genuinely unbuildable in this
//!   environment — a signed kernel-mode callout driver actually registered
//!   at the redirect layers (`FwpsCalloutRegister1`, WDK-gated, no signing
//!   in this build) — is a maintainer-gated follow-up, not an
//!   implementation gap in the userspace floor. See
//!   the WFP design grounding §4.
//! - **E2.13 half 2 — the eBPF-side flow/verdict telemetry bridge** — [`telemetry`]
//!   builds the real OTel+Prometheus exporter half over the existing
//!   userspace `datapath::DropEvent` taxonomy (the [`telemetry::TelemetrySink`]
//!   trait consumes it, live-tested against a real
//!   `opentelemetry_sdk::testing::trace::InMemorySpanExporter` and a real
//!   `prometheus::Registry`, and shipped in production via the official
//!   `opentelemetry-stdout` exporter). It does NOT read the kernel-side
//!   `nz-agent-ebpf` maps to turn a kernel-observed flow/verdict into a
//!   `DropEvent` — that bridge is Linux/aya-build-gated (same reasoning as
//!   `capture`'s eBPF-execution gap) and would call the SAME
//!   `TelemetrySink::export` seam this crate now ships, not a new one.
//! - **Gateway API / GAMMA control-plane wiring (R12 AC4)** — this build ships
//!   only the DATA-plane agent (identity/authz/tunnel/waypoint-dispatch); no
//!   Kubernetes controller reads Gateway API `HTTPRoute`/`Backend`/GAMMA-Mesh
//!   CRDs and configures `nz-agent`/`AuthzTable`/`PeerDirectory` from them. The
//!   `AuthzTable`/`PeerDirectory` population seams this build DOES ship
//!   (`allow`/`register`, and the CLI's `--allow`/`--register-peer`) are
//!   exactly what such a controller would call — a control-plane binding onto
//!   those seams is unbuilt, not merely untested.

pub mod agent;
pub mod audit_seal;
pub mod authz;
pub mod capture;
pub mod datapath;
pub mod gateway_backend;
pub mod identity;
pub mod spire_client;
pub mod telemetry;
pub mod tunnel;
pub mod waypoint;
/// The Windows Filtering Platform (WFP) datapath rung (R13-C) — the Windows
/// analog of [`datapath`]'s eBPF ladder; Windows-only by construction (see
/// `wfp`'s own module docs for why this is a sibling module rather than a
/// new `datapath::DatapathStrategy` variant, and the WFP design grounding
/// for the primary-source grounding).
#[cfg(windows)]
pub mod wfp;
/// The WFP kernel-callout <-> userspace wire codec (E2.14 userspace floor).
/// Deliberately NOT `#[cfg(windows)]`-gated — pure `std`, no FFI — so it
/// compiles and its tests run on every platform this crate builds on; see
/// `wfp_wire`'s own module docs for why it is a byte-level sibling to
/// [`wfp`] rather than part of that module.
pub mod wfp_wire;
