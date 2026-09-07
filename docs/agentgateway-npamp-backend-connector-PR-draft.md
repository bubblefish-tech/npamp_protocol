# PR draft: `appProtocol: npamp` backend connection type for agentgateway (R14, E2.19)

Status: draft, not yet opened against `agentgateway/agentgateway` (a separate
upstream repository this build environment has no write access to). This
document is the concrete PR writeup E2.19 asks for, citing the exact
upstream source seam this build grounded against on 2026-09-04, plus a
working, mutation-tested Rust prototype of the connection type's core in
this repository (`impl/rust/nz-agent/src/gateway_backend.rs`).

## Upstream project

`github.com/agentgateway/agentgateway` — "Next Generation Agentic Proxy for
AI Agents and MCP servers", Apache-2.0, Rust (Tokio, Hyper/Axum, Rustls with
AWS-LC).

## The exact seam (read this session, quoted from the published source)

1. **`crates/agentgateway/src/types/agent.rs`** declares the closed
   `TransportProtocol` enum a `Backend`'s `appProtocol` resolves to:

   ```rust
   pub enum TransportProtocol {
       http,
       https,
       hbone,
       tcp,
       tls,
   }
   ```

   A `Backend` configured with `appProtocol: npamp` needs one new variant
   here (`npamp`), the same way `hbone` already names Istio's ztunnel
   HBONE transport.

2. **`crates/agentgateway/src/client/mod.rs`**'s `Connector::connect` is
   the single dial entry point every backend connection goes through:

   ```rust
   async fn connect(
       &mut self,
       target: Target,
       ep: SocketAddr,
       connection: ConnectionConfig,
       http: bool,
   ) -> Result<Socket, http::Error>
   ```

   It matches on a `Transport` enum and dispatches per transport, e.g.:

   ```rust
   Transport::Hbone(...) => {
       hbone_tunnel::handshake(pool, ep, hbone_port, identities, headers)
   }
   ```

   A `Transport::Npamp(WorkloadKey)` (or equivalent) arm would add one more
   match arm here, dispatching to a new `npamp_tunnel::handshake`.

3. **`crates/agentgateway/src/client/hbone_tunnel.rs`**'s `handshake` is the
   exact shape the new module mirrors:

   ```rust
   pub async fn handshake(
       mut hbone_pool: agent_hbone::pool::WorkloadHBONEPool<hbone::WorkloadKey>,
       ep: SocketAddr,
       hbone_port: u16,
       identities: Vec<Identity>,
       headers: HboneHeaders,
   ) -> Result<Socket, Error>
   ```

   `identities: Vec<Identity>` is agentgateway's own peer-identity pin (the
   set of acceptable proven identities for the dialed backend) — the same
   role `expected_peer` plays in this build's prototype. `Socket`
   (`crate::transport::stream::Socket`) is agentgateway's boxed
   `AsyncRead + AsyncWrite` wrapper — whatever a `Transport::Npamp` arm
   hands back only needs to present that interface.

## The proposed change (not yet built upstream)

1. Add `TransportProtocol::npamp` to `types/agent.rs`.
2. Add a `Transport::Npamp(WorkloadKey)` variant and one match arm in
   `client/mod.rs`'s `Connector::connect`, dispatching to a new
   `client/npamp_tunnel.rs` module.
3. `npamp_tunnel::handshake` wraps this repository's
   `nz_agent::gateway_backend::connect_npamp_backend` (the SYNC core — see
   below) via `tokio::task::spawn_blocking`, because
   `npamp::session::Session`'s bounded-core API is deliberately synchronous
   (that crate's own module docs) — an async host wraps it, it does not
   reimplement the handshake.
4. `npamp_tunnel::handshake`'s returned `NpampBackendSocket` (this
   repository) needs an `AsyncRead + AsyncWrite` adapter over its sync
   `Read + Write` implementation (e.g. `tokio::io::AsyncFd` or
   `tokio_util::io::SyncIoBridge`, wired the same way `spawn_blocking`
   pairs with either) before it can satisfy agentgateway's `Socket` type —
   tracked here as the concrete remaining integration step, not built in
   this repository (which has no dependency on agentgateway's crate graph
   and cannot compile against its private `Socket`/`Identity`/`WorkloadKey`
   types without vendoring that project).

## What this repository builds today (the prototype, E2.19)

`impl/rust/nz-agent/src/gateway_backend.rs`:

- `connect_npamp_backend(raw, local_signing_key, expected_peer)` — dials
  the real N-PAMP 1.5-RTT handshake (`npamp::session::Session::dial`) over
  any `Read + Write` transport, optionally pinning the backend's expected
  proven identity exactly like agentgateway's own `identities: Vec<Identity>`
  parameter.
- `NpampBackendSocket` — the `Read + Write` adapter a proxy forwards
  arbitrary backend bytes (HTTP/JSON-RPC/gRPC) through, carried as
  `N-PAMP-CC-OPAQUE` carriage-class frames (companion spec 25 — the same
  class `nz_agent::waypoint::CarriageClass::Opaque` already declares and
  `impl/go/proxy/carriage_opaque.go` already carries raw bytes under). No
  new carriage class, no new wire bytes.
- The fail-closed downgrade property E2.20 requires (see that module's docs
  and `RED-EVIDENCE.md`'s M-gw-1/M-gw-2 for the two mutation-tested runtime
  faces, plus the structural/type-level face that needs no mutation because
  there is no code path to remove).

Demonstrated in isolation with a concrete input producing a correct
concrete output (a full request/reply round-trip through the adapter
against a plain `npamp::session::Session` peer) — see
`gateway_backend::tests::opaque_backend_bytes_round_trip_after_a_completed_pqc_handshake`.

## Reconciling with the prior (doc-only) scoping pass

`_r14-agentgateway-scoping.md` (2026-08-31, this repository's root, a
read-only research pass) found agentgateway's `Backend.spec` YAML is a
**closed enum** — `ai | static | dynamicForwardProxy | mcp | aws | a2a` —
with no `npamp` slot, and explicitly flagged that it had NOT opened
agentgateway's actual Rust source to confirm this against the code (relying
on the published docs schema only), naming that as a residual for "a future
build task." This build closes that residual: the Rust source (fetched
directly, 2026-09-04) shows `Backend.spec`'s closed kind-enum and the
`TransportProtocol`/`Transport` enums cited above are **two different
axes** — `Backend.spec` selects WHAT the backend is (a static endpoint, an
MCP server, an A2A peer, ...); `TransportProtocol`/`Transport` selects HOW
bytes are carried to it (http/https/hbone/tcp/tls). `appProtocol: npamp`
(the Kubernetes/Gateway-API `appProtocol` field convention this task's
title cites) resolves into the SECOND axis, not the first — so a
`Transport::Npamp` variant does not need a new `Backend.spec` kind at all;
it needs one new arm in `client::mod.rs`'s existing transport-dispatch
match, exactly as described above. This does not contradict the prior
pass's Unit C classification (still a genuine upstream Rust source change,
still proposal-only until agentgateway's maintainers signal interest) — it
sharpens WHERE in that source the change lands, and confirms it is smaller
in scope (one enum variant + one dispatch module) than "a new backend
kind" would have implied.

## Why this stops at a prototype + PR draft, not a merged upstream change

E2.19's acceptance criterion is explicitly disjunctive ("a working prototype
connection type OR a concrete upstream PR draft with the exact source seam
cited") — this document plus the working, tested prototype above satisfy
both halves without requiring write access to, or a full local build of,
the separate `agentgateway/agentgateway` project (a large external Rust
workspace this repository does not vendor and is not a dependency of).
Opening the actual PR is a human action against a third-party repository —
tracked here as the next step, not faked as already submitted.
