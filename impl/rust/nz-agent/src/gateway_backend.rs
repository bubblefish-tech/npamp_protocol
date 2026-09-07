// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! R14 (E2.19/E2.20): the `appProtocol: npamp` BACKEND connection type this
//! crate offers a host proxy (agentgateway, or any Envoy-shaped
//! backend-dialer host). This is the same composable core [`crate::waypoint`]'s
//! module docs already point at ("this is where N-PAMP becomes the PQC
//! transport under agentgateway ... R14 shares this same composable core, it
//! does not reimplement it").
//!
//! # The upstream seam this prototypes (grounded this build, 2026-09-04)
//!
//! agentgateway (`github.com/agentgateway/agentgateway`, Rust, Apache-2.0)
//! dials every backend through one function, read this session via the
//! GitHub API/raw source:
//!
//! - `crates/agentgateway/src/types/agent.rs` declares the closed
//!   `TransportProtocol` enum a Backend's `appProtocol` resolves to:
//!   `{ http, https, hbone, tcp, tls }`.
//! - `crates/agentgateway/src/client/mod.rs`'s `Connector::connect` —
//!
//!   ```text
//!   async fn connect(
//!       &mut self,
//!       target: Target,
//!       ep: SocketAddr,
//!       connection: ConnectionConfig,
//!       http: bool,
//!   ) -> Result<Socket, http::Error>
//!   ```
//!
//!   — matches on a `Transport` enum and dispatches to a per-transport
//!   handshake module, e.g. `Transport::Hbone(...) => hbone_tunnel::handshake(...)`.
//! - `crates/agentgateway/src/client/hbone_tunnel.rs`'s `handshake` is the
//!   exact shape a new transport arm would mirror:
//!
//!   ```text
//!   pub async fn handshake(
//!       mut hbone_pool: agent_hbone::pool::WorkloadHBONEPool<hbone::WorkloadKey>,
//!       ep: SocketAddr,
//!       hbone_port: u16,
//!       identities: Vec<Identity>,
//!       headers: HboneHeaders,
//!   ) -> Result<Socket, Error>
//!   ```
//!
//!   `identities: Vec<Identity>` is agentgateway's own peer-identity pin —
//!   the same role [`connect_npamp_backend`]'s `expected_peer` plays here.
//!   `Socket` (`crate::transport::stream::Socket`) is agentgateway's boxed
//!   `AsyncRead + AsyncWrite` wrapper; whatever a `Transport::Npamp(...)` arm
//!   hands back only needs to present that shape.
//!
//! A concrete upstream change would add one `Transport::Npamp(WorkloadKey)`
//! variant to `client::mod.rs`'s match and a new `client/npamp_tunnel.rs`
//! module built to the `handshake` shape above, dispatching into
//! [`connect_npamp_backend`]'s SYNC core via `tokio::task::spawn_blocking`
//! (`npamp::session::Session`'s bounded-core API is deliberately
//! synchronous — see that crate's own module docs — so an async host wraps
//! it, it does not reimplement it). See
//! `docs/agentgateway-npamp-backend-connector-PR-draft.md` for the concrete
//! PR-shaped writeup citing this seam, since this build environment does
//! not have write access to the upstream `agentgateway/agentgateway`
//! repository (a separate project) to open that PR directly.
//!
//! # What this module actually builds (the prototype connection type)
//!
//! [`connect_npamp_backend`] is the SYNC core of that future
//! `npamp_tunnel::handshake`: given any `Read + Write` transport (a
//! `TcpStream`, in a real deployment), it dials the N-PAMP 1.5-RTT handshake
//! (`npamp::session::Session::dial`), optionally pinning the backend's
//! expected proven identity, and — only on a completed handshake — returns
//! [`NpampBackendSocket`], a `Read + Write` adapter that carries whatever
//! bytes a host proxy forwards (the proxied HTTP/JSON-RPC/gRPC request) as
//! `N-PAMP-CC-OPAQUE` carriage-class frames (companion spec 25 — the same
//! carriage class [`crate::waypoint::CarriageClass::Opaque`] already
//! declares, and the same shape `impl/go/proxy/carriage_opaque.go`'s Go leg
//! already carries raw byte payloads under). This module defines no new
//! carriage class and no new wire bytes.
//!
//! # The fail-closed downgrade property (E2.20)
//!
//! This property has two complementary faces:
//!
//! 1. **Connect-time, structural (type-level):** [`NpampBackendSocket`]'s
//!    `session: Session` field is non-optional and private; the ONLY way to
//!    construct one is [`NpampBackendSocket::new`], called from exactly one
//!    place ([`connect_npamp_backend`]'s `Ok` arm), which only runs after a
//!    completed `Session::dial`. There is no `Option<Session>`, no
//!    plaintext/classical-TLS variant, and `npamp::session::Session` exposes
//!    no public constructor other than a completed handshake — so there is
//!    no code path, mutated or otherwise, that can produce a "connected"
//!    [`NpampBackendSocket`] without a live PQC session. This is a stronger
//!    guarantee than a runtime check (nothing to remove), so RED-EVIDENCE.md
//!    tests the two RUNTIME decisions this module still makes (below)
//!    instead of re-deriving this structural fact as a mutation.
//! 2. **Connect-time, identity pinning (mutation-tested, M-gw-1):** a
//!    backend whose PROVEN identity does not match a caller-supplied
//!    `expected_peer` pin is refused exactly like an outright handshake
//!    failure — `connect_npamp_backend` never silently drops the pin and
//!    proceeds trust-on-first-use when the caller asked for pinning.
//! 3. **Data-time (mutation-tested, M-gw-2):** every byte
//!    [`NpampBackendSocket::write`] sends is sealed through
//!    `Session::send` — there is no path that forwards application bytes to
//!    the raw transport unsealed once a session exists.

use std::collections::VecDeque;
use std::io::{self, Read, Write};

use ed25519_dalek::SigningKey;
use npamp::session::Session;

use crate::waypoint::{authorize, AuthzHook, EffectClass, WaypointDenied};

/// The one fixed `(channel, ftype)` pair backend bytes travel under. A
/// prototype needs exactly one, matching `CarriageClass::Opaque`'s "no
/// further structure" semantics — a real integration would let the host
/// proxy pick `channel` per logical stream (mirroring `crate::tunnel`'s own
/// `stream_id` framing), which is out of scope for this connect-time
/// prototype (tracked below, not faked).
const OPAQUE_BACKEND_CHANNEL: u16 = 0;
const OPAQUE_BACKEND_FTYPE: u16 = 0;

/// Why [`connect_npamp_backend`] refused a backend connection. Every variant
/// means "no [`NpampBackendSocket`] exists" — there is no variant that means
/// "proceed anyway" (fail-closed by construction, same discipline as
/// `nz_agent_extauthz::extract::TripleExtractError`).
#[derive(Debug)]
pub enum ConnectorError {
    /// The N-PAMP PQC handshake did not complete against this backend — a
    /// non-N-PAMP-speaking backend, a truncated/malformed handshake, OR a
    /// proven identity that does not match a pinned `expected_peer`.
    /// `npamp::session::Session::dial` itself is what folds "wrong
    /// identity" into this same fail-closed refusal (see that function's
    /// own docs: "rejecting any server whose proven Ed25519 identity does
    /// not match — checked BEFORE CLIENT_AUTH is sent").
    PqcHandshakeRefused(io::Error),
}

impl std::fmt::Display for ConnectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectorError::PqcHandshakeRefused(e) => write!(
                f,
                "nz-agent/gateway_backend: refusing backend connection, PQC handshake did not complete: {e} (no plaintext/classical-TLS fallback exists for this connection type)"
            ),
        }
    }
}

impl std::error::Error for ConnectorError {}

/// A connected `appProtocol: npamp` backend socket: a live [`Session`] plus
/// the raw transport it was established over, presenting `Read + Write` to
/// whatever runs on top (an HTTP/1.1 client, agentgateway's own request
/// forwarding — see module docs for the seam this stands in for).
pub struct NpampBackendSocket<S: Read + Write> {
    session: Session,
    raw: S,
    send_seq: u64,
    recv_seq: u64,
    read_buf: VecDeque<u8>,
}

impl<S: Read + Write> NpampBackendSocket<S> {
    fn new(session: Session, raw: S) -> Self {
        NpampBackendSocket { session, raw, send_seq: 0, recv_seq: 0, read_buf: VecDeque::new() }
    }

    /// The backend's proven Ed25519 identity (post-handshake) — the same
    /// value `expected_peer`, if `Some`, was checked against.
    pub fn peer_identity(&self) -> [u8; 32] {
        self.session.peer_identity()
    }
}

impl<S: Read + Write> Read for NpampBackendSocket<S> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.read_buf.is_empty() {
            let (_channel, _ftype, payload) = self.session.recv(&mut self.raw, self.recv_seq)?;
            self.recv_seq += 1;
            self.read_buf.extend(payload);
        }
        let n = out.len().min(self.read_buf.len());
        for slot in out.iter_mut().take(n) {
            *slot = self.read_buf.pop_front().expect("checked len above");
        }
        Ok(n)
    }
}

impl<S: Read + Write> Write for NpampBackendSocket<S> {
    /// Seals `buf` as one `N-PAMP-CC-OPAQUE` frame through the live
    /// session — see module docs, face 3 (M-gw-2). This is the ONE line a
    /// downgrade defect would bypass (write straight to `self.raw`
    /// instead); RED-EVIDENCE.md mutates exactly this call.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.session.send(&mut self.raw, OPAQUE_BACKEND_CHANNEL, OPAQUE_BACKEND_FTYPE, self.send_seq, buf)?;
        self.send_seq += 1;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.raw.flush()
    }
}

/// The prototype `appProtocol: npamp` backend connection type (E2.19):
/// dials the N-PAMP handshake over `raw` and, ONLY on success, returns a
/// usable [`NpampBackendSocket`]. `expected_peer`, when `Some`, pins the
/// backend's proven identity exactly like agentgateway's own HBONE dial
/// pins `identities: Vec<Identity>` (module docs); `None` (trust-on-first-
/// use) is the caller's own explicit choice, matching `nz_agent::agent`'s
/// documented convention for the same parameter — this function never
/// silently substitutes one for the other (M-gw-1).
///
/// There is exactly one success path and it requires a completed
/// `Session::dial`; there is no branch that returns `Ok` on a failed or
/// identity-mismatched handshake (E2.20 — see module docs for the full
/// fail-closed-downgrade property this implements).
pub fn connect_npamp_backend<S: Read + Write>(mut raw: S, local_signing_key: &SigningKey, expected_peer: Option<[u8; 32]>) -> Result<NpampBackendSocket<S>, ConnectorError> {
    let session = Session::dial(&mut raw, local_signing_key, expected_peer).map_err(ConnectorError::PqcHandshakeRefused)?;
    Ok(NpampBackendSocket::new(session, raw))
}

// ---------------------------------------------------------------------------
// E2.7 reconciliation (R14 AC3): the waypoint AuthzHook composed with this
// connection type. E2.7 (R12 AC3) names TWO L7-waypoint hosting shapes: "an
// Envoy proxy-wasm N-PAMP filter and/or an agentgateway backend" — this is
// the SECOND, applied to the ONE backend connection type this crate ships.
// Before this addition, [`connect_npamp_backend`]/[`NpampBackendSocket`]
// were a pure PQC-transport connector with NO N-AALP effect-class/audience
// check on outgoing bytes at all — [`AuthorizedNpampBackendSocket`] closes
// that gap by composing [`crate::waypoint::authorize`] (the SAME decision
// [`crate::waypoint`]'s native L7 waypoint and `nz-waypoint-wasm`'s Envoy
// proxy-wasm filter both already enforce) BEFORE any byte reaches
// [`NpampBackendSocket::write`]'s sealed session.
//
// This is a FOCUSED composition, not a claim of R14 AC3/E2.21's full
// authorization-composition conformance (agentgateway's own per-tool CEL
// RBAC layer, the agent-JWT-`sub`-as-foreign-identity-linkage distinction,
// and the fully-fledged conformance test suite are `tasks.md`'s
// SEPARATE E2.21 task, R14.3/14.4 — this crate's own
// `nz-agent-extauthz`/`service.rs` already builds and mutation-tests that
// composition for the ext_authz hosting shape). What this addition DOES
// guarantee, mutation-tested below: a carriage object whose declared
// audience or effect the hook denies NEVER reaches
// [`NpampBackendSocket::write`]'s sealed session at all — the same
// fail-closed-by-composition shape [`crate::datapath::install_splice`] and
// [`crate::datapath::install_redirect`] already use one layer down.
// ---------------------------------------------------------------------------

/// Why [`AuthorizedNpampBackendSocket::write_authorized`] refused to write.
/// Every variant means "no bytes reached the sealed session" — there is no
/// variant that means "write anyway" (fail-closed by construction, the
/// same discipline [`ConnectorError`] enforces one layer up).
#[derive(Debug)]
pub enum WriteAuthorizedError {
    /// [`crate::waypoint::authorize`] denied this `(signer_id, audience,
    /// effect)` triple — the object never reaches the sealed session.
    Denied(WaypointDenied),
    /// The write itself failed AFTER authorization succeeded (an
    /// underlying transport/session I/O error — distinct from a denial,
    /// which never reaches the write call at all).
    Io(io::Error),
}

impl std::fmt::Display for WriteAuthorizedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WriteAuthorizedError::Denied(e) => write!(f, "nz-agent/gateway_backend: write refused, {e}"),
            WriteAuthorizedError::Io(e) => write!(f, "nz-agent/gateway_backend: authorized write failed: {e}"),
        }
    }
}

impl std::error::Error for WriteAuthorizedError {}

/// Composes an [`NpampBackendSocket`] with an [`AuthzHook`] (`H`): every
/// write is authorized against the hook's grant table BEFORE it reaches
/// the sealed session, so a denied carriage object never touches the wire
/// at all — not even sealed-but-unauthorized.
pub struct AuthorizedNpampBackendSocket<S: Read + Write, H: AuthzHook> {
    inner: NpampBackendSocket<S>,
    hook: H,
    signer_id: String,
}

impl<S: Read + Write, H: AuthzHook> AuthorizedNpampBackendSocket<S, H> {
    /// Wraps an already-connected `inner` socket with `hook` and the
    /// `signer_id` this connector authorizes writes AS — mirrors
    /// [`crate::waypoint::resolve_grant_for_export`]'s own
    /// `(signer_id, hook)` composition, one layer closer to the wire.
    pub fn new(inner: NpampBackendSocket<S>, hook: H, signer_id: impl Into<String>) -> Self {
        AuthorizedNpampBackendSocket { inner, hook, signer_id: signer_id.into() }
    }

    /// The backend's proven Ed25519 identity, delegated to the wrapped
    /// [`NpampBackendSocket`].
    pub fn peer_identity(&self) -> [u8; 32] {
        self.inner.peer_identity()
    }

    /// Authorizes `object_audience`/`object_effect` — the audience and
    /// effect class the CALLER's carriage object declares — against
    /// `hook`'s grant table for `signer_id`, and ONLY on `Ok(())` writes
    /// `payload` through the wrapped [`NpampBackendSocket`]'s sealed
    /// session ([`NpampBackendSocket::write`], which itself still enforces
    /// M-gw-2's "every byte is sealed" property — this function composes
    /// that gate, it does not bypass or replace it). A denial returns
    /// before `inner.write` is ever called: no byte, sealed or otherwise,
    /// reaches the raw transport for a denied object.
    pub fn write_authorized(&mut self, object_audience: &str, object_effect: EffectClass, payload: &[u8]) -> Result<usize, WriteAuthorizedError> {
        authorize(&self.hook, &self.signer_id, object_audience, object_effect).map_err(WriteAuthorizedError::Denied)?;
        self.inner.write(payload).map_err(WriteAuthorizedError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waypoint::TableAuthzHook;
    use npamp::session::{duplex_pair, generate_identity};
    use std::sync::mpsc;
    use std::thread;

    /// The prototype connection type actually carries bytes: a live PQC
    /// handshake, then a request/response round-trip through
    /// `NpampBackendSocket`'s `Read`/`Write` — demonstrated in isolation
    /// with a concrete input producing a correct concrete output (A9),
    /// against a peer that runs the plain `npamp::session::Session` API
    /// directly (proving this module adds no new wire bytes of its own).
    #[test]
    fn opaque_backend_bytes_round_trip_after_a_completed_pqc_handshake() {
        let (a, mut b) = duplex_pair();
        let client_key = generate_identity();
        let server_key = generate_identity();

        let request = b"GET / HTTP/1.1\r\nHost: backend\r\n\r\n".to_vec();
        let request_for_server = request.clone();

        let server = thread::spawn(move || {
            let server_session = Session::accept(&mut b, &server_key, None).expect("server-side N-PAMP handshake must complete");
            let (channel, ftype, payload) = server_session.recv(&mut b, 0).expect("server must receive the backend request frame");
            assert_eq!(channel, OPAQUE_BACKEND_CHANNEL);
            assert_eq!(ftype, OPAQUE_BACKEND_FTYPE);
            assert_eq!(payload, request_for_server, "backend must see the exact bytes the connector wrote, byte-identical");
            server_session.send(&mut b, OPAQUE_BACKEND_CHANNEL, OPAQUE_BACKEND_FTYPE, 0, b"HTTP/1.1 200 OK\r\n\r\n").expect("server echo must send");
        });

        let mut sock = connect_npamp_backend(a, &client_key, None).expect("dial must succeed against a live N-PAMP-speaking backend");
        sock.write_all(&request).expect("connector write must succeed");
        server.join().expect("server thread must not panic");

        let mut reply = [0u8; 19]; // len("HTTP/1.1 200 OK\r\n\r\n")
        sock.read_exact(&mut reply).expect("connector read must return the backend's reply");
        assert_eq!(&reply, b"HTTP/1.1 200 OK\r\n\r\n");
    }

    /// E2.20, face 2: a backend that never runs the N-PAMP handshake at all
    /// (peer dropped before any handshake byte round-trips) is refused, not
    /// silently accepted as a plaintext-capable connection.
    #[test]
    fn refuses_a_backend_that_never_speaks_npamp_at_all() {
        let (a, b) = duplex_pair();
        drop(b); // the "backend" end is gone before any handshake byte crosses
        let client_key = generate_identity();
        let result = connect_npamp_backend(a, &client_key, None);
        assert!(result.is_err(), "a backend that never completes the N-PAMP handshake must be refused, never returned as a connected socket");
    }

    /// E2.20, face 3 (mutation-tested, M-gw-2): every byte `write` sends
    /// must be sealed through the live session. Bounded via a channel +
    /// `recv_timeout` (matching `crate::tunnel`'s own EOF regression test)
    /// so that a mutation which desyncs the peer's frame parser and hangs
    /// it fails this test via a timeout rather than hanging the whole
    /// suite — a hang is itself evidence the property broke, not an
    /// inconclusive result.
    #[test]
    fn write_never_bypasses_the_sealed_session_to_reach_the_raw_transport_unsealed() {
        let (a, mut b) = duplex_pair();
        let client_key = generate_identity();
        let server_key = generate_identity();

        let (done_tx, done_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let server_session = match Session::accept(&mut b, &server_key, None) {
                Ok(s) => s,
                Err(_) => {
                    let _ = done_tx.send(false);
                    return;
                }
            };
            // A correctly-sealed write produces a frame `recv` can open; a
            // write that bypassed sealing does not (or desyncs the parser).
            match server_session.recv(&mut b, 0) {
                Ok((_channel, _ftype, payload)) => {
                    let _ = done_tx.send(payload == b"probe");
                }
                Err(_) => {
                    let _ = done_tx.send(false);
                }
            }
        });

        let mut sock = connect_npamp_backend(a, &client_key, None).expect("dial must succeed");
        let _ = sock.write_all(b"probe");

        match done_rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(true) => {} // the server opened exactly the sealed-then-unsealed payload
            Ok(false) => panic!("the server either failed to open the frame or received the wrong payload — write() must seal every byte through the session"),
            Err(_) => panic!("server-side recv did not resolve within 5s — a write that bypasses sealing can desync the peer's frame parser, which is itself the downgrade defect this test guards against"),
        }
        let _ = server.join();
    }

    /// E2.20, face 2 (mutation-tested, M-gw-1): a backend that DOES speak
    /// N-PAMP, but whose proven identity does not match a pinned
    /// `expected_peer`, is refused exactly like an outright handshake
    /// failure — never silently downgraded to trust-on-first-use.
    #[test]
    fn refuses_a_backend_whose_identity_does_not_match_the_pinned_expectation() {
        let (a, mut b) = duplex_pair();
        let client_key = generate_identity();
        let server_key = generate_identity();
        let wrong_pin = [0xABu8; 32]; // deliberately NOT server_key's public identity

        let server = thread::spawn(move || {
            // The server itself completes its half fine (or errors once the
            // client aborts) — what matters is the CLIENT's own decision.
            let _ = Session::accept(&mut b, &server_key, None);
        });

        let result = connect_npamp_backend(a, &client_key, Some(wrong_pin));
        assert!(result.is_err(), "a pinned-identity mismatch must refuse the backend connection, never proceed trust-on-first-use");
        let _ = server.join();
    }

    // -- E2.7 reconciliation: the waypoint AuthzHook wired into this backend
    // connector (R14 AC3's "N-AALP effect/audience (gateway->upstream)"
    // applied at the ONE connection type this crate ships) -------------

    #[test]
    fn write_authorized_denies_wrong_audience_and_never_reaches_the_raw_transport() {
        let (a, mut b) = duplex_pair();
        let client_key = generate_identity();
        let server_key = generate_identity();
        let hook = TableAuthzHook::new("gateway-a", &[("agent-b", EffectClass::Destructive)]);

        let (done_tx, done_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let server_session = Session::accept(&mut b, &server_key, None).expect("server handshake must complete");
            // A denied write must send NOTHING -- recv must NOT resolve.
            let result = server_session.recv(&mut b, 0);
            let _ = done_tx.send(result.is_ok());
        });

        let sock = connect_npamp_backend(a, &client_key, None).expect("dial must succeed");
        let mut authorized = AuthorizedNpampBackendSocket::new(sock, hook, "agent-b");
        let err = authorized
            .write_authorized("gateway-WRONG", EffectClass::ReadOnly, b"probe")
            .expect_err("a wrong-audience object must be denied, never written");
        assert!(matches!(err, WriteAuthorizedError::Denied(WaypointDenied::WrongAudience { .. })));

        match done_rx.recv_timeout(std::time::Duration::from_millis(500)) {
            Err(_) => {} // timed out waiting for a frame that correctly never arrived
            Ok(got_something) => assert!(!got_something, "a denied write must not reach the raw transport at all"),
        }
        drop(authorized);
        let _ = server.join();
    }

    #[test]
    fn write_authorized_denies_effect_above_grant_and_never_reaches_the_raw_transport() {
        let (a, mut b) = duplex_pair();
        let client_key = generate_identity();
        let server_key = generate_identity();
        let hook = TableAuthzHook::new("gateway-a", &[("agent-b", EffectClass::ReadOnly)]);

        let (done_tx, done_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let server_session = Session::accept(&mut b, &server_key, None).expect("server handshake must complete");
            let result = server_session.recv(&mut b, 0);
            let _ = done_tx.send(result.is_ok());
        });

        let sock = connect_npamp_backend(a, &client_key, None).expect("dial must succeed");
        let mut authorized = AuthorizedNpampBackendSocket::new(sock, hook, "agent-b");
        let err = authorized
            .write_authorized("gateway-a", EffectClass::Destructive, b"probe")
            .expect_err("an above-grant effect must be denied, never written");
        assert!(matches!(err, WriteAuthorizedError::Denied(WaypointDenied::EffectExceedsGrant { .. })));

        match done_rx.recv_timeout(std::time::Duration::from_millis(500)) {
            Err(_) => {}
            Ok(got_something) => assert!(!got_something, "a denied write must not reach the raw transport at all"),
        }
        drop(authorized);
        let _ = server.join();
    }

    /// E2.7 reconciliation, mutation-tested (M-gw-3): an authorized write
    /// composes BOTH gates in order — `authorize` first, THEN the existing
    /// sealed-session write (M-gw-2's own property) — and the peer receives
    /// the exact byte-identical payload, proving authorization does not
    /// silently swallow or corrupt the sealed carriage.
    #[test]
    fn write_authorized_writes_through_the_sealed_session_when_authorized() {
        let (a, mut b) = duplex_pair();
        let client_key = generate_identity();
        let server_key = generate_identity();
        let hook = TableAuthzHook::new("gateway-a", &[("agent-b", EffectClass::NonIdempotentWrite)]);

        let (done_tx, done_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let server_session = Session::accept(&mut b, &server_key, None).expect("server handshake must complete");
            match server_session.recv(&mut b, 0) {
                Ok((_channel, _ftype, payload)) => {
                    let _ = done_tx.send(payload == b"authorized-probe");
                }
                Err(_) => {
                    let _ = done_tx.send(false);
                }
            }
        });

        let sock = connect_npamp_backend(a, &client_key, None).expect("dial must succeed");
        let mut authorized = AuthorizedNpampBackendSocket::new(sock, hook, "agent-b");
        let n = authorized
            .write_authorized("gateway-a", EffectClass::IdempotentWrite, b"authorized-probe")
            .expect("within-grant, correct-audience write must succeed");
        assert_eq!(n, b"authorized-probe".len());

        match done_rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(true) => {}
            Ok(false) => panic!("the server received the wrong payload — authorization must not corrupt the sealed write"),
            Err(_) => panic!("server-side recv did not resolve within 5s — an authorized write must still reach the peer"),
        }
        let _ = server.join();
    }
}
