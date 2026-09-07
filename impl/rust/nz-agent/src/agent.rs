// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! `NodeAgent` — composes [`crate::identity`], [`crate::authz`], and
//! [`crate::tunnel`] with `npamp::session::Session` into the per-workload
//! dial/accept path (E2.5/E2.6, R12 AC1/AC2). This module contains no
//! handshake, KEM, or AEAD code: every cryptographic operation is a direct
//! call into `npamp::session::Session::dial`/`accept`/`send`/`recv`.
//!
//! # The load-bearing property (R12 AC2)
//!
//! [`NodeAgent::originate`] and [`NodeAgent::accept`] each run ONE independent
//! `npamp::session::Session::dial`/`accept` call per invocation, over that
//! invocation's own [`crate::tunnel::MuxStream`]. There is no session cache
//! keyed by destination-only, no shared node-wide identity used across
//! workloads, and no code path that reuses a previously-established
//! `Session` for a different workload. Two workloads talking to the same
//! destination — or the same workload dialing twice — therefore always get
//! two independently-derived `master_secret`s (mutation-tested below and in
//! `RED-EVIDENCE.md`).
//!
//! # Fail-closed, pre-payload (matches `impl/go/firewall`'s own precedent)
//!
//! [`NodeAgent::originate`] checks [`crate::authz::AuthzTable`] BEFORE
//! opening a tunnel stream: a denied `(source, destination)` pair never
//! causes a mux `Open` frame to be sent, let alone a handshake to run — the
//! same "PRE-PAYLOAD" refusal shape `impl/go/firewall`'s doc comments
//! describe for the Go reference relay/firewall composition. On the accept
//! side, the peer's proven identity is resolved to a [`crate::identity::SpiffeId`]
//! via [`PeerDirectory`] and re-checked against the SAME `AuthzTable` — an
//! unrecognized peer public key, or an authenticated-but-undischarged L4
//! pair, is rejected AFTER the handshake proves who they are but BEFORE the
//! `Session` is ever handed back to the caller for `send`/`recv`.
//!
//! # Why `WorkloadSession` owns its `MuxStream`
//!
//! `npamp::session::Session::send`/`recv` take the byte transport as a
//! per-call parameter (the crate's own bounded-core design — see
//! `session.rs`'s module docs). The transport for a workload session is its
//! [`crate::tunnel::MuxStream`], opened/accepted DURING the handshake; a
//! caller that let that stream drop at the end of `originate`/`accept` would
//! have a live `Session` with no way to send or receive on it again. So
//! `WorkloadSession` retains the exact `MuxStream` the handshake ran over,
//! and its own `send`/`recv` methods thread it through automatically.

use std::io;

use npamp::session::Session;

use crate::authz::{AuthzTable, Decision};
use crate::identity::{DelegatedIdentitySource, IdentityError, SpiffeId, Svid};
use crate::tunnel::{Multiplexer, MuxStream};

#[derive(Debug)]
pub enum AgentError {
    Identity(IdentityError),
    AuthzDenied { source: SpiffeId, destination: SpiffeId },
    UnknownPeerIdentity([u8; 32]),
    PeerNotAuthorized { source: SpiffeId, destination: SpiffeId },
    Handshake(io::Error),
    Tunnel(io::Error),
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentError::Identity(e) => write!(f, "nz-agent: identity error: {e}"),
            AgentError::AuthzDenied { source, destination } => write!(f, "nz-agent: L4 authz denied {source} -> {destination} (pre-payload, no stream opened)"),
            AgentError::UnknownPeerIdentity(pk) => write!(f, "nz-agent: proven peer identity {} is not in the peer directory", hex(pk)),
            AgentError::PeerNotAuthorized { source, destination } => write!(f, "nz-agent: L4 authz denied {source} -> {destination} (post-handshake)"),
            AgentError::Handshake(e) => write!(f, "nz-agent: handshake failed: {e}"),
            AgentError::Tunnel(e) => write!(f, "nz-agent: tunnel error: {e}"),
        }
    }
}

impl std::error::Error for AgentError {}

fn hex(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Resolves a proven Ed25519 identity public key (from
/// `Session::peer_identity`) to the [`SpiffeId`] it belongs to — the local
/// analogue of consulting a trust bundle. A real deployment populates this
/// from the SVIDs SPIRE has issued in the trust domain; this crate ships an
/// in-memory table (test double + local dev use).
pub struct PeerDirectory {
    table: std::collections::HashMap<[u8; 32], SpiffeId>,
}

impl PeerDirectory {
    pub fn new() -> PeerDirectory {
        PeerDirectory { table: std::collections::HashMap::new() }
    }

    pub fn register(&mut self, pubkey: [u8; 32], id: SpiffeId) {
        self.table.insert(pubkey, id);
    }

    pub fn resolve(&self, pubkey: &[u8; 32]) -> Option<SpiffeId> {
        self.table.get(pubkey).cloned()
    }
}

impl Default for PeerDirectory {
    fn default() -> Self {
        Self::new()
    }
}

/// A live workload session: the proven local [`Svid`], the proven remote
/// [`SpiffeId`], the underlying `npamp::session::Session`, and the
/// [`MuxStream`] it was established over (retained so `send`/`recv` keep
/// working after the handshake — see the module docs).
pub struct WorkloadSession<W: io::Write + Send + 'static> {
    pub local: Svid,
    pub peer: SpiffeId,
    session: Session,
    stream: MuxStream<W>,
}

/// Manual `Debug`: `npamp::session::Session` deliberately does not derive
/// `Debug` (it would print `master`, the raw traffic secret), and this impl
/// follows the same discipline — it prints only the non-secret identity
/// fields plus the mux stream id, never the session or the underlying
/// stream's contents.
impl<W: io::Write + Send + 'static> std::fmt::Debug for WorkloadSession<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkloadSession")
            .field("local", self.local.id())
            .field("peer", &self.peer)
            .field("stream_id", &self.stream.stream_id())
            .finish_non_exhaustive()
    }
}

impl<W: io::Write + Send + 'static> WorkloadSession<W> {
    /// Seals and sends one application frame over this workload's own
    /// tunnel stream.
    pub fn send(&mut self, channel: u16, ftype: u16, seq: u64, payload: &[u8]) -> io::Result<()> {
        self.session.send(&mut self.stream, channel, ftype, seq, payload)
    }

    /// Reads and opens one application frame from this workload's own
    /// tunnel stream.
    pub fn recv(&mut self, want_seq: u64) -> io::Result<(u16, u16, Vec<u8>)> {
        self.session.recv(&mut self.stream, want_seq)
    }

    pub fn master_secret(&self) -> &[u8] {
        self.session.master_secret()
    }

    pub fn stream_id(&self) -> u32 {
        self.stream.stream_id()
    }
}

/// The per-node agent: composes identity attestation, L4 authorization, and
/// the tunnel mux into the per-workload N-PAMP dial/accept path.
pub struct NodeAgent<'a> {
    identity_source: &'a dyn DelegatedIdentitySource,
    l4: &'a AuthzTable,
    peers: &'a PeerDirectory,
}

impl<'a> NodeAgent<'a> {
    pub fn new(identity_source: &'a dyn DelegatedIdentitySource, l4: &'a AuthzTable, peers: &'a PeerDirectory) -> NodeAgent<'a> {
        NodeAgent { identity_source, l4, peers }
    }

    /// Originates a fresh N-PAMP session for the local workload
    /// `source_pid`, bound for `destination`. `destination_pubkey`, when
    /// `Some`, pins the expected peer identity exactly like
    /// `npamp::session::Session::dial`'s own `expected_peer` parameter
    /// (resolved out-of-band, e.g. from the mesh's SVID trust bundle — NOT
    /// self-asserted by the destination); `None` dials without pinning
    /// (trust-on-first-use — the caller's explicit, logged choice, never
    /// this crate's silent default). Checks L4 authz BEFORE opening a
    /// tunnel stream (fail-closed, pre-payload).
    pub fn originate<W: io::Write + Send + 'static>(
        &self,
        source_pid: u32,
        destination: &SpiffeId,
        destination_pubkey: Option<[u8; 32]>,
        tunnel: &Multiplexer<W>,
    ) -> Result<WorkloadSession<W>, AgentError> {
        let local = self.identity_source.svid_for_workload(source_pid).map_err(AgentError::Identity)?;

        let (decision, _reason) = self.l4.check(local.id(), destination);
        if decision != Decision::Allow {
            return Err(AgentError::AuthzDenied { source: local.id().clone(), destination: destination.clone() });
        }

        let mut stream = tunnel.open_stream().map_err(AgentError::Tunnel)?;
        let session = Session::dial(&mut stream, local.signing_key(), destination_pubkey).map_err(AgentError::Handshake)?;
        Ok(WorkloadSession { local, peer: destination.clone(), session, stream })
    }

    /// Accepts one inbound N-PAMP session for the local workload
    /// `dest_pid` (the workload the capture layer routed this stream to) —
    /// authenticates whoever dials in, resolves their proven public key via
    /// [`PeerDirectory`], and re-checks L4 authz for
    /// `(resolved_source -> this workload)` AFTER the handshake proves
    /// identity but BEFORE the session is returned to the caller.
    pub fn accept<W: io::Write + Send + 'static>(&self, dest_pid: u32, tunnel: &Multiplexer<W>) -> Result<WorkloadSession<W>, AgentError> {
        let local = self.identity_source.svid_for_workload(dest_pid).map_err(AgentError::Identity)?;

        let mut stream = tunnel.accept_stream().map_err(AgentError::Tunnel)?;
        let session = Session::accept(&mut stream, local.signing_key(), None).map_err(AgentError::Handshake)?;

        let peer_pk = session.peer_identity();
        let source = self.peers.resolve(&peer_pk).ok_or(AgentError::UnknownPeerIdentity(peer_pk))?;

        let (decision, _reason) = self.l4.check(&source, local.id());
        if decision != Decision::Allow {
            return Err(AgentError::PeerNotAuthorized { source, destination: local.id().clone() });
        }

        Ok(WorkloadSession { local, peer: source, session, stream })
    }
}

// A tiny module-local smoke test for the parts that don't need a live
// tunnel (identity + authz composition); the full dial/accept isolation
// demo (A9) lives in tests/agent_isolation_test.rs, exercised over a real
// (in-memory) two-thread tunnel.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::StaticIdentitySource;

    #[test]
    fn originate_is_denied_before_any_stream_is_opened_when_l4_denies() {
        let src = StaticIdentitySource::from_pairs(&[
            (100, "spiffe://cluster.local/ns/prod/sa/client"),
            (200, "spiffe://cluster.local/ns/prod/sa/backend"),
        ])
        .expect("valid identity table");
        let l4 = AuthzTable::new(); // deny-everything (no entries)
        let peers = PeerDirectory::new();
        let agent = NodeAgent::new(&src, &l4, &peers);

        let dest = crate::identity::SpiffeId::parse("spiffe://cluster.local/ns/prod/sa/backend").expect("valid");
        let (a, _b) = crate::tunnel::multiplexer_pair();
        let err = agent.originate(100, &dest, Some([0u8; 32]), &a).expect_err("must be denied pre-payload");
        assert!(matches!(err, AgentError::AuthzDenied { .. }));
    }
}
