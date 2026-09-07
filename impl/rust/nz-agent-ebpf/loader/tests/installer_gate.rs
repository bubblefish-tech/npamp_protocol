// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Portable (no CAP_BPF, no loaded eBPF object, no root) tests of
// `AyaSpliceInstaller`'s fail-closed gating logic, against a fake in-memory
// `SplicerBackend` — mirrors how `nz-agent`'s own `datapath.rs` tests
// `install_splice` against `NoopSpliceInstaller`. Real sockets are plain
// loopback TCP connections (no privilege needed to create them); what is
// faked is only the KERNEL side (the two `bpf()` map-update calls), via
// `FakeBackend`.
//
// `denied_pair_never_touches_the_backend` and
// `registered_but_unauthorized_pair_never_touches_the_backend` are the two
// halves of M-ebpf-1 (see RED-EVIDENCE.md): together they prove
// `AyaSpliceInstaller::install` cannot reach `SplicerBackend` for a pair
// that is EITHER unauthorized OR only partially registered.

use std::net::{TcpListener, TcpStream};

use nz_agent::authz::AuthzTable;
use nz_agent::datapath::{install_splice, DatapathError};
use nz_agent::identity::SpiffeId;
use nz_agent_ebpf_common::ConnKey;
use nz_agent_ebpf_loader::{conn_key_of, AyaSpliceInstaller, SplicerBackend};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    InsertSock(ConnKey, i32),
    LinkPeer(ConnKey, ConnKey),
}

#[derive(Default)]
struct FakeBackend {
    calls: Vec<Call>,
}

impl SplicerBackend for FakeBackend {
    fn insert_sock(&mut self, key: ConnKey, fd: std::os::fd::RawFd) -> Result<(), String> {
        self.calls.push(Call::InsertSock(key, fd));
        Ok(())
    }

    fn link_peer(&mut self, a: ConnKey, b: ConnKey) -> Result<(), String> {
        self.calls.push(Call::LinkPeer(a, b));
        Ok(())
    }
}

fn id(path: &str) -> SpiffeId {
    SpiffeId::parse(&format!("spiffe://cluster.local/ns/prod/sa/{path}")).expect("valid id")
}

/// A real (unprivileged) loopback TCP connection: `(accepted_side, client_side)`.
/// Two calls to this function yield four real, distinct, same-node sockets —
/// enough to build two independent "connections" to register as a splice
/// pair, matching the real workload<->agent / agent<->destination topology
/// (see `loader/src/lib.rs`'s module docs).
fn loopback_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let addr = listener.local_addr().expect("listener addr");
    let client = TcpStream::connect(addr).expect("connect loopback client");
    let (accepted, _peer) = listener.accept().expect("accept loopback client");
    (accepted, client)
}

#[test]
fn conn_key_of_derives_from_the_sockets_own_addresses() {
    let (a, _b) = loopback_pair();
    let local = a.local_addr().unwrap();
    let remote = a.peer_addr().unwrap();
    let key = conn_key_of(local, remote).expect("ipv4 pair must derive a key");
    // The derivation must reproduce the EXACT byte layout the kernel's
    // `sk_msg_md` exposes (uapi linux/bpf.h), because `ebpf/src/main.rs::
    // try_redirect` builds its `SPLICE_PEER` lookup key from those RAW fields:
    // `local_port` in HOST byte order, but `remote_port` in NETWORK byte order
    // (the ctx-access rewrite places it in the high 16 bits on little-endian).
    // Asserting the network-order form here GUARDS the R13-D fix — a revert to
    // a host-order `remote_port` (which silently breaks the sockhash lookup, so
    // the data-plane splice never fires) flips this test red.
    assert_eq!(key.local_port, u32::from(local.port()));
    assert_eq!(key.remote_port, (remote.port() as u32).to_be());
    // Discriminating (not a tautology): for any nonzero port the network-order
    // form (high 16 bits) is never the host-order form (low 16 bits).
    assert_ne!(
        key.remote_port,
        u32::from(remote.port()),
        "remote_port must be network byte order to match sk_msg_md, not host order"
    );
}

#[test]
fn conn_key_of_fails_closed_on_ipv6() {
    let local: std::net::SocketAddr = "[::1]:1234".parse().unwrap();
    let remote: std::net::SocketAddr = "[::1]:5678".parse().unwrap();
    assert_eq!(conn_key_of(local, remote), None);
}

#[test]
fn register_socket_reports_the_derived_key() {
    let (a, _b) = loopback_pair();
    let local = a.local_addr().unwrap();
    let remote = a.peer_addr().unwrap();
    let mut installer = AyaSpliceInstaller::new(FakeBackend::default());
    let workload = id("workload-solo");
    installer.register_socket(workload.clone(), &a, local, remote).expect("register real socket");
    assert_eq!(installer.key_of(&workload), conn_key_of(local, remote));
}

#[test]
fn denied_pair_never_touches_the_backend() {
    let a = id("denied-a");
    let b = id("denied-b");
    let (sock_a, _keep_a) = loopback_pair();
    let (sock_b, _keep_b) = loopback_pair();
    let mut installer = AyaSpliceInstaller::new(FakeBackend::default());
    installer.register_socket(a.clone(), &sock_a, sock_a.local_addr().unwrap(), sock_a.peer_addr().unwrap()).unwrap();
    installer.register_socket(b.clone(), &sock_b, sock_b.local_addr().unwrap(), sock_b.peer_addr().unwrap()).unwrap();

    let empty_authz = AuthzTable::new(); // no allow() call: the pair is DENIED
    let result = install_splice(&mut installer, &a, &b, &empty_authz);

    assert!(result.is_err(), "an unauthorized pair MUST NOT install");
    assert_eq!(installer_calls(&installer), 0, "backend MUST NOT be touched for a denied pair, even though both sockets were registered");
}

#[test]
fn registered_but_unauthorized_pair_never_touches_the_backend() {
    // Same as above with an explicit ALLOW for a DIFFERENT pair, to prove the
    // gate is pair-specific, not merely "table is non-empty".
    let a = id("scoped-a");
    let b = id("scoped-b");
    let other = id("scoped-other");
    let (sock_a, _keep_a) = loopback_pair();
    let (sock_b, _keep_b) = loopback_pair();
    let mut installer = AyaSpliceInstaller::new(FakeBackend::default());
    installer.register_socket(a.clone(), &sock_a, sock_a.local_addr().unwrap(), sock_a.peer_addr().unwrap()).unwrap();
    installer.register_socket(b.clone(), &sock_b, sock_b.local_addr().unwrap(), sock_b.peer_addr().unwrap()).unwrap();

    let mut authz = AuthzTable::new();
    authz.allow(a.clone(), other); // allows a->other, NOT a->b
    let result = install_splice(&mut installer, &a, &b, &authz);

    assert!(result.is_err());
    assert_eq!(installer_calls(&installer), 0);
}

#[test]
fn allowed_and_fully_registered_pair_installs_both_directions() {
    let a = id("allowed-a");
    let b = id("allowed-b");
    let (sock_a, _keep_a) = loopback_pair();
    let (sock_b, _keep_b) = loopback_pair();
    let key_a = conn_key_of(sock_a.local_addr().unwrap(), sock_a.peer_addr().unwrap()).unwrap();
    let key_b = conn_key_of(sock_b.local_addr().unwrap(), sock_b.peer_addr().unwrap()).unwrap();

    let mut installer = AyaSpliceInstaller::new(FakeBackend::default());
    installer.register_socket(a.clone(), &sock_a, sock_a.local_addr().unwrap(), sock_a.peer_addr().unwrap()).unwrap();
    installer.register_socket(b.clone(), &sock_b, sock_b.local_addr().unwrap(), sock_b.peer_addr().unwrap()).unwrap();

    let mut authz = AuthzTable::new();
    authz.allow(a.clone(), b.clone());
    let token = install_splice(&mut installer, &a, &b, &authz).expect("allowed + registered pair must install");
    assert_eq!(token.source(), &a);
    assert_eq!(token.destination(), &b);

    let calls = &installer.backend().calls;
    assert_eq!(calls.len(), 4, "exactly 2 insert_sock + 2 link_peer calls, never more, never fewer");
    assert!(calls.contains(&Call::InsertSock(key_a, std::os::fd::AsRawFd::as_raw_fd(&sock_a))));
    assert!(calls.contains(&Call::InsertSock(key_b, std::os::fd::AsRawFd::as_raw_fd(&sock_b))));
    assert!(calls.contains(&Call::LinkPeer(key_a, key_b)));
    assert!(calls.contains(&Call::LinkPeer(key_b, key_a)));
}

#[test]
fn allowed_pair_missing_one_registration_fails_without_touching_the_backend() {
    // The property M-ebpf-1 mutates away: install() requires BOTH endpoints
    // registered before it ever calls SplicerBackend.
    let a = id("half-a");
    let b = id("half-b"); // never registered
    let (sock_a, _keep_a) = loopback_pair();
    let mut installer = AyaSpliceInstaller::new(FakeBackend::default());
    installer.register_socket(a.clone(), &sock_a, sock_a.local_addr().unwrap(), sock_a.peer_addr().unwrap()).unwrap();

    let mut authz = AuthzTable::new();
    authz.allow(a.clone(), b.clone());
    let result = install_splice(&mut installer, &a, &b, &authz);

    match result {
        Err(DatapathError::InstallFailed(msg)) => assert!(msg.contains("not registered"), "unexpected message: {msg}"),
        other => panic!("expected InstallFailed for an unregistered endpoint, got {other:?}"),
    }
    assert_eq!(installer_calls(&installer), 0, "an authorized-but-half-registered pair MUST NOT touch the backend");
}

fn installer_calls(installer: &AyaSpliceInstaller<FakeBackend>) -> usize {
    installer.backend().calls.len()
}
