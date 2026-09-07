// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Portable (no CAP_BPF, no loaded eBPF object, no root) tests of
// `InboundLookupInstaller`'s fail-closed gating logic, against a fake
// in-memory `InboundBackend`. Real sockets are plain loopback TCP listeners
// (no privilege needed); what is faked is only the KERNEL side (the one
// `bpf()` map-update call), via `FakeInboundBackend`.

use std::net::{SocketAddrV4, TcpListener};

use nz_agent::authz::AuthzTable;
use nz_agent::datapath::{install_redirect, DatapathError};
use nz_agent::identity::SpiffeId;
use nz_agent_ebpf_common::InboundKey;
use nz_agent_ebpf_loader::{inbound_key_of, InboundBackend, InboundLookupInstaller};

#[derive(Debug, Clone, PartialEq, Eq)]
struct Call {
    key: InboundKey,
    fd: i32,
}

#[derive(Default)]
struct FakeInboundBackend {
    calls: Vec<Call>,
}

impl InboundBackend for FakeInboundBackend {
    fn insert_listener(&mut self, key: InboundKey, fd: std::os::fd::RawFd) -> Result<(), String> {
        self.calls.push(Call { key, fd });
        Ok(())
    }
}

fn id(path: &str) -> SpiffeId {
    SpiffeId::parse(&format!("spiffe://cluster.local/ns/prod/sa/{path}")).expect("valid id")
}

fn addr(s: &str) -> SocketAddrV4 {
    s.parse().expect("valid ipv4 socket addr")
}

#[test]
fn inbound_key_of_is_network_order_ip_but_host_order_port() {
    // The deliberate asymmetry `bpf_sk_lookup` carries (local_ip4 network
    // order, local_port HOST order) — grounded directly from this host's
    // uapi struct comment, unlike `egress_key_of`'s port placement which is
    // grounded from the kernel selftest SOURCE (see that function's doc
    // comment for the distinction in confidence).
    let key = inbound_key_of(addr("10.0.0.7:8443"));
    assert_eq!(key.dest_ip, u32::from_ne_bytes([10, 0, 0, 7]));
    assert_eq!(key.dest_port, 8443, "local_port is HOST byte order per bpf_sk_lookup's uapi doc -- the bare decimal value");
    assert_ne!(key.dest_port, u32::from(8443u16.to_be()), "must NOT be network order, unlike EgressKey::dest_port");
}

#[test]
fn denied_pair_never_touches_the_backend() {
    let source = id("peer-a");
    let destination = id("svc-a");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let dest = SocketAddrV4::new("127.0.0.1".parse().unwrap(), listener.local_addr().expect("listener addr").port());

    let mut installer = InboundLookupInstaller::new(FakeInboundBackend::default());
    installer.register_listener(destination.clone(), &listener, dest);

    let empty_authz = AuthzTable::new(); // no allow(): DENIED
    let result = install_redirect(&mut installer, &source, &destination, &empty_authz);

    assert!(result.is_err(), "an unauthorized destination MUST NOT install");
    assert_eq!(installer.backend().calls.len(), 0, "backend MUST NOT be touched for a denied pair, even though the listener was registered");
}

#[test]
fn registered_but_unauthorized_pair_never_touches_the_backend() {
    let source = id("peer-b");
    let destination = id("svc-b");
    let other = id("svc-other");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let dest = SocketAddrV4::new("127.0.0.1".parse().unwrap(), listener.local_addr().unwrap().port());

    let mut installer = InboundLookupInstaller::new(FakeInboundBackend::default());
    installer.register_listener(destination.clone(), &listener, dest);

    let mut authz = AuthzTable::new();
    authz.allow(source.clone(), other); // allows source->other, NOT source->destination
    let result = install_redirect(&mut installer, &source, &destination, &authz);

    assert!(result.is_err());
    assert_eq!(installer.backend().calls.len(), 0);
}

#[test]
fn allowed_and_registered_listener_installs_exactly_once() {
    let source = id("peer-c");
    let destination = id("svc-c");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let dest = SocketAddrV4::new("127.0.0.1".parse().unwrap(), listener.local_addr().unwrap().port());
    let expected_key = inbound_key_of(dest);
    let expected_fd = std::os::fd::AsRawFd::as_raw_fd(&listener);

    let mut installer = InboundLookupInstaller::new(FakeInboundBackend::default());
    installer.register_listener(destination.clone(), &listener, dest);

    let mut authz = AuthzTable::new();
    authz.allow(source.clone(), destination.clone());
    let token = install_redirect(&mut installer, &source, &destination, &authz).expect("allowed + registered listener must install");
    assert_eq!(token.destination(), &destination);

    let calls = &installer.backend().calls;
    assert_eq!(calls.len(), 1, "exactly one insert_listener call, never more, never fewer");
    assert_eq!(calls[0], Call { key: expected_key, fd: expected_fd });
}

#[test]
fn allowed_but_unregistered_destination_fails_without_touching_the_backend() {
    let source = id("peer-d");
    let destination = id("svc-d"); // never registered
    let mut installer = InboundLookupInstaller::new(FakeInboundBackend::default());

    let mut authz = AuthzTable::new();
    authz.allow(source.clone(), destination.clone());
    let result = install_redirect(&mut installer, &source, &destination, &authz);

    match result {
        Err(DatapathError::InstallFailed(msg)) => assert!(msg.contains("not registered"), "unexpected message: {msg}"),
        other => panic!("expected InstallFailed for an unregistered destination, got {other:?}"),
    }
    assert_eq!(installer.backend().calls.len(), 0);
}
