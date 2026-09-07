// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Portable (no CAP_BPF, no loaded eBPF object, no root, no live interface)
// tests of `TcFallbackInstaller`'s fail-closed gating logic, against a fake
// in-memory `TcBackend`.

use std::net::SocketAddrV4;

use nz_agent::authz::AuthzTable;
use nz_agent::datapath::{install_redirect, DatapathError};
use nz_agent::identity::SpiffeId;
use nz_agent_ebpf_common::{TcFlowKey, Waypoint};
use nz_agent_ebpf_loader::{tc_flow_key_of, waypoint_of, TcBackend, TcFallbackInstaller};

#[derive(Debug, Clone, PartialEq, Eq)]
struct Call {
    key: TcFlowKey,
    waypoint: Waypoint,
}

#[derive(Default)]
struct FakeTcBackend {
    calls: Vec<Call>,
}

impl TcBackend for FakeTcBackend {
    fn insert_flow_waypoint(&mut self, key: TcFlowKey, waypoint: Waypoint) -> Result<(), String> {
        self.calls.push(Call { key, waypoint });
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
fn tc_flow_key_of_is_network_order_all_four_fields() {
    let key = tc_flow_key_of(addr("10.0.0.1:5000"), addr("10.0.0.2:443"));
    assert_eq!(key.src_ip, u32::from_ne_bytes([10, 0, 0, 1]));
    assert_eq!(key.dst_ip, u32::from_ne_bytes([10, 0, 0, 2]));
    assert_eq!(key.src_port, u32::from(5000u16.to_be()));
    assert_eq!(key.dst_port, u32::from(443u16.to_be()));
    assert_eq!(key.src_port >> 16, 0);
    assert_eq!(key.dst_port >> 16, 0);
}

#[test]
fn denied_pair_never_touches_the_backend() {
    let source = id("flow-src-a");
    let destination = id("flow-dst-a");
    let mut installer = TcFallbackInstaller::new(FakeTcBackend::default());
    installer.register_flow(destination.clone(), addr("10.0.0.1:5000"), addr("93.184.216.34:443"), addr("127.0.0.1:15006"));

    let empty_authz = AuthzTable::new(); // no allow(): DENIED
    let result = install_redirect(&mut installer, &source, &destination, &empty_authz);

    assert!(result.is_err(), "an unauthorized flow MUST NOT install");
    assert_eq!(installer.backend().calls.len(), 0, "backend MUST NOT be touched for a denied pair, even though the flow was registered");
}

#[test]
fn registered_but_unauthorized_pair_never_touches_the_backend() {
    let source = id("flow-src-b");
    let destination = id("flow-dst-b");
    let other = id("flow-dst-other");
    let mut installer = TcFallbackInstaller::new(FakeTcBackend::default());
    installer.register_flow(destination.clone(), addr("10.0.0.1:5000"), addr("93.184.216.34:443"), addr("127.0.0.1:15006"));

    let mut authz = AuthzTable::new();
    authz.allow(source.clone(), other);
    let result = install_redirect(&mut installer, &source, &destination, &authz);

    assert!(result.is_err());
    assert_eq!(installer.backend().calls.len(), 0);
}

#[test]
fn allowed_and_registered_flow_installs_exactly_once() {
    let source = id("flow-src-c");
    let destination = id("flow-dst-c");
    let src_addr = addr("10.0.0.1:5000");
    let dst_addr = addr("93.184.216.34:443");
    let waypoint_addr = addr("127.0.0.1:15006");
    let expected_key = tc_flow_key_of(src_addr, dst_addr);
    let expected_waypoint = waypoint_of(waypoint_addr);

    let mut installer = TcFallbackInstaller::new(FakeTcBackend::default());
    installer.register_flow(destination.clone(), src_addr, dst_addr, waypoint_addr);

    let mut authz = AuthzTable::new();
    authz.allow(source.clone(), destination.clone());
    let token = install_redirect(&mut installer, &source, &destination, &authz).expect("allowed + registered flow must install");
    assert_eq!(token.destination(), &destination);

    let calls = &installer.backend().calls;
    assert_eq!(calls.len(), 1, "exactly one insert_flow_waypoint call, never more, never fewer");
    assert_eq!(calls[0], Call { key: expected_key, waypoint: expected_waypoint });
}

#[test]
fn allowed_but_unregistered_flow_fails_without_touching_the_backend() {
    let source = id("flow-src-d");
    let destination = id("flow-dst-d"); // never registered
    let mut installer = TcFallbackInstaller::new(FakeTcBackend::default());

    let mut authz = AuthzTable::new();
    authz.allow(source.clone(), destination.clone());
    let result = install_redirect(&mut installer, &source, &destination, &authz);

    match result {
        Err(DatapathError::InstallFailed(msg)) => assert!(msg.contains("not registered"), "unexpected message: {msg}"),
        other => panic!("expected InstallFailed for an unregistered flow, got {other:?}"),
    }
    assert_eq!(installer.backend().calls.len(), 0);
}
