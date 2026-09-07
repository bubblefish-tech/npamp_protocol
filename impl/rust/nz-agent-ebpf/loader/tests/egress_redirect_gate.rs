// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Portable (no CAP_BPF, no loaded eBPF object, no root) tests of
// `EgressRedirectInstaller`'s fail-closed gating logic, against a fake
// in-memory `EgressBackend` — mirrors `installer_gate.rs`'s own structure
// for `AyaSpliceInstaller`. What is faked is only the KERNEL side (the one
// `bpf()` map-update call), via `FakeEgressBackend`.

use std::net::SocketAddrV4;

use nz_agent::authz::AuthzTable;
use nz_agent::datapath::{install_redirect, DatapathError};
use nz_agent::identity::SpiffeId;
use nz_agent_ebpf_common::{EgressKey, Waypoint};
use nz_agent_ebpf_loader::{egress_key_of, waypoint_of, EgressBackend, EgressRedirectInstaller};

#[derive(Debug, Clone, PartialEq, Eq)]
struct Call {
    key: EgressKey,
    waypoint: Waypoint,
}

#[derive(Default)]
struct FakeEgressBackend {
    calls: Vec<Call>,
}

impl EgressBackend for FakeEgressBackend {
    fn insert_waypoint(&mut self, key: EgressKey, waypoint: Waypoint) -> Result<(), String> {
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
fn egress_key_of_is_network_order_both_fields() {
    // 10.0.0.5:8080 -> dest_ip must be the raw network-order octets (not
    // host-order-widened), dest_port must be a be16 value ZERO-EXTENDED IN
    // THE LOW 16 BITS (the opposite placement from ConnKey::remote_port,
    // which is deliberately high-16-bit per R13-D — see the doc comment on
    // `egress_key_of` for the grounding citation).
    let key = egress_key_of(addr("10.0.0.5:8080"));
    assert_eq!(key.dest_ip, u32::from_ne_bytes([10, 0, 0, 5]));
    assert_eq!(key.dest_port, u32::from(8080u16.to_be()));
    assert_eq!(key.dest_port >> 16, 0, "must be zero in the high 16 bits, unlike sk_msg_md::remote_port");
    assert_ne!(key.dest_port, 8080, "must not be the bare host-order port value");
}

#[test]
fn waypoint_of_mirrors_egress_key_of_byte_order() {
    let wp = waypoint_of(addr("127.0.0.1:9443"));
    assert_eq!(wp.waypoint_ip, u32::from_ne_bytes([127, 0, 0, 1]));
    assert_eq!(wp.waypoint_port, u32::from(9443u16.to_be()));
}

#[test]
fn denied_pair_never_touches_the_backend() {
    let source = id("workload-a");
    let destination = id("dest-a");
    let mut installer = EgressRedirectInstaller::new(FakeEgressBackend::default());
    installer.register_destination(destination.clone(), addr("93.184.216.34:443"), addr("127.0.0.1:15001"));

    let empty_authz = AuthzTable::new(); // no allow(): DENIED
    let result = install_redirect(&mut installer, &source, &destination, &empty_authz);

    assert!(result.is_err(), "an unauthorized pair MUST NOT install");
    assert_eq!(installer.backend().calls.len(), 0, "backend MUST NOT be touched for a denied pair, even though the destination was registered");
}

#[test]
fn registered_but_unauthorized_pair_never_touches_the_backend() {
    let source = id("workload-b");
    let destination = id("dest-b");
    let other = id("dest-other");
    let mut installer = EgressRedirectInstaller::new(FakeEgressBackend::default());
    installer.register_destination(destination.clone(), addr("93.184.216.34:443"), addr("127.0.0.1:15001"));

    let mut authz = AuthzTable::new();
    authz.allow(source.clone(), other); // allows source->other, NOT source->destination
    let result = install_redirect(&mut installer, &source, &destination, &authz);

    assert!(result.is_err());
    assert_eq!(installer.backend().calls.len(), 0);
}

#[test]
fn allowed_and_registered_destination_installs_exactly_once() {
    let source = id("workload-c");
    let destination = id("dest-c");
    let mut installer = EgressRedirectInstaller::new(FakeEgressBackend::default());
    let dest_addr = addr("93.184.216.34:443");
    let waypoint_addr = addr("127.0.0.1:15001");
    installer.register_destination(destination.clone(), dest_addr, waypoint_addr);
    let expected_key = egress_key_of(dest_addr);
    let expected_waypoint = waypoint_of(waypoint_addr);

    let mut authz = AuthzTable::new();
    authz.allow(source.clone(), destination.clone());
    let token = install_redirect(&mut installer, &source, &destination, &authz).expect("allowed + registered destination must install");
    assert_eq!(token.source(), &source);
    assert_eq!(token.destination(), &destination);

    let calls = &installer.backend().calls;
    assert_eq!(calls.len(), 1, "exactly one insert_waypoint call, never more, never fewer");
    assert_eq!(calls[0], Call { key: expected_key, waypoint: expected_waypoint });
}

#[test]
fn allowed_but_unregistered_destination_fails_without_touching_the_backend() {
    // The property M-egress-1 (see RED-EVIDENCE.md) mutates away: install()
    // requires the destination registered before it ever calls
    // EgressBackend.
    let source = id("workload-d");
    let destination = id("dest-d"); // never registered
    let mut installer = EgressRedirectInstaller::new(FakeEgressBackend::default());

    let mut authz = AuthzTable::new();
    authz.allow(source.clone(), destination.clone());
    let result = install_redirect(&mut installer, &source, &destination, &authz);

    match result {
        Err(DatapathError::InstallFailed(msg)) => assert!(msg.contains("not registered"), "unexpected message: {msg}"),
        other => panic!("expected InstallFailed for an unregistered destination, got {other:?}"),
    }
    assert_eq!(installer.backend().calls.len(), 0, "an authorized-but-unregistered destination MUST NOT touch the backend");
}
