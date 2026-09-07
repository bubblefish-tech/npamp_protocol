// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! `ConnKey`: the map key shared byte-for-byte between the kernel-side
//! sockmap-splice program (`ebpf/src/main.rs`) and the userspace loader
//! (`loader/src/lib.rs`). `#[repr(C)]` fixes the field layout so the two
//! independently-compiled crates (one `no_std`/`bpfel-unknown-none`, one
//! `std`/host) agree on the exact bytes the kernel's `BPF_MAP_TYPE_SOCKHASH`
//! and `BPF_MAP_TYPE_HASH` (`SPLICE_PEER`) compare and hash.
//!
//! # The keying scheme (IPv4-only in this sub-unit)
//!
//! A socket's own key is its **own** (local, remote) 4-tuple, exactly as
//! `getsockname`/`getpeername` report it for that socket — i.e. what the
//! kernel-side `sk_msg_md` context already carries for the sending socket
//! (`ebpf/src/main.rs::my_key_from_ctx`), and what the userspace loader
//! derives from `TcpStream::local_addr`/`peer_addr`
//! (`loader/src/lib.rs::conn_key_of`). The kernel program never has to be
//! told "which map slot am I" — it recomputes its own key from context on
//! every invocation, exactly as a real (non-test) sockmap deployment would.
//!
//! `no_std` except under `cargo test`, where the standard `#[test]` harness
//! needs `std` — the `ebpf` crate (the only consumer that actually builds
//! for the `no_std` `bpfel-unknown-none` target) never sets `cfg(test)` for
//! this dependency, so its build is unaffected.
#![cfg_attr(not(test), no_std)]

/// One socket's own (local, remote) IPv4 4-tuple, in network byte order (the
/// same byte order `sk_msg_md.local_ip4`/`remote_ip4` and
/// `Ipv4Addr::octets()` both already use — no host/network conversion is
/// performed on the IP fields; ports are stored host-endian to match
/// `sk_msg_md.local_port`/`remote_port`, which the kernel exposes host-endian
/// per the BPF UAPI).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct ConnKey {
    pub local_ip: u32,
    pub remote_ip: u32,
    pub local_port: u32,
    pub remote_port: u32,
}

impl ConnKey {
    /// The reverse of this key: swaps local<->remote. If `self` is the key
    /// under which socket A is registered, `self.reversed()` is the key
    /// under which A's direct peer (the other end of the SAME TCP
    /// connection) would be registered. NOT used for the workload<->agent
    /// same-node SPLICE pairing this crate builds (that pairing is
    /// maintained explicitly, in `SPLICE_PEER`, because the two spliced
    /// sockets are ends of two DIFFERENT connections) — kept because it is
    /// the natural inverse operation on a `ConnKey` and is exercised by this
    /// crate's own unit tests as a sanity check on the struct's symmetry.
    pub fn reversed(&self) -> ConnKey {
        ConnKey {
            local_ip: self.remote_ip,
            remote_ip: self.local_ip,
            local_port: self.remote_port,
            remote_port: self.local_port,
        }
    }
}

// Implementing the userspace `aya::Pod` marker trait HERE (not in `loader`,
// which depends on this crate) is what keeps the impl legal under Rust's
// orphan rule: both the trait (`aya::Pod`) and the type (`ConnKey`) would be
// foreign to `loader`, but `ConnKey` is local to THIS crate. Gated behind
// the "user" feature so the `no_std`/`bpfel-unknown-none` kernel build (the
// `ebpf` crate, which depends on this package WITHOUT "user") never pulls
// in `aya` (a `std` crate) at all.
#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnKey {}

/// `EGRESS_WAYPOINT`/`TC_WAYPOINTS` map key (R13-B-cont: the `egress_redirect`
/// `cgroup/connect4` rung and the `tc_fallback` TC-clsact rung), keyed by the
/// ORIGINAL destination a workload's `connect()` (egress_redirect) or an
/// already-established TCP flow (tc_fallback) targets.
///
/// # Byte order (grounded against this host's `/usr/include/linux/bpf.h`)
///
/// Both fields are **network byte order**. For `egress_redirect`, this
/// mirrors `struct bpf_sock_addr`'s own `user_ip4`/`user_port` fields, which
/// the uapi header documents as "Stored in network byte order" for BOTH the
/// address AND the port — unlike `sk_msg_md`/`bpf_sk_lookup` (see
/// [`InboundKey`]), `bpf_sock_addr` has NO local/remote byte-order asymmetry:
/// every rewritable field on it is uniformly network order. For
/// `tc_fallback`, the fields are raw bytes copied off the wire (an IPv4
/// address and a TCP port are always big-endian on the wire per RFC 791/793),
/// so a direct `ctx.load::<u32>`/`ctx.load::<u16>` read reproduces the same
/// network-order convention without any conversion — both producers agree on
/// this struct's layout for exactly that reason.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct EgressKey {
    /// The destination IPv4 address in network byte order (`bpf_sock_addr::user_ip4`).
    pub dest_ip: u32,
    /// The destination port, network byte order, held in a `u32` to match
    /// `bpf_sock_addr::user_port`'s own 4-byte-wide field (the kernel treats
    /// `user_port` as a 32-bit store whose low 16 bits carry the real
    /// network-order port and whose high 16 bits are zero — the same
    /// zero-extension convention `Waypoint::waypoint_port` below uses on the
    /// write side).
    pub dest_port: u32,
}

/// The local waypoint (this node's `nz-agent`) address a matched
/// [`EgressKey`]/[`TcFlowKey`] is redirected to. Shared, byte-identical
/// shape between `egress_redirect` (written into `ctx.user_ip4`/`user_port`
/// verbatim) and `tc_fallback` (its `waypoint_port` truncated to the real
/// 16-bit TCP port field before being stored into the packet — see
/// `ebpf/src/tc_fallback.rs`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Waypoint {
    /// Network byte order (matches `bpf_sock_addr::user_ip4`'s convention).
    pub waypoint_ip: u32,
    /// Network byte order, held in the low 16 bits with the high 16 bits
    /// zero (matches `bpf_sock_addr::user_port`'s convention — see
    /// [`EgressKey::dest_port`]).
    pub waypoint_port: u32,
}

/// `INBOUND_LISTEN` `SockHash` key (R13-B-cont: the `inbound_lookup`
/// `sk_lookup` rung) — the destination (this node's own bound address) an
/// inbound TCP SYN is targeting.
///
/// # Byte order (grounded against this host's `/usr/include/linux/bpf.h`,
/// `struct bpf_sk_lookup`)
///
/// **Deliberately asymmetric, unlike [`EgressKey`]:** `local_ip4` is
/// documented "Network byte order" but `local_port` is documented "Host byte
/// order" — the SAME local-vs-remote asymmetry `ConnKey`/`sk_msg_md` already
/// carries in this crate (see `ebpf/src/main.rs`'s module docs), just
/// expressed on `bpf_sk_lookup`'s *local* side instead of `sk_msg_md`'s
/// *remote* side. Confirmed directly from the uapi struct definition, not
/// inferred from the `sk_msg_md` precedent.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct InboundKey {
    /// Network byte order (`bpf_sk_lookup::local_ip4`).
    pub dest_ip: u32,
    /// **Host** byte order (`bpf_sk_lookup::local_port` — a genuine `u32`
    /// field in the uapi struct, not a zero-extended 16-bit value like
    /// [`EgressKey::dest_port`]).
    pub dest_port: u32,
}

/// `TC_WAYPOINTS` map key (R13-B-cont: the `tc_fallback` TC-clsact rung) —
/// the full 4-tuple of an established TCP flow, parsed directly off the wire
/// (Ethernet + IPv4 + TCP headers; see `ebpf/src/tc_fallback.rs`), since a
/// `classifier` program's `__sk_buff` context carries NO convenience
/// socket-address fields for `BPF_PROG_TYPE_SCHED_CLS` programs (the
/// `family`/`remote_ip4`/`local_ip4`/`remote_port`/`local_port` fields on
/// `__sk_buff` are documented in the uapi header as accessible only by
/// `BPF_PROG_TYPE_sk_skb` programs — this is the byte-order-adjacent finding
/// this sub-unit's grounding pass surfaced: NOT a byte-order asymmetry within
/// one field, but an entirely different, program-type-gated context shape).
///
/// All four fields are raw network-order bytes read straight off the wire
/// (RFC 791/793 fix the IPv4/TCP header field byte order as big-endian) —
/// ports are widened to `u32` to match this crate's existing `ConnKey`
/// convention (fixed-width `#[repr(C)]` fields), not because the wire field
/// is wider than 16 bits.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct TcFlowKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u32,
    pub dst_port: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for EgressKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for Waypoint {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for InboundKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for TcFlowKey {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reversed_swaps_local_and_remote() {
        let k = ConnKey { local_ip: 1, remote_ip: 2, local_port: 3, remote_port: 4 };
        let r = k.reversed();
        assert_eq!(r, ConnKey { local_ip: 2, remote_ip: 1, local_port: 4, remote_port: 3 });
    }

    #[test]
    fn reversed_is_its_own_inverse() {
        let k = ConnKey { local_ip: 10, remote_ip: 20, local_port: 30, remote_port: 40 };
        assert_eq!(k.reversed().reversed(), k);
    }

    #[test]
    fn distinct_ports_yield_distinct_keys() {
        let a = ConnKey { local_ip: 0x7f000001, remote_ip: 0x7f000001, local_port: 1000, remote_port: 2000 };
        let b = ConnKey { local_ip: 0x7f000001, remote_ip: 0x7f000001, local_port: 1001, remote_port: 2000 };
        assert_ne!(a, b);
    }

    #[test]
    fn egress_key_distinguishes_port_from_ip() {
        let a = EgressKey { dest_ip: 0x0100007f, dest_port: 0x5000 };
        let b = EgressKey { dest_ip: 0x0100007f, dest_port: 0x5100 };
        assert_ne!(a, b);
    }

    #[test]
    fn inbound_key_and_egress_key_are_not_interchangeable_shapes() {
        // Both structs happen to share a field-count/name shape (dest_ip,
        // dest_port), which is exactly why a byte-order mixup between them
        // (host vs network local_port) would compile silently. This test
        // documents the two are DISTINCT types (not literally testable as a
        // type-confusion at runtime; the discriminating behavioral guard is
        // `inbound_key_of`'s own byte-order test in `loader/tests`), and
        // pins the zero-extension convention `EgressKey::dest_port` carries
        // that `InboundKey::dest_port` does NOT.
        let egress_port_zero_extended = EgressKey { dest_ip: 0, dest_port: 0x0000_5000 };
        assert_eq!(egress_port_zero_extended.dest_port >> 16, 0, "egress dest_port must be zero-extended in the high 16 bits");
    }

    #[test]
    fn waypoint_distinguishes_ip_from_port() {
        let a = Waypoint { waypoint_ip: 0x0100007f, waypoint_port: 0x1f90 };
        let b = Waypoint { waypoint_ip: 0x0200007f, waypoint_port: 0x1f90 };
        assert_ne!(a, b);
    }

    #[test]
    fn tc_flow_key_distinguishes_all_four_fields() {
        let base = TcFlowKey { src_ip: 1, dst_ip: 2, src_port: 3, dst_port: 4 };
        assert_ne!(base, TcFlowKey { src_ip: 9, ..base });
        assert_ne!(base, TcFlowKey { dst_ip: 9, ..base });
        assert_ne!(base, TcFlowKey { src_port: 9, ..base });
        assert_ne!(base, TcFlowKey { dst_port: 9, ..base });
    }
}
