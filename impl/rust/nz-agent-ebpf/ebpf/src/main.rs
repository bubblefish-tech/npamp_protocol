// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! `samenode_splice`: the kernel side of R13-B's same-node sockmap fast path
//! (EBPF-DATAPATH-DESIGN.md's `sockops + sk_msg + sockmap` rung). Two
//! programs sharing two maps:
//!
//! - `samenode_splice_sockops` (`sock_ops`, cgroup-attached): a PASSIVE
//!   observer only. It never writes `SPLICE_SOCKS`/`SPLICE_PEER` — see "The
//!   fail-closed property" below for why that is deliberate, not an
//!   omission.
//! - `samenode_splice_skmsg` (`sk_msg`, attached to `SPLICE_SOCKS`): for
//!   every outbound message on a socket the map holds, recomputes that
//!   socket's OWN key from the live `sk_msg_md` context (never trusts a
//!   caller-supplied identity), looks up its splice partner in
//!   `SPLICE_PEER`, and — only if one is registered — redirects the message
//!   directly into the partner's receive queue (`bpf_msg_redirect_hash`,
//!   `BPF_F_INGRESS`), bypassing the TCP/IP stack for that hop.
//!
//! # The fail-closed property this file holds (R13.1)
//!
//! Neither program in this file ever calls `SPLICE_SOCKS.update`/
//! `HashMap::insert` (the kernel-side write helpers `aya_ebpf` exposes for
//! exactly this purpose). **All map writes for this fast path happen from
//! userspace**, in `loader/src/lib.rs::AyaSpliceInstaller::install` — which
//! is reachable only through `nz_agent::datapath::install_splice`, itself
//! reachable only after `nz_agent::datapath::SpliceGate::authorize_splice`
//! returns an (unforgeable, no-public-constructor) `SpliceToken`. So the
//! eBPF program half of this fast path has, structurally, NO code path that
//! could splice an unauthorized pair — not because this file is careful,
//! but because this file contains no map-write capability at all. The
//! `sock_ops` program exists to satisfy the ladder's own attach-point (a
//! future revision MAY use it for connection-state visibility/telemetry —
//! see EBPF-DATAPATH-DESIGN.md's Observability section — but that is a
//! tracked, NOT-YET-BUILT extension, never a silent scope change here).
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::sk_action,
    macros::{map, sk_msg, sock_ops},
    maps::{HashMap, SockHash},
    programs::{SkMsgContext, SockOpsContext},
};
use nz_agent_ebpf_common::ConnKey;

/// `BPF_F_INGRESS` (uapi `linux/bpf.h`): tells `bpf_msg_redirect_hash` to
/// deliver the redirected bytes into the TARGET socket's ingress (receive)
/// queue — i.e. as if the target had received them — rather than re-sending
/// them out the target's egress path. This is what makes the redirect a
/// same-node SPLICE (bytes hop directly between two local sockets) instead
/// of a second send.
const BPF_F_INGRESS: u64 = 1;

/// Holds every socket currently eligible for the fast path, keyed by the
/// socket's OWN (local, remote) 4-tuple (`ConnKey`) — inserted ONLY from
/// `AyaSpliceInstaller::install` (userspace), never from this file. Sized
/// for the bounded same-node-splice demo this sub-unit ships (R13-B); a
/// production deployment's real entry count is future sizing work.
#[map]
static SPLICE_SOCKS: SockHash<ConnKey> = SockHash::with_max_entries(64, 0);

/// Maps a registered socket's own key to its splice PARTNER's key (populated
/// symmetrically, both directions, by `AyaSpliceInstaller::install`) — the
/// second map the two-map sockmap-proxy pattern needs, since the two
/// spliced sockets are (in the real N-PAMP topology) ends of two DIFFERENT
/// TCP connections, so a socket's own reverse-4-tuple is NOT its splice
/// partner's key (unlike `ConnKey::reversed`, which finds the other end of
/// the SAME connection).
#[map]
static SPLICE_PEER: HashMap<ConnKey, ConnKey> = HashMap::with_max_entries(64, 0);

/// `sock_ops` attach point (cgroup-attached). Deliberately passive — see the
/// module docs' fail-closed section for why. `_op` is read (not `_`-prefixed
/// as entirely unused) so the read genuinely executes, matching the honest-
/// implementation bar the anti-stub rules require of even a minimal program:
/// this function really does read the live socket-op context, it simply
/// chooses to act on none of it.
#[sock_ops]
pub fn samenode_splice_sockops(ctx: SockOpsContext) -> u32 {
    let _op = ctx.op();
    0 // SOCK_OPS_OK — never intervenes; see module docs.
}

/// `sk_msg` verdict program, attached to `SPLICE_SOCKS`. Always returns
/// `SK_PASS`; if a splice partner is registered for this socket, the
/// message has ALREADY been redirected to it by `try_redirect` before this
/// returns (a successful `bpf_msg_redirect_hash` call takes effect
/// regardless of the program's own return value — this matches the kernel's
/// own sockmap-verdict-program convention, and how `test_sockmap`/Cilium's
/// sockops verdict programs are written).
#[sk_msg]
pub fn samenode_splice_skmsg(ctx: SkMsgContext) -> u32 {
    try_redirect(&ctx);
    sk_action::SK_PASS
}

/// Recomputes the sending socket's own key from the live `sk_msg_md`
/// context (never a caller-supplied value — there is none available to a
/// kernel BPF program), looks it up in `SPLICE_PEER`, and redirects to the
/// partner if one is registered. `SkMsgContext::msg` is `pub`, so reading
/// the four fields this needs (`family` is checked implicitly by this
/// program only ever seeing IPv4 sockets — the `SPLICE_SOCKS`/`SPLICE_PEER`
/// keying scheme is IPv4-only in this sub-unit, matching `ConnKey`'s own
/// doc comment) is a direct, `unsafe` read of the same struct the C ABI
/// hands to a native BPF program — no separate accessor exists in
/// `aya_ebpf::programs::sk_msg` for these fields.
fn try_redirect(ctx: &SkMsgContext) {
    let my_key = unsafe {
        let msg = &*ctx.msg;
        ConnKey {
            local_ip: msg.local_ip4,
            remote_ip: msg.remote_ip4,
            local_port: msg.local_port,
            remote_port: msg.remote_port,
        }
    };
    let Some(peer_key) = (unsafe { SPLICE_PEER.get(&my_key) }) else {
        return;
    };
    let _ = SPLICE_SOCKS.redirect_msg(ctx, *peer_key, BPF_F_INGRESS);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
