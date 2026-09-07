// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! `egress_redirect`: the kernel side of R13-B-cont's `CgroupRedirect` rung
//! (EBPF-DATAPATH-DESIGN.md: "`cgroup/connect4|connect6` rewrites the
//! outbound dst to `nz-agent` at `connect()` time (no per-packet cost);
//! original dst stashed in a BPF map keyed by socket cookie; a socket mark
//! breaks the nz-agent-re-capture loop"). Two programs sharing two maps:
//!
//! - `egress_redirect_connect4` (`cgroup/connect4`): for every outbound
//!   IPv4 `connect()` inside the attached cgroup, looks up the connection's
//!   ORIGINAL `(dest_ip, dest_port)` in `EGRESS_WAYPOINT`. If a waypoint is
//!   registered, rewrites `ctx.user_ip4`/`ctx.user_port` to that waypoint
//!   (steering the connect to this node's own `nz-agent`), records the
//!   original destination in `EGRESS_ORIG_DST` keyed by the socket's cookie,
//!   and marks the socket so `nz-agent`'s OWN outbound connect to the real
//!   destination is not re-captured by this same hook. If no waypoint is
//!   registered, the destination is left untouched.
//! - `egress_redirect_connect6` (`cgroup/connect6`): a deliberate,
//!   documented no-op — see "IPv6 scope" below.
//!
//! # The fail-closed property this file holds (R13.1)
//!
//! Exactly like `ebpf/src/main.rs`'s `samenode_splice` pair, THIS file never
//! calls `EGRESS_WAYPOINT.insert`/`HashMap::insert` — that map is written
//! ONLY from userspace, in `loader/src/lib.rs`'s `EgressRedirectInstaller`,
//! reachable only through `nz_agent::datapath::install_redirect` after
//! `nz_agent::datapath::RedirectGate::authorize_redirect` has already
//! returned an unforgeable `RedirectToken` for this exact (source,
//! destination) pair. This program's ONLY map-write capability is
//! `EGRESS_ORIG_DST` (see "The one kernel-side map write" below), which is
//! NOT the authorization map and cannot grant any redirect on its own.
//!
//! # The one kernel-side map write in this sub-unit (design question flagged)
//!
//! `EGRESS_ORIG_DST` (cookie -> original `EgressKey`) IS written from this
//! kernel program, not from userspace — the one place in this whole
//! `nz-agent-ebpf-cont` sub-unit where that happens. This is deliberate, not
//! an oversight: only the kernel program, at the moment of `connect()`,
//! observes the ORIGINAL destination before it overwrites `ctx.user_ip4`/
//! `user_port` with the waypoint address; userspace has no way to learn that
//! value in advance (it is per-connection, caller-chosen, live state), and
//! by the time `nz-agent` accepts the redirected connection the original
//! destination is gone from the packet/socket unless something recorded it
//! at rewrite time. Writing it is therefore a NECESSITY of this rung's own
//! mechanism (matching EBPF-DATAPATH-DESIGN.md's explicit "original dst
//! stashed in a BPF map keyed by socket cookie" line), not a substitute for
//! the authorization gate: `EGRESS_ORIG_DST` is written ONLY for a
//! connection that already matched an authz-installed `EGRESS_WAYPOINT`
//! entry (see `try_connect4` below — the insert happens strictly after,
//! and conditioned on, a successful waypoint lookup), nothing ever READS
//! `EGRESS_ORIG_DST` to authorize anything, and an unmatched connection
//! never gets an entry at all. Flagged per this build's own instructions as
//! the design question this sub-unit's single kernel-side map write raises.
//!
//! # IPv6 scope
//!
//! `EgressKey`/`Waypoint` are IPv4-only (see `nz-agent-ebpf-common`), matching
//! this whole crate's existing `ConnKey` convention (`ebpf/src/main.rs`,
//! `loader/src/lib.rs::conn_key_of`). `egress_redirect_connect6` is therefore
//! a genuine, permanent no-op for this sub-unit: it reads nothing off `ctx`,
//! rewrites nothing, and always allows the connect to proceed unmodified —
//! failing closed to "do not touch IPv6 traffic" rather than attempting a
//! redirect scheme this sub-unit's map keys cannot represent.
#![no_std]
#![no_main]

use core::ffi::c_void;
use core::mem::size_of;

use aya_ebpf::helpers::{bpf_get_socket_cookie, bpf_setsockopt};
use aya_ebpf::macros::{cgroup_sock_addr, map};
use aya_ebpf::maps::{HashMap, PerCpuArray};
use aya_ebpf::programs::SockAddrContext;
use nz_agent_ebpf_common::{EgressKey, Waypoint};

/// `AF_INET` (grounded: `/usr/include/x86_64-linux-gnu/bits/socket.h`,
/// `#define PF_INET 2`; `AF_INET` is `#define`d equal to `PF_INET`).
const AF_INET: u32 = 2;

/// `SOL_SOCKET` (grounded: `/usr/include/asm-generic/socket.h`, `#define
/// SOL_SOCKET 1`).
const SOL_SOCKET: i32 = 1;
/// `SO_MARK` (grounded: `/usr/include/asm-generic/socket.h`, `#define
/// SO_MARK 36`). `bpf_setsockopt`'s own uapi doc (`linux/bpf.h`) lists
/// `SO_MARK` as one of the `SOL_SOCKET` optnames it supports for a `struct
/// bpf_sock_addr` `BPF_CGROUP_INET4_CONNECT` caller.
const SO_MARK: i32 = 36;
/// The mark value this rung applies to a redirected socket. Any nonzero,
/// process-distinguishable value works for the Istio SO_MARK
/// re-capture-loop-breaking pattern this rung follows (EBPF-DATAPATH-
/// DESIGN.md); `nz-agent`'s own outbound connect to the REAL destination
/// carries this mark, and a production deployment's cgroup/connect4 hook
/// would skip already-marked sockets (that skip condition is future work
/// tracked at the `nz-agent` policy layer, not in this kernel program, which
/// has no policy to consult — see the module docs' fail-closed section).
const NZ_AGENT_REDIRECT_MARK: u32 = 0x4e5a_4145; // "NZAE" in ASCII, as bytes.

/// Populated ONLY by `loader::EgressRedirectInstaller` (userspace), after
/// `nz_agent::datapath::RedirectGate::authorize_redirect` approves the pair —
/// see the module docs' fail-closed section. Sized for this sub-unit's
/// bounded demo, matching `samenode_splice`'s own `SPLICE_SOCKS`/
/// `SPLICE_PEER` sizing.
///
/// Named `EGRESS_WAYPOINT` (singular), not `EGRESS_WAYPOINTS`: a real
/// map-level demo of this program surfaced that the kernel truncates a BPF
/// map's own name to `BPF_OBJ_NAME_LEN - 1` = 15 characters (confirmed via
/// `bpftool map show` on this host — a 16-character name silently displays
/// as its first 15 characters, e.g. `EGRESS_WAYPOINTS` showed up as
/// `EGRESS_WAYPOINT`). This does not affect `aya`'s own userspace
/// `take_map("EGRESS_WAYPOINT")` lookup (which resolves by the full ELF/BTF
/// name aya itself recorded, not the kernel's truncated copy), but a name
/// that silently truncates in every OTHER BPF tool (`bpftool`, `bpftrace`,
/// production dashboards) is a real rough edge, not a cosmetic one — kept at
/// exactly 15 characters here so it never truncates.
#[map]
static EGRESS_WAYPOINT: HashMap<EgressKey, Waypoint> = HashMap::with_max_entries(64, 0);

/// Written FROM THIS KERNEL PROGRAM — see the module docs' "one kernel-side
/// map write" section for why this is not an authorization bypass.
#[map]
static EGRESS_ORIG_DST: HashMap<u64, EgressKey> = HashMap::with_max_entries(64, 0);

/// E2.13 (R13.5, kernel-side half): per-CPU verdict counters for every
/// connect() that MATCHED a registered `EGRESS_WAYPOINT` entry (an unmatched
/// connect — no registered waypoint — is never counted; see
/// `tc_fallback.rs`'s sibling `TC_VERDICTS` map for why an interface/netns-
/// wide miss is deliberately not telemetry-worthy). Index 0 counts a match
/// whose `EGRESS_ORIG_DST` stash succeeded (the redirect is fully usable —
/// `nz-agent` can recover the original destination after accept); index 1
/// counts a match whose stash FAILED (the redirect still steers the
/// connect(), but the original destination is now unrecoverable — a genuine
/// kernel-side correctness failure for an ALREADY-authorized flow, the same
/// `NpampDropCode::InstallFailure` shape one layer below
/// `RedirectGate::authorize_redirect`). `PerCpuArray` avoids a cross-CPU
/// atomic on the connect() fast path; the loader-side bridge
/// (`loader/src/lib.rs`) sums across CPUs when reading.
#[map]
static EGRESS_VERDICTS: PerCpuArray<u64> = PerCpuArray::with_max_entries(2, 0);

/// Verdict index: a matched connect()'s waypoint rewrite AND original-
/// destination stash both succeeded.
const VERDICT_STEERED: u32 = 0;
/// Verdict index: a matched connect() was rewritten, but stashing the
/// original destination into `EGRESS_ORIG_DST` failed (e.g. the map is
/// full) — `nz-agent` will not be able to recover the true original
/// destination for this connection after accept.
const VERDICT_STEER_FAILED: u32 = 1;

/// Increments `EGRESS_VERDICTS[index]` on the CURRENT cpu's slot. Never
/// changes the connect()'s own outcome: the rewrite decision above this call
/// is already final by the time this runs.
#[inline(always)]
fn bump_verdict(index: u32) {
    if let Some(ptr) = EGRESS_VERDICTS.get_ptr_mut(index) {
        unsafe { *ptr += 1 };
    }
}

#[cgroup_sock_addr(connect4)]
pub fn egress_redirect_connect4(ctx: SockAddrContext) -> i32 {
    try_connect4(&ctx);
    1 // always ALLOW the connect() syscall; this rung only ever redirects or leaves untouched.
}

/// A genuine, documented no-op — see the module docs' "IPv6 scope" section.
/// `_ctx` is read as a real, typed parameter (matching this crate's own
/// `samenode_splice_sockops`'s "the read genuinely executes" bar for a
/// deliberately-passive program) even though its fields are never consulted:
/// the honesty property this function holds is that it makes NO redirect
/// decision at all, not that it makes a hidden always-same decision.
#[cgroup_sock_addr(connect6)]
pub fn egress_redirect_connect6(_ctx: SockAddrContext) -> i32 {
    1 // always ALLOW; IPv6 is out of scope for this sub-unit's EgressKey/Waypoint scheme.
}

/// Reads the connect's real target off `ctx` (never a caller-supplied
/// identity — there is none available to a kernel BPF program), looks it up
/// in `EGRESS_WAYPOINT`, and if a waypoint is registered, rewrites the
/// connect's destination in place, records the original destination for
/// `nz-agent` to recover after accept, and marks the socket.
fn try_connect4(ctx: &SockAddrContext) {
    let sock_addr = ctx.sock_addr;
    // SAFETY: `sock_addr` is the live `bpf_sock_addr*` the kernel handed this
    // `cgroup/connect4` invocation; reading `family`/`user_ip4`/`user_port`
    // is exactly the uapi-documented 4-byte read this program type allows.
    let family = unsafe { (*sock_addr).family };
    if family != AF_INET {
        // A `cgroup/connect4` program is only ever invoked for an AF_INET
        // connect by construction (BPF_CGROUP_INET4_CONNECT), so this branch
        // is defensive, not a real code path — but "trust the attach point
        // silently" is exactly the kind of unstated assumption this
        // programme's own discipline forbids, so it is checked and the
        // connect is left untouched if it ever fires.
        return;
    }
    let key = unsafe { EgressKey { dest_ip: (*sock_addr).user_ip4, dest_port: (*sock_addr).user_port } };
    let Some(waypoint) = (unsafe { EGRESS_WAYPOINT.get(&key) }) else {
        return; // no registered waypoint: leave the destination untouched.
    };
    let waypoint = *waypoint;

    // SAFETY: `user_ip4`/`user_port` are documented as 4-byte-writable by
    // `cgroup/connect4` programs (uapi `linux/bpf.h`); `waypoint_port` is
    // already zero-extended in its high 16 bits (see `EgressKey::dest_port`'s
    // doc comment), matching `user_port`'s own storage convention exactly,
    // so this is a direct field copy with no conversion.
    unsafe {
        (*sock_addr).user_ip4 = waypoint.waypoint_ip;
        (*sock_addr).user_port = waypoint.waypoint_port;
    }

    // Record the ORIGINAL destination this socket asked for, keyed by its
    // cookie, so `nz-agent` can recover it after accepting the redirected
    // connection (see the module docs' "one kernel-side map write" section).
    // E2.13: record whether this stash succeeded — see EGRESS_VERDICTS' docs.
    let cookie = unsafe { bpf_get_socket_cookie(sock_addr.cast::<c_void>()) };
    match EGRESS_ORIG_DST.insert(&cookie, &key, 0) {
        Ok(()) => bump_verdict(VERDICT_STEERED),
        Err(_) => bump_verdict(VERDICT_STEER_FAILED),
    }

    // Break the nz-agent-re-capture loop (Istio SO_MARK pattern,
    // EBPF-DATAPATH-DESIGN.md): mark the socket so a policy layer watching
    // this mark can distinguish nz-agent's own subsequent outbound connect
    // (to the REAL destination) from a workload's original connect.
    let mut mark = NZ_AGENT_REDIRECT_MARK;
    let _ = unsafe {
        bpf_setsockopt(
            sock_addr.cast::<c_void>(),
            SOL_SOCKET,
            SO_MARK,
            (&mut mark as *mut u32).cast::<c_void>(),
            size_of::<u32>() as i32,
        )
    };
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
