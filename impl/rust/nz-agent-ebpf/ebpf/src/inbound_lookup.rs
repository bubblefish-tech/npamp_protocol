// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! `inbound_lookup`: the kernel side of R13-B-cont's inbound-steering rung
//! (EBPF-DATAPATH-DESIGN.md: "`sk_lookup` steers inbound to nz-agent's
//! listener without the workload rebinding"). One program, one map:
//!
//! - `inbound_lookup_select` (`sk_lookup`, network-namespace-attached): for
//!   every incoming TCP packet the kernel would otherwise deliver via its
//!   normal socket lookup, looks up the packet's destination
//!   `(dest_ip, dest_port)` in `INBOUND_LISTEN`. If a registered listener
//!   is found, assigns it as the delivery target via
//!   `SockHash::redirect_sk_lookup` (which wraps `bpf_sk_assign` +
//!   `bpf_sk_release`). If no listener is registered, the packet is left to
//!   the kernel's normal lookup.
//!
//! # The fail-closed property this file holds (R13.1)
//!
//! Exactly like `samenode_splice`/`egress_redirect`, THIS file never calls
//! `INBOUND_LISTEN.update`/`SockHash::insert` — that map is written ONLY
//! from userspace, in `loader/src/lib.rs`'s `InboundLookupInstaller`,
//! reachable only through `nz_agent::datapath::install_redirect` after
//! `nz_agent::datapath::RedirectGate::authorize_redirect` has already
//! approved this destination. This file contains no map-WRITE capability of
//! any kind (unlike `egress_redirect`, which legitimately needs one — see
//! that file's module docs), so there is nothing here for an authorization
//! bypass to reach.
//!
//! # IPv4/TCP scope
//!
//! Matches this crate's existing `ConnKey`/`EgressKey` IPv4-only convention.
//! UDP and IPv6 traffic is explicitly out of scope for this sub-unit's
//! `INBOUND_LISTEN` keying — such a lookup is left entirely to the
//! kernel's normal socket lookup (never dropped, never redirected).
#![no_std]
#![no_main]

use aya_ebpf::macros::{map, sk_lookup};
use aya_ebpf::maps::{PerCpuArray, SockHash};
use aya_ebpf::programs::SkLookupContext;
use nz_agent_ebpf_common::InboundKey;

/// `ENOENT` (grounded: `/usr/include/asm-generic/errno-base.h`,
/// `#define ENOENT 2`). `SockHash::redirect_sk_lookup` (aya-ebpf-0.2.1,
/// read this session) returns `Err(-ENOENT)` specifically for "no entry
/// registered for this key" — the SAME constant aya_ebpf's own
/// `lookup()` helper uses internally (`aya-ebpf-0.2.1/src/lib.rs`,
/// `pub(crate) const ENOENT: i32 = 2`, not reachable from this crate, hence
/// the local re-grounding).
const ENOENT: i32 = 2;

/// `sk_action::SK_PASS`/`SK_DROP` (aya-ebpf-bindings `sk_action` module):
/// `SK_PASS` both accepts a socket THIS program assigned via
/// `bpf_sk_assign` AND, when no assignment was made, tells the kernel to
/// continue its normal lookup — the correct return for BOTH the matched and
/// unmatched cases in this rung (see `try_select` below). `SK_DROP` is never
/// returned by this program: a missing waypoint means "not ours to steer",
/// never "drop this traffic" (an `sk_lookup` program is netns-wide, so a
/// DROP verdict here would break every OTHER connection in the namespace,
/// not just the ones this rung cares about).
const SK_PASS: u32 = 1;

/// `AF_INET` — see `egress_redirect.rs` for the grounding citation.
const AF_INET: u32 = 2;
/// `IPPROTO_TCP` (grounded: `/usr/include/linux/in.h`, `IPPROTO_TCP = 6`).
const IPPROTO_TCP: u32 = 6;

/// Populated ONLY by `loader::InboundLookupInstaller` (userspace), after
/// `RedirectGate::authorize_redirect` approves this destination — see the
/// module docs' fail-closed section. The map's VALUE slot (implicit in
/// `SockHash`'s own map type, exactly as `SPLICE_SOCKS` uses it in
/// `main.rs`) holds the registered listening socket's fd.
///
/// Named `INBOUND_LISTEN`, not `INBOUND_LISTENERS`: the kernel truncates a
/// BPF map's own name to `BPF_OBJ_NAME_LEN - 1` = 15 characters — see
/// `egress_redirect.rs`'s identical note on `EGRESS_WAYPOINT` for the
/// `bpftool`-confirmed finding this crate's own map-level demo surfaced.
#[map]
static INBOUND_LISTEN: SockHash<InboundKey> = SockHash::with_max_entries(64, 0);

/// E2.13 (R13.5, kernel-side half): per-CPU verdict counters for every
/// incoming SYN whose destination MATCHED a registered `INBOUND_LISTEN`
/// entry — an `-ENOENT` miss (no registered listener) is never counted; see
/// this file's own doc comment above on why an `sk_lookup` program is
/// netns-wide, so counting every non-match would flood telemetry with
/// traffic this rung has no opinion on. Index 0 counts a match whose
/// `bpf_sk_assign` succeeded (the SYN was steered to the registered
/// listener); index 1 counts a match whose `bpf_sk_assign` itself FAILED —
/// a genuine kernel-side steering failure for an ALREADY-authorized
/// destination (the `NpampDropCode::InstallFailure` shape one layer below
/// `RedirectGate::authorize_redirect`).
#[map]
static INBOUND_VERDICT: PerCpuArray<u64> = PerCpuArray::with_max_entries(2, 0);

/// Verdict index: a matched destination's `bpf_sk_assign` succeeded.
const VERDICT_STEERED: u32 = 0;
/// Verdict index: a matched destination's `bpf_sk_assign` failed (an error
/// distinct from `-ENOENT`, which means no match at all — see
/// `try_select` below).
const VERDICT_STEER_FAILED: u32 = 1;

/// Increments `INBOUND_VERDICT[index]` on the CURRENT cpu's slot.
#[inline(always)]
fn bump_verdict(index: u32) {
    if let Some(ptr) = INBOUND_VERDICT.get_ptr_mut(index) {
        unsafe { *ptr += 1 };
    }
}

#[sk_lookup]
pub fn inbound_lookup_select(ctx: SkLookupContext) -> u32 {
    try_select(&ctx);
    SK_PASS
}

/// Builds this packet's destination key from the live `bpf_sk_lookup`
/// context (never a caller-supplied identity) and attempts to redirect it to
/// a registered listener. An `-ENOENT` result from `redirect_sk_lookup`
/// (no registered listener for this destination) is treated identically to
/// "no entry" and is NOT telemetry-worthy (see `INBOUND_VERDICT`'s doc
/// comment); any OTHER error means a match WAS found but `bpf_sk_assign`
/// itself failed — a genuine, countable steering failure. Either way the
/// packet falls through to the kernel's own lookup, never dropped.
fn try_select(ctx: &SkLookupContext) {
    let lookup = ctx.lookup;
    // SAFETY: `lookup` is the live `bpf_sk_lookup*` the kernel handed this
    // `sk_lookup` invocation. `family`/`protocol` are plain 4-byte reads;
    // `local_ip4`/`local_port` are the fields this rung's `InboundKey`
    // reproduces byte-for-byte (see `nz-agent-ebpf-common`'s doc comment on
    // `InboundKey` for the grounded byte-order citation: `local_ip4` network
    // order, `local_port` HOST order).
    let (family, protocol) = unsafe { ((*lookup).family, (*lookup).protocol) };
    if family != AF_INET || protocol != IPPROTO_TCP {
        return; // out of scope for this sub-unit; leave to normal lookup.
    }
    let key = unsafe { InboundKey { dest_ip: (*lookup).local_ip4, dest_port: (*lookup).local_port } };
    match INBOUND_LISTEN.redirect_sk_lookup(ctx, key, 0) {
        Ok(()) => bump_verdict(VERDICT_STEERED),
        Err(e) if e == -ENOENT => {} // no registered listener: not a match, not counted.
        Err(_) => bump_verdict(VERDICT_STEER_FAILED),
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
