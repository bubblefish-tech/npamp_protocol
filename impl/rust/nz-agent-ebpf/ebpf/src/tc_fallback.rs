// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! `tc_fallback`: the kernel side of R13-B-cont's TC-clsact fallback rung
//! (EBPF-DATAPATH-DESIGN.md: "TC-clsact fallback (the Istio-ambient path);
//! used when the fast-path techniques above are not applicable ... but a
//! recent-enough kernel with `CAP_BPF` can still attach a classifier
//! program"). One program, one map:
//!
//! - `tc_fallback` (`classifier`, TC-clsact-attached): for every packet on
//!   the attached interface, parses the raw Ethernet+IPv4+TCP headers,
//!   builds the flow's `(src_ip, dst_ip, src_port, dst_port)` key, and looks
//!   it up in `TC_WAYPOINTS`. If a waypoint is registered, DNATs the packet's
//!   destination IP/port to the waypoint in place (fixing up the IP and TCP
//!   checksums), steering it to this node's own `nz-agent`. If no waypoint
//!   is registered — or the packet is not a plain (no-options) IPv4/TCP
//!   packet — the packet is left untouched.
//!
//! # A context-shape finding this sub-unit's grounding pass surfaced
//!
//! Unlike `sk_msg_md` (used by `samenode_splice`) or `bpf_sk_lookup` (used
//! by `inbound_lookup`), a TC classifier's `__sk_buff` context has NO
//! `family`/`remote_ip4`/`local_ip4`/`remote_port`/`local_port` convenience
//! fields available to it — the uapi header (`linux/bpf.h`) documents that
//! block of `__sk_buff` fields as "Accessed by BPF_PROG_TYPE_sk_skb types
//! from here to ... here", explicitly excluding `BPF_PROG_TYPE_SCHED_CLS`
//! (what `#[classifier]` compiles to). `aya_ebpf::programs::TcContext`'s own
//! API confirms this: it exposes only raw packet primitives
//! (`load`/`load_bytes`/`store`/`l3_csum_replace`/`l4_csum_replace`/
//! `data`/`data_end`), no socket-address convenience accessor at all. This
//! program therefore parses the packet's own header bytes directly — the
//! standard TC-BPF DNAT pattern (the same shape used by, e.g., Cilium's
//! `bpf_lxc.c` and the classic `tc`-BPF NAT samples) — rather than reading a
//! context field, and every offset below is a fixed RFC 791 (IPv4) / RFC 793
//! (TCP) header layout constant, not a byte-order-narrowed context field.
//!
//! # The fail-closed property this file holds (R13.1)
//!
//! THIS file never writes `TC_WAYPOINTS` — that map is written ONLY from
//! userspace, in `loader/src/lib.rs`'s `TcFallbackInstaller`, reachable only
//! through `nz_agent::datapath::install_redirect` after
//! `nz_agent::datapath::RedirectGate::authorize_redirect` has already
//! approved this flow's (source, destination) pair. This program contains
//! no other map, so — like `inbound_lookup` — there is no authorization
//! bypass surface here at all.
//!
//! # Scope (fixed-offset parse; deliberate, documented, fail-closed)
//!
//! Only plain IPv4 (no IP options: IHL must be exactly 5, i.e. a 20-byte
//! header) carrying TCP is handled; anything else — a different ethertype,
//! an IPv4 header with options, UDP/ICMP/etc — is passed through completely
//! untouched (`TC_ACT_OK`, never dropped). A load/store/checksum-replace
//! failure (e.g. a truncated packet) also passes through untouched rather
//! than dropping: a TC-clsact fallback rung breaking traffic it does not
//! understand would be a worse failure than simply not accelerating it.
#![no_std]
#![no_main]

use aya_ebpf::bindings::TC_ACT_OK;
use aya_ebpf::macros::{classifier, map};
use aya_ebpf::maps::{HashMap, PerCpuArray};
use aya_ebpf::programs::TcContext;
use nz_agent_ebpf_common::{TcFlowKey, Waypoint};

/// Ethernet header: `ethertype` sits at byte offset 12 (after the 6-byte
/// destination + 6-byte source MAC addresses); the IPv4 header starts
/// immediately after the 14-byte Ethernet header.
const ETH_ETHERTYPE_OFFSET: usize = 12;
const ETH_HDR_LEN: usize = 14;
/// `ETH_P_IP` (0x0800) compared via `u16::from_be` against the raw
/// big-endian wire bytes `ctx.load` returns — see the `from_be` usage below.
const ETH_P_IP: u16 = 0x0800;

/// IPv4 header (RFC 791 §3.1), offsets relative to `ETH_HDR_LEN`:
/// byte 0 = version(4 bits)+IHL(4 bits), byte 9 = protocol, bytes 10-11 =
/// header checksum, bytes 12-15 = source address, bytes 16-19 = destination
/// address. `IP_HDR_LEN_NO_OPTIONS` (20) is the header length this program
/// requires (IHL == 5, i.e. no IP options) — see the module docs' scope note.
const IP_VER_IHL_OFFSET: usize = ETH_HDR_LEN;
const IP_PROTOCOL_OFFSET: usize = ETH_HDR_LEN + 9;
const IP_CHECKSUM_OFFSET: usize = ETH_HDR_LEN + 10;
const IP_SRC_OFFSET: usize = ETH_HDR_LEN + 12;
const IP_DST_OFFSET: usize = ETH_HDR_LEN + 16;
const IP_HDR_LEN_NO_OPTIONS: usize = 20;
/// `IPPROTO_TCP` — see `egress_redirect.rs`/`inbound_lookup.rs` for the
/// grounding citation (`/usr/include/linux/in.h`, `IPPROTO_TCP = 6`).
const IPPROTO_TCP: u8 = 6;

/// TCP header (RFC 793 §3.1), offsets relative to the TCP header's own
/// start (`ETH_HDR_LEN + IP_HDR_LEN_NO_OPTIONS`, valid only when IHL == 5):
/// bytes 0-1 = source port, bytes 2-3 = destination port, bytes 16-17 =
/// checksum.
const TCP_HDR_OFFSET: usize = ETH_HDR_LEN + IP_HDR_LEN_NO_OPTIONS;
const TCP_SRC_PORT_OFFSET: usize = TCP_HDR_OFFSET;
const TCP_DST_PORT_OFFSET: usize = TCP_HDR_OFFSET + 2;
const TCP_CHECKSUM_OFFSET: usize = TCP_HDR_OFFSET + 16;

/// `BPF_F_PSEUDO_HDR` (grounded: `/usr/include/linux/bpf.h`,
/// `BPF_F_PSEUDO_HDR = (1ULL << 4)`): tells `bpf_l4_csum_replace` the
/// changed field participates in the TCP pseudo-header checksum (true for an
/// IP-address change, false for a plain TCP-header-field change like the
/// destination port — see `try_fallback`'s two separate `l4_csum_replace`
/// calls below).
const BPF_F_PSEUDO_HDR: u64 = 1 << 4;

/// Populated ONLY by `loader::TcFallbackInstaller` (userspace), after
/// `RedirectGate::authorize_redirect` approves this flow — see the module
/// docs' fail-closed section.
#[map]
static TC_WAYPOINTS: HashMap<TcFlowKey, Waypoint> = HashMap::with_max_entries(64, 0);

/// E2.13 (R13.5, kernel-side half): per-CPU verdict counters for every packet
/// that MATCHED a registered `TC_WAYPOINTS` entry (a packet that missed —
/// no registered flow — is never counted here; see the module docs above
/// this map's sibling in `egress_redirect.rs`/`inbound_lookup.rs` for why a
/// netns/interface-wide miss is deliberately NOT telemetry-worthy). Index 0
/// counts a match whose DNAT rewrite (both checksum fixups + both header
/// stores) completed; index 1 counts a match whose rewrite FAILED partway
/// through — a genuine kernel-side steering failure for a flow that was
/// ALREADY authorized (an `nz_agent::datapath::NpampDropCode::InstallFailure`-
/// shaped event one layer lower than `RedirectGate::authorize_redirect`).
/// `PerCpuArray` avoids a cross-CPU atomic on the packet fast path — the
/// loader-side bridge (`loader/src/lib.rs`) sums across CPUs when reading.
#[map]
static TC_VERDICTS: PerCpuArray<u64> = PerCpuArray::with_max_entries(2, 0);

/// Verdict index: a matched flow's DNAT rewrite completed successfully.
const VERDICT_STEERED: u32 = 0;
/// Verdict index: a matched (already-authorized) flow's DNAT rewrite failed
/// partway through (a checksum-replace or header-store call returned an
/// error) — the packet was left untouched and passed through unrewritten.
const VERDICT_STEER_FAILED: u32 = 1;

/// Increments `TC_VERDICTS[index]` on the CURRENT cpu's slot. Never fails
/// silently in a way that changes behavior: if the map lookup itself somehow
/// misses (it cannot, for a fixed-size `PerCpuArray` indexed within bounds),
/// the counter is simply not incremented — the packet's own verdict
/// (steered/dropped) is decided entirely before this call and is never
/// affected by it.
#[inline(always)]
fn bump_verdict(index: u32) {
    if let Some(ptr) = TC_VERDICTS.get_ptr_mut(index) {
        unsafe { *ptr += 1 };
    }
}

#[classifier]
pub fn tc_fallback(ctx: TcContext) -> i32 {
    match try_fallback(&ctx) {
        Ok(action) | Err(action) => action,
    }
}

/// Parses the packet's own Ethernet+IPv4+TCP headers (see the module docs
/// for why: `TcContext` has no convenience socket-address fields), looks the
/// resulting flow up in `TC_WAYPOINTS`, and DNATs the packet in place if a
/// waypoint is registered. Every parse/rewrite step that can fail returns
/// `Err(TC_ACT_OK)` rather than propagating a drop — see the module docs'
/// scope note.
fn try_fallback(ctx: &TcContext) -> Result<i32, i32> {
    let ethertype: u16 = ctx.load(ETH_ETHERTYPE_OFFSET).map_err(|_| TC_ACT_OK as i32)?;
    if u16::from_be(ethertype) != ETH_P_IP {
        return Err(TC_ACT_OK as i32); // not IPv4: out of scope, leave untouched.
    }

    let ver_ihl: u8 = ctx.load(IP_VER_IHL_OFFSET).map_err(|_| TC_ACT_OK as i32)?;
    let version = ver_ihl >> 4;
    let ihl_words = ver_ihl & 0x0f;
    if version != 4 || usize::from(ihl_words) * 4 != IP_HDR_LEN_NO_OPTIONS {
        return Err(TC_ACT_OK as i32); // IP options present (or malformed version): out of scope.
    }

    let protocol: u8 = ctx.load(IP_PROTOCOL_OFFSET).map_err(|_| TC_ACT_OK as i32)?;
    if protocol != IPPROTO_TCP {
        return Err(TC_ACT_OK as i32); // UDP/ICMP/etc: out of scope for this sub-unit.
    }

    let src_ip: u32 = ctx.load(IP_SRC_OFFSET).map_err(|_| TC_ACT_OK as i32)?;
    let dst_ip: u32 = ctx.load(IP_DST_OFFSET).map_err(|_| TC_ACT_OK as i32)?;
    let src_port: u16 = ctx.load(TCP_SRC_PORT_OFFSET).map_err(|_| TC_ACT_OK as i32)?;
    let dst_port: u16 = ctx.load(TCP_DST_PORT_OFFSET).map_err(|_| TC_ACT_OK as i32)?;

    let key = TcFlowKey { src_ip, dst_ip, src_port: u32::from(src_port), dst_port: u32::from(dst_port) };
    let Some(waypoint) = (unsafe { TC_WAYPOINTS.get(&key) }) else {
        return Err(TC_ACT_OK as i32); // no registered waypoint: leave this flow untouched.
    };
    let waypoint = *waypoint;

    let new_dst_ip = waypoint.waypoint_ip;
    // `waypoint_port` is zero-extended in its high 16 bits (see
    // `EgressKey::dest_port`'s doc comment in `nz-agent-ebpf-common`); the
    // real TCP header field is 16 bits, so this truncates to exactly that.
    let new_dst_port = waypoint.waypoint_port as u16;

    // From here on this flow HAS a registered (already-authorized) waypoint:
    // every exit records a verdict (E2.13) — VERDICT_STEERED on total
    // success, VERDICT_STEER_FAILED the instant any rewrite step fails —
    // never neither, since a match was found.
    //
    // Fix up both checksums using the OLD values captured above BEFORE
    // overwriting the header bytes below. `l3_csum_replace`/`l4_csum_replace`
    // take explicit old/new values and do not themselves re-read the packet,
    // so this ordering (checksum-fixup, then store) is not load-bearing for
    // correctness, but keeping the old values in named variables (rather
    // than re-loading after the store) is what avoids ever reading a value
    // this function itself just changed.
    if ctx.l3_csum_replace(IP_CHECKSUM_OFFSET, u64::from(dst_ip), u64::from(new_dst_ip), 4).is_err() {
        bump_verdict(VERDICT_STEER_FAILED);
        return Err(TC_ACT_OK as i32);
    }
    // The destination-IP change touches the TCP pseudo-header, so this
    // update needs BPF_F_PSEUDO_HDR; the destination-PORT change (next call)
    // is a plain TCP-header field and does not.
    if ctx.l4_csum_replace(TCP_CHECKSUM_OFFSET, u64::from(dst_ip), u64::from(new_dst_ip), 4 | BPF_F_PSEUDO_HDR).is_err() {
        bump_verdict(VERDICT_STEER_FAILED);
        return Err(TC_ACT_OK as i32);
    }
    if ctx.l4_csum_replace(TCP_CHECKSUM_OFFSET, u64::from(dst_port), u64::from(new_dst_port), 2).is_err() {
        bump_verdict(VERDICT_STEER_FAILED);
        return Err(TC_ACT_OK as i32);
    }

    if ctx.store(IP_DST_OFFSET, &new_dst_ip, 0).is_err() {
        bump_verdict(VERDICT_STEER_FAILED);
        return Err(TC_ACT_OK as i32);
    }
    if ctx.store(TCP_DST_PORT_OFFSET, &new_dst_port, 0).is_err() {
        bump_verdict(VERDICT_STEER_FAILED);
        return Err(TC_ACT_OK as i32);
    }

    bump_verdict(VERDICT_STEERED);
    Ok(TC_ACT_OK as i32)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
