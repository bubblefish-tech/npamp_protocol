// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! `AyaSpliceInstaller`: the live implementation of
//! `nz_agent::datapath::SpliceInstaller` (R13-A's seam) that R13-B adds —
//! the real aya `SockHash`/`HashMap` map-updates a live `nz-agent` deployment
//! performs to install a same-node sockmap splice.
//!
//! # The fail-closed property this file holds (R13.1, one layer under `nz-agent`)
//!
//! `nz-agent`'s own `datapath.rs` already makes it structurally impossible
//! to call [`SpliceInstaller::install`] for an unauthorized pair — a
//! [`nz_agent::datapath::SpliceToken`] has no public constructor, so
//! `install` can only ever be invoked (via
//! `nz_agent::datapath::install_splice`) with a token
//! `SpliceGate::authorize_splice` actually approved. This crate adds ONE
//! further gate on top, entirely internal to [`AyaSpliceInstaller`]: `install`
//! also requires BOTH endpoints named by the token to have already been
//! [`AyaSpliceInstaller::register_socket`]'d. Registration alone never
//! touches [`SplicerBackend`] — it only stages an fd + derived [`ConnKey`] in
//! an in-memory table — so **the only code path in this crate that calls
//! [`SplicerBackend::insert_sock`]/[`SplicerBackend::link_peer`] (the two
//! real `bpf()` map-update operations) is `install`, reached only for a
//! token that is BOTH authorized AND fully registered.** Mutated away by
//! `M-ebpf-1` in `RED-EVIDENCE.md`.
//!
//! [`SplicerBackend`] exists so that invariant is testable without CAP_BPF
//! or a live kernel: `loader/tests/installer_gate.rs` exercises
//! [`AyaSpliceInstaller`] against a fake, in-memory backend — mirroring how
//! `nz-agent`'s own tests exercise `SpliceGate`/`install_splice` against
//! [`nz_agent::datapath::NoopSpliceInstaller`] one layer up.

use std::collections::HashMap as StdHashMap;
use std::net::{SocketAddr, SocketAddrV4};
use std::os::fd::{AsRawFd, RawFd};

use nz_agent::datapath::{DatapathError, RedirectToken, SpliceInstaller, SpliceToken, WaypointInstaller};
use nz_agent::identity::SpiffeId;
use nz_agent_ebpf_common::{ConnKey, EgressKey, InboundKey, TcFlowKey, Waypoint};

/// Derives a socket's own [`ConnKey`] from its (local, remote) address pair
/// — exactly what `TcpStream::local_addr()`/`peer_addr()` (or any live
/// connected socket) already reports, and exactly the fields the kernel-side
/// `sk_msg` program recomputes from `sk_msg_md` on every invocation
/// (`ebpf/src/main.rs::try_redirect`). IPv6 is out of scope for this
/// sub-unit (same-node loopback demo; `ConnKey` is IPv4-only) — an IPv6 pair
/// fails closed with `None` rather than silently truncating an address.
pub fn conn_key_of(local: SocketAddr, remote: SocketAddr) -> Option<ConnKey> {
    match (local, remote) {
        (SocketAddr::V4(l), SocketAddr::V4(r)) => Some(ConnKey {
            local_ip: u32::from_ne_bytes(l.ip().octets()),
            remote_ip: u32::from_ne_bytes(r.ip().octets()),
            // The kernel's `sk_msg_md` exposes `local_port` in HOST byte order
            // but `remote_port` in NETWORK byte order (uapi linux/bpf.h), and
            // its ctx-access rewrite places `remote_port` in the high 16 bits on
            // little-endian hosts. `ebpf/src/main.rs::try_redirect` reads those
            // fields RAW to build the `SPLICE_PEER` lookup key, so this stored
            // key MUST reproduce that exact layout or the lookup misses and the
            // redirect never fires (R13-D: verified end-to-end by the
            // `load_demo` data-plane splice + `bpftool map dump`).
            local_port: u32::from(l.port()),
            remote_port: (r.port() as u32).to_be(),
        }),
        _ => None,
    }
}

/// The seam a real kernel-backed splice takes: exactly the two `bpf()`
/// syscall-performing operations `AyaSpliceInstaller::install` needs,
/// abstracted so the fail-closed GATING logic above it is testable without
/// CAP_BPF/a live kernel (see the module docs).
pub trait SplicerBackend {
    /// Inserts `fd` into the kernel's `SPLICE_SOCKS` sockhash under `key` —
    /// a real `bpf(BPF_MAP_UPDATE_ELEM)` in [`RealAyaBackend`].
    fn insert_sock(&mut self, key: ConnKey, fd: RawFd) -> Result<(), String>;
    /// Records that `a`'s splice partner is `b` in `SPLICE_PEER` — a real
    /// `bpf(BPF_MAP_UPDATE_ELEM)` in [`RealAyaBackend`]. Callers link both
    /// directions (`a -> b` and `b -> a`) so either socket's `sk_msg`
    /// invocation finds its partner.
    fn link_peer(&mut self, a: ConnKey, b: ConnKey) -> Result<(), String>;
}

/// The real aya-backed [`SplicerBackend`]: owns the loaded `SPLICE_SOCKS`
/// (`SockHash`) and `SPLICE_PEER` (`HashMap`) maps taken from a live
/// `aya::Ebpf`, and performs the actual kernel map-updates R13-B's A9
/// demonstration exercises. Requires `CAP_BPF` and a loaded
/// `samenode_splice` object to construct (see `src/bin/load_demo.rs`) — this
/// is the ONLY part of this crate that needs a live, privileged kernel.
pub struct RealAyaBackend {
    socks: aya::maps::SockHash<aya::maps::MapData, ConnKey>,
    peer: aya::maps::HashMap<aya::maps::MapData, ConnKey, ConnKey>,
}

impl RealAyaBackend {
    pub fn new(
        socks: aya::maps::SockHash<aya::maps::MapData, ConnKey>,
        peer: aya::maps::HashMap<aya::maps::MapData, ConnKey, ConnKey>,
    ) -> RealAyaBackend {
        RealAyaBackend { socks, peer }
    }
}

impl SplicerBackend for RealAyaBackend {
    fn insert_sock(&mut self, key: ConnKey, fd: RawFd) -> Result<(), String> {
        self.socks.insert(key, fd, 0).map_err(|e| e.to_string())
    }

    fn link_peer(&mut self, a: ConnKey, b: ConnKey) -> Result<(), String> {
        self.peer.insert(a, b, 0).map_err(|e| e.to_string())
    }
}

/// A socket endpoint registered with [`AyaSpliceInstaller::register_socket`]
/// but not yet (or not necessarily ever) spliced.
struct Registered {
    key: ConnKey,
    fd: RawFd,
}

/// [`nz_agent::datapath::SpliceInstaller`] backed by a real (or, in tests,
/// fake) [`SplicerBackend`]. See the module docs for the fail-closed
/// property this type holds.
pub struct AyaSpliceInstaller<B: SplicerBackend> {
    backend: B,
    registered: StdHashMap<SpiffeId, Registered>,
}

impl<B: SplicerBackend> AyaSpliceInstaller<B> {
    pub fn new(backend: B) -> AyaSpliceInstaller<B> {
        AyaSpliceInstaller { backend, registered: StdHashMap::new() }
    }

    /// Stages a live socket as the candidate splice endpoint for `id`.
    /// Touches ONLY this instance's in-memory table — no `SplicerBackend`
    /// call, no kernel map write. `socket` must be an `AsRawFd` whose
    /// `local_addr`/`peer_addr` this function reads via the two callback-
    /// style getters (`local`, `remote`) rather than requiring
    /// `std::net::TcpStream` specifically, so a caller (or a test) can
    /// register any live connected socket.
    pub fn register_socket<S: AsRawFd>(
        &mut self,
        id: SpiffeId,
        socket: &S,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Result<(), DatapathError> {
        let key = conn_key_of(local, remote)
            .ok_or_else(|| DatapathError::InstallFailed("IPv6 socket: not supported by this sub-unit's ConnKey scheme".to_string()))?;
        self.registered.insert(id, Registered { key, fd: socket.as_raw_fd() });
        Ok(())
    }

    /// Returns the [`ConnKey`] this instance derived for `id`, if
    /// registered — used by the demo/tests to assert the map holds the
    /// EXACT key the kernel program will independently recompute.
    pub fn key_of(&self, id: &SpiffeId) -> Option<ConnKey> {
        self.registered.get(id).map(|r| r.key)
    }

    /// Read access to the underlying [`SplicerBackend`] — for the demo
    /// binary (to hand the real `aya` maps to `bpftool`-verifiable state)
    /// and for tests (to assert exactly which calls a fake backend
    /// recorded). Mirrors `nz_agent::datapath::NoopSpliceInstaller`'s own
    /// public `installed` field one layer up: the backend's recorded state
    /// is observability, not a hidden implementation detail.
    pub fn backend(&self) -> &B {
        &self.backend
    }
}

impl<B: SplicerBackend> SpliceInstaller for AyaSpliceInstaller<B> {
    /// Only reachable via `nz_agent::datapath::install_splice`, and only
    /// after `SpliceGate::authorize_splice` has already returned this exact
    /// `token` — see the module docs. Requires both `token.source()` and
    /// `token.destination()` to have been `register_socket`'d; if either is
    /// missing, returns `Err` WITHOUT calling `self.backend` at all (no
    /// partial/garbage map write).
    fn install(&mut self, token: &SpliceToken) -> Result<(), DatapathError> {
        let src = self
            .registered
            .get(token.source())
            .ok_or_else(|| DatapathError::InstallFailed(format!("source socket not registered: {}", token.source())))?;
        let dst = self
            .registered
            .get(token.destination())
            .ok_or_else(|| DatapathError::InstallFailed(format!("destination socket not registered: {}", token.destination())))?;
        let (src_key, src_fd) = (src.key, src.fd);
        let (dst_key, dst_fd) = (dst.key, dst.fd);

        self.backend.insert_sock(src_key, src_fd).map_err(DatapathError::InstallFailed)?;
        self.backend.insert_sock(dst_key, dst_fd).map_err(DatapathError::InstallFailed)?;
        self.backend.link_peer(src_key, dst_key).map_err(DatapathError::InstallFailed)?;
        self.backend.link_peer(dst_key, src_key).map_err(DatapathError::InstallFailed)?;
        Ok(())
    }
}

// =====================================================================
// R13-B-cont — egress_redirect (`CgroupRedirect` rung, `cgroup/connect4`)
// =====================================================================

/// Derives the [`EgressKey`] a given (original) destination corresponds to.
///
/// Both fields network order, matching `bpf_sock_addr::user_ip4`/
/// `user_port`'s own convention — grounded against the Linux kernel's own
/// `tools/testing/selftests/bpf/progs/connect4_prog.c`, which sets
/// `ctx->user_port = bpf_htons(port)`: a plain 16-bit-value assignment into
/// the 32-bit field, i.e. the network-order port lives in the LOW 16 bits,
/// zero-extended upward — the OPPOSITE placement from `sk_msg_md::remote_port`
/// (see [`conn_key_of`] above, `.to_be()` on the already-widened `u32`,
/// fixed by R13-D to land in the HIGH 16 bits). This is exactly the "each
/// context has its own documented byte order" property this sub-unit's
/// grounding pass was told to expect, and it is UNVERIFIED against a live
/// kernel by this sub-unit (see the R13-B-cont report's "what was not
/// verified" section) — R13-D's `remote_port` fix was confirmed by an actual
/// data-plane redirect; this one is confirmed only against the kernel
/// selftest SOURCE, not by observing a real rewritten `connect()` land at
/// the right port on this host.
pub fn egress_key_of(dest: SocketAddrV4) -> EgressKey {
    EgressKey { dest_ip: u32::from_ne_bytes(dest.ip().octets()), dest_port: u32::from(dest.port().to_be()) }
}

/// Derives the [`Waypoint`] a given local waypoint address corresponds to —
/// same byte-order convention as [`egress_key_of`] (both fields ultimately
/// get copied into `ctx.user_ip4`/`ctx.user_port` verbatim by
/// `ebpf/src/egress_redirect.rs`, so they share its byte-order contract).
pub fn waypoint_of(addr: SocketAddrV4) -> Waypoint {
    Waypoint { waypoint_ip: u32::from_ne_bytes(addr.ip().octets()), waypoint_port: u32::from(addr.port().to_be()) }
}

/// The seam a real kernel-backed `egress_redirect` install takes: the one
/// `bpf()` map-update operation [`EgressRedirectInstaller::install`] needs,
/// abstracted for the same testability reason [`SplicerBackend`] is (see
/// that trait's doc comment).
pub trait EgressBackend {
    /// Inserts `key -> waypoint` into the kernel's `EGRESS_WAYPOINT` map —
    /// a real `bpf(BPF_MAP_UPDATE_ELEM)` in [`RealAyaEgressBackend`].
    fn insert_waypoint(&mut self, key: EgressKey, waypoint: Waypoint) -> Result<(), String>;
}

/// The real aya-backed [`EgressBackend`]: owns the loaded `EGRESS_WAYPOINT`
/// map taken from a live `aya::Ebpf`.
pub struct RealAyaEgressBackend {
    waypoints: aya::maps::HashMap<aya::maps::MapData, EgressKey, Waypoint>,
}

impl RealAyaEgressBackend {
    pub fn new(waypoints: aya::maps::HashMap<aya::maps::MapData, EgressKey, Waypoint>) -> RealAyaEgressBackend {
        RealAyaEgressBackend { waypoints }
    }
}

impl EgressBackend for RealAyaEgressBackend {
    fn insert_waypoint(&mut self, key: EgressKey, waypoint: Waypoint) -> Result<(), String> {
        self.waypoints.insert(key, waypoint, 0).map_err(|e| e.to_string())
    }
}

/// A destination registered with [`EgressRedirectInstaller::register_destination`]
/// but not yet (or not necessarily ever) installed.
struct RegisteredEgress {
    destination: EgressKey,
    waypoint: Waypoint,
}

/// [`WaypointInstaller`] backed by a real (or, in tests, fake)
/// [`EgressBackend`]. Mirrors [`AyaSpliceInstaller`]'s registration-then-
/// install shape one-sidedly: unlike a socket splice (which needs TWO live
/// fds, one per endpoint), a `cgroup/connect4` waypoint entry is keyed
/// purely by the ORIGINAL destination a workload intends to reach — there is
/// no per-source fd this rung's kernel program ever consults (it observes
/// whichever process happens to call `connect()` inside the attached
/// cgroup), so only the DESTINATION side is registered here. `install` still
/// requires that registration to exist before it ever calls
/// [`EgressBackend::insert_waypoint`] — the fail-closed shape M-ebpf-1
/// exercises for the splice installer, applied to this rung's one-sided
/// registration model.
pub struct EgressRedirectInstaller<B: EgressBackend> {
    backend: B,
    registered: StdHashMap<SpiffeId, RegisteredEgress>,
}

impl<B: EgressBackend> EgressRedirectInstaller<B> {
    pub fn new(backend: B) -> EgressRedirectInstaller<B> {
        EgressRedirectInstaller { backend, registered: StdHashMap::new() }
    }

    /// Stages the (original destination, local waypoint) pair a `destination`
    /// SpiffeId should be redirected through. Touches ONLY this instance's
    /// in-memory table — no [`EgressBackend`] call, no kernel map write.
    pub fn register_destination(&mut self, destination: SpiffeId, dest: SocketAddrV4, waypoint: SocketAddrV4) {
        self.registered.insert(destination, RegisteredEgress { destination: egress_key_of(dest), waypoint: waypoint_of(waypoint) });
    }

    /// Returns the [`EgressKey`] this instance derived for `destination`, if
    /// registered.
    pub fn key_of(&self, destination: &SpiffeId) -> Option<EgressKey> {
        self.registered.get(destination).map(|r| r.destination)
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }
}

impl<B: EgressBackend> WaypointInstaller for EgressRedirectInstaller<B> {
    /// Only reachable via `nz_agent::datapath::install_redirect`, and only
    /// after `RedirectGate::authorize_redirect` has already returned this
    /// exact `token`. Requires `token.destination()` to have been
    /// `register_destination`'d; if missing, returns `Err` WITHOUT calling
    /// `self.backend` at all.
    fn install(&mut self, token: &RedirectToken) -> Result<(), DatapathError> {
        let reg = self
            .registered
            .get(token.destination())
            .ok_or_else(|| DatapathError::InstallFailed(format!("egress destination not registered: {}", token.destination())))?;
        self.backend.insert_waypoint(reg.destination, reg.waypoint).map_err(DatapathError::InstallFailed)
    }
}

// =====================================================================
// R13-B-cont — inbound_lookup (inbound-steering rung, `sk_lookup`)
// =====================================================================

/// Derives the [`InboundKey`] a given local (bound) destination corresponds
/// to.
///
/// **Deliberately asymmetric vs [`egress_key_of`]:** `dest_ip` is network
/// order (matches `bpf_sk_lookup::local_ip4`) but `dest_port` is HOST order
/// (matches `bpf_sk_lookup::local_port` — confirmed directly from this
/// host's own `/usr/include/linux/bpf.h` uapi struct comment, not inferred).
/// This mirrors `ConnKey`'s own local-port-is-host-order convention in
/// `ebpf/src/main.rs`, just on `bpf_sk_lookup`'s local side rather than
/// `sk_msg_md`'s (both crate-internal precedents agree, AND the uapi header
/// itself says so directly for this field — this one IS confirmed by
/// primary source, not by inference from a sibling context).
pub fn inbound_key_of(dest: SocketAddrV4) -> InboundKey {
    InboundKey { dest_ip: u32::from_ne_bytes(dest.ip().octets()), dest_port: u32::from(dest.port()) }
}

/// The seam a real kernel-backed `inbound_lookup` install takes: the one
/// `bpf()` map-update operation [`InboundLookupInstaller::install`] needs.
pub trait InboundBackend {
    /// Inserts `fd` into the kernel's `INBOUND_LISTEN` sockhash under
    /// `key` — a real `bpf(BPF_MAP_UPDATE_ELEM)` in
    /// [`RealAyaInboundBackend`].
    fn insert_listener(&mut self, key: InboundKey, fd: RawFd) -> Result<(), String>;
}

/// The real aya-backed [`InboundBackend`]: owns the loaded
/// `INBOUND_LISTEN` `SockHash` taken from a live `aya::Ebpf`.
pub struct RealAyaInboundBackend {
    listeners: aya::maps::SockHash<aya::maps::MapData, InboundKey>,
}

impl RealAyaInboundBackend {
    pub fn new(listeners: aya::maps::SockHash<aya::maps::MapData, InboundKey>) -> RealAyaInboundBackend {
        RealAyaInboundBackend { listeners }
    }
}

impl InboundBackend for RealAyaInboundBackend {
    fn insert_listener(&mut self, key: InboundKey, fd: RawFd) -> Result<(), String> {
        self.listeners.insert(key, fd, 0).map_err(|e| e.to_string())
    }
}

/// A listener registered with
/// [`InboundLookupInstaller::register_listener`] but not yet (or not
/// necessarily ever) installed.
struct RegisteredListener {
    key: InboundKey,
    fd: RawFd,
}

/// [`WaypointInstaller`] backed by a real (or, in tests, fake)
/// [`InboundBackend`]. One-sided registration, same shape as
/// [`EgressRedirectInstaller`]: `sk_lookup` steers by DESTINATION only (the
/// "source" of an inbound connection is, by definition, an arbitrary remote
/// peer this node does not register).
pub struct InboundLookupInstaller<B: InboundBackend> {
    backend: B,
    registered: StdHashMap<SpiffeId, RegisteredListener>,
}

impl<B: InboundBackend> InboundLookupInstaller<B> {
    pub fn new(backend: B) -> InboundLookupInstaller<B> {
        InboundLookupInstaller { backend, registered: StdHashMap::new() }
    }

    /// Stages `socket` (nz-agent's own listening socket) as the delivery
    /// target for inbound connections addressed to `dest`, under
    /// `destination`'s identity. Touches ONLY this instance's in-memory
    /// table — no [`InboundBackend`] call, no kernel map write.
    pub fn register_listener<S: AsRawFd>(&mut self, destination: SpiffeId, socket: &S, dest: SocketAddrV4) {
        self.registered.insert(destination, RegisteredListener { key: inbound_key_of(dest), fd: socket.as_raw_fd() });
    }

    pub fn key_of(&self, destination: &SpiffeId) -> Option<InboundKey> {
        self.registered.get(destination).map(|r| r.key)
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }
}

impl<B: InboundBackend> WaypointInstaller for InboundLookupInstaller<B> {
    fn install(&mut self, token: &RedirectToken) -> Result<(), DatapathError> {
        let reg = self
            .registered
            .get(token.destination())
            .ok_or_else(|| DatapathError::InstallFailed(format!("inbound listener not registered: {}", token.destination())))?;
        self.backend.insert_listener(reg.key, reg.fd).map_err(DatapathError::InstallFailed)
    }
}

// =====================================================================
// R13-B-cont — tc_fallback (TC-clsact fallback rung, `classifier`)
// =====================================================================

/// Derives the [`TcFlowKey`] a given (source, destination) flow corresponds
/// to. All four fields network order — matches raw wire bytes exactly as
/// `ebpf/src/tc_fallback.rs` parses them off the packet (RFC 791/793 fix
/// IPv4/TCP header byte order as big-endian); the same
/// zero-extend-the-be16-into-the-low-16-bits convention `egress_key_of`
/// uses, because it is the SAME operation `tc_fallback.rs`'s own
/// `u32::from(src_port)`/`u32::from(dst_port)` performs on a value it just
/// loaded as a genuine 16-bit wire field.
pub fn tc_flow_key_of(src: SocketAddrV4, dst: SocketAddrV4) -> TcFlowKey {
    TcFlowKey {
        src_ip: u32::from_ne_bytes(src.ip().octets()),
        dst_ip: u32::from_ne_bytes(dst.ip().octets()),
        src_port: u32::from(src.port().to_be()),
        dst_port: u32::from(dst.port().to_be()),
    }
}

/// The seam a real kernel-backed `tc_fallback` install takes: the one
/// `bpf()` map-update operation [`TcFallbackInstaller::install`] needs.
pub trait TcBackend {
    /// Inserts `key -> waypoint` into the kernel's `TC_WAYPOINTS` map — a
    /// real `bpf(BPF_MAP_UPDATE_ELEM)` in [`RealAyaTcBackend`].
    fn insert_flow_waypoint(&mut self, key: TcFlowKey, waypoint: Waypoint) -> Result<(), String>;
}

/// The real aya-backed [`TcBackend`]: owns the loaded `TC_WAYPOINTS` map
/// taken from a live `aya::Ebpf`.
pub struct RealAyaTcBackend {
    waypoints: aya::maps::HashMap<aya::maps::MapData, TcFlowKey, Waypoint>,
}

impl RealAyaTcBackend {
    pub fn new(waypoints: aya::maps::HashMap<aya::maps::MapData, TcFlowKey, Waypoint>) -> RealAyaTcBackend {
        RealAyaTcBackend { waypoints }
    }
}

impl TcBackend for RealAyaTcBackend {
    fn insert_flow_waypoint(&mut self, key: TcFlowKey, waypoint: Waypoint) -> Result<(), String> {
        self.waypoints.insert(key, waypoint, 0).map_err(|e| e.to_string())
    }
}

/// A flow registered with [`TcFallbackInstaller::register_flow`] but not yet
/// (or not necessarily ever) installed.
struct RegisteredFlow {
    key: TcFlowKey,
    waypoint: Waypoint,
}

/// [`WaypointInstaller`] backed by a real (or, in tests, fake) [`TcBackend`].
pub struct TcFallbackInstaller<B: TcBackend> {
    backend: B,
    registered: StdHashMap<SpiffeId, RegisteredFlow>,
}

impl<B: TcBackend> TcFallbackInstaller<B> {
    pub fn new(backend: B) -> TcFallbackInstaller<B> {
        TcFallbackInstaller { backend, registered: StdHashMap::new() }
    }

    /// Stages the (flow, waypoint) pair `destination`'s identity should be
    /// redirected through. Touches ONLY this instance's in-memory table — no
    /// [`TcBackend`] call, no kernel map write.
    pub fn register_flow(&mut self, destination: SpiffeId, src: SocketAddrV4, dst: SocketAddrV4, waypoint: SocketAddrV4) {
        self.registered.insert(destination, RegisteredFlow { key: tc_flow_key_of(src, dst), waypoint: waypoint_of(waypoint) });
    }

    pub fn key_of(&self, destination: &SpiffeId) -> Option<TcFlowKey> {
        self.registered.get(destination).map(|r| r.key)
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }
}

impl<B: TcBackend> WaypointInstaller for TcFallbackInstaller<B> {
    fn install(&mut self, token: &RedirectToken) -> Result<(), DatapathError> {
        let reg = self
            .registered
            .get(token.destination())
            .ok_or_else(|| DatapathError::InstallFailed(format!("tc flow not registered: {}", token.destination())))?;
        self.backend.insert_flow_waypoint(reg.key, reg.waypoint).map_err(DatapathError::InstallFailed)
    }
}

// =====================================================================
// E2.13 (R13.5, kernel-side half) — the eBPF-side flow/verdict telemetry
// bridge `nz_agent::telemetry`'s own module docs name as a tracked gap:
// "a future kernel-side bridge would call the SAME TelemetrySink::export
// seam this module defines, not a new one." This is that bridge.
// =====================================================================

/// The seam a live deployment supplies to read one rung's kernel-side
/// verdict counters (`EGRESS_VERDICTS`/`INBOUND_VERDICT`/`TC_VERDICTS` — all
/// three kernel programs in this crate use the SAME two-index convention:
/// index 0 = a matched flow's kernel-side steering succeeded, index 1 = a
/// matched flow's kernel-side steering FAILED after authorization already
/// approved it). Abstracted for the same testability reason
/// [`SplicerBackend`]/[`EgressBackend`]/[`InboundBackend`]/[`TcBackend`] are.
pub trait VerdictCounters {
    /// Returns `(steered_total, steer_failed_total)` — the CUMULATIVE
    /// counter values (summed across every CPU for a real backend), never a
    /// delta; [`VerdictBridge::poll_into`] computes the delta itself so a
    /// caller can poll as often as it likes without double-exporting.
    fn read_totals(&self) -> Result<(u64, u64), String>;
}

/// The real aya-backed [`VerdictCounters`]: owns a loaded `PerCpuArray<u64>`
/// taken from a live `aya::Ebpf` (any of the three rungs' verdict maps — the
/// map shape is identical across all three, so one backend type serves all).
pub struct RealAyaVerdictCounters {
    map: aya::maps::PerCpuArray<aya::maps::MapData, u64>,
}

impl RealAyaVerdictCounters {
    pub fn new(map: aya::maps::PerCpuArray<aya::maps::MapData, u64>) -> RealAyaVerdictCounters {
        RealAyaVerdictCounters { map }
    }
}

impl VerdictCounters for RealAyaVerdictCounters {
    fn read_totals(&self) -> Result<(u64, u64), String> {
        let steered: u64 = self.map.get(&0, 0).map_err(|e| e.to_string())?.iter().sum();
        let steer_failed: u64 = self.map.get(&1, 0).map_err(|e| e.to_string())?.iter().sum();
        Ok((steered, steer_failed))
    }
}

/// Turns kernel-observed STEER FAILURES (index 1 of any rung's verdict
/// counter) into real [`nz_agent::telemetry::TelemetrySink::export`] calls,
/// keyed exactly as `nz_agent::datapath`'s own module docs specify
/// ("authenticated peer SPIFFE id + carriage class + session/tunnel id").
///
/// Deliberately does NOT export anything for a SUCCESSFUL steer (index 0):
/// [`nz_agent::datapath::DropEvent`]/`TelemetrySink` model DROPS — a
/// successful kernel-side steer is not one, and synthesizing a fake "drop"
/// for it would misuse the drop-specific seam this bridge composes with,
/// not extend it. A live deployment that also wants to export STEERED
/// counts has [`VerdictBridge::poll_into`]'s own `steered_delta` return
/// value available for a separate (non-drop) metrics path — this bridge's
/// job is exactly the tracked gap `nz_agent::telemetry`'s module docs name,
/// no more.
///
/// Stateful by design: [`VerdictBridge::poll_into`] computes the delta
/// against the LAST poll's totals (a `PerCpuArray` counter only increases,
/// so `saturating_sub` is exact whenever the counter has not been reset
/// out from under this bridge — e.g. by an eBPF object reload), and exports
/// exactly one [`nz_agent::datapath::DropEvent`] per UNIT increase in the
/// steer-failed total, so a caller polling at any cadence never double-
/// counts and never silently drops a real kernel-observed failure between
/// polls.
pub struct VerdictBridge<V: VerdictCounters> {
    counters: V,
    last_steered: u64,
    last_steer_failed: u64,
    /// The `DropEvent.carriage` label this bridge's rung is reported under
    /// (e.g. `"npamp-datapath-egress-redirect"`).
    rung: String,
    peer: SpiffeId,
    session: String,
}

impl<V: VerdictCounters> VerdictBridge<V> {
    pub fn new(counters: V, rung: impl Into<String>, peer: SpiffeId, session: impl Into<String>) -> VerdictBridge<V> {
        VerdictBridge { counters, last_steered: 0, last_steer_failed: 0, rung: rung.into(), peer, session: session.into() }
    }

    /// Polls the kernel counters once, exports one
    /// [`nz_agent::datapath::DropEvent`] through `sink` per unit increase in
    /// the steer-failed total since the LAST poll, and returns
    /// `(steered_delta, steer_failed_delta)` for the caller's own (non-drop)
    /// observability if it wants it.
    pub fn poll_into(&mut self, sink: &dyn nz_agent::telemetry::TelemetrySink) -> Result<(u64, u64), String> {
        let (steered, steer_failed) = self.counters.read_totals()?;
        let steered_delta = steered.saturating_sub(self.last_steered);
        let steer_failed_delta = steer_failed.saturating_sub(self.last_steer_failed);
        for _ in 0..steer_failed_delta {
            sink.export(&nz_agent::datapath::DropEvent {
                code: nz_agent::datapath::NpampDropCode::InstallFailure,
                peer: self.peer.clone(),
                carriage: self.rung.clone(),
                session: self.session.clone(),
            });
        }
        self.last_steered = steered;
        self.last_steer_failed = steer_failed;
        Ok((steered_delta, steer_failed_delta))
    }
}

#[cfg(test)]
mod verdict_bridge_tests {
    use std::cell::RefCell;

    use nz_agent::datapath::{DropEvent, NpampDropCode};
    use nz_agent::telemetry::TelemetrySink;

    use super::*;

    /// A scripted, in-memory [`VerdictCounters`] test double: returns the
    /// next `(steered, steer_failed)` pair from a fixed sequence on each
    /// call, mirroring this crate's other fake-backend test doubles
    /// (`SplicerBackend`/`EgressBackend`/etc.).
    struct ScriptedCounters {
        sequence: RefCell<std::vec::IntoIter<(u64, u64)>>,
    }

    impl ScriptedCounters {
        fn new(sequence: Vec<(u64, u64)>) -> ScriptedCounters {
            ScriptedCounters { sequence: RefCell::new(sequence.into_iter()) }
        }
    }

    impl VerdictCounters for ScriptedCounters {
        fn read_totals(&self) -> Result<(u64, u64), String> {
            self.sequence.borrow_mut().next().ok_or_else(|| "ScriptedCounters exhausted".to_string())
        }
    }

    /// Records every [`DropEvent`] `export`ed into it — the assertion target
    /// for every test below.
    #[derive(Default)]
    struct RecordingSink {
        events: RefCell<Vec<DropEvent>>,
    }

    impl TelemetrySink for RecordingSink {
        fn export(&self, event: &DropEvent) {
            self.events.borrow_mut().push(event.clone());
        }
    }

    fn peer(path: &str) -> SpiffeId {
        SpiffeId::parse(&format!("spiffe://cluster.local/ns/prod/sa/{path}")).expect("valid id")
    }

    /// Mutated away by M-verdict-1 in RED-EVIDENCE.md: a bridge that exports
    /// on the STEERED delta instead of (or in addition to) the STEER_FAILED
    /// delta would make this test fail (a spurious export with zero
    /// steer-failed events).
    #[test]
    fn a_pure_steered_increase_exports_nothing() {
        let counters = ScriptedCounters::new(vec![(0, 0), (5, 0)]);
        let mut bridge = VerdictBridge::new(counters, "npamp-datapath-egress-redirect", peer("dst"), "sess-1");
        let sink = RecordingSink::default();
        bridge.poll_into(&sink).expect("baseline poll");
        let (steered_delta, steer_failed_delta) = bridge.poll_into(&sink).expect("second poll");
        assert_eq!(steered_delta, 5);
        assert_eq!(steer_failed_delta, 0);
        assert!(sink.events.borrow().is_empty(), "a successful steer must never be exported as a DropEvent");
    }

    #[test]
    fn a_single_steer_failed_increase_exports_exactly_one_drop_event() {
        let counters = ScriptedCounters::new(vec![(0, 0), (0, 1)]);
        let mut bridge = VerdictBridge::new(counters, "npamp-datapath-inbound-lookup", peer("svc-inbound"), "sess-42");
        let sink = RecordingSink::default();
        bridge.poll_into(&sink).expect("baseline poll");
        let (_, steer_failed_delta) = bridge.poll_into(&sink).expect("second poll");
        assert_eq!(steer_failed_delta, 1);
        let events = sink.events.borrow();
        assert_eq!(events.len(), 1, "exactly one export per unit increase in steer_failed");
        assert_eq!(events[0].code, NpampDropCode::InstallFailure);
        assert_eq!(events[0].peer, peer("svc-inbound"));
        assert_eq!(events[0].carriage, "npamp-datapath-inbound-lookup");
        assert_eq!(events[0].session, "sess-42");
    }

    /// Mutated away by M-verdict-2 in RED-EVIDENCE.md: a bridge that exports
    /// only once per POLL (rather than once per UNIT of delta) would report
    /// 1 event here instead of 3, silently under-reporting real kernel
    /// failures that happened between two polls.
    #[test]
    fn multiple_unit_increases_between_polls_export_one_event_each() {
        let counters = ScriptedCounters::new(vec![(0, 0), (2, 3)]);
        let mut bridge = VerdictBridge::new(counters, "npamp-datapath-tc-fallback", peer("dst"), "sess-1");
        let sink = RecordingSink::default();
        bridge.poll_into(&sink).expect("baseline poll");
        bridge.poll_into(&sink).expect("second poll");
        assert_eq!(sink.events.borrow().len(), 3);
    }

    #[test]
    fn a_poll_with_no_change_since_the_previous_poll_exports_nothing() {
        // Three totals-readings: (0,0) establishes the baseline, (4,2) is
        // the first real observation (a genuine delta, correctly exported),
        // and the THIRD reading repeats (4,2) unchanged — that third poll is
        // the one under test: it must report zero deltas and export nothing
        // more, because nothing NEW happened since the second poll.
        let counters = ScriptedCounters::new(vec![(0, 0), (4, 2), (4, 2)]);
        let mut bridge = VerdictBridge::new(counters, "npamp-datapath-egress-redirect", peer("dst"), "sess-1");
        let sink = RecordingSink::default();
        bridge.poll_into(&sink).expect("baseline poll"); // (0,0): 0 deltas
        bridge.poll_into(&sink).expect("first real reading"); // (4,2): 2 exports
        assert_eq!(sink.events.borrow().len(), 2);
        let (steered_delta, steer_failed_delta) = bridge.poll_into(&sink).expect("unchanged reading");
        assert_eq!((steered_delta, steer_failed_delta), (0, 0));
        assert_eq!(sink.events.borrow().len(), 2, "an unchanged reading must export nothing further");
    }

    #[test]
    fn consecutive_failure_deltas_across_three_polls_each_export_correctly() {
        let counters = ScriptedCounters::new(vec![(0, 0), (0, 1), (0, 1), (0, 3)]);
        let mut bridge = VerdictBridge::new(counters, "npamp-datapath-tc-fallback", peer("dst"), "sess-1");
        let sink = RecordingSink::default();
        bridge.poll_into(&sink).expect("p0"); // baseline
        bridge.poll_into(&sink).expect("p1"); // +1 failed -> 1 event
        bridge.poll_into(&sink).expect("p2"); // +0 failed -> 0 events
        bridge.poll_into(&sink).expect("p3"); // +2 failed -> 2 events
        assert_eq!(sink.events.borrow().len(), 3);
    }
}
