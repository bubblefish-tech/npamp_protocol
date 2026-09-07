// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! eBPF datapath selection + fast-path authorization gate (R13-A, the
//! userspace-selector rung of Requirement 13; design: EBPF-DATAPATH-DESIGN.md).
//!
//! # Scope of THIS module (R13-A only)
//!
//! This module builds the capability-probed strategy selector
//! ([`DatapathSelector`]), the fast-path authorization gate ([`SpliceGate`]),
//! and named-code drop telemetry ([`DropEvent`]/[`NpampDropCode`]) — all pure
//! userspace logic requiring no kernel privilege. It does NOT build: the
//! eBPF program sources (C/aya), a kernel loader, the Windows WFP callout
//! driver, or the acceleration benchmark harness — those are later R13
//! sub-units (R13.3/R13.4/R13.6) per the design doc's own rung split. This
//! module contains no N-PAMP handshake, KEM, or AEAD code — it composes
//! [`crate::authz::AuthzTable`], the SAME L4 decision `agent::NodeAgent`
//! already enforces (R13.2: "userspace PQC by default; eBPF does L3/L4
//! steering only").
//!
//! # The one property every other property depends on (R13.1)
//!
//! **A same-node sockmap splice entry is inserted ONLY for a socket pair
//! N-PAMP L4 authorization has already approved.** [`SpliceToken`] has no
//! public constructor: the only way to obtain one is
//! [`SpliceGate::authorize_splice`] returning `Ok`, which itself only
//! happens when [`crate::authz::AuthzTable::check`] returns
//! [`crate::authz::Decision::Allow`]. There is therefore no code path in
//! this crate that can hand a [`SpliceInstaller`] a token for a denied,
//! unknown, or self-asserted pair — the fast path cannot become an authz
//! bypass by construction, not merely by convention.
//!
//! # What this module does NOT do (tracked gap)
//!
//! [`SpliceInstaller`] is the seam a live deployment supplies to actually
//! push an approved [`SpliceToken`] into the kernel's sockmap (a real
//! `bpf()` syscall / `aya` map-update requiring `CAP_BPF` and a live
//! eBPF-capable Linux kernel). This build ships [`NoopSpliceInstaller`], a
//! deterministic in-memory test double — it records what it would have
//! installed and touches no kernel state. Wiring a live installer is future
//! work behind this same trait, mirroring [`crate::identity::DelegatedIdentitySource`]'s
//! and [`crate::capture::RuleExecutor`]'s "real seam, honest tracked gap"
//! pattern; standing up a privileged Linux runner with `CAP_BPF` is infra
//! this build environment cannot host.
//!
//! # `DatapathCapabilities::probe()` on THIS build environment
//!
//! This crate is developed on Windows. [`DatapathCapabilities::probe`]
//! genuinely reads `cfg!(target_os = "linux")` at compile time and, being
//! compiled for a non-Linux target here, genuinely reports every eBPF
//! capability absent (`is_linux: false`, `has_cap_bpf: false`,
//! `bpffs_mounted: false`, `kernel_version: None`) — this is real probed
//! behavior for this platform, not a hardcoded stub; on a real Linux host
//! the `#[cfg(target_os = "linux")]` implementation reads
//! `/proc/sys/kernel/osrelease`, `/proc/self/status`'s `CapEff` bitmask, and
//! `/proc/mounts` to answer the same four questions from the actual kernel.
//! [`DatapathSelector::select`] run against a real `probe()` on this build
//! therefore deterministically (and correctly) selects
//! [`DatapathStrategy::IptablesTproxy`] — R13.2/R13.4's documented Windows
//! floor.

use std::fmt;

use crate::authz::{AuthzTable, Decision};
use crate::identity::SpiffeId;

// ---------------------------------------------------------------------
// Strategy ladder
// ---------------------------------------------------------------------

/// The datapath steering strategy `nz-agent` installs, ordered
/// fastest -> fallback per EBPF-DATAPATH-DESIGN.md's capability-probed
/// ladder. Every variant steers traffic only — the hybrid-PQC handshake and
/// AES-256-GCM/ChaCha20-Poly1305 record layer run in userspace under EVERY
/// strategy (R13.2); this enum never selects a record-layer offload (R13.3
/// rules out kTLS entirely, for the reasons recorded in the design doc).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatapathStrategy {
    /// `sockops`+`sk_msg`+`sockmap` same-node socket-to-socket splice — the
    /// fast path. Gated by [`SpliceGate`] (R13.1).
    SockmapSplice,
    /// `cgroup/connect4`/`connect6` egress capture at `connect()` time —
    /// zero per-packet cost, original destination stashed by socket cookie.
    CgroupRedirect,
    /// TC-clsact fallback (the Istio-ambient path); used when the fast-path
    /// techniques above are not applicable (this build's proxy for that:
    /// bpffs unavailable to pin the sockmap/cgroup maps) but a recent-enough
    /// kernel with `CAP_BPF` can still attach a classifier program.
    TcClsact,
    /// `iptables REDIRECT`+`TPROXY` — last resort and the benchmark
    /// baseline (`capture::IptablesCapture` builds this rule set). The only
    /// strategy available with no eBPF capability at all, and the strategy
    /// this crate's `probe()` genuinely selects on Windows today (R13.4).
    IptablesTproxy,
}

/// Probed eBPF-readiness facts for the current host. Construct via
/// [`DatapathCapabilities::probe`] (reads the real environment) or
/// [`DatapathCapabilities::from_parts`] (injects a synthetic capability set
/// for tests — every rung of the ladder below is reachable only through
/// `from_parts`, since a single CI host cannot exhibit all four).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatapathCapabilities {
    pub is_linux: bool,
    /// `(major, minor, patch)`, parsed from `/proc/sys/kernel/osrelease` on
    /// Linux; `None` when the platform is not Linux, or the version string
    /// could not be read/parsed (fails closed to "no version floor met").
    pub kernel_version: Option<(u32, u32, u32)>,
    /// Whether this process holds `CAP_BPF` (bit 39 of `/proc/self/status`'s
    /// `CapEff`, effective since Linux 5.8 — before that kernels required
    /// the much broader `CAP_SYS_ADMIN` for BPF, which this probe does not
    /// credit as `CAP_BPF`).
    pub has_cap_bpf: bool,
    /// Whether `bpffs` is mounted at `/sys/fs/bpf` (needed to PIN the
    /// sockmap/cgroup-hook maps so they persist across an `nz-agent`
    /// restart without re-authorizing every live pair).
    pub bpffs_mounted: bool,
}

impl DatapathCapabilities {
    /// Builds a capability set from explicit parts — for tests, and for any
    /// caller (e.g. a future control-plane binding, R12 AC4's tracked gap)
    /// that already knows the host's capabilities from another source.
    pub fn from_parts(is_linux: bool, kernel_version: Option<(u32, u32, u32)>, has_cap_bpf: bool, bpffs_mounted: bool) -> DatapathCapabilities {
        DatapathCapabilities { is_linux, kernel_version, has_cap_bpf, bpffs_mounted }
    }

    /// Probes the ACTUAL running environment. On Linux, reads
    /// `/proc/sys/kernel/osrelease`, `/proc/self/status`, and
    /// `/proc/mounts`; on any other platform, returns every eBPF capability
    /// as absent (real, honest behavior for a platform with no `bpf(2)`
    /// syscall — see the module docs).
    #[cfg(target_os = "linux")]
    pub fn probe() -> DatapathCapabilities {
        DatapathCapabilities {
            is_linux: true,
            kernel_version: probe_kernel_version(),
            has_cap_bpf: probe_cap_bpf(),
            bpffs_mounted: probe_bpffs_mounted(),
        }
    }

    /// Probes the ACTUAL running environment: on a non-Linux platform,
    /// every eBPF capability is genuinely absent (there is no `bpf(2)`
    /// syscall, no `CAP_BPF`, no `bpffs`) — this is the real answer for
    /// this platform, not a placeholder pending a "real" implementation.
    #[cfg(not(target_os = "linux"))]
    pub fn probe() -> DatapathCapabilities {
        DatapathCapabilities { is_linux: false, kernel_version: None, has_cap_bpf: false, bpffs_mounted: false }
    }
}

#[cfg(target_os = "linux")]
fn probe_kernel_version() -> Option<(u32, u32, u32)> {
    let raw = std::fs::read_to_string("/proc/sys/kernel/osrelease").ok()?;
    parse_kernel_version(raw.trim())
}

/// Parses the leading `major.minor[.patch]` digits off a Linux
/// `osrelease` string (e.g. `"6.8.0-45-generic"` -> `(6, 8, 0)`,
/// `"5.15-arch1-1"` -> `(5, 15, 0)`), defaulting an absent patch component
/// to 0. Returns `None` on anything that does not parse as at least
/// `major.minor` (fails closed to "no version floor met").
#[cfg(target_os = "linux")]
fn parse_kernel_version(s: &str) -> Option<(u32, u32, u32)> {
    let core = s.split(|c: char| !c.is_ascii_digit() && c != '.').next().unwrap_or("");
    let mut parts = core.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    let patch: u32 = parts.next().unwrap_or("0").parse().unwrap_or(0);
    Some((major, minor, patch))
}

/// Reads this process's effective `CAP_BPF` bit (39) out of
/// `/proc/self/status`'s `CapEff` hex bitmask — the kernel's own record of
/// this process's effective capabilities, not a self-asserted claim.
#[cfg(target_os = "linux")]
fn probe_cap_bpf() -> bool {
    const CAP_BPF_BIT: u32 = 39;
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return false,
    };
    let Some(hex) = status.lines().find_map(|line| line.strip_prefix("CapEff:")).map(|v| v.trim()) else {
        return false;
    };
    let Ok(mask) = u64::from_str_radix(hex, 16) else {
        return false;
    };
    (mask & (1u64 << CAP_BPF_BIT)) != 0
}

/// Reads `/proc/mounts` for a `bpf`-fstype mount at `/sys/fs/bpf`.
#[cfg(target_os = "linux")]
fn probe_bpffs_mounted() -> bool {
    let mounts = match std::fs::read_to_string("/proc/mounts") {
        Ok(s) => s,
        Err(_) => return false,
    };
    mounts.lines().any(|line| {
        let mut cols = line.split_whitespace();
        let _device = cols.next();
        let mountpoint = cols.next();
        let fstype = cols.next();
        mountpoint == Some("/sys/fs/bpf") && fstype == Some("bpf")
    })
}

// Kernel-version floors for the three eBPF-backed strategies. SockmapSplice
// needs `sk_msg` redirect (added ~4.18); CgroupRedirect needs
// `BPF_CGROUP_INET4_CONNECT` (added ~4.17); TcClsact matches
// EBPF-DATAPATH-DESIGN.md's own cited floor ("TC-clsact — kernel >=4.20").
const SOCKMAP_KERNEL_FLOOR: (u32, u32, u32) = (4, 18, 0);
const CGROUP_REDIRECT_KERNEL_FLOOR: (u32, u32, u32) = (4, 17, 0);
const TC_CLSACT_KERNEL_FLOOR: (u32, u32, u32) = (4, 20, 0);

fn meets_kernel_floor(version: Option<(u32, u32, u32)>, floor: (u32, u32, u32)) -> bool {
    match version {
        Some(v) => v >= floor,
        None => false,
    }
}

/// The capability-probed strategy selector (R13's redirect-strategy ladder).
pub struct DatapathSelector;

impl DatapathSelector {
    /// Deterministically picks the fastest [`DatapathStrategy`] `caps`
    /// actually supports, degrading toward [`DatapathStrategy::IptablesTproxy`]
    /// as capabilities are missing. eBPF is unavailable outright — and this
    /// always returns `IptablesTproxy` — when the platform is not Linux or
    /// `CAP_BPF` is absent; those two facts gate ALL THREE eBPF strategies.
    /// Among the eBPF strategies: `SockmapSplice` and `CgroupRedirect` also
    /// require `bpffs_mounted` (their maps need pinning); `TcClsact` does
    /// not (a TC classifier program attaches via netlink without a bpffs
    /// pin), so it remains reachable as a real fallback when `CAP_BPF` is
    /// present, the kernel is new enough, but bpffs has not been mounted.
    pub fn select(caps: &DatapathCapabilities) -> DatapathStrategy {
        if !caps.is_linux || !caps.has_cap_bpf {
            return DatapathStrategy::IptablesTproxy;
        }
        if caps.bpffs_mounted && meets_kernel_floor(caps.kernel_version, SOCKMAP_KERNEL_FLOOR) {
            return DatapathStrategy::SockmapSplice;
        }
        if caps.bpffs_mounted && meets_kernel_floor(caps.kernel_version, CGROUP_REDIRECT_KERNEL_FLOOR) {
            return DatapathStrategy::CgroupRedirect;
        }
        if meets_kernel_floor(caps.kernel_version, TC_CLSACT_KERNEL_FLOOR) {
            return DatapathStrategy::TcClsact;
        }
        DatapathStrategy::IptablesTproxy
    }
}

// ---------------------------------------------------------------------
// E2.9 — runtime hot-reconfig: re-probe + re-select
// ---------------------------------------------------------------------

/// A live, re-probeable datapath selection (R13's hot-reconfig requirement,
/// E2.9). [`DatapathSelector::select`] itself is a stateless, one-shot pure
/// function of a [`DatapathCapabilities`] snapshot — it has no memory of
/// what was previously selected and nothing calls it more than once on a
/// running host. `DatapathHandle` is the thin stateful wrapper a live
/// `nz-agent` process holds: it remembers the CURRENTLY active
/// [`DatapathStrategy`] and exposes [`DatapathHandle::reselect`] as the one
/// trigger point that re-runs the capability probe and re-selects,
/// switching the active strategy when (and only when) the probed
/// capabilities actually changed the outcome.
///
/// A live deployment wires [`DatapathHandle::reselect`] behind whichever
/// runtime signal it wants to treat as "re-check my eBPF capabilities now"
/// — an explicit admin/control-plane call (e.g. a future gRPC
/// `Reconfigure()` RPC) and/or a `SIGHUP`-style OS signal handler are both
/// legitimate triggers per R13's design; this module owns the re-probe +
/// re-select DECISION, not the OS-level plumbing that invokes it (mirrors
/// every other "real seam, honest tracked gap" boundary in this crate —
/// see the module docs' [`SpliceInstaller`] note).
pub struct DatapathHandle {
    current: DatapathStrategy,
}

impl DatapathHandle {
    /// Selects an initial strategy from `caps` and returns a handle holding
    /// it — the normal startup path (equivalent to
    /// `DatapathSelector::select` for a process that will never
    /// hot-reconfig, but every handle is reselect-capable from construction
    /// on).
    pub fn new(caps: &DatapathCapabilities) -> DatapathHandle {
        DatapathHandle { current: DatapathSelector::select(caps) }
    }

    /// The currently active strategy — what a live agent should be steering
    /// traffic through right now.
    pub fn current(&self) -> DatapathStrategy {
        self.current
    }

    /// Re-runs [`DatapathSelector::select`] against a freshly-probed `caps`
    /// snapshot and updates the active strategy to match. Returns `true`
    /// when the active strategy CHANGED as a result (the real hot-reconfig
    /// event: a live agent should react to `true` by tearing down whatever
    /// the OLD strategy had installed — e.g. draining `SpliceGate`-issued
    /// tokens — before relying on the new one), and `false` when the
    /// re-probe confirms the currently active strategy is still correct
    /// (a re-select ran, but nothing needs to change).
    pub fn reselect(&mut self, caps: &DatapathCapabilities) -> bool {
        let next = DatapathSelector::select(caps);
        let changed = next != self.current;
        self.current = next;
        changed
    }
}

// ---------------------------------------------------------------------
// R13.1 — the fast-path authorization gate
// ---------------------------------------------------------------------

/// A named, fail-closed datapath error — never an opaque `String`-only
/// failure for the security-load-bearing paths in this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatapathError {
    /// [`SpliceGate::authorize_splice`] found no `Allow` entry in the
    /// `AuthzTable` for the requested `(source, destination)` pair.
    SpliceDenied,
    /// A [`SpliceInstaller`] failed to install an ALREADY-authorized token
    /// (a kernel-side push failure) — distinct from an authorization
    /// denial, which never reaches an installer at all.
    InstallFailed(String),
}

impl fmt::Display for DatapathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DatapathError::SpliceDenied => write!(f, "nz-agent/datapath: sockmap splice denied — no L4 authorization entry for this (source, destination) pair"),
            DatapathError::InstallFailed(reason) => write!(f, "nz-agent/datapath: splice install failed: {reason}"),
        }
    }
}

impl std::error::Error for DatapathError {}

/// Proof that [`SpliceGate::authorize_splice`] approved this exact
/// `(source, destination)` pair. Deliberately has NO public constructor:
/// the only way any code in this crate can obtain a `SpliceToken` is a
/// successful `authorize_splice` call, which itself only succeeds past the
/// `AuthzTable::check` gate — so a [`SpliceInstaller`] can never be handed a
/// token for a pair that was never authorized (R13.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpliceToken {
    source: SpiffeId,
    destination: SpiffeId,
}

impl SpliceToken {
    pub fn source(&self) -> &SpiffeId {
        &self.source
    }

    pub fn destination(&self) -> &SpiffeId {
        &self.destination
    }
}

/// The fast-path authorization gate (R13.1). Consults the SAME
/// [`crate::authz::AuthzTable`] L4 decision [`crate::agent::NodeAgent::originate`]
/// already enforces before any handshake runs — this module does not
/// reimplement authorization, it composes the existing gate before ever
/// constructing a token a [`SpliceInstaller`] could act on.
pub struct SpliceGate;

impl SpliceGate {
    /// Authorizes a same-node sockmap splice for `(source, destination)`.
    /// Returns `Ok(SpliceToken)` ONLY when `authz.check(source, destination)`
    /// returns [`Decision::Allow`]; every other decision is
    /// `Err(DatapathError::SpliceDenied)` and no token is constructed. This
    /// is the single security-load-bearing function in this module.
    pub fn authorize_splice(source: &SpiffeId, destination: &SpiffeId, authz: &AuthzTable) -> Result<SpliceToken, DatapathError> {
        let (decision, _reason) = authz.check(source, destination);
        if decision != Decision::Allow {
            return Err(DatapathError::SpliceDenied);
        }
        Ok(SpliceToken { source: source.clone(), destination: destination.clone() })
    }
}

/// The seam a live deployment supplies to actually push an authorized
/// [`SpliceToken`] into the kernel's sockmap (a real `bpf()` syscall / `aya`
/// map-update requiring `CAP_BPF` and a live eBPF-capable Linux kernel —
/// NOT implemented by this crate; see the module docs' tracked-gap note).
pub trait SpliceInstaller {
    fn install(&mut self, token: &SpliceToken) -> Result<(), DatapathError>;
}

/// A deterministic, side-effect-free [`SpliceInstaller`] test double:
/// records every token it "installed" (in order) instead of touching a real
/// kernel sockmap. Used by this crate's own tests and by any caller running
/// `nz-agent` without a live eBPF-capable kernel — NOT for production (it
/// performs no actual kernel install).
#[derive(Debug)]
pub struct NoopSpliceInstaller {
    pub installed: Vec<SpliceToken>,
}

impl NoopSpliceInstaller {
    pub fn new() -> NoopSpliceInstaller {
        NoopSpliceInstaller { installed: Vec::new() }
    }
}

impl Default for NoopSpliceInstaller {
    fn default() -> Self {
        Self::new()
    }
}

impl SpliceInstaller for NoopSpliceInstaller {
    fn install(&mut self, token: &SpliceToken) -> Result<(), DatapathError> {
        self.installed.push(token.clone());
        Ok(())
    }
}

/// Composes [`SpliceGate::authorize_splice`] with [`SpliceInstaller::install`]
/// behind one call — the ONLY path a live `nz-agent` would use to actually
/// install a fast-path splice entry, so the fail-closed gate can never be
/// skipped by construction (mirrors [`crate::capture::CaptureSource::install`]'s
/// construct-then-apply composition).
pub fn install_splice<I: SpliceInstaller>(installer: &mut I, source: &SpiffeId, destination: &SpiffeId, authz: &AuthzTable) -> Result<SpliceToken, DatapathError> {
    let token = SpliceGate::authorize_splice(source, destination, authz)?;
    installer.install(&token)?;
    Ok(token)
}

// ---------------------------------------------------------------------
// R13-B-cont — the generalized seam for the CgroupRedirect / TcClsact /
// inbound-`sk_lookup` rungs (mirrors SpliceInstaller/SpliceToken/SpliceGate
// above, one layer more general)
// ---------------------------------------------------------------------

/// Proof that [`RedirectGate::authorize_redirect`] approved this exact
/// `(source, destination)` pair for a NON-splice steering mechanism
/// (`CgroupRedirect`'s egress waypoint rewrite, `TcClsact`'s TC-DNAT
/// fallback, or the inbound `sk_lookup` listener handoff — all three ladder
/// rungs `nz-agent-ebpf`'s `egress_redirect`/`tc_fallback`/`inbound_lookup`
/// programs implement). Deliberately has NO public constructor, for exactly
/// the reason [`SpliceToken`] does not: the only way any code in a
/// downstream crate can obtain a [`RedirectToken`] is a successful
/// `authorize_redirect` call, which itself only succeeds past the
/// `AuthzTable::check` gate — so a [`WaypointInstaller`] can never be handed
/// a token for a pair that was never authorized.
///
/// [`RedirectToken`] is intentionally the SAME shape as [`SpliceToken`]
/// (a bare `(source, destination)` pair) rather than three separate
/// per-rung token types: the authorization QUESTION is identical across all
/// three rungs ("may `source` reach `destination` via a steered path at
/// all?") — only the kernel MECHANISM differs, and that lives entirely in
/// each rung's own [`WaypointInstaller`] implementation (in
/// `nz-agent-ebpf`'s `loader` crate), never in this token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectToken {
    source: SpiffeId,
    destination: SpiffeId,
}

impl RedirectToken {
    pub fn source(&self) -> &SpiffeId {
        &self.source
    }

    pub fn destination(&self) -> &SpiffeId {
        &self.destination
    }
}

/// The fail-closed authorization gate for the CgroupRedirect/TcClsact/
/// inbound-lookup rungs — the generalization of [`SpliceGate`] one rung
/// family wider. Consults the SAME [`AuthzTable`] L4 decision every other
/// gate in this module composes; this type does not reimplement
/// authorization, it composes the existing gate before ever constructing a
/// token a [`WaypointInstaller`] could act on.
pub struct RedirectGate;

impl RedirectGate {
    /// Authorizes a non-splice steered path for `(source, destination)`.
    /// Returns `Ok(RedirectToken)` ONLY when `authz.check(source,
    /// destination)` returns [`Decision::Allow`]; every other decision is
    /// `Err(DatapathError::SpliceDenied)` (the same error variant
    /// [`SpliceGate::authorize_splice`] returns — the denial reason is
    /// identical across every rung on this ladder: no L4 authorization entry
    /// for the pair) and no token is constructed.
    pub fn authorize_redirect(source: &SpiffeId, destination: &SpiffeId, authz: &AuthzTable) -> Result<RedirectToken, DatapathError> {
        let (decision, _reason) = authz.check(source, destination);
        if decision != Decision::Allow {
            return Err(DatapathError::SpliceDenied);
        }
        Ok(RedirectToken { source: source.clone(), destination: destination.clone() })
    }
}

/// The seam a live deployment supplies to actually push an authorized
/// [`RedirectToken`] into ITS OWN kernel mechanism — a `cgroup/connect4`
/// waypoint map entry, a TC-clsact DNAT waypoint map entry, or an
/// `sk_lookup` listener-socket registration, depending on which rung's
/// installer implements this trait (`nz-agent-ebpf`'s `loader` crate;
/// NOT implemented by this crate — see [`SpliceInstaller`]'s identical
/// tracked-gap note, which applies here for the same reason: standing up a
/// privileged Linux runner with `CAP_BPF` is infra this build environment
/// cannot host).
pub trait WaypointInstaller {
    fn install(&mut self, token: &RedirectToken) -> Result<(), DatapathError>;
}

/// A deterministic, side-effect-free [`WaypointInstaller`] test double:
/// records every token it "installed" (in order) instead of touching a real
/// kernel map. Mirrors [`NoopSpliceInstaller`] exactly.
#[derive(Debug)]
pub struct NoopWaypointInstaller {
    pub installed: Vec<RedirectToken>,
}

impl NoopWaypointInstaller {
    pub fn new() -> NoopWaypointInstaller {
        NoopWaypointInstaller { installed: Vec::new() }
    }
}

impl Default for NoopWaypointInstaller {
    fn default() -> Self {
        Self::new()
    }
}

impl WaypointInstaller for NoopWaypointInstaller {
    fn install(&mut self, token: &RedirectToken) -> Result<(), DatapathError> {
        self.installed.push(token.clone());
        Ok(())
    }
}

/// Composes [`RedirectGate::authorize_redirect`] with
/// [`WaypointInstaller::install`] behind one call — the ONLY path a live
/// `nz-agent` would use to actually install a CgroupRedirect/TcClsact/
/// inbound-lookup steering entry, so the fail-closed gate can never be
/// skipped by construction. Mirrors [`install_splice`] exactly.
pub fn install_redirect<I: WaypointInstaller>(installer: &mut I, source: &SpiffeId, destination: &SpiffeId, authz: &AuthzTable) -> Result<RedirectToken, DatapathError> {
    let token = RedirectGate::authorize_redirect(source, destination, authz)?;
    installer.install(&token)?;
    Ok(token)
}

// ---------------------------------------------------------------------
// R13.5 — named-code drop telemetry
// ---------------------------------------------------------------------

/// A named datapath-layer drop reason (R13.5: "every DROP carries its named
/// error code — no opaque drops"). Not the full Part-1 telemetry/error
/// registry (that registry is Part-1 scope); this is this module's own
/// datapath-layer drop taxonomy, reported via [`DropEvent`] keyed exactly as
/// the design doc's Observability section specifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NpampDropCode {
    /// [`SpliceGate::authorize_splice`] denied this pair (R13.1).
    SpliceAuthzDenied,
    /// No datapath strategy could carry the packet (the selected strategy's
    /// install failed and there was no further fallback to try).
    NoDatapathAvailable,
    /// A selected eBPF strategy's kernel-side install failed AFTER
    /// authorization already succeeded (a [`SpliceInstaller`] error).
    InstallFailure,
}

impl fmt::Display for NpampDropCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            NpampDropCode::SpliceAuthzDenied => "SPLICE_AUTHZ_DENIED",
            NpampDropCode::NoDatapathAvailable => "NO_DATAPATH_AVAILABLE",
            NpampDropCode::InstallFailure => "INSTALL_FAILURE",
        };
        write!(f, "{s}")
    }
}

/// One drop event, keyed exactly as EBPF-DATAPATH-DESIGN.md's Observability
/// section specifies: "authenticated peer SPIFFE id + carriage class +
/// session/tunnel id".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropEvent {
    pub code: NpampDropCode,
    pub peer: SpiffeId,
    pub carriage: String,
    pub session: String,
}

/// Records one drop event into `sink`. This build's sink is an in-process
/// `Vec` — no live Hubble-otel/Prometheus exporter (that wiring is future
/// work, same shape as every other seam in this crate). The load-bearing
/// property this function's signature enforces: there is no way to call it,
/// and therefore no way to record a drop through this module, without
/// supplying a [`NpampDropCode`] — an opaque/unnamed drop cannot type-check.
pub fn record_drop(sink: &mut Vec<DropEvent>, code: NpampDropCode, peer: SpiffeId, carriage: &str, session: &str) {
    sink.push(DropEvent { code, peer, carriage: carriage.to_string(), session: session.to_string() });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(path: &str) -> SpiffeId {
        SpiffeId::parse(&format!("spiffe://cluster.local/ns/prod/sa/{path}")).expect("valid id")
    }

    fn table_allow(src: &SpiffeId, dst: &SpiffeId) -> AuthzTable {
        let mut t = AuthzTable::new();
        t.allow(src.clone(), dst.clone());
        t
    }

    // -- selector fallback ladder -------------------------------------

    #[test]
    fn no_bpf_selects_iptables_fallback() {
        // Full Linux + bpffs + a very modern kernel, but no CAP_BPF: must
        // still degrade all the way to the fallback. Mutated away by
        // M-datapath-2 in RED-EVIDENCE.md.
        let caps = DatapathCapabilities::from_parts(true, Some((6, 8, 0)), false, true);
        assert_eq!(DatapathSelector::select(&caps), DatapathStrategy::IptablesTproxy);
    }

    #[test]
    fn non_linux_selects_iptables_fallback_even_with_full_caps() {
        let caps = DatapathCapabilities::from_parts(false, Some((6, 8, 0)), true, true);
        assert_eq!(DatapathSelector::select(&caps), DatapathStrategy::IptablesTproxy);
    }

    #[test]
    fn full_caps_modern_kernel_selects_sockmap_splice() {
        let caps = DatapathCapabilities::from_parts(true, Some((6, 8, 0)), true, true);
        assert_eq!(DatapathSelector::select(&caps), DatapathStrategy::SockmapSplice);
    }

    #[test]
    fn kernel_below_sockmap_floor_selects_cgroup_redirect() {
        let caps = DatapathCapabilities::from_parts(true, Some((4, 17, 0)), true, true);
        assert_eq!(DatapathSelector::select(&caps), DatapathStrategy::CgroupRedirect);
    }

    #[test]
    fn bpffs_unmounted_but_new_kernel_falls_to_tc_clsact() {
        let caps = DatapathCapabilities::from_parts(true, Some((5, 15, 0)), true, false);
        assert_eq!(DatapathSelector::select(&caps), DatapathStrategy::TcClsact);
    }

    #[test]
    fn bpffs_unmounted_and_old_kernel_falls_all_the_way_to_iptables() {
        let caps = DatapathCapabilities::from_parts(true, Some((4, 19, 0)), true, false);
        assert_eq!(DatapathSelector::select(&caps), DatapathStrategy::IptablesTproxy);
    }

    #[test]
    fn missing_kernel_version_never_meets_any_floor() {
        let caps = DatapathCapabilities::from_parts(true, None, true, true);
        assert_eq!(DatapathSelector::select(&caps), DatapathStrategy::IptablesTproxy);
    }

    #[test]
    fn probe_matches_this_platform_and_select_never_panics() {
        let caps = DatapathCapabilities::probe();
        if !cfg!(target_os = "linux") {
            assert!(!caps.is_linux, "this build environment is not Linux");
            assert!(!caps.has_cap_bpf);
            assert!(!caps.bpffs_mounted);
            assert_eq!(caps.kernel_version, None);
            assert_eq!(DatapathSelector::select(&caps), DatapathStrategy::IptablesTproxy);
        } else {
            let _ = DatapathSelector::select(&caps);
        }
    }

    // -- E2.9 hot-reconfig: runtime re-probe + re-select ----------------

    #[test]
    fn reselect_switches_strategy_when_capabilities_change() {
        // Starts with no CAP_BPF (iptables fallback), then a capability gain
        // (CAP_BPF granted, modern kernel, bpffs mounted) must re-select up
        // to SockmapSplice and report that the strategy CHANGED. Mutated
        // away by M-datapath-3 in RED-EVIDENCE.md.
        let no_bpf = DatapathCapabilities::from_parts(true, Some((6, 8, 0)), false, true);
        let mut handle = DatapathHandle::new(&no_bpf);
        assert_eq!(handle.current(), DatapathStrategy::IptablesTproxy);

        let full_caps = DatapathCapabilities::from_parts(true, Some((6, 8, 0)), true, true);
        let changed = handle.reselect(&full_caps);
        assert!(changed, "a capability gain must be reported as a strategy change");
        assert_eq!(handle.current(), DatapathStrategy::SockmapSplice);
    }

    #[test]
    fn reselect_reports_no_change_when_capabilities_are_stable() {
        let caps = DatapathCapabilities::from_parts(true, Some((6, 8, 0)), true, true);
        let mut handle = DatapathHandle::new(&caps);
        assert_eq!(handle.current(), DatapathStrategy::SockmapSplice);

        // Re-probing the SAME capabilities must NOT report a change, even
        // though a real re-select ran internally.
        let changed = handle.reselect(&caps);
        assert!(!changed, "reselect against unchanged capabilities must report no change");
        assert_eq!(handle.current(), DatapathStrategy::SockmapSplice);
    }

    #[test]
    fn reselect_can_downgrade_when_a_capability_is_lost() {
        // A live host that loses CAP_BPF (e.g. a privilege drop) mid-run
        // must degrade its active strategy, not keep believing it still
        // holds the fast path.
        let full_caps = DatapathCapabilities::from_parts(true, Some((6, 8, 0)), true, true);
        let mut handle = DatapathHandle::new(&full_caps);
        assert_eq!(handle.current(), DatapathStrategy::SockmapSplice);

        let lost_bpf = DatapathCapabilities::from_parts(true, Some((6, 8, 0)), false, true);
        let changed = handle.reselect(&lost_bpf);
        assert!(changed, "a capability loss must be reported as a strategy change");
        assert_eq!(handle.current(), DatapathStrategy::IptablesTproxy);
    }

    // -- R13.1 fast-path authorization gate ----------------------------

    #[test]
    fn denied_pair_yields_no_token_and_is_splice_denied() {
        // Mutated away by M-datapath-1 in RED-EVIDENCE.md.
        let a = id("a");
        let b = id("b");
        let empty = AuthzTable::new();
        let err = SpliceGate::authorize_splice(&a, &b, &empty).expect_err("must fail closed with no authz entry");
        assert_eq!(err, DatapathError::SpliceDenied);
    }

    #[test]
    fn allowed_pair_yields_a_token_matching_the_pair() {
        let a = id("a");
        let b = id("b");
        let table = table_allow(&a, &b);
        let token = SpliceGate::authorize_splice(&a, &b, &table).expect("allowed pair must yield a token");
        assert_eq!(token.source(), &a);
        assert_eq!(token.destination(), &b);
    }

    /// Directionality/destination-specificity must survive through the
    /// splice gate, not just `AuthzTable::check` directly: `allow(A, B)`
    /// must not authorize a splice for `B -> A` or `A -> C`.
    #[test]
    fn splice_gate_does_not_widen_the_underlying_authz_decision() {
        let a = id("a");
        let b = id("b");
        let c = id("c");
        let table = table_allow(&a, &b);
        assert!(SpliceGate::authorize_splice(&b, &a, &table).is_err());
        assert!(SpliceGate::authorize_splice(&a, &c, &table).is_err());
    }

    #[test]
    fn denied_pair_never_reaches_the_installer() {
        let a = id("a");
        let b = id("b");
        let empty = AuthzTable::new();
        let mut installer = NoopSpliceInstaller::new();
        let result = install_splice(&mut installer, &a, &b, &empty);
        assert!(result.is_err());
        assert!(installer.installed.is_empty(), "installer MUST NOT be invoked for a denied pair");
    }

    #[test]
    fn allowed_pair_reaches_the_installer_exactly_once() {
        let a = id("a");
        let b = id("b");
        let table = table_allow(&a, &b);
        let mut installer = NoopSpliceInstaller::new();
        let token = install_splice(&mut installer, &a, &b, &table).expect("allowed pair installs");
        assert_eq!(installer.installed, vec![token]);
    }

    // -- R13-B-cont generalized redirect gate ---------------------------

    #[test]
    fn redirect_denied_pair_yields_no_token() {
        let a = id("a");
        let b = id("b");
        let empty = AuthzTable::new();
        let err = RedirectGate::authorize_redirect(&a, &b, &empty).expect_err("must fail closed with no authz entry");
        assert_eq!(err, DatapathError::SpliceDenied);
    }

    #[test]
    fn redirect_allowed_pair_yields_a_token_matching_the_pair() {
        let a = id("a");
        let b = id("b");
        let table = table_allow(&a, &b);
        let token = RedirectGate::authorize_redirect(&a, &b, &table).expect("allowed pair must yield a token");
        assert_eq!(token.source(), &a);
        assert_eq!(token.destination(), &b);
    }

    /// Directionality/destination-specificity must survive through the
    /// redirect gate too, exactly as it does for the splice gate.
    #[test]
    fn redirect_gate_does_not_widen_the_underlying_authz_decision() {
        let a = id("a");
        let b = id("b");
        let c = id("c");
        let table = table_allow(&a, &b);
        assert!(RedirectGate::authorize_redirect(&b, &a, &table).is_err());
        assert!(RedirectGate::authorize_redirect(&a, &c, &table).is_err());
    }

    #[test]
    fn redirect_denied_pair_never_reaches_the_installer() {
        let a = id("a");
        let b = id("b");
        let empty = AuthzTable::new();
        let mut installer = NoopWaypointInstaller::new();
        let result = install_redirect(&mut installer, &a, &b, &empty);
        assert!(result.is_err());
        assert!(installer.installed.is_empty(), "installer MUST NOT be invoked for a denied pair");
    }

    #[test]
    fn redirect_allowed_pair_reaches_the_installer_exactly_once() {
        let a = id("a");
        let b = id("b");
        let table = table_allow(&a, &b);
        let mut installer = NoopWaypointInstaller::new();
        let token = install_redirect(&mut installer, &a, &b, &table).expect("allowed pair installs");
        assert_eq!(installer.installed, vec![token]);
    }

    // -- R13.5 named-code drop telemetry --------------------------------

    #[test]
    fn every_drop_carries_a_named_code() {
        let mut sink = Vec::new();
        record_drop(&mut sink, NpampDropCode::SpliceAuthzDenied, id("a"), "npamp-cc-http", "sess-1");
        record_drop(&mut sink, NpampDropCode::NoDatapathAvailable, id("b"), "npamp-cc-grpc", "sess-2");
        assert_eq!(sink.len(), 2);
        assert_eq!(sink[0].code, NpampDropCode::SpliceAuthzDenied);
        assert_eq!(sink[0].code.to_string(), "SPLICE_AUTHZ_DENIED");
        assert_eq!(sink[1].code, NpampDropCode::NoDatapathAvailable);
        assert_eq!(sink[1].code.to_string(), "NO_DATAPATH_AVAILABLE");
    }

    #[test]
    fn drop_event_keys_by_peer_carriage_and_session() {
        let mut sink = Vec::new();
        let peer = id("workload-x");
        record_drop(&mut sink, NpampDropCode::InstallFailure, peer.clone(), "npamp-cc-mcp", "sess-42");
        let ev = &sink[0];
        assert_eq!(ev.peer, peer);
        assert_eq!(ev.carriage, "npamp-cc-mcp");
        assert_eq!(ev.session, "sess-42");
        assert_eq!(ev.code.to_string(), "INSTALL_FAILURE");
    }
}
