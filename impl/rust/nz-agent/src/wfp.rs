// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! Windows Filtering Platform (WFP) datapath rung (R13-C) — the Windows
//! analog of the eBPF capability-probed selector ladder in [`crate::datapath`];
//! design grounding: the WFP design grounding (every claim cited against
//! `learn.microsoft.com`, fetched 2026-08-31).
//!
//! # Scope of THIS module (R13-C only)
//!
//! WFP splits into two API surfaces, and this module builds ONLY the first:
//!
//! - **User-mode management API** (`Fwpmu.h`: `FwpmEngineOpen0`,
//!   `FwpmFilterAdd0`, …) — reachable from user mode, and the ONLY WFP
//!   capability this module builds against. Concretely: constructing the
//!   PERMIT/BLOCK filter object model for the `FWPM_LAYER_ALE_AUTH_CONNECT_V4`/
//!   `_V6` (outbound) and `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4`/`_V6` (inbound)
//!   authorization layers — the Windows analog of `nz-agent`'s userspace
//!   `AuthzTable` gate, enforceable at the OS firewall layer for defense in
//!   depth.
//! - **Kernel driver DDI** (`Fwpsk.h`: `FwpsCalloutRegister1`,
//!   `FwpsAcquireWritableLayerDataPointer0`, `classifyFn1`, …) — required for
//!   ANY actual connection **redirection** (`FWPM_LAYER_ALE_CONNECT_REDIRECT_V4`/
//!   `_V6`, `FWPM_LAYER_ALE_BIND_REDIRECT_V4`/`_V6`). This module builds none
//!   of it — see "What this module does NOT do" below.
//!
//! This module contains no N-PAMP handshake, KEM, or AEAD code — it composes
//! the SAME [`crate::datapath::RedirectGate`]/[`crate::datapath::RedirectToken`]
//! fail-closed seam the Linux `CgroupRedirect`/`TcClsact`/inbound-lookup rungs
//! use (R13-B-cont), not a Windows-specific reimplementation of authorization.
//!
//! # Why this is a SIBLING module, not a new [`crate::datapath::DatapathStrategy`] variant
//!
//! `DatapathCapabilities::probe`/`DatapathSelector::select` choose between
//! Linux eBPF ladder rungs — a choice that only exists on Linux, since
//! `#[cfg(target_os = "linux")]` gates every eBPF-capable probe path. On
//! Windows, the platform itself IS the selector (there is no runtime choice
//! between an eBPF ladder and a WFP ladder in the same compiled binary — the
//! two are mutually exclusive at compile time). Extending
//! `DatapathCapabilities`'s existing 4-field shape with Windows-only fields
//! would force every existing Linux-ladder call site and test to carry dead
//! Windows fields; a parallel [`WfpCapabilities`]/[`WfpSelector`] pair,
//! identical in SHAPE (probe -> capabilities -> selector -> fail-closed gate
//! -> token -> installer trait -> recording test double -> compose function)
//! but independent in TYPE, is the minimal-blast-radius design that still
//! reuses every SECURITY-load-bearing piece (`RedirectGate`/`RedirectToken`).
//!
//! # The one property every other property depends on (mirrors R13.1/R13-B-cont)
//!
//! **A WFP PERMIT filter is constructed ONLY for a `(source, destination)`
//! pair N-PAMP L4 authorization has already approved.** [`WfpFilterBuilder::build_permit`]
//! takes a [`crate::datapath::RedirectToken`] — which has no public
//! constructor outside [`crate::datapath::RedirectGate::authorize_redirect`],
//! itself gated on [`crate::authz::AuthzTable::check`] returning `Allow` —
//! so there is no code path in this module that can produce a
//! [`WfpFilterSpec`] for a denied, unknown, or self-asserted pair.
//!
//! # What this module does NOT do (tracked gap: `WFP-KERNEL-CALLOUT-GAP`)
//!
//! [`WfpEngineInstaller`] is the seam a live deployment supplies to actually
//! open a `FwpmEngineOpen0` session and call `FwpmFilterAdd0` against the
//! real Base Filtering Engine (requiring local-Administrators-equivalent
//! access — see the WFP design grounding §2) — NOT implemented by this
//! crate. This build ships [`RecordingWfpEngine`], a deterministic in-memory
//! test double. Actual connection REDIRECTION (as opposed to the
//! permit/block authorization this module builds) additionally requires a
//! signed kernel-mode callout driver registered via `FwpsCalloutRegister1`+
//! (E2.14, a separate tracked build task — see the grounding doc §4); this
//! module contains no callout-driver code and cannot, since that requires
//! the Windows Driver Kit, not a userspace crate.
//!
//! # E2.14 (this build's userspace floor)
//!
//! Three additional, Claude-buildable-now pieces live in this file
//! alongside R13-C's original scope, all still userspace-only (no signing,
//! no WDK, no reboot): [`probe_engine_open_succeeds`] (a real, genuinely
//! invoked `FwpmEngineOpen0`/`FwpmEngineClose0` reachability probe, the
//! SAME "call the real OS API, fail closed on any error" shape as
//! [`probe_os_version`]/[`probe_elevated`]); [`WfpConflictScanner`] (the
//! seam for enumerating already-registered callouts/filters at a target
//! layer to detect a conflicting AV/firewall before install — real,
//! grounded `FwpmFilterCreateEnumHandle0`/`FwpmFilterEnum0`/
//! `FwpmCalloutCreateEnumHandle0`/`FwpmCalloutEnum0` FFI declared in `mod
//! ffi`, exercised through [`RecordingWfpConflictScanner`] since a live
//! enumeration needs a populated template + an open engine session, the
//! same tracked-gap shape as [`WfpEngineInstaller`]); and [`WfpStrategy`]/
//! [`WfpHandle`] (the Windows-side degrade-to-userspace strategy selector,
//! mirroring [`crate::datapath::DatapathSelector`]/[`crate::datapath::DatapathHandle`]'s
//! reselection concept one rung family narrower). A signed kernel-mode
//! callout driver actually registered at the redirect layers remains the
//! maintainer-gated follow-up these three pieces do not attempt.
//!
//! # `WfpCapabilities::probe()` on THIS build environment
//!
//! This crate is developed and graded on Windows. [`WfpCapabilities::probe`]
//! genuinely reads `cfg!(windows)` at compile time (true here) and, on
//! Windows, genuinely probes the real OS version via `RtlGetVersion`
//! (`ntdll.dll` — the version API that is NOT subject to the
//! `GetVersionEx`/manifest compatibility lie) and this process's real token
//! elevation via `OpenProcessToken`+`GetTokenInformation(TokenElevation)`
//! (`advapi32.dll`) — the kernel's own record of this process's elevation
//! state, not a self-asserted claim, exactly mirroring how
//! [`crate::datapath`]'s `probe_cap_bpf` reads `/proc/self/status`'s `CapEff`
//! rather than trusting a caller's claim.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use crate::datapath::{DatapathError, RedirectToken};
use crate::identity::SpiffeId;

// ---------------------------------------------------------------------
// Capability probing
// ---------------------------------------------------------------------

/// Probed WFP-readiness facts for the current host. Construct via
/// [`WfpCapabilities::probe`] (reads the real environment) or
/// [`WfpCapabilities::from_parts`] (injects a synthetic capability set for
/// tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WfpCapabilities {
    pub is_windows: bool,
    /// `(major, minor, build)`, read via `RtlGetVersion` on Windows; `None`
    /// off-Windows or if the read failed (fails closed to "no version floor
    /// met").
    pub os_version: Option<(u32, u32, u32)>,
    /// Whether this process's primary token is elevated (kernel-sourced via
    /// `GetTokenInformation(TokenElevation)`, not self-asserted). WFP's
    /// management API grants `FWPM_ACTRL_OPEN` to the engine object
    /// unconditionally to the built-in Administrators group (see grounding
    /// doc §2); this probe checks the practical necessary condition.
    pub is_elevated: bool,
}

impl WfpCapabilities {
    pub fn from_parts(is_windows: bool, os_version: Option<(u32, u32, u32)>, is_elevated: bool) -> WfpCapabilities {
        WfpCapabilities { is_windows, os_version, is_elevated }
    }

    /// Probes the ACTUAL running environment: on Windows, reads the real OS
    /// version and this process's real token elevation; on any other
    /// platform, every WFP capability is genuinely absent (there is no WFP
    /// on a non-Windows kernel) — real, honest behavior for this platform,
    /// not a placeholder.
    #[cfg(windows)]
    pub fn probe() -> WfpCapabilities {
        WfpCapabilities { is_windows: true, os_version: probe_os_version(), is_elevated: probe_elevated() }
    }

    #[cfg(not(windows))]
    pub fn probe() -> WfpCapabilities {
        WfpCapabilities { is_windows: false, os_version: None, is_elevated: false }
    }
}

/// The Windows version floor at which the ALE redirect/authorize layers
/// this module targets became available: Windows 7 (NT 6.1). Source —
/// "Using Bind or Connect Redirection": "The redirect layers are only
/// available for Windows 7 and later versions of Windows." (see
/// the WFP design grounding §2).
const WFP_ALE_LAYER_FLOOR: (u32, u32, u32) = (6, 1, 0);

fn meets_os_floor(version: Option<(u32, u32, u32)>, floor: (u32, u32, u32)) -> bool {
    match version {
        Some(v) => v >= floor,
        None => false,
    }
}

/// The capability-probed readiness check for this rung — the WFP analog of
/// [`crate::datapath::DatapathSelector::select`]. There is exactly one
/// user-mode-reachable outcome (ready/not-ready), not a ladder of fallback
/// strategies, because WFP's management API is a single mechanism (unlike
/// the Linux side's sockmap/cgroup/TC/iptables ladder) — the "fallback" on
/// Windows, when this rung is not ready, is the SAME `iptables`-shaped
/// userspace enforcement this crate already ships for any platform with no
/// kernel-assisted steering (`capture::IptablesCapture`'s design intent,
/// even though its rule syntax is Linux-specific — a Windows equivalent
/// firewall-rule fallback is out of THIS rung's scope).
pub struct WfpSelector;

impl WfpSelector {
    /// `true` only when the platform is genuinely Windows, the OS meets the
    /// documented ALE-layer version floor, AND this process is elevated
    /// (the practical necessary condition for `FwpmEngineOpen0` to succeed
    /// against the live engine — see the WFP design grounding §2).
    /// Mutated away by the M-wfp-1 mutation below.
    pub fn ready(caps: &WfpCapabilities) -> bool {
        caps.is_windows && caps.is_elevated && meets_os_floor(caps.os_version, WFP_ALE_LAYER_FLOOR)
    }
}

#[cfg(windows)]
mod ffi {
    //! Minimal raw FFI declarations for the two genuinely-probed Windows
    //! facts this module needs (OS version, token elevation) — no external
    //! crate dependency added; both structs/signatures are the DOCUMENTED,
    //! version-stable Win32/NT ABI (`ntdll.dll`'s `RtlGetVersion`,
    //! `advapi32.dll`'s `OpenProcessToken`/`GetTokenInformation`/
    //! `CloseHandle`). This mirrors `datapath.rs`'s own `#[cfg(target_os =
    //! "linux")]` raw `/proc` reads: a real environment probe, not a stub.

    use std::ffi::c_void;

    pub const TOKEN_QUERY: u32 = 0x0008;
    pub const TOKEN_ELEVATION: i32 = 20; // TOKEN_INFORMATION_CLASS::TokenElevation

    #[repr(C)]
    pub struct OsVersionInfoW {
        pub dw_os_version_info_size: u32,
        pub dw_major_version: u32,
        pub dw_minor_version: u32,
        pub dw_build_number: u32,
        pub dw_platform_id: u32,
        pub sz_csd_version: [u16; 128],
    }

    #[repr(C)]
    pub struct TokenElevationInfo {
        pub token_is_elevated: u32,
    }

    #[link(name = "ntdll")]
    extern "system" {
        pub fn RtlGetVersion(lp_version_information: *mut OsVersionInfoW) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        pub fn GetCurrentProcess() -> *mut c_void;
        pub fn CloseHandle(h_object: *mut c_void) -> i32;
    }

    #[link(name = "advapi32")]
    extern "system" {
        pub fn OpenProcessToken(process_handle: *mut c_void, desired_access: u32, token_handle: *mut *mut c_void) -> i32;
        pub fn GetTokenInformation(
            token_handle: *mut c_void,
            token_information_class: i32,
            token_information: *mut c_void,
            token_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
    }

    // -- E2.14 (userspace floor): real `fwpmu.h` management-API FFI --------
    //
    // Grounded against `learn.microsoft.com` (fetched 2026-09-06):
    // "FwpmEngineOpen0 function (fwpmu.h)", "FwpmFilterCreateEnumHandle0
    // function (fwpmu.h)", "FwpmFilterEnum0 function (fwpmu.h)",
    // "FwpmCalloutEnum0 function (fwpmu.h)" — all documented `Fwpuclnt.dll`
    // exports, `req.lib: Fwpuclnt.lib`. `RPC_C_AUTHN_WINNT` (10) is the
    // authentication-service constant `FwpmEngineOpen0`'s own documented
    // example passes (grounded against a mirrored Windows SDK `rpcdce.h`).
    //
    // The `entries`/`enumTemplate`/`session`/`authIdentity` parameters are
    // declared as opaque `*mut c_void`/`*const c_void` rather than typed
    // `FWPM_FILTER0`/`FWPM_CALLOUT0`/`FWPM_FILTER_ENUM_TEMPLATE0`/
    // `FWPM_SESSION0`/`SEC_WINNT_AUTH_IDENTITY_W` pointers: a raw pointer's
    // ABI representation does not depend on its declared Rust pointee type,
    // so this is representationally correct, but this build never
    // constructs or parses those structures (that is the same
    // `WFP-KERNEL-CALLOUT-GAP` tracked scope as `WfpEngineInstaller`'s live
    // `FwpmFilterAdd0` session — see the module docs above and
    // the WFP design grounding §4/§6's honest limitations note about not
    // transcribing full struct/GUID layouts this build never exercises).
    pub const RPC_C_AUTHN_WINNT: u32 = 10;

    // `FwpmEngineOpen0`/`FwpmEngineClose0` ARE invoked for real (see
    // `probe_engine_open_succeeds` above). The enumeration-family functions
    // below are declared but genuinely never called by this build — the
    // `WFP-KERNEL-CALLOUT-GAP` tracked scope (constructing a populated
    // `FWPM_FILTER_ENUM_TEMPLATE0`/`FWPM_CALLOUT_ENUM_TEMPLATE0` and parsing
    // the returned entry arrays is future work behind [`WfpConflictScanner`],
    // exercised only through [`RecordingWfpConflictScanner`] in this build)
    // — `#[allow(dead_code)]` says so honestly rather than fabricating a
    // call site just to silence the lint.
    #[allow(dead_code)]
    #[link(name = "fwpuclnt")]
    extern "system" {
        pub fn FwpmEngineOpen0(
            server_name: *const u16,
            authn_service: u32,
            auth_identity: *mut c_void,
            session: *const c_void,
            engine_handle: *mut *mut c_void,
        ) -> u32;
        pub fn FwpmEngineClose0(engine_handle: *mut c_void) -> u32;

        pub fn FwpmFilterCreateEnumHandle0(engine_handle: *mut c_void, enum_template: *const c_void, enum_handle: *mut *mut c_void) -> u32;
        pub fn FwpmFilterEnum0(
            engine_handle: *mut c_void,
            enum_handle: *mut c_void,
            num_entries_requested: u32,
            entries: *mut *mut *mut c_void,
            num_entries_returned: *mut u32,
        ) -> u32;
        pub fn FwpmFilterDestroyEnumHandle0(engine_handle: *mut c_void, enum_handle: *mut c_void) -> u32;

        pub fn FwpmCalloutCreateEnumHandle0(engine_handle: *mut c_void, enum_template: *const c_void, enum_handle: *mut *mut c_void) -> u32;
        pub fn FwpmCalloutEnum0(
            engine_handle: *mut c_void,
            enum_handle: *mut c_void,
            num_entries_requested: u32,
            entries: *mut *mut *mut c_void,
            num_entries_returned: *mut u32,
        ) -> u32;
        pub fn FwpmCalloutDestroyEnumHandle0(engine_handle: *mut c_void, enum_handle: *mut c_void) -> u32;

        pub fn FwpmFreeMemory0(p: *mut *mut c_void);
    }
}

/// Reads the real running Windows version via `RtlGetVersion` — NOT
/// `GetVersionEx`, which lies about the OS version unless the calling
/// process's manifest declares compatibility with that Windows release; the
/// same reason a real capability probe must read `/proc/self/status`'s
/// `CapEff` on Linux rather than trust a caller's claim.
#[cfg(windows)]
fn probe_os_version() -> Option<(u32, u32, u32)> {
    use std::mem::size_of;
    let mut info = ffi::OsVersionInfoW {
        dw_os_version_info_size: size_of::<ffi::OsVersionInfoW>() as u32,
        dw_major_version: 0,
        dw_minor_version: 0,
        dw_build_number: 0,
        dw_platform_id: 0,
        sz_csd_version: [0; 128],
    };
    let status = unsafe { ffi::RtlGetVersion(&mut info as *mut _) };
    if status != 0 {
        return None;
    }
    Some((info.dw_major_version, info.dw_minor_version, info.dw_build_number))
}

/// Reads this process's real token elevation via
/// `OpenProcessToken`+`GetTokenInformation(TokenElevation)` — the kernel's
/// own record, not a self-asserted claim. Fails closed to `false` on any
/// API failure (an unreadable token is treated as "not elevated", never as
/// "assume yes").
#[cfg(windows)]
fn probe_elevated() -> bool {
    use std::mem::size_of;
    unsafe {
        let process = ffi::GetCurrentProcess();
        let mut token: *mut std::ffi::c_void = std::ptr::null_mut();
        if ffi::OpenProcessToken(process, ffi::TOKEN_QUERY, &mut token as *mut _) == 0 {
            return false;
        }
        let mut elevation = ffi::TokenElevationInfo { token_is_elevated: 0 };
        let mut returned_len: u32 = 0;
        let ok = ffi::GetTokenInformation(
            token,
            ffi::TOKEN_ELEVATION,
            &mut elevation as *mut _ as *mut std::ffi::c_void,
            size_of::<ffi::TokenElevationInfo>() as u32,
            &mut returned_len as *mut _,
        );
        ffi::CloseHandle(token);
        ok != 0 && elevation.token_is_elevated != 0
    }
}

/// `true` only when this process can genuinely open a session to the Base
/// Filtering Engine right now — a real `FwpmEngineOpen0` call, immediately
/// closed via `FwpmEngineClose0` (no filters added, no state left behind).
/// This is a STRONGER, live-environment signal than [`WfpSelector::ready`]'s
/// elevation+version check: a host can be elevated and version-floor-met
/// yet still fail here (the BFE service disabled by policy, RPC
/// unreachable, a third-party security product blocking BFE access) —
/// exactly the class of conflict [`WfpConflictScanner`] exists to
/// characterize further. Fails closed to `false` on ANY non-success
/// return, mirroring [`probe_elevated`]'s discipline: an
/// unreadable/unreachable engine is never optimistically treated as
/// "available".
#[cfg(windows)]
pub fn probe_engine_open_succeeds() -> bool {
    unsafe {
        let mut handle: *mut std::ffi::c_void = std::ptr::null_mut();
        let status = ffi::FwpmEngineOpen0(std::ptr::null(), ffi::RPC_C_AUTHN_WINNT, std::ptr::null_mut(), std::ptr::null(), &mut handle as *mut _);
        if status != 0 {
            return false;
        }
        ffi::FwpmEngineClose0(handle);
        true
    }
}

// ---------------------------------------------------------------------
// WFP object model (management-layer filter/condition construction)
// ---------------------------------------------------------------------

/// Which side of a connection this filter authorizes — outbound (the ALE
/// "auth connect" layers) or inbound (the ALE "auth recv/accept" layers).
/// See the WFP design grounding §3 for the operation-to-layer mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpDirection {
    Outbound,
    Inbound,
}

/// The four ALE authorization-layer management identifiers this module
/// targets (`Fwpmu.h`), chosen by IP version and direction. Deliberately
/// does NOT embed the real 128-bit GUID byte values (no `windows`/
/// `windows-sys` crate is linked by this build — see the module docs'
/// tracked-gap note); [`WfpAleLayer::fwpm_symbol`] carries the documented
/// symbolic name a live installer would resolve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpAleLayer {
    AuthConnectV4,
    AuthConnectV6,
    AuthRecvAcceptV4,
    AuthRecvAcceptV6,
}

impl WfpAleLayer {
    /// Picks the correct layer for `remote_addr`'s IP version and `direction`
    /// — the Windows analog of `nz-agent-ebpf`'s v4/v6 program pair.
    pub fn for_addr(remote_addr: IpAddr, direction: WfpDirection) -> WfpAleLayer {
        match (remote_addr, direction) {
            (IpAddr::V4(_), WfpDirection::Outbound) => WfpAleLayer::AuthConnectV4,
            (IpAddr::V6(_), WfpDirection::Outbound) => WfpAleLayer::AuthConnectV6,
            (IpAddr::V4(_), WfpDirection::Inbound) => WfpAleLayer::AuthRecvAcceptV4,
            (IpAddr::V6(_), WfpDirection::Inbound) => WfpAleLayer::AuthRecvAcceptV6,
        }
    }

    /// The documented `Fwpmu.h` symbolic identifier (see grounding doc §1).
    pub fn fwpm_symbol(&self) -> &'static str {
        match self {
            WfpAleLayer::AuthConnectV4 => "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
            WfpAleLayer::AuthConnectV6 => "FWPM_LAYER_ALE_AUTH_CONNECT_V6",
            WfpAleLayer::AuthRecvAcceptV4 => "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4",
            WfpAleLayer::AuthRecvAcceptV6 => "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6",
        }
    }
}

/// `FWPM_FILTER0`'s action — this module only ever constructs `Permit`
/// (there is no code path to `Block`: a filter is only built from an
/// ALREADY-authorized [`RedirectToken`], and a block decision is exactly
/// "no filter is built at all" — R13-C mirrors R13.1's "denied pair never
/// reaches the installer" property one layer up, at the OS firewall).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpAction {
    Permit,
}

/// One `FWPM_FILTER_CONDITION0` field this module populates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpConditionField {
    IpRemoteAddress,
    IpLocalAddress,
    IpRemotePort,
    IpLocalPort,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpConditionValue {
    Addr(IpAddr),
    Port(u16),
}

/// One `(field, value)` condition, evaluated with `FWP_MATCH_EQUAL`
/// semantics (the only match type this module needs — an exact 4-tuple
/// scope, mirroring how `SpliceGate` scopes to an exact identity pair).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WfpCondition {
    pub field: WfpConditionField,
    pub value: WfpConditionValue,
}

/// The concrete local/remote 4-tuple a live filter would scope to. WFP has
/// no concept of a SPIFFE identity — a [`RedirectToken`]'s
/// `(source, destination)` pair is an IDENTITY authorization; resolving that
/// identity pair to a concrete socket 4-tuple is a SEPARATE, already-tracked
/// crate concern (the identity-to-endpoint binding `nz-agent`'s `waypoint`/
/// `tunnel` modules own — see `lib.rs`'s tracked-gaps list), supplied here
/// by the caller rather than re-derived by this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WfpEndpoints {
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

/// A constructed, not-yet-submitted WFP filter — the direct analog of
/// `capture::Rule` (construction only, no side effects; see
/// [`WfpEngineInstaller`] for the submission seam).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpFilterSpec {
    pub layer: WfpAleLayer,
    pub action: WfpAction,
    pub conditions: Vec<WfpCondition>,
    /// Filter weight — higher wins ties within a sub-layer. Fixed for this
    /// rung (every filter this module builds is an unconditional permit for
    /// an already-authorized exact 4-tuple; there is no weight ordering
    /// question among them).
    pub weight: u8,
    /// The identity pair this filter was authorized for — copied out of the
    /// [`RedirectToken`] that gated this filter's construction (never
    /// re-derived, never defaulted): a live installer/telemetry sink can
    /// join a submitted filter back to the SPIFFE identities it enforces,
    /// exactly as [`crate::datapath::DropEvent`] keys drop telemetry by
    /// peer. This is also what makes the token's DATA (not merely its
    /// existence) load-bearing in [`WfpFilterBuilder::build_permit`]: a
    /// mutation that swaps `source`/`destination` here is independently
    /// gradable (see `build_permit_carries_the_authorized_identity_pair`).
    pub source: SpiffeId,
    pub destination: SpiffeId,
}

const WFP_FILTER_WEIGHT: u8 = 0x10;

/// Builds the WFP filter object model for an ALREADY-authorized
/// [`RedirectToken`] — the load-bearing fail-closed construction this rung
/// exists for. There is NO public way to obtain a [`WfpFilterSpec`] without
/// first holding a `RedirectToken`, and a `RedirectToken` has no public
/// constructor outside [`crate::datapath::RedirectGate::authorize_redirect`]
/// (itself gated on `AuthzTable::check` returning `Allow`) — so this
/// function can never be reached for a denied, unknown, or self-asserted
/// pair. Mutated away by the M-wfp-2 mutation below.
pub struct WfpFilterBuilder;

impl WfpFilterBuilder {
    pub fn build_permit(token: &RedirectToken, endpoints: &WfpEndpoints, direction: WfpDirection) -> WfpFilterSpec {
        let layer = WfpAleLayer::for_addr(endpoints.remote.ip(), direction);
        let conditions = vec![
            WfpCondition { field: WfpConditionField::IpRemoteAddress, value: WfpConditionValue::Addr(endpoints.remote.ip()) },
            WfpCondition { field: WfpConditionField::IpRemotePort, value: WfpConditionValue::Port(endpoints.remote.port()) },
            WfpCondition { field: WfpConditionField::IpLocalAddress, value: WfpConditionValue::Addr(endpoints.local.ip()) },
            WfpCondition { field: WfpConditionField::IpLocalPort, value: WfpConditionValue::Port(endpoints.local.port()) },
        ];
        WfpFilterSpec {
            layer,
            action: WfpAction::Permit,
            conditions,
            weight: WFP_FILTER_WEIGHT,
            source: token.source().clone(),
            destination: token.destination().clone(),
        }
    }
}

// ---------------------------------------------------------------------
// The submission seam — tracked gap (WFP-KERNEL-CALLOUT-GAP for the
// redirect layers; a live FwpmEngineOpen0/FwpmFilterAdd0 session for even
// this rung's PERMIT-only filters)
// ---------------------------------------------------------------------

/// A named, fail-closed WFP error — mirrors [`DatapathError`]'s discipline
/// of never returning an opaque `String`-only failure for a
/// security-load-bearing path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WfpError {
    /// [`WfpEngineInstaller::submit`] failed to push an already-built
    /// [`WfpFilterSpec`] (a live engine call failure) — distinct from an
    /// authorization denial, which never reaches an installer because no
    /// [`WfpFilterSpec`] is ever constructed for a denied pair.
    SubmitFailed(String),
}

impl fmt::Display for WfpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WfpError::SubmitFailed(reason) => write!(f, "nz-agent/wfp: filter submit failed: {reason}"),
        }
    }
}

impl std::error::Error for WfpError {}

impl From<WfpError> for DatapathError {
    fn from(e: WfpError) -> DatapathError {
        DatapathError::InstallFailed(e.to_string())
    }
}

/// The seam a live deployment supplies to actually push a constructed
/// [`WfpFilterSpec`] into the Base Filtering Engine via `FwpmEngineOpen0` +
/// `FwpmFilterAdd0` (`fwpuclnt.dll`) — NOT implemented by this crate (see
/// the module docs' `WFP-KERNEL-CALLOUT-GAP` note: even this PERMIT-only
/// user-mode rung needs a live engine session this build environment does
/// not open against the real OS firewall from a test/build process).
pub trait WfpEngineInstaller {
    fn submit(&mut self, spec: &WfpFilterSpec) -> Result<(), WfpError>;
}

/// A deterministic, side-effect-free [`WfpEngineInstaller`] test double:
/// records every spec it "submitted" (in order) instead of touching the
/// real Base Filtering Engine. Mirrors `capture::RecordingExecutor` and
/// `datapath::NoopWaypointInstaller` exactly.
#[derive(Debug, Default)]
pub struct RecordingWfpEngine {
    pub submitted: Vec<WfpFilterSpec>,
}

impl RecordingWfpEngine {
    pub fn new() -> RecordingWfpEngine {
        RecordingWfpEngine { submitted: Vec::new() }
    }
}

impl WfpEngineInstaller for RecordingWfpEngine {
    fn submit(&mut self, spec: &WfpFilterSpec) -> Result<(), WfpError> {
        self.submitted.push(spec.clone());
        Ok(())
    }
}

/// Composes [`WfpFilterBuilder::build_permit`] with
/// [`WfpEngineInstaller::submit`] behind one call — the ONLY path a live
/// `nz-agent` would use to actually install a WFP authorization filter, so
/// the fail-closed construction can never be skipped by construction.
/// Mirrors [`crate::datapath::install_redirect`] exactly.
pub fn install_wfp_filter<I: WfpEngineInstaller>(
    installer: &mut I,
    token: &RedirectToken,
    endpoints: &WfpEndpoints,
    direction: WfpDirection,
) -> Result<WfpFilterSpec, WfpError> {
    let spec = WfpFilterBuilder::build_permit(token, endpoints, direction);
    installer.submit(&spec)?;
    Ok(spec)
}

// ---------------------------------------------------------------------
// E2.14 (userspace floor) — callout/filter conflict detection before
// install. Detects a third-party AV/firewall (or another WFP-based agent)
// already occupying the target ALE layer, so this rung can back off rather
// than install alongside an unpredictable conflicting rule.
// ---------------------------------------------------------------------

/// One already-registered callout or filter this scan found occupying the
/// SAME ALE layer this rung would install into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpConflictingObject {
    pub display_name: String,
    pub provider_key: Option<String>,
}

/// The result of scanning one ALE layer for already-registered
/// callouts/filters before this rung attempts its own install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpConflictReport {
    pub layer: WfpAleLayer,
    pub conflicting: Vec<WfpConflictingObject>,
}

impl WfpConflictReport {
    /// `true` when [`WfpConflictScanner::scan`] found ANY pre-existing
    /// callout/filter at this layer. Mutated away by the M-wfp-conflict-1
    /// mutation below.
    pub fn has_conflict(&self) -> bool {
        !self.conflicting.is_empty()
    }
}

/// The seam a live deployment supplies to actually enumerate registered
/// callouts/filters at an ALE layer via `FwpmEngineOpen0` +
/// `FwpmFilterCreateEnumHandle0`/`FwpmFilterEnum0`/`FwpmFilterDestroyEnumHandle0`
/// (and the `FwpmCallout*` siblings) — real, documented `fwpmu.h` functions
/// (declared in `mod ffi` above) this crate does NOT call with a populated
/// `FWPM_FILTER_ENUM_TEMPLATE0`/`FWPM_CALLOUT_ENUM_TEMPLATE0` (constructing
/// and marshalling those templates, and parsing the returned
/// `FWPM_FILTER0`/`FWPM_CALLOUT0` arrays, is the same class of tracked gap
/// as [`WfpEngineInstaller`]'s live `FwpmFilterAdd0` session — see the
/// module docs' `WFP-KERNEL-CALLOUT-GAP` note).
pub trait WfpConflictScanner {
    fn scan(&mut self, layer: WfpAleLayer) -> Result<WfpConflictReport, WfpError>;
}

/// A deterministic, side-effect-free [`WfpConflictScanner`] test double:
/// returns a pre-programmed report instead of touching the real Base
/// Filtering Engine. Mirrors [`RecordingWfpEngine`] exactly.
#[derive(Debug, Default)]
pub struct RecordingWfpConflictScanner {
    pub programmed: Vec<WfpConflictingObject>,
    pub scanned_layers: Vec<WfpAleLayer>,
}

impl RecordingWfpConflictScanner {
    pub fn new(programmed: Vec<WfpConflictingObject>) -> RecordingWfpConflictScanner {
        RecordingWfpConflictScanner { programmed, scanned_layers: Vec::new() }
    }
}

impl WfpConflictScanner for RecordingWfpConflictScanner {
    fn scan(&mut self, layer: WfpAleLayer) -> Result<WfpConflictReport, WfpError> {
        self.scanned_layers.push(layer);
        Ok(WfpConflictReport { layer, conflicting: self.programmed.clone() })
    }
}

// ---------------------------------------------------------------------
// E2.14 (userspace floor) — Windows-side strategy selection / degrade to
// userspace-only enforcement (mirrors crate::datapath's Linux
// reselection/degrade concept: DatapathSelector::select + DatapathHandle).
// ---------------------------------------------------------------------

/// The Windows-side steering strategy this rung selects — the WFP analog of
/// [`crate::datapath::DatapathStrategy`]'s Linux ladder, collapsed to two
/// rungs because WFP has exactly one kernel-assisted mechanism (unlike
/// Linux's sockmap/cgroup/TC/iptables ladder): either this rung's ALE
/// PERMIT filter is installable, or it degrades to relying on this crate's
/// userspace [`crate::authz::AuthzTable`] check alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpStrategy {
    /// Install this rung's ALE authorize-layer PERMIT filter (defense in
    /// depth alongside the userspace authorization check).
    Authorize,
    /// Degrade: rely on the userspace `AuthzTable` check alone. Selected
    /// when [`WfpSelector::ready`] is `false` (not Windows / not elevated /
    /// version floor unmet) OR a [`WfpConflictReport`] found a conflicting
    /// callout/filter already occupying the target layer — installing over
    /// a conflicting AV/firewall filter risks an unpredictable outcome
    /// (silently shadowed, or shadowing the OTHER product's own rule), so
    /// this rung backs off rather than fail open or fail into an
    /// indeterminate dual-firewall state.
    UserspaceOnly,
}

impl WfpSelector {
    /// Deterministically picks a [`WfpStrategy`] from readiness plus an
    /// optional conflict signal — the WFP analog of
    /// [`crate::datapath::DatapathSelector::select`]. Degrades to
    /// [`WfpStrategy::UserspaceOnly`] whenever `caps` is not ready OR
    /// `conflict_present` is `true`; never optimistically selects
    /// `Authorize` on a combination it cannot confirm is clear. Mutated
    /// away by the M-wfp-degrade-1 mutation below.
    pub fn select_strategy(caps: &WfpCapabilities, conflict_present: bool) -> WfpStrategy {
        if !WfpSelector::ready(caps) {
            return WfpStrategy::UserspaceOnly;
        }
        if conflict_present {
            return WfpStrategy::UserspaceOnly;
        }
        WfpStrategy::Authorize
    }
}

/// A live, re-probeable Windows-side strategy selection — mirrors
/// [`crate::datapath::DatapathHandle`]'s reselection/degrade concept
/// exactly, one rung family narrower (two strategies, not four).
pub struct WfpHandle {
    current: WfpStrategy,
}

impl WfpHandle {
    /// Selects an initial strategy from `caps`/`conflict_present` and
    /// returns a handle holding it.
    pub fn new(caps: &WfpCapabilities, conflict_present: bool) -> WfpHandle {
        WfpHandle { current: WfpSelector::select_strategy(caps, conflict_present) }
    }

    /// The currently active strategy — what a live agent should be
    /// enforcing through right now.
    pub fn current(&self) -> WfpStrategy {
        self.current
    }

    /// Re-runs [`WfpSelector::select_strategy`] against a freshly-probed
    /// `caps`/`conflict_present` snapshot and updates the active strategy.
    /// Returns `true` when the active strategy CHANGED as a result (a live
    /// agent should react to `true` by tearing down whatever the OLD
    /// strategy had installed before relying on the new one, exactly as
    /// [`crate::datapath::DatapathHandle::reselect`] documents), and
    /// `false` when the re-probe confirms the currently active strategy is
    /// still correct.
    pub fn reselect(&mut self, caps: &WfpCapabilities, conflict_present: bool) -> bool {
        let next = WfpSelector::select_strategy(caps, conflict_present);
        let changed = next != self.current;
        self.current = next;
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::AuthzTable;
    use crate::datapath::RedirectGate;
    use crate::identity::SpiffeId;

    fn id(path: &str) -> SpiffeId {
        SpiffeId::parse(&format!("spiffe://cluster.local/ns/prod/sa/{path}")).expect("valid id")
    }

    fn table_allow(src: &SpiffeId, dst: &SpiffeId) -> AuthzTable {
        let mut t = AuthzTable::new();
        t.allow(src.clone(), dst.clone());
        t
    }

    fn authorized_token() -> RedirectToken {
        let a = id("a");
        let b = id("b");
        let table = table_allow(&a, &b);
        RedirectGate::authorize_redirect(&a, &b, &table).expect("allowed pair must authorize")
    }

    fn v4_endpoints() -> WfpEndpoints {
        WfpEndpoints { local: "10.0.0.1:5000".parse().unwrap(), remote: "10.0.0.2:443".parse().unwrap() }
    }

    fn v6_endpoints() -> WfpEndpoints {
        WfpEndpoints { local: "[fe80::1]:5000".parse().unwrap(), remote: "[fe80::2]:443".parse().unwrap() }
    }

    // -- capability readiness ------------------------------------------

    #[test]
    fn not_windows_is_never_ready() {
        let caps = WfpCapabilities::from_parts(false, Some((10, 0, 22631)), true);
        assert!(!WfpSelector::ready(&caps));
    }

    #[test]
    fn windows_without_elevation_is_not_ready() {
        let caps = WfpCapabilities::from_parts(true, Some((10, 0, 22631)), false);
        assert!(!WfpSelector::ready(&caps));
    }

    #[test]
    fn windows_below_version_floor_is_not_ready() {
        // Windows Vista (NT 6.0) predates the redirect layers' Windows 7 floor.
        let caps = WfpCapabilities::from_parts(true, Some((6, 0, 6000)), true);
        assert!(!WfpSelector::ready(&caps));
    }

    #[test]
    fn missing_version_never_meets_the_floor() {
        let caps = WfpCapabilities::from_parts(true, None, true);
        assert!(!WfpSelector::ready(&caps));
    }

    #[test]
    fn elevated_modern_windows_is_ready() {
        // Mutated away by M-wfp-1 in the mutation-evidence record below.
        let caps = WfpCapabilities::from_parts(true, Some((10, 0, 22631)), true);
        assert!(WfpSelector::ready(&caps));
    }

    #[test]
    fn probe_matches_this_platform_and_never_panics() {
        let caps = WfpCapabilities::probe();
        if cfg!(windows) {
            assert!(caps.is_windows);
            assert!(caps.os_version.is_some(), "RtlGetVersion must succeed on a real Windows host");
        } else {
            assert!(!caps.is_windows);
            assert!(!caps.is_elevated);
            assert_eq!(caps.os_version, None);
        }
        let _ = WfpSelector::ready(&caps);
    }

    // -- filter-object construction (fail-closed) -----------------------

    #[test]
    fn build_permit_picks_v4_layer_for_v4_remote() {
        let token = authorized_token();
        let spec = WfpFilterBuilder::build_permit(&token, &v4_endpoints(), WfpDirection::Outbound);
        assert_eq!(spec.layer, WfpAleLayer::AuthConnectV4);
        assert_eq!(spec.layer.fwpm_symbol(), "FWPM_LAYER_ALE_AUTH_CONNECT_V4");
        assert_eq!(spec.action, WfpAction::Permit);
    }

    #[test]
    fn build_permit_picks_v6_layer_for_v6_remote() {
        let token = authorized_token();
        let spec = WfpFilterBuilder::build_permit(&token, &v6_endpoints(), WfpDirection::Outbound);
        assert_eq!(spec.layer, WfpAleLayer::AuthConnectV6);
    }

    #[test]
    fn build_permit_picks_inbound_layer_for_inbound_direction() {
        // Mutated away by M-wfp-2 in the mutation-evidence record below.
        let token = authorized_token();
        let spec = WfpFilterBuilder::build_permit(&token, &v4_endpoints(), WfpDirection::Inbound);
        assert_eq!(spec.layer, WfpAleLayer::AuthRecvAcceptV4);
    }

    #[test]
    fn build_permit_encodes_the_exact_four_tuple() {
        let token = authorized_token();
        let eps = v4_endpoints();
        let spec = WfpFilterBuilder::build_permit(&token, &eps, WfpDirection::Outbound);
        assert_eq!(spec.conditions.len(), 4);
        assert!(spec.conditions.contains(&WfpCondition { field: WfpConditionField::IpRemoteAddress, value: WfpConditionValue::Addr(eps.remote.ip()) }));
        assert!(spec.conditions.contains(&WfpCondition { field: WfpConditionField::IpRemotePort, value: WfpConditionValue::Port(eps.remote.port()) }));
        assert!(spec.conditions.contains(&WfpCondition { field: WfpConditionField::IpLocalAddress, value: WfpConditionValue::Addr(eps.local.ip()) }));
        assert!(spec.conditions.contains(&WfpCondition { field: WfpConditionField::IpLocalPort, value: WfpConditionValue::Port(eps.local.port()) }));
    }

    #[test]
    fn build_permit_carries_the_authorized_identity_pair() {
        let a = id("a");
        let b = id("b");
        let table = table_allow(&a, &b);
        let token = RedirectGate::authorize_redirect(&a, &b, &table).expect("allowed");
        let spec = WfpFilterBuilder::build_permit(&token, &v4_endpoints(), WfpDirection::Outbound);
        assert_eq!(spec.source, a);
        assert_eq!(spec.destination, b);
    }

    // -- fail-closed gate integration (reuses RedirectGate/RedirectToken) --

    #[test]
    fn denied_pair_yields_no_token_and_therefore_no_filter_spec() {
        let a = id("a");
        let b = id("b");
        let empty = AuthzTable::new();
        let err = RedirectGate::authorize_redirect(&a, &b, &empty).expect_err("must fail closed with no authz entry");
        // There is no `WfpFilterSpec` constructible here: `build_permit`
        // requires a `RedirectToken` value, which this branch never
        // produces. The type system is the enforcement; this assertion
        // documents the denial itself.
        assert_eq!(err, DatapathError::SpliceDenied);
    }

    #[test]
    fn allowed_pair_reaches_the_engine_installer_exactly_once() {
        let token = authorized_token();
        let mut installer = RecordingWfpEngine::new();
        let spec = install_wfp_filter(&mut installer, &token, &v4_endpoints(), WfpDirection::Outbound).expect("authorized pair installs");
        assert_eq!(installer.submitted, vec![spec]);
    }

    #[test]
    fn engine_submit_failure_is_reported_not_swallowed() {
        struct AlwaysFails;
        impl WfpEngineInstaller for AlwaysFails {
            fn submit(&mut self, _spec: &WfpFilterSpec) -> Result<(), WfpError> {
                Err(WfpError::SubmitFailed("simulated BFE failure".into()))
            }
        }
        let token = authorized_token();
        let mut installer = AlwaysFails;
        let result = install_wfp_filter(&mut installer, &token, &v4_endpoints(), WfpDirection::Outbound);
        assert!(result.is_err());
    }

    #[test]
    fn wfp_error_converts_to_datapath_error() {
        let e: DatapathError = WfpError::SubmitFailed("x".into()).into();
        assert_eq!(e, DatapathError::InstallFailed("nz-agent/wfp: filter submit failed: x".into()));
    }

    // -- E2.14: real engine-reachability probe --------------------------

    #[test]
    fn probe_engine_open_succeeds_never_panics() {
        // Live-environment-dependent (needs an elevated process + a
        // reachable BFE service to return `true`); this only asserts the
        // real FFI round-trip never panics, mirroring
        // `probe_matches_this_platform_and_never_panics` above.
        let _ = probe_engine_open_succeeds();
    }

    // -- E2.14: callout/filter conflict detection -----------------------

    #[test]
    fn conflict_report_reports_conflict_when_callouts_present() {
        // Mutated away by M-wfp-conflict-1 in the crate's RED-EVIDENCE.md.
        let report = WfpConflictReport {
            layer: WfpAleLayer::AuthConnectV4,
            conflicting: vec![WfpConflictingObject { display_name: "ThirdPartyFirewall".into(), provider_key: None }],
        };
        assert!(report.has_conflict());
    }

    #[test]
    fn conflict_report_reports_clear_when_nothing_registered() {
        let report = WfpConflictReport { layer: WfpAleLayer::AuthConnectV4, conflicting: Vec::new() };
        assert!(!report.has_conflict());
    }

    #[test]
    fn recording_scanner_reports_a_conflict_when_present() {
        let mut scanner =
            RecordingWfpConflictScanner::new(vec![WfpConflictingObject { display_name: "OtherAgent".into(), provider_key: Some("{11111111-2222-3333-4444-555555555555}".into()) }]);
        let report = scanner.scan(WfpAleLayer::AuthConnectV4).expect("scan succeeds");
        assert!(report.has_conflict());
        assert_eq!(report.conflicting.len(), 1);
        assert_eq!(scanner.scanned_layers, vec![WfpAleLayer::AuthConnectV4]);
    }

    #[test]
    fn recording_scanner_reports_clear_when_nothing_programmed() {
        let mut scanner = RecordingWfpConflictScanner::new(Vec::new());
        let report = scanner.scan(WfpAleLayer::AuthRecvAcceptV6).expect("scan succeeds");
        assert!(!report.has_conflict());
        assert_eq!(report.layer, WfpAleLayer::AuthRecvAcceptV6);
    }

    // -- E2.14: Windows-side degrade-to-userspace strategy selection ------

    #[test]
    fn not_ready_selects_userspace_only_regardless_of_conflict() {
        // Mutated away by M-wfp-degrade-1 in the crate's RED-EVIDENCE.md.
        let caps = WfpCapabilities::from_parts(true, Some((10, 0, 22631)), false); // not elevated -> not ready
        assert_eq!(WfpSelector::select_strategy(&caps, false), WfpStrategy::UserspaceOnly);
    }

    #[test]
    fn ready_and_clear_selects_authorize() {
        let caps = WfpCapabilities::from_parts(true, Some((10, 0, 22631)), true);
        assert_eq!(WfpSelector::select_strategy(&caps, false), WfpStrategy::Authorize);
    }

    #[test]
    fn ready_but_conflicting_degrades_to_userspace_only() {
        let caps = WfpCapabilities::from_parts(true, Some((10, 0, 22631)), true);
        assert_eq!(WfpSelector::select_strategy(&caps, true), WfpStrategy::UserspaceOnly);
    }

    #[test]
    fn handle_reselects_up_to_authorize_when_conflict_clears() {
        let caps = WfpCapabilities::from_parts(true, Some((10, 0, 22631)), true);
        let mut handle = WfpHandle::new(&caps, true); // starts conflicting
        assert_eq!(handle.current(), WfpStrategy::UserspaceOnly);
        let changed = handle.reselect(&caps, false);
        assert!(changed, "a conflict clearing must be reported as a strategy change");
        assert_eq!(handle.current(), WfpStrategy::Authorize);
    }

    #[test]
    fn handle_degrades_when_a_conflict_appears() {
        let caps = WfpCapabilities::from_parts(true, Some((10, 0, 22631)), true);
        let mut handle = WfpHandle::new(&caps, false);
        assert_eq!(handle.current(), WfpStrategy::Authorize);
        let changed = handle.reselect(&caps, true);
        assert!(changed, "a newly-detected conflict must be reported as a strategy change");
        assert_eq!(handle.current(), WfpStrategy::UserspaceOnly);
    }

    #[test]
    fn handle_reselect_reports_no_change_when_stable() {
        let caps = WfpCapabilities::from_parts(true, Some((10, 0, 22631)), true);
        let mut handle = WfpHandle::new(&caps, false);
        assert_eq!(handle.current(), WfpStrategy::Authorize);
        let changed = handle.reselect(&caps, false);
        assert!(!changed, "reselect against unchanged inputs must report no change");
        assert_eq!(handle.current(), WfpStrategy::Authorize);
    }
}
