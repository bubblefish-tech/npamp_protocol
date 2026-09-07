// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! WFP kernel-callout <-> userspace wire codec (E2.14, the Claude-buildable
//! userspace floor) — the byte format a future signed WFP callout driver
//! (the redirect-layer `classifyFn`/`FwpsCalloutRegister1` code
//! the WFP design grounding §4's tracked `WFP-KERNEL-CALLOUT-GAP` names)
//! would use to report an observed redirect-layer decision back to this
//! crate's userspace process.
//!
//! # Why this exists before the driver does
//!
//! This is pure, driver-independent Rust: a fixed header, a versioned
//! schema, little-endian fields, and fail-closed truncation/version checks
//! — no dependency on the (not yet built, WDK- and signing-gated) kernel
//! callout driver itself, and no Windows FFI of any kind. Encoding and
//! decoding this frame shape can therefore be built, tested, and used the
//! moment a driver exists, without the two sides drifting out of agreement
//! about the byte layout — the same reasoning [`crate::wfp::WfpEngineInstaller`]
//! applies to filter submission, one layer lower (raw bytes across a
//! device-IOCTL boundary, not a Rust trait boundary a single compiled binary
//! shares).
//!
//! This module is deliberately NOT `#[cfg(windows)]`-gated (unlike
//! [`crate::wfp`], which is Windows-only because it links real Win32/NT
//! FFI): it is plain `std`-only Rust, so it compiles and its tests run on
//! any target this crate is built on, exactly mirroring how the
//! object-model construction in `wfp.rs` (`WfpFilterBuilder::build_permit`)
//! is gradable without a live engine handle.
//!
//! # Scope
//!
//! [`WireLayer`] models the REDIRECT layers specifically
//! (`FWPM_LAYER_ALE_CONNECT_REDIRECT_V4`/`_V6`,
//! `FWPM_LAYER_ALE_BIND_REDIRECT_V4`/`_V6`) — the layer family
//! the WFP design grounding §2/§3 identifies as requiring a signed
//! kernel-mode callout driver (`classifyFn`, `FwpsCalloutRegister1`), NOT
//! the ALE AUTHORIZE layers [`crate::wfp::WfpAleLayer`] already models: the
//! authorize layers need no kernel callout at all (a user-mode
//! `FwpmFilterAdd0` PERMIT/BLOCK filter suffices, `wfp.rs`'s existing
//! scope), so there is nothing for a driver to report back to userspace
//! about them. This module's frame is the byte shape a driver sitting at
//! the REDIRECT layers would use to tell userspace what it did to one flow.
//! [`WireLayer`] is intentionally a SEPARATE enum from [`crate::wfp::WfpAleLayer`]
//! rather than an extension of it — `wfp.rs`'s own module docs already
//! establish this crate's precedent that a "same shape, different concern"
//! pair is a parallel, independently-typed sibling, not a conflated variant
//! set on an existing type.
//!
//! # What this module does NOT do
//!
//! It does not open a device handle, does not issue a `DeviceIoControl`/
//! `FSCTL_*` call, and runs no FFI — this is a standalone codec. The actual
//! IOCTL plumbing that would move these bytes across the driver/userspace
//! boundary is part of the same `WFP-KERNEL-CALLOUT-GAP` tracked gap
//! `wfp.rs` already names (E2.14's signed-driver half, maintainer-gated —
//! see `lib.rs`'s tracked-gaps list).
//!
//! # Frame shape
//!
//! One [`WfpCalloutRecord`] frame, every multi-byte field little-endian:
//!
//! | Offset | Size | Field | Meaning |
//! |---|---|---|---|
//! | 0 | 4 | `total_length` | Total frame length in bytes, including this header and the trailing note. |
//! | 4 | 4 | `schema_version` | Must equal [`SCHEMA_VERSION`] or the frame is rejected outright, never reinterpreted under a new layout. |
//! | 8 | 8 | `process_id` | The PID the callout attributed the flow to. |
//! | 16 | 8 | `timestamp_qpc` | `KeQueryPerformanceCounter` ticks at classify time. |
//! | 24 | 1 | `layer` | Encoded [`WireLayer`]. |
//! | 25 | 1 | `direction` | Encoded [`WireDirection`]. |
//! | 26 | 1 | `action` | Encoded [`WireAction`]. |
//! | 27 | 1 | `ip_version` | `4` or `6` — which bytes of `local_addr`/`remote_addr` are meaningful. |
//! | 28 | 2 | `local_port` | |
//! | 30 | 2 | `remote_port` | |
//! | 32 | 2 | `redirected_remote_port` | Meaningful only when `action == Redirect`; MUST be `0` otherwise (checked on decode, not silently ignored). |
//! | 34 | 2 | reserved | MUST be `0` (checked on decode). |
//! | 36 | 16 | `local_addr` | IPv4 in the first 4 bytes, remaining 12 zero; IPv6 in all 16. |
//! | 52 | 16 | `remote_addr` | Same convention as `local_addr`. |
//! | 68 | 2 | `note_units` | Length of the trailing note, in UTF-16 code units. |
//! | 70 | `note_units * 2` | `note` | UTF-16LE free-text diagnostic note (may be empty). |
//!
//! [`FIXED_HEADER_LEN`] (70) is the minimum length of any valid frame — even
//! an empty note still needs the 2-byte `note_units` field.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The wire schema version this module encodes and the only version it will
/// decode. A future incompatible wire change bumps this constant and adds
/// an explicit decode path for the new version rather than silently
/// reinterpreting old bytes under a new layout.
pub const SCHEMA_VERSION: u32 = 1;

/// Length, in bytes, of a [`WfpCalloutRecord`] frame's fixed-size header
/// (offsets 0-69: `total_length` through `note_units`).
pub const FIXED_HEADER_LEN: usize = 70;

// ---------------------------------------------------------------------
// Wire-level enums (self-contained: no dependency on `crate::wfp`'s
// object-model types, so this module stays free of the Windows FFI those
// types are declared alongside — see the module docs above)
// ---------------------------------------------------------------------

/// The redirect-layer identity a callout classified at. See the module
/// docs' "Scope" section for why this is a layer family distinct from
/// [`crate::wfp::WfpAleLayer`]'s authorize layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireLayer {
    ConnectRedirectV4,
    ConnectRedirectV6,
    BindRedirectV4,
    BindRedirectV6,
}

/// Which side of the connection the classify happened on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireDirection {
    Outbound,
    Inbound,
}

/// What the (future) driver's callout did with the flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireAction {
    Permit,
    Block,
    Redirect,
}

fn encode_layer(layer: WireLayer) -> u8 {
    match layer {
        WireLayer::ConnectRedirectV4 => 0,
        WireLayer::ConnectRedirectV6 => 1,
        WireLayer::BindRedirectV4 => 2,
        WireLayer::BindRedirectV6 => 3,
    }
}

fn decode_layer(b: u8) -> Result<WireLayer, WfpWireError> {
    match b {
        0 => Ok(WireLayer::ConnectRedirectV4),
        1 => Ok(WireLayer::ConnectRedirectV6),
        2 => Ok(WireLayer::BindRedirectV4),
        3 => Ok(WireLayer::BindRedirectV6),
        other => Err(WfpWireError::UnknownLayer(other)),
    }
}

fn encode_direction(direction: WireDirection) -> u8 {
    match direction {
        WireDirection::Outbound => 0,
        WireDirection::Inbound => 1,
    }
}

fn decode_direction(b: u8) -> Result<WireDirection, WfpWireError> {
    match b {
        0 => Ok(WireDirection::Outbound),
        1 => Ok(WireDirection::Inbound),
        other => Err(WfpWireError::UnknownDirection(other)),
    }
}

fn encode_action(action: WireAction) -> u8 {
    match action {
        WireAction::Permit => 0,
        WireAction::Block => 1,
        WireAction::Redirect => 2,
    }
}

fn decode_action(b: u8) -> Result<WireAction, WfpWireError> {
    match b {
        0 => Ok(WireAction::Permit),
        1 => Ok(WireAction::Block),
        2 => Ok(WireAction::Redirect),
        other => Err(WfpWireError::UnknownAction(other)),
    }
}

fn addr16(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => {
            let mut out = [0u8; 16];
            out[0..4].copy_from_slice(&v4.octets());
            out
        }
        IpAddr::V6(v6) => v6.octets(),
    }
}

fn read_addr16(bytes: &[u8; 16], ip_version: u8) -> Result<IpAddr, WfpWireError> {
    match ip_version {
        4 => Ok(IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))),
        6 => Ok(IpAddr::V6(Ipv6Addr::from(*bytes))),
        other => Err(WfpWireError::UnknownIpVersion(other)),
    }
}

// ---------------------------------------------------------------------
// The record + codec
// ---------------------------------------------------------------------

/// One decoded (or to-be-encoded) redirect-layer callout event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpCalloutRecord {
    pub process_id: u64,
    pub timestamp_qpc: u64,
    pub layer: WireLayer,
    pub direction: WireDirection,
    pub action: WireAction,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    /// Only meaningful when `action == WireAction::Redirect`; MUST be `0`
    /// for every other action ([`encode_wfp_callout_record`] and
    /// [`decode_wfp_callout_record`] both reject a non-zero value paired
    /// with a non-`Redirect` action rather than silently ignoring it).
    pub redirected_remote_port: u16,
    pub note: String,
}

/// A named, fail-closed wire error — mirrors [`crate::wfp::WfpError`]'s
/// discipline of never returning an opaque `String`-only failure. Every
/// decode failure mode is a distinct variant so a caller (and a test) can
/// assert exactly WHICH safety check rejected a malformed frame, not merely
/// that decoding failed somehow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WfpWireError {
    BufferShorterThanFixedHeader { have: usize, need: usize },
    UnsupportedSchemaVersion { got: u32, supported: u32 },
    TotalLengthExceedsBuffer { total_length: u32, have: usize },
    TotalLengthTooSmall { total_length: u32, min: usize },
    FrameTooShortForField { at: usize, need: usize, have: usize },
    NoteLengthMismatch { note_units: u16, total_length: u32 },
    UnknownLayer(u8),
    UnknownDirection(u8),
    UnknownAction(u8),
    UnknownIpVersion(u8),
    ReservedFieldNotZero(u16),
    NonZeroRedirectPortWithoutRedirectAction(u16),
    MismatchedAddressFamilies,
    NoteTooLong(usize),
}

impl fmt::Display for WfpWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WfpWireError::BufferShorterThanFixedHeader { have, need } => {
                write!(f, "nz-agent/wfp_wire: buffer ({have} bytes) shorter than the fixed header ({need} bytes)")
            }
            WfpWireError::UnsupportedSchemaVersion { got, supported } => {
                write!(f, "nz-agent/wfp_wire: unsupported schema version {got} (this decoder supports {supported})")
            }
            WfpWireError::TotalLengthExceedsBuffer { total_length, have } => {
                write!(f, "nz-agent/wfp_wire: frame total_length={total_length} exceeds the available buffer ({have} bytes)")
            }
            WfpWireError::TotalLengthTooSmall { total_length, min } => {
                write!(f, "nz-agent/wfp_wire: frame total_length={total_length} is smaller than the minimum frame size ({min} bytes)")
            }
            WfpWireError::FrameTooShortForField { at, need, have } => {
                write!(f, "nz-agent/wfp_wire: frame too short for a field at offset {at} (need {need} more bytes, have {have} total)")
            }
            WfpWireError::NoteLengthMismatch { note_units, total_length } => {
                write!(f, "nz-agent/wfp_wire: note_units={note_units} does not exactly fill the declared total_length={total_length}")
            }
            WfpWireError::UnknownLayer(b) => write!(f, "nz-agent/wfp_wire: unknown layer byte {b}"),
            WfpWireError::UnknownDirection(b) => write!(f, "nz-agent/wfp_wire: unknown direction byte {b}"),
            WfpWireError::UnknownAction(b) => write!(f, "nz-agent/wfp_wire: unknown action byte {b}"),
            WfpWireError::UnknownIpVersion(b) => write!(f, "nz-agent/wfp_wire: unknown ip_version byte {b} (expected 4 or 6)"),
            WfpWireError::ReservedFieldNotZero(v) => write!(f, "nz-agent/wfp_wire: reserved field is {v}, must be 0"),
            WfpWireError::NonZeroRedirectPortWithoutRedirectAction(port) => {
                write!(f, "nz-agent/wfp_wire: redirected_remote_port={port} is non-zero but action is not Redirect")
            }
            WfpWireError::MismatchedAddressFamilies => {
                write!(f, "nz-agent/wfp_wire: local and remote endpoints are different IP address families")
            }
            WfpWireError::NoteTooLong(units) => write!(f, "nz-agent/wfp_wire: note too long to encode ({units} UTF-16 units)"),
        }
    }
}

impl std::error::Error for WfpWireError {}

/// Serializes `rec` into the wire frame format the module docs' table
/// defines. Fails closed (never emits a self-inconsistent frame) rather
/// than silently normalizing an invalid `WfpCalloutRecord`.
pub fn encode_wfp_callout_record(rec: &WfpCalloutRecord) -> Result<Vec<u8>, WfpWireError> {
    if rec.action != WireAction::Redirect && rec.redirected_remote_port != 0 {
        return Err(WfpWireError::NonZeroRedirectPortWithoutRedirectAction(rec.redirected_remote_port));
    }
    let local_ip = rec.local.ip();
    let remote_ip = rec.remote.ip();
    let ip_version: u8 = match (local_ip, remote_ip) {
        (IpAddr::V4(_), IpAddr::V4(_)) => 4,
        (IpAddr::V6(_), IpAddr::V6(_)) => 6,
        _ => return Err(WfpWireError::MismatchedAddressFamilies),
    };

    let note_units: Vec<u16> = rec.note.encode_utf16().collect();
    if note_units.len() > 0xFFFF {
        return Err(WfpWireError::NoteTooLong(note_units.len()));
    }

    let total_length = FIXED_HEADER_LEN + note_units.len() * 2;
    let mut buf = vec![0u8; total_length];

    buf[0..4].copy_from_slice(&(total_length as u32).to_le_bytes());
    buf[4..8].copy_from_slice(&SCHEMA_VERSION.to_le_bytes());
    buf[8..16].copy_from_slice(&rec.process_id.to_le_bytes());
    buf[16..24].copy_from_slice(&rec.timestamp_qpc.to_le_bytes());
    buf[24] = encode_layer(rec.layer);
    buf[25] = encode_direction(rec.direction);
    buf[26] = encode_action(rec.action);
    buf[27] = ip_version;
    buf[28..30].copy_from_slice(&rec.local.port().to_le_bytes());
    buf[30..32].copy_from_slice(&rec.remote.port().to_le_bytes());
    buf[32..34].copy_from_slice(&rec.redirected_remote_port.to_le_bytes());
    buf[34..36].copy_from_slice(&0u16.to_le_bytes());
    buf[36..52].copy_from_slice(&addr16(local_ip));
    buf[52..68].copy_from_slice(&addr16(remote_ip));
    buf[68..70].copy_from_slice(&(note_units.len() as u16).to_le_bytes());
    for (i, unit) in note_units.iter().enumerate() {
        let o = FIXED_HEADER_LEN + i * 2;
        buf[o..o + 2].copy_from_slice(&unit.to_le_bytes());
    }

    Ok(buf)
}

/// Decodes exactly one frame starting at `buf[0]`, returning the decoded
/// record and the number of bytes consumed (the frame's own `total_length`,
/// i.e. the offset of the NEXT frame in a concatenated buffer). Fails
/// closed on any inconsistency between the declared lengths and the buffer
/// actually available — never a panic, never a best-effort guess at a
/// misshapen buffer (a future kernel driver's IPC channel is untrusted
/// input from this userspace process's point of view, exactly like a
/// network peer's bytes).
pub fn decode_wfp_callout_record(buf: &[u8]) -> Result<(WfpCalloutRecord, usize), WfpWireError> {
    if buf.len() < FIXED_HEADER_LEN {
        return Err(WfpWireError::BufferShorterThanFixedHeader { have: buf.len(), need: FIXED_HEADER_LEN });
    }
    // Safe: buf.len() >= FIXED_HEADER_LEN (70), so every fixed-offset slice
    // below (all offsets < 70) is in bounds by construction.
    let total_length = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    let schema_version = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    if schema_version != SCHEMA_VERSION {
        return Err(WfpWireError::UnsupportedSchemaVersion { got: schema_version, supported: SCHEMA_VERSION });
    }
    if (total_length as usize) > buf.len() {
        return Err(WfpWireError::TotalLengthExceedsBuffer { total_length, have: buf.len() });
    }
    if (total_length as usize) < FIXED_HEADER_LEN {
        return Err(WfpWireError::TotalLengthTooSmall { total_length, min: FIXED_HEADER_LEN });
    }

    let process_id = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    let timestamp_qpc = u64::from_le_bytes(buf[16..24].try_into().unwrap());
    let layer = decode_layer(buf[24])?;
    let direction = decode_direction(buf[25])?;
    let action = decode_action(buf[26])?;
    let ip_version = buf[27];
    let local_port = u16::from_le_bytes(buf[28..30].try_into().unwrap());
    let remote_port = u16::from_le_bytes(buf[30..32].try_into().unwrap());
    let redirected_remote_port = u16::from_le_bytes(buf[32..34].try_into().unwrap());
    let reserved = u16::from_le_bytes(buf[34..36].try_into().unwrap());
    if reserved != 0 {
        return Err(WfpWireError::ReservedFieldNotZero(reserved));
    }
    if action != WireAction::Redirect && redirected_remote_port != 0 {
        return Err(WfpWireError::NonZeroRedirectPortWithoutRedirectAction(redirected_remote_port));
    }
    let local_addr_bytes: [u8; 16] = buf[36..52].try_into().unwrap();
    let remote_addr_bytes: [u8; 16] = buf[52..68].try_into().unwrap();
    let local_ip = read_addr16(&local_addr_bytes, ip_version)?;
    let remote_ip = read_addr16(&remote_addr_bytes, ip_version)?;
    let note_units = u16::from_le_bytes(buf[68..70].try_into().unwrap());

    let note_start = FIXED_HEADER_LEN;
    let note_bytes_len = note_units as usize * 2;
    let note_end = note_start + note_bytes_len;
    if note_end != total_length as usize {
        return Err(WfpWireError::NoteLengthMismatch { note_units, total_length });
    }
    // `.get()` (never a panicking direct index) for the ONE part of the
    // frame whose length is driven by an attacker/frame-controlled field
    // (`note_units`) rather than the already-bounds-checked fixed header.
    let note_bytes = buf
        .get(note_start..note_end)
        .ok_or(WfpWireError::FrameTooShortForField { at: note_start, need: note_bytes_len, have: buf.len() })?;
    let mut units = Vec::with_capacity(note_units as usize);
    for chunk in note_bytes.chunks_exact(2) {
        units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    let note = String::from_utf16_lossy(&units);

    let record = WfpCalloutRecord {
        process_id,
        timestamp_qpc,
        layer,
        direction,
        action,
        local: SocketAddr::new(local_ip, local_port),
        remote: SocketAddr::new(remote_ip, remote_port),
        redirected_remote_port,
        note,
    };
    Ok((record, total_length as usize))
}

/// Decodes every frame in `buf` (the shape a future
/// `FSCTL_WFP_READ_EVENTS`-style IOCTL might return: several queued
/// callout events concatenated in one buffer). Fails closed on the first
/// malformed frame rather than returning the events successfully decoded
/// so far silently mixed with a dropped tail.
pub fn decode_wfp_callout_records(buf: &[u8]) -> Result<Vec<WfpCalloutRecord>, WfpWireError> {
    let mut records = Vec::new();
    let mut offset = 0usize;
    while offset < buf.len() {
        let (record, consumed) = decode_wfp_callout_record(&buf[offset..])?;
        records.push(record);
        offset += consumed;
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record_v4() -> WfpCalloutRecord {
        WfpCalloutRecord {
            process_id: 4242,
            timestamp_qpc: 1_234_567_890,
            layer: WireLayer::ConnectRedirectV4,
            direction: WireDirection::Outbound,
            action: WireAction::Permit,
            local: "10.0.0.1:5000".parse().unwrap(),
            remote: "10.0.0.2:443".parse().unwrap(),
            redirected_remote_port: 0,
            note: String::new(),
        }
    }

    fn sample_record_v6() -> WfpCalloutRecord {
        WfpCalloutRecord {
            process_id: 99,
            timestamp_qpc: 42,
            layer: WireLayer::BindRedirectV6,
            direction: WireDirection::Inbound,
            action: WireAction::Block,
            local: "[fe80::1]:5000".parse().unwrap(),
            remote: "[fe80::2]:8443".parse().unwrap(),
            redirected_remote_port: 0,
            note: String::new(),
        }
    }

    fn sample_record_with_note(note: &str) -> WfpCalloutRecord {
        let mut rec = sample_record_v4();
        rec.note = note.to_string();
        rec
    }

    // -- round trip -----------------------------------------------------

    #[test]
    fn round_trip_preserves_all_fields_v4() {
        // Mutated away by M-wire-1 in the crate's RED-EVIDENCE.md.
        let rec = sample_record_v4();
        let buf = encode_wfp_callout_record(&rec).expect("encode");
        let (decoded, consumed) = decode_wfp_callout_record(&buf).expect("decode");
        assert_eq!(consumed, buf.len());
        assert_eq!(decoded, rec);
        assert_ne!(rec.local.port(), rec.remote.port(), "fixture must use distinct ports to make a port swap observable");
    }

    #[test]
    fn round_trip_preserves_all_fields_v6() {
        let rec = sample_record_v6();
        let buf = encode_wfp_callout_record(&rec).expect("encode");
        let (decoded, _) = decode_wfp_callout_record(&buf).expect("decode");
        assert_eq!(decoded, rec);
    }

    #[test]
    fn round_trip_preserves_a_non_empty_note() {
        let rec = sample_record_with_note("blocked by third-party firewall callout {guid}");
        let buf = encode_wfp_callout_record(&rec).expect("encode");
        let (decoded, consumed) = decode_wfp_callout_record(&buf).expect("decode");
        assert_eq!(consumed, buf.len());
        assert_eq!(decoded.note, rec.note);
        assert_eq!(decoded, rec);
    }

    #[test]
    fn round_trip_preserves_a_redirect_action_and_port() {
        let mut rec = sample_record_v4();
        rec.action = WireAction::Redirect;
        rec.redirected_remote_port = 9443;
        let buf = encode_wfp_callout_record(&rec).expect("encode");
        let (decoded, _) = decode_wfp_callout_record(&buf).expect("decode");
        assert_eq!(decoded.action, WireAction::Redirect);
        assert_eq!(decoded.redirected_remote_port, 9443);
    }

    // -- truncation-reject ------------------------------------------------

    #[test]
    fn decode_rejects_truncated_buffer() {
        // Mutated away by M-wire-2 in the crate's RED-EVIDENCE.md.
        let rec = sample_record_with_note("hello");
        let full = encode_wfp_callout_record(&rec).expect("encode");
        let truncated = &full[..full.len() - 3];
        assert!(truncated.len() >= FIXED_HEADER_LEN, "fixture must keep the fixed header intact");
        let err = decode_wfp_callout_record(truncated).expect_err("a truncated frame must be rejected");
        assert!(matches!(err, WfpWireError::TotalLengthExceedsBuffer { .. }), "got {err:?}");
    }

    #[test]
    fn decode_rejects_buffer_shorter_than_fixed_header() {
        let short = vec![0u8; FIXED_HEADER_LEN - 1];
        let err = decode_wfp_callout_record(&short).expect_err("a too-short buffer must be rejected");
        assert!(matches!(err, WfpWireError::BufferShorterThanFixedHeader { .. }), "got {err:?}");
    }

    // -- version-reject ---------------------------------------------------

    #[test]
    fn decode_rejects_unsupported_schema_version() {
        // Mutated away by M-wire-3 in the crate's RED-EVIDENCE.md.
        let rec = sample_record_v4();
        let mut buf = encode_wfp_callout_record(&rec).expect("encode");
        buf[4..8].copy_from_slice(&999u32.to_le_bytes());
        let err = decode_wfp_callout_record(&buf).expect_err("an unsupported schema version must be rejected");
        assert!(matches!(err, WfpWireError::UnsupportedSchemaVersion { got: 999, supported: 1 }), "got {err:?}");
    }

    // -- other fail-closed structural checks ------------------------------

    #[test]
    fn decode_rejects_unknown_layer_byte() {
        let rec = sample_record_v4();
        let mut buf = encode_wfp_callout_record(&rec).expect("encode");
        buf[24] = 0xEE;
        let err = decode_wfp_callout_record(&buf).expect_err("an unknown layer byte must be rejected");
        assert!(matches!(err, WfpWireError::UnknownLayer(0xEE)), "got {err:?}");
    }

    #[test]
    fn decode_rejects_unknown_direction_byte() {
        let rec = sample_record_v4();
        let mut buf = encode_wfp_callout_record(&rec).expect("encode");
        buf[25] = 0xEE;
        let err = decode_wfp_callout_record(&buf).expect_err("an unknown direction byte must be rejected");
        assert!(matches!(err, WfpWireError::UnknownDirection(0xEE)), "got {err:?}");
    }

    #[test]
    fn decode_rejects_unknown_action_byte() {
        let rec = sample_record_v4();
        let mut buf = encode_wfp_callout_record(&rec).expect("encode");
        buf[26] = 0xEE;
        let err = decode_wfp_callout_record(&buf).expect_err("an unknown action byte must be rejected");
        assert!(matches!(err, WfpWireError::UnknownAction(0xEE)), "got {err:?}");
    }

    #[test]
    fn decode_rejects_unknown_ip_version_byte() {
        let rec = sample_record_v4();
        let mut buf = encode_wfp_callout_record(&rec).expect("encode");
        buf[27] = 5;
        let err = decode_wfp_callout_record(&buf).expect_err("an unknown ip_version byte must be rejected");
        assert!(matches!(err, WfpWireError::UnknownIpVersion(5)), "got {err:?}");
    }

    #[test]
    fn decode_rejects_nonzero_reserved_field() {
        let rec = sample_record_v4();
        let mut buf = encode_wfp_callout_record(&rec).expect("encode");
        buf[34..36].copy_from_slice(&1u16.to_le_bytes());
        let err = decode_wfp_callout_record(&buf).expect_err("a non-zero reserved field must be rejected");
        assert!(matches!(err, WfpWireError::ReservedFieldNotZero(1)), "got {err:?}");
    }

    #[test]
    fn decode_rejects_redirect_port_without_redirect_action() {
        let rec = sample_record_v4(); // action == Permit
        let mut buf = encode_wfp_callout_record(&rec).expect("encode");
        buf[32..34].copy_from_slice(&443u16.to_le_bytes());
        let err = decode_wfp_callout_record(&buf).expect_err("a redirect port on a non-redirect action must be rejected");
        assert!(matches!(err, WfpWireError::NonZeroRedirectPortWithoutRedirectAction(443)), "got {err:?}");
    }

    #[test]
    fn encode_rejects_mismatched_address_families() {
        let mut rec = sample_record_v4();
        rec.remote = "[fe80::2]:443".parse().unwrap();
        let err = encode_wfp_callout_record(&rec).expect_err("mismatched address families must be rejected");
        assert_eq!(err, WfpWireError::MismatchedAddressFamilies);
    }

    #[test]
    fn encode_rejects_redirect_port_without_redirect_action() {
        let mut rec = sample_record_v4();
        rec.redirected_remote_port = 443; // action is still Permit
        let err = encode_wfp_callout_record(&rec).expect_err("must be rejected at encode time too");
        assert_eq!(err, WfpWireError::NonZeroRedirectPortWithoutRedirectAction(443));
    }

    #[test]
    fn encode_rejects_note_too_long() {
        let rec = sample_record_with_note(&"x".repeat(0x10000));
        let err = encode_wfp_callout_record(&rec).expect_err("an oversized note must be rejected");
        assert!(matches!(err, WfpWireError::NoteTooLong(0x10000)), "got {err:?}");
    }

    // -- batch decode ------------------------------------------------------

    #[test]
    fn decode_wfp_callout_records_decodes_a_concatenated_batch() {
        let a = sample_record_v4();
        let b = sample_record_v6();
        let mut buf = encode_wfp_callout_record(&a).expect("encode a");
        buf.extend(encode_wfp_callout_record(&b).expect("encode b"));
        let records = decode_wfp_callout_records(&buf).expect("decode batch");
        assert_eq!(records, vec![a, b]);
    }

    #[test]
    fn decode_wfp_callout_records_fails_closed_on_a_malformed_second_frame() {
        let a = sample_record_v4();
        let mut buf = encode_wfp_callout_record(&a).expect("encode a");
        let first_frame_len = buf.len();
        buf.extend(vec![0u8; FIXED_HEADER_LEN - 1]); // a malformed (too-short) second frame
        let err = decode_wfp_callout_records(&buf).expect_err("a malformed second frame must fail the whole batch");
        assert!(matches!(err, WfpWireError::BufferShorterThanFixedHeader { .. }), "got {err:?}");
        assert!(first_frame_len < buf.len());
    }
}
