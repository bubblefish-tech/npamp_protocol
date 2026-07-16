//! Native-channel operation-body decoders for the eight N-PAMP application channels
//! (draft-bubblefish-npamp-01 companion specs 84–8b): Capability, Immune, Settlement,
//! Telemetry, Commerce, Interaction, Workflow, and Knowledge.
//!
//! Every native-channel frame payload is a deterministic (canonical) CBOR map
//! (RFC 8949 §4.2.1). This module provides:
//!
//!  1. A strict deterministic-CBOR decoder ([`decode_top`]) that admits ONLY the
//!     subset the bodies use — unsigned/negative integers, byte/text strings, arrays,
//!     maps, and the simple values false/true/null, all definite-length, shortest-form,
//!     with map keys in canonical (bytewise-of-encoded-key) ascending order — and
//!     REJECTS everything else (indefinite lengths, non-shortest integer/length
//!     encodings, tags, floats, out-of-order or duplicate keys), which is exactly what a
//!     deterministic-encoding receiver MUST reject.
//!  2. Per-channel structural validators that enforce the common envelope (frame_kind
//!     at key 0 MUST equal the frame type; corr at key 1 per each channel's rule), the
//!     per-frame required/typed field schemas, the forward-compatibility rule (accept an
//!     unknown NON-negative integer key, reject an unknown NEGATIVE or non-integer key),
//!     and the channel-specific nested MUST-reject clauses (Immune gossip
//!     descriptors/items, Telemetry report content + nested samples, Commerce monetary
//!     amounts + settlement-leg party membership, Knowledge update results-or-removed).
//!
//! The behavior mirrors the Go reference (`impl/go/{memory_cbor,*_bodies}.go`); on any
//! structural fault a validator returns [`Err`], which is precisely the graded
//! MUST-reject outcome of the shared conformance corpus.

use std::fmt;

// ------------------------------------------------------------------------------------
// Decoded CBOR value model
// ------------------------------------------------------------------------------------

/// A decoded deterministic-CBOR value. `Uint` is CBOR major 0, `Nint` is major 1 (always
/// negative, value = -1 - argument), `Bytes` major 2, `Text` major 3, `Array` major 4,
/// `Map` major 5, and `Bool`/`Null` are the major-7 simple values true/false/null.
#[derive(Debug, Clone, PartialEq)]
pub enum CborValue {
    Uint(u64),
    Nint(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CborValue>),
    Map(CborMap),
    Bool(bool),
    Null,
}

/// A CBOR map preserving decode (canonical) key order. Native-channel keys are always
/// integers; entries hold the decoded key and value.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CborMap {
    pub entries: Vec<(CborValue, CborValue)>,
}

impl CborMap {
    /// Returns the value for an unsigned-integer key, if present.
    pub fn get(&self, key: u64) -> Option<&CborValue> {
        for (k, v) in &self.entries {
            if let CborValue::Uint(u) = k {
                if *u == key {
                    return Some(v);
                }
            }
        }
        None
    }

    /// Reports whether an unsigned-integer key is present.
    pub fn has(&self, key: u64) -> bool {
        self.get(key).is_some()
    }

    /// Returns the value at `key` when it is an unsigned integer.
    pub fn get_u64(&self, key: u64) -> Option<u64> {
        match self.get(key) {
            Some(CborValue::Uint(u)) => Some(*u),
            _ => None,
        }
    }

    /// Returns the value at `key` when it is a byte string.
    pub fn get_bytes(&self, key: u64) -> Option<&[u8]> {
        match self.get(key) {
            Some(CborValue::Bytes(b)) => Some(b.as_slice()),
            _ => None,
        }
    }
}

// ------------------------------------------------------------------------------------
// Errors
// ------------------------------------------------------------------------------------

/// A deterministic-CBOR decode fault: the input is outside the admitted canonical subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Bytes remain after the single top-level item.
    Trailing,
    /// The input ended inside an item.
    Truncated,
    /// An integer or length was not in shortest form (non-deterministic).
    NotShortest,
    /// An indefinite-length item (non-deterministic).
    Indefinite,
    /// An unsupported major type (tag) or simple value/float.
    Unsupported,
    /// Map keys were not in strictly ascending canonical order (or a duplicate key).
    MapOrder,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            DecodeError::Trailing => "trailing bytes after top-level item",
            DecodeError::Truncated => "truncated input",
            DecodeError::NotShortest => "integer/length not in shortest form",
            DecodeError::Indefinite => "indefinite-length item (non-deterministic)",
            DecodeError::Unsupported => "unsupported major type or simple value",
            DecodeError::MapOrder => "map keys not in canonical ascending order (or duplicate)",
        };
        write!(f, "npamp/cbor: {s}")
    }
}

/// A structural body fault. A native-channel receiver reports this as its channel's
/// `malformed_request` (or Telemetry `malformed_payload`) error; for conformance grading
/// it is the MUST-reject outcome. The message names the specific clause violated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Malformed(pub String);

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed: {}", self.0)
    }
}

impl From<DecodeError> for Malformed {
    fn from(e: DecodeError) -> Self {
        Malformed(e.to_string())
    }
}

fn err<T>(msg: impl Into<String>) -> Result<T, Malformed> {
    Err(Malformed(msg.into()))
}

// ------------------------------------------------------------------------------------
// Deterministic-CBOR decoder
// ------------------------------------------------------------------------------------

/// Decodes a single canonical CBOR item and requires it to consume all of `b` (the shape
/// of a frame payload). Enforces the deterministic subset strictly.
pub fn decode_top(b: &[u8]) -> Result<CborValue, DecodeError> {
    let (v, n) = decode(b)?;
    if n != b.len() {
        return Err(DecodeError::Trailing);
    }
    Ok(v)
}

/// `true` iff `a` sorts strictly before `b` in bytewise (shorter-first, then
/// lexicographic) order — RFC 8949 §4.2.1 canonical map-key ordering.
fn byte_less(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return a.len() < b.len();
    }
    for i in 0..a.len() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

/// Decodes one item from `b`, returning the value and the number of bytes consumed.
fn decode(b: &[u8]) -> Result<(CborValue, usize), DecodeError> {
    if b.is_empty() {
        return Err(DecodeError::Truncated);
    }
    let ib = b[0];
    let major = ib >> 5;
    let ai = ib & 0x1f;

    if major == 7 {
        // Only the simple values false(20)/true(21)/null(22) are in the deterministic
        // subset; floats (25/26/27), other simple values, and the break stop (31) are
        // rejected. The shortest-form argument check does not apply to a float payload.
        return match ai {
            20 => Ok((CborValue::Bool(false), 1)),
            21 => Ok((CborValue::Bool(true), 1)),
            22 => Ok((CborValue::Null, 1)),
            _ => Err(DecodeError::Unsupported),
        };
    }

    let (arg, n) = decode_arg(ai, b)?;
    match major {
        0 => Ok((CborValue::Uint(arg), n)),
        1 => {
            // negative int: value = -1 - arg. Reject an argument beyond i64 range (not
            // used by any native body), matching the Go reference.
            if arg > i64::MAX as u64 {
                return Err(DecodeError::Unsupported);
            }
            Ok((CborValue::Nint(-1 - arg as i64), n))
        }
        2 | 3 => {
            let end = n
                .checked_add(arg as usize)
                .ok_or(DecodeError::Truncated)?;
            if arg > b.len() as u64 || end > b.len() {
                return Err(DecodeError::Truncated);
            }
            let payload = &b[n..end];
            if major == 2 {
                Ok((CborValue::Bytes(payload.to_vec()), end))
            } else {
                // Text major type is accepted regardless of UTF-8 validity (as in the Go
                // reference, which does string(payload)); lossy conversion never changes
                // the major-type classification the schemas check.
                Ok((CborValue::Text(String::from_utf8_lossy(payload).into_owned()), end))
            }
        }
        4 => {
            // Each element is >= 1 byte, so a declared count exceeding the remaining input
            // cannot be satisfied — reject before allocating on an attacker count.
            if arg > (b.len() - n) as u64 {
                return Err(DecodeError::Truncated);
            }
            let mut out = Vec::with_capacity(arg as usize);
            let mut off = n;
            for _ in 0..arg {
                let (el, en) = decode(&b[off..])?;
                out.push(el);
                off += en;
            }
            Ok((CborValue::Array(out), off))
        }
        5 => {
            // Each entry is a key plus a value — >= 2 bytes — so a declared count exceeding
            // the remaining input cannot be satisfied.
            if arg > (b.len() - n) as u64 {
                return Err(DecodeError::Truncated);
            }
            let mut entries: Vec<(CborValue, CborValue)> = Vec::with_capacity(arg as usize);
            let mut off = n;
            let mut prev_key_enc: Option<Vec<u8>> = None;
            for _ in 0..arg {
                let key_start = off;
                let (key, kn) = decode(&b[off..])?;
                let key_enc = &b[key_start..key_start + kn];
                // Canonical order: each key MUST sort strictly after the previous one.
                if let Some(prev) = &prev_key_enc {
                    if !byte_less(prev, key_enc) {
                        return Err(DecodeError::MapOrder);
                    }
                }
                prev_key_enc = Some(key_enc.to_vec());
                off += kn;
                let (val, vn) = decode(&b[off..])?;
                off += vn;
                entries.push((key, val));
            }
            Ok((CborValue::Map(CborMap { entries }), off))
        }
        _ => Err(DecodeError::Unsupported), // major 6 (tags)
    }
}

/// Reads the argument for additional-information `ai`, enforcing shortest form
/// (RFC 8949 §4.2.1) and rejecting indefinite lengths. Returns the argument and the total
/// header length (including the leading byte).
fn decode_arg(ai: u8, b: &[u8]) -> Result<(u64, usize), DecodeError> {
    match ai {
        0..=23 => Ok((ai as u64, 1)),
        24 => {
            if b.len() < 2 {
                return Err(DecodeError::Truncated);
            }
            let v = b[1] as u64;
            if v < 24 {
                return Err(DecodeError::NotShortest);
            }
            Ok((v, 2))
        }
        25 => {
            if b.len() < 3 {
                return Err(DecodeError::Truncated);
            }
            let v = (b[1] as u64) << 8 | b[2] as u64;
            if v < 1 << 8 {
                return Err(DecodeError::NotShortest);
            }
            Ok((v, 3))
        }
        26 => {
            if b.len() < 5 {
                return Err(DecodeError::Truncated);
            }
            let v = (b[1] as u64) << 24 | (b[2] as u64) << 16 | (b[3] as u64) << 8 | b[4] as u64;
            if v < 1 << 16 {
                return Err(DecodeError::NotShortest);
            }
            Ok((v, 5))
        }
        27 => {
            if b.len() < 9 {
                return Err(DecodeError::Truncated);
            }
            let mut v: u64 = 0;
            for i in 1..=8 {
                v = v << 8 | b[i] as u64;
            }
            if v < 1 << 32 {
                return Err(DecodeError::NotShortest);
            }
            Ok((v, 9))
        }
        31 => Err(DecodeError::Indefinite),
        _ => Err(DecodeError::Unsupported), // 28, 29, 30 reserved
    }
}

// ------------------------------------------------------------------------------------
// Shared field-schema machinery
// ------------------------------------------------------------------------------------

/// The expected CBOR type of a body field. `Number` accepts an unsigned OR negative
/// integer (the two numeric shapes the deterministic codec produces for a signed value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Uint,
    Text,
    Bytes,
    Array,
    Map,
    Bool,
    Number,
}

/// One body field: integer key, expected kind, and whether the spec marks it REQUIRED.
type Field = (u64, Kind, bool);

fn matches_kind(v: &CborValue, k: Kind) -> bool {
    match k {
        Kind::Uint => matches!(v, CborValue::Uint(_)),
        Kind::Text => matches!(v, CborValue::Text(_)),
        Kind::Bytes => matches!(v, CborValue::Bytes(_)),
        Kind::Array => matches!(v, CborValue::Array(_)),
        Kind::Map => matches!(v, CborValue::Map(_)),
        Kind::Bool => matches!(v, CborValue::Bool(_)),
        Kind::Number => matches!(v, CborValue::Uint(_) | CborValue::Nint(_)),
    }
}

/// Enforces a schema's REQUIRED/typed fields and then the forward-compatibility key rule:
/// an unknown NON-negative integer key is accepted; an unknown NEGATIVE integer key, or a
/// non-integer key, is rejected. Does not itself validate envelope keys 0/1.
fn check_fields(m: &CborMap, schema: &[Field]) -> Result<(), Malformed> {
    for &(key, kind, required) in schema {
        match m.get(key) {
            None => {
                if required {
                    return err(format!("missing required field (key {key})"));
                }
            }
            Some(v) => {
                if !matches_kind(v, kind) {
                    return err(format!("field (key {key}) has the wrong CBOR type"));
                }
            }
        }
    }
    forward_compat_keys(m)
}

/// Forward-compat key rule over a decoded map: accept unknown non-negative integer keys;
/// reject an unknown negative or non-integer key.
fn forward_compat_keys(m: &CborMap) -> Result<(), Malformed> {
    for (k, _) in &m.entries {
        match k {
            CborValue::Uint(_) => {}
            CborValue::Nint(n) => return err(format!("unknown negative key {n} (reserved)")),
            _ => return err("non-integer map key"),
        }
    }
    Ok(())
}

/// frame_kind (0) MUST be an unsigned int equal to the frame type.
fn check_frame_kind(m: &CborMap, ft: u64) -> Result<(), Malformed> {
    match m.get(0) {
        None => err("missing frame_kind (0)"),
        Some(CborValue::Uint(u)) => {
            if *u == ft {
                Ok(())
            } else {
                err(format!(
                    "frame_kind 0x{u:04X} contradicts frame type 0x{ft:04X}"
                ))
            }
        }
        Some(_) => err("frame_kind (0) is not an unsigned int"),
    }
}

/// corr (1) MUST be present and a byte string of 1–64 bytes.
fn check_corr_required(m: &CborMap) -> Result<(), Malformed> {
    match m.get(1) {
        None => err("missing corr (1)"),
        Some(CborValue::Bytes(b)) => {
            if b.is_empty() || b.len() > 64 {
                err("corr (1) must be a byte string of 1–64 bytes")
            } else {
                Ok(())
            }
        }
        Some(_) => err("corr (1) must be a byte string"),
    }
}

/// Decodes `payload` to a top-level CBOR map, or errors (invalid CBOR / not a map).
fn decode_map(payload: &[u8]) -> Result<CborMap, Malformed> {
    match decode_top(payload)? {
        CborValue::Map(m) => Ok(m),
        _ => err("payload is not a CBOR map"),
    }
}

// ------------------------------------------------------------------------------------
// Capability (companion 84)
// ------------------------------------------------------------------------------------

fn capability_schema(ft: u64) -> Option<&'static [Field]> {
    use Kind::*;
    Some(match ft {
        0x0100 => &[(2, Text, true), (3, Text, true), (4, Map, false), (5, Text, false), (6, Text, false), (7, Uint, false), (8, Text, false), (9, Uint, true)],
        0x0101 => &[(2, Map, true), (3, Text, true)],
        0x0102 => &[(2, Text, true), (3, Text, true), (4, Map, false), (5, Text, false), (6, Uint, false), (7, Uint, true)],
        0x0103 => &[(2, Map, true), (3, Text, true)],
        0x0104 => &[(2, Text, true), (3, Bool, false), (4, Text, false), (5, Uint, true)],
        0x0105 => &[(2, Text, true), (3, Text, true), (4, Uint, false)],
        0x0106 => &[(2, Text, false), (3, Text, false), (4, Text, false), (5, Bool, false), (6, Uint, false), (7, Bytes, false), (8, Uint, true)],
        0x0107 => &[(2, Array, true), (3, Bool, true), (4, Bytes, false)],
        0x0108 => &[(2, Uint, true), (3, Text, true), (4, Uint, false), (5, Text, false)],
        0x0060 => &[(2, Map, true), (3, Array, false), (4, Uint, true)],
        0x0061 => &[(2, Text, true), (3, Text, true)],
        0x0062 => &[(2, Text, true), (3, Bytes, true), (4, Uint, true)],
        0x0063 => &[(2, Text, true), (3, Bytes, true)],
        _ => return None,
    })
}

/// Decodes and structurally validates a Capability (companion 84) frame body for `ft`.
pub fn validate_capability(ft: u64, payload: &[u8]) -> Result<CborMap, Malformed> {
    let schema = capability_schema(ft)
        .ok_or_else(|| Malformed(format!("0x{ft:04X} is not a Capability frame type")))?;
    let m = decode_map(payload)?;
    check_frame_kind(&m, ft)?;
    check_corr_required(&m)?;
    check_fields(&m, schema)?;
    Ok(m)
}

// ------------------------------------------------------------------------------------
// Immune (companion 85)
// ------------------------------------------------------------------------------------

fn immune_schema(ft: u64) -> Option<&'static [Field]> {
    use Kind::*;
    Some(match ft {
        0x0100 => &[(2, Text, true), (3, Uint, true), (4, Uint, true), (5, Text, false), (6, Text, false), (7, Text, false), (8, Bytes, false), (9, Uint, false), (10, Text, false)],
        0x0101 => &[(2, Uint, true), (3, Text, false)],
        0x0102 => &[(2, Uint, true), (3, Text, true), (4, Uint, false)],
        0x00C0 => &[(2, Array, true), (3, Bool, false)],
        0x00C1 => &[(2, Array, false), (3, Array, false), (4, Uint, false)],
        0x00C2 => &[(2, Array, true)],
        0x00C3 => &[(2, Array, true)],
        0x00C4 => &[(2, Bytes, true), (3, Uint, true), (4, Uint, false)],
        _ => return None,
    })
}

const GOSSIP_DESCRIPTOR_SCHEMA: &[Field] = {
    use Kind::*;
    &[(0, Bytes, true), (1, Uint, true), (2, Uint, false), (3, Uint, false), (4, Bytes, false), (5, Text, false), (6, Text, false), (7, Uint, false), (8, Bytes, false), (9, Bytes, false)]
};

const GOSSIP_ITEM_SCHEMA: &[Field] = {
    use Kind::*;
    &[(0, Bytes, true), (1, Uint, true), (2, Uint, false), (3, Uint, false), (4, Bytes, false), (5, Text, false), (6, Text, false), (7, Uint, false), (8, Bytes, true)]
};

/// Validates each element of the items(2) array against a nested gossip schema. A non-map
/// element or one failing the nested schema is malformed; an empty array is permitted.
fn validate_gossip_array(m: &CborMap, nested: &[Field]) -> Result<(), Malformed> {
    let arr = match m.get(2) {
        Some(CborValue::Array(a)) => a,
        _ => return err("missing items (2) array"),
    };
    for (i, el) in arr.iter().enumerate() {
        match el {
            CborValue::Map(em) => check_fields(em, nested)?,
            _ => return err(format!("items[{i}] is not a CBOR map")),
        }
    }
    Ok(())
}

/// Decodes and structurally validates an Immune (companion 85) frame body for `ft`,
/// including the nested gossip-descriptor / gossip-item required-key enforcement.
pub fn validate_immune(ft: u64, payload: &[u8]) -> Result<CborMap, Malformed> {
    let schema = immune_schema(ft)
        .ok_or_else(|| Malformed(format!("0x{ft:04X} is not an Immune frame type")))?;
    let m = decode_map(payload)?;
    check_frame_kind(&m, ft)?;
    check_corr_required(&m)?;
    check_fields(&m, schema)?;
    match ft {
        0x00C0 => validate_gossip_array(&m, GOSSIP_DESCRIPTOR_SCHEMA)?,
        0x00C3 => validate_gossip_array(&m, GOSSIP_ITEM_SCHEMA)?,
        _ => {}
    }
    Ok(m)
}

// ------------------------------------------------------------------------------------
// Settlement (companion 86)
// ------------------------------------------------------------------------------------

fn settlement_schema(ft: u64) -> Option<&'static [Field]> {
    use Kind::*;
    Some(match ft {
        0x0100 => &[(2, Text, true), (3, Text, false), (4, Text, false), (5, Text, false), (6, Text, false), (7, Text, false), (8, Uint, true)],
        0x0101 => &[(2, Text, true), (3, Text, true), (4, Text, false)],
        0x0102 => &[(2, Text, true), (3, Text, false), (4, Uint, true)],
        0x0103 => &[(2, Map, true)],
        0x0104 => &[(2, Uint, true), (3, Text, true), (4, Uint, false), (5, Text, false)],
        0x00A0 => &[(2, Text, true), (3, Bytes, true), (4, Text, false), (5, Uint, false), (6, Text, false), (7, Uint, true)],
        0x00A1 => &[(2, Text, true), (3, Text, true), (4, Text, false)],
        _ => return None,
    })
}

/// Decodes and structurally validates a Settlement (companion 86) frame body for `ft`.
pub fn validate_settlement(ft: u64, payload: &[u8]) -> Result<CborMap, Malformed> {
    let schema = settlement_schema(ft)
        .ok_or_else(|| Malformed(format!("0x{ft:04X} is not a Settlement frame type")))?;
    let m = decode_map(payload)?;
    check_frame_kind(&m, ft)?;
    check_corr_required(&m)?;
    check_fields(&m, schema)?;
    Ok(m)
}

// ------------------------------------------------------------------------------------
// Telemetry (companion 87)
// ------------------------------------------------------------------------------------

const TELEMETRY_METRIC_SCHEMA: &[Field] = {
    use Kind::*;
    &[(0, Text, true), (1, Uint, true), (2, Uint, true), (3, Number, true), (4, Text, false), (5, Map, false), (6, Uint, false)]
};
const TELEMETRY_EVENT_SCHEMA: &[Field] = {
    use Kind::*;
    &[(0, Text, true), (1, Uint, true), (2, Uint, false), (3, Map, false), (4, Text, false), (5, Uint, false)]
};
const TELEMETRY_HEALTH_SCHEMA: &[Field] = {
    use Kind::*;
    &[(0, Text, true), (1, Uint, true), (2, Uint, true), (3, Text, false), (4, Map, false)]
};

fn telemetry_schema(ft: u64) -> Option<&'static [Field]> {
    use Kind::*;
    Some(match ft {
        0x0101 => &[(2, Array, false), (3, Array, false), (4, Array, false), (5, Uint, false), (6, Uint, false), (7, Uint, true)],
        0x0102 => &[(2, Bytes, true), (3, Uint, true), (4, Array, false)],
        0x0103 => &[(2, Bytes, true)],
        0x0104 => &[(2, Bytes, true), (3, Uint, true), (4, Uint, false)],
        0x0105 => &[(2, Uint, true), (3, Text, false), (4, Bytes, false)],
        _ => return None,
    })
}

/// Validates a TELEMETRY_REPORT (0x0100) body (§5): corr(1) is CONDITIONAL (present iff the
/// batch answers a subscription, in which case sub_id(2) MUST also be present; a standalone
/// report omits both); batch_seq(3) is REQUIRED; the report MUST carry at least one
/// non-empty content array among metrics(4)/events(5)/health(6), each element validated
/// against its nested schema.
fn validate_telemetry_report(m: &CborMap) -> Result<CborMap, Malformed> {
    let has_corr = m.has(1);
    let has_sub_id = m.has(2);
    if has_corr {
        match m.get(1) {
            Some(CborValue::Bytes(b)) if !b.is_empty() && b.len() <= 64 => {}
            _ => return err("corr (1) must be a byte string of 1–64 bytes"),
        }
        if !has_sub_id {
            return err("subscribed report carries corr (1) but omits sub_id (2)");
        }
        if !matches!(m.get(2), Some(CborValue::Bytes(_))) {
            return err("sub_id (2) must be a byte string");
        }
    } else if has_sub_id {
        return err("standalone report carries sub_id (2) without corr (1)");
    }

    match m.get(3) {
        None => return err("missing required batch_seq (3)"),
        Some(CborValue::Uint(_)) => {}
        Some(_) => return err("batch_seq (3) is not an unsigned int"),
    }

    let mut non_empty = 0usize;
    for (key, schema, what) in [
        (4u64, TELEMETRY_METRIC_SCHEMA, "metric"),
        (5, TELEMETRY_EVENT_SCHEMA, "event"),
        (6, TELEMETRY_HEALTH_SCHEMA, "health"),
    ] {
        let arr = match m.get(key) {
            None => continue,
            Some(CborValue::Array(a)) => a,
            Some(_) => return err(format!("{what} array (key {key}) is not a CBOR array")),
        };
        if !arr.is_empty() {
            non_empty += 1;
        }
        for el in arr {
            match el {
                CborValue::Map(em) => check_fields(em, schema)?,
                _ => return err(format!("{what} array element is not a CBOR map")),
            }
        }
    }
    if non_empty == 0 {
        return err("TELEMETRY_REPORT carries no metrics, events, or health (§5)");
    }

    forward_compat_keys(m)?;
    Ok(m.clone())
}

/// Decodes and structurally validates a Telemetry (companion 87) frame body for `ft`.
pub fn validate_telemetry(ft: u64, payload: &[u8]) -> Result<CborMap, Malformed> {
    if !(0x0100..=0x0105).contains(&ft) {
        return err(format!("0x{ft:04X} is not a Telemetry frame type"));
    }
    let m = decode_map(payload)?;
    check_frame_kind(&m, ft)?;
    if ft == 0x0100 {
        return validate_telemetry_report(&m);
    }
    // Every non-REPORT Telemetry frame carries a REQUIRED, non-empty corr(1) (§4.1).
    check_corr_required(&m)?;
    let schema = telemetry_schema(ft).expect("checked range above");
    check_fields(&m, schema)?;
    Ok(m)
}

// ------------------------------------------------------------------------------------
// Commerce (companion 88)
// ------------------------------------------------------------------------------------

fn commerce_schema(ft: u64) -> Option<&'static [Field]> {
    use Kind::*;
    Some(match ft {
        0x0100 => &[(2, Text, true), (3, Text, true), (4, Map, true), (5, Text, false), (6, Text, false), (7, Text, false), (8, Map, false), (9, Text, false), (10, Bytes, false), (11, Text, false), (12, Text, false), (13, Uint, true)],
        0x0101 => &[(2, Text, true), (3, Text, true)],
        0x0102 => &[(2, Text, true), (3, Uint, true)],
        0x0103 => &[(2, Map, true)],
        0x0104 => &[(2, Text, true), (3, Text, false), (4, Uint, true)],
        0x0105 => &[(2, Text, true), (3, Text, true)],
        0x0106 => &[(2, Text, true), (3, Uint, true)],
        0x0107 => &[(2, Text, true), (3, Text, true), (4, Text, false)],
        0x0108 => &[(2, Array, true), (3, Array, true), (4, Text, false), (5, Map, false), (6, Text, false), (7, Uint, true)],
        0x0109 => &[(2, Text, true), (3, Text, true)],
        0x010A => &[(2, Text, true), (3, Uint, true), (4, Array, false), (5, Text, false), (6, Uint, true)],
        0x010B => &[(2, Text, true), (3, Text, true)],
        0x010C => &[(2, Text, true), (3, Uint, true)],
        0x010D => &[(2, Text, true), (3, Text, true), (4, Array, false), (5, Array, false)],
        0x010E => &[(2, Uint, true), (3, Text, true), (4, Uint, false), (5, Text, false)],
        _ => return None,
    })
}

/// Enforces the §4.3 monetary-amount structure: units(0) a signed integer, scale(1) an
/// unsigned int, currency(2) a text string — all REQUIRED — plus the forward-compat key
/// rule on the nested amount map.
fn validate_commerce_amount(v: &CborValue) -> Result<(), Malformed> {
    let m = match v {
        CborValue::Map(m) => m,
        _ => return err("`amount` is not a CBOR map (§4.3)"),
    };
    match m.get(0) {
        None => return err("`amount` omits REQUIRED units (0) (§4.3)"),
        Some(CborValue::Uint(_)) | Some(CborValue::Nint(_)) => {}
        Some(_) => return err("`amount` units (0) is not an integer (§4.3)"),
    }
    match m.get(1) {
        None => return err("`amount` omits REQUIRED scale (1) (§4.3)"),
        Some(CborValue::Uint(_)) => {}
        Some(_) => return err("`amount` scale (1) is not an unsigned int (§4.3)"),
    }
    match m.get(2) {
        None => return err("`amount` omits REQUIRED currency (2) (§4.3)"),
        Some(CborValue::Text(_)) => {}
        Some(_) => return err("`amount` currency (2) is not a text string (§4.3)"),
    }
    forward_compat_keys(m)
}

/// Enforces the §6.6 settlement-leg shape { from(0):tstr, to(1):tstr, amount(2):amount }
/// and the rule that from/to MUST be named parties, plus the nested amount and forward-compat.
fn validate_commerce_leg(v: &CborValue, parties: &[String]) -> Result<(), Malformed> {
    let m = match v {
        CborValue::Map(m) => m,
        _ => return err("a settlement leg is not a CBOR map (§6.6)"),
    };
    let frm = match m.get(0) {
        Some(CborValue::Text(s)) => s,
        Some(_) => return err("a leg `from` (0) is not a text string (§6.6)"),
        None => return err("a leg omits REQUIRED `from` (0) (§6.6)"),
    };
    let to = match m.get(1) {
        Some(CborValue::Text(s)) => s,
        Some(_) => return err("a leg `to` (1) is not a text string (§6.6)"),
        None => return err("a leg omits REQUIRED `to` (1) (§6.6)"),
    };
    match m.get(2) {
        Some(a) => validate_commerce_amount(a)?,
        None => return err("a leg omits REQUIRED `amount` (2) (§6.6)"),
    }
    if !parties.iter().any(|p| p == frm) {
        return err("leg `from` names a party not in `parties` (§6.6)");
    }
    if !parties.iter().any(|p| p == to) {
        return err("leg `to` names a party not in `parties` (§6.6)");
    }
    forward_compat_keys(m)
}

/// Applies the §4.3 amount and §6.6 leg-party MUST-reject rules for the frame types that
/// carry those nested structures.
fn validate_commerce_nested(ft: u64, m: &CborMap) -> Result<(), Malformed> {
    match ft {
        0x0100 => {
            // amount (4) is REQUIRED (schema-checked as Map) and is a §4.3 monetary amount.
            if let Some(a) = m.get(4) {
                validate_commerce_amount(a)?;
            }
        }
        0x0108 => {
            // parties (2) REQUIRED array of text; legs (3) REQUIRED array; every leg's
            // from/to MUST be a named party and its amount well-formed.
            let parties = match m.get(2) {
                Some(CborValue::Array(a)) => {
                    let mut set = Vec::with_capacity(a.len());
                    for p in a {
                        match p {
                            CborValue::Text(s) => set.push(s.clone()),
                            _ => return err("a `parties` element is not a text string (§6.6)"),
                        }
                    }
                    set
                }
                _ => return err("missing parties (2) array (§6.6)"),
            };
            if let Some(CborValue::Array(legs)) = m.get(3) {
                for lg in legs {
                    validate_commerce_leg(lg, &parties)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// Decodes and structurally validates a Commerce (companion 88) frame body for `ft`,
/// including the nested monetary-amount and settlement-leg party-membership rules.
pub fn validate_commerce(ft: u64, payload: &[u8]) -> Result<CborMap, Malformed> {
    let schema = commerce_schema(ft)
        .ok_or_else(|| Malformed(format!("0x{ft:04X} is not a Commerce frame type")))?;
    let m = decode_map(payload)?;
    check_frame_kind(&m, ft)?;
    check_corr_required(&m)?;
    check_fields(&m, schema)?;
    validate_commerce_nested(ft, &m)?;
    Ok(m)
}

// ------------------------------------------------------------------------------------
// Interaction (companion 89)
// ------------------------------------------------------------------------------------

fn interaction_schema(ft: u64) -> Option<&'static [Field]> {
    use Kind::*;
    Some(match ft {
        0x0100 => &[(2, Uint, true), (3, Text, false), (4, Map, false), (5, Bool, false)],
        0x0101 => &[],
        0x0102 => &[(2, Uint, true), (3, Text, true), (4, Array, false), (5, Map, false), (6, Uint, false)],
        0x0103 => &[(2, Uint, true)],
        0x0104 => &[(2, Text, true), (3, Uint, false), (4, Map, false), (5, Uint, false)],
        0x0105 => &[(2, Uint, true), (3, Text, false)],
        0x0106 => &[(2, Uint, false)],
        0x0107 => &[(2, Uint, true), (3, Text, true), (4, Uint, false), (5, Text, false)],
        _ => return None,
    })
}

/// Decodes and structurally validates an Interaction (companion 89) frame body for `ft`.
pub fn validate_interaction(ft: u64, payload: &[u8]) -> Result<CborMap, Malformed> {
    let schema = interaction_schema(ft)
        .ok_or_else(|| Malformed(format!("0x{ft:04X} is not an Interaction frame type")))?;
    let m = decode_map(payload)?;
    check_frame_kind(&m, ft)?;
    check_corr_required(&m)?;
    check_fields(&m, schema)?;
    Ok(m)
}

// ------------------------------------------------------------------------------------
// Workflow (companion 8a)
// ------------------------------------------------------------------------------------

fn workflow_schema(ft: u64) -> Option<&'static [Field]> {
    use Kind::*;
    Some(match ft {
        0x0100 => &[(2, Text, true), (3, Bytes, false), (4, Map, false), (5, Uint, false), (6, Text, false), (7, Text, false), (8, Text, false), (9, Text, false), (10, Map, false), (11, Uint, true)],
        0x0101 => &[(2, Text, true), (3, Uint, true)],
        0x0102 => &[(2, Text, true)],
        0x0103 => &[(2, Text, true), (3, Uint, true), (4, Uint, false), (5, Text, false), (6, Uint, false), (7, Text, false)],
        0x0104 => &[(2, Text, true), (3, Text, false)],
        0x0105 => &[(2, Text, true), (3, Uint, true)],
        0x0106 => &[(2, Text, true), (3, Uint, true), (4, Uint, true), (5, Uint, false), (6, Text, false), (7, Uint, false), (8, Bytes, false), (9, Text, false)],
        0x0107 => &[(2, Text, true), (3, Uint, true), (4, Uint, true), (5, Bytes, false), (6, Uint, false), (7, Text, false)],
        0x0108 => &[(2, Uint, true), (3, Text, true), (4, Uint, false), (5, Text, false)],
        _ => return None,
    })
}

/// WORKFLOW_STEP_EVENT (0x0106) and WORKFLOW_COMPLETE (0x0107) are unsolicited task-scoped
/// notifications and carry NO corr (§4.2, §5.2); every other Workflow frame carries corr.
fn workflow_has_corr(ft: u64) -> bool {
    ft != 0x0106 && ft != 0x0107
}

/// Decodes and structurally validates a Workflow (companion 8a) frame body for `ft`.
pub fn validate_workflow(ft: u64, payload: &[u8]) -> Result<CborMap, Malformed> {
    let schema = workflow_schema(ft)
        .ok_or_else(|| Malformed(format!("0x{ft:04X} is not a Workflow frame type")))?;
    let m = decode_map(payload)?;
    check_frame_kind(&m, ft)?;
    if workflow_has_corr(ft) {
        check_corr_required(&m)?;
    }
    check_fields(&m, schema)?;
    Ok(m)
}

// ------------------------------------------------------------------------------------
// Knowledge (companion 8b)
// ------------------------------------------------------------------------------------

fn knowledge_schema(ft: u64) -> Option<&'static [Field]> {
    use Kind::*;
    Some(match ft {
        0x0100 => &[(2, Text, false), (3, Text, false), (4, Text, false), (5, Text, false), (6, Uint, false), (8, Text, false), (9, Bytes, false)],
        0x0101 => &[(2, Array, true), (3, Bool, true), (4, Bytes, false), (5, Uint, false), (6, Bool, false)],
        0x0102 => &[(2, Array, true)],
        0x0103 => &[(2, Array, false), (3, Bool, true)],
        0x0104 => &[(2, Text, false), (3, Text, false), (4, Text, false), (5, Text, false), (7, Text, false), (8, Bool, false), (9, Uint, true)],
        0x0105 => &[(2, Bytes, true), (3, Uint, true), (4, Bool, false)],
        0x0106 => &[(2, Bytes, true), (3, Uint, true), (4, Array, false), (5, Array, false)],
        0x0107 => &[(2, Bytes, true), (3, Uint, true), (4, Uint, false)],
        0x0108 => &[(2, Bytes, true)],
        0x0109 => &[(2, Uint, true), (3, Text, true), (4, Uint, false), (5, Bytes, false)],
        _ => return None,
    })
}

/// Decodes and structurally validates a Knowledge (companion 8b) frame body for `ft`,
/// including the §6.5 rule that a KNOWLEDGE_UPDATE MUST carry results(4) or removed(5).
pub fn validate_knowledge(ft: u64, payload: &[u8]) -> Result<CborMap, Malformed> {
    let schema = knowledge_schema(ft)
        .ok_or_else(|| Malformed(format!("0x{ft:04X} is not a Knowledge frame type")))?;
    let m = decode_map(payload)?;
    check_frame_kind(&m, ft)?;
    check_corr_required(&m)?;
    check_fields(&m, schema)?;
    if ft == 0x0106 && !m.has(4) && !m.has(5) {
        return err("KNOWLEDGE_UPDATE carries neither results (4) nor removed (5) (§6.5)");
    }
    Ok(m)
}

// ------------------------------------------------------------------------------------
// Dispatch by conformance op name
// ------------------------------------------------------------------------------------

/// Validates a native-channel body by the conformance-corpus op name (e.g.
/// `"capability.body.decode"`). Returns the decoded map on success. Unknown op → `Err`.
pub fn validate_by_op(op: &str, ft: u64, payload: &[u8]) -> Result<CborMap, Malformed> {
    match op {
        "capability.body.decode" => validate_capability(ft, payload),
        "immune.body.decode" => validate_immune(ft, payload),
        "settlement.body.decode" => validate_settlement(ft, payload),
        "telemetry.body.decode" => validate_telemetry(ft, payload),
        "commerce.body.decode" => validate_commerce(ft, payload),
        "interaction.body.decode" => validate_interaction(ft, payload),
        "workflow.body.decode" => validate_workflow(ft, payload),
        "knowledge.body.decode" => validate_knowledge(ft, payload),
        _ => err(format!("unknown op {op}")),
    }
}
