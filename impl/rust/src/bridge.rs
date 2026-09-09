//! NPAMP-BRIDGE frame codec — spec/companion/10_bridge_framework.md §2–§8.
//!
//! Mirrors the Go reference (`impl/go/{bridge.go,bridge_bodies.go,bridge_api.go}`)
//! byte-for-byte. Unlike the native-channel bodies (`bodies.rs`, deterministic CBOR),
//! a Bridge frame payload (Bridge channel 0x000D) is a fixed-layout TLV envelope
//! carried AROUND a foreign message (MCP, A2A, …):
//!
//!   BridgeEnvelope TLV (Type 0x0010, REQUIRED, first)  — §4, routing/correlation/method
//!   SafetyLabel   TLV (Type 0x0013, OPTIONAL)          — §7, side-effect class + scope hint
//!   <foreign message>                                  — §1, carried verbatim, never modified
//!
//! TLVs use the core extension-TLV encoding (Type u16, Length u16, Value — both
//! big-endian). This module owns its own minimal TLV header encode/decode (the crate
//! has no shared generic TLV module to reuse, unlike `impl/go/tlv.go`).

/// Bridge frame types (§2). These values live in the per-channel application band
/// (0x0100+) and carry their NPAMP-BRIDGE meaning ONLY on the Bridge channel (0x000D).
pub const FRAME_BRIDGE_REQUEST: u16 = 0x0100;
pub const FRAME_BRIDGE_RESPONSE: u16 = 0x0101;
pub const FRAME_BRIDGE_ERROR: u16 = 0x0102;
pub const FRAME_BRIDGE_NOTIFY: u16 = 0x0103;
pub const FRAME_BRIDGE_STREAM_DATA: u16 = 0x0104;
pub const FRAME_BRIDGE_STREAM_END: u16 = 0x0105;

/// TLV extension types defined by NPAMP-BRIDGE within the Bridge-channel payload (§3).
pub const TLV_BRIDGE_ENVELOPE: u16 = 0x0010;
pub const TLV_SAFETY_LABEL: u16 = 0x0013;

/// Envelope `flags` bit 0 (§4): set on the terminating frame of a stream. Bits 1–7 are
/// reserved; a receiver MUST ignore them (never rejects on a nonzero reserved bit).
pub const FLAG_FINAL: u8 = 0x01;

/// §7 SafetyLabel `effect` values — a receiver MUST treat the ABSENCE of a SafetyLabel
/// on a state-mutating operation as destructive, never read_only (fail-safe; see
/// [`BridgeFrame::effective_effect`]).
pub const EFFECT_READ_ONLY: u8 = 0x00;
pub const EFFECT_IDEMPOTENT_WRITE: u8 = 0x01;
pub const EFFECT_NON_IDEMPOTENT_WRITE: u8 = 0x02;
pub const EFFECT_DESTRUCTIVE: u8 = 0x03;

/// A structural fault — reported as BRIDGE_ERROR code EnvelopeMalformed (§4/§6 code 1).
/// The message names the specific clause violated, mirroring the Go reference's
/// `fmt.Errorf` text (`ErrBridgeMalformed`-wrapped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeMalformed(pub String);

impl std::fmt::Display for BridgeMalformed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "npamp/bridge: envelope_malformed: {}", self.0)
    }
}

impl std::error::Error for BridgeMalformed {}

/// The decoded §4 BridgeEnvelope value. Multi-octet integers are big-endian on the
/// wire; every scalar is a single octet EXCEPT `protocol` (protocol_id), which is two
/// octets (NPAMP-REG §8.4 widening). `correlation_id` and `method` are the raw
/// variable-length fields, each length-prefixed by a u8 on the wire (so each is at
/// most 255 octets).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BridgeEnvelope {
    /// protocol_id (§4) — the foreign agentic protocol this frame carries.
    pub protocol: u16,
    /// message_kind (§4) — MUST agree with the frame type ([`kind_for_frame`]).
    pub kind: u8,
    /// content_type (§4) — the foreign message's own encoding.
    pub content_type: u8,
    /// flags (§4) — bit 0 = final, bits 1–7 reserved/ignored.
    pub flags: u8,
    /// correlation_id (§5) — non-empty on request/reply, empty on notify.
    pub correlation_id: Vec<u8>,
    /// method (§4) — UTF-8 op name (e.g. "tools/call"); empty when not applicable.
    pub method: Vec<u8>,
}

impl BridgeEnvelope {
    /// Reports whether the envelope's `final` flag (bit 0) is set (§4). Reserved bits
    /// 1–7 are ignored per §4, so only bit 0 is consulted.
    pub fn final_flag(&self) -> bool {
        self.flags & FLAG_FINAL != 0
    }
}

/// The decoded §7 SafetyLabel value.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SafetyLabel {
    /// effect (§7 side-effect class).
    pub effect: u8,
    /// scope (§7; UTF-8 resource/scope hint, advisory); at most 255 octets.
    pub scope: Vec<u8>,
}

/// A fully decoded Bridge payload: the required envelope, the optional SafetyLabel
/// (`None` when absent), and the foreign message carried verbatim (§1, §3).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BridgeFrame {
    pub envelope: BridgeEnvelope,
    /// `None` when no SafetyLabel TLV was present.
    pub safety: Option<SafetyLabel>,
    /// The foreign message, octet-for-octet (may be empty).
    pub foreign: Vec<u8>,
}

impl BridgeFrame {
    /// Applies the §7 fail-safe: when a SafetyLabel is present its effect governs;
    /// when it is ABSENT the effect MUST be treated as destructive (a receiver MUST
    /// NOT treat absence on a state-mutating operation as read_only). Callers use this
    /// rather than reading `safety` directly so the fail-safe cannot be forgotten.
    pub fn effective_effect(&self) -> u8 {
        match &self.safety {
            Some(s) => s.effect,
            None => EFFECT_DESTRUCTIVE,
        }
    }
}

/// Returns the message_kind that a frame of type `ft` MUST carry, and `None` if `ft`
/// is not a Bridge frame type at all (§4). Note the mapping is NOT the identity of the
/// low byte: BRIDGE_ERROR (0x0102) pairs with kind 0x04 and BRIDGE_NOTIFY (0x0103)
/// with kind 0x03, so a table — not arithmetic — defines the agreement.
pub fn kind_for_frame(ft: u16) -> Option<u8> {
    match ft {
        FRAME_BRIDGE_REQUEST => Some(0x01),
        FRAME_BRIDGE_RESPONSE => Some(0x02),
        FRAME_BRIDGE_ERROR => Some(0x04),
        FRAME_BRIDGE_NOTIFY => Some(0x03),
        FRAME_BRIDGE_STREAM_DATA => Some(0x05),
        FRAME_BRIDGE_STREAM_END => Some(0x06),
        _ => None,
    }
}

/// Reports whether `ft` is an NPAMP-BRIDGE frame type (0x0100–0x0105). Does not
/// consider the channel; a caller has already established the frame arrived on the
/// Bridge channel (0x000D), on which these values carry their NPAMP-BRIDGE meaning.
pub fn is_bridge_frame(ft: u16) -> bool {
    (FRAME_BRIDGE_REQUEST..=FRAME_BRIDGE_STREAM_END).contains(&ft)
}

/// Reports whether `ft` is the reply-eliciting Bridge frame (§2, §5). MUST carry a
/// non-empty correlation_id.
pub fn is_bridge_request(ft: u16) -> bool {
    ft == FRAME_BRIDGE_REQUEST
}

/// Reports whether `ft` is a frame that echoes an originating request's
/// correlation_id (§5): RESPONSE, ERROR, STREAM_DATA, or STREAM_END.
pub fn is_bridge_reply(ft: u16) -> bool {
    matches!(
        ft,
        FRAME_BRIDGE_RESPONSE | FRAME_BRIDGE_ERROR | FRAME_BRIDGE_STREAM_DATA | FRAME_BRIDGE_STREAM_END
    )
}

// ---------------------------------------------------------------------------
// TLV header helpers (Type u16, Length u16, big-endian).
// ---------------------------------------------------------------------------

fn encode_tlv(out: &mut Vec<u8>, typ: u16, value: &[u8]) {
    out.extend_from_slice(&typ.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

/// Encodes the §4 BridgeEnvelope value (the TLV Value, without the 4-octet TLV
/// header). Layout: protocol_id (u16, big-endian), message_kind, content_type, flags,
/// corr_len, correlation_id, method_len, method. Panics if `correlation_id` or
/// `method` exceeds 255 octets, which the u8 length fields cannot represent — mirrors
/// the Go reference's `encodeEnvelopeValue`, which panics under the same condition.
fn encode_envelope_value(e: &BridgeEnvelope) -> Vec<u8> {
    assert!(
        e.correlation_id.len() <= 255,
        "npamp/bridge: correlation_id {} octets exceeds u8 corr_len",
        e.correlation_id.len()
    );
    assert!(
        e.method.len() <= 255,
        "npamp/bridge: method {} octets exceeds u8 method_len",
        e.method.len()
    );
    let mut out = Vec::with_capacity(6 + e.correlation_id.len() + 1 + e.method.len());
    out.extend_from_slice(&e.protocol.to_be_bytes());
    out.push(e.kind);
    out.push(e.content_type);
    out.push(e.flags);
    out.push(e.correlation_id.len() as u8);
    out.extend_from_slice(&e.correlation_id);
    out.push(e.method.len() as u8);
    out.extend_from_slice(&e.method);
    out
}

/// Encodes the §7 SafetyLabel value (effect, scope_len, scope). Panics if `scope`
/// exceeds 255 octets, mirroring the Go reference's `encodeSafetyValue`.
fn encode_safety_value(s: &SafetyLabel) -> Vec<u8> {
    assert!(
        s.scope.len() <= 255,
        "npamp/bridge: scope {} octets exceeds u8 scope_len",
        s.scope.len()
    );
    let mut out = Vec::with_capacity(2 + s.scope.len());
    out.push(s.effect);
    out.push(s.scope.len() as u8);
    out.extend_from_slice(&s.scope);
    out
}

/// Encodes a [`BridgeFrame`] to its canonical wire payload (§3): the envelope TLV, the
/// optional SafetyLabel TLV, then the foreign message verbatim. The layout is fully
/// determined (fixed field order, definite lengths), so a decode followed by
/// `encode_bridge_frame` reproduces the exact input octets.
pub fn encode_bridge_frame(f: &BridgeFrame) -> Vec<u8> {
    let mut out = Vec::new();
    encode_tlv(&mut out, TLV_BRIDGE_ENVELOPE, &encode_envelope_value(&f.envelope));
    if let Some(s) = &f.safety {
        encode_tlv(&mut out, TLV_SAFETY_LABEL, &encode_safety_value(s));
    }
    out.extend_from_slice(&f.foreign);
    out
}

/// Builds a canonical Bridge frame payload (§3) from its parts. Pass `None` for
/// `safety` to omit the SafetyLabel TLV; pass an empty (but present) `foreign` for a
/// payload with no foreign body. Mirrors the Go reference's `EncodeBridgePayload`.
pub fn encode_bridge_payload(env: &BridgeEnvelope, safety: Option<&SafetyLabel>, foreign: &[u8]) -> Vec<u8> {
    encode_bridge_frame(&BridgeFrame {
        envelope: env.clone(),
        safety: safety.cloned(),
        foreign: foreign.to_vec(),
    })
}

// ---------------------------------------------------------------------------
// Decode + structural validation
// ---------------------------------------------------------------------------

/// Decodes a §4 BridgeEnvelope value and requires that it consumes the whole slice
/// (the declared TLV Value): trailing octets inside the envelope TLV are a
/// malformation.
fn decode_envelope_value(v: &[u8]) -> Result<BridgeEnvelope, BridgeMalformed> {
    // Fixed head: protocol_id (u16 BE), message_kind, content_type, flags, corr_len.
    if v.len() < 6 {
        return Err(BridgeMalformed(format!(
            "envelope value truncated before corr_len ({} < 6 octets)",
            v.len()
        )));
    }
    let corr_len = v[5] as usize;
    // correlation_id (corr_len octets) then method_len (1 octet).
    if v.len() < 6 + corr_len + 1 {
        return Err(BridgeMalformed(
            "envelope value truncated in correlation_id/method_len".to_string(),
        ));
    }
    let corr = &v[6..6 + corr_len];
    let method_len = v[6 + corr_len] as usize;
    let end = 6 + corr_len + 1 + method_len;
    if v.len() < end {
        return Err(BridgeMalformed("envelope value truncated in method".to_string()));
    }
    if v.len() != end {
        return Err(BridgeMalformed(format!(
            "envelope value has {} trailing octet(s)",
            v.len() - end
        )));
    }
    Ok(BridgeEnvelope {
        protocol: u16::from_be_bytes([v[0], v[1]]),
        kind: v[2],
        content_type: v[3],
        flags: v[4],
        correlation_id: corr.to_vec(),
        method: v[6 + corr_len + 1..end].to_vec(),
    })
}

/// Decodes a §7 SafetyLabel value (effect, scope_len, scope) and requires exact
/// consumption of the declared TLV Value.
fn decode_safety_value(v: &[u8]) -> Result<SafetyLabel, BridgeMalformed> {
    if v.len() < 2 {
        return Err(BridgeMalformed(format!(
            "SafetyLabel value truncated before scope_len ({} < 2 octets)",
            v.len()
        )));
    }
    let scope_len = v[1] as usize;
    let end = 2 + scope_len;
    if v.len() < end {
        return Err(BridgeMalformed("SafetyLabel value truncated in scope".to_string()));
    }
    if v.len() != end {
        return Err(BridgeMalformed(format!(
            "SafetyLabel value has {} trailing octet(s)",
            v.len() - end
        )));
    }
    Ok(SafetyLabel { effect: v[0], scope: v[2..end].to_vec() })
}

/// Decodes and structurally validates a Bridge frame payload for frame type `ft`,
/// returning the decoded [`BridgeFrame`] on success. On any structural fault returns
/// an error (§4/§6 EnvelopeMalformed):
///
///   - `ft` is not a Bridge frame type (§2);
///   - the payload does not begin with a BridgeEnvelope TLV (Type 0x0010), or that TLV
///     is truncated or trailing-garbled (§4);
///   - message_kind does not agree with `ft` (§4);
///   - a BRIDGE_REQUEST or a reply frame carries an empty correlation_id, or a
///     BRIDGE_NOTIFY carries a non-empty one (§5, §8);
///   - a present SafetyLabel TLV is malformed (§7).
///
/// The foreign message (the octets after the final TLV) is returned verbatim in
/// `BridgeFrame::foreign` and is never inspected. A missing SafetyLabel is NOT a
/// structural fault here — its §7 fail-safe is applied by
/// [`BridgeFrame::effective_effect`].
pub fn validate_bridge_payload(ft: u16, payload: &[u8]) -> Result<BridgeFrame, BridgeMalformed> {
    let want_kind = match kind_for_frame(ft) {
        Some(k) => k,
        None => return Err(BridgeMalformed(format!("0x{ft:04X} is not a Bridge frame type"))),
    };

    // §4: the envelope MUST be present as the first TLV. Need at least a 4-octet TLV
    // header to read its Type and Length.
    if payload.len() < 4 {
        return Err(BridgeMalformed(format!(
            "payload too short for a BridgeEnvelope TLV ({} < 4 octets)",
            payload.len()
        )));
    }
    let env_type = u16::from_be_bytes([payload[0], payload[1]]);
    let env_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    if env_type != TLV_BRIDGE_ENVELOPE {
        return Err(BridgeMalformed(format!(
            "first TLV type 0x{env_type:04X} is not BridgeEnvelope (0x0010)"
        )));
    }
    if payload.len() < 4 + env_len {
        return Err(BridgeMalformed(format!(
            "BridgeEnvelope TLV length {env_len} exceeds remaining payload"
        )));
    }
    let env = decode_envelope_value(&payload[4..4 + env_len])?;

    // §4: message_kind MUST agree with the frame type.
    if env.kind != want_kind {
        return Err(BridgeMalformed(format!(
            "message_kind 0x{:02X} contradicts frame type 0x{ft:04X} (expected kind 0x{want_kind:02X})",
            env.kind
        )));
    }

    // §5/§8: correlation_id presence rules keyed on the frame's role.
    if ft == FRAME_BRIDGE_NOTIFY {
        if !env.correlation_id.is_empty() {
            return Err(BridgeMalformed(format!(
                "BRIDGE_NOTIFY MUST set corr_len=0 (got {}, §5/§8)",
                env.correlation_id.len()
            )));
        }
    } else if ft == FRAME_BRIDGE_REQUEST {
        if env.correlation_id.is_empty() {
            return Err(BridgeMalformed(
                "BRIDGE_REQUEST MUST carry a non-empty correlation_id (§5)".to_string(),
            ));
        }
    } else {
        // Reply frames (RESPONSE, ERROR, STREAM_DATA, STREAM_END): a reply MUST echo
        // the originating request's correlation_id verbatim; since a request's id is
        // non-empty, an empty id on a reply cannot echo one.
        if env.correlation_id.is_empty() {
            return Err(BridgeMalformed(
                "a reply frame MUST echo the request's non-empty correlation_id (§5)".to_string(),
            ));
        }
    }

    // §3/§7: an OPTIONAL SafetyLabel TLV may immediately follow the envelope; the
    // octets after it (or after the envelope, if none) are the foreign message.
    let mut rest = &payload[4 + env_len..];
    let mut safety = None;
    if rest.len() >= 4 && u16::from_be_bytes([rest[0], rest[1]]) == TLV_SAFETY_LABEL {
        let s_len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        if rest.len() < 4 + s_len {
            return Err(BridgeMalformed(format!(
                "SafetyLabel TLV length {s_len} exceeds remaining payload"
            )));
        }
        let s = decode_safety_value(&rest[4..4 + s_len])?;
        safety = Some(s);
        rest = &rest[4 + s_len..];
    }

    Ok(BridgeFrame { envelope: env, safety, foreign: rest.to_vec() })
}

/// Validates a Bridge payload for frame type `ft` and returns the decoded
/// [`BridgeFrame`]. A non-`Ok` result means the frame MUST be rejected with
/// BRIDGE_ERROR code EnvelopeMalformed (§6). Mirrors the Go reference's
/// `DecodeBridgeFrame`.
pub fn decode_bridge_frame(ft: u16, payload: &[u8]) -> Result<BridgeFrame, BridgeMalformed> {
    validate_bridge_payload(ft, payload)
}

/// Validates a Bridge payload for frame type `ft` and returns just the decoded
/// envelope (§4), discarding the SafetyLabel and foreign message. Mirrors the Go
/// reference's `DecodeBridgeEnvelope`.
pub fn decode_bridge_envelope(ft: u16, payload: &[u8]) -> Result<BridgeEnvelope, BridgeMalformed> {
    validate_bridge_payload(ft, payload).map(|f| f.envelope)
}

/// Reports whether a decoded reply envelope correlates to a decoded request envelope
/// (§5): the reply's correlation_id MUST equal the request's verbatim, and
/// correlation is by identifier, NOT by frame sequence number. Returns `false` when
/// either identifier is empty (an empty id never correlates).
pub fn correlate_bridge_reply(request: &BridgeEnvelope, reply: &BridgeEnvelope) -> bool {
    if request.correlation_id.is_empty() || reply.correlation_id.is_empty() {
        return false;
    }
    request.correlation_id == reply.correlation_id
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trips the corpus's tcId=1 vector (BRIDGE_REQUEST, MCP tools/call, with a
    /// SafetyLabel) end-to-end: decode then re-encode MUST reproduce the exact input
    /// octets (the property `EncodeBridgeFrame`'s doc comment claims).
    #[test]
    fn decode_then_encode_round_trips_tc1() {
        let payload = hex(
            "001000150001010100040a0b0c0d0a746f6f6c732f63616c6c00130009020766733a2f746d707b\
             226a736f6e727063223a22322e30222c226964223a312c226d6574686f64223a22746f6f6c732f\
             63616c6c227d",
        );
        let ft = FRAME_BRIDGE_REQUEST;
        let f = decode_bridge_frame(ft, &payload).expect("valid vector must decode");
        assert_eq!(f.envelope.protocol, 1);
        assert_eq!(f.envelope.kind, 0x01);
        assert_eq!(f.envelope.content_type, 0x01);
        assert_eq!(f.envelope.flags, 0);
        assert!(!f.envelope.final_flag());
        assert_eq!(f.envelope.correlation_id, hex("0a0b0c0d"));
        assert_eq!(f.envelope.method, b"tools/call");
        let safety = f.safety.as_ref().expect("SafetyLabel present");
        assert_eq!(safety.effect, 0x02);
        assert_eq!(safety.scope, b"fs:/tmp");
        assert_eq!(f.effective_effect(), 0x02);

        let re_encoded = encode_bridge_frame(&f);
        assert_eq!(re_encoded, payload, "decode->encode must reproduce the exact input octets");
    }

    /// A BRIDGE_REQUEST with an empty correlation_id MUST be rejected (§5); the sole
    /// gate is the corr_len==0 check inside `validate_bridge_payload`'s
    /// FRAME_BRIDGE_REQUEST branch (corpus tcId=21).
    #[test]
    fn request_with_empty_correlation_id_is_rejected() {
        let payload = hex(
            "001000110001010100000a746f6f6c732f63616c6c7b226a736f6e727063223a22322e30222c22\
             6964223a312c226d6574686f64223a22746f6f6c732f63616c6c227d",
        );
        let err = decode_bridge_frame(FRAME_BRIDGE_REQUEST, &payload)
            .expect_err("empty correlation_id on a request MUST be rejected");
        assert!(err.0.contains("non-empty correlation_id"), "unexpected error: {}", err.0);
    }

    /// A reply echoing the request's correlation_id correlates (§5, corpus
    /// bridge.correlate tcId=1); a reply with a different correlation_id does not.
    #[test]
    fn correlate_matches_by_identifier_not_by_frame_sequence() {
        let a = BridgeEnvelope { correlation_id: vec![0x0a, 0x0b], ..Default::default() };
        let b = BridgeEnvelope { correlation_id: vec![0x0a, 0x0b], ..Default::default() };
        let c = BridgeEnvelope { correlation_id: vec![0xff, 0xff], ..Default::default() };
        assert!(correlate_bridge_reply(&a, &b));
        assert!(!correlate_bridge_reply(&a, &c));
        assert!(!correlate_bridge_reply(&BridgeEnvelope::default(), &b));
    }

    fn hex(s: &str) -> Vec<u8> {
        let b = s.as_bytes();
        assert_eq!(b.len() % 2, 0);
        let mut out = Vec::with_capacity(b.len() / 2);
        let mut i = 0;
        while i < b.len() {
            let hi = (b[i] as char).to_digit(16).unwrap() as u8;
            let lo = (b[i + 1] as char).to_digit(16).unwrap() as u8;
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }
}
