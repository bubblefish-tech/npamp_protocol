// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! NPAMP-CC-STREAM (spec/companion/23_carriage_streaming.md) StreamControl TLV
//! codec — composed by every "STREAM" carriage class in the Go reference (SSE,
//! gRPC, WebSocket); this module ports the StreamControl TLV itself (§5.2/§5.3)
//! only, matching what `tests/carriage_shared_corpus_test.rs` grades. See the
//! `crate::carriage` module docs for the full scope boundary (no
//! BRIDGE_STREAM_DATA/END frame assembly, no event-id monotonicity tracker, no
//! producer/consumer loop — those are session/streaming-runtime concerns this
//! octet-exact carriage-object task does not build).

use crate::carriage::CarriageError;

/// NPAMP-CC-STREAM §5.3 StreamControl TLV Type. PROVISIONAL pending an
/// explicit core-specification reservation (§11), matching the Go reference's
/// own documented caveat: usable today, without a guarantee of interoperability
/// with an independently developed peer that has bound 0x0011 to a different
/// meaning.
pub const TLV_STREAM_CONTROL: u16 = 0x0011;

/// StreamControl `control` selector values (§5.2).
pub const STREAM_CONTROL_DATA: u8 = 0x00;
pub const STREAM_CONTROL_RESUME: u8 = 0x01;
pub const STREAM_CONTROL_CANCEL: u8 = 0x02;

/// StreamControl `flags` bits (§5.2).
pub const STREAM_FLAG_RESUMABLE: u8 = 0x01;
pub const STREAM_FLAG_CANCEL_ACK: u8 = 0x02;

/// The only StreamControl format version this document defines (§5.2); a
/// peer's TLV carrying any other version MUST be rejected.
const STREAM_CONTROL_VERSION: u8 = 0x01;

/// The decoded §5.2 StreamControl TLV value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamControl {
    pub control: u8,
    pub flags: u8,
    pub event_id: u64,
}

impl StreamControl {
    pub fn resumable(&self) -> bool {
        self.flags & STREAM_FLAG_RESUMABLE != 0
    }
    pub fn cancel_ack(&self) -> bool {
        self.flags & STREAM_FLAG_CANCEL_ACK != 0
    }
}

/// Encodes the fixed 11-octet §5.2 value: version(1) + control(1) + flags(1) +
/// event_id(8, big-endian).
pub fn encode_stream_control_value(sc: StreamControl) -> Vec<u8> {
    let mut v = vec![0u8; 11];
    v[0] = STREAM_CONTROL_VERSION;
    v[1] = sc.control;
    v[2] = sc.flags;
    v[3..11].copy_from_slice(&sc.event_id.to_be_bytes());
    v
}

/// Encodes a bare TLV header + value: Type (u16 BE) || Length (u16 BE) ||
/// Value — the core extension-TLV encoding this companion spec reuses (§5.3).
pub fn encode_tlv(typ: u16, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + value.len());
    out.extend_from_slice(&typ.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
    out
}

/// Parses a StreamControl TLV from the FRONT of `buf` and returns the decoded
/// control plus the remaining bytes (the real foreign event, carried verbatim,
/// NPAMP-BRIDGE §1). A bare TLV-header parse: exactly one TLV precedes opaque
/// event bytes that MUST NOT themselves be parsed as TLVs (§9: "MUST treat the
/// foreign event as opaque").
pub fn decode_leading_stream_control(buf: &[u8]) -> Result<(StreamControl, &[u8]), CarriageError> {
    if buf.len() < 4 {
        return Err(CarriageError(format!(
            "payload {} octets, too short for a TLV header",
            buf.len()
        )));
    }
    let typ = u16::from_be_bytes([buf[0], buf[1]]);
    let ln = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if typ != TLV_STREAM_CONTROL {
        return Err(CarriageError(format!(
            "first TLV type 0x{typ:04x} is not StreamControl (0x0011)"
        )));
    }
    if buf.len() < 4 + ln {
        return Err(CarriageError(
            "StreamControl TLV Length exceeds remaining payload".into(),
        ));
    }
    let v = &buf[4..4 + ln];
    if v.len() != 11 {
        return Err(CarriageError(format!(
            "StreamControl TLV Length {}, want 11 (§5.2)",
            v.len()
        )));
    }
    if v[0] != STREAM_CONTROL_VERSION {
        return Err(CarriageError(format!(
            "StreamControl version 0x{:02x} not implemented (this build implements 0x01)",
            v[0]
        )));
    }
    match v[1] {
        STREAM_CONTROL_DATA | STREAM_CONTROL_RESUME | STREAM_CONTROL_CANCEL => {}
        other => {
            return Err(CarriageError(format!(
                "undefined StreamControl control value 0x{other:02x}"
            )))
        }
    }
    let event_id = u64::from_be_bytes(v[3..11].try_into().expect("v is exactly 11 bytes"));
    let sc = StreamControl {
        control: v[1],
        flags: v[2],
        event_id,
    };
    Ok((sc, &buf[4 + ln..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_stream_control_value_layout() {
        let sc = StreamControl {
            control: STREAM_CONTROL_RESUME,
            flags: STREAM_FLAG_CANCEL_ACK,
            event_id: 0x0102_0304_0506_0708,
        };
        let v = encode_stream_control_value(sc);
        assert_eq!(
            v,
            vec![0x01, 0x01, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn encode_tlv_header_is_type_then_length_be() {
        let out = encode_tlv(0x1234, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(out, vec![0x12, 0x34, 0x00, 0x03, 0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn decode_rejects_wrong_tlv_type() {
        let mut buf = encode_tlv(0x0099, &encode_stream_control_value(StreamControl {
            control: STREAM_CONTROL_DATA,
            flags: 0,
            event_id: 1,
        }));
        buf.extend_from_slice(b"event");
        let err = decode_leading_stream_control(&buf).unwrap_err();
        assert!(err.0.contains("not StreamControl"), "{err}");
    }

    #[test]
    fn decode_rejects_short_buffer() {
        let err = decode_leading_stream_control(&[0x00, 0x11, 0x00]).unwrap_err();
        assert!(err.0.contains("too short"), "{err}");
    }

    #[test]
    fn decode_rejects_wrong_value_length() {
        // TLV header claims a 3-octet value (not 11).
        let buf = [0x00, 0x11, 0x00, 0x03, 0x01, 0x00, 0x00];
        let err = decode_leading_stream_control(&buf).unwrap_err();
        assert!(err.0.contains("want 11"), "{err}");
    }

    #[test]
    fn decode_rejects_unsupported_version() {
        let mut v = encode_stream_control_value(StreamControl {
            control: STREAM_CONTROL_DATA,
            flags: 0,
            event_id: 0,
        });
        v[0] = 0x02; // not the only defined version
        let buf = encode_tlv(TLV_STREAM_CONTROL, &v);
        let err = decode_leading_stream_control(&buf).unwrap_err();
        assert!(err.0.contains("not implemented"), "{err}");
    }

    #[test]
    fn decode_rejects_undefined_control_value() {
        let mut v = encode_stream_control_value(StreamControl {
            control: STREAM_CONTROL_DATA,
            flags: 0,
            event_id: 0,
        });
        v[1] = 0x7F; // not one of DATA/RESUME/CANCEL
        let buf = encode_tlv(TLV_STREAM_CONTROL, &v);
        let err = decode_leading_stream_control(&buf).unwrap_err();
        assert!(err.0.contains("undefined StreamControl control value"), "{err}");
    }

    #[test]
    fn resumable_and_cancel_ack_read_distinct_bits() {
        let both = StreamControl {
            control: STREAM_CONTROL_DATA,
            flags: STREAM_FLAG_RESUMABLE | STREAM_FLAG_CANCEL_ACK,
            event_id: 0,
        };
        assert!(both.resumable());
        assert!(both.cancel_ack());
        let neither = StreamControl {
            control: STREAM_CONTROL_DATA,
            flags: 0,
            event_id: 0,
        };
        assert!(!neither.resumable());
        assert!(!neither.cancel_ack());
    }
}
