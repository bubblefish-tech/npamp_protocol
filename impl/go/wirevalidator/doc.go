// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package wirevalidator implements a registry-driven, fail-closed wire
// validator for N-PAMP frames (task E2.3, R3.3).
//
// # Why hand-written, not CDDL-driven
//
// schema/npamp-wire.cddl (RFC 8610) can express only lengths and permitted
// value/bit-sets for N-PAMP's byte-exact binary wire format -- it has no
// octet-concatenation, endianness, or bit-packing primitive (RFC 8610 §1
// Abstract; see the CDDL file's own "HONEST SCOPE CAVEAT"). As of this
// package's authoring (2026-08-27) no actively-maintained, production-ready
// Go CDDL runtime library exists: github.com/HannesKimara/cddlc is ~22
// months stale with an explicit "Do not use in production" README warning,
// and a pkg.go.dev search for "cddl" returns only that package, a
// single-repo hand-rolled tool (bsv8/go-bitfs/docs/cddltool), and an
// unrelated CBOR-certificate library (smolcert) -- no general Go CDDL
// engine. Adopting a stale/do-not-use library, or FFI/cgo into the Rust
// (anweiss/cddl) or Ruby (cddl gem) engines, would not shorten the real
// work anyway: even a working CDDL engine cannot check the byte-exact
// properties (big-endianness, the octet-4 Ver/Flags nibble split, CRC32C,
// reserved-nonzero rejection) this validator exists to check, because CDDL
// itself cannot express them.
//
// This package instead validates RAW WIRE BYTES directly against (a) the
// structural rules npamp.Frame.UnmarshalBinary already enforces (reused,
// never reimplemented) and (b) the code-point REGISTRIES under registries/
// (channels.csv, frame_types_reserved.csv, frame_types_channel.csv,
// tlv_tags.csv, error_codes.csv), loaded from disk at Load time -- never
// hand-copied as Go literals, so a registry edit is picked up without
// re-deriving anything here (F6 currency) and the expected values remain an
// INDEPENDENT authority from this validator's own logic (F3 non-circular).
//
// # Fail-closed allowlist posture (an intentional design choice)
//
// Every check in this package is a strict ALLOWLIST: a channel, frame type,
// or TLV tag must be explicitly present in the loaded registry data to be
// accepted; anything absent -- an unassigned code point, a companion-spec
// "(reserved)" placeholder not yet defined, a GREASE/extension channel, an
// out-of-range error code -- is REJECTED. This is deliberately STRICTER
// than the core SDK's own per-connection peer behavior, which implements
// RFC-style forward compatibility (e.g. npamp.CheckMustUnderstand ignores
// an unrecognized TLV whose high bit is clear, and unknown_channel is a
// discard-and-survive reaction, not a hard reject -- registries/error_codes.csv).
// A wire-level gate meant to plug into a relay/firewall seam (E2.2,
// impl/go/relay.HookFunc) is a different kind of component from a
// protocol peer: its job is default-deny, not maximal interoperability.
// This deliberate divergence from the SDK's lenient peer behavior is
// documented here, not hidden.
package wirevalidator
