// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package proxy

import (
	"encoding/binary"
	"fmt"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// gRPC carriage under NPAMP-CC-STREAM (spec/companion/23_carriage_streaming.md)
// -- the third carriage leg of E2.4/R10 (doc.go). See carriage_stream.go's
// package doc for why this build places gRPC under carriage class STREAM.

// grpcProtocolID is the protocol_id this build uses for gRPC generic
// carriage. NPAMP-REG (spec/companion/30_protocol_registry.md §6) originally
// assigned code points 0x01-0x04 only (MCP, A2A, HTTP/2, WebSocket); gRPC had
// no assigned code point, and this build used an EXPERIMENTAL value (§7.1)
// pending registration -- see decisions/adr/0015 for the derivation. gRPC
// generic carriage is now assigned 0x05 -- the next available code point in
// the standards-assigned range (registries/bridge_protocol_ids.csv,
// spec/companion/30_protocol_registry.md §6/§8), mirroring the existing 0x04
// WebSocket row's own "generic carriage" pattern. Once assigned, §7.1
// forbids using the experimental range for a protocol that has a registered
// code point ("a sender MUST NOT ... use an experimental protocol_id for a
// protocol that has an assigned code point in §6"), so this leg moved off
// 0x10.
const grpcProtocolID npamp.BridgeProtocol = 0x05

// errGRPCMalformed reports a gRPC Length-Prefixed-Message structural failure.
type errGRPCMalformed struct{ reason string }

func (e *errGRPCMalformed) Error() string {
	return fmt.Sprintf("npamp/proxy: gRPC Length-Prefixed-Message frame malformed: %s", e.reason)
}

// encodeGRPCLengthPrefixedMessage builds gRPC's own standard per-message wire
// framing -- a 1-octet compressed-flag then a 4-octet big-endian message
// length then the message itself -- the octet layout the `application/
// grpc+proto` content_type (already reserved by Part-1, bridge.go
// BridgeContentGRPCProto) commits this leg to producing. This is independent
// of the surrounding HTTP/2 DATA-frame transport a real grpc-go client/server
// uses, which this leg does not carry (doc.go per-leg scope note: N-PAMP's
// Bridge channel is the transport here, not HTTP/2); it reproduces exactly
// the per-message framing so the carried octets are what a real gRPC
// endpoint's own codec recognizes as one Length-Prefixed-Message unit.
func encodeGRPCLengthPrefixedMessage(compressed bool, msg []byte) []byte {
	out := make([]byte, 5+len(msg))
	if compressed {
		out[0] = 1
	}
	binary.BigEndian.PutUint32(out[1:5], uint32(len(msg)))
	copy(out[5:], msg)
	return out
}

// decodeGRPCLengthPrefixedMessage parses the frame encodeGRPCLengthPrefixedMessage
// produces and validates its declared length against the actual remaining
// octets.
func decodeGRPCLengthPrefixedMessage(buf []byte) (compressed bool, msg []byte, err error) {
	if len(buf) < 5 {
		return false, nil, &errGRPCMalformed{reason: fmt.Sprintf("%d octets, too short for the 5-octet LPM header", len(buf))}
	}
	flag := buf[0]
	if flag > 1 {
		return false, nil, &errGRPCMalformed{reason: fmt.Sprintf("compressed-flag octet 0x%02x is neither 0 nor 1", flag)}
	}
	ln := binary.BigEndian.Uint32(buf[1:5])
	if uint32(len(buf)-5) != ln {
		return false, nil, &errGRPCMalformed{reason: fmt.Sprintf("declared message length %d disagrees with %d remaining octets", ln, len(buf)-5)}
	}
	return flag == 1, buf[5:], nil
}
