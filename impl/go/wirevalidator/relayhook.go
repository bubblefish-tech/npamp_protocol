// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package wirevalidator

import (
	"fmt"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
	"github.com/bubblefish-tech/npamp_protocol/impl/go/relay"
)

// RelayHook returns a relay.HookFunc backed by reg: E2.2's firewall seam
// (impl/go/relay.Relay.Hook) plugs this in directly to reject any relayed
// frame whose frame type is reserved (0x0000), whose channel is not a
// registered channel, whose frame type is not registered for that channel,
// or whose declared total size exceeds MaxFrameSize.
//
// relay.FrameHeader carries ONLY the cleartext header fields (Type,
// Channel, Seq, PayloadLen, Flags, the raw 36 header octets) -- the relay
// itself never opens an AEAD-sealed payload (impl/go/relay/doc.go, "Why
// this preserves end-to-end security") -- so the hook returned here can
// only run the checks that operate on header-derived fields: checkFrameType
// and the frame-size half of checkBounds. It CANNOT run ValidateTLVSequence
// or ValidateErrorCode, because those require decoded payload content the
// relay never has access to. This is an honest capability boundary, not an
// oversight: a caller that also wants TLV-tag or error-code enforcement
// must run those checks at a layer that DOES decrypt the payload (e.g. an
// SDK-level connection, not a non-decrypting relay).
//
// Returning a non-nil error from the hook rejects the frame; per
// relay.HookFunc's documented contract, Relay.Run then tears down BOTH legs
// of the flow rather than forwarding it or silently dropping only that
// frame (fail-closed, R12).
func (reg *Registries) RelayHook() relay.HookFunc {
	return func(dir relay.Direction, header relay.FrameHeader) error {
		if err := reg.checkFrameType(header.Channel, header.Type); err != nil {
			return fmt.Errorf("wirevalidator: %s: %w", dir, err)
		}
		total := npamp.HeaderSize + int(header.PayloadLen)
		if err := checkBounds(total, -1); err != nil {
			return fmt.Errorf("wirevalidator: %s: %w", dir, err)
		}
		return nil
	}
}
