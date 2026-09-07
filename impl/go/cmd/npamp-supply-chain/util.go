// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"strings"

	supplychain "github.com/bubblefish-tech/npamp_protocol/impl/go/ecosystem/npamp-supply-chain"
)

// bytesReader wraps a []byte as an io.Reader for supplychain.DecodeGoListModules, which
// takes an io.Reader (a streaming decoder over `go list -m -json all`'s concatenated-JSON
// output), not a []byte.
func bytesReader(b []byte) io.Reader {
	return bytes.NewReader(b)
}

// trimNewline strips a single trailing "\n" (and any preceding "\r") — the shape
// os.WriteFile(..., []byte(hex+"\n"), ...) produces in writeOutputs.
func trimNewline(s string) string {
	return strings.TrimRight(s, "\r\n")
}

// decodeEnvelopePayload base64-decodes a DSSE envelope's Payload field (StdEncoding, per
// dsse.go's SignStatement: base64.StdEncoding.EncodeToString(statementJSON)).
func decodeEnvelopePayload(env *supplychain.Envelope) ([]byte, error) {
	return base64.StdEncoding.DecodeString(env.Payload)
}
