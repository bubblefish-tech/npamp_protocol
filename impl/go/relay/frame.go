// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package relay

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// readRawFrame reads exactly one self-delimiting N-PAMP frame off r: the
// fixed 36-octet header (npamp.HeaderSize), then the payload whose length
// the header's Payload Length field (octets 17..20) declares. It returns the
// header || payload bytes VERBATIM, unmodified, so the caller can forward
// them without any re-encoding step.
//
// maxFrameSize bounds the total frame size (header + payload) BEFORE the
// payload is read, using an int64 comparison so a hostile high-bit length
// field cannot wrap negative and slip past the cap (mirrors
// impl/go/sdk/conn.go's readFrame and npamp.ReadFrame — the three
// implementations of this same boundary rule share one behavior: reject an
// oversized declared length before buffering it, R12).
//
// The header and the payload are each read with io.ReadFull, which gives
// readRawFrame the distinction the caller (Relay.forward) depends on: an
// error with ZERO bytes consumed for the piece being read (io.EOF) means the
// stream ended exactly at a frame boundary — a clean peer close, not a
// defect — while an error with SOME-but-not-all bytes consumed
// (io.ErrUnexpectedEOF) means the stream ended mid-frame — a truncation,
// which the caller tears the flow down for (R12). A peer that advertises a
// large payload length it never fully delivers cannot force a large
// up-front allocation beyond the already-enforced maxFrameSize bound: the
// short read simply resolves to io.ErrUnexpectedEOF once the stream ends.
//
// readRawFrame validates only the frame BOUNDARY (the magic prefix and the
// size cap); full header integrity — CRC32C, wire version, reserved
// octets/flags — is validated by the caller via npamp.Frame.UnmarshalBinary
// on the returned buffer, exactly as impl/go/sdk/conn.go documents for its
// own readFrame.
func readRawFrame(r io.Reader, maxFrameSize uint32) ([]byte, error) {
	header := make([]byte, npamp.HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err // io.EOF (clean boundary) / io.ErrUnexpectedEOF (mid-header) pass through unwrapped
	}
	if !bytes.Equal(header[:4], npamp.Magic[:]) {
		return nil, fmt.Errorf("npamp/relay: bad frame magic %#x, want NPAM", header[:4])
	}
	payloadLen := binary.BigEndian.Uint32(header[17:21])
	total := int64(npamp.HeaderSize) + int64(payloadLen)
	if total > int64(maxFrameSize) {
		return nil, fmt.Errorf("npamp/relay: frame size %d exceeds max %d", total, maxFrameSize)
	}
	buf := make([]byte, npamp.HeaderSize+int(payloadLen))
	copy(buf, header)
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, buf[npamp.HeaderSize:]); err != nil {
			if err == io.EOF {
				// The header arrived complete but not one payload octet
				// followed. The header already announced this frame, so the
				// stream still ended MID-FRAME, not at a clean boundary —
				// reclassify to ErrUnexpectedEOF so the caller never
				// confuses "peer vanished after announcing a frame" with
				// "peer closed cleanly between frames."
				err = io.ErrUnexpectedEOF
			}
			return nil, fmt.Errorf("npamp/relay: read frame payload (%d octets): %w", payloadLen, err)
		}
	}
	return buf, nil
}

// writeRawFrame writes raw — already-validated header||payload bytes exactly
// as returned by readRawFrame — to w unmodified. It never re-marshals or
// re-derives any field: the bytes that leave the relay are byte-identical to
// the bytes that entered it.
func writeRawFrame(w io.Writer, raw []byte) error {
	_, err := w.Write(raw)
	return err
}
