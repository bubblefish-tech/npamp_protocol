// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// Direction identifies which leg of a Relay a frame is traveling FROM,
// toward the other: DirAToB means the frame arrived on Relay.A and is being
// forwarded to Relay.B, and DirBToA is the reverse. It carries no meaning
// beyond "which of the two flow endpoints this relay instance calls A/B" —
// unlike npamp.Direction (client-to-server / server-to-client, a property of
// the N-PAMP session itself), a relay's A/B labeling is purely local
// plumbing chosen by whoever constructed the Relay.
type Direction uint8

const (
	// DirAToB is a frame read from Relay.A and about to be written to Relay.B.
	DirAToB Direction = iota
	// DirBToA is a frame read from Relay.B and about to be written to Relay.A.
	DirBToA
)

// String renders the direction for log lines and error messages.
func (d Direction) String() string {
	switch d {
	case DirAToB:
		return "A->B"
	case DirBToA:
		return "B->A"
	default:
		return fmt.Sprintf("Direction(%d)", uint8(d))
	}
}

// FrameHeader is the CLEARTEXT routing metadata of one relayed frame — the
// parsed fields of the 36-octet fixed header (frame.go) — exposed to a
// HookFunc. It never carries payload bytes: a HookFunc can inspect frame
// type, channel, sequence number, flags, and declared length, but has no way
// to see (or accidentally leak) the AEAD-protected application payload the
// relay itself never decrypts.
type FrameHeader struct {
	// Raw holds the exact 36 header octets as they appeared on the wire
	// (Magic || Ver/Flags || Type || Channel || Seq || PayloadLen || CRC32C
	// || Reserved), for a hook that wants to re-validate or hash the header
	// itself rather than trust the parsed fields below.
	Raw [npamp.HeaderSize]byte

	Version    uint8
	Flags      uint8
	Type       uint16
	Channel    uint16
	Seq        uint64
	PayloadLen uint32
}

// HookFunc is the per-frame inspection seam a policy layer (E2.2, a
// frame-inspecting firewall) plugs into. It runs once per relayed frame,
// after the frame's header has been fully validated (CRC32C, wire version,
// reserved octets/flags all checked) but before the frame is written to the
// destination leg. Returning a non-nil error REJECTS the frame: Relay.Run
// tears the whole flow down (closes both legs) rather than forwarding it or
// silently dropping just that one frame, matching the fail-closed posture
// R12 requires for a malformed frame. A nil Hook on a Relay means "forward
// every well-formed frame" — this package's default, and this package's
// only policy.
type HookFunc func(dir Direction, header FrameHeader) error

// Relay owns exactly two connection legs (A and B) of ONE forwarded N-PAMP
// flow and copies self-delimiting frames between them, in both directions,
// without ever deriving an AEAD key or opening a payload. See doc.go for the
// full design rationale (why this preserves end-to-end security, the
// firewall seam, per-flow state ownership, and the fail-closed posture).
//
// A Relay value is single-flow and single-use: construct one per forwarded
// session and call Run once. It is not safe to reuse after Run returns, and
// A/B must not be shared with another Relay while this one is running.
type Relay struct {
	// A and B are the two connection legs this Relay forwards frames
	// between. Required.
	A, B net.Conn

	// Hook, if non-nil, is called once per relayed frame before it is
	// forwarded (see HookFunc). A nil Hook forwards every well-formed frame
	// unconditionally — the default, and this package's own policy.
	Hook HookFunc

	// MaxFrameSize bounds the total size (36-octet header + payload) this
	// Relay accepts on either leg. Zero means npamp.MaxFrameSize (16 MiB),
	// the same cap the base wire parser (frame.go) and the SDK (sdk/conn.go)
	// enforce, so a relay deployment never diverges from the rest of the
	// implementation on what "too large" means.
	MaxFrameSize uint32
}

// maxFrameSize returns r.MaxFrameSize, defaulting to npamp.MaxFrameSize when
// unset.
func (r *Relay) maxFrameSize() uint32 {
	if r.MaxFrameSize == 0 {
		return npamp.MaxFrameSize
	}
	return r.MaxFrameSize
}

// Run forwards frames bidirectionally between r.A and r.B until either
// direction's copy loop ends — a clean peer close (io.EOF at a frame
// boundary), a transport error, a malformed frame, an oversized declared
// length, a truncated stream, or the Hook rejecting a frame — and then
// closes BOTH legs so the flow tears down as a single unit (fail-closed,
// R12): whichever leg is still blocked in a read or write unblocks with a
// closed-connection error rather than hanging forever, and Run does not
// return until both forwarding goroutines have exited (no leaked
// goroutine).
//
// Run returns the error that ended the FIRST direction to stop. A clean
// peer-initiated close (io.EOF encountered exactly at a frame boundary) is
// not itself a defect and is reported as nil for that direction; a
// malformed frame, an oversized length, a truncated stream, a Hook
// rejection, or any other transport error is reported as a non-nil error
// describing which direction and what failed. ctx, if it carries a
// deadline, bounds every individual frame read/write on both legs (the same
// per-call-deadline pattern impl/go/sdk/conn.go uses); a canceled ctx with
// no deadline does not itself abort a blocked read — close A or B directly
// to force that.
func (r *Relay) Run(ctx context.Context) error {
	resA := make(chan error, 1)
	resB := make(chan error, 1)
	go func() { resA <- r.forward(ctx, r.A, r.B, DirAToB) }()
	go func() { resB <- r.forward(ctx, r.B, r.A, DirBToA) }()

	var first error
	select {
	case first = <-resA:
	case first = <-resB:
	}
	// One direction ended. Close BOTH legs immediately so the other
	// direction's blocked I/O unblocks instead of hanging on a half-dead
	// flow, then drain its result (always a consequence of the Close just
	// issued — a closed-connection I/O error, not new information) so Run
	// never returns while a forwarding goroutine is still running.
	_ = r.A.Close()
	_ = r.B.Close()
	select {
	case <-resA:
	case <-resB:
	}
	return first
}

// forward copies frames from src to dst until src yields a clean EOF at a
// frame boundary (returns nil: not a defect), a read/parse/write error
// occurs, or the Hook rejects a frame (both returned as a non-nil error
// naming dir). The caller (Run) is responsible for closing src/dst once
// forward returns; forward itself never closes either connection, so a
// single forward call can be tested in isolation against a src that still
// has more to give.
func (r *Relay) forward(ctx context.Context, src, dst net.Conn, dir Direction) error {
	maxSz := r.maxFrameSize()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("npamp/relay: %s: %w", dir, ctx.Err())
		default:
		}

		raw, err := readDeadlined(ctx, src, maxSz)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil // peer closed cleanly at a frame boundary; not a defect
			}
			return fmt.Errorf("npamp/relay: %s: read frame: %w", dir, err)
		}

		var f npamp.Frame
		if err := f.UnmarshalBinary(raw); err != nil {
			// Malformed frame (bad CRC32C, unsupported version, a nonzero
			// reserved octet or reserved flag bit): fail closed, tear the
			// flow down. Never forward bytes that failed validation.
			return fmt.Errorf("npamp/relay: %s: malformed frame: %w", dir, err)
		}

		if r.Hook != nil {
			var hdr FrameHeader
			copy(hdr.Raw[:], raw[:npamp.HeaderSize])
			hdr.Version = f.Version
			hdr.Flags = f.Flags
			hdr.Type = f.Type
			hdr.Channel = f.Channel
			hdr.Seq = f.Seq
			hdr.PayloadLen = uint32(len(f.Payload))
			if err := r.Hook(dir, hdr); err != nil {
				return fmt.Errorf("npamp/relay: %s: frame rejected: %w", dir, err)
			}
		}

		if err := writeDeadlined(ctx, dst, raw); err != nil {
			return fmt.Errorf("npamp/relay: %s: write frame: %w", dir, err)
		}
	}
}

// readDeadlined applies ctx's deadline (if any) to conn before reading one
// raw frame, mirroring impl/go/sdk/conn.go's per-call-deadline pattern so a
// Relay honors the same caller-supplied timeout discipline the SDK does.
//
// SetReadDeadline is always the FIRST operation attempted for a new frame —
// before any header byte has been read — so if it fails because conn is
// already closed, that failure is, by construction, positioned exactly at a
// frame boundary: no byte of a new frame was ever consumed. It is therefore
// reported as plain io.EOF (the same "clean boundary" signal readRawFrame
// itself would eventually produce), not wrapped as a distinct "set
// deadline" fault — so Relay.forward's single EOF check correctly treats an
// already-closed leg the same as one that closes normally mid-read.
// net.Pipe (used by this package's own tests and the SDK's) surfaces this
// as io.ErrClosedPipe, a real net.Conn as net.ErrClosed; both are
// recognized.
func readDeadlined(ctx context.Context, conn net.Conn, maxFrameSize uint32) ([]byte, error) {
	if dl, ok := ctx.Deadline(); ok {
		if err := conn.SetReadDeadline(dl); err != nil {
			if isClosedConnError(err) {
				return nil, io.EOF
			}
			return nil, fmt.Errorf("npamp/relay: set read deadline: %w", err)
		}
		defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	}
	return readRawFrame(conn, maxFrameSize)
}

// isClosedConnError reports whether err indicates the underlying connection
// is already closed, across the two sentinel forms this package's transports
// can surface: net.ErrClosed (a real net.Conn, e.g. *net.TCPConn — see the
// net package doc, "should normally be tested using errors.Is(err,
// net.ErrClosed)") and io.ErrClosedPipe (net.Pipe's pre-net.ErrClosed
// sentinel, which it still returns).
func isClosedConnError(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)
}

// writeDeadlined is readDeadlined's write-side counterpart.
func writeDeadlined(ctx context.Context, conn net.Conn, raw []byte) error {
	if dl, ok := ctx.Deadline(); ok {
		if err := conn.SetWriteDeadline(dl); err != nil {
			return fmt.Errorf("npamp/relay: set write deadline: %w", err)
		}
		defer func() { _ = conn.SetWriteDeadline(time.Time{}) }()
	}
	return writeRawFrame(conn, raw)
}
