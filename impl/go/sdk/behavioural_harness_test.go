// SPDX-License-Identifier: Apache-2.0

package sdk_test

// Go<->Go behavioural live-exchange harness (TRACK C2, START).
//
// WHY THIS EXISTS. The companion specs for the graded channels are graded on their
// *payload-decode* surface only: `stream.body.decode` / `interaction.body.decode` in the
// npamp conformance corpus cover the deterministic-CBOR encoding and the common-envelope
// MUST-reject clauses (spec/companion/80 §4, spec/companion/89 §4). Both specs state, in
// their own §10, that the remaining *behavioural* clauses — flow control, the sub-stream
// state machine, half-close, abrupt reset, and the approval-hold distinction — are "graded
// only by a live-exchange harness". This file is the first increment of that harness: it
// drives those clauses over a REAL loopback N-PAMP session (the exported sdk.Conn, a real
// 1.5-RTT post-quantum handshake, a real AEAD record layer) using the REFERENCE
// deterministic-CBOR codec (npamp.EncodeStreamBody / npamp.EncodeInteractionBody /
// npamp.DecodeInteractionBody / npamp.DecodeStreamEnvelope) to build and read the frame
// bodies actually placed on the wire.
//
// WHAT IS AND IS NOT GRADED HERE (honest status — do not overstate).
//   - GRADED end-to-end over the wire by this file:
//       * Stream §5.2/§6.2 per-sub-stream absolute-offset flow control: an in-window
//         STREAM_DATA is accepted; a STREAM_WINDOW_UPDATE raises the absolute limit and a
//         duplicate window update is proven idempotent; an over-window STREAM_DATA is
//         rejected with a real STREAM_RESET carrying error_code FlowControlError (2),
//         decoded off the wire by the peer.
//       * Stream §5.4/§7.3/§7.4 reset/close: a graceful half-close by `fin`+STREAM_CLOSE,
//         a clean STREAM_RESET cancellation (error_code NoError, 0), and the idempotence
//         of a second STREAM_RESET for an already-closed sub-stream (ignored, no reply).
//       * Interaction §6.3/§8.1 approval-hold distinction: an INTERACT_APPROVAL_REQ
//         answered — over the wire, decoded by the requester with the reference
//         npamp.DecodeInteractionBody — as four DISTINCT outcomes (granted result, denied
//         result, policy_denied error, approval_held error carrying approval_id), asserting
//         approval_held is never collapsed into granted / denied / policy_denied and that
//         approval_id is present on, and only on, the held outcome.
//   - NOT graded here (larger corpus, later C2 increments): sub-stream id parity by
//     handshake role across BOTH parities with concurrent opens; every §8 stream error
//     code; the full prompt-kind matrix (§6.2) and INTERACT_CANCEL race (§6.4); two-level
//     composition with the connection-level FLOW_UPDATE (§6.3); the §8.2 leak-prevention
//     surface. The emitted result names each covered clause explicitly.
//
// NON-CIRCULARITY. The stream behavioural clauses have no separate reference state-machine
// implementation in impl/go (the specs say so): the conformant receiver/enforcer that
// applies §6.2 lives in this harness. That is inherent to a live-exchange harness. To keep
// the check honest it is driven over the real SDK transport and the real reference CBOR
// codec, and the harness's own independent CBOR field reader (bhCBORMap) is grounded against
// the reference encoder by bhSelfCheckCodec before any live exchange runs. The interaction
// approval-hold distinction is stronger: the requester decodes the responder's reply with the
// reference decoder and asserts the semantic distinction the spec requires.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// ---------------------------------------------------------------------------
// Machine-readable behavioural_conformance result
// ---------------------------------------------------------------------------

// bhClause is one behavioural conformance clause result.
type bhClause struct {
	ID     string `json:"id"`     // stable slug, e.g. "stream.flow_control.overwindow_reject"
	Spec   string `json:"spec"`   // spec anchor, e.g. "80_stream_channel.md §5.2/§6.2"
	Desc   string `json:"desc"`   // one-line description of what was exercised
	Status string `json:"status"` // "PASS" | "FAIL"
	Detail string `json:"detail"` // observed evidence
}

// bhResult is the machine-readable behavioural_conformance emission for one run.
type bhResult struct {
	Kind         string     `json:"kind"`          // constant "behavioural_conformance"
	Harness      string     `json:"harness"`       // this file's identity
	Grading      string     `json:"grading"`       // grading method, honest
	Transport    string     `json:"transport"`     // how the exchange was carried
	Codec        string     `json:"codec"`         // codec used for bodies
	GeneratedUTC string     `json:"generated_utc"` // RFC3339 timestamp
	Passed       int        `json:"passed"`
	Failed       int        `json:"failed"`
	Clauses      []bhClause `json:"clauses"`
}

func (r *bhResult) add(id, spec, desc string, ok bool, detail string) {
	st := "FAIL"
	if ok {
		st = "PASS"
		r.Passed++
	} else {
		r.Failed++
	}
	r.Clauses = append(r.Clauses, bhClause{ID: id, Spec: spec, Desc: desc, Status: st, Detail: detail})
}

// emit writes the result to the test log with stable delimiters and, when the
// NPAMP_BEHAVIOURAL_OUT environment variable is set, to that file as JSON. It never writes a
// committed artifact by default, so the harness leaves no generated file in the tree unless a
// caller explicitly asks for one.
func (r *bhResult) emit(t *testing.T) {
	t.Helper()
	blob, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		t.Fatalf("marshal behavioural_conformance result: %v", err)
	}
	t.Logf("BEHAVIOURAL_CONFORMANCE_BEGIN\n%s\nBEHAVIOURAL_CONFORMANCE_END", blob)
	if out := os.Getenv("NPAMP_BEHAVIOURAL_OUT"); out != "" {
		if err := os.WriteFile(out, append(blob, '\n'), 0o600); err != nil {
			t.Fatalf("write NPAMP_BEHAVIOURAL_OUT=%q: %v", out, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Independent CBOR field reader (non-circular observation of the wire)
// ---------------------------------------------------------------------------

// bhCBORMap decodes a definite-length deterministic-CBOR map (RFC 8949 §3, §4.2) into a
// map[uint64]any. It supports exactly the value shapes NPAMP-STREAM / NPAMP-INTERACT bodies
// use: unsigned integers (major 0), byte strings (major 2), and text strings (major 3), with
// unsigned-int map keys. It is deliberately independent of the reference encoder so that
// reading a reference-encoded body here is a genuine cross-decode, not a self-check. It is
// used only to observe the numeric flow-control fields of Stream frames (offset, data length,
// max_data, error_code) that the exported reference surface does not project as typed fields;
// envelope and interaction bodies are read with the reference decoder instead.
func bhCBORMap(b []byte) (map[uint64]any, error) {
	p := &bhCborReader{buf: b}
	maj, n, err := p.head()
	if err != nil {
		return nil, err
	}
	if maj != 5 {
		return nil, fmt.Errorf("bhCBORMap: top item is major %d, want map(5)", maj)
	}
	out := make(map[uint64]any, n)
	for i := uint64(0); i < n; i++ {
		kMaj, key, err := p.head()
		if err != nil {
			return nil, err
		}
		if kMaj != 0 {
			return nil, fmt.Errorf("bhCBORMap: map key major %d, want uint(0)", kMaj)
		}
		vMaj, arg, err := p.head()
		if err != nil {
			return nil, err
		}
		switch vMaj {
		case 0: // unsigned int
			out[key] = arg
		case 2: // byte string
			s, err := p.take(arg)
			if err != nil {
				return nil, err
			}
			out[key] = append([]byte(nil), s...)
		case 3: // text string
			s, err := p.take(arg)
			if err != nil {
				return nil, err
			}
			out[key] = string(s)
		default:
			return nil, fmt.Errorf("bhCBORMap: unsupported value major %d at key %d", vMaj, key)
		}
	}
	if len(p.buf) != 0 {
		return nil, fmt.Errorf("bhCBORMap: %d trailing octets after map", len(p.buf))
	}
	return out, nil
}

type bhCborReader struct{ buf []byte }

// head reads one CBOR head, returning the major type and the decoded argument (the length for
// strings, the value for unsigned ints, the entry count for maps). Only the additional-info
// forms 0..23 inline and 24/25/26/27 (1/2/4/8-byte) are supported — the deterministic
// encoding this codec emits uses the shortest such form.
func (r *bhCborReader) head() (major byte, arg uint64, err error) {
	if len(r.buf) == 0 {
		return 0, 0, errors.New("bhCBOR: unexpected end of input")
	}
	ib := r.buf[0]
	r.buf = r.buf[1:]
	major = ib >> 5
	ai := ib & 0x1f
	switch {
	case ai < 24:
		return major, uint64(ai), nil
	case ai == 24:
		v, err := r.uintN(1)
		return major, v, err
	case ai == 25:
		v, err := r.uintN(2)
		return major, v, err
	case ai == 26:
		v, err := r.uintN(4)
		return major, v, err
	case ai == 27:
		v, err := r.uintN(8)
		return major, v, err
	default:
		return 0, 0, fmt.Errorf("bhCBOR: unsupported additional info %d", ai)
	}
}

func (r *bhCborReader) uintN(n int) (uint64, error) {
	if len(r.buf) < n {
		return 0, errors.New("bhCBOR: truncated integer argument")
	}
	var v uint64
	for i := 0; i < n; i++ {
		v = v<<8 | uint64(r.buf[i])
	}
	r.buf = r.buf[n:]
	return v, nil
}

func (r *bhCborReader) take(n uint64) ([]byte, error) {
	if uint64(len(r.buf)) < n {
		return nil, errors.New("bhCBOR: truncated string payload")
	}
	s := r.buf[:n]
	r.buf = r.buf[n:]
	return s, nil
}

// bhCborUint fetches an unsigned-int field decoded by bhCBORMap.
func bhCborUint(m map[uint64]any, key uint64) (uint64, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	u, ok := v.(uint64)
	return u, ok
}

// bhCborBytes fetches a byte-string field decoded by bhCBORMap.
func bhCborBytes(m map[uint64]any, key uint64) ([]byte, bool) {
	v, ok := m[key]
	if !ok {
		return nil, false
	}
	b, ok := v.([]byte)
	return b, ok
}

// bhSelfCheckCodec grounds the independent reader against the reference encoder: it encodes a
// map with the reference npamp.EncodeStreamBody, reads it back with bhCBORMap, and confirms the
// values round-trip. It also confirms the reference envelope decoder agrees on frame_kind and
// sub_stream_id, so both decode paths are exercised on identical bytes. A failure here is a
// harness-reader bug and must abort before any behavioural claim is made.
func bhSelfCheckCodec(t *testing.T) {
	t.Helper()
	body := npamp.EncodeStreamBody(map[uint64]any{
		0: uint64(npamp.FrameStreamData), // frame_kind
		1: uint64(0),                     // sub_stream_id
		2: uint64(7),                     // offset
		3: []byte("abcd"),                // data
		4: uint64(1),                     // flags (fin)
	})
	m, err := bhCBORMap(body)
	if err != nil {
		t.Fatalf("bhSelfCheckCodec: independent reader rejected reference-encoded body: %v", err)
	}
	if u, ok := bhCborUint(m, 2); !ok || u != 7 {
		t.Fatalf("bhSelfCheckCodec: offset round-trip got (%d,%v), want 7", u, ok)
	}
	if b, ok := bhCborBytes(m, 3); !ok || !bytes.Equal(b, []byte("abcd")) {
		t.Fatalf("bhSelfCheckCodec: data round-trip got (%q,%v), want abcd", b, ok)
	}
	fk, ssid, err := npamp.DecodeStreamEnvelope(npamp.FrameStreamData, body)
	if err != nil {
		t.Fatalf("bhSelfCheckCodec: reference envelope decode failed: %v", err)
	}
	if fk != uint64(npamp.FrameStreamData) || ssid != 0 {
		t.Fatalf("bhSelfCheckCodec: reference envelope got frame_kind=%#x ssid=%d", fk, ssid)
	}
}

// ---------------------------------------------------------------------------
// Wire helpers over the real loopback session
// ---------------------------------------------------------------------------

// bhFrame is one channel/type/body triple to place on the wire.
type bhFrame struct {
	ch   npamp.ChannelID
	ft   npamp.FrameType
	body []byte
}

// bhInbound is one frame observed by a receive pump.
type bhInbound struct {
	ch  npamp.ChannelID
	ft  npamp.FrameType
	pt  []byte
	err error
}

// bhStreamBody builds a Stream frame body with the common envelope (frame_kind, sub_stream_id)
// plus the given body fields, encoded by the reference deterministic-CBOR encoder.
func bhStreamBody(ft npamp.FrameType, ssid uint64, fields map[uint64]any) []byte {
	m := map[uint64]any{0: uint64(ft), 1: ssid}
	for k, v := range fields {
		m[k] = v
	}
	return npamp.EncodeStreamBody(m)
}

// bhInteractBody builds an Interaction frame body with the common envelope (frame_kind, corr)
// plus the given body fields, encoded by the reference deterministic-CBOR encoder.
func bhInteractBody(ft npamp.FrameType, corr []byte, fields map[uint64]any) []byte {
	m := map[uint64]any{0: uint64(ft), 1: corr}
	for k, v := range fields {
		m[k] = v
	}
	return npamp.EncodeInteractionBody(m)
}

// ---------------------------------------------------------------------------
// Server-side conformant reactor (stream enforcer + interaction responder)
// ---------------------------------------------------------------------------

// bhObs is one server-side behavioural observation, drained by the driver after a barrier.
type bhObs struct {
	tag    string
	ok     bool
	detail string
}

// bhReactor is the conformant server-side peer: it enforces per-sub-stream absolute-offset
// flow control (§6.2) and the reset/close state machine (§7) for the Stream channel, and
// answers INTERACT_APPROVAL_REQ per a deterministic policy (§6.3/§8.1) on the Interaction
// channel. It reacts to inbound frames by returning frames to send and by pushing behavioural
// observations; the single server-side pump goroutine performs the actual sends.
type bhReactor struct {
	granted     map[uint64]uint64 // per-sub-stream absolute credit for the inbound (peer->server) direction
	grantedOnce map[uint64]bool   // whether a one-shot window raise has been issued for a sub-stream
	highest     map[uint64]uint64 // highest inbound offset+len accepted per sub-stream
	finSeen     map[uint64]bool   // whether inbound fin was observed per sub-stream
	closed      map[uint64]bool   // whether a sub-stream is closed (reset or graceful)

	// obs is written by the server pump goroutine and read by the driver goroutine after the
	// end-of-run barrier; obsMu provides the memory-synchronization edge the barrier's ordering
	// relies on (socket I/O is not a Go happens-before primitive). The maps above are touched
	// only by the single server pump goroutine and need no lock.
	obsMu sync.Mutex
	obs   []bhObs
}

func newBHReactor() *bhReactor {
	return &bhReactor{
		granted:     map[uint64]uint64{},
		grantedOnce: map[uint64]bool{},
		highest:     map[uint64]uint64{},
		finSeen:     map[uint64]bool{},
		closed:      map[uint64]bool{},
	}
}

func (r *bhReactor) note(tag string, ok bool, detail string) {
	r.obsMu.Lock()
	r.obs = append(r.obs, bhObs{tag: tag, ok: ok, detail: detail})
	r.obsMu.Unlock()
}

// snapshotObs returns a copy of the observations recorded so far, under the lock.
func (r *bhReactor) snapshotObs() []bhObs {
	r.obsMu.Lock()
	defer r.obsMu.Unlock()
	return append([]bhObs(nil), r.obs...)
}

// initialWindowFor picks the server's receive credit for a newly-opened sub-stream. ss==0 is
// deliberately tight (8) to force the flow-control path; other sub-streams get ample credit so
// the reset/close scenarios are not perturbed by flow control.
func (r *bhReactor) initialWindowFor(ssid uint64) uint64 {
	if ssid == 0 {
		return 8
	}
	return 64
}

// onStream applies one inbound Stream frame and returns the frames to send in reply.
func (r *bhReactor) onStream(ft npamp.FrameType, body []byte) []bhFrame {
	// Envelope via the reference decoder (exercises the graded decode surface too).
	_, ssid, err := npamp.DecodeStreamEnvelope(ft, body)
	if err != nil {
		r.note("stream.envelope.reject", true, err.Error())
		return nil
	}
	m, err := bhCBORMap(body)
	if err != nil {
		r.note("stream.body.readfail", false, err.Error())
		return nil
	}

	switch ft {
	case npamp.FrameStreamOpen:
		if r.closed[ssid] {
			return nil
		}
		win := r.initialWindowFor(ssid)
		r.granted[ssid] = win
		reply := bhStreamBody(npamp.FrameStreamOpen, ssid, map[uint64]any{
			2: win,       // init_window: server's receive credit governing peer->server
			3: uint64(0), // content_type: opaque
		})
		return []bhFrame{{npamp.ChanStream, npamp.FrameStreamOpen, reply}}

	case npamp.FrameStreamData:
		if r.closed[ssid] {
			// Data after close is an illegal transition; a real peer would STREAM_RESET
			// StreamStateError. Not part of the graded set here — record and drop.
			r.note("stream.data.after_close", true, "dropped")
			return nil
		}
		if r.finSeen[ssid] {
			reset := bhStreamBody(npamp.FrameStreamReset, ssid, map[uint64]any{
				2: uint64(3),       // StreamStateError
				3: r.highest[ssid], // final_offset
			})
			r.closed[ssid] = true
			r.note("stream.state.data_after_fin_reset", true, "StreamStateError")
			return []bhFrame{{npamp.ChanStream, npamp.FrameStreamReset, reset}}
		}
		offset, _ := bhCborUint(m, 2)
		data, _ := bhCborBytes(m, 3)
		flags, _ := bhCborUint(m, 4)
		reach := offset + uint64(len(data))
		credit := r.granted[ssid]
		if reach > credit {
			// §5.2/§6.2 violation: reject with STREAM_RESET(FlowControlError). Never buffer
			// past the limit (§9).
			reset := bhStreamBody(npamp.FrameStreamReset, ssid, map[uint64]any{
				2: uint64(2),       // FlowControlError
				3: r.highest[ssid], // final_offset delivered before teardown
			})
			r.closed[ssid] = true
			r.note("stream.fc.reject.overwindow", true,
				fmt.Sprintf("ss=%d reach=%d credit=%d -> FlowControlError", ssid, reach, credit))
			return []bhFrame{{npamp.ChanStream, npamp.FrameStreamReset, reset}}
		}
		// Accepted within credit.
		if reach > r.highest[ssid] {
			r.highest[ssid] = reach
		}
		if flags&0x01 != 0 {
			r.finSeen[ssid] = true
		}
		var out []bhFrame
		if ssid == 0 && !r.grantedOnce[ssid] && reach == credit {
			// One-shot credit extension proving STREAM_WINDOW_UPDATE raises the absolute
			// limit, followed by a duplicate proving idempotence (§5.5/§6.2).
			newMax := credit + 8
			r.granted[ssid] = newMax
			r.grantedOnce[ssid] = true
			wu := bhStreamBody(npamp.FrameStreamWindowUpdate, ssid, map[uint64]any{2: newMax})
			dup := bhStreamBody(npamp.FrameStreamWindowUpdate, ssid, map[uint64]any{2: newMax})
			out = append(out,
				bhFrame{npamp.ChanStream, npamp.FrameStreamWindowUpdate, wu},
				bhFrame{npamp.ChanStream, npamp.FrameStreamWindowUpdate, dup})
			r.note("stream.fc.accept.inwindow", true,
				fmt.Sprintf("ss=%d reach=%d<=credit=%d; granted->%d(+dup)", ssid, reach, credit, newMax))
		} else {
			r.note("stream.fc.accept.aftergrant", true,
				fmt.Sprintf("ss=%d reach=%d<=credit=%d", ssid, reach, credit))
		}
		return out

	case npamp.FrameStreamClose:
		final, _ := bhCborUint(m, 2)
		// §5.3: STREAM_CLOSE final_offset must be consistent with an observed fin / highest.
		consistent := final == r.highest[ssid]
		r.note("stream.close.halfclose", consistent,
			fmt.Sprintf("ss=%d final_offset=%d highest=%d fin=%v", ssid, final, r.highest[ssid], r.finSeen[ssid]))
		return nil

	case npamp.FrameStreamReset:
		// §5.4/§7.3: a STREAM_RESET for an unknown or already-closed sub-stream MUST be
		// ignored (idempotent) and MUST NOT provoke another STREAM_RESET.
		if r.closed[ssid] {
			r.note("stream.reset.idempotent", true,
				fmt.Sprintf("ss=%d second reset ignored (already closed)", ssid))
			return nil
		}
		code, _ := bhCborUint(m, 2)
		r.closed[ssid] = true
		r.note("stream.reset.cancel", true,
			fmt.Sprintf("ss=%d error_code=%d -> closed", ssid, code))
		return nil

	default:
		return nil
	}
}

// onInteract applies one inbound Interaction frame and returns the reply frame(s). It decodes
// with the reference decoder and answers an INTERACT_APPROVAL_REQ per a deterministic policy
// keyed on the `action` text, so the requester observes the four distinct §8.1 outcomes; it
// also answers the end-of-run barrier INTERACT_EVENT(ack) with an INTERACT_EVENT_ACK.
func (r *bhReactor) onInteract(ft npamp.FrameType, body []byte) []bhFrame {
	fields, err := npamp.DecodeInteractionBody(ft, body)
	if err != nil {
		return nil
	}
	corrAny, ok := fields[1]
	if !ok {
		return nil
	}
	corr, ok := corrAny.([]byte)
	if !ok {
		return nil
	}

	switch ft {
	case npamp.FrameInteractApprovalReq:
		action, _ := fields[2].(string)
		switch action {
		case "grant-me":
			reply := bhInteractBody(npamp.FrameInteractApprovalResult, corr, map[uint64]any{
				2: uint64(npamp.ApprovalGranted), // decision granted
			})
			return []bhFrame{{npamp.ChanInteraction, npamp.FrameInteractApprovalResult, reply}}
		case "deny-me":
			reply := bhInteractBody(npamp.FrameInteractApprovalResult, corr, map[uint64]any{
				2: uint64(npamp.ApprovalDenied), // decision denied (a completed human refusal)
				3: "not this time",
			})
			return []bhFrame{{npamp.ChanInteraction, npamp.FrameInteractApprovalResult, reply}}
		case "policy-block":
			reply := bhInteractBody(npamp.FrameInteractError, corr, map[uint64]any{
				2: uint64(npamp.IntErrPolicyDenied), // policy_denied (automated, never shown to a human)
				3: "policy denied",
			})
			return []bhFrame{{npamp.ChanInteraction, npamp.FrameInteractError, reply}}
		case "hold-me":
			reply := bhInteractBody(npamp.FrameInteractError, corr, map[uint64]any{
				2: uint64(npamp.IntErrApprovalHeld), // approval_held: escalated, NOT obtained
				3: "awaiting human approval",
				5: "hold-8f3a2c", // approval_id, present iff approval_held (§8)
			})
			return []bhFrame{{npamp.ChanInteraction, npamp.FrameInteractError, reply}}
		default:
			reply := bhInteractBody(npamp.FrameInteractError, corr, map[uint64]any{
				2: uint64(npamp.IntErrUnknownOperation),
				3: "unknown action",
			})
			return []bhFrame{{npamp.ChanInteraction, npamp.FrameInteractError, reply}}
		}

	case npamp.FrameInteractEvent:
		// Barrier: reply with an ACK only when the `ack` flag (key 5) is set (§6.1).
		if ack, _ := fields[5].(bool); ack {
			reply := bhInteractBody(npamp.FrameInteractEventAck, corr, nil)
			return []bhFrame{{npamp.ChanInteraction, npamp.FrameInteractEventAck, reply}}
		}
		return nil

	default:
		return nil
	}
}

// ---------------------------------------------------------------------------
// Interaction outcome classification (the §8.1 distinctness surface)
// ---------------------------------------------------------------------------

// bhOutcome is the requester's classification of a reply to an INTERACT_APPROVAL_REQ. The
// point of §8.1 is that these are DISTINCT: a held approval is never a granted/denied result
// nor a policy_denied error.
type bhOutcome struct {
	verdict    string // "GRANTED" | "DENIED" | "POLICY_DENIED" | "HELD" | "OTHER"
	approvalID string // non-empty only for HELD
}

// bhClassify decodes an interaction reply with the reference decoder and classifies it.
func bhClassify(ft npamp.FrameType, body []byte) (bhOutcome, error) {
	fields, err := npamp.DecodeInteractionBody(ft, body)
	if err != nil {
		return bhOutcome{}, err
	}
	switch ft {
	case npamp.FrameInteractApprovalResult:
		dec, _ := fields[2].(uint64)
		switch npamp.ApprovalDecision(dec) {
		case npamp.ApprovalGranted:
			return bhOutcome{verdict: "GRANTED"}, nil
		case npamp.ApprovalDenied:
			return bhOutcome{verdict: "DENIED"}, nil
		default:
			return bhOutcome{verdict: "OTHER"}, nil
		}
	case npamp.FrameInteractError:
		code, _ := fields[2].(uint64)
		switch npamp.InteractionErrorCode(code) {
		case npamp.IntErrPolicyDenied:
			return bhOutcome{verdict: "POLICY_DENIED"}, nil
		case npamp.IntErrApprovalHeld:
			id, _ := fields[5].(string)
			return bhOutcome{verdict: "HELD", approvalID: id}, nil
		default:
			return bhOutcome{verdict: "OTHER"}, nil
		}
	default:
		return bhOutcome{verdict: "OTHER"}, nil
	}
}

// ---------------------------------------------------------------------------
// The live-exchange test
// ---------------------------------------------------------------------------

// TestBehaviouralConformanceLiveExchange drives the stream flow-control, reset/close, and
// interaction approval-hold behavioural clauses over a real loopback N-PAMP session and emits
// a machine-readable behavioural_conformance result. dialPair and loopbackTLS are the shared
// loopback helpers (ratchet_e2e_test.go / sdk_test.go); this test defines only bh-prefixed
// symbols so it never collides with other tests in the package.
func TestBehaviouralConformanceLiveExchange(t *testing.T) {
	bhSelfCheckCodec(t)

	res := &bhResult{
		Kind:         "behavioural_conformance",
		Harness:      "impl/go/sdk/behavioural_harness_test.go",
		Grading:      "live-exchange harness (harness-resident conformant enforcer over the real SDK transport and reference CBOR codec); interaction approval-hold distinction decoded by the reference decoder",
		Transport:    "real loopback sdk.Conn (1.5-RTT PQ handshake + AEAD record layer, dialPair)",
		Codec:        "reference npamp.EncodeStreamBody/EncodeInteractionBody + npamp.DecodeInteractionBody/DecodeStreamEnvelope; independent bhCBORMap reader for stream numeric fields",
		GeneratedUTC: time.Now().UTC().Format(time.RFC3339),
	}
	defer res.emit(t)

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	client, server := dialPair(t, ctx)
	defer client.Close()
	defer server.Close()

	reactor := newBHReactor()

	// Client receive pump: routes inbound frames by channel to typed buffers.
	cStreamIn := make(chan bhInbound, 64)
	cInteractIn := make(chan bhInbound, 64)
	go func() {
		for {
			ch, ft, pt, err := client.Recv(ctx)
			if err != nil {
				in := bhInbound{err: err}
				select {
				case cStreamIn <- in:
				default:
				}
				select {
				case cInteractIn <- in:
				default:
				}
				return
			}
			in := bhInbound{ch: ch, ft: ft, pt: pt}
			switch ch {
			case npamp.ChanStream:
				cStreamIn <- in
			case npamp.ChanInteraction:
				cInteractIn <- in
			}
		}
	}()

	// Server receive pump: the conformant reactor. It is the ONLY server-side sender, so its
	// reactive sends never race an application send.
	serverErr := make(chan error, 1)
	go func() {
		for {
			ch, ft, pt, err := server.Recv(ctx)
			if err != nil {
				serverErr <- err
				return
			}
			var replies []bhFrame
			switch ch {
			case npamp.ChanStream:
				replies = reactor.onStream(ft, pt)
			case npamp.ChanInteraction:
				replies = reactor.onInteract(ft, pt)
			}
			for _, f := range replies {
				if err := server.Send(ctx, f.ch, f.ft, f.body); err != nil {
					serverErr <- err
					return
				}
			}
		}
	}()

	// awaitStream reads the client's stream inbox until pred matches, discarding non-matching
	// frames (extra window updates, etc.). It fails the test on timeout or pump error.
	awaitStream := func(what string, pred func(bhInbound) bool) bhInbound {
		t.Helper()
		deadline := time.After(15 * time.Second)
		for {
			select {
			case in := <-cStreamIn:
				if in.err != nil {
					t.Fatalf("await %s: client stream pump error: %v", what, in.err)
				}
				if pred(in) {
					return in
				}
			case <-deadline:
				t.Fatalf("await %s: timed out", what)
			}
		}
	}

	send := func(f bhFrame) {
		t.Helper()
		if err := client.Send(ctx, f.ch, f.ft, f.body); err != nil {
			t.Fatalf("client send ch=%#x ft=%#x: %v", uint16(f.ch), uint16(f.ft), err)
		}
	}

	// ---------------- Scenario 1: stream flow control (sub-stream 0) ----------------
	// 1a. Open sub-stream 0 (client is the handshake initiator -> even parity id 0).
	send(bhFrame{npamp.ChanStream, npamp.FrameStreamOpen,
		bhStreamBody(npamp.FrameStreamOpen, 0, map[uint64]any{2: uint64(64), 3: uint64(0)})})
	openReply := awaitStream("STREAM_OPEN reply", func(in bhInbound) bool {
		return in.ft == npamp.FrameStreamOpen
	})
	openM, err := bhCBORMap(openReply.pt)
	if err != nil {
		t.Fatalf("decode server STREAM_OPEN reply: %v", err)
	}
	serverWindow, _ := bhCborUint(openM, 2)
	res.add("stream.open.reply", "80_stream_channel.md §7.1",
		"bidirectional STREAM_OPEN/STREAM_OPEN handshake establishes the sub-stream",
		serverWindow == 8, fmt.Sprintf("server init_window=%d", serverWindow))

	// 1b. In-window STREAM_DATA: 8 octets at offset 0 reaches 8 == credit 8 (not exceeding).
	send(bhFrame{npamp.ChanStream, npamp.FrameStreamData,
		bhStreamBody(npamp.FrameStreamData, 0, map[uint64]any{2: uint64(0), 3: []byte("01234567")})})
	// The reactor grants a window raise to 16 and a duplicate; await the raise and prove the
	// duplicate is idempotent (max_data does not increase past 16).
	var maxData, updates uint64
	awaitStream("STREAM_WINDOW_UPDATE(16)", func(in bhInbound) bool {
		if in.ft != npamp.FrameStreamWindowUpdate {
			return false
		}
		wm, e := bhCBORMap(in.pt)
		if e != nil {
			t.Fatalf("decode STREAM_WINDOW_UPDATE: %v", e)
		}
		md, _ := bhCborUint(wm, 2)
		updates++
		if md > maxData {
			maxData = md
		}
		return md >= 16
	})
	// Drain a possible duplicate window update already queued and confirm it does not raise the
	// absolute limit past 16 (idempotence).
	drainDeadline := time.After(750 * time.Millisecond)
	dupIdempotent := true
draindup:
	for {
		select {
		case in := <-cStreamIn:
			if in.err != nil {
				t.Fatalf("drain duplicate window update: pump error: %v", in.err)
			}
			if in.ft == npamp.FrameStreamWindowUpdate {
				wm, e := bhCBORMap(in.pt)
				if e != nil {
					t.Fatalf("decode duplicate STREAM_WINDOW_UPDATE: %v", e)
				}
				md, _ := bhCborUint(wm, 2)
				updates++
				if md > maxData {
					dupIdempotent = false // a duplicate must not raise the limit
					maxData = md
				}
			}
		case <-drainDeadline:
			break draindup
		}
	}
	res.add("stream.flow_control.window_raise", "80_stream_channel.md §5.5/§6.2",
		"STREAM_WINDOW_UPDATE raises the absolute per-sub-stream limit", maxData == 16,
		fmt.Sprintf("granted absolute max_data=%d", maxData))
	res.add("stream.flow_control.duplicate_idempotent", "80_stream_channel.md §5.5/§6.2",
		"a duplicate STREAM_WINDOW_UPDATE grants no new credit (absolute-offset idempotence)",
		dupIdempotent && updates >= 2,
		fmt.Sprintf("observed %d window updates; absolute limit stayed %d", updates, maxData))

	// 1c. Second in-window STREAM_DATA: 8 octets at offset 8 reaches 16 == raised credit 16.
	send(bhFrame{npamp.ChanStream, npamp.FrameStreamData,
		bhStreamBody(npamp.FrameStreamData, 0, map[uint64]any{2: uint64(8), 3: []byte("89abcdef")})})

	// 1d. Over-window STREAM_DATA: 1 octet at offset 16 reaches 17 > 16 -> FlowControlError.
	send(bhFrame{npamp.ChanStream, npamp.FrameStreamData,
		bhStreamBody(npamp.FrameStreamData, 0, map[uint64]any{2: uint64(16), 3: []byte("!")})})
	resetIn := awaitStream("STREAM_RESET(FlowControlError)", func(in bhInbound) bool {
		return in.ft == npamp.FrameStreamReset
	})
	rk, rssid, err := npamp.DecodeStreamEnvelope(npamp.FrameStreamReset, resetIn.pt)
	if err != nil {
		t.Fatalf("decode STREAM_RESET envelope: %v", err)
	}
	rm, err := bhCBORMap(resetIn.pt)
	if err != nil {
		t.Fatalf("decode STREAM_RESET body: %v", err)
	}
	resetCode, _ := bhCborUint(rm, 2)
	fcOK := rk == uint64(npamp.FrameStreamReset) && rssid == 0 && resetCode == 2
	res.add("stream.flow_control.overwindow_reject", "80_stream_channel.md §5.2/§6.2/§8",
		"an over-window STREAM_DATA is rejected with STREAM_RESET FlowControlError(2)",
		fcOK, fmt.Sprintf("reset ss=%d error_code=%d (want ss=0 code=2)", rssid, resetCode))

	// ---------------- Scenario 2: graceful half-close (sub-stream 2) ----------------
	send(bhFrame{npamp.ChanStream, npamp.FrameStreamOpen,
		bhStreamBody(npamp.FrameStreamOpen, 2, map[uint64]any{2: uint64(64), 3: uint64(0)})})
	awaitStream("STREAM_OPEN reply ss=2", func(in bhInbound) bool {
		if in.ft != npamp.FrameStreamOpen {
			return false
		}
		_, ss, _ := npamp.DecodeStreamEnvelope(npamp.FrameStreamOpen, in.pt)
		return ss == 2
	})
	// Final STREAM_DATA with fin (4 octets), then a confirming STREAM_CLOSE(final_offset=4).
	send(bhFrame{npamp.ChanStream, npamp.FrameStreamData,
		bhStreamBody(npamp.FrameStreamData, 2, map[uint64]any{2: uint64(0), 3: []byte("done"), 4: uint64(1)})})
	send(bhFrame{npamp.ChanStream, npamp.FrameStreamClose,
		bhStreamBody(npamp.FrameStreamClose, 2, map[uint64]any{2: uint64(4)})})

	// ---------------- Scenario 3: clean reset + idempotence (sub-stream 4) ----------------
	send(bhFrame{npamp.ChanStream, npamp.FrameStreamOpen,
		bhStreamBody(npamp.FrameStreamOpen, 4, map[uint64]any{2: uint64(64), 3: uint64(0)})})
	awaitStream("STREAM_OPEN reply ss=4", func(in bhInbound) bool {
		if in.ft != npamp.FrameStreamOpen {
			return false
		}
		_, ss, _ := npamp.DecodeStreamEnvelope(npamp.FrameStreamOpen, in.pt)
		return ss == 4
	})
	// Clean cancellation (NoError, 0), then a second reset that must be ignored (idempotent).
	send(bhFrame{npamp.ChanStream, npamp.FrameStreamReset,
		bhStreamBody(npamp.FrameStreamReset, 4, map[uint64]any{2: uint64(0), 3: uint64(0)})})
	send(bhFrame{npamp.ChanStream, npamp.FrameStreamReset,
		bhStreamBody(npamp.FrameStreamReset, 4, map[uint64]any{2: uint64(0), 3: uint64(0)})})

	// ---------------- Scenario 4: interaction approval-hold distinction ----------------
	type appReq struct {
		corr   []byte
		action string
		want   string
	}
	reqs := []appReq{
		{[]byte("corr-grant"), "grant-me", "GRANTED"},
		{[]byte("corr-deny"), "deny-me", "DENIED"},
		{[]byte("corr-policy"), "policy-block", "POLICY_DENIED"},
		{[]byte("corr-hold"), "hold-me", "HELD"},
	}
	for _, rq := range reqs {
		send(bhFrame{npamp.ChanInteraction, npamp.FrameInteractApprovalReq,
			bhInteractBody(npamp.FrameInteractApprovalReq, rq.corr, map[uint64]any{
				2: rq.action, // action
				3: uint64(2), // severity: sensitive
			})})
	}
	// Collect the four replies, routed by corr.
	got := map[string]bhOutcome{}
	for i := 0; i < len(reqs); i++ {
		select {
		case in := <-cInteractIn:
			if in.err != nil {
				t.Fatalf("interaction reply %d: pump error: %v", i, in.err)
			}
			_, corr, derr := npamp.DecodeInteractionEnvelope(in.ft, in.pt)
			if derr != nil {
				t.Fatalf("interaction reply %d: envelope decode: %v", i, derr)
			}
			oc, cerr := bhClassify(in.ft, in.pt)
			if cerr != nil {
				t.Fatalf("interaction reply %d: classify: %v", i, cerr)
			}
			got[string(corr)] = oc
		case <-time.After(15 * time.Second):
			t.Fatalf("timed out awaiting interaction reply %d/%d", i+1, len(reqs))
		}
	}
	allDistinct := true
	held := got["corr-hold"]
	for _, rq := range reqs {
		oc, ok := got[string(rq.corr)]
		match := ok && oc.verdict == rq.want
		if !match {
			allDistinct = false
		}
		res.add("interaction.approval."+rq.want,
			"89_interaction_channel.md §6.3/§8.1",
			fmt.Sprintf("INTERACT_APPROVAL_REQ %q answered as the distinct %s outcome", rq.action, rq.want),
			match, fmt.Sprintf("verdict=%q approval_id=%q", oc.verdict, oc.approvalID))
	}
	// The load-bearing §8.1 assertion: HELD is its own outcome, never collapsed into
	// GRANTED / DENIED / POLICY_DENIED, and approval_id is present iff HELD.
	holdIsDistinct := held.verdict == "HELD" &&
		held.verdict != got["corr-grant"].verdict &&
		held.verdict != got["corr-deny"].verdict &&
		held.verdict != got["corr-policy"].verdict &&
		held.approvalID != "" &&
		got["corr-grant"].approvalID == "" &&
		got["corr-deny"].approvalID == "" &&
		got["corr-policy"].approvalID == ""
	res.add("interaction.approval.hold_is_distinct_outcome",
		"89_interaction_channel.md §8.1",
		"approval_held is preserved as a distinct non-success outcome (never granted/denied/policy_denied) and carries approval_id",
		holdIsDistinct && allDistinct,
		fmt.Sprintf("held=%q id=%q; grant=%q deny=%q policy=%q",
			held.verdict, held.approvalID,
			got["corr-grant"].verdict, got["corr-deny"].verdict, got["corr-policy"].verdict))

	// ---------------- Barrier: flush all server-side processing ----------------
	// A trailing INTERACT_EVENT(ack) is answered by INTERACT_EVENT_ACK. Because the client is
	// the single sender, every frame above was written before this barrier and processed by the
	// single server pump in order, so the ACK proves the reset/close observations are recorded.
	send(bhFrame{npamp.ChanInteraction, npamp.FrameInteractEvent,
		bhInteractBody(npamp.FrameInteractEvent, []byte("corr-barrier"), map[uint64]any{
			2: uint64(npamp.EventClassLifecycle),
			5: true, // ack
		})})
	select {
	case in := <-cInteractIn:
		if in.err != nil {
			t.Fatalf("barrier: pump error: %v", in.err)
		}
		if in.ft != npamp.FrameInteractEventAck {
			t.Fatalf("barrier: got ft=%#x, want INTERACT_EVENT_ACK", uint16(in.ft))
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("barrier: timed out awaiting INTERACT_EVENT_ACK")
	}

	// Fold the server-side observations into clause results. snapshotObs takes the lock, giving
	// the memory edge; the barrier above guarantees the server pump finished writing them.
	obsBy := map[string]bhObs{}
	for _, o := range reactor.snapshotObs() {
		obsBy[o.tag] = o // last observation per tag wins
	}
	must := func(id, spec, desc, tag string) {
		o, ok := obsBy[tag]
		res.add(id, spec, desc, ok && o.ok, fmt.Sprintf("server-observed[%s]=%q", tag, o.detail))
	}
	must("stream.flow_control.accept_inwindow", "80_stream_channel.md §5.2/§6.2",
		"an in-window STREAM_DATA is accepted", "stream.fc.accept.inwindow")
	must("stream.flow_control.accept_aftergrant", "80_stream_channel.md §5.2/§6.2",
		"a STREAM_DATA within a raised window is accepted", "stream.fc.accept.aftergrant")
	must("stream.halfclose.graceful", "80_stream_channel.md §5.3/§7.2",
		"a graceful half-close (fin + STREAM_CLOSE with consistent final_offset)", "stream.close.halfclose")
	must("stream.reset.clean_cancel", "80_stream_channel.md §5.4/§7.3",
		"a clean STREAM_RESET cancellation (error_code NoError) closes the sub-stream", "stream.reset.cancel")
	must("stream.reset.idempotent", "80_stream_channel.md §5.4/§7.3/§7.4",
		"a second STREAM_RESET for a closed sub-stream is ignored (idempotent, no reply)", "stream.reset.idempotent")

	// ---------------- Session close path ----------------
	if err := client.Close(); err != nil {
		t.Fatalf("client.Close: %v", err)
	}
	// After Close the connection MUST refuse to Send (the master secret is wiped); a nil error
	// would mean a frame was sealed under a torn-down key.
	closeErr := client.Send(ctx, npamp.ChanStream, npamp.FrameStreamData,
		bhStreamBody(npamp.FrameStreamData, 0, map[uint64]any{2: uint64(0), 3: []byte("x")}))
	res.add("session.close.send_refused_after_close", "sdk/conn.go Close/Zeroize",
		"Send after Close is refused (no frame sealed under a wiped key)", closeErr != nil,
		fmt.Sprintf("post-close Send err=%v", closeErr))

	// Drain the server pump's terminal error (from the closed socket) so the goroutine is not
	// reported as leaked; its value is not asserted (a closed-connection read error is expected).
	select {
	case <-serverErr:
	case <-time.After(2 * time.Second):
	}

	if res.Failed != 0 {
		t.Fatalf("behavioural_conformance: %d/%d clauses failed", res.Failed, res.Passed+res.Failed)
	}
}
