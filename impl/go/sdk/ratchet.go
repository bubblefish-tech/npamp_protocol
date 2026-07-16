// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"context"
	"encoding/binary"
	"fmt"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// Master ratchet (Hybrid Tree Ratchet, spec/10 section 5) control frames. These
// are Control-channel-specific frame types (>= 0x0100), interpreted only on the
// Control channel (0x0000); the same numeric values carry a different meaning on
// other channels' per-channel frame-type namespaces (draft-01 section 4.6), so
// the SDK dispatches ratchet handling ONLY when a frame of this type arrives on
// the Control channel.
//
//	0x0104 MASTER_RATCHET      Tier-1 boundary: last frame at genSend; carries the target generation
//	0x0105 MASTER_RATCHET_ACK  Tier-1 informational confirmation (like KEY_UPDATE_ACK)
//	0x0106 REKEM               Tier-2 request: carries KEMShare + target generation
//	0x0107 REKEM_ACK           Tier-2 boundary for the responder's send direction: carries KEMCiphertext + target generation
const (
	frameMasterRatchet    npamp.FrameType = 0x0104
	frameMasterRatchetAck npamp.FrameType = 0x0105
	frameReKEM            npamp.FrameType = 0x0106
	frameReKEMAck         npamp.FrameType = 0x0107
)

// pendingReKEM is the initiator-side state of an in-flight Tier-2 re-KEM: the
// ephemeral KEM client (holding the ML-KEM decapsulation key + X25519 private
// key), the exact KEMShare bytes sent (needed to reconstruct TH_rekem), and the
// generation the receive direction will heal to. Set under wmu by ReKEM,
// consumed under rmu by the REKEM_ACK handler, guarded by pmu.
type pendingReKEM struct {
	client    *npamp.KEMClient
	kemShare  []byte
	targetGen uint64
}

// zeroize drops the ephemeral KEM private-key material. crypto/mlkem and
// crypto/ecdh do not expose an in-place wipe of the private keys, so the best
// available action is to drop the reference for garbage collection (best-effort,
// per the design's zeroization caveat).
func (p *pendingReKEM) zeroize() {
	if p == nil {
		return
	}
	p.client = nil
	wipeRoot(p.kemShare)
}

// --- TLV codecs for the ratchet control frames ---

// ratchetGenMarker encodes a single TLVRatchetGeneration (0x19) carrying the
// generation as an 8-octet big-endian value, mirroring keyUpdateMarker.
func ratchetGenMarker(gen uint64) []byte {
	var v [8]byte
	binary.BigEndian.PutUint64(v[:], gen)
	return npamp.TLV{Type: npamp.TLVRatchetGeneration, Value: v[:]}.Encode(nil)
}

// parseRatchetGenMarker decodes a MASTER_RATCHET / MASTER_RATCHET_ACK payload
// into its announced generation, enforcing the single 8-octet TLV layout.
func parseRatchetGenMarker(payload []byte) (uint64, error) {
	tlvs, err := npamp.DecodeTLVs(payload)
	if err != nil {
		return 0, err
	}
	if len(tlvs) != 1 || tlvs[0].Type != npamp.TLVRatchetGeneration {
		return 0, fmt.Errorf("expected a single RatchetGeneration TLV")
	}
	if len(tlvs[0].Value) != 8 {
		return 0, fmt.Errorf("RatchetGeneration is %d octets, want 8", len(tlvs[0].Value))
	}
	return binary.BigEndian.Uint64(tlvs[0].Value), nil
}

// encodeReKEM encodes a REKEM payload: TLVKEMShare (0x07) followed by
// TLVRatchetGeneration (0x19).
func encodeReKEM(kemShare []byte, gen uint64) []byte {
	var g [8]byte
	binary.BigEndian.PutUint64(g[:], gen)
	out := npamp.TLV{Type: npamp.TLVKEMShare, Value: kemShare}.Encode(nil)
	return npamp.TLV{Type: npamp.TLVRatchetGeneration, Value: g[:]}.Encode(out)
}

// parseReKEM decodes a REKEM payload into (KEMShare, target generation),
// enforcing the KEMShare + RatchetGeneration TLV layout and the KEMShare size.
func parseReKEM(payload []byte) (kemShare []byte, gen uint64, err error) {
	tlvs, err := npamp.DecodeTLVs(payload)
	if err != nil {
		return nil, 0, err
	}
	if len(tlvs) != 2 || tlvs[0].Type != npamp.TLVKEMShare || tlvs[1].Type != npamp.TLVRatchetGeneration {
		return nil, 0, fmt.Errorf("expected KEMShare + RatchetGeneration TLVs")
	}
	if len(tlvs[0].Value) != npamp.KEMShareSize768 {
		return nil, 0, npamp.ErrKEMShareSize
	}
	if len(tlvs[1].Value) != 8 {
		return nil, 0, fmt.Errorf("RatchetGeneration is %d octets, want 8", len(tlvs[1].Value))
	}
	return tlvs[0].Value, binary.BigEndian.Uint64(tlvs[1].Value), nil
}

// encodeReKEMAck encodes a REKEM_ACK payload: TLVKEMCiphertext (0x08) followed
// by TLVRatchetGeneration (0x19).
func encodeReKEMAck(kemCT []byte, gen uint64) []byte {
	var g [8]byte
	binary.BigEndian.PutUint64(g[:], gen)
	out := npamp.TLV{Type: npamp.TLVKEMCiphertext, Value: kemCT}.Encode(nil)
	return npamp.TLV{Type: npamp.TLVRatchetGeneration, Value: g[:]}.Encode(out)
}

// parseReKEMAck decodes a REKEM_ACK payload into (KEMCiphertext, target
// generation), enforcing the KEMCiphertext + RatchetGeneration TLV layout and the
// KEMCiphertext size.
func parseReKEMAck(payload []byte) (kemCT []byte, gen uint64, err error) {
	tlvs, err := npamp.DecodeTLVs(payload)
	if err != nil {
		return nil, 0, err
	}
	if len(tlvs) != 2 || tlvs[0].Type != npamp.TLVKEMCiphertext || tlvs[1].Type != npamp.TLVRatchetGeneration {
		return nil, 0, fmt.Errorf("expected KEMCiphertext + RatchetGeneration TLVs")
	}
	if len(tlvs[0].Value) != npamp.KEMCiphertextSize768 {
		return nil, 0, npamp.ErrKEMCiphertextSize
	}
	if len(tlvs[1].Value) != 8 {
		return nil, 0, fmt.Errorf("RatchetGeneration is %d octets, want 8", len(tlvs[1].Value))
	}
	return tlvs[0].Value, binary.BigEndian.Uint64(tlvs[1].Value), nil
}

// thRekem computes the TH_rekem transcript point that binds the exact
// REKEM/REKEM_ACK exchange into the Tier-2 root (spec/10 section 3): H over the
// REKEM frame type + its TLVs, then the REKEM_ACK frame type + its TLVs, using
// the same per-TLV canonical Type||Length||Value construction as the handshake
// transcript. Both peers assemble it identically from the wire bytes they
// exchanged, so a spliced or reflected exchange yields a divergent root.
func thRekem(p npamp.Profile, kemShare, kemCT []byte, gen uint64) []byte {
	var g [8]byte
	binary.BigEndian.PutUint64(g[:], gen)
	tr := npamp.NewTranscript(p)
	tr.AddFrameType(frameReKEM)
	tr.AddTLV(npamp.TLV{Type: npamp.TLVKEMShare, Value: kemShare})
	tr.AddTLV(npamp.TLV{Type: npamp.TLVRatchetGeneration, Value: g[:]})
	tr.AddFrameType(frameReKEMAck)
	tr.AddTLV(npamp.TLV{Type: npamp.TLVKEMCiphertext, Value: kemCT})
	tr.AddTLV(npamp.TLV{Type: npamp.TLVRatchetGeneration, Value: g[:]})
	return tr.Sum()
}

// --- Tier 1: symmetric forward step (cheap, frequent) → forward secrecy ---

// RatchetSend performs a Tier-1 master-ratchet step on the SEND direction: it
// seals a MASTER_RATCHET boundary frame (carrying the target generation) under
// the CURRENT generation's Control-channel key — the last frame at this
// generation on the send stream — writes it, then advances masterSend one
// generation via the one-way HKDF-Expand-Label step, wiping the retired root in
// place and dropping every cached send key so all channels re-derive off the new
// root at leaf epoch 0. The peer advances its matching receive root when it
// processes the boundary. Conn-scope across channels, per-direction across the
// two streams; serialized with Send/KeyUpdate under wmu.
func (c *Conn) RatchetSend(ctx context.Context) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed {
		return errClosed
	}
	target := c.genSend.Load() + 1
	st, err := c.sendState(npamp.ChanControl)
	if err != nil {
		return fmt.Errorf("npamp/sdk: derive Control send key: %w", err)
	}
	if st.seq == ^uint64(0) {
		return fmt.Errorf("npamp/sdk: Control channel epoch %d sequence space exhausted", st.epoch)
	}
	wire, err := sealWith(st, npamp.ChanControl, frameMasterRatchet, ratchetGenMarker(target))
	if err != nil {
		return fmt.Errorf("npamp/sdk: seal MASTER_RATCHET: %w", err)
	}
	if err := c.writeWire(ctx, wire); err != nil {
		return err
	}
	st.seq++
	nr, err := npamp.RatchetMasterTier1(c.masterSend, target, c.profile)
	if err != nil {
		return fmt.Errorf("npamp/sdk: advance send root: %w", err)
	}
	wipeRoot(c.masterSend)
	c.masterSend = nr
	c.genSend.Store(target)
	c.dropSendKeys()
	return nil
}

// handleMasterRatchet processes a received MASTER_RATCHET boundary on the receive
// direction: it validates the marker announces exactly genRecv+1, advances
// masterRecv one generation via the same one-way step (wiping the retired root
// and dropping every cached receive key), then replies MASTER_RATCHET_ACK off the
// receive path. Caller holds rmu (the Recv loop); the ACK is dispatched on its own
// goroutine that takes wmu alone, so no goroutine nests wmu inside rmu.
func (c *Conn) handleMasterRatchet(channel npamp.ChannelID, plaintext []byte) error {
	next, err := parseRatchetGenMarker(plaintext)
	if err != nil {
		return fmt.Errorf("npamp/sdk: MASTER_RATCHET on channel %d: %w", channel, err)
	}
	if next != c.genRecv.Load()+1 {
		return fmt.Errorf("npamp/sdk: MASTER_RATCHET announced gen %d, want %d", next, c.genRecv.Load()+1)
	}
	nr, err := npamp.RatchetMasterTier1(c.masterRecv, next, c.profile)
	if err != nil {
		return fmt.Errorf("npamp/sdk: advance recv root: %w", err)
	}
	wipeRoot(c.masterRecv)
	c.masterRecv = nr
	c.genRecv.Store(next)
	c.dropRecvKeys()
	go c.sendMasterRatchetAck(next)
	return nil
}

// sendMasterRatchetAck seals + writes an informational MASTER_RATCHET_ACK on the
// Control channel, off the receive path (its own goroutine taking wmu, bounded by
// ackWriteTimeout), mirroring sendKeyUpdateAck. The ACK rides the send direction
// (unaffected by the receive-direction ratchet that triggered it). A failed write
// corrupts our send stream, so it tears the connection down; a seal/derive error
// simply skips the informational ACK.
func (c *Conn) sendMasterRatchetAck(gen uint64) {
	ctx, cancel := context.WithTimeout(context.Background(), ackWriteTimeout)
	defer cancel()

	c.wmu.Lock()
	st, err := c.sendState(npamp.ChanControl)
	if err != nil {
		c.wmu.Unlock()
		return
	}
	ack, err := sealWith(st, npamp.ChanControl, frameMasterRatchetAck, ratchetGenMarker(gen))
	if err != nil {
		c.wmu.Unlock()
		return
	}
	werr := c.writeWire(ctx, ack)
	if werr == nil {
		st.seq++
	}
	c.wmu.Unlock()

	if werr != nil {
		_ = c.Close()
	}
}

// --- Tier 2: asymmetric re-KEM step (periodic) → forward secrecy + post-compromise security ---

// ReKEM initiates a Tier-2 re-KEM that heals the RECEIVE direction (the stream
// this endpoint receives; the peer refreshes its matching send root). It
// generates a fresh ephemeral X25519MLKEM768 client, seals a REKEM request
// (KEMShare + the target generation) under the current send-generation Control
// key, writes it, and stashes the pending ephemeral state. It does NOT advance
// any root yet: the heal completes when the peer's REKEM_ACK arrives. A second
// ReKEM is refused while one is in flight (single writer per direction, no
// tie-break). A lost REKEM_ACK leaves the receive direction safely at its current
// generation; the pending state is wiped at Close.
func (c *Conn) ReKEM(ctx context.Context) error {
	c.pmu.Lock()
	if c.pendingReKEM != nil {
		c.pmu.Unlock()
		return fmt.Errorf("npamp/sdk: a Tier-2 re-KEM is already in flight")
	}
	c.pmu.Unlock()

	client, err := npamp.GenerateKEMClient()
	if err != nil {
		return fmt.Errorf("npamp/sdk: re-KEM keygen: %w", err)
	}
	kemShare := client.KEMShare()

	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed {
		return errClosed
	}
	// Snapshot the receive generation we intend to heal. genRecv is atomic and read
	// LOCK-FREE here: ReKEM holds wmu, and an app Recv-loop holds rmu for its whole
	// blocking call, so ReKEM must never take rmu. If the receive direction
	// independently ratchets before the ACK arrives, this target goes stale and is
	// rejected at REKEM_ACK time under rmu (fails closed).
	target := c.genRecv.Load() + 1

	st, err := c.sendState(npamp.ChanControl)
	if err != nil {
		return fmt.Errorf("npamp/sdk: derive Control send key: %w", err)
	}
	if st.seq == ^uint64(0) {
		return fmt.Errorf("npamp/sdk: Control channel epoch %d sequence space exhausted", st.epoch)
	}
	wire, err := sealWith(st, npamp.ChanControl, frameReKEM, encodeReKEM(kemShare, target))
	if err != nil {
		return fmt.Errorf("npamp/sdk: seal REKEM: %w", err)
	}
	if err := c.writeWire(ctx, wire); err != nil {
		return err
	}
	st.seq++

	c.pmu.Lock()
	c.pendingReKEM = &pendingReKEM{client: client, kemShare: kemShare, targetGen: target}
	c.pmu.Unlock()
	return nil
}

// handleReKEM processes a received REKEM request on the receive direction. The
// encapsulation and the send-root advance happen OFF the receive path
// (respondReKEM takes wmu), so the recv loop never nests wmu inside rmu — the
// same discipline as sendKeyUpdateAck. Caller holds rmu.
func (c *Conn) handleReKEM(channel npamp.ChannelID, plaintext []byte) error {
	kemShare, target, err := parseReKEM(plaintext)
	if err != nil {
		return fmt.Errorf("npamp/sdk: REKEM on channel %d: %w", channel, err)
	}
	// Copy the KEMShare out of the receive buffer: respondReKEM runs on its own
	// goroutine after Recv has moved on and may reuse the underlying storage.
	go c.respondReKEM(append([]byte(nil), kemShare...), target)
	return nil
}

// respondReKEM is the responder's off-path Tier-2 work: encapsulate to the
// initiator's ephemeral key, seal the REKEM_ACK boundary (KEMCiphertext + the
// target generation) under the current send-generation Control key, write it,
// then advance the send root via the Extract-then-Expand re-KEM step (mixing the
// fresh KEM entropy), dropping cached send keys and wiping the shared secrets. It
// validates the target equals genSend+1 under wmu; a mismatch (a stale/skewed
// generation) aborts without advancing, leaving the direction safe and the
// initiator to time out. Takes wmu alone (bounded by ackWriteTimeout).
func (c *Conn) respondReKEM(kemShare []byte, target uint64) {
	ctx, cancel := context.WithTimeout(context.Background(), ackWriteTimeout)
	defer cancel()

	kemCT, ss, err := npamp.Encapsulate(kemShare)
	if err != nil {
		// Invalid KEMShare (bad size / low-order X25519): abort; the initiator's
		// pending re-KEM times out and the direction stays at its current gen.
		return
	}
	newSS := ss.Combined()
	th := thRekem(c.profile, kemShare, kemCT, target)
	defer func() {
		wipeRoot(newSS)
		wipeRoot(ss.MLKEM)
		wipeRoot(ss.X25519)
	}()

	c.wmu.Lock()
	if c.closed {
		c.wmu.Unlock()
		return
	}
	if target != c.genSend.Load()+1 {
		// Generation skew: refuse to advance (fails closed; direction stays at gen G).
		c.wmu.Unlock()
		return
	}
	st, err := c.sendState(npamp.ChanControl)
	if err != nil {
		c.wmu.Unlock()
		return
	}
	ack, err := sealWith(st, npamp.ChanControl, frameReKEMAck, encodeReKEMAck(kemCT, target))
	if err != nil {
		c.wmu.Unlock()
		return
	}
	werr := c.writeWire(ctx, ack)
	var aerr error
	if werr == nil {
		st.seq++
		var nr []byte
		nr, aerr = npamp.RatchetMasterTier2(c.masterSend, newSS, th, c.profile)
		if aerr == nil {
			wipeRoot(c.masterSend)
			c.masterSend = nr
			c.genSend.Store(target)
			c.dropSendKeys()
		}
	}
	c.wmu.Unlock()

	// The REKEM_ACK is a boundary: if it wrote but the root advance failed, our send
	// stream is now desynchronized from the peer. Either failure corrupts the send
	// stream, so tear the connection down (fails closed).
	if werr != nil || aerr != nil {
		_ = c.Close()
	}
}

// handleReKEMAck finalizes a Tier-2 re-KEM on the initiator: it opens the
// REKEM_ACK boundary under the current receive root, decapsulates to recover the
// fresh shared secret, reconstructs TH_rekem identically, and advances masterRecv
// via the same Extract-then-Expand re-KEM step — mixing entropy the attacker
// lacks (post-compromise self-heal). Caller holds rmu. Consumes and wipes the
// pending ephemeral state. A missing pending, a generation mismatch, or a decaps
// failure surfaces as an error (fails closed).
func (c *Conn) handleReKEMAck(plaintext []byte) error {
	kemCT, gen, err := parseReKEMAck(plaintext)
	if err != nil {
		return fmt.Errorf("npamp/sdk: REKEM_ACK: %w", err)
	}
	c.pmu.Lock()
	pend := c.pendingReKEM
	c.pendingReKEM = nil
	c.pmu.Unlock()
	if pend == nil {
		return fmt.Errorf("npamp/sdk: REKEM_ACK with no pending re-KEM")
	}
	defer pend.zeroize()

	if gen != c.genRecv.Load()+1 || gen != pend.targetGen {
		return fmt.Errorf("npamp/sdk: REKEM_ACK announced gen %d, want %d", gen, c.genRecv.Load()+1)
	}
	ss, err := pend.client.SharedSecrets(kemCT) // Decapsulate
	if err != nil {
		return fmt.Errorf("npamp/sdk: re-KEM decapsulate: %w", err)
	}
	newSS := ss.Combined()
	th := thRekem(c.profile, pend.kemShare, kemCT, gen)
	nr, err := npamp.RatchetMasterTier2(c.masterRecv, newSS, th, c.profile)
	wipeRoot(newSS)
	wipeRoot(ss.MLKEM)
	wipeRoot(ss.X25519)
	if err != nil {
		return fmt.Errorf("npamp/sdk: advance recv root: %w", err)
	}
	wipeRoot(c.masterRecv)
	c.masterRecv = nr
	c.genRecv.Store(gen)
	c.dropRecvKeys()
	return nil
}
