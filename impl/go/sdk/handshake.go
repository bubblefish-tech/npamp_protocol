// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"context"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"slices"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// ErrKEMDowngrade is returned when a peer's negotiated KEM group is not the
// one required by the negotiated profile's minimum KEM (spec/05_profiles.md
// "Minimum KEM"; spec/10 section 4a: "Sovereign MUST NOT accept
// X25519MLKEM768"). High and Sovereign refuse a downgrade to
// X25519MLKEM768; conversely a client that generated key material only for
// X25519MLKEM768 (because it did not offer High/Sovereign) refuses a
// SecP384r1MLKEM1024 selection it cannot decapsulate. This is the wire-level
// enforcement of the profile-level downgrade refusal in
// spec/05_profiles.md's negotiation rules.
var ErrKEMDowngrade = errors.New("npamp/sdk: negotiated KEM group does not match the selected profile's minimum KEM (downgrade refused)")

// sdkProfile is the default security profile a zero-value Config.Profiles
// offers/accepts — Standard, so an existing single-profile caller's wire
// behavior is unchanged. Multi-profile callers set Config.Profiles instead.
var sdkProfile = npamp.ProfileStandard

// localIdentity carries the resolved local identity key material for one or
// more security profiles, built by resolveIdentity from a Config (or by
// stdIdentity for the pre-multi-profile Ed25519-only test callers). It is
// deliberately NOT exported: callers configure identity via Config.Identity /
// Config.MLDSAIdentity / Config.Profiles, never this type directly.
type localIdentity struct {
	edPriv ed25519.PrivateKey
	edPub  ed25519.PublicKey

	mldsaPriv *mldsa.PrivateKey
	mldsaPub  *mldsa.PublicKey

	// profiles is the ProfileOffer this endpoint sends (client) or the
	// preference-ordered set it accepts (server). Always non-empty:
	// resolveIdentity/stdIdentity default it to [npamp.ProfileStandard].
	profiles []npamp.Profile
}

// profilesOrDefault returns profiles unchanged if non-empty, else the
// single-element Standard-only default — the zero-value Config.Profiles
// behavior that keeps an existing caller's wire bytes unchanged.
func profilesOrDefault(profiles []npamp.Profile) []npamp.Profile {
	if len(profiles) == 0 {
		return []npamp.Profile{sdkProfile}
	}
	return profiles
}

// needsMLDSA reports whether profiles contains High or Sovereign, both of
// which this SDK signs CertVerify with ML-DSA-87 (spec/05_profiles.md:
// High allows Ed25519 OR ML-DSA-87; this SDK always uses ML-DSA-87 for High,
// matching Sovereign's hard requirement, per the task's per-profile dispatch).
func needsMLDSA(profiles []npamp.Profile) bool {
	return slices.Contains(profiles, npamp.ProfileHigh) || slices.Contains(profiles, npamp.ProfileSovereign)
}

// needsEd25519 reports whether profiles contains Standard.
func needsEd25519(profiles []npamp.Profile) bool {
	return slices.Contains(profiles, npamp.ProfileStandard)
}

// kemGroupForProfiles returns the single KEM group this SDK generates
// ephemeral key material for and offers as CLIENT_HELLO's KEMOffer/KEMShare
// (spec/05_profiles.md "Minimum KEM"; spec/10 section 4/4a): SecP384r1MLKEM1024
// whenever High or Sovereign is in profiles (their minimum KEM — the same set
// needsMLDSA tests), else X25519MLKEM768 (Standard's minimum KEM, and this
// SDK's pre-multi-profile default). A CLIENT_HELLO carries exactly ONE
// physical KEMShare TLV (spec/10 section 1.1: a single `0x07` per frame), so a
// client offering both a Standard-only profile and a High/Sovereign profile in
// the same ProfileOffer sends only the stronger group's share and lists only
// that group in KEMOffer; the server can then select only a profile whose
// MinKEM() is present in KEMOffer (requireOffers), and this client's own
// requireSelections refuses any SERVER_HELLO whose selection it did not
// generate key material for.
func kemGroupForProfiles(profiles []npamp.Profile) npamp.KEMID {
	if needsMLDSA(profiles) {
		return npamp.KEMSecP384r1MLKEM1024
	}
	return npamp.KEMX25519MLKEM768
}

// resolveIdentity builds a localIdentity from cfg: it defaults cfg.Profiles to
// Standard-only when unset, resolves the Ed25519 half via identity()
// (generating an ephemeral key when cfg.Identity is nil, exactly today's
// behavior) whenever Standard is offered/accepted, and requires
// cfg.MLDSAIdentity whenever High or Sovereign is offered/accepted — a
// fail-closed Config error rather than a silent downgrade or a nil-key panic
// later in the handshake.
func resolveIdentity(cfg Config) (*localIdentity, error) {
	profiles := profilesOrDefault(cfg.Profiles)
	for _, p := range profiles {
		if !p.Valid() {
			return nil, fmt.Errorf("npamp/sdk: Config.Profiles contains invalid profile 0x%02x", uint8(p))
		}
	}
	id := &localIdentity{profiles: profiles}
	if needsEd25519(profiles) {
		priv, pub, err := identity(cfg.Identity)
		if err != nil {
			return nil, err
		}
		id.edPriv, id.edPub = priv, pub
	}
	if needsMLDSA(profiles) {
		if cfg.MLDSAIdentity == nil {
			return nil, fmt.Errorf("npamp/sdk: Config.Profiles offers/accepts High or Sovereign but Config.MLDSAIdentity is nil")
		}
		id.mldsaPriv = cfg.MLDSAIdentity
		id.mldsaPub = cfg.MLDSAIdentity.PublicKey()
	}
	return id, nil
}

// stdIdentity builds a Standard-profile-only localIdentity from a bare
// Ed25519 keypair — the shape the pre-multi-profile deviant-peer tests in
// statetrace_test.go already construct their keys in.
func stdIdentity(priv ed25519.PrivateKey, pub ed25519.PublicKey) *localIdentity {
	return &localIdentity{edPriv: priv, edPub: pub, profiles: []npamp.Profile{npamp.ProfileStandard}}
}

// sigForProfile returns the SigID this SDK signs/expects CertVerify with for
// profile p: Ed25519 at Standard, ML-DSA-87 at High or Sovereign
// (spec/05_profiles.md "Allowed signatures"; task-directed per-profile
// dispatch — see needsMLDSA's doc for why High always uses ML-DSA-87 here).
func sigForProfile(p npamp.Profile) npamp.SigID {
	if p == npamp.ProfileStandard {
		return npamp.SigEd25519
	}
	return npamp.SigMLDSA87
}

// offeredSigs returns the SigOffer for profiles: SigEd25519 if Standard is
// present, SigMLDSA87 if High or Sovereign is present, in that order — the
// union of sigForProfile over the offered set, deduplicated. A Standard-only
// offer (the default) produces exactly [SigEd25519], byte-identical to the
// pre-multi-profile ClientHello.
func offeredSigs(profiles []npamp.Profile) []npamp.SigID {
	var out []npamp.SigID
	if needsEd25519(profiles) {
		out = append(out, npamp.SigEd25519)
	}
	if needsMLDSA(profiles) {
		out = append(out, npamp.SigMLDSA87)
	}
	return out
}

// selectProfile picks the profile the server selects: the first entry of
// allowed (the server's preference order, per Config.Profiles' doc) that also
// appears in offered (the client's ProfileOffer). It returns an error if no
// entry matches — the server MUST select from the client's offered set
// (spec/05_profiles.md "Negotiation rules") and never invents a profile the
// client did not offer.
func selectProfile(offered, allowed []npamp.Profile) (npamp.Profile, error) {
	for _, p := range allowed {
		if slices.Contains(offered, p) {
			return p, nil
		}
	}
	return 0, fmt.Errorf("npamp/sdk: no profile in the client's offer is acceptable to this server")
}

// localIdentityKeyBytes returns the raw public-key encoding this endpoint
// proves for profile p: id.edPub at Standard, id.mldsaPub.Bytes() at High or
// Sovereign. It is the TLV 0x09 IdentityKey value both AUTH frames carry.
func localIdentityKeyBytes(id *localIdentity, p npamp.Profile) ([]byte, error) {
	if p == npamp.ProfileStandard {
		if len(id.edPub) == 0 {
			return nil, fmt.Errorf("npamp/sdk: profile Standard selected but no Ed25519 identity is configured")
		}
		return append([]byte(nil), id.edPub...), nil
	}
	if id.mldsaPub == nil {
		return nil, fmt.Errorf("npamp/sdk: profile %s selected but no ML-DSA-87 identity is configured", p)
	}
	return append([]byte(nil), id.mldsaPub.Bytes()...), nil
}

// signCertVerify produces the TLV 0x0A CertVerify value for role at
// transcript point th, dispatching on the negotiated profile p: Standard
// signs with npamp.SignCertVerify (Ed25519); High and Sovereign sign with
// npamp.SignCertVerifyMLDSA87. Fail-closed: an endpoint that negotiated a
// profile it has no matching identity key for (should be unreachable —
// resolveIdentity requires the key before the profile can even be offered)
// returns a named error rather than silently falling back to a weaker
// scheme.
func signCertVerify(id *localIdentity, p npamp.Profile, role npamp.Role, th []byte) ([]byte, error) {
	if p == npamp.ProfileStandard {
		if id.edPriv == nil {
			return nil, fmt.Errorf("npamp/sdk: profile Standard selected but no Ed25519 identity is configured")
		}
		return npamp.SignCertVerify(id.edPriv, role, th)
	}
	if id.mldsaPriv == nil {
		return nil, fmt.Errorf("npamp/sdk: profile %s selected but no ML-DSA-87 identity is configured", p)
	}
	return npamp.SignCertVerifyMLDSA87(id.mldsaPriv, role, th)
}

// verifyCertVerify checks a TLV 0x0A CertVerify value against the peer's
// claimed identity-key bytes, dispatching on the negotiated profile p:
// Standard verifies with npamp.VerifyCertVerify (Ed25519); High and Sovereign
// decode peerPub as an ML-DSA-87 public key and verify with
// npamp.VerifyCertVerifyMLDSA87. Fail-closed on every path: a malformed
// peerPub encoding, a wrong signature scheme, or a bad signature all return a
// non-nil error and the caller aborts the handshake — never a fallback to a
// weaker check.
func verifyCertVerify(peerPub []byte, p npamp.Profile, role npamp.Role, th, certVerifyValue []byte) error {
	if p == npamp.ProfileStandard {
		return npamp.VerifyCertVerify(peerPub, role, th, certVerifyValue)
	}
	pub, err := mldsa.NewPublicKey(mldsa.MLDSA87(), peerPub)
	if err != nil {
		return fmt.Errorf("npamp/sdk: peer ML-DSA-87 identity key: %w", err)
	}
	return npamp.VerifyCertVerifyMLDSA87(pub, role, th, certVerifyValue)
}

// Dial establishes an N-PAMP session to addr ("host:port") over TCP + TLS 1.3,
// completes the 1.5-RTT mutually-authenticated handshake, and returns the
// established Conn. The caller MUST Close the returned Conn.
func Dial(ctx context.Context, addr string, cfg Config) (*Conn, error) {
	if cfg.TLSConfig == nil {
		return nil, fmt.Errorf("npamp/sdk: Config.TLSConfig is required")
	}
	id, err := resolveIdentity(cfg)
	if err != nil {
		return nil, err
	}
	d := &tls.Dialer{Config: withNpampTLS(cfg.TLSConfig)}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("npamp/sdk: dial %s: %w", addr, err)
	}
	if err := requireALPN(raw); err != nil {
		_ = raw.Close()
		return nil, err
	}
	master, peerID, profile, err := runClientHandshake(ctx, raw, id, cfg.ExpectedPeerKey)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	conn := newConn(raw, master, peerID, npamp.DirClientToServer, npamp.DirServerToClient)
	conn.profile = profile
	return conn, nil
}

// Listener accepts N-PAMP connections. Create one with Listen and Close it when
// done.
type Listener struct {
	ln  net.Listener
	cfg Config
}

// Listen starts a TCP + TLS 1.3 listener on addr negotiating ALPN "n-pamp/3".
func Listen(addr string, cfg Config) (*Listener, error) {
	if cfg.TLSConfig == nil {
		return nil, fmt.Errorf("npamp/sdk: Config.TLSConfig is required")
	}
	ln, err := tls.Listen("tcp", addr, withNpampTLS(cfg.TLSConfig))
	if err != nil {
		return nil, fmt.Errorf("npamp/sdk: listen %s: %w", addr, err)
	}
	return &Listener{ln: ln, cfg: cfg}, nil
}

// Addr returns the listener's network address (useful with a ":0" port).
func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// Close stops the listener.
func (l *Listener) Close() error { return l.ln.Close() }

// Accept waits for the next connection, completes the TLS and N-PAMP handshakes
// under ctx, and returns the established Conn. The caller MUST Close the
// returned Conn. Accept is safe to call from multiple goroutines.
func (l *Listener) Accept(ctx context.Context) (*Conn, error) {
	raw, err := l.ln.Accept()
	if err != nil {
		return nil, fmt.Errorf("npamp/sdk: accept: %w", err)
	}
	id, err := resolveIdentity(l.cfg)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	// Bound the handshake (TLS + N-PAMP) per connection, starting AFTER the raw
	// accept — so the deadline covers only the handshake work, not the idle wait for
	// a connection (l.ln.Accept does not observe ctx). This closes the pre-auth
	// stalled-handshake DoS: a peer that completes TCP/TLS but never finishes the
	// N-PAMP handshake is dropped after HandshakeTimeout instead of pinning this
	// goroutine and socket. A zero HandshakeTimeout leaves only the caller's ctx.
	hctx := ctx
	if l.cfg.HandshakeTimeout > 0 {
		var cancel context.CancelFunc
		hctx, cancel = context.WithTimeout(ctx, l.cfg.HandshakeTimeout)
		defer cancel()
	}
	// Force the TLS handshake here, in the per-connection path, so ALPN is
	// populated and a slow client cannot stall the accept loop.
	if tc, ok := raw.(*tls.Conn); ok {
		if err := tc.HandshakeContext(hctx); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("npamp/sdk: TLS handshake: %w", err)
		}
	}
	if err := requireALPN(raw); err != nil {
		_ = raw.Close()
		return nil, err
	}
	master, peerID, profile, err := runServerHandshake(hctx, raw, id, l.cfg.ExpectedPeerKey)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	conn := newConn(raw, master, peerID, npamp.DirServerToClient, npamp.DirClientToServer)
	conn.profile = profile
	return conn, nil
}

func newConn(raw net.Conn, master []byte, peerID []byte, sendDir, recvDir npamp.Direction) *Conn {
	// Seed both per-direction ratchet roots from the handshake master at
	// generation 0. Independent copies so each direction can advance (and wipe its
	// predecessor) without disturbing the other; the caller's `master` backing
	// array is not retained. Generation-0 roots ARE the handshake master, so
	// gen-0 traffic keys are byte-identical to the pre-ratchet schedule (R4).
	return &Conn{
		raw:        raw,
		profile:    sdkProfile,
		masterSend: append([]byte(nil), master...),
		masterRecv: append([]byte(nil), master...),
		peerID:     append([]byte(nil), peerID...),
		sendDir:    sendDir,
		recvDir:    recvDir,
		sendKeys:   make(map[npamp.ChannelID]*epochKeys),
		recvKeys:   make(map[npamp.ChannelID]*epochKeys),
	}
}

func identity(priv ed25519.PrivateKey) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if priv == nil {
		pub, p, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("npamp/sdk: generate identity: %w", err)
		}
		return p, pub, nil
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("npamp/sdk: Config.Identity is not a valid Ed25519 key")
	}
	return priv, pub, nil
}

func requireALPN(raw net.Conn) error {
	tc, ok := raw.(*tls.Conn)
	if !ok {
		return fmt.Errorf("npamp/sdk: connection is not TLS")
	}
	if got := tc.ConnectionState().NegotiatedProtocol; got != ALPN {
		return fmt.Errorf("npamp/sdk: negotiated ALPN %q, want %q", got, ALPN)
	}
	return nil
}

// runClientHandshake drives the client's side of the 1.5-RTT draft-01 handshake
// (spec/10) over raw, returning the master secret, the peer's authenticated
// identity-key bytes, and the negotiated profile. The transcript/key-schedule
// steps mirror the reference flow in impl/go's TestHandshakeFlowStandard,
// which is pinned to the published KATs. id.profiles is the ProfileOffer;
// CertVerify sign/verify dispatches on the profile the SERVER selects
// (sigForProfile/signCertVerify/verifyCertVerify). The KEM group is decided
// upfront by kemGroupForProfiles (X25519MLKEM768 unless High/Sovereign is
// offered, in which case SecP384r1MLKEM1024 — spec/05_profiles.md "Minimum
// KEM") since CLIENT_HELLO carries only one physical KEMShare; requireSelections
// then refuses any SERVER_HELLO that selected a different group (ErrKEMDowngrade).
func runClientHandshake(ctx context.Context, raw net.Conn, id *localIdentity, expectedPeer []byte) (master []byte, peerID []byte, profile npamp.Profile, err error) {
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
		defer func() { _ = raw.SetDeadline(time.Time{}) }()
	}
	profiles := profilesOrDefault(id.profiles)
	wantKEM := kemGroupForProfiles(profiles)

	var kem768 *npamp.KEMClient
	var kem1024 *npamp.KEMClient1024
	var kemShare []byte
	switch wantKEM {
	case npamp.KEMSecP384r1MLKEM1024:
		kem1024, err = npamp.GenerateKEMClient1024()
		if err != nil {
			return nil, nil, 0, fmt.Errorf("npamp/sdk: KEM-1024 keygen: %w", err)
		}
		kemShare = kem1024.KEMShare()
	default:
		kem768, err = npamp.GenerateKEMClient()
		if err != nil {
			return nil, nil, 0, fmt.Errorf("npamp/sdk: KEM keygen: %w", err)
		}
		kemShare = kem768.KEMShare()
	}
	ch := &npamp.ClientHello{
		ProfileOffer: profiles,
		KEMOffer:     []npamp.KEMID{wantKEM},
		SigOffer:     offeredSigs(profiles),
		AEADOffer:    []npamp.AEADID{npamp.AEADAES256GCM},
		KEMShare:     kemShare,
	}
	if err := sendCleartext(raw, npamp.FrameClientHello, ch.Encode()); err != nil {
		return nil, nil, 0, fmt.Errorf("npamp/sdk: send CLIENT_HELLO: %w", err)
	}

	shPayload, err := recvCleartext(raw, npamp.FrameServerHello)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("npamp/sdk: recv SERVER_HELLO: %w", err)
	}
	sh, err := npamp.DecodeServerHello(shPayload)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("npamp/sdk: decode SERVER_HELLO: %w", err)
	}
	if err := requireSelections(sh, profiles, wantKEM); err != nil {
		return nil, nil, 0, err
	}
	// The transcript's KDF hash depends on the NEGOTIATED profile (sh.ProfileSelect),
	// which is not known until SERVER_HELLO arrives — so the transcript is built here,
	// after negotiation, absorbing CLIENT_HELLO then SERVER_HELLO in wire order (the
	// bytes absorbed are identical either way; only the hash function used by Sum()
	// depends on construction time, per NewTranscript(p)'s doc).
	p := sh.ProfileSelect
	t := npamp.NewTranscript(p)
	t.AddFrame(npamp.FrameClientHello, ch.TLVs())
	t.AddFrame(npamp.FrameServerHello, sh.TLVs())

	var hs []byte
	switch wantKEM {
	case npamp.KEMSecP384r1MLKEM1024:
		ss1024, derr := kem1024.SharedSecrets(sh.KEMCiphertext)
		if derr != nil {
			return nil, nil, 0, fmt.Errorf("npamp/sdk: KEM-1024 decapsulate: %w", derr)
		}
		hs, err = npamp.HandshakeSecret1024(ss1024, p)
		if err != nil {
			return nil, nil, 0, err
		}
	default:
		ss, derr := kem768.SharedSecrets(sh.KEMCiphertext)
		if derr != nil {
			return nil, nil, 0, fmt.Errorf("npamp/sdk: KEM decapsulate: %w", derr)
		}
		hs, err = npamp.HandshakeSecret(ss, p)
		if err != nil {
			return nil, nil, 0, err
		}
	}
	cHS, sHS, err := npamp.DeriveHandshakeTrafficSecrets(hs, t.Sum(), p) // TH_kem
	if err != nil {
		return nil, nil, 0, err
	}

	// --- SERVER_AUTH (AEAD-sealed under the server handshake key) ---
	saWire, err := readFrame(raw)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("npamp/sdk: recv SERVER_AUTH: %w", err)
	}
	// WAIT_SA is POST-KEY (the handshake traffic keys cHS/sHS exist), so a fatal reject of
	// the SERVER_AUTH flight seals an ERROR under the CLIENT handshake send key
	// (cHS/DirClientToServer) before teardown. The client has not yet sent CLIENT_AUTH, so
	// its Control send seq under cHS is still 0 — the ERROR takes seq 0.
	sAuth, code, err := openAuthFrame(saWire, npamp.FrameServerAuth, sHS, npamp.DirServerToClient, p)
	if err != nil {
		return nil, nil, 0, emitHandshakeError(raw, cHS, npamp.DirClientToServer, 0, code, p,
			fmt.Errorf("npamp/sdk: open SERVER_AUTH: %w", err))
	}
	t.AddFrameType(npamp.FrameServerAuth)
	t.AddTLV(npamp.TLV{Type: npamp.TLVIdentityKey, Value: sAuth.IdentityKey})
	if err := verifyCertVerify(sAuth.IdentityKey, p, npamp.RoleServer, t.Sum(), sAuth.CertVerify); err != nil {
		return nil, nil, 0, emitHandshakeError(raw, cHS, npamp.DirClientToServer, 0, npamp.ErrCodeDecryptFailed, p,
			fmt.Errorf("npamp/sdk: server CertVerify: %w", err))
	}
	t.AddTLV(npamp.TLV{Type: npamp.TLVCertVerify, Value: sAuth.CertVerify})
	sFinKey, err := npamp.DeriveFinishedKey(sHS, p)
	if err != nil {
		return nil, nil, 0, err
	}
	if err := npamp.VerifyFinished(sFinKey, t.Sum(), sAuth.Finished, p); err != nil {
		return nil, nil, 0, emitHandshakeError(raw, cHS, npamp.DirClientToServer, 0, npamp.ErrCodeDecryptFailed, p,
			fmt.Errorf("npamp/sdk: server Finished: %w", err))
	}
	t.AddTLV(npamp.TLV{Type: npamp.TLVFinished, Value: sAuth.Finished})
	peerID = append([]byte(nil), sAuth.IdentityKey...)

	// Pinned-key check BEFORE CLIENT_AUTH: never authenticate to an impostor.
	if expectedPeer != nil && subtle.ConstantTimeCompare(peerID, expectedPeer) != 1 {
		return nil, nil, 0, fmt.Errorf("npamp/sdk: server identity does not match the pinned key")
	}

	// --- CLIENT_AUTH (AEAD-sealed under the client handshake key) ---
	localPub, err := localIdentityKeyBytes(id, p)
	if err != nil {
		return nil, nil, 0, err
	}
	t.AddFrameType(npamp.FrameClientAuth)
	t.AddTLV(npamp.TLV{Type: npamp.TLVIdentityKey, Value: localPub})
	cCV, err := signCertVerify(id, p, npamp.RoleClient, t.Sum()) // TH_cId
	if err != nil {
		return nil, nil, 0, err
	}
	t.AddTLV(npamp.TLV{Type: npamp.TLVCertVerify, Value: cCV})
	thCCV := t.Sum()
	cFinKey, err := npamp.DeriveFinishedKey(cHS, p)
	if err != nil {
		return nil, nil, 0, err
	}
	cFin := npamp.ComputeFinished(cFinKey, thCCV, p)
	auth := &npamp.AuthMessage{IdentityKey: localPub, CertVerify: cCV, Finished: cFin}
	caWire, err := sealFrame(cHS, npamp.DirClientToServer, npamp.ChanControl, 0, npamp.FrameClientAuth, auth.Encode(), p)
	if err != nil {
		return nil, nil, 0, err
	}
	if err := writeFrame(raw, caWire); err != nil {
		return nil, nil, 0, fmt.Errorf("npamp/sdk: send CLIENT_AUTH: %w", err)
	}

	master, err = npamp.DeriveMasterSecret(hs, thCCV, p)
	if err != nil {
		return nil, nil, 0, err
	}
	return master, peerID, p, nil
}

// runServerHandshake drives the server's side of the 1.5-RTT draft-01 handshake
// over raw, returning the master secret, the peer's authenticated
// identity-key bytes, and the negotiated profile. id.profiles is the
// server's accepted-profile preference order (selectProfile picks the first
// entry also present in the client's ProfileOffer).
func runServerHandshake(ctx context.Context, raw net.Conn, id *localIdentity, expectedPeer []byte) (master []byte, peerID []byte, profile npamp.Profile, err error) {
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
		defer func() { _ = raw.SetDeadline(time.Time{}) }()
	}
	allowed := profilesOrDefault(id.profiles)

	chPayload, err := recvCleartext(raw, npamp.FrameClientHello)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("npamp/sdk: recv CLIENT_HELLO: %w", err)
	}
	ch, err := npamp.DecodeClientHello(chPayload)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("npamp/sdk: decode CLIENT_HELLO: %w", err)
	}
	p, err := requireOffers(ch, allowed)
	if err != nil {
		return nil, nil, 0, err
	}
	// See runClientHandshake's matching comment: the transcript hash depends on the
	// negotiated profile, known here as soon as the server selects it from the offer.
	t := npamp.NewTranscript(p)
	t.AddFrame(npamp.FrameClientHello, ch.TLVs())

	// The KEM group is p.MinKEM() (spec/05_profiles.md): X25519MLKEM768 at Standard,
	// SecP384r1MLKEM1024 at High/Sovereign. requireOffers already confirmed
	// ch.KEMOffer contains this group, so ch.KEMShare is expected to be the matching
	// group's share; Encapsulate/Encapsulate1024 fail closed on a size mismatch.
	var kemCT []byte
	var hs []byte
	switch p.MinKEM() {
	case npamp.KEMSecP384r1MLKEM1024:
		ct, ss, eerr := npamp.Encapsulate1024(ch.KEMShare)
		if eerr != nil {
			return nil, nil, 0, fmt.Errorf("npamp/sdk: KEM-1024 encapsulate: %w", eerr)
		}
		kemCT = ct
		hs, err = npamp.HandshakeSecret1024(ss, p)
		if err != nil {
			return nil, nil, 0, err
		}
	default:
		ct, ss, eerr := npamp.Encapsulate(ch.KEMShare)
		if eerr != nil {
			return nil, nil, 0, fmt.Errorf("npamp/sdk: KEM encapsulate: %w", eerr)
		}
		kemCT = ct
		hs, err = npamp.HandshakeSecret(ss, p)
		if err != nil {
			return nil, nil, 0, err
		}
	}
	sh := &npamp.ServerHello{
		ProfileSelect: p,
		KEMSelect:     p.MinKEM(),
		SigSelect:     sigForProfile(p),
		AEADSelect:    npamp.AEADAES256GCM,
		KEMCiphertext: kemCT,
	}
	if err := sendCleartext(raw, npamp.FrameServerHello, sh.Encode()); err != nil {
		return nil, nil, 0, fmt.Errorf("npamp/sdk: send SERVER_HELLO: %w", err)
	}
	t.AddFrame(npamp.FrameServerHello, sh.TLVs())

	cHS, sHS, err := npamp.DeriveHandshakeTrafficSecrets(hs, t.Sum(), p) // TH_kem
	if err != nil {
		return nil, nil, 0, err
	}

	// --- SERVER_AUTH ---
	localPub, err := localIdentityKeyBytes(id, p)
	if err != nil {
		return nil, nil, 0, err
	}
	t.AddFrameType(npamp.FrameServerAuth)
	t.AddTLV(npamp.TLV{Type: npamp.TLVIdentityKey, Value: localPub})
	sCV, err := signCertVerify(id, p, npamp.RoleServer, t.Sum()) // TH_sId
	if err != nil {
		return nil, nil, 0, err
	}
	t.AddTLV(npamp.TLV{Type: npamp.TLVCertVerify, Value: sCV})
	sFinKey, err := npamp.DeriveFinishedKey(sHS, p)
	if err != nil {
		return nil, nil, 0, err
	}
	sFin := npamp.ComputeFinished(sFinKey, t.Sum(), p) // TH_sCV
	t.AddTLV(npamp.TLV{Type: npamp.TLVFinished, Value: sFin})
	// srvSendSeq tracks the server's Control send sequence under the server handshake key
	// (sHS/DirServerToClient) so a post-key handshake ERROR never reuses a nonce already
	// spent on SERVER_AUTH. SERVER_AUTH is the first such frame (seq 0); a subsequent ERROR
	// at WAIT_CA is therefore seq 1.
	var srvSendSeq uint64
	auth := &npamp.AuthMessage{IdentityKey: localPub, CertVerify: sCV, Finished: sFin}
	saWire, err := sealFrame(sHS, npamp.DirServerToClient, npamp.ChanControl, srvSendSeq, npamp.FrameServerAuth, auth.Encode(), p)
	if err != nil {
		return nil, nil, 0, err
	}
	if err := writeFrame(raw, saWire); err != nil {
		return nil, nil, 0, fmt.Errorf("npamp/sdk: send SERVER_AUTH: %w", err)
	}
	srvSendSeq++ // SERVER_AUTH consumed seq 0; the next sHS/Control send (an ERROR) is seq 1

	// --- CLIENT_AUTH ---
	caWire, err := readFrame(raw)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("npamp/sdk: recv CLIENT_AUTH: %w", err)
	}
	// WAIT_CA is POST-KEY: a fatal reject of the CLIENT_AUTH flight seals an ERROR under the
	// SERVER handshake send key (sHS/DirServerToClient) at srvSendSeq (== 1, since
	// SERVER_AUTH already used seq 0) before teardown.
	cAuth, code, err := openAuthFrame(caWire, npamp.FrameClientAuth, cHS, npamp.DirClientToServer, p)
	if err != nil {
		return nil, nil, 0, emitHandshakeError(raw, sHS, npamp.DirServerToClient, srvSendSeq, code, p,
			fmt.Errorf("npamp/sdk: open CLIENT_AUTH: %w", err))
	}
	t.AddFrameType(npamp.FrameClientAuth)
	t.AddTLV(npamp.TLV{Type: npamp.TLVIdentityKey, Value: cAuth.IdentityKey})
	if err := verifyCertVerify(cAuth.IdentityKey, p, npamp.RoleClient, t.Sum(), cAuth.CertVerify); err != nil {
		return nil, nil, 0, emitHandshakeError(raw, sHS, npamp.DirServerToClient, srvSendSeq, npamp.ErrCodeDecryptFailed, p,
			fmt.Errorf("npamp/sdk: client CertVerify: %w", err))
	}
	t.AddTLV(npamp.TLV{Type: npamp.TLVCertVerify, Value: cAuth.CertVerify})
	thCCV := t.Sum()
	cFinKey, err := npamp.DeriveFinishedKey(cHS, p)
	if err != nil {
		return nil, nil, 0, err
	}
	if err := npamp.VerifyFinished(cFinKey, thCCV, cAuth.Finished, p); err != nil {
		return nil, nil, 0, emitHandshakeError(raw, sHS, npamp.DirServerToClient, srvSendSeq, npamp.ErrCodeDecryptFailed, p,
			fmt.Errorf("npamp/sdk: client Finished: %w", err))
	}
	peerID = append([]byte(nil), cAuth.IdentityKey...)
	if expectedPeer != nil && subtle.ConstantTimeCompare(peerID, expectedPeer) != 1 {
		return nil, nil, 0, fmt.Errorf("npamp/sdk: client identity does not match the pinned key")
	}

	master, err = npamp.DeriveMasterSecret(hs, thCCV, p)
	if err != nil {
		return nil, nil, 0, err
	}
	return master, peerID, p, nil
}

// sendCleartext writes a cleartext handshake HELLO frame (Control channel,
// seq 0, no FlagENC) carrying payload.
func sendCleartext(raw net.Conn, ft npamp.FrameType, payload []byte) error {
	f := npamp.Frame{Type: uint16(ft), Channel: uint16(npamp.ChanControl), Seq: 0, Payload: payload}
	wire, err := f.MarshalBinary()
	if err != nil {
		return err
	}
	return writeFrame(raw, wire)
}

// recvCleartext reads one cleartext HELLO frame, checks its type, and returns
// its payload.
func recvCleartext(raw net.Conn, want npamp.FrameType) ([]byte, error) {
	wire, err := readFrame(raw)
	if err != nil {
		return nil, err
	}
	var f npamp.Frame
	if err := f.UnmarshalBinary(wire); err != nil {
		return nil, err
	}
	if f.Type != uint16(want) {
		return nil, fmt.Errorf("npamp/sdk: got frame type 0x%04x, want 0x%04x", f.Type, uint16(want))
	}
	if f.Flags&npamp.FlagENC != 0 {
		return nil, fmt.Errorf("npamp/sdk: handshake hello frame unexpectedly encrypted")
	}
	return f.Payload, nil
}

// openAuthFrame parses, type-checks, and AEAD-opens an AUTH frame into its AuthMessage.
// On failure it returns the wire ERROR code the total default assigns to that failure
// (draft §State Machine): a structural reject before the AEAD open — a malformed frame, a
// wrong frame type, or a missing FlagENC — is `unexpected_message`; a failure at or after
// the AEAD open — the tag did not verify, or the authenticated plaintext did not decode —
// is `decrypt_failed` (the fatal handshake-authentication failure). The code is only
// meaningful when the returned error is non-nil.
func openAuthFrame(wire []byte, want npamp.FrameType, baseSecret []byte, dir npamp.Direction, p npamp.Profile) (*npamp.AuthMessage, npamp.SessionErrorCode, error) {
	var f npamp.Frame
	if err := f.UnmarshalBinary(wire); err != nil {
		return nil, npamp.ErrCodeUnexpectedMessage, err
	}
	if f.Type != uint16(want) {
		return nil, npamp.ErrCodeUnexpectedMessage, fmt.Errorf("npamp/sdk: got frame type 0x%04x, want 0x%04x", f.Type, uint16(want))
	}
	if f.Flags&npamp.FlagENC == 0 {
		return nil, npamp.ErrCodeUnexpectedMessage, fmt.Errorf("npamp/sdk: AUTH frame is not AEAD-encrypted")
	}
	pt, err := openFrame(&f, baseSecret, dir, p)
	if err != nil {
		return nil, npamp.ErrCodeDecryptFailed, err
	}
	am, err := npamp.DecodeAuthMessage(pt)
	if err != nil {
		return nil, npamp.ErrCodeDecryptFailed, err
	}
	return am, 0, nil
}

// emitHandshakeError is the POST-KEY reaction of the state machine's total default in the
// handshake states WAIT_SA / WAIT_CA (draft {#error-handling}): once a handshake traffic
// key exists, an endpoint that aborts on a fatal reject MUST seal and send an ERROR frame
// (0x0005, Control channel, carrying the code) before it tears the connection down. It
// seals under the local handshake send key (baseSecret on dir) at the given Control send
// seq — which the caller threads so the ERROR never reuses a nonce already spent on an
// AUTH frame in this direction — writes it best-effort, and returns wrapped unchanged. A
// seal or write failure is deliberately swallowed: the endpoint aborts regardless, and the
// original error is what the caller reports. Pre-key states (LISTEN / WAIT_SH) never call
// this — they abort by returning their error, and the peer detects the abort through the
// transport or the handshake-completion timer.
func emitHandshakeError(raw net.Conn, baseSecret []byte, dir npamp.Direction, seq uint64, code npamp.SessionErrorCode, p npamp.Profile, wrapped error) error {
	if wire, err := sealFrame(baseSecret, dir, npamp.ChanControl, seq, npamp.FrameError, npamp.EncodeErrorBody(code, nil), p); err == nil {
		_ = writeFrame(raw, wire)
	}
	return wrapped
}

// requireSelections validates the server's SERVER_HELLO against what this
// client offered: the selected profile must be one this client actually
// offered (offeredProfiles — the server MUST select from the client's
// offered set, spec/05_profiles.md "Negotiation rules"), the selected KEM
// must be BOTH the group this client generated key material for (wantKEM,
// from kemGroupForProfiles — otherwise decapsulation is impossible) AND the
// negotiated profile's minimum KEM (sh.ProfileSelect.MinKEM() —
// spec/05_profiles.md "Minimum KEM"; spec/10 section 4a "Sovereign MUST NOT
// accept X25519MLKEM768"), the selected signature scheme must be the one this
// SDK expects for that profile (sigForProfile), and AEADSelect must match what
// was offered. A mismatched KEM at either check is ErrKEMDowngrade — this is
// the wire-level enforcement of the profile-level downgrade refusal: a client
// that offered High/Sovereign (wantKEM = SecP384r1MLKEM1024) refuses a
// SERVER_HELLO selecting X25519MLKEM768, and any profile/KEM inconsistency a
// deviant peer might construct is refused before any KEM material is touched.
func requireSelections(sh *npamp.ServerHello, offeredProfiles []npamp.Profile, wantKEM npamp.KEMID) error {
	switch {
	case !slices.Contains(offeredProfiles, sh.ProfileSelect):
		return fmt.Errorf("npamp/sdk: server selected profile 0x%02x, which this client did not offer", uint8(sh.ProfileSelect))
	case sh.KEMSelect != wantKEM:
		return fmt.Errorf("%w: server selected KEM 0x%04x, this client generated key material only for 0x%04x", ErrKEMDowngrade, uint16(sh.KEMSelect), uint16(wantKEM))
	case sh.ProfileSelect.MinKEM() != wantKEM:
		return fmt.Errorf("%w: server selected profile %s (minimum KEM 0x%04x) with KEM 0x%04x", ErrKEMDowngrade, sh.ProfileSelect, uint16(sh.ProfileSelect.MinKEM()), uint16(wantKEM))
	case sh.SigSelect != sigForProfile(sh.ProfileSelect):
		return fmt.Errorf("npamp/sdk: server selected signature 0x%04x, want 0x%04x for profile %s", uint16(sh.SigSelect), uint16(sigForProfile(sh.ProfileSelect)), sh.ProfileSelect)
	case sh.AEADSelect != npamp.AEADAES256GCM:
		return fmt.Errorf("npamp/sdk: server selected unsupported AEAD 0x%04x", uint16(sh.AEADSelect))
	}
	return nil
}

// requireOffers validates the client's CLIENT_HELLO against what this server
// accepts (allowedProfiles, the server's preference order), selects the
// profile (selectProfile: the first allowedProfiles entry also present in
// ch.ProfileOffer), and confirms the client offered the KEM group required by
// the selected profile's minimum KEM (p.MinKEM(), spec/05_profiles.md), the
// matching signature scheme, and AEAD. Gating KEMOffer on p.MinKEM() rather
// than a fixed group means the server never selects a profile the client's
// single physical KEMShare cannot serve (ErrKEMDowngrade's server-side
// counterpart: a client that only sent a SecP384r1MLKEM1024 share cannot be
// downgraded to Standard here, because Standard's KEMOffer requirement,
// X25519MLKEM768, would then be absent). It returns the selected profile so
// the caller need not re-derive it.
func requireOffers(ch *npamp.ClientHello, allowedProfiles []npamp.Profile) (npamp.Profile, error) {
	p, err := selectProfile(ch.ProfileOffer, allowedProfiles)
	if err != nil {
		return 0, err
	}
	wantKEM := p.MinKEM()
	switch {
	case !slices.Contains(ch.KEMOffer, wantKEM):
		return 0, fmt.Errorf("npamp/sdk: client did not offer KEM 0x%04x required for profile %s", uint16(wantKEM), p)
	case !slices.Contains(ch.SigOffer, sigForProfile(p)):
		return 0, fmt.Errorf("npamp/sdk: client did not offer signature 0x%04x required for profile %s", uint16(sigForProfile(p)), p)
	case !slices.Contains(ch.AEADOffer, npamp.AEADAES256GCM):
		return 0, fmt.Errorf("npamp/sdk: client did not offer AES-256-GCM")
	}
	return p, nil
}
