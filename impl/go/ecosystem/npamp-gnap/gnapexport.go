// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npampgnap

import "encoding/json"

// Option B: the N-PAMP delegation-EXPORT bridge — export an N-PAMP waypoint authorization
// decision OUT through GNAP as delegation evidence, matching N-AALP's export-only bridge
// design (impl/go/ecosystem/naalp-gnap/gnapclient.go's ExportDelegationEvidence, in the
// naalp_draft-01 repo) and its D15 fail-closed, export-only posture.
//
// # The cross-language contract this file does NOT invent (flagged, not decided here)
//
// naalp-gnap's ExportDelegationEvidence takes an ALREADY-VERIFIED delegation.Resolved leaf
// — a signed, content-addressed N-AALP object (design.md §18, C15) that
// impl/go/delegation.VerifyChain produced by walking a real chain. N-PAMP's analogous
// authorization decision — nz-agent's Rust waypoint::authorize
// (impl/rust/nz-agent/src/waypoint.rs, read directly this build) — has NO such object: it
// is a plain Rust function returning Result<(), WaypointDenied> over an in-memory AuthzHook
// grant table (signer_id -> EffectClass), and EffectClass/WaypointDenied/AuthzHook carry no
// #[derive(Serialize)], no wire encoding, no content-id, and no cross-process/cross-language
// channel today.
//
// So there is nothing for a Go process to decode yet. This file therefore accepts the grant
// ceiling as a DOCUMENTED, CALLER-SUPPLIED Go value (WaypointGrant, below) rather than
// decoding a Rust-produced wire object, and surfaces — rather than silently resolves — the
// choice between two real options for closing that gap later:
//
//   - Option B1 (RECOMMENDED): a SHARED WIRE FORMAT. nz-agent (or a control-plane process
//     that already talks to it) serializes the resolved (signer_id, consuming_authority,
//     max_grant) triple as JSON — matching this ecosystem tree's existing "purely
//     additive, JSON-only, no CBOR/wire touch" convention (doc.go; npamp-discovery and
//     Option A of this very package are both plain-JSON, non-wire tooling already) — and
//     this Go package decodes and independently re-checks it (never trusting a
//     Rust-side "it passed" verdict at face value, mirroring ExportWaypointEvidence's own
//     re-check below). No cgo, no linked binary, no shared address space: nz-agent (a
//     per-node Rust binary, R12.1) and a GNAP-capable control-plane tool (Go ecosystem
//     tooling) already run as separate processes in this architecture, so a JSON handoff
//     over an existing process/IPC/admin-API boundary is the natural shape, not an added
//     one. Smaller diff, no new toolchain coupling, and it keeps each language's crypto
//     and identity primitives in their own runtime (matching this package's existing
//     "reimplements no cryptography" posture).
//   - Option B2: an FFI/linked boundary (cgo calling into nz-agent, or embedding a Go
//     runtime inside the Rust binary). Heavier: it forces nz-agent and this Go tooling
//     into the same address space or adds a cgo dependency this module's
//     zero-external-dependency discipline (doc.go; BubbleFish Policy 1) does not
//     otherwise need, and does not match the separate-process deployment shape above.
//
// This file builds the re-check-and-export logic that is identical under either option —
// WaypointGrant's three fields are exactly what either transport would carry — and leaves
// the transport/decode step (reading a real Rust-emitted JSON payload, or wiring an FFI
// call) for whichever option the maintainer picks. Nothing here fakes that decode step:
// WaypointGrant is constructed by the CALLER, and no function in this file claims to read
// bytes that came from nz-agent.

// EffectClass mirrors nz-agent's Rust EffectClass lattice
// (impl/rust/nz-agent/src/waypoint.rs, read directly this build, not re-derived from
// memory): ReadOnly(0) < IdempotentWrite(1) < NonIdempotentWrite(2) < Destructive(3) — the
// same four-value lattice draft-bubblefish-naalp-01 defines and waypoint.rs itself cites.
// This is a second, LOCAL Go copy of that lattice, symmetric with waypoint.rs's own stance
// ("This crate does NOT depend on the N-AALP repository ... EffectClass ... is this
// crate's own local, composable representation") — this package is, in the same way, its
// own local Go representation, not a type shared by reference with the Rust crate.
type EffectClass uint8

// The four effect classes, ordered exactly as waypoint.rs orders them (Destructive is the
// top of the lattice — a plain integer comparison on EffectClass values reproduces the
// Rust side's derived Ord).
const (
	EffectReadOnly EffectClass = iota
	EffectIdempotentWrite
	EffectNonIdempotentWrite
	EffectDestructive
)

// EffectClassFromWire decodes a wire effect-class octet per the SAME fail-closed rule
// waypoint.rs's EffectClass::from_wire implements: an unrecognized value maps to
// EffectDestructive, never to the least-privileged class — a silent default to ReadOnly
// would fail OPEN, exactly the mistake draft-bubblefish-naalp-01's effect-class field text
// rules out ("An unrecognized effect value MUST be treated as destructive and MUST NOT
// fail open").
func EffectClassFromWire(v uint8) EffectClass {
	switch v {
	case 0:
		return EffectReadOnly
	case 1:
		return EffectIdempotentWrite
	case 2:
		return EffectNonIdempotentWrite
	default:
		return EffectDestructive // includes 3 AND every unrecognized value
	}
}

// String names the effect class using the same lowercase snake_case tokens
// draft-bubblefish-naalp-01 and waypoint.rs's Display impl both use.
func (e EffectClass) String() string {
	switch e {
	case EffectReadOnly:
		return "read_only"
	case EffectIdempotentWrite:
		return "idempotent_write"
	case EffectNonIdempotentWrite:
		return "non_idempotent_write"
	default:
		return "destructive"
	}
}

// AssertionFormatWaypointGrant is the SELF-ASSIGNED "GNAP Assertion Formats" (RFC 9635 §10.6)
// registry value for carrying an N-PAMP waypoint authorization decision — DECIDED 2026-09-02
// (maintainer, decision A; matches naalp-gnap's AssertionFormatDelegationGrant precedent).
// The name is self-assigned now; only the external IANA registration under RFC 9635 §10.6 is
// DEFERRED to post-publish (a frozen, published payload spec is the prerequisite). It carries
// no wire/CDDL/conformance-vector dependency (it never appears in any of those).
const AssertionFormatWaypointGrant = "npamp-waypoint-grant"

// WaypointAssertionPayload is the JSON shape serialized into an Assertion's Value field for
// AssertionFormatWaypointGrant (RFC 9635 §2.4: "value" is "the JSON string serialization of
// the assertion"). Mirrors naalp-gnap's DelegationAssertionPayload where an N-PAMP analog
// exists; two of that sibling's fields have NO analog here and are honestly omitted rather
// than faked:
//
//   - Scope: waypoint.rs's authorize() checks only audience + effect-class, not a
//     resource-scope/path-prefix dimension like N-AALP's DelegationGrant.Scope — N-PAMP's
//     waypoint decision has nothing to narrow there.
//   - ContentID: naalp-gnap's leaf is a COSE-signed, content-addressed envelope a relying
//     party can independently re-verify against; N-PAMP's AuthzHook grant table is
//     unsigned in-memory data with no content-addressable form. A relying party trusting
//     this assertion is therefore trusting THIS BRIDGE's own re-check (below), not an
//     independently re-verifiable signed object — a materially weaker guarantee than
//     naalp-gnap's ContentID-bound export, named here rather than glossed over.
type WaypointAssertionPayload struct {
	// SignerID is the N-PAMP agent identity (the AuthzHook grant-table key, nz-agent's
	// signer_id) this evidence is FOR.
	SignerID string `json:"signer_id"`
	// Audience is the consuming authority this grant is scoped to (waypoint.rs's
	// consuming_authority) — equals the grant's own ConsumingAuthority
	// (ExportWaypointEvidence enforces this, the same WrongAudience check
	// waypoint::authorize performs).
	Audience string `json:"audience"`
	// Effect is the exported effect ceiling's name (EffectClass.String()). It is the
	// REQUESTED ceiling, never higher than the grant's own MaxGrant
	// (ExportWaypointEvidence enforces this via the same lattice comparison
	// waypoint::authorize performs).
	Effect string `json:"effect"`
	// MaxGrant is the underlying grant's full ceiling, carried for transparency so a
	// relying party can see the export did not silently widen against a wider,
	// undisclosed ceiling.
	MaxGrant string `json:"max_grant"`
}

// WaypointGrant is the DOCUMENTED INPUT SHAPE this export bridge requires until the
// cross-language contract in this file's header is decided. It is NOT decoded from a
// Rust-produced wire object today — the caller constructs it directly from whatever
// source already holds the resolved grant (a future JSON handoff under Option B1 above,
// or any other already-trusted source the caller supplies). ExportWaypointEvidence does
// not trust the caller's own pass/fail verdict for that source: it independently
// re-derives BOTH refusal reasons waypoint.rs's authorize() checks (WrongAudience,
// EffectExceedsGrant) from these raw fields, so a caller cannot bypass the ceiling merely
// by claiming success.
type WaypointGrant struct {
	// SignerID is the N-PAMP agent identity this grant was resolved for.
	SignerID string
	// MaxGrant is the effect-class ceiling waypoint.rs's AuthzHook.max_grant_for_signer
	// resolved for SignerID (or EffectReadOnly, mirroring waypoint.rs's own default for
	// an unrecognized signer — see waypoint.rs's authorize(), which never defaults an
	// unrecognized signer to anything ABOVE ReadOnly).
	MaxGrant EffectClass
	// ConsumingAuthority is the waypoint's own identity this grant was resolved against
	// (waypoint.rs's AuthzHook.consuming_authority()) — the value an export's requested
	// audience must equal.
	ConsumingAuthority string
}

// ExportWaypointEvidence is this bridge's sole authority-carrying operation for Option B
// (mirrors naalp-gnap's ExportDelegationEvidence and its D15 export-only posture): given a
// WaypointGrant describing an already-resolved grant ceiling, it serializes EXACTLY that
// ceiling's post-check authority for the requested (audience, effect) pair — never more.
// This is what keeps the bridge EXPORT-ONLY: there is no code path here, or anywhere in
// Client/GrantRequest construction, that lets an external GNAP AS mint NEW N-PAMP
// authority — this function only narrows or reproduces what the grant already specifies,
// and it checks that narrowing itself, independent of whatever the caller claims.
//
// The requested export is rejected ErrAuthorityExport, fail-closed, if EITHER of:
//   - audience does not equal grant.ConsumingAuthority (waypoint.rs's WrongAudience
//     check, reproduced exactly — checked FIRST, matching authorize()'s own ordering:
//     wrong audience is denied before effect is even checked);
//   - requestedEffect exceeds grant.MaxGrant on the four-value lattice (waypoint.rs's
//     EffectExceedsGrant check, reproduced exactly).
func ExportWaypointEvidence(grant WaypointGrant, audience string, requestedEffect EffectClass) (Assertion, error) {
	if audience != grant.ConsumingAuthority {
		return Assertion{}, ErrAuthorityExport
	}
	if requestedEffect > grant.MaxGrant {
		return Assertion{}, ErrAuthorityExport
	}
	payload := WaypointAssertionPayload{
		SignerID: grant.SignerID,
		Audience: audience,
		Effect:   requestedEffect.String(),
		MaxGrant: grant.MaxGrant.String(),
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return Assertion{}, err
	}
	return Assertion{Format: AssertionFormatWaypointGrant, Value: string(b)}, nil
}
