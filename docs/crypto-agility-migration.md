# N-PAMP crypto-agility and generation-migration runbook

*Requirement R2.3 acceptance criterion 3:
"The PQC modules SHALL address the documented production gap: versioned key formats,
a crypto-agility/migration runbook, and a hybrid-by-default posture."*

This runbook is the deployment-facing companion to
[`impl/go/keyformat`](../impl/go/keyformat) (the versioned key-storage format) and to
[decisions/adr/0014](../../decisions/adr/0014-certverify-context-and-alpn-track-crypto-generation-decoupled-from-wire-version.md)
(the decision that separated N-PAMP's crypto generation from its wire-format version).
It answers the operational question those two documents leave open: **given that
N-PAMP crypto generations change and code points get re-anchored across them, how does
a real deployment detect that, and what does it do about it?**

## 1. The three axes, and why this document exists

N-PAMP tracks three independent things that a migration can confuse if it treats them
as one:

| Axis | Carrier | Current value | Changes on |
|---|---|---|---|
| Wire-format version | Frame header `Ver` nibble | `0x2` (invariant) | A frame-LAYOUT-breaking change (has not happened since draft-00) |
| Crypto generation | ALPN identifier (live) / `KeyRecord.Generation` (at rest) | `n-pamp/3` | A cryptographically incompatible change (combiner order, code-point re-anchor) — decisions/adr/0014 |
| Profile | `ProfileOffer`/`ProfileSelect` TLV, `registries/profiles.csv` | Standard / High / Sovereign | An operator's own security-posture choice, independent of generation |

The production gap this runbook closes is specifically the crypto-generation axis: an
algorithm code point (an `npamp.KEMID` or `npamp.SigID` value) has **no fixed meaning**
without knowing which generation's registry to read it under. Per decisions/adr/0014,
this is not hypothetical — N-PAMP has already re-anchored code points across a
generation boundary once (the `SigID` values naming ML-DSA-65 vs ML-DSA-87 moved
between `n-pamp/2` and `n-pamp/3`). A migration tool, a key-management system, or an
operator's own audit script that reads a stored key's algorithm field without also
reading its generation field can silently misinterpret it.

## 2. Detection: how a deployment recognizes a generation mismatch

**Live connections** are self-protecting by construction: decisions/adr/0014 fixes the
crypto generation to the negotiated ALPN identifier, and "an endpoint MUST NOT process
frames under a generation it did not negotiate or configure." A `n-pamp/3`-only
endpoint simply fails ALPN negotiation against a peer offering only `n-pamp/2` — there
is no code path where a live session runs under an ambiguous or unstated generation.

**Stored and transported keys** have no ALPN negotiation to anchor them, which is
exactly the gap [`impl/go/keyformat`](../impl/go/keyformat) closes: every versioned key
record carries an explicit `Generation` field (the same ALPN-style token, e.g.
`"n-pamp/3"`), and `keyformat.Decode` refuses to resolve a record's algorithm code
point against any generation the caller has not explicitly opted into
(`ErrGenerationNotAccepted`). Concretely:

```go
// A key-inventory / migration tool opts into BOTH generations so it can find
// old material without misinterpreting it: keyformat has no algorithm/size
// registry for "n-pamp/2" (never implemented in this Go tree), so a record
// under that generation decodes structurally but is returned unvalidated —
// exactly the "detectable, not silently misread" property this runbook needs.
rec, err := keyformat.Decode(storedKeyBytes, npamp.ALPN, "n-pamp/2")
switch {
case errors.Is(err, keyformat.ErrGenerationNotAccepted):
    // A generation neither n-pamp/3 nor n-pamp/2 (a future n-pamp/4, or
    // corruption) — refuse and alert; do not guess.
case err != nil:
    // Malformed record, unregistered algorithm, wrong component sizes, etc.
default:
    if rec.Generation != npamp.ALPN {
        // Found: a key minted under a superseded generation. Flag it for
        // the migration ladder below; do not hand it to a live n-pamp/3
        // handshake path.
    }
}
```

A fleet-wide inventory pass — run `keyformat.Decode` with an accept-list including
every generation the deployment has ever used, over every stored key — is the
detection mechanism this runbook assumes for step 1 of the migration ladder.

## 3. Migration ladder: `n-pamp/2` → `n-pamp/3`

This is the concrete instance of the ladder; the same five steps apply to any future
crypto-incompatible generation bump.

### Step 1 — Inventory

Run the detection pass in section 2 across every key store (HSM-backed, file-backed,
or a key-management service export) the deployment holds. Classify every key by its
`KeyRecord.Generation`. A key already tagged `n-pamp/3` needs no action. A key tagged
`n-pamp/2` (or any older/unrecognized generation) enters the ladder below. A key with
**no** version tag at all (pre-dating this format) cannot be classified automatically —
treat it as untrusted-generation and re-key it (step 3) rather than guessing.

### Step 2 — Dual-stack transition window

Deploy endpoints that offer **both** ALPN identifiers (`n-pamp/3` and `n-pamp/2`)
during a bounded transition window, so already-deployed `n-pamp/2`-only peers keep
working while newly-deployed or newly-rekeyed peers move to `n-pamp/3`.

- An endpoint capable of both generations MUST prefer `n-pamp/3` whenever the peer
  also offers it. Never let a peer capable of `n-pamp/3` be negotiated down to
  `n-pamp/2` — that is a downgrade, not a compatibility accommodation, and the
  Standard/High/Sovereign downgrade-refusal rules in `registries/profiles.csv` are the
  existing mechanism for refusing a profile downgrade; treat a generation downgrade
  with the same suspicion even though it is a separate axis.
- Bound the window. A dual-stack endpoint is carrying the risk of the deprecated
  generation (whatever motivated deprecating it) for as long as the window is open;
  track window closure as an explicit operational milestone, not an indefinite state.
- The transition window is a **deployment-fleet** property, not a protocol
  requirement: N-PAMP has no wire-level "generation negotiation handshake" beyond
  ordinary ALPN — the ladder is operational discipline layered on top of the existing
  mechanism decisions/adr/0014 already defines.

### Step 3 — Re-key under the current generation

Mint new key material under `n-pamp/3` using `keyformat.EncodeKEMPrivate` /
`keyformat.EncodeKEMPublic` / `keyformat.EncodeSigPrivate` / `keyformat.EncodeSigPublic`.
These functions only ever mint records tagged `npamp.ALPN` (`Encode` returns
`ErrGenerationNotAccepted` for any other `Generation` value) — this is a deliberate
safety rail: nothing in this Go reference can accidentally mint a new key that is
already stale on arrival.

Re-keying is the point at which an operator should also revisit the **provider**
question tracked in [`docs/provider-matrix.md`](provider-matrix.md)'s FIPS-boundary
caveat: "ML-KEM is present in the OpenSSL 3.5 library" is a different claim from
"ML-KEM is in a FIPS-140-3-validated OpenSSL module," and a re-key is a natural
checkpoint to confirm which posture the new keys' provider actually delivers for this
deployment's compliance requirements.

### Step 4 — Cutover

Once fleet telemetry confirms every peer negotiates `n-pamp/3` (no live `n-pamp/2`
sessions observed over a monitoring period the operator sets), remove `n-pamp/2` from
the offered ALPN set. Per decisions/adr/0014, the `n-pamp/2` **IANA registration
record itself is not retracted** — it stands as the historical record of a superseded
generation — so cutover is an endpoint-configuration change, not a registry change.

Retain (do not delete) the inventory of `n-pamp/2`-tagged keys from step 1 for the
deployment's own audit-retention period; `keyformat.Decode` remains able to
structurally recognize them (opted into explicitly) for as long as that inventory is
needed, even though this reference never re-gains the ability to validate their
algorithm/size pairing against a generation it does not implement.

### Step 5 — Sunset and rollback

If a defect surfaces after cutover, rollback means **redeploying the pre-cutover
software** to the affected fleet segment (which still carries correct `n-pamp/2`
registry knowledge) and re-opening the dual-stack window (step 2) for that segment —
not asking a `n-pamp/3`-era `keyformat` build to re-implement a retired generation's
registry. This is why `keyformat` keeps every generation's records structurally
decodable indefinitely (section 2): a rollback's first move is always "find out which
keys are on which generation," and that must still work after cutover.

## 4. Hybrid-by-default: already the deployed posture

R2.3's third acceptance-criterion clause — a "hybrid-by-default posture" — is already
satisfied structurally and is confirmed here rather than newly built:
`registries/profiles.csv` defines exactly three profiles (Standard, High, Sovereign),
and **every one of them mandates a hybrid KEM** — Standard uses `X25519MLKEM768`, High
and Sovereign use `SecP384r1MLKEM1024` — per `registries/kem.csv`. No N-PAMP profile
offers a classical-only or a post-quantum-only key exchange. A crypto-agility
migration therefore never has to choose *whether* to run hybrid; it only ever
migrates *which* hybrid generation's combiner and code points are in effect, which is
exactly what this runbook's ladder covers.

## 5. Operational checklist

- [ ] Inventory every key store; classify by `KeyRecord.Generation` (section 2).
- [ ] Confirm the provider posture for any re-keyed material against
      `docs/provider-matrix.md` (library-level vs. FIPS-140-3-validated-module-level).
- [ ] Open the dual-stack transition window; confirm `n-pamp/3` preference is enforced
      end-to-end (no observed downgrade of an `n-pamp/3`-capable peer).
- [ ] Re-key affected material via `keyformat.Encode*` (mints `n-pamp/3` only).
- [ ] Monitor for zero live `n-pamp/2` sessions over the fleet's chosen observation
      window before closing the window.
- [ ] Cutover: remove `n-pamp/2` from the offered ALPN set; retain the step-1
      inventory for the audit-retention period.
- [ ] Record the rollback plan (which pre-cutover build/config to redeploy) *before*
      cutover, not after a defect is found.

## 6. Non-scope

This runbook does not cover: per-language SDK migration mechanics beyond the Go
reference shown here (the same `Generation`-tagged CBOR record and ladder apply to
every language's own key-storage binding; each language's own I/O and key-management
integration is out of scope for this document); ML-DSA operational signing/rotation
procedures (no Go standard-library ML-DSA implementation exists yet to operate one —
see `impl/go/keyformat`'s package documentation); and wire-format-version migrations
(the `Ver` nibble is an invariant per decisions/adr/0014 and has never moved — a future
frame-layout break would need its own runbook, not this one).

## 7. References

- decisions/adr/0014 — crypto generation and wire-format version, decoupled axes.
- `registries/kem.csv`, `registries/signatures.csv`, `registries/profiles.csv` — the
  authoritative code-point and profile registries this runbook and `keyformat` both
  read from.
- `docs/provider-matrix.md` — per-language PQC provider bindings and the FIPS-boundary
  caveat this runbook's re-key step revisits.
- `impl/go/keyformat` — the versioned key-storage format and reference (en/de)coder
  this runbook's detection mechanism and migration commands are built on.
