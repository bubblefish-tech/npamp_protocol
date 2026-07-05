# Formal methods — models & proofs

Per the surveyed industry consensus (TLS/QUIC/HPKE all reference formal work externally
rather than vendoring it into the spec repo), this directory holds **models and links**, not
a vendored proof tree.

## Contents (as they are added)

- Links to the analysis tools and external proof artifacts that target the N-PAMP draft-00
  binding (e.g. Tamarin / ProVerif / CryptoVerif / Alloy / SPIN / DeepSec / Squirrel /
  VerifPal), with the exact protocol revision each model targets.
- A status table: which security property each model establishes, against which draft
  revision, and whether the result is complete or partial (overstated results MUST be
  marked, not glossed).

## Status

**Pending.** The prior proof artifacts modeled an earlier protocol generation, not the draft-00
binding, and two overstated their results. Re-targeting them is gated on the draft-01
handshake-binding spec (so the proofs have a precise, current target). Until then this is a
link-out stub; no proof is claimed here.
