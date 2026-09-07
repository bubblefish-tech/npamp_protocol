# Formal methods — models & proofs

Per the surveyed industry consensus (TLS/QUIC/HPKE all reference formal work externally
rather than vendoring it into the spec repo), this directory holds **models and links**, not
a vendored proof tree.

## Contents

- Links to the analysis tools and external proof artifacts that target the N-PAMP
  n-pamp/3 handshake binding (`spec/10_handshake_binding.md`), with the exact protocol
  revision each model targets.
- A status table: which security property each model establishes, against which draft
  revision, and whether the result is complete or partial (overstated results MUST be
  marked, not glossed).

## Status

**Re-targeted to n-pamp/3.** The prior proof artifacts modeled an earlier protocol
generation, not the current handshake binding, and two overstated their results (one
also used a KEM topology that does not match the wire — a static, pre-shared server
KEM key, rather than the server encapsulating against the client's per-session
ephemeral share). New models targeting the current 1.5-RTT, four-frame,
mutually-authenticated hybrid-PQ handshake (`spec/10_handshake_binding.md`) have been
authored and independently machine-verified by two tools using distinct proof
techniques (Horn-clause resolution and constraint-based multiset rewriting).

| Property | ProVerif | Tamarin |
|---|---|---|
| Secrecy of the application `master` secret | **Verified** | **Verified** (unbounded agent identities) |
| Mutual authentication — client authenticates server (non-injective + injective) | **Verified** | **Verified** |
| Mutual authentication — server authenticates client (non-injective + injective) | **Verified** | **Verified** |
| Downgrade-resistance of the negotiated (profile, KEM, signature, AEAD) tuple | **Verified** (folded into the authentication correspondences, which carry the full negotiated tuple and transcript) | **Verified** (as above) |
| Policy soundness — the Sovereign profile never pairs with the Standard/High-only KEM | **Verified** (unreachable) | **Verified** (unreachable) |

No attack trace was found for any declared property in either tool's pass. A
mutation-based negative control (deleting the client's check of the presented
server identity) confirms the queries are not vacuously true: it correctly
flips secrecy, both client-side authentication queries, and the policy-
soundness query, while correctly leaving the (untouched) server-side
authentication queries unaffected. The formal models are attacker-model
documents (a Dolev-Yao active network attacker), not implementation audits;
they assume long-term identity keys are pre-distributed, and do not cover
post-compromise / forward-secrecy claims for the separate §9 Hybrid Tree
Ratchet extension, which remains KAT-graded rather than formal-methods-graded.
The models and full run logs are maintained in this programme's private
engineering tree (build/audit artifacts are not vendored into this public
repo, per the policy stated above) and are available on request.
