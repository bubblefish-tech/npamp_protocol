# Formal methods — models & proofs

Per the surveyed industry consensus (TLS/QUIC/HPKE all reference formal work externally
rather than vendoring it into the spec repo), this directory holds **models and links**, not
a vendored proof tree.

## Status

The prior proof artifacts modeled an earlier protocol
generation, not the current handshake binding, and two overstated their results (one
also used a KEM topology that does not match the wire — a static, pre-shared server
KEM key, rather than the server encapsulating against the client's per-session
ephemeral share).
