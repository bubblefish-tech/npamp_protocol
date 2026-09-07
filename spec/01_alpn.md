# N-PAMP-01 — ALPN Protocol Identifier (reference)

> **Derived extract.** Authoritative source: `../ietf/draft-bubblefish-npamp-latest.md`
> (revision draft-bubblefish-npamp-01; integrity pinned in ../PIN.json),
> §9.1 "ALPN Protocol Identifier". This file is a structured restatement of that
> section; if any value here disagrees with the draft, **the draft governs.**

## Registration request (RFC 7301 registry, Expert Review)

| Protocol | Identification Sequence | Reference |
|---|---|---|
| N-PAMP, crypto generation 3 | `0x6E 0x2D 0x70 0x61 0x6D 0x70 0x2F 0x33` ("n-pamp/3") | (this document) |

- The identification sequence is the 8-octet UTF-8 string **`n-pamp/3`**.
- The trailing digit `3` is the **crypto generation** — the cryptographic
  construction (hybrid combiner order, KEM and signature code points). It is an
  axis independent of the wire-format version: the `Ver` nibble `0x2` in the frame
  header identifies the frame layout and is invariant across generations (see
  decision 0014). A raw frame is not generation-self-describing; the generation is
  fixed by ALPN negotiation, or by explicit configuration where frames are
  exchanged without TLS.
- Registration policy for the ALPN registry is **Expert Review** (RFC 8126).

## Deprecation

- **`n-pamp/1` and `n-pamp/2` are deprecated.** Implementations **SHOULD NOT**
  negotiate them for new associations. `n-pamp/2` identifies the prior crypto
  generation (the original construction of draft-bubblefish-npamp-01), superseded
  by generation 3.
- Each crypto generation uses a distinct ALPN identifier; a future generation would
  use `n-pamp/4`.

## Transport binding

N-PAMP runs over **QUIC** (TLS 1.3) as primary transport and **TCP + TLS 1.3** as
fallback. In both cases the application protocol is negotiated with the ALPN
extension (RFC 7301) using `n-pamp/3`.

## Conformance note for implementers

A conforming endpoint offers **only** `n-pamp/3` and rejects any other
negotiated protocol. TLS **1.3 minimum** is required.
