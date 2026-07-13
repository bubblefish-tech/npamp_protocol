# N-PAMP-01 — ALPN Protocol Identifier (reference)

> **Derived extract.** Authoritative source: `../ietf/draft-bubblefish-npamp-latest.md`
> (revision draft-bubblefish-npamp-01; integrity pinned in ../PIN.json),
> §9.1 "ALPN Protocol Identifier". This file is a structured restatement of that
> section; if any value here disagrees with the draft, **the draft governs.**

## Registration request (RFC 7301 registry, Expert Review)

| Protocol | Identification Sequence | Reference |
|---|---|---|
| N-PAMP, wire major version 2 | `0x6E 0x2D 0x70 0x61 0x6D 0x70 0x2F 0x32` ("n-pamp/2") | draft-bubblefish-npamp-01 |

- The identification sequence is the 8-octet UTF-8 string **`n-pamp/2`**.
- The trailing digit `2` equals the N-PAMP wire major version (the value `0x02`
  carried in the `Ver` field of the frame header).
- Registration policy for the ALPN registry is **Expert Review** (RFC 8126).

## Deprecation

- **`n-pamp/1` is deprecated.** Implementations **SHOULD NOT** negotiate `n-pamp/1`
  for new associations.
- Future wire major versions use distinct ALPN identifiers (for example, `n-pamp/3`).

## Transport binding

N-PAMP runs over **QUIC** (TLS 1.3) as primary transport and **TCP + TLS 1.3** as
fallback. In both cases the application protocol is negotiated with the ALPN
extension (RFC 7301) using `n-pamp/2`.

## Conformance note for implementers

A conforming -00 endpoint offers **only** `n-pamp/2` and rejects any other
negotiated protocol. TLS **1.3 minimum** is required.
