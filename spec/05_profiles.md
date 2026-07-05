# N-PAMP-01 — Profile Negotiation (reference)

> **Derived extract.** Authoritative source: `../ietf/draft-bubblefish-npamp-latest.md`
> (revision draft-bubblefish-npamp-01; integrity pinned in ../PIN.json), §6 "Profile Negotiation". The draft governs.
> Machine-readable: `../registries/profiles.csv`.

N-PAMP defines **three** security profiles. They share one wire format and differ
only in cryptographic primitives and operational requirements. Each is an
escalation of the previous.

| Profile | Code | Summary |
|---|---|---|
| Standard | 0x01 | Baseline hybrid post-quantum security. |
| High | 0x02 | Stronger KEM parameters and stronger hash; downgrade refusal to Standard. |
| Sovereign | 0x03 | Highest standard-crypto strength; downgrade refusal below Sovereign. |

**Profile code points `0x00` and `0x04`–`0xFF` are reserved by this specification.**

## Profile invariants

| Property | Standard | High | Sovereign |
|---|---|---|---|
| Minimum KEM | X25519MLKEM768 | X25519MLKEM1024 | X25519MLKEM1024 |
| Allowed signatures | Ed25519 | Ed25519, ML-DSA-87 | ML-DSA-87 |
| KDF hash | SHA-256 | SHA-384 | SHA-384 |
| Per-frame AEAD diversification | Off | On | On |
| Downgrade refusal | Off | Refuses Standard | Refuses below Sovereign |
| Mandatory key update | Yes | Yes (tighter bounds) | Yes (tightest bounds) |

## Negotiation rules

- The profile is **offered by the client and selected by the server** during the
  handshake, and is carried in the handshake transcript. Because the profile is
  part of the transcript the Finished MAC covers, stripping a profile from the
  offer or forcing a lower selection invalidates the MAC and aborts the handshake.
- The server **MUST select a profile from the client's offered set**. The selected
  profile MUST be **no lower than the server's configured minimum acceptable peer
  profile**.
- A Sovereign server whose minimum acceptable peer profile is Sovereign completes a
  handshake only when the client offers Sovereign and Sovereign is selected.
- A High or Sovereign endpoint MAY interoperate with a lower-profile peer for
  read-only or capability-discovery operations when local policy permits, by
  accepting a lower selected profile; otherwise it refuses the downgrade.
