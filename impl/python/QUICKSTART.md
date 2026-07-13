# N-PAMP draft-01 — Python quickstart

`impl/python` is the Python port of the **OPEN-protocol reference library** for N-PAMP
`draft-bubblefish-npamp-01`: the wire-format and cryptographic *primitives*. Standard profile only
(SHA-256, X25519MLKEM768, Ed25519, AES-256-GCM).

## What this port provides

The single module `npamp/__init__.py` exports:

- **Frame codec** — the 36-octet header (magic `NPAM`, version, flags, type, channel, seq, CRC32C) +
  payload: `Frame.marshal` / `Frame.unmarshal` / `Frame.header_prefix`, plus `crc32c`.
- **AES-256-GCM record layer** — `seal_aes256gcm` / `open_aes256gcm` / `derive_nonce`, using the
  21-octet header prefix as AEAD associated data.
- **HKDF key schedule** — `hkdf_extract`, `hkdf_expand`, `hkdf_expand_label` (RFC 8446 §7.1 with the
  `"n-pamp "` label prefix), `derive_traffic_secret`, `derive_key_iv`.
- **Handshake-binding primitives** (binding `spec/10`) — `Transcript` (§3), the key-schedule trunk
  `derive_handshake_secret` / `derive_handshake_traffic_secrets` / `derive_finished_key` (§5),
  `compute_finished` / `verify_finished` (§6.2), and `sign_cert_verify` / `verify_cert_verify` (§6.1,
  Ed25519).
- **Registry code points** — channel / frame-type / TLV / KEM / AEAD / signature constants.

(High / Sovereign profiles, ML-KEM-1024, and ML-DSA-87 are out of scope for this open module.)

## What this port does NOT provide

- **KEM operations** — no X25519MLKEM768 encapsulation/decapsulation; the key-schedule trunk takes
  the two KEM shared secrets as inputs.
- A **TCP/TLS transport** (ALPN `n-pamp/2`), connection management, or an RPC/MCP client. Those live
  in a consuming product, which composes primitives like these with its own
  handshake + transport.

## Install

Python ≥ 3.9 with the [`cryptography`](https://pypi.org/project/cryptography/) package (≥ 42), the
port's only dependency:

```
pip install "cryptography>=42"
```

Or install the module itself from `impl/python`: `pip install -e .`

## Run the tests

All commands run from `impl/python`. The test scripts import the `npamp` package from the working
directory, so set `PYTHONPATH=.` (this mirrors `_conformance-harness/kat-handshake-all-langs.sh`):

```
# bash
PYTHONPATH=. python tests/test_conformance.py       # 4 golden vectors + 5 property tests
PYTHONPATH=. python tests/test_transcript_kat.py    # handshake KATs (spec/10 §3, §5, §6.2, §6.1) —
PYTHONPATH=. python tests/test_key_schedule_kat.py  # three-leg ANCHOR/ORACLE/IMPL against the
PYTHONPATH=. python tests/test_finished_kat.py      # pinned vectors in ../../test-vectors/v1/
PYTHONPATH=. python tests/test_certverify_kat.py
```

```powershell
# PowerShell
$env:PYTHONPATH = "."
python tests/test_conformance.py
```

Each script prints one `PASS`/`FAIL` line per check and exits non-zero on any failure. The pinned
KAT vectors are SHA-256-checked inside each test (fail-loud on a swapped vector).

Two further checks need corpora that are **not included in this open reference repository** and are
runnable only where those corpora are provided:

- `test/kat_aesgcm_wycheproof.py <aesgcm_kat.tsv>` — Project Wycheproof AES-256-GCM verdicts.
- `python npamp_vectors.py` — emits the cross-language conformance vectors as JSON for the
  byte-compare drift gate (`_conformance-harness/run-all-langs.sh`). The generator itself runs
  anywhere; only the byte-compare needs the externally-provided `vectors.json`.

## Run the example

`examples/secure_record_layer.py` composes the key schedule + record layer + frame codec into one
send → receive round-trip (a Python mirror of the Go `Example_secureRecordLayer`):

```
python examples/secure_record_layer.py
```

Expected output:

```
channel=1 seq=0 encrypted=true
recovered: hello over n-pamp
```

## Conformance

The language-agnostic conformance corpus + KAT vectors live in `test-vectors/v1/` (frozen in
`MANIFEST.sha256`). This port is one of the handshake-bearing implementations graded by
`impl/_conformance-harness/kat-handshake-all-langs.sh`; the handshake KATs grade it against NIST/RFC
anchors, non-circularly.

## License

Apache-2.0 — see `LICENSE` / `NOTICE` at the repository root.
