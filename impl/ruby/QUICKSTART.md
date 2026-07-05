# N-PAMP draft-00 — Ruby quickstart

`impl/ruby` is the Ruby port of the **OPEN-protocol reference library** for N-PAMP
`draft-bubblefish-npamp-00`: the wire-format and cryptographic *primitives*. Standard profile only
(SHA-256, X25519MLKEM768, Ed25519, AES-256-GCM). Pure Ruby on the standard library — crypto comes
from stdlib `openssl` (CRC32C — Castagnoli, poly `0x82F63B78` — is hand-rolled). No gems to
install.

## What this port provides

The single file `lib/npamp.rb` defines module `Npamp`:

- **Frame codec** — the 36-octet header (magic `NPAM`, version, flags, type, channel, seq, CRC32C) +
  payload: `Frame#marshal` / `Frame.unmarshal` / `Frame#header_prefix`, plus `Npamp.crc32c`.
- **AES-256-GCM record layer** — `seal_aes256gcm` / `open_aes256gcm` / `derive_nonce`, using the
  21-octet header prefix as AEAD associated data.
- **HKDF key schedule** — `hkdf_extract`, `hkdf_expand`, `hkdf_expand_label` (RFC 8446 §7.1 with the
  `"n-pamp "` label prefix), `derive_traffic_secret`, `derive_key_iv`, and the key-schedule trunk
  `derive_handshake_secret` / `derive_client_handshake_secret` / `derive_server_handshake_secret` /
  `derive_master_secret` / `derive_finished_key` (binding `spec/10` §5).
- **Handshake-binding primitives** (binding `spec/10`) — `Transcript` (§3), `compute_finished` /
  `verify_finished` (§6.2), and `sign_cert_verify` / `verify_cert_verify` (§6.1, Ed25519 via stdlib
  OpenSSL).
- **Registry code points** — channel / frame-type / TLV / KEM / AEAD / signature constants.

(High / Sovereign profiles, ML-KEM-1024, and ML-DSA-87 are out of scope for this open module.)

## What this port does NOT provide

- **KEM operations** — no X25519MLKEM768 encapsulation/decapsulation; the key-schedule trunk takes
  the two KEM shared secrets as inputs.
- A **TCP/TLS transport** (ALPN `n-pamp/2`), connection management, or an RPC/MCP client. Those live
  in a consuming product, which composes primitives like these with its own
  handshake + transport.

## Install

A Ruby with the stdlib `openssl` extension built against an OpenSSL that provides Ed25519 (verified
with Ruby 4.0.5). Nothing else — no Gemfile, no gems.

## Run the tests

From `impl/ruby` (the tests use `require_relative`, so the working directory does not actually
matter):

```
ruby test/conformance_test.rb    # 4 golden vectors + 5 property tests
ruby test/transcript_kat.rb      # handshake KATs (spec/10 §3, §5, §6.2, §6.1) —
ruby test/key_schedule_kat.rb    # three-leg ANCHOR/ORACLE/IMPL against the
ruby test/finished_kat.rb        # pinned vectors in ../../test-vectors/v1/
ruby test/certverify_kat.rb
```

Each prints one `ok`/`FAIL` line per check, ends with `ALL PASS`, and exits non-zero on any
failure. The pinned KAT vectors are SHA-256-checked inside each test (fail-loud on a swapped
vector).

Two further checks need corpora that are **not included in this open reference repository** and are
runnable only where those corpora are provided:

- `ruby test/kat_aesgcm.rb <aesgcm_kat.tsv>` — Project Wycheproof AES-256-GCM verdicts.
- `ruby bin/npamp_vectors.rb` — emits the cross-language conformance vectors as JSON for the
  byte-compare drift gate (`_conformance-harness/run-all-langs.sh`). The generator itself runs
  anywhere; only the byte-compare needs the externally-provided `vectors.json`.

## Run the example

`examples/secure_record_layer.rb` composes the key schedule + record layer + frame codec into one
send → receive round-trip (a Ruby mirror of the Go `Example_secureRecordLayer`):

```
ruby examples/secure_record_layer.rb
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
