# N-PAMP draft-01 — PHP quickstart

`impl/php` is the PHP port of the **OPEN-protocol reference library** for N-PAMP
`draft-bubblefish-npamp-01`: the wire-format and cryptographic *primitives*. Standard profile only
(SHA-256, X25519MLKEM768, Ed25519, AES-256-GCM). Pure PHP with no Composer dependencies — crypto
comes from `ext-openssl` (AES-256-GCM) and `ext-sodium` (Ed25519); CRC32C is hand-rolled (PHP's
built-in `crc32()` computes the IEEE polynomial and MUST NOT be used).

## What this port provides

The single file `src/Npamp.php` (namespace `Sh\Bubblefish\Npamp`) defines:

- **Frame codec** (`Frame`) — the 36-octet header (magic `NPAM`, version, flags, type, channel,
  seq, CRC32C) + payload: `Frame::marshal` / `Frame::unmarshal` / `Frame::headerPrefix`, plus
  `Npamp::crc32c`.
- **AES-256-GCM record layer** — `Npamp::sealAes256Gcm` / `Npamp::openAes256Gcm` /
  `Npamp::deriveNonce`, using the 21-octet header prefix as AEAD associated data.
- **HKDF key schedule** — `Npamp::hkdfExtract`, `Npamp::hkdfExpandLabel` (RFC 9846 §7.1 with the
  `"n-pamp "` label prefix), `Npamp::deriveTrafficSecret`, `Npamp::deriveKeyIv`, and the
  key-schedule trunk `deriveHandshakeSecret` / `deriveClientHandshakeSecret` /
  `deriveServerHandshakeSecret` / `deriveMasterSecret` / `deriveFinishedKey` (binding `spec/10` §5).
- **Handshake-binding primitives** (binding `spec/10`) — `Transcript` (§3),
  `Handshake::computeFinished` / `Handshake::verifyFinished` (§6.2), and
  `Handshake::signCertVerify` / `Handshake::verifyCertVerify` (§6.1, Ed25519 via `ext-sodium`).
- **Registry code points** — channel / frame-type / TLV / KEM / AEAD / signature constants.

(High / Sovereign profiles, ML-KEM-1024, and ML-DSA-87 are out of scope for this open module.)

## What this port does NOT provide

- **KEM operations** — no X25519MLKEM768 encapsulation/decapsulation; the key-schedule trunk takes
  the two KEM shared secrets as inputs.
- A **TCP/TLS transport** (ALPN `n-pamp/3`), connection management, or an RPC/MCP client. Those live
  in a consuming product, which composes primitives like these with its own
  handshake + transport.

## Install

PHP CLI with `ext-openssl` enabled (verified with PHP 8.5). `ext-sodium` ships bundled with PHP and
is needed only for the CertVerify (Ed25519) KAT — that test tries to `dl()` it if it is not
enabled in `php.ini`, and exits with a clear message if unavailable. No Composer packages.

## Run the tests

From `impl/php`:

```
php test/ConformanceTest.php     # 4 golden vectors + 5 property tests
php test/transcript_kat.php     # handshake KATs (spec/10 §3, §5, §6.2, §6.1) —
php test/key_schedule_kat.php   # three-leg ANCHOR/ORACLE/IMPL against the
php test/finished_kat.php       # pinned vectors in ../../test-vectors/v1/
php test/certverify_kat.php
```

Each prints one `ok`/`FAIL` line per check, ends with `ALL PASS`, and exits non-zero on any
failure. The pinned KAT vectors are SHA-256-checked inside each test (fail-loud on a swapped
vector).

Two further checks need corpora that are **not included in this open reference repository** and are
runnable only where those corpora are provided:

- `php test/kat_aesgcm.php <aesgcm_kat.tsv>` — Project Wycheproof AES-256-GCM verdicts.
- `php bin/npamp-vectors.php` — emits the cross-language conformance vectors as JSON for the
  byte-compare drift gate (`_conformance-harness/run-all-langs.sh`). The generator itself runs
  anywhere; only the byte-compare needs the externally-provided `vectors.json`.

## Run the example

`examples/secure_record_layer.php` composes the key schedule + record layer + frame codec into one
send → receive round-trip (a PHP mirror of the Go `Example_secureRecordLayer`):

```
php examples/secure_record_layer.php
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
