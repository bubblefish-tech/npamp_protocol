# N-PAMP draft-00 — Java quickstart

`impl/java` is the Java port of the **OPEN-protocol reference library** for N-PAMP
`draft-bubblefish-npamp-00`: the wire-format and cryptographic *primitives*. Standard profile only
(SHA-256, X25519MLKEM768, Ed25519, AES-256-GCM). Dependency-free — everything is built on the JDK
(`javax.crypto`, `java.security`); there is no Maven/Gradle build, just `javac`.

## What this port provides

`src/main/java/sh/bubblefish/npamp/`:

- **`Npamp.java`** — the frame codec (36-octet header: magic `NPAM`, version, flags, type, channel,
  seq, CRC32C: `Frame.marshal` / `Frame.unmarshal` / `Frame.headerPrefix`, plus `crc32c`), the
  AES-256-GCM record layer (`sealAes256Gcm` / `openAes256Gcm` / `deriveNonce`, AAD = the 21-octet
  header prefix), the HKDF key schedule (`hkdfExtract` / `hkdfExpand` / `hkdfExpandLabel` with the
  `"n-pamp "` label prefix, `deriveTrafficSecret`, `deriveKeyIv`), and the registry code points.
- **`Handshake.java`** (binding `spec/10`) — `Transcript` (§3), the key-schedule trunk
  `deriveHandshakeSecret` / `deriveClientHandshakeSecret` / `deriveServerHandshakeSecret` /
  `deriveMasterSecret` / `deriveFinishedKey` (§5), `computeFinished` / `verifyFinished` (§6.2), and
  `signCertVerify` / `verifyCertVerify` (§6.1, Ed25519 via the JDK's `EdDSA` provider).
- **`Vectors.java`** — the cross-language conformance-vector generator (`main` emits JSON).

(High / Sovereign profiles, ML-KEM-1024, and ML-DSA-87 are out of scope for this open module.)

## What this port does NOT provide

- **KEM operations** — no X25519MLKEM768 encapsulation/decapsulation; the key-schedule trunk takes
  the two KEM shared secrets as inputs.
- A **TCP/TLS transport** (ALPN `n-pamp/2`), connection management, or an RPC/MCP client. Those live
  in a consuming product, which composes primitives like these with its own
  handshake + transport.

## Install

A JDK whose `java.security` providers include `EdDSA` (Ed25519) — the case for current standard
OpenJDK distributions (verified with OpenJDK 21). No build tool and no third-party jars.

## Run the tests

From `impl/java`, compile everything to a scratch dir, then run each test's `main`:

```
javac -d out src/main/java/sh/bubblefish/npamp/*.java src/test/java/sh/bubblefish/npamp/*.java

java -cp out sh.bubblefish.npamp.ConformanceTest   # 4 golden vectors + 5 property tests
java -cp out sh.bubblefish.npamp.TranscriptKat     # handshake KATs (spec/10 §3, §5, §6.2, §6.1) —
java -cp out sh.bubblefish.npamp.KeyScheduleKat    # three-leg ANCHOR/ORACLE/IMPL against the
java -cp out sh.bubblefish.npamp.FinishedKat       # pinned vectors in ../../test-vectors/v1/
java -cp out sh.bubblefish.npamp.CertVerifyKat
```

Each prints one `ok`/`FAIL` line per check, ends with `ALL PASS`, and exits non-zero on any
failure. The KATs locate `test-vectors/v1` by walking up from the working directory (an explicit
path as `args[0]` overrides); the pinned vectors are SHA-256-checked inside each test (fail-loud on
a swapped vector).

Two further checks need corpora that are **not included in this open reference repository** and are
runnable only where those corpora are provided:

- `java -cp out sh.bubblefish.npamp.KatAesGcmWycheproof <aesgcm_kat.tsv>` — Project Wycheproof
  AES-256-GCM verdicts (`KatHkdf` is the HKDF companion).
- `java -cp out sh.bubblefish.npamp.Vectors` — emits the cross-language conformance vectors as JSON
  for the byte-compare drift gate (`_conformance-harness/run-all-langs.sh`). The generator itself
  runs anywhere; only the byte-compare needs the externally-provided `vectors.json`.

## Run the example

`examples/SecureRecordLayer.java` composes the key schedule + record layer + frame codec into one
send → receive round-trip (a Java mirror of the Go `Example_secureRecordLayer`):

```
javac -d out src/main/java/sh/bubblefish/npamp/Npamp.java examples/SecureRecordLayer.java
java  -cp out SecureRecordLayer
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
