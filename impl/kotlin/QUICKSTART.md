# N-PAMP draft-01 — Kotlin quickstart

`impl/kotlin` is the Kotlin/JVM port of the **OPEN-protocol reference library** for N-PAMP
`draft-bubblefish-npamp-01`: the wire-format and cryptographic *primitives*. Standard profile only
(SHA-256, X25519MLKEM768, Ed25519, AES-256-GCM). Dependency-free beyond the Kotlin standard library
— crypto comes from the JDK (`javax.crypto`, `java.security`); there is no Gradle/Maven build, just
`kotlinc`.

## What this port provides

`src/main/kotlin/sh/bubblefish/npamp/`:

- **`Npamp.kt`** — the frame codec (36-octet header: magic `NPAM`, version, flags, type, channel,
  seq, CRC32C: `Frame.marshal` / `Frame.unmarshal` / `Frame.headerPrefix`, plus `crc32c`), the
  AES-256-GCM record layer (`sealAes256Gcm` / `openAes256Gcm` / `deriveNonce`, AAD = the 21-octet
  header prefix), the HKDF key schedule (`hkdfExtract` / `hkdfExpandLabel` with the `"n-pamp "`
  label prefix, `deriveTrafficSecret`, `deriveKeyIv`, and the key-schedule trunk
  `deriveHandshakeSecret` / `deriveClientHandshakeSecret` / `deriveServerHandshakeSecret` /
  `deriveMasterSecret` / `deriveFinishedKey`, binding `spec/10` §5), and the registry code points.
- **`Handshake.kt`** (binding `spec/10`) — `Transcript` (§3), `computeFinished` / `verifyFinished`
  (§6.2), and `signCertVerify` / `verifyCertVerify` (§6.1, Ed25519 via the JDK's `EdDSA` provider).
- **`Vectors.kt`** — the cross-language conformance-vector generator (`main` emits JSON).

(High / Sovereign profiles, ML-KEM-1024, and ML-DSA-87 are out of scope for this open module.)

## What this port does NOT provide

- **KEM operations** — no X25519MLKEM768 encapsulation/decapsulation; the key-schedule trunk takes
  the two KEM shared secrets as inputs.
- A **TCP/TLS transport** (ALPN `n-pamp/2`), connection management, or an RPC/MCP client. Those live
  in a consuming product, which composes primitives like these with its own
  handshake + transport.

## Install

The Kotlin command-line compiler (`kotlinc`, verified with kotlinc-jvm 2.4.0) on a JDK whose
`java.security` providers include `EdDSA` (Ed25519) — the case for current standard OpenJDK
distributions (verified with OpenJDK 21).

## Run the tests

From `impl/kotlin`, compile main + test sources to a scratch dir, then run each test's `main` on
the JVM with `kotlin-stdlib.jar` on the classpath (on Windows the classpath separator is `;`, on
Unix `:` — `$KOTLIN_HOME/lib/kotlin-stdlib.jar` ships next to `kotlinc`):

```
kotlinc src/main/kotlin src/test/kotlin -d out

java -cp "out:$KOTLIN_HOME/lib/kotlin-stdlib.jar" sh.bubblefish.npamp.ConformanceTest  # 4 golden vectors + 5 property tests
java -cp "out:$KOTLIN_HOME/lib/kotlin-stdlib.jar" sh.bubblefish.npamp.TranscriptKat    # handshake KATs (spec/10 §3, §5,
java -cp "out:$KOTLIN_HOME/lib/kotlin-stdlib.jar" sh.bubblefish.npamp.KeyScheduleKat   # §6.2, §6.1) — three-leg
java -cp "out:$KOTLIN_HOME/lib/kotlin-stdlib.jar" sh.bubblefish.npamp.FinishedKat      # ANCHOR/ORACLE/IMPL against the
java -cp "out:$KOTLIN_HOME/lib/kotlin-stdlib.jar" sh.bubblefish.npamp.CertVerifyKat    # pinned ../../test-vectors/v1/
```

(Note: `KatAesGcm.kt` compiles along with the rest but needs the externally-provided Wycheproof TSV
— see below — so that one test is only runnable where its corpus is vendored.)

Each prints one `ok`/`FAIL` line per check, ends with `ALL PASS`, and exits non-zero on any
failure. The KATs locate `test-vectors/v1` by walking up from the working directory (an explicit
path as `args[0]` overrides); the pinned vectors are SHA-256-checked inside each test (fail-loud on
a swapped vector).

Two further checks need corpora that are **not included in this open reference repository** and are
runnable only where those corpora are provided:

- `java -cp … sh.bubblefish.npamp.KatAesGcm <aesgcm_kat.tsv>` — Project Wycheproof AES-256-GCM
  verdicts.
- `java -cp … sh.bubblefish.npamp.Vectors` — emits the cross-language conformance vectors as JSON
  for the byte-compare drift gate (`_conformance-harness/run-all-langs.sh`). The generator itself
  runs anywhere; only the byte-compare needs the externally-provided `vectors.json`.

## Run the example

`examples/SecureRecordLayer.kt` composes the key schedule + record layer + frame codec into one
send → receive round-trip (a Kotlin mirror of the Go `Example_secureRecordLayer`):

```
kotlinc src/main/kotlin/sh/bubblefish/npamp/Npamp.kt examples/SecureRecordLayer.kt \
    -include-runtime -d secure-record-layer.jar
java -jar secure-record-layer.jar
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
