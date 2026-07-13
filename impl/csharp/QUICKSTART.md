# N-PAMP draft-01 — C# quickstart

`impl/csharp` is the C# port of the **OPEN-protocol reference library** for N-PAMP
`draft-bubblefish-npamp-01`: the wire-format and cryptographic *primitives*. Standard profile only
(SHA-256, X25519MLKEM768, Ed25519, AES-256-GCM). The core (`Npamp.cs`) is BCL-only
(`System.Security.Cryptography`); the handshake layer (`Handshake.cs`) additionally needs
**BouncyCastle.Cryptography 2.6.2** for Ed25519, which the .NET BCL does not provide.

## What this port provides

Namespace `Sh.Bubblefish.Npamp`:

- **`Npamp.cs`** — the frame codec (36-octet header: magic `NPAM`, version, flags, type, channel,
  seq, CRC32C: `Frame.Marshal` / `Frame.Unmarshal` / `Frame.HeaderPrefix`, plus `Crc32c`), the
  AES-256-GCM record layer (`SealAes256Gcm` / `OpenAes256Gcm` / `DeriveNonce`, AAD = the 21-octet
  header prefix), the HKDF key schedule (`HkdfExtract` / `HkdfExpandLabel` with the `"n-pamp "`
  label prefix, `DeriveTrafficSecret`, `DeriveKeyIv`, and the key-schedule trunk `HandshakeSecret`
  / `DeriveClientHandshakeSecret` / `DeriveServerHandshakeSecret` / `DeriveMasterSecret` /
  `DeriveFinishedKey`, binding `spec/10` §5), and the registry code points.
- **`Handshake.cs`** (binding `spec/10`) — `Transcript` (§3), `ComputeFinished` / `VerifyFinished`
  (§6.2), and `SignCertVerify` / `VerifyCertVerify` (§6.1, Ed25519 via BouncyCastle).
- **`Vectors.cs`** — the cross-language conformance-vector generator (the `Npamp.csproj` entry
  point).

(High / Sovereign profiles, ML-KEM-1024, and ML-DSA-87 are out of scope for this open module.)

## What this port does NOT provide

- **KEM operations** — no X25519MLKEM768 encapsulation/decapsulation; the key-schedule trunk takes
  the two KEM shared secrets as inputs.
- A **TCP/TLS transport** (ALPN `n-pamp/2`), connection management, or an RPC/MCP client. Those live
  in a consuming product, which composes primitives like these with its own
  handshake + transport.

## Install

Either of:

- The **.NET 8 SDK** (`dotnet build` path — used by CI), or
- The **.NET 8 runtime + VS Build Tools** (Roslyn `csc.exe` fallback — every script in this port
  auto-detects which path is available).

The handshake KAT script fetches BouncyCastle.Cryptography 2.6.2 from the local NuGet cache or
nuget.org.

## Run the tests

From `impl/csharp`. Everything is built in a **temp dir from an explicit file list** (this port's
convention), so no `bin/`/`obj/` lands in the source tree:

```
pwsh test/build-handshake-kat.ps1     # the four handshake KATs (spec/10 §3, §5, §6.2, §6.1):
                                      # TranscriptKat, FinishedKat, CertVerifyKat, KeyScheduleKat —
                                      # three-leg ANCHOR/ORACLE/IMPL against the pinned vectors in
                                      # ../../test-vectors/v1/ (SHA-256-checked; exit 0 iff ALL PASS)
```

The conformance suite (`test/ConformanceTest.cs`: 4 golden vectors + 5 property tests, BCL-only) is
run by `build-local.ps1`, which also byte-compares the vector generator against
`_shared/conformance-vectors/vectors.json` — a corpus that is **not included in this open reference
repository**, so `build-local.ps1` as a whole runs only where that is provided. On
an SDK host CI instead builds a throwaway copy and runs the dll (see the `csharp` blocks in
`_conformance-harness/`); on a host without that corpus you can compile `Npamp.cs` +
`test/ConformanceTest.cs` with `csc -main:Sh.Bubblefish.Npamp.ConformanceTest` and run the dll —
it prints one `ok`/`FAIL` line per check and ends with `ALL PASS (9/9)`.

Also not shipped here: `test/KatAesGcm.cs` (Project Wycheproof AES-256-GCM verdicts) needs the
externally-provided `aesgcm_kat.tsv` corpus.

## Run the example

`examples/SecureRecordLayer.cs` composes the key schedule + record layer + frame codec into one
send → receive round-trip (a C# mirror of the Go `Example_secureRecordLayer`, BCL-only):

```
pwsh examples/build-example.ps1
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
