# `_conformance-harness/` — cross-language conformance + KAT gates

Independent gates that run the multi-language reference implementations under `impl/` against
authorities that never saw this code, so a shared bug cannot pass. Each gate is a standalone script.

## Gates

- **`kat-handshake-all-langs.sh`** — the draft-00 **handshake** KAT gate. Builds + runs every
  handshake-bearing reference impl against the standards-anchored, NON-CIRCULAR known-answer tests for
  transcript (spec/10 §3), key-schedule (§5), Finished (§6.2), and CertVerify (§6.1), consuming the
  pinned vectors in `test-vectors/v1/{transcript,key-schedule,finished,certverify}-kat.json`. Each
  per-language KAT is three-leg: ANCHOR (FIPS 180-4 / RFC 5869 / RFC 8448 / RFC 4231 / RFC 8032) +
  ORACLE (independent reconstruction) + IMPL. The key-schedule KAT carries the full handshake key
  schedule (HKDF-Extract → `c_hs`/`s_hs`/`master` ladder → `finished_key` + traffic key/iv) in each
  language, binding the AES-256-GCM AEAD code point `0x0001` (per `registries/aead.csv`). Covers the
  nine handshake impls (`typescript, python, rust, java, kotlin, ruby, php, csharp, swift`);
  `swift` (native toolchain, or WSL Ubuntu on a Windows host via `swift/run.sh`) additionally
  executes the KEM-wire KAT (`test-vectors/v1/kem-wire-kat.json`, §4/ADR-0005/0007): the RFC 7748
  X25519 anchor, the ML-KEM-first KEMShare/KEMCiphertext wire order, and the HKDF-Extract IKM order —
  its two ML-KEM-768 legs (NIST `d‖z → ek` keygen; expanded-dk decaps) are explicit, printed SKIPs
  because swift-crypto's `Crypto` product exposes no ML-KEM API (the decaps deferral matches the Go
  reference, ADR-0007). `go` SKIPs here — the Go handshake layer + KATs run under the module's own
  `go test` (`impl/go`), not this cross-language shell harness.
  A language is PASS only on exit 0 **and** its positive pass token; a missing toolchain is
  a tracked SKIP (the summary reports `ran N; skipped …` so an ALL-PASS banner cannot mask zero
  coverage). Each vector is SHA-256-pinned inside the test (fail-loud on a swapped vector). This gate
  is **self-contained** — its vectors are in-tree. Run: `bash kat-handshake-all-langs.sh`.

- **`kat-all-langs.sh`** — the AES-256-GCM record-layer KAT gate: each impl's seal/open must reproduce
  the Google/C2SP **Project Wycheproof** verdicts. NOTE: its corpus
  (`_shared/wycheproof/aesgcm_kat.tsv`) is **not included in this open reference repository**, so this
  gate runs where that corpus is present (a host that vendors it).
  Run: `bash kat-all-langs.sh`.

- **`run-all-langs.sh`** — conformance-vector drift gate: regenerates the conformance vectors from
  every impl and compares them (line-ending-normalized) against `_shared/conformance-vectors/vectors.json`
  (also not included in this open repository). Run: `bash run-all-langs.sh`.

- **`all-gates.sh`** — aggregator: runs every gate above plus the structural JSON-Schema validation
  (`scripts/validate-schemas.py`) and the pin check (`scripts/verify-pins.ps1`) in one pass, with the
  same HONEST ran/skipped accounting as the handshake gate — a gate whose toolchain or externally-provided
  `_shared/` corpus is absent is a tracked SKIP, never a silent green, so `ALL GATES: ALL PASS` counts
  only the gates that actually RAN. Run: `bash all-gates.sh`.

## Notes

- The Go-side handshake KATs run under the Go module's own `go test` in `impl/go`, not through
  this cross-language shell harness.
- `test-vectors/v1/` is the in-tree conformance corpus, SHA-256-pinned via `MANIFEST.sha256` /
  `PIN.json` (recompute-and-compare: `scripts/verify-pins.ps1`). The handshake-KAT gate is fully
  self-contained against it. Each vector also has a draft-2020-12 JSON Schema in `test-vectors/schemas/`
  (itself SHA-256-pinned); `scripts/validate-schemas.py` validates every vector against its schema
  (Python `jsonschema`) — a structural verifier complementary to the byte-pin: it catches a malformed
  vector (missing field, wrong type, non-hex bytes) before the pin is recomputed.
- Toolchain/portability: on MSYS/Cygwin the Kotlin run converts the classpath with `cygpath -m` for
  `java.exe`; the C# handshake build uses `csharp/test/build-handshake-kat.ps1` (a .NET-SDK
  PackageReference path, or a Roslyn-`csc` fallback on hosts with only the runtime).
