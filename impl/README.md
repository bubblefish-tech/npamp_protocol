# impl/ — multi-language reference implementations

One subdirectory per language (`go/`, `rust/`, `ts/`, …), co-located with the spec
(C2SP model). The Go implementation (`github.com/bubblefish-tech/npamp_protocol/impl/go`) is the primary
reference that consuming products vendor.

**Status: populated.** Each language directory carries the draft-00 wire primitives + conformance
and KAT tests; the cross-language gates live in `_conformance-harness/` — `kat-all-langs.sh`
(AES-GCM Wycheproof), `kat-handshake-all-langs.sh` (transcript / Finished / CertVerify handshake
KATs), and `run-all-langs.sh` (conformance-vector drift). **Build artifacts are excluded** —
`.gitignore` keeps this tree source-only. A consuming product vendors the Go module via a `go.mod`
`replace` directive; repointing that at this open reference is a separate, build-verified operator
step.
