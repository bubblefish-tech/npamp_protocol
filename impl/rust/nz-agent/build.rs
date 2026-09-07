// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Compiles the vendored SPIRE Workload API (DelegatedIdentity) proto subset
// under `proto/` into Rust via tonic-build/prost-build. Uses
// `protoc-bin-vendored` (a bundled `protoc` binary shipped as a crate
// dependency) so this crate's build does not require a system-installed
// `protoc` on any developer machine or CI runner — no new manual toolchain
// step (E2.6, R12 AC2).
//
// `build_server(true)` is intentional even though this crate never runs a
// production DelegatedIdentity SERVER: `spire_client.rs`'s tests stand up an
// in-process mock DelegatedIdentity server over a real Unix-domain-socket
// listener as the non-circular F3 witness for the client's wire behavior
// (no live SPIRE deployment is available in this build environment — see
// `identity.rs`'s module docs).

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc_path = protoc_bin_vendored::protoc_bin_path()?;
    // Safety note (not a footgun here): build scripts run single-threaded,
    // before any of the crate's own code executes, so there is no data race
    // on the process environment at this point.
    unsafe {
        std::env::set_var("PROTOC", protoc_path);
    }

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(
            &["proto/spire/api/agent/delegatedidentity/v1/delegatedidentity.proto"],
            &["proto"],
        )?;

    println!("cargo:rerun-if-changed=proto");
    Ok(())
}
