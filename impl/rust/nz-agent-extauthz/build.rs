// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Compiles `proto/ext_authz.proto` into Rust gRPC client+server code via
// tonic-prost-build, WITHOUT invoking a `protoc` binary (none is installed
// on this build machine — confirmed this session). `protox` is a pure-Rust
// protobuf compiler that produces a `FileDescriptorSet` directly from the
// `.proto` text; `tonic_prost_build::Builder::compile_fds` accepts that
// descriptor set in place of the usual protoc-invoking `compile_protos`
// path (both APIs verified against docs.rs/tonic-prost-build 0.14.6 and
// docs.rs/protox 0.9.1 this session).

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/ext_authz.proto");

    let fds = protox::compile(["proto/ext_authz.proto"], ["proto"])?;

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_fds(fds)?;

    Ok(())
}
