// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Drives the nightly `-Z build-std=core` / `bpfel-unknown-none` compile of
// `../ebpf` via `aya_build::build_ebpf`, exactly the confirmed-working
// pattern from this machine's own aya smoke test (reproduced, not
// re-derived): resolve the sibling `nz-agent-ebpf-ebpf` package via
// `cargo_metadata`, hand its root dir to `aya_build::build_ebpf`. The
// compiled object lands at `$OUT_DIR/samenode_splice` (the `[[bin]] name`
// in `../ebpf/Cargo.toml`), embedded by `src/lib.rs`/`src/bin/load_demo.rs`
// via `aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/samenode_splice"))`.

use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "nz-agent-ebpf-ebpf")
        .ok_or_else(|| anyhow!("nz-agent-ebpf-ebpf package not found"))?;
    let cargo_metadata::Package { name, manifest_path, .. } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], Toolchain::default())
}
