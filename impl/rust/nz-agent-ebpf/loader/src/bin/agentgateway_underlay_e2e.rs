// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Mesh-underlay validation: the SAME `egress_redirect` harness `egress_e2e.rs`
// proves against this crate's OWN test binary, run instead against a REAL,
// UNMODIFIED `agentgateway` process (built from upstream source, no
// agentgateway-side code change) as the workload — proving the zero
// agentgateway-code-change claim: nz-agent's already-built egress_redirect
// eBPF program captures its outbound dial with no changes on the
// agentgateway side.
//
// Unlike `egress_e2e.rs` (which does its OWN `connect()` as the probe), this
// binary does NOT connect anywhere itself. It only:
//   1. loads + attaches `egress_redirect_connect4` to the root cgroup2
//      (`/sys/fs/cgroup`) — CgroupAttachMode::Single means EVERY process on
//      this host's cgroup2 hierarchy is subject to the hook, including a
//      SEPARATE `agentgateway` process started concurrently by the
//      orchestration script, with ZERO agentgateway-side awareness;
//   2. installs ONE authorized waypoint mapping (past the SAME
//      `AuthzTable`/`install_redirect` gate `egress_e2e.rs` uses) from an
//      env-var-supplied DEAD target address to an env-var-supplied waypoint
//      address (in the mesh-underlay design, the waypoint is a real N-PAMP
//      sidecar's plain-HTTP ingress listener — see
//      `impl/go/cmd/n-pamp-proxy`'s INGRESS role; this binary does not care
//      what the waypoint is, only that it is a real, already-listening
//      socket);
//   3. sleeps for an env-var-supplied duration, during which the
//      orchestration script starts `agentgateway` (configured with a
//      `backends: [{host: <the SAME dead target>}]` route) and drives one
//      real HTTP/JSON-RPC request through it;
//   4. reads back `EGRESS_ORIG_DST`'s entry count and `EGRESS_VERDICTS`
//      (steered/steer_failed) — the SAME kernel-side proof egress_e2e.rs and
//      telemetry_bridge_e2e.rs use — and reports whether agentgateway's own
//      outbound dial was actually captured, before exiting (which drops the
//      `aya::Ebpf` handle and detaches the program).
//
// Env vars (all required; no hardcoded defaults, so a human running this
// cannot silently mismatch the orchestration script's own addresses):
//   AGW_DEAD_TARGET   e.g. 127.0.0.7:19994   (must match agentgateway's
//                     configured backend host)
//   AGW_WAYPOINT      e.g. 127.0.0.1:47730   (the n-pamp-proxy INGRESS
//                     -http-listen address, or any other real listener)
//   AGW_HOLD_SECS     e.g. 20                (how long to keep the hook
//                     attached while the orchestration script runs)
//
// Run as root (CAP_BPF + cgroup2 attach on /sys/fs/cgroup).

use std::net::SocketAddrV4;
use std::time::Duration;

use anyhow::Context as _;
use aya::maps::HashMap as AyaHashMap;
use aya::programs::{CgroupAttachMode, CgroupSockAddr};

use nz_agent::authz::AuthzTable;
use nz_agent::datapath::install_redirect;
use nz_agent::identity::SpiffeId;
use nz_agent_ebpf_common::{EgressKey, Waypoint};
use nz_agent_ebpf_loader::{EgressRedirectInstaller, RealAyaEgressBackend};

fn raise_memlock_rlimit() {
    let rlim = libc::rlimit { rlim_cur: libc::RLIM_INFINITY, rlim_max: libc::RLIM_INFINITY };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        eprintln!("warn: setrlimit(RLIMIT_MEMLOCK) failed, ret={ret}");
    }
}

fn id(path: &str) -> SpiffeId {
    SpiffeId::parse(&format!("spiffe://cluster.local/ns/prod/sa/{path}")).expect("valid id")
}

fn env_addr(name: &str) -> anyhow::Result<SocketAddrV4> {
    let raw = std::env::var(name).with_context(|| format!("{name} not set"))?;
    raw.parse::<SocketAddrV4>().with_context(|| format!("{name}={raw:?} is not a valid IPv4 socket address"))
}

fn main() -> anyhow::Result<()> {
    raise_memlock_rlimit();

    let target = env_addr("AGW_DEAD_TARGET")?;
    let waypoint_addr = env_addr("AGW_WAYPOINT")?;
    let hold_secs: u64 = std::env::var("AGW_HOLD_SECS").context("AGW_HOLD_SECS not set")?.parse().context("AGW_HOLD_SECS is not a valid integer")?;

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/egress_redirect"))).context("Ebpf::load")?;
    {
        let prog: &mut CgroupSockAddr = ebpf.program_mut("egress_redirect_connect4").context("find connect4 program")?.try_into()?;
        prog.load().context("connect4.load()")?;
        let cg = std::fs::File::open("/sys/fs/cgroup").context("open /sys/fs/cgroup (root cgroup2)")?;
        prog.attach(cg, CgroupAttachMode::Single).context("connect4.attach()")?;
        println!("AGW-E2E: egress_redirect_connect4 loaded + attached to /sys/fs/cgroup (whole-host root cgroup2 -- catches ANY process, including a separately-started agentgateway)");
    }
    let waypoints: AyaHashMap<_, EgressKey, Waypoint> = AyaHashMap::try_from(ebpf.take_map("EGRESS_WAYPOINT").context("take EGRESS_WAYPOINT")?)?;
    let orig_dst: AyaHashMap<_, u64, EgressKey> = AyaHashMap::try_from(ebpf.take_map("EGRESS_ORIG_DST").context("take EGRESS_ORIG_DST")?)?;
    let verdicts: aya::maps::PerCpuArray<_, u64> = aya::maps::PerCpuArray::try_from(ebpf.take_map("EGRESS_VERDICTS").context("take EGRESS_VERDICTS")?)?;

    let backend = RealAyaEgressBackend::new(waypoints);
    let mut installer = EgressRedirectInstaller::new(backend);
    let source = id("agw-underlay-src");
    let destination = id("agw-underlay-dst");
    installer.register_destination(destination.clone(), target, waypoint_addr);
    let mut authz = AuthzTable::new();
    authz.allow(source.clone(), destination.clone());
    install_redirect(&mut installer, &source, &destination, &authz).context("install authorized waypoint")?;
    println!("AGW-E2E: installed EGRESS_WAYPOINT[{target}] -> {waypoint_addr} (real bpf() map write, past the authz gate)");
    println!("AGW-E2E: holding attachment for {hold_secs}s -- orchestration script should now start agentgateway (backend host={target}) and drive a request through it");

    std::thread::sleep(Duration::from_secs(hold_secs));

    let n = orig_dst.iter().count();
    let steered: u64 = verdicts.get(&0, 0)?.iter().sum();
    let steer_failed: u64 = verdicts.get(&1, 0)?.iter().sum();
    println!("AGW-E2E: EGRESS_ORIG_DST holds {n} entry/entries; EGRESS_VERDICTS steered={steered} steer_failed={steer_failed}");
    if n >= 1 && steered >= 1 {
        println!(
            "AGW-E2E: RESULT=CONFIRMED -- a process's real connect() to {target} was captured by egress_redirect_connect4 and \
             stashed in EGRESS_ORIG_DST/EGRESS_VERDICTS with ZERO code change to that process. If the orchestration script's \
             agentgateway process was the only thing dialing {target} during the hold window, this is agentgateway's own \
             unmodified outbound dial being redirected."
        );
    } else {
        println!(
            "AGW-E2E: RESULT=NOT-CONFIRMED -- no captured connect() to {target} was observed during the {hold_secs}s hold \
             window (EGRESS_ORIG_DST={n} entries, steered={steered}). Either nothing dialed {target}, or the redirect did \
             not fire."
        );
    }
    Ok(())
}
