// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// A MAP-LEVEL demonstration for `egress_redirect`: loads the
// `egress_redirect` object, attaches `cgroup/connect4` + `cgroup/connect6`,
// then uses `EgressRedirectInstaller<RealAyaEgressBackend>` -- the SAME code
// path a live `nz-agent` would use -- to (1) install an authz-APPROVED
// egress waypoint and (2) attempt a DENIED one. Prints enough for
// `bpftool prog show` + `bpftool map show`/`map dump` (run from the SAME
// `wsl` invocation) to independently confirm kernel-side residency.
//
// This is a MAP-LEVEL demo only: it does NOT trigger a real connect() and
// therefore does NOT witness the kernel's own `try_connect4` rewriting a
// live socket's destination, nor confirm which half of `user_port`'s 32
// bits the kernel actually expects the network-order value in -- that is
// left to the live end-to-end test (`egress_e2e.rs`). `EGRESS_ORIG_DST`
// (the kernel-written map) is therefore expected to remain EMPTY here: it
// is only ever populated by the kernel program itself, at a real
// `connect()`, which this demo does not perform.

use std::net::SocketAddrV4;

use anyhow::Context as _;
use aya::maps::HashMap as AyaHashMap;
use aya::programs::{CgroupAttachMode, CgroupSockAddr};

use nz_agent::authz::AuthzTable;
use nz_agent::datapath::install_redirect;
use nz_agent::identity::SpiffeId;
use nz_agent_ebpf_common::{EgressKey, Waypoint};
use nz_agent_ebpf_loader::{waypoint_of, EgressRedirectInstaller, RealAyaEgressBackend};

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

fn key_hex(k: EgressKey) -> String {
    let mut bytes = Vec::with_capacity(8);
    bytes.extend_from_slice(&k.dest_ip.to_ne_bytes());
    bytes.extend_from_slice(&k.dest_port.to_ne_bytes());
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

fn waypoint_hex(w: Waypoint) -> String {
    let mut bytes = Vec::with_capacity(8);
    bytes.extend_from_slice(&w.waypoint_ip.to_ne_bytes());
    bytes.extend_from_slice(&w.waypoint_port.to_ne_bytes());
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

fn main() -> anyhow::Result<()> {
    raise_memlock_rlimit();

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/egress_redirect"))).context("Ebpf::load")?;
    println!("DEMO: eBPF object loaded into userspace representation: OK");

    let cgroup = std::fs::File::open("/sys/fs/cgroup").context("open /sys/fs/cgroup (root cgroup2)")?;

    {
        let prog: &mut CgroupSockAddr = ebpf.program_mut("egress_redirect_connect4").context("find cgroup/connect4 program")?.try_into()?;
        prog.load().context("connect4.load()")?;
        let cg = std::fs::File::open("/sys/fs/cgroup").context("reopen cgroup for connect4")?;
        prog.attach(cg, CgroupAttachMode::Single).context("connect4.attach()")?;
        println!("DEMO: cgroup/connect4 program.load()+attach(/sys/fs/cgroup): OK");
    }
    {
        // Loaded via a second `Ebpf` handle's program lookup would double-load
        // the object; instead look the second program up on the SAME `ebpf`
        // instance (aya supports multiple programs sharing one loaded object,
        // exactly as `samenode_splice`'s sockops+sk_msg pair already does).
        let prog: &mut CgroupSockAddr = ebpf.program_mut("egress_redirect_connect6").context("find cgroup/connect6 program")?.try_into()?;
        prog.load().context("connect6.load()")?;
        prog.attach(cgroup, CgroupAttachMode::Single).context("connect6.attach()")?;
        println!("DEMO: cgroup/connect6 program.load()+attach(/sys/fs/cgroup): OK (fail-closed no-op program)");
    }

    let waypoints: AyaHashMap<_, EgressKey, Waypoint> = AyaHashMap::try_from(ebpf.take_map("EGRESS_WAYPOINT").context("take EGRESS_WAYPOINT map")?)?;
    let orig_dst: AyaHashMap<_, u64, EgressKey> = AyaHashMap::try_from(ebpf.take_map("EGRESS_ORIG_DST").context("take EGRESS_ORIG_DST map")?)?;
    println!("DEMO: took EGRESS_WAYPOINT + EGRESS_ORIG_DST maps: OK");

    let backend = RealAyaEgressBackend::new(waypoints);
    let mut installer = EgressRedirectInstaller::new(backend);

    // ================= (1) an authz-APPROVED destination =================
    let source = id("workload-egress-src");
    let destination = id("workload-egress-dst"); // stands in for "reach 93.184.216.34:443"
    let dest_addr: SocketAddrV4 = "93.184.216.34:443".parse().unwrap();
    let waypoint_addr: SocketAddrV4 = "127.0.0.1:15001".parse().unwrap();

    installer.register_destination(destination.clone(), dest_addr, waypoint_addr);
    let key = installer.key_of(&destination).expect("registered");
    println!("DEMO: registered egress destination key={} (dest={dest_addr})", key_hex(key));

    let mut authz = AuthzTable::new();
    authz.allow(source.clone(), destination.clone());
    let token = install_redirect(&mut installer, &source, &destination, &authz).context("install authorized egress waypoint")?;
    println!("DEMO: ALLOWED destination installed: source={} destination={} -- real bpf() HashMap::insert performed", token.source(), token.destination());
    println!("DEMO: bpftool-verifiable: EGRESS_WAYPOINT should hold key [{}] -> waypoint [{}]", key_hex(key), waypoint_hex(waypoint_of(waypoint_addr)));

    // ================= (2) a DENIED destination =================
    let source_denied = id("workload-egress-src-denied");
    let destination_denied = id("workload-egress-dst-denied");
    let denied_dest_addr: SocketAddrV4 = "203.0.113.9:443".parse().unwrap();
    installer.register_destination(destination_denied.clone(), denied_dest_addr, waypoint_addr);
    let denied_key = installer.key_of(&destination_denied).expect("registered");
    let empty_authz = AuthzTable::new(); // no allow(): DENIED
    match install_redirect(&mut installer, &source_denied, &destination_denied, &empty_authz) {
        Ok(_) => anyhow::bail!("BUG: a denied destination installed -- the deny invariant was violated"),
        Err(e) => println!("DEMO: DENIED destination correctly refused: {e}"),
    }
    println!("DEMO: bpftool-verifiable: EGRESS_WAYPOINT must NOT contain key [{}] (registered but never installed)", key_hex(denied_key));

    println!("DEMO: EGRESS_ORIG_DST entries currently held: {} (expected 0 -- no real connect() was performed by this map-level demo; see module docs)", orig_dst.iter().count());

    println!("DEMO: READY -- sleeping 8s for external bpftool inspection of EGRESS_WAYPOINT/EGRESS_ORIG_DST/prog list");
    std::thread::sleep(std::time::Duration::from_secs(8));
    println!("DEMO: exiting; programs/maps detach on drop");
    Ok(())
}
