// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// A real-load demonstration: loads `samenode_splice` into the
// kernel, attaches `sock_ops` (cgroup) + `sk_msg` (SPLICE_SOCKS), then uses
// `AyaSpliceInstaller<RealAyaBackend>` — the SAME code path a live
// `nz-agent` would use — to (1) install an authz-APPROVED same-node pair
// and (2) attempt a DENIED pair. Prints enough for `bpftool prog show` +
// `bpftool map show`/`map dump` (run from the SAME `wsl` invocation, per
// this build environment's own reap-on-exit constraint) to independently
// confirm kernel-side residency, then attempts (best-effort; a stretch goal
// beyond the map-level demonstration) an actual data-plane splice: write on
// one leg, read the redirected bytes back on the OTHER leg, with no explicit
// send between them. Run as root (`wsl -u root`) — CAP_BPF + cgroup-attach
// both need it.

use std::fs::File;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::time::Duration;

use anyhow::Context as _;
use aya::maps::{HashMap as AyaHashMap, SockHash};
use aya::programs::{CgroupAttachMode, SkMsg, SockOps};

use nz_agent::authz::AuthzTable;
use nz_agent::datapath::install_splice;
use nz_agent::identity::SpiffeId;
use nz_agent_ebpf_common::ConnKey;
use nz_agent_ebpf_loader::{AyaSpliceInstaller, RealAyaBackend};

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

/// One real, unprivileged, same-node loopback TCP connection: returns the
/// two live sockets that ARE the connection's two ends.
fn loopback_pair() -> anyhow::Result<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind("127.0.0.1:0").context("bind loopback listener")?;
    let addr = listener.local_addr()?;
    let client = TcpStream::connect(addr).context("connect loopback client")?;
    let (accepted, _peer) = listener.accept().context("accept loopback client")?;
    Ok((accepted, client))
}

/// Prints a `ConnKey` as the raw 16 little-endian bytes the kernel's
/// `SPLICE_SOCKS`/`SPLICE_PEER` maps actually store on this (x86_64) host —
/// directly comparable, byte-for-byte, against `bpftool map dump`'s own hex
/// key output.
fn key_hex(k: ConnKey) -> String {
    let mut bytes = Vec::with_capacity(16);
    bytes.extend_from_slice(&k.local_ip.to_ne_bytes());
    bytes.extend_from_slice(&k.remote_ip.to_ne_bytes());
    bytes.extend_from_slice(&k.local_port.to_ne_bytes());
    bytes.extend_from_slice(&k.remote_port.to_ne_bytes());
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

fn main() -> anyhow::Result<()> {
    raise_memlock_rlimit();

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/samenode_splice")))
        .context("Ebpf::load")?;
    println!("DEMO: eBPF object loaded into userspace representation: OK");

    // -- sock_ops: cgroup-attach (passive observer; see ebpf/src/main.rs) --
    {
        let prog: &mut SockOps = ebpf.program_mut("samenode_splice_sockops").context("find sockops program")?.try_into()?;
        prog.load().context("sockops.load()")?;
        let cgroup = File::open("/sys/fs/cgroup").context("open /sys/fs/cgroup (root cgroup2)")?;
        match prog.attach(cgroup, CgroupAttachMode::Single) {
            Ok(_link) => println!("DEMO: sock_ops program.load()+attach(/sys/fs/cgroup): OK"),
            Err(e) => println!("DEMO: sock_ops attach FAILED (non-fatal to the splice path itself): {e:#}"),
        }
    }

    // -- take the two maps BEFORE loading sk_msg, so we can attach it to
    //    SPLICE_SOCKS's real map fd --
    let socks: SockHash<_, ConnKey> = SockHash::try_from(ebpf.take_map("SPLICE_SOCKS").context("take SPLICE_SOCKS map")?)?;
    let peer: AyaHashMap<_, ConnKey, ConnKey> = AyaHashMap::try_from(ebpf.take_map("SPLICE_PEER").context("take SPLICE_PEER map")?)?;
    let sockmap_fd = socks.fd().try_clone().context("clone SPLICE_SOCKS map fd")?;
    println!("DEMO: took SPLICE_SOCKS + SPLICE_PEER maps: OK");

    // -- sk_msg: attach to SPLICE_SOCKS --
    {
        let prog: &mut SkMsg = ebpf.program_mut("samenode_splice_skmsg").context("find sk_msg program")?.try_into()?;
        prog.load().context("sk_msg.load()")?;
        prog.attach(&sockmap_fd).context("sk_msg.attach(SPLICE_SOCKS)")?;
        println!("DEMO: sk_msg program.load()+attach(SPLICE_SOCKS): OK");
    }

    let backend = RealAyaBackend::new(socks, peer);
    let mut installer = AyaSpliceInstaller::new(backend);

    // ================= (1) an authz-APPROVED pair =================
    let workload_a = id("workload-a"); // stands in for the workload<->agent leg
    let workload_b = id("workload-b"); // stands in for the agent<->destination leg
    let (leg_a, _leg_a_far_end) = loopback_pair()?; // agent-side fd we register as workload_a
    let (_leg_b_far_end, leg_b) = loopback_pair()?; // agent-side fd we register as workload_b

    installer.register_socket(workload_a.clone(), &leg_a, leg_a.local_addr()?, leg_a.peer_addr()?)?;
    installer.register_socket(workload_b.clone(), &leg_b, leg_b.local_addr()?, leg_b.peer_addr()?)?;
    let key_a = installer.key_of(&workload_a).expect("registered");
    let key_b = installer.key_of(&workload_b).expect("registered");
    println!("DEMO: registered workload-a fd={} key={}", leg_a.as_raw_fd(), key_hex(key_a));
    println!("DEMO: registered workload-b fd={} key={}", leg_b.as_raw_fd(), key_hex(key_b));

    let mut authz = AuthzTable::new();
    authz.allow(workload_a.clone(), workload_b.clone());
    let token = install_splice(&mut installer, &workload_a, &workload_b, &authz).context("install authorized pair")?;
    println!(
        "DEMO: ALLOWED pair installed: source={} destination={} -- real bpf() SockHash::insert x2 + HashMap::insert x2 performed",
        token.source(),
        token.destination()
    );
    println!(
        "DEMO: bpftool-verifiable: SPLICE_SOCKS should now hold keys [{}] [{}]; SPLICE_PEER should hold {} -> {} and {} -> {}",
        key_hex(key_a),
        key_hex(key_b),
        key_hex(key_a),
        key_hex(key_b),
        key_hex(key_b),
        key_hex(key_a)
    );

    // ================= (2) a DENIED pair =================
    let workload_c = id("workload-c");
    let workload_d = id("workload-d");
    let (leg_c, _leg_c_far_end) = loopback_pair()?;
    let (_leg_d_far_end, leg_d) = loopback_pair()?;
    installer.register_socket(workload_c.clone(), &leg_c, leg_c.local_addr()?, leg_c.peer_addr()?)?;
    installer.register_socket(workload_d.clone(), &leg_d, leg_d.local_addr()?, leg_d.peer_addr()?)?;
    let key_c = installer.key_of(&workload_c).expect("registered");
    let key_d = installer.key_of(&workload_d).expect("registered");
    let empty_authz = AuthzTable::new(); // no allow() for c/d: DENIED
    match install_splice(&mut installer, &workload_c, &workload_d, &empty_authz) {
        Ok(_) => anyhow::bail!("BUG: a denied pair installed — the deny invariant was violated"),
        Err(e) => println!("DEMO: DENIED pair correctly refused: {e}"),
    }
    println!(
        "DEMO: bpftool-verifiable: SPLICE_SOCKS/SPLICE_PEER must NOT contain keys [{}] [{}] (registered but never installed — no backend call was made for this pair)",
        key_hex(key_c),
        key_hex(key_d)
    );

    // ================= (3) stretch: an actual data-plane splice =================
    // Write on leg_a; if the kernel program's redirect worked, the bytes
    // should be directly readable on leg_b — with NOTHING sent over leg_b's
    // own TCP connection, and no explicit copy in this process.
    {
        let payload = b"SPLICE-PROOF";
        let mut leg_a_mut = leg_a.try_clone().context("clone leg_a for write")?;
        leg_a_mut.write_all(payload).context("write on leg_a")?;
        leg_b.set_read_timeout(Some(Duration::from_secs(3)))?;
        let mut leg_b_mut = leg_b.try_clone().context("clone leg_b for read")?;
        let mut buf = [0u8; 64];
        match leg_b_mut.read(&mut buf) {
            Ok(n) if &buf[..n] == payload => {
                println!("DEMO: STRETCH data-plane splice CONFIRMED: {n} bytes written on leg_a arrived verbatim on leg_b's OWN receive queue: {:?}", String::from_utf8_lossy(&buf[..n]));
            }
            Ok(n) => {
                println!("DEMO: STRETCH data-plane splice NOT confirmed: leg_b read {n} bytes not matching the payload -- treat as map-level demonstration only (see report).");
            }
            Err(e) => {
                println!("DEMO: STRETCH data-plane splice NOT confirmed: leg_b read timed out/errored ({e}) -- treat as map-level demonstration only (see report).");
            }
        }
    }

    println!("DEMO: READY -- sleeping 8s for external bpftool inspection of SPLICE_SOCKS/SPLICE_PEER/prog list");
    std::thread::sleep(Duration::from_secs(8));
    println!("DEMO: exiting; programs/maps detach on drop");
    Ok(())
}
