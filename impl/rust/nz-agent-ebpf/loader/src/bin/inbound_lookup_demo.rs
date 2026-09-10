// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// A MAP-LEVEL demonstration for `inbound_lookup`: loads the
// `inbound_lookup` object, attaches `sk_lookup` to this process's own
// network namespace, then uses `InboundLookupInstaller<RealAyaInboundBackend>`
// -- the SAME code path a live `nz-agent` would use -- to (1) install an
// authz-APPROVED listener registration and (2) attempt a DENIED one. Prints
// enough for `bpftool prog show` + `bpftool map show`/`map dump` (run from
// the SAME `wsl` invocation) to independently confirm kernel-side residency.
//
// This is a MAP-LEVEL demo only: it does NOT dial a real connection into the
// registered destination and therefore does NOT witness the kernel's
// `bpf_sk_assign` actually steering a live inbound SYN to the registered
// listener -- that is left to the live end-to-end test (`inbound_lookup_e2e.rs`).

use std::net::{SocketAddrV4, TcpListener};
use std::os::fd::AsRawFd;

use anyhow::Context as _;
use aya::maps::SockHash;
use aya::programs::SkLookup;

use nz_agent::authz::AuthzTable;
use nz_agent::datapath::install_redirect;
use nz_agent::identity::SpiffeId;
use nz_agent_ebpf_common::InboundKey;
use nz_agent_ebpf_loader::{InboundLookupInstaller, RealAyaInboundBackend};

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

fn key_hex(k: InboundKey) -> String {
    let mut bytes = Vec::with_capacity(8);
    bytes.extend_from_slice(&k.dest_ip.to_ne_bytes());
    bytes.extend_from_slice(&k.dest_port.to_ne_bytes());
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

fn main() -> anyhow::Result<()> {
    raise_memlock_rlimit();

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/inbound_lookup"))).context("Ebpf::load")?;
    println!("DEMO: eBPF object loaded into userspace representation: OK");

    {
        let prog: &mut SkLookup = ebpf.program_mut("inbound_lookup_select").context("find sk_lookup program")?.try_into()?;
        prog.load().context("sk_lookup.load()")?;
        let netns = std::fs::File::open("/proc/self/ns/net").context("open /proc/self/ns/net")?;
        prog.attach(netns).context("sk_lookup.attach(netns)")?;
        println!("DEMO: sk_lookup program.load()+attach(/proc/self/ns/net): OK");
    }

    let listeners: SockHash<_, InboundKey> = SockHash::try_from(ebpf.take_map("INBOUND_LISTEN").context("take INBOUND_LISTEN map")?)?;
    println!("DEMO: took INBOUND_LISTEN map: OK");

    let backend = RealAyaInboundBackend::new(listeners);
    let mut installer = InboundLookupInstaller::new(backend);

    // ================= (1) an authz-APPROVED listener =================
    let source = id("peer-any"); // stands in for "any remote peer"
    let destination = id("svc-inbound"); // the service this node fronts

    let agent_listener = TcpListener::bind("127.0.0.1:0").context("bind agent listener")?;
    let dest_addr = SocketAddrV4::new("127.0.0.1".parse().unwrap(), agent_listener.local_addr()?.port());

    installer.register_listener(destination.clone(), &agent_listener, dest_addr);
    let key = installer.key_of(&destination).expect("registered");
    println!("DEMO: registered inbound listener fd={} key={} (dest={dest_addr})", agent_listener.as_raw_fd(), key_hex(key));

    let mut authz = AuthzTable::new();
    authz.allow(source.clone(), destination.clone());
    let token = install_redirect(&mut installer, &source, &destination, &authz).context("install authorized inbound listener")?;
    println!("DEMO: ALLOWED listener installed: source={} destination={} -- real bpf() SockHash::insert performed", token.source(), token.destination());
    println!("DEMO: bpftool-verifiable: INBOUND_LISTEN should hold key [{}]", key_hex(key));

    // ================= (2) a DENIED listener =================
    let source_denied = id("peer-any-denied");
    let destination_denied = id("svc-inbound-denied");
    let other_listener = TcpListener::bind("127.0.0.1:0").context("bind other listener")?;
    let denied_dest_addr = SocketAddrV4::new("127.0.0.1".parse().unwrap(), other_listener.local_addr()?.port());
    installer.register_listener(destination_denied.clone(), &other_listener, denied_dest_addr);
    let denied_key = installer.key_of(&destination_denied).expect("registered");
    let empty_authz = AuthzTable::new(); // no allow(): DENIED
    match install_redirect(&mut installer, &source_denied, &destination_denied, &empty_authz) {
        Ok(_) => anyhow::bail!("BUG: a denied listener installed -- the deny invariant was violated"),
        Err(e) => println!("DEMO: DENIED listener correctly refused: {e}"),
    }
    println!("DEMO: bpftool-verifiable: INBOUND_LISTEN must NOT contain key [{}] (registered but never installed)", key_hex(denied_key));

    println!("DEMO: READY -- sleeping 8s for external bpftool inspection of INBOUND_LISTEN/prog list");
    std::thread::sleep(std::time::Duration::from_secs(8));
    println!("DEMO: exiting; programs/maps detach on drop");
    Ok(())
}
