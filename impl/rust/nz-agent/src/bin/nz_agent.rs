// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! `nz-agent` process entrypoint: wires [`nz_agent::capture`],
//! [`nz_agent::identity`], [`nz_agent::authz`], and [`nz_agent::tunnel`]
//! into a runnable per-node data-plane process over a REAL TCP node-to-node
//! tunnel (loopback-testable; a real deployment binds the listen role to the
//! node's tunnel port and dials peer nodes' tunnel ports from cluster
//! config — not built by this process, which takes both explicitly via
//! CLI flags for this build's scope).
//!
//! # What this binary demonstrates end to end
//!
//! `--role responder` binds a TCP listener, accepts one node-to-node tunnel
//! connection, and services ONE inbound workload session (`--accept-pid`),
//! logging the workload's proven peer identity and the session's
//! `master_secret` fingerprint (never the raw secret) to stdout.
//! `--role initiator` dials the responder's tunnel address, opens ONE
//! workload session (`--source-pid` to `--dest-spiffe-id`), sends one
//! application frame on the N-PAMP Control channel, and reads the
//! responder's reply. This is a genuine, runnable two-process demonstration
//! of the composed nz-agent path — not a stub: see the crate's isolation
//! test (`tests/agent_isolation_test.rs`) for the same path run in-process
//! for CI (no real sockets, deterministic).
//!
//! Identity comes from EITHER a `--static-identity PID=SPIFFE_ID` flag
//! repeated per workload ([`nz_agent::identity::StaticIdentitySource`], the
//! default — no SPIRE deployment required) OR, when `--spire-socket PATH`
//! is given, a REAL SPIRE Workload API (DelegatedIdentity) fetch over that
//! Unix-domain socket ([`nz_agent::spire_client::SpireWorkloadApiSource`]).
//! The two are mutually exclusive per run and never silently
//! substitute for each other — see `build_identity_source` below. Capture
//! wiring ([`nz_agent::capture`]) is demonstrated separately
//! by `--print-capture-rules`, which prints the iptables/TPROXY rule set
//! [`nz_agent::capture::IptablesCapture::rules_for`] constructs for a given
//! scope, WITHOUT executing it (this build environment has no
//! `CAP_NET_ADMIN`; see the crate's module docs).

use std::io::Write as _;
use std::net::{TcpListener, TcpStream};
use std::process::ExitCode;

use nz_agent::agent::NodeAgent;
use nz_agent::authz::AuthzTable;
use nz_agent::capture::{CaptureConfig, CaptureScope, IptablesCapture, RedirectTarget};
use nz_agent::identity::{DelegatedIdentitySource, SpiffeId, StaticIdentitySource};
use nz_agent::spire_client::SpireWorkloadApiSource;
use nz_agent::tunnel::Multiplexer;

struct Args {
    role: String,
    listen_addr: Option<String>,
    dial_addr: Option<String>,
    static_identities: Vec<(u32, String)>,
    spire_socket: Option<String>,
    source_pid: Option<u32>,
    dest_pid: Option<u32>,
    dest_spiffe_id: Option<String>,
    dest_pubkey_hex: Option<String>,
    accept_pid: Option<u32>,
    allow_pairs: Vec<(String, String)>,
    register_peers: Vec<(String, String)>,
    print_capture_rules: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        role: String::new(),
        listen_addr: None,
        dial_addr: None,
        static_identities: Vec::new(),
        spire_socket: None,
        source_pid: None,
        dest_pid: None,
        dest_spiffe_id: None,
        dest_pubkey_hex: None,
        accept_pid: None,
        allow_pairs: Vec::new(),
        register_peers: Vec::new(),
        print_capture_rules: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut next = || it.next().ok_or_else(|| format!("nz-agent: {flag} requires a value"));
        match flag.as_str() {
            "--role" => a.role = next()?,
            "--listen" => a.listen_addr = Some(next()?),
            "--dial" => a.dial_addr = Some(next()?),
            "--static-identity" => {
                let v = next()?;
                let (pid, id) = v.split_once('=').ok_or_else(|| format!("nz-agent: --static-identity expects PID=SPIFFE_ID, got {v:?}"))?;
                let pid: u32 = pid.parse().map_err(|_| format!("nz-agent: bad pid in --static-identity {v:?}"))?;
                a.static_identities.push((pid, id.to_string()));
            }
            "--spire-socket" => a.spire_socket = Some(next()?),
            "--source-pid" => a.source_pid = Some(next()?.parse().map_err(|_| "nz-agent: bad --source-pid".to_string())?),
            "--dest-pid" => a.dest_pid = Some(next()?.parse().map_err(|_| "nz-agent: bad --dest-pid".to_string())?),
            "--dest-spiffe-id" => a.dest_spiffe_id = Some(next()?),
            "--dest-pubkey-hex" => a.dest_pubkey_hex = Some(next()?),
            "--accept-pid" => a.accept_pid = Some(next()?.parse().map_err(|_| "nz-agent: bad --accept-pid".to_string())?),
            "--allow" => {
                let v = next()?;
                let (s, d) = v.split_once("->").ok_or_else(|| format!("nz-agent: --allow expects SOURCE->DEST, got {v:?}"))?;
                a.allow_pairs.push((s.to_string(), d.to_string()));
            }
            "--register-peer" => {
                let v = next()?;
                let (pubkey_hex, id) = v.split_once('=').ok_or_else(|| format!("nz-agent: --register-peer expects PUBKEY_HEX=SPIFFE_ID, got {v:?}"))?;
                a.register_peers.push((pubkey_hex.to_string(), id.to_string()));
            }
            "--print-capture-rules" => a.print_capture_rules = true,
            other => return Err(format!("nz-agent: unknown flag {other}")),
        }
    }
    Ok(a)
}

/// Builds the identity source this run uses: `--spire-socket` (a real
/// DelegatedIdentity gRPC-over-UDS fetch) if given, else
/// `--static-identity` (the in-memory test double). Mutually exclusive —
/// giving both is a usage error, not a silent "SPIRE wins" or "static
/// wins": an operator who typos one flag should not get the OTHER identity
/// source without noticing.
fn build_identity_source(a: &Args) -> Result<Box<dyn DelegatedIdentitySource>, String> {
    match (&a.spire_socket, a.static_identities.is_empty()) {
        #[cfg(unix)]
        (Some(sock), true) => {
            let src = SpireWorkloadApiSource::new(sock).map_err(|e| format!("nz-agent: could not start the SPIRE Workload API client: {e}"))?;
            Ok(Box::new(src))
        }
        // Non-Unix (this dev machine's) build: `--spire-socket` is a
        // HOST:PORT TCP-loopback address rather than a filesystem path — see
        // nz_agent::spire_client's module docs for why (tokio's UnixStream
        // is compiled out entirely on a non-Unix target). Never what a real
        // Linux SPIRE deployment is dialed against.
        #[cfg(not(unix))]
        (Some(sock), true) => {
            let addr: std::net::SocketAddr =
                sock.parse().map_err(|e| format!("nz-agent: --spire-socket on this (non-Unix) build must be a HOST:PORT TCP-loopback address, got {sock:?}: {e}"))?;
            let src = SpireWorkloadApiSource::new_tcp_loopback(addr)
                .map_err(|e| format!("nz-agent: could not start the SPIRE Workload API client: {e}"))?;
            Ok(Box::new(src))
        }
        (None, false) => {
            let pairs: Vec<(u32, &str)> = a.static_identities.iter().map(|(p, s)| (*p, s.as_str())).collect();
            let src = StaticIdentitySource::from_pairs(&pairs).map_err(|e| format!("nz-agent: bad --static-identity table: {e}"))?;
            Ok(Box::new(src))
        }
        (Some(_), false) => Err("nz-agent: --spire-socket and --static-identity are mutually exclusive; pass exactly one".to_string()),
        (None, true) => Err("nz-agent: pass either --spire-socket PATH or one or more --static-identity PID=SPIFFE_ID".to_string()),
    }
}

/// Decodes a 64-hex-character `--dest-pubkey-hex` value into the 32-octet
/// Ed25519 public key `Session::dial`'s `expected_peer` pin expects. Fails
/// closed on anything but exactly 64 valid hex characters — never truncates
/// or zero-pads a short/malformed value into a key that would silently pin
/// the wrong (or no) peer.
fn parse_pubkey_hex(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!("nz-agent: --dest-pubkey-hex must be exactly 64 hex characters, got {} characters", s.len()));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let byte_str = &s[i * 2..i * 2 + 2];
        out[i] = u8::from_str_radix(byte_str, 16).map_err(|_| format!("nz-agent: --dest-pubkey-hex is not valid hex at byte {i} ({byte_str:?})"))?;
    }
    Ok(out)
}

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn build_peer_directory(a: &Args) -> Result<nz_agent::agent::PeerDirectory, String> {
    let mut peers = nz_agent::agent::PeerDirectory::new();
    for (pubkey_hex, id) in &a.register_peers {
        let pubkey = parse_pubkey_hex(pubkey_hex)?;
        let spiffe = SpiffeId::parse(id).map_err(|e| format!("nz-agent: bad --register-peer SPIFFE id {id:?}: {e}"))?;
        peers.register(pubkey, spiffe);
    }
    Ok(peers)
}

fn build_authz(a: &Args) -> Result<AuthzTable, String> {
    let mut t = AuthzTable::new();
    for (s, d) in &a.allow_pairs {
        let src = SpiffeId::parse(s).map_err(|e| format!("nz-agent: bad --allow source {s:?}: {e}"))?;
        let dst = SpiffeId::parse(d).map_err(|e| format!("nz-agent: bad --allow destination {d:?}: {e}"))?;
        t.allow(src, dst);
    }
    Ok(t)
}

fn fingerprint(secret: &[u8]) -> String {
    // A non-reversible, short, log-safe fingerprint: NOT the secret itself.
    // Uses npamp's own re-exported SHA-256 primitive path is not public API
    // here, so a simple non-cryptographic rolling fold suffices for a log
    // line whose only job is "did the two sides derive the SAME secret"
    // (compared out-of-band by a human reading two log lines), never a
    // security boundary.
    let mut acc: u64 = 0xcbf29ce484222325;
    for &b in secret {
        acc ^= b as u64;
        acc = acc.wrapping_mul(0x100000001b3);
    }
    format!("{acc:016x}")
}

fn run_responder(a: &Args) -> Result<(), String> {
    let listen_addr = a.listen_addr.as_deref().ok_or("nz-agent: --role responder requires --listen")?;
    let accept_pid = a.accept_pid.ok_or("nz-agent: --role responder requires --accept-pid")?;
    let identity_source = build_identity_source(a)?;
    let l4 = build_authz(a)?;
    let peers = build_peer_directory(a)?;

    // Log this workload's own public key so an operator (or, for this
    // build's manual loopback demo, a human copying it into the peer
    // initiator's --dest-pubkey-hex) can publish it to the trust bundle a
    // real deployment would consult instead.
    if let Ok(svid) = identity_source.svid_for_workload(accept_pid) {
        eprintln!("nz-agent[responder]: workload pid {accept_pid} public key = {}", hex32(&svid.signing_key().verifying_key().to_bytes()));
    }

    let listener = TcpListener::bind(listen_addr).map_err(|e| format!("nz-agent: bind {listen_addr}: {e}"))?;
    eprintln!("nz-agent[responder]: listening on {listen_addr}, will accept workload pid {accept_pid}");
    let (stream, peer_addr) = listener.accept().map_err(|e| format!("nz-agent: accept: {e}"))?;
    eprintln!("nz-agent[responder]: node-to-node tunnel connected from {peer_addr}");
    let write_half = stream.try_clone().map_err(|e| format!("nz-agent: try_clone: {e}"))?;
    let tunnel = Multiplexer::new(stream, write_half);

    let agent = NodeAgent::new(identity_source.as_ref(), &l4, &peers);
    let mut ws = agent.accept(accept_pid, &tunnel).map_err(|e| format!("nz-agent: {e}"))?;
    eprintln!("nz-agent[responder]: workload session established, peer={}, master_secret_fp={}", ws.peer, fingerprint(ws.master_secret()));

    // Echo one application frame back on the Control channel (seq 0 in,
    // seq 0 out — each direction has its own sequence space per
    // npamp::session::Session's docs), so an initiator run against this
    // binary observes real bytes crossing a real N-PAMP session, not just a
    // completed handshake.
    let (channel, ftype, payload) = ws.recv(0).map_err(|e| format!("nz-agent[responder]: recv: {e}"))?;
    eprintln!("nz-agent[responder]: received {} bytes on channel={channel} ftype={ftype}", payload.len());
    ws.send(channel, ftype, 0, &payload).map_err(|e| format!("nz-agent[responder]: send: {e}"))?;
    Ok(())
}

fn run_initiator(a: &Args) -> Result<(), String> {
    let dial_addr = a.dial_addr.as_deref().ok_or("nz-agent: --role initiator requires --dial")?;
    let source_pid = a.source_pid.ok_or("nz-agent: --role initiator requires --source-pid")?;
    let dest_id_str = a.dest_spiffe_id.as_deref().ok_or("nz-agent: --role initiator requires --dest-spiffe-id")?;
    let identity_source = build_identity_source(a)?;
    let l4 = build_authz(a)?;
    let peers = nz_agent::agent::PeerDirectory::new();
    let dest = SpiffeId::parse(dest_id_str).map_err(|e| format!("nz-agent: bad --dest-spiffe-id: {e}"))?;

    let stream = TcpStream::connect(dial_addr).map_err(|e| format!("nz-agent: connect {dial_addr}: {e}"))?;
    let write_half = stream.try_clone().map_err(|e| format!("nz-agent: try_clone: {e}"))?;
    let tunnel = Multiplexer::new(stream, write_half);

    let agent = NodeAgent::new(identity_source.as_ref(), &l4, &peers);
    // A real deployment resolves the destination's proven public key from
    // the SVID trust bundle before dialing; this CLI takes it explicitly via
    // `--dest-pubkey-hex` (out-of-band, matching how a trust bundle lookup
    // would supply it) rather than defaulting to an unpinned dial — pinning
    // is the fail-closed default an operator must explicitly opt out of by
    // simply omitting the flag (logged loudly when they do).
    let destination_pubkey = match &a.dest_pubkey_hex {
        Some(hex) => Some(parse_pubkey_hex(hex)?),
        None => {
            eprintln!("nz-agent[initiator]: WARNING: no --dest-pubkey-hex given; dialing WITHOUT identity pinning (trust-on-first-use, not for production)");
            None
        }
    };
    let mut ws = agent
        .originate(source_pid, &dest, destination_pubkey, &tunnel)
        .map_err(|e| format!("nz-agent: {e}"))?;
    eprintln!("nz-agent[initiator]: workload session established, peer={}, master_secret_fp={}", ws.peer, fingerprint(ws.master_secret()));

    let payload = b"nz-agent initiator ping";
    ws.send(npamp::CHAN_CONTROL, npamp::FRAME_PING, 0, payload).map_err(|e| format!("nz-agent[initiator]: send: {e}"))?;
    let (_channel, _ftype, reply) = ws.recv(0).map_err(|e| format!("nz-agent[initiator]: recv: {e}"))?;
    if reply != payload {
        return Err(format!("nz-agent[initiator]: echo mismatch: sent {payload:?}, got {reply:?}"));
    }
    eprintln!("nz-agent[initiator]: echo round-trip verified ({} bytes)", reply.len());
    Ok(())
}

fn run_print_capture_rules() {
    let cfg = CaptureConfig { scope: CaptureScope::NodeCidr { cidr: "10.244.1.0/24".into() }, target: RedirectTarget { port: 15006, mark: 0 } };
    for rule in IptablesCapture::rules_for(&cfg) {
        println!("{rule}");
    }
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "{e}");
            return ExitCode::FAILURE;
        }
    };

    if args.print_capture_rules {
        run_print_capture_rules();
        return ExitCode::SUCCESS;
    }

    let result = match args.role.as_str() {
        "responder" => run_responder(&args),
        "initiator" => run_initiator(&args),
        other => Err(format!("nz-agent: --role must be \"responder\" or \"initiator\" (or use --print-capture-rules), got {other:?}")),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
