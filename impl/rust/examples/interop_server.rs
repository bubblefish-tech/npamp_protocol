//! Live N-PAMP interop SERVER (raw TCP).
//!
//! Listens on an address, accepts one connection, completes the server side of the
//! 1.5-RTT mutually-authenticated N-PAMP handshake (binding spec/10) via
//! `npamp::session::Session`, then receives one AEAD-protected application frame on
//! the Memory channel and echoes it back under the server-to-client key.
//! Interoperates with either this crate's interop_client example (Rust<->Rust) or
//! the Go reference harness impl/go/cmd/npamp-interop -role client (Go<->Rust).
//!
//! At `--profile standard` (the default) this drives `Session::accept` — the
//! original Ed25519-only entry point, byte-unchanged. At `--profile high` /
//! `--profile sovereign` this drives the multi-profile entry point
//! `Session::accept_with_profiles` (spec/05_profiles.md; draft-00 section 6)
//! instead, allowing exactly the requested profile and authenticating with a
//! freshly generated ML-DSA-87 identity — the SAME entry point
//! `session.rs`'s own `#[cfg(test)]` module drives over an in-memory pipe,
//! run here for the first time over a real loopback `TcpStream`. Pass the
//! SAME `--profile` value the client uses (`interop_client`'s offered
//! profile and this server's allowed profile must agree, or the handshake is
//! correctly rejected as a downgrade — see `dial_with_profiles`'s docs).
//!
//!   cargo run --example interop_server -- 127.0.0.1:47700 --profile standard
//!   cargo run --example interop_server -- 127.0.0.1:47700 --profile high
//!   cargo run --example interop_server -- 127.0.0.1:47700 --profile sovereign
//!
//! Transport: the N-PAMP handshake is transport-agnostic; this example runs it
//! directly over TCP. The Go SDK's TLS 1.3 (ALPN "n-pamp/3") transport binding is
//! layered by sdk.Dial/Listen and is not exercised here (see `npamp::session` docs).

use npamp::mldsa87;
use npamp::session::{self, Session};
use std::net::TcpListener;
use std::process::exit;

const APP_FRAME_TYPE: u16 = 0x0120; // application-defined frame type

/// Mirrors `interop_client`'s `Profile`: the three profiles
/// `Session::accept_with_profiles` allows (spec/05_profiles.md). Standard still
/// runs through the original `Session::accept` — this enum only selects which
/// entry point + identity material this example builds, never a new wire behavior.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Profile {
    Standard,
    High,
    Sovereign,
}

impl Profile {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "standard" => Some(Profile::Standard),
            "high" => Some(Profile::High),
            "sovereign" => Some(Profile::Sovereign),
            _ => None,
        }
    }

    /// The TLV_PROFILE_OFFER / TLV_PROFILE_SELECT wire byte this profile negotiates as
    /// (`session::PROFILE_STANDARD`/`PROFILE_HIGH`/`PROFILE_SOVEREIGN`).
    fn wire_byte(self) -> u8 {
        match self {
            Profile::Standard => session::PROFILE_STANDARD,
            Profile::High => session::PROFILE_HIGH,
            Profile::Sovereign => session::PROFILE_SOVEREIGN,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Profile::Standard => "standard",
            Profile::High => "high",
            Profile::Sovereign => "sovereign",
        }
    }
}

fn main() {
    let mut addr = "127.0.0.1:47700".to_string();
    let mut profile = Profile::Standard;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--profile" {
            let val = args.next().unwrap_or_default();
            profile = match Profile::parse(&val) {
                Some(p) => p,
                None => {
                    eprintln!("interop_server: unknown --profile {val:?} (expected standard|high|sovereign)");
                    exit(1);
                }
            };
        } else {
            addr = arg;
        }
    }

    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("interop_server: bind {addr}: {e}");
            exit(1);
        }
    };
    let bound = listener.local_addr().map(|a| a.to_string()).unwrap_or(addr.clone());
    println!("interop_server: listening on {bound}");
    println!("interop_server: allowing profile={}", profile.name());

    let identity = session::generate_identity();
    let id_bytes = identity.verifying_key().to_bytes();
    println!("interop_server: identity ed25519 = {}", hex8(&id_bytes));

    // Standard runs the original Session::accept (byte-unchanged); High/Sovereign
    // runs the multi-profile entry point with a freshly generated ML-DSA-87
    // long-term identity — required (fail-closed inside accept_with_profiles) for
    // either non-Standard profile.
    let mldsa_identity = if profile != Profile::Standard {
        let id = mldsa87::Identity::generate();
        println!("interop_server: identity ml-dsa-87 = {}", hex8(id.public_key_bytes()));
        Some(id)
    } else {
        None
    };

    let (mut stream, peer) = match listener.accept() {
        Ok(x) => x,
        Err(e) => {
            eprintln!("interop_server: accept: {e}");
            exit(1);
        }
    };
    println!("interop_server: accepted {peer}");

    let sess = match profile {
        Profile::Standard => Session::accept(&mut stream, &identity, None),
        Profile::High | Profile::Sovereign => Session::accept_with_profiles(
            &mut stream,
            &identity,
            mldsa_identity.as_ref(),
            &[profile.wire_byte()],
            None,
            None,
        ),
    };
    let sess = match sess {
        Ok(s) => s,
        Err(e) => {
            eprintln!("interop_server: handshake failed: {e}");
            exit(1);
        }
    };

    // accept_with_profiles allowed exactly one profile, so a completed handshake
    // proves the client negotiated that SAME profile — and kem_group_for_profiles
    // forces SecP384r1MLKEM1024 (0x11ed) whenever High or Sovereign is offered, so
    // peer_identity_mldsa87() being populated is live proof both the KEM group and
    // the ML-DSA-87 CertVerify negotiated as expected for the requested profile,
    // not merely that SOME handshake completed.
    match sess.peer_identity_mldsa87() {
        Some(peer_mldsa) => println!(
            "interop_server: handshake OK — profile={} negotiated KEM SecP384r1MLKEM1024 (0x11ed) + ML-DSA-87 CertVerify; authenticated client ml-dsa-87 = {} ({} octets)",
            profile.name(),
            hex8(peer_mldsa),
            peer_mldsa.len()
        ),
        None => println!(
            "interop_server: handshake OK — profile=standard; authenticated client ed25519 = {}",
            hex8(&sess.peer_identity())
        ),
    }

    // Receive one application frame from the client (Memory channel, seq 0).
    let (channel, ftype, pt) = match sess.recv(&mut stream, 0) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("interop_server: recv data frame: {e}");
            exit(1);
        }
    };
    println!(
        "interop_server: recv channel=0x{channel:04x} type=0x{ftype:04x} payload={:?}",
        String::from_utf8_lossy(&pt)
    );

    // Echo it back under the server->client key (seq 0).
    if let Err(e) = sess.send(&mut stream, channel, APP_FRAME_TYPE, 0, &pt) {
        eprintln!("interop_server: echo data frame: {e}");
        exit(1);
    }
    println!("interop_server: echoed payload back; interop OK (profile={})", profile.name());
}

fn hex8(b: &[u8]) -> String {
    b.iter().take(8).map(|x| format!("{x:02x}")).collect()
}
