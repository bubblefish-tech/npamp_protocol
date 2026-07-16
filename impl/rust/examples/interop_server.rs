//! Live N-PAMP interop SERVER (raw TCP).
//!
//! Listens on an address, accepts one connection, completes the server side of the
//! 1.5-RTT mutually-authenticated N-PAMP handshake (spec/10), then receives one
//! AEAD-protected application frame on the Memory channel and echoes it back under
//! the server-to-client key. Interoperates with either this crate's interop_client
//! example (Rust<->Rust) or the Go reference harness impl/go/cmd/npamp-interop
//! -role client (Go<->Rust).
//!
//!   cargo run --example interop_server -- 127.0.0.1:47700
//!
//! Transport: the N-PAMP handshake is transport-agnostic; this example runs it
//! directly over TCP. The Go SDK's TLS 1.3 (ALPN "n-pamp/2") transport binding is
//! layered by sdk.Dial/Listen and is not exercised here (see examples/support).

#[path = "support/npamp_live.rs"]
mod npamp_live;

use std::net::TcpListener;
use std::process::exit;

const APP_FRAME_TYPE: u16 = 0x0120; // application-defined frame type
const DIR_C2S: u8 = 0; // receive direction for the server
const DIR_S2C: u8 = 1; // send direction for the server

fn main() {
    let addr = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:47700".to_string());
    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("interop_server: bind {addr}: {e}");
            exit(1);
        }
    };
    let bound = listener.local_addr().map(|a| a.to_string()).unwrap_or(addr.clone());
    let identity = npamp_live::generate_identity();
    let id_bytes = identity.verifying_key().to_bytes();
    println!("interop_server: listening on {bound}");
    println!("interop_server: identity ed25519 = {}", hex8(&id_bytes));

    let (mut stream, peer) = match listener.accept() {
        Ok(x) => x,
        Err(e) => {
            eprintln!("interop_server: accept: {e}");
            exit(1);
        }
    };
    println!("interop_server: accepted {peer}");

    let session = match npamp_live::run_server_handshake(&mut stream, &identity, None) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("interop_server: handshake failed: {e}");
            exit(1);
        }
    };
    println!(
        "interop_server: handshake OK — authenticated client ed25519 = {}",
        hex8(&session.peer_identity)
    );

    // Receive one application frame from the client (Memory channel, seq 0).
    let (channel, ftype, pt) = match npamp_live::recv_data(&mut stream, &session.master, DIR_C2S, 0) {
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
    if let Err(e) = npamp_live::send_data(&mut stream, &session.master, DIR_S2C, channel, APP_FRAME_TYPE, 0, &pt) {
        eprintln!("interop_server: echo data frame: {e}");
        exit(1);
    }
    println!("interop_server: echoed payload back; interop OK");
}

fn hex8(b: &[u8]) -> String {
    b.iter().take(8).map(|x| format!("{x:02x}")).collect()
}
