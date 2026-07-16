//! Live N-PAMP interop CLIENT (raw TCP).
//!
//! Connects to an N-PAMP server, completes the client side of the 1.5-RTT
//! mutually-authenticated handshake (spec/10), sends one AEAD-protected
//! application frame on the Memory channel, and verifies the server's echo.
//! Interoperates with either this crate's interop_server example (Rust<->Rust) or
//! the Go reference harness impl/go/cmd/npamp-interop -role server (Go<->Rust) —
//! the two-interoperable-implementations unlock.
//!
//!   cargo run --example interop_client -- 127.0.0.1:47700
//!
//! Exit code 0 iff the handshake completes AND the server echo byte-matches the
//! sent payload. Transport: raw TCP (the handshake is transport-agnostic; the Go
//! SDK's TLS transport binding is not exercised here — see examples/support).

#[path = "support/npamp_live.rs"]
mod npamp_live;

use std::net::TcpStream;
use std::process::exit;

const APP_FRAME_TYPE: u16 = 0x0120; // application-defined frame type
const CHAN_MEMORY: u16 = 0x0001;
const DIR_C2S: u8 = 0; // send direction for the client
const DIR_S2C: u8 = 1; // receive direction for the client

fn main() {
    let addr = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:47700".to_string());
    let mut stream = match TcpStream::connect(&addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("interop_client: connect {addr}: {e}");
            exit(1);
        }
    };
    println!("interop_client: connected to {addr}");

    let identity = npamp_live::generate_identity();
    println!("interop_client: identity ed25519 = {}", hex8(&identity.verifying_key().to_bytes()));

    let session = match npamp_live::run_client_handshake(&mut stream, &identity, None) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("interop_client: handshake failed: {e}");
            exit(1);
        }
    };
    println!(
        "interop_client: handshake OK — authenticated server ed25519 = {}",
        hex8(&session.peer_identity)
    );

    // Send one application frame on the Memory channel (seq 0).
    let payload = b"hello from the rust interop client";
    if let Err(e) = npamp_live::send_data(&mut stream, &session.master, DIR_C2S, CHAN_MEMORY, APP_FRAME_TYPE, 0, payload) {
        eprintln!("interop_client: send data frame: {e}");
        exit(1);
    }
    println!("interop_client: sent {} octets on the Memory channel", payload.len());

    // Read the server's echo (server->client, seq 0) and verify byte-equality.
    let (channel, ftype, echo) = match npamp_live::recv_data(&mut stream, &session.master, DIR_S2C, 0) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("interop_client: recv echo: {e}");
            exit(1);
        }
    };
    println!(
        "interop_client: recv echo channel=0x{channel:04x} type=0x{ftype:04x} payload={:?}",
        String::from_utf8_lossy(&echo)
    );

    if echo != payload {
        eprintln!("interop_client: FAIL — echo did not match sent payload");
        exit(1);
    }
    println!("interop_client: PASS — live N-PAMP handshake + data frame round-trip verified");
}

fn hex8(b: &[u8]) -> String {
    b.iter().take(8).map(|x| format!("{x:02x}")).collect()
}
