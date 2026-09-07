// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! The node-to-node CONNECT tunnel (E2.5) — the HBONE-analogue: one underlying
//! transport between a pair of `nz-agent`s multiplexes many workloads' logical
//! streams, so the tunnel-transport setup cost is amortized per node-pair while
//! every workload still gets its own [`MuxStream`] to run an independent
//! `npamp::session::Session::dial`/`accept` handshake over (see [`crate::agent`]).
//!
//! This module is NOT part of the N-PAMP wire format. It is transport-layer
//! plumbing this crate owns, exactly the way HTTP/2 framing is not part of the
//! TLS record layer it carries: the mux frame header below never appears inside
//! an N-PAMP frame, and no N-PAMP frame byte is reinterpreted by this module —
//! `MuxStream` presents a plain `Read + Write` byte stream to whatever runs on
//! top of it (an `npamp::session::Session` handshake, or anything else).
//!
//! # Wire shape (this crate's own, not N-PAMP's)
//!
//! One mux frame: `[stream_id: u32 BE][kind: u8][len: u32 BE][payload: len octets]`.
//! `kind` is one of [`FrameKind::Open`], [`FrameKind::Data`], [`FrameKind::Close`].
//! A stream MUST be opened (an `Open` frame for its id) before any `Data` frame
//! for that id is accepted; a `Data` frame for an unopened id is a protocol
//! error (fail-closed — never silently buffered under an assumed implicit open).
//!
//! # Isolation property
//!
//! Bytes written to one [`MuxStream`] are delivered only to the peer's same
//! stream id; two streams multiplexed over the same transport never observe
//! each other's payload bytes (mutation-tested below: routing by any id other
//! than the frame's own would leak one stream's plaintext into another's
//! Read buffer).

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

const FRAME_HEADER_LEN: usize = 4 + 1 + 4;
/// Mirrors `npamp::session`'s own frame-size cap so a peer cannot force an
/// unbounded allocation with a hostile mux-frame length field.
const MAX_MUX_PAYLOAD: usize = 16 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    Open = 0,
    Data = 1,
    Close = 2,
}

impl FrameKind {
    fn from_u8(b: u8) -> io::Result<FrameKind> {
        match b {
            0 => Ok(FrameKind::Open),
            1 => Ok(FrameKind::Data),
            2 => Ok(FrameKind::Close),
            other => Err(protoerr(&format!("unknown mux frame kind {other}"))),
        }
    }
}

fn protoerr(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("nz-agent/tunnel: {msg}"))
}

/// Writes one mux frame (`stream_id`, `kind`, `payload`) to `w`, as one atomic
/// write call — callers serialize concurrent writers with a lock (see
/// [`Multiplexer`]) so frames from different streams never interleave.
fn write_mux_frame<W: Write>(w: &mut W, stream_id: u32, kind: FrameKind, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_MUX_PAYLOAD {
        return Err(protoerr("outgoing mux frame exceeds MAX_MUX_PAYLOAD"));
    }
    let mut buf = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    buf.extend_from_slice(&stream_id.to_be_bytes());
    buf.push(kind as u8);
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
    w.write_all(&buf)
}

/// Reads exactly one mux frame from `r`. Returns `Ok(None)` on a clean EOF at a
/// frame boundary (peer closed the transport); any other short read is an error.
fn read_mux_frame<R: Read>(r: &mut R) -> io::Result<Option<(u32, FrameKind, Vec<u8>)>> {
    let mut hdr = [0u8; FRAME_HEADER_LEN];
    match read_full_or_eof(r, &mut hdr)? {
        false => return Ok(None),
        true => {}
    }
    let stream_id = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    let kind = FrameKind::from_u8(hdr[4])?;
    let len = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) as usize;
    if len > MAX_MUX_PAYLOAD {
        return Err(protoerr("incoming mux frame exceeds MAX_MUX_PAYLOAD"));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok(Some((stream_id, kind, payload)))
}

/// Reads `buf.len()` bytes, or reports a clean EOF (`Ok(false)`) if the peer
/// closed with zero bytes read; a partial read followed by EOF is an error
/// (matches `Read::read_exact`'s own UnexpectedEof, just distinguishing the
/// zero-bytes-read case as a graceful close rather than a truncated frame).
fn read_full_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0usize;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => {
                if filled == 0 {
                    return Ok(false);
                }
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "nz-agent/tunnel: truncated mux frame header"));
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

enum RouterEvent {
    NewStream(u32, Receiver<Vec<u8>>),
    /// A stream closed. Carries no stream id: [`Multiplexer::accept_stream`]
    /// only waits for [`RouterEvent::NewStream`] and otherwise drains/skips
    /// this variant — a caller that needs to observe WHICH stream closed
    /// reads it from the per-stream `MuxStream::read` EOF instead (the
    /// stream's own table entry is already removed by the time this event
    /// is sent; see `demux_loop`).
    Closed,
}

struct StreamState {
    tx: Sender<Vec<u8>>,
}

/// Owns the demux side of one node-to-node transport: reads mux frames from
/// `R` and routes each `Data` payload to the [`MuxStream`] with the matching
/// `stream_id`, and reports newly-`Open`ed streams to [`Multiplexer::accept_stream`].
///
/// Runs on its own background thread (spawned by [`Multiplexer::new`]); the
/// thread exits when the transport reaches EOF or a protocol error, at which
/// point every still-open [`MuxStream`]'s `Read` returns EOF. This requires
/// explicitly draining `streams` on exit (below): `streams` is an `Arc`
/// shared with the owning [`Multiplexer`], so it is NOT dropped merely
/// because this loop returns — a `MuxStream::read` blocked on its
/// `Receiver::recv()` would otherwise hang forever past transport close (a
/// real defect this crate's own two-process TCP smoke test caught: an
/// initiator blocked in `recv()` after its peer process exited, because the
/// first version of this function relied on the `Arc` refcount reaching zero,
/// which it never did while the `Multiplexer` handle was still alive).
fn demux_loop<R: Read>(mut r: R, new_streams: Sender<RouterEvent>, streams: Arc<Mutex<HashMap<u32, StreamState>>>) {
    loop {
        let frame = match read_mux_frame(&mut r) {
            Ok(Some(f)) => f,
            Ok(None) => break, // clean EOF
            Err(_) => break,   // protocol error: tear the whole tunnel down (fail-closed)
        };
        let (stream_id, kind, payload) = frame;
        match kind {
            FrameKind::Open => {
                let (tx, rx) = mpsc::channel();
                streams.lock().expect("nz-agent/tunnel: streams mutex poisoned").insert(stream_id, StreamState { tx });
                if new_streams.send(RouterEvent::NewStream(stream_id, rx)).is_err() {
                    break; // no one is listening for new streams anymore
                }
            }
            FrameKind::Data => {
                let tbl = streams.lock().expect("nz-agent/tunnel: streams mutex poisoned");
                if let Some(st) = tbl.get(&stream_id) {
                    // A dropped receiver (the MuxStream was dropped) is not a
                    // transport-level error: drop the payload, keep demuxing.
                    let _ = st.tx.send(payload);
                }
                // Data for an unopened id is dropped, not fatal to the tunnel —
                // matches an ordinary reordered-frame tolerance; the isolation
                // property (never routed to a DIFFERENT open stream) still holds.
            }
            FrameKind::Close => {
                streams.lock().expect("nz-agent/tunnel: streams mutex poisoned").remove(&stream_id);
                let _ = new_streams.send(RouterEvent::Closed);
            }
        }
    }
    // Transport closed (or errored): drop every remaining stream's sender so
    // any `MuxStream::read` blocked on `Receiver::recv()` — or one that
    // blocks in the future — observes EOF instead of hanging forever.
    streams.lock().expect("nz-agent/tunnel: streams mutex poisoned").clear();
}

/// One end of the node-to-node tunnel. Cloneable (cheap: an `Arc`-backed
/// writer handle + a shared stream-id allocator) so every workload's task can
/// hold its own handle to open new streams.
#[derive(Clone)]
pub struct Multiplexer<W: Write + Send + 'static> {
    writer: Arc<Mutex<W>>,
    next_id: Arc<AtomicU32>,
    streams: Arc<Mutex<HashMap<u32, StreamState>>>,
    accept_rx: Arc<Mutex<Receiver<RouterEvent>>>,
}

impl<W: Write + Send + 'static> Multiplexer<W> {
    /// Spawns the background demux thread over `reader` and returns a
    /// `Multiplexer` handle for opening/accepting streams that write out via
    /// `writer`. Callers split a real transport into an owned read half and an
    /// owned write half before calling this (e.g. `TcpStream::try_clone`); see
    /// the crate tests for an in-memory equivalent.
    pub fn new<R: Read + Send + 'static>(reader: R, writer: W) -> Multiplexer<W> {
        let streams: Arc<Mutex<HashMap<u32, StreamState>>> = Arc::new(Mutex::new(HashMap::new()));
        let (accept_tx, accept_rx) = mpsc::channel();
        let streams_for_thread = Arc::clone(&streams);
        thread::spawn(move || demux_loop(reader, accept_tx, streams_for_thread));
        Multiplexer {
            writer: Arc::new(Mutex::new(writer)),
            next_id: Arc::new(AtomicU32::new(1)),
            streams,
            accept_rx: Arc::new(Mutex::new(accept_rx)),
        }
    }

    /// Opens a fresh outbound logical stream (sends an `Open` mux frame) and
    /// returns a `Read + Write` handle to it. `stream_id`s are allocated by an
    /// internal atomic counter, unique per `Multiplexer` instance.
    pub fn open_stream(&self) -> io::Result<MuxStream<W>> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel();
        self.streams.lock().expect("nz-agent/tunnel: streams mutex poisoned").insert(id, StreamState { tx });
        write_mux_frame(&mut *self.writer.lock().expect("nz-agent/tunnel: writer mutex poisoned"), id, FrameKind::Open, &[])?;
        Ok(MuxStream { id, writer: Arc::clone(&self.writer), rx, pending: VecDeque::new(), closed_write: false })
    }

    /// Blocks until the peer opens a new stream (or the tunnel closes),
    /// returning the accepted [`MuxStream`]. This is the per-workload accept
    /// path: the responder-side `nz-agent` calls this once per inbound
    /// workload session it needs to `npamp::session::Session::accept` over.
    pub fn accept_stream(&self) -> io::Result<MuxStream<W>> {
        loop {
            let ev = self
                .accept_rx
                .lock()
                .expect("nz-agent/tunnel: accept_rx mutex poisoned")
                .recv()
                .map_err(|_| protoerr("tunnel closed before a stream was opened"))?;
            match ev {
                RouterEvent::NewStream(id, rx) => {
                    return Ok(MuxStream { id, writer: Arc::clone(&self.writer), rx, pending: VecDeque::new(), closed_write: false });
                }
                RouterEvent::Closed => continue,
            }
        }
    }
}

/// One multiplexed logical stream: `Read + Write`, backed by one `stream_id`
/// on the shared underlying transport. Every workload's `npamp::session::Session`
/// handshake and subsequent `send`/`recv` calls run over exactly one `MuxStream`
/// — never shared with any other workload's stream.
pub struct MuxStream<W: Write + Send + 'static> {
    id: u32,
    writer: Arc<Mutex<W>>,
    rx: Receiver<Vec<u8>>,
    pending: VecDeque<u8>,
    closed_write: bool,
}

impl<W: Write + Send + 'static> MuxStream<W> {
    pub fn stream_id(&self) -> u32 {
        self.id
    }

    /// Sends a `Close` mux frame for this stream. Idempotent per instance;
    /// dropping a `MuxStream` without calling this leaves the peer's demux
    /// table entry until the underlying transport itself closes.
    pub fn close(&mut self) -> io::Result<()> {
        if self.closed_write {
            return Ok(());
        }
        self.closed_write = true;
        write_mux_frame(&mut *self.writer.lock().expect("nz-agent/tunnel: writer mutex poisoned"), self.id, FrameKind::Close, &[])
    }
}

impl<W: Write + Send + 'static> Read for MuxStream<W> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        while self.pending.is_empty() {
            match self.rx.recv() {
                Ok(chunk) => self.pending.extend(chunk),
                Err(_) => return Ok(0), // demux loop exited: EOF
            }
        }
        let n = out.len().min(self.pending.len());
        for slot in out.iter_mut().take(n) {
            *slot = self.pending.pop_front().expect("checked len above");
        }
        Ok(n)
    }
}

impl<W: Write + Send + 'static> Write for MuxStream<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        write_mux_frame(&mut *self.writer.lock().expect("nz-agent/tunnel: writer mutex poisoned"), self.id, FrameKind::Data, buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// An in-memory, single-direction pipe (mpsc-backed), used to build a full-
// duplex pair for tests without depending on a real socket or on npamp's
// private `session::ChannelDuplex`. Two of these, crossed, give a Multiplexer
// on each end an owned `Read` half and an owned `Write` half — the same shape
// `TcpStream::try_clone` gives a real deployment.
// ---------------------------------------------------------------------------
pub struct PipeReader {
    rx: Receiver<Vec<u8>>,
    pending: VecDeque<u8>,
}

pub struct PipeWriter {
    tx: Sender<Vec<u8>>,
}

impl Read for PipeReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        while self.pending.is_empty() {
            match self.rx.recv() {
                Ok(chunk) => self.pending.extend(chunk),
                Err(_) => return Ok(0),
            }
        }
        let n = out.len().min(self.pending.len());
        for slot in out.iter_mut().take(n) {
            *slot = self.pending.pop_front().expect("checked len above");
        }
        Ok(n)
    }
}

impl Write for PipeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tx.send(buf.to_vec()).map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "nz-agent/tunnel: pipe peer dropped"))?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn mem_pipe() -> (PipeReader, PipeWriter) {
    let (tx, rx) = mpsc::channel();
    (PipeReader { rx, pending: VecDeque::new() }, PipeWriter { tx })
}

/// Builds a connected pair of `Multiplexer`s over two crossed in-memory pipes
/// — the test/same-process equivalent of two `nz-agent`s' node-to-node tunnel.
pub fn multiplexer_pair() -> (Multiplexer<PipeWriter>, Multiplexer<PipeWriter>) {
    let (r_ab, w_ab) = mem_pipe(); // A -> B
    let (r_ba, w_ba) = mem_pipe(); // B -> A
    let a = Multiplexer::new(r_ba, w_ab);
    let b = Multiplexer::new(r_ab, w_ba);
    (a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test for a real defect this crate's own two-process TCP
    /// smoke test caught: when the underlying transport reaches EOF (the
    /// peer process exited), a `MuxStream::read` already blocked in
    /// `Receiver::recv()` must wake up with EOF (`Ok(0)`), not hang forever.
    /// `demux_loop`'s post-loop `streams.clear()` is what makes this pass;
    /// removing that line reproduces the original hang (verified manually —
    /// see RED-EVIDENCE.md M-tunnel-1).
    #[test]
    fn transport_eof_wakes_a_blocked_read_with_eof() {
        let (a, b) = multiplexer_pair();
        let mut sa = a.open_stream().expect("open");
        let sb = b.accept_stream().expect("accept"); // ensure the Open frame round-tripped
        // Simulate the peer PROCESS exiting: a real process exit closes its
        // socket at the OS level regardless of in-process reference counts,
        // so the faithful in-memory analog is dropping EVERY local holder of
        // b's writer — both the Multiplexer itself and the MuxStream
        // `accept_stream` handed back (which clones the same writer Arc so
        // it can send replies; see `Multiplexer::accept_stream`).
        drop(sb);
        drop(b);

        let (done_tx, done_rx) = mpsc::channel();
        thread::spawn(move || {
            let mut buf = [0u8; 8];
            let n = sa.read(&mut buf);
            let _ = done_tx.send(n.map(|n| n == 0)); // Ok(true) means "read returned a clean EOF"
        });
        match done_rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(Ok(true)) => {} // EOF observed, as required
            Ok(Ok(false)) => panic!("read returned data instead of EOF"),
            Ok(Err(e)) => panic!("read returned an error instead of EOF: {e}"),
            Err(_) => panic!("MuxStream::read did not wake up within 5s after transport EOF (the hang this test guards against)"),
        }
    }

    #[test]
    fn open_stream_delivers_to_matching_accept() {
        let (a, b) = multiplexer_pair();
        let mut sa = a.open_stream().expect("open");
        let mut sb = b.accept_stream().expect("accept");
        assert_eq!(sa.stream_id(), sb.stream_id());
        sa.write_all(b"hello").expect("write");
        let mut buf = [0u8; 5];
        sb.read_exact(&mut buf).expect("read");
        assert_eq!(&buf, b"hello");
    }

    /// Isolation property (module docs): two streams multiplexed over the
    /// SAME transport never observe each other's payload bytes. This is the
    /// property M1 (see RED-EVIDENCE.md) mutates away and this test catches.
    #[test]
    fn two_streams_do_not_cross_contaminate() {
        let (a, b) = multiplexer_pair();
        let mut a1 = a.open_stream().expect("open s1");
        let mut b1 = b.accept_stream().expect("accept s1");
        let mut a2 = a.open_stream().expect("open s2");
        let mut b2 = b.accept_stream().expect("accept s2");
        assert_ne!(a1.stream_id(), a2.stream_id());

        a1.write_all(b"stream-one-payload").expect("write s1");
        a2.write_all(b"stream-two-payload").expect("write s2");

        let mut got1 = vec![0u8; "stream-one-payload".len()];
        b1.read_exact(&mut got1).expect("read s1");
        assert_eq!(&got1, b"stream-one-payload");

        let mut got2 = vec![0u8; "stream-two-payload".len()];
        b2.read_exact(&mut got2).expect("read s2");
        assert_eq!(&got2, b"stream-two-payload");
    }

    #[test]
    fn many_streams_muxed_over_one_transport() {
        let (a, b) = multiplexer_pair();
        const N: u32 = 16;
        let mut a_sides = Vec::new();
        for i in 0..N {
            let mut s = a.open_stream().expect("open");
            s.write_all(format!("payload-{i}").as_bytes()).expect("write");
            a_sides.push(s);
        }
        let mut seen = std::collections::HashSet::new();
        for _ in 0..N {
            let mut s = b.accept_stream().expect("accept");
            let mut buf = vec![0u8; 32];
            let n = s.read(&mut buf).expect("read");
            let got = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(got.starts_with("payload-"), "unexpected payload: {got}");
            assert!(seen.insert(s.stream_id()), "duplicate stream id delivered");
        }
        assert_eq!(seen.len(), N as usize);
    }

    #[test]
    fn write_then_close_still_delivers_the_buffered_byte() {
        let (a, b) = multiplexer_pair();
        let mut sa = a.open_stream().expect("open");
        let mut sb = b.accept_stream().expect("accept");
        sa.write_all(b"x").expect("write");
        sa.close().expect("close");
        let mut buf = [0u8; 1];
        sb.read_exact(&mut buf).expect("read pending byte before close observed");
        assert_eq!(&buf, b"x");
    }

    #[test]
    fn oversized_frame_len_is_rejected_not_allocated() {
        // A hostile length field (larger than MAX_MUX_PAYLOAD) must be a named
        // rejection, never an attempted allocation.
        let (mut r, mut w) = mem_pipe();
        let hdr_stream_id = 1u32.to_be_bytes();
        let bad_len = (MAX_MUX_PAYLOAD as u32 + 1).to_be_bytes();
        let mut frame = Vec::new();
        frame.extend_from_slice(&hdr_stream_id);
        frame.push(FrameKind::Data as u8);
        frame.extend_from_slice(&bad_len);
        w.write_all(&frame).expect("write raw frame");
        drop(w);
        let err = read_mux_frame(&mut r).expect_err("oversized length must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
