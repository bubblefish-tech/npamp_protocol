# N-PAMP Go SDK — Quickstart

`github.com/bubblefish-tech/npamp_protocol/impl/go/sdk` is the ergonomic Go
client/server layer for N-PAMP (`draft-bubblefish-npamp-01`) over the `npamp://`
transport. It builds on the wire-only reference package (`impl/go`), adding the
TCP + TLS 1.3 transport and the 1.5-RTT mutually-authenticated post-quantum
handshake so you can open an authenticated session in a few lines.

Scope: **Standard profile** (X25519MLKEM768 + Ed25519 + AES-256-GCM + SHA-256),
Apache-2.0. The SDK moves opaque payloads on a caller-chosen channel and
application frame type; application semantics are yours.

## Install

```sh
go get github.com/bubblefish-tech/npamp_protocol/impl/go/sdk
```

Requires Go 1.26+ (the standard-library post-quantum KEM, `crypto/mlkem`). Before
the first `impl/go/vX.Y.Z` module tag is published, use `@main` or a local
checkout of this repository.

## Server

```go
ln, err := sdk.Listen("127.0.0.1:9440", sdk.Config{
    TLSConfig: serverTLS, // your *tls.Config carrying a certificate
    Identity:  serverKey, // ed25519.PrivateKey (a fresh key is generated if nil)
})
if err != nil { log.Fatal(err) }
defer ln.Close()

for {
    conn, err := ln.Accept(context.Background())
    if err != nil { log.Fatal(err) }
    go func() {
        defer conn.Close()
        ch, ft, payload, err := conn.Recv(context.Background())
        if err != nil { return }
        // ...handle payload on channel ch / frame type ft...
        _ = conn.Send(context.Background(), ch, ft, []byte("ack"))
    }()
}
```

## Client

```go
conn, err := sdk.Dial(context.Background(), "127.0.0.1:9440", sdk.Config{
    TLSConfig:       clientTLS,    // your *tls.Config
    Identity:        clientKey,    // ed25519.PrivateKey (generated if nil)
    ExpectedPeerKey: serverPubKey, // pin the server identity (recommended)
})
if err != nil { log.Fatal(err) }
defer conn.Close()

if err := conn.Send(context.Background(), npamp.ChanMemory, 0x0120, []byte("hello")); err != nil {
    log.Fatal(err)
}
ch, ft, reply, err := conn.Recv(context.Background())
```

## Identity & TLS

- The **N-PAMP handshake** authenticates the peer's Ed25519 identity. Set
  `ExpectedPeerKey` to pin it — the check runs before the client sends
  CLIENT_AUTH, so a client never authenticates to an impostor. `Conn.PeerIdentity()`
  returns the proven key for trust-on-first-use.
- `TLSConfig` is required and governs certificate verification; the SDK pins ALPN
  `n-pamp/2` and a TLS 1.3 floor but never weakens the verification you configure.
  For loopback development a self-signed certificate with `InsecureSkipVerify` is
  acceptable because peer authentication comes from the handshake, not the
  certificate.

## A complete runnable reference

`sdk_test.go` is an end-to-end loopback example: it dials a server over a real
TCP+TLS socket, completes the full post-quantum handshake, verifies both
identities, and exchanges frames in both directions. Read it top to bottom for a
working reference, or run it:

```sh
GOWORK=off go test ./impl/go/sdk/... -run TestLoopbackHandshakeAndRoundTrip -v
```
