// SPDX-License-Identifier: Apache-2.0

// Package sdk is the ergonomic client/server SDK for N-PAMP
// (draft-bubblefish-npamp-01) over the npamp:// transport.
//
// The sibling root package
// (github.com/bubblefish-tech/npamp_protocol/impl/go) is deliberately wire-only:
// it provides the frame codec, the hybrid post-quantum KEM (X25519MLKEM768),
// the key schedule, the transcript, and the AEAD record layer — but no network
// transport and no handshake orchestration. This package supplies exactly those
// two missing pieces so a developer can open a mutually-authenticated,
// post-quantum session in a few lines:
//
//   - Dial / Listen: a TCP + TLS 1.3 transport that negotiates ALPN "n-pamp/2".
//   - The full 1.5-RTT, mutually-authenticated draft-01 handshake
//     (CLIENT_HELLO, SERVER_HELLO, SERVER_AUTH, CLIENT_AUTH) driving the
//     impl/go primitives, ending in a Conn whose Send/Recv apply the
//     per-(direction, channel) AEAD record layer.
//
// Scope: Standard profile only (X25519MLKEM768 + Ed25519 + AES-256-GCM +
// SHA-256). The SDK carries no application semantics — Send and Recv move
// opaque payloads on a caller-chosen channel and application frame type; what
// those bytes mean is the caller's contract. A Conn is full-duplex: either peer
// may originate frames on the same authenticated session.
package sdk
