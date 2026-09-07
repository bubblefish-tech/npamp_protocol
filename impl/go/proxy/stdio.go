// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// stdio-local-MCP carriage -- the fifth carriage leg named in R10 AC1,
// sharing NPAMP-CC-JSONRPC's wire mapping (carriage_jsonrpc.go/jsonrpc.go)
// with a LOCAL transport binding instead of Streamable HTTP: the egress side
// of an n-pamp-proxy speaks to a LOCAL MCP server process over its
// stdin/stdout, newline-delimited JSON-RPC 2.0 (MCP's own stdio transport
// binding: each message is a single line and MUST NOT contain an embedded
// newline). This file defines no new Bridge wire behavior; StdioBackend only
// supplies a JSONRPCHandlerFunc/JSONRPCNotifyFunc pair (jsonrpc.go) so
// handleInboundJSONRPCRequest/handleInboundNotify (jsonrpc.go) carry a
// request to/from the child process exactly as they would to any other
// JSONRPCHandler -- reusing the SAME NPAMP-CC-JSONRPC Bridge-side codec as
// the Streamable-HTTP JSON-RPC leg (proxy.go's StdioBackend field wires this
// automatically; see Proxy.init).

// StdioBackend spawns and owns one local child process, translating between
// this Proxy's inbound Bridge-carried JSON-RPC calls and that process's
// stdio-newline-delimited JSON-RPC 2.0 transport. The zero value is not
// usable; construct with NewStdioBackend. StdioBackend's own request/reply
// correlation (a local monotonic id) is entirely independent of the N-PAMP
// Bridge correlation_id space (§8) -- it is a private detail of talking to
// the one child process this instance owns.
type StdioBackend struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	nextID uint64

	mu      sync.Mutex
	pending map[string]chan stdioReply
}

type stdioReply struct {
	result json.RawMessage
	rpcErr *JSONRPCError
	err    error
}

// NewStdioBackend starts name with args as a child process and begins
// reading its stdout for newline-delimited JSON-RPC 2.0 responses in a
// background goroutine. The caller MUST call Close when done.
func NewStdioBackend(ctx context.Context, name string, args ...string) (*StdioBackend, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("npamp/proxy: stdio-local-MCP stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("npamp/proxy: stdio-local-MCP stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("npamp/proxy: stdio-local-MCP start %q: %w", name, err)
	}
	b := &StdioBackend{cmd: cmd, stdin: stdin, pending: make(map[string]chan stdioReply)}
	go b.readLoop(stdout)
	return b, nil
}

// readLoop consumes one JSON-RPC 2.0 object per line from the child's stdout
// for the process's lifetime, delivering each Response to the Call waiting
// on its local id. A malformed or unmatched line is dropped -- the child's
// stdout is untrusted local-process input, not an N-PAMP Bridge frame this
// package must reject on the wire; the N-PAMP-facing failure, if any,
// surfaces as the egress Call's own error/timeout.
func (b *StdioBackend) readLoop(stdout io.ReadCloser) {
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		parsed, perr := parseJSONRPCObject(line)
		if perr != nil || parsed.ID == nil {
			continue // a Request/Notification FROM the child is not answered by this leg
		}
		key := string(parsed.ID)
		b.mu.Lock()
		waiter, ok := b.pending[key]
		if ok {
			delete(b.pending, key)
		}
		b.mu.Unlock()
		if !ok {
			continue
		}
		if parsed.HasError {
			var je JSONRPCError
			if uerr := json.Unmarshal(parsed.Error, &je); uerr != nil {
				waiter <- stdioReply{err: fmt.Errorf("npamp/proxy: malformed stdio-local-MCP error object: %w", uerr)}
				continue
			}
			waiter <- stdioReply{rpcErr: &je}
			continue
		}
		waiter <- stdioReply{result: parsed.Result}
	}
}

// Call implements JSONRPCHandlerFunc (jsonrpc.go): it writes a
// newline-delimited JSON-RPC 2.0 Request to the child's stdin under a LOCAL
// numeric id and waits for the matching line from readLoop.
//
// The id is passed to encodeJSONRPCRequest as a Go uint64 (not a string) SO
// THAT it is JSON-encoded as a bare number (`"id":7`), matching
// strconv.FormatUint's bare-digit output exactly -- readLoop's key is the RAW
// JSON id token as it appears on the wire (json.RawMessage, §8.2: "quotes
// included" for a JSON string id), so a string-typed local id here would
// register the pending waiter under `"7"` (no quotes) while readLoop looks it
// up under the wire token `"7"` WITH quotes -- a mismatch that hangs every
// call. Keying both sides off the same bare-digit format avoids that.
func (b *StdioBackend) Call(ctx context.Context, protocol npamp.BridgeProtocol, method string, params json.RawMessage) (result json.RawMessage, rpcErr *JSONRPCError, err error) {
	localID := atomic.AddUint64(&b.nextID, 1)
	key := strconv.FormatUint(localID, 10)
	// encodeJSONRPCRequest's derived N-PAMP correlation_id is irrelevant here
	// (this backend correlates by its own local id, above) and is discarded.
	wire, _, cerr := encodeJSONRPCRequest(method, params, localID)
	if cerr != nil {
		return nil, nil, cerr
	}
	ch := make(chan stdioReply, 1)
	b.mu.Lock()
	b.pending[key] = ch
	b.mu.Unlock()

	if _, werr := b.stdin.Write(append(wire, '\n')); werr != nil {
		b.mu.Lock()
		delete(b.pending, key)
		b.mu.Unlock()
		return nil, nil, fmt.Errorf("npamp/proxy: writing to stdio-local-MCP child stdin: %w", werr)
	}

	select {
	case reply := <-ch:
		return reply.result, reply.rpcErr, reply.err
	case <-ctx.Done():
		b.mu.Lock()
		delete(b.pending, key)
		b.mu.Unlock()
		return nil, nil, ctx.Err()
	}
}

// Notify implements JSONRPCNotifyFunc (jsonrpc.go): it writes a JSON-RPC
// Notification (§7, no id) to the child's stdin and does not wait for
// anything.
func (b *StdioBackend) Notify(ctx context.Context, protocol npamp.BridgeProtocol, method string, params json.RawMessage) {
	wire, err := encodeJSONRPCNotification(method, params)
	if err != nil {
		return
	}
	_, _ = b.stdin.Write(append(wire, '\n'))
}

// Close terminates the child process and releases its pipes.
func (b *StdioBackend) Close() error {
	_ = b.stdin.Close()
	if b.cmd.Process != nil {
		_ = b.cmd.Process.Kill()
	}
	return b.cmd.Wait()
}
