// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// GoProcessSUL adapts the Go statelearn-sul binary (sul/) to LearnLib's de.learnlib.sul.SUL
// interface. It speaks the stdio line protocol the binary implements: RESET -> OK|ERR, then
// one <input-symbol> per line -> one <output-symbol> line. The child process is spawned once
// and kept alive for the whole learn run; pre() issues RESET (which tears down any prior
// episode and drives the SUT to a fresh real net.Pipe N-PAMP session — see sul/main.go), so a
// membership query never needs a fresh process spawn.

import de.learnlib.sul.SUL;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

final class GoProcessSUL implements SUL<String, String> {
    private final ProcessBuilder pb;
    private Process proc;
    private BufferedWriter out;
    private BufferedReader in;
    private long resetCount;
    private long queryCount;

    GoProcessSUL(String binaryPath, String role) {
        pb = new ProcessBuilder(binaryPath, "--role=" + role);
        // Inherit stderr so the SUL's diagnostic logf() lines (wire.go/common.go) surface
        // directly in this process's console for debugging a stuck or misbehaving learn run.
        pb.redirectError(ProcessBuilder.Redirect.INHERIT);
    }

    long getResetCount() {
        return resetCount;
    }

    long getQueryCount() {
        return queryCount;
    }

    private void ensureStarted() {
        if (proc != null && proc.isAlive()) {
            return;
        }
        try {
            proc = pb.start();
            out = new BufferedWriter(new OutputStreamWriter(proc.getOutputStream(), StandardCharsets.US_ASCII));
            in = new BufferedReader(new InputStreamReader(proc.getInputStream(), StandardCharsets.US_ASCII));
        } catch (IOException e) {
            throw new RuntimeException("statelearn: failed to start SUL process " + pb.command(), e);
        }
    }

    @Override
    public void pre() {
        ensureStarted();
        resetCount++;
        send("RESET");
        String resp = recv();
        if (!"OK".equals(resp)) {
            throw new RuntimeException("statelearn: RESET failed: " + resp);
        }
    }

    @Override
    public void post() {
        // The process is a long-lived resource kept across queries (RESET is what tears the
        // PROTOCOL episode down; killing the process on every post() would spend a fresh
        // process spawn per query for no behavioral benefit).
    }

    @Override
    public String step(String input) {
        queryCount++;
        send(input);
        return recv();
    }

    private void send(String line) {
        try {
            out.write(line);
            out.write("\n");
            out.flush();
        } catch (IOException e) {
            throw new RuntimeException("statelearn: write to SUL process failed", e);
        }
    }

    private String recv() {
        try {
            String line = in.readLine();
            if (line == null) {
                throw new RuntimeException("statelearn: SUL process closed stdout unexpectedly (exit="
                        + (proc.isAlive() ? "still running" : proc.exitValue()) + ")");
            }
            return line;
        } catch (IOException e) {
            throw new RuntimeException("statelearn: read from SUL process failed", e);
        }
    }

    void shutdown() {
        if (proc == null) {
            return;
        }
        try {
            out.close();
        } catch (IOException ignored) {
            // best effort
        }
        proc.destroy();
        try {
            proc.waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
