// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
)

// scenario is what main drives: a fresh N-PAMP endpoint scripted against the real SDK,
// speaking the abstract input/output alphabet defined by
// harness/statemodel/npamp-state-table.json.
type scenario interface {
	reset() error
	step(input string) string
	closeScenario()
}

// main implements the T18.2 stdio SUL protocol: read one command per line from stdin, write
// exactly one response line to stdout (flushed after every line), loop until EOF.
//
//	RESET          -> OK | ERR <message>
//	<input-symbol>  -> <output-symbol>
func main() {
	role := flag.String("role", "", `SUT role: "initiator" or "responder"`)
	flag.Parse()

	var sc scenario
	switch *role {
	case "initiator":
		sc = newInitiatorScenario()
	case "responder":
		sc = newResponderScenario()
	default:
		fmt.Fprintln(os.Stderr, `sul: --role must be "initiator" or "responder"`)
		os.Exit(2)
	}
	defer sc.closeScenario()

	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 4096), 1<<16)
	out := bufio.NewWriter(os.Stdout)

	for in.Scan() {
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		if line == "RESET" {
			if err := sc.reset(); err != nil {
				fmt.Fprintf(out, "ERR %v\n", err)
			} else {
				fmt.Fprintln(out, "OK")
			}
			if ferr := out.Flush(); ferr != nil {
				logf("flush after RESET: %v", ferr)
			}
			continue
		}
		result := sc.step(line)
		fmt.Fprintln(out, result)
		if ferr := out.Flush(); ferr != nil {
			logf("flush after step %q: %v", line, ferr)
		}
	}
	if err := in.Err(); err != nil {
		logf("stdin scan error: %v", err)
	}
}
