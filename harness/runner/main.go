// npamp-conform: a single-binary, language-agnostic conformance runner for the
// npamp_00 protocol. It owns the test-vector corpus and grading; the developer writes
// only a thin "testee" adapter (any language) that reads length-prefixed JSON requests
// on stdin and writes length-prefixed JSON responses on stdout. See INSTRUCTIONS.md.
package main

import (
	"bufio"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed corpus/conformance-corpus.json
var corpusJSON []byte

type Test struct {
	TcId        int                    `json:"tcId"`
	Requirement string                 `json:"requirement"`
	Comment     string                 `json:"comment"`
	In          map[string]interface{} `json:"in"`
	Expected    map[string]interface{} `json:"expected"`
	Result      string                 `json:"result"`
	Flags       []string               `json:"flags"`
}
type Group struct {
	Op      string `json:"op"`
	Profile string `json:"profile"`
	Tests   []Test `json:"tests"`
}
type Corpus struct {
	Algorithm     string  `json:"algorithm"`
	SchemaVersion string  `json:"schemaVersion"`
	SpecRevision  string  `json:"specRevision"`
	TestGroups    []Group `json:"testGroups"`
}

type Request struct {
	Op string                 `json:"op"`
	In map[string]interface{} `json:"in"`
}
type Response struct {
	Out     map[string]interface{} `json:"out,omitempty"`
	Error   string                 `json:"error,omitempty"`
	Skipped string                 `json:"skipped,omitempty"`
}

// ---- testee subprocess driver (length-prefixed: u32-LE len + JSON) ----

type Testee struct {
	cmd     *exec.Cmd
	in      io.WriteCloser
	out     *bufio.Reader
	timeout time.Duration
}

// splitCommand splits a --testee command line into fields, honoring single and double
// quotes so a program path containing spaces can be quoted, e.g.
//   --testee '"/opt/adapters/my adapter" --break'
func splitCommand(s string) []string {
	var out []string
	var cur strings.Builder
	var quote rune
	started := false
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote = r
			started = true
		case r == ' ' || r == '\t':
			if started {
				out = append(out, cur.String())
				cur.Reset()
				started = false
			}
		default:
			cur.WriteRune(r)
			started = true
		}
	}
	if started {
		out = append(out, cur.String())
	}
	return out
}

func startTestee(cmdline string, timeout time.Duration) (*Testee, error) {
	parts := splitCommand(cmdline)
	if len(parts) == 0 {
		return nil, fmt.Errorf("empty --testee command")
	}
	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &Testee{cmd: cmd, in: stdin, out: bufio.NewReader(stdout), timeout: timeout}, nil
}

// callRaw performs one request/response over the pipe (blocking).
func (t *Testee) callRaw(req Request) (Response, error) {
	b, err := json.Marshal(req)
	if err != nil {
		return Response{}, err
	}
	var lp [4]byte
	binary.LittleEndian.PutUint32(lp[:], uint32(len(b)))
	if _, err := t.in.Write(lp[:]); err != nil {
		return Response{}, err
	}
	if _, err := t.in.Write(b); err != nil {
		return Response{}, err
	}
	var rl [4]byte
	if _, err := io.ReadFull(t.out, rl[:]); err != nil {
		return Response{}, fmt.Errorf("reading response length: %w", err)
	}
	n := binary.LittleEndian.Uint32(rl[:])
	buf := make([]byte, n)
	if _, err := io.ReadFull(t.out, buf); err != nil {
		return Response{}, fmt.Errorf("reading response body: %w", err)
	}
	var resp Response
	if err := json.Unmarshal(buf, &resp); err != nil {
		return Response{}, fmt.Errorf("decoding response %q: %w", string(buf), err)
	}
	return resp, nil
}

// call wraps callRaw with a timeout so a hung or non-conforming adapter fails the
// case instead of hanging the runner forever.
func (t *Testee) call(req Request) (Response, error) {
	type res struct {
		r Response
		e error
	}
	ch := make(chan res, 1)
	go func() { r, e := t.callRaw(req); ch <- res{r, e} }()
	select {
	case x := <-ch:
		return x.r, x.e
	case <-time.After(t.timeout):
		return Response{}, fmt.Errorf("adapter did not respond within %s", t.timeout)
	}
}

func (t *Testee) close() {
	t.in.Close()
	if t.cmd.Process != nil {
		t.cmd.Process.Kill()
	}
	t.cmd.Wait()
}

// ---- grading ----

const (
	Pass          = "Pass"
	Fail          = "Fail"
	Unimplemented = "Unimplemented"
	NonStrict     = "Non-Strict"
)

func valEqual(a, b interface{}) bool {
	switch av := a.(type) {
	case string:
		bs, ok := b.(string)
		return ok && strings.EqualFold(av, bs)
	case float64:
		bf, ok := b.(float64)
		return ok && av == bf
	case bool:
		bb, ok := b.(bool)
		return ok && av == bb
	default:
		return fmt.Sprint(a) == fmt.Sprint(b)
	}
}

func matchExpected(exp, out map[string]interface{}) (bool, string) {
	keys := make([]string, 0, len(exp))
	for k := range exp {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ov, ok := out[k]
		if !ok {
			return false, fmt.Sprintf("%s: expected %v, missing in output", k, exp[k])
		}
		if !valEqual(exp[k], ov) {
			return false, fmt.Sprintf("%s: expected %v, got %v", k, exp[k], ov)
		}
	}
	return true, ""
}

func gradeCase(tc Test, resp Response, callErr error) (string, string) {
	if callErr != nil {
		return Fail, "adapter-error: " + callErr.Error()
	}
	if resp.Skipped != "" {
		return Unimplemented, resp.Skipped
	}
	switch tc.Result {
	case "invalid":
		if resp.Error != "" {
			return Pass, ""
		}
		return Fail, fmt.Sprintf("MUST reject, but adapter accepted (out=%v)", resp.Out)
	case "acceptable":
		return Pass, ""
	default: // valid
		if resp.Error != "" {
			return Fail, "expected success, adapter errored: " + resp.Error
		}
		ok, detail := matchExpected(tc.Expected, resp.Out)
		if ok {
			return Pass, ""
		}
		return Fail, detail
	}
}

// ---- run ----

type caseResult struct {
	op, requirement, verdict, detail string
	tcId                             int
}

func runConformance(testeeCmd, junitPath string, timeout time.Duration) int {
	var corpus Corpus
	if err := json.Unmarshal(corpusJSON, &corpus); err != nil {
		fmt.Fprintln(os.Stderr, "corrupt embedded corpus:", err)
		return 3
	}
	tt, err := startTestee(testeeCmd, timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot start testee:", err)
		return 3
	}
	defer tt.close()

	var results []caseResult
	tally := map[string]int{}
	fmt.Printf("npamp_00 conformance — spec %s, corpus %s\n", corpus.SpecRevision, corpus.SchemaVersion)
	aborted := false
	for _, g := range corpus.TestGroups {
		var p, f, u int
		for _, tc := range g.Tests {
			resp, callErr := tt.call(Request{Op: g.Op, In: tc.In})
			verdict, detail := gradeCase(tc, resp, callErr)
			tally[verdict]++
			results = append(results, caseResult{g.Op, tc.Requirement, verdict, detail, tc.TcId})
			switch verdict {
			case Pass:
				p++
			case Unimplemented:
				u++
			default:
				f++
			}
			if verdict == Fail {
				fmt.Printf("  FAIL %-20s tcId=%-5d %s\n        %s\n", g.Op, tc.TcId, tc.Requirement, detail)
			}
			if callErr != nil {
				aborted = true // transport failure (timeout / broken pipe): pipe unusable, stop
				break
			}
		}
		status := "pass"
		if f > 0 {
			status = "FAIL"
		} else if u == len(g.Tests) {
			status = "unimplemented"
		}
		fmt.Printf("  %-22s %3d/%-3d %s\n", g.Op, p, len(g.Tests), status)
		_ = u
		if aborted {
			fmt.Println("  ABORTED: adapter transport failure; remaining cases not run")
			break
		}
	}
	fmt.Printf("Summary: Pass=%d Fail=%d Unimplemented=%d Non-Strict=%d\n",
		tally[Pass], tally[Fail], tally[Unimplemented], tally[NonStrict])
	if junitPath != "" {
		writeJUnit(junitPath, results)
	}
	if tally[Fail] > 0 {
		fmt.Println("RESULT: FAIL")
		return 1
	}
	fmt.Println("RESULT: PASS")
	return 0
}

func writeJUnit(path string, rs []caseResult) {
	var b strings.Builder
	fails := 0
	for _, r := range rs {
		if r.verdict == Fail {
			fails++
		}
	}
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	fmt.Fprintf(&b, `<testsuite name="npamp_00-conformance" tests="%d" failures="%d">`+"\n", len(rs), fails)
	for _, r := range rs {
		fmt.Fprintf(&b, `  <testcase classname="%s" name="%s#%d">`, r.op, r.requirement, r.tcId)
		switch r.verdict {
		case Fail:
			fmt.Fprintf(&b, "\n    <failure>%s</failure>\n  ", escapeXML(r.detail))
		case Unimplemented:
			b.WriteString("\n    <skipped/>\n  ")
		}
		b.WriteString("</testcase>\n")
	}
	b.WriteString("</testsuite>\n")
	if err := os.WriteFile(path, []byte(b.String()), 0644); err != nil {
		fmt.Fprintln(os.Stderr, "warning: cannot write junit report:", err)
		return
	}
	fmt.Println("wrote JUnit report:", path)
}

func escapeXML(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}

func usage() int {
	fmt.Fprintln(os.Stderr, `npamp-conform — npamp_00 conformance runner

Usage:
  npamp-conform run --testee "<command>" [--junit <path>]
      Drive your implementation (as a subprocess adapter) against the corpus and grade it.
  npamp-conform vectors
      Print the embedded conformance corpus (for your own test harness).`)
	return 2
}

func main() {
	if len(os.Args) < 2 {
		os.Exit(usage())
	}
	switch os.Args[1] {
	case "vectors":
		os.Stdout.Write(corpusJSON)
		if len(corpusJSON) == 0 || corpusJSON[len(corpusJSON)-1] != '\n' {
			fmt.Println()
		}
		os.Exit(0)
	case "run":
		testee, junit := "", ""
		timeoutSec := 30
		args := os.Args[2:]
		for i := 0; i < len(args); i++ {
			switch args[i] {
			case "--testee":
				if i+1 < len(args) {
					testee = args[i+1]
					i++
				}
			case "--junit":
				if i+1 < len(args) {
					junit = args[i+1]
					i++
				}
			case "--timeout":
				if i+1 < len(args) {
					if v, err := strconv.Atoi(args[i+1]); err == nil && v > 0 {
						timeoutSec = v
					}
					i++
				}
			}
		}
		if testee == "" {
			fmt.Fprintln(os.Stderr, "run: --testee \"<command>\" is required")
			os.Exit(2)
		}
		os.Exit(runConformance(testee, junit, time.Duration(timeoutSec)*time.Second))
	default:
		os.Exit(usage())
	}
}
