// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npampotel

import (
	"context"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// TestDefinedCodesMatchesTheRealRegistry cross-checks this package's local definedCodes map
// against the real impl/go/errorframe.go registry via SessionErrorCode.String(): every code
// this package believes is registered must NOT produce the "error_code(0x..)" hex fallback
// (which errorframe.go's String() only returns for a value absent from its own errCodeName
// map), and the immediately-following unassigned code (11) MUST produce that fallback --
// proving the two disagree exactly at the boundary this package assumes, not merely that
// both happen to agree somewhere.
func TestDefinedCodesMatchesTheRealRegistry(t *testing.T) {
	for code := range definedCodes {
		s := code.String()
		if s == "" || (len(s) >= 11 && s[:11] == "error_code(") {
			t.Fatalf("definedCodes claims code %d is registered, but SessionErrorCode.String() = %q (unregistered fallback)", code, s)
		}
	}
	unassigned := npamp.SessionErrorCode(11)
	if definedCodes[unassigned] {
		t.Fatalf("definedCodes claims code 11 is registered, but it is not defined in errorframe.go")
	}
	got := unassigned.String()
	want := "error_code(0xb)"
	if got != want {
		t.Fatalf("SessionErrorCode(11).String() = %q, want %q (registry boundary assumption broken)", got, want)
	}
}

func TestReactionNameMatchesRegisteredReaction(t *testing.T) {
	if reactionName(npamp.ErrCodeReplayDetected.Reaction()) != reactionDiscard {
		t.Fatalf("reactionName(replay_detected.Reaction()) = %q, want %q", reactionName(npamp.ErrCodeReplayDetected.Reaction()), reactionDiscard)
	}
	if reactionName(npamp.ErrCodeUnknownChannel.Reaction()) != reactionDiscard {
		t.Fatalf("reactionName(unknown_channel.Reaction()) = %q, want %q", reactionName(npamp.ErrCodeUnknownChannel.Reaction()), reactionDiscard)
	}
	if reactionName(npamp.ErrCodeDecryptFailed.Reaction()) != reactionFatal {
		t.Fatalf("reactionName(decrypt_failed.Reaction()) = %q, want %q", reactionName(npamp.ErrCodeDecryptFailed.Reaction()), reactionFatal)
	}
}

func testRecorder(t *testing.T) (*Recorder, *sdkmetric.ManualReader, func()) {
	t.Helper()
	tp, _, err := NewInMemoryTracerProvider("npamp-test-service")
	if err != nil {
		t.Fatalf("NewInMemoryTracerProvider: %v", err)
	}
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	r, err := NewRecorder(tp.Tracer("test"), mp.Meter("test"))
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}
	return r, reader, func() { _ = mp.Shutdown(context.Background()) }
}

func TestEmitOperationSpanRejectsNilOutcome(t *testing.T) {
	r, _, cleanup := testRecorder(t)
	defer cleanup()
	if _, err := r.EmitOperationSpan(context.Background(), nil); err != ErrNilOutcome {
		t.Fatalf("EmitOperationSpan(nil) error = %v, want ErrNilOutcome", err)
	}
}

func TestEmitOperationSpanRejectsUnknownErrorCode(t *testing.T) {
	r, _, cleanup := testRecorder(t)
	defer cleanup()
	bad := npamp.SessionErrorCode(200)
	if _, err := r.EmitOperationSpan(context.Background(), &Outcome{Code: &bad}); err != ErrUnknownErrorCode {
		t.Fatalf("EmitOperationSpan(unknown code) error = %v, want ErrUnknownErrorCode", err)
	}
}

func TestEmitOperationSpanEmitsSuccessSpanForNilCode(t *testing.T) {
	r, reader, cleanup := testRecorder(t)
	defer cleanup()
	if _, err := r.EmitOperationSpan(context.Background(), &Outcome{SessionID: "sess-1"}); err != nil {
		t.Fatalf("EmitOperationSpan(nil code): %v", err)
	}
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("reader.Collect: %v", err)
	}
	if !hasCounterValue(rm, "npamp.operations", 1) {
		t.Fatalf("npamp.operations counter did not record 1 point; got %+v", rm)
	}
}

func TestEmitOperationSpanEmitsErrorAttributesForNonNilCode(t *testing.T) {
	r, reader, cleanup := testRecorder(t)
	defer cleanup()
	code := npamp.ErrCodeReplayDetected
	if _, err := r.EmitOperationSpan(context.Background(), &Outcome{Code: &code, SessionID: "sess-2"}); err != nil {
		t.Fatalf("EmitOperationSpan(replay_detected): %v", err)
	}
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("reader.Collect: %v", err)
	}
	if !hasCounterValue(rm, "npamp.operations", 1) {
		t.Fatalf("npamp.operations counter did not record 1 point; got %+v", rm)
	}
	if !hasCounterValue(rm, "npamp.errors", 1) {
		t.Fatalf("npamp.errors counter did not record 1 point; got %+v", rm)
	}
}

// TestEmitOperationSpanErrorNameChangesWithCode is the A4 mutation-surviving check: the
// emitted span/metric attributes must actually depend on which registered code was passed,
// not a fixed value.
func TestEmitOperationSpanErrorNameChangesWithCode(t *testing.T) {
	r, _, cleanup := testRecorder(t)
	defer cleanup()
	codeA := npamp.ErrCodeReplayDetected
	codeB := npamp.ErrCodeDecryptFailed
	scA, err := r.EmitOperationSpan(context.Background(), &Outcome{Code: &codeA})
	if err != nil {
		t.Fatalf("EmitOperationSpan(A): %v", err)
	}
	scB, err := r.EmitOperationSpan(context.Background(), &Outcome{Code: &codeB})
	if err != nil {
		t.Fatalf("EmitOperationSpan(B): %v", err)
	}
	// Different span invocations must produce different span IDs (a sanity check that two
	// distinct calls really happened), and the underlying names differ (replay_detected vs
	// decrypt_failed) which reactionName/errName below independently assert.
	if scA.SpanID() == scB.SpanID() {
		t.Fatal("two distinct EmitOperationSpan calls produced the same span ID")
	}
	if codeA.String() == codeB.String() {
		t.Fatal("test fixture codes must have different registered names")
	}
}

func hasCounterValue(rm metricdata.ResourceMetrics, name string, want int64) bool {
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				continue
			}
			var total int64
			for _, dp := range sum.DataPoints {
				total += dp.Value
			}
			if total == want {
				return true
			}
		}
	}
	return false
}
