// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package npampotel implements ecosystem task E5.6 (structured telemetry emission mapped to
// the Part-1 R10 error registry, feeding the Part-5/N-AALP OTel work) per requirements.md
// Requirement 8 item 2 (R8.2): "The core SHALL emit structured telemetry mapped to the
// Part-1 R10 error registry."
//
// This is an ECOSYSTEM/adoption-layer package: additive only, no wire/CDDL/frame change. It
// performs no cryptography and computes no wire-level fact of its own -- every byte-level
// fact it reports (a SessionErrorCode's registered name and reaction) is read from the real
// Part-1 reference implementation (impl/go/errorframe.go's SessionErrorCode.String() /
// .Reaction()), never reinvented, matching the "buy-before-make" pattern the sibling
// N-AALP ecosystem/naalp-otel module already follows.
//
// # Shape reference (verify-relay: re-derived, not merely copied)
//
// This package structurally mirrors the sibling N-AALP ecosystem/naalp-otel module (its
// TracerProvider construction in export.go, its Recorder/EmitOperationSpan shape in
// span.go), read directly this session. It deliberately departs from that sibling on ONE
// point: N-PAMP's Part-1 R10 error registry (SessionErrorCode) is a session/handshake-layer
// concept with no gen_ai.* semantic-convention correspondence, so this package emits no
// gen_ai.* attributes at all -- see attrs.go for the full reasoning. Every other structural
// choice (a Recorder holding pre-created instruments, EmitOperationSpan validating its
// input against the real registry before emitting anything, fail-closed on an unresolvable
// input) is the identical, re-derived-as-correct pattern.
package npampotel

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// definedCodes lists every SessionErrorCode this package recognizes as a registered Part-1
// R10 error-registry entry (impl/go/errorframe.go). Cross-checked in span_test.go against
// npamp.SessionErrorCode.String() (which returns a "error_code(0x..)" hex fallback for any
// value NOT in errorframe.go's own errCodeName map) so a registry drift -- a new code added
// upstream, not yet added here -- flips a test rather than silently mis-classifying an
// unresolvable code as resolvable.
var definedCodes = map[npamp.SessionErrorCode]bool{
	npamp.ErrCodeUnexpectedMessage:   true,
	npamp.ErrCodeDecryptFailed:       true,
	npamp.ErrCodeReplayDetected:      true,
	npamp.ErrCodeUnknownChannel:      true,
	npamp.ErrCodeUnknownCriticalTLV:  true,
	npamp.ErrCodeHandshakeTimeout:    true,
	npamp.ErrCodeDowngradeDetected:   true,
	npamp.ErrCodeCloseIncomplete:     true,
	npamp.ErrCodeKeyUpdateOutOfOrder: true,
	npamp.ErrCodeFlowControl:         true,
}

// reactionName renders a real npamp.ErrorReaction as the AttrNpampReaction string value
// this package emits.
func reactionName(r npamp.ErrorReaction) string {
	if r == npamp.ReactionDiscard {
		return reactionDiscard
	}
	return reactionFatal
}

// Outcome describes one observed N-PAMP session outcome -- the input to EmitOperationSpan.
// A nil Code means the operation completed with no registered error (a successful span); a
// non-nil Code names an observed Part-1 R10 error (from a received/decoded ERROR frame,
// impl/go/errorframe.go's DecodeErrorBody, or a locally-detected condition the caller has
// already classified against the same registry).
type Outcome struct {
	Code *npamp.SessionErrorCode

	// SessionID is an OPTIONAL caller-supplied session/connection identifier; "" = omit.
	SessionID string
}

// Recorder holds the OTel instruments EmitOperationSpan uses. Created once per
// tracer/meter pair (NewRecorder), not per call, so instrument creation errors surface at
// setup time rather than being swallowed per-span.
type Recorder struct {
	tracer     trace.Tracer
	opCounter  metric.Int64Counter
	errCounter metric.Int64Counter
}

// NewRecorder builds a Recorder against a real tracer and meter (obtained from a real
// trace.TracerProvider / metric.MeterProvider -- an SDK provider in production, an
// in-memory/manual-reader provider in tests; see export.go and span_test.go). Fails closed
// if instrument creation itself fails (a malformed unit/description would be a programmer
// error in this package, not a runtime input).
func NewRecorder(tracer trace.Tracer, meter metric.Meter) (*Recorder, error) {
	if tracer == nil || meter == nil {
		return nil, fmt.Errorf("npamp/otel: NewRecorder: tracer and meter must both be non-nil")
	}
	opCounter, err := meter.Int64Counter(
		"npamp.operations",
		metric.WithDescription("count of N-PAMP session outcomes emitted as OTel spans (npampotel)"),
		metric.WithUnit("{operation}"),
	)
	if err != nil {
		return nil, fmt.Errorf("npamp/otel: creating npamp.operations counter: %w", err)
	}
	errCounter, err := meter.Int64Counter(
		"npamp.errors",
		metric.WithDescription("count of N-PAMP Part-1 R10 registered error codes observed by npampotel"),
		metric.WithUnit("{error}"),
	)
	if err != nil {
		return nil, fmt.Errorf("npamp/otel: creating npamp.errors counter: %w", err)
	}
	return &Recorder{tracer: tracer, opCounter: opCounter, errCounter: errCounter}, nil
}

// EmitOperationSpan emits one completed span (and the associated npamp.operations /
// npamp.errors metric points) for a single N-PAMP session outcome. It reports on an
// ALREADY-COMPLETED outcome, so the span is started and ended within this call -- there is
// no separate "start" call.
//
// Fail-closed: a nil Outcome, or a non-nil Outcome.Code that does not resolve in the Part-1
// R10 error registry (definedCodes), returns a named error and emits NEITHER a span NOR a
// metric point. A caller MUST NOT treat a returned error as "emit an empty span anyway" --
// there is no code path in this function that does that.
func (r *Recorder) EmitOperationSpan(ctx context.Context, out *Outcome) (trace.SpanContext, error) {
	if out == nil {
		return trace.SpanContext{}, ErrNilOutcome
	}

	failed := out.Code != nil
	var errName, reaction string
	if failed {
		code := *out.Code
		if !definedCodes[code] {
			return trace.SpanContext{}, ErrUnknownErrorCode
		}
		errName = code.String()
		reaction = reactionName(code.Reaction())
	}

	spanName := "npamp.session"
	if failed {
		spanName = "npamp.error." + errName
	}

	attrs := make([]attribute.KeyValue, 0, 5)
	if out.SessionID != "" {
		attrs = append(attrs, attribute.String(AttrNpampSessionID, out.SessionID))
	}
	if failed {
		attrs = append(attrs,
			attribute.Int64(AttrNpampErrorCode, int64(*out.Code)),
			attribute.String(AttrNpampErrorName, errName),
			attribute.String(AttrNpampReaction, reaction),
			attribute.String(AttrErrorType, errName),
		)
	}

	_, span := r.tracer.Start(ctx, spanName, trace.WithAttributes(attrs...))
	if failed {
		span.SetStatus(codes.Error, errName)
	} else {
		span.SetStatus(codes.Ok, "")
	}
	sc := span.SpanContext()
	span.End()

	metricAttrs := make([]attribute.KeyValue, 0, 2)
	if failed {
		metricAttrs = append(metricAttrs,
			attribute.String(AttrNpampErrorName, errName),
			attribute.String(AttrNpampReaction, reaction),
		)
	}
	r.opCounter.Add(ctx, 1, metric.WithAttributes(metricAttrs...))

	if failed {
		r.errCounter.Add(ctx, 1, metric.WithAttributes(
			attribute.String(AttrNpampErrorName, errName),
			attribute.String(AttrNpampReaction, reaction),
		))
	}

	return sc, nil
}
