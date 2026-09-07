// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npampotel

// The OpenTelemetry Go SDK this package builds on (go.opentelemetry.io/otel, .../sdk,
// .../sdk/metric, .../exporters/otlp/otlptrace/otlptracehttp -- all v1.46.0) is the OTel
// project's own stable v1.x line, matching the sibling N-AALP ecosystem/naalp-otel module's
// pinned version (that module's own attrs.go confirms v1.46.0 released 2026-08-25 via the
// Go module proxy). Building against it is real, production-grade dependency use.
//
// Unlike naalp-otel, this package emits NO gen_ai.* attributes: N-PAMP's Part-1 R10 error
// registry (impl/go/errorframe.go, SessionErrorCode) is a session/handshake-layer
// transport-protocol concept with no honest correspondence to any
// open-telemetry/semantic-conventions-genai enum member (that schema names LLM/agent
// operations -- execute_tool, invoke_agent, chat -- not transport error codes), so stretching
// an experimental, zero-tagged-release schema onto it would be exactly the invented-name
// failure the sibling package's own attrs.go documents avoiding. This package therefore
// uses ONLY stable, general OTel semantic-convention attributes ("service.name",
// "error.type" -- both confirmed present and stable at the main
// open-telemetry/semantic-conventions repository) plus its own clearly namespaced npamp.*
// attributes for the error-registry fields N-AALP's gen_ai schema does not cover.
const (
	// ServiceName is the stable, general "service.name" resource attribute.
	ServiceName = "service.name"

	// AttrErrorType is the stable "error.type" attribute (General Attributes,
	// model/error/registry.yaml, id "registry.error", stability: stable at the main
	// open-telemetry/semantic-conventions repository -- confirmed by the sibling
	// naalp-otel/attrs.go's identical citation, re-affirmed here since the RFC/schema
	// text does not change between protocols).
	AttrErrorType = "error.type"
)

// npamp.* attributes: the Part-1 R10 error-registry fields this package maps
// (impl/go/errorframe.go's SessionErrorCode, .String(), .Reaction()) onto structured
// telemetry.
const (
	// AttrNpampErrorCode is the numeric SessionErrorCode value (registries/error_codes.csv).
	AttrNpampErrorCode = "npamp.error.code"
	// AttrNpampErrorName is the registered error name (SessionErrorCode.String()), e.g.
	// "replay_detected".
	AttrNpampErrorName = "npamp.error.name"
	// AttrNpampReaction is the registered reaction (SessionErrorCode.Reaction()): "fatal"
	// (aborts the connection) or "discard" (drops the frame, connection survives).
	AttrNpampReaction = "npamp.reaction"
	// AttrNpampSessionID is an OPTIONAL caller-supplied session/connection identifier;
	// omitted when the caller does not supply one.
	AttrNpampSessionID = "npamp.session_id"
)

// reactionFatal / reactionDiscard are the two AttrNpampReaction string values this package
// emits, matching impl/go/errorframe.go's ErrorReaction enum names.
const (
	reactionFatal   = "fatal"
	reactionDiscard = "discard"
)
