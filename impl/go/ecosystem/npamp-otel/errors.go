// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npampotel

import "errors"

// Named, fail-closed errors, in this repository's ecosystem-package convention (see e.g.
// npampdiscovery.ErrKeySize -- a plain errors.New sentinel, not a custom error struct
// type). Every rejection returns exactly one of these -- no partial result, no silent
// fallback.
var (
	// ErrNilOutcome is returned when EmitOperationSpan is called with a nil *Outcome.
	ErrNilOutcome = errors.New("npamp/otel: Outcome must not be nil")

	// ErrUnknownErrorCode is returned when Outcome.Code names a SessionErrorCode value not
	// present in the Part-1 R10 error registry this package knows about (definedCodes,
	// span.go) -- emitting error.type from an unresolvable code would be a fabricated name.
	ErrUnknownErrorCode = errors.New("npamp/otel: error code does not resolve in the Part-1 R10 error registry")

	// ErrEmptyServiceName is returned by the provider constructors when serviceName is
	// empty -- a resource with no service.name attribute asserts nothing identifiable.
	ErrEmptyServiceName = errors.New("npamp/otel: serviceName must not be empty")

	// ErrEmptyEndpoint is returned by NewOTLPHTTPTracerProvider when endpoint is empty.
	ErrEmptyEndpoint = errors.New("npamp/otel: endpoint must not be empty")
)
