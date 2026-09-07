// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npampotel

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// NewOTLPHTTPTracerProvider builds a real OTLP/HTTP trace exporter (E5.6, R8.2) and wraps
// it in a batching TracerProvider. This constructs a real go.opentelemetry.io/otel/sdk
// provider talking the real OTLP/HTTP wire protocol via the stable v1.46.0 exporter --
// nothing here is mocked. It does NOT connect eagerly: otlptracehttp.New only dials lazily
// on the first export, so constructing a provider against an endpoint with nothing
// listening succeeds; only an actual Export/ForceFlush/Shutdown call would surface a
// connection failure. Callers own calling the returned shutdown func exactly once
// (idempotent shutdown is the exporter's own contract, not this package's).
//
// serviceName becomes the resource's service.name attribute. endpoint is a host:port (no
// scheme) per otlptracehttp.WithEndpoint's contract; insecure disables TLS (plaintext
// collector, e.g. a local sidecar) via otlptracehttp.WithInsecure.
func NewOTLPHTTPTracerProvider(ctx context.Context, serviceName, endpoint string, insecure bool) (*sdktrace.TracerProvider, func(context.Context) error, error) {
	if serviceName == "" {
		return nil, nil, ErrEmptyServiceName
	}
	if endpoint == "" {
		return nil, nil, ErrEmptyEndpoint
	}

	opts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(endpoint)}
	if insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	exp, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("npamp/otel: constructing OTLP/HTTP exporter: %w", err)
	}

	res := resource.NewSchemaless(attribute.String(ServiceName, serviceName))

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
	)

	shutdown := func(shutdownCtx context.Context) error {
		if err := tp.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("npamp/otel: tracer provider shutdown: %w", err)
		}
		return nil
	}
	return tp, shutdown, nil
}

// NewInMemoryTracerProvider builds a TracerProvider backed by the OTel SDK's own
// tracetest.InMemoryExporter -- a real SDK component (go.opentelemetry.io/otel/sdk/trace/
// tracetest, part of the stable v1.46.0 sdk module), not a hand-rolled fake. It uses a
// SYNCHRONOUS span processor (sdktrace.WithSyncer, not WithBatcher) so a caller observes
// every span immediately after Span.End() returns, with no batching delay -- the correct
// choice for tests and for a local demo/CLI path, never for a production OTLP export path
// (use NewOTLPHTTPTracerProvider for that). Returned exporter.GetSpans() reads back what
// was recorded; exporter.Reset() clears it between test cases.
func NewInMemoryTracerProvider(serviceName string) (*sdktrace.TracerProvider, *tracetest.InMemoryExporter, error) {
	if serviceName == "" {
		return nil, nil, ErrEmptyServiceName
	}
	exp := tracetest.NewInMemoryExporter()
	res := resource.NewSchemaless(attribute.String(ServiceName, serviceName))
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exp),
		sdktrace.WithResource(res),
	)
	return tp, exp, nil
}
