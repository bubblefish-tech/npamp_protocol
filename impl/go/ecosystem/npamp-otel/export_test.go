// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npampotel

import (
	"context"
	"testing"
)

func TestNewInMemoryTracerProviderRejectsEmptyServiceName(t *testing.T) {
	if _, _, err := NewInMemoryTracerProvider(""); err != ErrEmptyServiceName {
		t.Fatalf("NewInMemoryTracerProvider(\"\") error = %v, want ErrEmptyServiceName", err)
	}
}

func TestNewInMemoryTracerProviderBuildsAWorkingProvider(t *testing.T) {
	tp, exp, err := NewInMemoryTracerProvider("npamp-test-service")
	if err != nil {
		t.Fatalf("NewInMemoryTracerProvider: %v", err)
	}
	if tp == nil || exp == nil {
		t.Fatal("NewInMemoryTracerProvider returned nil provider or exporter")
	}
	_, span := tp.Tracer("test").Start(context.Background(), "test-span")
	span.End()
	spans := exp.GetSpans()
	if len(spans) != 1 || spans[0].Name != "test-span" {
		t.Fatalf("exporter recorded %d spans, want 1 named test-span; got %+v", len(spans), spans)
	}
}

func TestNewOTLPHTTPTracerProviderRejectsEmptyServiceName(t *testing.T) {
	if _, _, err := NewOTLPHTTPTracerProvider(context.Background(), "", "127.0.0.1:4318", true); err != ErrEmptyServiceName {
		t.Fatalf("NewOTLPHTTPTracerProvider(empty service) error = %v, want ErrEmptyServiceName", err)
	}
}

func TestNewOTLPHTTPTracerProviderRejectsEmptyEndpoint(t *testing.T) {
	if _, _, err := NewOTLPHTTPTracerProvider(context.Background(), "npamp-test-service", "", true); err != ErrEmptyEndpoint {
		t.Fatalf("NewOTLPHTTPTracerProvider(empty endpoint) error = %v, want ErrEmptyEndpoint", err)
	}
}

func TestNewOTLPHTTPTracerProviderConstructsLazily(t *testing.T) {
	// otlptracehttp.New dials lazily -- construction against an endpoint with nothing
	// listening MUST still succeed (only an actual export call would surface a connection
	// failure). This is a real SDK component being exercised, not a mock.
	tp, shutdown, err := NewOTLPHTTPTracerProvider(context.Background(), "npamp-test-service", "127.0.0.1:1", true)
	if err != nil {
		t.Fatalf("NewOTLPHTTPTracerProvider: %v", err)
	}
	if tp == nil || shutdown == nil {
		t.Fatal("NewOTLPHTTPTracerProvider returned nil provider or shutdown func")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}
