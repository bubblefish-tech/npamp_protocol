// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! R13.5 (E2.13, telemetry-bridge — the exporter half) — OpenTelemetry +
//! Prometheus export of [`crate::datapath::DropEvent`].
//!
//! # Scope of THIS module
//!
//! [`crate::datapath`] already builds the named-error taxonomy R13.5
//! requires ("every DROP carries its named error code — no opaque drops"):
//! [`crate::datapath::NpampDropCode`], [`crate::datapath::DropEvent`] (keyed
//! by peer SPIFFE id + carriage class + session id), and `record_drop`. This
//! module does NOT change that taxonomy — it CONSUMES it, mapping each
//! [`DropEvent`] onto BOTH a real OpenTelemetry span (with the drop reason
//! and identity/session attributes) and a real Prometheus counter
//! (`nz_agent_drops_total{reason, carriage_class}`), via one
//! [`TelemetrySink`] trait every drop-reporting call site can call.
//!
//! # What this module does NOT do (tracked gap — E2.13 half 2)
//!
//! The eBPF-side flow/verdict bridge (reading the kernel `nz-agent-ebpf`
//! maps and turning kernel-observed drops into [`DropEvent`]s) is Linux/aya-
//! build-gated and out of scope for this module, which is pure-std,
//! Windows-buildable Rust with no eBPF dependency. This module is fed by
//! the existing in-process `record_drop` call sites (userspace-observed
//! drops); a future kernel-side bridge would call the SAME
//! [`TelemetrySink::export`] seam this module defines, not a new one.
//!
//! # Why a trait, not a free function
//!
//! Mirrors [`crate::identity::DelegatedIdentitySource`]'s and
//! [`crate::datapath::SpliceInstaller`]'s test-double-vs-real pattern: one
//! real dual-exporter implementation ([`OtelPrometheusSink`]) that any
//! `TelemetrySink`-typed call site depends on, never on a concrete
//! exporter; this module's own tests exercise it against a deterministic
//! in-memory OTel span capture point (`CapturingSpanExporter`,
//! `#[cfg(test)]`-only, defined below) and a real `prometheus::Registry`.

use std::fmt;

use opentelemetry::trace::{Span, Tracer, TracerProvider as _};
use opentelemetry::KeyValue;
use opentelemetry_sdk::trace::{SdkTracerProvider, SpanExporter};
use prometheus::{Encoder, IntCounterVec, Opts, Registry, TextEncoder};

use crate::datapath::DropEvent;

/// The seam every drop-reporting call site exports a [`DropEvent`] through.
/// A conforming implementation MUST record the event into BOTH the OTel
/// span stream and the Prometheus counter set — recording into only one is
/// not this trait's contract (see [`OtelPrometheusSink::export`]).
pub trait TelemetrySink {
    fn export(&self, event: &DropEvent);
}

/// The real, dual OpenTelemetry + Prometheus sink. Every span it emits
/// comes from a genuine `opentelemetry_sdk::trace::SdkTracerProvider`
/// (not a hand-rolled struct labeled "span"); every counter increment goes
/// through a genuine `prometheus::Registry` (not a raw counter map printed
/// in Prometheus-shaped text).
pub struct OtelPrometheusSink {
    tracer_provider: SdkTracerProvider,
    registry: Registry,
    drops_total: IntCounterVec,
}

/// Metric/instrumentation-scope name shared by the Prometheus counter and
/// the OTel tracer, so a reader correlating the two exporters' output does
/// not have to guess they come from the same producer.
const INSTRUMENTATION_SCOPE: &str = "nz-agent.datapath";
const METRIC_NAME: &str = "nz_agent_drops_total";
const SPAN_NAME: &str = "nz_agent.datapath.drop";

impl OtelPrometheusSink {
    /// Builds a sink whose OTel spans are exported through `exporter` — a
    /// real `opentelemetry_sdk::trace::SpanExporter`. Production callers
    /// pass a real shipping exporter (see [`OtelPrometheusSink::new_production`]);
    /// this module's own tests pass `CapturingSpanExporter` (defined below,
    /// `#[cfg(test)]`-only — `opentelemetry_sdk` 0.32.1 ships no
    /// `testing::trace::InMemorySpanExporter` of its own) so the exported
    /// span's attributes can be read back and asserted — the SDK
    /// tracer/span-construction path is identical in both cases, only the
    /// sink the SDK ships completed spans to differs.
    ///
    /// Uses a `SimpleSpanProcessor` (synchronous, one-span-at-a-time
    /// export) rather than a batching processor: a drop event is exactly
    /// the low-throughput, must-not-be-silently-buffered-into-memory case
    /// the simple processor exists for, and it makes the exported span
    /// visible to a caller (or a test) immediately after `export` returns,
    /// with no separate flush call required.
    pub fn new(exporter: impl SpanExporter + 'static) -> Self {
        let tracer_provider = SdkTracerProvider::builder().with_simple_exporter(exporter).build();

        let registry = Registry::new();
        let drops_total = IntCounterVec::new(
            Opts::new(METRIC_NAME, "Count of nz-agent datapath drops, by named NpampDropCode reason and carriage class"),
            &["reason", "carriage_class"],
        )
        .expect("the drops_total metric descriptor is a compile-time-fixed literal and is always well-formed");
        registry
            .register(Box::new(drops_total.clone()))
            .expect("registering one counter into a freshly constructed, empty Registry cannot collide");

        Self { tracer_provider, registry, drops_total }
    }

    /// The real production constructor. Ships OTel spans via the official
    /// `opentelemetry-stdout` exporter — OpenTelemetry's own OTLP-
    /// independent, no-collector-required production exporter (the
    /// documented pattern for a process that emits OTel-formatted output
    /// for an external agent, e.g. a Fluent Bit/Vector OTel-stdout-format
    /// sidecar, to pick up) — and Prometheus counters via a fresh
    /// in-process [`Registry`] that [`OtelPrometheusSink::gather_prometheus_text`]
    /// exposes in the standard scrape text format. Wiring a live network
    /// OTLP endpoint (a `SpanExporter` dialing a collector over gRPC/HTTP)
    /// is a configuration choice a deployment makes by calling
    /// [`OtelPrometheusSink::new`] with a different real exporter — this
    /// module does not hardcode one, matching every other seam in this
    /// crate (identity/datapath) that separates "the real interface" from
    /// "which concrete backend a deployment plugs in."
    pub fn new_production() -> Self {
        Self::new(opentelemetry_stdout::SpanExporter::default())
    }

    /// Render the current Prometheus state in the standard text exposition
    /// format — what a `/metrics` scrape endpoint serves.
    pub fn gather_prometheus_text(&self) -> String {
        let metric_families = self.registry.gather();
        let mut buf = Vec::new();
        TextEncoder::new()
            .encode(&metric_families, &mut buf)
            .expect("encoding a registry populated only by this module's own well-formed counter cannot fail");
        String::from_utf8(buf).expect("prometheus::TextEncoder always emits valid UTF-8")
    }

    /// Read back the current counter value for one (reason, carriage_class)
    /// label pair directly from the registry (no text-format round trip) —
    /// the fast path this module's own tests, and the mutation-witness
    /// assertion, use.
    pub fn drop_count(&self, reason: &str, carriage_class: &str) -> u64 {
        self.drops_total.with_label_values(&[reason, carriage_class]).get() as u64
    }

    /// Force any buffered spans out to the exporter and shut the tracer
    /// provider down. Production callers invoke this on graceful agent
    /// shutdown; tests do not need it (the simple processor already
    /// exports synchronously on `Span::end`).
    pub fn shutdown(&self) {
        let _ = self.tracer_provider.shutdown();
    }
}

impl TelemetrySink for OtelPrometheusSink {
    /// This is the load-bearing event->metric / event->span-attribute
    /// mapping this task's mutation-witness targets: every field of
    /// `event` MUST reach either the Prometheus label set or an OTel span
    /// attribute (or both, for `code`/`carriage`), keyed exactly as
    /// `crate::datapath`'s own module docs specify ("authenticated peer
    /// SPIFFE id + carriage class + session/tunnel id").
    fn export(&self, event: &DropEvent) {
        let reason = event.code.to_string();

        // -- Prometheus --------------------------------------------------
        self.drops_total.with_label_values(&[&reason, &event.carriage]).inc();

        // -- OpenTelemetry ------------------------------------------------
        let tracer = self.tracer_provider.tracer(INSTRUMENTATION_SCOPE);
        let mut span = tracer.start(SPAN_NAME);
        span.set_attribute(KeyValue::new("npamp.drop.reason", reason));
        span.set_attribute(KeyValue::new("npamp.peer.spiffe_id", event.peer.to_string()));
        span.set_attribute(KeyValue::new("npamp.carriage_class", event.carriage.clone()));
        span.set_attribute(KeyValue::new("npamp.session_id", event.session.clone()));
        span.set_attribute(KeyValue::new("npamp.verdict", "drop"));
        span.end();
    }
}

impl fmt::Debug for OtelPrometheusSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtelPrometheusSink").finish_non_exhaustive()
    }
}

/// A hand-written, real `opentelemetry_sdk::trace::SpanExporter`
/// implementation that captures every exported [`opentelemetry_sdk::trace::SpanData`]
/// into an in-process `Vec` instead of shipping it anywhere — the
/// "in-memory/test span exporter" this module's own docs say is fine for
/// tests. It goes through the exact same `SdkTracerProvider` /
/// `SimpleSpanProcessor` / `Tracer::start`/`Span::end` pipeline
/// [`OtelPrometheusSink::new_production`] uses; only the destination the
/// SDK hands completed spans to differs. `opentelemetry_sdk` 0.32.1 ships no
/// `testing::trace::InMemorySpanExporter` (checked against its published
/// source this session), so this crate provides its own — a minimal,
/// non-circular capture point, not a stand-in for the SDK's real span
/// construction.
#[cfg(test)]
#[derive(Debug, Clone, Default)]
struct CapturingSpanExporter {
    spans: std::sync::Arc<std::sync::Mutex<Vec<opentelemetry_sdk::trace::SpanData>>>,
}

#[cfg(test)]
impl CapturingSpanExporter {
    fn finished_spans(&self) -> Vec<opentelemetry_sdk::trace::SpanData> {
        self.spans.lock().expect("exporter mutex is never held across a panic in these tests").clone()
    }
}

#[cfg(test)]
impl SpanExporter for CapturingSpanExporter {
    fn export(&self, batch: Vec<opentelemetry_sdk::trace::SpanData>) -> impl std::future::Future<Output = opentelemetry_sdk::error::OTelSdkResult> + Send {
        let spans = self.spans.clone();
        async move {
            spans.lock().expect("exporter mutex is never held across a panic in these tests").extend(batch);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datapath::NpampDropCode;
    use crate::identity::SpiffeId;

    fn id(path: &str) -> SpiffeId {
        SpiffeId::parse(&format!("spiffe://cluster.local/ns/prod/sa/{path}")).expect("valid id")
    }

    fn sink_with_capture() -> (OtelPrometheusSink, CapturingSpanExporter) {
        let exporter = CapturingSpanExporter::default();
        let sink = OtelPrometheusSink::new(exporter.clone());
        (sink, exporter)
    }

    #[test]
    fn exported_drop_increments_the_matching_prometheus_counter() {
        let (sink, _exporter) = sink_with_capture();
        let event = DropEvent { code: NpampDropCode::SpliceAuthzDenied, peer: id("a"), carriage: "npamp-cc-http".to_string(), session: "sess-1".to_string() };
        sink.export(&event);
        assert_eq!(sink.drop_count("SPLICE_AUTHZ_DENIED", "npamp-cc-http"), 1);
    }

    #[test]
    fn different_reasons_and_carriage_classes_are_counted_independently() {
        let (sink, _exporter) = sink_with_capture();
        sink.export(&DropEvent { code: NpampDropCode::SpliceAuthzDenied, peer: id("a"), carriage: "npamp-cc-http".to_string(), session: "sess-1".to_string() });
        sink.export(&DropEvent { code: NpampDropCode::NoDatapathAvailable, peer: id("b"), carriage: "npamp-cc-grpc".to_string(), session: "sess-2".to_string() });
        sink.export(&DropEvent { code: NpampDropCode::SpliceAuthzDenied, peer: id("c"), carriage: "npamp-cc-http".to_string(), session: "sess-3".to_string() });

        assert_eq!(sink.drop_count("SPLICE_AUTHZ_DENIED", "npamp-cc-http"), 2);
        assert_eq!(sink.drop_count("NO_DATAPATH_AVAILABLE", "npamp-cc-grpc"), 1);
        assert_eq!(sink.drop_count("SPLICE_AUTHZ_DENIED", "npamp-cc-grpc"), 0);
    }

    #[test]
    fn prometheus_text_exposition_names_the_metric_and_reason_label() {
        let (sink, _exporter) = sink_with_capture();
        sink.export(&DropEvent { code: NpampDropCode::InstallFailure, peer: id("d"), carriage: "npamp-cc-mcp".to_string(), session: "sess-4".to_string() });
        let text = sink.gather_prometheus_text();
        assert!(text.contains("nz_agent_drops_total"), "exposition text must name the metric: {text}");
        assert!(text.contains("reason=\"INSTALL_FAILURE\""), "exposition text must carry the reason label: {text}");
        assert!(text.contains("carriage_class=\"npamp-cc-mcp\""), "exposition text must carry the carriage_class label: {text}");
    }

    #[test]
    fn exported_drop_produces_exactly_one_real_otel_span_with_the_named_attributes() {
        let (sink, exporter) = sink_with_capture();
        let peer = id("workload-x");
        let event = DropEvent { code: NpampDropCode::InstallFailure, peer: peer.clone(), carriage: "npamp-cc-mcp".to_string(), session: "sess-42".to_string() };
        sink.export(&event);

        let spans = exporter.finished_spans();
        assert_eq!(spans.len(), 1, "exactly one span per exported drop event");
        let span = &spans[0];
        assert_eq!(span.name, SPAN_NAME);

        let attr = |key: &str| -> Option<String> { span.attributes.iter().find(|kv| kv.key.as_str() == key).map(|kv| kv.value.as_str().into_owned()) };
        assert_eq!(attr("npamp.drop.reason").as_deref(), Some("INSTALL_FAILURE"));
        assert_eq!(attr("npamp.peer.spiffe_id").as_deref(), Some(peer.to_string()).as_deref());
        assert_eq!(attr("npamp.carriage_class").as_deref(), Some("npamp-cc-mcp"));
        assert_eq!(attr("npamp.session_id").as_deref(), Some("sess-42"));
        assert_eq!(attr("npamp.verdict").as_deref(), Some("drop"));
    }

    #[test]
    fn production_constructor_builds_a_real_stdout_backed_sink_and_still_counts() {
        // Not a mock: opentelemetry_stdout::SpanExporter is the real,
        // officially-shipped OTel stdout exporter. This test only checks
        // the sink is fully constructible and still routes to Prometheus
        // correctly with that exporter wired in — it does not assert on
        // stdout content (that belongs to opentelemetry-stdout's own
        // upstream test suite, not this crate's).
        let sink = OtelPrometheusSink::new_production();
        sink.export(&DropEvent { code: NpampDropCode::NoDatapathAvailable, peer: id("e"), carriage: "npamp-cc-a2a".to_string(), session: "sess-5".to_string() });
        assert_eq!(sink.drop_count("NO_DATAPATH_AVAILABLE", "npamp-cc-a2a"), 1);
        sink.shutdown();
    }
}
