use base64::{Engine, engine::general_purpose::STANDARD};
use http::{HeaderMap, HeaderValue};
use opentelemetry::{
    Context, KeyValue,
    trace::{
        Span as _, SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState, Tracer,
        TracerProvider,
    },
};
use opentelemetry_proto::{
    tonic::{collector::trace::v1::ExportTraceServiceRequest, trace::v1::ResourceSpans},
    transform::common::tonic::ResourceAttributesWithSchema,
};
use opentelemetry_sdk::{
    Resource,
    error::OTelSdkResult,
    trace::{Sampler, SdkTracerProvider, Span, SpanData, SpanExporter},
};
use prost::Message;
use std::{
    future::ready,
    sync::{Arc, Mutex},
};

pub(super) const RESPONSE_HEADER: &str = "cf-int-cloudflared-tracing";

#[derive(Debug, Default)]
struct HeaderExporter {
    completed: Arc<Mutex<Vec<ResourceSpans>>>,
    resource: ResourceAttributesWithSchema,
}
impl SpanExporter for HeaderExporter {
    fn export(
        &self,
        batch: Vec<SpanData>,
    ) -> impl std::future::Future<Output = OTelSdkResult> + Send {
        let mut completed = self.completed.lock().unwrap();
        if completed.len() + batch.len() <= 20 {
            completed.extend(
                batch
                    .into_iter()
                    .map(|span| ResourceSpans::new(span, &self.resource)),
            );
        }
        ready(Ok(()))
    }
    fn set_resource(&mut self, resource: &Resource) {
        self.resource = resource.into();
    }
}

#[derive(Default)]
pub(super) struct HttpTrace(Option<TracedRequest>);
struct TracedRequest {
    provider: SdkTracerProvider,
    parent: Context,
    completed: Arc<Mutex<Vec<ResourceSpans>>>,
}
impl HttpTrace {
    pub(super) fn extract(
        headers: &mut HeaderMap,
        logger: &crate::observability::logging::Logger,
    ) -> Self {
        let value = headers
            .get_all("cf-trace-id")
            .iter()
            .next_back()
            .filter(|value| !value.is_empty())
            .cloned();
        headers.remove("cf-trace-id");
        let Some(value) = value else {
            return Self::default();
        };
        let completed = Arc::new(Mutex::new(Vec::new()));
        let parent = std::str::from_utf8(value.as_bytes())
            .ok()
            .and_then(remote_parent)
            .unwrap_or_default();
        let provider = SdkTracerProvider::builder()
            .with_resource(
                Resource::builder_empty()
                    .with_schema_url(
                        [
                            KeyValue::new("service.name", "cloudflared"),
                            KeyValue::new("jaeger.version", "rust-otel-0.33.0"),
                            KeyValue::new(
                                "hostname",
                                crate::observability::management::system_hostname(),
                            ),
                            KeyValue::new(
                                "process.runtime.version",
                                crate::config::UPSTREAM_VERSION,
                            ),
                            KeyValue::new("host.type", "linux"),
                            KeyValue::new("host.arch", "amd64"),
                        ],
                        "https://opentelemetry.io/schemas/1.7.0",
                    )
                    .build(),
            )
            .with_sampler(sampler(logger))
            .with_simple_exporter(HeaderExporter {
                completed: completed.clone(),
                resource: Default::default(),
            })
            .build();
        Self(Some(TracedRequest {
            provider,
            parent,
            completed,
        }))
    }
    pub(super) fn start(&self, name: &'static str) -> Option<Span> {
        let request = self.0.as_ref()?;
        Some(
            request
                .provider
                .tracer("origin")
                .start_with_context(name, &request.parent),
        )
    }
    pub(super) fn response(&self, headers: &mut HeaderMap) {
        let Some(request) = &self.0 else {
            return;
        };
        let mut completed = request.completed.lock().unwrap();
        if completed.is_empty() {
            return;
        }
        let encoded = STANDARD.encode(
            ExportTraceServiceRequest {
                resource_spans: std::mem::take(&mut *completed),
            }
            .encode_to_vec(),
        );
        headers.insert(
            RESPONSE_HEADER,
            HeaderValue::from_str(&encoded).expect("base64 header is ASCII"),
        );
    }
}

fn remote_parent(text: &str) -> Option<Context> {
    let parts: Vec<_> = text.splitn(5, ':').collect();
    if parts.len() != 4 || !matches!(parts[0].len(), 16 | 32) || parts[1].len() != 16 {
        return None;
    }
    if !parts[..2].iter().all(|part| {
        part.bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        return None;
    }
    let trace = TraceId::from_hex(parts[0]).ok()?;
    let span = SpanId::from_hex(parts[1]).ok()?;
    let flags = if parts[3].is_empty() {
        0
    } else {
        i64::from_str_radix(parts[3], 16).ok()?
    };
    let context = SpanContext::new(
        trace,
        span,
        if flags & 1 == 1 {
            TraceFlags::SAMPLED
        } else {
            TraceFlags::default()
        },
        true,
        TraceState::default(),
    );
    context
        .is_valid()
        .then(|| Context::new().with_remote_span_context(context))
}

fn sampler(logger: &crate::observability::logging::Logger) -> Sampler {
    let default = || Sampler::ParentBased(Box::new(Sampler::AlwaysOn));
    let Ok(value) = std::env::var("OTEL_TRACES_SAMPLER") else {
        return default();
    };
    let selected = value.trim().to_ascii_lowercase();
    match selected.as_str() {
        "always_on" => Sampler::AlwaysOn,
        "always_off" => Sampler::AlwaysOff,
        "parentbased_always_on" => default(),
        "parentbased_always_off" => Sampler::ParentBased(Box::new(Sampler::AlwaysOff)),
        "traceidratio" | "parentbased_traceidratio" => {
            let ratio = std::env::var("OTEL_TRACES_SAMPLER_ARG")
                .ok()
                .map(|value| value.trim().parse::<f64>())
                .transpose();
            let ratio = match ratio {
                Ok(None) => 1.0,
                Ok(Some(ratio)) if (0.0..=1.0).contains(&ratio) => ratio,
                _ => {
                    sampler_warning(logger);
                    1.0
                }
            };
            let sampler = Sampler::TraceIdRatioBased(ratio);
            if selected == "traceidratio" {
                sampler
            } else {
                Sampler::ParentBased(Box::new(sampler))
            }
        }
        _ => {
            sampler_warning(logger);
            default()
        }
    }
}
fn sampler_warning(logger: &crate::observability::logging::Logger) {
    let _ = logger.log(
        crate::observability::logging::Level::Warn,
        crate::observability::logging::Event::Cloudflared,
        "Invalid HTTP trace sampler configuration; using the default sampling policy",
        serde_json::json!({}),
    );
}

pub(super) fn end_response(mut span: Option<Span>, status: u16) {
    if let Some(span) = &mut span {
        span.set_attribute(KeyValue::new("upstreamStatusCode", i64::from(status)));
        span.set_status(opentelemetry::trace::Status::Ok);
        span.end();
    }
}
pub(super) fn end_error(mut span: Option<Span>, message: &str) {
    if let Some(span) = &mut span {
        let mut end = message.len().min(100);
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        span.set_status(opentelemetry::trace::Status::error(
            message[..end].to_owned(),
        ));
        span.end();
    }
}
