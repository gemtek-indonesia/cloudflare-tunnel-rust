use opentelemetry_proto::tonic::{
    collector::trace::v1::ExportTraceServiceRequest,
    common::v1::{AnyValue, InstrumentationScope, KeyValue, any_value::Value},
    resource::v1::Resource,
    trace::v1::{ResourceSpans, ScopeSpans, Span, Status},
};
use prost::Message;
use std::time::{SystemTime, UNIX_EPOCH};
#[derive(Clone)]
pub(crate) struct Identity(pub [u8; 25]);
impl Identity {
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let parts: Vec<_> = text.split(':').collect();
        if parts.len() != 4 || parts[0].is_empty() || parts[0].len() > 32 {
            return None;
        }
        let trace = u128::from_str_radix(parts[0], 16).ok()?;
        let span = u64::from_str_radix(parts[1], 16).ok()?;
        let flags = u8::from_str_radix(parts[3], 16).ok()?;
        let mut bytes = [0; 25];
        bytes[..16].copy_from_slice(&trace.to_be_bytes());
        bytes[16..24].copy_from_slice(&span.to_be_bytes());
        bytes[24] = flags;
        Some(Self(bytes))
    }
    pub(crate) fn sampled(&self) -> bool {
        self.0[24] & 1 != 0
            && self.0[..16].iter().any(|b| *b != 0)
            && self.0[16..24].iter().any(|b| *b != 0)
    }
}
pub(crate) struct Trace {
    identity: Option<Identity>,
    name: String,
    start: u64,
    attributes: Vec<KeyValue>,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(u64::MAX as u128) as u64
}
impl Trace {
    pub(crate) fn new(context: &str, name: &str) -> Self {
        Self {
            identity: Identity::parse(context),
            name: name.into(),
            start: now(),
            attributes: vec![],
        }
    }
    pub(crate) fn with_identity(identity: Identity, name: &str) -> Self {
        Self {
            identity: Some(identity),
            name: name.into(),
            start: now(),
            attributes: vec![],
        }
    }
    pub(crate) fn attribute(mut self, key: &str, value: Value) -> Self {
        self.attributes.push(KeyValue {
            key: key.into(),
            value: Some(AnyValue { value: Some(value) }),
            ..Default::default()
        });
        self
    }
    pub(crate) fn finish(self, error: Option<&str>) -> Vec<u8> {
        let Some(identity) = self.identity.filter(Identity::sampled) else {
            return Vec::new();
        };
        let mut span_id = [0; 8];
        if boring::rand::rand_bytes(&mut span_id).is_err() {
            return Vec::new();
        }
        let span = Span {
            trace_id: identity.0[..16].to_vec(),
            span_id: span_id.to_vec(),
            parent_span_id: identity.0[16..24].to_vec(),
            name: self.name,
            kind: 1,
            start_time_unix_nano: self.start,
            end_time_unix_nano: now(),
            flags: u32::from(identity.0[24]),
            attributes: self.attributes,
            status: error.map(|message| Status {
                message: message.chars().take(100).collect(),
                code: 2,
            }),
            ..Default::default()
        };
        ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(Resource {
                    attributes: [
                        ("service.name", "cloudflared"),
                        ("process.runtime.version", crate::config::UPSTREAM_VERSION),
                        ("host.type", "linux"),
                        ("host.arch", "amd64"),
                    ]
                    .into_iter()
                    .map(|(key, value)| KeyValue {
                        key: key.into(),
                        value: Some(AnyValue {
                            value: Some(Value::StringValue(value.into())),
                        }),
                        ..Default::default()
                    })
                    .collect(),
                    ..Default::default()
                }),
                schema_url: "https://opentelemetry.io/schemas/1.7.0".into(),
                scope_spans: vec![ScopeSpans {
                    scope: Some(InstrumentationScope {
                        name: "origin".into(),
                        ..Default::default()
                    }),
                    spans: vec![span],
                    ..Default::default()
                }],
            }],
        }
        .encode_to_vec()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn span_is_actual_otlp_and_keeps_incoming_parent() {
        let data = Trace::new(
            "11111111111111111111111111111111:2222222222222222:0:1",
            "register-session",
        )
        .finish(None);
        let message = ExportTraceServiceRequest::decode(data.as_slice()).unwrap();
        let span = &message.resource_spans[0].scope_spans[0].spans[0];
        assert_eq!(span.trace_id, [0x11; 16]);
        assert_eq!(span.parent_span_id, [0x22; 8]);
        assert_eq!(span.name, "register-session");
        assert_eq!(span.kind, 1);
        assert_eq!(
            message.resource_spans[0].scope_spans[0]
                .scope
                .as_ref()
                .unwrap()
                .name,
            "origin"
        );
        assert!(span.end_time_unix_nano >= span.start_time_unix_nano);
        assert!(
            Trace::new("invalid", "register-session")
                .finish(None)
                .is_empty()
        );
    }
}
