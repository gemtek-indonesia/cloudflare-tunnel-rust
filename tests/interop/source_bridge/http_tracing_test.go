package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/cloudflare/cloudflared/connection"
	"github.com/cloudflare/cloudflared/ingress"
	"github.com/cloudflare/cloudflared/ingress/middleware"
	"github.com/cloudflare/cloudflared/tracing"
)

type sourceTraceTransport func(*http.Request) (*http.Response, error)

func (f sourceTraceTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func sourceTraceProxy(transport http.RoundTripper) *Proxy {
	log := zerolog.Nop()
	return NewOriginProxy(ingress.Ingress{Rules: []ingress.Rule{{Service: ingress.MockOriginHTTPService{Transport: transport}}}}, nil, nil, nil, &log)
}
func sourceTraceRequest(t *testing.T, values []string) *tracing.TracedHTTPRequest {
	t.Helper()
	tracing.Init("2026.10.0")
	req := httptest.NewRequest("GET", "http://app.example.invalid/path", nil)
	for _, value := range values {
		req.Header.Add("Cf-Trace-Id", value)
	}
	req.Header.Set("Uber-Trace-Id", "unchanged-uber")
	req.Header.Set("Traceparent", "unchanged-w3c")
	log := zerolog.Nop()
	return tracing.NewTracedHTTPRequest(req, 2, &log)
}
func sourceTraceDecode(t *testing.T, value string) []*tracepb.Span {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(value)
	require.NoError(t, err)
	decoded := &coltracepb.ExportTraceServiceRequest{}
	require.NoError(t, proto.Unmarshal(raw, decoded))
	require.Len(t, decoded.ResourceSpans, 2)
	var spans []*tracepb.Span
	for _, resource := range decoded.ResourceSpans {
		require.Equal(t, "https://opentelemetry.io/schemas/1.7.0", resource.SchemaUrl)
		require.Len(t, resource.ScopeSpans, 1)
		attrs := map[string]string{}
		for _, attribute := range resource.Resource.Attributes {
			value, ok := attribute.Value.Value.(*commonpb.AnyValue_StringValue)
			require.True(t, ok)
			attrs[attribute.Key] = value.StringValue
		}
		hostname, err := os.Hostname()
		require.NoError(t, err)
		require.Equal(t, "cloudflared", attrs["service.name"])
		require.Equal(t, "2026.10.0", attrs["process.runtime.version"])
		require.Equal(t, hostname, attrs["hostname"])
		require.Equal(t, "linux", attrs["host.type"])
		require.Equal(t, "amd64", attrs["host.arch"])
		require.True(t, strings.HasPrefix(attrs["jaeger.version"], "go-otel-"))
		require.Equal(t, "origin", resource.ScopeSpans[0].Scope.Name)
		require.Len(t, resource.ScopeSpans[0].Spans, 1)
		spans = append(spans, resource.ScopeSpans[0].Spans[0])
	}
	require.Equal(t, "ingress_match", spans[0].Name)
	require.Equal(t, "ttfb_origin", spans[1].Name)
	require.Equal(t, tracepb.Status_STATUS_CODE_UNSET, spans[0].GetStatus().GetCode())
	require.Equal(t, tracepb.Status_STATUS_CODE_OK, spans[1].GetStatus().GetCode())
	require.Equal(t, tracepb.Span_SPAN_KIND_INTERNAL, spans[0].Kind)
	require.Equal(t, tracepb.Span_SPAN_KIND_INTERNAL, spans[1].Kind)
	return spans
}

func TestPinnedGoHTTPTraceContextAndResponse(t *testing.T) {
	t.Setenv("OTEL_TRACES_SAMPLER", "parentbased_always_on")
	valid := "11111111111111111111111111111111:2222222222222222:ignored:1"
	for _, tc := range []struct {
		name    string
		headers []string
		want    bool
		remote  bool
	}{
		{"absent", nil, false, false}, {"empty", []string{""}, false, false},
		{"sampled", []string{valid}, true, true},
		{"unsampled", []string{strings.TrimSuffix(valid, "1") + "0"}, false, false},
		{"last_empty", []string{valid, ""}, false, false},
		{"last_valid", []string{"bad", valid}, true, true},
		{"last_bad", []string{valid, "bad"}, true, false},
		{"64bit", []string{"1111111111111111:2222222222222222:0:1"}, true, true},
		{"short_private_form", []string{"1:2222222222222222:0:1"}, true, false},
		{"short_span", []string{"11111111111111111111111111111111:2:0:1"}, true, false},
		{"zero_parent", []string{"11111111111111111111111111111111:0000000000000000:0:1"}, true, false},
		{"upper_hex", []string{"ABCDEF11111111111111111111111111:2222222222222222:0:1"}, true, false},
		{"negative_flags", []string{"11111111111111111111111111111111:2222222222222222:0:-1"}, true, true},
		{"empty_flags", []string{"11111111111111111111111111111111:2222222222222222:0:"}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := sourceTraceRequest(t, tc.headers)
			require.Empty(t, request.Header.Values("Cf-Trace-Id"))
			seen := false
			p := sourceTraceProxy(sourceTraceTransport(func(req *http.Request) (*http.Response, error) {
				seen = true
				require.Empty(t, req.Header.Values("Cf-Trace-Id"))
				require.Equal(t, "unchanged-uber", req.Header.Get("Uber-Trace-Id"))
				require.Equal(t, "unchanged-w3c", req.Header.Get("Traceparent"))
				return &http.Response{StatusCode: 503, Header: http.Header{"Cf-Int-Cloudflared-Tracing": []string{"origin-trace"}}, Body: io.NopCloser(strings.NewReader("body"))}, nil
			}))
			writer := newMockHTTPRespWriter()
			require.NoError(t, p.ProxyHTTP(writer, request, false))
			require.True(t, seen)
			encoded := writer.Header().Get("Cf-Int-Cloudflared-Tracing")
			if !tc.want {
				require.Equal(t, "origin-trace", encoded)
				return
			}
			require.NotEqual(t, "origin-trace", encoded)
			spans := sourceTraceDecode(t, encoded)
			if tc.remote {
				require.Equal(t, spans[0].TraceId, spans[1].TraceId)
				require.Len(t, spans[0].ParentSpanId, 8)
				require.Equal(t, uint32(0x301), spans[0].Flags)
			} else {
				require.Empty(t, spans[0].ParentSpanId)
				require.Empty(t, spans[1].ParentSpanId)
				require.NotEqual(t, spans[0].TraceId, spans[1].TraceId)
				require.Equal(t, uint32(0x101), spans[0].Flags)
			}
			require.Empty(t, request.GetProtoSpans(), "successful header export consumes spans")
		})
	}
}

type sourceTraceDeny struct{}

func (sourceTraceDeny) Name() string { return "synthetic-deny" }
func (sourceTraceDeny) Handle(context.Context, *http.Request) (*middleware.HandleResult, error) {
	return &middleware.HandleResult{ShouldFilterRequest: true, StatusCode: 403, Reason: "synthetic"}, nil
}

func TestPinnedGoHTTPTraceFailureDenialAndNilHeaders(t *testing.T) {
	t.Setenv("OTEL_TRACES_SAMPLER", "parentbased_always_on")
	valid := []string{"11111111111111111111111111111111:2222222222222222:0:1"}
	for _, name := range []string{"failure", "middleware", "quick", "status_nil"} {
		t.Run(name, func(t *testing.T) {
			seen := false
			request := sourceTraceRequest(t, valid)
			p := sourceTraceProxy(sourceTraceTransport(func(*http.Request) (*http.Response, error) {
				seen = true
				return nil, errors.New("synthetic origin failure")
			}))
			if name == "middleware" {
				p.ingressRules.Rules[0].Handlers = []middleware.Handler{sourceTraceDeny{}}
			}
			if name == "quick" {
				p.httpRequestAuthorizer = &mockHTTPRequestAuthorizer{}
			}
			if name == "status_nil" {
				p.ingressRules = createSingleIngressConfig(t, "http_status:503")
			}
			writer := newMockHTTPRespWriter()
			err := p.ProxyHTTP(writer, request, false)
			require.Equal(t, name == "failure", err != nil)
			require.Equal(t, name == "failure", seen)
			require.Empty(t, writer.Header().Get("Cf-Int-Cloudflared-Tracing"))
			if name == "quick" {
				require.Empty(t, request.GetProtoSpans())
			} else {
				require.NotEmpty(t, request.GetProtoSpans(), "completed but unexported spans remain owned by request")
			}
		})
	}
}

type sourceTraceWriter struct {
	*mockHTTPRespWriter
	sent chan http.Header
}

func (w *sourceTraceWriter) WriteRespHeaders(code int, headers http.Header) error {
	err := w.mockHTTPRespWriter.WriteRespHeaders(code, headers)
	w.sent <- headers.Clone()
	return err
}

func TestPinnedGoHTTPTraceHeadersCompleteBeforeBodyAndFollowOriginHeaderTime(t *testing.T) {
	t.Setenv("OTEL_TRACES_SAMPLER", "parentbased_always_on")
	entered, release := make(chan struct{}), make(chan struct{})
	body, bodyWriter := io.Pipe()
	defer body.Close()
	defer bodyWriter.Close()
	p := sourceTraceProxy(sourceTraceTransport(func(*http.Request) (*http.Response, error) {
		close(entered)
		<-release
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: body}, nil
	}))
	request := sourceTraceRequest(t, []string{"11111111111111111111111111111111:2222222222222222:0:1"})
	writer := &sourceTraceWriter{newMockHTTPRespWriter(), make(chan http.Header, 1)}
	done := make(chan error, 1)
	go func() { done <- p.ProxyHTTP(writer, request, false) }()
	<-entered
	select {
	case <-writer.sent:
		t.Fatal("headers preceded origin headers")
	default:
	}
	releasedAt := time.Now().UnixNano()
	close(release)
	headers := <-writer.sent
	spans := sourceTraceDecode(t, headers.Get("Cf-Int-Cloudflared-Tracing"))
	require.GreaterOrEqual(t, spans[1].EndTimeUnixNano, uint64(releasedAt))
	require.LessOrEqual(t, spans[0].EndTimeUnixNano, spans[1].StartTimeUnixNano)
	select {
	case <-done:
		t.Fatal("body completed before EOF")
	default:
	}
	require.NoError(t, bodyWriter.Close())
	require.NoError(t, <-done)
}

var _ connection.ResponseWriter = (*sourceTraceWriter)(nil)

func TestPinnedGoHTTPTraceSamplerEnvFraming(t *testing.T) {
	for _, tc := range []struct {
		name, sampler, arg, flags string
		exported                  bool
	}{
		{"trim_case", " PARENTBASED_ALWAYS_ON ", "", "1", true},
		{"off", "always_off", "", "1", false},
		{"on_unsampled", "always_on", "", "0", true},
		{"ratio_zero", "traceidratio", "0", "1", false},
		{"ratio_invalid", "traceidratio", "-1", "0", true},
		{"parent_ratio_zero", "parentbased_traceidratio", "0", "1", true},
		{"unknown", "unsupported", "", "1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OTEL_TRACES_SAMPLER", tc.sampler)
			t.Setenv("OTEL_TRACES_SAMPLER_ARG", tc.arg)
			request := sourceTraceRequest(t, []string{"11111111111111111111111111111111:2222222222222222:0:" + tc.flags})
			p := sourceTraceProxy(sourceTraceTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
			}))
			writer := newMockHTTPRespWriter()
			require.NoError(t, p.ProxyHTTP(writer, request, false))
			value := writer.Header().Get("Cf-Int-Cloudflared-Tracing")
			require.Equal(t, tc.exported, value != "")
			if tc.exported {
				sourceTraceDecode(t, value)
			}
		})
	}
}
