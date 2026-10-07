package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"github.com/cloudflare/cloudflared/ingress"
	"github.com/cloudflare/cloudflared/management"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
	"io"
	"net/http"
	"testing"
)

type boundaryOrigin struct {
	entered, release chan struct{}
	err              error
	conn             *boundaryConn
}

func (o boundaryOrigin) EstablishConnection(context.Context, string, *zerolog.Logger) (ingress.OriginConnection, error) {
	close(o.entered)
	<-o.release
	return o.conn, o.err
}

type boundaryConn struct{ stream, closed bool }

func (c *boundaryConn) Stream(context.Context, io.ReadWriter, *zerolog.Logger) { c.stream = true }
func (c *boundaryConn) Close() error                                           { c.closed = true; return nil }

type boundaryAck struct {
	headers chan http.Header
	fail    bool
}

func (*boundaryAck) Read([]byte) (int, error)    { return 0, io.EOF }
func (*boundaryAck) Write(p []byte) (int, error) { return len(p), nil }
func (a *boundaryAck) AckConnection(s string) error {
	h := http.Header{}
	if s != "" {
		h.Set("Cf-Int-Cloudflared-Tracing", s)
	}
	a.headers <- h
	if a.fail {
		return errors.New("synthetic ACK failure")
	}
	return nil
}
func boundaryDecode(t *testing.T, s string) []*tracepb.Span {
	t.Helper()
	b, e := base64.StdEncoding.DecodeString(s)
	require.NoError(t, e)
	r := &coltracepb.ExportTraceServiceRequest{}
	require.NoError(t, proto.Unmarshal(b, r))
	var spans []*tracepb.Span
	for _, rs := range r.ResourceSpans {
		for _, ss := range rs.ScopeSpans {
			spans = append(spans, ss.Spans...)
		}
	}
	return spans
}
func TestPinnedGoHTTPTraceStreamOwnershipBoundary(t *testing.T) {
	t.Setenv("OTEL_TRACES_SAMPLER", "parentbased_always_on")
	for _, tc := range []struct {
		name                      string
		sample, failDial, failAck bool
	}{{"sampled", true, false, false}, {"unsampled", false, false, false}, {"dial_error", true, true, false}, {"ack_error", true, false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			flags := "0"
			if tc.sample {
				flags = "1"
			}
			tr := sourceTraceRequest(t, []string{"11111111111111111111111111111111:2222222222222222:0:" + flags})
			_, ingressSpan := tr.Tracer().Start(tr.Context(), "ingress_match")
			ingressSpan.End()
			origin := boundaryOrigin{entered: make(chan struct{}), release: make(chan struct{}), conn: &boundaryConn{}}
			if tc.failDial {
				origin.err = errors.New("synthetic dial failure")
			}
			ack := &boundaryAck{headers: make(chan http.Header, 1), fail: tc.failAck}
			log := zerolog.Nop()
			p := sourceTraceProxy(nil)
			done := make(chan error, 1)
			go func() { done <- p.proxyStream(tr.ToTracedContext(), ack, "127.0.0.1:1", origin, &log) }()
			<-origin.entered
			select {
			case <-ack.headers:
				t.Fatal("ACK preceded establishment")
			default:
			}
			close(origin.release)
			err := <-done
			require.Equal(t, tc.failDial || tc.failAck, err != nil)
			if tc.failDial {
				require.Len(t, ack.headers, 0)
				spans := boundaryDecode(t, base64.StdEncoding.EncodeToString(tr.GetProtoSpans()))
				require.Len(t, spans, 2)
				require.Equal(t, tracepb.Status_STATUS_CODE_ERROR, spans[1].GetStatus().GetCode())
				require.False(t, origin.conn.closed)
				return
			}
			headers := <-ack.headers
			if tc.sample {
				spans := boundaryDecode(t, headers.Get("Cf-Int-Cloudflared-Tracing"))
				require.Len(t, spans, 2)
				require.Equal(t, "stream-connect", spans[1].Name)
				require.Equal(t, tracepb.Status_STATUS_CODE_UNSET, spans[1].GetStatus().GetCode())
				require.Empty(t, spans[1].Attributes)
				require.Equal(t, spans[0].ParentSpanId, spans[1].ParentSpanId)
			} else {
				require.Empty(t, headers)
			}
			require.Empty(t, tr.GetProtoSpans(), "GetSpans drains before even a failed ACK")
			require.Equal(t, !tc.failAck, origin.conn.stream)
			require.True(t, origin.conn.closed)
		})
	}
}
func TestPinnedGoHTTPTraceManagementLocalNoExport(t *testing.T) {
	t.Setenv("OTEL_TRACES_SAMPLER", "parentbased_always_on")
	log := zerolog.Nop()
	m := management.New("management.argotunnel.com", false, "127.0.0.1:1", uuid.Nil, "", &log, nil)
	p := sourceTraceProxy(nil)
	p.ingressRules = ingress.Ingress{Rules: []ingress.Rule{ingress.NewManagementRule(m)}}
	tr := sourceTraceRequest(t, []string{"11111111111111111111111111111111:2222222222222222:0:1"})
	tr.Host = "management.argotunnel.com"
	tr.URL.Path = "/ping"
	tr.URL.RawQuery = "access_token=" + base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"tun":{"id":"00000000-0000-0000-0000-000000000001","account_tag":"synthetic"},"actor":{"id":"synthetic@example.invalid"},"res":["logs"]}`)) + "." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0}, 64))
	w := newMockHTTPRespWriter()
	require.NoError(t, p.ProxyHTTP(w, tr, false))
	require.Equal(t, 200, w.Code)
	require.Empty(t, w.Header().Get("Cf-Int-Cloudflared-Tracing"))
	require.Empty(t, tr.Header.Values("Cf-Trace-Id"))
	spans := boundaryDecode(t, base64.StdEncoding.EncodeToString(tr.GetProtoSpans()))
	require.Len(t, spans, 1)
	require.Equal(t, "ingress_match", spans[0].Name)
	require.Equal(t, tracepb.Status_STATUS_CODE_UNSET, spans[0].GetStatus().GetCode())
}

func TestPinnedGoHTTPTracePublicSocksEstablishmentPrecedesDestinationDial(t *testing.T) {
	t.Setenv("OTEL_TRACES_SAMPLER", "parentbased_always_on")
	p := sourceTraceProxy(nil)
	p.ingressRules = createSingleIngressConfig(t, "socks-proxy")
	tr := sourceTraceRequest(t, []string{"11111111111111111111111111111111:2222222222222222:0:1"})
	tr.Body = io.NopCloser(bytes.NewReader(nil))
	w := newMockHTTPRespWriter()
	require.NoError(t, p.ProxyHTTP(w, tr, true))
	require.Equal(t, 101, w.Code)
	spans := boundaryDecode(t, w.Header().Get("Cf-Int-Cloudflared-Tracing"))
	require.Len(t, spans, 2)
	require.Equal(t, "stream-connect", spans[1].Name)
	require.Equal(t, tracepb.Status_STATUS_CODE_UNSET, spans[1].GetStatus().GetCode())
	require.Empty(t, spans[1].Attributes)
	require.Empty(t, tr.GetProtoSpans())
}
