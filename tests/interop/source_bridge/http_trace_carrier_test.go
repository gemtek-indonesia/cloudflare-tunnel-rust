package connection

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestPinnedGoHTTPTraceH2DirectCarrier(t *testing.T) {
	log := zerolog.Nop()
	req := httptest.NewRequest(http.MethodGet, "http://app.example.invalid/", nil)
	sink := httptest.NewRecorder()
	writer, err := NewHTTP2RespWriter(req, sink, TypeHTTP, &log)
	require.NoError(t, err)
	header := http.Header{"Cf-Int-Cloudflared-Tracing": []string{"source-one", "source-two"}, "X-Ordinary": []string{"user-value"}}
	require.NoError(t, writer.WriteRespHeaders(http.StatusOK, header))
	require.Equal(t, header["Cf-Int-Cloudflared-Tracing"], sink.Header().Values("Cf-Int-Cloudflared-Tracing"))
	users, err := DeserializeHeaders(sink.Header().Get(CanonicalResponseUserHeaders))
	require.NoError(t, err)
	require.Len(t, users, 1)
	require.Equal(t, "X-Ordinary", string(users[0].Name))
	require.Equal(t, "user-value", string(users[0].Value))
}
