package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"

	"github.com/cloudflare/cloudflared/management"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

func originsCorpus(input string) {
	var cases []struct{ Host, Origin string }
	body, err := os.ReadFile(input)
	must(err)
	must(json.Unmarshal(body, &cases))
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"tun":{"id":"00000000-0000-0000-0000-000000000000","account_tag":"synthetic-account"},"actor":{"id":"synthetic-actor"}}`))
	token := header + "." + claims + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	log := zerolog.Nop()
	service := management.New("management.argotunnel.com", false, "", uuid.Nil, "synthetic", &log, management.NewLogger())
	results := make([]map[string]any, 0, len(cases))
	for _, item := range cases {
		ping := httptest.NewRequest("GET", "http://"+item.Host+"/ping?access_token="+token, nil)
		ping.Header.Set("Origin", item.Origin)
		response := httptest.NewRecorder()
		service.ServeHTTP(response, ping)
		request := httptest.NewRequest("GET", "http://"+item.Host+"/logs?access_token="+token, nil)
		request.Header.Set("Origin", item.Origin)
		request.Header.Set("Connection", "Upgrade")
		request.Header.Set("Upgrade", "websocket")
		request.Header.Set("Sec-WebSocket-Version", "13")
		request.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString([]byte("the sample nonce")))
		websocket := httptest.NewRecorder()
		service.ServeHTTP(websocket, request)
		results = append(results, map[string]any{"cors": response.Header().Get("Access-Control-Allow-Origin"), "vary": response.Header().Get("Vary"), "ws": websocket.Code != 403})
	}
	must(json.NewEncoder(os.Stdout).Encode(results))
}
