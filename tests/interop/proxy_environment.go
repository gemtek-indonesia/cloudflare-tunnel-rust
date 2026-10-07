package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

type input struct {
	DialOverride string            `json:"dial_override,omitempty"`
	Environment  map[string]string `json:"environment"`
	Bytes        map[string]string `json:"bytes,omitempty"`
	After        map[string]string `json:"after,omitempty"`
	Unix         string            `json:"unix,omitempty"`
	Host         string            `json:"host,omitempty"`
	Probe        string            `json:"probe,omitempty"`
	Targets      []string          `json:"targets"`
}
type proxy struct {
	Scheme    string  `json:"scheme"`
	Authority string  `json:"authority"`
	Username  *string `json:"username"`
	Password  *string `json:"password"`
}
type result struct {
	Scheme   string `json:"scheme"`
	Hostname string `json:"hostname"`
	Port     string `json:"port"`
	Invalid  bool   `json:"invalid,omitempty"`
	Error    bool   `json:"error"`
	Proxy    *proxy `json:"proxy"`
}

func main() {
	var request input
	if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil {
		panic(err)
	}
	keys := []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy", "REQUEST_METHOD"}
	for _, key := range keys {
		_ = os.Unsetenv(key)
	}
	for key, value := range request.Environment {
		_ = os.Setenv(key, value)
	}
	for key, value := range request.Bytes {
		bytes, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			panic(err)
		}
		_ = os.Setenv(key, string(bytes))
	}
	if request.Probe != "" {
		client := &http.Client{Timeout: 3 * time.Second}
		dialAddress := ""
		if request.DialOverride != "" {
			client.Transport = &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialAddress = address
				return (&net.Dialer{}).DialContext(ctx, network, request.DialOverride)
			}}
		}
		if request.Unix != "" {
			client.Transport = &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", request.Unix)
			}}
		}
		outgoing, err := http.NewRequest(http.MethodGet, request.Probe, nil)
		if err != nil {
			panic(err)
		}
		outgoing.Host = request.Host
		response, err := client.Do(outgoing)
		var body []byte
		if response != nil {
			body, _ = io.ReadAll(response.Body)
			_ = response.Body.Close()
		}
		if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"success": err == nil, "body": base64.StdEncoding.EncodeToString(body), "dial_address": dialAddress}); err != nil {
			panic(err)
		}
		return
	}
	var output []result
	for index, target := range request.Targets {
		if index == 1 {
			for key, value := range request.After {
				_ = os.Setenv(key, value)
			}
		}
		parsed, err := url.Parse(target)
		if err != nil {
			output = append(output, result{Invalid: true})
			continue
		}
		selected, err := http.ProxyFromEnvironment(&http.Request{URL: parsed})
		item := result{Scheme: parsed.Scheme, Hostname: parsed.Hostname(), Port: parsed.Port(), Error: err != nil}
		if selected != nil {
			item.Proxy = &proxy{Scheme: selected.Scheme, Authority: base64.StdEncoding.EncodeToString([]byte(selected.Host))}
			if selected.User != nil {
				username := base64.StdEncoding.EncodeToString([]byte(selected.User.Username()))
				item.Proxy.Username = &username
				if value, present := selected.User.Password(); present {
					password := base64.StdEncoding.EncodeToString([]byte(value))
					item.Proxy.Password = &password
				}
			}
		}
		output = append(output, item)
	}
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		panic(err)
	}
}
