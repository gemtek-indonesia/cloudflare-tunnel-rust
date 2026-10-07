package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/cloudflare/cloudflared/carrier"
)

type policyCase struct {
	Method       string              `json:"method"`
	Headers      map[string][]string `json:"headers"`
	Coding       string              `json:"coding"`
	Corrupt      bool                `json:"corrupt"`
	Truncate     bool                `json:"truncate"`
	Concatenated bool                `json:"concatenated"`
	Garbage      string              `json:"garbage"`
}

func gzipMember(value string) []byte {
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	_, _ = writer.Write([]byte(value))
	_ = writer.Close()
	return buffer.Bytes()
}
func main() {
	if len(os.Args) > 1 && os.Args[1] == "redirect" {
		redirectCorpus()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "resolve" {
		resolveCorpus()
		return
	}
	for _, name := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy", "REQUEST_METHOD"} {
		_ = os.Unsetenv(name)
	}
	var cases []policyCase
	if err := json.NewDecoder(os.Stdin).Decode(&cases); err != nil {
		panic(err)
	}
	var results []map[string]any
	for _, item := range cases {
		payload := gzipMember("owned-gzip")
		if item.Concatenated {
			payload = append(payload, gzipMember("second-member")...)
		}
		if item.Corrupt {
			payload[len(payload)-8] ^= 1
		}
		if item.Truncate {
			payload = payload[:len(payload)-4]
		}
		payload = append(payload, item.Garbage...)
		encoding := make(chan []string, 1)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			encoding <- append([]string(nil), r.Header.Values("Accept-Encoding")...)
			w.Header().Set("Content-Encoding", item.Coding)
			_, _ = w.Write(payload)
		}))
		request, err := http.NewRequest(item.Method, server.URL, nil)
		if err != nil {
			panic(err)
		}
		for key, values := range item.Headers {
			request.Header[key] = values
		}
		client := &http.Client{Timeout: time.Second}
		response, err := client.Do(request)
		if err != nil {
			panic(err)
		}
		body, readError := io.ReadAll(response.Body)
		_ = response.Body.Close()
		result := map[string]any{"wire_encoding": <-encoding, "wire_body": base64.StdEncoding.EncodeToString(payload), "content_encoding": response.Header.Get("Content-Encoding"), "length": response.ContentLength, "body": base64.StdEncoding.EncodeToString(body), "read_error": readError != nil, "uncompressed": response.Uncompressed}
		results = append(results, result)
		server.Close()
	}
	if err := json.NewEncoder(os.Stdout).Encode(results); err != nil {
		panic(err)
	}
}

type redirectCase struct {
	Base      string              `json:"base"`
	Method    string              `json:"method"`
	Body      string              `json:"body"`
	Host      string              `json:"host"`
	Headers   map[string][]string `json:"headers"`
	Statuses  []int               `json:"statuses"`
	Locations [][]string          `json:"locations"`
}

type redirectTransport struct {
	item     redirectCase
	requests []map[string]any
}

func (transport *redirectTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	var body []byte
	if request.Body != nil {
		body, _ = io.ReadAll(request.Body)
		_ = request.Body.Close()
	}
	headers := make(map[string][]string)
	for name, values := range request.Header {
		headers[strings.ToLower(name)] = values
	}
	host := request.Host
	if host == "" {
		host = request.URL.Host
	}
	target := *request.URL
	target.User = nil
	target.Fragment = ""
	if target.Path == "" {
		target.Path = "/"
	}
	authority := (&url.URL{Host: host}).String()
	transport.requests = append(transport.requests, map[string]any{
		"method": request.Method, "target": target.String(),
		"raw_host": host, "serialized_host": strings.TrimPrefix(authority, "//"), "body": string(body), "headers": headers,
	})
	hop := len(transport.requests) - 1
	status := http.StatusOK
	if hop < len(transport.item.Statuses) {
		status = transport.item.Statuses[hop]
	}
	response := &http.Response{StatusCode: status, Request: request, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), ContentLength: 0}
	if hop < len(transport.item.Locations) {
		response.Header["Location"] = transport.item.Locations[hop]
	}
	return response, nil
}

func redirectCorpus() {
	var cases []redirectCase
	if err := json.NewDecoder(os.Stdin).Decode(&cases); err != nil {
		panic(err)
	}
	var results []map[string]any
	for _, item := range cases {
		request, err := http.NewRequest(item.Method, item.Base, bytes.NewReader([]byte(item.Body)))
		transport := &redirectTransport{item: item}
		status := 0
		if err == nil {
			if item.Host != "" {
				request.Host = item.Host
			}
			for name, values := range item.Headers {
				request.Header[http.CanonicalHeaderKey(name)] = values
			}
			client := &http.Client{Transport: transport}
			response, requestError := client.Do(request)
			err = requestError
			if response != nil {
				status = response.StatusCode
				_ = response.Body.Close()
			}
		}
		results = append(results, map[string]any{"requests": transport.requests, "error": err != nil, "status": status})
	}
	if err := json.NewEncoder(os.Stdout).Encode(results); err != nil {
		panic(err)
	}
}

func resolveCorpus() {
	var cases []map[string]string
	if err := json.NewDecoder(os.Stdin).Decode(&cases); err != nil {
		panic(err)
	}
	results := make([]map[string]any, 0, len(cases))
	for _, item := range cases {
		result := map[string]any{"valid": false}
		request, err := http.NewRequest("HEAD", item["base"], nil)
		if err == nil {
			target, err := request.URL.Parse(item["ref"])
			if err == nil && target.Host != "" && (target.Scheme == "http" || target.Scheme == "https") {
				result["valid"] = true
				result["url"] = target.String()
				result["host"] = target.Host
				result["path"] = target.EscapedPath()
				result["decoded_path"] = base64.StdEncoding.EncodeToString([]byte(target.Path))
				result["query"] = target.RawQuery
				result["request_uri"] = target.RequestURI()
				var wire bytes.Buffer
				wireRequest := &http.Request{Method: http.MethodHead, URL: target, Host: target.Host, Header: make(http.Header)}
				if wireRequest.Write(&wire) == nil {
					if observed, err := http.ReadRequest(bufio.NewReader(&wire)); err == nil {
						result["wire_host"] = observed.Host
					}
				}
				response := &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{item["ref"]}}, Request: request}
				result["login"] = carrier.IsAccessResponse(response)
				result["login_contains"] = strings.Contains(target.Path, "/cdn-cgi/access/login")
				result["authorized_contains"] = strings.Contains(target.Path, "/cdn-cgi/access/authorized")
			}
		}
		results = append(results, result)
	}
	if err := json.NewEncoder(os.Stdout).Encode(results); err != nil {
		panic(err)
	}
}
