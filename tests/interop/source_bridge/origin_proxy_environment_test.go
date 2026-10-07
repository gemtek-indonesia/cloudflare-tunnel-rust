package ingress

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"context"
	"github.com/cloudflare/cloudflared/config"
	"github.com/rs/zerolog"
)

func TestRustOriginProxyEnvironmentContract(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"request.invalid", "physical.invalid", "configured.invalid"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	root := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(root, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	type names struct{ first, target string }
	observed := make(chan names, 4)
	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Host != "physical.invalid:443" {
			t.Errorf("unexpected owned CONNECT target")
			w.WriteHeader(400)
			return
		}
		conn, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = buffered.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
		_ = buffered.Flush()
		target := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}})
		if err := target.Handshake(); err != nil {
			t.Error(err)
			return
		}
		observed <- names{r.TLS.ServerName, target.ConnectionState().ServerName}
		request, err := http.ReadRequest(bufio.NewReader(target))
		if err != nil {
			t.Error(err)
			return
		}
		_ = request.Body.Close()
		_, _ = io.WriteString(target, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nowned")
	}))
	firstProtocols := make(chan []string, 4)
	proxy.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		firstProtocols <- append([]string(nil), hello.SupportedProtos...)
		return nil, nil
	}}
	proxy.StartTLS()
	defer proxy.Close()
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "http://origin-host.invalid/raw?x=%ff" || r.Host != "origin-host.invalid" {
			t.Errorf("unexpected source HTTP proxy target %q", r.URL.String())
		}
		_, _ = io.WriteString(w, "owned")
	}))
	defer plain.Close()
	for _, key := range []string{"http_proxy", "https_proxy", "NO_PROXY", "no_proxy", "REQUEST_METHOD"} {
		t.Setenv(key, "")
	}
	t.Setenv("HTTP_PROXY", plain.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	log := zerolog.Nop()
	for _, item := range []struct {
		match, configured bool
		first, target     string
	}{
		{false, false, "", "physical.invalid"},
		{false, true, "configured.invalid", "configured.invalid"},
		{true, false, "request.invalid", "physical.invalid"},
		{true, true, "request.invalid", "configured.invalid"},
	} {
		physical, _ := url.Parse("https://physical.invalid:443/")
		service := &httpService{url: physical}
		cfg := OriginRequestConfig{CAPool: root, HTTPHostHeader: "request.invalid", MatchSNIToHost: item.match, Http2Origin: true}
		if item.configured {
			cfg.OriginServerName = "configured.invalid"
		}
		if err := service.start(&log, nil, cfg); err != nil {
			t.Fatal(err)
		}
		request, _ := http.NewRequest("GET", "https://incoming.invalid/", nil)
		response, err := service.RoundTrip(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		service.transport.CloseIdleConnections()
		select {
		case got := <-observed:
			protocols := <-firstProtocols
			if item.match && len(protocols) != 0 {
				t.Fatalf("custom proxy first hop advertised ALPN %v", protocols)
			}
			if !item.match && (len(protocols) != 2 || protocols[0] != "h2" || protocols[1] != "http/1.1") {
				t.Fatalf("standard proxy ALPN %v", protocols)
			}
			if got != (names{item.first, item.target}) {
				t.Fatalf("source TLS names = %v, expected %v", got, names{item.first, item.target})
			}
		case <-time.After(3 * time.Second):
			t.Fatal("owned TLS names absent")
		}
	}
	direct := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "request.invalid" {
			t.Errorf("effective source authority %q", r.Host)
		}
		_, _ = io.WriteString(w, "owned")
	}))
	direct.EnableHTTP2 = true
	offeredProtocols := make(chan []string, 2)
	direct.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		offeredProtocols <- append([]string(nil), hello.SupportedProtos...)
		return nil, nil
	}}
	direct.StartTLS()
	defer direct.Close()
	for _, match := range []bool{false, true} {
		physical, _ := url.Parse(direct.URL)
		service := &httpService{url: physical}
		cfg := OriginRequestConfig{CAPool: root, HTTPHostHeader: "request.invalid", Http2Origin: true, MatchSNIToHost: match}
		if err := service.start(&log, nil, cfg); err != nil {
			t.Fatal(err)
		}
		request, _ := http.NewRequest("GET", "https://incoming.invalid/", nil)
		response, err := service.RoundTrip(request)
		if err != nil {
			t.Fatal(err)
		}
		expected := 2
		if match {
			expected = 1
		}
		offered := <-offeredProtocols
		if match && len(offered) != 0 {
			t.Fatalf("custom first hop advertised ALPN %v", offered)
		}
		if !match && (len(offered) != 2 || offered[0] != "h2" || offered[1] != "http/1.1") {
			t.Fatalf("standard first-hop ALPN %v", offered)
		}
		if response.ProtoMajor != expected {
			t.Fatalf("direct match=%v protocol=%d, expected=%d", match, response.ProtoMajor, expected)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		service.transport.CloseIdleConnections()
	}
	for _, item := range []struct{ match, proxy bool }{{false, false}, {true, false}, {false, true}, {true, true}} {
		match := item.match
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		accepted := make(chan struct{})
		closed := make(chan struct{})
		go func() {
			defer close(closed)
			socket, err := listener.Accept()
			if err != nil {
				return
			}
			defer socket.Close()
			first := make([]byte, 1)
			if _, err := io.ReadFull(socket, first); err != nil {
				return
			}
			close(accepted)
			_, _ = io.Copy(io.Discard, socket)
		}()
		physical, _ := url.Parse("https://" + listener.Addr().String())
		service := &httpService{url: physical}
		if err := service.start(&log, nil, OriginRequestConfig{CAPool: root, HTTPHostHeader: "request.invalid", MatchSNIToHost: match, TLSTimeout: config.CustomDuration{Duration: 20 * time.Millisecond}}); err != nil {
			t.Fatal(err)
		}
		if item.proxy {
			proxyURL, _ := url.Parse("https://" + listener.Addr().String())
			service.url, _ = url.Parse("https://physical.invalid/")
			service.transport.Proxy = func(*http.Request) (*url.URL, error) { return proxyURL, nil }
		}
		ctx, cancel := context.WithCancel(context.Background())
		request, _ := http.NewRequestWithContext(ctx, "GET", "https://incoming.invalid/", nil)
		finished := make(chan error, 1)
		go func() { _, err := service.RoundTrip(request); finished <- err }()
		select {
		case <-accepted:
		case <-time.After(time.Second):
			t.Fatal("owned held handshake absent")
		}
		if match {
			select {
			case err := <-finished:
				t.Fatalf("custom first hop used configured TLS deadline: %v", err)
			case <-time.After(60 * time.Millisecond):
			}
			cancel()
			select {
			case err := <-finished:
				if err == nil {
					t.Fatal("canceled custom handshake succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("custom handshake ignored request cancellation")
			}
		} else {
			select {
			case err := <-finished:
				if err == nil {
					t.Fatal("held default handshake succeeded")
				}
			case <-time.After(60 * time.Millisecond):
				t.Fatal("default handshake ignored configured TLS deadline")
			}
			cancel()
		}
		service.transport.CloseIdleConnections()
		_ = listener.Close()
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("owned held handshake socket leaked")
		}
	}
	physical, _ := url.Parse("http://physical.invalid:080/")
	service := &httpService{url: physical}
	if err := service.start(&log, nil, OriginRequestConfig{CAPool: root, HTTPHostHeader: "origin-host.invalid"}); err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest("GET", "https://incoming.invalid/raw?x=%ff", nil)
	response, err := service.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	service.transport.CloseIdleConnections()
	path := filepath.Join(t.TempDir(), "origin.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	unixServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "http://incoming.invalid/raw?x=%ff" || r.Host != "incoming.invalid" {
			t.Errorf("source Unix Host override unexpectedly applied")
		}
		_, _ = io.WriteString(w, "owned")
	})}
	defer unixServer.Close()
	go func() { _ = unixServer.Serve(listener) }()
	unix := &unixSocketPath{path: path, scheme: "http"}
	if err := unix.start(&log, nil, OriginRequestConfig{CAPool: root, HTTPHostHeader: "ignored.invalid", MatchSNIToHost: true}); err != nil {
		t.Fatal(err)
	}
	request, _ = http.NewRequest("GET", "https://incoming.invalid/raw?x=%ff", nil)
	response, err = unix.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	unix.transport.CloseIdleConnections()
}
