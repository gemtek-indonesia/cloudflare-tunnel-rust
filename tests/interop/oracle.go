package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"time"

	cfaccess "github.com/cloudflare/cloudflared/cmd/cloudflared/access"
	cftunnel "github.com/cloudflare/cloudflared/cmd/cloudflared/tunnel"
	"github.com/cloudflare/cloudflared/config"
	"github.com/cloudflare/cloudflared/connection"
	"github.com/cloudflare/cloudflared/ingress"
	quicwire "github.com/cloudflare/cloudflared/quic"
	v3 "github.com/cloudflare/cloudflared/quic/v3"
	"github.com/cloudflare/cloudflared/tunnelrpc"
	"github.com/cloudflare/cloudflared/tunnelrpc/pogs"
	rpcquic "github.com/cloudflare/cloudflared/tunnelrpc/quic"
	"github.com/cloudflare/cloudflared/validation"
	"github.com/google/uuid"
	"github.com/urfave/cli/v2/altsrc"
	capnp "zombiezen.com/go/capnproto2"
)

var fixtureID = uuid.MustParse("11111111-1111-4111-8111-111111111111")
var fixtureClient = uuid.MustParse("22222222-2222-4222-8222-222222222222")
var fixtureConnection = uuid.MustParse("33333333-3333-4333-8333-333333333333")

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func file(dir, name string, data []byte) { must(os.WriteFile(filepath.Join(dir, name), data, 0600)) }

func fixtures(dir string) {
	must(os.MkdirAll(dir, 0700))
	request := pogs.ConnectRequest{Dest: "https://example.invalid/path", Type: pogs.ConnectionTypeHTTP,
		Metadata: []pogs.Metadata{{Key: "HttpMethod", Val: "POST"}, {Key: "HttpHeader:X-Test", Val: "first"}, {Key: "HttpHeader:X-Test", Val: "second"}}}
	message, err := request.ToPogs()
	must(err)
	var encoded bytes.Buffer
	encoded.Write([]byte{0x0a, 0x36, 0xcd, 0x12, 0xa1, 0x3e, '0', '1'})
	must(capnp.NewEncoder(&encoded).Encode(message))
	encoded.WriteString("synthetic body")
	file(dir, "go-request.bin", encoded.Bytes())
	h := http.Header{"Set-Cookie": []string{"a=1", "b=2"}, "X-Binary": []string{string([]byte{0xff, ':', ';'})}}
	file(dir, "go-headers.txt", []byte(connection.SerializeHeaders(h)))
	payload, err := quicwire.SuffixSessionID(fixtureID, []byte{0, 1, 255})
	must(err)
	payload, err = quicwire.SuffixType(payload, quicwire.DatagramTypeUDP)
	must(err)
	file(dir, "go-v2.bin", payload)
	id, err := v3.RequestIDFromSlice(fixtureID[:])
	must(err)
	registration := v3.UDPSessionRegistrationDatagram{RequestID: id, Dest: netip.MustParseAddrPort("[2001:db8::1]:53"), Traced: true, IdleDurationHint: 210 * time.Second, Payload: []byte{0, 1, 255}}
	binary, err := registration.MarshalBinary()
	must(err)
	file(dir, "go-v3.bin", binary)
	response := v3.UDPSessionRegistrationResponseDatagram{RequestID: id, ResponseType: v3.ResponseErrorWithMsg, ErrorMsg: "synthetic error"}
	binary, err = response.MarshalBinary()
	must(err)
	file(dir, "go-v3-response.bin", binary)
}

func decode(dir string) {
	f, err := os.Open(filepath.Join(dir, "rust-request.bin"))
	must(err)
	defer f.Close()
	signature := make([]byte, 8)
	_, err = io.ReadFull(f, signature)
	must(err)
	if !bytes.Equal(signature, []byte{0x0a, 0x36, 0xcd, 0x12, 0xa1, 0x3e, '0', '1'}) {
		panic("wrong data preamble")
	}
	message, err := capnp.NewDecoder(f).Decode()
	must(err)
	var request pogs.ConnectRequest
	must(request.FromPogs(message))
	if request.Dest != "https://example.invalid/path" || request.Type != pogs.ConnectionTypeHTTP || !reflect.DeepEqual(request.Metadata, []pogs.Metadata{{Key: "HttpMethod", Val: "POST"}, {Key: "HttpHeader:X-Test", Val: "first"}, {Key: "HttpHeader:X-Test", Val: "second"}}) {
		panic("wrong request fields")
	}
	rest, err := io.ReadAll(f)
	must(err)
	if string(rest) != "synthetic body" {
		panic("metadata consumed body")
	}
	headers, err := os.ReadFile(filepath.Join(dir, "rust-headers.txt"))
	must(err)
	pairs, err := connection.DeserializeHeaders(string(headers))
	must(err)
	var cookies []string
	var binaryHeader string
	for _, pair := range pairs {
		if pair.Name == "Set-Cookie" {
			cookies = append(cookies, pair.Value)
		}
		if pair.Name == "X-Binary" {
			binaryHeader = pair.Value
		}
	}
	sort.Strings(cookies)
	if len(pairs) != 3 || !reflect.DeepEqual(cookies, []string{"a=1", "b=2"}) || binaryHeader != string([]byte{255, ':', ';'}) {
		panic("header duplicates lost")
	}
	binary, err := os.ReadFile(filepath.Join(dir, "rust-v3.bin"))
	must(err)
	var datagram v3.UDPSessionRegistrationDatagram
	must(datagram.UnmarshalBinary(binary))
	if datagram.Dest != netip.MustParseAddrPort("[2001:db8::1]:53") || !datagram.Traced || datagram.IdleDurationHint != 210*time.Second || !bytes.Equal(datagram.Payload, []byte{0, 1, 255}) {
		panic("v3 mismatch")
	}
	response, err := os.ReadFile(filepath.Join(dir, "rust-response.bin"))
	must(err)
	stream := rpcquic.RequestClientStream{ReadWriteCloser: readCloser{bytes.NewBuffer(response)}}
	result, err := stream.ReadConnectResponseData()
	must(err)
	if result.Error != "synthetic error" || !reflect.DeepEqual(result.Metadata, []pogs.Metadata{{Key: "HttpStatus", Val: "502"}}) {
		panic("response mismatch")
	}
}

type readCloser struct{ *bytes.Buffer }

func (readCloser) Close() error { return nil }

type registrationServer struct {
	mode string
	conn net.Conn
}

func (s *registrationServer) RegisterConnection(ctx context.Context, auth pogs.TunnelAuth, id uuid.UUID, index byte, options *pogs.ConnectionOptions) (*pogs.ConnectionDetails, error) {
	features := append([]string(nil), options.Client.Features...)
	sort.Strings(features)
	if auth.AccountTag != "synthetic-account" || string(auth.TunnelSecret) != "synthetic-secret" || id != fixtureID || index != 2 || !bytes.Equal(options.Client.ClientID, fixtureClient[:]) || options.Client.Version != "synthetic-version" || options.Client.Arch != "linux_amd64" || options.NumPreviousAttempts != 3 || options.ReplaceExisting || options.CompressionQuality != 0 || !reflect.DeepEqual(features, []string{"serialized_headers", "support_quic_eof"}) || !options.OriginLocalIP.Equal(net.ParseIP("192.0.2.1")) {
		return nil, errors.New("registration field mismatch")
	}
	switch s.mode {
	case "reject":
		return nil, errors.New("synthetic permanent rejection")
	case "retry":
		return nil, pogs.RetryErrorAfter(errors.New("synthetic transient rejection"), 2*time.Second)
	case "timeout":
		<-ctx.Done()
		return nil, ctx.Err()
	case "disconnect":
		go func() { time.Sleep(100 * time.Millisecond); s.conn.Close() }()
	}
	return &pogs.ConnectionDetails{UUID: fixtureConnection, Location: "TST", TunnelIsRemotelyManaged: false}, nil
}
func (s *registrationServer) UnregisterConnection(context.Context) {}
func (s *registrationServer) UpdateLocalConfiguration(_ context.Context, config []byte) error {
	if string(config) != "{\"synthetic\":true}" {
		return errors.New("configuration mismatch")
	}
	return nil
}

func serve(mode string) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	defer listener.Close()
	fmt.Println(listener.Addr().String())
	conn, err := listener.Accept()
	must(err)
	defer conn.Close()
	must(conn.SetDeadline(time.Now().Add(15 * time.Second)))
	impl := &registrationServer{mode: mode, conn: conn}
	client := pogs.RegistrationServer_ServerToClient(impl)
	rpc := tunnelrpc.NewServerConn(tunnelrpc.SafeTransport(conn), client.Client)
	defer rpc.Close()
	<-rpc.Done()
}

func callbacks(address string) {
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	must(err)
	defer conn.Close()
	must(conn.SetDeadline(time.Now().Add(10 * time.Second)))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := rpcquic.NewCloudflaredClient(ctx, conn, 5*time.Second)
	must(err)
	defer client.Close()
	result, err := client.UpdateConfiguration(ctx, 7, []byte("{\"synthetic\":true}"))
	must(err)
	if result.LastAppliedVersion != 7 || result.Err != nil {
		panic("configuration callback mismatch")
	}
	session, err := client.RegisterUdpSession(ctx, fixtureID, net.ParseIP("192.0.2.53"), 53, 210*time.Second, "synthetic-trace")
	must(err)
	if session.Err != nil || !bytes.Equal(session.Spans, []byte{1, 2, 3}) {
		panic("session callback mismatch")
	}
	must(client.UnregisterUdpSession(ctx, fixtureID, "synthetic close"))
	must(json.NewEncoder(os.Stdout).Encode(map[string]bool{"callbacks": true}))
}
func main() {
	if len(os.Args) < 3 {
		panic("oracle mode argument required")
	}
	switch os.Args[1] {
	case "watcher":
		watcherCorpus(os.Args[2])
	case "access-url":
		accessURLCorpus(os.Args[2])
	case "quick-mime":
		var inputs []string
		must(json.Unmarshal([]byte(os.Args[2]), &inputs))
		results := make([]bool, 0, len(inputs))
		for _, input := range inputs {
			mediaType, _, err := mime.ParseMediaType(input)
			results = append(results, err == nil && mediaType == "application/x-www-form-urlencoded")
		}
		must(json.NewEncoder(os.Stdout).Encode(results))
	case "origins":
		originsCorpus(os.Args[2])
	case "regex":
		regexCorpus(os.Args[2])
	case "ingress":
		ingressCorpus(os.Args[2])
	case "fixtures":
		fixtures(os.Args[2])
	case "decode":
		decode(os.Args[2])
	case "server":
		serve(os.Args[2])
	case "callbacks":
		callbacks(os.Args[2])
	default:
		panic("unknown oracle mode")
	}
}

func watcherCorpus(input string) {
	var vectors []struct {
		Forwarder config.Forwarder `json:"forwarder"`
		Listener  string           `json:"listener"`
	}
	must(json.Unmarshal([]byte(input), &vectors))
	results := make([]map[string]any, 0, len(vectors))
	for _, vector := range vectors {
		result := map[string]any{"hash": vector.Forwarder.Hash(), "listener_valid": false}
		listener, err := validation.ValidateUrl(vector.Listener)
		if err == nil {
			_, port, addressErr := net.SplitHostPort(listener.Host)
			if addressErr == nil && port != "" {
				result["listener_valid"] = true
				result["listener_address"] = listener.Host
			}
		}
		results = append(results, result)
	}
	names := make([]string, 0)
	for _, flag := range cftunnel.Flags() {
		if _, ok := flag.(altsrc.FlagInputSourceExtension); ok {
			names = append(names, flag.Names()[0])
		}
	}
	sort.Strings(names)
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"root_yaml_names": names, "vectors": results}))
}

func accessURLCorpus(input string) {
	var vectors []struct {
		Input string `json:"input"`
		Curl  bool   `json:"curl"`
	}
	must(json.Unmarshal([]byte(input), &vectors))
	results := make([]map[string]any, 0, len(vectors))
	for _, vector := range vectors {
		var parsed *url.URL
		var err error
		if vector.Curl {
			parsed, err = cfaccess.RustInteropCurlURL(vector.Input)
		} else {
			parsed, err = cfaccess.RustInteropAccessURL(vector.Input)
		}
		result := map[string]any{"valid": err == nil}
		if err == nil {
			result["url"] = parsed.String()
			result["host"] = parsed.Host
			result["path"] = parsed.EscapedPath()
			result["query"] = parsed.RawQuery
			request, requestErr := http.NewRequest(http.MethodHead, parsed.String(), nil)
			result["request_valid"] = requestErr == nil
			if requestErr == nil {
				result["request_uri"] = request.URL.RequestURI()
				result["request_host"] = request.Host
			}
		}
		results = append(results, result)
	}
	must(json.NewEncoder(os.Stdout).Encode(results))
}

func regexCorpus(input string) {
	var vectors []struct {
		Pattern string   `json:"pattern"`
		Inputs  []string `json:"inputs"`
	}
	must(json.Unmarshal([]byte(input), &vectors))
	results := make([]map[string]any, 0, len(vectors))
	for _, vector := range vectors {
		expression, err := regexp.Compile(vector.Pattern)
		matches := make([]bool, 0, len(vector.Inputs))
		if err == nil {
			for _, input := range vector.Inputs {
				matches = append(matches, expression.MatchString(input))
			}
		}
		results = append(results, map[string]any{"valid": err == nil, "matches": matches})
	}
	must(json.NewEncoder(os.Stdout).Encode(results))
}

func ingressCorpus(input string) {
	var vectors []struct {
		Configuration config.Configuration `json:"configuration"`
		Disable       bool                 `json:"disable"`
		URL           string               `json:"url"`
	}
	must(json.Unmarshal([]byte(input), &vectors))
	results := make([]int, 0, len(vectors))
	for _, vector := range vectors {
		parsed, err := ingress.ParseIngress(&vector.Configuration)
		must(err)
		parsed.DisablePathNormalization = vector.Disable
		request, err := url.Parse(vector.URL)
		must(err)
		_, index := parsed.FindMatchingRule(request.Host, request.Path)
		results = append(results, index)
	}
	must(json.NewEncoder(os.Stdout).Encode(results))
}
