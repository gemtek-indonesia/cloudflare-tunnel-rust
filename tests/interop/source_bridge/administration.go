package tunnel

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/cloudflared/cmd/cloudflared/cliutil"
	"github.com/cloudflare/cloudflared/cmd/cloudflared/updater"
	"github.com/cloudflare/cloudflared/credentials"
	"github.com/urfave/cli/v2"
)

type RustAdministrationInput struct {
	Command    string            `json:"command"`
	Args       []string          `json:"args"`
	ParentArgs []string          `json:"parent_args"`
	Pages      []json.RawMessage `json:"pages"`
	Statuses   []int             `json:"statuses"`
	FileMode   string            `json:"file_mode"`
}

type RustAdministrationOutput struct {
	Queries      []string `json:"queries"`
	Requests     []string `json:"requests"`
	Bodies       []string `json:"bodies"`
	Error        string   `json:"error"`
	Output       string   `json:"output"`
	Stderr       string   `json:"stderr"`
	Failure      bool     `json:"failure"`
	ParseFailure bool     `json:"parse_failure"`
	Unix         int64    `json:"unix"`
	Nanoseconds  int      `json:"nanoseconds"`
	Credentials  string   `json:"credentials"`
	FileExists   bool     `json:"file_exists"`
	FilePerm     uint32   `json:"file_perm"`
	ExitCode     int      `json:"exit_code"`
}

type rustDeniedUpdateTransport struct{}

func (rustDeniedUpdateTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("synthetic update transport denied before I/O")
}

func RustInteropAdministration(input RustAdministrationInput) (RustAdministrationOutput, error) {
	if input.Command == "token-codec" {
		if len(input.Args) != 1 {
			return RustAdministrationOutput{}, errors.New("synthetic token codec requires one argument")
		}
		token, err := ParseToken(input.Args[0])
		output := RustAdministrationOutput{Queries: []string{}, Requests: []string{}, Failure: err != nil}
		if err != nil {
			return output, nil
		}
		output.Output, err = token.Encode()
		output.Failure = err != nil
		credentials, err := json.Marshal(token.Credentials())
		if err != nil {
			return RustAdministrationOutput{}, err
		}
		output.Credentials = string(credentials)
		return output, nil
	}
	if input.Command == "date" {
		date, err := time.Parse(time.RFC3339, input.Args[0])
		output := RustAdministrationOutput{Queries: []string{}, ParseFailure: err != nil}
		if err != nil {
			return output, nil
		}
		output.Unix = date.Unix()
		output.Nanoseconds = date.Nanosecond()
		encoded, err := date.MarshalJSON()
		output.Output = string(encoded)
		output.Failure = err != nil
		return output, nil
	}
	var command []string
	switch input.Command {
	case "list":
		command = []string{"tunnel", "list"}
	case "routes":
		command = []string{"tunnel", "route", "ip", "show"}
	case "vnets":
		command = []string{"tunnel", "vnet", "list"}
	case "info":
		command = []string{"tunnel", "info"}
	case "delete":
		command = []string{"tunnel", "delete"}
	case "cleanup":
		command = []string{"tunnel", "cleanup"}
	case "token":
		command = []string{"tunnel", "token"}
	case "create":
		command = []string{"tunnel", "create"}
	default:
		return RustAdministrationOutput{}, errors.New("unsupported synthetic command")
	}
	for _, arg := range append(append([]string{}, input.ParentArgs...), input.Args...) {
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		name := strings.TrimLeft(strings.SplitN(arg, "=", 2)[0], "-")
		switch name {
		case "api-url", "origincert", "config", "logfile", "log-directory", "credentials-file", "cred-file":
			return RustAdministrationOutput{}, errors.New("synthetic fixture cannot override its endpoint or files")
		}
	}
	for _, status := range input.Statuses {
		if status < 200 || status > 599 {
			return RustAdministrationOutput{}, errors.New("unsupported synthetic HTTP status")
		}
	}
	directory, err := os.MkdirTemp("", "admin-source-")
	if err != nil {
		return RustAdministrationOutput{}, err
	}
	defer os.RemoveAll(directory)
	cert, err := (&credentials.OriginCert{AccountID: "synthetic-account", ZoneID: "synthetic-zone", APIToken: "synthetic-token"}).EncodeOriginCert()
	if err != nil {
		return RustAdministrationOutput{}, err
	}
	certPath := filepath.Join(directory, "cert.pem")
	if err := os.WriteFile(certPath, cert, 0600); err != nil {
		return RustAdministrationOutput{}, err
	}
	configPath := filepath.Join(directory, "config.yml")
	if err := os.WriteFile(configPath, []byte("{}\n"), 0600); err != nil {
		return RustAdministrationOutput{}, err
	}
	credentialPath := filepath.Join(directory, "credentials.json")
	if input.Command == "create" && input.FileMode == "" {
		credentialPath = filepath.Join(directory, "11111111-1111-1111-1111-111111111111.json")
	}
	switch input.FileMode {
	case "", "absent":
	case "existing":
		if err := os.WriteFile(credentialPath, []byte("preserved"), 0400); err != nil {
			return RustAdministrationOutput{}, err
		}
	case "missing-parent":
		credentialPath = filepath.Join(directory, "missing", "credentials.json")
	case "directory":
		if err := os.Mkdir(credentialPath, 0700); err != nil {
			return RustAdministrationOutput{}, err
		}
	default:
		return RustAdministrationOutput{}, errors.New("unsupported synthetic credential-file mode")
	}
	output := RustAdministrationOutput{Queries: []string{}, Requests: []string{}, Bodies: []string{}}
	var mutex sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		mutex.Lock()
		defer mutex.Unlock()
		create := input.Command == "create" && request.Method == http.MethodPost && request.URL.Path == "/client/v4/accounts/synthetic-account/cfd_tunnel"
		if (!create && request.Method != http.MethodGet && request.Method != http.MethodDelete) || !strings.HasPrefix(request.URL.Path, "/client/v4/accounts/synthetic-account/") {
			http.Error(w, "unexpected synthetic request", http.StatusBadRequest)
			return
		}
		output.Queries = append(output.Queries, request.URL.RawQuery)
		output.Requests = append(output.Requests, request.Method+" "+request.URL.RequestURI())
		body, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(w, "synthetic body read failed", http.StatusBadRequest)
			return
		}
		output.Bodies = append(output.Bodies, string(body))
		index := len(output.Queries) - 1
		if index >= len(input.Pages) {
			http.Error(w, "unexpected page", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if index < len(input.Statuses) {
			w.WriteHeader(input.Statuses[index])
		}
		_, _ = w.Write(input.Pages[index])
	}))
	defer server.Close()
	// Source warning checks use the default transport; account requests use their own loopback transport.
	http.DefaultTransport = rustDeniedUpdateTransport{}
	info := &cliutil.BuildInfo{CloudflaredVersion: "2026.10.0", GoOS: "linux", GoArch: "amd64"}
	Init(info, make(chan struct{}))
	updater.Init(info)
	app := &cli.App{Name: "synthetic", Flags: Flags(), Commands: Commands(), Writer: io.Discard, ErrWriter: io.Discard, ExitErrHandler: func(*cli.Context, error) {}}
	args := []string{"synthetic", "--config", configPath, "--origincert", certPath, "--api-url", server.URL + "/client/v4", "--loglevel", "fatal"}
	args = append(args, command[0])
	args = append(args, input.ParentArgs...)
	args = append(args, command[1:]...)
	if input.Command == "delete" {
		args = append(args, "--credentials-file", credentialPath)
	}
	if (input.Command == "token" || input.Command == "create") && input.FileMode != "" {
		args = append(args, "--credentials-file", credentialPath)
	}
	args = append(args, input.Args...)
	reader, writer, err := os.Pipe()
	if err != nil {
		return RustAdministrationOutput{}, err
	}
	oldStdout := os.Stdout
	os.Stdout = writer
	collected := make(chan []byte, 1)
	go func() { body, _ := io.ReadAll(reader); collected <- body }()
	errorReader, errorWriter, err := os.Pipe()
	if err != nil {
		os.Stdout = oldStdout
		writer.Close()
		reader.Close()
		return RustAdministrationOutput{}, err
	}
	oldStderr := os.Stderr
	os.Stderr = errorWriter
	errorsCollected := make(chan []byte, 1)
	go func() { body, _ := io.ReadAll(errorReader); errorsCollected <- body }()
	err = app.Run(args)
	os.Stdout = oldStdout
	os.Stderr = oldStderr
	writer.Close()
	errorWriter.Close()
	output.Output = string(<-collected)
	output.Stderr = string(<-errorsCollected)
	reader.Close()
	errorReader.Close()
	output.Failure = err != nil
	if err != nil {
		output.Error = err.Error()
		output.ExitCode = 1
		if exit, ok := err.(cli.ExitCoder); ok {
			output.ExitCode = exit.ExitCode() & 255
		}
	}
	if input.FileMode != "" || input.Command == "create" {
		if stat, err := os.Stat(credentialPath); err == nil && stat.Mode().IsRegular() {
			output.FileExists = true
			output.FilePerm = uint32(stat.Mode().Perm())
			body, err := os.ReadFile(credentialPath)
			if err != nil {
				return RustAdministrationOutput{}, err
			}
			output.Credentials = string(body)
		}
	}
	if input.Command == "create" {
		output.Output = strings.ReplaceAll(output.Output, directory, "<directory>")
		output.Error = strings.ReplaceAll(output.Error, directory, "<directory>")
		output.Stderr = strings.ReplaceAll(output.Stderr, directory, "<directory>")
	}
	return output, nil
}

func RustInteropAdministrationJSON(data []byte) ([]byte, error) {
	var input RustAdministrationInput
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&input); err != nil {
		return nil, err
	}
	output, err := RustInteropAdministration(input)
	if err != nil {
		return nil, err
	}
	return json.Marshal(output)
}
