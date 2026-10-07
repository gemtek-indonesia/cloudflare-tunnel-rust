package main

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	configuration "github.com/cloudflare/cloudflared/config"
	"github.com/rs/zerolog"
	"github.com/urfave/cli/v2"
	"github.com/urfave/cli/v2/altsrc"
)

func TestRustWatcherInvocationContract(t *testing.T) {
	cases := []struct {
		name                    string
		args                    []string
		env                     map[string]string
		yaml                    string
		local, parent           int
		empty, service, failure bool
	}{
		{name: "empty", empty: true, service: true},
		{name: "separator", args: []string{"--"}, empty: true, service: true},
		{name: "explicit_false", args: []string{"--hello-world=false"}, local: 1},
		{name: "environment", env: map[string]string{"TUNNEL_LOGLEVEL": "debug"}, yaml: "loglevel: error\n", empty: true, service: true},
		{name: "yaml", yaml: "loglevel: debug\n", local: 1},
		{name: "ignored_yaml", yaml: "no-tls-verify: false\nha-connections: 0\nurl: ''\nrpc-timeout: -1s\n", empty: true, service: true},
		{name: "empty_yaml_list", yaml: "edge: []\n", local: 1},
		{name: "numeric_duration", yaml: "rpc-timeout: 1\n", failure: true},
		{name: "float_duration", yaml: "rpc-timeout: 1.5\n", failure: true},
		{name: "null_generic_flag", yaml: "loglevel: null\n", failure: true},
		{name: "first_document", yaml: "forwarders: []\n---\ninvalid: [\n", empty: true, service: true},
		{name: "non_root_yaml", yaml: "token: ignored\nfeatures: [ignored]\noutput: json\n", empty: true, service: true},
		{name: "yaml_aliases", yaml: "protocol: quic\n", local: 2},
		{name: "root_before_local", args: []string{"--loglevel", "warn", "version"}, parent: 1, empty: true},
		{name: "local_flag", args: []string{"version", "--short"}, local: 2},
		{name: "extra_string_empty_env", env: map[string]string{"BUCKET_ID": ""}, yaml: "bucket-name: synthetic\n", empty: true, service: true},
		{name: "extra_integer_invalid_env", env: map[string]string{"TUNNEL_COMPRESSION_LEVEL": "invalid"}, failure: true},
		{name: "extra_integer_empty_env", env: map[string]string{"TUNNEL_COMPRESSION_LEVEL": ""}, yaml: "compression-quality: 1\n", empty: true, service: true},
		{name: "extra_integer_hex_env", env: map[string]string{"TUNNEL_COMPRESSION_LEVEL": "0x10"}, empty: true, service: true},
		{name: "extra_integer_negative_env", env: map[string]string{"TUNNEL_COMPRESSION_LEVEL": "-1"}, empty: true, service: true},
		{name: "extra_duration_invalid_env", env: map[string]string{"TUNNEL_METRICS_UPDATE_FREQ": "invalid"}, failure: true},
		{name: "extra_duration_empty_env", env: map[string]string{"TUNNEL_METRICS_UPDATE_FREQ": ""}, yaml: "metrics-update-freq: 1s\n", empty: true, service: true},
		{name: "extra_duration_negative_env", env: map[string]string{"TUNNEL_METRICS_UPDATE_FREQ": "-1s"}, empty: true, service: true},
		{name: "extra_duration_signed_zero_env", env: map[string]string{"TUNNEL_METRICS_UPDATE_FREQ": "+0"}, empty: true, service: true},
		{name: "extra_duration_duplicate_sign_env", env: map[string]string{"TUNNEL_METRICS_UPDATE_FREQ": "-+1s"}, failure: true},
		{name: "extra_bool_invalid_env", env: map[string]string{"TUNNEL_USE_RECONNECT_TOKEN": "invalid"}, failure: true},
		{name: "extra_bool_empty_env", env: map[string]string{"TUNNEL_USE_RECONNECT_TOKEN": ""}, yaml: "use-reconnect-token: true\n", empty: true, service: true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			rootFlags := flags()
			for _, flag := range rootFlags {
				value := reflect.ValueOf(flag)
				if value.Kind() != reflect.Pointer {
					continue
				}
				environment := value.Elem().FieldByName("EnvVars")
				if !environment.IsValid() {
					continue
				}
				for index := 0; index < environment.Len(); index++ {
					key := environment.Index(index).String()
					old, exists := os.LookupEnv(key)
					if err := os.Unsetenv(key); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						if exists {
							_ = os.Setenv(key, old)
						} else {
							_ = os.Unsetenv(key)
						}
					})
				}
			}
			for key, value := range test.env {
				t.Setenv(key, value)
			}
			config := filepath.Join(home, "config.yml")
			if err := os.WriteFile(config, []byte(test.yaml), 0600); err != nil {
				t.Fatal(err)
			}
			for _, flag := range rootFlags {
				if option, ok := flag.(*cli.StringFlag); ok && option.Name == "config" {
					option.Value = config
				}
			}
			configuration.RustInteropResetFileConfiguration()
			called := false
			capture := func(context *cli.Context) error {
				log := zerolog.Nop()
				input, _, err := configuration.ReadConfigFile(context, &log)
				if err != nil {
					return err
				}
				if err := altsrc.ApplyInputSource(context, input); err != nil {
					return err
				}
				called = true
				if got := context.NumFlags(); got != test.local {
					t.Fatalf("local NumFlags=%d, want %d", got, test.local)
				}
				lineage := context.Lineage()
				if len(lineage) > 1 && lineage[1].Command != nil {
					if got := lineage[1].NumFlags(); got != test.parent {
						t.Fatalf("parent NumFlags=%d, want %d", got, test.parent)
					}
				}
				empty := isEmptyInvocation(context)
				if empty != test.empty {
					t.Fatalf("isEmptyInvocation=%v, want %v", empty, test.empty)
				}
				service := context.Command.Name == "" && empty
				if service != test.service {
					t.Fatalf("service dispatch=%v, want %v", service, test.service)
				}
				return nil
			}
			app := &cli.App{Flags: rootFlags, Commands: commands(func(*cli.Context) {}), Action: capture, Writer: io.Discard, ErrWriter: io.Discard}
			for _, command := range app.Commands {
				if command.Name == "version" {
					command.Action = capture
				}
			}
			err := app.Run(append([]string{"cloudflared"}, test.args...))
			if (err != nil) != test.failure {
				t.Fatalf("initialization error=%v, want failure=%v", err, test.failure)
			}
			if called == test.failure {
				t.Fatalf("action called=%v, want %v", called, !test.failure)
			}
		})
	}
}
