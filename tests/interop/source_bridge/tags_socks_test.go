package main

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cloudflare/cloudflared/cmd/cloudflared/tunnel"
	"github.com/cloudflare/cloudflared/config"
	"github.com/cloudflare/cloudflared/ingress"
	"github.com/rs/zerolog"
	"github.com/urfave/cli/v2"
	"github.com/urfave/cli/v2/altsrc"
)

func TestRustTagsAndSocksContract(t *testing.T) {
	cases := []struct {
		name               string
		args               []string
		global, runArgs    []string
		env                map[string]string
		yaml               string
		tags               []string
		tagError, socksSet bool
		initError          bool
		proxyType          string
	}{
		{name: "cli_raw_repeats", args: []string{"--tag", "x=one,two", "--tag", "x= ", "--tag", "ID=user"}, tags: []string{"x=one,two", "x= ", "ID=user"}},
		{name: "global_cli", global: []string{"--tag", "x=root"}, tags: []string{"x=root"}},
		{name: "parent_cli_replaces_global", global: []string{"--tag", "x=root"}, args: []string{"--tag", "x=parent"}, tags: []string{"x=parent"}},
		{name: "tag_after_run_rejected", runArgs: []string{"--tag", "x=late"}, initError: true},
		{name: "env_trim_split", env: map[string]string{"TUNNEL_TAG": " x=one , ID=two "}, tags: []string{"x=one", "ID=two"}},
		{name: "yaml_raw_entries", yaml: "tag: ['x=one,two', 'x= ', 'x=three']\n", tags: []string{"x=one,two", "x= ", "x=three"}},
		{name: "yaml_empty", yaml: "tag: []\n"},
		{name: "cli_replaces_env_yaml", args: []string{"--tag", "x=cli"}, env: map[string]string{"TUNNEL_TAG": "x=env"}, yaml: "tag: ['x=yaml']\n", tags: []string{"x=cli"}},
		{name: "env_replaces_yaml", env: map[string]string{"TUNNEL_TAG": "x=env"}, yaml: "tag: ['x=yaml']\n", tags: []string{"x=env"}},
		{name: "empty_tag_env", env: map[string]string{"TUNNEL_TAG": ""}, tags: []string{""}, tagError: true},
		{name: "cli_false_socks", args: []string{"--socks5=false"}, socksSet: true, proxyType: "socks"},
		{name: "env_false_socks", env: map[string]string{"TUNNEL_SOCKS": "false"}, socksSet: true, proxyType: "socks"},
		{name: "env_empty_socks_suppresses_yaml", env: map[string]string{"TUNNEL_SOCKS": ""}, yaml: "socks5: true\n"},
		{name: "yaml_false_socks", yaml: "socks5: false\n"},
		{name: "yaml_true_socks", yaml: "socks5: true\n", socksSet: true, proxyType: "socks"},
		{name: "yaml_ingress_bypasses_cli", args: []string{"--socks5=false"}, yaml: "ingress:\n  - service: tcp://127.0.0.1:8080\n", socksSet: true},
		{name: "yaml_ingress_proxy_type", args: []string{"--socks5=false"}, yaml: "originRequest:\n  proxyType: socks\ningress:\n  - service: tcp://127.0.0.1:8080\n", socksSet: true, proxyType: "socks"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
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
					_ = os.Unsetenv(key)
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
			path := filepath.Join(t.TempDir(), "config.yml")
			if err := os.WriteFile(path, []byte(test.yaml), 0600); err != nil {
				t.Fatal(err)
			}
			config.RustInteropResetFileConfiguration()
			called := false
			capture := func(context *cli.Context) error {
				called = true
				log := zerolog.Nop()
				input, _, err := config.ReadConfigFile(context, &log)
				if err != nil {
					return err
				}
				if err = altsrc.ApplyInputSource(context, input); err != nil {
					return err
				}
				tags := context.StringSlice("tag")
				if len(tags) != len(test.tags) || len(tags) > 0 && !reflect.DeepEqual(tags, test.tags) {
					t.Fatalf("tag slice=%q, want %q", tags, test.tags)
				}
				_, err = tunnel.NewTagSliceFromCLI(tags)
				if (err != nil) != test.tagError {
					t.Fatalf("tag error=%v, expected failure=%v", err, test.tagError)
				}
				if context.IsSet("socks5") != test.socksSet {
					t.Fatalf("SOCKS IsSet=%v, want %v", context.IsSet("socks5"), test.socksSet)
				}
				rules, err := ingress.ParseIngressFromConfigAndCLI(config.GetConfiguration(), context, &log)
				if err != nil {
					return err
				}
				if rules.Rules[0].Config.ProxyType != test.proxyType {
					t.Fatalf("proxyType=%q, want %q", rules.Rules[0].Config.ProxyType, test.proxyType)
				}
				return nil
			}
			app := &cli.App{Name: "cloudflared", Flags: rootFlags, Commands: commands(cli.ShowVersion), Action: capture, Writer: io.Discard, ErrWriter: io.Discard}
			var configure func([]cli.Flag, []*cli.Command)
			configure = func(options []cli.Flag, commands []*cli.Command) {
				for _, flag := range options {
					if option, ok := flag.(*cli.StringFlag); ok && option.Name == "config" {
						option.Value = path
					}
				}
				for _, command := range commands {
					command.Action = capture
					configure(command.Flags, command.Subcommands)
				}
			}
			configure(app.Flags, app.Commands)
			args := append([]string{"cloudflared"}, test.global...)
			args = append(args, "tunnel")
			args = append(args, test.args...)
			args = append(args, "run", "--url", "tcp://127.0.0.1:8080")
			args = append(args, test.runArgs...)
			if err := app.Run(args); (err != nil) != test.initError {
				t.Fatalf("initialization error=%v, expected failure=%v", err, test.initError)
			}
			if called == test.initError {
				t.Fatalf("capture reached=%v, expected %v", called, !test.initError)
			}
		})
	}
}
