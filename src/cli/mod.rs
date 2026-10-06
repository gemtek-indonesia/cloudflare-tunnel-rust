pub mod flags;

use crate::config::{self, DurationValue, IngressRule, LoadedConfig, OriginRequest, RunConfig};
use anyhow::{Context, Result, bail};
use flags::Kind;
use std::{collections::BTreeMap, path::Path, time::Duration};

pub static COMMANDS: &[&str] = &[
    "version",
    "update",
    "login",
    "db-connect",
    "proxy-dns",
    "service install",
    "service uninstall",
    "tunnel",
    "tunnel login",
    "tunnel create",
    "tunnel run",
    "tunnel list",
    "tunnel ready",
    "tunnel info",
    "tunnel delete",
    "tunnel cleanup",
    "tunnel token",
    "tunnel diag",
    "tunnel proxy-dns",
    "tunnel db-connect",
    "tunnel ingress validate",
    "tunnel ingress rule",
    "tunnel route dns",
    "tunnel route lb",
    "tunnel route ip add",
    "tunnel route ip show",
    "tunnel route ip delete",
    "tunnel route ip get",
    "tunnel vnet add",
    "tunnel vnet list",
    "tunnel vnet delete",
    "tunnel vnet update",
    "access login",
    "access curl",
    "access token",
    "access tcp",
    "access ssh-config",
    "access ssh-gen",
    "tail",
    "tail token",
    "management token",
];

pub enum Action {
    Help(String),
    Version {
        short: bool,
    },
    IngressValidate(LoadedConfig),
    IngressRule {
        configuration: LoadedConfig,
        url: String,
    },
    Run(Box<RunConfig>),
    Ready {
        metrics: String,
    },
    Admin(Invocation),
    Service(Invocation),
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct ExitFailure {
    pub code: u8,
    pub message: String,
}

pub struct Invocation {
    pub command: String,
    pub args: Vec<String>,
    pub configuration: LoadedConfig,
    values: BTreeMap<String, Vec<String>>,
    specified: BTreeMap<String, bool>,
}

impl Invocation {
    pub fn from_env(args: impl IntoIterator<Item = String>) -> Result<Self> {
        let env = flags::FLAGS
            .iter()
            .flat_map(|flag| flag.env.iter())
            .filter_map(|key| {
                std::env::var(key)
                    .ok()
                    .map(|value| ((*key).to_owned(), value))
            })
            .collect();
        let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
        Self::parse(args, &env, home.as_deref())
    }

    pub fn parse(
        args: impl IntoIterator<Item = String>,
        env: &BTreeMap<String, String>,
        home: Option<&Path>,
    ) -> Result<Self> {
        let mut values: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut positional = Vec::new();
        let mut args = args.into_iter();
        let mut flags_done = false;
        while let Some(arg) = args.next() {
            if arg == "--" {
                flags_done = true;
                continue;
            }
            if !flags_done && arg.starts_with('-') && arg != "-" {
                let name_value = arg.trim_start_matches('-');
                let (name, inline) = name_value
                    .split_once('=')
                    .map_or((name_value, None), |(name, value)| (name, Some(value)));
                let name = match (
                    name,
                    positional.first().map(String::as_str),
                    positional.get(1).map(String::as_str),
                ) {
                    ("s", Some("tunnel"), Some("create")) => "secret",
                    ("f", Some("login"), _)
                    | ("f", Some("tunnel"), Some("login"))
                    | ("f", Some("access"), _) => "fedramp",
                    ("c", Some("tunnel"), Some("vnet")) => "comment",
                    ("d", Some("tunnel"), Some("vnet")) => "default",
                    ("o", _, _) => "output",
                    ("i", Some("tunnel"), Some("list")) => "id",
                    ("np", Some("tunnel"), Some("list")) => "name-prefix",
                    ("rd", Some("tunnel"), _) => "show-recently-disconnected",
                    _ => name,
                };
                let flag = flags::find(name).context("Unknown command-line flag; see --help")?;
                let kind = if flag.name == "version"
                    && positional.first().is_some_and(|word| word == "update")
                {
                    Kind::String
                } else {
                    flag.kind
                };
                let value = if kind == Kind::Bool {
                    inline.unwrap_or("true").to_owned()
                } else {
                    inline
                        .map(str::to_owned)
                        .or_else(|| args.next())
                        .with_context(|| format!("--{} requires a value", flag.name))?
                };
                validate_value(flag.name, kind, &value)?;
                let entry = values.entry(flag.name.to_owned()).or_default();
                if kind != Kind::List {
                    entry.clear();
                }
                entry.extend(split_value(kind, &value));
            } else {
                positional.push(arg);
            }
        }
        if positional.first().is_some_and(|word| word == "help") {
            positional.remove(0);
            values.insert("help".into(), vec!["true".into()]);
        }
        if positional.first().is_some_and(|word| word == "forward") {
            positional[0] = "access".into();
        }
        if positional.first().is_some_and(|word| word == "access")
            && positional
                .get(1)
                .is_some_and(|word| ["ssh", "rdp", "smb"].contains(&word.as_str()))
        {
            positional[1] = "tcp".into();
        }
        if positional.first().is_some_and(|word| word == "tunnel")
            && positional.get(1).is_some_and(|word| word == "route")
            && positional.get(2).is_some_and(|word| word == "ip")
            && positional.get(3).is_some_and(|word| word == "list")
        {
            positional[3] = "show".into();
        }
        let count = (1..=positional.len())
            .rev()
            .find(|count| COMMANDS.contains(&positional[..*count].join(" ").as_str()))
            .unwrap_or(0);
        if count == 0 && !positional.is_empty() {
            bail!("Unknown command; see --help");
        }
        let command = positional[..count].join(" ");
        let command_args = positional[count..].to_vec();
        let mut specified = values
            .keys()
            .map(|name| (name.to_owned(), true))
            .collect::<BTreeMap<_, _>>();
        if values
            .get("help")
            .is_some_and(|v| v.last().is_some_and(|v| v == "true"))
            || values
                .get("version")
                .is_some_and(|v| v.last().is_some_and(|v| v == "true"))
        {
            return Ok(Self {
                command,
                args: command_args,
                configuration: LoadedConfig::default(),
                values,
                specified,
            });
        }
        let path = values
            .get("config")
            .and_then(|values| values.last())
            .map(|path| config::expand_home(path, home))
            .transpose()?
            .or_else(|| config::discover_config(&config::search_directories(home)));
        let configuration = LoadedConfig::read(path.as_deref())?;
        for flag in flags::FLAGS {
            if values.contains_key(flag.name) {
                continue;
            }
            if let Some(value) = flag.env.iter().find_map(|key| env.get(*key)) {
                validate_value(flag.name, flag.kind, value)?;
                values.insert(flag.name.to_owned(), split_value(flag.kind, value));
                specified.insert(flag.name.to_owned(), true);
            } else if flag.yaml
                && let Some(value) = configuration.settings.get(flag.name)
            {
                let value = yaml_value(flag.kind, value)
                    .with_context(|| format!("invalid YAML type for {}", flag.name))?;
                if let Some(value) = value {
                    validate_value(flag.name, flag.kind, &value)?;
                    values.insert(flag.name.to_owned(), split_value(flag.kind, &value));
                    specified.insert(flag.name.to_owned(), true);
                }
            }
            if !values.contains_key(flag.name)
                && let Some(value) = flag.default
            {
                values.insert(flag.name.to_owned(), split_value(flag.kind, value));
            }
        }
        Ok(Self {
            command,
            args: command_args,
            configuration,
            values,
            specified,
        })
    }

    pub fn string(&self, name: &str) -> &str {
        self.values
            .get(name)
            .and_then(|values| values.last())
            .map_or("", String::as_str)
    }
    pub fn list(&self, name: &str) -> Vec<String> {
        self.values.get(name).cloned().unwrap_or_default()
    }
    pub fn bool(&self, name: &str) -> bool {
        matches!(
            self.string(name),
            "true" | "1" | "TRUE" | "True" | "t" | "T"
        )
    }
    pub fn is_set(&self, name: &str) -> bool {
        self.specified.contains_key(name)
    }
    pub fn duration(&self, name: &str) -> Result<Duration> {
        config::parse_duration(self.string(name)).with_context(|| format!("invalid --{name}"))
    }

    pub fn action(self, home: Option<&Path>) -> Result<Action> {
        if self.bool("help") {
            return Ok(Action::Help(self.command));
        }
        if self.command == "version" || self.bool("version") {
            return Ok(Action::Version {
                short: self.bool("short"),
            });
        }
        match self.command.as_str() {
            "tunnel ingress validate" => {
                if self.is_set("url") {
                    bail!("--url is incompatible with ingress rules");
                }
                let configuration = if self.is_set("json") {
                    LoadedConfig::from_json(self.string("json"))?
                } else {
                    self.configuration.clone()
                };
                config::validate_ingress(&configuration.ingress)?;
                Ok(Action::IngressValidate(configuration))
            }
            "tunnel ingress rule" => {
                let url = self
                    .args
                    .first()
                    .context("cloudflared tunnel rule expects a single argument, the URL to test")?
                    .clone();
                url::Url::parse(&url)
                    .context("Request must be a URL with a scheme and hostname")?;
                config::validate_ingress(&self.configuration.ingress)?;
                Ok(Action::IngressRule {
                    configuration: self.configuration,
                    url,
                })
            }
            "tunnel run" => Ok(Action::Run(Box::new(self.run_config(home)?))),
            "tunnel ready" => {
                if !self.is_set("metrics") {
                    bail!("--metrics has to be provided");
                }
                Ok(Action::Ready {
                    metrics: self.string("metrics").to_owned(),
                })
            }
            "proxy-dns" | "tunnel proxy-dns" => bail!("dns-proxy feature is no longer supported"),
            "db-connect" | "tunnel db-connect" => bail!("db-connect has been removed"),
            "update" => Err(ExitFailure {
                code: 10,
                message:
                    "Self-update is excluded; install updates through the Rust package distribution"
                        .into(),
            }
            .into()),
            command if command.starts_with("service ") => Ok(Action::Service(self)),
            "login" => Ok(Action::Admin(self)),
            command
                if command.starts_with("tunnel ")
                    && !["tunnel diag", "tunnel proxy-dns", "tunnel db-connect"]
                        .contains(&command) =>
            {
                Ok(Action::Admin(self))
            }
            "" | "tunnel" if !self.string("hostname").is_empty() => {
                bail!("Classic tunnels have been deprecated, please use Named Tunnels.")
            }
            "" | "tunnel" if self.is_set("url") || self.is_set("hello-world") => {
                bail!("Quick Tunnel provisioning is not implemented yet")
            }
            "" | "tunnel" if !self.configuration.tunnel.is_empty() => {
                bail!("use `cloudflared tunnel run` to start tunnel configured in YAML")
            }
            "" => bail!("Configuration watcher service mode is not implemented yet"),
            "tunnel" => {
                bail!("Use `cloudflared tunnel run` for a named tunnel or --url for a Quick Tunnel")
            }
            command => {
                bail!("Capability '{command}' is not implemented yet; see docs/compatibility.md")
            }
        }
    }

    pub fn run_config(&self, home: Option<&Path>) -> Result<RunConfig> {
        if self.args.len() > 1 {
            bail!(
                "\"cloudflared tunnel run\" accepts only one argument, the ID or name of the tunnel to run."
            );
        }
        if !self.list("allowed-mail").is_empty() {
            bail!("--allowed-mail is only supported for Quick Tunnels");
        }
        let tunnel = self
            .args
            .first()
            .map_or(self.configuration.tunnel.as_str(), String::as_str);
        let token_file = (!self.string("token-file").is_empty())
            .then(|| config::expand_home(self.string("token-file"), home))
            .transpose()?;
        let credential_file = (!self.string("credentials-file").is_empty())
            .then(|| config::expand_home(self.string("credentials-file"), home))
            .transpose()?;
        let origin_cert = (!self.string("origincert").is_empty())
            .then(|| config::expand_home(self.string("origincert"), home))
            .transpose()?;
        let (credentials, token_authenticated) = config::resolve_credentials(
            Some(self.string("token")),
            token_file.as_deref(),
            Some(self.string("credentials-contents")),
            credential_file.as_deref(),
            tunnel,
            origin_cert.as_deref(),
            &config::search_directories(home),
        )?;
        let mut ingress = self.configuration.ingress.clone();
        let origin_request = if ingress.is_empty() {
            self.single_origin_request()?
        } else {
            self.configuration.origin_request.clone()
        };
        if ingress.is_empty() {
            let service = if self.is_set("hello-world") {
                "hello_world".to_owned()
            } else if self.is_set("bastion") {
                "bastion".to_owned()
            } else if self.is_set("url") {
                self.string("url").to_owned()
            } else if self.is_set("unix-socket") {
                format!("unix:{}", self.string("unix-socket"))
            } else {
                "http_status:503".to_owned()
            };
            ingress.push(IngressRule {
                service,
                ..Default::default()
            });
        }
        if self.is_set("unix-socket") && self.is_set("url") {
            bail!("--unix-socket must be used exclusively.");
        }
        config::validate_ingress(&ingress)?;
        let grace_period = self.duration("grace-period")?;
        if grace_period > Duration::from_secs(180) {
            bail!("grace-period must be equal or less than 3m0s");
        }
        let edge_ip_version = self.string("edge-ip-version").to_owned();
        if !["auto", "4", "6"].contains(&edge_ip_version.as_str()) {
            bail!("edge-ip-version must be auto, 4, or 6");
        }
        if !self.string("region").is_empty()
            && credentials
                .endpoint
                .as_deref()
                .is_some_and(|value| !value.is_empty())
        {
            bail!("region provided with a token that has an endpoint");
        }
        let integer = |name: &str| -> Result<u64> {
            self.string(name)
                .parse()
                .with_context(|| format!("invalid --{name}"))
        };
        let ha_connections = u8::try_from(integer("ha-connections")?)
            .context("ha-connections outside supported range")?;
        if ha_connections == 0 {
            bail!("ha-connections must be positive");
        }
        Ok(RunConfig {
            region: credentials
                .endpoint
                .clone()
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| self.string("region").to_owned()),
            credentials,
            ingress,
            origin_request,
            source: self.configuration.source.clone(),
            protocol: self.string("protocol").parse()?,
            edge_ip_version,
            metrics: self.string("metrics").to_owned(),
            ha_connections,
            grace_period,
            edge_bind_address: (!self.string("edge-bind-address").is_empty())
                .then(|| self.string("edge-bind-address").parse())
                .transpose()
                .context("invalid edge-bind-address")?,
            post_quantum: self.bool("post-quantum"),
            quic_disable_pmtu_discovery: self.bool("quic-disable-pmtu-discovery"),
            connection_window: integer("quic-connection-level-flow-control-limit")?,
            stream_window: integer("quic-stream-level-flow-control-limit")?,
            edge_ca: (!self.string("cacert").is_empty())
                .then(|| config::expand_home(self.string("cacert"), home))
                .transpose()?,
            token_authenticated,
            rpc_timeout: self.duration("rpc-timeout")?,
            write_stream_timeout: self.duration("write-stream-timeout")?,
            dial_edge_timeout: self.duration("dial-edge-timeout")?,
            retries: integer("retries")?
                .try_into()
                .context("retries outside supported range")?,
            max_edge_addr_retries: integer("max-edge-addr-retries")?
                .try_into()
                .context("max-edge-addr-retries outside supported range")?,
            edge: self.list("edge"),
            no_prechecks: self.bool("no-prechecks"),
            pidfile: (!self.string("pidfile").is_empty())
                .then(|| config::expand_home(self.string("pidfile"), home))
                .transpose()?,
            disable_path_normalization: self.bool("disable-path-normalization"),
            configuration: self.configuration.clone(),
        })
    }

    fn single_origin_request(&self) -> Result<OriginRequest> {
        Ok(OriginRequest {
            connect_timeout: Some(DurationValue(self.duration("proxy-connect-timeout")?)),
            tls_timeout: Some(DurationValue(self.duration("proxy-tls-timeout")?)),
            tcp_keep_alive: Some(DurationValue(self.duration("proxy-tcp-keepalive")?)),
            keep_alive_timeout: Some(DurationValue(self.duration("proxy-keepalive-timeout")?)),
            keep_alive_connections: Some(
                self.string("proxy-keepalive-connections")
                    .parse()
                    .context("invalid proxy-keepalive-connections")?,
            ),
            no_happy_eyeballs: Some(self.bool("proxy-no-happy-eyeballs")),
            http_host_header: (!self.string("http-host-header").is_empty())
                .then(|| self.string("http-host-header").to_owned()),
            origin_server_name: (!self.string("origin-server-name").is_empty())
                .then(|| self.string("origin-server-name").to_owned()),
            ca_pool: (!self.string("origin-ca-pool").is_empty())
                .then(|| self.string("origin-ca-pool").to_owned()),
            no_tls_verify: Some(self.bool("no-tls-verify")),
            disable_chunked_encoding: Some(self.bool("no-chunked-encoding")),
            http2_origin: Some(self.bool("http2-origin")),
            ..Default::default()
        })
    }
}

fn split_value(kind: Kind, value: &str) -> Vec<String> {
    if kind == Kind::List {
        value
            .split(',')
            .map(|value| value.trim().to_owned())
            .collect()
    } else {
        vec![value.to_owned()]
    }
}

fn validate_value(name: &str, kind: Kind, value: &str) -> Result<()> {
    let valid = match kind {
        Kind::Bool => [
            "1", "0", "true", "false", "TRUE", "FALSE", "True", "False", "t", "f", "T", "F",
        ]
        .contains(&value),
        Kind::Integer => value.parse::<i64>().is_ok(),
        Kind::Duration => config::parse_duration(value).is_ok(),
        _ => true,
    };
    if !valid {
        bail!("invalid value for --{name}");
    }
    Ok(())
}

fn yaml_value(kind: Kind, value: &serde_yaml_ng::Value) -> Result<Option<String>> {
    use serde_yaml_ng::Value;
    Ok(match (kind, value) {
        (Kind::String, Value::String(value)) if !value.is_empty() => Some(value.clone()),
        (Kind::String, Value::String(_)) => None,
        (Kind::Bool, Value::Bool(true)) => Some("true".into()),
        (Kind::Bool, Value::Bool(false)) => None,
        (Kind::Integer, Value::Number(value)) => value
            .as_i64()
            .filter(|value| *value > 0)
            .map(|value| value.to_string()),
        (Kind::Duration, Value::String(value)) => {
            if config::parse_duration(value)?.is_zero() {
                None
            } else {
                Some(value.clone())
            }
        }
        (Kind::List, Value::Sequence(values)) => Some(
            values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .context("expected string list")
                })
                .collect::<Result<Vec<_>>>()?
                .join(","),
        ),
        _ => bail!("unexpected value type"),
    })
}

pub fn help(command: &str) -> String {
    let commands = COMMANDS
        .iter()
        .filter(|entry| command.is_empty() || entry.starts_with(command))
        .copied()
        .collect::<Vec<_>>()
        .join("\n  ");
    format!(
        "cloudflared: Rust compatibility implementation (upstream {})\nUsage: cloudflared [options] [command] [options]\n\nCommands:\n  {commands}\n\nNamed tunnel options: --config FILE --token TOKEN --token-file FILE\n  --credentials-file FILE --credentials-contents JSON --protocol auto|quic|http2\n  --url URL --metrics ADDRESS --ha-connections N\n\nRecognized commands may still be unimplemented; see docs/compatibility.md.\n",
        config::UPSTREAM_VERSION
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn env_cli_precedence_and_token_runtime_inputs() {
        let token = base64::engine::general_purpose::STANDARD.encode(
            br#"{"a":"synthetic","s":"c3ludGhldGlj","t":"00000000-0000-4000-8000-000000000001"}"#,
        );
        let env = BTreeMap::from([
            ("TUNNEL_TOKEN".into(), token),
            ("TUNNEL_TRANSPORT_PROTOCOL".into(), "quic".into()),
        ]);
        let cli = Invocation::parse(
            ["tunnel", "run", "-p", "http2", "--hello-world"].map(str::to_owned),
            &env,
            None,
        )
        .unwrap();
        assert_eq!(cli.string("protocol"), "http2");
        let run = cli.run_config(None).unwrap();
        assert_eq!(run.protocol, config::Protocol::Http2);
        assert_eq!(run.ingress[0].service, "hello_world");
        assert!(run.token_authenticated);
    }

    #[test]
    fn yaml_false_and_zero_preserve_upstream_altsrc_behavior() {
        assert!(
            yaml_value(Kind::Bool, &serde_yaml_ng::Value::Bool(false))
                .unwrap()
                .is_none()
        );
        assert!(
            yaml_value(Kind::Integer, &serde_yaml_ng::Value::Number(0.into()))
                .unwrap()
                .is_none()
        );
        assert!(
            yaml_value(Kind::Duration, &serde_yaml_ng::Value::String("0s".into()))
                .unwrap()
                .is_none()
        );
        assert!(
            Invocation::parse(
                ["tunnel", "run", "--token", "DO-NOT-ECHO"].map(str::to_owned),
                &BTreeMap::new(),
                None
            )
            .unwrap()
            .run_config(None)
            .unwrap_err()
            .to_string()
            .contains("not valid")
        );
    }

    #[test]
    fn help_does_not_read_config_or_claim_capability() {
        let cli = Invocation::parse(
            ["--config", "does-not-exist", "tunnel", "run", "--help"].map(str::to_owned),
            &BTreeMap::new(),
            None,
        )
        .unwrap();
        assert!(matches!(cli.action(None).unwrap(), Action::Help(_)));
        assert!(help("").contains("may still be unimplemented"));
    }
}
