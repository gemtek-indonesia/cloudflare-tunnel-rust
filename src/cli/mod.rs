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
        normalize: bool,
    },
    Run(Box<RunConfig>),
    RunNamed(Invocation),
    Ready {
        metrics: String,
    },
    Admin(Invocation),
    Service(Invocation),
    Access(Invocation),
    Operations(Invocation),
    Diagnostics(Invocation),
    Quick(Invocation),
    Adhoc(Invocation),
    Watch(Invocation),
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
    source_flags_set: bool,
}

// These root altsrc flags are not part of the current runtime flag definitions.
const ROOT_YAML_EXTRA: &[(&str, Kind, Option<&str>)] = &[
    ("access-key-id", Kind::String, Some("ACCESS_CLIENT_ID")),
    ("bucket-name", Kind::String, Some("BUCKET_ID")),
    (
        "compression-quality",
        Kind::Integer,
        Some("TUNNEL_COMPRESSION_LEVEL"),
    ),
    ("heartbeat-count", Kind::Integer, None),
    ("heartbeat-interval", Kind::Duration, None),
    ("host-key-path", Kind::String, Some("HOST_KEY_PATH")),
    ("is-autoupdated", Kind::Bool, None),
    (
        "metrics-update-freq",
        Kind::Duration,
        Some("TUNNEL_METRICS_UPDATE_FREQ"),
    ),
    ("region-name", Kind::String, Some("REGION_ID")),
    ("s3-url-host", Kind::String, Some("S3_URL")),
    ("secret-id", Kind::String, Some("SECRET_ID")),
    ("session-token", Kind::String, Some("SESSION_TOKEN_ID")),
    ("ui", Kind::Bool, None),
    (
        "use-reconnect-token",
        Kind::Bool,
        Some("TUNNEL_USE_RECONNECT_TOKEN"),
    ),
];
fn root_yaml_kind(name: &str) -> Option<Kind> {
    if [
        "credentials-contents",
        "features",
        "output",
        "token",
        "token-file",
    ]
    .contains(&name)
    {
        return None;
    }
    flags::find(name)
        .filter(|flag| flag.yaml)
        .map(|flag| flag.kind)
        .or_else(|| {
            ROOT_YAML_EXTRA
                .iter()
                .find(|(key, _, _)| *key == name)
                .map(|(_, kind, _)| *kind)
        })
}

impl Invocation {
    pub fn from_env(args: impl IntoIterator<Item = String>) -> Result<Self> {
        let env = flags::FLAGS
            .iter()
            .flat_map(|flag| flag.env.iter())
            .copied()
            .chain([
                "TUNNEL_MANAGEMENT_TOKEN",
                "TUNNEL_MANAGEMENT_CONNECTOR",
                "TUNNEL_SERVICE_HOSTNAME",
                "TUNNEL_SERVICE_URL",
            ])
            .chain(ROOT_YAML_EXTRA.iter().filter_map(|(_, _, key)| *key))
            .filter_map(|key| std::env::var(key).ok().map(|value| (key.to_owned(), value)))
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
        let mut positional: Vec<String> = Vec::new();
        let mut args = args.into_iter();
        let mut flags_done = false;
        let mut tag_scope = None;
        while let Some(arg) = args.next() {
            if positional.len() >= 2
                && ["access", "forward"].contains(&positional[0].as_str())
                && positional[1] == "curl"
            {
                positional.push(arg);
                positional.extend(args);
                break;
            }
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
                    ("T" | "tunnel-host", Some("access" | "forward"), _) => "hostname",
                    ("L" | "listener", Some("access" | "forward"), _) => "url",
                    ("id", Some("access" | "forward"), _) => "service-token-id",
                    ("secret", Some("access" | "forward"), _) => "service-token-secret",
                    ("loglevel", Some("access" | "forward"), _) => "log-level",
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
                let next_tag_scope = if flag.name == "tag" {
                    Some(if positional.is_empty() {
                        0
                    } else if positional.len() == 1 && positional[0] == "tunnel" {
                        1
                    } else {
                        bail!("--tag must precede the tunnel subcommand");
                    })
                } else {
                    None
                };
                let entry = values.entry(flag.name.to_owned()).or_default();
                if kind != Kind::List {
                    entry.clear();
                }
                if flag.name == "tag" {
                    if tag_scope != next_tag_scope {
                        entry.clear();
                    }
                    tag_scope = next_tag_scope;
                    entry.push(value);
                } else {
                    entry.extend(split_value(kind, &value));
                }
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
        if command.is_empty() {
            for &(name, kind, environment) in ROOT_YAML_EXTRA {
                if let Some(value) = environment.and_then(|key| env.get(key))
                    && !value.is_empty()
                {
                    match kind {
                        Kind::Integer => {
                            root_integer(value).with_context(|| {
                                format!("invalid environment value for --{name}")
                            })?;
                        }
                        Kind::Duration => {
                            root_duration(value).with_context(|| {
                                format!("invalid environment value for --{name}")
                            })?;
                        }
                        _ => validate_value(name, kind, value)?,
                    }
                }
            }
        }
        let mut specified = values
            .keys()
            .map(|name| (name.to_owned(), true))
            .collect::<BTreeMap<_, _>>();
        let mut source_flags_set = !values.is_empty();
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
                source_flags_set,
            });
        }
        let path = values
            .get("config")
            .and_then(|values| values.last())
            .map(|path| config::expand_home(path, home))
            .transpose()?
            .or_else(|| config::discover_config(&config::search_directories(home)));
        let access = command.starts_with("access ");
        let configuration = if access {
            LoadedConfig::default()
        } else if command.is_empty() {
            root_configuration(path.as_deref())?
        } else {
            LoadedConfig::read(path.as_deref())?
        };
        for flag in flags::FLAGS {
            if values.contains_key(flag.name) {
                continue;
            }
            let management = ["tail", "tail token", "management token"].contains(&command.as_str());
            let environment: &[&str] = if management && flag.name == "token" {
                &["TUNNEL_MANAGEMENT_TOKEN"]
            } else if management && flag.name == "connector-id" {
                &["TUNNEL_MANAGEMENT_CONNECTOR"]
            } else if access && flag.name == "hostname" {
                &["TUNNEL_SERVICE_HOSTNAME"]
            } else if access && flag.name == "url" {
                &["TUNNEL_SERVICE_URL"]
            } else {
                flag.env
            };
            if let Some(value) = environment.iter().find_map(|key| env.get(*key)) {
                if flag.name == "socks5" && value.is_empty() {
                    values.insert(flag.name.to_owned(), vec!["false".into()]);
                    continue;
                }
                validate_value(flag.name, flag.kind, value)?;
                values.insert(flag.name.to_owned(), split_value(flag.kind, value));
                specified.insert(flag.name.to_owned(), true);
            } else if flag.yaml
                && (!command.is_empty() || root_yaml_kind(flag.name).is_some())
                && let Some(value) = configuration.settings.get(flag.name)
            {
                if flag.name == "tag" {
                    let tag_values = value
                        .as_sequence()
                        .context("invalid YAML type for tag")?
                        .iter()
                        .map(|value| {
                            value
                                .as_str()
                                .map(str::to_owned)
                                .context("invalid YAML type for tag")
                        })
                        .collect::<Result<Vec<_>>>()?;
                    values.insert(flag.name.to_owned(), tag_values);
                    specified.insert(flag.name.to_owned(), true);
                    source_flags_set = true;
                    continue;
                }
                let value = if command.is_empty() {
                    root_yaml_value(flag.kind, value)
                } else {
                    yaml_value(flag.kind, value)
                }
                .with_context(|| format!("invalid YAML type for {}", flag.name))?;
                if let Some(value) = value {
                    validate_value(flag.name, flag.kind, &value)?;
                    values.insert(flag.name.to_owned(), split_value(flag.kind, &value));
                    specified.insert(flag.name.to_owned(), true);
                    source_flags_set = true;
                }
            }
            if !values.contains_key(flag.name)
                && !(access && flag.name == "url")
                && let Some(value) = flag.default
            {
                values.insert(flag.name.to_owned(), split_value(flag.kind, value));
            }
        }
        if command.is_empty() {
            for &(name, kind, environment) in ROOT_YAML_EXTRA {
                if environment.is_some_and(|key| env.contains_key(key)) {
                    continue;
                }
                if let Some(value) = configuration.settings.get(name) {
                    source_flags_set |= root_yaml_value(kind, value)
                        .with_context(|| format!("invalid YAML type for {name}"))?
                        .is_some();
                }
            }
        }
        Ok(Self {
            command,
            args: command_args,
            configuration,
            values,
            specified,
            source_flags_set,
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
        if self.command.is_empty() && self.args.is_empty() && !self.source_flags_set {
            return Ok(Action::Watch(self));
        }
        if ["", "tunnel", "tunnel run"].contains(&self.command.as_str()) {
            config::parse_tags(&self.list("tag"))?;
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
                    normalize: !self.bool("disable-path-normalization")
                        && config::ingress_requires_normalization(&self.configuration),
                    configuration: self.configuration,
                    url,
                })
            }
            "tunnel run" => self.run_action(home),
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
            command if command.starts_with("access ") => Ok(Action::Access(self)),
            "tail" | "tail token" | "management token" => Ok(Action::Operations(self)),
            "tunnel diag" => Ok(Action::Diagnostics(self)),
            command
                if command.starts_with("tunnel ")
                    && !["tunnel diag", "tunnel proxy-dns", "tunnel db-connect"]
                        .contains(&command) =>
            {
                Ok(Action::Admin(self))
            }
            "" | "tunnel" if !self.string("name").is_empty() => {
                if !self.list("allowed-mail").is_empty() {
                    bail!("--allowed-mail is only supported for Quick Tunnels");
                }
                if !self.string("hostname").is_empty()
                    && self.string("hostname") == self.string("url")
                {
                    bail!("hostname and url shouldn't match. See --help for more information");
                }
                Ok(Action::Adhoc(self))
            }
            "" | "tunnel"
                if !self.string("quick-service").is_empty()
                    && (self.is_set("url") || self.is_set("hello-world")) =>
            {
                Ok(Action::Quick(self))
            }
            "" | "tunnel" if !self.configuration.tunnel.is_empty() => {
                bail!("use `cloudflared tunnel run` to start tunnel configured in YAML")
            }
            "" | "tunnel" if !self.string("hostname").is_empty() => {
                bail!("Classic tunnels have been deprecated, please use Named Tunnels.")
            }
            "" => {
                bail!("Use `cloudflared tunnel run` for a named tunnel or --url for a Quick Tunnel")
            }
            "tunnel" => {
                bail!("Use `cloudflared tunnel run` for a named tunnel or --url for a Quick Tunnel")
            }
            command => {
                bail!("Capability '{command}' is not implemented yet; see docs/compatibility.md")
            }
        }
    }

    fn run_action(self, home: Option<&Path>) -> Result<Action> {
        let reference = self
            .args
            .first()
            .map_or(self.configuration.tunnel.as_str(), String::as_str);
        if !reference.is_empty()
            && uuid::Uuid::parse_str(reference).is_err()
            && self.string("token").is_empty()
        {
            Ok(Action::RunNamed(self))
        } else {
            Ok(Action::Run(Box::new(self.run_config(home)?)))
        }
    }

    pub async fn named_config(mut self, home: Option<&Path>) -> Result<RunConfig> {
        if self.args.len() > 1 {
            bail!(
                "\"cloudflared tunnel run\" accepts only one argument, the ID or name of the tunnel to run."
            );
        }
        if !self.list("allowed-mail").is_empty() {
            bail!("--allowed-mail is only supported for Quick Tunnels");
        }
        if !self.string("token-file").is_empty() {
            let token =
                std::fs::read_to_string(config::expand_home(self.string("token-file"), home)?)
                    .context("Failed to read token file")?;
            if !token.trim().is_empty() {
                return self.run_config(home);
            }
        }
        let reference = self
            .args
            .first()
            .map_or(self.configuration.tunnel.as_str(), String::as_str)
            .to_owned();
        // The source first accepts a real non-nil UUID from explicit credentials.
        let contents = if !self.string("credentials-contents").is_empty() {
            Some(self.string("credentials-contents").to_owned())
        } else if !self.string("credentials-file").is_empty() {
            std::fs::read_to_string(config::expand_home(self.string("credentials-file"), home)?)
                .ok()
        } else {
            None
        };
        let id = if let Some(id) = contents
            .as_deref()
            .and_then(|contents| serde_json::from_str::<config::Credentials>(contents).ok())
            .map(|credentials| credentials.tunnel_id)
            .filter(|id| !id.is_nil())
        {
            id
        } else {
            let explicit = if self.string("origincert").is_empty() {
                String::new()
            } else {
                config::expand_home(self.string("origincert"), home)?
                    .to_string_lossy()
                    .into_owned()
            };
            let credentials = crate::administration::credentials::AccountCredentials::read(
                &crate::administration::credentials::cert_path(&explicit)?,
            )?;
            crate::administration::AccountClient::new(credentials, self.string("api-url"))?
                .resolve_tunnel(&reference)
                .await?
        };
        self.args = vec![id.to_string()];
        self.run_config(home)
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
        self.run_config_for_credentials(credentials, token_authenticated, home)
    }

    pub fn run_config_for_credentials(
        &self,
        credentials: config::Credentials,
        token_authenticated: bool,
        home: Option<&Path>,
    ) -> Result<RunConfig> {
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
        let known_secrets = [
            "token",
            "credentials-contents",
            "api-key",
            "api-ca-key",
            "secret",
            "service-token-secret",
        ]
        .iter()
        .filter(|name| !self.string(name).is_empty())
        .map(|name| self.string(name).to_owned())
        .chain(std::iter::once(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &credentials.tunnel_secret,
        )))
        .collect();
        Ok(RunConfig {
            tags: config::parse_tags(&self.list("tag"))?,
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
            max_active_flows: self
                .is_set("max-active-flows")
                .then(|| self.string("max-active-flows").parse())
                .transpose()
                .context("invalid max-active-flows")?,
            dns_resolver_addrs: self
                .list("dns-resolver-addrs")
                .iter()
                .map(|address| address.parse().context("invalid DNS resolver address:port"))
                .collect::<Result<Vec<_>>>()?,
            icmpv4_src: (!self.string("icmpv4-src").is_empty())
                .then(|| self.string("icmpv4-src").parse())
                .transpose()
                .context("invalid icmpv4-src")?,
            icmpv6_src: if self.string("icmpv6-src").is_empty() {
                None
            } else {
                let value = self.string("icmpv6-src");
                let (address, interface) = value
                    .split_once('%')
                    .map_or((value, None), |(address, interface)| {
                        (address, Some(interface))
                    });
                address
                    .parse::<std::net::Ipv6Addr>()
                    .context("invalid icmpv6-src")?;
                if interface.is_some_and(str::is_empty) {
                    bail!("icmpv6-src interface cannot be empty");
                }
                Some(value.to_owned())
            },
            features: self.list("features"),
            logging: crate::observability::logging::Options {
                level: crate::observability::logging::Level::parse(self.string("loglevel"))
                    .unwrap_or_default(),
                json: self.string("output") == "json",
                file: (!self.string("logfile").is_empty())
                    .then(|| config::expand_home(self.string("logfile"), home))
                    .transpose()?,
                directory: (!self.string("log-directory").is_empty())
                    .then(|| config::expand_home(self.string("log-directory"), home))
                    .transpose()?,
                disable_terminal: false,
            },
            known_secrets,
            management_hostname: self.string("management-hostname").to_owned(),
            service_op_ip: self.string("service-op-ip").to_owned(),
            diagnostic_cli_flags: self.diagnostic_flags(home)?,
            management_diagnostics: self.bool("management-diagnostics"),
            connector_label: self.string("label").to_owned(),
            token_authenticated,
            quick_hostname: String::new(),
            quick_authorizer: None,
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

    fn diagnostic_flags(&self, home: Option<&Path>) -> Result<BTreeMap<String, String>> {
        const INCLUDED: &[&str] = &[
            "config",
            "autoupdate-freq",
            "no-autoupdate",
            "no-prechecks",
            "metrics",
            "pidfile",
            "url",
            "hello-world",
            "socks5",
            "proxy-connect-timeout",
            "proxy-tls-timeout",
            "proxy-tcp-keepalive",
            "proxy-no-happy-eyeballs",
            "proxy-keepalive-connections",
            "proxy-keepalive-timeout",
            "proxy-connection-timeout",
            "proxy-expect-continue-timeout",
            "http-host-header",
            "origin-server-name",
            "unix-socket",
            "origin-ca-pool",
            "no-tls-verify",
            "no-chunked-encoding",
            "http2-origin",
            "management-hostname",
            "service-op-ip",
            "local-ssh-port",
            "ssh-idle-timeout",
            "ssh-max-timeout",
            "ssh-server",
            "bastion",
            "proxy-address",
            "proxy-port",
            "loglevel",
            "logfile",
            "log-directory",
            "trace-output",
            "edge",
            "region",
            "edge-ip-version",
            "edge-bind-address",
            "cacert",
            "hostname",
            "id",
            "lb-pool",
            "api-url",
            "tag",
            "max-edge-addr-retries",
            "retries",
            "ha-connections",
            "rpc-timeout",
            "write-stream-timeout",
            "quic-disable-pmtu-discovery",
            "quic-connection-level-flow-control-limit",
            "quic-stream-level-flow-control-limit",
            "label",
            "grace-period",
            "dial-edge-timeout",
            "name",
            "quick-service",
        ];
        self.specified
            .keys()
            .filter(|name| INCLUDED.contains(&name.as_str()))
            .filter(|name| !self.string(name).is_empty())
            .map(|name| {
                let value = if ["logfile", "log-directory"].contains(&name.as_str()) {
                    let path = config::expand_home(self.string(name), home)?;
                    if path.is_absolute() {
                        path
                    } else {
                        std::env::current_dir()?.join(path)
                    }
                    .to_string_lossy()
                    .into_owned()
                } else {
                    self.string(name).to_owned()
                };
                Ok((name.clone(), value))
            })
            .collect()
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
            proxy_type: self.is_set("socks5").then(|| "socks".into()),
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
        Kind::Float => value.parse::<f64>().is_ok_and(|value| value.is_finite()),
        Kind::Duration => config::parse_duration(value).is_ok(),
        _ => true,
    };
    if !valid {
        bail!("invalid value for --{name}");
    }
    Ok(())
}

fn root_configuration(path: Option<&Path>) -> Result<LoadedConfig> {
    let Some(path) = path else {
        return Ok(LoadedConfig::default());
    };
    let bytes = std::fs::read(path).context("Cannot read configuration file")?;
    let document = serde_yaml_ng::Deserializer::from_slice(&bytes).next();
    let mut configuration = match document {
        Some(document) => <Option<LoadedConfig> as serde::Deserialize>::deserialize(document)
            .map(Option::unwrap_or_default)
            .map_err(|_| anyhow::anyhow!("error parsing YAML in config file"))?,
        None => LoadedConfig::default(),
    };
    configuration.source = Some(path.to_owned());
    Ok(configuration)
}

fn root_yaml_value(kind: Kind, value: &serde_yaml_ng::Value) -> Result<Option<String>> {
    use serde_yaml_ng::Value;
    match (kind, value) {
        (Kind::Duration, Value::String(duration)) if duration.starts_with('-') => {
            root_duration(duration)?;
            Ok(None)
        }
        (Kind::Duration, Value::String(duration)) if duration.starts_with('+') => {
            root_duration(duration)?;
            yaml_value(kind, &Value::String(duration[1..].into()))
        }
        _ => yaml_value(kind, value),
    }
}

fn root_duration(value: &str) -> Result<()> {
    let magnitude = value
        .strip_prefix('-')
        .or_else(|| value.strip_prefix('+'))
        .unwrap_or(value);
    if magnitude.starts_with(['+', '-']) {
        bail!("invalid duration sign");
    }
    config::parse_duration(magnitude)?;
    Ok(())
}

fn root_integer(value: &str) -> Result<()> {
    let negative = value.starts_with('-');
    let unsigned = value
        .strip_prefix('-')
        .or_else(|| value.strip_prefix('+'))
        .unwrap_or(value);
    let (radix, digits, prefix) = if let Some(digits) = unsigned
        .strip_prefix("0x")
        .or_else(|| unsigned.strip_prefix("0X"))
    {
        (16, digits, true)
    } else if let Some(digits) = unsigned
        .strip_prefix("0b")
        .or_else(|| unsigned.strip_prefix("0B"))
    {
        (2, digits, true)
    } else if let Some(digits) = unsigned
        .strip_prefix("0o")
        .or_else(|| unsigned.strip_prefix("0O"))
    {
        (8, digits, true)
    } else if unsigned.starts_with('0') && unsigned.len() > 1 {
        (8, unsigned, false)
    } else {
        (10, unsigned, false)
    };
    if digits.contains(['+', '-']) {
        bail!("invalid integer sign");
    }
    for (index, byte) in digits.bytes().enumerate() {
        if byte == b'_'
            && !(index == 0 && prefix || index > 0 && digits.as_bytes()[index - 1] != b'_')
        {
            bail!("invalid integer separator");
        }
    }
    if digits.ends_with('_') {
        bail!("invalid integer separator");
    }
    let magnitude =
        u64::from_str_radix(&digits.replace('_', ""), radix).context("invalid integer")?;
    if magnitude > i64::MAX as u64 + u64::from(negative) {
        bail!("integer outside supported range");
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
    #[ignore = "requires the pinned Go source oracle"]
    fn go_root_altsrc_scope_contract() {
        let oracle = std::env::var_os("CLOUDFLARED_GO_ORACLE").expect("pinned Go oracle");
        let output = std::process::Command::new(oracle)
            .args(["watcher", "[]"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let source: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let source = source["root_yaml_names"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect::<std::collections::BTreeSet<_>>();
        let names = flags::FLAGS
            .iter()
            .map(|flag| flag.name)
            .chain(ROOT_YAML_EXTRA.iter().map(|(name, _, _)| *name));
        let actual = names
            .filter(|name| root_yaml_kind(name).is_some())
            .map(str::to_owned)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(actual, source);
    }

    #[test]
    fn watcher_dispatch_counts_cli_and_effective_yaml_but_not_environment() {
        let home = std::env::temp_dir().join(format!(
            "cloudflared-empty-invocation-{}",
            uuid::Uuid::new_v4()
        ));
        let directory = home.join(".cloudflared");
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("config.yml");
        for (args, environment, yaml, watcher) in [
            (vec![], BTreeMap::new(), "forwarders: []\n", true),
            (vec!["--"], BTreeMap::new(), "forwarders: []\n", true),
            (
                vec![],
                BTreeMap::from([("TUNNEL_NAME", "synthetic")]),
                "forwarders: []\n",
                true,
            ),
            (
                vec![],
                BTreeMap::from([("TUNNEL_LOGLEVEL", "debug")]),
                "loglevel: error\n",
                true,
            ),
            (
                vec!["--hello-world=false"],
                BTreeMap::new(),
                "forwarders: []\n",
                false,
            ),
            (vec!["version"], BTreeMap::new(), "forwarders: []\n", false),
            (vec![], BTreeMap::new(), "loglevel: debug\n", false),
            (
                vec![],
                BTreeMap::new(),
                "no-tls-verify: false\nha-connections: 0\nurl: ''\nrpc-timeout: -1s\n",
                true,
            ),
            (vec![], BTreeMap::new(), "edge: []\n", false),
            (
                vec![],
                BTreeMap::new(),
                "token: ignored\nfeatures: [ignored]\noutput: json\n",
                true,
            ),
            (vec![], BTreeMap::new(), "bucket-name: synthetic\n", false),
            (
                vec![],
                BTreeMap::from([("BUCKET_ID", "")]),
                "bucket-name: synthetic\n",
                true,
            ),
            (
                vec![],
                BTreeMap::new(),
                "forwarders: []\n---\ninvalid: [\n",
                true,
            ),
        ] {
            std::fs::write(&path, yaml).unwrap();
            let env = environment
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect();
            let invocation =
                Invocation::parse(args.into_iter().map(str::to_owned), &env, Some(&home)).unwrap();
            assert_eq!(
                matches!(invocation.action(Some(&home)), Ok(Action::Watch(_))),
                watcher,
                "{yaml}"
            );
        }
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn watcher_extra_environment_initialization_matches_source_types() {
        let home = std::env::temp_dir().join(format!(
            "cloudflared-extra-environment-{}",
            uuid::Uuid::new_v4()
        ));
        let directory = home.join(".cloudflared");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("config.yml"), "forwarders: []\n").unwrap();
        for (key, value, valid) in [
            ("TUNNEL_COMPRESSION_LEVEL", "invalid", false),
            ("TUNNEL_COMPRESSION_LEVEL", "", true),
            ("TUNNEL_COMPRESSION_LEVEL", "0x10", true),
            ("TUNNEL_COMPRESSION_LEVEL", "-1", true),
            ("TUNNEL_METRICS_UPDATE_FREQ", "invalid", false),
            ("TUNNEL_METRICS_UPDATE_FREQ", "", true),
            ("TUNNEL_METRICS_UPDATE_FREQ", "-1s", true),
            ("TUNNEL_METRICS_UPDATE_FREQ", "+0", true),
            ("TUNNEL_METRICS_UPDATE_FREQ", "-+1s", false),
            ("TUNNEL_USE_RECONNECT_TOKEN", "invalid", false),
            ("TUNNEL_USE_RECONNECT_TOKEN", "", true),
        ] {
            let env = BTreeMap::from([(key.into(), value.into())]);
            let invocation = Invocation::parse(std::iter::empty(), &env, Some(&home));
            assert_eq!(invocation.is_ok(), valid, "{key}/{value}");
            if let Ok(invocation) = invocation {
                assert!(matches!(
                    invocation.action(Some(&home)),
                    Ok(Action::Watch(_))
                ));
            }
        }
        for invalid in ["rpc-timeout: 1\n", "rpc-timeout: 1.5\n", "loglevel: null\n"] {
            std::fs::write(directory.join("config.yml"), invalid).unwrap();
            assert!(Invocation::parse(std::iter::empty(), &BTreeMap::new(), Some(&home)).is_err());
        }
        std::fs::remove_dir_all(home).unwrap();
    }

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
    #[test]
    fn invalid_tags_fail_before_credential_or_admin_effects() {
        for arguments in [
            vec!["tunnel", "--tag", "key=", "run"],
            vec!["tunnel", "--name", "synthetic", "--tag", "=DO-NOT-ECHO"],
        ] {
            let invocation = Invocation::parse(
                arguments.into_iter().map(str::to_owned),
                &BTreeMap::new(),
                None,
            )
            .unwrap();
            let error = invocation.action(None).err().unwrap();
            assert!(error.to_string().contains("Cannot parse tag value"));
            assert!(!error.to_string().contains("DO-NOT-ECHO"));
        }
    }

    #[test]
    fn tag_sources_and_socks_is_set_preserve_source_semantics() {
        let home =
            std::env::temp_dir().join(format!("cloudflared-tags-socks-{}", uuid::Uuid::new_v4()));
        let directory = home.join(".cloudflared");
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("config.yml");
        std::fs::write(&path, "tag: ['x=y,z', 'x= ', 'ID=user']\n").unwrap();
        let yaml = Invocation::parse(
            ["tunnel", "run"].map(str::to_owned),
            &BTreeMap::new(),
            Some(&home),
        )
        .unwrap();
        assert_eq!(yaml.list("tag"), ["x=y,z", "x= ", "ID=user"]);
        assert!(config::parse_tags(&yaml.list("tag")).is_ok());
        let env = BTreeMap::from([("TUNNEL_TAG".into(), " x=one , ID=two ".into())]);
        let environment =
            Invocation::parse(["tunnel", "run"].map(str::to_owned), &env, Some(&home)).unwrap();
        assert_eq!(environment.list("tag"), ["x=one", "ID=two"]);
        let cli = Invocation::parse(
            ["tunnel", "--tag", "x=one,two", "--tag", "x= ", "run"].map(str::to_owned),
            &env,
            Some(&home),
        )
        .unwrap();
        assert_eq!(cli.list("tag"), ["x=one,two", "x= "]);
        let scopes = Invocation::parse(
            ["--tag", "x=root", "tunnel", "--tag", "x=parent", "run"].map(str::to_owned),
            &BTreeMap::new(),
            Some(&home),
        )
        .unwrap();
        assert_eq!(scopes.list("tag"), ["x=parent"]);
        assert!(
            Invocation::parse(
                ["tunnel", "run", "--tag", "x=late"].map(str::to_owned),
                &BTreeMap::new(),
                Some(&home)
            )
            .is_err()
        );
        std::fs::write(&path, "tag: []\n").unwrap();
        assert!(
            Invocation::parse(
                ["tunnel", "run"].map(str::to_owned),
                &BTreeMap::new(),
                Some(&home)
            )
            .unwrap()
            .list("tag")
            .is_empty()
        );
        for (arguments, environment, yaml, expected) in [
            (vec!["--socks5=false"], BTreeMap::new(), "", true),
            (
                vec![],
                BTreeMap::from([("TUNNEL_SOCKS", "false")]),
                "socks5: false\n",
                true,
            ),
            (
                vec![],
                BTreeMap::from([("TUNNEL_SOCKS", "")]),
                "socks5: true\n",
                false,
            ),
            (vec![], BTreeMap::new(), "socks5: true\n", true),
            (vec![], BTreeMap::new(), "socks5: false\n", false),
        ] {
            std::fs::write(&path, yaml).unwrap();
            let environment = environment
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect();
            let args = ["tunnel", "run"]
                .into_iter()
                .chain(arguments)
                .map(str::to_owned);
            let invocation = Invocation::parse(args, &environment, Some(&home)).unwrap();
            assert_eq!(invocation.is_set("socks5"), expected);
            assert_eq!(
                invocation
                    .single_origin_request()
                    .unwrap()
                    .proxy_type
                    .as_deref(),
                expected.then_some("socks")
            );
        }
        std::fs::remove_dir_all(home).unwrap();
    }
}
