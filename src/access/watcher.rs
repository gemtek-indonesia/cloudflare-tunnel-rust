use super::{forward, token::TokenClient};
use crate::{
    cli::Invocation,
    observability::{
        Context,
        logging::{Event, Level, Options},
    },
};
use anyhow::{Context as _, Result, bail};
use futures::{StreamExt, stream::FuturesUnordered};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    ffi::CString,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    io::{AsyncWriteExt, unix::AsyncFd},
    net::TcpListener,
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Default, Deserialize)]
pub(super) struct Forwarder {
    #[serde(default, deserialize_with = "string_or_null")]
    pub(super) url: String,
    #[serde(default, deserialize_with = "string_or_null")]
    pub(super) listener: String,
    #[serde(
        default,
        rename = "serviceTokenID",
        deserialize_with = "string_or_null"
    )]
    pub(super) token_client_id: String,
    #[serde(
        default,
        rename = "serviceTokenSecret",
        deserialize_with = "string_or_null"
    )]
    pub(super) token_secret: String,
    #[serde(default, deserialize_with = "string_or_null")]
    pub(super) destination: String,
    #[serde(default, rename = "isFedramp", deserialize_with = "bool_or_null")]
    pub(super) is_fedramp: bool,
}
impl Forwarder {
    fn hash(&self) -> Result<Vec<u8>> {
        let input = [
            &self.url,
            &self.listener,
            &self.token_client_id,
            &self.token_secret,
            &self.destination,
        ]
        .map(String::as_str)
        .concat();
        Ok(boring::hash::hash(boring::hash::MessageDigest::sha256(), input.as_bytes())?.to_vec())
    }
}

fn string_or_null<'de, D: serde::Deserializer<'de>>(
    value: D,
) -> std::result::Result<String, D::Error> {
    Ok(Option::<String>::deserialize(value)?.unwrap_or_default())
}

fn bool_or_null<'de, D: serde::Deserializer<'de>>(value: D) -> std::result::Result<bool, D::Error> {
    Ok(Option::<bool>::deserialize(value)?.unwrap_or_default())
}

#[derive(Default, Deserialize)]
struct Root {
    #[serde(default)]
    forwarders: Option<Vec<Forwarder>>,
    #[serde(default, rename = "logDirectory", deserialize_with = "string_or_null")]
    _log_directory: String,
    #[serde(default, rename = "logLevel", deserialize_with = "string_or_null")]
    _log_level: String,
    #[serde(default, rename = "tunnels")]
    _tunnels: Option<Vec<Tunnel>>,
}
#[derive(Deserialize)]
struct Tunnel {
    #[serde(default, rename = "url", deserialize_with = "string_or_null")]
    _url: String,
    #[serde(default, rename = "origin", deserialize_with = "string_or_null")]
    _origin: String,
    #[serde(default, rename = "type", deserialize_with = "string_or_null")]
    _protocol_type: String,
}
async fn read_config(path: &Path) -> Result<Root> {
    let bytes = tokio::fs::read(path)
        .await
        .context("Cannot read forwarder configuration")?;
    let Some(document) = serde_yaml_ng::Deserializer::from_slice(&bytes).next() else {
        return Ok(Root::default());
    };
    Option::<Root>::deserialize(document)
        .map(Option::unwrap_or_default)
        .map_err(|_| anyhow::anyhow!("error parsing forwarder YAML configuration"))
}

async fn find_or_create(
    directories: &[PathBuf],
    default_path: &Path,
    log_directory: &Path,
) -> Result<PathBuf> {
    if let Some(path) = crate::config::discover_config(directories) {
        return Ok(path);
    }
    tokio::fs::create_dir_all(
        default_path
            .parent()
            .context("Invalid default configuration path")?,
    )
    .await?;
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o666);
    let mut file = match options.open(default_path).await {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Ok(default_path.to_owned());
        }
        Err(_) => bail!("Cannot create default configuration file"),
    };
    let _ = tokio::fs::create_dir_all(log_directory).await;
    let config = BTreeMap::from([("logDirectory", log_directory.to_string_lossy().into_owned())]);
    file.write_all(serde_yaml_ng::to_string(&config)?.as_bytes())
        .await?;
    file.flush().await?;
    Ok(default_path.to_owned())
}

struct FileWatch(AsyncFd<OwnedFd>);
impl FileWatch {
    fn new(path: &Path) -> Result<Self> {
        let path =
            CString::new(path.as_os_str().as_bytes()).context("Invalid configuration path")?;
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mask = libc::IN_MODIFY | libc::IN_ATTRIB | libc::IN_MOVE_SELF | libc::IN_DELETE_SELF;
        if unsafe { libc::inotify_add_watch(fd.as_raw_fd(), path.as_ptr(), mask) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self(AsyncFd::new(fd)?))
    }
    async fn next_write(&self) -> std::io::Result<()> {
        let mut buffer = [0u8; 4096];
        loop {
            let mut ready = self.0.readable().await?;
            let count = match ready.try_io(|fd| {
                let count = unsafe {
                    libc::read(
                        fd.get_ref().as_raw_fd(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                    )
                };
                if count < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(count as usize)
                }
            }) {
                Ok(result) => result?,
                Err(_) => continue,
            };
            let mut offset = 0;
            let mut changed = false;
            while offset + size_of::<libc::inotify_event>() <= count {
                let event = unsafe {
                    std::ptr::read_unaligned(
                        buffer.as_ptr().add(offset).cast::<libc::inotify_event>(),
                    )
                };
                offset += size_of::<libc::inotify_event>() + event.len as usize;
                if offset > count {
                    return Err(std::io::Error::other("Invalid configuration watch event"));
                }
                if event.mask & libc::IN_Q_OVERFLOW != 0 {
                    return Err(std::io::Error::other("Configuration watch overflow"));
                }
                changed |= event.mask & libc::IN_MODIFY != 0;
            }
            if changed {
                return Ok(());
            }
        }
    }
}

struct Entry {
    hash: Vec<u8>,
    forwarder: Arc<Forwarder>,
    listener: Option<TcpListener>,
}
struct Watcher {
    entries: BTreeMap<String, Entry>,
    flows: JoinSet<Result<()>>,
    context: Arc<Context>,
    token_directory: PathBuf,
}
impl Watcher {
    fn new(context: Arc<Context>, token_directory: PathBuf) -> Self {
        Self {
            entries: BTreeMap::new(),
            flows: JoinSet::new(),
            context,
            token_directory,
        }
    }
    fn log(&self, level: Level, message: &str) -> Result<()> {
        self.context
            .logger
            .log(level, Event::Tcp, message, serde_json::Value::Null)
    }
    async fn replace(&mut self, root: Root) -> Result<()> {
        let mut active = std::collections::BTreeSet::new();
        for forwarder in root.forwarders.unwrap_or_default() {
            active.insert(forwarder.listener.clone());
            let hash = forwarder.hash()?;
            if self
                .entries
                .get(&forwarder.listener)
                .is_some_and(|entry| entry.hash == hash)
            {
                continue;
            }
            self.entries.remove(&forwarder.listener);
            let listener = match listener_address(&forwarder.listener) {
                Ok(address) => match bind_listener(&address).await {
                    Ok(listener) => Some(listener),
                    Err(_) => {
                        self.log(Level::Error, "Forwarder listener could not bind")?;
                        None
                    }
                },
                Err(_) => {
                    self.log(Level::Error, "Forwarder listener URL is invalid")?;
                    None
                }
            };
            self.entries.insert(
                forwarder.listener.clone(),
                Entry {
                    hash,
                    forwarder: Arc::new(forwarder),
                    listener,
                },
            );
        }
        self.entries.retain(|name, _| active.contains(name));
        Ok(())
    }
    async fn accept(
        entries: &BTreeMap<String, Entry>,
    ) -> (String, std::io::Result<tokio::net::TcpStream>) {
        let mut pending = entries
            .iter()
            .filter_map(|(name, entry)| {
                entry.listener.as_ref().map(|listener| async move {
                    (
                        name.clone(),
                        listener.accept().await.map(|(socket, _)| socket),
                    )
                })
            })
            .collect::<FuturesUnordered<_>>();
        pending.next().await.expect("active listener")
    }
    fn start_flow(&mut self, name: &str, socket: tokio::net::TcpStream) {
        let forwarder = self.entries[name].forwarder.clone();
        let directory = self.token_directory.clone();
        self.flows.spawn(async move {
            let options = forward::Options::from_forwarder(&forwarder, &directory)?;
            let websocket = options.connect().await?;
            let (reader, writer) = socket.into_split();
            forward::pipe(websocket, reader, writer).await
        });
    }
    async fn run(mut self, path: &Path, cancel: CancellationToken) -> Result<()> {
        let watch = FileWatch::new(path)?;
        let initial = read_config(path).await?;
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            result = self.replace(initial) => result?,
        }
        let result = async {
            loop {
                enum Work {
                    Stop,
                    Change(std::io::Result<()>),
                    Accepted(String, std::io::Result<tokio::net::TcpStream>),
                    Flow(Option<std::result::Result<Result<()>, tokio::task::JoinError>>),
                }
                let work = tokio::select! {
                    _ = cancel.cancelled() => { Work::Stop }
                    changed = watch.next_write() => { Work::Change(changed) }
                    (name, socket) = Self::accept(&self.entries),
                        if self.entries.values().any(|entry| entry.listener.is_some()) => {
                        Work::Accepted(name, socket)
                    }
                    result = self.flows.join_next(), if !self.flows.is_empty() => {
                        Work::Flow(result)
                    }
                };
                match work {
                    Work::Stop => break,
                    Work::Change(Ok(())) => match read_config(path).await {
                        Ok(config) => {
                            tokio::select! {
                                _ = cancel.cancelled() => break,
                                result = self.replace(config) => result?,
                            }
                        }
                        Err(_) => {
                            self.log(Level::Error, "Failed to read new forwarder configuration")?
                        }
                    },
                    Work::Change(Err(_)) => {
                        self.log(Level::Error, "Configuration watcher encountered an error")?
                    }
                    Work::Accepted(name, Ok(socket)) => self.start_flow(&name, socket),
                    Work::Accepted(name, Err(_)) => {
                        self.entries
                            .get_mut(&name)
                            .expect("active listener")
                            .listener = None;
                        self.log(Level::Error, "Forwarder listener encountered an error")?;
                    }
                    Work::Flow(Some(Err(_) | Ok(Err(_)))) => {
                        self.log(Level::Error, "Access client connection failed")?
                    }
                    Work::Flow(_) => {}
                }
            }
            Ok(())
        }
        .await;
        self.entries.clear();
        self.flows.abort_all();
        while self.flows.join_next().await.is_some() {}
        result
    }
}

pub(super) fn listener_address(input: &str) -> Result<String> {
    if input.is_empty() {
        bail!("Access listener URL should not be empty");
    }
    let mut bytes = input.as_bytes().iter().copied();
    while let Some(byte) = bytes.next() {
        if byte == b'%'
            && !(bytes.next().is_some_and(|byte| byte.is_ascii_hexdigit())
                && bytes.next().is_some_and(|byte| byte.is_ascii_hexdigit()))
        {
            bail!("Invalid Access listener URL escape");
        }
    }
    let decoded = percent_encoding::percent_decode_str(input)
        .decode_utf8()
        .context("Invalid Access listener URL")?;
    let input = decoded.split('#').next().unwrap_or_default();
    if input.starts_with(':') {
        bail!("Invalid Access listener URL");
    }
    if let Some((scheme, rest)) = input.split_once("://") {
        let authority = rest.split(['/', '?']).next().unwrap_or_default();
        if let Some(port) = authority.strip_prefix(':')
            && !port.is_empty()
            && port.bytes().all(|byte| byte.is_ascii_digit())
        {
            if !["http", "https", "ssh", "rdp", "smb", "tcp"]
                .contains(&scheme.to_ascii_lowercase().as_str())
            {
                bail!("Unsupported Access listener scheme");
            }
            return Ok(authority.to_owned());
        }
    } else if let Some((host, _)) = input.rsplit_once(':') {
        let ip = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok();
        if !ip
            && !(host
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphabetic())
                && host
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"+-.".contains(&byte)))
        {
            bail!("Invalid Access listener URL");
        }
    }
    let target = if input.contains("://") {
        input.to_owned()
    } else {
        format!("http://{input}")
    };
    let target = super::ApplicationUrl::remote(&target)?;
    if !["http", "https", "ssh", "rdp", "smb", "tcp"].contains(&target.scheme()) {
        bail!("Unsupported Access listener scheme");
    }
    let address = target.host();
    let host = target.hostname();
    let port = address
        .strip_prefix(&format!("[{host}]:"))
        .or_else(|| address.strip_prefix(&format!("{host}:")))
        .context("Access listener requires an explicit port")?;
    if port.is_empty() {
        bail!("Access listener requires an explicit port");
    }
    Ok(address.to_owned())
}

pub(super) async fn bind_listener(address: &str) -> std::io::Result<TcpListener> {
    let Some(port) = address.strip_prefix(':') else {
        return TcpListener::bind(address).await;
    };
    let port: u16 = port.parse().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid Access listener port",
        )
    })?;
    let dual_stack = || -> std::io::Result<TcpListener> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        socket.set_only_v6(false)?;
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;
        let address = std::net::SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), port);
        socket.bind(&address.into())?;
        socket.listen(libc::SOMAXCONN)?;
        TcpListener::from_std(socket.into())
    };
    match dual_stack() {
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT | libc::EADDRNOTAVAIL)
            ) =>
        {
            TcpListener::bind(std::net::SocketAddr::new(
                std::net::Ipv4Addr::UNSPECIFIED.into(),
                port,
            ))
            .await
        }
        result => result,
    }
}

pub async fn execute(invocation: Invocation) -> Result<()> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let path = find_or_create(
        &crate::config::search_directories(home.as_deref()),
        Path::new("/usr/local/etc/cloudflared/config.yml"),
        Path::new("/var/log/cloudflared"),
    )
    .await?;
    let context = Context::new(
        Options {
            level: Level::parse(invocation.string("loglevel")).unwrap_or(Level::Info),
            json: invocation.string("output") == "json",
            file: (!invocation.string("logfile").is_empty())
                .then(|| invocation.string("logfile").into()),
            directory: (!invocation.string("log-directory").is_empty())
                .then(|| invocation.string("log-directory").into()),
            disable_terminal: true,
        },
        vec![],
    )?;
    let cancel = CancellationToken::new();
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let watcher =
        Watcher::new(context, TokenClient::default_directory()?).run(&path, cancel.clone());
    tokio::pin!(watcher);
    tokio::select! {
        result = &mut watcher => return result,
        _ = interrupt.recv() => cancel.cancel(),
        _ = terminate.recv() => cancel.cancel(),
    }
    watcher.await
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::tungstenite::Message;

    #[test]
    #[ignore = "requires the pinned Go source oracle"]
    fn go_forwarder_hash_and_listener_contract() {
        let listeners = [
            "127.0.0.1:0",
            "localhost:2222",
            "http://127.0.0.1:0/path?x=1",
            "https://localhost:443/a#fragment",
            "http://[::1]:0/a",
            "[::1]:0",
            "0.0.0.0:0",
            ":0",
            "http://:0",
            "::1",
            "[::1]",
            "127.0.0.1",
            "localhost",
            "localhost:",
            "http://localhost",
            "localhost:http",
            "ftp://localhost:22",
            "ssh://localhost:2222",
            "tcp://[0:0:0:0:0:0:0:1]:0",
            "rdp://127.0.0.1:3389",
            "smb://localhost:445",
            "localhost:65536",
            "http%3A%2F%2Flocalhost%3A2222%2Fa",
            "http://user:password@localhost:22/a",
            "LOCALHOST:2222",
            "b\u{fc}cher.invalid:2222",
            "https://b\u{fc}cher.invalid:443",
            "localhost:0/path",
            "127.0.0.1:0/path",
            "http://localhost:%30",
            "http://localhost:22/%zz",
            "http://localhost:22#fragment",
        ];
        let vectors = listeners.iter().enumerate().map(|(index, listener)| {
            let item = forwarder("http://synthetic.invalid/a", listener, "one");
            serde_json::json!({"listener":listener, "forwarder":{
                "url":item.url, "listener":item.listener, "service_token_id":item.token_client_id,
                "secret_token_id":item.token_secret, "destination":item.destination,
                "is_fedramp":index%2==1,
            }})
        }).collect::<Vec<_>>();
        let oracle = std::env::var_os("CLOUDFLARED_GO_ORACLE").expect("pinned Go oracle");
        let output = std::process::Command::new(oracle)
            .arg("watcher")
            .arg(serde_json::to_string(&vectors).unwrap())
            .output()
            .unwrap();
        assert!(output.status.success());
        let source: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        for (listener, source) in listeners.iter().zip(source["vectors"].as_array().unwrap()) {
            let item = forwarder("http://synthetic.invalid/a", listener, "one");
            let digest = item
                .hash()
                .unwrap()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(digest, source["hash"].as_str().unwrap());
            let address = listener_address(listener);
            assert_eq!(
                address.is_ok(),
                source["listener_valid"].as_bool().unwrap(),
                "{listener}"
            );
            if let Ok(address) = address {
                assert_eq!(
                    address,
                    source["listener_address"].as_str().unwrap(),
                    "{listener}"
                );
            }
        }
    }

    struct Temporary(PathBuf);
    impl Temporary {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("cloudflared-watcher-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temporary {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn forwarder(url: &str, listener: &str, destination: &str) -> Forwarder {
        Forwarder {
            url: url.into(),
            listener: listener.into(),
            destination: destination.into(),
            token_client_id: "synthetic-client".into(),
            token_secret: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                b"fixture",
            ),
            ..Default::default()
        }
    }
    fn config(forwarder: &Forwarder) -> Vec<u8> {
        serde_yaml_ng::to_string(&serde_json::json!({"forwarders":[{
            "url":forwarder.url, "listener":forwarder.listener,
            "serviceTokenID":forwarder.token_client_id, "serviceTokenSecret":forwarder.token_secret,
            "destination":forwarder.destination, "isFedramp":forwarder.is_fedramp,
        }]}))
        .unwrap()
        .into_bytes()
    }
    async fn round_trip(socket: &mut tokio::net::TcpStream, destination: &str) {
        socket.write_all(b"payload").await.unwrap();
        let expected = format!("{destination}:payload");
        let mut response = vec![0; expected.len()];
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            socket.read_exact(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response, expected.as_bytes());
    }

    #[tokio::test]
    async fn native_file_write_only_and_no_rename_rearm() {
        let temporary = Temporary::new();
        let path = temporary.0.join("config.yml");
        std::fs::write(&path, "forwarders: []\n").unwrap();
        let watch = FileWatch::new(&path).unwrap();
        std::fs::write(&path, "forwarders: []\n# written\n").unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), watch.next_write())
            .await
            .unwrap()
            .unwrap();
        std::fs::rename(&path, temporary.0.join("previous.yml")).unwrap();
        std::fs::write(&path, "forwarders: []\n# replacement\n").unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), watch.next_write())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn failed_entries_same_hash_skip_and_empty_configuration_removes() {
        let temporary = Temporary::new();
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = occupied.local_addr().unwrap().to_string();
        let item = forwarder("invalid remote deferred", &address, "one");
        let path = temporary.0.join("config.yml");
        std::fs::write(&path, config(&item)).unwrap();
        let mut watcher = Watcher::new(Context::quiet().unwrap(), temporary.0.join("credentials"));
        watcher
            .replace(read_config(&path).await.unwrap())
            .await
            .unwrap();
        assert!(watcher.entries[&address].listener.is_none());
        drop(occupied);
        watcher
            .replace(read_config(&path).await.unwrap())
            .await
            .unwrap();
        assert!(watcher.entries[&address].listener.is_none());
        let mut changed = item.clone();
        changed.is_fedramp = true;
        std::fs::write(&path, config(&changed)).unwrap();
        watcher
            .replace(read_config(&path).await.unwrap())
            .await
            .unwrap();
        assert!(watcher.entries[&address].listener.is_none());
        changed.destination = "two".into();
        std::fs::write(&path, config(&changed)).unwrap();
        watcher
            .replace(read_config(&path).await.unwrap())
            .await
            .unwrap();
        assert!(watcher.entries[&address].listener.is_some());
        std::fs::write(&path, "").unwrap();
        watcher
            .replace(read_config(&path).await.unwrap())
            .await
            .unwrap();
        assert!(watcher.entries.is_empty());
        std::fs::write(&path, "forwarders: [\n").unwrap();
        assert!(read_config(&path).await.is_err());
        let cancel = CancellationToken::new();
        cancel.cancel();
        std::fs::write(&path, "").unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            watcher.run(&path, cancel),
        )
        .await
        .unwrap()
        .unwrap();
    }

    #[tokio::test]
    async fn unsupported_remote_scheme_fails_without_origin_connection() {
        let temporary = Temporary::new();
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let item = forwarder(
            &format!("ftp://{}", origin.local_addr().unwrap()),
            "127.0.0.1:0",
            "one",
        );
        let options = forward::Options::from_forwarder(&item, &temporary.0).unwrap();
        assert!(options.connect().await.is_err());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), origin.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn default_config_creation_and_first_yaml_document() {
        let temporary = Temporary::new();
        let default = temporary.0.join("default/config.yml");
        let logs = temporary.0.join("logs");
        assert_eq!(find_or_create(&[], &default, &logs).await.unwrap(), default);
        assert!(logs.is_dir());
        assert!(read_config(&default).await.unwrap().forwarders.is_none());
        std::fs::write(&default, "forwarders: []\n---\nmalformed: [\n").unwrap();
        assert!(read_config(&default).await.is_ok());
        let existing = temporary.0.join("existing");
        std::fs::create_dir(&existing).unwrap();
        std::fs::write(existing.join("config.yaml"), "forwarders: []\n").unwrap();
        assert_eq!(
            find_or_create(std::slice::from_ref(&existing), &default, &logs)
                .await
                .unwrap(),
            existing.join("config.yaml")
        );
    }

    #[tokio::test]
    async fn watcher_reloads_preserves_streams_and_cancels_owned_flows() {
        struct Handshake<'a> {
            destination: &'a mut String,
            requests: &'a tokio::sync::mpsc::UnboundedSender<(String, http::HeaderMap)>,
        }
        impl tokio_tungstenite::tungstenite::handshake::server::Callback for Handshake<'_> {
            fn on_request(
                self,
                request: &tokio_tungstenite::tungstenite::handshake::server::Request,
                response: tokio_tungstenite::tungstenite::handshake::server::Response,
            ) -> std::result::Result<
                tokio_tungstenite::tungstenite::handshake::server::Response,
                tokio_tungstenite::tungstenite::handshake::server::ErrorResponse,
            > {
                *self.destination = request.headers()["cf-access-jump-destination"]
                    .to_str()
                    .unwrap()
                    .to_owned();
                self.requests
                    .send((request.uri().to_string(), request.headers().clone()))
                    .unwrap();
                Ok(response)
            }
        }
        let temporary = Temporary::new();
        let remote = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let remote_address = remote.local_addr().unwrap();
        let (requests, mut received) = tokio::sync::mpsc::unbounded_channel();
        let server = crate::runtime::AbortTask(tokio::spawn(async move {
            let mut flows = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = remote.accept() => {
                        let (socket, _) = accepted.unwrap();
                        let requests = requests.clone();
                        flows.spawn(async move {
                            let mut destination = String::new();
                            let mut websocket = tokio_tungstenite::accept_hdr_async(socket, Handshake { destination: &mut destination, requests: &requests }).await.unwrap();
                            while let Some(message) = websocket.next().await {
                                match message {
                                    Ok(Message::Binary(bytes)) => {
                                        let mut reply = format!("{destination}:").into_bytes();
                                        reply.extend(bytes);
                                        if websocket.send(Message::Binary(reply.into())).await.is_err() { break; }
                                    }
                                    _ => break,
                                }
                            }
                        });
                    }
                    _ = flows.join_next(), if !flows.is_empty() => {}
                }
            }
        }));
        let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        let mut item = forwarder(
            &format!("http://{remote_address}/a/../raw%2e?q=1"),
            &address.to_string(),
            "one",
        );
        let path = temporary.0.join("config.yml");
        std::fs::write(&path, config(&item)).unwrap();
        let cancel = CancellationToken::new();
        let token_directory = temporary.0.join("credentials");
        let watcher = Watcher::new(Context::quiet().unwrap(), token_directory.clone());
        let owned_path = path.clone();
        let stopped = cancel.clone();
        let mut task = crate::runtime::AbortTask(tokio::spawn(async move {
            watcher.run(&owned_path, stopped).await
        }));
        let mut old = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Ok(socket) = tokio::net::TcpStream::connect(address).await {
                    break socket;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        round_trip(&mut old, "one").await;
        let (target, headers) = received.recv().await.unwrap();
        assert_eq!(target, "/a/../raw%2e?q=1");
        assert_eq!(headers["cf-access-client-id"], item.token_client_id);
        assert_eq!(headers["cf-access-client-secret"], item.token_secret);
        assert!(!token_directory.exists());

        item.destination = "two".into();
        std::fs::write(&path, config(&item)).unwrap();
        let mut new = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Ok(mut socket) = tokio::net::TcpStream::connect(address).await {
                    socket.write_all(b"x").await.unwrap();
                    let mut response = [0; 5];
                    if socket.read_exact(&mut response).await.is_ok() && &response == b"two:x" {
                        break socket;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        round_trip(&mut old, "one").await;
        round_trip(&mut new, "two").await;
        std::fs::write(&path, "forwarders: [\n").unwrap();
        let mut retained = tokio::net::TcpStream::connect(address).await.unwrap();
        round_trip(&mut retained, "two").await;
        std::fs::write(&path, "").unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while tokio::net::TcpStream::connect(address).await.is_ok() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        round_trip(&mut old, "one").await;
        cancel.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(2), &mut task.0)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let mut byte = [0];
        assert_eq!(old.read(&mut byte).await.unwrap(), 0);
        assert!(tokio::net::TcpStream::connect(address).await.is_err());
        drop(server);
    }
}
