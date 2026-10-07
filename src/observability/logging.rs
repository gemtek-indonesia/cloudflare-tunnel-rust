use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tokio::sync::{Notify, mpsc};

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Debug,
    #[default]
    Info,
    Warn,
    Error,
    Fatal,
}
impl Level {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "debug" => Ok(Self::Debug),
            "" | "info" => Ok(Self::Info),
            "warn" | "warning" => Ok(Self::Warn),
            "error" => Ok(Self::Error),
            "fatal" => Ok(Self::Fatal),
            _ => bail!("loglevel must be debug, info, warn, error or fatal"),
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
            Self::Fatal => "fatal",
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Event {
    #[default]
    Cloudflared,
    Http,
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Log {
    #[serde(default)]
    pub time: String,
    #[serde(default = "debug_level")]
    pub level: Level,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub event: Event,
    #[serde(skip_serializing_if = "Map::is_empty", default)]
    pub fields: Map<String, Value>,
}
fn debug_level() -> Level {
    Level::Debug
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Filters {
    #[serde(default)]
    pub events: Vec<Event>,
    pub level: Option<Level>,
    #[serde(default)]
    pub sampling: f64,
}
impl Filters {
    fn matches(&self, log: &Log) -> bool {
        if self.level.is_some_and(|level| log.level < level)
            || !self.events.is_empty() && !self.events.contains(&log.event)
        {
            return false;
        }
        let sampling = self.sampling.clamp(0.0, 1.0);
        if sampling > 0.0 && sampling < 1.0 {
            let mut random = [0; 1];
            if boring::rand::rand_bytes(&mut random).is_err() {
                return false;
            }
            return (random[0] as f64) / 255.0 <= sampling;
        }
        true
    }
}

#[derive(Clone, Default)]
pub struct Options {
    pub level: Level,
    pub json: bool,
    pub file: Option<PathBuf>,
    pub directory: Option<PathBuf>,
    pub disable_terminal: bool,
}
struct Output {
    file: Option<File>,
    path: Option<PathBuf>,
    rolling: bool,
    bytes: u64,
}
struct Session {
    id: u64,
    actor: String,
    filters: Filters,
    sender: mpsc::Sender<Log>,
    cancel: tokio_util::sync::CancellationToken,
}
pub struct Logger {
    options: Options,
    output: Mutex<Output>,
    secrets: Vec<String>,
    sessions: Mutex<Vec<Session>>,
    next: std::sync::atomic::AtomicU64,
    changed: Notify,
}

impl Logger {
    pub fn new(mut options: Options, secrets: Vec<String>) -> Result<Arc<Self>> {
        let conflicting = options.file.is_some() && options.directory.is_some();
        let (mut path, mut rolling) = if let Some(path) = &options.file {
            (Some(path.clone()), false)
        } else if let Some(dir) = &options.directory {
            (Some(dir.join("cloudflared.log")), true)
        } else {
            (None, false)
        };
        let file_result = path
            .as_ref()
            .map(|path| {
                if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                    std::fs::create_dir_all(parent)?;
                }
                OpenOptions::new().create(true).append(true).open(path)
            })
            .transpose();
        let failed_output = file_result.is_err();
        let file = match file_result {
            Ok(file) => file,
            Err(_) => {
                options.disable_terminal = false;
                options.level = Level::Info;
                path = None;
                rolling = false;
                None
            }
        };
        let bytes = file
            .as_ref()
            .map(|file| file.metadata().map(|meta| meta.len()))
            .transpose()?
            .unwrap_or(0);
        let logger = Arc::new(Self {
            options,
            output: Mutex::new(Output {
                file,
                path,
                rolling,
                bytes,
            }),
            secrets: secrets.into_iter().filter(|s| !s.is_empty()).collect(),
            sessions: Mutex::new(Vec::new()),
            next: std::sync::atomic::AtomicU64::new(1),
            changed: Notify::new(),
        });
        if failed_output {
            let _ = logger.log(
                Level::Error,
                Event::Cloudflared,
                "Falling back to a default logger due to logger setup failure",
                Value::Null,
            );
        }
        if conflicting {
            let _ = logger.log(
                Level::Error,
                Event::Cloudflared,
                "logfile and log-directory are incompatible; logfile takes precedence",
                Value::Null,
            );
        }
        Ok(logger)
    }
    pub fn redact(&self, text: &str) -> String {
        let mut result = text.to_owned();
        for secret in &self.secrets {
            result = result.replace(secret, "[redacted]");
        }
        result
    }
    pub fn redact_value(&self, value: &Value) -> Value {
        match value {
            Value::String(value) => Value::String(self.redact(value)),
            Value::Array(values) => Value::Array(
                values
                    .iter()
                    .map(|value| self.redact_value(value))
                    .collect(),
            ),
            Value::Object(values) => Value::Object(
                values
                    .iter()
                    .map(|(key, value)| {
                        let name = key.to_ascii_lowercase().replace(['-', '_'], "");
                        let sensitive = name.contains("token")
                            || name.contains("secret")
                            || name.contains("password")
                            || matches!(
                                name.as_str(),
                                "authorization" | "cookie" | "credentialscontents"
                            );
                        (
                            key.clone(),
                            if sensitive {
                                Value::String("[redacted]".into())
                            } else {
                                self.redact_value(value)
                            },
                        )
                    })
                    .collect(),
            ),
            value => value.clone(),
        }
    }
    pub fn log(&self, level: Level, event: Event, message: &str, fields: Value) -> Result<()> {
        let fields = self
            .redact_value(&fields)
            .as_object()
            .cloned()
            .unwrap_or_default();
        let log = Log {
            time: timestamp(),
            level: if fields.get("error").is_some_and(|error| !error.is_null()) {
                Level::Error
            } else {
                level
            },
            event,
            message: self.redact(message),
            fields,
        };
        let mut failure = None;
        if log.level >= self.options.level {
            let mut record = serde_json::to_value(&log)?;
            let object = record.as_object_mut().unwrap();
            object.remove("fields");
            object.extend(log.fields.clone());
            let mut encoded = serde_json::to_vec(&record)?;
            encoded.push(b'\n');
            if !self.options.disable_terminal {
                let result = if self.options.json {
                    io::stderr().lock().write_all(&encoded)
                } else {
                    writeln!(
                        io::stderr().lock(),
                        "{} {} {} {}",
                        log.time,
                        log.level.label().to_uppercase(),
                        log.message,
                        serde_json::to_string(&log.fields)?
                    )
                };
                if let Err(error) = result {
                    failure = Some(error);
                }
            }
            match self.output.lock() {
                Ok(mut output) => {
                    if output.rolling
                        && output.bytes + encoded.len() as u64 > 1024 * 1024
                        && let Err(error) = rotate(&mut output)
                    {
                        failure = Some(io::Error::other(error));
                    }
                    if let Some(file) = &mut output.file {
                        if let Err(error) = file.write_all(&encoded) {
                            failure = Some(error);
                        } else {
                            output.bytes += encoded.len() as u64;
                        }
                    }
                }
                Err(_) => {
                    failure = Some(io::Error::other("log output lock poisoned"));
                }
            }
        }
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("log session lock poisoned"))?;
        sessions.retain(|session| !session.sender.is_closed() && !session.cancel.is_cancelled());
        for session in sessions.iter() {
            if session.filters.matches(&log) {
                let _ = session.sender.try_send(log.clone());
            }
        }
        if let Some(error) = failure {
            return Err(error.into());
        }
        Ok(())
    }
    pub fn subscribe(&self, actor: &str, filters: Filters) -> Result<Subscription> {
        if !filters.sampling.is_finite() {
            bail!("invalid log sampling value");
        }
        if filters.level == Some(Level::Fatal) {
            bail!("invalid management log level");
        }
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("log session lock poisoned"))?;
        sessions.retain(|session| !session.sender.is_closed() && !session.cancel.is_cancelled());
        if sessions.iter().any(|session| session.actor != actor) {
            bail!("limit exceeded for streaming sessions");
        }
        for session in sessions.drain(..) {
            session.cancel.cancel();
        }
        let (sender, receiver) = mpsc::channel(30);
        let cancel = tokio_util::sync::CancellationToken::new();
        let id = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        sessions.push(Session {
            id,
            actor: actor.into(),
            filters,
            sender,
            cancel: cancel.clone(),
        });
        self.changed.notify_waiters();
        Ok(Subscription {
            receiver,
            cancel,
            id,
        })
    }
    pub fn remove(&self, id: u64) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.retain(|session| {
                if session.id == id {
                    session.cancel.cancel();
                    false
                } else {
                    true
                }
            });
        }
        self.changed.notify_waiters();
    }
    pub fn log_path(&self) -> Option<PathBuf> {
        self.output
            .lock()
            .ok()
            .and_then(|output| output.path.clone())
    }
}
pub struct Subscription {
    pub receiver: mpsc::Receiver<Log>,
    pub cancel: tokio_util::sync::CancellationToken,
    pub id: u64,
}
impl Drop for Subscription {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn rotate(output: &mut Output) -> Result<()> {
    let path = output
        .path
        .as_ref()
        .context("rolling log path unavailable")?;
    output.file.take();
    for index in (1..=5).rev() {
        let next = backup(path, index);
        let previous = if index == 1 {
            path.clone()
        } else {
            backup(path, index - 1)
        };
        if previous.exists() {
            if next.exists() {
                std::fs::remove_file(&next)?;
            }
            std::fs::rename(previous, next)?;
        }
    }
    output.file = Some(OpenOptions::new().create(true).append(true).open(path)?);
    output.bytes = 0;
    Ok(())
}
fn backup(path: &Path, index: usize) -> PathBuf {
    path.with_file_name(format!("cloudflared-{index}.log"))
}
pub fn timestamp() -> String {
    timestamp_at(std::time::SystemTime::now())
}
pub(super) fn timestamp_at(now: std::time::SystemTime) -> String {
    let seconds = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as _;
    let mut time = std::mem::MaybeUninit::<libc::tm>::uninit();
    // SAFETY: both pointers refer to live, correctly sized values; gmtime_r initializes tm on success.
    if unsafe { libc::gmtime_r(&seconds, time.as_mut_ptr()) }.is_null() {
        return seconds.to_string();
    }
    // SAFETY: gmtime_r returned non-null and initialized time.
    let time = unsafe { time.assume_init() };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        time.tm_year + 1900,
        time.tm_mon + 1,
        time.tm_mday,
        time.tm_hour,
        time.tm_min,
        time.tm_sec
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn logs_filter_redact_bound_window_and_preempt_same_actor() {
        let logger = Logger::new(
            Options {
                disable_terminal: true,
                ..Default::default()
            },
            vec!["synthetic-sensitive-value".into()],
        )
        .unwrap();
        let mut first = logger
            .subscribe(
                "actor",
                Filters {
                    level: Some(Level::Warn),
                    ..Default::default()
                },
            )
            .unwrap();
        logger
            .log(Level::Info, Event::Http, "ignored", Value::Null)
            .unwrap();
        assert!(first.receiver.try_recv().is_err());
        logger
            .log(
                Level::Debug,
                Event::Cloudflared,
                "synthetic-sensitive-value",
                serde_json::json!({"error":"synthetic-sensitive-value","token":"other-secret"}),
            )
            .unwrap();
        let log = first.receiver.recv().await.unwrap();
        let json = serde_json::to_string(&log).unwrap();
        assert!(!json.contains("synthetic-sensitive-value"));
        assert!(!json.contains("other-secret"));
        assert_eq!(log.level, Level::Error);
        assert!(logger.subscribe("different", Filters::default()).is_err());
        let mut next = logger.subscribe("actor", Filters::default()).unwrap();
        assert!(first.cancel.is_cancelled());
        for _ in 0..31 {
            logger
                .log(Level::Info, Event::Udp, "bounded", Value::Null)
                .unwrap();
        }
        assert_eq!(next.receiver.len(), 30);
        assert!(next.receiver.recv().await.is_some());
    }
}
