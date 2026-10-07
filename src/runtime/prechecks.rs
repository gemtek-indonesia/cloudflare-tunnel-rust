use super::discovery;
use crate::{
    config::{Protocol, RunConfig},
    crypto::{EdgeTls, TlsPolicy},
    observability::{
        Context,
        logging::{Event, Level},
    },
    transport,
};
use anyhow::{Result, bail};
use serde::{Serialize, Serializer};
use std::{future::Future, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Pass,
    Fail,
    Skip,
}
impl Status {
    fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Skip => "SKIP",
        }
    }
    fn severity(self) -> u8 {
        match self {
            Self::Pass => 1,
            Self::Fail => 2,
            Self::Skip => 0,
        }
    }
}
impl Serialize for Status {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(match self {
            Self::Pass => 0,
            Self::Fail => 1,
            Self::Skip => 2,
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Dns,
    Quic,
    Http2,
    Management,
}
impl Kind {
    fn component(self) -> &'static str {
        match self {
            Self::Dns => "DNS Resolution",
            Self::Quic => "UDP Connectivity",
            Self::Http2 => "TCP Connectivity",
            Self::Management => "Cloudflare API",
        }
    }
    fn action(self) -> &'static str {
        match self {
            Self::Quic => "Allow outbound QUIC traffic on port 7844 or use HTTP2.",
            Self::Http2 => "Allow outbound TCP on port 7844.",
            Self::Management => {
                "Allow outbound TCP on port 443 to api.cloudflare.com for Cloudflare API connectivity."
            }
            Self::Dns => "",
        }
    }
    fn detail(self, passed: bool) -> &'static str {
        match (self, passed) {
            (Self::Quic, true) => "QUIC connection successful",
            (Self::Quic, false) => "QUIC connection failed",
            (Self::Http2, true) => "HTTP/2 connection successful",
            (Self::Http2, false) => "HTTP/2 connection is blocked or unreachable",
            (Self::Management, true) => "API is reachable",
            (Self::Management, false) => "API Connection failed",
            (Self::Dns, true) => "DNS Resolved successfully",
            (Self::Dns, false) => "No addresses returned",
        }
    }
}
impl Serialize for Kind {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(match self {
            Self::Dns => 0,
            Self::Quic => 1,
            Self::Http2 => 2,
            Self::Management => 3,
        })
    }
}
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct CheckResult {
    #[serde(rename = "Type")]
    kind: Kind,
    component: String,
    target: String,
    probe_status: Status,
    details: String,
    action: String,
}
impl CheckResult {
    fn new(kind: Kind, target: &str, status: Status, details: &str) -> Self {
        let action = if status == Status::Fail {
            if kind == Kind::Dns {
                format!(
                    "Ensure your DNS resolver can resolve '{target}'. Run: dig A {target} @1.1.1.1. If that fails, contact your network administrator."
                )
            } else {
                kind.action().into()
            }
        } else {
            String::new()
        };
        Self {
            kind,
            component: kind.component().into(),
            target: target.into(),
            probe_status: status,
            details: details.into(),
            action,
        }
    }
}
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct Report {
    #[serde(rename = "RunID")]
    run_id: uuid::Uuid,
    results: Vec<CheckResult>,
    suggested_protocol: Option<u8>,
}
impl Report {
    fn hard_fail(&self) -> bool {
        self.results
            .iter()
            .any(|r| r.kind == Kind::Dns && r.probe_status == Status::Fail)
            || self.failed(Kind::Quic) && self.failed(Kind::Http2)
    }
    fn failed(&self, kind: Kind) -> bool {
        self.results
            .iter()
            .any(|r| r.kind == kind && r.probe_status == Status::Fail)
    }
    fn warning(&self) -> bool {
        !self.hard_fail()
            && (self.failed(Kind::Quic) != self.failed(Kind::Http2)
                || self.failed(Kind::Management))
    }
    fn protocol_name(&self) -> Option<&'static str> {
        self.suggested_protocol
            .map(|protocol| if protocol == 1 { "quic" } else { "http2" })
    }
    fn table(&self) -> Vec<String> {
        let mut rows = vec![[
            "COMPONENT".to_owned(),
            "TARGET".into(),
            "STATUS".into(),
            "DETAILS".into(),
        ]];
        rows.extend(self.results.iter().map(|r| {
            [
                r.component.clone(),
                r.target.clone(),
                r.probe_status.label().into(),
                r.details.clone(),
            ]
        }));
        let widths: [usize; 3] = std::array::from_fn(|column| {
            rows.iter()
                .map(|row| row[column].chars().count())
                .max()
                .unwrap_or(0)
        });
        let mut lines = rows
            .into_iter()
            .map(|row| {
                format!(
                    "{:<a$}  {:<b$}  {:<c$}  {}",
                    row[0],
                    row[1],
                    row[2],
                    row[3],
                    a = widths[0],
                    b = widths[1],
                    c = widths[2]
                )
            })
            .collect::<Vec<_>>();
        lines.extend(
            self.results
                .iter()
                .filter(|r| r.probe_status == Status::Fail && !r.action.is_empty())
                .map(|r| {
                    format!(
                        "{}: {}",
                        if self.hard_fail() { "ERROR" } else { "WARNING" },
                        r.action
                    )
                }),
        );
        lines.push(String::new());
        lines.push(if self.hard_fail(){"SUMMARY: Environment has critical failures. cloudflared may not be able to establish a tunnel.".into()}else if self.warning(){self.protocol_name().map_or_else(||"SUMMARY: Environment ready with degraded transport.".into(),|protocol|format!("SUMMARY: Environment ready with degraded transport. cloudflared will proceed using '{protocol}'."))}else{self.protocol_name().map_or_else(||"SUMMARY: Environment is healthy.".into(),|protocol|format!("SUMMARY: Environment is healthy. cloudflared will use '{protocol}' as primary protocol."))});
        lines
    }
    fn log(&self, context: &Context) {
        let title = "CONNECTIVITY PRE-CHECKS";
        let table = self.table();
        let width = table
            .iter()
            .map(String::len)
            .max()
            .unwrap_or(0)
            .max(title.len());
        let border = format!("+{}+", "-".repeat(width + 4));
        let centered = format!(
            "{}{}{}",
            " ".repeat((width - title.len()) / 2),
            title,
            " ".repeat((width - title.len()).div_ceil(2))
        );
        let boxed = std::iter::once(border.clone())
            .chain(std::iter::once(format!("|  {centered}  |")))
            .chain(std::iter::once(border.clone()))
            .chain(
                table
                    .into_iter()
                    .map(|line| format!("|  {line}{}  |", " ".repeat(width - line.len()))),
            )
            .chain(std::iter::once(border));
        for line in boxed {
            let _ = context.logger.log(
                Level::Info,
                Event::Cloudflared,
                &line,
                serde_json::json!({}),
            );
        }
        for result in &self.results {
            let _=context.logger.log(Level::Info,Event::Cloudflared,"precheck",serde_json::json!({"run_id":self.run_id,"component":result.component,"target":result.target,"status":result.probe_status.label().to_ascii_lowercase(),"details":result.details}));
        }
        let mut fields = serde_json::json!({"run_id":self.run_id,"hard_fail":self.hard_fail()});
        if let Some(protocol) = self.protocol_name() {
            fields["suggested_protocol"] = serde_json::json!(protocol);
        }
        let _ = context
            .logger
            .log(Level::Info, Event::Cloudflared, "precheck complete", fields);
    }
}
struct Config {
    region: String,
    ip_version: String,
    edges: Vec<String>,
    protocol: Protocol,
    ca: Option<PathBuf>,
    strict_pq: bool,
    timeout: Duration,
}
impl Config {
    fn startup(config: &RunConfig) -> Self {
        Self {
            region: if config.region.is_empty() {
                config.credentials.endpoint.clone().unwrap_or_default()
            } else {
                config.region.clone()
            },
            ip_version: config.edge_ip_version.clone(),
            edges: config.edge.clone(),
            protocol: config.protocol,
            ca: config.edge_ca.clone(),
            strict_pq: config.post_quantum,
            timeout: Duration::from_secs(10),
        }
    }
    fn diagnostic(region: &str) -> Self {
        Self {
            region: region.into(),
            ip_version: "auto".into(),
            edges: vec![],
            protocol: Protocol::Auto,
            ca: None,
            strict_pq: false,
            timeout: Duration::from_secs(15),
        }
    }
}
trait Dialers {
    async fn resolve(&self, region: &str) -> Result<Vec<Vec<SocketAddr>>>;
    async fn lookup_host(&self, address: &str) -> Result<Vec<ProbeAddress>>;
    async fn connect(&self, kind: Kind, address: SocketAddr, tls: &EdgeTls) -> Result<()>;
    async fn management(&self) -> Result<()>;
}
struct Native {
    management_target: String,
}
impl Default for Native {
    fn default() -> Self {
        Self {
            management_target: "api.cloudflare.com:443".into(),
        }
    }
}
#[derive(Clone, Copy)]
struct ProbeAddress {
    tcp: SocketAddr,
    udp: SocketAddr,
}
impl From<SocketAddr> for ProbeAddress {
    fn from(address: SocketAddr) -> Self {
        Self {
            tcp: address,
            udp: address,
        }
    }
}
async fn resolve_one(address: &str) -> Result<SocketAddr> {
    let addresses = tokio::net::lookup_host(address).await?.collect::<Vec<_>>();
    let prefer_ipv4 = !address.contains('[');
    addresses
        .iter()
        .find(|address| address.ip().to_canonical().is_ipv4() == prefer_ipv4)
        .or_else(|| addresses.first())
        .copied()
        .ok_or_else(|| anyhow::anyhow!("No addresses returned"))
}
impl Dialers for Native {
    async fn resolve(&self, region: &str) -> Result<Vec<Vec<SocketAddr>>> {
        discovery::resolve_groups(region).await
    }
    async fn lookup_host(&self, address: &str) -> Result<Vec<ProbeAddress>> {
        Ok(vec![ProbeAddress {
            tcp: resolve_one(address).await?,
            udp: resolve_one(address).await?,
        }])
    }
    async fn connect(&self, kind: Kind, address: SocketAddr, tls: &EdgeTls) -> Result<()> {
        let options = transport::EdgeDialOptions {
            dial_timeout: Duration::from_secs(5),
            ..Default::default()
        };
        match kind {
            Kind::Quic => {
                let conn = transport::quic::dial_with_options(
                    address,
                    "probe.cftunnel.com",
                    tls,
                    &options,
                )
                .await?;
                conn.close();
            }
            Kind::Http2 => {
                let (stream, _) = transport::h2::dial_tls_with_options(
                    address,
                    "probe.cftunnel.com",
                    tls,
                    &options,
                )
                .await?;
                drop(stream);
            }
            _ => bail!("invalid edge probe kind"),
        }
        Ok(())
    }
    async fn management(&self) -> Result<()> {
        drop(tokio::net::TcpStream::connect(&self.management_target).await?);
        Ok(())
    }
}
struct Budget {
    deadline: Instant,
    cancel: CancellationToken,
}
impl Budget {
    async fn bounded<T>(
        &self,
        timeout: Duration,
        future: impl Future<Output = Result<T>>,
    ) -> Result<T> {
        if self.cancel.is_cancelled() {
            bail!("precheck canceled");
        }
        if Instant::now() >= self.deadline {
            bail!("precheck deadline exceeded");
        }
        tokio::select! {
            _ = self.cancel.cancelled() => bail!("precheck canceled"),
            result = tokio::time::timeout_at(self.deadline.min(Instant::now()+timeout),future) => result.map_err(|_|anyhow::anyhow!("precheck deadline exceeded"))?,
        }
    }
    async fn retry<T, F: Future<Output = Result<T>>>(
        &self,
        timeout: Duration,
        mut call: impl FnMut() -> F,
    ) -> Result<T> {
        for attempt in 0..=2 {
            let result = self.bounded(timeout, call()).await;
            if result.is_ok()
                || attempt == 2
                || self.cancel.is_cancelled()
                || Instant::now() >= self.deadline
            {
                return result;
            }
            tokio::select! {
                _ = self.cancel.cancelled() => return result,
                _ = tokio::time::sleep_until(self.deadline.min(Instant::now()+Duration::from_secs(1<<attempt))) => {},
            }
        }
        unreachable!()
    }
}
struct Target {
    dns: CheckResult,
    addresses: Vec<ProbeAddress>,
}
fn labels(region: &str) -> [String; 2] {
    let prefix = match region {
        "us" => "us-",
        "fed" => "fed-",
        _ => "",
    };
    [
        format!("{prefix}region1.v2.argotunnel.com"),
        format!("{prefix}region2.v2.argotunnel.com"),
    ]
}
async fn resolve(config: &Config, dialers: &impl Dialers, budget: &Budget) -> Vec<Target> {
    if !config.edges.is_empty() {
        let mut targets = Vec::new();
        for address in &config.edges {
            let result = budget
                .bounded(config.timeout, dialers.lookup_host(address))
                .await;
            let addresses = result.unwrap_or_default();
            let passed = !addresses.is_empty();
            targets.push(Target {
                dns: CheckResult::new(
                    Kind::Dns,
                    address,
                    if passed { Status::Pass } else { Status::Fail },
                    Kind::Dns.detail(passed),
                ),
                addresses,
            });
        }
        return targets;
    }
    let target_labels = labels(&config.region);
    let last = std::cell::RefCell::new(None);
    let result = budget
        .retry(config.timeout, || async {
            let targets = match dialers.resolve(&config.region).await {
                Ok(groups) if !groups.is_empty() => groups
                    .into_iter()
                    .zip(&target_labels)
                    .map(|(addresses, label)| {
                        let passed = !addresses.is_empty();
                        Target {
                            dns: CheckResult::new(
                                Kind::Dns,
                                label,
                                if passed { Status::Pass } else { Status::Fail },
                                Kind::Dns.detail(passed),
                            ),
                            addresses: addresses.into_iter().map(ProbeAddress::from).collect(),
                        }
                    })
                    .collect::<Vec<_>>(),
                result => {
                    let detail = result
                        .err()
                        .map(|e| e.to_string())
                        .unwrap_or_else(|| "No addresses returned".into());
                    target_labels
                        .iter()
                        .map(|label| Target {
                            dns: CheckResult::new(Kind::Dns, label, Status::Fail, &detail),
                            addresses: vec![],
                        })
                        .collect()
                }
            };
            let passed = !targets.is_empty()
                && targets
                    .iter()
                    .all(|target| target.dns.probe_status == Status::Pass);
            *last.borrow_mut() = Some(targets);
            if passed {
                Ok(())
            } else {
                bail!("DNS resolution failed")
            }
        })
        .await;
    last.into_inner().unwrap_or_else(|| {
        target_labels
            .iter()
            .map(|label| Target {
                dns: CheckResult::new(
                    Kind::Dns,
                    label,
                    Status::Fail,
                    &result
                        .as_ref()
                        .err()
                        .map(ToString::to_string)
                        .unwrap_or_default(),
                ),
                addresses: vec![],
            })
            .collect()
    })
}
fn addresses(target: &Target, family: &str) -> Vec<ProbeAddress> {
    let mut selected = Vec::new();
    for ipv4 in [true, false] {
        if (ipv4 && family == "6") || (!ipv4 && family == "4") {
            continue;
        }
        let group = target
            .addresses
            .iter()
            .copied()
            .filter(|address| address.udp.ip().to_canonical().is_ipv4() == ipv4)
            .collect::<Vec<_>>();
        if !group.is_empty() {
            selected.push(group[discovery::random_below(group.len() as u64).unwrap_or(0) as usize]);
        }
    }
    selected
}
async fn transport_results(
    kind: Kind,
    targets: &[Target],
    config: &Config,
    tls: &Result<EdgeTls>,
    dialers: &impl Dialers,
    budget: &Budget,
) -> Vec<CheckResult> {
    let dns_ok = targets.iter().any(|target| !target.addresses.is_empty());
    let mut results = Vec::new();
    for target in targets {
        if !dns_ok {
            results.push(CheckResult::new(
                kind,
                &target.dns.target,
                Status::Skip,
                "DNS prerequisite failed",
            ));
            continue;
        }
        let Ok(tls) = tls else {
            results.push(CheckResult::new(
                kind,
                &target.dns.target,
                Status::Fail,
                &format!("TLS configuration failed: {}", tls.as_ref().err().unwrap()),
            ));
            continue;
        };
        let addresses = addresses(target, &config.ip_version);
        if addresses.is_empty() {
            results.push(CheckResult::new(
                kind,
                &target.dns.target,
                Status::Skip,
                "No suitable address found for configured IP version",
            ));
            continue;
        }
        let mut passed = false;
        for address in addresses {
            let address = if kind == Kind::Quic {
                address.udp
            } else {
                address.tcp
            };
            passed |= budget
                .retry(Duration::from_secs(5), || {
                    dialers.connect(kind, address, tls)
                })
                .await
                .is_ok();
        }
        results.push(CheckResult::new(
            kind,
            &target.dns.target,
            if passed { Status::Pass } else { Status::Fail },
            kind.detail(passed),
        ));
    }
    results
}
fn suggested(quic: &[CheckResult], h2: &[CheckResult], protocol: Protocol) -> Option<u8> {
    let worst = |results: &[CheckResult]| {
        results
            .iter()
            .map(|r| r.probe_status)
            .max_by_key(|s| s.severity())
    };
    if protocol == Protocol::Quic && !quic.is_empty() && worst(quic) != Some(Status::Fail) {
        return Some(1);
    }
    if protocol == Protocol::Http2 && !h2.is_empty() && worst(h2) != Some(Status::Fail) {
        return Some(0);
    }
    if worst(quic) == Some(Status::Pass) {
        Some(1)
    } else if worst(h2) == Some(Status::Pass) {
        Some(0)
    } else {
        None
    }
}
async fn run(config: &Config, dialers: &impl Dialers, cancel: CancellationToken) -> Report {
    let budget = Budget {
        deadline: Instant::now() + config.timeout,
        cancel,
    };
    let ca = match &config.ca {
        Some(path) => budget
            .bounded(config.timeout, async { Ok(tokio::fs::read(path).await?) })
            .await
            .map(Some),
        None => Ok(None),
    };
    let tls = ca.and_then(|ca| {
        EdgeTls::new(
            if config.strict_pq {
                TlsPolicy::RequirePostQuantum
            } else {
                TlsPolicy::PreferPostQuantum
            },
            ca.as_deref(),
        )
    });
    let targets = resolve(config, dialers, &budget).await;
    let management = async {
        let passed = budget
            .retry(Duration::from_secs(5), || dialers.management())
            .await
            .is_ok();
        CheckResult::new(
            Kind::Management,
            "api.cloudflare.com:443",
            if passed { Status::Pass } else { Status::Fail },
            Kind::Management.detail(passed),
        )
    };
    let (quic, h2, management) = tokio::join!(
        transport_results(Kind::Quic, &targets, config, &tls, dialers, &budget),
        transport_results(Kind::Http2, &targets, config, &tls, dialers, &budget),
        management
    );
    let protocol = suggested(&quic, &h2, config.protocol);
    let mut results = targets
        .into_iter()
        .map(|target| target.dns)
        .collect::<Vec<_>>();
    results.extend(quic);
    results.extend(h2);
    results.push(management);
    Report {
        run_id: uuid::Uuid::new_v4(),
        results,
        suggested_protocol: protocol,
    }
}
pub(crate) async fn startup(config: &RunConfig, context: &Arc<Context>, cancel: CancellationToken) {
    run(&Config::startup(config), &Native::default(), cancel)
        .await
        .log(context);
}
pub(crate) async fn collect(region: &str, cancel: CancellationToken) -> Report {
    run(&Config::diagnostic(region), &Native::default(), cancel).await
}

pub(super) fn spawn_if_enabled(
    config: &RunConfig,
    snapshot: &super::features::FeatureSnapshot,
    work: impl Future<Output = ()> + 'static,
) -> Option<super::AbortTask<()>> {
    if config.no_prechecks || snapshot.skip_prechecks {
        None
    } else {
        Some(super::AbortTask(tokio::task::spawn_local(work)))
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
pub(crate) use tests::fixture_report;
