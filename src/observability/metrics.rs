use anyhow::Result;
use prometheus::{
    Encoder, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    IntGaugeVec, Opts, Registry, TextEncoder,
};
use std::{sync::Arc, time::Instant};

pub struct Metrics {
    pub registry: Registry,
    pub ha_connections: IntGauge,
    pub config_version: IntGauge,
    pub register_success: IntCounterVec,
    pub register_fail: IntCounterVec,
    pub server_locations: IntGaugeVec,
    pub local_config_pushes: IntCounter,
    pub local_config_pushes_errors: IntCounter,
    pub user_hostnames: IntCounterVec,
    pub tcp_active: IntGauge,
    pub tcp_total: IntCounter,
    pub udp_active_sessions: IntGauge,
    pub udp_total_sessions: IntCounter,
    pub packet_too_big_dropped: IntCounter,
    pub udp_active_flows: IntGaugeVec,
    pub udp_total_flows: IntCounterVec,
    pub udp_failed_flows: IntCounterVec,
    pub udp_retry_flow_responses: IntCounterVec,
    pub udp_migrated_flows: IntCounterVec,
    pub udp_unsupported_remote_commands: IntCounterVec,
    pub udp_dropped_datagrams: IntCounterVec,
    pub connect_latency: Histogram,
    pub connect_errors: IntCounter,
    pub rpc_client_operations: IntCounterVec,
    pub rpc_client_failures: IntCounterVec,
    pub rpc_client_latency: HistogramVec,
    pub rpc_server_operations: IntCounterVec,
    pub rpc_server_failures: IntCounterVec,
    pub rpc_server_latency: HistogramVec,
    requests: IntCounter,
    concurrent: IntGauge,
    responses: IntCounterVec,
    errors: IntCounter,
}
impl Metrics {
    pub fn new() -> Result<Arc<Self>> {
        let registry = Registry::new();
        macro_rules! counter {
            ($name:literal,$help:literal) => {{
                let value = IntCounter::new($name, $help)?;
                registry.register(Box::new(value.clone()))?;
                value
            }};
        }
        macro_rules! gauge {
            ($name:literal,$help:literal) => {{
                let value = IntGauge::new($name, $help)?;
                registry.register(Box::new(value.clone()))?;
                value
            }};
        }
        macro_rules! counters {
            ($name:literal,$help:literal,$labels:expr) => {{
                let value = IntCounterVec::new(Opts::new($name, $help), $labels)?;
                registry.register(Box::new(value.clone()))?;
                value
            }};
        }
        let requests = counter!(
            "cloudflared_tunnel_total_requests",
            "Amount of requests proxied through all the tunnels"
        );
        let concurrent = gauge!(
            "cloudflared_tunnel_concurrent_requests_per_tunnel",
            "Concurrent requests proxied through each tunnel"
        );
        let responses = counters!(
            "cloudflared_tunnel_response_by_code",
            "Count of responses by HTTP status code",
            &["status_code"]
        );
        let errors = counter!(
            "cloudflared_tunnel_request_errors",
            "Count of error proxying to origin"
        );
        let ha_connections = gauge!(
            "cloudflared_tunnel_ha_connections",
            "Number of active ha connections"
        );
        let config_version = gauge!(
            "cloudflared_orchestration_config_version",
            "Configuration version"
        );
        let register_success = counters!(
            "cloudflared_tunnel_tunnel_register_success",
            "Count of successful tunnel registrations",
            &["rpcName"]
        );
        let register_fail = counters!(
            "cloudflared_tunnel_tunnel_register_fail",
            "Count of tunnel registration errors by type",
            &["error", "rpcName"]
        );
        let server_locations = IntGaugeVec::new(
            Opts::new(
                "cloudflared_tunnel_server_locations",
                "Where each tunnel is connected to. 1 means current location, 0 means previous locations.",
            ),
            &["connection_id", "edge_location"],
        )?;
        registry.register(Box::new(server_locations.clone()))?;
        let local_config_pushes = counter!(
            "cloudflared_config_local_config_pushes",
            "Number of local configuration pushes to the edge"
        );
        let local_config_pushes_errors = counter!(
            "cloudflared_config_local_config_pushes_errors",
            "Number of errors occurred during local configuration pushes"
        );
        let user_hostnames = counters!(
            "cloudflared_tunnel_user_hostnames_counts",
            "Which user hostnames cloudflared is serving",
            &["userHostname"]
        );
        let tcp_active = gauge!(
            "cloudflared_tcp_active_sessions",
            "Concurrent count of TCP sessions that are being proxied to any origin"
        );
        let tcp_total = counter!(
            "cloudflared_tcp_total_sessions",
            "Total count of TCP sessions that have been proxied to any origin"
        );
        let connect_latency = Histogram::with_opts(
            HistogramOpts::new(
                "cloudflared_proxy_connect_latency",
                "Time it takes to establish and acknowledge connections in milliseconds",
            )
            .buckets(vec![1., 10., 25., 50., 100., 500., 1000., 5000.]),
        )?;
        registry.register(Box::new(connect_latency.clone()))?;
        let connect_errors = counter!(
            "cloudflared_proxy_connect_streams_errors",
            "Total count of failure to establish and acknowledge connections"
        );
        let rpc_client_operations = counters!(
            "cloudflared_rpc_client_operations",
            "Number of rpc methods by handler requested",
            &["handler", "method"]
        );
        let rpc_client_failures = counters!(
            "cloudflared_rpc_client_failures",
            "Number of rpc method failures by handler requested",
            &["handler", "method"]
        );
        let rpc_server_operations = counters!(
            "cloudflared_rpc_server_operations",
            "Number of rpc methods by handler served",
            &["handler", "method"]
        );
        let rpc_server_failures = counters!(
            "cloudflared_rpc_server_failures",
            "Number of rpc methods failures by handler served",
            &["handler", "method"]
        );
        let buckets = vec![0.05, 0.15, 0.45, 1.35, 4.05];
        let rpc_client_latency = HistogramVec::new(
            HistogramOpts::new(
                "cloudflared_rpc_client_latency_secs",
                "Latency of rpc methods by handler requested",
            )
            .buckets(buckets.clone()),
            &["handler", "method"],
        )?;
        registry.register(Box::new(rpc_client_latency.clone()))?;
        let rpc_server_latency = HistogramVec::new(
            HistogramOpts::new(
                "cloudflared_rpc_server_latency_secs",
                "Latency of rpc methods by handler served",
            )
            .buckets(buckets),
            &["handler", "method"],
        )?;
        registry.register(Box::new(rpc_server_latency.clone()))?;
        let build = IntGaugeVec::new(
            Opts::new("build_info", "Build and version information"),
            &["type", "revision", "version"],
        )?;
        registry.register(Box::new(build.clone()))?;
        build
            .with_label_values(&[
                "Rust",
                option_env!("CLOUDFLARED_BUILD_REVISION").unwrap_or("unknown"),
                env!("CARGO_PKG_VERSION"),
            ])
            .set(1);
        registry.register(Box::new(
            prometheus::process_collector::ProcessCollector::for_self(),
        ))?;
        let udp_active_sessions = gauge!(
            "cloudflared_udp_active_sessions",
            "Concurrent count of UDP sessions that are being proxied to any origin"
        );
        let udp_total_sessions = counter!(
            "cloudflared_udp_total_sessions",
            "Total count of UDP sessions that have been proxied to any origin"
        );
        let packet_too_big_dropped = counter!(
            "quic_client_packet_too_big_dropped",
            "Count of packets received from origin that are too big to send to the edge and are dropped as a result"
        );
        let udp_active_flows = IntGaugeVec::new(
            Opts::new(
                "cloudflared_udp_active_flows",
                "Concurrent count of UDP flows that are being proxied to any origin",
            ),
            &["conn_index"],
        )?;
        registry.register(Box::new(udp_active_flows.clone()))?;
        let udp_total_flows = counters!(
            "cloudflared_udp_total_flows",
            "Total count of UDP flows that have been proxied to any origin",
            &["conn_index"]
        );
        let udp_failed_flows = counters!(
            "cloudflared_udp_failed_flows",
            "Total count of flows that errored and closed",
            &["conn_index"]
        );
        let udp_retry_flow_responses = counters!(
            "cloudflared_udp_retry_flow_responses",
            "Total count of UDP flows that have had to send their registration response more than once",
            &["conn_index"]
        );
        let udp_migrated_flows = counters!(
            "cloudflared_udp_migrated_flows",
            "Total count of UDP flows have been migrated across local connections",
            &["conn_index"]
        );
        let udp_unsupported_remote_commands = counters!(
            "cloudflared_udp_unsupported_remote_command_total",
            "Total count of unsupported remote RPC commands called",
            &["conn_index", "command"]
        );
        let udp_dropped_datagrams = counters!(
            "cloudflared_udp_dropped_datagrams",
            "Total count of UDP dropped datagrams",
            &["conn_index", "reason"]
        );
        Ok(Arc::new(Self {
            registry,
            ha_connections,
            config_version,
            register_success,
            register_fail,
            server_locations,
            local_config_pushes,
            local_config_pushes_errors,
            user_hostnames,
            tcp_active,
            tcp_total,
            udp_active_sessions,
            udp_total_sessions,
            packet_too_big_dropped,
            udp_active_flows,
            udp_total_flows,
            udp_failed_flows,
            udp_retry_flow_responses,
            udp_migrated_flows,
            udp_unsupported_remote_commands,
            udp_dropped_datagrams,
            connect_latency,
            connect_errors,
            rpc_client_operations,
            rpc_client_failures,
            rpc_client_latency,
            rpc_server_operations,
            rpc_server_failures,
            rpc_server_latency,
            requests,
            concurrent,
            responses,
            errors,
        }))
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        TextEncoder::new().encode(&self.registry.gather(), &mut bytes)?;
        Ok(bytes)
    }
    pub fn begin_request(self: &Arc<Self>, tcp: bool) -> RequestGuard {
        self.requests.inc();
        self.concurrent.inc();
        if tcp {
            self.tcp_active.inc();
            self.tcp_total.inc();
        }
        RequestGuard {
            metrics: self.clone(),
            tcp,
            error: false,
        }
    }
    pub fn response(&self, status: u16) {
        self.responses
            .with_label_values(&[&status.to_string()])
            .inc();
    }
    pub fn begin_tcp(self: &Arc<Self>) -> TcpGuard {
        self.tcp_active.inc();
        self.tcp_total.inc();
        TcpGuard(self.clone())
    }
    pub fn rpc_client(self: &Arc<Self>, handler: &str, method: &str) -> RpcGuard {
        RpcGuard {
            metrics: self.clone(),
            handler: handler.into(),
            method: method.into(),
            started: Instant::now(),
            server: false,
            failed: false,
        }
    }
    pub fn rpc_server(self: &Arc<Self>, handler: &str, method: &str) -> RpcGuard {
        RpcGuard {
            metrics: self.clone(),
            handler: handler.into(),
            method: method.into(),
            started: Instant::now(),
            server: true,
            failed: false,
        }
    }
}
pub struct TcpGuard(Arc<Metrics>);
impl Drop for TcpGuard {
    fn drop(&mut self) {
        self.0.tcp_active.dec();
    }
}
pub struct RequestGuard {
    metrics: Arc<Metrics>,
    tcp: bool,
    error: bool,
}
impl RequestGuard {
    pub fn failed(&mut self) {
        if !self.error {
            self.metrics.errors.inc();
            self.error = true;
        }
    }
}
impl Drop for RequestGuard {
    fn drop(&mut self) {
        self.metrics.concurrent.dec();
        if self.tcp {
            self.metrics.tcp_active.dec();
        }
    }
}
pub struct RpcGuard {
    metrics: Arc<Metrics>,
    handler: String,
    method: String,
    started: Instant,
    server: bool,
    failed: bool,
}
impl RpcGuard {
    pub fn failed(&mut self) {
        self.failed = true;
    }
}
impl Drop for RpcGuard {
    fn drop(&mut self) {
        let m = &self.metrics;
        let labels = [self.handler.as_str(), self.method.as_str()];
        let (operations, failures, latency) = if self.server {
            (
                &m.rpc_server_operations,
                &m.rpc_server_failures,
                &m.rpc_server_latency,
            )
        } else {
            (
                &m.rpc_client_operations,
                &m.rpc_client_failures,
                &m.rpc_client_latency,
            )
        };
        operations.with_label_values(&labels).inc();
        latency
            .with_label_values(&labels)
            .observe(self.started.elapsed().as_secs_f64());
        if self.failed {
            failures.with_label_values(&labels).inc();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registry_is_owned_and_lifetimes_update_consumed_metrics() {
        let m = Metrics::new().unwrap();
        let other = Metrics::new().unwrap();
        {
            let mut req = m.begin_request(false);
            m.response(200);
            req.failed();
        }
        let text = String::from_utf8(m.encode().unwrap()).unwrap();
        assert!(text.contains("cloudflared_tunnel_total_requests 1"));
        assert!(text.contains("cloudflared_tunnel_concurrent_requests_per_tunnel 0"));
        assert!(text.contains("cloudflared_tunnel_response_by_code{status_code=\"200\"} 1"));
        assert!(!text.contains("go_goroutines"));
        assert!(!text.contains("goversion"));
        assert!(
            String::from_utf8(other.encode().unwrap())
                .unwrap()
                .contains("cloudflared_tunnel_total_requests 0")
        );
    }
}
