pub mod h2;
pub mod quic;

#[derive(Clone, Debug)]
pub struct EdgeDialOptions {
    pub bind_ip: Option<std::net::IpAddr>,
    pub dial_timeout: std::time::Duration,
    pub quic_disable_pmtu_discovery: bool,
    pub connection_window: u64,
    pub stream_window: u64,
}
impl Default for EdgeDialOptions {
    fn default() -> Self {
        Self {
            bind_ip: None,
            dial_timeout: std::time::Duration::from_secs(15),
            quic_disable_pmtu_discovery: false,
            connection_window: 30 * 1024 * 1024,
            stream_window: 6 * 1024 * 1024,
        }
    }
}
