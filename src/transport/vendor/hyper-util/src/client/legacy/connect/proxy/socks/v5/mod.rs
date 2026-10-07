mod errors;
pub use errors::*;

pub(super) mod messages;
use messages::*;

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::task::{Context, Poll};

use http::Uri;
use hyper::rt::{Read, Write};
use tower_service::Service;

use bytes::BytesMut;

use super::{Handshaking, SocksError};

/// Tunnel Proxy via SOCKSv5
///
/// This is a connector that can be used by the `legacy::Client`. It wraps
/// another connector, and after getting an underlying connection, it establishes
/// a TCP tunnel over it using SOCKSv5.
#[derive(Clone)]
pub struct SocksV5<C> {
    inner: C,
    config: SocksConfig,
}

#[derive(Clone)]
pub struct SocksConfig {
    proxy: Uri,
    proxy_auth: Option<Credentials>,

    allow_no_auth: bool,

    local_dns: bool,
    optimistic: bool,
}

#[derive(Clone)]
struct Credentials {
    user: Vec<u8>,
    password: Vec<u8>,
    allow_empty_user: bool,
}
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials").finish_non_exhaustive()
    }
}
impl std::fmt::Debug for SocksConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocksConfig")
            .field("proxy_auth", &self.proxy_auth)
            .field("allow_no_auth", &self.allow_no_auth)
            .field("local_dns", &self.local_dns)
            .field("optimistic", &self.optimistic)
            .finish_non_exhaustive()
    }
}
impl<C> std::fmt::Debug for SocksV5<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocksV5")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
enum State {
    SendingNegReq,
    ReadingNegRes,
    SendingAuthReq,
    ReadingAuthRes,
    SendingProxyReq,
    ReadingProxyRes,
}

impl<C> SocksV5<C> {
    /// Create a new SOCKSv5 handshake service.
    ///
    /// Wraps an underlying connector and stores the address of a tunneling
    /// proxying server.
    ///
    /// A `SocksV5` can then be called with any destination. The `dst` passed to
    /// `call` will not be used to create the underlying connection, but will
    /// be used in a SOCKS handshake with the proxy destination.
    pub fn new(proxy_dst: Uri, connector: C) -> Self {
        Self {
            inner: connector,
            config: SocksConfig::new(proxy_dst),
        }
    }

    /// Use User/Pass authentication method during handshake.
    ///
    /// Username and Password must be maximum of 255 characters each.
    /// 0 length strings are allowed despite RFC prohibiting it. This is done for
    /// compatibility with server implementations that use empty credentials
    /// to allow returning error codes during IP authentication.
    pub fn with_auth(mut self, user: String, pass: String) -> Self {
        self.config.proxy_auth = Some(Credentials {
            user: user.into_bytes(),
            password: pass.into_bytes(),
            allow_empty_user: true,
        });
        self
    }

    /// Use raw username/password bytes. An empty username is rejected only if password authentication is selected.
    pub fn with_auth_bytes(mut self, user: Vec<u8>, pass: Vec<u8>) -> Self {
        self.config.proxy_auth = Some(Credentials {
            user,
            password: pass,
            allow_empty_user: false,
        });
        self
    }

    /// Explicitly offer no authentication before password authentication. Existing password-only policy is unchanged by default.
    /// Optimistic password transmission is disabled when both methods are offered.
    pub fn allow_no_auth(mut self) -> Self {
        self.config.allow_no_auth = true;
        self
    }

    /// Resolve domain names locally on the client, rather than on the proxy server.
    ///
    /// Disabled by default as local resolution of domain names can be detected as a
    /// DNS leak.
    pub fn local_dns(mut self, local_dns: bool) -> Self {
        self.config.local_dns = local_dns;
        self
    }

    /// Send all messages of the handshake optmistically (without waiting for server response).
    ///
    /// A typical SOCKS handshake with user/pass authentication takes 3 round trips Optimistic sending
    /// can reduce round trip times and dramatically increase speed of handshake at the cost of
    /// reduced portability; many server implementations do not support optimistic sending as it
    /// is not defined in the RFC.
    ///
    /// Recommended to ensure connector works correctly without optimistic sending before trying
    /// with optimistic sending.
    pub fn send_optimistically(mut self, optimistic: bool) -> Self {
        self.config.optimistic = optimistic;
        self
    }
}

impl SocksConfig {
    fn new(proxy: Uri) -> Self {
        Self {
            proxy,
            proxy_auth: None,
            allow_no_auth: false,

            local_dns: false,
            optimistic: false,
        }
    }

    async fn execute<T, E>(self, mut conn: T, host: String, port: u16) -> Result<T, SocksError<E>>
    where
        T: Read + Write + Unpin,
    {
        let address = match host.parse::<IpAddr>() {
            Ok(ip) => Address::Socket(SocketAddr::new(ip, port)),
            Err(_) if host.len() <= 255 => {
                if self.local_dns {
                    let socket = (host, port)
                        .to_socket_addrs()?
                        .next()
                        .ok_or(SocksError::DnsFailure)?;

                    Address::Socket(socket)
                } else {
                    Address::Domain(host, port)
                }
            }
            Err(_) => return Err(SocksV5Error::HostTooLong.into()),
        };

        let method = if self.proxy_auth.is_some() {
            AuthMethod::UserPass
        } else {
            AuthMethod::NoAuth
        };

        let optimistic = self.optimistic && !(self.allow_no_auth && self.proxy_auth.is_some());

        let mut recv_buf = BytesMut::with_capacity(513); // Max length of valid recievable message is 513 from Auth Request
        let mut send_buf = BytesMut::with_capacity(262); // Max length of valid sendable message is 262 from Auth Response
        let mut state = State::SendingNegReq;

        loop {
            match state {
                State::SendingNegReq => {
                    let req = NegotiationReq(&method, self.allow_no_auth);

                    let start = send_buf.len();
                    req.write_to_buf(&mut send_buf)?;
                    crate::rt::write_all(&mut conn, &send_buf[start..]).await?;

                    if optimistic {
                        if method == AuthMethod::UserPass {
                            state = State::SendingAuthReq;
                        } else {
                            state = State::SendingProxyReq;
                        }
                    } else {
                        state = State::ReadingNegRes;
                    }
                }

                State::ReadingNegRes => {
                    let res: NegotiationRes =
                        super::read_message_bounded(&mut conn, &mut recv_buf).await?;

                    if res.0 == AuthMethod::NoneAcceptable {
                        return Err(SocksV5Error::Auth(AuthError::Unsupported).into());
                    }

                    if res.0 != method
                        && !(self.allow_no_auth
                            && method == AuthMethod::UserPass
                            && res.0 == AuthMethod::NoAuth)
                    {
                        return Err(SocksV5Error::Auth(AuthError::MethodMismatch).into());
                    }

                    if optimistic {
                        if res.0 == AuthMethod::UserPass {
                            state = State::ReadingAuthRes;
                        } else {
                            state = State::ReadingProxyRes;
                        }
                    } else if res.0 == AuthMethod::UserPass {
                        state = State::SendingAuthReq;
                    } else {
                        state = State::SendingProxyReq;
                    }
                }

                State::SendingAuthReq => {
                    let credentials = self.proxy_auth.as_ref().unwrap();
                    if credentials.user.len() > 255
                        || credentials.password.len() > 255
                        || credentials.user.is_empty() && !credentials.allow_empty_user
                    {
                        return Err(SocksV5Error::Auth(AuthError::Failed).into());
                    }
                    send_buf.reserve(3 + credentials.user.len() + credentials.password.len());
                    let req = AuthenticationReq(&credentials.user, &credentials.password);

                    let start = send_buf.len();
                    req.write_to_buf(&mut send_buf)?;
                    crate::rt::write_all(&mut conn, &send_buf[start..]).await?;

                    if optimistic {
                        state = State::SendingProxyReq;
                    } else {
                        state = State::ReadingAuthRes;
                    }
                }

                State::ReadingAuthRes => {
                    let res: AuthenticationRes =
                        super::read_message_bounded(&mut conn, &mut recv_buf).await?;

                    if !res.0 {
                        return Err(SocksV5Error::Auth(AuthError::Failed).into());
                    }

                    if optimistic {
                        state = State::ReadingProxyRes;
                    } else {
                        state = State::SendingProxyReq;
                    }
                }

                State::SendingProxyReq => {
                    let req = ProxyReq(&address);
                    send_buf.reserve(262);

                    let start = send_buf.len();
                    req.write_to_buf(&mut send_buf)?;
                    crate::rt::write_all(&mut conn, &send_buf[start..]).await?;

                    if optimistic {
                        state = State::ReadingNegRes;
                    } else {
                        state = State::ReadingProxyRes;
                    }
                }

                State::ReadingProxyRes => {
                    let res: ProxyRes =
                        super::read_message_bounded(&mut conn, &mut recv_buf).await?;

                    if res.0 == Status::Success {
                        return Ok(conn);
                    } else {
                        return Err(SocksV5Error::Command(res.0).into());
                    }
                }
            }
        }
    }
}

impl<C> Service<Uri> for SocksV5<C>
where
    C: Service<Uri>,
    C::Future: Send + 'static,
    C::Response: Read + Write + Unpin + Send + 'static,
    C::Error: Send + 'static,
{
    type Response = C::Response;
    type Error = SocksError<C::Error>;
    type Future = Handshaking<C::Future, C::Response, C::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(SocksError::Inner)
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let config = self.config.clone();
        let connecting = self.inner.call(config.proxy.clone());

        let fut = async move {
            let port = dst.port().map(|p| p.as_u16()).unwrap_or(443);
            let host_from_uri = dst.host().ok_or(SocksError::MissingHost)?;

            // Note: host() returns the host part of the URI which could be a square bracketed IPv6
            // address. We need to remove any brackets to make it a valid IP address.
            let host = crate::client::strip_ipv6_brackets(host_from_uri).to_string();

            let conn = connecting.await.map_err(SocksError::Inner)?;
            config.execute(conn, host, port).await
        };

        Handshaking {
            fut: Box::pin(fut),
            _marker: Default::default(),
        }
    }
}
