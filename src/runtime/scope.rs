use super::features::FeatureSnapshot;
use crate::config::RunConfig;
use std::{net::SocketAddr, sync::Arc};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

struct Identity {
    account_tag: String,
    tunnel_id: Uuid,
    index: u8,
    generation: Uuid,
    transport: &'static str,
    peer: SocketAddr,
    features: FeatureSnapshot,
}
pub(crate) struct PendingSessionContext {
    identity: Arc<Identity>,
    cancel: CancellationToken,
    management_hostname: String,
}
#[derive(Clone)]
pub(super) struct RequestContext {
    identity: Arc<Identity>,
    cancel: CancellationToken,
    management_hostname: String,
}
impl Drop for PendingSessionContext {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
impl PendingSessionContext {
    pub(super) fn new(
        config: &RunConfig,
        index: u8,
        transport: &'static str,
        peer: SocketAddr,
        features: FeatureSnapshot,
        management_hostname: String,
    ) -> Self {
        Self {
            identity: Arc::new(Identity {
                account_tag: config.credentials.account_tag.clone(),
                tunnel_id: config.credentials.tunnel_id,
                index,
                generation: Uuid::new_v4(),
                transport,
                peer,
                features,
            }),
            cancel: CancellationToken::new(),
            management_hostname,
        }
    }
    pub(crate) fn cancellation(&self) -> CancellationToken {
        self.cancel.clone()
    }
    pub(crate) fn index(&self) -> u8 {
        self.identity.index
    }
    pub(crate) fn generation(&self) -> Uuid {
        self.identity.generation
    }
    pub(crate) fn snapshot(&self) -> &FeatureSnapshot {
        &self.identity.features
    }
    pub(super) fn requests(&self) -> RequestContext {
        RequestContext {
            identity: self.identity.clone(),
            cancel: self.cancel.clone(),
            management_hostname: self.management_hostname.clone(),
        }
    }
}
impl RequestContext {
    pub(super) fn management_request(&self, authority: &str) -> Option<EdgeManagementRequest> {
        let hostname = authority.split(':').next().unwrap_or(authority);
        if !hostname.eq_ignore_ascii_case(&self.management_hostname) {
            return None;
        }
        Some(EdgeManagementRequest {
            identity: self.identity.clone(),
            cancel: self.cancel.clone(),
        })
    }
    pub(super) fn cancellation(&self) -> CancellationToken {
        self.cancel.clone()
    }
}
pub(crate) struct EdgeManagementRequest {
    identity: Arc<Identity>,
    cancel: CancellationToken,
}
impl EdgeManagementRequest {
    pub(crate) fn is_live(&self) -> bool {
        !self.cancel.is_cancelled()
    }
    pub(crate) fn tunnel_id(&self) -> Uuid {
        self.identity.tunnel_id
    }
    pub(crate) fn account_tag(&self) -> &str {
        &self.identity.account_tag
    }
    pub(crate) fn transport(&self) -> &str {
        self.identity.transport
    }
    pub(crate) fn peer(&self) -> SocketAddr {
        self.identity.peer
    }
    pub(crate) fn connection_index(&self) -> u8 {
        self.identity.index
    }
    pub(crate) fn cancellation(&self) -> CancellationToken {
        self.cancel.clone()
    }
}

#[cfg(test)]
pub(crate) fn fixture_scope(
    config: &RunConfig,
    index: u8,
    version: crate::network::DatagramVersion,
) -> PendingSessionContext {
    PendingSessionContext::new(
        config,
        index,
        "quic",
        "127.0.0.1:7844".parse().unwrap(),
        FeatureSnapshot {
            version,
            features: vec![],
            skip_prechecks: true,
        },
        config.management_hostname.clone(),
    )
}

#[cfg(test)]
pub(crate) fn fixture_receipt(tunnel_id: Uuid, account_tag: &str) -> EdgeManagementRequest {
    EdgeManagementRequest {
        identity: Arc::new(Identity {
            account_tag: account_tag.into(),
            tunnel_id,
            index: 0,
            generation: Uuid::new_v4(),
            transport: "quic",
            peer: "127.0.0.1:7844".parse().unwrap(),
            features: FeatureSnapshot {
                version: crate::network::DatagramVersion::V2,
                features: vec![],
                skip_prechecks: false,
            },
        }),
        cancel: CancellationToken::new(),
    }
}
