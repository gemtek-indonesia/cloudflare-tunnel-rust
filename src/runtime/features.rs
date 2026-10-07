use crate::network::DatagramVersion;
use serde::Deserialize;
use std::{sync::RwLock, time::Duration};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug)]
pub(crate) struct FeatureSnapshot {
    pub version: DatagramVersion,
    pub features: Vec<String>,
    pub skip_prechecks: bool,
}
#[derive(Clone, Copy, Default, Deserialize)]
struct Record {
    #[serde(default, rename = "dv3_2")]
    percentage: u32,
    #[serde(default)]
    skip_prechecks: bool,
}
pub(crate) struct FeatureSelector {
    threshold: u32,
    cli: Vec<String>,
    strict_pq: bool,
    record: RwLock<Record>,
}
impl FeatureSelector {
    pub(crate) fn new(account: &str, cli: Vec<String>, strict_pq: bool) -> Self {
        Self {
            threshold: account.as_bytes().iter().fold(2166136261u32, |hash, b| {
                (hash ^ u32::from(*b)).wrapping_mul(16777619)
            }) % 100,
            cli,
            strict_pq,
            record: RwLock::new(Record::default()),
        }
    }
    pub(crate) fn snapshot(&self, management: bool) -> FeatureSnapshot {
        let record = *self.record.read().unwrap();
        let version = if self.cli.iter().any(|s| s == "support_datagram_v3_2") {
            DatagramVersion::V3
        } else if self.cli.iter().any(|s| s == "support_datagram_v2") {
            DatagramVersion::V2
        } else if record.percentage > self.threshold {
            DatagramVersion::V3
        } else {
            DatagramVersion::V2
        };
        let mut features = vec![
            "allow_remote_config".into(),
            "serialized_headers".into(),
            "support_datagram_v2".into(),
            "support_quic_eof".into(),
        ];
        features.extend(
            self.cli
                .iter()
                .filter(|s| {
                    !matches!(
                        s.as_str(),
                        "support_datagram_v3" | "support_datagram_v3_1" | "management_logs"
                    )
                })
                .cloned(),
        );
        if version == DatagramVersion::V3 {
            features.push("support_datagram_v3_2".into());
        }
        if self.strict_pq {
            features.push("postquantum".into());
        }
        if management {
            features.push("management_logs".into());
        }
        features.sort();
        features.dedup();
        FeatureSnapshot {
            version,
            features,
            skip_prechecks: record.skip_prechecks,
        }
    }
    pub(crate) async fn refresh(&self) -> anyhow::Result<()> {
        use hickory_resolver::proto::rr::RData;
        let resolver = hickory_resolver::Resolver::builder_tokio()?.build()?;
        let lookup = tokio::time::timeout(
            Duration::from_secs(10),
            resolver.txt_lookup("cfd-features.argotunnel.com."),
        )
        .await??;
        let bytes = lookup
            .answers()
            .iter()
            .find_map(|record| match &record.data {
                RData::TXT(txt) => Some(
                    txt.txt_data
                        .iter()
                        .flat_map(|part| part.iter().copied())
                        .collect::<Vec<_>>(),
                ),
                _ => None,
            })
            .ok_or_else(|| anyhow::anyhow!("no feature TXT record"))?;
        let record = serde_json::from_slice(&bytes)?;
        *self.record.write().unwrap() = record;
        Ok(())
    }
    pub(crate) async fn refresh_loop(&self, cancel: CancellationToken) {
        loop {
            tokio::select! {_=cancel.cancelled()=>return,_=tokio::time::sleep(Duration::from_secs(3600))=>{}}
            let result =
                tokio::select! {_=cancel.cancelled()=>return,result=self.refresh()=>result};
            if let Err(error) = result {
                eprintln!("Failed to refresh feature selector: {error}");
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_fnv_rollout_cli_precedence_and_frozen_connection_snapshot() {
        let selector = FeatureSelector::new("synthetic-account", vec![], false);
        let original = selector.snapshot(false);
        assert_eq!(original.version, DatagramVersion::V2);
        *selector.record.write().unwrap() = Record {
            percentage: 100,
            skip_prechecks: true,
        };
        assert_eq!(selector.snapshot(false).version, DatagramVersion::V3);
        assert!(selector.snapshot(false).skip_prechecks);
        assert_eq!(original.version, DatagramVersion::V2);
        let selector = FeatureSelector::new(
            "synthetic-account",
            vec![
                "support_datagram_v2".into(),
                "support_datagram_v3_2".into(),
                "support_datagram_v3".into(),
            ],
            true,
        );
        let selected = selector.snapshot(false);
        assert_eq!(selected.version, DatagramVersion::V3);
        assert!(selected.features.iter().any(|s| s == "postquantum"));
        assert!(!selected.features.iter().any(|s| s == "support_datagram_v3"));
        assert!(!selected.features.iter().any(|s| s == "management_logs"));
    }
}
