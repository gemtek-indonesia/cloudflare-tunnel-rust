pub mod bundle;
pub mod diagnostics;
mod log_collection;
pub mod logging;
pub(crate) mod management;
pub mod metrics;
mod network_diagnostic;
pub mod tail;

use anyhow::Result;
use std::sync::Arc;

pub struct Context {
    pub logger: Arc<logging::Logger>,
    pub metrics: Arc<metrics::Metrics>,
}
impl Context {
    pub fn new(options: logging::Options, secrets: Vec<String>) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            logger: logging::Logger::new(options, secrets)?,
            metrics: metrics::Metrics::new()?,
        }))
    }
    pub fn quiet() -> Result<Arc<Self>> {
        Self::new(
            logging::Options {
                disable_terminal: true,
                ..Default::default()
            },
            vec![],
        )
    }
}
