use super::AsyncScheduler;
use crate::{async_auto_fix, async_run};
use tokio::task::JoinSet;

/// The asynchronous scheduler
///
/// The asynchronous scheduler will run each check asynchronously.
///
/// This will use a join set to store all of the async handles.
#[derive(Debug, Clone, Copy, Default)]
pub struct AsyncTokioScheduler;

impl AsyncTokioScheduler {
    /// Create a new asynchronous scheduler.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl AsyncScheduler for AsyncTokioScheduler {
    /// Run the checks and return the checks and their results.
    async fn async_run<
        Item: crate::Item + Send + Sync + 'static,
        Items: std::iter::IntoIterator<Item = Item> + Send + Sync + 'static,
    >(
        &self,
        checks: Vec<Box<dyn crate::AsyncCheck<Item = Item, Items = Items> + Send + Sync>>,
    ) -> Vec<(
        Box<dyn crate::AsyncCheck<Item = Item, Items = Items> + Send + Sync>,
        crate::CheckResult<Item, Items>,
    )> {
        let mut set = JoinSet::new();
        let mut results = Vec::with_capacity(checks.len());

        for check in checks {
            set.spawn(async move {
                let result = async_run(check.as_ref()).await;

                (check, result)
            });
        }

        while let Some(result) = set.join_next().await {
            let result = result.expect("Task failed to complete.");
            results.push(result);
        }

        results
    }

    /// Run the auto fix for the checks and return the results.
    async fn async_auto_fix<
        Item: crate::Item + Send + Sync + 'static,
        Items: std::iter::IntoIterator<Item = Item> + Send + Sync + 'static,
    >(
        &self,
        checks: Vec<Box<dyn crate::AsyncCheck<Item = Item, Items = Items> + Send + Sync>>,
    ) -> Vec<(
        Box<dyn crate::AsyncCheck<Item = Item, Items = Items> + Send + Sync>,
        crate::CheckResult<Item, Items>,
    )> {
        let mut set = JoinSet::new();
        let mut results = Vec::with_capacity(checks.len());

        for mut check in checks {
            set.spawn(async move {
                let result = async_auto_fix(check.as_mut()).await;

                (check, result)
            });
        }

        while let Some(result) = set.join_next().await {
            let result = result.expect("Task failed to complete.");
            results.push(result);
        }

        results
    }
}
