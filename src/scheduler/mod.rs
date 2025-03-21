//! TODO

use crate::{AsyncCheck, Check, CheckResult};

mod serial_scheduler;
pub use serial_scheduler::SerialScheduler;

#[cfg(feature = "threaded-scheduler")]
mod threaded_scheduler;
#[cfg(feature = "threaded-scheduler")]
pub use threaded_scheduler::ThreadedScheduler;

#[cfg(feature = "async-tokio-scheduler")]
mod async_tokio_scheduler;
#[cfg(feature = "async-tokio-scheduler")]
pub use async_tokio_scheduler::AsyncTokioScheduler;

/// TODO
pub trait Scheduler {
    /// TODO
    fn run<Item: crate::Item + Send, Items: std::iter::IntoIterator<Item = Item> + Send>(
        &self,
        checks: Vec<Box<dyn Check<Item = Item, Items = Items> + Send>>,
    ) -> Vec<(
        Box<dyn Check<Item = Item, Items = Items> + Send>,
        CheckResult<Item, Items>,
    )>;

    /// TODO
    fn auto_fix<Item: crate::Item + Send, Items: std::iter::IntoIterator<Item = Item> + Send>(
        &self,
        checks: Vec<Box<dyn Check<Item = Item, Items = Items> + Send>>,
    ) -> Vec<(
        Box<dyn Check<Item = Item, Items = Items> + Send>,
        CheckResult<Item, Items>,
    )>;
}

/// TODO
#[async_trait::async_trait]
pub trait AsyncScheduler {
    /// TODO
    async fn async_run<
        Item: crate::Item + Send + Sync + 'static,
        Items: std::iter::IntoIterator<Item = Item> + Send + Sync + 'static,
    >(
        &self,
        checks: Vec<Box<dyn AsyncCheck<Item = Item, Items = Items> + Send + Sync>>,
    ) -> Vec<(
        Box<dyn AsyncCheck<Item = Item, Items = Items> + Send + Sync>,
        CheckResult<Item, Items>,
    )>;

    /// TODO
    async fn async_auto_fix<
        Item: crate::Item + Send + Sync + 'static,
        Items: std::iter::IntoIterator<Item = Item> + Send + Sync + 'static,
    >(
        &self,
        checks: Vec<Box<dyn AsyncCheck<Item = Item, Items = Items> + Send + Sync>>,
    ) -> Vec<(
        Box<dyn AsyncCheck<Item = Item, Items = Items> + Send + Sync>,
        CheckResult<Item, Items>,
    )>;
}
