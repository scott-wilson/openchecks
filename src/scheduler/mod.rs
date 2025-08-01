//! The scheduler system
//!
//! The scheduler system is responsible for processing checks either
//! sequentially (via the [SerialScheduler]), threaded
//! (via the [ThreadedScheduler]), or async (via the [AsyncTokioScheduler]).
//!
//! While it is possible, and valid, to process each check by hand, this will
//! abstract away the need to manage the checks and their results.

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

/// A trait for building schedulers.
///
/// A type implementing the scheduler should avoid requiring any state except
/// for the most absolute bare necessities such as thread or worker count. The
/// methods of this trait should also do as little work as possible and just
/// handle taking in a vector of checks and outputting the results of the
/// checks/fixes.
pub trait Scheduler {
    /// Run all of the input checks and return back the checks and the
    /// associated result.
    ///
    /// This should call the [run](crate::runner::run) function to handle
    /// getting the result from the check.
    fn run<Item: crate::Item + Send, Items: std::iter::IntoIterator<Item = Item> + Send>(
        &self,
        checks: Vec<Box<dyn Check<Item = Item, Items = Items> + Send>>,
    ) -> Vec<(
        Box<dyn Check<Item = Item, Items = Items> + Send>,
        CheckResult<Item, Items>,
    )>;

    /// Run the auto fix for all of the input checks and return back the checks
    /// and the associated result.
    ///
    /// This should call the [auto_fix](crate::runner::auto_fix) function to
    /// handle attempting to fix the issue and getting the result from the
    /// check.
    fn auto_fix<Item: crate::Item + Send, Items: std::iter::IntoIterator<Item = Item> + Send>(
        &self,
        checks: Vec<Box<dyn Check<Item = Item, Items = Items> + Send>>,
    ) -> Vec<(
        Box<dyn Check<Item = Item, Items = Items> + Send>,
        CheckResult<Item, Items>,
    )>;
}

/// A trait for building asynchronous schedulers.
///
/// A type implementing the scheduler should avoid requiring any state except
/// for the most absolute bare necessities such as thread or worker count. The
/// methods of this trait should also do as little work as possible and just
/// handle taking in a vector of checks and outputting the results of the
/// checks/fixes.
#[async_trait::async_trait]
pub trait AsyncScheduler {
    /// Run all of the input checks and return back the checks and the
    /// associated result.
    ///
    /// This should call the [async_run](crate::runner::async_run) function to
    /// handle getting the result from the check.
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

    /// Run the auto fix for all of the input checks and return back the checks
    /// and the associated result.
    ///
    /// This should call the [async_auto_fix](crate::runner::async_auto_fix)
    /// function to handle attempting to fix the issue and getting the result
    /// from the check.
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
