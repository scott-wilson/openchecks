use super::Scheduler;
use crate::{auto_fix, run};
use rayon::prelude::*;

/// The threaded scheduler
///
/// The threaded scheduler will iterate over all of the checks using all of the
/// available threads in parallel.
#[derive(Debug, Clone, Copy, Default)]
pub struct ThreadedScheduler;

impl ThreadedScheduler {
    /// Create a new threaded scheduler.
    pub fn new() -> Self {
        Self
    }
}

impl Scheduler for ThreadedScheduler {
    /// Run the checks and return the checks and their results.
    fn run<Item: crate::Item + Send, Items: std::iter::IntoIterator<Item = Item> + Send>(
        &self,
        checks: Vec<Box<dyn crate::Check<Item = Item, Items = Items> + Send>>,
    ) -> Vec<(
        Box<dyn crate::Check<Item = Item, Items = Items> + Send>,
        crate::CheckResult<Item, Items>,
    )> {
        checks
            .into_par_iter()
            .map(|c| {
                let result = run(c.as_ref());
                (c, result)
            })
            .collect()
    }

    /// Run the auto fix for the checks and return the results.
    fn auto_fix<Item: crate::Item + Send, Items: std::iter::IntoIterator<Item = Item> + Send>(
        &self,
        checks: Vec<Box<dyn crate::Check<Item = Item, Items = Items> + Send>>,
    ) -> Vec<(
        Box<dyn crate::Check<Item = Item, Items = Items> + Send>,
        crate::CheckResult<Item, Items>,
    )> {
        checks
            .into_par_iter()
            .map(|mut c| {
                let result = auto_fix(c.as_mut());
                (c, result)
            })
            .collect()
    }
}
