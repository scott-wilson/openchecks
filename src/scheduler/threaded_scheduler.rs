use super::Scheduler;
use crate::{auto_fix, run};
use rayon::prelude::*;

/// TODO
#[derive(Debug, Clone, Copy, Default)]
pub struct ThreadedScheduler;

impl ThreadedScheduler {
    /// TODO
    pub fn new() -> Self {
        Self
    }
}

impl Scheduler for ThreadedScheduler {
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
