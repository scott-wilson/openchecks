use discovery_registry::DiscoveryRegistry;
use pyo3::prelude::*;

mod check;
mod check_wrapper;
mod discovery_registry;
mod error;
mod item;
mod item_wrapper;
mod result;
mod runner;
mod scheduler;
mod status;

use check::{AsyncBaseCheck, BaseCheck, CheckHint, CheckMetadata};
use error::CheckError;
use item::Item;
use result::CheckResult;
use runner::{async_auto_fix, async_run, auto_fix, run};
use scheduler::{
    async_base_scheduler::AsyncBaseScheduler, base_scheduler::BaseScheduler, sched::Scheduler,
};
use status::Status;

#[pymodule(gil_used = false)]
pub mod openchecks {
    #[pymodule_export]
    use super::{async_auto_fix, async_run, auto_fix, run};

    #[pymodule_export]
    use super::{
        AsyncBaseCheck, AsyncBaseScheduler, BaseCheck, BaseScheduler, CheckError, CheckHint,
        CheckMetadata, CheckResult, DiscoveryRegistry, Item, Scheduler, Status,
    };
}
