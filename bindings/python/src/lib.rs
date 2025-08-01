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
    async_base_scheduler::AsyncBaseScheduler, base_scheduler::BaseScheduler, scheduler::Scheduler,
};
use status::Status;

#[pymodule(gil_used = false)]
fn openchecks(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(async_auto_fix, m)?)?;
    m.add_function(wrap_pyfunction!(async_run, m)?)?;
    m.add_function(wrap_pyfunction!(auto_fix, m)?)?;
    m.add_function(wrap_pyfunction!(run, m)?)?;

    m.add_class::<AsyncBaseCheck>()?;
    m.add_class::<BaseCheck>()?;
    m.add_class::<CheckHint>()?;
    m.add_class::<CheckMetadata>()?;
    m.add_class::<CheckResult>()?;
    m.add_class::<DiscoveryRegistry>()?;
    m.add_class::<Item>()?;
    m.add_class::<Status>()?;
    m.add_class::<AsyncBaseScheduler>()?;
    m.add_class::<BaseScheduler>()?;
    m.add_class::<Scheduler>()?;
    m.add("CheckError", py.get_type::<CheckError>())?;

    Ok(())
}
