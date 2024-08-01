use pyo3::prelude::*;

mod check;
mod check_wrapper;
mod error;
mod item;
mod item_wrapper;
mod result;
mod runner;
mod status;

use check::{AsyncBaseCheck, BaseCheck, CheckHint, CheckMetadata};
use error::CheckError;
use item::Item;
use result::CheckResult;
use runner::{async_auto_fix, async_run, auto_fix, run};
use status::Status;

#[pymodule]
fn openchecks(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(async_auto_fix, m)?)?;
    m.add_function(wrap_pyfunction!(async_run, m)?)?;
    m.add_function(wrap_pyfunction!(auto_fix, m)?)?;
    m.add_function(wrap_pyfunction!(run, m)?)?;

    m.add_class::<AsyncBaseCheck>()?;
    m.add_class::<BaseCheck>()?;
    m.add_class::<CheckHint>()?;
    m.add_class::<CheckMetadata>()?;
    m.add_class::<CheckResult>()?;
    m.add_class::<Item>()?;
    m.add_class::<Status>()?;
    m.add("CheckError", py.get_type::<CheckError>())?;

    Ok(())
}
