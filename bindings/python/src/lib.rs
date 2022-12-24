use pyo3::prelude::*;

mod check;
mod item;
mod result;
mod status;

use check::{BaseCheck, CheckHint};
use item::Item;
use result::CheckResult;
use status::Status;

#[pymodule]
fn pychecks(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Status>()?;
    m.add_class::<Item>()?;
    m.add_class::<CheckResult>()?;
    m.add_class::<CheckHint>()?;
    m.add_class::<BaseCheck>()?;

    Ok(())
}
