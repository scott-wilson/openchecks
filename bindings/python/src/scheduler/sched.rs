use super::base_scheduler::BaseScheduler;
use crate::result::CheckResult;
use pyo3::prelude::*;

#[pyclass(extends = BaseScheduler, subclass)]
pub(crate) struct Scheduler;

#[pymethods]
impl Scheduler {
    #[new]
    #[pyo3(signature = (*args, **kwargs))]
    pub(crate) fn new(
        args: &Bound<'_, PyAny>,
        kwargs: Option<&Bound<'_, PyAny>>,
    ) -> (Self, BaseScheduler) {
        (Self, BaseScheduler::new(args, kwargs))
    }

    pub(crate) fn run(
        &self,
        py: Python,
        checks: &Bound<'_, PyAny>,
    ) -> PyResult<Vec<(Py<PyAny>, CheckResult)>> {
        let mut results = Vec::with_capacity(checks.len()?);

        for check in checks.try_iter()? {
            let check = check?.unbind();
            let result = crate::run(py, check.clone_ref(py))?;
            results.push((check, result));
        }

        Ok(results)
    }

    pub(crate) fn auto_fix(
        &self,
        py: Python,
        checks: &Bound<'_, PyAny>,
    ) -> PyResult<Vec<(Py<PyAny>, CheckResult)>> {
        let mut results = Vec::with_capacity(checks.len()?);

        for check in checks.try_iter()? {
            let check = check?.unbind();
            let result = crate::auto_fix(py, check.clone_ref(py))?;
            results.push((check, result));
        }

        Ok(results)
    }
}
