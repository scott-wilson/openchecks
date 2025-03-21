use pyo3::{exceptions::PyNotImplementedError, prelude::*};

#[pyclass(subclass)]
pub(crate) struct BaseScheduler;

#[pymethods]
impl BaseScheduler {
    #[new]
    #[pyo3(signature = (*args, **kwargs))]
    pub(crate) fn new(
        #[allow(unused_variables)] args: &Bound<'_, PyAny>,
        #[allow(unused_variables)] kwargs: Option<&Bound<'_, PyAny>>,
    ) -> Self {
        Self
    }

    pub(crate) fn run(
        &self,
        #[allow(unused_variables)] checks: &Bound<'_, PyAny>,
    ) -> PyResult<&Bound<'_, PyAny>> {
        Err(PyNotImplementedError::new_err("run not implemented"))
    }

    pub(crate) fn auto_fix(
        &mut self,
        #[allow(unused_variables)] checks: &Bound<'_, PyAny>,
    ) -> PyResult<&Bound<'_, PyAny>> {
        Err(PyNotImplementedError::new_err("auto_fix not implemented"))
    }
}
