use pyo3::{exceptions::PyNotImplementedError, prelude::*};

#[pyclass(subclass)]
pub(crate) struct AsyncBaseScheduler;

#[pymethods]
impl AsyncBaseScheduler {
    #[new]
    #[pyo3(signature = (*args, **kwargs))]
    pub(crate) fn new(
        #[allow(unused_variables)] args: &Bound<'_, PyAny>,
        #[allow(unused_variables)] kwargs: Option<&Bound<'_, PyAny>>,
    ) -> Self {
        Self
    }

    pub(crate) fn async_run<'py>(
        &self,
        py: Python<'py>,
        #[allow(unused_variables)] checks: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py::<_, ()>(py, async {
            Err(PyNotImplementedError::new_err("async_run not implemented"))
        })
    }

    pub(crate) fn async_auto_fix<'py>(
        &self,
        py: Python<'py>,
        #[allow(unused_variables)] checks: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py::<_, ()>(py, async {
            Err(PyNotImplementedError::new_err(
                "async_auto_fix not implemented",
            ))
        })
    }
}
