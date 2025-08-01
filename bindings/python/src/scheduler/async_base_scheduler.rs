use pyo3::{exceptions::PyNotImplementedError, prelude::*};

/// A base class for building asynchronous schedulers.
///
/// A type implementing the scheduler should avoid requiring any state except
/// for the most absolute bare necessities such as thread or worker count. The
/// methods of this class should also do as little work as possible and just
/// handle taking in a list of checks and outputting the results of the
/// checks/fixes.
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

    /// Run all of the input checks and return back the checks and the
    /// associated result.
    ///
    /// This should call the :code:`async_run` function to handle getting the
    /// result from the check.
    pub(crate) fn async_run<'py>(
        &self,
        py: Python<'py>,
        #[allow(unused_variables)] checks: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py::<_, ()>(py, async {
            Err(PyNotImplementedError::new_err("async_run not implemented"))
        })
    }

    /// Run the auto fix for all of the input checks and return back the checks
    /// and the associated result.
    ///
    /// This should call the :code:`async_auto_fix` function to handle
    /// attempting to fix the issue and getting the result from the check.
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
